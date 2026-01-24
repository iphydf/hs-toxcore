{-# LANGUAGE LambdaCase    #-}
{-# LANGUAGE StrictData    #-}
{-# LANGUAGE TupleSections #-}
-- | Nodes on a virtual clock, with the packets between them delayed, lost,
-- or dropped while a node is down, and some nodes behind NATs. Each node runs
-- as the shell runs it: an input, then what's due. The same seed always gives
-- the same run.
module Tox.Simulator
  ( Sim
  , Link (..)
  , Nat (..)
  , Mapping (..)
  , Filtering (..)
  , newSim
  , simTime
  , addresses
  , addNode
  , addNodeWith
  , addRelay
  , setDown
  , setUdpCut
  , setNat
  , command
  , runFor
  , runUntil
  , stepUntil
  , peekAt
  , realKey
  , dhtNode
  , eventsOf
  , logOf
  , wakeUps
  , trafficOf
  , inFlight
  , kept
  , nextKind
  ) where

import           Control.Monad                      (guard)
import           Control.Monad.Random               (Rand, runRand)
import           Data.List                          (find)
import           Data.List.NonEmpty                 (nonEmpty)
import           Data.Map                           (Map)
import qualified Data.Map.Strict                    as Map
import           Data.Maybe                         (catMaybes, fromMaybe,
                                                     isNothing)
import           Data.Set                           (Set)
import qualified Data.Set                           as Set
import           Data.Text                          (Text, pack)
import           System.Random                      (StdGen, mkStdGen, randomR)

import           Tox.Application.Node
import           Tox.Application.State              (App, Context (..),
                                                     GlobalState (..),
                                                     Output (..), RelayOwner,
                                                     gets, initState)
import           Tox.Core.Log                       (LogLevel (..))
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes   (newKeyPair)
import qualified Tox.DHT.DhtState                   as DhtState
import           Tox.Network.Core.HostAddress       (HostAddress)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.PortNumber        (PortNumber)
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol)
import qualified Tox.Network.TCP.Server             as Server
import qualified Tox.Session.Connection             as Connection

-- | How packets go between any two nodes. Relay connections take the delay
-- too, but lose nothing.
data Link = Link
  { linkDelay  :: TimeDiff
  , linkJitter :: TimeDiff -- ^ Up to this much more, at random, so packets don't all come at once.
  , linkLoss   :: Double -- ^ The chance a packet is lost.
  }

-- | A NAT in front of one node, in RFC 4787's terms, at a public host of
-- its own. TCP connections out get through it whatever it is.
data Nat = Nat
  { natHost      :: HostAddress
  , natMapping   :: Mapping
  , natFiltering :: Filtering
  , natTimeout   :: TimeDiff -- ^ How long a mapping lasts with nothing going out on it.
  }

-- | Which public port a packet goes out from.
data Mapping
  = SamePort -- ^ The same for every destination (endpoint-independent).
  | PortPerDestination -- ^ The next one up for each new destination (address and port dependent), as symmetric NATs do.

-- | Which packets to a public port get through.
data Filtering
  = FromAnyone -- ^ Endpoint-independent.
  | FromHostsSentTo -- ^ Address-dependent.
  | FromAddressesSentTo -- ^ Address and port dependent.

-- | A NAT and the ports it has mapped: by port, where each sent to and
-- when it last did.
data Box = Box
  { boxNat   :: Nat
  , boxPorts :: Map PortNumber (Map SocketAddress Timestamp)
  , boxNext  :: PortNumber
  }

data Peer = Peer
  { peerNode   :: Node
  , peerEvents :: [(Timestamp, Event)] -- ^ Newest first.
  , peerLog    :: [(Timestamp, Text)] -- ^ Info and above, newest first.
  , peerWakes  :: Int -- ^ Times what was due ran.
  , peerAgain  :: (Timestamp, Int) -- ^ How often in a row it ran at that time, with no input between.
  , peerEdge   :: Map Traffic.Counted Traffic.Count -- ^ What its shell would count.
  , peerDue    :: Maybe Timestamp -- ^ Its node's next deadline, as of its last step.
  }

-- | A layer can leave another due at once, so a node may run what's due a
-- few times at one moment with no input between. Many more times and it
-- never sleeps.
spinLimit :: Int
spinLimit = 100

-- | A relay connection, as each end knows it.
data Stream = Stream
  { streamClient :: SocketAddress
  , streamOwner  :: RelayOwner
  , streamRelay  :: PublicKey
  , streamSocket :: Int
  , streamServer :: SocketAddress
  , streamId     :: Server.ClientId
  }

data Sim = Sim
  { simTime     :: Timestamp
  , simPeers    :: Map SocketAddress Peer
  , simDues     :: Set (Timestamp, SocketAddress) -- ^ The peers' deadlines, so the next is cheap to find.
  , simArrivals :: Map (Timestamp, Int) (SocketAddress, Input)
    -- ^ By when they arrive, then by when they were sent.
  , simSent     :: Int
  , simDown     :: Set SocketAddress
  , simCuts     :: Set (SocketAddress, SocketAddress) -- ^ Lower address first.
  , simRelays   :: Set SocketAddress -- ^ Nodes that take relay connections.
  , simStreams  :: [Stream]
  , simClients  :: Server.ClientId -- ^ The next relay client's number.
  , simRandom   :: StdGen
  , simLink     :: Link
  , simLast     :: Map (SocketAddress, SocketAddress) Timestamp
    -- ^ When the last input from each sender to each receiver arrives, with jitter.
  , simNats     :: Map SocketAddress Box -- ^ By the node behind each.
  , simHosts    :: Map HostAddress SocketAddress -- ^ The node behind each NAT's public host.
  }

newSim :: Int -> Link -> Sim
newSim seed link = Sim (Time.fromSeconds 1000) Map.empty Set.empty Map.empty 0 Set.empty Set.empty Set.empty [] 0 (mkStdGen seed) link Map.empty Map.empty Map.empty

-- | A node with new keys, at that address.
addNode :: Setup -> SocketAddress -> Sim -> Sim
addNode setup addr sim = place setup (newKeyPair >>= \dht -> newKeyPair >>= initState (simTime sim) dht) addr sim

-- | A node with these as its real keys (by which friends know it) and a new
-- DHT key, at that address.
addNodeWith :: Setup -> KeyPair.KeyPair -> SocketAddress -> Sim -> Sim
addNodeWith setup keys addr sim = place setup (newKeyPair >>= \dht -> initState (simTime sim) dht keys) addr sim

place :: Setup -> Rand StdGen GlobalState -> SocketAddress -> Sim -> Sim
place setup state addr sim = moveDue addr Nothing (nextDeadline node)
  sim { simPeers = Map.insert addr (Peer node [] [] 0 (simTime sim, 0) Map.empty (nextDeadline node)) (simPeers sim), simRandom = g }
  where
    (node, g) = runRand (newNode setup (simTime sim) <$> state) (simRandom sim)

-- | A node that runs a relay at its address, and uses it itself.
addRelay :: Setup -> SocketAddress -> Sim -> Sim
addRelay setup addr = command addr (useOwnRelay addr) . listen . addNode setup addr
  where listen sim = sim { simRelays = Set.insert addr (simRelays sim) }

-- | While a node is down, nothing reaches it or leaves it, and its relay
-- connections break. The other ends hear of it, and the node itself when it
-- next sends on one.
setDown :: SocketAddress -> Bool -> Sim -> Sim
setDown addr False sim = sim { simDown = Set.delete addr (simDown sim) }
setDown addr True sim = foldl' broken sim { simDown = Set.insert addr (simDown sim) } touching
  where
    touching = filter (\s -> addr `elem` [streamClient s, streamServer s]) (simStreams sim)
    broken s stream
      | streamServer stream == addr = clientHears s stream
      | otherwise = serverHears s stream

-- | UDP between the two doesn't get through, as behind some NATs.
setUdpCut :: SocketAddress -> SocketAddress -> Bool -> Sim -> Sim
setUdpCut a b cut sim = sim { simCuts = (if cut then Set.insert else Set.delete) (pair a b) (simCuts sim) }

-- | Puts the node behind the NAT, its first port picked at random. Packets
-- to its own address no longer reach it.
setNat :: SocketAddress -> Nat -> Sim -> Sim
setNat addr nat sim = sim
  { simNats = Map.insert addr (Box nat Map.empty (fromInteger first)) (simNats sim)
  , simHosts = Map.insert (natHost nat) addr (simHosts sim)
  , simRandom = g
  }
  where (first, g) = randomR (1024, 60000) (simRandom sim)

-- | Where a packet from the node to the address seems to come from, past
-- the node's NAT, if it has one.
outbound :: SocketAddress -> SocketAddress -> Sim -> (SocketAddress, Sim)
outbound from to sim = case Map.lookup from (simNats sim) of
  Nothing -> (from, sim)
  Just box ->
    let nat = boxNat box
        live = Map.filter (any (\t -> Time.addTime t (natTimeout nat) > now)) (boxPorts box)
        existing = case natMapping nat of
          SamePort           -> fst <$> Map.lookupMin live
          PortPerDestination -> fst <$> find (Map.member to . snd) (Map.toList live)
        port = fromMaybe (boxNext box) existing
        box' = box
          { boxPorts = Map.insertWith Map.union port (Map.singleton to now) live
          , boxNext = if isNothing existing then boxNext box + 1 else boxNext box
          }
    in (SocketAddress (natHost nat) port, sim { simNats = Map.insert from box' (simNats sim) })
  where now = simTime sim

-- | The node a packet from the address to the other reaches, past the
-- receiver's NAT, if it lets it in.
inbound :: SocketAddress -> SocketAddress -> Sim -> Maybe SocketAddress
inbound source to@(SocketAddress host port) sim = case Map.lookup host (simHosts sim) of
  Just addr -> do
    box <- Map.lookup addr (simNats sim)
    sent <- Map.filter (\t -> Time.addTime t (natTimeout (boxNat box)) > simTime sim) <$> Map.lookup port (boxPorts box)
    guard (not (Map.null sent) && admits (natFiltering (boxNat box)) (Map.keys sent))
    return addr
  Nothing -> to <$ guard (not (Map.member to (simNats sim)))
  where
    admits FromAnyone _             = True
    admits FromHostsSentTo sent     = any (\(SocketAddress h _) -> h == sourceHost) sent
    admits FromAddressesSentTo sent = source `elem` sent
    SocketAddress sourceHost _ = source

pair :: SocketAddress -> SocketAddress -> (SocketAddress, SocketAddress)
pair a b = (min a b, max a b)

-- | An API call, now.
command :: SocketAddress -> App () -> Sim -> Sim
command addr act sim = arrive (simTime sim) addr (Command act) sim

peekAt :: SocketAddress -> App a -> Sim -> a
peekAt addr act = peek act . peerNode . (Map.! addr) . simPeers

addresses :: Sim -> [SocketAddress]
addresses = Map.keys . simPeers

-- | Its friends know it by this key.
realKey :: SocketAddress -> Sim -> PublicKey
realKey addr = peekAt addr (gets (KeyPair.publicKey . Connection.ourRealKeys . connManager))

-- | Its DHT node, or its relay.
dhtNode :: TransportProtocol -> SocketAddress -> Sim -> NodeInfo
dhtNode transport addr = NodeInfo transport addr . peekAt addr (gets (KeyPair.publicKey . DhtState.dhtKeyPair . dhtState))

-- | Oldest first.
eventsOf :: SocketAddress -> Sim -> [(Timestamp, Event)]
eventsOf addr = reverse . peerEvents . (Map.! addr) . simPeers

-- | Oldest first.
logOf :: SocketAddress -> Sim -> [(Timestamp, Text)]
logOf addr = reverse . peerLog . (Map.! addr) . simPeers

wakeUps :: SocketAddress -> Sim -> Int
wakeUps addr = peerWakes . (Map.! addr) . simPeers

-- | What it sent and received so far, as its core and its shell count it.
trafficOf :: SocketAddress -> Sim -> Map Traffic.Counted Traffic.Count
trafficOf addr sim = Map.unionWith Traffic.addCount (peekAt addr (gets counted) sim) (peerEdge (simPeers sim Map.! addr))

-- | What the next step does: the kind of input it takes, or due work.
nextKind :: Sim -> Maybe Text
nextKind sim = next sim >>= \case
  (_, Due _)       -> Just (pack "due work")
  (_, Arrival key) -> inputName . snd <$> Map.lookup key (simArrivals sim)

-- | Packets and other inputs on their way.
inFlight :: Sim -> Int
inFlight = Map.size . simArrivals

-- | The events and log lines it keeps of all nodes.
kept :: Sim -> Int
kept = sum . map (\p -> length (peerEvents p) + length (peerLog p)) . Map.elems . simPeers

runFor :: TimeDiff -> Sim -> Sim
runFor d sim = runUntil (Time.addTime (simTime sim) d) sim

runUntil :: Timestamp -> Sim -> Sim
runUntil end sim = maybe sim { simTime = end } (runUntil end . snd) (stepUntil end sim)

-- | The next arrival or due work, if it comes by then, and the node it woke
-- (none for a packet to a node that's down). Work a node left due earlier
-- runs now, as the shell runs it: the clock never goes back.
stepUntil :: Timestamp -> Sim -> Maybe (Maybe SocketAddress, Sim)
stepUntil end sim = case next sim of
  Just (t, happening) | t <= end -> Just $ happen happening sim { simTime = max t (simTime sim) }
  _                              -> Nothing

-- | An arrival, or a node with something due. At the same time arrivals come
-- first, as the shell takes an input before what's due.
data Happening = Arrival (Timestamp, Int) | Due SocketAddress
  deriving (Eq, Ord)

next :: Sim -> Maybe (Timestamp, Happening)
next sim = minimum <$> nonEmpty (arrivals ++ dues)
  where
    arrivals = [ (t, Arrival key) | Just (key@(t, _), _) <- [Map.lookupMin (simArrivals sim)] ]
    dues = [ (t, Due addr) | Just (t, addr) <- [Set.lookupMin (simDues sim)] ]

happen :: Happening -> Sim -> (Maybe SocketAddress, Sim)
happen (Due addr) sim = (Just addr, wake addr Nothing sim)
happen (Arrival key) sim = case Map.lookup key (simArrivals sim) of
  Just (addr, input) | not (Set.member addr (simDown sim)) -> (Just addr, wake addr (Just input) sim')
  _                                                      -> (Nothing, sim')
  where sim' = sim { simArrivals = Map.delete key (simArrivals sim) }

-- | As the shell does it: the input, then what's due.
wake :: SocketAddress -> Maybe Input -> Sim -> Sim
wake addr input sim = case Map.lookup addr (simPeers sim) of
  Nothing -> sim
  Just peer ->
    let ctx = Context now (fromIntegral (Time.timestampToMicroseconds now `div` 1000000)) False
        Stepped node outputs events = maybe (Stepped (peerNode peer) [] []) (\i -> handleInput ctx i (peerNode peer)) input
        due = maybe False (<= now) (nextDeadline node)
        Stepped node' outputs' events'
          | due = handleDue ctx node
          | otherwise = Stepped node [] []
        logged = [ (now, line) | Log level line <- outputs ++ outputs', level >= LevelInfo ]
        again = case peerAgain peer of
          (t, n) | t == now && due && isNothing input -> (now, n + 1)
          _                                           -> (now, fromEnum due)
        edge = foldl' (\m (what, n) -> Map.insertWith Traffic.addCount what (Traffic.Count 1 (fromIntegral n)) m) (peerEdge peer)
          . catMaybes $ (inputCounted =<< input) : map outputCounted (outputs ++ outputs')
        peer' = Peer node' (reverse (map (now,) (events ++ events')) ++ peerEvents peer)
          (reverse logged ++ peerLog peer) (peerWakes peer + fromEnum due) again edge (nextDeadline node')
    in if snd again > spinLimit
      then error $ "the node at " <> show addr <> " never sleeps"
      else foldl' (send addr) (moveDue addr (peerDue peer) (peerDue peer') sim { simPeers = Map.insert addr peer' (simPeers sim) }) (outputs ++ outputs')
  where
    now = simTime sim

-- | Moves the peer's deadline in the index.
moveDue :: SocketAddress -> Maybe Timestamp -> Maybe Timestamp -> Sim -> Sim
moveDue addr old new sim = sim { simDues = foldr (Set.insert . (, addr)) (foldr (Set.delete . (, addr)) (simDues sim) old) new }

-- | What a node's shell would do with an output. Replies have no part in it.
send :: SocketAddress -> Sim -> Output -> Sim
send from sim = \case
  SendUdp to bytes
    | Set.member from (simDown sim) -> sim'
    -- The NAT maps it before the network loses it.
    | lost -> natted
    | otherwise -> case inbound source to natted of
        Just addr | not (Set.member addr (simDown sim) || Set.member (pair from addr) (simCuts sim)) ->
          later from addr (Datagram source bytes) natted
        _ -> natted
    where
      (chance, g) = randomR (0, 1) (simRandom sim)
      lost = chance < linkLoss (simLink sim)
      sim' = sim { simRandom = g }
      (source, natted) = outbound from to sim'
  RelayConnect owner relay socket
    | Set.member server (simRelays replaced) && not (any (`Set.member` simDown sim) [from, server]) ->
        later from server (ClientAccepted (simClients replaced)) replaced
          { simStreams = Stream from owner (publicKey relay) socket server (simClients replaced) : simStreams replaced
          , simClients = simClients replaced + 1
          }
    | otherwise -> later from from (RelayClosed owner (publicKey relay) socket) replaced
    where
      server = address relay
      -- The shell closes the socket a new one replaces.
      replaced = maybe sim (serverHears sim) (ours owner (publicKey relay))
  RelaySend owner pk socket bytes -> case ours owner pk of
    Just stream | streamSocket stream == socket -> later from (streamServer stream) (ClientBytes (streamId stream) bytes) sim
    _ -> later from from (RelayClosed owner pk socket) sim
  RelayClose owner pk -> maybe sim (serverHears sim) (ours owner pk)
  ClientSend client bytes -> maybe sim (\s -> later from (streamClient s) (RelayBytes (streamOwner s) (streamRelay s) (streamSocket s) bytes) sim) (theirs client)
  ClientClose client -> maybe sim (clientHears sim) (theirs client)
  _ -> sim
  where
    ours owner pk = find (\s -> (streamClient s, streamOwner s, streamRelay s) == (from, owner, pk)) (simStreams sim)
    theirs client = find (\s -> (streamServer s, streamId s) == (from, client)) (simStreams sim)

-- | The stream ends, and the relay hears of it.
serverHears :: Sim -> Stream -> Sim
serverHears sim stream = later (streamClient stream) (streamServer stream) (ClientClosed (streamId stream)) (closed stream sim)

-- | The stream ends, and the client hears of it.
clientHears :: Sim -> Stream -> Sim
clientHears sim stream =
  later (streamServer stream) (streamClient stream) (RelayClosed (streamOwner stream) (streamRelay stream) (streamSocket stream)) (closed stream sim)

closed :: Stream -> Sim -> Sim
closed stream sim = sim { simStreams = filter (not . same) (simStreams sim) }
  where same s = (streamServer s, streamId s) == (streamServer stream, streamId stream)

-- | After the link's delay, and with jitter some more, from the sender to
-- the receiver.
later :: SocketAddress -> SocketAddress -> Input -> Sim -> Sim
later from to input sim
  | linkJitter link == 0 = arrive (Time.addTime (simTime sim) (linkDelay link)) to input sim
  | otherwise = arrive t to input sim { simRandom = g, simLast = Map.insert (from, to) t (simLast sim) }
  where
    link = simLink sim
    (extra, g) = randomR (0, Time.toMilliseconds (linkJitter link) * 1000000) (simRandom sim)
    -- Not before what the sender sent the receiver earlier: one path keeps
    -- its packets' order.
    t = maybe id max (Map.lookup (from, to) (simLast sim)) $
      Time.addTime (simTime sim) (linkDelay link + fromInteger extra)

arrive :: Timestamp -> SocketAddress -> Input -> Sim -> Sim
arrive t addr input sim = sim
  { simArrivals = Map.insert (t, simSent sim) (addr, input) (simArrivals sim)
  , simSent = simSent sim + 1
  }
