{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}
-- | A Tox node's core: what each input does, and what's due when. It does no
-- IO. The shell in "Tox.Application.Tox" reads the sockets and the clock and
-- carries out what each step asks for.
module Tox.Application.Node
    ( -- * Types
      ConnectionStatus (..)
    , Event (..)
    , Input (..)
    , inputName
    , inputCounted
    , outputCounted
      -- * The node
    , Node
    , Stepped (..)
    , Setup (..)
    , newNode
    , handleInput
    , handleDue
    , nextDeadline
    , peek
      -- * For the API
    , restore
    , goodbye
    , useOwnRelay
    , bootstrapNode
    , getFriendConnection
    , linkStatus
    , getSelfConnection
    , touchLastSeen
    , unixClock
    , concatMapM
    , clientLossless
    , clientLossy
      -- * For tests
    , connectionEvents
    , handleDatagram
    , senderKey
    ) where

import           Control.Monad                      (foldM, forM, forM_, void,
                                                     when, (>=>))
import           Control.Monad.State                (modify)
import qualified Crypto.Saltine.Class               as Sodium
import qualified Data.Binary                        as Binary
import           Data.Bool                          (bool)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.List.NonEmpty                 (nonEmpty)
import qualified Data.Map                           as Map
import           Data.Maybe                         (catMaybes, fromJust,
                                                     fromMaybe, listToMaybe,
                                                     maybeToList)
import           Data.Text                          (Text, pack)
import           Data.Word                          (Word16, Word32, Word64,
                                                     Word8)

import           Tox.Application.Save               (Profile (..),
                                                     SavedFriend (..))
import qualified Tox.Application.Sizes              as Sizes
import           Tox.Application.State
import qualified Tox.Chat.Conference                as Conference
import qualified Tox.Chat.GroupChat                 as Group
import           Tox.Core.Log                       (logWarn)
import qualified Tox.Core.Schedule                  as Schedule
import           Tox.Core.Schedule                  (Schedule)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import           Tox.Core.Timed                     (Timed (..))
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import qualified Tox.DHT.DhtState                   as DhtState
import qualified Tox.DHT.KBuckets                   as KBuckets
import qualified Tox.DHT.Nat                        as Nat
import qualified Tox.DHT.Node                       as DHTNode
import qualified Tox.DHT.Operation                  as DHT
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..),
                                                     RawPayload (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import qualified Tox.Network.Core.SocketAddress     as SocketAddress
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.Discovery.LAN          as LAN
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Network.TCP.Server             as Server
import qualified Tox.Onion.Operation                as Onion
import qualified Tox.Onion.Path                     as Path
import qualified Tox.Session.Connection             as Connection
import qualified Tox.Session.Friend                 as Messenger


{-------------------------------------------------------------------------------
 -
 - :: Types.
 -
 ------------------------------------------------------------------------------}

data ConnectionStatus = NotConnected | ConnectedTcp | ConnectedUdp
  deriving (Eq, Show)

data Event
  = SelfConnectionChanged ConnectionStatus
  | FriendConnectionChanged PublicKey ConnectionStatus
  | FriendRequest PublicKey BS.ByteString
  | FriendMessage PublicKey Messenger.MessageType BS.ByteString
  | FriendReadReceipt PublicKey Word32
  | FriendName PublicKey BS.ByteString
  | FriendStatusMessage PublicKey BS.ByteString
  | FriendStatus PublicKey Messenger.UserStatus
  | FriendTyping PublicKey Bool
  | FileReceive PublicKey Word8 Word32 Word64 BS.ByteString BS.ByteString
    -- ^ File number, kind, size, ID and name. Accept it with 'Tox.Application.Tox.fileControl'.
  | FileReceiveChunk PublicKey Word8 Word64 BS.ByteString
    -- ^ Empty means the file is complete.
  | FileChunkRequest PublicKey Word8 Word64 Int
    -- ^ Send this much of a file from this position with 'Tox.Application.Tox.fileSendChunk'.
    -- A length of 0 means the friend has the whole file.
  | FileControlChanged PublicKey Messenger.FileRef Messenger.FileControl
  | FriendLosslessPacket PublicKey BS.ByteString
    -- ^ Including its ID.
  | FriendLossyPacket PublicKey BS.ByteString
  | ConferenceInvite PublicKey Word8 BS.ByteString
    -- ^ Conference type and cookie. Join with 'Tox.Application.Tox.conferenceJoin'.
  | ConferenceConnected Conference.ConferenceNumber
  | ConferenceMessage Conference.ConferenceNumber Conference.PeerNumber Messenger.MessageType BS.ByteString
  | ConferenceTitle Conference.ConferenceNumber (Maybe Conference.PeerNumber) BS.ByteString
  | ConferencePeerName Conference.ConferenceNumber Conference.PeerNumber BS.ByteString
  | ConferencePeerListChanged Conference.ConferenceNumber
  | GroupInvite PublicKey BS.ByteString BS.ByteString
    -- ^ Invite data for 'Tox.Application.Tox.groupInviteAccept', and the group name.
  | GroupSelfJoin Group.GroupNumber
  | GroupJoinFail Group.GroupNumber Group.JoinFail
  | GroupPeerJoin Group.GroupNumber Group.PeerId PublicKey
  | GroupPeerExit Group.GroupNumber Group.PeerId Group.ExitType BS.ByteString BS.ByteString
  | GroupPeerName Group.GroupNumber Group.PeerId BS.ByteString
  | GroupPeerStatus Group.GroupNumber Group.PeerId Word8
  | GroupMessage Group.GroupNumber Group.PeerId Messenger.MessageType BS.ByteString Word32
  | GroupPrivateMessage Group.GroupNumber Group.PeerId Messenger.MessageType BS.ByteString Word32
  | GroupTopic Group.GroupNumber (Maybe Group.PeerId) BS.ByteString
  | GroupModeration Group.GroupNumber (Maybe Group.PeerId) (Maybe Group.PeerId) Group.Moderation
    -- ^ Setter and target, 'Nothing' for us.
  | GroupPrivacy Group.GroupNumber Bool -- ^ Whether it is private now.
  | GroupPeerLimit Group.GroupNumber Word16
  | GroupPassword Group.GroupNumber BS.ByteString
  | GroupTopicLock Group.GroupNumber Bool
  | GroupVoiceState Group.GroupNumber Group.Voice
  | GroupCustomPacket Group.GroupNumber Group.PeerId BS.ByteString
  | GroupCustomPrivatePacket Group.GroupNumber Group.PeerId BS.ByteString
  deriving (Eq, Show)

-- | Relay sockets are numbered, so we can tell an old socket's input from
-- the new one's.
data Input
  = Datagram SocketAddress BS.ByteString
  | RelayBytes RelayOwner PublicKey Int BS.ByteString
  | RelayClosed RelayOwner PublicKey Int
  | RelayBusy RelayOwner PublicKey Int
    -- ^ The socket holds too many of our bytes for data that can wait.
  | RelayWritable RelayOwner PublicKey Int
  | ClientAccepted Server.ClientId
  | ClientBytes Server.ClientId BS.ByteString
  | ClientClosed Server.ClientId
  | ClientBusy Server.ClientId
  | ClientWritable Server.ClientId
  | Command (App ())

-- | For the main loop's timings.
inputName :: Input -> Text
inputName = pack . \case
  Datagram _ bs -> "UDP " <> maybe "unknown" show (BS.uncons bs >>= PacketKind.byteToKind . fst)
  RelayBytes {} -> "TCP relay data"
  RelayClosed {} -> "TCP relay closed"
  ClientAccepted _ -> "Our relay: new client"
  ClientBytes _ _ -> "Our relay: client data"
  ClientClosed _ -> "Our relay: client closed"
  RelayBusy {} -> "TCP relay busy"
  RelayWritable {} -> "TCP relay writable"
  ClientBusy _ -> "Our relay: client busy"
  ClientWritable _ -> "Our relay: client writable"
  Command _ -> "API call"

inputCounted :: Input -> Maybe (Traffic.Counted, Int)
inputCounted = \case
  Datagram _ bs -> datagramCounted Traffic.Received bs
  RelayBytes _ _ _ bytes -> Just (Traffic.RelayLink Traffic.Received, BS.length bytes)
  _ -> Nothing

outputCounted :: Output -> Maybe (Traffic.Counted, Int)
outputCounted = \case
  SendUdp _ bs -> datagramCounted Traffic.Sent bs
  RelaySend _ _ _ bytes -> Just (Traffic.RelayLink Traffic.Sent, BS.length bytes)
  _ -> Nothing

datagramCounted :: Traffic.Way -> BS.ByteString -> Maybe (Traffic.Counted, Int)
datagramCounted way bs = (\(kind, _) -> (Traffic.Packets way Traffic.Udp kind, BS.length bs)) <$> BS.uncons bs


{-------------------------------------------------------------------------------
 -
 - :: The node.
 -
 ------------------------------------------------------------------------------}

-- | Everything an instance knows, apart from its sockets.
data Node = Node LoopState GlobalState

data Stepped = Stepped Node [Output] [Event]

data Setup = Setup
  { setupUdp  :: Bool -- ^ Without it, only through TCP relays.
  , setupIpv6 :: Bool
  , setupLan  :: Bool -- ^ Needs UDP.
  }

-- | Every job is due at the start.
newNode :: Setup -> Timestamp -> GlobalState -> Node
newNode (Setup udp ipv6 discovery) now gs = Node (LoopState (startJobs lan now) NotConnected False False (LAN.portFrom + 1) lan) gs
  { udpEnabled = udp
  , udpIpv6 = ipv6
  , onionState = (onionState gs) { Onion.onionTcpOnly = not udp }
  }
  where lan = udp && discovery

-- | Friends see us go offline.
goodbye :: App ()
goodbye = Connection.getsConn (Map.keys . Connection.friends) >>= mapM_ (Connection.killSession Connection.Stopping)

-- | Like toxcore, we use our own relay as a client too.
useOwnRelay :: SocketAddress -> App ()
useOwnRelay addr = gets (KeyPair.publicKey . DhtState.dhtKeyPair . dhtState) >>= Tcp.addRelay . NodeInfo TCP addr

handleInput :: Context -> Input -> Node -> Stepped
handleInput ctx = runNode ctx . flip step

handleDue :: Context -> Node -> Stepped
handleDue ctx = runNode ctx runDue

nextDeadline :: Node -> Maybe Timestamp
nextDeadline (Node ls gs) =
  fmap minimum . nonEmpty . catMaybes $ Schedule.next (lsJobs ls) : map (`layerNext` gs) layers

-- | Changes the action makes are thrown away.
peek :: App a -> Node -> a
peek act (Node _ gs) = fst (runApp act gs)

runNode :: Context -> (LoopState -> App (LoopState, [Event])) -> Node -> Stepped
runNode ctx act (Node ls gs) = case runApp (setContext ctx *> ((,) <$> (act ls >>= selfStatus >>= relayed >>= dhtFilled) <*> takeOutbox)) gs of
  (((ls', events), outputs), gs') -> Stepped (Node ls' gs') outputs events

-- | When we're back online, so are friends whose sessions timed out
-- meanwhile.
selfStatus :: (LoopState, [Event]) -> App (LoopState, [Event])
selfStatus (ls, events) = do
  conn <- getSelfConnection
  when (lsSelfConn ls == NotConnected && conn /= NotConnected) Connection.weAreBack
  return (ls { lsSelfConn = conn }, events ++ [SelfConnectionChanged conn | conn /= lsSelfConn ls])

-- | When we get a relay, online friends hear of it, and we build onion
-- paths.
relayed :: (LoopState, [Event]) -> App (LoopState, [Event])
relayed (ls, events) = do
  have <- gets (not . null . Tcp.confirmedRelays . tcpState)
  now <- askTime
  let first = have && not (lsRelayed ls)
  when first Connection.relaysUp
  -- A relay can start onion paths, which without UDP would otherwise wait
  -- for the next upkeep.
  let jobs = if first then Schedule.soonest now DhtUpkeep (lsJobs ls) else lsJobs ls
  return (ls { lsRelayed = have, lsJobs = jobs }, events)


{-------------------------------------------------------------------------------
 -
 - :: Periodic work.
 -
 ------------------------------------------------------------------------------}

-- | Interval of DHT and onion maintenance.
dhtInterval :: Time.TimeDiff
dhtInterval = Time.seconds 2

data LoopState = LoopState
  { lsJobs        :: Schedule Job
  , lsSelfConn    :: ConnectionStatus
  , lsRelayed     :: Bool -- ^ We have a confirmed relay.
  , lsDhtNodes    :: Bool -- ^ Our DHT has enough nodes for a path.
  , lsNextLanPort :: Word16
  , lsLan         :: Bool
  }

-- | Jobs due together run in this order.
data Job
  = DhtUpkeep -- ^ DHT and onion.
  | LanAnnounce
  | SizeCheck
  deriving (Eq, Ord, Show, Enum, Bounded)

jobInterval :: Job -> TimeDiff
jobInterval = \case
  DhtUpkeep   -> dhtInterval
  LanAnnounce -> LAN.interval
  SizeCheck   -> checkInterval

-- | When the DHT first has enough nodes for a path, its upkeep (with the
-- onion's) runs at once, as until then it couldn't build any.
dhtFilled :: (LoopState, [Event]) -> App (LoopState, [Event])
dhtFilled (ls, events) = do
  now <- askTime
  have <- gets ((>= Path.pathLength) . length . take Path.pathLength . KBuckets.getAllNodes . DhtState.dhtCloseList . dhtState)
  let jobs = if have && not (lsDhtNodes ls) then Schedule.soonest now DhtUpkeep (lsJobs ls) else lsJobs ls
  return (ls { lsDhtNodes = have, lsJobs = jobs }, events)

startJobs :: Bool -> Timestamp -> Schedule Job
startJobs lan now = foldr (Schedule.at now) Schedule.empty [ j | j <- [minBound ..], lan || j /= LanAnnounce ]

data Layer = Layer
  { layerNext :: GlobalState -> Maybe Timestamp
  , layerRun  :: App [Event]
  }

layers :: [Layer]
layers =
  [ Layer (DHT.queueDue . dhtState) ([] <$ DHT.sendQueued)
  , Layer (Nat.nextDue . dhtState) ([] <$ Nat.runDue)
  , Layer (Onion.nextDue . onionState) ([] <$ Onion.runDue)
  , Layer (Tcp.nextDue . tcpState) ([] <$ Tcp.runDue)
  , Layer (Server.nextDue . tcpServer) ([] <$ Server.runDue)
  , Layer (Conference.nextDue . conferences) (map conferenceEvent <$> Conference.runDue)
  , Layer groupsDue (map groupEvent <$> Group.runDue)
  , Layer groupTcpDue ([] <$ runGroupTcpDue)
  , Layer (Connection.nextDue . connManager) (Connection.runDue >>= connectionEvents)
  , Layer (Messenger.nextDue . messenger) (Messenger.runDue >>= concatMapM toEvent)
  , Layer leftGroupTcpDue ([] <$ closeLeftGroupTcp)
  ]

-- | Also due at once when our address or relays changed what a group would
-- announce.
groupsDue :: GlobalState -> Maybe Timestamp
groupsDue gs = fmap minimum . nonEmpty . catMaybes $
  Group.nextDue (groupChats gs) : [ Just (stepTime gs) | any changed (Group.groups (groupChats gs)) ]
  where
    changed gr = Group.announceChanged (DhtState.dhtSelfAddress (dhtState gs)) (relay gr) gr
    relay gr = listToMaybe . Tcp.confirmedRelays . gtState =<< Map.lookup (Group.grChatId gr) (groupTcp gs)

runDue :: LoopState -> App (LoopState, [Event])
runDue ls = do
  now <- askTime
  let (due, waiting) = Schedule.takeDue now (lsJobs ls)
      again job = Schedule.at (Time.addTime now (jobInterval job)) job
      run (st, events) job = fmap (events ++) <$> runJob st job
  (ls', jobEvents) <- foldM run (ls { lsJobs = waiting }, []) due
  layerEvents <- fmap concat . forM layers $ \layer -> do
    layerDue <- gets (maybe False (<= now) . layerNext layer)
    if layerDue then layerRun layer else return []
  return (ls' { lsJobs = foldr again (lsJobs ls') due }, jobEvents ++ layerEvents)

runJob :: LoopState -> Job -> App (LoopState, [Event])
runJob ls = \case
  DhtUpkeep -> (ls, []) <$ (DHTNode.handleMaintenance >> Onion.doOnion)
  LanAnnounce -> do
    ipv6 <- gets udpIpv6
    port <- LAN.announce ipv6 (lsNextLanPort ls)
    return (ls { lsNextLanPort = port }, [])
  SizeCheck -> do
    over <- gets (filter Sizes.overLimit . Sizes.stateSizes)
    (ls, []) <$ mapM_ (logWarn . (pack "Over its limit: " <>) . describeSize) over

-- | How often we look for state that grew past its limit.
checkInterval :: TimeDiff
checkInterval = Time.seconds 60

describeSize :: Sizes.Size -> Text
describeSize s =
  Sizes.sizeName s <> pack (": " <> show (Sizes.sizeCount s) <> maybe "" ((" of " <>) . show) (Sizes.sizeLimit s))


{-------------------------------------------------------------------------------
 -
 - :: Inputs.
 -
 ------------------------------------------------------------------------------}

step :: LoopState -> Input -> App (LoopState, [Event])
step ls input = case input of
  Datagram addr bs -> do
    keep <- keeping
    (,) ls <$> concatMapM (handleDatagram (lsLan ls) addr) (filter keep . maybeToList $ decodePacket bs)
  RelayBytes owner pk gen bytes -> do
    keep <- keeping
    (,) ls <$> ifCurrent owner pk gen (relayBytes keep owner pk bytes)
  RelayClosed owner pk gen -> (,) ls <$> ifCurrent owner pk gen ([] <$ (relayGone owner pk >> relayClosed owner pk))
  RelayBusy owner pk gen -> (,) ls <$> ifCurrent owner pk gen ([] <$ relayBusy owner pk)
  RelayWritable owner pk gen -> (,) ls <$> ifCurrent owner pk gen ([] <$ relayWritable owner pk)
  ClientAccepted client -> (ls, []) <$ Server.clientAccepted client
  ClientBytes client bytes -> do
    serverEvents <- Server.clientBytes client bytes
    forM_ serverEvents $ \(Server.ServerOnionRequest from request) -> Onion.handleTcpOnionRequest from request
    return (ls, [])
  ClientClosed client -> (ls, []) <$ (clientWritable client >> Server.killClient client)
  ClientBusy client -> (ls, []) <$ clientBusy client
  ClientWritable client -> (ls, []) <$ clientWritable client
  Command action -> (ls, []) <$ action
  where
    -- Ignore input from a socket we've replaced.
    ifCurrent owner pk gen act = currentSocket owner pk gen >>= bool (return []) act

keeping :: App (Packet RawPayload -> Bool)
keeping = gets $ \gs pkt -> not (clientBehind gs) || packetKind pkt `notElem` dataKinds

-- | Peers send these again when they're lost.
dataKinds :: [PacketKind.PacketKind]
dataKinds = [PacketKind.CryptoData, PacketKind.GroupLossless, PacketKind.GroupLossy]

relayBytes :: (Packet RawPayload -> Bool) -> RelayOwner -> PublicKey -> BS.ByteString -> App [Event]
relayBytes keep (Just chatId) pk bytes = do
  keys <- gets (fmap gtKeys . Map.lookup chatId . groupTcp)
  relayEvents <- maybe (return []) (\k -> runGroupTcp chatId k (Tcp.handleRelayBytes pk bytes)) keys
  mapM_ countRouted relayEvents
  flip concatMapM relayEvents $ \case
    Tcp.TcpPacket _ packet -> case decodePacket packet of
      Just pkt@(Packet kind (RawPayload payload)) | kind `elem` groupKinds, keep pkt ->
        map groupEvent <$> Group.handlePacket Nothing kind payload
      _ -> return []
    Tcp.TcpOnionResponse _ -> return []
relayBytes keep Nothing pk bytes = do
  relayEvents <- Tcp.handleRelayBytes pk bytes
  mapM_ countRouted relayEvents
  flip concatMapM relayEvents $ \case
    Tcp.TcpPacket link packet -> flip concatMapM (filter keep . maybeToList $ decodePacket packet) $ \pkt ->
      Connection.handlePacket link (fmap unRawPayload pkt) >>= connectionEvents
    Tcp.TcpOnionResponse packet -> flip concatMapM (maybeToList $ decodePacket packet) $ \pkt ->
      Onion.handleOnionPacket noAddress (fmap unRawPayload pkt) >>= onionEvents

countRouted :: Tcp.TcpEvent -> App ()
countRouted event = forM_ (BS.uncons packet) $ \(kind, _) ->
  countTraffic (Traffic.Packets Traffic.Received Traffic.Relay kind) (BS.length packet)
  where
    packet = case event of
      Tcp.TcpPacket _ p      -> p
      Tcp.TcpOnionResponse p -> p

relayClosed :: RelayOwner -> PublicKey -> App ()
relayClosed (Just chatId) pk = do
  keys <- gets (fmap gtKeys . Map.lookup chatId . groupTcp)
  forM_ keys $ \k -> runGroupTcp chatId k (Tcp.relayClosed pk)
relayClosed Nothing pk = Tcp.relayClosed pk

handleDatagram :: Bool -> SocketAddress -> Packet RawPayload -> App [Event]
handleDatagram lan sa pktRaw
  | kind == PacketKind.LanDiscovery = [] <$ when lan (LAN.handlePacket sa payload)
  | kind `elem` groupKinds =
      map groupEvent <$> Group.handlePacket (Just sa) kind payload
  | kind == PacketKind.Crypto = do
      DHTNode.handleIncomingPacket from pkt
      Onion.handleDhtRequest payload >>= onionEvents
  | kind `elem` [PacketKind.PingRequest, PacketKind.PingResponse, PacketKind.NodesRequest, PacketKind.NodesResponse] =
      [] <$ DHTNode.handleIncomingPacket from pkt
  | kind `elem` [ PacketKind.OnionRequest0, PacketKind.OnionRequest1, PacketKind.OnionRequest2
                , PacketKind.OnionResponse1, PacketKind.OnionResponse2, PacketKind.OnionResponse3
                , PacketKind.AnnounceRequest, PacketKind.AnnounceResponse
                , PacketKind.OnionDataRequest, PacketKind.OnionDataResponse ] =
      Onion.handleOnionPacket sa pkt >>= onionEvents
  | kind `elem` [ PacketKind.CookieRequest, PacketKind.CookieResponse
                , PacketKind.CryptoHandshake, PacketKind.CryptoData ] =
      Connection.handlePacket from pkt >>= connectionEvents
  | otherwise = return []
  where
    pkt = fmap unRawPayload pktRaw
    kind = packetKind pkt
    payload = packetPayload pkt
    from = NodeInfo UDP sa (senderKey kind payload)

-- | Zeros if the packet has no sender key.
senderKey :: PacketKind.PacketKind -> BS.ByteString -> PublicKey
senderKey kind payload
  | kind `elem` [PacketKind.PingRequest, PacketKind.PingResponse, PacketKind.NodesRequest, PacketKind.NodesResponse] =
      keyAt 0
  | kind == PacketKind.Crypto = keyAt 32
  | kind == PacketKind.CookieRequest = keyAt 0
  | otherwise = nullPk
  where
    nullPk = fromJust (Sodium.decode $ BS.replicate 32 0)
    keyAt offset = fromMaybe nullPk $ Sodium.decode (BS.take 32 $ BS.drop offset payload)

-- | Onion responses from a relay have no address. Only requests use it.
noAddress :: SocketAddress
noAddress = SocketAddress (IPv4 0) 0

groupKinds :: [PacketKind.PacketKind]
groupKinds = [PacketKind.GroupHandshake, PacketKind.GroupLossless, PacketKind.GroupLossy]

decodePacket :: BS.ByteString -> Maybe (Packet RawPayload)
decodePacket bytes = case Binary.decodeOrFail (LBS.fromStrict bytes) of
  Right (_, _, pkt) -> Just pkt
  Left _            -> Nothing


{-------------------------------------------------------------------------------
 -
 - :: Events.
 -
 ------------------------------------------------------------------------------}

-- | Between UDP and TCP, as toxcore reports. Only once we told the client the
-- friend is online.
moved :: PublicKey -> App [Event]
moved pk = do
  reported <- gets (Map.lookup pk . friendLinks)
  link <- Connection.friendLink pk
  case (reported, link) of
    (Just was, Just to) | NodeInfo.protocol to /= was -> do
      modify $ \gs -> gs { friendLinks = Map.insert pk (NodeInfo.protocol to) (friendLinks gs) }
      return [FriendConnectionChanged pk (linkStatus to)]
    _ -> return []

onionEvents :: [Onion.OnionEvent] -> App [Event]
onionEvents events = do
  fromGroups <- concatMapM Group.handleOnionEvent events
  (map groupEvent fromGroups ++) <$> (concatMapM Connection.handleOnionEvent >=> connectionEvents) events

connectionEvents :: [Connection.ConnectionEvent] -> App [Event]
connectionEvents events = do
  fromMessenger <- concatMapM Messenger.handleConnectionEvent events >>= concatMapM toEvent
  fromConferences <- concatMapM Conference.handleConnectionEvent events
  fromGroups <- concatMapM Group.handleConnectionEvent events
  fromClient <- concatMapM customPacket events
  moves <- concatMapM moved [ pk | Connection.FriendMoved pk <- events ]
  return $ fromMessenger ++ map conferenceEvent fromConferences ++ map groupEvent fromGroups ++ fromClient ++ moves

-- | Client packets are toxcore's custom lossless range (toxcore only takes
-- calls from it) and every lossy ID.
clientLossless, clientLossy :: Word8 -> Bool
clientLossless ident = (ident >= 160 && ident < 192) || ident == msiPacketId
clientLossy ident = ident >= 192 && ident < 255

-- | Call signalling packet ID (toxcore leaves it to toxav).
msiPacketId :: Word8
msiPacketId = 69

customPacket :: Connection.ConnectionEvent -> App [Event]
customPacket = \case
  Connection.FriendData pk bytes | Just (ident, _) <- BS.uncons bytes, clientLossless ident -> do
    online <- Messenger.isFriendOnline pk
    return [FriendLosslessPacket pk bytes | online]
  Connection.FriendLossyData pk bytes | Just (ident, _) <- BS.uncons bytes, clientLossy ident -> do
    online <- Messenger.isFriendOnline pk
    return [FriendLossyPacket pk bytes | online]
  _ -> return []

groupEvent :: Group.GroupEvent -> Event
groupEvent = \case
  Group.GroupInvite friend invite name      -> GroupInvite friend invite name
  Group.GroupSelfJoin g                     -> GroupSelfJoin g
  Group.GroupJoinFail g reason              -> GroupJoinFail g reason
  Group.GroupPeerJoin g n pk                -> GroupPeerJoin g n pk
  Group.GroupPeerExit g n exit name part    -> GroupPeerExit g n exit name part
  Group.GroupPeerName g n name              -> GroupPeerName g n name
  Group.GroupPeerStatus g n status          -> GroupPeerStatus g n status
  Group.GroupMessage g n ty msg msgId       -> GroupMessage g n ty msg msgId
  Group.GroupPrivateMessage g n ty msg msgId -> GroupPrivateMessage g n ty msg msgId
  Group.GroupTopic g n topic                -> GroupTopic g n topic
  Group.GroupModeration g setter target m   -> GroupModeration g setter target m
  Group.GroupPrivacy g private              -> GroupPrivacy g private
  Group.GroupPeerLimit g n                  -> GroupPeerLimit g n
  Group.GroupPassword g pw                  -> GroupPassword g pw
  Group.GroupTopicLock g locked             -> GroupTopicLock g locked
  Group.GroupVoiceState g v                 -> GroupVoiceState g v
  Group.GroupCustomPacket g n bytes         -> GroupCustomPacket g n bytes
  Group.GroupCustomPrivatePacket g n bytes  -> GroupCustomPrivatePacket g n bytes

conferenceEvent :: Conference.ConferenceEvent -> Event
conferenceEvent = \case
  Conference.ConferenceInvited pk ty cookie -> ConferenceInvite pk ty cookie
  Conference.ConferenceConnected g          -> ConferenceConnected g
  Conference.ConferenceMessage g n ty msg   -> ConferenceMessage g n ty msg
  Conference.ConferenceTitle g n title      -> ConferenceTitle g n title
  Conference.ConferencePeerName g n name    -> ConferencePeerName g n name
  Conference.ConferencePeerListChanged g    -> ConferencePeerListChanged g

toEvent :: Messenger.MessengerEvent -> App [Event]
toEvent = \case
  Messenger.FriendConnectionStatus pk online -> do
    link <- if online then Connection.friendLink pk else return Nothing
    modify $ \gs -> gs { friendLinks = Map.alter (const $ NodeInfo.protocol <$> link) pk (friendLinks gs) }
    touchLastSeen pk
    return [FriendConnectionChanged pk (maybe NotConnected linkStatus link)]
  Messenger.FriendMessage pk ty msg          -> return [FriendMessage pk ty msg]
  Messenger.FriendNameChanged pk name        -> return [FriendName pk name]
  Messenger.FriendStatusMessageChanged pk m  -> return [FriendStatusMessage pk m]
  Messenger.FriendUserStatusChanged pk s     -> return [FriendStatus pk s]
  Messenger.FriendTypingChanged pk t         -> return [FriendTyping pk t]
  Messenger.FriendRequestReceived pk msg     -> return [FriendRequest pk msg]
  Messenger.FriendReadReceipt pk msgId       -> return [FriendReadReceipt pk msgId]
  Messenger.FileReceived pk n kind size fileId name -> return [FileReceive pk n kind size fileId name]
  Messenger.FileChunkReceived pk n pos bytes -> return [FileReceiveChunk pk n pos bytes]
  Messenger.FileChunkRequested pk n pos len  -> return [FileChunkRequest pk n pos len]
  Messenger.FileControlReceived pk ref c     -> return [FileControlChanged pk ref c]


{-------------------------------------------------------------------------------
 -
 - :: For the API.
 -
 ------------------------------------------------------------------------------}

restore :: Maybe Profile -> App ()
restore Nothing = return ()
restore (Just p) = do
  forM_ (profileFriends p) $ \f -> do
    case sfRequest f of
      Nothing                -> Messenger.addFriend (sfPublicKey f)
      Just (nospam, message) -> void $ Messenger.addFriendWithRequest (sfPublicKey f) nospam message
    Messenger.modifyFriend (sfPublicKey f) $ \friend -> friend
      { Messenger.friendName = sfName f
      , Messenger.friendMsg = sfStatusMessage f
      , Messenger.friendStatus = sfStatus f
      , Messenger.friendLastSeen = sfLastSeen f
      }
  mapM_ bootstrapNode (profileDhtNodes p)
  Onion.addBootstrapNodes (profilePathNodes p)
  mapM_ Tcp.addRelay (profileTcpRelays p)
  Conference.restore (profileConferences p)
  Group.restore (profileGroups p)

bootstrapNode :: NodeInfo -> App ()
bootstrapNode node = do
  DHTNode.handleBootstrap node
  Onion.addBootstrapNodes [node]

getFriendConnection :: PublicKey -> App ConnectionStatus
getFriendConnection pk = maybe NotConnected linkStatus <$> Connection.friendLink pk

linkStatus :: NodeInfo -> ConnectionStatus
linkStatus link = if NodeInfo.protocol link == TCP then ConnectedTcp else ConnectedUdp

-- | As in toxcore, UDP only counts with DHT nodes outside the LAN.
getSelfConnection :: App ConnectionStatus
getSelfConnection = do
  connected <- gets (Onion.isConnected . onionState)
  udp <- gets $ \gs -> udpEnabled gs && not (all (SocketAddress.isLan . NodeInfo.address)
    (KBuckets.getAllNodes . DhtState.dhtCloseList $ dhtState gs))
  return $ if not connected then NotConnected else if udp then ConnectedUdp else ConnectedTcp

-- | The friend is online, or was until just now.
touchLastSeen :: PublicKey -> App ()
touchLastSeen pk = do
  now <- gets stepUnixTime
  Messenger.modifyFriend pk $ \f -> f { Messenger.friendLastSeen = now }

unixClock :: App (Timestamp -> Word64)
unixClock = do
  unixNow <- gets stepUnixTime
  now <- askTime
  return $ \t -> unixNow - fromIntegral (Time.toMilliseconds (Time.diffTime now t) `div` 1000)

concatMapM :: Monad m => (a -> m [b]) -> [a] -> m [b]
concatMapM f = fmap concat . mapM f
