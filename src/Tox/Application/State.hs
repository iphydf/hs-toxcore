{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StrictData                 #-}
module Tox.Application.State where

import           Control.Monad                      (forM_, when, (<$!>))
import           Control.Monad.Reader               (ReaderT, ask, asks,
                                                     runReaderT)
import           Control.Monad.State.Strict         (MonadState (..), State,
                                                     modify, runState)
import           Control.Monad.Trans                (lift)
import qualified Data.Binary                        as Binary
import qualified Data.Binary.Put                    as Put
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.List                          (partition)
import           Data.List.NonEmpty                 (nonEmpty)
import           Data.Map                           (Map)
import qualified Data.Map.Strict                    as Map
import           Data.Maybe                         (fromMaybe, mapMaybe)
import           Data.Set                           (Set)
import qualified Data.Set                           as Set
import           Data.Text                          (Text, pack)
import           Data.Word                          (Word64)

import qualified Tox.Chat.Conference                as Conference
import qualified Tox.Chat.GroupChat                 as Group
import           Tox.Core.Log                       (LogLevel, MonadLog (..),
                                                     logDebug)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (Timestamp)
import           Tox.Core.Timed                     (Timed (..))
import           Tox.Crypto.Core.Box                (PlainText (..))
import           Tox.Crypto.Core.Generator          (Generator, newGenerator,
                                                     takeBytes)
import           Tox.Crypto.Core.Key                (PublicKey)
import           Tox.Crypto.Core.Keyed              (KeyRing, Keyed (..),
                                                     combinedKey, emptyKeyRing)
import           Tox.Crypto.Core.KeyPair            (KeyPair)
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes (..),
                                                     randomKey, randomWord32)
import qualified Tox.DHT.DhtPacket                  as DhtPacket
import qualified Tox.DHT.DhtState                   as DhtState
import           Tox.DHT.DhtState                   (DhtState)
import qualified Tox.DHT.Nat                        as Nat
import           Tox.DHT.Operation                  (DhtNodeMonad (..))
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.Networked         (Networked (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Network.TCP.Server             as Server
import qualified Tox.Onion.Operation                as Onion
import           Tox.Onion.Operation                (OnionState)
import qualified Tox.Session.Connection             as Connection
import           Tox.Session.Connection             (ConnectionManager)
import qualified Tox.Session.Friend                 as Messenger
import           Tox.Session.Friend                 (Messenger)

data GlobalState = GlobalState
  { dhtState     :: DhtState
  , onionState   :: OnionState
  , connManager  :: ConnectionManager
  , messenger    :: Messenger
  , udpEnabled   :: Bool
  , udpIpv6      :: Bool
  , tcpState     :: Tcp.TcpState
  , tcpServer    :: Server.TcpServer
  , conferences  :: Conference.Conferences
  , groupChats   :: Group.Groups
  , groupTcp     :: Map BS.ByteString GroupTcp -- ^ By chat ID.
  , groupTcpLeft :: [(Timestamp, BS.ByteString, [PublicKey])]
    -- ^ Relays of groups we left, by when to close them and chat ID. A
    -- toxcore relay drops what comes with a closing connection unread (like
    -- our parting message).
  , friendLinks  :: Map PublicKey TransportProtocol -- ^ Last connection type we reported for each online friend.
  , stepTime     :: Timestamp -- ^ Read once per input, so a step sees one time.
  , stepUnixTime :: Word64    -- ^ Wall clock seconds, read with 'stepTime'.
  , clientBehind :: Bool
    -- ^ The client hasn't taken many of our events yet, so data peers send
    -- again can wait. Read with 'stepTime'.
  , counted      :: Map Traffic.Counted Traffic.Count
    -- ^ What only the core sees (packets inside relay connections, and what
    -- onion requests are for).
  , outbox       :: [Output] -- ^ What the step wants done, newest first, for 'takeOutbox'.
  , busyRelays   :: Set (RelayOwner, PublicKey)
    -- ^ Relay connections and clients of our relay holding more than the
    -- system has taken, as the shell tells us. Only what can't wait goes to
    -- them.
  , busyClients  :: Set Server.ClientId
  , relaySockets :: Map (RelayOwner, PublicKey) Int
    -- ^ The number of each relay connection's current socket, so input from
    -- an older one is ignored.
  , nextSocket   :: Int
  , generator    :: Generator -- ^ All our randomness after the start.
  , keyRing      :: KeyRing
  }

data Output
  = SendUdp SocketAddress BS.ByteString
  | RelayConnect RelayOwner NodeInfo Int -- ^ With the socket's number.
  | RelaySend RelayOwner PublicKey Int BS.ByteString -- ^ On that socket.
  | RelayClose RelayOwner PublicKey
  | ClientSend Server.ClientId BS.ByteString
  | ClientClose Server.ClientId
  | Log LogLevel ~Text -- ^ Made only if the client's logger reads it.
  | Reply (IO ()) -- ^ An API call's result, once what it asked for is done.

-- | Made with the group's own keys.
data GroupTcp = GroupTcp
  { gtKeys  :: KeyPair
  , gtState :: Tcp.TcpState
  }

-- | Ours, or a group's by chat ID.
type RelayOwner = Maybe BS.ByteString

initState :: MonadRandomBytes m => Timestamp -> KeyPair -> KeyPair -> m GlobalState
initState now dhtKeys realKeys = do
  random <- randomBytes 32
  cKey <- randomKey
  nospam <- randomWord32
  onion <- Onion.initState realKeys
  return GlobalState
    { dhtState    = DhtState.empty now dhtKeys
    , onionState  = onion
    , connManager = Connection.initManager realKeys dhtKeys cKey
    , messenger   = Messenger.initMessenger nospam
    , udpEnabled  = True
    , udpIpv6     = False
    , tcpState    = Tcp.emptyTcpState
    , tcpServer   = Server.newTcpServer dhtKeys
    , conferences = Conference.emptyConferences
    , groupChats  = Group.emptyGroups
    , groupTcp    = Map.empty
    , groupTcpLeft = []
    , friendLinks = Map.empty
    , stepTime    = now
    , stepUnixTime = 0
    , clientBehind = False
    , counted     = Map.empty
    , outbox      = []
    , busyRelays  = Set.empty
    , busyClients = Set.empty
    , relaySockets = Map.empty
    , nextSocket  = 0
    , generator   = fromMaybe (error "32 bytes make a key") (newGenerator random)
    , keyRing     = emptyKeyRing
    }

-- | What a step does. It reads and writes only the state, so the same state
-- and input always do the same.
newtype App a = App (State GlobalState a)
    deriving (Functor, Applicative, Monad)

runApp :: App a -> GlobalState -> (a, GlobalState)
runApp (App m) = runState m

-- | We evaluate each new state, so a step doesn't pile up thunks of the
-- ones before.
instance MonadState GlobalState App where
    state f = App . state $ \s -> case f s of (a, s') -> s' `seq` (a, s')

instance MonadRandomBytes App where
    randomBytes n = state $ \gs -> (\g -> gs { generator = g }) <$> takeBytes n (generator gs)

-- | What the shell reads once for each wake-up, for every step it runs then.
data Context = Context
  { ctxTime     :: Timestamp
  , ctxUnixTime :: Word64
  , ctxBehind   :: Bool
  }

setContext :: Context -> App ()
setContext (Context now unixNow behind) = modify $ \gs ->
    gs { stepTime = now, stepUnixTime = unixNow, clientBehind = behind }

-- | Like mtl's, but evaluated, so the result doesn't keep the whole state
-- alive.
gets :: MonadState s m => (s -> a) -> m a
gets f = f <$!> get

instance Timed App where
    askTime = gets stepTime

instance MonadLog App where
    logAt level = output . Log level

instance Keyed App where
    getCombinedKey sk pk = state $ \gs -> (\ring -> gs { keyRing = ring }) <$> combinedKey sk pk (keyRing gs)

instance DhtNodeMonad App where
    getDhtState = gets dhtState
    putDhtState s = modify $ \gs -> gs { dhtState = s }
    nodeAnswered = Connection.dhtNodeFound
    handleDhtRequestPayload _ pkt = do
        keys <- gets (DhtState.dhtKeyPair . dhtState)
        plain <- DhtPacket.decryptKeyed keys pkt
        case BS.uncons . unPlainText <$> plain of
            Just (Just (ident, rest)) | ident == Nat.packetIdNatPing ->
              Nat.handleNatPing (DhtPacket.senderPublicKey pkt) rest
            _ -> return ()

instance Onion.OnionNodeMonad App where
    getOnionState = gets onionState
    putOnionState s = modify $ \gs -> gs { onionState = s }
    getDhtKeyPair = gets (DhtState.dhtKeyPair . dhtState)
    getCloseNodes n key = gets (DhtState.takeClosestNodesTo n key . dhtState)
    getCloseNodesFor from n key = gets (DhtState.takeClosestNodesFor from n key . dhtState)
    getTcpRelays = Tcp.connectedRelays
    sendOnionViaRelay = Tcp.sendOnionRequest
    sendToTcpClient = Server.sendOnionResponse
    sendDhtRequest to plain = Nat.dhtRequest to plain >>= Nat.routeToFriend to
    countRequest purpose = countTraffic (Traffic.Requests purpose)
    friendHeld = Messenger.friendReachable

output :: Output -> App ()
output o = modify $ \gs -> gs { outbox = o : outbox gs }

-- | In the order the step asked.
takeOutbox :: App [Output]
takeOutbox = state $ \gs -> (reverse (outbox gs), gs { outbox = [] })

-- | Replaces any socket we had.
relayConnect :: RelayOwner -> NodeInfo -> App ()
relayConnect owner relay = do
    relayGone owner (publicKey relay)
    socket <- gets nextSocket
    modify $ \gs -> gs { nextSocket = socket + 1
                       , relaySockets = Map.insert (owner, publicKey relay) socket (relaySockets gs) }
    output (RelayConnect owner relay socket)

-- | On the connection's current socket, if it has one.
relaySend :: RelayOwner -> PublicKey -> BS.ByteString -> App ()
relaySend owner pk bytes = gets (Map.lookup (owner, pk) . relaySockets) >>= mapM_ (\socket ->
    output (RelaySend owner pk socket bytes))

relayClose :: RelayOwner -> PublicKey -> App ()
relayClose owner pk = relayGone owner pk >> output (RelayClose owner pk)

-- | Its socket closed, or is about to.
relayGone :: RelayOwner -> PublicKey -> App ()
relayGone owner pk = do
    modify $ \gs -> gs { relaySockets = Map.delete (owner, pk) (relaySockets gs) }
    relayWritable owner pk

currentSocket :: RelayOwner -> PublicKey -> Int -> App Bool
currentSocket owner pk socket = gets $ (== Just socket) . Map.lookup (owner, pk) . relaySockets

-- | The shell says it holds too many of our bytes to take data that can wait.
relayBusy :: RelayOwner -> PublicKey -> App ()
relayBusy owner pk = modify $ \gs -> gs { busyRelays = Set.insert (owner, pk) (busyRelays gs) }

-- | The shell says it has room again, or the connection's gone.
relayWritable :: RelayOwner -> PublicKey -> App ()
relayWritable owner pk = modify $ \gs -> gs { busyRelays = Set.delete (owner, pk) (busyRelays gs) }

clientBusy, clientWritable :: Server.ClientId -> App ()
clientBusy client = modify $ \gs -> gs { busyClients = Set.insert client (busyClients gs) }
clientWritable client = modify $ \gs -> gs { busyClients = Set.delete client (busyClients gs) }

instance Tcp.TcpNetworked App where
    tcpConnect = relayConnect Nothing
    tcpSend = relaySend Nothing
    tcpClose = relayClose Nothing
    tcpBusy pk = gets (Set.member (Nothing, pk) . busyRelays)

instance Tcp.TcpMonad App where
    getTcpState = gets tcpState
    putTcpState s = modify $ \gs -> gs { tcpState = s }
    getTcpDhtKeys = gets (DhtState.dhtKeyPair . dhtState)

instance Server.TcpServerMonad App where
    getTcpServer = gets tcpServer
    putTcpServer s = modify $ \gs -> gs { tcpServer = s }
    serverSend client bytes = output (ClientSend client bytes)
    serverClose client = clientWritable client >> output (ClientClose client)
    serverBusy client = gets (Set.member client . busyClients)

instance Connection.ConnectionMonad App where
    getConnManager = gets connManager
    putConnManager s = modify $ \gs -> gs { connManager = s }

instance Messenger.MessengerMonad App where
    getMessenger = gets messenger
    putMessenger s = modify $ \gs -> gs { messenger = s }

instance Conference.ConferenceMonad App where
    getConferences = gets conferences
    putConferences s = modify $ \gs -> gs { conferences = s }

instance Group.GroupMonad App where
    getGroups = gets groupChats
    putGroups s = modify $ \gs -> gs { groupChats = s }
    withGroupTcp = runGroupTcp
    groupUdp = gets udpEnabled
    dropGroupTcp chatId = do
        relays <- gets (maybe [] (Map.keys . Tcp.tsRelays . gtState) . Map.lookup chatId . groupTcp)
        closing <- (`Time.addTime` leftGroupTcpDelay) <$> askTime
        modify $ \gs -> gs { groupTcp = Map.delete chatId (groupTcp gs)
                           , groupTcpLeft = (closing, chatId, relays) : groupTcpLeft gs }

leftGroupTcpDue :: GlobalState -> Maybe Timestamp
leftGroupTcpDue = fmap minimum . nonEmpty . map (\(closing, _, _) -> closing) . groupTcpLeft

-- | Except relays that a group we rejoined still uses.
closeLeftGroupTcp :: App ()
closeLeftGroupTcp = do
    now <- askTime
    (due, waiting) <- gets (partition (\(closing, _, _) -> closing <= now) . groupTcpLeft)
    forM_ due $ \(_, chatId, relays) -> do
        used <- gets (maybe [] (Map.keys . Tcp.tsRelays . gtState) . Map.lookup chatId . groupTcp)
        mapM_ (relayClose (Just chatId)) (filter (`notElem` used) relays)
    modify $ \gs -> gs { groupTcpLeft = waiting }

-- | Long enough for a relay to read what we sent before we closed.
leftGroupTcpDelay :: Time.TimeDiff
leftGroupTcpDelay = Time.seconds 2

groupTcpDue :: GlobalState -> Maybe Timestamp
groupTcpDue = fmap minimum . nonEmpty . mapMaybe (Tcp.nextDue . gtState) . Map.elems . groupTcp

runGroupTcpDue :: App ()
runGroupTcpDue = do
    now <- askTime
    due <- gets (Map.toList . Map.filter (maybe False (<= now) . Tcp.nextDue . gtState) . groupTcp)
    forM_ due $ \(chatId, gt) -> runGroupTcp chatId (gtKeys gt) Tcp.runDue

-- | TCP layer on one group's connections.
newtype GroupTcpM a = GroupTcpM { unGroupTcpM :: ReaderT (BS.ByteString, KeyPair) App a }
    deriving (Functor, Applicative, Monad, MonadLog, MonadRandomBytes)

runGroupTcp :: BS.ByteString -> KeyPair -> GroupTcpM a -> App a
runGroupTcp chatId keys act = runReaderT (unGroupTcpM act) (chatId, keys)

instance Timed GroupTcpM where
    askTime = GroupTcpM (lift askTime)

instance Tcp.TcpNetworked GroupTcpM where
    tcpConnect relay = inGroup $ \chatId -> relayConnect (Just chatId) relay
    tcpSend pk bytes = inGroup $ \chatId -> relaySend (Just chatId) pk bytes
    tcpClose pk = inGroup $ \chatId -> relayClose (Just chatId) pk

inGroup :: (BS.ByteString -> App a) -> GroupTcpM a
inGroup f = GroupTcpM $ asks fst >>= lift . f

instance Tcp.TcpMonad GroupTcpM where
    getTcpState = GroupTcpM $ do
        (chatId, _) <- ask
        lift $ gets (maybe Tcp.emptyTcpState gtState . Map.lookup chatId . groupTcp)
    putTcpState st = GroupTcpM $ do
        (chatId, keys) <- ask
        lift . modify $ \gs -> gs { groupTcp = Map.insert chatId (GroupTcp keys st) (groupTcp gs) }
    getTcpDhtKeys = GroupTcpM $ asks snd

instance Networked App where
    linkBusy ni = if protocol ni == TCP then Tcp.peerBusy ni else return False
    sendPacket ni packet = do
        ipv6 <- gets udpIpv6
        udp <- gets ((&& (ipv6 || not (isIpv6 $ address ni))) . udpEnabled)
        let bs = LBS.toStrict $ Put.runPut $ do
                Binary.put (packetKind packet)
                Binary.put (packetPayload packet)
        logDebug $ "Sending packet to " <> pack (show $ address ni) <> ": " <> pack (show $ packetKind packet)
          <> " (" <> pack (show $ BS.length bs) <> " bytes)"
        if protocol ni == TCP
            then Tcp.sendToPeer ni bs >>= (`when` forM_ (BS.uncons bs) (\(kind, _) ->
                countTraffic (Traffic.Packets Traffic.Sent Traffic.Relay kind) (BS.length bs)))
            else when udp $ output (SendUdp (address ni) bs)

-- | Counted in the core, not by the shell.
countTraffic :: Traffic.Counted -> Int -> App ()
countTraffic what bytes = modify $ \gs ->
    gs { counted = Map.insertWith Traffic.addCount what (Traffic.Count 1 (fromIntegral bytes)) (counted gs) }

isIpv6 :: SocketAddress -> Bool
isIpv6 (SocketAddress (IPv6 _) _) = True
isIpv6 _                          = False
