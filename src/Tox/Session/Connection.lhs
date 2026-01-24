\chapter{Friend connection}

\texttt{friend\_connection} is the module that sits on top of the DHT, onion and
\texttt{net\_crypto} modules and takes care of linking the 3 together.

Friends in \texttt{friend\_connection} are represented by their real public key.
When a friend is added in \texttt{friend\_connection}, an onion search entry is
created for that friend.  This means that the onion module will start looking
for this friend and send that friend their DHT public key, and the TCP relays
it is connected to, in case a connection is only possible with TCP.

\begin{code}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
module Tox.Session.Connection where

import           Control.Applicative                ((<|>))
import           Control.Monad                      (forM_, guard, join, unless,
                                                     void, when, (<$!>), (<=<))
import           Control.Monad.State                (StateT, runStateT)
import qualified Data.Binary                        as Binary
import qualified Data.Binary.Get                    as Get
import qualified Data.Binary.Put                    as Put
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.Foldable                      (find)
import           Data.List                          (partition)
import           Data.List.NonEmpty                 (nonEmpty)
import           Data.Map                           (Map)
import qualified Data.Map                           as Map
import           Data.Maybe                         (catMaybes, fromMaybe,
                                                     isJust, isNothing,
                                                     mapMaybe, maybeToList)
import           Data.Set                           (Set)
import qualified Data.Set                           as Set
import           Data.Text                          (Text, pack)
import           Data.Word                          (Word32, Word8)

import           Tox.Core.Log                       (MonadLog, logInfo)
import qualified Tox.Core.Schedule                  as Schedule
import           Tox.Core.Schedule                  (Schedule)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import qualified Tox.Core.Timed                     as Timed
import           Tox.Core.Timed                     (Timed)
import           Tox.Crypto.Core.Key                (CombinedKey, PublicKey)
import           Tox.Crypto.Core.Keyed              (Keyed)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.KeyPair            (KeyPair)
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes)
import qualified Tox.DHT.DhtState                   as DhtState
import qualified Tox.DHT.Operation                  as DHT
import qualified Tox.Network.Core.HostAddress       as HostAddress
import           Tox.Network.Core.Networked         (Networked)
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo)
import           Tox.Network.Core.Packet            (Packet (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Onion.Operation                as Onion
import qualified Tox.Transport.SecureSession        as SecureSession
import           Tox.Transport.SecureSession        (SecureSessionState,
                                                     SessionEvent (..))

{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

packetIdAlive, packetIdShareRelays, packetIdFriendRequests :: Word8
packetIdAlive          = 16
packetIdShareRelays    = 17
packetIdFriendRequests = 18

packetIds :: [Word8]
packetIds = [packetIdAlive, packetIdShareRelays, packetIdFriendRequests]

friendPingInterval :: TimeDiff
friendPingInterval = Time.seconds 8

friendConnectionTimeout :: TimeDiff
friendConnectionTimeout = Time.seconds 32

shareRelaysInterval :: TimeDiff
shareRelaysInterval = Time.seconds 120

-- | After a session fails we connect again this long after, then twice as
-- long each time up to the last, and then wait for news of the friend.
firstConnectWait, lastConnectWait :: TimeDiff
firstConnectWait = Time.seconds 8
lastConnectWait  = Time.seconds 64


maxSharedRelays, maxStoredRelays :: Int
maxSharedRelays = 3
maxStoredRelays = 24

data FriendConnection = FriendConnection
  { fcRealPk         :: PublicKey
  , fcDhtPk          :: Maybe PublicKey
  , fcIpPort         :: Maybe NodeInfo -- ^ Direct UDP address of the friend's DHT node.
  , fcRelays         :: [NodeInfo]     -- ^ TCP relays the friend said it's on.
  , fcSession        :: Maybe SecureSessionState
  , fcOnline         :: Bool
  , fcPingLastSent   :: Maybe Timestamp
  , fcPingLastRecv   :: Maybe Timestamp
  , fcRelaysLastSent :: Maybe Timestamp
  , fcConnectWait    :: Maybe TimeDiff
    -- ^ Before connecting again when a session fails, or Nothing to wait for
    -- news of the friend.
  , fcResume         :: Bool
    -- ^ Its session timed out since our own connection was last back, so it
    -- may have been us who went.
  } deriving (Eq, Show)

data ConnectionManager = ConnectionManager
  { friends     :: Map PublicKey FriendConnection
  , routes      :: Map Route (Set PublicKey)
    -- ^ Friends with a session, by where their packets may come from, so a
    -- packet doesn't go through every friend to find it. Kept by 'setFriend'.
  , byDhtKey    :: Map PublicKey PublicKey -- ^ Friends by DHT key. Kept by 'setFriend'.
  , connJobs    :: Schedule ConnectionJob
  , ourRealKeys :: KeyPair
  , ourDhtKeys  :: KeyPair
  , cookieKey   :: CombinedKey
  }

data ConnectionEvent
  = FriendOnline PublicKey
  | FriendOffline PublicKey
  | FriendData PublicKey ByteString
  | FriendLossyData PublicKey ByteString
  | FriendRequest PublicKey ByteString -- ^ Sender, then nospam and message.
  | FriendMoved PublicKey -- ^ Its session, between UDP and a relay.
  | FriendRoom PublicKey -- ^ It acknowledged packets, or our send budget for it grew.
  deriving (Eq, Show)


class ( Monad m, Timed m, MonadRandomBytes m, Keyed m, Networked m, MonadLog m
      , Tcp.TcpMonad m, Onion.OnionNodeMonad m, DHT.DhtNodeMonad m )
      => ConnectionMonad m where
  getConnManager :: m ConnectionManager
  putConnManager :: ConnectionManager -> m ()

getsConn :: ConnectionMonad m => (ConnectionManager -> a) -> m a
getsConn f = f <$!> getConnManager

modifyConn :: ConnectionMonad m => (ConnectionManager -> ConnectionManager) -> m ()
modifyConn f = getConnManager >>= putConnManager . f

modifyFriend :: ConnectionMonad m => PublicKey -> (FriendConnection -> FriendConnection) -> m ()
modifyFriend pk f = do
  now <- Timed.askTime
  modifyConn $ \s -> maybe s (\fc -> setFriend now pk (Just (f fc)) s) (Map.lookup pk (friends s))

-- | A session's packets come from an address, or through relays with the
-- friend's DHT key.
data Route = FromAddress SocketAddress | FromRelay PublicKey
  deriving (Eq, Ord, Show)

routeOf :: NodeInfo -> Route
routeOf node
  | NodeInfo.protocol node == UDP = FromAddress (NodeInfo.address node)
  | otherwise = FromRelay (NodeInfo.publicKey node)

-- | Every way 'sessionFrom' takes a packet as the friend's.
routesOf :: FriendConnection -> [Route]
routesOf f = case fcSession f of
  Nothing -> []
  Just ss -> routeOf (SecureSession.ssPeerNodeInfo ss)
    : map (FromAddress . NodeInfo.address) (maybeToList (fcIpPort f)) ++ map FromRelay (maybeToList (fcDhtPk f))

-- | The only way to change 'friends', so 'routes', 'byDhtKey' and the
-- friend's upkeep stay in step.
setFriend :: Timestamp -> PublicKey -> Maybe FriendConnection -> ConnectionManager -> ConnectionManager
setFriend time pk new s = s
  { friends = Map.alter (const new) pk (friends s)
  , routes = if old == now then routes s else foldr held (foldr gone (routes s) old) now
  , byDhtKey = if oldDhtPk == newDhtPk then byDhtKey s
      else maybe id (`Map.insert` pk) newDhtPk . maybe id Map.delete oldDhtPk $ byDhtKey s
  , connJobs = maybe (Schedule.cancel (Upkeep pk)) (`Schedule.at` Upkeep pk) (upkeepDue time =<< new)
      . (if maybe True (isJust . fcSession) new then Schedule.cancel (Connect pk) else id) $ connJobs s
  }
  where
    oldDhtPk = fcDhtPk =<< Map.lookup pk (friends s)
    newDhtPk = fcDhtPk =<< new
    old = maybe [] routesOf (Map.lookup pk (friends s))
    now = maybe [] routesOf new
    gone = Map.update (\pks -> let pks' = Set.delete pk pks in if Set.null pks' then Nothing else Just pks')
    held route = Map.insertWith Set.union route (Set.singleton pk)


initManager :: KeyPair -> KeyPair -> CombinedKey -> ConnectionManager
initManager realKeys dhtKeys cKey = ConnectionManager
  { friends = Map.empty
  , routes = Map.empty
  , byDhtKey = Map.empty
  , connJobs = Schedule.empty
  , ourRealKeys = realKeys
  , ourDhtKeys = dhtKeys
  , cookieKey = cKey
  }


addFriend :: ConnectionMonad m => PublicKey -> m ()
addFriend realPk = do
  logInfo $ "Adding friend: " <> pack (show realPk)
  now <- Timed.askTime
  modifyConn $ \s ->
    let newFriend = FriendConnection
          { fcRealPk         = realPk
          , fcDhtPk          = Nothing
          , fcIpPort         = Nothing
          , fcRelays         = []
          , fcSession        = Nothing
          , fcOnline         = False
          , fcPingLastSent   = Nothing
          , fcPingLastRecv   = Nothing
          , fcRelaysLastSent = Nothing
          , fcConnectWait    = Just firstConnectWait
          , fcResume         = False
          }
    in if Map.member realPk (friends s) then s else setFriend now realPk (Just newFriend) s
  Onion.startFriendSearch realPk
\end{code}

Once the onion returns the DHT public key of the peer, the DHT public key is
saved, added to the DHT friends list and a new \texttt{net\_crypto} connection
is created.  Any TCP relays returned by the onion for this friend are passed to
the \texttt{net\_crypto} connection.

If the DHT establishes a direct UDP connection with the friend,
\texttt{friend\_connection} will pass the IP/port of the friend to
\texttt{net\_crypto} and also save it to be used to reconnect to the friend if
they disconnect.

If \texttt{net\_crypto} finds that the friend has a different DHT public key,
which can happen if the friend restarted their client, \texttt{net\_crypto} will
pass the new DHT public key to the onion module and will remove the DHT entry
for the old DHT public key and replace it with the new one.  The current
\texttt{net\_crypto} connection will also be killed and a new one with the
correct DHT public key will be created.

When the \texttt{net\_crypto} connection for a friend goes online,
\texttt{friend\_connection} will tell the onion module that the friend is online
so that it can stop spending resources looking for the friend.  When the friend
connection goes offline, \texttt{friend\_connection} will tell the onion module
so that it can start looking for the friend again.

There are 2 types of data packets sent to friends with the \texttt{net\_crypto}
connection handled at the level of \texttt{friend\_connection}, Alive packets
and TCP relay packets.  Alive packets are packets with the packet id or first
byte of data (only byte in this packet) being 16.  They are used in order to
check if the other friend is still online.  \texttt{net\_crypto} does not have
any timeout when the connection is established so timeouts are caught using
this packet.  In toxcore, this packet is sent every 8 seconds.  If none of
these packets are received for 32 seconds, the connection is timed out and
killed.  These numbers seem to cause the least issues and 32 seconds is not too
long so that, if a friend times out, toxcore won't falsely see them online for
too long.  Usually when a friend goes offline they have time to send a
disconnect packet in the \texttt{net\_crypto} connection which makes them appear
offline almost instantly.

\begin{code}
-- | Found by the onion, in a handshake, or another way. A different key means
-- the friend restarted, so drop the old session.
setFriendDhtPk :: ConnectionMonad m => PublicKey -> PublicKey -> m [ConnectionEvent]
setFriendDhtPk realPk dhtPk = do
  mFriend <- getsConn (Map.lookup realPk . friends)
  case mFriend of
    Just f | fcDhtPk f /= Just dhtPk -> do
      events <- killSession NewDhtKey realPk
      mapM_ Tcp.removePeer (fcDhtPk f)
      -- We search for friends' current DHT keys, and only those: else one
      -- whose session came through a relay never finds its address.
      now <- Timed.askTime
      mapM_ (DHT.modifyDht . DhtState.removeSearchKey) (fcDhtPk f)
      DHT.modifyDht $ DhtState.addSearchKey now dhtPk
      modifyFriend realPk $ \f' -> f' { fcDhtPk = Just dhtPk, fcIpPort = Nothing, fcRelays = [] }
      news "its DHT key" realPk
      return events
    _ -> return []

setFriendIpPort :: ConnectionMonad m => PublicKey -> NodeInfo -> m ()
setFriendIpPort realPk node = do
  mFriend <- getsConn (Map.lookup realPk . friends)
  forM_ mFriend $ \f -> when (fcDhtPk f == Just (NodeInfo.publicKey node) && fcIpPort f /= Just node) $ do
    modifyFriend realPk $ \f' -> f' { fcIpPort = Just node }
    news "its address" realPk

-- | The friend's node answered us in the DHT.
dhtNodeFound :: ConnectionMonad m => NodeInfo -> m ()
dhtNodeFound node = getsConn (Map.lookup (NodeInfo.publicKey node) . byDhtKey) >>= mapM_ (`setFriendIpPort` node)

-- | Our own connection is back. Friends whose sessions timed out meanwhile are
-- likely still where they were, if it was us who went.
weAreBack :: ConnectionMonad m => m ()
weAreBack = do
  resumed <- getsConn (Map.keys . Map.filter fcResume . friends)
  forM_ resumed $ \pk -> do
    modifyFriend pk $ \f -> f { fcResume = False }
    news "we're back" pk

-- | Something new about where the friend is, so we connect at once, and again
-- for a while if that fails.
news :: ConnectionMonad m => Text -> PublicKey -> m ()
news what pk = do
  logInfo $ "News of " <> pack (show pk) <> ": " <> what
  now <- Timed.askTime
  modifyConn $ \s -> case Map.lookup pk (friends s) of
    Nothing -> s
    Just f -> (setFriend now pk (Just f { fcConnectWait = Just firstConnectWait }) s)
      { connJobs = if isJust (fcSession f) then connJobs s else Schedule.at now (Connect pk) (connJobs s) }

sendFriendRequestPacket :: ConnectionMonad m => PublicKey -> ByteString -> m Bool
sendFriendRequestPacket pk request = do
  online <- getsConn (maybe False fcOnline . Map.lookup pk . friends)
  if online
  then sendFriendData pk (BS.cons packetIdFriendRequests request)
  else (> 0) <$> Onion.sendToFriend Traffic.SendFriendRequest pk (BS.cons Onion.packetIdFriendRequest request)

sendFriendData :: ConnectionMonad m => PublicKey -> ByteString -> m Bool
sendFriendData pk bytes = isJust <$> sendFriendDataNumbered pk bytes

sendFriendDataNumbered :: ConnectionMonad m => PublicKey -> ByteString -> m (Maybe Word32)
sendFriendDataNumbered pk bytes = join <$> withSession pk (SecureSession.sendLossless bytes)

sendFriendLossy :: ConnectionMonad m => PublicKey -> ByteString -> m Bool
sendFriendLossy pk bytes = or <$> withSession pk (SecureSession.sendLossy bytes)

sendFriendDataCongested :: ConnectionMonad m => PublicKey -> ByteString -> m (Maybe Word32)
sendFriendDataCongested pk bytes = join <$> withSession pk (SecureSession.sendCongested bytes)

-- | Congestion controlled packets we may send the friend now.
freeSendSlots :: ConnectionMonad m => PublicKey -> m Int
freeSendSlots pk = getsConn $ \s -> maybe 0 SecureSession.freeSendSlots (Map.lookup pk (friends s) >>= fcSession)

isDelivered :: ConnectionMonad m => PublicKey -> Word32 -> m Bool
isDelivered pk num = getsConn $ \s ->
  maybe False (SecureSession.isDelivered num) (Map.lookup pk (friends s) >>= fcSession)

-- | 'SecureSession.packetsHeld' of the friend whose session holds most.
busiestHeld :: ConnectionManager -> Int
busiestHeld = maximum . (0 :) . map SecureSession.packetsHeld . mapMaybe fcSession . Map.elems . friends

-- | Lossless packets the friend hasn't confirmed yet.
sendQueueLength :: ConnectionMonad m => PublicKey -> m Int
sendQueueLength pk = getsConn $ \s -> maybe 0 SecureSession.sendQueueLength (Map.lookup pk (friends s) >>= fcSession)

friendLink :: ConnectionMonad m => PublicKey -> m (Maybe NodeInfo)
friendLink pk = getsConn $ \s -> do
  f <- Map.lookup pk (friends s)
  guard $ fcOnline f
  SecureSession.ssPeerNodeInfo <$> fcSession f

removeFriend :: ConnectionMonad m => PublicKey -> m ()
removeFriend pk = do
  mFriend <- getsConn (Map.lookup pk . friends)
  forM_ mFriend $ \f -> do
    _ <- killSession Removed pk
    forM_ (fcDhtPk f) $ \dhtPk -> do
      DHT.modifyDht $ DhtState.removeSearchKey dhtPk
      Tcp.removePeer dhtPk
    Onion.removeFriend pk
    now <- Timed.askTime
    modifyConn $ setFriend now pk Nothing


withSession :: ConnectionMonad m => PublicKey -> StateT SecureSessionState m a -> m (Maybe a)
withSession pk action = do
  mSession <- getsConn (\s -> Map.lookup pk (friends s) >>= fcSession)
  case mSession of
    Nothing -> return Nothing
    Just ss -> do
      (a, ss') <- runStateT action ss
      modifyFriend pk $ \f -> f { fcSession = Just ss' }
      return $ Just a

runSession :: ConnectionMonad m
           => PublicKey -> StateT SecureSessionState m [SessionEvent] -> m [ConnectionEvent]
runSession pk action = withSession pk action >>= fmap concat . mapM (sessionEvent pk) . fromMaybe []

-- | Why a session ended, for the log.
data SessionEnd
  = PeerKilled   -- ^ The friend said so.
  | GaveUp       -- ^ The friend never finished the handshake.
  | TimedOut     -- ^ The friend stopped answering.
  | NewDhtKey    -- ^ The friend restarted.
  | Removed      -- ^ We removed the friend.
  | Stopping     -- ^ We're shutting down.
  deriving (Eq, Show)

killSession :: ConnectionMonad m => SessionEnd -> PublicKey -> m [ConnectionEvent]
killSession why pk = do
  _ <- withSession pk SecureSession.sendKill
  dropSession why pk

-- | A session that fails is tried again later, a few times.
dropSession :: ConnectionMonad m => SessionEnd -> PublicKey -> m [ConnectionEvent]
dropSession why pk = do
  now <- Timed.askTime
  mFriend <- getsConn (Map.lookup pk . friends)
  let wasOnline = maybe False fcOnline mFriend
      wait = fcConnectWait =<< mFriend
  forM_ (fcSession =<< mFriend) $ \_ -> logInfo $ "Session with " <> pack (show pk) <> " ended: " <> pack (show why)
    <> (if wasOnline then ", it was online" else "")
    <> maybe ", waiting for news" (\w -> ", connecting again in " <> pack (show (Time.toMilliseconds w `div` 1000)) <> " s") wait
  modifyFriend pk $ \f -> f
    { fcSession = Nothing
    , fcOnline = False
    , fcConnectWait = (\w -> if w * 2 <= lastConnectWait then Just (w * 2) else Nothing) =<< wait
    , fcResume = fcResume f || why == TimedOut
    }
  modifyConn $ \s -> s { connJobs = maybe (Schedule.cancel (Connect pk)) (\w -> Schedule.at (Time.addTime now w) (Connect pk)) wait $ connJobs s }
  when wasOnline $ Onion.setFriendOnline pk False
  return [FriendOffline pk | wasOnline]

sessionEvent :: ConnectionMonad m => PublicKey -> SessionEvent -> m [ConnectionEvent]
sessionEvent pk event = case event of
  SessionEstablished -> do
    now <- Timed.askTime
    modifyFriend pk $ \f -> f
      { fcOnline = True, fcPingLastRecv = Just now, fcPingLastSent = Nothing, fcRelaysLastSent = Nothing
      , fcConnectWait = Just firstConnectWait, fcResume = False }
    Onion.setFriendOnline pk True
    return [FriendOnline pk]
  SessionKilled -> dropSession PeerKilled pk
  SessionGaveUp -> dropSession GaveUp pk
  SessionDhtPkChanged dhtPk -> setFriendDhtPk pk dhtPk
  SessionMoved -> return [FriendMoved pk]
  SessionRoom -> return [FriendRoom pk]
  SessionLossyData bytes -> return [FriendLossyData pk bytes]
  SessionLosslessData bytes -> case BS.uncons bytes of
    Just (ident, _)
      | ident == packetIdAlive -> do
          now <- Timed.askTime
          modifyFriend pk $ \f -> f { fcPingLastRecv = Just now }
          return []
      | ident == packetIdFriendRequests -> return [FriendRequest pk (BS.drop 1 bytes)]
      | ident == packetIdShareRelays -> do
          mapM_ (addFriendRelay pk) . filter ((== TCP) . NodeInfo.protocol) . take maxSharedRelays
            $ decodeNodes (BS.drop 1 bytes)
          return []
    _ -> return [FriendData pk bytes]


-- | net_crypto packet. We find the session by the link it came from. A
-- handshake from elsewhere may start a session.
handlePacket :: ConnectionMonad m => NodeInfo -> Packet ByteString -> m [ConnectionEvent]
handlePacket from pkt@(Packet kind payload) = do
  cm <- getConnManager
  case (kind, sessionFrom from cm) of
    (PacketKind.CookieRequest, _) -> do
      SecureSession.handleCookieRequest (cookieKey cm) (ourDhtKeys cm) from payload
      return []
    (_, Just f) -> runSession (fcRealPk f) (SecureSession.handlePacket (cookieKey cm) from pkt)
    (PacketKind.CryptoHandshake, Nothing) -> handleNewHandshake from payload
    _ -> return []

-- | Packets also come from the friend's DHT address when it moves off a
-- relay, and through any relay we share, not only the session's.
sessionFrom :: NodeInfo -> ConnectionManager -> Maybe FriendConnection
sessionFrom from cm =
  find fromSession . mapMaybe (`Map.lookup` friends cm) . Set.toAscList
    $ Map.findWithDefault Set.empty (routeOf from) (routes cm)
  where
    fromSession f = case fcSession f of
      Nothing -> False
      Just ss -> sameLink from (SecureSession.ssPeerNodeInfo ss)
        || (NodeInfo.protocol from == UDP && (NodeInfo.address <$> fcIpPort f) == Just (NodeInfo.address from))
        || (NodeInfo.protocol from == TCP && fcDhtPk f == Just (NodeInfo.publicKey from))

sameLink :: NodeInfo -> NodeInfo -> Bool
sameLink a b =
  NodeInfo.protocol a == NodeInfo.protocol b && NodeInfo.address a == NodeInfo.address b
    && (NodeInfo.protocol a == UDP || NodeInfo.publicKey a == NodeInfo.publicKey b)

-- | From a friend, not for a session. As in toxcore, a new DHT key means the
-- friend restarted, so it replaces the session (or starts one if there's
-- none). A session that still waits for the friend's handshake takes it.
-- One further along keeps going, as the friend sends its handshake through
-- every relay, and a new session would have keys the friend doesn't use.
handleNewHandshake :: ConnectionMonad m => NodeInfo -> ByteString -> m [ConnectionEvent]
handleNewHandshake from payload = do
  cm <- getConnManager
  opened <- SecureSession.openHandshake (cookieKey cm) (KeyPair.secretKey $ ourRealKeys cm) payload
  case opened of
    Nothing -> return []
    Just oh -> case Map.lookup (SecureSession.ohPeerRealPk oh) (friends cm) of
      Just f
        | fcDhtPk f /= Just (SecureSession.ohPeerDhtPk oh) || isNothing (fcSession f) -> do
            let pk = fcRealPk f
                dhtNode = from { NodeInfo.publicKey = SecureSession.ohPeerDhtPk oh }
            logInfo $ "Accepting session from " <> pack (show pk) <> " at " <> pack (show dhtNode)
            events <- setFriendDhtPk pk (SecureSession.ohPeerDhtPk oh)
            ss <- SecureSession.acceptSession (cookieKey cm) (ourRealKeys cm) (ourDhtKeys cm) from oh
            modifyFriend pk $ \f' -> f'
              { fcSession = Just ss
              , fcIpPort = if NodeInfo.protocol from == UDP then Just dhtNode else fcIpPort f'
              }
            return events
        | maybe False SecureSession.awaitsHandshake (fcSession f) ->
            logInfo ("Taking the handshake of " <> pack (show (fcRealPk f)) <> " into our session")
              >> ([] <$ withSession (fcRealPk f) (SecureSession.adoptHandshake (cookieKey cm) from oh))
      _ -> return []


-- | The onion found a friend's DHT key, so ask the nodes the friend sent for
-- its address.
handleOnionEvent :: ConnectionMonad m
                 => Onion.OnionEvent -> m [ConnectionEvent]
handleOnionEvent (Onion.FriendRequestReceived pk bytes) = return [FriendRequest pk bytes]
handleOnionEvent (Onion.GroupAnnouncesFound _ _) = return []
handleOnionEvent (Onion.FriendDhtPkFound pk dhtPk nodes) = do
  known <- getsConn (Map.member pk . friends)
  if not known then return [] else do
    events <- setFriendDhtPk pk dhtPk
    -- Even an old key is news, as the friend is back.
    news "its DHT key from the onion" pk
    let (relays, dhtNodes) = partition ((== TCP) . NodeInfo.protocol) nodes
    mapM_ (\node -> DHT.sendNodesRequest $ DHT.RequestInfo node dhtPk) dhtNodes
    mapM_ (addFriendRelay pk) relays
    return events

-- | Relay the friend is on, to be routed to them. A relay the friend runs
-- itself is reached at the friend's address.
addFriendRelay :: ConnectionMonad m => PublicKey -> NodeInfo -> m ()
addFriendRelay pk relay0 = getsConn (Map.lookup pk . friends) >>= mapM_ (\f -> do
  let relay = case (NodeInfo.address relay0, NodeInfo.address <$> fcIpPort f) of
        (SocketAddress host port, Just (SocketAddress friendHost _))
          | HostAddress.isLoopback host, fcDhtPk f == Just (NodeInfo.publicKey relay0) ->
              relay0 { NodeInfo.address = SocketAddress friendHost port }
        _ -> relay0
      other = (/= NodeInfo.publicKey relay) . NodeInfo.publicKey
  modifyFriend pk $ \f' -> f' { fcRelays = take maxStoredRelays $ relay : filter other (fcRelays f') }
  unless (relay `elem` fcRelays f) $ news "a relay it's on" pk
  mapM_ (`Tcp.addPeerRelay` relay) (fcDhtPk f))

decodeNodes :: ByteString -> [NodeInfo]
decodeNodes = either (const []) (\(_, _, nodes) -> nodes) . Get.runGetOrFail NodeInfo.getNodes . LBS.fromStrict
\end{code}

The timeout for when to stop retrying to connect to a friend by creating new
\texttt{net\_crypto} connections when the old one times out in toxcore is the
same as the timeout for DHT peers (122 seconds).  However, it is calculated
from the last time a DHT public key was received for the friend or time the
friend's \texttt{net\_crypto} connection went offline after being online.  The
highest time is used to calculate when the timeout is.  \texttt{net\_crypto}
connections will be recreated (if the connection fails) until this timeout.

\texttt{friend\_connection} sends a list of 3 relays (the same number as the
target number of TCP relay connections in \texttt{TCP\_connections}) to each
connected friend every 5 minutes in toxcore.  Immediately before sending the
relays, they are associated to the current \texttt{net\_crypto->TCP\_connections}
connection.  This facilitates connecting the two friends together using the
relays as the friend who receives the packet will associate the sent relays to
the \texttt{net\_crypto} connection they received it from.  When both sides do
this they will be able to connect to each other using the relays.  The packet
id or first byte of the packet of share relay packets is 0x11.  This is then
followed by some TCP relays stored in packed node format.

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x11) \\
  variable           & TCP relays in packed node format (see DHT) \\
\end{tabular}

If local IPs are received as part of the packet, the local IP will be replaced
with the IP of the peer that sent the relay.  This is because we assume this is
the best way to attempt to connect to the TCP relay.  If the peer that sent the
relay is using a local IP, then the sent local IP should be used to connect to
the relay.

For all other data packets, are passed by \texttt{friend\_connection} up to the
upper Messenger module.  It also separates lossy and lossless packets from
\texttt{net\_crypto}.

Friend connection takes care of establishing the connection to the friend and
gives the upper messenger layer a simple interface to receive and send
messages, add and remove friends and know if a friend is connected (online) or
not connected (offline).

\begin{code}
-- | A friend's work, each part due on its own.
data ConnectionJob
  = Connect PublicKey -- ^ Without a session.
  | Upkeep PublicKey  -- ^ With one.
  deriving (Eq, Ord, Show)

nextDue :: ConnectionManager -> Maybe Timestamp
nextDue = Schedule.next . connJobs

runDue :: ConnectionMonad m => m [ConnectionEvent]
runDue = do
  now <- Timed.askTime
  (due, waiting) <- getsConn $ Schedule.takeDue now . connJobs
  modifyConn $ \s -> s { connJobs = waiting }
  concat <$> mapM (\case Connect pk -> connect pk; Upkeep pk -> upkeep pk) due

-- | Straight to the friend's DHT node if we know where it is, else through a
-- relay it's on.
connect :: ConnectionMonad m => PublicKey -> m [ConnectionEvent]
connect pk = do
  mFriend <- getsConn (Map.lookup pk . friends)
  case mFriend of
    Just f | Nothing <- fcSession f, Just dhtPk <- fcDhtPk f -> do
      dht <- DHT.getDht
      case (DhtState.findNode dhtPk dht <|> fcIpPort f, fcRelays f) of
        (Just node, _)    -> setFriendIpPort pk node >> connectThrough pk dhtPk node
        (Nothing, relay : _) -> connectThrough pk dhtPk (Tcp.peerLink relay dhtPk)
        _                 -> return []
    _ -> return []

upkeep :: ConnectionMonad m => PublicKey -> m [ConnectionEvent]
upkeep pk = getsConn (fcSession <=< Map.lookup pk . friends) >>= \case
  Nothing -> return []
  Just ss -> do
    -- C only takes handshakes out of band, so the relay must connect us.
    let link = SecureSession.ssPeerNodeInfo ss
    when (NodeInfo.protocol link == TCP) $ Tcp.addPeerOnLink link
    events <- runSession pk SecureSession.maintainSession
    shareRelays pk
    events' <- pingFriend pk
    return (events ++ events')

-- | When a friend with a session next needs its session's work, a ping, our
-- relays or its timeout.
upkeepDue :: Timestamp -> FriendConnection -> Maybe Timestamp
upkeepDue now f = do
  ss <- fcSession f
  fmap minimum . nonEmpty . catMaybes $ SecureSession.nextDue now ss : concat
    [ [ after friendPingInterval (fcPingLastSent f)
      , (`Time.addTime` friendConnectionTimeout) <$> fcPingLastRecv f
      , after shareRelaysInterval (fcRelaysLastSent f)
      ]
    | fcOnline f ]
  where
    after interval = Just . maybe now (`Time.addTime` interval)

connectThrough :: ConnectionMonad m => PublicKey -> PublicKey -> NodeInfo -> m [ConnectionEvent]
connectThrough pk dhtPk link = do
  cm <- getConnManager
  logInfo $ "Connecting to " <> pack (show pk) <> " at " <> pack (show link)
  ss <- SecureSession.initSession (ourRealKeys cm) pk (ourDhtKeys cm) dhtPk link
  modifyFriend pk $ \f -> f { fcSession = Just ss }
  runSession pk SecureSession.maintainSession

-- | Tell an online friend our relays, and get routed to us on them. With
-- none yet, it waits for 'relaysUp'.
shareRelays :: ConnectionMonad m => PublicKey -> m ()
shareRelays pk = do
  now <- Timed.askTime
  mFriend <- getsConn (Map.lookup pk . friends)
  relays <- take maxSharedRelays <$> Tcp.connectedRelays
  case mFriend of
    Just f | fcOnline f, Time.due now shareRelaysInterval (fcRelaysLastSent f) -> do
      unless (null relays) $ do
        mapM_ (addFriendRelay pk) relays
        void . sendFriendData pk . LBS.toStrict . Put.runPut $ Put.putWord8 packetIdShareRelays >> mapM_ Binary.put relays
      modifyFriend pk $ \f' -> f' { fcRelaysLastSent = Just now }
    _ -> return ()

-- | We have relays now, so online friends hear of them at once.
relaysUp :: ConnectionMonad m => m ()
relaysUp = getsConn (Map.keys . Map.filter fcOnline . friends) >>= mapM_ (\pk -> modifyFriend pk $ \f -> f { fcRelaysLastSent = Nothing })

-- | Pings the friend when due, or ends the session if they stopped
-- answering.
pingFriend :: ConnectionMonad m => PublicKey -> m [ConnectionEvent]
pingFriend pk = do
  now <- Timed.askTime
  mFriend <- getsConn (Map.lookup pk . friends)
  case mFriend of
    Just f | fcOnline f -> do
      let due = Time.due now friendPingInterval
      if maybe False (\t -> Time.addTime t friendConnectionTimeout <= now) (fcPingLastRecv f)
      then do
        killSession TimedOut pk
      else do
        when (due $ fcPingLastSent f) $ do
          let alive = BS.singleton packetIdAlive
          sent <- sendFriendDataNumbered pk alive
          modifyFriend pk $ \f' -> f' { fcPingLastSent = Just now }
          forM_ sent $ \num ->
            -- On a relay, also try the friend's direct address with the same
            -- packet, so nothing waits for it if it doesn't get there.
            case (NodeInfo.protocol . SecureSession.ssPeerNodeInfo <$> fcSession f, fcIpPort f) of
              (Just TCP, Just node) -> void $ withSession pk (SecureSession.sendDataPacketTo node num alive)
              _ -> return ()
        return []
    _ -> return []
\end{code}
