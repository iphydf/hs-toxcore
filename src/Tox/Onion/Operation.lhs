\section{Onion Operation}

\begin{code}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE MultiWayIf            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE UndecidableInstances  #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}
module Tox.Onion.Operation where

import           Control.Monad                      (forM_, replicateM,
                                                     replicateM_, unless, void,
                                                     when, (<$!>))
import           Control.Monad.State                (StateT, runStateT)
import qualified Crypto.Saltine.Class               as Sodium
import qualified Data.Binary                        as Binary
import qualified Data.Binary.Get                    as Get
import qualified Data.Binary.Put                    as Put
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.Function                      (on)
import           Data.List                          (nubBy, sortOn)
import           Data.List.NonEmpty                 (nonEmpty)
import           Data.Map                           (Map)
import qualified Data.Map                           as Map
import           Data.Maybe                         (catMaybes, fromJust,
                                                     fromMaybe, isJust,
                                                     isNothing)
import qualified Data.Set                           as Set
import           Data.Text                          (pack)
import           Data.Word                          (Word32, Word64, Word8)

import           Tox.Core.Log                       (MonadLog, logDebug,
                                                     logInfo)
import qualified Tox.Core.PingArray                 as PingArray
import qualified Tox.Core.Schedule                  as Schedule
import           Tox.Core.Schedule                  (Schedule)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import           Tox.Core.Timed                     (Timed (..))
import qualified Tox.Crypto.Core.Box                as Box
import           Tox.Crypto.Core.Box                (PlainText (..))
import qualified Tox.Crypto.Core.Hash               as Hash
import           Tox.Crypto.Core.Key                (CombinedKey, CryptoNumber,
                                                     Key, PublicKey)
import           Tox.Crypto.Core.Keyed              (Keyed (..))
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.KeyPair            (KeyPair)
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes (..),
                                                     randomKey, randomNonce,
                                                     randomWord64)
import qualified Tox.DHT.DhtPacket                  as DhtPacket
import           Tox.DHT.DhtRequestPacket           (DhtRequestPacket (..))
import qualified Tox.DHT.Distance                   as Distance
import           Tox.Network.Core.Networked         (Networked (..))
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..),
                                                     RawPayload (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import qualified Tox.Network.Core.SocketAddress     as SocketAddress
import           Tox.Network.Core.SocketAddress     (SocketAddress)
import           Tox.Network.Core.Traffic           (Purpose (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Onion.GroupAnnounce            as GroupAnnounce
import qualified Tox.Onion.Path                     as Path
import           Tox.Onion.Path                     (OnionPath, OnionPathState)
import qualified Tox.Onion.RPC                      as RPC
import qualified Tox.Onion.Tunnel                   as Tunnel


{-------------------------------------------------------------------------------
 -
 - :: Constants.
 -
 ------------------------------------------------------------------------------}

maxAnnounceNodes :: Int
maxAnnounceNodes = 12

maxFriendNodes :: Int
maxFriendNodes = 8

-- | Nodes put in announce responses and DHT public key packets.
maxSentNodes :: Int
maxSentNodes = 4

-- | For nodes that store our entry, and ones that don't yet.
announceIntervalStored, announceIntervalUnstored :: TimeDiff
announceIntervalStored   = Time.seconds 15
announceIntervalUnstored = Time.seconds 3

-- | Nodes that missed this many responses in a row aren't asked again, and
-- get dropped after 'onionNodeTimeout'.
maxUnansweredRequests :: Int
maxUnansweredRequests = 3

onionNodeTimeout :: TimeDiff
onionNodeTimeout = Time.seconds 15

dhtPkSendInterval, dhtPkDhtSendInterval :: TimeDiff
dhtPkSendInterval = Time.seconds 30
dhtPkDhtSendInterval = Time.seconds 20

-- | Between sends through the onion. The first few come sooner, or one lost
-- packet would keep a friend away for the whole interval after a restart.
dhtPkInterval :: Int -> TimeDiff
dhtPkInterval sends
  | sends < 3 = Time.seconds 5
  | otherwise = dhtPkSendInterval

-- | How long a ping ID and an announcement stay valid.
announceTimeout :: TimeDiff
announceTimeout = Time.seconds 300

maxAnnounceEntries :: Int
maxAnnounceEntries = 160

packetIdDhtPk, packetIdFriendRequest :: Word8
packetIdDhtPk         = 156
packetIdFriendRequest = 32

-- | Request and response lengths without the packet kind.
announceRequestLength, dataRequestMinLength :: Int
announceRequestLength = 24 + 32 + 32 + 32 + 32 + 8 + 16
dataRequestMinLength  = 32 + 24 + 32 + 16


{-------------------------------------------------------------------------------
 -
 - :: State.
 -
 ------------------------------------------------------------------------------}

class (Monad m, Timed m, MonadRandomBytes m, Keyed m, Networked m, MonadLog m) => OnionNodeMonad m where
  getOnionState :: m OnionState
  putOnionState :: OnionState -> m ()
  getDhtKeyPair :: m KeyPair
  -- | Up to the given number of DHT nodes closest to a key.
  getCloseNodes :: Int -> PublicKey -> m [NodeInfo]
  -- | As 'getCloseNodes', for a requester at that address.
  getCloseNodesFor :: SocketAddress -> Int -> PublicKey -> m [NodeInfo]
  -- | Connected TCP relays.
  getTcpRelays :: m [NodeInfo]
  getTcpRelays = return []
  -- | To a relay that's the first node of its path.
  sendOnionViaRelay :: NodeInfo -> BS.ByteString -> m ()
  sendOnionViaRelay _ _ = return ()
  -- | For onion responses.
  sendToTcpClient :: Word64 -> BS.ByteString -> m ()
  sendToTcpClient _ _ = return ()
  -- | Through the nodes close to it. Gives how many nodes it went through.
  sendDhtRequest :: PublicKey -> BS.ByteString -> m Int
  sendDhtRequest _ _ = return 0
  -- | A request just sent, with its size before any onion layers. Each
  -- copy sent counts once.
  countRequest :: Purpose -> Int -> m ()
  countRequest _ _ = return ()
  -- | Enough nodes store the friend now to send it data through them.
  friendHeld :: PublicKey -> m ()
  friendHeld _ = return ()

getsOnion :: OnionNodeMonad m => (OnionState -> a) -> m a
getsOnion f = f <$!> getOnionState

modifyOnion :: OnionNodeMonad m => (OnionState -> OnionState) -> m ()
modifyOnion f = getOnionState >>= putOnionState . f

instance OnionNodeMonad m => Path.OnionPathMonad (StateT OnionPathState m)

zoomOnionPath :: OnionNodeMonad m => StateT OnionPathState m a -> m a
zoomOnionPath st = do
  s <- getOnionState
  (a, s') <- runStateT st (onionPaths s)
  putOnionState s { onionPaths = s' }
  return a

-- | What an announce node said about the key we announced or searched for.
data AnnounceStatus
  = NotStored              -- ^ It gave us a ping ID to announce with.
  | StoresFriend PublicKey -- ^ With their data public key.
  | StoresUs
  deriving (Eq, Show)

-- | Node we announce ourselves to, or ask about a friend.
data OnionNode = OnionNode
  { onNode       :: NodeInfo
  , onStatus     :: AnnounceStatus
  , onPingId     :: Maybe PublicKey
  , onPathNum    :: Maybe Word32
  , onLastSent   :: Maybe Timestamp
  , onUnanswered :: Int
  , onAnswered   :: Bool
  } deriving (Eq, Show)

-- | Us, a friend, or a group search under a random key.
data Target = Self | Friend PublicKey | GroupSearch PublicKey
  deriving (Eq, Ord, Show)

-- | Onion nodes near a random search key store and return group
-- announcements by chat ID.
data OnionGroup = OnionGroup
  { ogTempKeys :: KeyPair
  , ogNodes    :: Map PublicKey OnionNode
  , ogChatId   :: BS.ByteString
  , ogAnnounce :: Maybe BS.ByteString -- ^ How to reach us, sent with each request.
  } deriving (Eq, Show)

-- | Group announcements we store for others: the newest 16 per chat ID.
data StoredGroup = StoredGroup
  { sgAnnounces :: [(PublicKey, BS.ByteString)]
  , sgLastSeen  :: Timestamp
  } deriving (Eq, Show)

maxOnionPacketSize :: Int
maxOnionPacketSize = 1400

-- | How long we use a return data key. As in toxcore, older return data stops
-- working.
returnKeyLifetime :: TimeDiff
returnKeyLifetime = Time.seconds (2 * 60 * 60)

maxStoredAnnounces, maxSentAnnounces, maxStoredGroups, maxExtraDataSize :: Int
maxStoredAnnounces = 16
maxSentAnnounces   = 4
maxStoredGroups    = 512
-- | Most an announce request carries after its own fields (a chat ID and an
-- announcement).
maxExtraDataSize   = 136

-- | Ping ID, search key, data key and sendback data.
announceRequestSize :: Int
announceRequestSize = 32 + 32 + 32 + 8

storedGroupTimeout :: TimeDiff
storedGroupTimeout = Time.seconds 60

data OnionFriend = OnionFriend
  { ofTempKeys         :: KeyPair -- ^ Keeps searches unlinkable to us.
  , ofNodes            :: Map PublicKey OnionNode -- ^ Only ones that answered, so silent ones take no place.
  , ofAsked            :: Map PublicKey Timestamp -- ^ Others we asked, and when.
  , ofLastDhtPkSent    :: Maybe Timestamp
  , ofLastDhtPkDhtSent :: Maybe Timestamp -- ^ Sent through the DHT.
  , ofDhtPk            :: Maybe PublicKey
  , ofLastNoReplay     :: Word64
  , ofOnline           :: Bool -- ^ Connected, so we don't search.
  , ofPings            :: Int  -- ^ Requests since the friend was last online.
  , ofLastPinged       :: Maybe Timestamp
  , ofDhtPkSends       :: Int  -- ^ Through the onion, since the friend was last online.
  } deriving (Eq, Show)

-- | Often at first, then less and less while they stay away (as toxcore
-- does). After the first rounds we also spread requests over the nodes.
friendInterval :: Int -> TimeDiff
friendInterval pings
  | newFriend pings = Time.seconds 3
  | otherwise = Time.seconds . min 3600 $ 2 ^ min 12 (friendRounds pings - 2)

-- | Between requests to different nodes, once past the first rounds.
friendSpacing :: Int -> TimeDiff
friendSpacing pings
  | newFriend pings = friendInterval pings
  | otherwise = Time.milliseconds $ Time.toMilliseconds (friendInterval pings) `div` fromIntegral (maxFriendNodes `div` 2)

friendRounds :: Int -> Int
friendRounds pings = pings `div` (maxFriendNodes `div` 2)

newFriend :: Int -> Bool
newFriend = (<= 5) . friendRounds

data Sendback = Sendback
  { sbTarget  :: Target
  , sbNode    :: NodeInfo
  , sbPathNum :: Word32
  } deriving (Eq, Show)

-- | Stored by us as an announce node.
data AnnounceEntry = AnnounceEntry
  { aeDataPk  :: PublicKey
  , aeAddress :: SocketAddress     -- ^ Last relay of the announcing path.
  , aeReturn  :: BS.ByteString     -- ^ Return data to reach the announcer.
  , aeTime    :: Timestamp
  } deriving (Eq, Show)

data OnionState = OnionState
  { onionPaths      :: OnionPathState
  , ourRealKeys     :: KeyPair
  , ourDataKeys     :: KeyPair -- ^ Others encrypt onion data to us with this.
  , selfNodes       :: Map PublicKey OnionNode
  , onionFriends    :: Map PublicKey OnionFriend
  , sendbacks       :: PingArray.PingArray Sendback
  , returnKey       :: CombinedKey -- ^ Seals return data when relaying.
  , returnKeySince  :: Maybe Timestamp
  , pingIdSecret    :: BS.ByteString
  , announceEntries :: Map PublicKey AnnounceEntry
  , pathNodes       :: [NodeInfo] -- ^ From announce responses, for paths, newest first.
  , bootstrapNodes  :: [NodeInfo] -- ^ As 'pathNodes', from bootstrapping and saves.
  , onionTcpOnly    :: Bool -- ^ Without UDP, paths start at a TCP relay.
  , onionConnected  :: Int  -- ^ Goes up while we're announced, down while not.
  , onionGroups     :: Map PublicKey OnionGroup -- ^ By search key.
  , storedGroups    :: Map BS.ByteString StoredGroup -- ^ By chat ID.
  , onionJobs       :: Schedule OnionJob
  }

data OnionEvent
  = FriendDhtPkFound PublicKey PublicKey [NodeInfo] -- ^ Friend, its DHT key and nodes near it.
  | FriendRequestReceived PublicKey BS.ByteString    -- ^ Sender and the request after its packet ID.
  | GroupAnnouncesFound BS.ByteString BS.ByteString -- ^ Chat ID and packed announcements of its peers.
  deriving (Eq, Show)

initState :: MonadRandomBytes m => KeyPair -> m OnionState
initState realKeys = do
  dataKeys <- newKeyPair
  retKey <- randomKey
  secret <- randomBytes 32
  return OnionState
    { onionPaths      = Path.OnionPathState [] [] 0
    , ourRealKeys     = realKeys
    , ourDataKeys     = dataKeys
    , selfNodes       = Map.empty
    , onionFriends    = Map.empty
    , sendbacks       = PingArray.empty 1024 (Time.seconds 10)
    , returnKey       = retKey
    , returnKeySince  = Nothing
    , pingIdSecret    = secret
    , announceEntries = Map.empty
    , pathNodes       = []
    , bootstrapNodes  = []
    , onionTcpOnly    = False
    , onionConnected  = 0
    , onionGroups     = Map.empty
    , storedGroups    = Map.empty
    , onionJobs       = Schedule.empty
    }

maxPathNodes :: Int
maxPathNodes = 32

-- | Newer nodes replace the oldest, as in toxcore's ring buffers.
addNewest :: [NodeInfo] -> [NodeInfo] -> [NodeInfo]
addNewest nodes pool = take maxPathNodes $ foldl' add pool nodes
  where
    add acc n
      | NodeInfo.protocol n /= UDP || NodeInfo.publicKey n `elem` map NodeInfo.publicKey acc = acc
      | otherwise = n : acc

addPathNodes, addBootstrapNodes :: OnionNodeMonad m => [NodeInfo] -> m ()
addPathNodes nodes = modifyOnion $ \s -> s { pathNodes = addNewest nodes (pathNodes s) }
addBootstrapNodes nodes = modifyOnion $ \s -> s { bootstrapNodes = addNewest nodes (bootstrapNodes s) }

-- | Nodes to build paths from besides the DHT's.
pathPool :: OnionState -> [NodeInfo]
pathPool s = pathNodes s ++ filter ((`notElem` map NodeInfo.publicKey (pathNodes s)) . NodeInfo.publicKey)
  (bootstrapNodes s)

-- | Once DHT nodes answer us, other path nodes (like bootstrap nodes we may
-- not reach) only fill up if there are too few.
withPool :: Int -> [NodeInfo] -> [NodeInfo] -> [NodeInfo]
withPool n close pool
  | length close >= n = close
  | otherwise         = close ++ pool

zeroKey :: PublicKey
zeroKey = fromJust . Sodium.decode $ BS.replicate 32 0

sendTo :: OnionNodeMonad m => SocketAddress -> Packet RawPayload -> m ()
sendTo addr = sendPacket (NodeInfo UDP addr zeroKey)

encodeStrict :: Binary.Binary a => a -> BS.ByteString
encodeStrict = LBS.toStrict . Binary.encode

decodeStrict :: Binary.Binary a => BS.ByteString -> Maybe a
decodeStrict = Box.decode . PlainText


{-------------------------------------------------------------------------------
 -
\end{code}

To search/announce itself to peers, toxcore keeps the 8 closest peers (12 for
announcing) to each key it is searching (or announcing itself to).  To
populate these it starts by sending announce requests to random peers for all
the public keys it is searching for.  It then recursively searches closer and
closer peers (DHT distance function) until it no longer finds any.  It is
important to make sure it is not too aggressive at searching the peers as some
might no longer be online but peers might still send announce responses with
their information. Toxcore keeps lists of last pinged nodes for each key
searched so as not to ping dead nodes too aggressively.

Toxcore decides if it will send an announce packet to one of the 4 peers in the
announce response by checking if the peer would be stored as one of the stored
closest peers if it responded; if it would not be it doesn't send an announce
request, if it would be it sends one.

Peers are only put in the closest peers array if they respond to an announce
request.  If the peers fail to respond to 3 announce requests they are deemed
timed out and removed.  When sending an announce request to a peer to which we
have been announcing ourselves for at least 90 seconds and which has failed to
respond to the previous 2 requests, toxcore uses a random path for the request.
This reduces the chances that a good node will be removed due to bad paths.

The reason for the numbers of peers being 8 and 12 is that lower numbers might
make searching for and announcing too unreliable and a higher number too
bandwidth/resource intensive.

Toxcore uses \texttt{ping\_array} (see \texttt{ping\_array}) for the 8 byte
sendback data in announce packets to store information that it will need to
handle the response (key to decrypt it, why was it sent? (to announce ourselves
or to search? For what key? and some other info)).  For security purposes it
checks to make sure the packet was received from the right ip/port and checks
if the key in the unencrypted part of the packet is the right public key.

For peers we are announcing ourselves to, if we are not announced to them
toxcore tries every 3 seconds to announce ourselves to them until they return
that we have announced ourselves to them, then initially toxcore sends an
announce request packet every 15 seconds to see if we are still announced and
reannounce ourselves at the same time.  Toxcore sends every announce packet
with the \texttt{ping\_id} previously received from that peer with the same
path (if possible).  Toxcore use a timeout of 120 seconds rather than 15
seconds if we have been announcing to the peer for at least 90 seconds, and
the onion path we are are using for the peer has also been alive for at least
90 seconds, and we have not been waiting for at least 15 seconds for a
response to a request sent to the peer, nor for at least 10 seconds for a
response to a request sent via the path. The timeout of at most 120 seconds
means a \texttt{ping\_id} received in the last packet will not have had time
to expire (300 second minimum timeout) before it is resent 120 seconds later.

For friends this is slightly different.  It is important to start searching for
friends after we are fully announced.  Assuming a perfect network, we would
only need to do a search for friend public keys only when first starting the
instance (or going offline and back online) as peers starting up after us would
be able to find us immediately just by searching for us.  If we start searching
for friends after we are announced we prevent a scenario where 2 friends start
their clients at the same time but are unable to find each other right away
because they start searching for each other while they have not announced
themselves.

For this reason, after the peer is announced successfully, for 17 seconds
announce packets are sent aggressively every 3 seconds to each known close peer
(in the list of 8 peers) to search aggressively for peers that know the peer we
are searching for.

After this, toxcore sends requests once per 15 seconds initially, then
uses linear backoff to increase the interval.  In detail, the interval used
when searching for a given friend is at least 15 and at most 2400 seconds, and
within these bounds is calculated as one quarter of the time since we began
searching for the friend, or since the friend was last seen. For this purpose,
a friend is considered to be seen when some peer reports that the friend is
announced, or we receive a DHT Public Key packet from the friend, or we obtain
a new DHT key for them from a group, or a friend connection for the friend
goes offline.

There are other ways this could be done and which would still work but, if
making your own implementation, keep in mind that these are likely not the most
optimized way to do things.

\begin{code}
 - :: Announcing and searching.
 -
 ------------------------------------------------------------------------------}

-- | Does nothing if we're searching already.
startFriendSearch :: OnionNodeMonad m => PublicKey -> m ()
startFriendSearch friendPk = do
  known <- getsOnion $ Map.member friendPk . onionFriends
  unless known $ do
    tempKeys <- newKeyPair
    let friend = OnionFriend
          { ofTempKeys         = tempKeys
          , ofNodes            = Map.empty
          , ofAsked            = Map.empty
          , ofLastDhtPkSent    = Nothing
          , ofLastDhtPkDhtSent = Nothing
          , ofDhtPk            = Nothing
          , ofLastNoReplay     = 0
          , ofOnline           = False
          , ofPings            = 0
          , ofLastPinged       = Nothing
          , ofDhtPkSends       = 0
          }
    modifyOnion $ \s -> s { onionFriends = Map.insert friendPk friend (onionFriends s) }
    reschedule friendPk

-- | Keep paths and announce ourselves. Friends have their own turns, in
-- 'runDue'.
doOnion :: OnionNodeMonad m => m ()
doOnion = do
  now' <- askTime
  since <- getsOnion returnKeySince
  case since of
    Nothing -> modifyOnion $ \s -> s { returnKeySince = Just now' }
    Just t | Time.addTime t returnKeyLifetime <= now' -> do
      key <- randomKey
      modifyOnion $ \s -> s { returnKey = key, returnKeySince = Just now' }
    _ -> return ()
  ourDhtPk <- KeyPair.publicKey <$> getDhtKeyPair
  close <- getCloseNodes 32 ourDhtPk
  pool <- getsOnion pathPool
  tcpOnly <- getsOnion onionTcpOnly
  -- UDP doesn't work without DHT nodes, so go through relays.
  if tcpOnly || null close
  then getTcpRelays >>= \relays -> zoomOnionPath $ Path.maintainPathsVia relays (withPool maxAnnounceNodes close pool)
  else zoomOnionPath $ Path.maintainPaths (withPool maxAnnounceNodes close pool)
  announce Self
  now <- askTime
  modifyOnion $ \s -> s { onionConnected = if isAnnounced now s
    then min (2 * connectedRuns) (onionConnected s + 1)
    else max 0 (onionConnected s - 1) }
  groupKeys <- getsOnion $ Map.keys . onionGroups
  mapM_ (announce . GroupSearch) groupKeys
  modifyOnion $ \s ->
    s { storedGroups = Map.filter (\g -> Time.addTime (sgLastSeen g) storedGroupTimeout > now') (storedGroups s) }

-- | Searches skipped while the onion didn't work, or done while we were
-- away, may have missed friends who are there now, so we search often again.
searchAfresh :: OnionNodeMonad m => m ()
searchAfresh = do
  modifyOnion $ \s -> s { onionFriends = Map.map (\f -> f { ofPings = 0 }) (onionFriends s) }
  mapM_ reschedule =<< getsOnion (Map.keys . onionFriends)

removeFriend :: OnionNodeMonad m => PublicKey -> m ()
removeFriend pk = modifyOnion $ \s -> s
  { onionFriends = Map.delete pk (onionFriends s)
  , onionJobs = Schedule.cancel (FriendSearch pk) . Schedule.cancel (FriendDhtKey pk) $ onionJobs s
  }

-- | A friend's work, each part due on its own while the friend is offline.
data OnionJob = FriendSearch PublicKey | FriendDhtKey PublicKey
  deriving (Eq, Ord, Show)

nextDue :: OnionState -> Maybe Timestamp
nextDue = Schedule.next . onionJobs

runDue :: OnionNodeMonad m => m ()
runDue = do
  now <- askTime
  (due, waiting) <- getsOnion $ Schedule.takeDue now . onionJobs
  modifyOnion $ \s -> s { onionJobs = waiting }
  forM_ due $ \case
    -- Not before the onion works. 'searchAfresh' brings it back then.
    FriendSearch pk -> getsOnion (onionWorks now) >>= (`when` (announce (Friend pk) >> scheduleSearch Ran pk))
    FriendDhtKey pk -> sendDhtPkIfDue pk >> scheduleDhtKey Ran pk

-- | Why we work out a job's next turn (it just had one, or the friend
-- changed).
data Turn = Ran | Changed
  deriving (Eq, Show)

-- | After something that may bring the friend's turns forward.
reschedule :: OnionNodeMonad m => PublicKey -> m ()
reschedule pk = scheduleSearch Changed pk >> scheduleDhtKey Changed pk

-- | Just after its turn, a time that has come means it couldn't ask anyone,
-- so it waits its spacing.
scheduleSearch :: OnionNodeMonad m => Turn -> PublicKey -> m ()
scheduleSearch turn pk = whileOffline pk $ \now f ->
  let due = searchDue now f
  in Schedule.at (if turn == Ran && due <= now then Time.addTime now (friendSpacing (ofPings f)) else due) (FriendSearch pk)

scheduleDhtKey :: OnionNodeMonad m => Turn -> PublicKey -> m ()
scheduleDhtKey turn pk = whileOffline pk $ \now f ->
  maybe (Schedule.cancel (FriendDhtKey pk)) (`Schedule.at` FriendDhtKey pk) (dhtKeyDue turn now f)

whileOffline :: OnionNodeMonad m
             => PublicKey -> (Timestamp -> OnionFriend -> Schedule OnionJob -> Schedule OnionJob) -> m ()
whileOffline pk f = do
  now <- askTime
  mFriend <- getsOnion $ Map.lookup pk . onionFriends
  forM_ mFriend $ \friend -> unless (ofOnline friend) $
    modifyOnion $ \s -> s { onionJobs = f now friend (onionJobs s) }

-- | When one of the friend's nodes is due a request, and the spacing allows.
-- With too few nodes, asking others is what finds more.
searchDue :: Timestamp -> OnionFriend -> Timestamp
searchDue now f = max spaced $ case asked of
  [] -> now
  _  -> minimum asked
  where
    asked = [ now | Map.size (ofNodes f) < maxFriendNodes ] ++
            [ maybe now (`Time.addTime` friendInterval (ofPings f)) (onLastSent n)
            | n <- Map.elems (ofNodes f), onUnanswered n < maxUnansweredRequests ]
    spaced
      | newFriend (ofPings f) = now
      | otherwise = maybe now (`Time.addTime` friendSpacing (ofPings f)) (ofLastPinged f)

-- | Through nodes that store the friend, or through the DHT once we know its
-- DHT key. Just after its turn, a route still due didn't work, so it waits its
-- interval.
dhtKeyDue :: Turn -> Timestamp -> OnionFriend -> Maybe Timestamp
dhtKeyDue turn now f = minimum <$> nonEmpty (catMaybes [byOnion, byDht])
  where
    byOnion
      | null (friendHolders f) = Nothing
      | otherwise = Just $ next (dhtPkInterval (ofDhtPkSends f)) (ofLastDhtPkSent f)
    byDht = next dhtPkDhtSendInterval (ofLastDhtPkDhtSent f) <$ ofDhtPk f
    next interval lastSent = case (`Time.addTime` interval) <$> lastSent of
      Just t | t > now     -> t
      _ | turn == Ran -> Time.addTime now interval
        | otherwise   -> now

-- | We must be announced for this many 'doOnion' runs to be online. Toxcore
-- waits 3 seconds, and goes offline just as slowly.
connectedRuns :: Int
connectedRuns = 2

isConnected :: OnionState -> Bool
isConnected s = onionConnected s >= connectedRuns

-- | Announced to at least half the nodes that answer us.
isAnnounced :: Timestamp -> OnionState -> Bool
isAnnounced now s = announced > 0 && length live `div` 2 <= announced
  where
    live = answering now s
    announced = length $ filter ((== StoresUs) . onStatus) live

-- | Some node answers us through our paths, so searches can work.
onionWorks :: Timestamp -> OnionState -> Bool
onionWorks now = not . null . answering now

-- | The nodes we announce to that answer us.
answering :: Timestamp -> OnionState -> [OnionNode]
answering now = filter (\n -> onAnswered n && not (timedOut now n)) . Map.elems . selfNodes

setFriendOnline :: OnionNodeMonad m => PublicKey -> Bool -> m ()
setFriendOnline pk online = do
  modifyOnion $ \s -> s { onionFriends = Map.adjust update pk (onionFriends s) }
  if online
    then modifyOnion $ \s -> s { onionJobs = Schedule.cancel (FriendSearch pk) . Schedule.cancel (FriendDhtKey pk) $ onionJobs s }
    else reschedule pk
  where
    -- After going offline, the friend may restart with an older clock, so
    -- take its next public key packet anyway.
    update f
      | ofOnline f && not online = f { ofOnline = False, ofPings = 0, ofLastNoReplay = 0, ofDhtPkSends = 0 }
      | otherwise = f { ofOnline = online }

targetKey :: OnionState -> Target -> PublicKey
targetKey s Self             = KeyPair.publicKey $ ourRealKeys s
targetKey _ (Friend pk)      = pk
targetKey _ (GroupSearch pk) = pk

targetNodes :: OnionState -> Target -> Map PublicKey OnionNode
targetNodes s Self        = selfNodes s
targetNodes s (Friend pk) = maybe Map.empty ofNodes $ Map.lookup pk (onionFriends s)
targetNodes s (GroupSearch pk) = maybe Map.empty ogNodes $ Map.lookup pk (onionGroups s)

setTargetNodes :: Target -> Map PublicKey OnionNode -> OnionState -> OnionState
setTargetNodes Self nodes s = s { selfNodes = nodes }
setTargetNodes (Friend pk) nodes s =
  s { onionFriends = Map.adjust (\f -> f { ofNodes = nodes }) pk (onionFriends s) }
setTargetNodes (GroupSearch pk) nodes s =
  s { onionGroups = Map.adjust (\g -> g { ogNodes = nodes }) pk (onionGroups s) }

maxTargetNodes :: Target -> Int
maxTargetNodes Self            = maxAnnounceNodes
maxTargetNodes (Friend _)      = maxFriendNodes
maxTargetNodes (GroupSearch _) = maxFriendNodes

timedOut :: Timestamp -> OnionNode -> Bool
timedOut now n = onUnanswered n >= maxUnansweredRequests
  && maybe True (\t -> Time.addTime t onionNodeTimeout < now) (onLastSent n)

closestNodes :: Timestamp -> Int -> PublicKey -> Map PublicKey OnionNode -> Map PublicKey OnionNode
closestNodes now limit key =
  Map.fromList . take limit . sortOn (Distance.xorDistance key . fst) . Map.toList
    . Map.filter (not . timedOut now)

newOnionNode :: NodeInfo -> OnionNode
newOnionNode node = OnionNode
  { onNode       = node
  , onStatus     = NotStored
  , onPingId     = Nothing
  , onPathNum    = Nothing
  , onLastSent   = Nothing
  , onUnanswered = 0
  , onAnswered   = False
  }

-- | To the target's nodes that are due one.
announce :: OnionNodeMonad m => Target -> m ()
announce (Friend pk) = searchFriend pk
announce target = do
  s <- getOnionState
  now <- askTime
  near <- nearNodes target
  let fresh = Map.fromList [ (NodeInfo.publicKey n, newOnionNode n) | n <- near ]
      nodes = closestNodes now (maxTargetNodes target) (targetKey s target) (Map.union (targetNodes s target) fresh)
  modifyOnion $ setTargetNodes target nodes
  forM_ (filter ((< maxUnansweredRequests) . onUnanswered) $ Map.elems nodes) $ \node -> do
    let interval = if onStatus node == NotStored then announceIntervalUnstored else announceIntervalStored
    when (Time.due now interval (onLastSent node)) . void $ sendAnnounceRequest target node

-- | DHT nodes near the target's key, and path nodes if there are too few.
nearNodes :: OnionNodeMonad m => Target -> m [NodeInfo]
nearNodes target = do
  s <- getOnionState
  let key = targetKey s target
  close <- getCloseNodes (maxTargetNodes target) key
  let pool = take (maxTargetNodes target) . sortOn (Distance.xorDistance key . NodeInfo.publicKey) $ pathPool s
  return $ withPool (maxTargetNodes target) close pool

-- | To the friend's nodes that are due one, and while too few answer, to
-- nodes near the friend we haven't asked lately.
searchFriend :: OnionNodeMonad m => PublicKey -> m ()
searchFriend pk = do
  now <- askTime
  near <- nearNodes (Friend pk)
  getsOnion (Map.lookup pk . onionFriends) >>= mapM_ (\f -> do
    let nodes = closestNodes now maxFriendNodes pk (ofNodes f)
        others = [ n | Map.size nodes < maxFriendNodes, n <- near
                     , Map.notMember (NodeInfo.publicKey n) nodes, not (askedLately now f n) ]
        asks = [ (onLastSent n, sendAnnounceRequest (Friend pk) n)
               | n <- Map.elems nodes, onUnanswered n < maxUnansweredRequests ]
            ++ [ (Nothing, askOther pk n) | n <- others ]
    modifyOnion $ setTargetNodes (Friend pk) nodes
    forM_ asks $ \(lastSent, ask) -> getsOnion (Map.lookup pk . onionFriends) >>= mapM_ (\f' -> do
      let spaced = newFriend (ofPings f') || Time.due now (friendSpacing (ofPings f')) (ofLastPinged f')
      when (spaced && Time.due now (friendInterval (ofPings f')) lastSent) $ do
        sent <- ask
        let pinged f'' = f'' { ofPings = ofPings f'' + 1, ofLastPinged = Just now }
        when sent $ modifyOnion $ \st -> st { onionFriends = Map.adjust pinged pk (onionFriends st) }))

-- | Would be one of the friend's closest nodes we know of, counting ones we
-- asked and wait for. Without those, each answer would set off requests to
-- all the nodes it tells of that are closer than the ones that answered,
-- and while our view of the network is young, they all are.
worthAsking :: Timestamp -> PublicKey -> OnionFriend -> NodeInfo -> Bool
worthAsking now pk f n = Set.notMember key known && not (askedLately now f n)
  && (Set.size known < maxFriendNodes || distance key < Set.elemAt (maxFriendNodes - 1) (Set.map distance known))
  where
    key = NodeInfo.publicKey n
    distance = Distance.xorDistance pk
    known = Set.fromList $ Map.keys (ofNodes f)
      ++ [ k | (k, t) <- Map.toList (ofAsked f), not (Time.due now (friendInterval (ofPings f)) (Just t)) ]

-- | Within the friend's interval, so we don't ask a node again too soon.
askedLately :: Timestamp -> OnionFriend -> NodeInfo -> Bool
askedLately now f n = maybe False (not . Time.due now (friendInterval (ofPings f)) . Just) $
  Map.lookup (NodeInfo.publicKey n) (ofAsked f)

-- | A node that isn't one of the friend's. It becomes one if it answers.
askOther :: OnionNodeMonad m => PublicKey -> NodeInfo -> m Bool
askOther pk n = do
  sent <- isJust <$> askNode (Friend pk) (newOnionNode n)
  now <- askTime
  let asked f = f { ofAsked = Map.insert (NodeInfo.publicKey n) now $
        Map.filter (\t -> not (Time.due now (friendInterval (ofPings f)) (Just t))) (ofAsked f) }
  when sent $ modifyOnion $ \s -> s { onionFriends = Map.adjust asked pk (onionFriends s) }
  return sent

-- | To one of the target's nodes. Says whether there was a path for it.
sendAnnounceRequest :: OnionNodeMonad m => Target -> OnionNode -> m Bool
sendAnnounceRequest target node = do
  sentVia <- askNode target node
  forM_ sentVia $ \num -> do
    now <- askTime
    let node' = node { onLastSent = Just now, onUnanswered = onUnanswered node + 1, onPathNum = Just num }
    modifyOnion $ \st -> setTargetNodes target (Map.insert (NodeInfo.publicKey (onNode node)) node' $ targetNodes st target) st
  return (isJust sentVia)

-- | A ping ID only works through the path it came on, so reuse that path
-- while it lasts. Searches send no ping ID, so the node doesn't store their
-- temporary key as an announcement. Says which path it took, if there was one.
askNode :: OnionNodeMonad m => Target -> OnionNode -> m (Maybe Word32)
askNode target node = do
  s <- getOnionState
  samePath <- case (target, onPathNum node) of
    (Self, Just num) -> zoomOnionPath $ Path.findPath num
    _                -> return Nothing
  mPath <- maybe (zoomOnionPath $ Path.selectPath (target == Self)) (return . Just) samePath
  forM_ mPath $ \path -> do
    now <- askTime
    seed <- randomWord64
    let to = onNode node
        sendback = Sendback target to (Path.pathNum path)
        (sendbackId, sendbacks') = PingArray.addEntry now sendback seed (sendbacks s)
        group = case target of
          GroupSearch pk -> Map.lookup pk (onionGroups s)
          _              -> Nothing
        (keys, dataPk) = case target of
          Self     -> (ourRealKeys s, KeyPair.publicKey $ ourDataKeys s)
          Friend pk -> (maybe (ourRealKeys s) ofTempKeys $ Map.lookup pk (onionFriends s), zeroKey)
          GroupSearch _ -> (maybe (ourRealKeys s) ogTempKeys group, zeroKey)
        extra = group >>= ogAnnounce
        pingId = if isJust samePath then onPingId node else Nothing
        payload = RPC.AnnounceRequestPayload
          { RPC.announceRequestPingId          = fromMaybe zeroKey pingId
          , RPC.announceRequestSearchKey       = targetKey s target
          , RPC.announceRequestDataSendbackKey = dataPk
          , RPC.announceRequestSendbackData    = sendbackId
          }
    nonce <- randomNonce
    shared <- getCombinedKey (KeyPair.secretKey keys) (NodeInfo.publicKey to)
    let plain = Box.PlainText $ encodeStrict payload <> fromMaybe BS.empty extra
        request = Sodium.encode nonce <> keyBytes (KeyPair.publicKey keys)
          <> Box.unCipherText (Box.encrypt shared nonce plain)
        kind = if isJust extra then PacketKind.GroupAnnounceRequest else PacketKind.AnnounceRequest
    sendThroughPath path (NodeInfo.address to) $
      BS.cons (PacketKind.kindToByte kind) request
    countRequest (case target of
      Self          -> AnnounceUs
      Friend _      -> SearchFriend
      GroupSearch _ -> SearchGroup) (BS.length request + 1)
    modifyOnion $ \st -> st { sendbacks = sendbacks' }
  return (Path.pathNum <$> mPath)

sendThroughPath :: OnionNodeMonad m => OnionPath -> SocketAddress -> BS.ByteString -> m ()
sendThroughPath path dest bytes = case Path.pathNodes path of
  nodeA : _ -> do
    nonce <- randomNonce
    if NodeInfo.protocol nodeA == TCP
    then do
      layers <- Path.wrapLayers path dest nonce bytes
      sendOnionViaRelay nodeA $ Sodium.encode nonce <> encodeStrict layers
    else do
      request <- Path.wrapPath path dest nonce bytes
      sendPacket nodeA $ Packet PacketKind.OnionRequest0 request
    zoomOnionPath $ Path.markPathUsed (Path.pathNum path)
  [] -> return ()

handleAnnounceResponse :: OnionNodeMonad m => BS.ByteString -> m ()
handleAnnounceResponse payload = do
  s <- getOnionState
  now <- askTime
  case decodeStrict payload of
    Nothing -> return ()
    Just (res :: RPC.AnnounceResponse) -> do
      let (mSendback, sendbacks') = PingArray.takeEntry now (RPC.announceResponseSendbackData res) (sendbacks s)
      putOnionState s { sendbacks = sendbacks' }
      forM_ mSendback $ \(Sendback target from pathNum) -> do
        let keys = case target of
              Self           -> Just $ ourRealKeys s
              Friend pk      -> ofTempKeys <$> Map.lookup pk (onionFriends s)
              GroupSearch pk -> ogTempKeys <$> Map.lookup pk (onionGroups s)
        forM_ keys $ \kp -> do
          shared <- getCombinedKey (KeyPair.secretKey kp) (NodeInfo.publicKey from)
          let decrypted = Box.decrypt shared (RPC.announceResponseNonce res) (RPC.announceResponseEncryptedPayload res)
          forM_ (decrypted >>= Box.decode) $ \(plain :: RPC.AnnounceResponsePayload) ->
            handleAnnounceResult target from pathNum plain

handleAnnounceResult :: OnionNodeMonad m
                     => Target -> NodeInfo -> Word32 -> RPC.AnnounceResponsePayload -> m ()
handleAnnounceResult target from pathNum plain = do
  zoomOnionPath $ Path.markPathConfirmed pathNum
  let pingIdOrKey = RPC.announceResponsePingId plain
      (status, pingId) = case RPC.announceResponseIsStored plain of
        1 -> (StoresFriend pingIdOrKey, Nothing)
        2 -> (StoresUs, Just pingIdOrKey)
        _ -> (NotStored, Just pingIdOrKey)
  s <- getOnionState
  now <- askTime
  let key = targetKey s target
      held pk = maybe False (not . null . friendHolders) . Map.lookup pk . onionFriends
      old = Map.findWithDefault (newOnionNode from) (NodeInfo.publicKey from) (targetNodes s target)
      -- A node we asked outside the target's nodes was asked just now.
      node = old { onStatus = status, onPingId = pingId, onPathNum = Just pathNum, onUnanswered = 0, onAnswered = True
                 , onLastSent = Just $ fromMaybe now (onLastSent old) }
      -- As in toxcore, only a LAN node may tell us about LAN nodes.
      offered = [ n | n <- RPC.announceResponseNodes plain
                    , SocketAddress.isLan (NodeInfo.address from) || not (SocketAddress.isLan $ NodeInfo.address n) ]
      -- A friend's nodes must answer first.
      found = case target of
        Friend _ -> Map.empty
        _        -> Map.fromList [ (NodeInfo.publicKey n, newOnionNode n) | n <- offered ]
      nodes = closestNodes now (maxTargetNodes target) key $
        Map.insert (NodeInfo.publicKey from) node (targetNodes s target) `Map.union` found
  -- Build paths from nodes that worked, not ones we were told about.
  path <- zoomOnionPath $ Path.findPath pathNum
  addPathNodes $ from : maybe [] Path.pathNodes path
  when (status /= onStatus old) $ logDebug $ "Onion node " <> pack (show $ NodeInfo.publicKey from)
    <> " for " <> pack (show target) <> ": " <> pack (show status)
  modifyOnion $ setTargetNodes target nodes
  case target of
    Friend pk -> do
      forM_ offered $ \n -> getsOnion (Map.lookup pk . onionFriends) >>=
        mapM_ (\f -> when (worthAsking now pk f n) . void $ askOther pk n)
      reschedule pk
      nowHeld <- getsOnion (held pk)
      when (nowHeld && not (held pk s)) $ friendHeld pk
    Self -> do
      -- The first answer through our paths: the searches we skipped can go.
      works <- getsOnion (onionWorks now)
      when (works && not (onionWorks now s)) searchAfresh
      -- A node's first ping ID goes back at once, so being stored takes a
      -- round trip, not the unstored interval. Later ones wait for it, so a
      -- node that won't store us can't make us ask as fast as it answers.
      when (status == NotStored && isNothing (onPingId old)) $
        getsOnion (Map.lookup (NodeInfo.publicKey from) . selfNodes) >>= mapM_ (void . sendAnnounceRequest Self)
      closerNow
    GroupSearch _ -> closerNow
  where
    -- Closer nodes now, as for friends, not at the next upkeep: each step
    -- towards the key would wait for it.
    closerNow = announce target


{-------------------------------------------------------------------------------
 -
\end{code}

If we find peers (more than 1) that know a friend we will send them an onion
data packet with our DHT public key, up to 2 TCP relays we are connected to and
2 DHT peers close to us to help the friend connect back to us.

Onion data packets are packets sent as the data of data to route packets.

Onion data packets:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{32}        & Long term public key of sender \\
  variable           & Payload \\
\end{tabular}

The payload is encrypted with long term private key of the sender, the long
term public key of the receiver and the nonce used in the data to route request
packet used to send this onion data packet (shaves off 24 bytes).

DHT public key packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x9c) \\
  \texttt{8}         & \texttt{uint64\_t} \texttt{no\_replay} \\
  \texttt{32}        & Our DHT public key \\
  \texttt{[39, 204]} & Maximum of 4 nodes in packed format \\
\end{tabular}

The packet will only be accepted if the \texttt{no\_replay} number is greater
than the \texttt{no\_replay} number in the last packet received.

The nodes sent in the packet comprise 2 TCP relays to which we are
connected (or fewer if there are not 2 available) and a number of DHT nodes
from our Close List, with the total number of nodes sent being at most 4. The
nodes chosen from the Close List are those closest in DHT distance to us. This
allows the friend to find us more easily in the DHT, or to connect to us via a
TCP relay.

Why another round of encryption? We have to prove to the receiver that we own
the long term public key we say we own when sending them our DHT public key.
Friend requests are also sent using onion data packets but their exact format
is explained in Messenger.

The \texttt{no\_replay} number is protection if someone tries to replay an older
packet and should be set to an always increasing number.  It is 8 bytes so you
should set a high resolution monotonic time as the value.

We send this packet every 30 seconds if there is more than one peer (in the 8)
that says they our friend is announced on them.  This packet can also be sent
through the DHT module as a DHT request packet (see DHT) if we know the DHT
public key of the friend and are looking for them in the DHT but have not
connected to them yet.  30 second is a reasonable timeout to not flood the
network with too many packets while making sure the other will eventually
receive the packet.  Since packets are sent through every peer that knows the
friend, resending it right away without waiting has a high likelihood of
failure as the chances of packet loss happening to all (up to to 8) packets
sent is low.

When sent as a DHT request packet (this is the data sent in the DHT request
packet):

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x9c) \\
  \texttt{32}        & Long term public key of sender \\
  \texttt{24}        & Nonce \\
  variable           & Encrypted payload \\
\end{tabular}

The payload is encrypted with long term private key of sender, the long term
public key of receiver and the nonce, and contains the DHT public key packet.

When sent as a DHT request packet the DHT public key packet is (before being
sent as the data of a DHT request packet) encrypted with the long term keys of
both the sender and receiver and put in that format.  This is done for the same
reason as the double encryption of the onion data packet.

Toxcore tries to resend this packet through the DHT every 20 seconds.  20
seconds is a reasonable resend rate which isn't too aggressive.

Toxcore has a DHT request packet handler that passes received DHT public key
packets from the DHT module to this module.

If we receive a DHT public key packet, we will first check if the DHT packet is
from a friend, if it is not from a friend, it will be discarded.  The
\texttt{no\_replay} will then be checked to see if it is good and no packet with
a lower one was received during the session.  The DHT key, the TCP nodes in the
packed nodes and the DHT nodes in the packed nodes will be passed to their
relevant modules.  The fact that we have the DHT public key of a friend means
this module has achieved its goal.

If a friend is online and connected to us, the onion will stop all of its
actions for that friend.  If the peer goes offline it will restart searching
for the friend as if toxcore was just started.

If toxcore goes offline (no onion traffic for 75 seconds) toxcore will
aggressively reannounce itself and search for friends as if it was just
started.

\begin{code}
 - :: Onion data.
 -
 ------------------------------------------------------------------------------}

-- | Our DHT key and nodes near us, so the friend can find our address.
dhtPkData :: OnionNodeMonad m => m BS.ByteString
dhtPkData = do
  ourDhtPk <- KeyPair.publicKey <$> getDhtKeyPair
  relays <- take (maxSentNodes `div` 2) <$> getTcpRelays
  close <- getCloseNodes (maxSentNodes - length relays) ourDhtPk
  let nodes = relays ++ close
  now <- askTime
  return $ LBS.toStrict $ Put.runPut $ do
    Put.putWord8 packetIdDhtPk
    Put.putWord64be $ Time.timestampToMicroseconds now `div` 1000000
    Binary.put ourDhtPk
    mapM_ Binary.put nodes

-- | Through every node that stores them.
sendDhtPkIfDue :: OnionNodeMonad m => PublicKey -> m ()
sendDhtPkIfDue friendPk = do
  now <- askTime
  mFriend <- getsOnion $ Map.lookup friendPk . onionFriends
  forM_ mFriend $ \f ->
    when (not (null (friendHolders f)) && Time.due now (dhtPkInterval (ofDhtPkSends f)) (ofLastDhtPkSent f)) $ do
      sent <- dhtPkData >>= sendToFriend DhtKeyByOnion friendPk
      when (sent > 0) $ do
        logDebug $ "Sent our DHT public key to " <> pack (show friendPk)
        let sentNow f' = f' { ofLastDhtPkSent = Just now, ofDhtPkSends = ofDhtPkSends f' + 1 }
        modifyOnion $ \s -> s { onionFriends = Map.adjust sentNow friendPk (onionFriends s) }
  forM_ (mFriend >>= \f -> (,) f <$> ofDhtPk f) $ \(f, friendDhtPk) ->
    when (Time.due now dhtPkDhtSendInterval (ofLastDhtPkDhtSent f)) $ do
      sent <- dhtPkData >>= sendDhtPkViaDht friendPk friendDhtPk
      when (sent > 0) $
        modifyOnion $ \s ->
          s { onionFriends = Map.adjust (\f' -> f' { ofLastDhtPkDhtSent = Just now }) friendPk (onionFriends s) }

-- | In a DHT request to the friend's DHT node, encrypted with our real keys.
sendDhtPkViaDht :: OnionNodeMonad m => PublicKey -> PublicKey -> BS.ByteString -> m Int
sendDhtPkViaDht friendPk friendDhtPk dat = do
  realKeys <- getsOnion ourRealKeys
  shared <- getCombinedKey (KeyPair.secretKey realKeys) friendPk
  nonce <- randomNonce
  let request = BS.cons packetIdDhtPk (encodeStrict $ KeyPair.publicKey realKeys)
        <> Sodium.encode nonce <> Box.unCipherText (Box.encrypt shared nonce (PlainText dat))
  sent <- sendDhtRequest friendDhtPk request
  replicateM_ sent $ countRequest DhtKeyByDht (BS.length request)
  return sent

-- | Through the nodes that store their announcement, if enough of the nodes
-- near them do. Gives how many nodes it went through.
sendToFriend :: OnionNodeMonad m => Purpose -> PublicKey -> BS.ByteString -> m Int
sendToFriend purpose friendPk bytes = do
  holders <- getsOnion $ maybe [] friendHolders . Map.lookup friendPk . onionFriends
  forM_ holders $ \(node, dataPk) -> sendOnionData purpose friendPk node dataPk bytes
  return $ length holders

-- | The nodes that store the friend's announcement and their data keys, if
-- enough of the friend's nodes do.
friendHolders :: OnionFriend -> [(NodeInfo, PublicKey)]
friendHolders f
  | length holders < (length nodes - 1) `div` 4 + 1 = []
  | otherwise = holders
  where
    nodes = Map.elems (ofNodes f)
    holders = [ (onNode n, dataPk) | n <- nodes, StoresFriend dataPk <- [onStatus n] ]

-- | Through a node that stores their announcement.
sendOnionData :: OnionNodeMonad m => Purpose -> PublicKey -> NodeInfo -> PublicKey -> BS.ByteString -> m ()
sendOnionData purpose friendPk node dataPk bytes = do
  realKeys <- getsOnion ourRealKeys
  nonce <- randomNonce
  tempKeys <- newKeyPair
  innerKey <- getCombinedKey (KeyPair.secretKey realKeys) friendPk
  outerKey <- getCombinedKey (KeyPair.secretKey tempKeys) dataPk
  let inner = RPC.DataRouteInner (KeyPair.publicKey realKeys) (Box.encrypt innerKey nonce (PlainText bytes))
      request = RPC.DataRouteRequest friendPk nonce (KeyPair.publicKey tempKeys)
        (Box.encrypt outerKey nonce (Box.encode inner))
  mPath <- zoomOnionPath $ Path.selectPath False
  forM_ mPath $ \path -> do
    sendThroughPath path (NodeInfo.address node) $
      BS.cons (PacketKind.kindToByte PacketKind.OnionDataRequest) (encodeStrict request)
    countRequest purpose (BS.length bytes)

handleDataResponse :: OnionNodeMonad m => BS.ByteString -> m [OnionEvent]
handleDataResponse payload = do
  s <- getOnionState
  case decodeStrict payload of
    Nothing -> return []
    Just (res :: RPC.DataRouteResponse) -> do
      let nonce = RPC.dataRouteResponseNonce res
      outerKey <- getCombinedKey (KeyPair.secretKey $ ourDataKeys s) (RPC.dataRouteResponseTemporaryKey res)
      case Box.decrypt outerKey nonce (RPC.dataRouteResponseEncryptedPayload res) >>= Box.decode of
        Nothing -> return []
        Just (inner :: RPC.DataRouteInner) -> do
          let senderPk = RPC.dataRouteInnerSenderPublicKey inner
          innerKey <- getCombinedKey (KeyPair.secretKey $ ourRealKeys s) senderPk
          case Box.decrypt innerKey nonce (RPC.dataRouteInnerEncryptedPayload inner) of
            Just (PlainText bytes) | Just (ident, rest) <- BS.uncons bytes ->
              if | ident == packetIdDhtPk         -> handleDhtPk senderPk rest
                 | ident == packetIdFriendRequest -> return [FriendRequestReceived senderPk rest]
                 | otherwise                      -> return []
            _ -> return []

-- | Addressed to us. Friends also send their DHT key this way once they know
-- ours.
handleDhtRequest :: OnionNodeMonad m => BS.ByteString -> m [OnionEvent]
handleDhtRequest payload = do
  ourDht <- getDhtKeyPair
  realKeys <- getsOnion ourRealKeys
  case decodeStrict payload of
    Just (DhtRequestPacket addressee dhtPkt) | addressee == KeyPair.publicKey ourDht -> do
      plain <- DhtPacket.decryptKeyed ourDht dhtPkt
      case plain of
        Just (PlainText bytes) | Just (ident, rest) <- BS.uncons bytes, ident == packetIdDhtPk
                               , (senderBytes, rest') <- BS.splitAt 32 rest
                               , (nonceBytes, sealed) <- BS.splitAt 24 rest'
                               , Just senderPk <- Sodium.decode senderBytes
                               , Just nonce <- Sodium.decode nonceBytes
                               , Just ct <- Tunnel.cipherTextMaybe sealed -> do
          shared <- getCombinedKey (KeyPair.secretKey realKeys) senderPk
          case Box.decrypt shared nonce ct of
            Just (PlainText dhtPkBytes)
              | Just (ident', dhtPkPacket) <- BS.uncons dhtPkBytes, ident' == packetIdDhtPk
              , BS.take 32 (BS.drop 8 dhtPkPacket) == Sodium.encode (DhtPacket.senderPublicKey dhtPkt) ->
              handleDhtPk senderPk dhtPkPacket
            _ -> return []
        _ -> return []
    _ -> return []

handleDhtPk :: OnionNodeMonad m => PublicKey -> BS.ByteString -> m [OnionEvent]
handleDhtPk senderPk bytes = do
  mFriend <- getsOnion $ Map.lookup senderPk . onionFriends
  case (mFriend, decodeStrict bytes) of
    (Just f, Just (pkt :: RPC.DHTPublicKeyPacket)) | RPC.dhtPKPacketNoReplay pkt > ofLastNoReplay f -> do
      let f' = f { ofLastNoReplay = RPC.dhtPKPacketNoReplay pkt, ofDhtPk = Just (RPC.dhtPKPacketOurDHTKey pkt) }
      modifyOnion $ \s -> s { onionFriends = Map.insert senderPk f' (onionFriends s) }
      reschedule senderPk
      logInfo $ "Received DHT public key of " <> pack (show senderPk)
      return [FriendDhtPkFound senderPk (RPC.dhtPKPacketOurDHTKey pkt) (RPC.dhtPKPacketNodes pkt)]
    _ -> return []


{-------------------------------------------------------------------------------
 -
 - :: Announce node.
 -
 ------------------------------------------------------------------------------}

-- | Ties an announcement to the announcing key and the path's last relay.
-- Changes every 'announceTimeout'.
pingIdAt :: OnionState -> Integer -> PublicKey -> SocketAddress -> PublicKey
pingIdAt s period pk from =
  fromJust . Sodium.decode . BS.take 32 . Hash.hash $
    pingIdSecret s <> encodeStrict period <> encodeStrict pk <> encodeStrict (Tunnel.OnionIPPort from)

pingIdPeriod :: Timestamp -> Integer
pingIdPeriod now = toInteger (Time.timestampToMicroseconds now) `div` (1000 * Time.toMilliseconds announceTimeout)

-- | Like toxcore, store the sender if its ping ID is valid, and say whether
-- we store it or the key it searches for.
answerAnnounce :: OnionNodeMonad m
               => SocketAddress -> PublicKey -> BS.ByteString -> RPC.AnnounceRequestPayload
               -> m (Word8, PublicKey, [NodeInfo])
answerAnnounce from senderPk ret plain = do
  s <- getOnionState
  ourDht <- getDhtKeyPair
  now <- askTime
  let period = pingIdPeriod now
      pingId = pingIdAt s period senderPk from
      valid = RPC.announceRequestPingId plain `elem` [pingId, pingIdAt s (period - 1) senderPk from]
      searchKey = RPC.announceRequestSearchKey plain
      dataPk = RPC.announceRequestDataSendbackKey plain
      live = Map.filter (\e -> Time.addTime (aeTime e) announceTimeout > now) (announceEntries s)
      entries
        | valid = Map.fromList . take maxAnnounceEntries
            . sortOn (Distance.xorDistance (KeyPair.publicKey ourDht) . fst)
            . Map.toList $ Map.insert senderPk (AnnounceEntry dataPk from ret now) live
        | otherwise = live
      entryKey = if valid then senderPk else searchKey
      (status, pingIdOrKey) = case Map.lookup entryKey entries of
        Just e | entryKey /= senderPk -> (1, aeDataPk e)
               | aeDataPk e == dataPk -> (2, pingId)
        _ -> (0, pingId)
  putOnionState s { announceEntries = entries }
  nodes <- getCloseNodesFor from maxSentNodes searchKey
  return (status, pingIdOrKey, nodes)

-- | Followed by the return data of its path.
handleAnnounceRequest :: OnionNodeMonad m => SocketAddress -> BS.ByteString -> m ()
handleAnnounceRequest from payload = do
  let (requestBytes, ret) = BS.splitAt announceRequestLength payload
  ourDht <- getDhtKeyPair
  case decodeStrict requestBytes of
    Just (req :: RPC.AnnounceRequest) | BS.length ret == Tunnel.returnSize 3 -> do
      let senderPk = RPC.announceRequestSenderPublicKey req
      shared <- getCombinedKey (KeyPair.secretKey ourDht) senderPk
      let decrypted = Box.decrypt shared (RPC.announceRequestNonce req) (RPC.announceRequestEncryptedPayload req)
            >>= Box.decode
      forM_ decrypted $ \(plain :: RPC.AnnounceRequestPayload) -> do
        (status, pingIdOrKey, nodes) <- answerAnnounce from senderPk ret plain
        nonce <- randomNonce
        let response = RPC.AnnounceResponse
              { RPC.announceResponseSendbackData = RPC.announceRequestSendbackData plain
              , RPC.announceResponseNonce = nonce
              , RPC.announceResponseEncryptedPayload =
                  Box.encrypt shared nonce . Box.encode $ RPC.AnnounceResponsePayload status pingIdOrKey nodes
              }
        sendTo from . Tunnel.responseToReturn ret $
          BS.cons (PacketKind.kindToByte PacketKind.AnnounceResponse) (encodeStrict response)
    _ -> return ()

-- | To the announcer, along its stored path.
handleDataRequest :: OnionNodeMonad m => BS.ByteString -> m ()
handleDataRequest payload = do
  let (request, ret) = BS.splitAt (BS.length payload - Tunnel.returnSize 3) payload
      (destBytes, forwarded) = BS.splitAt 32 request
  entries <- getsOnion announceEntries
  now <- askTime
  case Sodium.decode destBytes of
    Just dest | BS.length request > dataRequestMinLength, BS.length ret == Tunnel.returnSize 3
              , Just e <- Map.lookup dest entries, Time.addTime (aeTime e) announceTimeout > now ->
      sendTo (aeAddress e) . Tunnel.responseToReturn (aeReturn e) $
        BS.cons (PacketKind.kindToByte PacketKind.OnionDataResponse) forwarded
    _ -> return ()


{-------------------------------------------------------------------------------
 -
 - :: Dispatch.
 -
 ------------------------------------------------------------------------------}

-- | Relay it, answer it as an announce node, or take a response to our own
-- requests.
handleOnionPacket :: OnionNodeMonad m => SocketAddress -> Packet BS.ByteString -> m [OnionEvent]
handleOnionPacket from (Packet kind payload) = case kind of
  PacketKind.OnionRequest0     -> [] <$ relayRequest 1
  PacketKind.OnionRequest1     -> [] <$ relayRequest 2
  PacketKind.OnionRequest2     -> [] <$ relayRequest 3
  PacketKind.OnionResponse3    -> [] <$ relayResponse 3
  PacketKind.OnionResponse2    -> [] <$ relayResponse 2
  PacketKind.OnionResponse1    -> [] <$ relayResponse 1
  PacketKind.AnnounceRequest   -> [] <$ handleAnnounceRequest from payload
  PacketKind.OnionDataRequest  -> [] <$ handleDataRequest payload
  PacketKind.AnnounceResponse  -> [] <$ handleAnnounceResponse payload
  PacketKind.GroupAnnounceRequest  -> [] <$ handleGroupAnnounceRequest from payload
  PacketKind.GroupAnnounceResponse -> handleGroupAnnounceResponse payload
  PacketKind.OnionDataResponse -> handleDataResponse payload
  _                            -> return []
  where
    -- Drop bigger packets, as toxcore relays do.
    tooBig = 1 + BS.length payload > maxOnionPacketSize
    relayRequest hop = unless tooBig $ do
      ourDht <- getDhtKeyPair
      retKey <- getsOnion returnKey
      nonce <- randomNonce
      relayed <- Tunnel.relayRequest ourDht retKey nonce hop from payload
      forwardRelayed relayed
    relayResponse hop = unless tooBig $ do
      retKey <- getsOnion returnKey
      forwardRelayed $ Tunnel.relayResponse retKey hop payload

keyBytes :: CryptoNumber a => Key a -> BS.ByteString
keyBytes = Sodium.encode

addGroupSearch :: OnionNodeMonad m => PublicKey -> BS.ByteString -> m ()
addGroupSearch searchKey chatId = do
  tempKeys <- newKeyPair
  let group = OnionGroup { ogTempKeys = tempKeys, ogNodes = Map.empty, ogChatId = chatId, ogAnnounce = Nothing }
  modifyOnion $ \s -> s { onionGroups = Map.insert searchKey group (onionGroups s) }

removeGroupSearch :: OnionNodeMonad m => PublicKey -> m ()
removeGroupSearch searchKey = modifyOnion $ \s -> s { onionGroups = Map.delete searchKey (onionGroups s) }

-- | Sets the announcement of the group with this search key.
setGroupAnnounce :: OnionNodeMonad m => PublicKey -> Maybe BS.ByteString -> m ()
setGroupAnnounce searchKey announcement = modifyOnion $ \s ->
  s { onionGroups = Map.adjust (\g -> g { ogAnnounce = announcement }) searchKey (onionGroups s) }

-- | An announce response with group announcements (toxcore's 0x88).
handleGroupAnnounceResponse :: OnionNodeMonad m => BS.ByteString -> m [OnionEvent]
handleGroupAnnounceResponse payload = do
  s <- getOnionState
  now <- askTime
  let sendback = Get.runGetOrFail Get.getWord64be (LBS.fromStrict payload)
  case (sendback, Sodium.decode (BS.take 24 $ BS.drop 8 payload)) of
    (Right (_, _, sendbackId), Just nonce) -> do
      let (mSendback, sendbacks') = PingArray.takeEntry now sendbackId (sendbacks s)
      putOnionState s { sendbacks = sendbacks' }
      case mSendback of
        Just (Sendback target@(GroupSearch k) from pathNum) | Just group <- Map.lookup k (onionGroups s) -> do
          shared <- getCombinedKey (KeyPair.secretKey $ ogTempKeys group) (NodeInfo.publicKey from)
          case Tunnel.cipherTextMaybe (BS.drop 32 payload) >>= Box.decrypt shared nonce of
            Just (Box.PlainText plain)
              | Just (isStored, key, nodes, announces) <- parseGroupResponse plain, isStored < 2 -> do
              handleAnnounceResult target from pathNum (RPC.AnnounceResponsePayload isStored key nodes)
              return [ GroupAnnouncesFound (ogChatId group) announces | not (BS.null announces) ]
            _ -> return []
        _ -> return []
    _ -> return []
  where
    parseGroupResponse = fmap (\(rest, _, r) -> let (a, b, c) = r in (a, b, c, LBS.toStrict rest))
      . either (const Nothing) Just . Get.runGetOrFail getHead . LBS.fromStrict
    getHead = do
      isStored <- Get.getWord8
      key <- Binary.get
      count <- Get.getWord8
      when (fromIntegral count > maxSentNodes) $ fail "too many nodes"
      nodes <- replicateM (fromIntegral count) Binary.get
      return (isStored, key, nodes)

-- | May carry a group announcement, as toxcore's 0x87. We store it and answer
-- with the group's other announcements.
handleGroupAnnounceRequest :: OnionNodeMonad m => SocketAddress -> BS.ByteString -> m ()
handleGroupAnnounceRequest from payload = do
  let (request, ret) = BS.splitAt (BS.length payload - Tunnel.returnSize 3) payload
      (nonceBytes, rest) = BS.splitAt 24 request
      (senderBytes, sealed) = BS.splitAt 32 rest
  ourDht <- getDhtKeyPair
  case (Sodium.decode nonceBytes, Sodium.decode senderBytes, Tunnel.cipherTextMaybe sealed) of
    (Just nonce, Just senderPk, Just ct) | BS.length ret == Tunnel.returnSize 3 -> do
      shared <- getCombinedKey (KeyPair.secretKey ourDht) senderPk
      case Box.decrypt shared nonce ct of
        Just (Box.PlainText plain) | (fields, extra) <- BS.splitAt announceRequestSize plain
                                   , Just (req :: RPC.AnnounceRequestPayload) <- decodeStrict fields
                                   , BS.length extra <= maxExtraDataSize -> do
          others <- if BS.null extra then return (Just []) else storeGroupAnnounce extra
          forM_ others $ \announces -> do
            (status, pingIdOrKey, nodes) <- answerAnnounce from senderPk ret req
            responseNonce <- randomNonce
            let body = LBS.toStrict . Put.runPut $ do
                  Put.putWord8 status
                  Binary.put pingIdOrKey
                  Put.putWord8 (fromIntegral $ length nodes)
                  mapM_ Binary.put nodes
                sealedResponse = Box.unCipherText . Box.encrypt shared responseNonce $
                  Box.PlainText (body <> BS.concat announces)
            sendTo from $ Tunnel.responseToReturn ret $ BS.concat
              [ BS.singleton (PacketKind.kindToByte PacketKind.GroupAnnounceResponse)
              , encodeStrict (RPC.announceRequestSendbackData req), keyBytes responseNonce, sealedResponse ]
        _ -> return ()
    _ -> return ()

-- | Chat ID and how to reach the peer, stored as we parsed it so others only
-- get announcements they can read. Gives the group's other announcements.
storeGroupAnnounce :: OnionNodeMonad m => BS.ByteString -> m (Maybe [BS.ByteString])
storeGroupAnnounce publicAnnounce = do
  now <- askTime
  s <- getOnionState
  let (chatId, announced) = BS.splitAt 32 publicAnnounce
      existing = Map.lookup chatId (storedGroups s)
      announces = maybe [] sgAnnounces existing
  case GroupAnnounce.unpackAnnounce announced of
    Just peer | isJust existing || Map.size (storedGroups s) < maxStoredGroups -> do
      let peerPk = GroupAnnounce.anPk peer
          others = take maxSentAnnounces . nubBy ((==) `on` fst) $ filter ((/= peerPk) . fst) announces
      let stored = StoredGroup (take maxStoredAnnounces $ (peerPk, GroupAnnounce.packAnnounce peer) : announces) now
      putOnionState s { storedGroups = Map.insert chatId stored (storedGroups s) }
      return . Just $ map snd others
    _ -> return Nothing

-- | From a client of our TCP relay. We relay it as the first node.
handleTcpOnionRequest :: OnionNodeMonad m => Word64 -> BS.ByteString -> m ()
handleTcpOnionRequest client payload = do
  retKey <- getsOnion returnKey
  nonce <- randomNonce
  forwardRelayed $ Tunnel.relayTcpRequest retKey nonce client payload

forwardRelayed :: OnionNodeMonad m => Maybe Tunnel.Relayed -> m ()
forwardRelayed = mapM_ $ \(Tunnel.Relayed to pkt) -> case to of
  Tunnel.ToUdp addr         -> sendTo addr pkt
  Tunnel.ToTcpClient client -> sendToTcpClient client (encodeStrict pkt)
\end{code}
