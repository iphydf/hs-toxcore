{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
{-# LANGUAGE TupleSections       #-}
-- | Tox instance like toxcore's tox.h. Runs the network on its own threads,
-- takes commands and reports events. Friends are identified by public key.
module Tox.Application.Tox
    ( Tox
    , Options (..)
    , Proxy (..)
    , ProxyType (..)
    , SaveData (..)
    , defaultOptions
    , Event (..)
    , ConnectionStatus (..)
    , FriendInfo (..)
    , Messenger.MessageType (..)
    , Messenger.UserStatus (..)
    , Messenger.AddFriendError (..)
    , Messenger.SendMessageError (..)
    , Messenger.FileRef (..)
    , Messenger.fileKindData
    , Messenger.fileKindAvatar
    , Messenger.FileControl (..)
    , Messenger.FileError (..)
    , NewError (..)
    , ToxStopped (..)
    , new
    , kill
    , nextEvent
      -- * Network
    , bootstrap
    , addTcpRelay
    , resolveNode
    , selfConnectionStatus
    , selfUdpPort
    , selfDhtId
  , nextInput
  , Shell (..)
  , TcpIo (..)
  , noTcpIo
  , noTcpServerIo
  , flush
  , queueBytes
  , maxQueuedBytes
  , maxWaitingEvents
      -- * Profile
    , saveData
    , selfPublicKey
    , selfSecretKey
    , selfAddress
    , selfGetNospam
    , selfSetNospam
    , maxNameLength
    , maxStatusMessageLength
    , selfGetName
    , selfSetName
    , selfGetStatusMessage
    , selfSetStatusMessage
    , selfGetStatus
    , selfSetStatus
      -- * Friends
    , parseAddress
    , friendAdd
    , friendAddNoRequest
    , maxFriendRequestLength
    , friendDelete
    , friendList
    , friendInfo
    , friendSendMessage
    , maxMessageLength
    , friendSetTyping
    , Messenger.CustomPacketError (..)
    , friendSendLosslessPacket
    , friendSendLossyPacket
    , friendQueueLosslessPacket
    , friendQueueLossyPacket
      -- * Conferences
    , Conference.ConferenceNumber
    , Conference.PeerNumber
    , Conference.JoinError (..)
    , ConferencePeer (..)
    , conferenceNew
    , conferenceInvite
    , conferenceJoin
    , conferenceDelete
    , conferenceSendMessage
    , conferenceSetTitle
    , conferenceTitle
    , conferencePeers
    , conferenceList
    , conferenceId
    , conferenceSave
    , conferenceRestore
      -- * Groups
    , Group.PeerId
    , Group.ExitType (..)
    , Group.JoinFail (..)
    , Group.AcceptError (..)
    , Group.GroupSendError (..)
    , Group.Role (..)
    , Group.Moderation (..)
    , Group.Voice (..)
    , Group.ModError (..)
    , GroupPeer (..)
    , GroupSettings (..)
    , GroupPackets.maxGroupNameSize
    , GroupPackets.maxPasswordSize
    , groupNew
    , groupInviteFriend
    , groupJoin
    , groupChatId
    , groupInviteAccept
    , groupSendMessage
    , groupSendPrivateMessage
    , groupSendCustomPacket
    , groupSendCustomPrivatePacket
    , groupSetTopic
    , groupMayTopic
    , groupSelfRole
    , groupSelfPublicKey
    , groupPeerCanSpeak
    , groupSettings
    , groupTopic
    , groupName
    , groupSetNick
    , groupSetStatus
    , groupPeers
    , groupLeave
    , groupList
    , groupSave
    , groupRestore
    , groupKickPeer
    , groupSetRole
    , groupSetPassword
    , groupSetPeerLimit
    , groupSetPrivacy
    , groupSetTopicLock
    , groupSetVoice
      -- * Files
    , fileSend
    , fileControl
    , fileSeek
    , fileSendChunk
      -- * Debugging
    , Sizes.Size (..)
    , Sizes.overLimit
    , sizes
    , Lanes.Lane (..)
    , timings
    , Traffic.Counted (..)
    , Traffic.Way (..)
    , Traffic.Carrier (..)
    , Traffic.Purpose (..)
    , Traffic.Count (..)
    , Traffic.countedName
    , Traffic.kindName
    , Traffic.purposeName
    , traffic
    ) where

import           Control.Concurrent                 (ThreadId, forkFinally,
                                                     forkIO, killThread,
                                                     threadDelay)
import           Control.Concurrent.Chan            (Chan, newChan, readChan,
                                                     writeChan)
import           Control.Concurrent.MVar            (MVar, modifyMVar_,
                                                     newEmptyMVar, newMVar,
                                                     readMVar, swapMVar,
                                                     takeMVar, tryPutMVar,
                                                     withMVar)
import           Control.Concurrent.STM             (TBQueue, TMVar, TQueue,
                                                     TVar, atomically,
                                                     isFullTBQueue, modifyTVar',
                                                     newEmptyTMVarIO,
                                                     newTBQueueIO, newTQueueIO,
                                                     newTVarIO, orElse,
                                                     putTMVar, readTBQueue,
                                                     readTMVar, readTQueue,
                                                     readTVarIO, tryReadTBQueue,
                                                     writeTBQueue, writeTQueue)
import           Control.Exception                  (AsyncException (..),
                                                     Exception, IOException,
                                                     evaluate, finally,
                                                     fromException, handle,
                                                     onException, throwIO, try)
import           Control.Monad                      (forM, forM_, forever,
                                                     unless, void, when, (<=<))
import           Control.Monad.Random               (evalRandT)
import           Control.Monad.State                (modify)
import           Data.Bifunctor                     (first)
import qualified Data.Binary                        as Binary
import           Data.Bool                          (bool)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.Functor.Identity              (runIdentity)
import           Data.IORef                         (IORef, atomicModifyIORef',
                                                     newIORef, readIORef)
import           Data.List                          (uncons)
import qualified Data.Map                           as Map
import           Data.Maybe                         (isJust)
import           Data.Text                          (Text, pack)
import           Data.Word                          (Word16, Word32, Word64,
                                                     Word8, byteSwap32)
import           GHC.Conc                           (labelThread, myThreadId)
import           GHC.IO.Exception                   (IOErrorType (..), ioe_type)
import qualified System.Clock                       as Clock
import           System.Random                      (mkStdGen)
import           System.Timeout                     (timeout)

import           Tox.Application.Node
import           Tox.Application.Proxy              (Proxy (..), ProxyType (..))
import qualified Tox.Application.Save               as Save
import           Tox.Application.Save               (Profile (..))
import qualified Tox.Application.Sizes              as Sizes
import qualified Tox.Application.Sockets            as Sockets
import           Tox.Application.State
import           Tox.Application.Transport          (Datagrams (..),
                                                     Listener (..), Stream (..))
import qualified Tox.Chat.Conference                as Conference
import qualified Tox.Chat.GroupChat                 as Group
import qualified Tox.Chat.GroupChatPackets          as GroupPackets
import qualified Tox.Core.Lanes                     as Lanes
import           Tox.Core.Lanes                     (Lanes)
import           Tox.Core.Log                       (LogLevel (..))
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (Timestamp, getTime)
import qualified Tox.Crypto.Core.Key                as Key
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes (..))
import qualified Tox.DHT.DhtState                   as DhtState
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.Discovery.LAN          as LAN
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Network.TCP.Server             as Server
import qualified Tox.Persistence.Groups             as PG
import qualified Tox.Session.Connection             as Connection
import qualified Tox.Session.Friend                 as Messenger


{-------------------------------------------------------------------------------
 -
 - :: Types.
 -
 ------------------------------------------------------------------------------}

data Options = Options
  { optUdpEnabled     :: Bool
  , optIpv6Enabled    :: Bool         -- ^ If the system has it.
  , optUdpPorts       :: (Word16, Word16) -- ^ Bind the first free port in this range, (0, 0) for any.
  , optTcpPort        :: Maybe Word16  -- ^ Run a TCP relay on this port.
  , optSaveData       :: SaveData
  , optSeed           :: Maybe Int     -- ^ Make new keys from this seed, for tests.
  , optLocalDiscovery :: Bool
  , optProxy          :: Maybe Proxy -- ^ Reach TCP relays through it.
  , optLogger         :: LogLevel -> Text -> IO ()
    -- ^ Runs on the main loop's thread, so it mustn't wait for the instance
    -- (e.g. by calling it).
  }

defaultOptions :: Options
defaultOptions = Options
  { optUdpEnabled     = True
  , optIpv6Enabled    = True
  , optUdpPorts       = (LAN.portFrom, LAN.portTo)
  , optTcpPort        = Nothing
  , optSaveData       = NoSaveData
  , optSeed           = Nothing
  , optLocalDiscovery = True
  , optProxy          = Nothing
  , optLogger         = \_ _ -> return ()
  }

-- | Like toxcore's savedata types.
data SaveData
  = NoSaveData
  | ToxSave BS.ByteString
    -- ^ In toxcore's save format.
  | SecretKey Key.SecretKey
    -- ^ For clients that save the rest themselves.

data NewError
  = BadSaveData
  | PortInUse
  deriving (Eq, Show)

data FriendInfo = FriendInfo
  { friendPublicKey     :: PublicKey
  , friendName          :: BS.ByteString
  , friendStatusMessage :: BS.ByteString
  , friendStatus        :: Messenger.UserStatus
  , friendTyping        :: Bool
  , friendConnection    :: ConnectionStatus
  , friendLastSeen      :: Word64 -- ^ Unix time we last saw the friend online, 0 for never.
  } deriving (Eq, Show)

-- | Queue for the main loop, and whether it ended. While the queue is full,
-- we drop datagrams, and the rest wait.
data Inputs = Inputs
  { inputQueue :: TBQueue Input
  , loopEnded  :: TMVar ()
  }

maxWaitingInputs :: Int
maxWaitingInputs = 4096

pushInput, offerInput :: Inputs -> Input -> IO ()
pushInput inputs input = atomically $ readTMVar (loopEnded inputs) `orElse` writeTBQueue (inputQueue inputs) input
offerInput inputs input = atomically $
  isFullTBQueue (inputQueue inputs) >>= \full -> unless full (writeTBQueue (inputQueue inputs) input)

data Tox = Tox
  { toxInputs    :: Inputs
  , toxEvents    :: TQueue Event
  , toxPublicKey :: PublicKey
  , toxSecretKey :: Key.SecretKey
  , toxDhtId     :: PublicKey
  , toxUdpPort   :: Word16
  , toxThreads   :: MVar [ThreadId]
  , toxShell     :: Shell
  , toxShutdown  :: IO ()
  , toxLanes     :: Lanes -- ^ Time the main loop spends on each kind of input.
  , toxWaiting   :: TVar Int -- ^ Events the client hasn't taken yet.
  }

-- | The instance was killed, or its main loop died.
data ToxStopped = ToxStopped
  deriving (Eq, Show)

instance Exception ToxStopped


{-------------------------------------------------------------------------------
 -
 - :: Lifecycle.
 -
 ------------------------------------------------------------------------------}

-- | Delays after a failed read or accept, so a lasting failure doesn't spin.
readRetryDelay, acceptRetryDelay :: Int
readRetryDelay = 10000
acceptRetryDelay = 1000000

new :: Options -> IO (Either NewError Tox)
new opts = case optSaveData opts of
  NoSaveData -> startWith opts Nothing Nothing
  ToxSave bytes -> case Binary.decodeOrFail (LBS.fromStrict bytes) of
    Right (_, _, sd) | Just profile <- Save.fromSaveData sd ->
      startWith opts (Just (profileKeys profile)) (Just profile)
    _ -> return $ Left BadSaveData
  SecretKey sk -> startWith opts (Just (KeyPair.fromSecretKey sk)) Nothing

startWith :: Options -> Maybe KeyPair.KeyPair -> Maybe Profile -> IO (Either NewError Tox)
startWith opts keys profile = openSockets >>= \case
  Nothing -> return $ Left PortInUse
  Just (udp, ipv6, inputs, server) -> fmap Right . (`onException` (mapM_ datagramsClose udp >> mapM_ snd server)) $ do
    now <- getTime
    initial <- case optSeed opts of
      Just seed -> return . runIdentity . evalRandT (initial0 now) $ mkStdGen seed
      Nothing   -> initial0 now
    events <- newTQueueIO
    lanes <- Lanes.newLanes
    counts <- Traffic.newTraffic
    waiting <- newTVarIO 0
    (tcp, stopTcp) <- makeTcpIo (optProxy opts) inputs
    threads <- newMVar []
    let shell = Shell udp tcp (maybe noTcpServerIo fst server) counts (optLogger opts)
        fork name action = forkNamed name action >>= \t -> modifyMVar_ threads (return . (t :))
    -- Keep listening after a failed read (some systems report one for an
    -- unreachable peer).
    forM_ udp $ \datagrams -> fork "tox udp" $ forever $ try (datagramsReceive datagrams) >>= \case
      Right (addr, bs)        -> offerInput inputs (Datagram addr bs)
      Left (e :: IOException) -> do
        optLogger opts LevelDebug (pack $ "Receiving failed: " ++ show e)
        threadDelay readRetryDelay
    let ended = \case
          Left e | fromException e /= Just ThreadKilled ->
            optLogger opts LevelError . pack $ "Main loop stopped: " ++ show e
          _ -> return ()
        setup = Setup (optUdpEnabled opts && isJust udp) ipv6 (optLocalDiscovery opts && isJust udp)
        localhost = IPv4 $ tupleToHostAddress (127, 0, 0, 1)
        start = restore profile >> mapM_ (useOwnRelay . SocketAddress localhost . fromIntegral) (optTcpPort opts)
        loop = do
          myThreadId >>= (`labelThread` "tox main loop")
          mainLoop (Loop inputs events waiting lanes shell) (newNode setup now initial) [Command start]
    loopThread <- forkFinally loop (\r -> ended r >> atomically (putTMVar (loopEnded inputs) ()))
    modifyMVar_ threads (return . (loopThread :))
    return Tox
      { toxInputs    = inputs
      , toxEvents    = events
      , toxPublicKey = KeyPair.publicKey . Connection.ourRealKeys $ connManager initial
      , toxSecretKey = KeyPair.secretKey . Connection.ourRealKeys $ connManager initial
      , toxDhtId     = KeyPair.publicKey . DhtState.dhtKeyPair $ dhtState initial
      , toxUdpPort   = maybe 0 datagramsPort udp
      , toxThreads   = threads
      , toxShell     = shell
      , toxShutdown  = mapM_ datagramsClose udp >> stopTcp >> mapM_ snd server
      , toxLanes     = lanes
      , toxWaiting   = waiting
      }
  where
    -- Without UDP, as in browsers, there's no port to take.
    openSockets = do
      let (from, to) = optUdpPorts opts
      opened <- if Sockets.datagramsAvailable
        then fmap (first Just) <$> Sockets.openDatagrams (optIpv6Enabled opts) [from .. to]
        else return $ Just (Nothing, False)
      inputs <- Inputs <$> newTBQueueIO (fromIntegral maxWaitingInputs) <*> newEmptyTMVarIO
      flip (maybe (return Nothing)) opened $ \(udp, ipv6) -> do
        server <- either (\(_ :: IOException) -> Nothing) Just
          <$> try (mapM (makeTcpServerIo (optLogger opts) inputs ipv6) (optTcpPort opts))
        case server of
          Just s  -> return $ Just (udp, ipv6, inputs, s)
          Nothing -> Nothing <$ mapM_ datagramsClose udp
    initial0 :: MonadRandomBytes m => Timestamp -> m GlobalState
    initial0 now = do
      realKeys <- maybe newKeyPair return keys
      dhtKeys <- newKeyPair
      gs <- initState now dhtKeys realKeys
      return $ case profile of
        Nothing -> gs
        Just p -> gs { messenger = (messenger gs)
          { Messenger.selfNospam = profileNospam p
          , Messenger.selfName   = profileName p
          , Messenger.selfMsg    = profileStatusMessage p
          , Messenger.selfStatus = profileStatus p
          } }

-- | Friends see us go offline.
kill :: Tox -> IO ()
kill tox = do
  handle (\ToxStopped -> return ()) $ call tox goodbye
  -- Stop the loop first, so it doesn't open sockets after we close them.
  mapM_ killThread =<< swapMVar (toxThreads tox) []
  toxShutdown tox

-- | After the main loop ends: the events it left, then 'ToxStopped'.
nextEvent :: Tox -> IO Event
nextEvent tox = atomically ((Just <$> taken) `orElse` (Nothing <$ readTMVar ended))
  >>= maybe (throwIO ToxStopped) return
  where
    Inputs _ ended = toxInputs tox
    taken = readTQueue (toxEvents tox) <* modifyTVar' (toxWaiting tox) (subtract 1)

-- | Throws 'ToxStopped' if the loop is not running.
call :: Tox -> App a -> IO a
call tox action = do
  result <- newEmptyMVar
  -- Wait while the queue is full, unless the loop ended.
  let Inputs queue ended = toxInputs tox
  sent <- atomically $ (False <$ readTMVar ended)
    `orElse` (True <$ writeTBQueue queue (Command (action >>= output . Reply . void . tryPutMVar result . Just)))
  unless sent $ throwIO ToxStopped
  watcher <- forkNamed "tox call watcher" $ atomically (readTMVar ended) >> void (tryPutMVar result Nothing)
  takeMVar result `finally` killThread watcher >>= maybe (throwIO ToxStopped) return

-- | Queue an action for the main loop without waiting, while the loop runs.
cast :: Tox -> App () -> IO ()
cast tox = pushInput (toxInputs tox) . Command


{-------------------------------------------------------------------------------
 -
 - :: Main loop.
 -
 ------------------------------------------------------------------------------}

data Loop = Loop
  { loopInputs  :: Inputs
  , loopEvents  :: TQueue Event
  , loopWaiting :: TVar Int
  , loopLanes   :: Lanes
  , loopShell   :: Shell
  }

-- | Takes the next input, or waits for the next job when there's none, then
-- runs the jobs that are due. Jobs run after any input, so inputs coming
-- without a break can't hold them up. What the shell learnt carrying out a
-- step comes first, as the queue may already hold what followed it.
mainLoop :: Loop -> Node -> [Input] -> IO ()
mainLoop loop node learnt = do
  (input, learnt') <- maybe ((, []) <$> nextInput (inputQueue (loopInputs loop)) (nextDeadline node))
    (return . first Just) (uncons learnt)
  ctx <- Context <$> getTime <*> unixTime <*> ((>= maxWaitingEvents) <$> readTVarIO (loopWaiting loop))
  forM_ (inputCounted =<< input) (count (loopShell loop))
  Stepped node' outputs events <- maybe (return (Stepped node [] [])) (timed . inputName <*> flip (handleInput ctx) node) input
  Stepped node'' outputs' events' <- if maybe False (<= ctxTime ctx) (nextDeadline node')
    then timed (pack "Periodic work") (handleDue ctx node')
    else return (Stepped node' [] [])
  news <- flush (loopShell loop) (outputs ++ outputs')
  emitEvents loop (events ++ events')
  mainLoop loop node'' (learnt' ++ news)
  where
    timed name = Lanes.timed (loopLanes loop) name . evaluate

-- | Nothing once the time comes with no input.
nextInput :: TBQueue a -> Maybe Timestamp -> IO (Maybe a)
nextInput queue wake = atomically (tryReadTBQueue queue) >>= \case
  Just input -> return (Just input)
  Nothing -> case wake of
    Nothing -> Just <$> atomically (readTBQueue queue)
    Just time -> do
      now <- getTime
      -- Rounded up, so we don't wake just before it.
      let wait = fromIntegral (Time.timestampToMicroseconds time) - fromIntegral (Time.timestampToMicroseconds now) + 1
      if wait <= 1 then return Nothing else timeout wait (atomically (readTBQueue queue))

emitEvents :: Loop -> [Event] -> IO ()
emitEvents loop es = atomically $ do
  mapM_ (writeTQueue (loopEvents loop)) es
  modifyTVar' (loopWaiting loop) (+ length es)

count :: Shell -> (Traffic.Counted, Int) -> IO ()
count = uncurry . Traffic.count . shellCounts

-- | State that others can grow, bytes waiting on sockets, and the events
-- the client hasn't taken yet.
sizes :: Tox -> IO [Sizes.Size]
sizes tox = do
  state <- call tox (gets Sizes.stateSizes)
  relays <- tcpIoQueued (shellTcp shell)
  clients <- serverIoQueued (shellServer shell)
  waiting <- readTVarIO (toxWaiting tox)
  return $ state ++
    [ Sizes.Size (pack "Bytes waiting on relay connections") relays Nothing
    , Sizes.Size (pack "Bytes waiting on our relay's clients") clients Nothing
    , Sizes.Size (pack "Events not taken yet") waiting Nothing
    ]
  where shell = toxShell tox

-- | What we sent and received since we started.
traffic :: Tox -> IO [(Traffic.Counted, Traffic.Count)]
traffic tox = do
  core <- call tox (gets counted)
  edge <- Traffic.totals . shellCounts $ toxShell tox
  return . Map.toList $ Map.unionWith Traffic.addCount core (Map.fromList edge)

-- | Time the main loop spent on each kind of input, over the last few
-- seconds.
timings :: Tox -> IO (Map.Map Text Lanes.Lane)
timings = Lanes.lanes . toxLanes

forkNamed :: String -> IO () -> IO ThreadId
forkNamed name act = forkIO $ (myThreadId >>= (`labelThread` name)) >> act

-- | Once the client is this many events behind, we drop the packets that
-- bring more, and peers send them again. A toxcore client that's slow to
-- iterate loses them too, as the system drops what it can't hold.
maxWaitingEvents :: Int
maxWaitingEvents = 1024

unixTime :: IO Word64
unixTime = fromIntegral . Clock.sec <$> Clock.getTime Clock.Realtime


{-------------------------------------------------------------------------------
 -
 - :: Sockets.
 -
 ------------------------------------------------------------------------------}

-- | Carries out the core's outputs.
data Shell = Shell
  { shellUdp    :: Maybe Datagrams -- ^ None where the system has no UDP.
  , shellTcp    :: TcpIo
  , shellServer :: TcpServerIo
  , shellCounts :: Traffic.Traffic -- ^ What crosses our sockets.
  , shellLog    :: LogLevel -> Text -> IO ()
  }

data TcpIo = TcpIo
  { tcpIoConnect :: RelayOwner -> NodeInfo -> Int -> IO () -- ^ Inputs from it carry this number.
  , tcpIoSend    :: RelayOwner -> PublicKey -> BS.ByteString -> IO Bool
    -- ^ True when this made it busy.
  , tcpIoClose   :: RelayOwner -> PublicKey -> IO ()
  , tcpIoQueued  :: IO Int -- ^ Bytes the system hasn't taken yet, on all of them.
  }

noTcpIo :: TcpIo
noTcpIo = TcpIo (\_ _ _ -> return ()) (\_ _ _ -> return False) (\_ _ -> return ()) (return 0)

data TcpServerIo = TcpServerIo
  { serverIoSend   :: Server.ClientId -> BS.ByteString -> IO Bool -- ^ As 'tcpIoSend'.
  , serverIoClose  :: Server.ClientId -> IO ()
  , serverIoQueued :: IO Int
  }

noTcpServerIo :: TcpServerIo
noTcpServerIo = TcpServerIo (\_ _ -> return False) (const $ return ()) (return 0)

-- | Returns what the shell learnt doing it, for the core.
flush :: Shell -> [Output] -> IO [Input]
flush shell = concatMapM $ \case
  sent@(SendUdp to bs) -> [] <$ forM_ (shellUdp shell) (\udp ->
    try (datagramsSend udp to bs) >>= \case
      -- Safely ignore "Address family not supported"
      Left (e :: IOException) | ioe_type e /= UnsupportedOperation ->
        shellLog shell LevelDebug . pack $ "Sending to " <> show to <> " failed: " <> show e
      Left _ -> return ()
      Right _ -> mapM_ (count shell) (outputCounted sent))
  RelayConnect owner relay socket -> [] <$ tcpIoConnect (shellTcp shell) owner relay socket
  sent@(RelaySend owner pk socket bytes) -> do
    mapM_ (count shell) (outputCounted sent)
    bool [] [RelayBusy owner pk socket] <$> tcpIoSend (shellTcp shell) owner pk bytes
  RelayClose owner pk -> [] <$ tcpIoClose (shellTcp shell) owner pk
  ClientSend client bytes -> bool [] [ClientBusy client] <$> serverIoSend (shellServer shell) client bytes
  ClientClose client -> [] <$ serverIoClose (shellServer shell) client
  Log level text -> [] <$ shellLog shell level text
  Reply answer -> [] <$ answer

-- | TCP relay connections. Each has a writer thread with a queue (so data
-- sent while connecting waits) and a reader thread feeding the main loop.
-- Also returns an action that closes them all.
makeTcpIo :: Maybe Proxy -> Inputs -> IO (TcpIo, IO ())
makeTcpIo proxy inputs = do
  sockets <- newMVar Map.empty
  let connect owner relay socket = do
        let pk = NodeInfo.publicKey relay
        queue <- newChan
        pending <- newIORef 0
        modifyMVar_ sockets $ \m -> do
          mapM_ (\(q, _) -> writeChan q Nothing) (Map.lookup (owner, pk) m)
          return $ Map.insert (owner, pk) (queue, pending) m
        void $ forkNamed "tox relay writer" $ do
          result <- try $ do
            stream <- timeout relayConnectTime (Sockets.connect proxy (NodeInfo.address relay))
              >>= maybe (throwIO (userError "No answer from the relay")) return
            void . forkNamed "tox relay reader" $
              readStream (RelayBytes owner pk socket) (RelayClosed owner pk socket) inputs stream
            writeStream (drained pending (pushInput inputs (RelayWritable owner pk socket))) stream queue
          case result of
            Left (_ :: IOException) -> pushInput inputs (RelayClosed owner pk socket)
            Right ()                -> return ()
      send owner pk bytes = withMVar sockets $ \m ->
        maybe (return False) (\(q, pending) -> queueBytes q pending bytes) (Map.lookup (owner, pk) m)
      close owner pk = modifyMVar_ sockets $ \m -> do
        mapM_ (\(q, _) -> writeChan q Nothing) (Map.lookup (owner, pk) m)
        return $ Map.delete (owner, pk) m
      closeAll = readMVar sockets >>= mapM_ (\(q, _) -> writeChan q Nothing) . Map.elems
      queued = readMVar sockets >>= fmap sum . mapM (queuedBytes . snd) . Map.elems
  return (TcpIo connect send close queued, closeAll)

-- | Once the system holds this many of our bytes, we hold back data that can
-- wait. toxcore does that as soon as the system takes no more.
maxPendingRelayBytes :: Int
maxPendingRelayBytes = 32768

-- | For a writer thread. Once the system holds too many of our bytes, the
-- socket closes instead, so a peer that doesn't read can't fill our memory.
-- True when this took it over 'maxPendingRelayBytes'.
queueBytes :: Chan (Maybe BS.ByteString) -> IORef Int -> BS.ByteString -> IO Bool
queueBytes queue pending bytes = do
  let n = BS.length bytes
  (next, crossed) <- atomicModifyIORef' pending $ \p -> if
    | p > maxQueuedBytes     -> (p, (Nothing, False))
    | p + n > maxQueuedBytes -> (maxBound, (Just Nothing, False))
    | otherwise              -> (p + n, (Just (Just bytes), p <= maxPendingRelayBytes && p + n > maxPendingRelayBytes))
  forM_ next (writeChan queue)
  return crossed

-- | For a writer thread, once the system took some bytes. Tells whoever waits
-- when it's no longer busy.
drained :: IORef Int -> IO () -> Int -> IO ()
drained pending writable n = do
  crossed <- atomicModifyIORef' pending $ \p -> (p - n, p > maxPendingRelayBytes && p - n <= maxPendingRelayBytes)
  when crossed writable

-- | One that went over the limit counts as full until it's gone.
queuedBytes :: IORef Int -> IO Int
queuedBytes = fmap (min maxQueuedBytes) . readIORef

-- | Only what can't wait goes past 'maxPendingRelayBytes', so this is a peer
-- that stopped reading. toxcore gives up after 1024 such packets.
maxQueuedBytes :: Int
maxQueuedBytes = 1048576

-- | Microseconds for a relay (or its proxy) to take the connection.
-- Otherwise one that never answers keeps a thread and socket forever.
relayConnectTime :: Int
relayConnectTime = 10000000

-- | Our TCP relay. Each client gets a writer thread and a reader thread
-- feeding the main loop. Also returns an action that stops it.
makeTcpServerIo :: (LogLevel -> Text -> IO ()) -> Inputs -> Bool -> Word16
                -> IO (TcpServerIo, IO ())
makeTcpServerIo logger inputs ipv6 port = do
  listener <- Sockets.listen ipv6 port
  queues <- newMVar Map.empty
  acceptor <- forkNamed "tox relay server" $ forM_ [0 ..] $ \client -> try (listenerAccept listener) >>= \case
    Left (e :: IOException) -> logger LevelWarn (pack $ "Accepting failed: " ++ show e) >> threadDelay acceptRetryDelay
    Right stream -> do
      queue <- newChan
      pending <- newIORef 0
      modifyMVar_ queues (return . Map.insert client (queue, pending))
      -- The writer closes the socket when we stop, even while we're waiting
      -- here.
      void . forkNamed "tox relay server writer" $
        writeStream (drained pending (pushInput inputs (ClientWritable client))) stream queue
      pushInput inputs (ClientAccepted client)
      void $ forkNamed "tox relay server reader" $ readStream (ClientBytes client) (ClientClosed client) inputs stream
  let send client bytes = withMVar queues $ \m ->
        maybe (return False) (\(q, pending) -> queueBytes q pending bytes) (Map.lookup client m)
      close client = modifyMVar_ queues $ \m -> do
        mapM_ ((`writeChan` Nothing) . fst) (Map.lookup client m)
        return $ Map.delete client m
      queued = readMVar queues >>= fmap sum . mapM (queuedBytes . snd) . Map.elems
      stop = do
        killThread acceptor
        listenerClose listener
        readMVar queues >>= mapM_ ((`writeChan` Nothing) . fst) . Map.elems
  return (TcpServerIo send close queued, stop)

readStream :: (BS.ByteString -> Input) -> Input -> Inputs -> Stream -> IO ()
readStream received closed inputs stream = do
  result <- try $ streamReceive stream
  case result of
    Right bytes | not (BS.null bytes) -> pushInput inputs (received bytes) >> readStream received closed inputs stream
    Right _                           -> pushInput inputs closed
    Left (_ :: IOException)           -> pushInput inputs closed

-- | Reports how much was written.
writeStream :: (Int -> IO ()) -> Stream -> Chan (Maybe BS.ByteString) -> IO ()
writeStream written stream queue = readChan queue >>= \case
  Just bytes -> do
    result <- try $ streamSend stream bytes
    case result of
      Right ()                -> written (BS.length bytes) >> writeStream written stream queue
      Left (_ :: IOException) -> streamClose stream
  Nothing -> streamClose stream


{-------------------------------------------------------------------------------
 -
 - :: Network.
 -
 ------------------------------------------------------------------------------}

bootstrap :: Tox -> NodeInfo -> IO ()
bootstrap tox = call tox . bootstrapNode

addTcpRelay :: Tox -> NodeInfo -> IO ()
addTcpRelay tox = call tox . Tcp.addRelay . (\n -> n { protocol = TCP })

-- | Node for each address of the host.
resolveNode :: String -> Word16 -> PublicKey -> IO [NodeInfo]
resolveNode host port pk = map (\sa -> NodeInfo UDP sa pk) <$> Sockets.resolve host port

selfConnectionStatus :: Tox -> IO ConnectionStatus
selfConnectionStatus tox = call tox getSelfConnection

selfUdpPort :: Tox -> Word16
selfUdpPort = toxUdpPort

selfDhtId :: Tox -> PublicKey
selfDhtId = toxDhtId


{-------------------------------------------------------------------------------
 -
 - :: Profile.
 -
 ------------------------------------------------------------------------------}

-- | In toxcore's save format.
saveData :: Tox -> IO BS.ByteString
saveData tox = call tox $ do
  gets (Map.keys . friendLinks) >>= mapM_ touchLastSeen
  unixAt <- unixClock
  gets (LBS.toStrict . Binary.encode . Save.toSaveData . Save.profileOf unixAt)

selfPublicKey :: Tox -> PublicKey
selfPublicKey = toxPublicKey

selfSecretKey :: Tox -> Key.SecretKey
selfSecretKey = toxSecretKey

selfAddress :: Tox -> IO BS.ByteString
selfAddress tox = call tox $ gets (Messenger.toxId (toxPublicKey tox) . messenger)

-- | As toxcore's API: the Tox ID bytes read big-endian.
selfGetNospam :: Tox -> IO Word32
selfGetNospam tox = call tox $ gets (byteSwap32 . Messenger.selfNospam . messenger)

-- | Changes our Tox ID, so requests to the old one fail.
selfSetNospam :: Tox -> Word32 -> IO ()
selfSetNospam tox nospam = call tox $ modify $ \gs ->
  gs { messenger = (messenger gs) { Messenger.selfNospam = byteSwap32 nospam } }

selfGetName :: Tox -> IO BS.ByteString
selfGetName tox = call tox $ gets (Messenger.selfName . messenger)

-- | 'False' if the name is too long.
selfSetName :: Tox -> BS.ByteString -> IO Bool
selfSetName tox name = call tox $ do
  ok <- Messenger.setSelfName name
  when ok Conference.nameChanged
  return ok

selfGetStatusMessage :: Tox -> IO BS.ByteString
selfGetStatusMessage tox = call tox $ gets (Messenger.selfMsg . messenger)

-- | In bytes.
maxNameLength, maxStatusMessageLength :: Int
maxNameLength = Messenger.maxNameLength
maxStatusMessageLength = Messenger.maxStatusMessageLength

-- | 'False' if the status message is too long.
selfSetStatusMessage :: Tox -> BS.ByteString -> IO Bool
selfSetStatusMessage tox = call tox . Messenger.setSelfStatusMessage

selfGetStatus :: Tox -> IO Messenger.UserStatus
selfGetStatus tox = call tox $ gets (Messenger.selfStatus . messenger)

selfSetStatus :: Tox -> Messenger.UserStatus -> IO ()
selfSetStatus tox = call tox . Messenger.setSelfStatus


{-------------------------------------------------------------------------------
 -
 - :: Friends.
 -
 ------------------------------------------------------------------------------}

-- | If the checksum is right.
parseAddress :: BS.ByteString -> Maybe (PublicKey, BS.ByteString)
parseAddress = Messenger.parseToxId

-- | Sends a friend request.
friendAdd :: Tox -> BS.ByteString -> BS.ByteString
          -> IO (Either (Maybe Messenger.AddFriendError) PublicKey)
friendAdd tox toxId message = case parseAddress toxId of
  Nothing -> return $ Left Nothing
  Just (pk, nospam) -> call tox $
    either (Left . Just) (const $ Right pk) <$> Messenger.addFriendWithRequest pk nospam message

-- | In bytes.
maxFriendRequestLength :: Int
maxFriendRequestLength = Messenger.maxFriendRequestLength

-- | To accept their request, or for friends who added us.
friendAddNoRequest :: Tox -> PublicKey -> IO (Either Messenger.AddFriendError ())
friendAddNoRequest tox pk = call tox $ do
  known <- Messenger.getsMessenger (Map.member pk . Messenger.messengerFriends)
  ourPk <- KeyPair.publicKey <$> Connection.getsConn Connection.ourRealKeys
  if | known       -> return $ Left Messenger.AlreadyFriend
     | pk == ourPk -> return $ Left Messenger.OwnKey
     | otherwise   -> Right <$> Messenger.addFriend pk

friendDelete :: Tox -> PublicKey -> IO Bool
friendDelete tox pk = call tox $ do
  modify $ \gs -> gs { friendLinks = Map.delete pk (friendLinks gs) }
  Messenger.deleteFriend pk <* Conference.releaseFriendConnection pk

friendList :: Tox -> IO [PublicKey]
friendList tox = call tox $ Messenger.getsMessenger (Map.keys . Messenger.messengerFriends)

friendInfo :: Tox -> PublicKey -> IO (Maybe FriendInfo)
friendInfo tox pk = call tox $ do
  mFriend <- Messenger.getsMessenger (Map.lookup pk . Messenger.messengerFriends)
  forM mFriend $ \f -> do
    conn <- if Messenger.friendOnline f then getFriendConnection pk else return NotConnected
    now <- gets stepUnixTime
    return FriendInfo
      { friendPublicKey     = pk
      , friendName          = Messenger.friendName f
      , friendStatusMessage = Messenger.friendMsg f
      , friendStatus        = Messenger.friendStatus f
      , friendTyping        = Messenger.friendTyping f
      , friendConnection    = conn
      , friendLastSeen      = if conn == NotConnected then Messenger.friendLastSeen f else now
      }

-- | Gives the ID for 'FriendReadReceipt'.
friendSendMessage :: Tox -> PublicKey -> Messenger.MessageType -> BS.ByteString
                  -> IO (Either Messenger.SendMessageError Word32)
friendSendMessage tox pk ty = call tox . Messenger.sendMessage pk ty

-- | In bytes.
maxMessageLength :: Int
maxMessageLength = Messenger.maxMessageLength

friendSetTyping :: Tox -> PublicKey -> Bool -> IO Bool
friendSetTyping tox pk = call tox . Messenger.setTyping pk

-- | Client packets including the ID: a lossless ID toxcore doesn't use, or
-- a lossy ID from 192 to 254.
friendSendLosslessPacket, friendSendLossyPacket
  :: Tox -> PublicKey -> BS.ByteString -> IO (Either Messenger.CustomPacketError ())
friendSendLosslessPacket tox pk = call tox . Messenger.sendCustomPacket clientLossless True pk
friendSendLossyPacket tox pk = call tox . Messenger.sendCustomPacket clientLossy False pk

-- | Same without waiting for the main loop. Refused packets are dropped.
-- Packets go out in the order they were queued.
friendQueueLosslessPacket, friendQueueLossyPacket :: Tox -> PublicKey -> BS.ByteString -> IO ()
friendQueueLosslessPacket tox pk = cast tox . void . Messenger.sendCustomPacket clientLossless True pk
friendQueueLossyPacket tox pk = cast tox . void . Messenger.sendCustomPacket clientLossy False pk


{-------------------------------------------------------------------------------
 -
 - :: Files.
 -
 ------------------------------------------------------------------------------}

-- | Random file ID if there's none. The friend accepts with
-- 'FileControlChanged', and 'FileChunkRequest' asks for the data.
fileSend :: Tox -> PublicKey -> Word32 -> Word64 -> Maybe BS.ByteString -> BS.ByteString
         -> IO (Either Messenger.FileError Word8)
fileSend tox pk kind size fileId name = call tox $ do
  fid <- maybe (randomBytes Messenger.fileIdLength) return fileId
  Messenger.sendFile pk kind size fid name

fileControl :: Tox -> PublicKey -> Messenger.FileRef -> Messenger.FileControl
            -> IO (Either Messenger.FileError ())
fileControl tox pk ref = call tox . Messenger.controlFile pk ref

-- | Before accepting it.
fileSeek :: Tox -> PublicKey -> Word8 -> Word64 -> IO (Either Messenger.FileError ())
fileSeek tox pk n = call tox . Messenger.seekFile pk n

fileSendChunk :: Tox -> PublicKey -> Word8 -> Word64 -> BS.ByteString
              -> IO (Either Messenger.FileError ())
fileSendChunk tox pk n position = call tox . Messenger.sendFileChunk pk n position

{-------------------------------------------------------------------------------
 -
 - :: Conferences.
 -
 ------------------------------------------------------------------------------}

data ConferencePeer = ConferencePeer
  { conferencePeerNumber    :: Conference.PeerNumber
  , conferencePeerPublicKey :: PublicKey
  , conferencePeerName      :: BS.ByteString
  } deriving (Eq, Show)

-- | Text conference. 'Nothing' if we're in too many.
conferenceNew :: Tox -> IO (Maybe Conference.ConferenceNumber)
conferenceNew tox = call tox Conference.newConference

conferenceInvite :: Tox -> PublicKey -> Conference.ConferenceNumber -> IO Bool
conferenceInvite tox friend = call tox . Conference.invite friend

-- | Takes the cookie of a 'ConferenceInvite'.
conferenceJoin :: Tox -> PublicKey -> BS.ByteString
               -> IO (Either Conference.JoinError Conference.ConferenceNumber)
conferenceJoin tox friend = call tox . Conference.join friend

conferenceDelete :: Tox -> Conference.ConferenceNumber -> IO Bool
conferenceDelete tox g = call tox $ Conference.leave g True

conferenceSendMessage :: Tox -> Conference.ConferenceNumber -> Messenger.MessageType
                      -> BS.ByteString -> IO Bool
conferenceSendMessage tox g ty = call tox . Conference.sendText g ty

conferenceSetTitle :: Tox -> Conference.ConferenceNumber -> BS.ByteString -> IO Bool
conferenceSetTitle tox g = call tox . Conference.changeTitle g

conferenceTitle :: Tox -> Conference.ConferenceNumber -> IO (Maybe BS.ByteString)
conferenceTitle tox g = call tox $ fmap Conference.cfTitle <$> Conference.getConference g

conferencePeers :: Tox -> Conference.ConferenceNumber -> IO [ConferencePeer]
conferencePeers tox g = call tox $ maybe [] peers <$> Conference.getConference g
  where
    peers c = [ ConferencePeer n (Conference.peerRealPk p) (Conference.peerName p)
              | (n, p) <- Map.toList (Conference.cfPeers c) ]

conferenceList :: Tox -> IO [Conference.ConferenceNumber]
conferenceList tox = call tox $ Map.keys . Conference.conferences <$> Conference.getConferences

-- | Type and ID, which stay the same between runs.
conferenceId :: Tox -> Conference.ConferenceNumber -> IO (Maybe BS.ByteString)
conferenceId tox g = call tox $ fmap Conference.identifier <$> Conference.getConference g

-- | One conference in toxcore's save format, for clients that save their own
-- state.
conferenceSave :: Tox -> Conference.ConferenceNumber -> IO (Maybe BS.ByteString)
conferenceSave tox g = call tox $ do
  unixAt <- unixClock
  (>>= fmap (LBS.toStrict . Binary.encode) . Save.savedConference unixAt) <$> Conference.getConference g

-- | From 'conferenceSave', unless we're in it.
conferenceRestore :: Tox -> BS.ByteString -> IO (Maybe Conference.ConferenceNumber)
conferenceRestore tox bytes = case Binary.decodeOrFail (LBS.fromStrict bytes) of
  Right (rest, _, saved) | LBS.null rest -> call tox $ Conference.restoreConference saved
  _ -> return Nothing

{-------------------------------------------------------------------------------
 -
 - :: Groups.
 -
 ------------------------------------------------------------------------------}

data GroupPeer = GroupPeer
  { groupPeerId     :: Group.PeerId
  , groupPeerKey    :: PublicKey
  , groupPeerName   :: BS.ByteString
  , groupPeerStatus :: Word8
  , groupPeerRole   :: Group.Role
  } deriving (Eq, Show)

-- | Private (joined by invite) or public, with its name and our nick.
groupNew :: Tox -> Bool -> BS.ByteString -> BS.ByteString -> IO (Maybe Group.GroupNumber)
groupNew tox private name = call tox . Group.createGroup private name

-- | Public group by chat ID, with our nick and its password if it has one.
groupJoin :: Tox -> BS.ByteString -> BS.ByteString -> BS.ByteString
          -> IO (Either Group.AcceptError Group.GroupNumber)
groupJoin tox chatId nick = call tox . Group.joinPublicGroup chatId nick

groupChatId :: Tox -> Group.GroupNumber -> IO (Maybe BS.ByteString)
groupChatId tox g = call tox $ fmap Group.grChatId <$> Group.getGroup g

groupInviteFriend :: Tox -> Group.GroupNumber -> PublicKey -> IO Bool
groupInviteFriend tox g = call tox . Group.inviteFriend g

-- | Takes the invite data of a 'GroupInvite', our nick, and the password if
-- it has one.
groupInviteAccept :: Tox -> PublicKey -> BS.ByteString -> BS.ByteString -> BS.ByteString
                  -> IO (Either Group.AcceptError Group.GroupNumber)
groupInviteAccept tox friend invite nick = call tox . Group.acceptInvite friend invite nick

-- | Gives the message ID peers see.
groupSendMessage :: Tox -> Group.GroupNumber -> Messenger.MessageType -> BS.ByteString
                 -> IO (Either Group.GroupSendError Word32)
groupSendMessage tox g ty = call tox . Group.sendMessage g ty

groupSendPrivateMessage :: Tox -> Group.GroupNumber -> Group.PeerId -> Messenger.MessageType
                        -> BS.ByteString -> IO (Either Group.GroupSendError Word32)
groupSendPrivateMessage tox g n ty = call tox . Group.sendPrivateMessage g n ty

-- | Client data for everyone in the group, lossless or not.
groupSendCustomPacket :: Tox -> Group.GroupNumber -> Bool -> BS.ByteString
                      -> IO (Either Group.GroupSendError ())
groupSendCustomPacket tox g lossless = call tox . Group.sendCustomPacket g Nothing lossless

groupSendCustomPrivatePacket :: Tox -> Group.GroupNumber -> Group.PeerId -> Bool -> BS.ByteString
                             -> IO (Either Group.GroupSendError ())
groupSendCustomPrivatePacket tox g n lossless = call tox . Group.sendCustomPacket g (Just n) lossless

groupSetTopic :: Tox -> Group.GroupNumber -> BS.ByteString -> IO Bool
groupSetTopic tox g = call tox . Group.setTopic g

groupSelfRole :: Tox -> Group.GroupNumber -> IO (Maybe Group.Role)
groupSelfRole tox g = call tox $ fmap Group.selfRole <$> Group.getGroup g

groupPeerCanSpeak :: Tox -> Group.GroupNumber -> Group.PeerId -> IO Bool
groupPeerCanSpeak tox g n = call tox $ maybe False (\gr -> maybe False (Group.canSpeak gr) (Group.confirmedPeer gr n)) <$> Group.getGroup g

-- | The key our peers know us by in the group.
groupSelfPublicKey :: Tox -> Group.GroupNumber -> IO (Maybe PublicKey)
groupSelfPublicKey tox g = call tox $ fmap Group.selfEncPk <$> Group.getGroup g

-- | Founder settings from the shared state.
data GroupSettings = GroupSettings
  { groupPrivate   :: Bool
  , groupPassword  :: BS.ByteString
  , groupPeerLimit :: Word16
  , groupTopicLock :: Bool
  , groupVoice     :: Group.Voice
  } deriving (Eq, Show)

-- | Once we have the shared state.
groupSettings :: Tox -> Group.GroupNumber -> IO (Maybe GroupSettings)
groupSettings tox g = call tox $ (>>= (settings . fst <=< Group.grSharedState)) <$> Group.getGroup g
  where
    settings s = GroupSettings (GroupPackets.ssPrivacy s == 1) (GroupPackets.ssPassword s) (GroupPackets.ssMaxPeers s)
      (GroupPackets.ssTopicLock s == 0) <$> Group.voiceOf (GroupPackets.ssVoice s)

-- | Whether 'groupSetTopic' would work now, by our role and the topic lock.
groupMayTopic :: Tox -> Group.GroupNumber -> IO Bool
groupMayTopic tox g = call tox $ maybe False Group.mayTopic <$> Group.getGroup g

groupTopic :: Tox -> Group.GroupNumber -> IO (Maybe BS.ByteString)
groupTopic tox g = call tox $ (>>= fmap (GroupPackets.tiTopic . fst) . Group.grTopic) <$> Group.getGroup g

groupName :: Tox -> Group.GroupNumber -> IO (Maybe BS.ByteString)
groupName tox g = call tox $ (>>= fmap (GroupPackets.ssGroupName . fst) . Group.grSharedState) <$> Group.getGroup g

groupSetNick :: Tox -> Group.GroupNumber -> BS.ByteString -> IO Bool
groupSetNick tox g = call tox . Group.setNick g

-- | Separate from the status friends see.
groupSetStatus :: Tox -> Group.GroupNumber -> Messenger.UserStatus -> IO Bool
groupSetStatus tox g = call tox . Group.setStatus g . fromIntegral . fromEnum

-- | Without us.
groupPeers :: Tox -> Group.GroupNumber -> IO [GroupPeer]
groupPeers tox g = call tox $ maybe [] peers <$> Group.getGroup g
  where
    peers gr = [ GroupPeer (Group.peerId p) (Group.peerEncPk p) (Group.peerNick p) (Group.peerStatus p)
                   (Group.peerRole gr p)
               | p <- Group.confirmedPeers gr ]

groupLeave :: Tox -> Group.GroupNumber -> BS.ByteString -> IO Bool
groupLeave tox g = call tox . Group.leave g

groupKickPeer :: Tox -> Group.GroupNumber -> Group.PeerId -> IO (Either Group.ModError ())
groupKickPeer tox g = call tox . Group.kickPeer g

groupSetRole :: Tox -> Group.GroupNumber -> Group.PeerId -> Group.Role
             -> IO (Either Group.ModError ())
groupSetRole tox g n = call tox . Group.setRole g n

-- | Founder settings. Each change goes to every peer.
groupSetPassword :: Tox -> Group.GroupNumber -> BS.ByteString -> IO Bool
groupSetPassword tox g = call tox . Group.setPassword g

groupSetPeerLimit :: Tox -> Group.GroupNumber -> Word16 -> IO Bool
groupSetPeerLimit tox g = call tox . Group.setPeerLimit g

groupSetPrivacy :: Tox -> Group.GroupNumber -> Bool -> IO Bool
groupSetPrivacy tox g = call tox . Group.setPrivacy g

groupSetTopicLock :: Tox -> Group.GroupNumber -> Bool -> IO Bool
groupSetTopicLock tox g = call tox . Group.setTopicLock g

groupSetVoice :: Tox -> Group.GroupNumber -> Group.Voice -> IO Bool
groupSetVoice tox g = call tox . Group.setVoice g

groupList :: Tox -> IO [Group.GroupNumber]
groupList tox = call tox $ Map.keys . Group.groups <$> Group.getGroups

-- | One group in toxcore's save format (with its keys), once we have the
-- shared state.
groupSave :: Tox -> Group.GroupNumber -> IO (Maybe BS.ByteString)
groupSave tox g = call tox $
  (>>= fmap (LBS.toStrict . Binary.encode . PG.Groups . pure) . Group.saveGroup) <$> Group.getGroup g

-- | From 'groupSave', unless we're in it.
groupRestore :: Tox -> BS.ByteString -> IO (Maybe Group.GroupNumber)
groupRestore tox bytes = case Binary.decodeOrFail (LBS.fromStrict bytes) of
  Right (rest, _, PG.Groups [saved]) | LBS.null rest -> call tox $ Group.restoreGroup saved
  _ -> return Nothing
