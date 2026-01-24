{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
{-# LANGUAGE TypeApplications  #-}
-- | A c-toxcore peer for interoperability tests, on hs-toxcore-c.
--
-- It adds the friends given with --friend without sending friend requests,
-- sends friend requests to the Tox IDs given with --add, accepts friend
-- requests with --accept-requests, prints its DHT key, UDP port and public
-- key, then echoes every message it receives back to the sender. With
-- --dht-nodes it also runs that many more Tox instances, connected to it, as
-- a local DHT and onion network. With --no-udp it reaches the network only
-- through the --tcp-relay. With --file-dir it saves the files it receives
-- there and sends them back. Custom lossless and lossy packets go back with
-- the same ID. With --av it answers calls and sends their audio and video
-- back, and with --av-call it also calls friends when they come online. With
-- --group-status it shows itself away or busy in the groups it is in.
module Main (main) where

import           Control.Concurrent     (threadDelay)
import           Control.Exception      (SomeException, bracket, try)
import           Control.Monad          (forM_, unless, void, when, (>=>))
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8  as Char8
import           Data.Char              (isUpper, toUpper)
import           Data.Coerce            (Coercible, coerce)
import           Data.Either            (fromRight, isRight)
import           Data.Int               (Int16)
import           Data.IORef
import qualified Data.Map.Strict        as Map
import           Data.Maybe             (fromMaybe, isJust)
import           Data.Time.Clock.POSIX  (getPOSIXTime)
import qualified Data.Vector.Storable   as V
import           Data.Word              (Word16, Word32, Word64, Word8)
import qualified FFI.Tox.Av             as Raw
import qualified FFI.Tox.Types          as Raw
import           Foreign.C.Enum         (CEnum (..))
import           Foreign.Marshal.Array  (withArrayLen)
import           Foreign.Ptr            (nullPtr)
import           GHC.Clock              (getMonotonicTime)
import qualified Network.Socket         as Socket
import           Network.Tox.C
import           System.Directory       (renameFile)
import           System.Environment     (getArgs)
import           System.Exit            (exitFailure)
import           System.IO              (BufferMode (..), hPutStrLn,
                                         hSetBuffering, stderr, stdout)
import           System.Posix.Process   (getProcessID)

data Config = Config
  { port           :: Word16
  , friends        :: [PublicKey]
  , requests       :: [Address]
  , acceptRequests :: Bool
  , dhtNodes       :: Int
  , relayPort      :: Word16
  , relay          :: Maybe Node
  , bootstrap      :: Maybe Node
  , udp            :: Bool
  , load           :: Maybe FilePath
  , save           :: Maybe FilePath
  , printId        :: Bool
  , discovery      :: Bool
  , fileDir        :: Maybe FilePath
  , ipv6           :: Bool
  , groupNew       :: Maybe BS.ByteString
  , groupPublic    :: Maybe BS.ByteString
  , groupJoin      :: Maybe GroupChatId
  , groupModerate  :: Bool
  , groupStatus    :: Maybe UserStatus
  , conferenceNew  :: Maybe BS.ByteString
  , av             :: Bool
  , avCall         :: Bool
  , verbose        :: Bool
  }

type Node = (String, Word16, DhtId)

usage :: String
usage = unlines
  [ "Usage: tox-c-peer [--port PORT] [--friend PUBLIC_KEY]... [--add TOX_ID]... [--accept-requests]"
  , "          [--dht-nodes N] [--tcp-relay-port PORT] [--tcp-relay HOST:PORT:KEY]"
  , "          [--no-udp] [--bootstrap HOST:PORT:KEY] [--load SAVE_FILE] [--save SAVE_FILE]"
  , "          [--print-id] [--local-discovery] [--file-dir DIR] [--ipv6] [--group-new NAME]"
  , "          [--group-public NAME] [--group-join CHAT_ID]"
  , "          [--group-moderate] [--group-status away|busy] [--conference-new TITLE] [--av]"
  , "          [--av-call] [--verbose]"
  ]

config :: [String] -> Either String Config
config = go (Config 0 [] [] False 0 0 Nothing Nothing True Nothing Nothing False False Nothing False Nothing Nothing Nothing False Nothing Nothing False False False)
  where
    go c = \case
      "--port" : n : rest -> go c { port = read n } rest
      "--friend" : k : rest -> fixed "public key" k >>= \key -> go c { friends = friends c <> [key] } rest
      "--add" : k : rest -> fixed "Tox ID" k >>= \address -> go c { requests = requests c <> [address] } rest
      "--tcp-relay-port" : n : rest -> go c { relayPort = read n } rest
      "--tcp-relay" : n : rest -> node n >>= \r -> go c { relay = Just r } rest
      "--bootstrap" : n : rest -> node n >>= \b -> go c { bootstrap = Just b } rest
      "--no-udp" : rest -> go c { udp = False } rest
      "--load" : path : rest -> go c { load = Just path } rest
      "--save" : path : rest -> go c { save = Just path } rest
      "--group-new" : name : rest -> go c { groupNew = Just (Char8.pack name) } rest
      "--conference-new" : title : rest -> go c { conferenceNew = Just (Char8.pack title) } rest
      "--group-public" : name : rest -> go c { groupPublic = Just (Char8.pack name) } rest
      "--group-status" : "away" : rest -> go c { groupStatus = Just UserStatusAway } rest
      "--group-status" : "busy" : rest -> go c { groupStatus = Just UserStatusBusy } rest
      "--group-moderate" : rest -> go c { groupModerate = True } rest
      "--group-join" : k : rest -> fixed "chat id" k >>= \chat -> go c { groupJoin = Just chat } rest
      "--file-dir" : dir : rest -> go c { fileDir = Just dir } rest
      "--ipv6" : rest -> go c { ipv6 = True } rest
      "--local-discovery" : rest -> go c { discovery = True } rest
      "--print-id" : rest -> go c { printId = True } rest
      "--av" : rest -> go c { av = True } rest
      "--av-call" : rest -> go c { av = True, avCall = True } rest
      "--accept-requests" : rest -> go c { acceptRequests = True } rest
      "--dht-nodes" : n : rest
        | read n > (32 :: Int) -> Left "At most 32 DHT nodes"
        | otherwise -> go c { dhtNodes = read n } rest
      "--verbose" : rest -> go c { verbose = True } rest
      [] -> Right c
      _ -> Left usage
    fixed what s = maybe (Left ("Invalid " <> what <> ": " <> s)) Right (fromHex s)

fromHex :: FixedBytes a => String -> Maybe a
fromHex = either (const Nothing) fromBytes . Base16.decode . Char8.pack

-- | HOST:PORT:KEY, with an IPv6 host in brackets.
node :: String -> Either String Node
node spec = maybe (Left ("Invalid node: " <> spec)) Right $ case spec of
  '[' : rest | (host, ']' : ':' : more) <- break (== ']') rest -> portKey host more
  _ | (host, ':' : more) <- break (== ':') spec -> portKey host more
  _ -> Nothing
  where
    portKey host more = case break (== ':') more of
      (p, ':' : key) | [(n, "")] <- reads p -> (,,) host n <$> fromHex key
      _                                     -> Nothing

hex :: BS.ByteString -> BS.ByteString
hex = Char8.map toUpper . Base16.encode

say :: [BS.ByteString] -> IO ()
say = Char8.putStrLn . Char8.unwords

shown :: Show a => a -> BS.ByteString
shown = Char8.pack . show

-- | The C name of an enum value: @ConnectionTcp@ is @TOX_CONNECTION_TCP@.
cName :: Show a => a -> BS.ByteString
cName v = Char8.pack ("TOX_" <> case show v of
  first : rest -> toUpper first : concatMap (\ch -> if isUpper ch then ['_', ch] else [toUpper ch]) rest
  []           -> [])

-- | The C name of a call's error, OK on success.
outcome :: Show e => BS.ByteString -> Either e a -> BS.ByteString
outcome ok = either cName (const ok)

-- | The C error code: 0 on success.
code :: CEnum e => Either e a -> BS.ByteString
code = shown . either toCEnum (const 0)

-- | Without its common prefix.
short :: Show a => BS.ByteString -> a -> BS.ByteString
short prefix v = let n = cName v in fromMaybe n (BS.stripPrefix prefix n)

number :: Coercible a Word32 => a -> BS.ByteString
number = shown @Word32 . coerce

-- | "echo: " and the message, cut to fit.
echo :: Int -> BS.ByteString -> BS.ByteString
echo size message = BS.take (size - 1) ("echo: " <> message)

isEcho :: BS.ByteString -> Bool
isEcho = BS.isPrefixOf "echo:"

-- | The packet starts with its ID, which the echo keeps.
packetEcho :: BS.ByteString -> BS.ByteString
packetEcho p = BS.take 1 p <> echo (toxMaxCustomPacketSize - 1) (BS.drop 1 p)

-- | Whether the packet's ID is in the range.
custom :: Word8 -> Word8 -> BS.ByteString -> Bool
custom from to = maybe False (\(i, _) -> i >= from && i <= to) . BS.uncons

-- | Files are kept in memory, so this is as big as they get.
maxFileSize :: Word64
maxFileSize = 64 * 1024 * 1024

data File = File
  { fileName   :: BS.ByteString
  , fileKind   :: Word32
  , fileSize   :: Word64
  , fileChunks :: Map.Map Word64 BS.ByteString
  , fileData   :: BS.ByteString
  , unsentFrom :: Word64
  , unsentTo   :: Word64
    -- ^ Requested bytes that toxcore had no room for yet.
  , chunkSize  :: Word64
    -- ^ toxcore asks for chunks of one size, except the last.
  }

-- | Friend, file, and whether we send it.
type FileKey = (FriendNumber, FileNumber, Bool)

data State = State
  { group      :: Maybe GroupNumber
  , conference :: Maybe ConferenceNumber
  , heard      :: Bool
  , files      :: Map.Map FileKey File
  , echoAudio  :: Maybe (FriendNumber, V.Vector Int16, Int, Word8, Word32)
  , echoVideo  :: Maybe (FriendNumber, Word16, Word16, BS.ByteString, BS.ByteString, BS.ByteString)
  , silenceAt  :: Double
  }

must :: Show e => String -> IO (Either e a) -> IO a
must what = (>>= either (\e -> hPutStrLn stderr (what <> ": " <> show e) >> exitFailure) pure)

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  c <- either (\e -> hPutStrLn stderr e >> exitFailure) pure . config =<< getArgs
  saved <- traverse BS.readFile (load c)
  defaults <- must "Failed to make options" defaultOptions
  pid <- getProcessID
  now <- getPOSIXTime
  -- toxcore's default ports are shared by every test running at once, so we
  -- pick from our own range unless told which port to use.
  let base = fromIntegral ((fromIntegral pid * 7919 + floor now :: Integer) `mod` 40000 + 20000)
      options tcp useUdp = defaults
        { ipv6Enabled = ipv6 c, localDiscoveryEnabled = discovery c
        , startPort = if port c /= 0 then port c else base, endPort = if port c /= 0 then port c else base + 100
        , tcpPort = tcp, udpEnabled = useUdp, experimentalGroupsPersistence = True }
      ours = (options 0 (udp c)) { savedataType = maybe SavedataTypeNone (const SavedataTypeToxSave) saved, savedata = fromMaybe BS.empty saved }
      logged level file line func message = when (level >= LogLevelWarning || verbose c) $
        hPutStrLn stderr ("[" <> Char8.unpack (cName level) <> "] " <> file <> ":" <> show line <> " " <> func <> ": " <> message)
      withToxes [] k = k []
      withToxes (o : os) k = must "Failed to create Tox instance" (withToxLogging o logged (\t -> withToxes os (k . (t :))))
  withToxes (ours : [options (if i == 0 then relayPort c else 0) True | i <- [0 .. dhtNodes c - 1]]) $ \case
    [] -> exitFailure
    tox : nodes
      | printId c -> printSaved tox
      | otherwise -> run c tox nodes

printSaved :: Tox -> IO ()
printSaved tox = do
  toxSelfGetPublicKey tox >>= \k -> say ["PUBLIC_KEY", hex (toBytes k)]
  toxSelfGetName tox >>= \n -> say ["NAME", n]
  -- A loaded profile numbers its friends from 0.
  toxSelfGetFriendList tox >>= mapM_ (toxFriendGetPublicKey tox >=> either (const (pure ())) (\k -> say ["FRIEND", hex (toBytes k)]))
  toxGroupGetGroupList tox >>= mapM_ (chatId tox "GROUP")

-- | A group's chat ID, or why we have none.
chatId :: Tox -> BS.ByteString -> GroupNumber -> IO ()
chatId tox label g = toxGroupGetChatId tox g >>= \case
  Right chat -> say [label, hex (toBytes chat)]
  Left err   -> say [label <> "_FAILED", cName err]

localhost :: Config -> String
localhost c = if ipv6 c then "::1" else "127.0.0.1"

-- | Bootstrap each of the two instances from the other.
connect :: Config -> Tox -> Tox -> IO ()
connect c a b = do
  link a b
  link b a
  where link x y = do
          key <- toxSelfGetDhtId y
          toxSelfGetUdpPort y >>= mapM_ (\p -> void (toxBootstrap x (localhost c) p key))

nick :: BS.ByteString
nick = "C peer"

run :: Config -> Tox -> [Tox] -> IO ()
run c tox nodes = do
  forM_ (zip [0 :: Int ..] nodes) $ \(i, n) -> do
    connect c tox n
    when (i > 0) $ connect c (nodes !! (i - 1)) n
  forM_ (bootstrap c) $ \(host, p, key) -> toxBootstrap tox host p key
  void (toxSelfSetName tox nick)
  forM_ (friends c) $ must "Failed to add friend" . toxFriendAddNorequest tox
  forM_ (requests c) $ \address -> must "Failed to add friend" (toxFriendAdd tox address "Hello from C")
  state <- newIORef (State Nothing Nothing False Map.empty Nothing Nothing 0)
  withAv $ \toxav -> do
    forM_ toxav (callbacks state)
    forM_ (groupPublic c) $ \name -> toxGroupNew tox GroupPrivacyStatePublic name nick >>= \case
      Left err -> say ["GROUP_NEW_FAILED", cName err]
      Right g -> setStatus g >> chatId tox "GROUP_CHAT_ID" g
    forM_ (groupJoin c) $ \chat -> do
      joined <- toxGroupJoin tox chat nick BS.empty
      say ["GROUP_JOIN", outcome "TOX_ERR_GROUP_JOIN_OK" joined, either (const (shown (maxBound :: Word32))) number joined]
    toxSelfGetDhtId tox >>= \k -> say ["DHT_ID", hex (toBytes k)]
    toxSelfGetUdpPort tox >>= \p -> say ["UDP_PORT", either (const "0") shown p]
    toxSelfGetPublicKey tox >>= \k -> say ["PUBLIC_KEY", hex (toBytes k)]
    let host = if ipv6 c then "[::1]" else "127.0.0.1"
    forM_ nodes $ \n -> do
      key <- toxSelfGetDhtId n
      p <- toxSelfGetUdpPort n
      say ["DHT_NODE " <> host <> ":" <> either (const "0") shown p <> ":" <> hex (toBytes key)]
    forM_ (take 1 nodes) $ \n -> when (relayPort c /= 0) $ do
      key <- toxSelfGetDhtId n
      say ["TCP_RELAY " <> host <> ":" <> shown (relayPort c) <> ":" <> hex (toBytes key)]
    toxSelfGetAddress tox >>= \a -> say ["TOX_ID", hex (toBytes a)]
    loop toxav state False 0
  where
    withAv k
      | av c = must "Failed to start toxav" (withToxAV tox (k . Just))
      | otherwise = k Nothing

    setStatus g = forM_ (groupStatus c) (void . toxGroupSelfSetStatus tox g)

    callbacks state toxav = do
      toxavCallbackCall toxav $ \f a v -> do
        say ["AV_CALL", number f, shown (fromEnum a), shown (fromEnum v)]
        answered <- toxavAnswer toxav f audioRate videoRate
        say ["AV_ANSWER", number f, code answered]
      toxavCallbackCallState toxav $ \f s -> say ["AV_STATE", number f, shown s]
      toxavCallbackAudioReceiveFrame toxav $ \f pcm samples channels rate -> do
        say ["AV_AUDIO", number f, shown samples, shown channels, shown rate]
        modifyIORef' state (\s -> s { echoAudio = Just (f, pcm, samples, channels, rate) })
      toxavCallbackVideoReceiveFrame toxav $ \f w h y u v ys us vs -> do
        say ["AV_VIDEO", number f, shown w, shown h]
        let cw = (w + 1) `div` 2
            ch = (h + 1) `div` 2
            plane bytes stride width height = BS.concat
              [BS.take (fromIntegral width) (BS.drop (r * abs (fromIntegral stride)) bytes) | r <- [0 .. fromIntegral height - 1]]
        modifyIORef' state (\s -> s { echoVideo = Just (f, w, h, plane y ys w h, plane u us cw ch, plane v vs cw ch) })

    -- Last frame of each kind, sent back after toxavIterate.
    sendEchoFrames toxav state = do
      s <- readIORef state
      forM_ (echoAudio s) $ \(f, pcm, samples, channels, rate) -> toxavAudioSendFrame toxav f pcm samples channels rate
      forM_ (echoVideo s) $ \(f, w, h, y, u, v) -> toxavVideoSendFrame toxav f w h y u v
      writeIORef state s { echoAudio = Nothing, echoVideo = Nothing }

    -- 20 ms of silence for the audio conference, every 20 ms.
    sendSilence state = readIORef state >>= \s -> forM_ (conference s) $ \(ConferenceNumber n) -> do
      t <- getMonotonicTime
      when (t - silenceAt s >= 0.02) $ do
        writeIORef state s { silenceAt = t }
        let Tox ptr = tox
        void $ withArrayLen (replicate 960 0) $ \len samples ->
          Raw.toxav_group_send_audio ptr n samples (fromIntegral len) 1 48000

    loop toxav state relayAdded lastSave = do
      -- toxcore drops a relay it can't reach, so wait for it to listen.
      added <- case relay c of
        Just (host, p, key) | not relayAdded -> tcpPortOpen host p >>= \open -> do
          when open $ toxAddTcpRelay tox host p key >>= \r -> say ["TCP_RELAY_ADDED", outcome "TOX_ERR_BOOTSTRAP_OK" r]
          pure open
        _ -> pure True
      readIORef state >>= mapM_ (sendUnsent state) . Map.keys . Map.filterWithKey (\(_, _, out) _ -> out) . files
      events <- fromRight [] <$> toxEventsIterate tox
      mapM_ (handle toxav state) events
      interval <- toxIterationInterval tox
      avInterval <- case toxav of
        Just a -> do
          toxavIterate a
          sendEchoFrames a state
          sendSilence state
          toxavIterationInterval a
        Nothing -> pure interval
      now <- floor <$> getPOSIXTime
      saved <- case save c of
        Just path | now /= lastSave -> do
          bytes <- toxGetSavedata tox
          -- Written next to the file and renamed over it, so a killed peer
          -- leaves a whole save.
          ok <- try (BS.writeFile (path <> ".new") bytes >> renameFile (path <> ".new") path)
          either (\e -> hPutStrLn stderr (show (e :: SomeException))) pure ok
          pure now
        _ -> pure lastSave
      nodeIntervals <- mapM (\n -> toxEventsIterate n >> toxIterationInterval n) nodes
      threadDelay (1000 * fromIntegral (minimum (interval : avInterval : nodeIntervals)))
      loop toxav state added (saved :: Integer)

    audioRate = 48
    videoRate = 1000

    handle toxav state = \case
      FriendRequest e | acceptRequests c -> do
        say ["FRIEND_REQUEST", hex (toBytes (friendRequestPublicKey e))]
        say ["FRIEND_REQUEST_MESSAGE", friendRequestMessage e]
        void (toxFriendAddNorequest tox (friendRequestPublicKey e))
      FriendConnectionStatus e -> do
        let f = friendConnectionStatusFriendNumber e
            online = friendConnectionStatus e /= ConnectionNone
        say ["FRIEND_CONNECTION", number f, cName (friendConnectionStatus e)]
        forM_ toxav $ \a -> when (avCall c && online) $ toxavCall a f audioRate videoRate >>= \r -> say ["AV_CALLING", number f, code r]
        -- toxcore ends the transfers of a friend who goes offline.
        unless online $ modifyIORef' state (\s -> s { files = Map.filterWithKey (\(g, _, _) _ -> g /= f) (files s) })
        forM_ (conferenceNew c) $ \title -> when online (inviteToConference toxav state title f)
        forM_ (groupNew c) $ \name -> when online (inviteToGroup state name f)
      FriendName e -> say ["FRIEND_NAME", number (friendNameFriendNumber e), friendName e]
      FriendStatus e -> say ["FRIEND_STATUS", number (friendStatusFriendNumber e), cName (friendStatus e)]
      FriendMessage e -> do
        say ["MESSAGE", number (friendMessageFriendNumber e), friendMessage e]
        void (toxFriendSendMessage tox (friendMessageFriendNumber e) (friendMessageType e) (friendMessage e))
      -- toxav's packets come as events too, but only the custom ranges are
      -- for us, as with toxcore's callbacks.
      FriendLosslessPacket e | custom 160 191 (friendLosslessPacketData e) -> do
        let p = friendLosslessPacketData e
        say ["LOSSLESS_PACKET", number (friendLosslessPacketFriendNumber e), BS.drop 1 p]
        unless (isEcho (BS.drop 1 p)) $ void (toxFriendSendLosslessPacket tox (friendLosslessPacketFriendNumber e) (packetEcho p))
      FriendLossyPacket e | custom 200 254 (friendLossyPacketData e) -> do
        let p = friendLossyPacketData e
        say ["LOSSY_PACKET", number (friendLossyPacketFriendNumber e), BS.drop 1 p]
        unless (isEcho (BS.drop 1 p)) $ void (toxFriendSendLossyPacket tox (friendLossyPacketFriendNumber e) (packetEcho p))
      FileRecv e | isJust (fileDir c) -> fileOffered state e
      FileRecvChunk e | Just dir <- fileDir c -> fileChunk state dir e
      FileRecvControl e | isJust (fileDir c), fileRecvControl e == FileControlCancel -> do
        let key out = (fileRecvControlFriendNumber e, fileRecvControlFileNumber e, out)
        s <- readIORef state
        forM_ (take 1 [(k, f) | k <- [key False, key True], Just f <- [Map.lookup k (files s)]]) $ \(k, f) -> do
          say ["FILE_CANCELLED", fileName f]
          writeIORef state s { files = Map.delete k (files s) }
      FileChunkRequest e | isJust (fileDir c) -> chunkRequested state e
      ConferenceInvite e -> toxConferenceJoin tox (conferenceInviteFriendNumber e) (conferenceInviteCookie e) >>= \case
        Right n -> say ["CONFERENCE_JOINED", number n]
        Left err -> say ["CONFERENCE_JOIN_FAILED", cName err]
      ConferenceTitle e -> say ["CONFERENCE_TITLE", number (conferenceTitleConferenceNumber e), conferenceTitle e]
      -- Echo messages from others back to the conference, but not echoes.
      ConferenceMessage e -> do
        let n = conferenceMessageConferenceNumber e
            m = conferenceMessage e
        ours <- toxConferencePeerNumberIsOurs tox n (conferenceMessagePeerNumber e)
        unless (ours == Right True) $ do
          say ["CONFERENCE_MESSAGE", number n, m]
          unless (isEcho m) $ void (toxConferenceSendMessage tox n (conferenceMessageType e) (echo toxMaxMessageLength m))
      GroupInvite e -> do
        joined <- toxGroupInviteAccept tox (groupInviteFriendNumber e) (groupInviteInviteData e) nick BS.empty
        say ["GROUP_INVITE", groupInviteGroupName e, outcome "TOX_ERR_GROUP_INVITE_ACCEPT_OK" joined, either (const (shown (maxBound :: Word32))) number joined]
      GroupSelfJoin e -> do
        say ["GROUP_SELF_JOIN", number (groupSelfJoinGroupNumber e)]
        setStatus (groupSelfJoinGroupNumber e)
      GroupPeerStatus e -> do
        name <- peerName (groupPeerStatusGroupNumber e) (groupPeerStatusPeerId e)
        say ["GROUP_PEER_STATUS", number (groupPeerStatusGroupNumber e), name, cName (groupPeerStatus e)]
      GroupPeerJoin e -> do
        let g = groupPeerJoinGroupNumber e
            p = groupPeerJoinPeerId e
        peerName g p >>= \name -> say ["GROUP_PEER_JOIN", number g, name]
        -- With --group-moderate, the founder tries every setting and role on
        -- the peer, then kicks it.
        role <- toxGroupSelfGetRole tox g
        when (groupModerate c && role == Right GroupRoleFounder) $ do
          set <- sequence
            [ isRight <$> toxGroupSetPeerLimit tox g 50
            , isRight <$> toxGroupSetVoiceState tox g GroupVoiceStateModerator
            , isRight <$> toxGroupSetTopicLock tox g GroupTopicLockDisabled
            , isRight <$> toxGroupSetPassword tox g "secret" ]
          say ("GROUP_SET" : map (shown . fromEnum) set)
          forM_ [GroupRoleModerator, GroupRoleObserver, GroupRoleUser] $ \r ->
            toxGroupSetRole tox g p r >>= \result -> say ["GROUP_SET_ROLE", outcome "TOX_ERR_GROUP_SET_ROLE_OK" result]
          toxGroupKickPeer tox g p >>= \result -> say ["GROUP_KICK", outcome "TOX_ERR_GROUP_KICK_PEER_OK" result]
      GroupModeration e -> say ["GROUP_MODERATION", number (groupModerationGroupNumber e), short "TOX_GROUP_MOD_EVENT_" (groupModerationModType e)]
      GroupPeerLimit e -> say ["GROUP_PEER_LIMIT", number (groupPeerLimitGroupNumber e), shown (groupPeerLimit e)]
      GroupVoiceState e -> say ["GROUP_VOICE", number (groupVoiceStateGroupNumber e), short "TOX_GROUP_VOICE_STATE_" (groupVoiceState e)]
      GroupTopicLock e -> say ["GROUP_TOPIC_LOCK", number (groupTopicLockGroupNumber e), short "TOX_GROUP_TOPIC_LOCK_" (groupTopicLock e)]
      GroupPassword e -> say ["GROUP_PASSWORD", number (groupPasswordGroupNumber e), groupPassword e]
      GroupPeerExit e -> say ["GROUP_PEER_EXIT", number (groupPeerExitGroupNumber e), groupPeerExitName e, cName (groupPeerExitExitType e)]
      GroupTopic e -> say ["GROUP_TOPIC", number (groupTopicGroupNumber e), groupTopic e]
      GroupJoinFail e -> say ["GROUP_JOIN_FAIL", number (groupJoinFailGroupNumber e), cName (groupJoinFailFailType e)]
      -- Echo group messages from others back to the group, but not echoes.
      GroupMessage e -> do
        let m = groupMessage e
        say ["GROUP_MESSAGE", number (groupMessageGroupNumber e), m]
        unless (isEcho m) $ void (toxGroupSendMessage tox (groupMessageGroupNumber e) (groupMessageMessageType e) (echo toxMaxMessageLength m))
      -- And private ones privately.
      GroupPrivateMessage e -> do
        let m = groupPrivateMessage e
        say ["GROUP_PRIVATE_MESSAGE", number (groupPrivateMessageGroupNumber e), m]
        unless (isEcho m) $ void $ toxGroupSendPrivateMessage tox (groupPrivateMessageGroupNumber e) (groupPrivateMessagePeerId e)
          (groupPrivateMessageMessageType e) (echo toxMaxMessageLength m)
      -- Echo custom group packets the same way, losslessly.
      GroupCustomPacket e -> do
        let p = groupCustomPacketData e
        say ["GROUP_CUSTOM", number (groupCustomPacketGroupNumber e), p]
        unless (isEcho p) $ void (toxGroupSendCustomPacket tox (groupCustomPacketGroupNumber e) True (echo toxMaxCustomPacketSize p))
      _ -> pure ()

    peerName g p = fromRight BS.empty <$> toxGroupPeerGetName tox g p

    -- With --conference-new, friends get an invite to a new conference when
    -- they connect, an audio one with --av (we send it silence).
    inviteToConference toxav state title f = do
      s <- readIORef state
      created <- case conference s of
        Just n -> pure (Just n)
        Nothing -> do
          made <- case toxav of
            Just _ -> do
              cb <- Raw.wrapToxavAudioDataCb $ \_ n _ _ _ _ _ _ -> readIORef state >>= \s' -> unless (heard s') $ do
                say ["CONFERENCE_AUDIO", shown n]
                writeIORef state s' { heard = True }
              let Tox ptr = tox
              r <- Raw.toxav_add_av_groupchat ptr cb nullPtr
              pure (if r < 0 then Nothing else Just (ConferenceNumber (fromIntegral r)))
            Nothing -> either (const Nothing) Just <$> toxConferenceNew tox
          case made of
            Nothing -> Nothing <$ say ["CONFERENCE_NEW_FAILED"]
            Just n -> do
              void (toxConferenceSetTitle tox n title)
              say ["CONFERENCE_NEW", number n]
              modifyIORef' state (\st -> st { conference = Just n })
              pure (Just n)
      forM_ created $ \n -> toxConferenceInvite tox f n >>= \r -> say ["CONFERENCE_INVITED", number n, outcome "TOX_ERR_CONFERENCE_INVITE_OK" r]

    -- With --group-new, friends get an invite to a new private group when
    -- they connect.
    inviteToGroup state name f = readIORef state >>= \s -> case group s of
      Just g -> toxGroupInviteFriend tox g f >>= \r -> say ["GROUP_INVITED", number g, outcome "TOX_ERR_GROUP_INVITE_FRIEND_OK" r]
      Nothing -> toxGroupNew tox GroupPrivacyStatePrivate name nick >>= \case
        Left err -> say ["GROUP_NEW_FAILED", cName err]
        Right g -> do
          setStatus g
          writeIORef state s { group = Just g }
          chatId tox "GROUP_CHAT_ID" g
          void (toxGroupSetTopic tox g "C topic")
          toxGroupInviteFriend tox g f >>= \r -> say ["GROUP_INVITED", number g, outcome "TOX_ERR_GROUP_INVITE_FRIEND_OK" r]

    fileOffered state e = do
      let name = fileRecvFilename e
          size = fileRecvFileSize e
          friend = fileRecvFriendNumber e
          n = fileRecvFileNumber e
          -- Refuse names that aren't plain file names, and sizes we can't
          -- hold.
          badName = BS.null name || Char8.elem '/' name || BS.isPrefixOf name ".." && BS.length name <= 2
      s <- readIORef state
      if badName || size > maxFileSize || Map.size (files s) >= 16
        then void (toxFileControl tox friend n FileControlCancel)
        else do
          writeIORef state s { files = Map.insert (friend, n, False) (File name (fileRecvKind e) size Map.empty BS.empty 0 0 0) (files s) }
          void (toxFileControl tox friend n FileControlResume)

    fileChunk state dir e = do
      let key = (fileRecvChunkFriendNumber e, fileRecvChunkFileNumber e, False)
          bytes = fileRecvChunkData e
          at = fileRecvChunkPosition e
      s <- readIORef state
      forM_ (Map.lookup key (files s)) $ \f -> if not (BS.null bytes)
        then when (at + fromIntegral (BS.length bytes) <= fileSize f) $
          writeIORef state s { files = Map.insert key f { fileChunks = Map.insert at bytes (fileChunks f) } (files s) }
        else do
          let whole = BS.concat (Map.elems (fileChunks f))
              echoName = BS.take toxMaxFilenameLength ("echo-" <> fileName f)
          _ <- try (BS.writeFile (dir <> "/" <> Char8.unpack (fileName f)) whole) :: IO (Either SomeException ())
          say ["FILE_RECEIVED", fileName f, shown (fileSize f)]
          toxFileSend tox (fileRecvChunkFriendNumber e) (fileKind f) (fileSize f) Nothing echoName >>= \case
            Left err -> do
              say ["FILE_SEND_FAILED", cName err]
              writeIORef state s { files = Map.delete key (files s) }
            Right n -> writeIORef state s { files = Map.insert (fileRecvChunkFriendNumber e, n, True)
              f { fileName = echoName, fileData = whole, fileChunks = Map.empty } (Map.delete key (files s)) }

    chunkRequested state e = do
      let key = (fileChunkRequestFriendNumber e, fileChunkRequestFileNumber e, True)
          at = fileChunkRequestPosition e
          len = fromIntegral (fileChunkRequestLength e)
      s <- readIORef state
      forM_ (Map.lookup key (files s)) $ \f -> if len == 0
        then do
          say ["FILE_SENT", fileName f]
          writeIORef state s { files = Map.delete key (files s) }
        else do
          let from = if unsentFrom f == unsentTo f then at else unsentFrom f
          writeIORef state s { files = Map.insert key f { unsentFrom = from, unsentTo = at + len, chunkSize = max len (chunkSize f) } (files s) }
          sendUnsent state key

    -- A chunk toxcore refused for a full queue must go again before later
    -- ones (it refuses those until then).
    sendUnsent state key = readIORef state >>= \s -> forM_ (Map.lookup key (files s)) $ \f0 -> do
      let (friend, n, _) = key
          go f
            | unsentFrom f >= unsentTo f = pure f
            | otherwise = do
                let len = min (chunkSize f) (unsentTo f - unsentFrom f)
                    bytes = BS.take (fromIntegral len) (BS.drop (fromIntegral (unsentFrom f)) (fileData f))
                toxFileSendChunk tox friend n (unsentFrom f) bytes >>= \case
                  Left ErrFileSendChunkSendq -> pure f
                  _ -> go f { unsentFrom = unsentFrom f + len }
      f' <- go f0
      modifyIORef' state (\st -> st { files = Map.adjust (const f') key (files st) })

-- | Something listens on the host and TCP port.
tcpPortOpen :: String -> Word16 -> IO Bool
tcpPortOpen host p = do
  addrs <- fromRight [] <$> (try (Socket.getAddrInfo (Just Socket.defaultHints { Socket.addrSocketType = Socket.Stream }) (Just host) (Just (show p))) :: IO (Either SomeException [Socket.AddrInfo]))
  or <$> mapM attempt addrs
  where
    attempt a = isRight <$> (try (bracket (Socket.openSocket a) Socket.close (`Socket.connect` Socket.addrAddress a)) :: IO (Either SomeException ()))
