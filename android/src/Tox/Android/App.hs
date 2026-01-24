{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
{-# LANGUAGE TypeApplications  #-}
-- | App state, the actions widgets fire, and the Tox behind them.
module Tox.Android.App
  ( app
  ) where

import           Control.Concurrent        (ThreadId, forkIO, killThread,
                                            threadDelay)
import           Control.Concurrent.Chan   (newChan, readChan, writeList2Chan)
import           Control.Concurrent.MVar   (MVar, modifyMVar, modifyMVar_,
                                            newMVar, readMVar, withMVar)
import           Control.Exception         (Exception (..), IOException,
                                            SomeException (..), evaluate,
                                            onException, throwIO, try)
import           Control.Monad             (forM_, forever, join, unless, void,
                                            when, (<=<))
import           Crypto.Saltine.Core.Utils (randomByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Internal  as BS
import           Data.Char                 (toLower)
import           Data.Int                  (Int16)
import           Data.IORef                (IORef, atomicModifyIORef',
                                            modifyIORef', newIORef, readIORef,
                                            writeIORef)
import           Data.List                 (find)
import qualified Data.Map.Strict           as Map
import           Data.Maybe                (catMaybes, fromMaybe, isJust,
                                            isNothing, listToMaybe)
import qualified Data.Set                  as Set
import qualified Data.Text                 as Text
import           Data.Time                 (NominalDiffTime, UTCTime,
                                            addUTCTime, diffUTCTime,
                                            getCurrentTime, getCurrentTimeZone,
                                            utctDay)
import           Data.Time.Clock.POSIX     (utcTimeToPOSIXSeconds)
import qualified Data.Vector.Storable      as V
import           Data.Word                 (Word64)
import           Foreign.ForeignPtr        (castForeignPtr)
import           Hatter                    (CallButton (..),
                                            LifecycleEvent (..), MobileApp (..),
                                            MobileContext (..), PickedFile (..),
                                            UserState (..), capturePicture,
                                            copyToClipboard, imageSize,
                                            is24HourClock, isDarkMode,
                                            loggingMobileContext, openFile,
                                            openUri, pickFiles, pickPicture,
                                            platformLog, saveFile)
import           Hatter.Action             (Action, ActionState, createAction,
                                            createOnChange, newActionState,
                                            runActionM)
import           Hatter.BottomSheet        (BottomSheetAction (..),
                                            BottomSheetConfig (..),
                                            showBottomSheet)
import           Hatter.CallAudio          (CallAudio, CallRoute, CallTone (..),
                                            playCallAudio, setCallRoute,
                                            setCallTone, startCallAudio,
                                            stopCallAudio)
import qualified Hatter.CallAudio          as CallAudio
import           Hatter.CallVideo          (CallCamera, VideoFrame (..),
                                            showVideoFrame, startCallCamera,
                                            stopCallCamera)
import           Hatter.DatabaseKey        (DatabaseKey (..), databaseKey)
import           Hatter.DeviceInfo         (DeviceInfo (..), getDeviceInfo)
import           Hatter.Dialog             (DialogAction (..),
                                            DialogConfig (..), showDialog)
import           Hatter.FilesDir           (getAppFilesDir)
import           Hatter.Http               (HttpMethod (..), HttpRequest (..),
                                            HttpResponse (..), performRequest)
import           Hatter.Location           (LocationData (..),
                                            startLocationUpdates,
                                            stopLocationUpdates)
import           Hatter.Notification       (Notification (..),
                                            NotificationKind (..),
                                            allowFullScreen, cancelNotification,
                                            fullScreenAllowed, setOngoingCall,
                                            setRunInBackground,
                                            setServiceStatus,
                                            setShowOverLockScreen,
                                            showNotification, stopBackground)
import           Hatter.Permission         (Permission (..), PermissionState,
                                            PermissionStatus (..),
                                            requestPermission)
import           Hatter.Picture            (PictureKind (..), picturePixels,
                                            shrinkPicture)
import           System.Directory          (createDirectoryIfMissing,
                                            removeDirectory, removeFile,
                                            renameFile)
import           System.FilePath           (dropExtension, takeDirectory,
                                            takeExtension, takeFileName, (</>))
import           System.IO                 (IOMode (..), hFileSize, withFile)
import qualified Tox.Application.Tox       as Tox
import           Tox.AV                    (Picture (..))

import qualified Tox.Android.Avatars       as Avatars
import           Tox.Android.Export        (exportSave)
import qualified Tox.Android.Formats       as Formats
import           Tox.Android.Identicon     (identicon, identiconPng)
import           Tox.Android.Import        (importSave)
import           Tox.Android.Links         (findLinks)
import           Tox.Android.Locations     (location, mapsUri)
import           Tox.Android.Model
import qualified Tox.Android.Network       as Network
import           Tox.Android.Nodes         (Node, builtIn, nodesUrl, readNodes)
import           Tox.Android.Pictures      (PictureFormat (..), pictureFormat,
                                            pictureFormats)
import           Tox.Android.Qoi           (isQoi, qoiBitmap, qoiSize)
import           Tox.Android.QrCode        (toxIdQr)
import qualified Tox.Android.Store         as Store
import           Tox.Android.Store         (Identity (..))
import           Tox.Android.Theme         (dp, theme)
import           Tox.Android.View
import qualified Tox.Sync.Pairing          as Pairing

-- | Update notifications for unread messages, missed calls and friend
-- requests, and the ringing call if this profile has it. Cancel what's been
-- read or answered.
notify :: Hub -> ProfileId -> Bool -> Model -> Model -> IO ()
notify hub pid owns old new = do
  now <- getCurrentTime
  named <- readIORef (hubNamed hub)
  -- Name the profile if more than 1 is online.
  let titled title
        | named = title <> " \x00B7 " <> profileNickname (modelProfile new)
        | otherwise = title
  let missed n = [if n == 1 then "Missed call" else Text.pack (show n) <> " missed calls"]
  forM_ [ (messagesKey, "Messages", "ic_chat_bubble_outline", MessageNotification, notifications now)
        , (missedKey, "Missed calls", "ic_call_missed", MissedCall, fmap missed . missedCalls now) ] $
    \(keyOf, channel, icon, kind, shown) -> do
      let before = shown old
          after = shown new
      forM_ (Map.toList after) $ \(cid, lines') ->
        unless (Map.lookup cid before == Just lines') $
          forM_ (Map.lookup cid (modelContacts new)) $ \contact -> showNotification Notification
            { notificationKey = keyed pid (keyOf cid)
            , notificationChannel = channel
            , notificationIcon = icon
            , notificationTitle = titled (contactLabel cid contact)
            , notificationLines = lines'
            , notificationKind = kind
            }
      forM_ (Map.keys (Map.difference before after)) (cancelNotification . keyed pid . keyOf)
  forM_ (Map.toList (modelRequests new)) $ \(cid, message) ->
    unless (Map.lookup cid (modelRequests old) == Just message) $ showNotification Notification
      { notificationKey = keyed pid (requestKey cid)
      , notificationChannel = "Friend requests"
      , notificationIcon = "ic_add"
      , notificationTitle = titled "Friend request"
      , notificationLines = [message]
      , notificationKind = MessageNotification
      }
  forM_ (Map.keys (Map.difference (modelRequests old) (modelRequests new))) (cancelNotification . keyed pid . requestKey)
  let groupsBefore = groupNotifications now old
      groupsAfter = groupNotifications now new
  forM_ (Map.toList groupsAfter) $ \(gid, lines') ->
    unless (Map.lookup gid groupsBefore == Just lines') $
      forM_ (Map.lookup gid (modelGroups new)) $ \g -> showNotification Notification
        { notificationKey = keyed pid (groupKey gid)
        , notificationChannel = "Messages"
        , notificationIcon = "ic_group"
        , notificationTitle = titled (groupLabel g)
        , notificationLines = lines'
        , notificationKind = MessageNotification
        }
  forM_ (Map.keys (Map.difference groupsBefore groupsAfter)) (cancelNotification . keyed pid . groupKey)
  let pending = Map.filter (isNothing . inviteAnswered) . modelInvites
  forM_ (Map.toList (pending new)) $ \(at@(cid, _), invite) ->
    unless (Map.member at (pending old)) $ showNotification Notification
      { notificationKey = keyed pid (inviteKey at)
      , notificationChannel = "Group invites"
      , notificationIcon = "ic_group"
      , notificationTitle = titled (inviteLabel invite)
      , notificationLines = [maybe "A friend" (contactLabel cid) (Map.lookup cid (modelContacts new)) <> " invited you"]
      , notificationKind = MessageNotification
      }
  forM_ (Map.keys (Map.difference (pending old) (pending new))) (cancelNotification . keyed pid . inviteKey)
  -- The service notification shows the call with its time.
  let ongoing model = case modelCall model of
        Just c | Talking since <- callPhase c ->
          (\contact -> (contactLabel (callContact c) contact, since)) <$> Map.lookup (callContact c) (modelContacts model)
        _ -> Nothing
  when (owns && ongoing old /= ongoing new) $ setOngoingCall (keyed pid callNotification) (ongoing new)
  when (modelConnection old /= modelConnection new) $ connected hub pid (Just (modelConnection new))
  when (settingStay (modelDevice old) /= settingStay (modelDevice new)) $
    setRunInBackground (settingStay (modelDevice new))
  -- Only the call shows over the lock screen, never the chats.
  let overLockScreen = maybe False (not . callHidden) . modelCall
  when (owns && overLockScreen old /= overLockScreen new) $ setShowOverLockScreen (overLockScreen new)
  when owns $ case (ringing old, ringing new) of
    (Nothing, Just c) -> forM_ (Map.lookup (callContact c) (modelContacts new)) $ \contact ->
      showNotification Notification
        { notificationKey = keyed pid callNotification
        , notificationChannel = "Incoming calls"
        , notificationIcon = "ic_call"
        , notificationTitle = titled (contactLabel (callContact c) contact)
        , notificationLines = [if callPeerVideo c then "Incoming video call" else "Incoming voice call"]
        , notificationKind = RingingCall
        }
    (Just _, Nothing) -> cancelNotification (keyed pid callNotification)
    _ -> pure ()
  where
    -- Only while hTox isn't in front (otherwise it rings itself, and nothing
    -- should cover the call screen).
    ringing model = case modelCall model of
      Just c | callPhase c == Ringing, not (modelShown model) -> Just c
      _                                                       -> Nothing

-- | Nothing when the profile goes away. The service notification shows the
-- best connection.
connected :: Hub -> ProfileId -> Maybe Connection -> IO ()
connected hub pid connection = modifyMVar_ (hubConnections hub) $ \known -> do
  let known' = Map.alter (const connection) pid known
      best = maximum . (Offline :) . Map.elems
  when (best known /= best known') $ setServiceStatus (connectionText (best known'))
  pure known'

connectionText :: Connection -> Text.Text
connectionText = \case
  Offline -> "Connecting\x2026"
  ViaTcp  -> "Online through a relay"
  ViaUdp  -> "Online"

-- | Longest side of pictures from the gallery or camera (we also strip the
-- location).
pictureSide :: Int
pictureSide = 2048

-- | How long we stay online after hTox is closed, with stay online off.
stayGrace :: NominalDiffTime
stayGrace = 15

-- | Notification key of the incoming call.
callNotification :: Text.Text
callNotification = "call"

pcmBytes :: V.Vector Int16 -> BS.ByteString
pcmBytes pcm = let (p, n) = V.unsafeToForeignPtr0 pcm in BS.fromForeignPtr0 (castForeignPtr p) (n * 2)

bytesPcm :: BS.ByteString -> V.Vector Int16
bytesPcm bytes = let (p, n) = BS.toForeignPtr0 bytes in V.unsafeFromForeignPtr0 (castForeignPtr p) (n `div` 2)

-- | We send audio to Tox in 20 ms frames.
audioRate, audioFrame :: Int
audioRate = 48000
audioFrame = 960

pictureFrame :: Picture -> VideoFrame
pictureFrame p = VideoFrame (pictureWidth p) (pictureHeight p) (BS.concat [pictureY p, pictureU p, pictureV p])

framePicture :: VideoFrame -> Picture
framePicture f = Picture w h y u v
  where
    w = frameWidth f
    h = frameHeight f
    (y, chroma) = BS.splitAt (w * h) (frameI420 f)
    (u, v) = BS.splitAt (half w * half h) chroma
    half n = (n + 1) `div` 2

mirrored :: VideoFrame -> VideoFrame
mirrored f = f { frameI420 = BS.concat (rows w y ++ rows half u ++ rows half v) }
  where
    w = frameWidth f
    half = (w + 1) `div` 2
    (y, chroma) = BS.splitAt (w * frameHeight f) (frameI420 f)
    (u, v) = BS.splitAt (BS.length chroma `div` 2) chroma
    rows n plane
      | BS.null plane = []
      | otherwise = let (row, rest) = BS.splitAt n plane in BS.reverse row : rows n rest

-- | What a picked file is for. Pictures may get converted to the chat's
-- picture format.
data Picking = ForPicture | ForFile | ForProfile | ForBackup
  deriving (Eq)

data Media = Media
  { mediaAudio  :: IORef (Maybe CallAudio)
  , mediaCamera :: IORef (Maybe CallCamera)
  , mediaMuted  :: IORef Bool
  }

-- | Start and stop call audio and the camera as the call changes.
callMedia :: Network.Network -> Media -> (Route -> [Route] -> IO ()) -> Model -> Model -> IO ()
callMedia network media onRoutes old new = do
  case (talking old, talking new) of
    (Nothing, Just cid) -> do
      let speaker = maybe False ((== Speaker) . callRoute) (modelCall new)
          sending frame = do
            silent <- readIORef (mediaMuted media)
            unless silent $ Network.sendAudio network cid audioRate 1 (bytesPcm frame)
      started <- startCallAudio audioRate audioFrame speaker sending $ \route routes ->
        onRoutes (fromCallRoute route) (map fromCallRoute routes)
      writeIORef (mediaAudio media) (Just started)
    (Just _, Nothing) -> stopping (mediaAudio media) stopCallAudio
    _ -> pure ()
  -- Restart with the other camera when the user flips it.
  when (filming old /= filming new) $ do
    stopping (mediaCamera media) stopCallCamera
    forM_ (filming new) $ \(cid, backCamera) -> do
      started <- startCallCamera (not backCamera) $ \frame -> do
        -- Mirror our own view (the friend gets it unmirrored).
        showVideoFrame selfStream (if backCamera then frame else mirrored frame)
        Network.sendVideo network cid (framePicture frame)
      writeIORef (mediaCamera media) (Just started)
  writeIORef (mediaMuted media) (maybe False callMuted (modelCall new))
  let tone model = case callPhase <$> modelCall model of
        Just Ringing | modelShown model -> Ringtone
        Just Calling                    -> Ringback
        _                               -> Quiet
  when (tone old /= tone new) $ setCallTone (tone new)
  where
    talking model = case modelCall model of
      Just c | Talking _ <- callPhase c -> Just (callTarget c)
      _                                 -> Nothing
    filming model = case modelCall model of
      Just c | callCamera c -> (, callBackCamera c) <$> talking model
      _                     -> Nothing
    stopping ref stop = readIORef ref >>= mapM_ stop >> writeIORef ref Nothing

fromCallRoute :: CallRoute -> Route
fromCallRoute = \case
  CallAudio.Earpiece  -> Earpiece
  CallAudio.Speaker   -> Speaker
  CallAudio.Wired     -> Wired
  CallAudio.Bluetooth -> Bluetooth

toCallRoute :: Route -> CallRoute
toCallRoute = \case
  Earpiece  -> CallAudio.Earpiece
  Speaker   -> CallAudio.Speaker
  Wired     -> CallAudio.Wired
  Bluetooth -> CallAudio.Bluetooth

messagesKey, missedKey, requestKey :: ContactId -> Text.Text
messagesKey (ContactId key) = key
missedKey (ContactId key) = "missed-" <> key
requestKey (ContactId key) = "request-" <> key

groupKey :: GroupId -> Text.Text
groupKey (GroupId chat) = "group-" <> chat

inviteKey :: (ContactId, GroupId) -> Text.Text
inviteKey (ContactId friend, GroupId chat) = "invite-" <> friend <> "-" <> chat

-- | Notification key with the profile in front.
keyed :: ProfileId -> Text.Text -> Text.Text
keyed (ProfileId i) key = Text.pack (show i) <> ":" <> key

-- | Profile and key from a notification key. Old ones (from before several
-- profiles were online at once) have no profile.
profileOf :: Text.Text -> (Maybe ProfileId, Text.Text)
profileOf key = case Text.breakOn ":" key of
  (i, rest) | not (Text.null rest), [(n, "")] <- reads (Text.unpack i) -> (Just (ProfileId n), Text.drop 1 rest)
  _ -> (Nothing, key)

notificationOf :: Text.Text -> Maybe Screen
notificationOf key
  | Just k <- Text.stripPrefix "missed-" key = Just (Chat (ContactId k))
  | Just _ <- Text.stripPrefix "request-" key = Just Contacts
  | Just k <- Text.stripPrefix "group-" key = Just (GroupChat (GroupId k))
  | Just k <- Text.stripPrefix "invite-" key, (friend, chat) <- Text.breakOn "-" k =
      Just (InviteScreen (ContactId friend) (GroupId (Text.drop 1 chat)))
  | key == callNotification = Nothing
  | otherwise = Just (Chat (ContactId key))

voices :: [(Text.Text, Tox.Voice)]
voices = [("Everyone but observers", Tox.VoiceAll), ("Moderators", Tox.VoiceModerators), ("The founder", Tox.VoiceFounder)]

memberActionName :: MemberAction -> Text.Text
memberActionName = \case
  MakeModerator -> "Make moderator"
  MakeUser      -> "Make a member who can speak"
  MakeObserver  -> "Make observer"
  Kick          -> "Remove from the group"

-- | Choices of the + button.
adding :: [(Text.Text, Screen)]
adding = [("Contact", AddContact), ("Group", NewGroupScreen), ("Public group by its chat ID", JoinGroupScreen)]

-- | Auto-accept sizes, including the old default.
autoAccepts :: [(Text.Text, Word64)]
autoAccepts =
  ("Never", 0) : [(Text.pack (show n) <> " MB", n * 1024 * 1024) | n <- [1, 4, 16, 32, 64, 256]]

routeName :: Route -> Text.Text
routeName = \case
  Earpiece  -> "Phone"
  Speaker   -> "Speaker"
  Wired     -> "Headset"
  Bluetooth -> "Bluetooth"

muteChoices :: [(Text.Text, Maybe NominalDiffTime)]
muteChoices =
  [("For 1 hour", Just 3600), ("For 8 hours", Just 28800), ("For 1 week", Just 604800), ("Always", Nothing)]

toMillis :: UTCTime -> Integer
toMillis = round . (* 1000) . utcTimeToPOSIXSeconds

data ContactActions = ContactActions
  { caOpen      :: Action
  , caAccept    :: Action
  , caReject    :: Action
  , caDetails   :: Action
  , caMute      :: Action
  , caDelete    :: Action
  , caCopyKey   :: Action
  , caForwardTo :: Action
  , caCallBack  :: Action
  , caPictures  :: Action
  }

data GroupActions = GroupActions
  { gaOpen      :: Action
  , gaDetails   :: Action
  , gaMute      :: Action
  , gaLeave     :: Action
  , gaDelete    :: Action
  , gaCopyId    :: Action
  , gaTopic     :: Action
  , gaMentions  :: Action
  , gaInvite    :: Action
  , gaSettings  :: Action
  , gaPrivacy   :: Action
  , gaTopicLock :: Action
  , gaVoice     :: Action
  , gaRelayBot  :: Action
    -- ^ Choose the relay bot.
  , gaStopRelay :: Action
  }

data InviteActions = InviteActions
  { iaOpen    :: Action
  , iaJoin    :: Action
  , iaDecline :: Action
  }

newtype ToxFailed = ToxFailed Tox.NewError
  deriving (Show)

instance Exception ToxFailed where
  displayException (ToxFailed err) = "Tox didn't start: " <> show err

-- | All profiles online, each with its own Tox.
data Hub = Hub
  { hubDatabase    :: Store.Database
  , hubDir         :: FilePath
  , hubSessions    :: MVar (Map.Map ProfileId Session)
  , hubShown       :: IORef ProfileId
  , hubRedraw      :: IORef (IO ())
  , hubNodes       :: IORef [Node]
  , hubFetched     :: IORef Bool
    -- ^ Whether we fetched the node list yet.
  , hubMedia       :: Media
  , hubCall        :: IORef (Maybe ProfileId)
    -- ^ Profile with the call. There's at most 1 (we have 1 microphone and
    -- speaker).
  , hubConnections :: MVar (Map.Map ProfileId Connection)
  , hubNamed       :: IORef Bool
    -- ^ Name the profile in notifications (more than 1 is online).
  , hubWatch       :: ThreadId
  }

data Session = Session
  { sessionModel   :: MVar Model
  , sessionNetwork :: Network.Network
  , sessionFire    :: Event -> IO ()
  , sessionStop    :: IO ()
  }

-- | Shown profile first. Others that can't start stay offline.
newHub :: IORef (IO ()) -> IO Hub
newHub redraw = do
  dir <- getAppFilesDir
  key <- databaseKey >>= \case
    DatabaseKey key -> pure (Just key)
    NoKeyStore      -> pure Nothing
    KeyStoreFailed  -> throwIO Store.Locked
  database <- Store.open key (dir </> "tox.db")
  mapM_ (createDirectoryIfMissing True) [dir </> "received", dir </> "sent"]
  shown <- Store.activeProfile database
  -- Last fetched node list, until we fetch a new one.
  cached <- either (const Nothing) readNodes <$> try @IOException (BS.readFile (dir </> "nodes.json"))
  sessions <- newMVar Map.empty
  media <- Media <$> newIORef Nothing <*> newIORef Nothing <*> newIORef False
  -- With stay online off, stop a while after hTox is closed (not during a
  -- call).
  watchThread <- forkIO $ do
    let watch since = do
          threadDelay 5000000
          models <- mapM (readMVar . sessionModel) . Map.elems =<< readMVar sessions
          now <- getCurrentTime
          if any (\m -> settingStay (modelDevice m) || modelShown m || isJust (modelCall m)) models
            then watch now
            else if diffUTCTime now since >= stayGrace then stopBackground else watch since
    getCurrentTime >>= watch
  hub <- Hub database dir sessions
    <$> newIORef shown <*> pure redraw <*> newIORef (fromMaybe builtIn cached) <*> newIORef False
    <*> pure media <*> newIORef Nothing <*> newMVar Map.empty <*> newIORef False <*> pure watchThread
  setServiceStatus (connectionText Offline)
  -- If the shown profile can't go online, stop the watch too, or it stops
  -- the app while the user is about to try again.
  void (sessionFor hub shown) `onException` killThread watchThread
  others <- filter (/= shown) . map accountId <$> Store.profiles database
  forM_ others $ \pid -> try @SomeException (sessionFor hub pid) >>= \case
    Left err -> platformLog ("A profile didn't go online: " <> Text.pack (displayException err))
    Right _ -> pure ()
  setRunInBackground . settingStay . modelDevice =<< readMVar . sessionModel =<< sessionFor hub shown
  pure hub

stopHub :: Hub -> IO ()
stopHub hub = do
  killThread (hubWatch hub)
  modifyMVar_ (hubSessions hub) $ \sessions -> Map.empty <$ mapM_ sessionStop sessions

-- | Goes online first if it isn't.
sessionFor :: Hub -> ProfileId -> IO Session
sessionFor hub pid = modifyMVar (hubSessions hub) $ \sessions -> case Map.lookup pid sessions of
  Just session -> pure (sessions, session)
  Nothing -> do
    session <- online hub pid
    let sessions' = Map.insert pid session sessions
    writeIORef (hubNamed hub) (Map.size sessions' > 1)
    pure (sessions', session)

-- | Also cancels its notifications.
goOffline :: Hub -> ProfileId -> IO ()
goOffline hub pid = modifyMVar_ (hubSessions hub) $ \sessions -> do
  mapM_ sessionStop (Map.lookup pid sessions)
  let sessions' = Map.delete pid sessions
  writeIORef (hubNamed hub) (Map.size sessions' > 1)
  pure sessions'

redrawIfShown :: Hub -> ProfileId -> IO ()
redrawIfShown hub pid = readIORef (hubShown hub) >>= \shown -> when (shown == pid) (join (readIORef (hubRedraw hub)))

online :: Hub -> ProfileId -> IO Session
online hub pid = do
  let store = Store.profileStore (hubDatabase hub) pid
      redraw = redrawIfShown hub pid
  model <- newMVar =<< Store.load store
  identity <- Store.identity store
  settings <- modelDevice <$> readMVar model
  -- Cancel a call that was ringing when hTox last stopped.
  cancelNotification (keyed pid callNotification)
  nodes <- readIORef (hubNodes hub)
  network <- either (throwIO . ToxFailed) pure =<< Network.start identity settings (hubDir hub </> "received") nodes
  unless (isJust identity) $ Network.identityOf network >>= Store.saveIdentity store
  Network.onMedia network Network.Media
    { Network.playAudio = \rate channels pcm -> playCallAudio rate channels (pcmBytes pcm)
    , Network.showVideo = showVideoFrame peerStream . pictureFrame
    }
  -- Run Tox commands in order on their own thread (Tox may be slow, and a
  -- tap shouldn't wait for it).
  asked <- newChan
  let fire event = do
        (commands, busy, device) <- modifyMVar model $ \old -> do
          let (new, commands) = update event old
          Store.save store old new
          owns <- claimCall hub pid old new
          notify hub pid owns old new
          -- Fork, as the platform reports routes while we hold the model.
          when owns $ callMedia network (hubMedia hub)
            (\route routes -> void . forkIO $ fire (RoutesChanged route routes) >> redraw)
            old new
          let busy = not owns && isNothing (modelCall old) && isJust (modelCall new)
          pure (new, (commands, busy, if modelDevice old /= modelDevice new then Just (modelDevice new) else Nothing))
        writeList2Chan asked commands
        when busy $ getCurrentTime >>= fire . CallElsewhere
        -- Device settings, so all profiles get them.
        forM_ device $ \d -> do
          others <- Map.elems . Map.delete pid <$> readMVar (hubSessions hub)
          forM_ others (`sessionFire` SetDevice d)
  askingThread <- Network.looping "Asking Tox" $
    readChan asked >>= Network.perform network >>= mapM_ fire >> redraw
  networkThreads <- Network.run network (\event -> fire event >> redraw)
  -- For the call timer and ring timeout.
  tickThread <- forkIO . forever $ do
    threadDelay 1000000
    calling <- isJust . modelCall <$> readMVar model
    when calling $ getCurrentTime >>= fire . Tick >> redraw
  let stop = modifyMVar_ model $ \current -> do
        mapM_ killThread (askingThread : tickThread : networkThreads)
        Network.stop network
        -- Cancel its notifications.
        owns <- claimCall hub pid current initial
        notify hub pid owns current initial { modelDevice = modelDevice current, modelProfile = modelProfile current }
        connected hub pid Nothing
        pure current
  pure (Session model network fire stop)

-- | Whether the profile has the call. It takes it if no other profile has
-- one, and gives it up when its call ends.
claimCall :: Hub -> ProfileId -> Model -> Model -> IO Bool
claimCall hub pid old new = atomicModifyIORef' (hubCall hub) $ \owner -> case (modelCall old, modelCall new) of
  (_, Just _) | maybe True (== pid) owner -> (Just pid, True)
  (Just _, Nothing) | owner == Just pid   -> (Nothing, True)
  _                                       -> (owner, False)

-- | Or a screen saying why it didn't start, with a button to try again.
app :: IO MobileApp
app = do
  actions <- newActionState
  -- With how to stop it, to show another profile.
  started <- newIORef Nothing
  failure <- newIORef Text.empty
  redraw <- newIORef (pure ())
  hub <- newIORef Nothing
  let start = try (hubbed >>= \h -> running actions h switch restart) >>= \case
        Right a -> writeIORef started (Just a)
        Left err@(SomeException inner) -> do
          platformLog ("hTox didn't start: " <> Text.pack (displayException err))
          -- Without the backtrace (that's in the log).
          writeIORef failure (Text.pack (displayException inner))
      hubbed = readIORef hub >>= \case
        Just h -> pure h
        Nothing -> newHub redraw >>= \h -> h <$ writeIORef hub (Just h)
      -- Show the newly chosen profile. All stay online.
      switch = do
        readIORef started >>= mapM_ snd
        writeIORef started Nothing
        start
        inApp (`onLifecycle` Start)
        join (readIORef redraw)
      -- Restart all profiles (Tox takes some settings only at the start).
      restart = do
        readIORef hub >>= mapM_ stopHub
        writeIORef hub Nothing
        switch
      inApp f = readIORef started >>= mapM_ (f . maContext . fst)
  start
  -- The app is in front when this is pressed, so tell the new app.
  retry <- runActionM actions (createAction (start >> inApp (`onLifecycle` Start)))
  device <- getDeviceInfo
  pure MobileApp
    { maContext = loggingMobileContext
        { onLifecycle = \event -> inApp (`onLifecycle` event)
        , onBack = readIORef started >>= maybe (pure False) (onBack . maContext . fst)
        , onNotificationOpened = \key -> inApp (`onNotificationOpened` key)
        , onCallButton = \key button -> inApp (\c -> onCallButton c key button)
        , onFilePicked = \picked -> inApp (`onFilePicked` picked)
        , onPicturePicked = \png -> inApp (`onPicturePicked` png)
        }
    , maActionState = actions
    , maView = \state -> writeIORef redraw (userRequestRedraw state) >> readIORef started >>= \case
        Just (a, _) -> maView a state
        Nothing -> do
          dark <- isDarkMode
          startFailure (theme (diScreenDensity device) (fromIntegral (diScreenWidth device)) dark) retry
            <$> readIORef failure
    }

-- | App showing a profile, and how to stop it. The first function shows
-- the profile chosen then, the second restarts all profiles.
running :: ActionState -> Hub -> IO () -> IO () -> IO (MobileApp, IO ())
running actions hub switch restart = do
  let database = hubDatabase hub
      dir = hubDir hub
      sent = dir </> "sent"
      nodesFile = dir </> "nodes.json"
      redraw = hubRedraw hub
  shownId <- Store.activeProfile database
  session <- sessionFor hub shownId
  writeIORef (hubShown hub) shownId
  let model = sessionModel session
      network = sessionNetwork session
      fire = sessionFire session
  -- Profiles may have changed while it wasn't shown.
  Store.profiles database >>= fire . ProfilesChanged
  settings <- modelDevice <$> readMVar model
  permissions <- newIORef (Nothing :: Maybe PermissionState)
  user <- newIORef (Nothing :: Maybe UserState)
  -- Whether we're waiting for a location fix.
  locating <- newIORef False
  -- What the next pick is for.
  picking <- newIORef ForFile
  let stop = fire (Shown False)
      -- Not during a call (it would get hidden).
      switching next = readMVar model >>= \current -> case modelCall current of
        Just _  -> fire (Notify "Not during a call") >> join (readIORef redraw)
        Nothing -> next >>= \pid -> if pid == shownId then join (readIORef redraw) else Store.setActive database pid >> switch
  let withUser f = readIORef user >>= mapM_ f
      redraw' = join (readIORef redraw)
      shareLocation = withUser $ \u -> requestPermission (userPermissionState u) PermissionLocation $ \case
        PermissionDenied -> fire (Notify "hTox may not use your location") >> redraw'
        PermissionGranted -> do
          fire (Notify "Finding where you are\x2026") >> redraw'
          writeIORef locating True
          startLocationUpdates (userLocationState u) $ \fix -> do
            waiting <- atomicModifyIORef' locating (False,)
            when waiting $ do
              stopLocationUpdates (userLocationState u)
              fire (ShareLocation (ldLatitude fix) (ldLongitude fix)) >> redraw'
          void . forkIO $ do
            threadDelay 30000000
            waiting <- atomicModifyIORef' locating (False,)
            when waiting $ do
              stopLocationUpdates (userLocationState u)
              fire (Notify "Couldn't find where you are") >> redraw'
      takePicture = withUser $ \u -> requestPermission (userPermissionState u) PermissionCamera $ \case
        PermissionDenied -> fire (Notify "hTox may not use the camera") >> redraw'
        PermissionGranted -> capturePicture
      attaching = withUser $ \u ->
        showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Attach" (map fst choices)) $ \case
          BottomSheetItemSelected n | (_, chosen) : _ <- drop (fromIntegral n) choices -> chosen
          _ -> pure ()
        where
          choices =
            [ ("Gallery", writeIORef picking ForPicture >> pickFiles "image/*")
            , ("Camera", writeIORef picking ForPicture >> takePicture)
            , ("File", writeIORef picking ForFile >> pickFiles "*/*"), ("Location", shareLocation) ]
  -- No call without the microphone, and no video without the camera. We
  -- redraw after the answer (Hatter doesn't).
  let allowing camera next = readIORef permissions >>= \case
        Nothing -> next camera
        Just state -> requestPermission state PermissionMicrophone $ \case
          PermissionDenied -> fire (Notify "Calls need the microphone") >> join (readIORef redraw)
          PermissionGranted
            | camera -> requestPermission state PermissionCamera $ \case
                PermissionGranted -> next True >> join (readIORef redraw)
                PermissionDenied -> do
                  fire (Notify "hTox may not use the camera, so the call goes on without it")
                  next False >> join (readIORef redraw)
            | otherwise -> next False >> join (readIORef redraw)
  handlers <- runActionM actions $ do
    back' <- createAction (fire Back)
    send <- createAction (getCurrentTime >>= fire . Send)
    openDrawer <- createAction (fire OpenDrawer)
    openProfile <- createAction (fire (Open ProfileScreen))
    openAddContact <- createAction $ withUser $ \u ->
      showBottomSheet (userBottomSheetState u) (BottomSheetConfig "New" (map fst adding)) $ \case
        BottomSheetItemSelected n | (_, screen') : _ <- drop (fromIntegral n) adding -> fire (Open screen') >> redraw'
        _ -> pure ()
    openChats <- createAction (fire (Open Contacts))
    openCalls <- createAction (fire (Open CallsScreen))
    allowFullScreen' <- createAction allowFullScreen
    applyProfile <- createAction (fire ApplyProfile)
    addFriend <- createAction (fire AddFriend)
    copyToxId <- createAction $
      readMVar model >>= copyToClipboard . profileToxId . modelProfile
    attach <- createAction attaching
    openSettings <- createAction (fire (Open SettingsScreen))
    openProfiles <- createAction (fire (Open ProfilesScreen))
    newProfile <- createAction (switching (Store.newProfile database Nothing (modelProfile initial)))
    importProfile <- createAction (writeIORef picking ForProfile >> pickFiles "*/*")
    openBackup <- createAction (fire (Open BackupScreen))
    restoreBackup <- createAction (writeIORef picking ForBackup >> pickFiles "*/*")
    -- Written to our files, then copied where the user chooses.
    backUp <- createAction $ do
      chosen <- Set.toList . modelBackup <$> readMVar model
      let path = dir </> "backup.sqlite"
      try @SomeException (Store.backUp database chosen path) >>= \case
        Left err -> do
          platformLog ("No backup: " <> Text.pack (displayException err))
          void (try @IOException (removeFile path))
          fire (Notify "Couldn't back up the profiles") >> redraw'
        Right () -> do
          today <- utctDay <$> getCurrentTime
          saveFile path ("htox-" <> Text.pack (show today) <> ".backup") "application/octet-stream"
    -- Try these sizes until the PNG is small enough for Tox clients.
    pickAvatar <- createAction (pickPicture [256, 192, 128, 96, 64] Avatars.maxSize)
    removeAvatar <- createAction (fire RemoveAvatar)
    -- Write it to our files, then copy it where the user chooses.
    exportProfile <- createAction $ do
      current <- readMVar model
      me <- Network.identityOf network
      forM_ (exportSave me current) $ \save -> do
        let path = dir </> "export.tox"
        BS.writeFile path save
        saveFile path (profileNickname (modelProfile current) <> ".tox") "application/octet-stream"
    chooseAway <- createAction $ withUser $ \u ->
      showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Status" (map awayName aways)) $ \case
        BottomSheetItemSelected n | away : _ <- drop (fromIntegral n) aways -> fire (AwayChosen away) >> redraw'
        _ -> pure ()
    chooseAutoAccept <- createAction $ withUser $ \u ->
      showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Accept files without asking" (map fst autoAccepts)) $ \case
        BottomSheetItemSelected n | (_, size) : _ <- drop (fromIntegral n) autoAccepts -> fire (SetAutoAccept size) >> redraw'
        _ -> pure ()
    let toggling f = createAction (readMVar model >>= fire . SetDevice . f . modelDevice)
    toggleUdp <- toggling (\d -> d { settingUdp = not (settingUdp d) })
    toggleIpv6 <- toggling (\d -> d { settingIpv6 = not (settingIpv6 d) })
    toggleLan <- toggling (\d -> d { settingLan = not (settingLan d) })
    toggleStay <- toggling (\d -> d { settingStay = not (settingStay d) })
    toggleFormats <- Map.fromList <$> traverse
      (\f -> (,) (Formats.formatKey f) <$> createAction (fire (ToggleFormat (Formats.formatKey f)))) Formats.formats
    openProxy <- createAction (fire (Open ProxyScreen))
    proxyKinds <- (,,)
      <$> createAction (fire (ProxyKindChosen Nothing))
      <*> createAction (fire (ProxyKindChosen (Just Tox.Socks5Proxy)))
      <*> createAction (fire (ProxyKindChosen (Just Tox.HttpProxy)))
    proxyHost <- createOnChange (fire . ProxyHostChanged)
    proxyPort <- createOnChange (fire . ProxyPortChanged)
    -- Tox only takes a proxy at the start, so restart (not during a call).
    applyProxy <- createAction $ do
      before <- settingProxy . modelDevice <$> readMVar model
      fire ApplyProxy
      current <- readMVar model
      if settingProxy (modelDevice current) == before || isJust (modelCall current)
        then redraw'
        else restart
    draft <- createOnChange (fire . DraftChanged)
    nickname <- createOnChange (fire . NicknameChanged)
    status <- createOnChange (fire . StatusChanged)
    address <- createOnChange (fire . AddressChanged)
    request <- createOnChange (fire . RequestChanged)
    let twice f = (,) <$> createAction (f False) <*> createAction (f True)
    calls <- twice $ \camera -> allowing camera (\allowed -> getCurrentTime >>= \now -> fire (StartCall now allowed))
    answers <- twice $ \camera -> allowing camera (\allowed -> getCurrentTime >>= \now -> fire (AnswerCall now allowed))
    hangUp <- createAction (getCurrentTime >>= fire . HangUp)
    mute <- createAction (fire ToggleMute)
    camera' <- createAction (fire ToggleCamera)
    -- The platform tells us the new route.
    route <- createAction $ readMVar model >>= mapM_ (\c -> case callRoutes c of
      routes | length routes <= 2 -> setCallRoute (toCallRoute (if callRoute c == Speaker then Earpiece else Speaker))
             | otherwise -> withUser $ \u ->
                 showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Audio" (map routeName routes)) $ \case
                   BottomSheetItemSelected n | r : _ <- drop (fromIntegral n) routes -> setCallRoute (toCallRoute r)
                   _ -> pure ()) . modelCall
    flipCamera <- createAction (fire FlipCamera)
    hideCall <- createAction (fire HideCall)
    showCall <- createAction (fire ShowCall)
    scrolled <- createOnChange (fire . ScrolledAway . (== "away"))
    jump <- createAction (fire JumpToEnd)
    unselect <- createAction (fire Unselect)
    -- Selected messages of the open chat.
    let selected f = readMVar model >>= \current -> case modelScreen current of
          Chat cid -> f current cid (Set.toList (modelSelected current))
          _        -> pure ()
    copySelected <- createAction $ selected $ \current cid is ->
      copyToClipboard (copiedText current cid is) >> fire Unselect
    forwardSelected <- createAction $ selected $ \_ cid is -> fire (Open (Forward cid is))
    cancelReply <- createAction (fire CancelReply)
    password <- createOnChange (fire . PasswordChanged)
    topic <- createOnChange (fire . TopicEdited)
    applyTopic <- createAction (fire ApplyTopic)
    foundings <- Map.fromList <$> traverse (\f -> (,) f <$> createAction (fire (FoundingChosen f))) [minBound .. maxBound]
    groupName' <- createOnChange (fire . GroupNameEdited)
    found <- createAction (fire Found)
    chatId <- createOnChange (fire . ChatIdEdited)
    joinPublic <- createAction (fire JoinPublic)
    endPrivate <- createAction (fire (PrivatelyTo Nothing))
    peerLimit <- createOnChange (fire . PeerLimitEdited)
    groupPassword <- createOnChange (fire . GroupPasswordEdited)
    applyGroupSettings <- createAction (fire ApplyGroupSettings)
    openLink <- createAction (fire (Open LinkScreen))
    linkEdited <- createOnChange (fire . LinkEdited)
    -- New profile for the linked account, online at once.
    link <- createAction $ readMVar model >>= \current ->
      case (linkError (modelLink current), Pairing.parseLink (modelLink current)) of
        (Nothing, Just pairing) -> do
          now <- getCurrentTime
          switching (Store.newLinkedProfile database (Pairing.linkAddress pairing) (Pairing.requestMessage pairing) now)
        (why, _) -> fire (Notify (fromMaybe "That isn't a pairing link" why)) >> redraw'
    pure $ \perContact perMessage perProfile perGroup perInvite perInviting perMember perStaged -> Handlers
      { hBack = back'
      , hSend = send
      , hOpenDrawer = openDrawer
      , hOpenProfile = openProfile
      , hOpenAddContact = openAddContact
      , hOpenChats = openChats
      , hOpenCalls = openCalls
      , hCallBack = caCallBack . perContact
      , hAllowFullScreen = allowFullScreen'
      , hApplyProfile = applyProfile
      , hAddFriend = addFriend
      , hCopyToxId = copyToxId
      , hAttach = attach
      , hTapMessage = \cid i -> let (tap, _, _) = perMessage Map.! (cid, i) in tap
      , hHoldMessage = \cid i -> let (_, hold, _) = perMessage Map.! (cid, i) in hold
      , hCancelFile = \cid i -> let (_, _, cancel) = perMessage Map.! (cid, i) in cancel
      , hUnselect = unselect
      , hCopySelected = copySelected
      , hForwardSelected = forwardSelected
      , hCancelReply = cancelReply
      , hUnstage = curry perStaged
      , hOpenSettings = openSettings
      , hOpenProfiles = openProfiles
      , hSwitchProfile = \pid -> let (switch', _, _) = perProfile pid in switch'
      , hDeleteProfile = \pid -> let (_, delete, _) = perProfile pid in delete
      , hNewProfile = newProfile
      , hImportProfile = importProfile
      , hOpenBackup = openBackup
      , hBackUp = backUp
      , hToggleBackup = \pid -> let (_, _, toggle) = perProfile pid in toggle
      , hRestore = restoreBackup
      , hPickAvatar = pickAvatar
      , hRemoveAvatar = removeAvatar
      , hExport = exportProfile
      , hAutoAccept = chooseAutoAccept
      , hAway = chooseAway
      , hToggleUdp = toggleUdp
      , hToggleIpv6 = toggleIpv6
      , hToggleLan = toggleLan
      , hToggleStay = toggleStay
      , hToggleFormat = (toggleFormats Map.!)
      , hOpenProxy = openProxy
      , hProxyKind = \case
          Nothing              -> let (none, _, _) = proxyKinds in none
          Just Tox.Socks5Proxy -> let (_, socks, _) = proxyKinds in socks
          Just Tox.HttpProxy   -> let (_, _, http) = proxyKinds in http
      , hProxyHost = proxyHost
      , hProxyPort = proxyPort
      , hApplyProxy = applyProxy
      , hForwardTo = caForwardTo . perContact
      , hOpenChat = caOpen . perContact
      , hAccept = caAccept . perContact
      , hReject = caReject . perContact
      , hDetails = caDetails . perContact
      , hMuteChat = caMute . perContact
      , hDelete = caDelete . perContact
      , hCopyKey = caCopyKey . perContact
      , hPictures = caPictures . perContact
      , hDraft = draft
      , hNickname = nickname
      , hStatus = status
      , hAddress = address
      , hRequest = request
      , hCall = \camera -> (if camera then snd else fst) calls
      , hAnswer = \camera -> (if camera then snd else fst) answers
      , hHangUp = hangUp
      , hMute = mute
      , hCamera = camera'
      , hRoute = route
      , hFlipCamera = flipCamera
      , hHideCall = hideCall
      , hShowCall = showCall
      , hScrolled = scrolled
      , hJump = jump
      , hOpenGroup = gaOpen . perGroup
      , hGroupDetails = gaDetails . perGroup
      , hMuteGroup = gaMute . perGroup
      , hLeaveGroup = gaLeave . perGroup
      , hDeleteGroup = gaDelete . perGroup
      , hCopyChatId = gaCopyId . perGroup
      , hOpenInvite = \cid gid -> iaOpen (perInvite (cid, gid))
      , hJoin = \cid gid -> iaJoin (perInvite (cid, gid))
      , hDecline = \cid gid -> iaDecline (perInvite (cid, gid))
      , hPassword = password
      , hEditTopic = gaTopic . perGroup
      , hToggleMentions = gaMentions . perGroup
      , hTopic = topic
      , hApplyTopic = applyTopic
      , hFounding = (foundings Map.!)
      , hGroupName = groupName'
      , hFound = found
      , hChatId = chatId
      , hJoinPublic = joinPublic
      , hInviteFriends = gaInvite . perGroup
      , hInviteFriend = curry perInviting
      , hMember = curry perMember
      , hEndPrivate = endPrivate
      , hGroupSettings = gaSettings . perGroup
      , hPrivacy = gaPrivacy . perGroup
      , hTopicLock = gaTopicLock . perGroup
      , hVoice = gaVoice . perGroup
      , hRelayBot = gaRelayBot . perGroup
      , hStopRelay = gaStopRelay . perGroup
      , hPeerLimit = peerLimit
      , hGroupPassword = groupPassword
      , hApplyGroupSettings = applyGroupSettings
      , hOpenLink = openLink
      , hLinkEdited = linkEdited
      , hLink = link
      }
  let redrawn = join (readIORef redraw)
      muting cid = do
        now <- getCurrentTime
        contact <- Map.lookup cid . modelContacts <$> readMVar model
        case contact of
          Just c | muted now c -> fire (UnmuteChat cid) >> redrawn
          Just _ -> readIORef user >>= mapM_ (\u ->
            showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Mute notifications" (map fst muteChoices)) $ \case
              BottomSheetItemSelected n | (_, for) : _ <- drop (fromIntegral n) muteChoices -> do
                from <- getCurrentTime
                fire (MuteChat cid ((`addUTCTime` from) <$> for)) >> redrawn
              _ -> pure ())
          Nothing -> pure ()
      deleting cid = do
        contact <- Map.lookup cid . modelContacts <$> readMVar model
        forM_ contact $ \c -> readIORef user >>= mapM_ (\u ->
          showDialog (userDialogState u) DialogConfig
            { dcTitle = "Delete " <> contactLabel cid c <> "?"
            , dcMessage = "Their chat can stay, and comes back if you add them again."
            , dcButton1 = "Keep chat"
            , dcButton2 = Just "Delete chat"
            , dcButton3 = Just "Cancel"
            } $ \case
              DialogButton1 -> fire (DeleteContact cid True) >> redrawn
              DialogButton2 -> fire (DeleteContact cid False) >> redrawn
              _ -> pure ())
      -- Change only what's different from the current settings.
      changing gid f = do
        wanted <- (groupSettings <=< Map.lookup gid) . modelGroups <$> readMVar model
        forM_ wanted $ \current -> fire (ChangeSettings gid (f current)) >> redrawn
      mutingGroup gid = do
        now <- getCurrentTime
        g <- Map.lookup gid . modelGroups <$> readMVar model
        case g of
          Just g' | groupMuted now g' -> fire (UnmuteGroup gid) >> redrawn
          Just _ -> withUser $ \u ->
            showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Mute notifications" (map fst muteChoices)) $ \case
              BottomSheetItemSelected n | (_, for) : _ <- drop (fromIntegral n) muteChoices -> do
                from <- getCurrentTime
                fire (MuteGroup gid ((`addUTCTime` from) <$> for)) >> redrawn
              _ -> pure ()
          Nothing -> pure ()
      asking title message yes event = withUser $ \u ->
        showDialog (userDialogState u) DialogConfig
          { dcTitle = title, dcMessage = message, dcButton1 = yes, dcButton2 = Just "Cancel", dcButton3 = Nothing } $ \case
            DialogButton1 -> fire event >> redrawn
            _ -> pure ()
  groupsMade <- newIORef Map.empty
  let groupActionsFor gid@(GroupId chat) = readIORef groupsMade >>= \known -> case Map.lookup gid known of
        Just these -> pure these
        Nothing -> do
          these <- runActionM actions $ GroupActions
            <$> createAction (fire (Open (GroupChat gid)))
            <*> createAction (fire (Open (GroupDetails gid)))
            <*> createAction (mutingGroup gid)
            <*> createAction (do
                  kind <- maybe "group" (kindName . groupKind) . Map.lookup gid . modelGroups <$> readMVar model
                  asking ("Leave the " <> kind <> "?") "Its chat stays here. To join again, ask for a new invite."
                    "Leave" (LeaveGroup gid))
            <*> createAction (asking "Delete the chat?" "Its messages go too, and you leave the group if you're in it."
                                "Delete" (DeleteGroup gid))
            <*> createAction (copyToClipboard chat)
            <*> createAction (fire (Open (TopicScreen gid)))
            <*> createAction (fire (ToggleMentions gid))
            <*> createAction (fire (Open (InviteFriendsScreen gid)))
            <*> createAction (fire (Open (GroupSettingsScreen gid)))
            <*> createAction (changing gid (\s -> s { Tox.groupPrivate = not (Tox.groupPrivate s) }))
            <*> createAction (changing gid (\s -> s { Tox.groupTopicLock = not (Tox.groupTopicLock s) }))
            <*> createAction (withUser $ \u ->
                  showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Who may speak" (map fst voices)) $ \case
                    BottomSheetItemSelected n | (_, v) : _ <- drop (fromIntegral n) voices ->
                      changing gid (\s -> s { Tox.groupVoice = v })
                    _ -> pure ())
            <*> createAction (do
                  current <- readMVar model
                  forM_ (Map.lookup gid (modelGroups current)) $ \g -> withUser $ \u -> do
                    let senders = relayCounts g
                        choice (m, relays, total) =
                          memberLabel m <> ": " <> Text.pack (show relays) <> " of " <> Text.pack (show total) <> " messages relayed"
                    showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Which member is the relay bot?" (map choice senders)) $ \case
                      BottomSheetItemSelected n | (m, _, _) : _ <- drop (fromIntegral n) senders ->
                        fire (ChooseRelayBot gid (Just (memberKey m))) >> redrawn
                      _ -> pure ())
            <*> createAction (fire (ChooseRelayBot gid Nothing))
          modifyIORef' groupsMade (Map.insert gid these)
          pure these
  invitesMade <- newIORef Map.empty
  -- Per friend and group, made once the screen shows them.
  invitingMade <- newIORef Map.empty
  -- X button of each staged item, by chat and index.
  unstagingMade <- newIORef Map.empty
  let unstagingFor at@(cid, k) = readIORef unstagingMade >>= \known -> case Map.lookup at known of
        Just this -> pure this
        Nothing -> do
          this <- runActionM actions (createAction (fire (Unstage cid k)))
          modifyIORef' unstagingMade (Map.insert at this)
          pure this
  -- Per member, offering what we may do to them now.
  membersMade <- newIORef Map.empty
  let memberFor at@(gid, n) = readIORef membersMade >>= \known -> case Map.lookup at known of
        Just this -> pure this
        Nothing -> do
          this <- runActionM actions $ createAction $ do
            g <- Map.lookup gid . modelGroups <$> readMVar model
            forM_ g $ \g' -> withUser $ \u -> do
              let theirs = Map.findWithDefault Tox.User n (groupRoles g')
                  choices = ("Message privately", fire (PrivatelyTo (memberKey <$> Map.lookup n (groupMembers g'))) >> fire (Open (GroupChat gid)))
                    : [ (memberActionName permission, fire (Moderate gid n permission))
                      | groupKind g' == NgcGroup, permission <- memberActions (groupSelfRole g') theirs ]
                  title = maybe "Member" memberLabel (Map.lookup n (groupMembers g'))
              showBottomSheet (userBottomSheetState u) (BottomSheetConfig title (map fst choices)) $ \case
                BottomSheetItemSelected k | (_, chosen) : _ <- drop (fromIntegral k) choices -> chosen >> redrawn
                _ -> pure ()
          modifyIORef' membersMade (Map.insert at this)
          pure this
  let invitingFor at@(gid, cid) = readIORef invitingMade >>= \known -> case Map.lookup at known of
        Just this -> pure this
        Nothing -> do
          this <- runActionM actions (createAction (fire (InviteFriend gid cid)))
          modifyIORef' invitingMade (Map.insert at this)
          pure this
  let inviteActionsFor at@(cid, gid) = readIORef invitesMade >>= \known -> case Map.lookup at known of
        Just these -> pure these
        Nothing -> do
          these <- runActionM actions $ InviteActions
            <$> createAction (fire (Open (InviteScreen cid gid)))
            <*> createAction (fire (AnswerInvite cid gid True))
            <*> createAction (fire (AnswerInvite cid gid False))
          modifyIORef' invitesMade (Map.insert at these)
          pure these
  -- Actions live as long as the app, so make each contact's once.
  made <- newIORef Map.empty
  let actionsFor cid = do
        known <- readIORef made
        case Map.lookup cid known of
          Just these -> pure these
          Nothing -> do
            these <- runActionM actions $ ContactActions
              <$> createAction (fire (Open (Chat cid)))
              <*> createAction (fire (Accept cid))
              <*> createAction (fire (Reject cid))
              <*> createAction (fire (Open (Details cid)))
              <*> createAction (muting cid)
              <*> createAction (deleting cid)
              <*> createAction (copyToClipboard (let ContactId key = cid in key))
              <*> createAction (getCurrentTime >>= fire . ForwardTo cid)
              -- From the chat (the call screen then covers it).
              <*> createAction (allowing False (\allowed -> do
                    fire (Open (Chat cid))
                    getCurrentTime >>= \now -> fire (StartCall now allowed)))
              <*> createAction (withUser $ \u ->
                    let ways = ("As they are", Nothing) : [ ("As " <> formatName f, Just (formatKey f)) | f <- pictureFormats ]
                    in showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Send pictures" (map fst ways)) $ \case
                         BottomSheetItemSelected n | (_, way) : _ <- drop (fromIntegral n) ways ->
                           fire (SendPictures cid way) >> redrawn
                         _ -> pure ())
            modifyIORef' made (Map.insert cid these)
            pure these
  -- Per message, once shown. A tap selects while others are selected, or
  -- opens or accepts a file. Long press opens the menu.
  messageActions <- newIORef Map.empty
  let messageAction ref@(cid, i) = do
        known <- readIORef messageActions
        case Map.lookup ref known of
          Just these -> pure these
          Nothing -> do
            let message current = Map.lookup cid (modelContacts current) >>= listToMaybe . drop i . contactMessages
            these <- runActionM actions $ (,,)
              <$> createAction (do
                current <- readMVar model
                if not (Set.null (modelSelected current)) then fire (Select i)
                else forM_ (message current) $ \m -> do
                 forM_ (location (messageText m)) $ \(latitude, longitude) ->
                   when (isNothing (messageFile m)) $ openUri (mapsUri latitude longitude)
                 forM_ (messageFile m) $ \file -> case attachmentState file of
                  Complete                      -> openFile (attachmentPath file)
                  Waiting | not (messageMine m) -> fire (Download cid i)
                  _                             -> pure ())
              <*> createAction (do
                current <- readMVar model
                forM_ (message current) $ \m -> do
                  let call = isJust (messageCall m)
                      choices =
                        [ ("Open " <> written, openUri uri)
                        | not call, isNothing (messageFile m), (written, uri) <- take 3 (findLinks (messageText m)) ]
                        ++ [("Reply", fire (Reply i)) | not call]
                        ++ [("Forward", fire (Open (Forward cid [i]))) | forwardable m]
                        ++ [("Copy", copyToClipboard (copiedText current cid [i])) | not call]
                        ++ [("Select", fire (Select i)), ("Info", fire (Open (MessageInfo cid i)))]
                  readIORef user >>= mapM_ (\u ->
                    showBottomSheet (userBottomSheetState u) (BottomSheetConfig "Message" (map fst choices)) $ \case
                      BottomSheetItemSelected n | (_, chosen) : _ <- drop (fromIntegral n) choices -> chosen >> redrawn
                      _ -> pure ()))
              <*> createAction (fire (Cancel cid i))
            modifyIORef' messageActions (Map.insert ref these)
            pure these
  device <- getDeviceInfo
  -- Identicons, made once at the largest size we show.
  avatars <- newIORef Map.empty
  let avatarSize = dp (theme (diScreenDensity device) 0 False) 48
      avatarOf key = atomicModifyIORef' avatars $ \known ->
        case Map.lookup key known of
          Just picture -> (known, picture)
          Nothing ->
            let picture = identiconPng (ceiling avatarSize) (identicon (unhex key))
            in (Map.insert key picture known, picture)
  -- Read once the picture is complete.
  pictureSizes <- newIORef Map.empty
  let sizeOf path = readIORef pictureSizes >>= \known -> case Map.lookup path known of
        Just size -> pure size
        Nothing -> do
          size <- if isQoi path
            then either (const Nothing) qoiSize <$> try @IOException (withFile path ReadMode (`BS.hGet` 14))
            else imageSize path
          modifyIORef' pictureSizes (Map.insert path size)
          pure size
  -- QOI pictures as bitmaps, decoded off the UI thread. Nothing while
  -- decoding, or if it isn't QOI. One at a time (each may take as much memory
  -- as the largest picture).
  decoded <- newIORef (Map.empty :: Map.Map FilePath (Maybe BS.ByteString))
  decoding <- newMVar ()
  let decodedOf path = do
        known <- readIORef decoded
        unless (Map.member path known) $ do
          modifyIORef' decoded (Map.insert path Nothing)
          void . forkIO . withMVar decoding $ \() -> do
            bitmap <- try @IOException (BS.readFile path)
            let shown = either (const Nothing) (either (const Nothing) Just . qoiBitmap (diScreenWidth device)) bitmap
            forM_ shown $ \b -> do
              -- Do the work here, not in the view.
              b' <- evaluate b
              atomicModifyIORef' decoded ((, ()) . Map.insert path (Just b')) >> join (readIORef redraw)
        pure (join (Map.lookup path known))
  -- Per account: switch to it, delete it, and choose it for a backup.
  profileActions <- newIORef Map.empty
  let profileActionsFor pid = readIORef profileActions >>= \known -> case Map.lookup pid known of
        Just these -> pure these
        Nothing -> do
          these <- runActionM actions $ (,,)
            <$> createAction (switching (pure pid))
            <*> createAction (withUser $ \u -> do
                  name <- maybe "this profile" accountName . find ((== pid) . accountId) . modelProfiles <$> readMVar model
                  showDialog (userDialogState u) DialogConfig
                    { dcTitle = "Delete " <> name <> "?"
                    , dcMessage = "Its chats and keys go too. Back it up first to keep it."
                    , dcButton1 = "Delete"
                    , dcButton2 = Just "Cancel"
                    , dcButton3 = Nothing
                    } $ \case
                      DialogButton1 -> do
                        goOffline hub pid
                        Store.deleteProfile database pid
                        Store.profiles database >>= fire . ProfilesChanged
                        redrawn
                      _ -> pure ())
            <*> createAction (fire (ToggleBackup pid))
          modifyIORef' profileActions (Map.insert pid these)
          pure these
      -- Import a .tox file as a profile, online at once, unless we have it
      -- already.
      taken path = do
        bytes <- BS.readFile path
        void (try @IOException (removeFile path >> removeDirectory (takeDirectory path)))
        case importSave bytes of
          Left why -> fire (Notify why) >> redrawn
          Right (known, imported) -> do
            others <- mapM (Store.identity . Store.profileStore database . accountId) =<< Store.profiles database
            if identitySecretKey known `elem` map identitySecretKey (catMaybes others)
              then fire (Notify "hTox has that profile already") >> redrawn
              else switching $ do
                pid <- Store.newProfile database (Just known) (modelProfile imported)
                Store.save (Store.profileStore database pid) initial imported
                pure pid
      -- Restore the backup's profiles we don't have, online at once.
      restored path = do
        result <- try @SomeException (Store.restore database path)
        void (try @IOException (removeFile path >> removeDirectory (takeDirectory path)))
        case result of
          Left err -> do
            platformLog ("No restore: " <> Text.pack (displayException err))
            fire (Notify (case fromException err of
              Just (Store.Newer _) -> "That backup is from a newer hTox"
              Nothing              -> "That isn't an hTox backup")) >> redrawn
          Right [] -> fire (Notify "hTox has those profiles already") >> redrawn
          Right pids -> do
            forM_ pids $ \pid -> try @SomeException (sessionFor hub pid) >>= \case
              Left err -> platformLog ("A profile didn't go online: " <> Text.pack (displayException err))
              Right _ -> pure ()
            Store.profiles database >>= fire . ProfilesChanged
            redrawn
  -- Notification's profile, or the shown one if the key has none.
  let forProfile key f = do
        let (whose, key') = profileOf key
            pid = fromMaybe shownId whose
        sessions <- readMVar (hubSessions hub)
        forM_ (Map.lookup pid sessions) $ \s -> f pid s key'
      showing pid = if pid == shownId then join (readIORef redraw) else switching (pure pid)
  -- Only made again when the Tox ID changes.
  qr <- newIORef (Text.empty, BS.empty)
  let qrOf address = atomicModifyIORef' qr $ \known@(shown, picture) ->
        if shown == address then (known, picture)
        else let new = toxIdQr (ceiling (dp (theme (diScreenDensity device) 0 False) 200)) address
             in ((address, new), new)
  pure (MobileApp
    { maContext = loggingMobileContext
        { onBack = readMVar model >>= \current ->
            if isJust (back current) then True <$ fire Back else pure False
        , onLifecycle = \case
            -- Also when back from the full screen setting.
            Start -> fullScreenAllowed >>= fire . FullScreenChecked >> fire (Shown True)
            Stop -> fire (Shown False)
            _ -> pure ()
        , onNotificationOpened = \key -> forProfile key $ \pid s key' -> case notificationOf key' of
            -- The call screen.
            Nothing -> showing pid
            Just opened -> do
              current <- readMVar (sessionModel s)
              let known = case opened of
                    Chat cid             -> Map.member cid (modelContacts current)
                    GroupChat gid        -> Map.member gid (modelGroups current)
                    InviteScreen cid gid -> Map.member (cid, gid) (modelInvites current)
                    _                    -> True
              when known $ sessionFire s (Open opened) >> showing pid
        , onCallButton = \key button -> forProfile key $ \pid s key' -> when (key' == callNotification) $ do
            call <- modelCall <$> readMVar (sessionModel s)
            forM_ call $ \c -> case button of
              Answer -> allowing (callPeerVideo c) $ \allowed -> do
                now <- getCurrentTime
                sessionFire s (AnswerCall now allowed) >> showing pid
              Decline -> getCurrentTime >>= sessionFire s . HangUp >> join (readIORef redraw)
              End -> getCurrentTime >>= sessionFire s . HangUp >> join (readIORef redraw)
        , onPicturePicked = fire . AvatarPicked
        , onFilePicked = \picked -> do
            chosen <- readIORef picking
            if chosen == ForProfile then taken (pickedPath picked)
            else if chosen == ForBackup then restored (pickedPath picked) else do
              -- Move it to our files (the system may clear the cache).
              now <- getCurrentTime
              let path = sent </> (show (toMillis now) <> "-" <> takeFileName (pickedPath picked))
              renameFile (pickedPath picked) path
              -- Remove the directory it was copied to, if it's empty.
              void (try (removeDirectory (takeDirectory (pickedPath picked))) :: IO (Either IOException ()))
              fileId <- randomByteString 32
              current <- readMVar model
              let shrinkable = chosen == ForPicture && map toLower (takeExtension path) /= ".gif"
                  way = case modelScreen current of
                    Chat cid -> pictureFormat =<< contactPictures =<< Map.lookup cid (modelContacts current)
                    _        -> Nothing
                  attach p name size = fire (Attach p name size fileId) >> redrawn
                  original = attach path (pickedName picked) (fromInteger (pickedSize picked))
                  -- Replaces the original, with the new extension.
                  instead extension write = do
                    let converted = dropExtension path <> extension
                    written <- write converted
                    if not written then original else do
                      -- A JPEG shrunk to JPEG has replaced it already.
                      when (converted /= path) (removeFile path)
                      size <- withFile converted ReadMode hFileSize
                      attach converted (Text.pack (dropExtension (Text.unpack (pickedName picked)) <> extension)) (fromInteger size)
              -- Off the UI thread. Send it as it is if that fails.
              if not shrinkable then original else void . forkIO $ case way of
                Nothing -> do
                  let out = dropExtension path <> ".tmp"
                  shrinkPicture path out pictureSide >>= \case
                    Nothing -> original
                    Just kind -> instead (if kind == Jpeg then ".jpg" else ".png") (\converted -> True <$ renameFile out converted)
                Just f -> do
                  encoded <- (>>= \(w, h, rgba) -> formatEncode f w h rgba)
                    <$> picturePixels path (min (formatMaxPixels f) (pictureSide * pictureSide))
                  case encoded of
                    Nothing    -> original
                    Just bytes -> instead (formatExtension f) (\converted -> True <$ BS.writeFile converted bytes)
        }
    , maActionState = actions
    , maView = \state -> do
        writeIORef redraw (userRequestRedraw state)
        writeIORef permissions (Just (userPermissionState state))
        writeIORef user (Just state)
        first <- not <$> atomicModifyIORef' (hubFetched hub) (True,)
        -- Fetch nodes once we have a screen to fetch with, but not with a
        -- proxy.
        when (first && isNothing (settingProxy settings)) $ performRequest (userHttpState state) (HttpRequest HttpGet nodesUrl [] BS.empty) $ \case
          Right response | hrStatusCode response == 200, Just nodes <- readNodes (hrRespBody response) -> do
            BS.writeFile nodesFile (hrRespBody response)
            writeIORef (hubNodes hub) nodes
            readMVar (hubSessions hub) >>= mapM_ ((`Network.useNodes` nodes) . sessionNetwork)
          other -> platformLog ("No nodes fetched: " <> Text.pack (either show (show . hrStatusCode) other))
        current <- readMVar model
        let contactIds = Map.keys (modelContacts current) ++ Map.keys (modelRequests current)
        perContact <- Map.fromList <$> traverse (\cid -> (,) cid <$> actionsFor cid) contactIds
        perMessage <- Map.fromList <$> traverse (\ref -> (,) ref <$> messageAction ref)
          [ (cid, i) | Chat cid <- [modelScreen current]
                     , contact <- maybe [] pure (Map.lookup cid (modelContacts current))
                     , i <- [0 .. length (contactMessages contact) - 1] ]
        perGroup <- Map.fromList <$> traverse (\gid -> (,) gid <$> groupActionsFor gid) (Map.keys (modelGroups current))
        perInvite <- Map.fromList <$> traverse (\at -> (,) at <$> inviteActionsFor at) (Map.keys (modelInvites current))
        perStaged <- Map.fromList <$> traverse (\at -> (,) at <$> unstagingFor at)
          [ (cid, k) | Chat cid <- [modelScreen current]
                     , k <- [0 .. length (Map.findWithDefault [] cid (modelStaged current)) - 1] ]
        perMember <- Map.fromList <$> traverse (\at -> (,) at <$> memberFor at)
          [ (gid, n) | GroupDetails gid <- [modelScreen current]
                     , g <- maybe [] pure (Map.lookup gid (modelGroups current)), n <- Map.keys (groupMembers g) ]
        perInviting <- Map.fromList <$> traverse (\at -> (,) at <$> invitingFor at)
          [ (gid, cid) | InviteFriendsScreen gid <- [modelScreen current]
                       , (cid, c) <- Map.toList (modelContacts current), contactOnline c ]
        identicons <- traverse avatarOf $ Map.fromList
          [ (key, key)
          | key <- Text.take 64 (profileToxId (modelProfile current))
                 : [key | ContactId key <- contactIds]
                 ++ [accountKey a | a <- modelProfiles current, not (Text.null (accountKey a))]
                 ++ [chat | GroupId chat <- Map.keys (modelGroups current)]
                 ++ [chat | (_, GroupId chat) <- Map.keys (modelInvites current)]
                 ++ [ memberKey m | GroupDetails gid <- [modelScreen current]
                                  , g <- maybe [] pure (Map.lookup gid (modelGroups current))
                                  , m <- Map.elems (groupMembers g), not (Text.null (memberKey m)) ] ]
        -- Avatars, or identicons.
        let pictures = Map.fromList $
              [ (Text.take 64 (profileToxId (modelProfile current)), png)
              | Just png <- [(`Map.lookup` modelAvatars current) =<< modelAvatar current] ]
              ++ [ (key, png) | (ContactId key, c) <- Map.toList (modelContacts current)
                              , Just png <- [(`Map.lookup` modelAvatars current) =<< contactAvatar c] ]
            keys = Map.union pictures identicons
        code <- qrOf (profileToxId (modelProfile current))
        sizes <- traverse sizeOf $ Map.fromList $
          [ (attachmentPath a, attachmentPath a)
          | Chat cid <- [modelScreen current], c <- maybe [] pure (Map.lookup cid (modelContacts current))
          , m <- contactMessages c, Just a <- [messageFile m]
          , messageMine m || attachmentState a == Complete ]
          -- And staged ones.
          ++ [ (path, path) | Chat cid <- [modelScreen current]
                            , StagedFile path _ _ _ <- Map.findWithDefault [] cid (modelStaged current) ]
        bitmaps <- Map.traverseWithKey (\path _ -> decodedOf path) (Map.filterWithKey (\path _ -> isQoi path) sizes)
        dark <- isDarkMode
        clock24 <- is24HourClock
        now <- getCurrentTime
        zone <- getCurrentTimeZone
        let env = Env
              { envTheme = theme (diScreenDensity device)
                  (fromIntegral (diScreenWidth device)) dark
              , envNow = now
              , envZone = zone
              , envAvatar = \key -> Map.findWithDefault BS.empty key keys
              , envQr = code
              , envClock24 = clock24
              , envPictureSize = \path -> Map.findWithDefault Nothing path sizes
              , envDecoded = \path -> join (Map.lookup path bitmaps)
              }
        perProfile <- Map.fromList <$> traverse (\a -> (,) (accountId a) <$> profileActionsFor (accountId a)) (modelProfiles current)
        pure $ view env (handlers (perContact Map.!) perMessage (perProfile Map.!) (perGroup Map.!) (perInvite Map.!) (perInviting Map.!) (perMember Map.!) (perStaged Map.!)) current
    }, stop)
