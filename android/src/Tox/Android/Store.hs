{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators     #-}
-- | SQLite database: per account its keys, profile, friends, requests and
-- chats, plus the device settings. We load the model at the start, and
-- write back what each event changes.
module Tox.Android.Store
  ( Database
  , Store
  , Identity (..)
  , open
  , opened
  , Newer (..)
  , Locked (..)
  , profiles
  , activeProfile
  , setActive
  , newProfile
  , newLinkedProfile
  , deleteProfile
  , backUp
  , restore
  , profileStore
  , identity
  , saveIdentity
  , load
  , save
  ) where

import           Control.Applicative       ((<|>))
import           Control.Concurrent.MVar   (MVar, newMVar, withMVar)
import           Control.Exception         (Exception (..), IOException,
                                            finally, throwIO, try)
import           Control.Monad             (forM, forM_, unless, void, when)
import qualified Crypto.Saltine.Class      as Sodium
import           Crypto.Saltine.Core.Utils (randomByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as Base16
import           Data.Int                  (Int64)
import qualified Data.Map.Strict           as Map
import           Data.Maybe                (catMaybes, fromMaybe, isJust)
import qualified Data.Set                  as Set
import           Data.Text                 (Text)
import qualified Data.Text                 as Text
import qualified Data.Text.Encoding        as Text
import           Data.Time                 (NominalDiffTime, UTCTime)
import           Data.Time.Clock.POSIX     (posixSecondsToUTCTime,
                                            utcTimeToPOSIXSeconds)
import           Data.Word                 (Word16, Word32, Word64)
import           Database.SQLite.Simple    (Only (..), execute, execute_, query,
                                            query_, withTransaction, (:.) (..))
import qualified Database.SQLite.Simple    as SQLite
import           System.Directory          (doesFileExist, removeFile,
                                            renameFile)
import           System.IO                 (IOMode (ReadMode), withBinaryFile)
import qualified Tox.Application.Tox       as Tox
import qualified Tox.Crypto.Core.KeyPair   as KeyPair

import qualified Tox.Android.Linked        as Linked
import           Tox.Android.Model
import qualified Tox.Sync.Event            as Sync
import qualified Tox.Sync.Id               as Sync
import qualified Tox.Sync.Replica          as Replica
import qualified Tox.Sync.Store            as Sync

-- | One thread at a time (each online profile saves from its own).
data Database = Database (MVar ()) SQLite.Connection

data Store = Store Database ProfileId

using :: Database -> (SQLite.Connection -> IO a) -> IO a
using (Database lock db) f = withMVar lock (const (f db))

-- | Database from a newer hTox.
newtype Newer = Newer Int
  deriving (Show)

instance Exception Newer where
  displayException (Newer version) =
    "The chats were saved by a newer hTox (version " <> show version <> "). Install that one again."

-- | Keystore gave us no key, so we can't read the database.
data Locked = Locked
  deriving (Show)

instance Exception Locked where
  displayException Locked =
    "The phone's keystore gave no key for the chats, so they can't be opened."

data Identity = Identity
  { identitySecretKey :: BS.ByteString
  , identityNospam    :: Word32
  } deriving (Eq, Show)

-- | Encrypted with the key if there is one. An old plain database gets
-- encrypted first.
open :: Maybe BS.ByteString -> FilePath -> IO Database
open Nothing path = SQLite.open path >>= opened
open (Just key) path = do
  plain <- isPlain path
  when plain $ encrypt key path
  db <- SQLite.open path
  unlock db key
  opened db

-- | Whether it starts with SQLite's plain header.
isPlain :: FilePath -> IO Bool
isPlain path = do
  exists <- doesFileExist path
  if exists
    then (== "SQLite format 3\0") <$> withBinaryFile path ReadMode (`BS.hGet` 16)
    else pure False

-- | Also reads something, which fails with the wrong key.
unlock :: SQLite.Connection -> BS.ByteString -> IO ()
unlock db key = do
  execute_ db (SQLite.Query ("PRAGMA key = \"" <> rawKey key <> "\""))
  void (query_ db "SELECT count(*) FROM sqlite_master" :: IO [Only Int])

-- | Raw key for SQLCipher (it's random already, so no key derivation).
rawKey :: BS.ByteString -> Text
rawKey key = "x'" <> Text.decodeUtf8 (Base16.encode key) <> "'"

-- | Into a new file, which then replaces the plain one.
encrypt :: BS.ByteString -> FilePath -> IO ()
encrypt key path = do
  let encrypted = path <> ".encrypting"
  void (try (removeFile encrypted) :: IO (Either IOException ()))
  plain <- SQLite.open path
  [Only version] <- query_ plain "PRAGMA user_version" :: IO [Only Int]
  execute plain "ATTACH DATABASE ? AS encrypted KEY ?" (encrypted, rawKey key)
  void (query_ plain "SELECT sqlcipher_export('encrypted')" :: IO [Only (Maybe Int)])
  execute_ plain (SQLite.Query ("PRAGMA encrypted.user_version = " <> Text.pack (show version)))
  execute_ plain "DETACH DATABASE encrypted"
  SQLite.close plain
  renameFile encrypted path

-- | Runs the migrations.
opened :: SQLite.Connection -> IO Database
opened db = do
  [Only version] <- query_ db "PRAGMA user_version"
  when (version > length migrations) $ throwIO (Newer version)
  forM_ (zip [1 ..] (drop version migrations)) $ \(done, steps) -> withTransaction db $ do
    mapM_ (execute_ db) steps
    execute_ db (SQLite.Query ("PRAGMA user_version = " <> Text.pack (show (version + done :: Int))))
  flip Database db <$> newMVar ()

-- | Each step takes the database to the next version, the first from
-- nothing.
migrations :: [[SQLite.Query]]
migrations =
  [ [ -- Keys (once Tox made them) and account settings.
      "CREATE TABLE profiles\
      \ (id INTEGER PRIMARY KEY, secret_key BLOB, nospam INTEGER, nickname TEXT NOT NULL, status TEXT NOT NULL,\
      \ away INTEGER NOT NULL DEFAULT 0, avatar BLOB, auto_accept INTEGER NOT NULL, formats_off TEXT NOT NULL DEFAULT '',\
      \ home TEXT, pairing TEXT, linked_at INTEGER)"
    , "CREATE TABLE contacts\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), key TEXT NOT NULL, name TEXT, unread INTEGER NOT NULL,\
      \ request_address TEXT, request_message TEXT, wanted INTEGER NOT NULL DEFAULT 1,\
      \ status_message TEXT NOT NULL DEFAULT '', muted INTEGER NOT NULL DEFAULT 0, muted_until INTEGER,\
      \ avatar BLOB, send_pictures TEXT, PRIMARY KEY (profile, key))"
    , "CREATE TABLE messages\
      \ (profile INTEGER NOT NULL, contact TEXT NOT NULL, place INTEGER NOT NULL,\
      \ mine INTEGER NOT NULL, text TEXT NOT NULL, time INTEGER NOT NULL, delivery TEXT NOT NULL,\
      \ file_size INTEGER, file_path TEXT, file_done INTEGER, file_state TEXT,\
      \ call_video INTEGER, call_duration INTEGER, call_missed INTEGER, parts INTEGER NOT NULL DEFAULT 0,\
      \ file_id BLOB, raw BLOB, kind INTEGER NOT NULL DEFAULT 0, delivered_time INTEGER, id BLOB NOT NULL,\
      \ PRIMARY KEY (profile, contact, place), FOREIGN KEY (profile, contact) REFERENCES contacts (profile, key))"
    , -- Stable ID that stays when the message changes.
      "CREATE UNIQUE INDEX messages_id ON messages (profile, id)"
    , "CREATE TABLE requests\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), key TEXT NOT NULL, message TEXT NOT NULL,\
      \ PRIMARY KEY (profile, key))"
    , "CREATE TABLE declined\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), key TEXT NOT NULL, message TEXT NOT NULL,\
      \ PRIMARY KEY (profile, key))"
    , "CREATE TABLE drafts\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), key TEXT NOT NULL, message TEXT NOT NULL,\
      \ PRIMARY KEY (profile, key))"
    , -- Our and friends' avatars, by SHA-256.
      "CREATE TABLE avatars\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), hash BLOB NOT NULL, png BLOB NOT NULL,\
      \ PRIMARY KEY (profile, hash))"
    , -- Also the active account.
      "CREATE TABLE device_settings\
      \ (id INTEGER PRIMARY KEY CHECK (id = 0), udp INTEGER NOT NULL, ipv6 INTEGER NOT NULL, lan INTEGER NOT NULL,\
      \ stay_online INTEGER NOT NULL, active_profile INTEGER REFERENCES profiles (id),\
      \ proxy_type TEXT, proxy_host TEXT, proxy_port INTEGER)"
    , "INSERT INTO device_settings (id, udp, ipv6, lan, stay_online) VALUES (0, 1, 1, 1, 1)"
    , -- The saved group has our keys in it.
      "CREATE TABLE groups\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), chat_id TEXT NOT NULL, name TEXT NOT NULL,\
      \ phase TEXT NOT NULL, unread INTEGER NOT NULL, saved BLOB, muted INTEGER NOT NULL DEFAULT 0, muted_until INTEGER,\
      \ draft TEXT, mentions INTEGER NOT NULL DEFAULT 1, topic TEXT NOT NULL DEFAULT '',\
      \ kind TEXT NOT NULL DEFAULT 'group', PRIMARY KEY (profile, chat_id))"
    , -- Messages with the sender's name at the time, joins and leaves.
      "CREATE TABLE group_entries\
      \ (profile INTEGER NOT NULL, chat_id TEXT NOT NULL, place INTEGER NOT NULL, time INTEGER NOT NULL,\
      \ what TEXT NOT NULL, member_key TEXT, member_name TEXT, kind INTEGER NOT NULL DEFAULT 0, text TEXT,\
      \ delivery TEXT, other_key TEXT, other_name TEXT, id BLOB NOT NULL, PRIMARY KEY (profile, chat_id, place),\
      \ FOREIGN KEY (profile, chat_id) REFERENCES groups (profile, chat_id))"
    , "CREATE UNIQUE INDEX group_entries_id ON group_entries (profile, id)"
    , -- Member key of the relay bot in each group.
      "CREATE TABLE relay_bots\
      \ (profile INTEGER NOT NULL, chat_id TEXT NOT NULL, bot TEXT NOT NULL, PRIMARY KEY (profile, chat_id),\
      \ FOREIGN KEY (profile, chat_id) REFERENCES groups (profile, chat_id))"
    , -- A file (our copy of it) or a location.
      "CREATE TABLE staged\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), contact TEXT NOT NULL, place INTEGER NOT NULL,\
      \ path TEXT, name TEXT, size INTEGER, file_id BLOB, latitude REAL, longitude REAL,\
      \ PRIMARY KEY (profile, contact, place))"
    , "CREATE TABLE invites\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), friend TEXT NOT NULL, chat_id TEXT NOT NULL,\
      \ name TEXT NOT NULL, data BLOB NOT NULL, answered INTEGER NOT NULL DEFAULT 0, password TEXT,\
      \ kind TEXT NOT NULL DEFAULT 'group',\
      \ PRIMARY KEY (profile, friend, chat_id))"
    , -- Linked accounts' events, as the home and other devices wrote them.
      -- The chats are derived from these.
      "CREATE TABLE sync_events\
      \ (profile INTEGER NOT NULL REFERENCES profiles (id), id BLOB NOT NULL, rank INTEGER NOT NULL,\
      \ bytes BLOB NOT NULL, PRIMARY KEY (profile, id))"
    ]
  ]

-- | Oldest first.
profiles :: Database -> IO [Account]
profiles database = using database accounts

accounts :: SQLite.Connection -> IO [Account]
accounts db = map account <$> query_ db "SELECT id, nickname, secret_key FROM profiles ORDER BY id"
  where
    account (i, name, secret) = Account (ProfileId i) name $ case Sodium.decode =<< secret of
      Just sk -> Text.toUpper (Text.decodeUtf8 (Base16.encode (Sodium.encode (KeyPair.publicKey (KeyPair.fromSecretKey sk)))))
      Nothing -> ""

-- | Last one chosen, or the first, or a new one.
activeProfile :: Database -> IO ProfileId
activeProfile database = do
  chosen <- using database $ \db -> query_ db "SELECT active_profile FROM device_settings WHERE active_profile IN (SELECT id FROM profiles)"
  case chosen of
    [Only (Just i)] -> pure (ProfileId i)
    _ -> profiles database >>= \case
      first : _ -> accountId first <$ setActive database (accountId first)
      [] -> newProfile database Nothing (modelProfile initial) >>= \new -> new <$ setActive database new

setActive :: Database -> ProfileId -> IO ()
setActive database (ProfileId i) = using database $ \db -> execute db "UPDATE device_settings SET active_profile = ?" (Only i)

-- | With its keys if it came from elsewhere.
newProfile :: Database -> Maybe Identity -> Profile -> IO ProfileId
newProfile database known profile = using database $ \db -> do
  execute db "INSERT INTO profiles (secret_key, nospam, nickname, status, auto_accept) VALUES (?, ?, ?, ?, ?)"
    ( identitySecretKey <$> known, identityNospam <$> known, profileNickname profile, profileStatus profile
    , settingAutoAccept (modelAccount initial) )
  ProfileId <$> SQLite.lastInsertRowId db

-- | Linked to an account on another device (its home), by the home's Tox
-- address and the pairing friend request. Makes our device key here (the
-- account's events name it).
newLinkedProfile :: Database -> Text -> Text -> UTCTime -> IO ProfileId
newLinkedProfile database home pairing now = using database $ \db -> do
  pair <- KeyPair.newKeyPair
  nospam <- BS.foldl' (\n x -> n * 256 + fromIntegral x) (0 :: Word32) <$> randomByteString 4
  execute db "INSERT INTO profiles (secret_key, nospam, nickname, status, auto_accept, home, pairing, linked_at)\
             \ VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ( (Sodium.encode (KeyPair.secretKey pair), nospam, "" :: Text, "" :: Text, settingAutoAccept (modelAccount initial))
    :. (home, pairing, toMillis now) )
  ProfileId <$> SQLite.lastInsertRowId db

-- | With its chats and their files.
deleteProfile :: Database -> ProfileId -> IO ()
deleteProfile database (ProfileId i) = using database $ \db -> withTransaction db $ do
  paths <- SQLite.query db "SELECT file_path FROM messages WHERE profile = ? AND file_path IS NOT NULL" (Only i)
  forM_ paths $ \(Only path) -> void (try (removeFile path) :: IO (Either IOException ()))
  forM_ ("staged" : owned) $ \table ->
    execute db (SQLite.Query ("DELETE FROM " <> table <> " WHERE profile = ?")) (Only i)
  execute db "UPDATE device_settings SET active_profile = NULL WHERE active_profile = ?" (Only i)
  execute db "DELETE FROM profiles WHERE id = ?" (Only i)

-- | Tables with rows of each profile, besides staged files (a backup has no
-- files).
owned :: [Text]
owned =
  [ "contacts", "messages", "requests", "declined", "drafts", "avatars", "groups", "group_entries", "relay_bots"
  , "invites", "sync_events" ]

-- | Copies the profiles into a new plain database, to restore here or on
-- another phone. Device settings stay here.
backUp :: Database -> [ProfileId] -> FilePath -> IO ()
backUp database pids path = do
  void (try (removeFile path) :: IO (Either IOException ()))
  SQLite.withConnection path $ \backup -> do
    void (opened backup)
    execute_ backup "DELETE FROM device_settings"
  attached database path $ \db -> forM_ pids $ \(ProfileId i) -> do
    execute db "INSERT INTO backup.profiles SELECT * FROM main.profiles WHERE id = ?" (Only i)
    forM_ owned $ \table ->
      execute db (SQLite.Query ("INSERT INTO backup." <> table <> " SELECT * FROM main." <> table <> " WHERE profile = ?"))
        (Only i)

-- | Adds the backup's profiles we don't have yet, with new IDs, and returns
-- them. Their files the phone doesn't have show as not received or sent.
restore :: Database -> FilePath -> IO [ProfileId]
restore database path = do
  -- Brings an older backup up to date, and refuses a newer one.
  SQLite.withConnection path (void . opened)
  attached database path $ \db -> do
    here <- query_ db "SELECT secret_key FROM main.profiles WHERE secret_key IS NOT NULL" :: IO [Only BS.ByteString]
    theirs <- query_ db "SELECT id, secret_key FROM backup.profiles ORDER BY id" :: IO [(Int64, Maybe BS.ByteString)]
    -- Both have the same tables now, but each row gets a new profile ID.
    let columnsBut :: Text -> Text -> IO Text
        columnsBut column table = Text.intercalate ", " . filter (/= column) . map fromOnly
          <$> query db "SELECT name FROM pragma_table_info(?)" (Only table)
    fmap catMaybes . forM theirs $ \(old, key) ->
      if maybe False ((`elem` here) . Only) key then pure Nothing else do
        names <- columnsBut "id" "profiles"
        execute db (SQLite.Query ("INSERT INTO main.profiles (" <> names <> ") SELECT " <> names
                                  <> " FROM backup.profiles WHERE id = ?")) (Only old)
        new <- SQLite.lastInsertRowId db
        forM_ owned $ \table -> do
          names' <- columnsBut "profile" table
          execute db (SQLite.Query ("INSERT INTO main." <> table <> " (profile, " <> names' <> ") SELECT ?, " <> names'
                                    <> " FROM backup." <> table <> " WHERE profile = ?")) (new, old)
        files <- query db "SELECT contact, place, file_path FROM messages WHERE profile = ? AND file_path IS NOT NULL" (Only new)
        forM_ files $ \(contact, place, file) -> do
          kept <- doesFileExist file
          unless kept $ execute db "UPDATE messages SET file_state = 'cancelled' WHERE profile = ? AND contact = ? AND place = ?"
            (new, contact :: Text, place :: Int)
        pure (Just (ProfileId new))

-- | In one transaction, with the plain database at the path attached as
-- "backup".
attached :: Database -> FilePath -> (SQLite.Connection -> IO a) -> IO a
attached database path f = using database $ \db -> do
  -- An empty key keeps it plain, even with an encrypted main database.
  execute db "ATTACH DATABASE ? AS backup KEY ''" (Only path)
  withTransaction db (f db) `finally` execute_ db "DETACH DATABASE backup"

profileStore :: Database -> ProfileId -> Store
profileStore = Store

identity :: Store -> IO (Maybe Identity)
identity (Store database (ProfileId i)) = using database $ \db -> do
  found <- SQLite.query db "SELECT secret_key, nospam FROM profiles WHERE id = ?" (Only i)
  pure $ case found of
    [(Just key, Just nospam)] -> Just (Identity key nospam)
    _                         -> Nothing

saveIdentity :: Store -> Identity -> IO ()
saveIdentity (Store database (ProfileId i)) (Identity key nospam) = using database $ \db ->
  execute db "UPDATE profiles SET secret_key = ?, nospam = ? WHERE id = ?" (key, nospam, i)

-- | Or the initial model if nothing was saved.
load :: Store -> IO Model
load (Store database pid@(ProfileId i)) = using database $ \db -> do
  let ofProfile q = SQLite.query db q (Only i)
  rows <- ofProfile "SELECT nickname, status, away, avatar, auto_accept, formats_off FROM profiles WHERE id = ?"
    :: IO [(Text, Text, Int, Maybe BS.ByteString, Word64, Text)]
  avatars <- ofProfile "SELECT hash, png FROM avatars WHERE profile = ?" :: IO [(BS.ByteString, BS.ByteString)]
  contacts <- ofProfile
    "SELECT key, name, unread, request_address, request_message, status_message, wanted, muted, muted_until,\
    \ avatar, send_pictures FROM contacts WHERE profile = ?"
    :: IO [(Text, Maybe Text, Int, Maybe Text, Maybe Text) :. (Text, Bool, Bool, Maybe Integer, Maybe BS.ByteString) :. Only (Maybe Text)]
  messages <- ofProfile
    "SELECT contact, mine, text, time, delivery, file_size, file_path, file_done, file_state,\
    \ call_video, call_duration, call_missed, parts, file_id, kind, raw, delivered_time\
    \ FROM messages WHERE profile = ? ORDER BY contact, place"
    :: IO [(Text, Bool, Text, Integer, Text) :. (Maybe Word64, Maybe FilePath, Maybe Word64, Maybe Text)
           :. (Maybe Bool, Maybe Integer, Maybe Bool, Int, Maybe BS.ByteString) :. (Int, Maybe BS.ByteString, Maybe Integer)]
  requests <- ofProfile "SELECT key, message FROM requests WHERE profile = ?" :: IO [(Text, Text)]
  declined <- ofProfile "SELECT key, message FROM declined WHERE profile = ?" :: IO [(Text, Text)]
  drafts <- ofProfile "SELECT key, message FROM drafts WHERE profile = ?" :: IO [(Text, Text)]
  groups <- ofProfile
    "SELECT chat_id, name, phase, unread, saved, muted, muted_until, draft, mentions, topic, kind\
    \ FROM groups WHERE profile = ?"
    :: IO [(Text, Text, Text, Int, Maybe BS.ByteString) :. (Bool, Maybe Integer, Maybe Text, Bool, Text) :. Only Text]
  entries <- ofProfile
    "SELECT chat_id, time, what, member_key, member_name, kind, text, delivery, other_key, other_name\
    \ FROM group_entries WHERE profile = ? ORDER BY chat_id, place"
    :: IO [(Text, Integer, Text, Maybe Text, Maybe Text) :. (Int, Maybe Text, Maybe Text, Maybe Text, Maybe Text)]
  bots <- ofProfile "SELECT chat_id, bot FROM relay_bots WHERE profile = ?" :: IO [(Text, Text)]
  invites <- ofProfile "SELECT friend, chat_id, name, data, answered, password, kind FROM invites WHERE profile = ?"
    :: IO [(Text, Text, Text, BS.ByteString, Bool, Maybe Text, Text)]
  staged <- ofProfile
    "SELECT contact, path, name, size, file_id, latitude, longitude FROM staged WHERE profile = ? ORDER BY contact, place"
    :: IO [(Text, Maybe FilePath, Maybe Text, Maybe Word64, Maybe BS.ByteString, Maybe Double, Maybe Double)]
  others <- accounts db
  linking <- ofProfile "SELECT home, pairing, linked_at, secret_key FROM profiles WHERE id = ?"
    :: IO [(Maybe Text, Maybe Text, Maybe Integer, Maybe BS.ByteString)]
  events <- ofProfile "SELECT bytes FROM sync_events WHERE profile = ? ORDER BY rank" :: IO [Only BS.ByteString]
  devices <- query_ db "SELECT udp, ipv6, lan, stay_online, proxy_type, proxy_host, proxy_port FROM device_settings"
    :: IO [(Bool, Bool, Bool, Bool, Maybe Text, Maybe Text, Maybe Word16)]
  let chats = Map.fromListWith (flip (++))
        [ (ContactId key, [interrupted (Message mine text (fromMillis time) (delivery' delivery) file call confirmed
                                             (fromMillis <$> delivered) (if kind == 1 then Tox.MessageAction else Tox.MessageNormal) raw)])
        | (key, mine, text, time, delivery) :. (size, path, done, state) :. (video, talked, missed, confirmed, fileId)
            :. (kind, raw, delivered) <- messages
        , let file = Attachment <$> size <*> path <*> done <*> (fileState' <$> state) <*> Just fileId
              call = CallRecord <$> video <*> Just (fromMillis' <$> talked) <*> missed ]
      kept =
        [ ( wanted
          , ( cid
            , Contact name False (Map.findWithDefault [] cid chats) unread ((,) <$> address <*> request)
                status Tox.Online (if mute then Just (maybe MutedAlways (MutedUntil . fromMillis) until') else Nothing) avatar
                pictures ) )
        | (key, name, unread, address, request) :. (status, wanted, mute, until', avatar) :. Only pictures <- contacts
        , let cid = ContactId key ]
      said = Map.fromListWith (flip (++))
        [ (GroupId chat, [GroupEntry (fromMillis time) happening])
        | (chat, time, what, key, name) :. (kind, text, delivery, otherKey, otherName) <- entries
        , let member = Member <$> key <*> name
              other = Member <$> otherKey <*> otherName
              kind' = if kind == 1 then Tox.MessageAction else Tox.MessageNormal
        , Just happening <- [case what of
            "said"     -> Just (Said member kind' (fromMaybe "" text) (maybe Delivered delivery' delivery))
            "private from" -> (\m -> PrivateFrom m kind' (fromMaybe "" text)) <$> member
            "private to" -> (\m -> PrivateTo m kind' (fromMaybe "" text) (maybe Delivered delivery' delivery)) <$> member
            "moderated" -> Moderated member other <$> (moderationOf =<< text)
            "arrived"  -> Arrived <$> member
            "departed" -> Departed <$> member
            "topic"    -> Just (TopicSet member (fromMaybe "" text))
            "noted"    -> Noted <$> text
            _          -> Nothing] ]
      profile = case rows of
        (nickname, status, away, _, _, _) : _ -> (modelProfile initial)
          { profileNickname = nickname, profileStatus = status, profileAway = awayOf away }
        [] -> modelProfile initial
  pure initial
    { modelProfile = profile
    , modelProfileId = pid
    , modelProfiles = others
    , modelAvatar = case rows of
        (_, _, _, avatar, _, _) : _ -> avatar
        []                          -> Nothing
    , modelAvatars = Map.fromList avatars
    , modelNickname = profileNickname profile
    , modelStatus = profileStatus profile
    , modelRequest = requestMessage profile
    , modelContacts = Map.fromList [contact | (True, contact) <- kept]
    , modelFormer = Map.fromList [contact | (False, contact) <- kept]
    , modelRequests = Map.fromList [(ContactId key, message) | (key, message) <- requests]
    , modelDeclined = Map.fromList [(ContactId key, message) | (key, message) <- declined]
    , modelDrafts = Map.fromList [(ContactId key, draft) | (key, draft) <- drafts]
    , modelStaged = Map.fromListWith (flip (++))
        [ (ContactId key, [item])
        | (key, path, name, size, fileId, latitude, longitude) <- staged
        , Just item <- [ (StagedFile <$> path <*> name <*> size <*> fileId)
                           <|> (StagedPlace <$> latitude <*> longitude) ] ]
    , modelGroups = Map.fromList
        [ ( gid
          , (newGroup name (kindOf kind) (phaseOf phase))
              { groupEntries = Map.findWithDefault [] gid said, groupUnread = unread, groupSaved = saved
              , groupMute = if mute then Just (maybe MutedAlways (MutedUntil . fromMillis) until') else Nothing
              , groupMentions = mentioned, groupTopic = topic, groupRelayBot = lookup chat bots } )
        | (chat, name, phase, unread, saved) :. (mute, until', _, mentioned, topic) :. Only kind <- groups
        , let gid = GroupId chat ]
    , modelGroupDrafts = Map.fromList [(GroupId chat, d) | (chat, _, _, _, _) :. (_, _, Just d, _, _) :. _ <- groups]
    , modelInvites = Map.fromList
        [ ( (ContactId friend, GroupId chat)
          , Invite (kindOf kind) name bytes (if answered then Just (fromMaybe "" password) else Nothing) )
        | (friend, chat, name, bytes, answered, password, kind) <- invites ]
    , modelAccount = case rows of
        (_, _, _, _, size, off) : _ -> AccountSettings size (Set.fromList (Text.words off))
        []                     -> modelAccount initial
    , modelDevice = case devices of
        (udp, ipv6, lan, stay, kind, host, port) : _ ->
          DeviceSettings udp ipv6 lan stay (Tox.Proxy <$> (proxyKind =<< kind) <*> (Text.unpack <$> host) <*> port)
        [] -> modelDevice initial
    , modelLinked = case linking of
        [(Just home, pairing, Just since, Just secret)] | Just sk <- Sodium.decode secret ->
          let device = Sync.PublicKey (Sodium.encode (KeyPair.publicKey (KeyPair.fromSecretKey sk)))
              held = foldl (\store bytes -> either (const store) snd (Sync.insert bytes store)) Sync.emptyStore [b | Only b <- events]
          in Just (Linked.newLinked home pairing (fromMillis since) device held)
        _ -> Nothing
    }

save :: Store -> Model -> Model -> IO ()
save store old new = case modelLinked new of
  Just l  -> saveLinked store old new l
  Nothing -> saveOwn store old new

-- | For linked accounts: new events, the account name, and what only this
-- device has.
saveLinked :: Store -> Model -> Model -> Linked.Linked -> IO ()
saveLinked (Store database (ProfileId i)) old new l = using database $ \db -> withTransaction db $ do
  let profile = modelProfile new
      events = Replica.replicaStore . Linked.linkedReplica
      before = maybe Set.empty (Sync.storedIds . events) (modelLinked old)
  when (modelProfile old /= profile) $
    execute db "UPDATE profiles SET nickname = ?, status = ? WHERE id = ?" (profileNickname profile, profileStatus profile, i)
  when ((Linked.linkedPairing <$> modelLinked old) /= Just (Linked.linkedPairing l)) $
    execute db "UPDATE profiles SET pairing = ? WHERE id = ?" (Linked.linkedPairing l, i)
  forM_ (Set.toList (Set.difference (Sync.storedIds (events l)) before)) $ \eid@(Sync.EventId key) ->
    forM_ ((,) <$> Sync.lookupEvent eid (events l) <*> Sync.eventBytes eid (events l)) $ \(e, bytes) ->
      execute db "INSERT OR IGNORE INTO sync_events (profile, id, rank, bytes) VALUES (?, ?, ?, ?)"
        (i, key, Sync.eventRank e, bytes)
  saveAvatars db i old new
  saveAccount db i old new
  saveDevice db old new
  saveStaged db i old new
  saveMessages db i "drafts" (modelDrafts old) (modelDrafts new)

saveOwn :: Store -> Model -> Model -> IO ()
saveOwn (Store database (ProfileId i)) old new = using database $ \db -> withTransaction db $ do
  let profile = modelProfile new
  when (modelProfile old /= profile || modelAvatar old /= modelAvatar new) $
    execute db "UPDATE profiles SET nickname = ?, status = ?, away = ?, avatar = ? WHERE id = ?"
      (profileNickname profile, profileStatus profile, fromEnum (profileAway profile), modelAvatar new, i)
  saveAvatars db i old new
  -- Contacts, and those deleted with their chats kept.
  let everyone m = Map.union ((,) True <$> modelContacts m) ((,) False <$> modelFormer m)
  forM_ (Map.toList (everyone new)) $ \(cid@(ContactId key), (wanted, contact)) -> do
    let before = Map.lookup cid (everyone old)
    unless (before == Just (wanted, contact)) $ do
      execute db
        "INSERT OR REPLACE INTO contacts (profile, key, name, unread, request_address, request_message,\
        \ status_message, wanted, muted, muted_until, avatar, send_pictures) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ( Only i
        :. ( key, contactName contact, contactUnread contact
          , fst <$> contactRequest contact, snd <$> contactRequest contact )
        :. ( contactStatusMessage contact, wanted, isJust (contactMute contact)
           , case contactMute contact of
               Just (MutedUntil end) -> Just (toMillis end)
               _                     -> Nothing
           , contactAvatar contact )
        :. Only (contactPictures contact) )
      let kept = maybe [] (contactMessages . snd) before
      forM_ (zip3 [0 :: Int ..] (map Just kept ++ repeat Nothing) (contactMessages contact)) $
        \(place, was, m) -> unless (was == Just m) $
          execute db
            "INSERT INTO messages (profile, contact, place, mine, text, time, delivery,\
            \ file_size, file_path, file_done, file_state, call_video, call_duration, call_missed, parts, file_id,\
            \ kind, raw, delivered_time, id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,\
            \ randomblob(32)) ON CONFLICT (profile, contact, place) DO UPDATE SET mine = excluded.mine,\
            \ text = excluded.text, time = excluded.time, delivery = excluded.delivery,\
            \ file_size = excluded.file_size, file_path = excluded.file_path, file_done = excluded.file_done,\
            \ file_state = excluded.file_state, call_video = excluded.call_video,\
            \ call_duration = excluded.call_duration, call_missed = excluded.call_missed, parts = excluded.parts,\
            \ file_id = excluded.file_id, kind = excluded.kind, raw = excluded.raw,\
            \ delivered_time = excluded.delivered_time"
            ( Only i
            :. ( key, place, messageMine m, messageText m, toMillis (messageTime m)
              , deliveryName (messageDelivery m) )
            :. ( attachmentSize <$> messageFile m, attachmentPath <$> messageFile m
               , attachmentDone <$> messageFile m, fileStateName . attachmentState <$> messageFile m )
            :. ( recordVideo <$> messageCall m, fmap toMillis' . recordDuration =<< messageCall m
               , recordMissed <$> messageCall m, messageParts m, attachmentId =<< messageFile m )
            :. ( if messageKind m == Tox.MessageAction then 1 else 0 :: Int, messageRaw m
               , toMillis <$> messageDelivered m ) )
  -- Deleted with their chats, so delete those and their files too.
  forM_ (Map.keys (Map.difference (everyone old) (everyone new))) $ \(ContactId key) -> do
    paths <- SQLite.query db "SELECT file_path FROM messages WHERE profile = ? AND contact = ? AND file_path IS NOT NULL" (i, key)
    forM_ paths $ \(Only path) -> void (try (removeFile path) :: IO (Either IOException ()))
    execute db "DELETE FROM messages WHERE profile = ? AND contact = ?" (i, key)
    execute db "DELETE FROM contacts WHERE profile = ? AND key = ?" (i, key)
  saveAccount db i old new
  saveDevice db old new
  let groupRow m gid = (,) <$> Map.lookup gid (modelGroups m) <*> Just (Map.lookup gid (modelGroupDrafts m))
      chats m = Map.keysSet (modelGroups m)
  forM_ (Map.keys (modelGroups new)) $ \gid@(GroupId chat) -> do
    let before = groupRow old gid
    forM_ (groupRow new gid) $ \now@(g, draft) -> unless (before == Just now) $ do
      execute db
        "INSERT OR REPLACE INTO groups (profile, chat_id, name, phase, unread, saved, muted, muted_until, draft,\
        \ mentions, topic, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ( (i, chat, groupName g, phaseName (groupPhase g), groupUnread g)
        :. ( groupSaved g, isJust (groupMute g)
           , case groupMute g of
               Just (MutedUntil end) -> Just (toMillis end)
               _                     -> Nothing
           , draft, groupMentions g, groupTopic g )
        :. Only (kindName (groupKind g)) )
      when (fmap (groupRelayBot . fst) before /= Just (groupRelayBot g)) $ case groupRelayBot g of
        Just bot -> execute db "INSERT OR REPLACE INTO relay_bots (profile, chat_id, bot) VALUES (?, ?, ?)" (i, chat, bot)
        Nothing  -> execute db "DELETE FROM relay_bots WHERE profile = ? AND chat_id = ?" (i, chat)
      let kept = maybe [] (groupEntries . fst) before
      forM_ (zip3 [0 :: Int ..] (map Just kept ++ repeat Nothing) (groupEntries g)) $
        \(place, was, GroupEntry time happening) -> unless (was == Just (GroupEntry time happening)) $ do
          let (what, member, kind, text, delivery, other) = case happening of
                Said who k t d       -> ("said" :: Text, who, k, Just t, Just (deliveryName d), Nothing)
                PrivateFrom who k t  -> ("private from", Just who, k, Just t, Nothing, Nothing)
                PrivateTo who k t d  -> ("private to", Just who, k, Just t, Just (deliveryName d), Nothing)
                Moderated by whom m  -> ("moderated", by, Tox.MessageNormal, Just (moderationName m), Nothing, whom)
                Arrived who          -> ("arrived", Just who, Tox.MessageNormal, Nothing, Nothing, Nothing)
                Departed who         -> ("departed", Just who, Tox.MessageNormal, Nothing, Nothing, Nothing)
                TopicSet who t       -> ("topic", who, Tox.MessageNormal, Just t, Nothing, Nothing)
                Noted t              -> ("noted", Nothing, Tox.MessageNormal, Just t, Nothing, Nothing)
          execute db
            "INSERT INTO group_entries (profile, chat_id, place, time, what, member_key, member_name,\
            \ kind, text, delivery, other_key, other_name, id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,\
            \ randomblob(32)) ON CONFLICT (profile, chat_id, place) DO UPDATE SET time = excluded.time,\
            \ what = excluded.what, member_key = excluded.member_key, member_name = excluded.member_name,\
            \ kind = excluded.kind, text = excluded.text, delivery = excluded.delivery,\
            \ other_key = excluded.other_key, other_name = excluded.other_name"
            ( (i, chat, place, toMillis time, what)
            :. ( memberKey <$> member, memberName <$> member
               , if kind == Tox.MessageAction then 1 else 0 :: Int, text, delivery )
            :. (memberKey <$> other, memberName <$> other) )
  forM_ (Set.toList (Set.difference (chats old) (chats new))) $ \(GroupId chat) -> do
    execute db "DELETE FROM group_entries WHERE profile = ? AND chat_id = ?" (i, chat)
    execute db "DELETE FROM relay_bots WHERE profile = ? AND chat_id = ?" (i, chat)
    execute db "DELETE FROM groups WHERE profile = ? AND chat_id = ?" (i, chat)
  forM_ (Map.toList (modelInvites new)) $ \(at@(ContactId friend, GroupId chat), invite) ->
    unless (Map.lookup at (modelInvites old) == Just invite) $
      execute db
        "INSERT OR REPLACE INTO invites (profile, friend, chat_id, name, data, answered, password, kind)\
        \ VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ( i, friend, chat, inviteName invite, inviteData invite, isJust (inviteAnswered invite), inviteAnswered invite
        , kindName (inviteKind invite) )
  forM_ (Map.keys (Map.difference (modelInvites old) (modelInvites new))) $ \(ContactId friend, GroupId chat) ->
    execute db "DELETE FROM invites WHERE profile = ? AND friend = ? AND chat_id = ?" (i, friend, chat)
  saveStaged db i old new
  saveMessages db i "requests" (modelRequests old) (modelRequests new)
  saveMessages db i "declined" (modelDeclined old) (modelDeclined new)
  saveMessages db i "drafts" (modelDrafts old) (modelDrafts new)

-- | Online if it's not a status.
awayOf :: Int -> Tox.UserStatus
awayOf n = if n >= 0 && n <= fromEnum (maxBound :: Tox.UserStatus) then toEnum n else Tox.Online

saveAccount :: SQLite.Connection -> Int64 -> Model -> Model -> IO ()
saveAccount db i old new =
  when (modelAccount old /= modelAccount new) $
    execute db "UPDATE profiles SET auto_accept = ?, formats_off = ? WHERE id = ?"
      (settingAutoAccept (modelAccount new), Text.unwords (Set.toList (settingFormatsOff (modelAccount new))), i)

saveStaged :: SQLite.Connection -> Int64 -> Model -> Model -> IO ()
saveStaged db i old new =
  forM_ (Set.toList (Map.keysSet (modelStaged old) <> Map.keysSet (modelStaged new))) $ \cid@(ContactId key) -> do
    let items = Map.findWithDefault [] cid (modelStaged new)
    unless (Map.lookup cid (modelStaged old) == Map.lookup cid (modelStaged new)) $ do
      execute db "DELETE FROM staged WHERE profile = ? AND contact = ?" (i, key)
      forM_ (zip [0 :: Int ..] items) $ \(place, item) ->
        execute db "INSERT INTO staged (profile, contact, place, path, name, size, file_id, latitude, longitude)\
                   \ VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ( (i, key, place)
          :. case item of
               StagedFile path name size fileId ->
                 (Just path, Just name, Just size, Just fileId, Nothing, Nothing)
               StagedPlace latitude longitude ->
                 (Nothing, Nothing, Nothing, Nothing, Just latitude, Just longitude) )

saveAvatars :: SQLite.Connection -> Int64 -> Model -> Model -> IO ()
saveAvatars db i old new = do
  forM_ (Map.toList (Map.difference (modelAvatars new) (modelAvatars old))) $ \(hash, png) ->
    execute db "INSERT OR REPLACE INTO avatars (profile, hash, png) VALUES (?, ?, ?)" (i, hash, png)
  forM_ (Map.keys (Map.difference (modelAvatars old) (modelAvatars new))) $ \hash ->
    execute db "DELETE FROM avatars WHERE profile = ? AND hash = ?" (i, hash)

saveDevice :: SQLite.Connection -> Model -> Model -> IO ()
saveDevice db old new = when (modelDevice old /= modelDevice new) $ do
  let DeviceSettings udp ipv6 lan stay proxy = modelDevice new
  execute db "UPDATE device_settings SET udp = ?, ipv6 = ?, lan = ?, stay_online = ?,\
             \ proxy_type = ?, proxy_host = ?, proxy_port = ?"
    ( (udp, ipv6, lan, stay)
    :. ( proxyKindName . Tox.proxyType <$> proxy, Tox.proxyHost <$> proxy, Tox.proxyPort <$> proxy ) )

-- | Writes what changed in a table with a text per contact.
saveMessages :: SQLite.Connection -> Int64 -> Text -> Map.Map ContactId Text -> Map.Map ContactId Text -> IO ()
saveMessages db i table old new = do
  forM_ (Map.toList new) $ \(cid@(ContactId key), message) ->
    unless (Map.lookup cid old == Just message) $
      execute db (SQLite.Query ("INSERT OR REPLACE INTO " <> table <> " (profile, key, message) VALUES (?, ?, ?)"))
        (i, key, message)
  forM_ (Map.keys (Map.difference old new)) $ \(ContactId key) ->
    execute db (SQLite.Query ("DELETE FROM " <> table <> " WHERE profile = ? AND key = ?")) (i, key)

toMillis :: UTCTime -> Integer
toMillis = toMillis' . utcTimeToPOSIXSeconds

fromMillis :: Integer -> UTCTime
fromMillis = posixSecondsToUTCTime . fromMillis'

toMillis' :: NominalDiffTime -> Integer
toMillis' = round . (* 1000)

fromMillis' :: Integer -> NominalDiffTime
fromMillis' = (/ 1000) . fromIntegral

proxyKindName :: Tox.ProxyType -> Text
proxyKindName = \case
  Tox.HttpProxy   -> "http"
  Tox.Socks5Proxy -> "socks5"

proxyKind :: Text -> Maybe Tox.ProxyType
proxyKind = \case
  "http"   -> Just Tox.HttpProxy
  "socks5" -> Just Tox.Socks5Proxy
  _        -> Nothing

kindOf :: Text -> GroupKind
kindOf = \case
  "conference"       -> TextConference
  "audio conference" -> AudioConference
  _                  -> NgcGroup

phaseName :: GroupPhase -> Text
phaseName = \case
  Joining                     -> "in"
  InGroup                     -> "in"
  Refused Tox.JoinFailFull    -> "full"
  Refused Tox.JoinFailBadPassword -> "password"
  Refused Tox.JoinFailUnknown -> "refused"
  Gone                        -> "gone"
  Kicked                      -> "kicked"

-- | Groups we were in are 'Joining' again after a restart.
phaseOf :: Text -> GroupPhase
phaseOf = \case
  "full"     -> Refused Tox.JoinFailFull
  "password" -> Refused Tox.JoinFailBadPassword
  "refused"  -> Refused Tox.JoinFailUnknown
  "gone"     -> Gone
  "kicked"   -> Kicked
  _          -> Joining

moderationName :: Tox.Moderation -> Text
moderationName = \case
  Tox.ModKick      -> "kick"
  Tox.ModObserver  -> "observer"
  Tox.ModUser      -> "user"
  Tox.ModModerator -> "moderator"

moderationOf :: Text -> Maybe Tox.Moderation
moderationOf = \case
  "kick"      -> Just Tox.ModKick
  "observer"  -> Just Tox.ModObserver
  "user"      -> Just Tox.ModUser
  "moderator" -> Just Tox.ModModerator
  _           -> Nothing

deliveryName :: Delivery -> Text
deliveryName delivery = case delivery of
  Pending   -> "pending"
  Sent      -> "sent"
  Delivered -> "delivered"

fileStateName :: FileState -> Text
fileStateName state = case state of
  Waiting     -> "waiting"
  Moving      -> "moving"
  Complete    -> "complete"
  Interrupted -> "interrupted"
  Cancelled   -> "cancelled"

fileState' :: Text -> FileState
fileState' name = case name of
  "waiting"     -> Waiting
  "moving"      -> Moving
  "complete"    -> Complete
  "interrupted" -> Interrupted
  -- Also "stopped", from before resuming.
  _             -> Cancelled

delivery' :: Text -> Delivery
delivery' name = case name of
  "sent"      -> Sent
  "delivered" -> Delivered
  _           -> Pending
