{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
-- | App state, how events change it, and the commands for Tox. Pure, so we
-- can test all the UI logic off the device.
module Tox.Android.Model
  ( ContactId (..)
  , MessageId
  , Contact (..)
  , contactLabel
  , contactOrder
  , GroupId (..)
  , Group (..)
  , GroupPhase (..)
  , GroupKind (..)
  , newGroup
  , MemberAction (..)
  , memberActions
  , aways
  , awayName
  , privateMember
  , Founding (..)
  , foundingError
  , chatIdError
  , Member (..)
  , GroupEntry (..)
  , Happening (..)
  , Invite (..)
  , groupMuted
  , mentions
  , memberLabel
  , uttered
  , relayCounts
  , relayedThrough
  , groupLabel
  , inviteLabel
  , capitalised
  , kindName
  , ChatRow (..)
  , chatOrder
  , groupNick
  , Mute (..)
  , muted
  , Message (..)
  , Attachment (..)
  , Staged (..)
  , CallRecord (..)
  , FileState (..)
  , FileRef (..)
  , autoAccepted
  , AccountSettings (..)
  , DeviceSettings (..)
  , preview
  , quoted
  , forwardable
  , copiedText
  , callText
  , duration
  , interrupted
  , linkError
  , Delivery (..)
  , Profile (..)
  , ProfileId (..)
  , Account (..)
  , Connection (..)
  , Call (..)
  , callTarget
  , CallPhase (..)
  , Glare (..)
  , Route (..)
  , ringTimeout
  , Screen (..)
  , Model (..)
  , Event (..)
  , Command (..)
  , toxIdLength
  , toxId
  , unhex
  , addressError
  , requestError
  , profileError
  , requestMessage
  , initial
  , update
  , back
  , notifications
  , groupNotifications
  , missedCalls
  , callHistory
  ) where

import           Control.Applicative    ((<|>))
import qualified Crypto.Hash.SHA256     as SHA256
import           Data.Bits              (xor)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as Base16
import           Data.Char              (isAlphaNum, isHexDigit)
import           Data.Either            (fromRight)
import           Data.Int               (Int64)
import           Data.List              (find, nub, sortOn)
import           Data.Map.Strict        (Map)
import qualified Data.Map.Strict        as Map
import           Data.Maybe             (fromMaybe, isJust, isNothing,
                                         listToMaybe, mapMaybe)
import           Data.Ord               (Down (..))
import           Data.Set               (Set)
import qualified Data.Set               as Set
import           Data.Text              (Text)
import qualified Data.Text              as Text
import qualified Data.Text.Encoding     as Text
import           Data.Time              (NominalDiffTime, UTCTime, diffUTCTime)
import           Data.Word              (Word64, Word8)
import           Text.Read              (readMaybe)
import qualified Tox.Application.Tox    as Tox

import           Tox.Android.Formats    (Format (..), Reading (..), formats,
                                         readWith)
import qualified Tox.Android.Linked     as Linked
import           Tox.Android.Linked     (Linked)
import           Tox.Android.Locations  (location, locationText)
import           Tox.Android.Messages   (parts)
import qualified Tox.Android.Pictures   as Pictures
import           Tox.Android.Relays     (relayed, relayedNames)
import qualified Tox.Sync.Account       as Sync
import qualified Tox.Sync.Event         as Sync
import qualified Tox.Sync.Fact          as Sync
import qualified Tox.Sync.Id            as Sync
import qualified Tox.Sync.Pairing       as Pairing
import qualified Tox.Sync.Protocol      as Protocol
import qualified Tox.Sync.Replica       as Replica
import qualified Tox.Sync.Setting       as Sync
import qualified Tox.Sync.Store         as Sync

-- | Friend's public key in upper case hex.
newtype ContactId = ContactId Text
  deriving (Eq, Ord, Show)

-- | Index of a message in its chat.
type MessageId = Int

data Delivery = Pending | Sent | Delivered
  deriving (Eq, Show)

data Message = Message
  { messageMine      :: Bool
  , messageText      :: Text
    -- ^ File name for files.
  , messageTime      :: UTCTime
  , messageDelivery  :: Delivery
    -- ^ Always 'Delivered' for theirs.
  , messageFile      :: Maybe Attachment
  , messageCall      :: Maybe CallRecord
    -- ^ 'messageTime' is when it started ringing.
  , messageParts     :: Int
    -- ^ How many of our 'parts' the friend confirmed.
  , messageDelivered :: Maybe UTCTime
    -- ^ When the friend got all of ours, if we know.
  , messageKind      :: Tox.MessageType
  , messageRaw       :: Maybe BS.ByteString
    -- ^ Their bytes as Tox carried them (the text is read from these).
    -- Nothing for messages from before we kept them.
  } deriving (Eq, Show)

-- | Picked for a chat, sent with its draft.
data Staged
  = StagedFile FilePath Text Word64 BS.ByteString
    -- ^ Path of our copy, name, size and a new file ID.
  | StagedPlace Double Double
  deriving (Eq, Show)

data CallRecord = CallRecord
  { recordVideo    :: Bool
  , recordDuration :: Maybe NominalDiffTime
    -- ^ Nothing if nobody answered.
  , recordMissed   :: Bool
    -- ^ Theirs, and we never answered.
  } deriving (Eq, Show)

data Attachment = Attachment
  { attachmentSize  :: Word64
  , attachmentPath  :: FilePath
    -- ^ Theirs gets written there as it comes in.
  , attachmentDone  :: Word64
    -- ^ Bytes sent or received so far.
  , attachmentState :: FileState
  , attachmentId    :: Maybe BS.ByteString
    -- ^ Tox file ID, so we can resume when it's offered again. Nothing for
    -- files from before we kept it.
  } deriving (Eq, Show)

data FileState
  = Waiting
    -- ^ For the friend to accept ours, or the user to accept theirs.
  | Moving
  | Complete
  | Interrupted
    -- ^ Theirs, cut off by going offline or a restart. Resumes when the
    -- friend offers it again.
  | Cancelled
    -- ^ By either side, or cut off and can't resume.
  deriving (Eq, Show)

-- | Tox's file number, valid while the friend stays online.
data FileRef = Sending Word8 | Receiving Word8
  deriving (Eq, Ord, Show)

-- | Text for the chat list and notifications. Actions get the name in front.
preview :: Text -> Message -> Text
preview name m = case (messageCall m, messageFile m) of
  (Just record, _) -> callText (messageMine m) record
  (_, Just _)      -> "\x1F4CE " <> messageText m
  _ | messageKind m == Tox.MessageAction -> "* " <> name <> " " <> messageText m
    | Just _ <- location (messageText m) -> "\x1F4CD Location"
    | otherwise -> messageText m

-- | Calls can't be forwarded, and files only if they're ours or complete.
forwardable :: Message -> Bool
forwardable m = isNothing (messageCall m)
  && maybe True (\a -> messageMine m || attachmentState a == Complete) (messageFile m)

quoted :: Message -> Text
quoted = Text.intercalate "\n" . map ("> " <>) . Text.lines . messageText

-- | Text to copy: 1 message as is, more with the sender's name in front.
-- Calls are left out.
copiedText :: Model -> ContactId -> [MessageId] -> Text
copiedText model cid is = case [m | (i, m) <- zip [0 ..] messages, i `elem` is, isNothing (messageCall m)] of
  [m] -> messageText m
  ms  -> Text.intercalate "\n" [whose m <> ": " <> messageText m | m <- ms]
  where
    contact = Map.lookup cid (modelContacts model)
    messages = maybe [] contactMessages contact
    whose m
      | messageMine m = profileNickname (modelProfile model)
      | otherwise = maybe "" (contactLabel cid) contact

callText :: Bool -> CallRecord -> Text
callText mine record =
  maybe kind (\talked -> kind <> " \x00B7 " <> duration (round talked)) (recordDuration record)
  where
    kind = whose <> (if recordVideo record then " video call" else " voice call")
    whose
      | recordMissed record = "Missed"
      | mine = "Outgoing"
      | otherwise = "Incoming"

-- | Minutes and seconds, e.g. 3:07.
duration :: Int -> Text
duration seconds = Text.pack (show (seconds `div` 60)) <> ":" <> Text.justifyRight 2 '0' (Text.pack (show (seconds `mod` 60)))

-- | Default auto-accept limit for their files.
autoAccepted :: Word64
autoAccepted = 4 * 1024 * 1024

-- | Settings of the account, the same on all its devices.
data AccountSettings = AccountSettings
  { settingAutoAccept :: Word64
    -- ^ Accept their files up to this size without asking (0 = never).
  , settingFormatsOff :: Set Text
    -- ^ Formats not to read (those messages show as Tox carried them).
  } deriving (Eq, Show)

readable :: AccountSettings -> [Format]
readable account = [f | f <- formats, formatKey f `Set.notMember` settingFormatsOff account]

-- | Settings of this device only. Changes apply when Tox restarts.
data DeviceSettings = DeviceSettings
  { settingUdp   :: Bool
  , settingIpv6  :: Bool
  , settingLan   :: Bool
  , settingStay  :: Bool
    -- ^ Stay online while hTox is closed, and start on boot.
  , settingProxy :: Maybe Tox.Proxy
    -- ^ For TCP relays. UDP and local discovery are off with a proxy.
  } deriving (Eq, Show)

data Contact = Contact
  { contactName          :: Maybe Text
  , contactOnline        :: Bool
  , contactMessages      :: [Message]
    -- ^ Oldest first.
  , contactUnread        :: Int
  , contactRequest       :: Maybe (Text, Text)
    -- ^ Our friend request (Tox ID and message) until they're first online.
    -- Tox forgets it on restart, so we send it again.
  , contactStatusMessage :: Text
  , contactStatus        :: Tox.UserStatus
  , contactMute          :: Maybe Mute
  , contactAvatar        :: Maybe BS.ByteString
    -- ^ Hash of their avatar in 'modelAvatars'.
  , contactPictures      :: Maybe Text
    -- ^ Picture format we send them, if not as they are.
  } deriving (Eq, Show)

data Mute = MutedUntil UTCTime | MutedAlways
  deriving (Eq, Show)

muted :: UTCTime -> Contact -> Bool
muted now = mutedBy now . contactMute

mutedBy :: UTCTime -> Maybe Mute -> Bool
mutedBy now = \case
  Just (MutedUntil end) -> now < end
  Just MutedAlways      -> True
  Nothing               -> False

-- | Name, or the start of the key if there's none.
contactLabel :: ContactId -> Contact -> Text
contactLabel (ContactId key) contact = fromMaybe (Text.take 8 key) (contactName contact)

-- | Latest chat first, then those without messages by name.
contactOrder :: Model -> [(ContactId, Contact)]
contactOrder = sortOn latest . Map.toList . modelContacts
  where
    latest (cid, c) =
      (Down (messageTime <$> listToMaybe (reverse (contactMessages c))), Text.toCaseFold (contactLabel cid c))

-- | Chat ID in upper case hex. Not the group number (Tox numbers groups anew
-- each time it starts).
newtype GroupId = GroupId Text
  deriving (Eq, Ord, Show)

-- | Member's key in that group (hex) and name.
data Member = Member
  { memberKey  :: Text
  , memberName :: Text
  } deriving (Eq, Show)

data GroupPhase
  = Joining
    -- ^ Until we have the group state from peers, also after each start.
  | InGroup
  | Refused Tox.JoinFail
  | Kicked
  | Gone
    -- ^ We left. The chat stays.
  deriving (Eq, Show)

-- | NGC groups and the old conferences. We join audio conferences for their
-- text only.
data GroupKind = NgcGroup | TextConference | AudioConference
  deriving (Eq, Show)

-- | Keyed by the chat ID, or the conference ID.
data Group = Group
  { groupName     :: Text
  , groupKind     :: GroupKind
  , groupPhase    :: GroupPhase
  , groupEntries  :: [GroupEntry]
    -- ^ Oldest first.
  , groupUnread   :: Int
  , groupMembers  :: Map Tox.PeerId Member
    -- ^ Others, by Tox's peer number. Not saved.
  , groupSaved    :: Maybe BS.ByteString
    -- ^ Last blob Tox gave us to rejoin it.
  , groupMute     :: Maybe Mute
  , groupMentions :: Bool
    -- ^ Notify about messages naming us while muted (on by default).
  , groupTopic    :: Text
  , groupMayTopic :: Bool
    -- ^ Whether Tox would take a topic from us. Not saved.
  , groupSince    :: Maybe UTCTime
    -- ^ When we last got in. Tox reports everyone already there as joining
    -- while it meets them. Not saved.
  , groupRoles    :: Map Tox.PeerId Tox.Role
    -- ^ Not saved.
  , groupStatuses :: Map Tox.PeerId Tox.UserStatus
    -- ^ Members who are away or busy. Not saved.
  , groupSelfRole :: Maybe Tox.Role
    -- ^ Not saved.
  , groupSettings :: Maybe Tox.GroupSettings
    -- ^ Founder's settings. Not saved.
  , groupRelayBot :: Maybe Text
    -- ^ Key of the bot whose messages show under the names it relays.
  } deriving (Eq, Show)

newGroup :: Text -> GroupKind -> GroupPhase -> Group
newGroup name kind phase = Group
  { groupName = name, groupKind = kind, groupPhase = phase, groupEntries = [], groupUnread = 0
  , groupMembers = Map.empty, groupSaved = Nothing, groupMute = Nothing, groupMentions = True, groupTopic = ""
  , groupMayTopic = False, groupSince = Nothing, groupRoles = Map.empty, groupStatuses = Map.empty, groupSelfRole = Nothing
  , groupSettings = Nothing, groupRelayBot = Nothing }

-- | As toxcore allows: the founder can set any other role and kick anyone,
-- moderators only users and observers.
data MemberAction = MakeModerator | MakeUser | MakeObserver | Kick
  deriving (Eq, Show)

memberActions :: Maybe Tox.Role -> Tox.Role -> [MemberAction]
memberActions ours theirs = case ours of
  Just Tox.Founder | theirs /= Tox.Founder ->
    [MakeModerator | theirs /= Tox.Moderator] ++ [MakeUser | theirs /= Tox.User]
      ++ [MakeObserver | theirs /= Tox.Observer] ++ [Kick]
  Just Tox.Moderator | theirs `elem` [Tox.User, Tox.Observer] ->
    [MakeUser | theirs /= Tox.User] ++ [MakeObserver | theirs /= Tox.Observer] ++ [Kick]
  _ -> []

-- | What a group's chat shows, at a time.
data GroupEntry = GroupEntry
  { entryTime :: UTCTime
  , entryWhat :: Happening
  } deriving (Eq, Show)

data Happening
  = Said (Maybe Member) Tox.MessageType Text Delivery
    -- ^ Nothing for ours. Ours only go 'Pending' to 'Sent' (groups confirm
    -- nothing).
  | PrivateFrom Member Tox.MessageType Text
  | PrivateTo Member Tox.MessageType Text Delivery
  | Moderated (Maybe Member) (Maybe Member) Tox.Moderation
    -- ^ Who did it to whom. Nothing means us.
  | Arrived Member
  | Departed Member
  | TopicSet (Maybe Member) Text
    -- ^ Nothing for ours.
  | Noted Text
    -- ^ From a linked account's home.
  deriving (Eq, Show)

data Invite = Invite
  { inviteKind     :: GroupKind
  , inviteName     :: Text
    -- ^ Empty for conferences.
  , inviteData     :: BS.ByteString
    -- ^ As Tox gave it (we need it to accept).
  , inviteAnswered :: Maybe Text
    -- ^ Accepted, with the password, until the friend is online.
  } deriving (Eq, Show)

-- | Name, or the start of the key if there's none.
memberLabel :: Member -> Text
memberLabel m
  | not (Text.null (memberName m)) = memberName m
  | not (Text.null (memberKey m)) = Text.take 8 (memberKey m)
  | otherwise = "Someone"

-- | Sender and text to show. Messages of the relay bot show as "Name via
-- Bot".
uttered :: Profile -> Group -> Member -> Text -> (Text, Text)
uttered profile g = utter
  where
    known = speakers profile g
    utter who text = case relayed known text of
      Just (name, said) | Just (memberKey who) == groupRelayBot g -> (name <> " via " <> memberLabel who, said)
      _ -> (memberLabel who, text)

-- | Names of everyone not relayed, us too, so we can tell where a relayed
-- name ends.
speakers :: Profile -> Group -> [Text]
speakers profile g = Set.toList $ Set.fromList $ groupNick profile
  : [memberLabel m | GroupEntry _ (Said (Just m) _ _ _) <- groupEntries g, Just (memberKey m) /= groupRelayBot g]

-- | Members who said anything, with how many of their messages look relayed
-- and how many there are. Likeliest bot first.
relayCounts :: Group -> [(Member, Int, Int)]
relayCounts g = sortOn (\(m, r, n) -> (Down r, Down n, memberLabel m)) $ Map.elems $ Map.fromListWith add
  [ (memberKey m, (m, fromEnum (isJust (relayed [] text)), 1)) | GroupEntry _ (Said (Just m) _ text _) <- groupEntries g ]
  where add (m, r, n) (_, r', n') = (m, r + r', n + n')

-- | Names the relay bot relayed, with the last time, latest first.
relayedThrough :: Profile -> Group -> [(Text, UTCTime)]
relayedThrough profile g = relayedNames (speakers profile g)
  [ (time, text) | GroupEntry time (Said (Just m) _ text _) <- groupEntries g, Just (memberKey m) == groupRelayBot g ]

-- | Private groups are joined by invite, public ones also by chat ID.
-- Conferences are for older clients.
data Founding = PrivateGroup | PublicGroup | NewConference
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Why the name isn't OK, if it isn't.
foundingError :: Founding -> Text -> Maybe Text
foundingError founding name
  | Text.null (Text.strip name) = Just "The name can't be empty"
  | BS.length (Text.encodeUtf8 (Text.strip name)) > limit = Just "The name is too long"
  | otherwise = Nothing
  where
    limit = if founding == NewConference then Tox.maxNameLength else Tox.maxGroupNameSize

-- | Why the text isn't a chat ID, if it isn't. Nothing while it's empty.
chatIdError :: Text -> Maybe Text
chatIdError chatId
  | Text.null chatId = Nothing
  | Text.length chatId /= 64 || not (Text.all isHexDigit chatId) = Just "Must be 64 hexadecimal characters"
  | otherwise = Nothing

kindName :: GroupKind -> Text
kindName = \case
  NgcGroup        -> "group"
  TextConference  -> "conference"
  AudioConference -> "audio conference"

-- | Name, or the kind if there's none (conferences start without one).
groupLabel :: Group -> Text
groupLabel g = nameOr (groupName g) (groupKind g)

inviteLabel :: Invite -> Text
inviteLabel invite = nameOr (inviteName invite) (inviteKind invite)

nameOr :: Text -> GroupKind -> Text
nameOr name kind
  | Text.null name = capitalised (kindName kind)
  | otherwise = name

capitalised :: Text -> Text
capitalised word = Text.toUpper (Text.take 1 word) <> Text.drop 1 word

groupMuted :: UTCTime -> Group -> Bool
groupMuted now = mutedBy now . groupMute

-- | Whether the text has the name as a whole word, ignoring case. Words are
-- letters, digits and underscores.
mentions :: Text -> Text -> Bool
mentions name text
  | Text.null needle = False
  | otherwise = any whole (Text.breakOnAll needle haystack)
  where
    needle = Text.toCaseFold (Text.strip name)
    haystack = Text.toCaseFold text
    whole (before, rest) = not (wordy (Text.takeEnd 1 before))
      && not (wordy (Text.take 1 (Text.drop (Text.length needle) rest)))
    wordy = Text.any (\c -> isAlphaNum c || c == '_')

data ChatRow = FriendRow ContactId Contact | GroupRow GroupId Group
  deriving (Eq, Show)

-- | Latest chat first, then those without messages by name.
chatOrder :: Model -> [ChatRow]
chatOrder model = sortOn latest $
  [FriendRow cid c | (cid, c) <- Map.toList (modelContacts model)]
  ++ [GroupRow gid g | (gid, g) <- Map.toList (modelGroups model)]
  where
    latest = \case
      FriendRow cid c ->
        (Down (messageTime <$> listToMaybe (reverse (contactMessages c))), Text.toCaseFold (contactLabel cid c))
      GroupRow _ g ->
        (Down (entryTime <$> listToMaybe (reverse (groupEntries g))), Text.toCaseFold (groupName g))

aways :: [Tox.UserStatus]
aways = [minBound .. maxBound]

awayName :: Tox.UserStatus -> Text
awayName = \case
  Tox.Online -> "Online"
  Tox.Away   -> "Away"
  Tox.Busy   -> "Busy"

-- | Our name in groups (Tox takes no empty one).
groupNick :: Profile -> Text
groupNick p = if Text.null (Text.strip (profileNickname p)) then "Tox User" else profileNickname p

data Profile = Profile
  { profileNickname :: Text
  , profileStatus   :: Text
  , profileAway     :: Tox.UserStatus
  , profileToxId    :: Text
  } deriving (Eq, Show)

-- | Database ID of an account.
newtype ProfileId = ProfileId Int64
  deriving (Eq, Ord, Show)

data Account = Account
  { accountId   :: ProfileId
  , accountName :: Text
  , accountKey  :: Text
    -- ^ Public key in hex. Empty until Tox first made its keys.
  } deriving (Eq, Show)

-- | Worst first.
data Connection = Offline | ViaTcp | ViaUdp
  deriving (Eq, Ord, Show)

-- | There's at most 1.
data Call = Call
  { callContact    :: ContactId
  , callPhase      :: CallPhase
  , callStarted    :: UTCTime
    -- ^ When it started ringing.
  , callMine       :: Bool
  , callVideo      :: Bool
    -- ^ Whether it started as a video call.
  , callCamera     :: Bool
    -- ^ Whether we send video.
  , callPeerVideo  :: Bool
  , callMuted      :: Bool
    -- ^ Our microphone (we drop its frames while muted).
  , callRoute      :: Route
  , callRoutes     :: [Route]
    -- ^ Routes we could switch to.
  , callBackCamera :: Bool
  , callHidden     :: Bool
    -- ^ The user went back to the chats (with a banner to return).
  , callGlare      :: Glare
  , callEntry      :: Maybe MessageId
    -- ^ Chat entry, added at the start so it's still there if hTox stops
    -- during the call.
  , callVia        :: Maybe ContactId
    -- ^ Linked account's home, which relays the audio and video.
  } deriving (Eq, Show)

callTarget :: Call -> ContactId
callTarget c = fromMaybe (callContact c) (callVia c)

-- | Video calls start on the loudspeaker (the phone isn't at the ear).
newCall :: ContactId -> CallPhase -> UTCTime -> Bool -> Call
newCall cid phase time video =
  Call cid phase time (phase == Calling) video False False False
    (if video then Speaker else Earpiece) [Earpiece, Speaker] False False Clear Nothing Nothing

data CallPhase
  = Calling
  | Ringing
    -- ^ They call us.
  | Talking UTCTime
  deriving (Eq, Show)

-- | If both ends call at once, Tox fails both calls. The end with the higher
-- key calls again and the other answers that (as other clients do).
data Glare
  = Clear
  | Glared UTCTime
  | Settling
    -- ^ Called again or answered, so another failure ends it.
  deriving (Eq, Show)

-- | How long the end calling again waits for the first call to go away, and
-- how long the other waits for the new call.
glareDelay, glareWait :: NominalDiffTime
glareDelay = 2
glareWait = 8

data Route = Earpiece | Speaker | Wired | Bluetooth
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | How long Tox takes to meet the peers already in a group after joining.
meeting :: NominalDiffTime
meeting = 15

-- | How long a call rings before we give up.
ringTimeout :: NominalDiffTime
ringTimeout = 60

data Screen
  = Contacts
  | Chat ContactId
  | Details ContactId
  | Forward ContactId [MessageId]
    -- ^ Choosing who to forward messages to.
  | MessageInfo ContactId MessageId
  | CallsScreen
  | ProfileScreen
  | SettingsScreen
  | ProfilesScreen
  | ProxyScreen
  | AddContact
  | GroupChat GroupId
  | GroupDetails GroupId
  | InviteScreen ContactId GroupId
    -- ^ Accepting a friend's invite (with the password if it has one).
  | TopicScreen GroupId
  | NewGroupScreen
  | JoinGroupScreen
    -- ^ Joining a public group by its chat ID.
  | InviteFriendsScreen GroupId
  | GroupSettingsScreen GroupId
  | LinkScreen
    -- ^ Linking to an account on another device, by its pairing link.
  | BackupScreen
    -- ^ Choosing the profiles to back up.
  deriving (Eq, Show)

data Model = Model
  { modelScreen        :: Screen
  , modelShown         :: Bool
    -- ^ Whether the app is in front of the user.
  , modelDrawer        :: Bool
  , modelProfile       :: Profile
  , modelConnection    :: Connection
  , modelContacts      :: Map ContactId Contact
  , modelRequests      :: Map ContactId Text
    -- ^ Friend requests and their messages.
  , modelFormer        :: Map ContactId Contact
    -- ^ Deleted with the chat kept. They come back when added again.
  , modelDeclined      :: Map ContactId Text
    -- ^ Rejected friend requests. They stay hidden while the message stays
    -- the same (Tox sends them again and again).
  , modelDrafts        :: Map ContactId Text
  , modelGroups        :: Map GroupId Group
  , modelInvites       :: Map (ContactId, GroupId) Invite
  , modelGroupDrafts   :: Map GroupId Text
  , modelPassword      :: Text
    -- ^ Of the invite open, or the public group to join.
  , modelTopic         :: Text
    -- ^ As edited until applied.
  , modelFounding      :: Founding
  , modelGroupName     :: Text
    -- ^ Of the group to found.
  , modelChatId        :: Text
  , modelPrivateTo     :: Maybe Text
    -- ^ Member key the open group chat's draft goes to privately.
  , modelPeerLimit     :: Text
    -- ^ Settings of the open group, as edited until applied.
  , modelGroupPassword :: Text
  , modelNickname      :: Text
    -- ^ As edited on the profile screen until applied, like the status.
  , modelStatus        :: Text
  , modelAddress       :: Text
  , modelRequest       :: Text
  , modelAddError      :: Maybe Text
    -- ^ Why Tox refused the contact last added.
  , modelProxyKind     :: Maybe Tox.ProxyType
    -- ^ As edited until applied, like the host and port.
  , modelProxyHost     :: Text
  , modelProxyPort     :: Text
  , modelTransfers     :: Map (ContactId, FileRef) MessageId
    -- ^ Messages of the transfers Tox has going.
  , modelCall          :: Maybe Call
  , modelFullScreen    :: Bool
    -- ^ Whether calls may ring over the lock screen.
  , modelProfileId     :: ProfileId
    -- ^ Shown account, one of 'modelProfiles'.
  , modelProfiles      :: [Account]
  , modelAway          :: Bool
    -- ^ Open chat is scrolled away from its newest messages.
  , modelUnseen        :: Int
    -- ^ Messages that came in while scrolled away.
  , modelJump          :: Int
    -- ^ Bumped to scroll the open chat to its newest messages.
  , modelSelected      :: Set MessageId
    -- ^ In the open chat.
  , modelStaged        :: Map ContactId [Staged]
    -- ^ In the order picked.
  , modelReplies       :: Map ContactId MessageId
    -- ^ Message each chat's draft replies to.
  , modelAvatar        :: Maybe BS.ByteString
    -- ^ Hash of our avatar.
  , modelAvatars       :: Map BS.ByteString BS.ByteString
    -- ^ Our and friends' avatars as PNGs, by SHA-256.
  , modelAccount       :: AccountSettings
  , modelDevice        :: DeviceSettings
  , modelNotice        :: Maybe Text
    -- ^ Shown until the user goes to another screen.
  , modelLinked        :: Maybe Linked
    -- ^ If this profile is linked to an account on another device. The
    -- chats are then derived from it.
  , modelLink          :: Text
    -- ^ Pairing link as typed.
  , modelBackup        :: Set ProfileId
    -- ^ Profiles chosen to back up.
  } deriving (Eq, Show)

data Event
  = Open Screen
  | Back
  | OpenDrawer
  | DraftChanged Text
  | Send UTCTime
  | NicknameChanged Text
  | StatusChanged Text
  | ApplyProfile
  | AwayChosen Tox.UserStatus
  | AddressChanged Text
  | RequestChanged Text
  | AddFriend
  | Accept ContactId
  | Reject ContactId
  | Started Text
    -- ^ Tox is running, with this Tox ID.
  | Connected Connection
  | FriendOnline ContactId Bool
  | FriendNamed ContactId Text
  | FriendStatusMessage ContactId Text
  | FriendStatus ContactId Tox.UserStatus
  | DeleteContact ContactId Bool
    -- ^ Keep the chat or not.
  | MuteChat ContactId (Maybe UTCTime)
    -- ^ Until a time, or forever.
  | UnmuteChat ContactId
  | Received ContactId UTCTime Tox.MessageType BS.ByteString
  | Delivering ContactId MessageId Delivery
  | Confirmed ContactId MessageId Int UTCTime
    -- ^ How many parts of our message the friend has.
  | ScrolledAway Bool
  | JumpToEnd
  | Select MessageId
    -- ^ Toggles.
  | Unselect
  | Reply MessageId
  | CancelReply
  | ForwardTo ContactId UTCTime
  | Requested ContactId Text
  | AddFailed Text Text
    -- ^ Tox refused to add a Tox ID, for this reason.
  | Shown Bool
    -- ^ The app came in front of the user, or went away.
  | FullScreenChecked Bool
  | ProfilesChanged [Account]
  | ProxyKindChosen (Maybe Tox.ProxyType)
  | ProxyHostChanged Text
  | ProxyPortChanged Text
  | ApplyProxy
  | SendPictures ContactId (Maybe Text)
    -- ^ Picture format to send them, by its key.
  | Attach FilePath Text Word64 BS.ByteString
    -- ^ Picked for the open chat: path of our copy, name, size and a new
    -- file ID.
  | Unstage ContactId Int
    -- ^ By its index in the staged list.
  | FileStarted ContactId MessageId FileRef
    -- ^ Tox offered the friend our file.
  | FileOffered ContactId FileRef UTCTime Text Word64 FilePath BS.ByteString
    -- ^ Name, size, path to save it to, and file ID.
  | Download ContactId MessageId
  | Cancel ContactId MessageId
  | FileMoved ContactId FileRef Word64
    -- ^ Bytes so far.
  | FileEnded ContactId FileRef Bool
    -- ^ Whether the whole file got through.
  | StartCall UTCTime Bool
    -- ^ Call the open chat's friend, with or without the camera.
  | AnswerCall UTCTime Bool
  | HangUp UTCTime
  | CallElsewhere UTCTime
    -- ^ Another profile has a call (we only do 1 at a time).
  | ToggleMute
  | ToggleCamera
  | HideCall
  | ShowCall
  | RoutesChanged Route [Route]
    -- ^ Current route, and the ones we could switch to.
  | FlipCamera
  | CallInvited ContactId UTCTime Bool
    -- ^ With video or not.
  | CallPeer ContactId UTCTime Bool
    -- ^ The friend answered our call, or turned video on or off.
  | CallEnded ContactId UTCTime
  | CallGlared ContactId UTCTime
    -- ^ Tox failed the call because both ends called at once.
  | Tick UTCTime
    -- ^ During calls.
  | Notify Text
  | AvatarPicked BS.ByteString
    -- ^ Our new avatar as a PNG.
  | RemoveAvatar
  | FriendAvatar ContactId (Maybe BS.ByteString)
    -- ^ PNG, or Nothing if they removed theirs.
  | SetAutoAccept Word64
  | ToggleFormat Text
  | SetDevice DeviceSettings
  | ShareLocation Double Double
    -- ^ To the open chat.
  | Invited ContactId GroupId GroupKind Text BS.ByteString
    -- ^ Group name and invite data.
  | MembersListed GroupId UTCTime [(Tox.PeerId, Member)]
    -- ^ Everyone in a conference now, except us.
  | PasswordChanged Text
  | AnswerInvite ContactId GroupId Bool
    -- ^ Join with the typed password, or decline.
  | GroupConnected GroupId UTCTime
    -- ^ We have the group state from peers.
  | GroupRefused GroupId Tox.JoinFail
  | MemberJoined GroupId UTCTime Tox.PeerId Member
  | MemberLeft GroupId UTCTime Tox.PeerId Tox.ExitType
  | MemberNamed GroupId Tox.PeerId Text
  | GroupReceived GroupId UTCTime Tox.PeerId Tox.MessageType Text
  | GroupSent GroupId MessageId
  | GroupSaved GroupId BS.ByteString
  | GroupNamed GroupId Text
  | LeaveGroup GroupId
  | DeleteGroup GroupId
  | MuteGroup GroupId (Maybe UTCTime)
  | UnmuteGroup GroupId
  | ToggleMentions GroupId
  | TopicChanged GroupId UTCTime (Maybe Tox.PeerId) Text
    -- ^ Peer, if Tox knows who.
  | TopicSetByUs GroupId UTCTime Text
  | TopicAllowed GroupId Bool
  | TopicEdited Text
  | ApplyTopic
  | FoundingChosen Founding
  | GroupNameEdited Text
  | Found
  | GroupCreated GroupId GroupKind Text UTCTime
    -- ^ We founded it.
  | ChatIdEdited Text
  | JoinPublic
  | InviteFriend GroupId ContactId
  | PrivateReceived GroupId UTCTime Tox.PeerId Tox.MessageType Text
  | PrivatelyTo (Maybe Text)
    -- ^ Write privately to a member of the open group (by key), or to
    -- everyone again.
  | RolesKnown GroupId (Maybe Tox.Role) [(Tox.PeerId, Tox.Role)]
    -- ^ Ours and the members'.
  | MemberStatus GroupId Tox.PeerId Tox.UserStatus
  | GroupModerated GroupId UTCTime (Maybe Tox.PeerId) (Maybe Tox.PeerId) Tox.Moderation
    -- ^ Who did it to whom. Nothing means us.
  | SettingsKnown GroupId Tox.GroupSettings
  | Moderate GroupId Tox.PeerId MemberAction
  | ChangeSettings GroupId Tox.GroupSettings
  | PeerLimitEdited Text
  | GroupPasswordEdited Text
  | ApplyGroupSettings
  | ChooseRelayBot GroupId (Maybe Text)
    -- ^ Member key of the relay bot, or none.
  | SyncReceived ContactId BS.ByteString
    -- ^ Only a linked account's home sends these.
  | FileShared ContactId UTCTime Text Word64 BS.ByteString FilePath
    -- ^ Our file for a linked account's friend, stored as a blob for the
    -- home: name, size, blob ID and path.
  | BlobArrived BS.ByteString FilePath (Maybe BS.ByteString)
    -- ^ From a linked account's home, in its file. Bytes too if it's small
    -- enough to be an avatar.
  | BlobMissing BS.ByteString
    -- ^ Came out of order, cut short, or doesn't match its ID.
  | LinkEdited Text
  | ToggleBackup ProfileId
  deriving (Eq, Show)

-- | For Tox to do.
data Command
  = SetProfile Profile
  | SetGroupStatus GroupId Tox.UserStatus
  | Befriend ContactId
    -- ^ Without a request: to accept theirs, or to add a friend back.
  | Unfriend ContactId
  | SendAvatar ContactId (Maybe BS.ByteString)
    -- ^ Our avatar as a PNG, or Nothing if we have none.
  | RequestFriend Text Text
    -- ^ Tox ID and message.
  | SendMessage ContactId MessageId Text Int
    -- ^ With how many of its parts the friend confirmed.
  | SendFile ContactId MessageId FilePath Text Word64 (Maybe BS.ByteString)
  | AcceptFile ContactId FileRef FilePath
    -- ^ Resumes after what's already in the file.
  | CancelFile ContactId FileRef
  | ForgetFile FilePath
    -- ^ Delete our copy of a file that was unstaged.
  | CallFriend ContactId Bool
    -- ^ With or without the camera, as for the other call commands.
  | AnswerFriend ContactId Bool
  | HangUpCall ContactId
  | CameraCall ContactId Bool
  | JoinGroup ContactId GroupId BS.ByteString Text Text
    -- ^ With the friend's invite, our name in the group and a password.
  | JoinConference ContactId GroupId BS.ByteString
  | RestoreGroup GroupKind GroupId BS.ByteString
  | SendGroupMessage GroupId MessageId Text
  | QuitGroup GroupId
  | SetGroupTopic GroupId Text
  | FoundGroup Founding Text Text
    -- ^ Group name and our name in it.
  | JoinPublicGroup GroupId Text Text
    -- ^ Our name in it and its password.
  | InviteToGroup GroupId ContactId
  | SendPrivate GroupId MessageId Tox.PeerId Text
  | ModerateMember GroupId Tox.PeerId MemberAction
  | SetGroupSettings GroupId Tox.GroupSettings
  | SendSync ContactId [BS.ByteString]
    -- ^ For a linked account's home.
  | FetchBlob ContactId BS.ByteString [BS.ByteString] (Maybe Text)
    -- ^ Get a blob from the home with these packets, unless we have it
    -- already (a file under its name, an avatar with the blobs).
  | ServeBlob ContactId BS.ByteString [BS.ByteString]
    -- ^ Send the home a blob it asked for, or these packets if we don't
    -- have it.
  | StoreBlob BS.ByteString
    -- ^ So the home can ask for it.
  | ShareFile ContactId FilePath Text Word64
    -- ^ Store a file as a blob, for the home to send to a linked account's
    -- friend.
  deriving (Eq, Show)

toxIdLength :: Int
toxIdLength = 76

-- | Tox ID from a public key and nospam in hex, with the checksum.
toxId :: Text -> Text -> Text
toxId key nospam = Text.toUpper (address <> hex (checksum (unhex address)))
  where address = key <> nospam

-- | 2 bytes: XOR of all the even bytes, and of all the odd ones.
checksum :: BS.ByteString -> BS.ByteString
checksum bytes = BS.pack [foldr xor 0 evens, foldr xor 0 odds]
  where
    indexed = zip [0 :: Int ..] (BS.unpack bytes)
    evens = [b | (i, b) <- indexed, even i]
    odds = [b | (i, b) <- indexed, odd i]

hex :: BS.ByteString -> Text
hex = Text.decodeUtf8 . Base16.encode

-- | Empty if it isn't hex.
unhex :: Text -> BS.ByteString
unhex = fromRight BS.empty . Base16.decode . Text.encodeUtf8

-- | Proxy as edited, or why it's wrong.
editedProxy :: Model -> Either Text (Maybe Tox.Proxy)
editedProxy model = case modelProxyKind model of
  Nothing -> Right Nothing
  Just kind
    | Text.null (modelProxyHost model) -> Left "Which host is the proxy on?"
    | Just port <- readMaybe (Text.unpack (modelProxyPort model)) :: Maybe Integer
    , port > 0 && port < 65536 ->
        Right (Just (Tox.Proxy kind (Text.unpack (modelProxyHost model)) (fromIntegral port)))
    | otherwise -> Left "The port is a number from 1 to 65535"

-- | Why the address isn't someone else's Tox ID, if it isn't. Nothing
-- while it's empty.
addressError :: Text -> Text -> Maybe Text
addressError ours address
  | Text.null address = Nothing
  | Text.length address /= toxIdLength || not (Text.all isHexDigit address) =
      Just $ "Must be " <> Text.pack (show toxIdLength) <> " hexadecimal characters"
  | toxId (Text.take 64 address) (Text.take 8 (Text.drop 64 address))
      /= Text.toUpper address =
      Just "Not a valid Tox ID, please check it for typos"
  | Text.toUpper (Text.take 64 address) == Text.toUpper (Text.take 64 ours) = Just "This is your own Tox ID"
  | otherwise = Nothing

-- | Why Tox wouldn't send this friend request message, if it wouldn't.
requestError :: Text -> Maybe Text
requestError request
  | Text.null (Text.strip request) = Just "The message can't be empty"
  | BS.length (Text.encodeUtf8 (Text.strip request)) > Tox.maxFriendRequestLength = Just "The message is too long"
  | otherwise = Nothing

-- | Why the nickname or status message is too long for Tox, if it is.
profileError :: Text -> Text -> Maybe Text
profileError nickname status
  | bytes nickname > Tox.maxNameLength = Just "The nickname is too long"
  | bytes status > Tox.maxStatusMessageLength = Just "The status message is too long"
  | otherwise = Nothing
  where bytes = BS.length . Text.encodeUtf8 . Text.strip

-- | Default friend request message.
requestMessage :: Profile -> Text
requestMessage p =
  "Hey, I'm " <> profileNickname p <> ", come chat with me on Tox!"

initial :: Model
initial = Model
  { modelScreen = Contacts
  , modelShown = False
  , modelDrawer = False
  , modelProfile = profile
  , modelConnection = Offline
  , modelContacts = Map.empty
  , modelRequests = Map.empty
  , modelFormer = Map.empty
  , modelDeclined = Map.empty
  , modelDrafts = Map.empty
  , modelGroups = Map.empty
  , modelInvites = Map.empty
  , modelGroupDrafts = Map.empty
  , modelPassword = ""
  , modelTopic = ""
  , modelFounding = PrivateGroup
  , modelGroupName = ""
  , modelChatId = ""
  , modelPrivateTo = Nothing
  , modelPeerLimit = ""
  , modelGroupPassword = ""
  , modelNickname = profileNickname profile
  , modelStatus = profileStatus profile
  , modelAddress = ""
  , modelRequest = requestMessage profile
  , modelAddError = Nothing
  , modelProxyKind = Nothing
  , modelProxyHost = ""
  , modelProxyPort = ""
  , modelTransfers = Map.empty
  , modelCall = Nothing
  , modelFullScreen = True
  , modelProfileId = ProfileId 0
  , modelProfiles = []
  , modelAway = False
  , modelUnseen = 0
  , modelJump = 0
  , modelSelected = Set.empty
  , modelStaged = Map.empty
  , modelReplies = Map.empty
  , modelAvatar = Nothing
  , modelAvatars = Map.empty
  , modelAccount = AccountSettings autoAccepted Set.empty
  , modelDevice = DeviceSettings True True True True Nothing
  , modelNotice = Nothing
  , modelLinked = Nothing
  , modelLink = ""
  , modelBackup = Set.empty
  }
  where
    profile = Profile
      { profileNickname = "Tox User"
      , profileStatus = "Toxing on Haskell"
      , profileAway = Tox.Online
      , profileToxId = ""
      }

update :: Event -> Model -> (Model, [Command])
update event model = case modelLinked model of
  Just l  -> linkedUpdate l event model
  Nothing -> ownUpdate event model

-- | For profiles whose Tox runs on this device.
ownUpdate :: Event -> Model -> (Model, [Command])
ownUpdate event model = case event of
  Open screen -> only $ opened screen model
    { modelScreen = screen, modelDrawer = False, modelNotice = Nothing, modelSelected = Set.empty
    , modelAway = False, modelUnseen = 0
    -- Keep the private recipient when going between a group's chat and its
    -- page.
    , modelPrivateTo = case (modelScreen model, screen) of
        (GroupDetails a, GroupChat b) | a == b -> modelPrivateTo model
        (GroupChat a, GroupDetails b) | a == b -> modelPrivateTo model
        _                                      -> Nothing }
  -- Only a linked account's home sends these.
  SyncReceived _ _ -> only model
  BlobArrived {} -> only model
  BlobMissing {} -> only model
  FileShared {} -> only model
  LinkEdited link -> only model { modelLink = link, modelNotice = Nothing }
  ToggleBackup pid -> only model
    { modelBackup = (if Set.member pid (modelBackup model) then Set.delete else Set.insert) pid (modelBackup model) }
  Back -> only $ fromMaybe model (back model { modelNotice = Nothing })
  Notify notice -> only model { modelNotice = Just notice }
  AvatarPicked png ->
    let hash = SHA256.hash png
    in ( pruned model { modelAvatar = Just hash, modelAvatars = Map.insert hash png (modelAvatars model) }
       , [SendAvatar cid (Just png) | (cid, c) <- Map.toList (modelContacts model), contactOnline c] )
  RemoveAvatar ->
    ( pruned model { modelAvatar = Nothing }
    , [SendAvatar cid Nothing | (cid, c) <- Map.toList (modelContacts model), contactOnline c] )
  FriendAvatar cid png -> only $ pruned $
    (adjusted cid (\c -> c { contactAvatar = SHA256.hash <$> png }))
      { modelAvatars = maybe id (\p -> Map.insert (SHA256.hash p) p) png (modelAvatars model) }
  SetAutoAccept size -> only model { modelAccount = (modelAccount model) { settingAutoAccept = size } }
  -- Read their messages again (as Tox carried them if the format is now
  -- off).
  ToggleFormat key ->
    let account = modelAccount model
        off = settingFormatsOff account
        account' = account { settingFormatsOff = (if Set.member key off then Set.delete key else Set.insert key) off }
        reread m = case messageRaw m of
          Just raw | not (messageMine m) -> m { messageText = readText (readWith (readable account') raw) }
          _ -> m
    in only model
         { modelAccount = account'
         , modelContacts = (\c -> c { contactMessages = map reread (contactMessages c) }) <$> modelContacts model
         , modelFormer = (\c -> c { contactMessages = map reread (contactMessages c) }) <$> modelFormer model }
  SetDevice device -> only model { modelDevice = device }
  ShareLocation latitude longitude -> only $ (staging (StagedPlace latitude longitude)) { modelNotice = Nothing }
  OpenDrawer -> only model { modelDrawer = True }
  DraftChanged draft -> only $ case modelScreen model of
    Chat cid      -> model { modelDrafts = Map.insert cid draft (modelDrafts model) }
    GroupChat gid -> model { modelGroupDrafts = Map.insert gid draft (modelGroupDrafts model) }
    _             -> model
  Send time -> case modelScreen model of
    GroupChat gid
      | Just g <- Map.lookup gid (modelGroups model)
      -- Never send a private message to everyone if the member is gone.
      , isJust (modelPrivateTo model)
      , isNothing (privateMember model g) -> only model { modelNotice = Just privateGone }
      | Just g <- Map.lookup gid (modelGroups model)
      , groupPhase g `elem` [Joining, InGroup]
      , Just draft <- Map.lookup gid (modelGroupDrafts model)
      , not (Text.null (Text.strip draft)) ->
          let text = Text.strip draft
              i = length (groupEntries g)
              (written, commands') = case privateMember model g of
                Just (n, m) -> (PrivateTo m Tox.MessageNormal text Pending, [SendPrivate gid i n text])
                Nothing -> (Said Nothing Tox.MessageNormal text Pending, [SendGroupMessage gid i text | groupPhase g == InGroup])
          in ( (withGroup gid g { groupEntries = groupEntries g ++ [GroupEntry time written] })
                 { modelGroupDrafts = Map.delete gid (modelGroupDrafts model)
                 , modelJump = modelJump model + 1
                 , modelUnseen = 0 }
             , commands' )
    -- Staged items first, then the text.
    Chat cid
      | Just contact <- Map.lookup cid (modelContacts model)
      , let staged = Map.findWithDefault [] cid (modelStaged model)
            draft = maybe "" Text.strip (Map.lookup cid (modelDrafts model))
      , not (null staged) || not (Text.null draft) ->
          let replied = Map.lookup cid (modelReplies model) >>= \i -> listToMaybe (drop i (contactMessages contact))
              message = maybe id (\m t -> quoted m <> "\n" <> t) replied draft
              picked = \case
                StagedFile path name size fileId -> ours name time (Just (Attachment size path 0 Waiting (Just fileId)))
                StagedPlace latitude longitude   -> ours (locationText latitude longitude) time Nothing
              sent = map picked staged ++ [ours message time Nothing | not (Text.null draft)]
          in
          ( (withContact cid contact { contactMessages = contactMessages contact ++ sent })
              { modelDrafts = Map.delete cid (modelDrafts model)
              , modelStaged = Map.delete cid (modelStaged model)
              , modelReplies = if Text.null draft then modelReplies model else Map.delete cid (modelReplies model)
              -- Scroll down to show what we sent.
              , modelJump = modelJump model + 1
              , modelUnseen = 0 }
          , [ case messageFile m of
                Just a  -> SendFile cid i (attachmentPath a) (messageText m) (attachmentSize a) (attachmentId a)
                Nothing -> SendMessage cid i (messageText m) 0
            | contactOnline contact, (i, m) <- zip [length (contactMessages contact) ..] sent ]
          )
    _ -> only model
  NicknameChanged nickname -> only model { modelNickname = nickname }
  StatusChanged status -> only model { modelStatus = status }
  ApplyProfile
    | Nothing <- profileError (modelNickname model) (modelStatus model) ->
        let applied = (modelProfile model)
              { profileNickname = Text.strip (modelNickname model)
              , profileStatus = Text.strip (modelStatus model)
              }
        in (model { modelProfile = applied }, [setProfile applied])
    | otherwise -> only model
  AwayChosen away ->
    let chosen = (modelProfile model) { profileAway = away } in (model { modelProfile = chosen }, [setProfile chosen])
  AddressChanged address -> only model { modelAddress = withoutScheme (Text.strip address), modelAddError = Nothing }
  RequestChanged request -> only model { modelRequest = request }
  AddFriend
    | not (Text.null address)
    , Nothing <- addressError (profileToxId (modelProfile model)) address
    , Nothing <- requestError (modelRequest model) ->
        let cid = ContactId (Text.toUpper (Text.take 64 address))
            request = (Text.toUpper address, Text.strip (modelRequest model))
            requesting c = c { contactRequest = Just request }
        in ( model
               { modelScreen = Chat cid
               , modelContacts = Map.alter (Just . requesting . fromMaybe (known cid)) cid (modelContacts model)
               , modelFormer = Map.delete cid (modelFormer model)
               , modelRequests = Map.delete cid (modelRequests model)
               , modelDeclined = Map.delete cid (modelDeclined model)
               , modelAddress = ""
               }
           , [uncurry RequestFriend request]
           )
    | otherwise -> only model
    where address = modelAddress model
  AddFailed address reason ->
    let cid = ContactId (Text.toUpper (Text.take 64 address))
        forget c
          | null (contactMessages c) = Nothing
          | otherwise = Just c { contactRequest = Nothing }
    in only model
         { modelScreen = AddContact
         , modelContacts = Map.update forget cid (modelContacts model)
         , modelAddress = address
         , modelAddError = Just reason
         }
  Accept cid
    | Map.member cid (modelRequests model) ->
        ( (withContact cid (known cid))
            { modelRequests = Map.delete cid (modelRequests model)
            , modelFormer = Map.delete cid (modelFormer model)
            , modelDeclined = Map.delete cid (modelDeclined model) }
        , [Befriend cid]
        )
    | otherwise -> only model
  Reject cid -> only model
    { modelRequests = Map.delete cid (modelRequests model)
    , modelDeclined = maybe id (Map.insert cid) (Map.lookup cid (modelRequests model)) (modelDeclined model)
    }
  Started address ->
    ( model { modelProfile = (modelProfile model) { profileToxId = address }
            -- Tox only knows these again once it hears from peers.
            , modelGroups = (\g -> g { groupPhase = if groupPhase g == InGroup then Joining else groupPhase g
                                     , groupMembers = Map.empty, groupSince = Nothing, groupRoles = Map.empty
                                     , groupSelfRole = Nothing, groupSettings = Nothing }) <$> modelGroups model }
    , setProfile (modelProfile model)
        : [ maybe (Befriend cid) (uncurry RequestFriend) (contactRequest c)
          | (cid, c) <- Map.toList (modelContacts model) ]
        -- After the friends (they may help find the peers).
        ++ [ RestoreGroup (groupKind g) gid saved
           | (gid, g) <- Map.toList (modelGroups model), groupPhase g `elem` [Joining, InGroup]
           , Just saved <- [groupSaved g] ]
    )
  Connected connection -> only model { modelConnection = connection }
  FriendOnline cid online -> case Map.lookup cid (modelContacts model) of
    Just contact ->
      -- Tox ends a friend's transfers when they go offline. We offer ours
      -- again when they're back.
      let (ended, going) = Map.partitionWithKey (\(c, _) _ -> c == cid && not online) (modelTransfers model)
          cut = foldr (\i -> adjustMessage cid i interrupted) model { modelTransfers = going } (Map.elems ended)
          -- Tox also says online when they move between TCP and UDP.
          returned = online && not (contactOnline contact)
          met c = c { contactOnline = online, contactRequest = if online then Nothing else contactRequest c
                    , contactStatus = if online then contactStatus c else Tox.Online }
          -- Done once the friend is back to get our answer.
          spent (c, _) invite = c /= cid || not returned || isNothing (inviteAnswered invite)
      in ( cut { modelContacts = Map.adjust met cid (modelContacts cut)
               , modelInvites = Map.filterWithKey spent (modelInvites cut) }
         , [ SendMessage cid i (messageText m) (messageParts m)
           | returned
           , (i, m) <- zip [0 ..] (contactMessages contact)
           , messageMine m, messageDelivery m /= Delivered, Nothing <- [messageFile m] ]
           ++
           [ SendAvatar cid (Just png) | returned, Just png <- [(`Map.lookup` modelAvatars model) =<< modelAvatar model] ]
           ++
           [ SendFile cid i (attachmentPath a) (messageText m) (attachmentSize a) (attachmentId a)
           | returned
           , (i, m) <- zip [0 ..] (contactMessages contact)
           , messageMine m, Just a <- [messageFile m], attachmentState a == Waiting ]
           -- Invites we accepted while the friend was away (Tox can only
           -- answer them through the friend).
           ++
           [ joinCommand cid gid invite password
           | returned
           , ((c, gid), invite) <- Map.toList (modelInvites model), c == cid
           , Just password <- [inviteAnswered invite] ]
         )
    Nothing -> only model
  FriendNamed cid name -> only $ adjusted cid (\c -> c { contactName = Just name })
  FriendStatusMessage cid status -> only $ adjusted cid (\c -> c { contactStatusMessage = status })
  FriendStatus cid status -> only $ adjusted cid (\c -> c { contactStatus = status })
  DeleteContact cid keep -> case Map.lookup cid (modelContacts model) of
    Just contact ->
      let calling = [c | Just c <- [modelCall model], callContact c == cid]
      in ( model
             { modelScreen = Contacts
             , modelContacts = Map.delete cid (modelContacts model)
             , modelFormer = if keep
                 then Map.insert cid contact { contactOnline = False, contactUnread = 0, contactRequest = Nothing }
                        (modelFormer model)
                 else modelFormer model
             , modelDrafts = Map.delete cid (modelDrafts model)
             , modelStaged = Map.delete cid (modelStaged model)
             , modelInvites = Map.filterWithKey (\(c, _) _ -> c /= cid) (modelInvites model)
             , modelTransfers = Map.filterWithKey (\(c, _) _ -> c /= cid) (modelTransfers model)
             , modelCall = if null calling then modelCall model else Nothing
             }
         , [HangUpCall cid | not (null calling)] ++ [Unfriend cid]
           ++ [ForgetFile path | StagedFile path _ _ _ <- Map.findWithDefault [] cid (modelStaged model)] )
    Nothing -> only model
  MuteChat cid until' -> only $ adjusted cid (\c -> c { contactMute = Just (maybe MutedAlways MutedUntil until') })
  UnmuteChat cid -> only $ adjusted cid (\c -> c { contactMute = Nothing })
  Received cid time kind bytes
    -- Some clients resend messages. Drop one with the key of an earlier
    -- one.
    | Just key <- readRepeat got
    , Just c <- Map.lookup cid (modelContacts model)
    , key `elem` [ k | m <- contactMessages c, not (messageMine m), Just raw <- [messageRaw m]
                     , Just k <- [readRepeat (readWith (readable (modelAccount model)) raw)] ] -> only model
    | otherwise -> only $ (adjusted cid $ \c -> c
        { contactMessages = contactMessages c ++ [Message False (readText got) time Delivered Nothing Nothing 0 Nothing kind (Just bytes)]
        , contactUnread = contactUnread c + (if reading cid then 0 else 1)
        }) { modelUnseen = modelUnseen model + (if modelScreen model == Chat cid && modelAway model then 1 else 0) }
    where got = readWith (readable (modelAccount model)) bytes
  Delivering cid i delivery -> only $ adjusted cid $ \c -> c
    { contactMessages =
        [ if j == i && messageDelivery m /= Delivered then m { messageDelivery = delivery } else m
        | (j, m) <- zip [0 ..] (contactMessages c) ]
    }
  Confirmed cid i n time -> only $ adjustMessage cid i (\m ->
    let confirmed = max n (messageParts m)
        whole = confirmed >= length (parts (messageText m))
    in m { messageParts = confirmed
         , messageDelivery = if whole then Delivered else messageDelivery m
         , messageDelivered = if whole && isNothing (messageDelivered m) then Just time else messageDelivered m
         }) model
  Select i -> only model
    { modelSelected = (if Set.member i (modelSelected model) then Set.delete else Set.insert) i (modelSelected model) }
  Unselect -> only model { modelSelected = Set.empty }
  ScrolledAway away -> only model { modelAway = away, modelUnseen = if away then modelUnseen model else 0 }
  JumpToEnd -> only model { modelJump = modelJump model + 1, modelUnseen = 0 }
  Reply i -> only $ case modelScreen model of
    Chat cid | Just m <- messageOf cid i, isNothing (messageCall m) ->
      model { modelReplies = Map.insert cid i (modelReplies model), modelSelected = Set.empty }
    _ -> model
  CancelReply -> only $ case modelScreen model of
    Chat cid -> model { modelReplies = Map.delete cid (modelReplies model) }
    _        -> model
  ForwardTo target time -> case (modelScreen model, Map.lookup target (modelContacts model)) of
    (Forward source is, Just contact) ->
      let start = length (contactMessages contact)
          sent = [ m | i <- is, Just m <- [messageOf source i], forwardable m ]
          copies = zipWith (\j m -> (j, copy m)) [start ..] sent
          copy m = ours (messageText m) time (forwardedFile <$> messageFile m)
          forwardedFile a = a { attachmentState = Waiting, attachmentDone = 0, attachmentId = Nothing }
      in ( (withContact target contact { contactMessages = contactMessages contact ++ map snd copies })
             { modelScreen = Chat target, modelSelected = Set.empty }
         , [ case messageFile m of
               Nothing -> SendMessage target j (messageText m) 0
               Just a  -> SendFile target j (attachmentPath a) (messageText m) (attachmentSize a) (attachmentId a)
           | contactOnline contact, (j, m) <- copies ] )
    _ -> only model
  Requested cid message
    | Map.member cid (modelContacts model) -> (model, [Befriend cid])
    | Map.lookup cid (modelDeclined model) == Just message -> only model
    | otherwise -> only model { modelRequests = Map.insert cid message (modelRequests model) }
  Attach path name size fileId -> case modelScreen model of
    Chat _ -> only (staging (StagedFile path name size fileId))
    -- The user left the chat while picking, so drop the copy.
    _      -> (model, [ForgetFile path])
  Unstage cid k ->
    let staged = Map.findWithDefault [] cid (modelStaged model)
    in ( model { modelStaged = Map.filter (not . null) (Map.insert cid (take k staged ++ drop (k + 1) staged) (modelStaged model)) }
       , [ForgetFile path | StagedFile path _ _ _ <- take 1 (drop k staged)] )
  FileStarted cid i ref -> only model { modelTransfers = Map.insert (cid, ref) i (modelTransfers model) }
  FileOffered cid ref time name size path fileId -> case Map.lookup cid (modelContacts model) of
    -- Resume a file of theirs that was cut off, in the same message.
    Just contact
      | (i, a) : _ <- [ (i, a) | (i, m) <- zip [0 ..] (contactMessages contact), not (messageMine m)
                               , Just a <- [messageFile m], attachmentId a == Just fileId
                               , attachmentSize a == size, attachmentState a `elem` [Waiting, Interrupted] ] ->
          let taken = attachmentState a == Interrupted || size <= settingAutoAccept (modelAccount model)
          in ( (adjustFile cid i (\b -> b { attachmentState = if taken then Moving else Waiting }) model)
                 { modelTransfers = Map.insert (cid, ref) i (modelTransfers model) }
             , [AcceptFile cid ref (attachmentPath a) | taken] )
    Just contact ->
      let i = length (contactMessages contact)
          taken = size <= settingAutoAccept (modelAccount model)
          file = Attachment size path 0 (if taken then Moving else Waiting) (Just fileId)
      in ( (withContact cid contact
             { contactMessages = contactMessages contact ++ [Message False name time Delivered (Just file) Nothing 0 Nothing Tox.MessageNormal Nothing]
             , contactUnread = contactUnread contact + (if reading cid then 0 else 1)
             }) { modelTransfers = Map.insert (cid, ref) i (modelTransfers model) }
         , [AcceptFile cid ref path | taken]
         )
    Nothing -> (model, [CancelFile cid ref])
  Download cid i
    | Just ref <- liveRef cid i ->
        ( adjustFile cid i (\a -> a { attachmentState = Moving }) model
        , [AcceptFile cid ref (attachmentPath a) | Just a <- [fileOf cid i]] )
    | otherwise -> only model
  Cancel cid i ->
    ( adjustFile cid i (\a -> a { attachmentState = Cancelled })
        model { modelTransfers = maybe id (\ref -> Map.delete (cid, ref)) (liveRef cid i) (modelTransfers model) }
    , [CancelFile cid ref | Just ref <- [liveRef cid i]] )
  FileMoved cid ref done -> only $ case Map.lookup (cid, ref) (modelTransfers model) of
    Just i -> adjustFile cid i (\a -> a { attachmentDone = done, attachmentState = Moving }) model
    Nothing -> model
  FileEnded cid ref whole -> only $ case Map.lookup (cid, ref) (modelTransfers model) of
    Just i -> adjustFile cid i
      (\a -> if whole then a { attachmentDone = attachmentSize a, attachmentState = Complete }
             else a { attachmentState = Cancelled })
      model { modelTransfers = Map.delete (cid, ref) (modelTransfers model) }
    Nothing -> model
  StartCall time camera -> case modelScreen model of
    Chat cid
      | Nothing <- modelCall model
      , Just contact <- Map.lookup cid (modelContacts model)
      , contactOnline contact ->
          (begun (newCall cid Calling time camera) { callCamera = camera }, [CallFriend cid camera])
    _ -> only model
  AnswerCall time camera -> case modelCall model of
    Just c | callPhase c == Ringing ->
      ( model { modelCall = Just c { callPhase = Talking time, callCamera = camera } }
      , [AnswerFriend (callContact c) camera] )
    _ -> only model
  HangUp time -> case modelCall model of
    Just c  -> ((recorded time False c) { modelCall = Nothing }, [HangUpCall (callContact c)])
    Nothing -> only model
  -- Theirs counts as missed, and ours isn't placed.
  CallElsewhere time -> case modelCall model of
    Just c | callPhase c == Ringing -> ((recorded time True c) { modelCall = Nothing }, [HangUpCall (callContact c)])
    Just c -> ( (recorded time False c) { modelCall = Nothing, modelNotice = Just "Another profile has a call" }
              , [HangUpCall (callContact c)] )
    Nothing -> only model
  ToggleMute -> only model { modelCall = (\c -> c { callMuted = not (callMuted c) }) <$> modelCall model }
  -- Tox only lets us change this once the call is going.
  ToggleCamera -> case modelCall model of
    Just c | Talking _ <- callPhase c ->
      let camera = not (callCamera c)
      in (model { modelCall = Just c { callCamera = camera } }, [CameraCall (callContact c) camera])
    _ -> only model
  HideCall -> only $ fromMaybe model (back model)
  ShowCall -> only model { modelCall = (\c -> c { callHidden = False }) <$> modelCall model }
  RoutesChanged route routes -> only model { modelCall = (\c -> c { callRoute = route, callRoutes = routes }) <$> modelCall model }
  FlipCamera -> only model { modelCall = (\c -> c { callBackCamera = not (callBackCamera c) }) <$> modelCall model }
  -- Their call came in before ours went out, or it's the call again after
  -- a glare. Either way, answer it.
  CallInvited cid time video -> case modelCall model of
    Just c | callContact c == cid, callPhase c == Calling, callGlare c /= Settling ->
      ( model { modelCall = Just c { callPhase = Talking time, callPeerVideo = video, callGlare = Settling } }
      , [AnswerFriend cid (callCamera c)] )
    Nothing | Map.member cid (modelContacts model) ->
      only (begun (newCall cid Ringing time video) { callPeerVideo = video })
    _ -> (recorded time True (newCall cid Ringing time video), [HangUpCall cid])
  CallPeer cid time video -> only model
    { modelCall = case modelCall model of
        Just c | callContact c == cid -> Just c
          { callPeerVideo = video
          , callPhase = if callPhase c == Calling then Talking time else callPhase c
          }
        other -> other
    }
  CallEnded cid time -> only $ case modelCall model of
    Just c | callContact c == cid -> (recorded time (callPhase c == Ringing) c) { modelCall = Nothing }
    _ -> model
  CallGlared cid time -> case modelCall model of
    Just c | callContact c == cid, callPhase c == Calling, callGlare c == Clear ->
      only model { modelCall = Just c { callGlare = Glared time } }
    _ -> update (CallEnded cid time) model
  Tick time -> case modelCall model of
    Just c
      | Glared since <- callGlare c
      , let again = Text.toUpper (Text.take 64 (profileToxId (modelProfile model))) > Text.toUpper key
            ContactId key = callContact c
      , diffUTCTime time since >= (if again then glareDelay else glareWait) ->
          if again
            then (model { modelCall = Just c { callGlare = Settling } }, [CallFriend (callContact c) (callCamera c)])
            else only (recorded time False c) { modelCall = Nothing }
    Just c
      | callPhase c `elem` [Calling, Ringing]
      , diffUTCTime time (callStarted c) >= ringTimeout ->
          ((recorded time (callPhase c == Ringing) c) { modelCall = Nothing }, [HangUpCall (callContact c)])
    _ -> only model
  FullScreenChecked allowed -> only model { modelFullScreen = allowed }
  -- Any notice on screen was about the profiles before.
  ProfilesChanged accounts -> only model { modelProfiles = accounts, modelNotice = Nothing }
  ProxyKindChosen kind -> only model { modelProxyKind = kind, modelNotice = Nothing }
  ProxyHostChanged host -> only model { modelProxyHost = Text.strip host, modelNotice = Nothing }
  ProxyPortChanged port -> only model { modelProxyPort = Text.strip port, modelNotice = Nothing }
  ApplyProxy -> only $ case editedProxy model of
    Left why -> model { modelNotice = Just why }
    Right proxy -> model { modelDevice = (modelDevice model) { settingProxy = proxy }, modelScreen = SettingsScreen }
  SendPictures cid way -> only (adjusted cid (\c -> c { contactPictures = way }))
  Shown shown -> only $ case modelScreen model of
    Chat cid | shown -> (adjusted cid (\c -> c { contactUnread = 0 })) { modelShown = True }
    GroupChat gid | shown -> (adjustedGroup gid (\g -> g { groupUnread = 0 })) { modelShown = True }
    _ -> model { modelShown = shown }
  Invited cid gid kind name bytes
    | Map.member cid (modelContacts model)
    , maybe True ((`notElem` [Joining, InGroup]) . groupPhase) (Map.lookup gid (modelGroups model)) ->
        only model { modelInvites = Map.insert (cid, gid) (Invite kind name bytes Nothing) (modelInvites model) }
    | otherwise -> only model
  PasswordChanged password -> only model { modelPassword = password }
  AnswerInvite cid gid join -> case Map.lookup (cid, gid) (modelInvites model) of
    Nothing -> only model
    Just invite
      | not join -> only model { modelInvites = Map.delete (cid, gid) (modelInvites model), modelScreen = Contacts }
      | otherwise ->
          let password = modelPassword model
              online = maybe False contactOnline (Map.lookup cid (modelContacts model))
              -- Keep the chat of a group we left before.
              before = Map.lookup gid (modelGroups model)
              joining = (fromMaybe (newGroup (inviteName invite) (inviteKind invite) Joining) before)
                { groupPhase = Joining, groupMembers = Map.empty, groupSaved = Nothing }
          in ( model
                 { modelInvites = if online then Map.delete (cid, gid) (modelInvites model)
                                  else Map.insert (cid, gid) invite { inviteAnswered = Just password } (modelInvites model)
                 , modelGroups = Map.insert gid joining (modelGroups model)
                 , modelScreen = GroupChat gid
                 , modelPassword = "" }
             , [joinCommand cid gid invite password | online] )
  GroupConnected gid time -> case Map.lookup gid (modelGroups model) of
    Just g | groupPhase g == Joining ->
      ( withGroup gid g { groupPhase = InGroup, groupSince = Just time }
      , [SetGroupStatus gid away | let away = profileAway (modelProfile model), away /= Tox.Online]
        -- Messages written while we weren't in it.
        ++ [ SendGroupMessage gid i text
           | (i, GroupEntry _ (Said Nothing _ text Pending)) <- zip [0 ..] (groupEntries g) ] )
    _ -> only model
  GroupRefused gid why -> case Map.lookup gid (modelGroups model) of
    Just g | groupPhase g `elem` [Joining, InGroup] ->
      -- Quit, or Tox keeps the group around for nothing.
      (withGroup gid g { groupPhase = Refused why, groupMembers = Map.empty, groupSaved = Nothing }, [QuitGroup gid])
    _ -> only model
  MemberJoined gid time n member -> only $ adjustedGroup gid $ \g -> g
    { groupMembers = Map.insert n member (groupMembers g)
    , groupEntries = groupEntries g ++ [GroupEntry time (Arrived member) | arrived g time] }
  MemberLeft gid time n how -> only $ adjustedGroup gid $ \g -> g
    { groupMembers = Map.delete n (groupMembers g)
    , groupStatuses = Map.delete n (groupStatuses g)
    , groupEntries = groupEntries g
        ++ [ GroupEntry time (Departed member)
           | groupPhase g == InGroup, how `notElem` [Tox.ExitSelfDisconnected, Tox.ExitKicked]
           , Just member <- [Map.lookup n (groupMembers g)] ] }
  MembersListed gid time listed -> case Map.lookup gid (modelGroups model) of
    Just g ->
      let keys = map memberKey . Map.elems
          now = Map.fromList listed
          came = [m | m <- Map.elems now, memberKey m `notElem` keys (groupMembers g)]
          went = [m | m <- Map.elems (groupMembers g), memberKey m `notElem` keys now]
      in ( withGroup gid g
             { groupMembers = now
             , groupEntries = groupEntries g
                 -- Silent for the first list after getting in (they were
                 -- already there).
                 ++ [ GroupEntry time e
                    | arrived g time, not (Map.null (groupMembers g)), e <- map Arrived came ++ map Departed went ] }
         -- Messages that went to nobody.
         , [ SendGroupMessage gid i text
           | groupPhase g == InGroup, not (Map.null now)
           , (i, GroupEntry _ (Said Nothing _ text Pending)) <- zip [0 ..] (groupEntries g) ] )
    Nothing -> only model
  MemberNamed gid n name -> only $ adjustedGroup gid $ \g -> g
    { groupMembers = Map.adjust (\m -> m { memberName = name }) n (groupMembers g) }
  GroupReceived gid time n kind text -> only $ (adjustedGroup gid $ \g -> g
    { groupEntries = groupEntries g ++ [GroupEntry time (Said (Just (memberOf g n)) kind text Delivered)]
    , groupUnread = groupUnread g + (if modelShown model && modelScreen model == GroupChat gid then 0 else 1) })
    { modelUnseen = modelUnseen model + (if modelScreen model == GroupChat gid && modelAway model then 1 else 0) }
  GroupSent gid i -> only $ adjustedGroup gid $ \g -> g
    { groupEntries = [ case e of
                         GroupEntry t (Said Nothing kind text Pending) | j == i -> GroupEntry t (Said Nothing kind text Sent)
                         GroupEntry t (PrivateTo who kind text Pending) | j == i -> GroupEntry t (PrivateTo who kind text Sent)
                         _ -> e
                     | (j, e) <- zip [0 ..] (groupEntries g) ] }
  PrivateReceived gid time n kind text -> only $ (adjustedGroup gid $ \g -> g
    { groupEntries = groupEntries g ++ [GroupEntry time (PrivateFrom (memberOf g n) kind text)]
    , groupUnread = groupUnread g + (if modelShown model && modelScreen model == GroupChat gid then 0 else 1) })
    { modelUnseen = modelUnseen model + (if modelScreen model == GroupChat gid && modelAway model then 1 else 0) }
  PrivatelyTo to -> only model { modelPrivateTo = to }
  RolesKnown gid self theirs -> only $ adjustedGroup gid $ \g -> g
    { groupSelfRole = self, groupRoles = Map.fromList theirs }
  MemberStatus gid n status -> only $ adjustedGroup gid $ \g -> g
    { groupStatuses = if status == Tox.Online then Map.delete n (groupStatuses g) else Map.insert n status (groupStatuses g) }
  GroupModerated gid time setter target moderation -> case Map.lookup gid (modelGroups model) of
    Just g ->
      let notice = GroupEntry time (Moderated (memberOf g <$> setter) (memberOf g <$> target) moderation)
          kicked = isNothing target && moderation == Tox.ModKick
      in if kicked
           -- Quit, or Tox keeps the group around for nothing.
           then ( withGroup gid g { groupPhase = Kicked, groupEntries = groupEntries g ++ [notice]
                                  , groupMembers = Map.empty, groupSaved = Nothing }
                , [QuitGroup gid] )
           else only (withGroup gid g { groupEntries = groupEntries g ++ [notice] })
    Nothing -> only model
  SettingsKnown gid settings -> only $ adjustedGroup gid (\g -> g { groupSettings = Just settings })
  Moderate gid n permission -> (model, [ModerateMember gid n permission])
  ChangeSettings gid settings -> (model, [SetGroupSettings gid settings])
  PeerLimitEdited limit -> only model { modelPeerLimit = limit }
  GroupPasswordEdited password -> only model { modelGroupPassword = password }
  ApplyGroupSettings -> case modelScreen model of
    GroupSettingsScreen gid
      | Just g <- Map.lookup gid (modelGroups model), Just settings <- groupSettings g ->
          case readMaybe (Text.unpack (Text.strip (modelPeerLimit model))) :: Maybe Integer of
            Just limit | limit > 0 && limit < 65536
                       , BS.length (Text.encodeUtf8 (modelGroupPassword model)) <= Tox.maxPasswordSize ->
              ( model { modelScreen = GroupDetails gid }
              , [SetGroupSettings gid settings { Tox.groupPeerLimit = fromIntegral limit
                                               , Tox.groupPassword = Text.encodeUtf8 (modelGroupPassword model) }] )
            _ -> only model { modelNotice = Just "The limit is a number from 1 to 65535, the password at most 32 bytes" }
    _ -> only model
  ChooseRelayBot gid bot -> only $ adjustedGroup gid (\g -> g { groupRelayBot = bot })
  ToggleMentions gid -> only $ adjustedGroup gid (\g -> g { groupMentions = not (groupMentions g) })
  TopicChanged gid time setter topic -> only $ adjustedGroup gid $ \g -> g
    { groupTopic = topic
    -- Silent for the topic Tox gets while joining.
    , groupEntries = groupEntries g
        ++ [ GroupEntry time (TopicSet (Just (maybe (Member "" "") (memberOf g) setter)) topic)
           | arrived g time, topic /= groupTopic g ] }
  TopicSetByUs gid time topic -> only $ adjustedGroup gid $ \g -> g
    { groupTopic = topic, groupEntries = groupEntries g ++ [GroupEntry time (TopicSet Nothing topic)] }
  TopicAllowed gid allowed -> only $ adjustedGroup gid (\g -> g { groupMayTopic = allowed })
  TopicEdited topic -> only model { modelTopic = topic }
  FoundingChosen founding -> only model { modelFounding = founding }
  GroupNameEdited name -> only model { modelGroupName = name }
  Found
    | Nothing <- foundingError (modelFounding model) (modelGroupName model) ->
        ( model { modelScreen = Contacts }
        , [FoundGroup (modelFounding model) (Text.strip (modelGroupName model)) (groupNick (modelProfile model))] )
    | otherwise -> only model { modelNotice = foundingError (modelFounding model) (modelGroupName model) }
  GroupCreated gid kind name time ->
    only (withGroup gid (newGroup name kind InGroup) { groupSince = Just time, groupSelfRole = Just Tox.Founder })
      { modelScreen = GroupChat gid }
  ChatIdEdited chatId -> only model { modelChatId = Text.toUpper (Text.strip chatId) }
  JoinPublic
    | not (Text.null chatId), Nothing <- chatIdError chatId ->
        let gid = GroupId chatId
            joining = maybe True ((`notElem` [Joining, InGroup]) . groupPhase) (Map.lookup gid (modelGroups model))
            fresh = newGroup "" NgcGroup Joining
        in ( model { modelGroups = if joining
                       then Map.insert gid (maybe fresh (\g -> g { groupPhase = Joining, groupSaved = Nothing })
                                              (Map.lookup gid (modelGroups model))) (modelGroups model)
                       else modelGroups model
                   , modelScreen = GroupChat gid, modelPassword = "" }
           , [JoinPublicGroup gid (groupNick (modelProfile model)) (modelPassword model) | joining] )
    | otherwise -> only model
    where chatId = modelChatId model
  InviteFriend gid cid -> (model, [InviteToGroup gid cid])
  ApplyTopic -> case modelScreen model of
    TopicScreen gid
      | Just g <- Map.lookup gid (modelGroups model), groupPhase g == InGroup, groupMayTopic g ->
          (model { modelScreen = GroupDetails gid }, [SetGroupTopic gid (Text.strip (modelTopic model))])
    _ -> only model
  GroupSaved gid saved -> only $ adjustedGroup gid $ \g ->
    if groupPhase g `elem` [Joining, InGroup] then g { groupSaved = Just saved } else g
  GroupNamed gid name -> only $ adjustedGroup gid $ \g -> g { groupName = name }
  LeaveGroup gid -> case Map.lookup gid (modelGroups model) of
    Just g | groupPhase g `elem` [Joining, InGroup] ->
      (withGroup gid g { groupPhase = Gone, groupMembers = Map.empty, groupSaved = Nothing }, [QuitGroup gid])
    _ -> only model
  DeleteGroup gid -> case Map.lookup gid (modelGroups model) of
    Just g ->
      ( model { modelGroups = Map.delete gid (modelGroups model)
              , modelGroupDrafts = Map.delete gid (modelGroupDrafts model)
              , modelScreen = Contacts }
      , [QuitGroup gid | groupPhase g `elem` [Joining, InGroup]] )
    Nothing -> only model
  MuteGroup gid until' -> only $ adjustedGroup gid (\g -> g { groupMute = Just (maybe MutedAlways MutedUntil until') })
  UnmuteGroup gid -> only $ adjustedGroup gid (\g -> g { groupMute = Nothing })
  where
    only m = (m, [])
    reading cid = modelShown model && modelScreen model == Chat cid
    newContact = Contact Nothing False [] 0 Nothing "" Tox.Online Nothing Nothing Nothing
    -- Drop avatars nobody uses any more.
    pruned m = m
      { modelAvatars = Map.restrictKeys (modelAvatars m) $ Set.fromList $
          maybe id (:) (modelAvatar m)
            [ h | c <- Map.elems (modelContacts m) ++ Map.elems (modelFormer m), Just h <- [contactAvatar c] ] }
    ours text time file = Message True text time Pending file Nothing 0 Nothing Tox.MessageNormal Nothing
    messageOf cid i = listToMaybe . drop i . contactMessages =<< Map.lookup cid (modelContacts model)
    -- Bring back a contact deleted with its chat kept.
    known cid = fromMaybe newContact (Map.lookup cid (modelFormer model))
    -- QR codes and links have it.
    withoutScheme a
      | Text.toLower (Text.take 4 a) == "tox:" = Text.drop 4 a
      | otherwise = a
    entry c record = Message (callMine c) "" (callStarted c) Delivered Nothing (Just record) 0 Nothing Tox.MessageNormal Nothing
    begun c = (adjusted (callContact c) $ \contact -> contact
        { contactMessages = contactMessages contact ++ [entry c (CallRecord (callVideo c) Nothing False)] })
      { modelCall = Just c { callEntry = length . contactMessages <$> Map.lookup (callContact c) (modelContacts model) } }
    -- Missed calls count as unread.
    recorded time missed c = adjusted (callContact c) $ \contact -> contact
      { contactMessages = case callEntry c of
          Just i  -> [ if j == i then entry c record else m | (j, m) <- zip [0 ..] (contactMessages contact) ]
          Nothing -> contactMessages contact ++ [entry c record]
      , contactUnread = contactUnread contact + (if missed && not (reading (callContact c)) then 1 else 0)
      }
      where
        record = CallRecord (callVideo c) talked missed
        talked = case callPhase c of
          Talking since -> Just (diffUTCTime time since)
          _             -> Nothing
    withContact cid contact = model { modelContacts = Map.insert cid contact (modelContacts model) }
    staging item = case modelScreen model of
      Chat cid -> model { modelStaged = Map.insertWith (flip (++)) cid [item] (modelStaged model) }
      _        -> model
    withGroup gid g = model { modelGroups = Map.insert gid g (modelGroups model) }
    adjustedGroup gid f = model { modelGroups = Map.adjust f gid (modelGroups model) }
    joinCommand cid gid invite password = case inviteKind invite of
      NgcGroup -> JoinGroup cid gid (inviteData invite) (groupNick (modelProfile model)) password
      _        -> JoinConference cid gid (inviteData invite)
    -- Joined after Tox met the peers already there.
    arrived g time = groupPhase g == InGroup && maybe False ((>= meeting) . diffUTCTime time) (groupSince g)
    memberOf g n = Map.findWithDefault (Member "" "") n (groupMembers g)
    adjusted cid f = model { modelContacts = Map.adjust f cid (modelContacts model) }
    fileOf cid i = messageFile =<< listToMaybe (drop i (maybe [] contactMessages (Map.lookup cid (modelContacts model))))
    liveRef cid i = case [ref | ((c, ref), j) <- Map.toList (modelTransfers model), c == cid, j == i] of
      ref : _ -> Just ref
      []      -> Nothing
    setProfile = SetProfile

-- Linked accounts

-- | Why the pairing link is wrong, if it is.
linkError :: Text -> Maybe Text
linkError link
  | Text.null (Text.strip link) = Just "Paste the link the other device shows"
  | isNothing (Pairing.parseLink link) = Just "That isn't a pairing link"
  | otherwise = Nothing

-- | For linked profiles. What the user does becomes events for the home,
-- and the chats are derived from the account's events. Our own Tox only
-- has the home as a friend.
linkedUpdate :: Linked -> Event -> Model -> (Model, [Command])
linkedUpdate l event model = case event of
  Started _ ->
    ( linkedView l model
    , [maybe (Befriend home) (RequestFriend (linkedHomeAddress l)) (Linked.linkedPairing l)] )
  FriendOnline cid online
    | cid == home && online -> (model, [SendSync home (Linked.homeOnline l)])
    | cid == home -> withLinked (Linked.homeOffline l) model []
  SyncReceived cid packet
    | cid == home ->
        let (replies, asked, l') = Linked.receivePacket packet l
            (m, commands) = withLinked l' model replies
        in (m, commands ++ [ServeBlob home blob (Linked.noBlob (Sync.BlobId blob)) | Sync.BlobId blob <- asked])
  BlobMissing blob -> withLinked (Linked.blobMissing (Sync.BlobId blob) l) model []
  BlobArrived blob path small ->
    let here = Linked.blobHere (Sync.BlobId blob) path l
        avatars = case small of
          Just png | blob `elem` avatarBlobs l -> Map.insert blob png (modelAvatars model)
          _                                    -> modelAvatars model
    in withLinked here model { modelAvatars = avatars } []
  -- The home accepts theirs, then we fetch it from the home.
  Download cid i | Just (fid, file) <- linkedFileAt l cid i -> case linkedEnd l fid of
    Just (True, Just blob) ->
      let (l', commands) = fetchFile l blob file in (fst (withLinked l' model []), commands)
    Nothing | Map.notMember fid (linkedAnswers l) ->
      let (l', packets) = authored (friendGraphOf cid) now (Sync.FileAnswered fid True) l in withLinked l' model packets
    _ -> only model
  Cancel cid i | Just (fid, _) <- linkedFileAt l cid i, isNothing (linkedEnd l fid) ->
    let (l', packets) = authored (friendGraphOf cid) now (Sync.FileAnswered fid False) l in withLinked l' model packets
  -- Staged items first, then the text. Files go once stored as blobs.
  Send time -> case modelScreen model of
    Chat cid
      | let staged = Map.findWithDefault [] cid (modelStaged model)
            draft = maybe "" Text.strip (Map.lookup cid (modelDrafts model))
      , not (null staged) || not (Text.null draft) ->
          let replied = Map.lookup cid (modelReplies model) >>= \i ->
                listToMaybe . drop i . contactMessages =<< Map.lookup cid (modelContacts model)
              text = maybe id (\m t -> quoted m <> "\n" <> t) replied draft
              g = friendGraphOf cid
              said = [locationText latitude longitude | StagedPlace latitude longitude <- staged]
                ++ [text | not (Text.null draft)]
              (l', packets) = foldl (\(l0, ps) t ->
                                       let (l1, p) = authored g time (Sync.Send (senderIn g) (Text.encodeUtf8 t) Sync.Normal) l0
                                       in (l1, ps ++ p)) (l, []) said
              (sending, commands) = withLinked l' model
                { modelDrafts = Map.delete cid (modelDrafts model)
                , modelStaged = Map.delete cid (modelStaged model)
                , modelReplies = if Text.null draft then modelReplies model else Map.delete cid (modelReplies model)
                , modelJump = modelJump model + 1, modelUnseen = 0 } packets
          in (sending, [ShareFile cid path name size | StagedFile path name size _ <- staged] ++ commands)
    GroupChat gid
      | Just c <- chatOf gid
      , Just draft <- Text.strip <$> Map.lookup gid (modelGroupDrafts model), not (Text.null draft) ->
          let g = Sync.chatGraph c
              bytes = Text.encodeUtf8 draft
              member = keyOf . memberKey . snd =<< privateMember model =<< Map.lookup gid (modelGroups model)
              send content = let (l', packets) = authored g time content l in withLinked l' model
                { modelGroupDrafts = Map.delete gid (modelGroupDrafts model)
                , modelJump = modelJump model + 1, modelUnseen = 0 } packets
          in case modelPrivateTo model of
               Nothing -> send (Sync.Send (senderIn g) bytes Sync.Normal)
               Just _ -> maybe (only model { modelNotice = Just privateGone })
                 (\pk -> send (Sync.SendPrivately pk (senderIn g) bytes Sync.Normal)) member
    _ -> only model
  AddFriend
    | Nothing <- addressError (profileToxId (modelProfile model)) address
    , Nothing <- requestError (modelRequest model)
    , Just pk <- keyOf (Text.take 64 address) ->
        let nospam = nospamOf (Text.take 8 (Text.drop 64 address))
            (l', packets) = authored account now
              (Sync.WantFriend pk (Just (Text.strip (modelRequest model))) nospam) l
        in withLinked l' model { modelScreen = Contacts, modelAddress = "" } packets
    | otherwise -> ownUpdate event model
    where address = modelAddress model
  Accept cid -> friendWish cid True
  Reject cid -> friendWish cid False
  DeleteContact cid _ -> let (m, cs) = friendWish cid False in (m { modelScreen = Contacts }, cs)
  MuteChat cid until' -> setting muteKind (friendGraphOf cid) (Just (muteOf until' True))
  UnmuteChat cid -> setting muteKind (friendGraphOf cid) Nothing
  -- Sending pictures as they are is the default, so clear the setting.
  SendPictures cid way -> setting picturesKind (friendGraphOf cid) (Sync.PictureFormat <$> (syncPictures =<< way))
  MuteGroup gid until' | Just c <- chatOf gid ->
    setting muteKind (Sync.chatGraph c) (Just (muteOf until' (maybe True groupMentions (Map.lookup gid (modelGroups model)))))
  UnmuteGroup gid | Just c <- chatOf gid -> setting muteKind (Sync.chatGraph c) Nothing
  ToggleMentions gid
    | Just c <- chatOf gid, Just g <- Map.lookup gid (modelGroups model), Just m <- groupMute g ->
        setting muteKind (Sync.chatGraph c) (Just (muteOf (case m of MutedUntil t -> Just t; MutedAlways -> Nothing)
                                                 (not (groupMentions g))))
  AnswerInvite _ (GroupId invite) join
    | Just i <- Sync.EventId <$> unhex' invite ->
        let password = if Text.null (modelPassword model) then Nothing else Just (modelPassword model)
            (l', packets) = authored account now (Sync.AnswerInvite i join password) l
        in withLinked l' model { modelScreen = Contacts, modelPassword = "" } packets
  LeaveGroup gid | Just c <- chatOf gid -> leaving c
  -- We only show chats the account is in, so deleting one leaves it.
  DeleteGroup gid | Just c <- chatOf gid -> leaving c
  ApplyProfile
    | Nothing <- profileError (modelNickname model) (modelStatus model) ->
        let (l1, p1) = authored account now (Sync.Wish Sync.AccountSubject (Sync.Name (Text.strip (modelNickname model)))) l
            (l2, p2) = authored account now (Sync.Wish Sync.AccountSubject (Sync.StatusMessage (Text.strip (modelStatus model)))) l1
        in withLinked l2 model (p1 ++ p2)
  AwayChosen away ->
    let (l', packets) = authored account now (Sync.Wish Sync.AccountSubject (Sync.Status (toEnum (fromEnum away)))) l
    in withLinked l' model packets
  ApplyTopic | TopicScreen gid <- modelScreen model, Just c <- chatOf gid ->
    let (l', packets) = authored account now (Sync.Wish (Sync.ChatSubject c) (Sync.Topic (Text.strip (modelTopic model)))) l
    in withLinked l' model { modelScreen = GroupDetails gid } packets
  ChooseRelayBot gid bot | Just c <- chatOf gid ->
    case (bot, Map.lookup c (Sync.accountRelayBots (Linked.accountState l))) of
      (Just key, _) | Just pk <- keyOf key ->
        let (l', packets) = authored account now (Sync.RelayBot c pk True) l in withLinked l' model packets
      (Nothing, Just pk) ->
        let (l', packets) = authored account now (Sync.RelayBot c pk False) l in withLinked l' model packets
      _ -> only model
  -- From our own Tox, whose only friend is the home.
  FriendNamed {} -> only model
  FriendStatusMessage {} -> only model
  FriendStatus {} -> only model
  FriendAvatar {} -> only model
  Received {} -> only model
  Requested {} -> only model
  AddFailed {} -> only model
  Invited {} -> only model
  FileShared cid time name size blob path ->
    let g = friendGraphOf cid
        (l', packets) = authored g time (Sync.File (senderIn g) Nothing name size False (Just (Sync.BlobId blob))) l
    in withLinked (Linked.blobHere (Sync.BlobId blob) path l') model packets
  AvatarPicked png ->
    let hash = SHA256.hash png
        (l', packets) = authored account now (Sync.Wish Sync.AccountSubject (Sync.Avatar (Just (Sync.BlobId hash)))) l
        (m, commands) = withLinked l' model { modelAvatars = Map.insert hash png (modelAvatars model) } packets
    in (m, StoreBlob png : commands)
  RemoveAvatar ->
    let (l', packets) = authored account now (Sync.Wish Sync.AccountSubject (Sync.Avatar Nothing)) l
    in withLinked l' model packets
  Found
    | Nothing <- foundingError (modelFounding model) (modelGroupName model) ->
        let (kind, privacy) = case modelFounding model of
              PrivateGroup  -> (Sync.GroupKind, Sync.Private)
              PublicGroup   -> (Sync.GroupKind, Sync.Public)
              NewConference -> (Sync.ConferenceKind, Sync.Public)
            (l', packets) = authored account now (Sync.NewChat kind (Text.strip (modelGroupName model)) privacy) l
        in withLinked l' model { modelScreen = Contacts } packets
  JoinPublic
    | Nothing <- chatIdError (modelChatId model), Just chatId <- unhex' (modelChatId model) ->
        let password = if Text.null (modelPassword model) then Nothing else Just (modelPassword model)
            (l', packets) = authored account now (Sync.JoinChat chatId password) l
        in withLinked l' model { modelScreen = Contacts, modelChatId = "", modelPassword = "" } packets
  InviteFriend gid (ContactId key) | Just c <- chatOf gid, Just friend <- keyOf key ->
    let (l', packets) = authored account now (Sync.InviteToChat c friend) l
    in withLinked l' model { modelNotice = Just "Invite sent" } packets
  -- The home answers or places the friend's call, then calls us and relays
  -- it.
  AnswerCall time camera -> case modelCall model of
    Just c | callPhase c == Ringing ->
      viaHome (model { modelCall = Just c { callPhase = Calling, callStarted = time, callCamera = camera } }, [CallFriend (callContact c) camera])
    _ -> only model
  StartCall {} -> viaHome (ownUpdate event model)
  HangUp {} -> viaHome (ownUpdate event model)
  ToggleCamera -> viaHome (ownUpdate event model)
  CallElsewhere {} -> viaHome (ownUpdate event model)
  -- The home gives up on a ringing call, not us.
  Tick {}
    | (callPhase <$> modelCall model) == Just Ringing -> only model
    | otherwise -> viaHome (ownUpdate event model)
  CallInvited cid time video | cid == home, Just friend <- relaying -> viaHome (ownUpdate (CallInvited friend time video) model)
  CallPeer cid time video | cid == home, Just friend <- relaying -> viaHome (ownUpdate (CallPeer friend time video) model)
  CallEnded cid time | cid == home, Just friend <- relaying -> viaHome (ownUpdate (CallEnded friend time) model)
  CallGlared cid time | cid == home, Just friend <- relaying -> viaHome (ownUpdate (CallEnded friend time) model)
  Moderate {} -> wishing
  ChangeSettings {} -> wishing
  ApplyGroupSettings -> wishing
  _ -> let (m, _) = ownUpdate event model in readToEnd l m []
  where
    only m = (m, [])
    leaving c =
      let (l', packets) = authored account now (Sync.Wish (Sync.ChatSubject c) (Sync.Joined False)) l
      in withLinked l' model { modelScreen = Contacts } packets
    home = ContactId (Text.toUpper (Text.take 64 (linkedHomeAddress l)))
    account = Sync.accountGraph (Linked.accountKey l)
    -- There's no clock in here, so use the latest event time.
    now = linkedClock l
    friendGraphOf (ContactId key) = Sync.friendGraph (Linked.accountKey l) (fromMaybe (Sync.PublicKey BS.empty) (keyOf key))
    chatOf gid = listToMaybe [c | c <- Sync.joinedChats (Linked.accountState l), chatGroupId c == gid]
    senderIn = linkedSender l
    relaying = case modelCall model of
      Just c | callVia c == Just home -> Just (callContact c)
      _                               -> Nothing
    -- Call commands go to the home, which relays the call. We ask it to
    -- place new ones.
    viaHome (m, commands) =
      let m' = m { modelCall = (\c -> c { callVia = Just home }) <$> modelCall m }
          toHome = \case
            CallFriend (ContactId key) camera | Just pk <- keyOf key -> [SendSync home (Linked.callAction pk (Protocol.Connect camera))]
            AnswerFriend _ camera -> [AnswerFriend home camera]
            HangUpCall (ContactId key) ->
              HangUpCall home : [SendSync home (Linked.callAction pk Protocol.HangUp) | Just pk <- [keyOf key]]
            CameraCall _ camera -> [CameraCall home camera]
            other -> [other]
      in (m', concatMap toHome commands)
    -- Turn Tox commands into wishes for the home.
    wishing =
      let (m, commands) = ownUpdate event model
          (l', packets) = foldl (\(l0, ps) (subject', value') ->
                                   let (l1, p) = authored account now (Sync.Wish subject' value') l0 in (l1, ps ++ p))
                                (l, []) (concatMap wishesOf commands)
      in withLinked l' m packets
    wishesOf = \case
      ModerateMember gid n action
        | Just c <- chatOf gid
        , Just pk <- keyOf . memberKey =<< Map.lookup n . groupMembers =<< Map.lookup gid (modelGroups model) ->
            [(Sync.PeerSubject c pk, case action of
                MakeModerator -> Sync.RoleValue Sync.Moderator
                MakeUser      -> Sync.RoleValue Sync.User
                MakeObserver  -> Sync.RoleValue Sync.Observer
                Kick          -> Sync.Present False)]
      SetGroupSettings gid new
        | Just c <- chatOf gid, Just old <- groupSettings =<< Map.lookup gid (modelGroups model) ->
            let differs f = f old /= f new
            in [ (Sync.ChatSubject c, v)
               | (True, v) <-
                   [ (differs Tox.groupPrivate, Sync.PrivacyValue (if Tox.groupPrivate new then Sync.Private else Sync.Public))
                   , (differs Tox.groupPeerLimit, Sync.PeerLimit (fromIntegral (Tox.groupPeerLimit new)))
                   , (differs Tox.groupPassword, Sync.Password (Text.decodeUtf8Lenient (Tox.groupPassword new)))
                   , (differs Tox.groupTopicLock, Sync.TopicLock (Tox.groupTopicLock new))
                   , (differs Tox.groupVoice, Sync.VoiceStateValue (syncVoice (Tox.groupVoice new))) ] ]
      _ -> []
    syncVoice = \case
      Tox.VoiceAll        -> Sync.VoiceEveryone
      Tox.VoiceModerators -> Sync.VoiceModerators
      Tox.VoiceFounder    -> Sync.VoiceFounder
    friendWish (ContactId key) wanted = case keyOf key of
      Just pk ->
        let content = if wanted then Sync.WantFriend pk Nothing Nothing else Sync.UnwantFriend pk
            (l', packets) = authored account now content l
        in withLinked l' model packets
      Nothing -> only model
    -- Mute or picture format of a conversation. Keep any fields newer
    -- clients added after ours.
    setting kind g s' =
      let scope = Sync.ConversationScope g
          old = Map.lookup kind =<< Map.lookup scope (Sync.accountSettings (Linked.accountState l))
          content = maybe (Sync.ClearSetting scope (fromIntegral kind))
            (\new -> Sync.SettingContent scope (maybe (Sync.kept new) (Sync.withSetting new) old)) s'
          (l', packets) = authored account now content l
      in withLinked l' model packets
    muteOf until' = Sync.Mute (fromIntegral . Linked.toMillis <$> until')
    nospamOf t = case unhex' t of
      Just bytes | BS.length bytes == 4 -> Just (BS.foldl' (\n b -> n * 256 + fromIntegral b) 0 bytes)
      _ -> Nothing

muteKind, picturesKind :: Word64
muteKind = Sync.settingKind (Sync.Mute Nothing True)
picturesKind = Sync.settingKind (Sync.PictureFormat Sync.Original)

-- | Sync picture format from our key, and back.
syncPictures :: Text -> Maybe Sync.PictureEncoding
syncPictures key
  | key == Pictures.formatKey Pictures.qoi = Just Sync.Qoi
  | otherwise = Nothing

picturesOf :: Sync.PictureEncoding -> Maybe Text
picturesOf = \case
  Sync.Qoi      -> Just (Pictures.formatKey Pictures.qoi)
  Sync.Original -> Nothing

withLinked :: Linked -> Model -> [BS.ByteString] -> (Model, [Command])
withLinked l model = readToEnd l (linkedView l model { modelLinked = Just l })

-- | Mark the open chat read to its end, as an event for the other devices.
readToEnd :: Linked -> Model -> [BS.ByteString] -> (Model, [Command])
readToEnd l0 model0 packets = case unreadEnd of
  Just (g, i, rank) ->
    let (l', more) = authored (Sync.accountGraph (Linked.accountKey l)) (linkedClock l) (Sync.ReadUpTo g i rank) l
    in (linkedView l' model { modelLinked = Just l' }, send (packets ++ more) ++ fetches)
  Nothing -> (model, send packets ++ fetches)
  where
    (l, fetches) = fetching l0 model0
    model = model0 { modelLinked = Just l }
    home = ContactId (Text.toUpper (Text.take 64 (linkedHomeAddress l)))
    send ps = [SendSync home ps | not (null ps)]
    store = Replica.replicaStore (Linked.linkedReplica l)
    shown g = modelShown model && not (modelAway model) && case modelScreen model of
      Chat (ContactId key) -> Just g == (Sync.friendGraph (Linked.accountKey l) <$> keyOf key)
      GroupChat gid -> g `elem` [Sync.chatGraph c | c <- Sync.joinedChats (Linked.accountState l), chatGroupId c == gid]
      _ -> False
    unreadEnd = listToMaybe
      [ (g, i, Sync.eventRank e)
      | g <- Sync.storeGraphs store, shown g
      , (i, e) <- take 1 (reverse (Sync.byRank g store))
      , unreadIn (Linked.accountState l) g e ]

-- | Whether no device has read the event yet. Read up to a rank means
-- everything of that rank or lower.
unreadIn :: Sync.AccountState -> Sync.GraphId -> Sync.Event -> Bool
unreadIn state g e = maybe True ((< Sync.eventRank e) . fst) (Map.lookup g (Sync.accountRead state))

-- | Ask the home for avatar blobs we don't have (once per session), and for
-- accepted files.
fetching :: Linked -> Model -> (Linked, [Command])
fetching l model = foldl (\(l', commands) (blob, file) -> (<>) commands <$> fetchFile l' blob file)
  (foldl ask (l, []) missing) files
  where
    missing = [ blob | Linked.inSession l, blob <- avatarBlobs l, Map.notMember blob (modelAvatars model)
                     , Set.notMember (Sync.BlobId blob) (Linked.linkedWanted l) ]
    files = [ (blob, file) | (fid, file@(_, size)) <- linkedFiles l
                           , size <= settingAutoAccept (modelAccount model) || Map.lookup fid (linkedAnswers l) == Just True
                           , Just (True, Just blob) <- [linkedEnd l fid] ]
      -- Ours, stored here as blobs (to find them again after a restart).
      ++ linkedOurs l
    home = ContactId (Text.toUpper (Text.take 64 (linkedHomeAddress l)))
    ask (l', commands) blob =
      let (packets, l'') = Linked.wantBlob (Sync.BlobId blob) l' in (l'', commands ++ [FetchBlob home blob packets Nothing])

-- | Use the blob if we have it, else ask the home in a session.
fetchFile :: Linked -> Sync.BlobId -> (Text, Word64) -> (Linked, [Command])
fetchFile l blob@(Sync.BlobId bytes) (name, _)
  | Map.member blob (Linked.linkedHave l) = (l, [])
  | Linked.inSession l, Set.notMember blob (Linked.linkedWanted l) =
      let (packets, l') = Linked.wantBlob blob l in (l', [FetchBlob home bytes packets (Just name)])
  | Set.notMember blob (Linked.linkedLooked l) = (Linked.lookForBlob blob l, [FetchBlob home bytes [] (Just name)])
  | otherwise = (l, [])
  where home = ContactId (Text.toUpper (Text.take 64 (linkedHomeAddress l)))

-- | Files friends sent the account, by event, with names and sizes.
linkedFiles :: Linked -> [(Sync.EventId, (Text, Word64))]
linkedFiles l =
  [ (i, (name, size)) | g <- Sync.storeGraphs store, (i, e) <- Sync.byRank g store
                      , Sync.File _ _ name size True _ <- [Sync.eventContent e] ]
  where store = Replica.replicaStore (Linked.linkedReplica l)

-- | Our files sent by the account's devices, by blob, with names and
-- sizes.
linkedOurs :: Linked -> [(Sync.BlobId, (Text, Word64))]
linkedOurs l =
  [ (blob, (name, size)) | g <- Sync.storeGraphs store, (_, e) <- Sync.byRank g store
                         , Sync.File _ _ name size False (Just blob) <- [Sync.eventContent e] ]
  where store = Replica.replicaStore (Linked.linkedReplica l)

-- | How a file ended, if it did: OK or not, and the home's blob.
linkedEnd :: Linked -> Sync.EventId -> Maybe (Bool, Maybe Sync.BlobId)
linkedEnd l fid = listToMaybe
  [ (ok, blob) | g <- Sync.storeGraphs store, (_, e) <- reverse (Sync.byRank g store)
               , Sync.FileEnded i ok blob <- [Sync.eventContent e], i == fid ]
  where store = Replica.replicaStore (Linked.linkedReplica l)

-- | Latest accept or decline of each file.
linkedAnswers :: Linked -> Map Sync.EventId Bool
linkedAnswers l = Map.fromList
  [ (i, yes) | g <- Sync.storeGraphs store, (_, e) <- Sync.byRank g store, Sync.FileAnswered i yes <- [Sync.eventContent e] ]
  where store = Replica.replicaStore (Linked.linkedReplica l)

-- | File at a message index, with its event, name and size.
linkedFileAt :: Linked -> ContactId -> MessageId -> Maybe (Sync.EventId, (Text, Word64))
linkedFileAt l (ContactId key) i = do
  pk <- keyOf key
  let g = Sync.friendGraph (Linked.accountKey l) pk
      store = Replica.replicaStore (Linked.linkedReplica l)
  (fid, e) <- listToMaybe (drop i (filter (shownAsMessage . Sync.eventContent . snd) (Sync.displayOrder g store)))
  case Sync.eventContent e of
    Sync.File _ _ name size True _ -> Just (fid, (name, size))
    _                              -> Nothing

shownAsMessage :: Sync.Content -> Bool
shownAsMessage = \case
  Sync.Received {}    -> True
  Sync.Send {}        -> True
  Sync.CallStarted {} -> True
  Sync.File {}        -> True
  _                   -> False

avatarBlobs :: Linked -> [BS.ByteString]
avatarBlobs l = nub [blob | (_, Sync.Avatar (Just (Sync.BlobId blob))) <- Sync.allFacts (Sync.accountFacts (Linked.accountState l))]

authored :: Sync.GraphId -> UTCTime -> Sync.Content -> Linked -> (Linked, [BS.ByteString])
authored g time content l = (l', packets)
  where (_, packets, l') = Linked.author g time content l

linkedHomeAddress :: Linked -> Text
linkedHomeAddress = Linked.linkedHome

-- | Latest event time, for our new events (there's no clock here).
linkedClock :: Linked -> UTCTime
linkedClock l = maximum (Linked.linkedSince l : [Linked.eventTime e | g <- Sync.storeGraphs store, (_, e) <- take 1 (reverse (Sync.byRank g store))])
  where store = Replica.replicaStore (Linked.linkedReplica l)

-- | Our name in a chat if we set one there, else the account's.
linkedSender :: Linked -> Sync.GraphId -> Text
linkedSender l g = fromMaybe ourName (listToMaybe
  [n | c <- Sync.joinedChats state, Sync.chatGraph c == g, Sync.SelfName n <- Sync.factsOf (Sync.ChatSubject c) facts])
  where
    state = Linked.accountState l
    facts = Sync.accountFacts state
    ourName = fromMaybe "" (listToMaybe [n | Sync.Name n <- Sync.factsOf Sync.AccountSubject facts])

keyOf :: Text -> Maybe Sync.PublicKey
keyOf key = case unhex' key of
  Just bytes | BS.length bytes == 32 -> Just (Sync.PublicKey bytes)
  _                                  -> Nothing

unhex' :: Text -> Maybe BS.ByteString
unhex' = either (const Nothing) Just . Base16.decode . Text.encodeUtf8

hexOf :: BS.ByteString -> Text
hexOf = Text.toUpper . Text.decodeUtf8 . Base16.encode

chatGroupId :: Sync.ChatId -> GroupId
chatGroupId (Sync.GroupChat i)      = GroupId (hexOf i)
chatGroupId (Sync.ConferenceChat i) = GroupId (hexOf i)

privateGone :: Text
privateGone = "They have left the group, so nothing was sent"

-- | Chats, friends, invites and profile of a linked account, from its
-- events and the home's live facts.
linkedView :: Linked -> Model -> Model
linkedView l model = model
  { modelProfile = (modelProfile model)
      { profileNickname = fromMaybe "" (listToMaybe [n | Sync.Name n <- kept Sync.AccountSubject])
      , profileStatus = fromMaybe "" (listToMaybe [t | Sync.StatusMessage t <- kept Sync.AccountSubject])
      , profileAway = maybe Tox.Online (toEnum . fromEnum)
          (listToMaybe [st | Sync.Status st <- kept Sync.AccountSubject])
      , profileToxId = fromMaybe (Text.toUpper (Linked.linkedHome l))
          (listToMaybe [hexOf a | Sync.Address a <- kept Sync.AccountSubject]) }
  , modelAvatar = avatarOf Sync.AccountSubject
  -- Ring while it rings at the home, until a device answers.
  , modelCall = case modelCall model of
      Nothing -> listToMaybe
        [ (newCall (contactIdOf pk) Ringing (linkedClock l) video) { callPeerVideo = video }
        | (Sync.FriendSubject pk, Sync.CallValue (Sync.Ringing video)) <- Sync.allFacts live ]
      Just c | callPhase c == Ringing, not (ringing (callContact c)) -> Nothing
      other -> other
  , modelContacts = Map.fromList
      -- Leave out the account's devices (they're the home's friends too,
      -- us even before the home lists us).
      [ (contactIdOf pk, contact pk) | (pk, f) <- Map.toList (Sync.accountFriends state), Sync.friendWanted f
      , pk /= Replica.replicaDevice (Linked.linkedReplica l), Map.notMember pk (Sync.accountDevices state) ]
  , modelRequests = Map.fromList
      [ (contactIdOf pk, asked) | (pk, Sync.Friend False (Just asked)) <- Map.toList (Sync.accountFriends state) ]
  , modelGroups = Map.fromList [(chatGroupId c, group c) | c <- Sync.joinedChats state]
  , modelInvites = Map.fromList
      [ ((contactIdOf (Sync.inviteFrom v), GroupId (hexOf i)), invite v)
      | (Sync.EventId i, v) <- Map.toList (Sync.accountInvites state)
      , Sync.inviteStatus v `elem` [Sync.Pending, Sync.Joining] ]
  }
  where
    state = Linked.accountState l
    facts = Sync.accountFacts state
    live = Linked.liveFacts l
    store = Replica.replicaStore (Linked.linkedReplica l)
    account = Linked.accountKey l
    kept s = Sync.factsOf s facts
    avatarOf s = listToMaybe [blob | Sync.Avatar (Just (Sync.BlobId blob)) <- kept s]
    ringing (ContactId key) = or
      [ True | Just pk <- [keyOf key], Sync.CallValue (Sync.Ringing _) <- Sync.factsOf (Sync.FriendSubject pk) live ]
    contactIdOf (Sync.PublicKey pk) = ContactId (hexOf pk)
    memberKey' (Sync.PublicKey pk) = hexOf pk
    toxKind Sync.Action = Tox.MessageAction
    toxKind Sync.Normal = Tox.MessageNormal
    readable' = readable (modelAccount model)
    timeline g = Sync.displayOrder g store
    went g = Set.fromList [i | (_, e) <- timeline g, Sync.Sent i <- [Sync.eventContent e]]
    arrived g = Map.fromList [(i, Linked.eventTime e) | (_, e) <- timeline g, Sync.Delivered i <- [Sync.eventContent e]]
    ended g = Map.fromList [(i, (d, declined)) | (_, e) <- timeline g, Sync.CallEnded i d declined <- [Sync.eventContent e]]
    delivery g i
      | Map.member i (arrived g) = Delivered
      | Set.member i (went g) = Sent
      | otherwise = Pending
    -- Theirs after the last read and since the link (earlier ones were for
    -- the other devices to notify). Only missed calls count.
    unread g theirs = length
      [ () | (i, e) <- timeline g
      , unreadIn state g e
      , Linked.eventTime e >= Linked.linkedSince l
      , theirs (i, e) ]
    theirMessage g = maybe False (\m -> not (messageMine m) && maybe True recordMissed (messageCall m)) . message g
    theirEntry (_, e) = case Sync.eventContent e of
      Sync.Received {}          -> True
      Sync.ReceivedPrivately {} -> True
      _                         -> False
    muteIn g = case Map.lookup muteKind =<< Map.lookup (Sync.ConversationScope g) (Sync.accountSettings state) of
      Just (Sync.Kept (Sync.Mute until' mentioned) _) ->
        Just (maybe MutedAlways (MutedUntil . Linked.fromMillis . fromIntegral) until', mentioned)
      _ -> Nothing
    contact pk = Contact
      { contactName = listToMaybe [n | Sync.Name n <- kept subject]
      , contactOnline = or [c /= Sync.NoConnection | Sync.ConnectionValue c <- Sync.factsOf subject live]
      , contactMessages = mapMaybe (message g) (timeline g)
      , contactUnread = unread g (theirMessage g)
      , contactRequest = Nothing
      , contactStatusMessage = fromMaybe "" (listToMaybe [t | Sync.StatusMessage t <- kept subject])
      , contactStatus = fromMaybe Tox.Online (listToMaybe [toEnum (fromEnum st) | Sync.Status st <- Sync.factsOf subject live])
      , contactMute = fst <$> muteIn g
      , contactAvatar = avatarOf subject
      , contactPictures = case Sync.keptValue <$> (Map.lookup picturesKind =<< Map.lookup (Sync.ConversationScope g) (Sync.accountSettings state)) of
          Just (Sync.PictureFormat way) -> picturesOf way
          _                             -> Nothing
      }
      where
        subject = Sync.FriendSubject pk
        g = Sync.friendGraph account pk
    message g (i, e) = case Sync.eventContent e of
      Sync.Received _ _ bytes kind ->
        Just (Message False (readText (readWith readable' bytes)) t Delivered Nothing Nothing 0 Nothing (toxKind kind) (Just bytes))
      Sync.Send _ bytes kind ->
        Just (Message True (Text.decodeUtf8Lenient bytes) t (delivery g i) Nothing Nothing 0 (Map.lookup i (arrived g)) (toxKind kind) Nothing)
      Sync.CallStarted _ incoming video ->
        let (talked, declined) = case Map.lookup i (ended g) of
              Just (d, no) -> (fromIntegral <$> d, no)
              Nothing      -> (Nothing, False)
            missed = incoming && Map.member i (ended g) && isNothing talked && not declined
        in Just (Message (not incoming) "" t Delivered Nothing
                   (Just (CallRecord video ((/ 1000) <$> talked) missed)) 0 Nothing Tox.MessageNormal Nothing)
      Sync.File _ _ name size incoming blob ->
        let end = linkedEnd l i
            held = case end of
              Just (_, b) -> b <|> blob
              Nothing     -> blob
            here = (`Map.lookup` Linked.linkedHave l) =<< held
            path = fromMaybe "" here
            progress = case end of
              Just (False, _) -> Cancelled
              Just (True, _) | isJust here -> Complete
              Just (True, Just b) | Set.member b (Linked.linkedMissing l) -> Cancelled
                                  | Set.member b (Linked.linkedWanted l) -> Moving
              Just (True, _) -> if incoming then Waiting else Complete
              Nothing -> case Map.lookup i (linkedAnswers l) of
                Just True  -> Moving
                Just False -> Cancelled
                Nothing    -> if incoming then Waiting else Moving
            done = if progress == Complete then size else 0
        in Just (Message (not incoming) name t (if isJust end then Delivered else Pending)
                   (Just (Attachment size path done progress Nothing)) Nothing 0 Nothing Tox.MessageNormal Nothing)
      _ -> Nothing
      where t = Linked.eventTime e
    group c = (newGroup name (if isGroup then NgcGroup else TextConference) InGroup)
      { groupEntries = mapMaybe (entry g peerName) (timeline g)
      , groupUnread = unread g theirEntry
      , groupMembers = Map.fromList [(n, Member (memberKey' pk) (peerName pk)) | (n, pk) <- peers]
      , groupMute = fst <$> muteIn g
      , groupMentions = maybe True snd (muteIn g)
      , groupTopic = fromMaybe "" (listToMaybe [t | Sync.Topic t <- kept subject])
      , groupMayTopic = not locked || selfRole `elem` [Just Tox.Founder, Just Tox.Moderator]
      , groupRoles = Map.fromList [(n, role) | (n, pk) <- peers, Sync.RoleValue r <- peerFacts pk, let role = toxRole r]
      , groupStatuses = Map.fromList
          [(n, status) | (n, pk) <- peers, Sync.Status st <- peerFacts pk, let status = toEnum (fromEnum st), status /= Tox.Online]
      , groupSelfRole = selfRole
      , groupSettings = Tox.GroupSettings
          <$> listToMaybe [p == Sync.Private | Sync.PrivacyValue p <- kept subject]
          <*> Just (Text.encodeUtf8 (fromMaybe "" (listToMaybe [p | Sync.Password p <- kept subject])))
          <*> listToMaybe [fromIntegral n | Sync.PeerLimit n <- kept subject]
          <*> Just locked
          <*> listToMaybe [toxVoice v | Sync.VoiceStateValue v <- kept subject]
      , groupRelayBot = memberKey' <$> Map.lookup c (Sync.accountRelayBots state)
      }
      where
        g = Sync.chatGraph c
        subject = Sync.ChatSubject c
        isGroup = case c of
          Sync.GroupChat _ -> True
          _                -> False
        name = fromMaybe "" (listToMaybe [n | Sync.Name n <- kept subject])
        locked = or [b | Sync.TopicLock b <- kept subject]
        selfRole = listToMaybe [toxRole r | Sync.RoleValue r <- kept subject]
        peerFacts pk = Sync.factsOf (Sync.PeerSubject c pk) live
        -- A member who left has no facts, so use the name of their last
        -- message.
        peerName pk = fromMaybe "" (listToMaybe [n | Sync.Name n <- peerFacts pk] <|> Map.lookup pk wroteAs)
        wroteAs = Map.fromList $ flip mapMaybe (timeline g) $ \(_, e) -> case Sync.eventContent e of
          Sync.Received (Just pk) said _ _   -> Just (pk, said)
          Sync.ReceivedPrivately pk said _ _ -> Just (pk, said)
          _                                  -> Nothing
        -- Our own numbers (Tox's are on the home).
        peers = zip [0 ..] [pk | (Sync.PeerSubject c' pk, Sync.Present True) <- Sync.allFacts live, c' == c]
    entry g nameOf (i, e) = GroupEntry (Linked.eventTime e) <$> case Sync.eventContent e of
      Sync.Received from sender bytes kind ->
        Just (Said (Just (Member (maybe "" memberKey' from) sender)) (toxKind kind) (readText (readWith readable' bytes)) Delivered)
      Sync.Send _ bytes kind -> Just (Said Nothing (toxKind kind) (Text.decodeUtf8Lenient bytes) (delivery g i))
      Sync.ReceivedPrivately from sender bytes kind ->
        Just (PrivateFrom (Member (memberKey' from) sender) (toxKind kind) (readText (readWith readable' bytes)))
      Sync.SendPrivately to _ bytes kind ->
        Just (PrivateTo (Member (memberKey' to) (nameOf to)) (toxKind kind) (Text.decodeUtf8Lenient bytes) (delivery g i))
      Sync.Notice t -> Just (Noted t)
      _ -> Nothing
    toxRole = \case
      Sync.Founder   -> Tox.Founder
      Sync.Moderator -> Tox.Moderator
      Sync.User      -> Tox.User
      Sync.Observer  -> Tox.Observer
    toxVoice = \case
      Sync.VoiceEveryone   -> Tox.VoiceAll
      Sync.VoiceModerators -> Tox.VoiceModerators
      Sync.VoiceFounder    -> Tox.VoiceFounder
    invite v = Invite
      { inviteKind = if Sync.inviteKind v == Sync.GroupKind then NgcGroup else TextConference
      , inviteName = Sync.inviteName v
      , inviteData = Sync.inviteData v
      , inviteAnswered = if Sync.inviteStatus v == Sync.Joining then Just (fromMaybe "" (Sync.invitePassword v)) else Nothing
      }

-- | Member the draft goes to privately, while they're in the group.
privateMember :: Model -> Group -> Maybe (Tox.PeerId, Member)
privateMember model g = do
  key <- modelPrivateTo model
  find ((== key) . memberKey . snd) (Map.toList (groupMembers g))

adjustMessage :: ContactId -> MessageId -> (Message -> Message) -> Model -> Model
adjustMessage cid i f model = model { modelContacts = Map.adjust contact cid (modelContacts model) }
  where
    contact c = c { contactMessages = [ if j == i then f m else m | (j, m) <- zip [0 ..] (contactMessages c) ] }

adjustFile :: ContactId -> MessageId -> (Attachment -> Attachment) -> Model -> Model
adjustFile cid i f = adjustMessage cid i (\m -> m { messageFile = f <$> messageFile m })

-- | Transfer that Tox ended early. Both ours and theirs wait to be offered
-- again and resume, but only if they have a file ID.
interrupted :: Message -> Message
interrupted m = m { messageFile = cut <$> messageFile m }
  where
    cut a
      | attachmentState a `notElem` [Waiting, Moving] = a
      | messageMine m && (attachmentState a == Waiting || resumable) = a { attachmentState = Waiting }
      | resumable && attachmentState a == Moving = a { attachmentState = Interrupted }
      | resumable = a
      | otherwise = a { attachmentState = Cancelled }
      where resumable = isJust (attachmentId a)

opened :: Screen -> Model -> Model
opened screen model = case screen of
  Chat cid -> model
    { modelContacts =
        Map.adjust (\c -> c { contactUnread = 0 }) cid (modelContacts model)
    }
  GroupChat gid -> model
    { modelGroups = Map.adjust (\g -> g { groupUnread = 0 }) gid (modelGroups model) }
  InviteScreen _ _ -> model { modelPassword = "" }
  TopicScreen gid -> model { modelTopic = maybe "" groupTopic (Map.lookup gid (modelGroups model)) }
  NewGroupScreen -> model { modelGroupName = "", modelFounding = PrivateGroup }
  GroupSettingsScreen gid -> case groupSettings =<< Map.lookup gid (modelGroups model) of
    Just settings -> model { modelPeerLimit = Text.pack (show (Tox.groupPeerLimit settings))
                           , modelGroupPassword = Text.decodeUtf8Lenient (Tox.groupPassword settings) }
    Nothing -> model
  JoinGroupScreen -> model { modelChatId = "", modelPassword = "" }
  LinkScreen -> model { modelLink = "" }
  BackupScreen -> model { modelBackup = Set.fromList (map accountId (modelProfiles model)) }
  ProfileScreen -> model
    { modelNickname = profileNickname (modelProfile model)
    , modelStatus = profileStatus (modelProfile model)
    }
  ProxyScreen ->
    let proxy = settingProxy (modelDevice model)
    in model
      { modelProxyKind = Tox.proxyType <$> proxy
      , modelProxyHost = maybe "" (Text.pack . Tox.proxyHost) proxy
      , modelProxyPort = maybe "" (Text.pack . show . Tox.proxyPort) proxy
      }
  AddContact -> model
    { modelAddress = ""
    , modelRequest = requestMessage (modelProfile model)
    , modelAddError = Nothing
    }
  _ -> model

-- | Nothing on the contacts screen (Back leaves the app).
back :: Model -> Maybe Model
back model
  -- Can't hide a ringing call. Others go behind a banner.
  | Just c <- modelCall model, not (callHidden c) =
      if callPhase c == Ringing then Nothing else Just model { modelCall = Just c { callHidden = True } }
  | modelDrawer model = Just model { modelDrawer = False }
  | modelScreen model == Contacts = Nothing
  | not (Set.null (modelSelected model)) = Just model { modelSelected = Set.empty }
  | Details cid <- modelScreen model = Just model { modelScreen = Chat cid }
  | GroupDetails gid <- modelScreen model = Just model { modelScreen = GroupChat gid }
  | TopicScreen gid <- modelScreen model = Just model { modelScreen = GroupDetails gid }
  | InviteFriendsScreen gid <- modelScreen model = Just model { modelScreen = GroupDetails gid }
  | GroupSettingsScreen gid <- modelScreen model = Just model { modelScreen = GroupDetails gid }
  | Forward cid _ <- modelScreen model = Just model { modelScreen = Chat cid }
  | MessageInfo cid _ <- modelScreen model = Just model { modelScreen = Chat cid }
  | modelScreen model == ProxyScreen = Just model { modelScreen = SettingsScreen }
  | modelScreen model == LinkScreen = Just model { modelScreen = ProfilesScreen }
  | modelScreen model == BackupScreen = Just model { modelScreen = ProfilesScreen }
  | otherwise = Just model { modelScreen = Contacts }

-- | Unread messages and files to notify about, oldest first. Not for muted
-- contacts.
notifications :: UTCTime -> Model -> Map ContactId [Text]
notifications now model = Map.mapMaybeWithKey lines' (unreadOf now model)
  where
    lines' cid = nonEmpty . map (preview (named cid)) . filter (isNothing . messageCall)
    named cid = maybe "" (contactLabel cid) (Map.lookup cid (modelContacts model))

-- | Newest first.
callHistory :: Model -> [(ContactId, Message, CallRecord)]
callHistory model = sortOn (\(_, m, _) -> Down (messageTime m))
  [ (cid, m, record)
  | (cid, c) <- Map.toList (modelContacts model), m <- contactMessages c, Just record <- [messageCall m] ]

-- | Unread group messages to notify about, oldest first, with the sender.
-- Muted groups still notify about mentions, unless turned off.
groupNotifications :: UTCTime -> Model -> Map GroupId [Text]
groupNotifications now model = Map.mapMaybe unread (modelGroups model)
  where
    unread g
      | groupUnread g > 0 && (not (groupMuted now g) || groupMentions g) =
          let said = uttered (modelProfile model) g
              received = \case
                GroupEntry _ (Said (Just who) kind text _) -> [(said who text, False, kind)]
                GroupEntry _ (PrivateFrom who kind text)   -> [((memberLabel who, text), True, kind)]
                _                                          -> []
              theirs = concatMap received (groupEntries g)
              -- Private messages count as mentions.
              shown ((_, text), private, _) = not (groupMuted now g) || private || mentions (groupNick (modelProfile model)) text
          in nonEmpty [ line m | m <- drop (length theirs - groupUnread g) theirs, shown m ]
      | otherwise = Nothing
    line ((who, text), private, kind)
      | kind == Tox.MessageAction = "* " <> name <> " " <> text
      | otherwise = name <> ": " <> text
      where name = who <> (if private then " (privately)" else "")

-- | Unread missed calls per contact (notified apart from messages). Not for
-- muted contacts.
missedCalls :: UTCTime -> Model -> Map ContactId Int
missedCalls now = Map.mapMaybe (positive . length . filter (isJust . messageCall)) . unreadOf now
  where positive n = if n > 0 then Just n else Nothing

-- | Theirs, oldest first. Only missed calls count. Nothing for muted
-- contacts.
unreadOf :: UTCTime -> Model -> Map ContactId [Message]
unreadOf now model = Map.mapMaybe unread (modelContacts model)
  where
    unread c
      | contactUnread c > 0 && not (muted now c) =
          let theirs = filter unreadable (contactMessages c)
          in Just (drop (length theirs - contactUnread c) theirs)
      | otherwise = Nothing
    unreadable m = not (messageMine m) && maybe True recordMissed (messageCall m)

nonEmpty :: [a] -> Maybe [a]
nonEmpty xs = if null xs then Nothing else Just xs
