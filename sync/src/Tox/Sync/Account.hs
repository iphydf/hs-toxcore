-- | State of an account, from its graph's events.
module Tox.Sync.Account
  ( AccountState (..)
  , Friend (..)
  , Merge (..)
  , Invite (..)
  , InviteStatus (..)
  , emptyAccount
  , accountOf
  , applyEvent
  , isOpen
  , joinedChats
  ) where

import           Control.Applicative ((<|>))
import qualified Data.ByteString     as BS
import           Data.Map.Strict     (Map)
import qualified Data.Map.Strict     as Map
import           Data.Maybe          (fromMaybe, isNothing)
import           Data.Text           (Text)
import           Data.Word           (Word64)

import           Tox.Sync.Event
import           Tox.Sync.Fact
import           Tox.Sync.Id
import           Tox.Sync.Setting
import           Tox.Sync.Store

data Friend = Friend
  { friendWanted  :: Bool
  , friendRequest :: Maybe Text
    -- ^ Waiting for an answer.
  } deriving (Eq, Show)

-- | Chat shown with another, by the keys of the bot relaying between them.
data Merge = Merge
  { mergeBot     :: PublicKey
  , mergeInto    :: ChatId
  , mergeIntoBot :: PublicKey
  } deriving (Eq, Show)

-- | From its last answer and what the home did with it.
data InviteStatus
  = Pending
  | Joining
    -- ^ Accepted, but the home hasn't joined yet.
  | JoinedChat ChatId
  | Failed Bool
    -- ^ The home couldn't join. Set if it was a missing or wrong password.
  | Declined
  deriving (Eq, Show)

data Invite = Invite
  { inviteFrom     :: PublicKey
  , inviteKind     :: ChatKind
  , inviteName     :: Text
  , inviteData     :: BS.ByteString
  , inviteStatus   :: InviteStatus
  , invitePassword :: Maybe Text
    -- ^ From the last accept.
  , inviteChat     :: Maybe ChatId
    -- ^ Chat the home joined, even if Tox failed it later.
  } deriving (Eq, Show)

-- | Whether accepting can still join. A chat that turned the home away has
-- used it up.
isOpen :: Invite -> Bool
isOpen invite = case inviteStatus invite of
  Pending  -> True
  Joining  -> True
  Failed _ -> isNothing (inviteChat invite)
  _        -> False

data AccountState = AccountState
  { accountFacts     :: Facts
    -- ^ Kept ones only (live facts are only in sessions).
  , accountFriends   :: Map PublicKey Friend
  , accountMerges    :: Map ChatId Merge
  , accountRelayBots :: Map ChatId PublicKey
  , accountRead      :: Map GraphId (Word64, EventId)
    -- ^ Rank and ID of the last event read, per conversation.
  , accountSettings  :: Map Scope (Map Word64 (Kept Setting))
  , accountInvites   :: Map EventId Invite
    -- ^ By their 'ChatInvite' events.
  , accountDevices   :: Map PublicKey Text
    -- ^ With their names.
  , accountChats     :: Map EventId (Maybe ChatId)
    -- ^ Chat the home founded or joined for each 'NewChat' and 'JoinChat'
    -- event. Nothing if Tox refused.
  } deriving (Eq, Show)

emptyAccount :: AccountState
emptyAccount = AccountState noFacts Map.empty Map.empty Map.empty Map.empty Map.empty Map.empty Map.empty Map.empty

-- | Events in rank order, so the last writer wins.
accountOf :: GraphId -> EventStore -> AccountState
accountOf g = foldl (\s (i, e) -> applyEvent i (eventContent e) s) emptyAccount . byRank g

joinedChats :: AccountState -> [ChatId]
joinedChats s = [c | (ChatSubject c, Joined True) <- allFacts (accountFacts s)]

-- | After all events of lower rank.
applyEvent :: EventId -> Content -> AccountState -> AccountState
applyEvent i c s = case c of
  FactContent subject' value' -> s { accountFacts = setFact subject' value' (accountFacts s) }
  WantFriend pk _ _ -> friend pk (const (Friend True Nothing))
  UnwantFriend pk -> friend pk (const (Friend False Nothing))
  ReadUpTo g event rank ->
    s { accountRead = Map.insertWith max g (rank, event) (accountRead s) }
  FriendRequest pk message -> friend pk (\f -> f { friendRequest = Just message })
  MergeChat chat' bot into intoBot merged
    | merged -> s { accountMerges = Map.insert chat' (Merge bot into intoBot) (accountMerges s) }
    | otherwise -> s { accountMerges = Map.delete chat' (accountMerges s) }
  RelayBot chat' bot relays
    | relays -> s { accountRelayBots = Map.insert chat' bot (accountRelayBots s) }
    | otherwise -> s { accountRelayBots = Map.delete chat' (accountRelayBots s) }
  SettingContent scope' setting ->
    s { accountSettings = Map.insertWith Map.union scope'
          (Map.singleton (settingKind (keptValue setting)) setting) (accountSettings s) }
  ClearSetting scope' kind ->
    s { accountSettings = Map.update cleared scope' (accountSettings s) }
    where
      cleared kinds = let rest = Map.delete (fromIntegral kind) kinds
                      in if Map.null rest then Nothing else Just rest
  ChatInvite from kind name invite ->
    s { accountInvites = Map.insert i (Invite from kind name invite Pending Nothing Nothing) (accountInvites s) }
  AnswerInvite invite join password -> invited invite $ \v ->
    v { inviteStatus = if join then Joining else Declined, invitePassword = password }
  InviteJoined invite chat' needsPassword -> invited invite $ \v ->
    v { inviteStatus = maybe (Failed needsPassword) JoinedChat chat'
      , inviteChat = chat' <|> inviteChat v }
  Device pk name -> s { accountDevices = Map.insert pk name (accountDevices s) }
  DeviceGone pk -> s { accountDevices = Map.delete pk (accountDevices s) }
  ChatJoined intent chat' -> s { accountChats = Map.insert intent chat' (accountChats s) }
  _ -> s
  where
    friend pk f = s { accountFriends = Map.alter (Just . f . fromMaybe (Friend False Nothing)) pk (accountFriends s) }
    invited invite f = s { accountInvites = Map.adjust f invite (accountInvites s) }
