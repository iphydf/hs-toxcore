{-# LANGUAGE OverloadedStrings #-}
module Tox.Android.StoreSpec (spec) where

import           Control.Monad          (foldM_, void, (<=<))
import qualified Data.ByteString        as BS
import qualified Data.Map.Strict        as Map
import           Data.Maybe             (listToMaybe)
import qualified Data.Set               as Set
import qualified Data.Text              as Text
import qualified Database.SQLite.Simple as SQLite
import           System.Directory       (getTemporaryDirectory)
import           System.FilePath        ((</>))
import           Test.Hspec

import qualified Tox.Application.Tox    as Tox

import           Tox.Android.Model
import           Tox.Android.Sample
import           Tox.Android.Store

-- | Store of the active account, with each event saved as it happens.
saved :: [Event] -> IO Store
saved events = open Nothing ":memory:" >>= \database -> savedIn database events

savedIn :: Database -> [Event] -> IO Store
savedIn database events = do
  store <- profileStore database <$> activeProfile database
  foldM_ (\old event -> let new = fst (update event old) in new <$ save store old new)
    initial events
  pure store

spec :: Spec
spec = do
  it "keeps the profile, friends, requests and chats" $ do
    model <- load =<< saved history
    model `shouldBe` sample
      { modelProfile = (modelProfile sample) { profileToxId = "" }
      , modelProfileId = modelProfileId model
      , modelProfiles = [Account (modelProfileId model) "Tox User" ""]
      , modelConnection = Offline
      , modelJump = 0
      , modelContacts = (\c -> c { contactOnline = False }) <$> modelContacts sample
      }

  it "keeps our pending request and the rejected ones" $ do
    let address = toxId (Text.replicate 8 "0123ABCD") "DEADBEEF"
        events = history ++ [Open AddContact, AddressChanged address, AddFriend, Reject carol]
    model <- load =<< saved events
    contactRequest <$> Map.lookup (ContactId (Text.take 64 address)) (modelContacts model)
      `shouldBe` Just (Just (address, "Hey, I'm Tox User, come chat with me on Tox!"))
    Map.keys (modelDeclined model) `shouldBe` [carol]

  it "keeps status messages, mutes, and chats kept of deleted contacts" $ do
    let events = history ++
          [ FriendStatusMessage alice "Busy day", MuteChat alice (Just (at 9 0 0))
          , Open (Chat bob), DraftChanged "hi", Send (at 3 9 0), DeleteContact bob True ]
    model <- load =<< saved events
    (contactStatusMessage <$> Map.lookup alice (modelContacts model)) `shouldBe` Just "Busy day"
    (contactMute <$> Map.lookup alice (modelContacts model)) `shouldBe` Just (Just (MutedUntil (at 9 0 0)))
    map messageText . contactMessages <$> Map.lookup bob (modelFormer model) `shouldBe` Just ["hi"]
    gone <- load =<< saved (events ++ [DeleteContact alice False])
    Map.member alice (modelContacts gone) || Map.member alice (modelFormer gone) `shouldBe` False

  it "keeps their messages as Tox carried them" $ do
    let bytes = "hi" <> BS.pack (0 : 0 : replicate 36 1)
    model <- load =<< saved (history ++ [Received alice (at 3 9 0) Tox.MessageAction bytes])
    [ (messageKind m, messageRaw m) | Just c <- [Map.lookup alice (modelContacts model)], m <- drop 3 (contactMessages c) ]
      `shouldBe` [(Tox.MessageAction, Just bytes)]

  it "keeps when our message was delivered" $ do
    model <- load =<< saved history
    (messageDelivered <=< listToMaybe . drop 1 . contactMessages <=< Map.lookup alice) (modelContacts model)
      `shouldBe` Just (at 1 15 16)

  it "keeps settings, new ones taking the default file size" $ do
    fresh <- load =<< saved history
    settingAutoAccept (modelAccount fresh) `shouldBe` 4 * 1024 * 1024
    let device = DeviceSettings False True False False (Just (Tox.Proxy Tox.Socks5Proxy "127.0.0.1" 9050))
    model <- load =<< saved (history ++ [SetAutoAccept 0, SetDevice device, ToggleFormat "message_v3"])
    (modelAccount model, modelDevice model) `shouldBe` (AccountSettings 0 (Set.fromList ["message_v3"]), device)

  it "keeps the pictures we and friends show" $ do
    model <- load =<< saved (history ++ [AvatarPicked "ours", FriendAvatar alice (Just "theirs")])
    ((`Map.lookup` modelAvatars model) =<< modelAvatar model) `shouldBe` Just "ours"
    ((`Map.lookup` modelAvatars model) =<< contactAvatar =<< Map.lookup alice (modelContacts model)) `shouldBe` Just "theirs"

  it "keeps drafts" $ do
    model <- load =<< saved (history ++ [Open (Chat bob), DraftChanged "later"])
    Map.lookup bob (modelDrafts model) `shouldBe` Just "later"

  it "keeps how far a message got" $ do
    let events = history ++ [Open (Chat bob), DraftChanged "hi", Send (at 3 9 0), Delivering bob 0 Sent]
    model <- load =<< saved events
    map messageDelivery . contactMessages <$> Map.lookup bob (modelContacts model)
      `shouldBe` Just [Sent]

  it "keeps how many parts of a message the friend has" $ do
    let events = history ++ [Open (Chat bob), DraftChanged (Text.replicate 3000 "a"), Send (at 3 9 0), Confirmed bob 0 2 (at 3 9 1)]
    model <- load =<< saved events
    map messageParts . contactMessages <$> Map.lookup bob (modelContacts model) `shouldBe` Just [2]

  it "gives each message an ID of its own, which stays when the message changes" $ do
    db <- SQLite.open ":memory:"
    database <- opened db
    let sent = history ++ [Open (Chat bob), DraftChanged "hi", Send (at 3 9 0), DraftChanged "again", Send (at 3 9 1)]
        ContactId key = bob
        ids = SQLite.query db "SELECT id FROM messages WHERE contact = ? ORDER BY place" (SQLite.Only key)
    _ <- savedIn database sent
    first <- ids
    _ <- savedIn database (sent ++ [Delivering bob 0 Sent])
    later <- ids
    map (BS.length . SQLite.fromOnly) first `shouldBe` [32, 32]
    Set.size (Set.fromList (map SQLite.fromOnly first :: [BS.ByteString])) `shouldBe` 2
    later `shouldBe` first

  it "refuses a database of a newer version, leaving it" $ do
    db <- SQLite.open ":memory:"
    SQLite.execute_ db "PRAGMA user_version = 99"
    void (opened db) `shouldThrow` (\(Newer v) -> v == 99)
    SQLite.query_ db "PRAGMA user_version" `shouldReturn` [SQLite.Only (99 :: Int)]

  it "keeps files, and stops those a restart cut off" $ do
    let events = history ++
          [ Open (Chat alice), Attach "/sent/a.png" "a.png" 10 "ours", Send (at 3 9 0)
          , FileOffered alice (Receiving 1) (at 3 9 1) "b.txt" 20 "/received/b.txt" "theirs"
          , FileMoved alice (Receiving 1) 5 ]
    model <- load =<< saved events
    [ (messageText m, f) | m <- maybe [] contactMessages (Map.lookup alice (modelContacts model)), Just f <- [messageFile m] ]
      `shouldBe` [ ("a.png", Attachment 10 "/sent/a.png" 0 Waiting (Just "ours"))
                 , ("b.txt", Attachment 20 "/received/b.txt" 5 Interrupted (Just "theirs")) ]

  it "keeps what is picked for a draft" $ do
    let staged = [StagedFile "/sent/a.png" "a.png" 10 "ours", StagedPlace 1.5 2.5]
    model <- load =<< saved (history ++ [Open (Chat alice), Attach "/sent/a.png" "a.png" 10 "ours", ShareLocation 1.5 2.5])
    Map.lookup alice (modelStaged model) `shouldBe` Just staged

  it "keeps calls" $ do
    let events = history ++
          [ Open (Chat alice), StartCall (at 3 9 0) True, CallPeer alice (at 3 9 0) True, HangUp (at 3 9 2)
          , CallInvited alice (at 3 9 3) False, CallEnded alice (at 3 9 4) ]
    model <- load =<< saved events
    [ c | m <- maybe [] contactMessages (Map.lookup alice (modelContacts model)), Just c <- [messageCall m] ]
      `shouldBe` [CallRecord True (Just 120) False, CallRecord False Nothing True]

  it "keeps each account's chats apart, and which is online" $ do
    database <- open Nothing ":memory:"
    first <- activeProfile database
    _ <- savedIn database history
    second <- newProfile database Nothing (modelProfile initial) { profileNickname = "Other" }
    setActive database second
    other <- load =<< savedIn database [Requested carol "hi"]
    (Map.keys (modelContacts other), Map.keys (modelRequests other)) `shouldBe` ([], [carol])
    map accountName (modelProfiles other) `shouldBe` ["Tox User", "Other"]
    activeProfile database `shouldReturn` second
    deleteProfile database first
    map accountId <$> profiles database `shouldReturn` [second]
    Map.keys . modelContacts <$> load (profileStore database first) `shouldReturn` []

  it "keeps groups with their chats, and invites" $ do
    let dana = Member (Text.replicate 8 "DA7A0000") "Dana"
        events = history ++
          [ Invited alice team NgcGroup "Team" "invite", AnswerInvite alice team True
          , MemberJoined team (at 3 9 0) 1 dana, GroupConnected team (at 3 9 0), GroupSaved team "state"
          , GroupReceived team (at 3 9 1) 1 Tox.MessageAction "waves", DraftChanged "later"
          , TopicChanged team (at 3 9 2) (Just 1) "plans", TopicSetByUs team (at 3 9 3) "ours"
          , MuteGroup team Nothing, ToggleMentions team, ChooseRelayBot team (Just (memberKey dana))
          , PrivateReceived team (at 3 9 4) 1 Tox.MessageNormal "psst"
          , GroupModerated team (at 3 9 5) Nothing (Just 1) Tox.ModObserver
          , GroupModerated team (at 3 9 6) (Just 1) Nothing Tox.ModKick
          , Invited bob (GroupId "C0DE") NgcGroup "Other" "other invite"
          , Invited bob (GroupId "01AB") AudioConference "" "cookie"
          , Invited alice (GroupId "00CD") TextConference "" "text cookie", AnswerInvite alice (GroupId "00CD") True ]
        expected = fst (update (Started "") (applying events initial))
    model <- load =<< saved events
    modelGroups model `shouldBe` modelGroups expected
    modelInvites model `shouldBe` modelInvites expected
    modelGroupDrafts model `shouldBe` Map.fromList [(team, "later")]

  it "keeps a linked account's settings and what waits to go" $ do
    database <- open Nothing ":memory:"
    store <- profileStore database <$> newLinkedProfile database (Text.replicate 76 "A") "pairing" (at 3 9 0)
    linked <- load store
    let events = [SetAutoAccept 0, Open (Chat alice), ShareLocation 1 2]
    foldM_ (\old event -> let new = fst (update event old) in new <$ save store old new) linked events
    model <- load store
    (settingAutoAccept (modelAccount model), Map.lookup alice (modelStaged model))
      `shouldBe` (0, Just [StagedPlace 1 2])

  it "backs up the chosen profiles and restores those it doesn't have" $ do
      backup <- (</> "htox-backup-test.sqlite") <$> getTemporaryDirectory
      let events = history ++
            [ Open (Chat alice), Attach "/sent/a.png" "a.png" 10 "ours", Send (at 3 9 0) ]
      here <- open Nothing ":memory:"
      first <- activeProfile here
      store <- savedIn here events
      saveIdentity store (Identity "key" 1)
      _ <- newProfile here Nothing (modelProfile initial) { profileNickname = "Other" }
      backUp here [first] backup
      restore here backup `shouldReturn` []
      phone <- open Nothing ":memory:"
      _ <- activeProfile phone
      [new] <- restore phone backup
      map accountName <$> profiles phone `shouldReturn` ["Tox User", "Tox User"]
      model <- load (profileStore phone new)
      identity (profileStore phone new) `shouldReturn` Just (Identity "key" 1)
      Map.keys (modelContacts model) `shouldBe` Map.keys (modelContacts sample)
      -- The phone doesn't have our file.
      [ attachmentState f | m <- maybe [] contactMessages (Map.lookup alice (modelContacts model)), Just f <- [messageFile m] ]
        `shouldBe` [Cancelled]

  it "keeps whether we are away" $ do
    model <- load =<< saved (history ++ [AwayChosen Tox.Busy])
    profileAway (modelProfile model) `shouldBe` Tox.Busy

  it "keeps who we are" $ do
    database <- open Nothing ":memory:"
    store <- profileStore database <$> activeProfile database
    identity store `shouldReturn` Nothing
    saveIdentity store (Identity "key" 0xDEADBEEF)
    identity store `shouldReturn` Just (Identity "key" 0xDEADBEEF)
