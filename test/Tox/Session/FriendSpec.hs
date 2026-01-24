{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Session.FriendSpec (spec) where

import           Control.Monad                      (void)
import           Data.Bits                          (xor)
import qualified Data.ByteString                    as BS
import qualified Data.Map                           as Map
import           Data.Word                          (Word32)
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Application.AppTest            (runApp)
import qualified Tox.Core.Schedule                  as Schedule
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Timed                     (askTime)
import           Tox.Crypto.Core.Key                (PublicKey)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Onion.Operation                as Onion
import           Tox.Session.Friend

spec :: Spec
spec = do
  describe "a friend's work" $ do
    it "is due only while the friend has some" $ property $ \pk -> ioProperty $ do
      let due = getsMessenger (Schedule.dueBy (Working pk) . messengerJobs)
      runApp $ do
        now <- askTime
        addFriend pk
        added <- due
        -- With no session, our info can't go yet.
        void $ setOnline pk True
        online <- due
        void $ setOnline pk False
        void runDue
        offline <- due
        return $ (added, online, offline) === (Nothing, Just now, Nothing)

    it "sends a friend request once nodes store the friend, and again after its timeout" $
      property $ \pk holder dataPk at -> ioProperty $ do
        let due = getsMessenger (Schedule.dueBy (Request pk) . messengerJobs)
            stored = (Onion.newOnionNode (NodeInfo UDP at holder)) { Onion.onStatus = Onion.StoresFriend dataPk }
        runApp $ do
          now <- askTime
          void $ addFriendWithRequest pk "nospam" "hi"
          void runDue
          unheld <- due
          Onion.modifyOnion $ \o -> o { Onion.onionFriends =
            Map.adjust (\f -> f { Onion.ofNodes = Map.singleton holder stored }) pk (Onion.onionFriends o) }
          friendReachable pk
          reachable <- due
          void runDue
          sent <- due
          return $ (unheld, reachable, sent) === (Nothing, Just now, Just (Time.addTime now friendRequestTimeout))

  describe "Tox ID" $ do
    it "parses back to the public key and nospam" $ property $
      \(pk :: PublicKey) (nospam :: Word32) ->
        let m = initMessenger nospam
        in parseToxId (toxId pk m) `shouldBe` Just (pk, nospamBytes m)

    it "is rejected if any byte changed" $ property $
      \(pk :: PublicKey) (nospam :: Word32) (NonNegative i) (NonZero x) ->
        let bytes = toxId pk (initMessenger nospam)
            j = i `mod` BS.length bytes
            changed = BS.take j bytes <> BS.singleton (BS.index bytes j `xor` x) <> BS.drop (j + 1) bytes
        in parseToxId changed `shouldBe` Nothing

  describe "file chunks" $ do
    it "are counted for a stream of unknown size" $
      chunksBetween 0 maxBound `shouldSatisfy` (> 0)

    it "are shared out between transfers in turn" $
      roundRobin 5 [10, 1, 10] `shouldBe` [2, 1, 2]
