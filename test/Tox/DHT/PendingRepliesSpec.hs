{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData   #-}
{-# LANGUAGE Trustworthy  #-}
module Tox.DHT.PendingRepliesSpec where

import           Control.Exception      (evaluate)
import           System.Timeout         (timeout)
import           Test.Hspec
import           Test.QuickCheck

import qualified Tox.Core.Time          as Time
import           Tox.DHT.PendingReplies as PendingReplies
import           Tox.DHT.RpcPacket      (RequestId (..))

spec :: Spec
spec = do
  it "Accepts a response with the same RequestID iff sent since the cutoff" $
    property $ \time time' node requestID ->
      let
        expecting = PendingReplies.expectReply time node requestID PendingReplies.empty
      in
        fst (PendingReplies.checkExpectedReply time' node requestID expecting)
        `shouldBe` time' <= time

  it "Rejects a response with a different requestID" $
    property $ \time node requestID requestID' ->
      let
        expecting = PendingReplies.expectReply time node requestID PendingReplies.empty
      in
        fst (PendingReplies.checkExpectedReply time node requestID' expecting)
        `shouldBe` requestID == requestID'

  it "Doesn't accept the same response twice" $
    property $ \time node requestID ->
      let
        expecting = PendingReplies.expectReply time node requestID PendingReplies.empty
        accepted  = snd $ PendingReplies.checkExpectedReply time node requestID expecting
      in
        fst (PendingReplies.checkExpectedReply time node requestID accepted)
        `shouldBe` False

  it "keeps up while many wait, as in a busy DHT" $ do
    node <- generate arbitrary
    -- A request each millisecond, with the reply to the one 50 s before, and
    -- those older than a minute forgotten.
    let n = 100000 :: Int
        at = Time.fromMillis . fromIntegral
        go !waiting !accepted i
          | i > n = accepted
          | otherwise =
              let asked = PendingReplies.expectReply (at i) node (RequestId (fromIntegral i)) waiting
                  kept = PendingReplies.dropOlder (at (i - 60000)) asked
                  (ok, waiting') = PendingReplies.checkExpectedReply (at 0) node (RequestId (fromIntegral (i - 50000))) kept
              in go waiting' (accepted + fromEnum ok) (i + 1)
    timeout 5000000 (evaluate (go PendingReplies.empty 0 1)) `shouldReturn` Just (n - 50000)
