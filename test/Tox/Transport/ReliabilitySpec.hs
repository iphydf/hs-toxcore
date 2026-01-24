{-# LANGUAGE OverloadedStrings #-}
module Tox.Transport.ReliabilitySpec where

import qualified Data.ByteString           as BS
import qualified Data.Map                  as Map
import           Test.Hspec
import           Tox.Transport.Reliability

spec :: Spec
spec = do
  describe "Sequence Numbers" $ do
    it "handles basic comparison" $ do
      SeqNum 1 < SeqNum 2 `shouldBe` True
      SeqNum 2 > SeqNum 1 `shouldBe` True

    it "handles rollover comparison" $ do
      SeqNum 0xFFFFFFFF < SeqNum 0 `shouldBe` True
      SeqNum 0 > SeqNum 0xFFFFFFFF `shouldBe` True
      SeqNum 0xFFFFFFFE < SeqNum 1 `shouldBe` True

  describe "Reliability Logic" $ do
    let s0 = initState

    it "extracts contiguous packets" $ do
      let window = Map.fromList [(SeqNum 0, "a"), (SeqNum 1, "b"), (SeqNum 3, "d")]
          (deliverable, remaining, next) = extractDeliverable 0 window
      deliverable `shouldBe` ["a", "b"]
      Map.keys remaining `shouldBe` [SeqNum 3]
      next `shouldBe` SeqNum 2

    it "handles incoming out-of-order packets" $ do
      let p1 = ReliablePacket 0 1 True "b"
          (s1, d1) = handleIncoming p1 s0
      d1 `shouldBe` []
      rsNextRecvSeq s1 `shouldBe` 0
      Map.keys (rsRecvWindow s1) `shouldBe` [SeqNum 1]

      let p0 = ReliablePacket 0 0 True "a"
          (s2, d2) = handleIncoming p0 s1
      d2 `shouldBe` ["a", "b"]
      rsNextRecvSeq s2 `shouldBe` 2
      Map.keys (rsRecvWindow s2) `shouldBe` []

    it "clears send window on peer ACKs" $ do
      let (_, s1) = createLossless "msg1" s0
          (_, s2) = createLossless "msg2" s1
          p = ReliablePacket 1 0 True "ack" -- Peer says they received up to 1
          (s3, _) = handleIncoming p s2
      Map.keys (rsSendWindow s3) `shouldBe` [SeqNum 1]
