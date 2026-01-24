{-# LANGUAGE OverloadedStrings #-}
module Tox.Transport.StreamSpec where

import           Data.Maybe                (isJust)
import           Test.Hspec
import qualified Tox.Core.Time             as Time
import           Tox.Transport.Reliability (SeqNum (..))
import           Tox.Transport.Stream

spec :: Spec
spec = do
  let t0 = Time.Timestamp 0
      t1s = t0 `Time.addTime` Time.seconds 1
      t12s = t0 `Time.addTime` Time.milliseconds 1200
      t2s = t0 `Time.addTime` Time.seconds 2
      t3s = t0 `Time.addTime` Time.seconds 3

  describe "RTT tracking" $ do
    it "updates RTT on ACK" $ do
      let s0 = initState t0
          s1 = recordPacketSent 1 t0 s0
          s2 = recordPacketAcked 1 t1s s1
      ssLastRTT s2 `shouldBe` Just (Time.seconds 1)
      ssMinRTT s2 `shouldBe` Just (Time.seconds 1)

    it "tracks minimum RTT" $ do
      let s0 = initState t0
          s1 = recordPacketSent 1 t0 s0
          s2 = recordPacketAcked 1 t2s s1 -- RTT 2s
          s3 = recordPacketSent 2 t2s s2
          s4 = recordPacketAcked 2 t3s s3 -- RTT 1s
      ssMinRTT s4 `shouldBe` Just (Time.seconds 1)
      ssLastRTT s4 `shouldBe` Just (Time.seconds 1)

  describe "Send Rate Calculation" $ do
    it "starts at 8.0" $ do
      ssCurrentSendRate (initState t0) `shouldBe` 8.0

    it "ignores updates before 1.2s" $ do
      let s0 = initState t0
          s1 = recordPacketSent 1 t0 s0
          s2 = updateSendRate 1 t1s s1
      ssCurrentSendRate s2 `shouldBe` 8.0

    it "calculates rate based on throughput" $ do
      let s0 = initState t0
          -- Q_prev = 0
          -- Sent 24 packets in 1.2s
          -- Q_now = 0
          -- Throughput = (24 - 0) / 1.2 = 20.0
          s1 = foldr (\s acc -> recordPacketSent (SeqNum s) t0 acc) s0 [1..24]
          s2 = recordCongestion t0 s1 -- Force recently congested to avoid 1.25x
          s3 = updateSendRate 0 t12s s2
      ssCurrentSendRate s3 `shouldBe` 20.0

    it "applies 1.25x increase when no congestion" $ do
      let s0 = initState t0
          -- Throughput = 10.0 (12 sent / 1.2s)
          -- No congestion recently -> 10.0 * 1.25 = 12.5
          s1 = foldr (\s acc -> recordPacketSent (SeqNum s) t0 acc) s0 [1..12]
          s2 = updateSendRate 0 t12s s1
      ssCurrentSendRate s2 `shouldBe` 12.5

    it "applies floor of 8.0" $ do
      let s0 = initState t0
          -- Throughput = 1.0 (1.2 sent / 1.2s)
          -- Recently congested -> floor to 8.0
          s1 = recordPacketSent 1 t0 s0
          s2 = recordCongestion t0 s1
          s3 = updateSendRate 0 t12s s2
      ssCurrentSendRate s3 `shouldBe` 8.0
