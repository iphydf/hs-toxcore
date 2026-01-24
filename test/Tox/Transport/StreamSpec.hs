module Tox.Transport.StreamSpec (spec) where

import           Control.Exception    (evaluate)
import           Data.List            (foldl')
import           Test.Hspec

import qualified Tox.Core.Time        as Time
import           Tox.Evaluated        (fullyEvaluated)
import           Tox.Transport.Stream

-- | Samples 50 ms apart, with the same number of new packets before each and
-- the same send queue length.
steady :: Int -> Int -> Congestion -> Congestion
steady perSample queue cc0 = foldl' step cc0 [1 .. 13]
  where
    step cc i = sample 0 queue False (Time.fromMillis (50 * i)) (iterate sentNew cc !! perSample)

spec :: Spec
spec = describe "congestion control" $ do
  it "keeps its samples evaluated, so they hold no older ones" $ do
    cc <- evaluate $ sample 0 5 True (Time.fromMillis 1000) (steady 3 5 initState)
    lists <- mapM evaluate [ccQueueSizes cc, ccSentHistory cc, ccResentHistory cc]
    and <$> mapM fullyEvaluated lists `shouldReturn` True

  it "sends a fifth faster than it measured" $
    ccSendRate (steady 3 0 initState) `shouldBe` 72

  it "sends a tenth slower within a second of a congestion event" $
    ccSendRate (steady 3 0 initState { ccLastCongestion = Just (Time.fromMillis 600) }) `shouldBe` 54

  it "slows down while the send queue holds more than two seconds" $
    ccSendRate (steady 3 300 initState) `shouldBe` 24

  it "refills its budget at the send rate, at most four samples' worth ahead" $ do
    let start = refill (Time.fromMillis 0) initState { ccSendRate = 72 }
    ccPacketsLeft start `shouldBe` minQueue
    ccPacketsLeft (refill (Time.fromMillis 100) start) `shouldBe` minQueue + 7
    ccPacketsLeft (refill (Time.fromMillis 1000) start) `shouldBe` minQueue + 4 * 4

  -- A session doesn't refill while it rests.
  it "has the same budget after a quiet spell as if it had refilled all along" $ do
    let start = refill (Time.fromMillis 0) initState { ccSendRate = 72, ccResendRate = 72 }
        budget cc = (ccPacketsLeft cc, ccResendsLeft cc)
        often = foldl' (flip refill) start (map (Time.fromMillis . (* 50)) [1 .. 1200])
    budget (refill (Time.fromMillis 60000) start) `shouldBe` budget often

  it "counts resending its whole budget as a congestion event" $ do
    let cc = refill (Time.fromMillis 0) initState
        now = Time.fromMillis 10
    ccLastCongestion (resent now 10 cc) `shouldBe` Nothing
    ccPacketsLeft (resent now 10 cc) `shouldBe` minQueue - 10
    ccLastCongestion (resent now minQueue cc) `shouldBe` Just now
