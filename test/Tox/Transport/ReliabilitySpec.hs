{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Transport.ReliabilitySpec where

import qualified Data.ByteString           as BS
import           Data.List                 (foldl', sortOn)
import qualified Data.Map                  as Map
import           Data.Maybe                (fromJust, fromMaybe, isNothing)
import qualified Data.Set                  as Set
import           Data.Word                 (Word8)
import           Test.Hspec
import           Test.QuickCheck

import qualified Tox.Core.Time             as Time
import           Tox.Transport.Reliability

-- | Sent @n@ packets at time 0.
sender :: Int -> ReliabilityState
sender n = foldl' send initState [1 .. n]
  where
    send rs i =
      let (num, rs') = fromJust $ addSent (BS.singleton $ fromIntegral i) rs
      in markSent (Time.fromSeconds 0) num rs'

spec :: Spec
spec = do
  describe "receiving" $ do
    it "delivers packets in order once the gap is filled" $ do
      let s1 = fromJust $ addReceived 1 "b" initState
          (d1, s1') = takeReceived s1
          s2 = fromJust $ addReceived 0 "a" s1'
          (d2, _) = takeReceived s2
      d1 `shouldBe` []
      d2 `shouldBe` ["a", "b"]

    it "rejects duplicates" $ do
      let s1 = fromJust $ addReceived 3 "x" initState
      addReceived 3 "x" s1 `shouldBe` Nothing

  describe "request packets" $
    it "make the sender resend exactly the missing packets" $
      property $ \(Positive n') (received :: [Int]) ->
        let n = n' `mod` 1000 + 1
            got = Set.fromList $ map (`mod` n) received
            recv = fromJust $ setReceivedEnd (fromIntegral n) $
              foldl' (\rs i -> fromJust $ addReceived (fromIntegral i) "x" rs) initState (Set.toList got)
            request = requestPacket maxCryptoDataSize recv
            sent' = fst . fromJust $ handleRequest (Time.fromSeconds 10) (Time.seconds 1) request (sender n)
            missing = [fromIntegral i | i <- [0 .. n - 1], Set.notMember i got]
        in map fst (unsentPackets sent') `shouldBe` missing

  describe "the packets still to send" $
    it "are kept in step with the buffer, in order, as numbers wrap round" $
      property $ \(Small below :: Small Int) (steps :: [(Int, Int, [Word8])]) ->
        let start = maxBound - fromIntegral (below `mod` 8)
            begun = initState { rsSend = PacketsArray start start Map.empty }
            rs = foldl' step begun steps
            send = rsSend rs
            unsent = [ k | (k, p) <- Map.toList (paPackets send), isNothing (spSentTime p) ]
        in (rsUnsent rs, map fst (unsentPackets rs))
           `shouldBe` (Set.fromList unsent, sortOn (subtract (paStart send)) unsent)

  describe "data packet contents" $
    it "round-trip with padding" $
      property $ \start num (NonEmpty bytes) ->
        let payload = BS.pack $ 16 : bytes
        in decodeData (encodeData start num payload) `shouldBe` Just (start, num, payload)

-- | Adds, sends, gets acknowledged, or gets a request, at some position in the
-- buffer. Requests ask for packets close together, so they hit some.
step :: ReliabilityState -> (Int, Int, [Word8]) -> ReliabilityState
step rs (kind, at, bytes) = case kind `mod` 4 of
  0 -> maybe rs snd (addSent "x" rs)
  1 -> markSent (Time.fromSeconds 0) (position len) rs
  2 -> fromMaybe rs (clearSentUntil (position (len + 1)) rs)
  _ -> maybe rs fst (handleRequest (Time.fromSeconds 10) (Time.seconds 1) (BS.pack (packetIdRequest : map ((+ 1) . (`mod` 3)) bytes)) rs)
  where
    len = arrayLength (rsSend rs)
    position n = paStart (rsSend rs) + fromIntegral at `mod` max 1 n
