{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Core.BitsSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import qualified Data.Binary.Get      as B
import qualified Data.Binary.Put      as B
import qualified Data.ByteString.Lazy as LBS
import           Data.Word

import           Tox.Core.Bits
import           Tox.Core.Bits.Get
import           Tox.Core.Bits.Put

spec :: Spec
spec = do
  describe "BinaryBit" $ do
    it "roundtrips Bool" $ property $
      \(b :: Bool) ->
        let bs = LBS.toStrict $ B.runPut (runBitPut $ putBits 1 b)
            res = B.runGet (runBitGet $ getBits 1) (LBS.fromStrict bs)
        in res `shouldBe` b

    it "roundtrips Word8" $ property $
      \(w :: Word8) ->
        let bs = LBS.toStrict $ B.runPut (runBitPut $ putBits 8 w)
            res = B.runGet (runBitGet $ getBits 8) (LBS.fromStrict bs)
        in res `shouldBe` w

    it "roundtrips Word16" $ property $
      \(w :: Word16) ->
        let bs = LBS.toStrict $ B.runPut (runBitPut $ putBits 16 w)
            res = B.runGet (runBitGet $ getBits 16) (LBS.fromStrict bs)
        in res `shouldBe` w

    it "roundtrips Word32" $ property $
      \(w :: Word32) ->
        let bs = LBS.toStrict $ B.runPut (runBitPut $ putBits 32 w)
            res = B.runGet (runBitGet $ getBits 32) (LBS.fromStrict bs)
        in res `shouldBe` w

    it "roundtrips Word64" $ property $
      \(w :: Word64) ->
        let bs = LBS.toStrict $ B.runPut (runBitPut $ putBits 64 w)
            res = B.runGet (runBitGet $ getBits 64) (LBS.fromStrict bs)
        in res `shouldBe` w
