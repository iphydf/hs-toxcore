{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Core.Bits.PutSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck      hiding ((.&.))

import qualified Data.Binary.Get      as G
import qualified Data.Binary.Put      as B
import           Data.Bits            ((.&.))
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as LBS
import           Data.Word

import           Tox.Core.Bits.Get    as TG
import           Tox.Core.Bits.Put

spec :: Spec
spec = do
  describe "BitPut" $ do
    it "can put a bool" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putBool True)
      in bs `shouldBe` BS.pack [0x80]

    it "can put multiple bools" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putBool True >> putBool False >> putBool True)
      in bs `shouldBe` BS.pack [0xA0] -- 1010 0000

    it "can put word8" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putWord8 4 7)
      in bs `shouldBe` BS.pack [0x70]

    it "can put across byte boundaries" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putWord8 4 0x0F >> putWord8 8 0xAA)
      in bs `shouldBe` BS.pack [0xFA, 0xA0] -- 1111 1010, 1010 0000

    it "can put word16be" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putWord16be 16 0x1234)
      in bs `shouldBe` BS.pack [0x12, 0x34]

    it "can put word32be" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putWord32be 32 0x12345678)
      in bs `shouldBe` BS.pack [0x12, 0x34, 0x56, 0x78]

    it "can put word64be" $
      let bs = LBS.toStrict $ B.runPut (runBitPut $ putWord64be 64 0x123456789ABCDEF0)
      in bs `shouldBe` BS.pack [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]

  describe "Roundtrip" $ do
    it "puts and gets correctly" $ property $
      \(w1 :: Word8, w2 :: Word16, w3 :: Word32) ->
        let putter = do
              putWord8 4 (w1 .&. 0x0F)
              putWord16be 12 (w2 .&. 0x0FFF)
              putWord32be 20 (w3 .&. 0x000FFFFF)
            getter = do
              v1 <- getWord8 4
              v2 <- getWord16be 12
              v3 <- getWord32be 20
              return (v1, v2, v3)
            bs = LBS.toStrict $ B.runPut (runBitPut putter)
            (r1, r2, r3) = G.runGet (TG.runBitGet getter) (LBS.fromStrict bs)
        in (r1, r2, r3) `shouldBe` (w1 .&. 0x0F, w2 .&. 0x0FFF, w3 .&. 0x000FFFFF)
