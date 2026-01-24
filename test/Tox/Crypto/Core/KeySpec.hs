{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
{-# LANGUAGE Trustworthy         #-}
module Tox.Crypto.Core.KeySpec where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Exception             (evaluate)
import           Control.Monad.Validate        (MonadValidate, runValidate)
import qualified Crypto.Saltine.Class          as Sodium
import           Data.Binary                   (Binary)
import           Data.Bits                     (xor)
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as ByteString
import           Data.List                     (foldl')
import           Data.MessagePack              (DecodeError, errorMessages)
import           Data.Proxy                    (Proxy (..))
import           Data.Typeable                 (Typeable)
import           System.Mem                    (getAllocationCounter)
import qualified Text.Read                     as Read
import           Tox.Core.TypeName             (typeName)
import qualified Tox.Crypto.Core.Key           as Key
import           Tox.Crypto.Core.Key           (Key, PublicKey)
import           Tox.Network.Core.EncodingSpec


readMaybe :: String -> Maybe Key.PublicKey
readMaybe = Read.readMaybe


decodeM :: MonadValidate DecodeError m => ByteString -> m Key.PublicKey
decodeM = Key.decode


keyToInteger :: String -> Integer
keyToInteger string =
  Key.keyToInteger (read string :: Key.PublicKey)


encodeDecodePublicKey :: Key.PublicKey -> Expectation
encodeDecodePublicKey key =
  Sodium.decode (Sodium.encode key) `shouldBe` Just key


localEncodingSpec
  :: (Typeable a, Read a, Show a, Binary a, Arbitrary a, Eq a)
  => Proxy a -> Spec
localEncodingSpec proxy =
  describe (typeName proxy) $ do
    binarySpec proxy
    readShowSpec proxy


spec :: Spec
spec = do
  -- PublicKey for RPC tests.
  rpcSpec (Proxy :: Proxy Key.PublicKey)

  -- All others only local tests.
  localEncodingSpec (Proxy :: Proxy Key.CombinedKey)
  localEncodingSpec (Proxy :: Proxy Key.Nonce)
  localEncodingSpec (Proxy :: Proxy Key.PublicKey)
  localEncodingSpec (Proxy :: Proxy Key.SecretKey)

  describe "IsEncoding" $
    it "decodes encoded public keys correctly" $
      property encodeDecodePublicKey

  describe "read" $ do
    it "decodes valid hex string to PublicKey" $
      let
        actual = readMaybe "\"0100000000000000000000000000000000000000000000000000000000000010\""
        Just expected = Sodium.decode $ ByteString.pack [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10]
      in
      actual `shouldBe` Just (expected :: PublicKey)

    it "decodes empty string to Nothing" $ do
      let actual = readMaybe ""
      actual `shouldBe` Nothing
      case runValidate $ decodeM ByteString.empty of
        Left msg -> errorMessages msg `shouldBe` ["unable to decode ByteString to Key: 0"]
        Right val -> expectationFailure $ "unexpected success: " ++ show val

    it "decodes valid hex string of wrong length to Nothing" $
      let actual = readMaybe "\"0110\"" in
      actual `shouldBe` Nothing

  describe "keyToInteger" $ do
    it "converts keys to Integer in big endian" $ do
      keyToInteger "\"fe00000000000000000000000000000000000000000000000000000000000000\""
        `shouldBe`  0xfe00000000000000000000000000000000000000000000000000000000000000
      keyToInteger "\"00000000000000000000000000000000000000000000000000000000000000fe\""
        `shouldBe`  0x00000000000000000000000000000000000000000000000000000000000000fe

    it "encodes all keys to positive Integers" $
      property $ \key ->
        Key.keyToInteger (key :: Key.PublicKey) `shouldSatisfy` (0 <=)

    it "reads every byte, the first as the most significant" $
      property $ \pk nonce ->
        let bigEndian = ByteString.foldl' (\n w -> n * 256 + toInteger w) 0
        in (Key.keyToInteger (pk :: Key.PublicKey), Key.keyToInteger (nonce :: Key.Nonce))
          `shouldBe` (bigEndian (Sodium.encode pk), bigEndian (Sodium.encode nonce))

    -- The DHT works out distances between keys all the time.
    it "allocates little" $ do
      keys <- generate (vector 1000) :: IO [Key.PublicKey]
      _ <- evaluate (foldr seq () keys)
      start <- getAllocationCounter
      _ <- evaluate (foldl' (\n k -> n `xor` Key.keyToInteger k) 0 keys)
      end <- getAllocationCounter
      -- Per key. Reading it through Binary took over 10 KB.
      (start - end) `div` 1000 `shouldSatisfy` (< 2000)
