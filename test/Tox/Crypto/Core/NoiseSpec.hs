{-# LANGUAGE OverloadedStrings #-}
module Tox.Crypto.Core.NoiseSpec (spec) where

import qualified Crypto.Saltine.Class                          as Sodium
import qualified Crypto.Saltine.Core.AEAD.ChaCha20Poly1305IETF as IETF
import           Data.ByteString                               (ByteString)
import qualified Data.ByteString                               as BS
import qualified Data.ByteString.Base16                        as Base16
import           Data.Maybe                                    (fromJust)
import           Test.Hspec

import           Tox.Crypto.Core.Key                           (PublicKey,
                                                                SecretKey)
import qualified Tox.Crypto.Core.KeyPair                       as KeyPair
import           Tox.Crypto.Core.Noise

hex :: ByteString -> ByteString
hex = either error id . Base16.decode

secret :: ByteString -> SecretKey
secret = fromJust . Sodium.decode . hex

public :: SecretKey -> PublicKey
public = KeyPair.publicKey . KeyPair.fromSecretKey

-- | Standard Noise transport: ChaChaPoly, nonce 0, no associated data.
transport :: CipherKey -> ByteString -> ByteString
transport key plain = IETF.aead
  (fromJust . Sodium.decode $ cipherKeyBytes key)
  (fromJust . Sodium.decode $ BS.replicate 12 0)
  plain BS.empty

-- | Noise_IK_25519_ChaChaPoly_BLAKE2b from noise-c's tests/vector/noise-c-basic.txt,
-- as c-toxcore's noise_test.cc uses it.
spec :: Spec
spec = describe "Noise IK" $ do
  let prologue = hex "50726f6c6f677565313233"
      initStatic = secret "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
      initEphemeral = secret "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
      respStatic = secret "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
      respEphemeral = secret "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"

  it "gives the test vectors' messages, handshake hash and transport keys" $ do
    Sodium.encode (public respStatic)
      `shouldBe` hex "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"
    Sodium.encode (public initEphemeral)
      `shouldBe` hex "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"

    -- -> e, es, s, ss
    let i0 = mixHash (Sodium.encode $ public initEphemeral) $ initialize prologue (public respStatic)
        (i1, kEs) = fromJust $ mixKey initEphemeral (public respStatic) i0
        (encStatic, i2) = encryptAndHash kEs (Sodium.encode $ public initStatic) i1
        (i3, kSs) = fromJust $ mixKey initStatic (public respStatic) i2
        (encPayload1, i4) = encryptAndHash kSs (hex "4c756477696720766f6e204d69736573") i3
    encStatic `shouldBe` hex "ba83a447b38c83e327ad936929812f624884847b7831e95e197b2f797088efdd232fe541af156ec6d0657602902a8c3e"
    encPayload1 `shouldBe` hex "e64e470f4b6fcd9298ce0b56fe20f86e60d9d933ec6e103ffb09e6001d6abb64"

    -- The responder reads it.
    let r0 = mixHash (Sodium.encode $ public initEphemeral) $ initialize prologue (public respStatic)
        (r1, rEs) = fromJust $ mixKey respStatic (public initEphemeral) r0
        (peerStatic, r2) = fromJust $ decryptAndHash rEs encStatic r1
    peerStatic `shouldBe` Sodium.encode (public initStatic)
    let (r3, rSs) = fromJust $ mixKey respStatic (fromJust $ Sodium.decode peerStatic) r2
        (payload1, r4) = fromJust $ decryptAndHash rSs encPayload1 r3
    payload1 `shouldBe` hex "4c756477696720766f6e204d69736573"
    r4 `shouldBe` i4

    -- <- e, ee, se
    Sodium.encode (public respEphemeral)
      `shouldBe` hex "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
    let r5 = mixHash (Sodium.encode $ public respEphemeral) r4
        (r6, _) = fromJust $ mixKey respEphemeral (public initEphemeral) r5
        (r7, rSe) = fromJust $ mixKey respEphemeral (public initStatic) r6
        (encPayload2, r8) = encryptAndHash rSe (hex "4d757272617920526f746862617264") r7
    encPayload2 `shouldBe` hex "9f069b267a06b3de3ecb1043bcb09807c6cd101f3826192a65f11ef3fe4317"

    let i5 = mixHash (Sodium.encode $ public respEphemeral) i4
        (i6, _) = fromJust $ mixKey initEphemeral (public respEphemeral) i5
        (i7, iSe) = fromJust $ mixKey initStatic (public respEphemeral) i6
        (payload2, i8) = fromJust $ decryptAndHash iSe encPayload2 i7
    payload2 `shouldBe` hex "4d757272617920526f746862617264"
    symHash i8 `shouldBe` hex "00e51d2aac81a9b8ebe441d6af3e1c8efc0f030cc608332edcb42588ff6a0ce26415ddc106e95277a5e6d54132f1e5245976b89caf96d262f1fe5a7f0c55c078"
    i8 `shouldBe` r8

    let (initSend, respSend) = split i8
    transport initSend (hex "462e20412e20486179656b")
      `shouldBe` hex "cd54383060e7a28434cca27fb1cc524cfbabeb18181589df219d07"
    transport respSend (hex "4361726c204d656e676572")
      `shouldBe` hex "a856d3bf0246bfc476c655009cd1ed677b8dcc5b349ae8ef2a05f2"
    split r8 `shouldBe` split i8

  it "rejects a DH with a low-order point" $
    fmap fst (mixKey initStatic (fromJust . Sodium.decode $ BS.replicate 32 0) (initialize prologue (public respStatic)))
      `shouldBe` Nothing

  it "doesn't open a message changed in transit" $ do
    let s = initialize prologue (public respStatic)
        (_, key) = fromJust $ mixKey initStatic (public respStatic) s
        (cipher, _) = encryptAndHash key "payload" s
    fmap fst (decryptAndHash key (BS.map (+ 1) cipher) s) `shouldBe` Nothing
