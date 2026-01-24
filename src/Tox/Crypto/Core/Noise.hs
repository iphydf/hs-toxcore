{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | The parts of Noise_IK_25519_ChaChaPoly_BLAKE2b that the Tox handshake
-- uses: the symmetric state, its HKDF and Split. Every 'mixKey' makes a new
-- key that encrypts once, so the AEAD nonce is always 0.
module Tox.Crypto.Core.Noise
  ( CipherKey
  , Symmetric (..)
  , blake2b
  , hkdf
  , initialize
  , mixHash
  , mixKey
  , encryptAndHash
  , decryptAndHash
  , split
  , encryptTransport
  , decryptTransport
  , cipherKeyBytes
  , cipherKeyFromBytes
  ) where

import qualified Crypto.Saltine.Class                          as Sodium
import qualified Crypto.Saltine.Core.AEAD.ChaCha20Poly1305IETF as IETF
import qualified Crypto.Saltine.Core.AEAD.XChaCha20Poly1305    as XChaCha
import qualified Crypto.Saltine.Core.Hash                      as Hash
import qualified Crypto.Saltine.Internal.ScalarMult            as ScalarMult
import           Data.Bits                                     (xor)
import           Data.ByteString                               (ByteString)
import qualified Data.ByteString                               as BS
import           Data.Maybe                                    (fromMaybe)
import           Foreign.Marshal.Alloc                         (allocaBytes)
import           System.IO.Unsafe                              (unsafeDupablePerformIO)

import           Tox.Crypto.Core.Key                           (Nonce,
                                                                PublicKey,
                                                                SecretKey)

-- | A 32-byte ChaCha20-Poly1305 key.
newtype CipherKey = CipherKey ByteString
  deriving (Eq)

instance Show CipherKey where
  show _ = "CipherKey <hidden>"

cipherKeyBytes :: CipherKey -> ByteString
cipherKeyBytes (CipherKey k) = k

cipherKeyFromBytes :: ByteString -> Maybe CipherKey
cipherKeyFromBytes k
  | BS.length k == keyLength = Just $ CipherKey k
  | otherwise = Nothing

-- | The handshake hash @h@ and chaining key @ck@, 64 bytes each.
data Symmetric = Symmetric
  { symHash        :: ByteString
  , symChainingKey :: ByteString
  } deriving (Eq, Show)

hashLength, blockLength, keyLength :: Int
hashLength = 64
blockLength = 128
keyLength = 32

blake2b :: ByteString -> ByteString
blake2b msg = Hash.generichash unkeyed msg outLen
  where
    unkeyed = fromMaybe (error "BLAKE2b: no empty key") $ Sodium.decode BS.empty
    outLen = fromMaybe (error "BLAKE2b: no 64-byte output") $ Hash.generichashOutLen hashLength

-- | RFC 2104 with BLAKE2b-512. Noise keys are never longer than a block.
hmac :: ByteString -> ByteString -> ByteString
hmac key msg = blake2b $ pad 0x5c <> blake2b (pad 0x36 <> msg)
  where
    padded = key <> BS.replicate (blockLength - BS.length key) 0
    pad byte = BS.map (xor byte) padded

-- | HKDF with two outputs, each 'hashLength' bytes.
hkdf :: ByteString -> ByteString -> (ByteString, ByteString)
hkdf chainingKey input = (out1, out2)
  where
    tempKey = hmac chainingKey input
    out1 = hmac tempKey (BS.singleton 1)
    out2 = hmac tempKey (out1 <> BS.singleton 2)

protocolName :: ByteString
protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2b"

-- | InitializeSymmetric, the prologue and the pre-message: the responder's
-- static key.
initialize :: ByteString -> PublicKey -> Symmetric
initialize prologue responderStatic =
  mixHash (Sodium.encode responderStatic) . mixHash prologue $ Symmetric start start
  where
    start = protocolName <> BS.replicate (hashLength - BS.length protocolName) 0

mixHash :: ByteString -> Symmetric -> Symmetric
mixHash bytes s = s { symHash = blake2b (symHash s <> bytes) }

-- | MixKey with the DH of the two keys, or 'Nothing' for a low-order point.
mixKey :: SecretKey -> PublicKey -> Symmetric -> Maybe (Symmetric, CipherKey)
mixKey sk pk s = do
  dh <- x25519 (Sodium.encode sk) (Sodium.encode pk)
  let (ck, k) = hkdf (symChainingKey s) dh
  return (s { symChainingKey = ck }, CipherKey $ BS.take keyLength k)

-- | libsodium fails for a low-order point and then leaves the output
-- unwritten, which saltine's own wrapper ignores.
x25519 :: ByteString -> ByteString -> Maybe ByteString
x25519 sk pk = unsafeDupablePerformIO $
  BS.useAsCString sk $ \psk -> BS.useAsCString pk $ \ppk ->
    allocaBytes 32 $ \out -> do
      failed <- ScalarMult.c_scalarmult out psk ppk
      if failed /= 0 then return Nothing else Just <$> BS.packCStringLen (out, 32)

-- | Our keys always have the length saltine wants.
decoded :: (Sodium.IsEncoding a, Sodium.IsEncoding b) => a -> b
decoded = fromMaybe (error "Noise: wrong key length") . Sodium.decode . Sodium.encode

zeroNonce :: IETF.Nonce
zeroNonce = fromMaybe (error "Noise: no 12-byte nonce") . Sodium.decode $ BS.replicate 12 0

ietfKey :: CipherKey -> IETF.Key
ietfKey (CipherKey k) = fromMaybe (error "Noise: no 32-byte key") $ Sodium.decode k

encryptAndHash :: CipherKey -> ByteString -> Symmetric -> (ByteString, Symmetric)
encryptAndHash key plain s = (cipher, mixHash cipher s)
  where
    cipher = IETF.aead (ietfKey key) zeroNonce plain (symHash s)

decryptAndHash :: CipherKey -> ByteString -> Symmetric -> Maybe (ByteString, Symmetric)
decryptAndHash key cipher s = do
  plain <- IETF.aeadOpen (ietfKey key) zeroNonce cipher (symHash s)
  return (plain, mixHash cipher s)

-- | The initiator's sending key, then the responder's.
split :: Symmetric -> (CipherKey, CipherKey)
split s = (CipherKey $ BS.take keyLength k1, CipherKey $ BS.take keyLength k2)
  where
    (k1, k2) = hkdf (symChainingKey s) BS.empty

-- | Tox sends data with the 'split' keys and XChaCha20-Poly1305, so a packet
-- can carry the same 2 bytes of its 24-byte nonce as with the legacy
-- handshake.
encryptTransport :: CipherKey -> Nonce -> ByteString -> ByteString
encryptTransport (CipherKey k) nonce plain = XChaCha.aead (decoded' k) (decoded nonce) plain BS.empty

decryptTransport :: CipherKey -> Nonce -> ByteString -> Maybe ByteString
decryptTransport (CipherKey k) nonce cipher = XChaCha.aeadOpen (decoded' k) (decoded nonce) cipher BS.empty

decoded' :: ByteString -> XChaCha.Key
decoded' = fromMaybe (error "Noise: no 32-byte key") . Sodium.decode
