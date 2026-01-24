{-# LANGUAGE StrictData #-}
-- | Keys from passwords, as toxencryptsave makes them: scrypt of the
-- password's SHA-256, at twice libsodium's interactive work.
module Tox.Crypto.Core.PassKey
  ( saltLength
  , passKey
  ) where

import           Control.Monad               (guard)
import qualified Crypto.Saltine.Class        as Sodium
import qualified Crypto.Saltine.Internal.Box as Sodium (box_beforenmbytes)
import           Data.ByteString             (ByteString)
import qualified Data.ByteString             as BS
import qualified Data.ByteString.Internal    as BSI
import qualified Data.ByteString.Unsafe      as BSU
import           Data.Word                   (Word8)
import           Foreign.C.Types             (CInt (..), CSize (..),
                                              CULLong (..))
import           Foreign.Ptr                 (Ptr, castPtr)
import           System.IO.Unsafe            (unsafeDupablePerformIO)

import           Tox.Crypto.Core.Key         (CombinedKey)
import           Tox.Crypto.Core.Sign        (sha256)

saltLength :: Int
saltLength = fromIntegral c_saltbytes

-- | Nothing for a salt of the wrong length.
passKey :: ByteString -> ByteString -> Maybe CombinedKey
passKey password salt = do
  guard (BS.length salt == saltLength)
  Sodium.decode =<< scrypt (sha256 password) salt

scrypt :: ByteString -> ByteString -> Maybe ByteString
scrypt passkey salt = unsafeDupablePerformIO $
  BSU.unsafeUseAsCStringLen passkey $ \(p, pn) ->
  BSU.unsafeUseAsCString salt $ \s -> do
    (key, ok) <- BSI.createAndTrim' Sodium.box_beforenmbytes $ \o -> do
      r <- c_scrypt o (fromIntegral Sodium.box_beforenmbytes) (castPtr p) (fromIntegral pn) (castPtr s)
             (2 * c_opslimit_interactive) c_memlimit_interactive
      pure (0, Sodium.box_beforenmbytes, r == 0)
    pure (key <$ guard ok)

foreign import ccall unsafe "crypto_pwhash_scryptsalsa208sha256_saltbytes"
  c_saltbytes :: CSize

foreign import ccall unsafe "crypto_pwhash_scryptsalsa208sha256_opslimit_interactive"
  c_opslimit_interactive :: CULLong

foreign import ccall unsafe "crypto_pwhash_scryptsalsa208sha256_memlimit_interactive"
  c_memlimit_interactive :: CSize

-- Safe: it takes a while.
foreign import ccall safe "crypto_pwhash_scryptsalsa208sha256"
  c_scrypt :: Ptr Word8 -> CULLong -> Ptr Word8 -> CULLong -> Ptr Word8 -> CULLong -> CSize -> IO CInt
