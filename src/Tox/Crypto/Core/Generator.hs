{-# LANGUAGE StrictData #-}
-- | Random bytes from a stream cipher keyed once, so a node's randomness is
-- part of its state and the same key always gives the same bytes. As strong
-- as the cipher while the key stays secret and no nonce comes twice, which
-- the counter makes sure of.
module Tox.Crypto.Core.Generator
  ( Generator
  , newGenerator
  , takeBytes
  ) where

import qualified Crypto.Saltine.Class       as Sodium
import qualified Crypto.Saltine.Core.Stream as Stream
import           Data.Binary.Put            (putByteString, putWord64be, runPut)
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as LBS
import           Data.Maybe                 (fromJust)
import           Data.Word                  (Word64)

data Generator = Generator
  { key     :: Stream.Key
  , counter :: Word64
  , buffer  :: ByteString
  }

-- | From 32 secret bytes, or Nothing for any other length.
newGenerator :: ByteString -> Maybe Generator
newGenerator bytes = (\k -> Generator k 0 BS.empty) <$> Sodium.decode bytes

-- | A block at a time, so most takes don't call the cipher.
blockSize :: Int
blockSize = 4096

-- | The bytes are the blocks one after another, however they're taken.
takeBytes :: Int -> Generator -> (ByteString, Generator)
takeBytes n g
  | BS.length (buffer g) >= n = (taken, g { buffer = rest })
  | otherwise = takeBytes n g
      { counter = counter g + 1
      , buffer = buffer g <> Stream.stream (key g) nonce blockSize
      }
  where
    (taken, rest) = BS.splitAt n (buffer g)
    -- The counter, then zeros to the nonce's 24 bytes.
    nonce = fromJust . Sodium.decode . LBS.toStrict . runPut $ putWord64be (counter g) >> putByteString (BS.replicate 16 0)
