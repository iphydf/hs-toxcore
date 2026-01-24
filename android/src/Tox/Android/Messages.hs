-- | Splitting messages for Tox, which only takes so many bytes in one.
module Tox.Android.Messages
  ( split
  , parts
  ) where

import           Data.Bits           ((.&.))
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as BS
import           Data.List           (find)
import           Data.Text           (Text)
import qualified Data.Text.Encoding  as Text
import qualified Tox.Application.Tox as Tox

-- | Never splits a UTF-8 character. Splits after whitespace if the second
-- half of the part has some.
split :: Int -> ByteString -> [ByteString]
split limit bytes
  | BS.length bytes <= limit = [bytes]
  | otherwise = let (part, rest) = BS.splitAt end bytes in part : split limit rest
  where
    whole = until (\i -> i <= 1 || not (continuing (BS.index bytes i))) (subtract 1) limit
    end = maybe whole (+ 1) (find (blank . BS.index bytes) [whole - 1, whole - 2 .. whole `div` 2])
    continuing b = b .&. 0xc0 == 0x80
    blank b = b `elem` [0x09, 0x0a, 0x0d, 0x20]

-- | 1 Tox message each. Only depends on the text, so it's the same after a
-- restart.
parts :: Text -> [ByteString]
parts = split Tox.maxMessageLength . Text.encodeUtf8
