{-# LANGUAGE OverloadedStrings #-}
-- | Message formats some clients use. The core only knows the bytes Tox
-- carried, and formats read them for display. Nothing outside this module
-- names a format.
module Tox.Android.Formats
  ( Format (..)
  , Reading (..)
  , formats
  , readWith
  ) where

import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as BS
import           Data.Maybe         (listToMaybe, mapMaybe)
import           Data.Text          (Text)
import qualified Data.Text.Encoding as Text

data Format = Format
  { formatKey   :: Text
    -- ^ Saved in the setting that turns it off.
  , formatName  :: Text
  , formatAbout :: Text
    -- ^ Shown with the setting.
  , readMessage :: ByteString -> Maybe Reading
    -- ^ Nothing if it isn't in this format.
  }

data Reading = Reading
  { readText   :: Text
    -- ^ To show, copy, quote and preview.
  , readRepeat :: Maybe ByteString
    -- ^ If an earlier message in the chat has the same key, this one is a
    -- repeat.
  } deriving (Eq, Show)

-- | Only for friends, never in groups.
formats :: [Format]
formats = [trifaV3]

-- | First format that can read it, else the plain text.
readWith :: [Format] -> ByteString -> Reading
readWith known bytes = case listToMaybe (mapMaybe (`readMessage` bytes) known) of
  Just r  -> r
  Nothing -> Reading (Text.decodeUtf8Lenient bytes) Nothing

-- | TRIfA's "message V3": the text, 2 zero bytes, an ID that stays the same
-- when TRIfA resends it, and the time as big-endian Unix seconds.
trifaV3 :: Format
trifaV3 = Format "message_v3" "TRIfA message IDs"
  "Hides the ID TRIfA adds to messages, and shows a message it sends again only once" $ \bytes ->
  let end = BS.length bytes - trailer
      (text, rest) = BS.splitAt end bytes
  in if end > 0 && BS.take 2 rest == BS.pack [0, 0]
       then Just (Reading (Text.decodeUtf8Lenient text) (Just (BS.take idLength (BS.drop 2 rest))))
       else Nothing
  where
    idLength = 32
    trailer = 2 + idLength + 4
