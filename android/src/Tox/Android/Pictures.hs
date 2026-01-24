{-# LANGUAGE OverloadedStrings #-}
-- | Picture formats to send in, other than as they are. The user picks one
-- per chat, and gallery and camera pictures get converted.
module Tox.Android.Pictures
  ( PictureFormat (..)
  , pictureFormats
  , qoi
  , pictureFormat
  ) where

import qualified Data.ByteString as BS
import           Data.List       (find)
import           Data.Text       (Text)

import           Tox.Android.Qoi (encodeQoi)

data PictureFormat = PictureFormat
  { formatKey       :: Text
  , formatName      :: Text
  , formatExtension :: String
  , formatMaxPixels :: Int
    -- ^ Larger pictures are sent as they are.
  , formatEncode    :: Int -> Int -> BS.ByteString -> Maybe BS.ByteString
    -- ^ RGBA pixels row by row to the file.
  }

pictureFormats :: [PictureFormat]
pictureFormats = [qoi]

qoi :: PictureFormat
qoi = PictureFormat "qoi" "QOI" ".qoi" (2 ^ (25 :: Int)) encodeQoi

pictureFormat :: Text -> Maybe PictureFormat
pictureFormat key = find ((== key) . formatKey) pictureFormats
