{-# LANGUAGE OverloadedStrings #-}
-- | Locations, sent as "geo:<latitude>,<longitude>" (every client can read
-- it). Nothing else knows the convention.
module Tox.Android.Locations
  ( location
  , locationText
  , mapsUri
  ) where

import           Control.Monad (guard)
import           Data.Char     (isDigit)
import           Data.Maybe    (fromMaybe)
import           Data.Text     (Text)
import qualified Data.Text     as Text
import           Numeric       (showFFloat)
import           Text.Read     (readMaybe)

-- | Only exactly "geo:" and 2 decimal numbers in range.
location :: Text -> Maybe (Double, Double)
location text = do
  rest <- Text.stripPrefix "geo:" text
  [lat, lon] <- Just (Text.splitOn "," rest)
  latitude <- number lat
  longitude <- number lon
  if abs latitude <= 90 && abs longitude <= 180 then Just (latitude, longitude) else Nothing
  where
    number t = do
      let (whole, fraction) = Text.breakOn "." (fromMaybe t (Text.stripPrefix "-" t))
      guard (not (Text.null whole) && Text.all isDigit whole)
      guard (Text.null fraction || (Text.length fraction > 1 && Text.all isDigit (Text.tail fraction)))
      readMaybe (Text.unpack t)

-- | Fixed decimals (other clients don't read exponents like 5.0e-2).
locationText :: Double -> Double -> Text
locationText latitude longitude = "geo:" <> fixed latitude <> "," <> fixed longitude
  where fixed x = Text.pack (showFFloat (Just 6) x "")

-- | Opens the maps app with a pin.
mapsUri :: Double -> Double -> Text
mapsUri latitude longitude = "geo:0,0?q=" <> point <> "," <> point'
  where
    point = Text.pack (showFFloat (Just 6) latitude "")
    point' = Text.pack (showFFloat (Just 6) longitude "")
