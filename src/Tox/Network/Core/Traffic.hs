{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | How much we send and receive, by kind, since we started. Cheap enough to
-- keep on all the time, as a packet is one increment with nothing allocated.
-- Totals rather than windows, so a rate is the difference of two readings.
module Tox.Network.Core.Traffic
  ( Traffic (..)
  , Counted (..)
  , Way (..)
  , Carrier (..)
  , Purpose (..)
  , Count (..)
  , addCount
  , newTraffic
  , noTraffic
  , countedName
  , kindName
  , purposeName
  , everything
  , slot
  ) where

import           Control.Monad               (forM)
import           Data.Array.IO               (IOUArray, newArray, readArray,
                                              writeArray)
import           Data.Maybe                  (catMaybes)
import           Data.Text                   (Text, pack)
import qualified Data.Text                   as Text
import           Data.Word                   (Word64, Word8)

import qualified Tox.Network.Core.PacketKind as PacketKind

data Way = Sent | Received
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Whether a Tox packet went on its own or inside a TCP relay connection.
data Carrier = Udp | Relay
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | What a request we send through the onion or the DHT is for. Packet kinds
-- can't say, as they're all onion requests on the wire.
data Purpose
  = AnnounceUs
  | SearchFriend
  | SearchGroup
  | DhtKeyByOnion
  | DhtKeyByDht
  | SendFriendRequest
  deriving (Eq, Ord, Show, Enum, Bounded)

data Counted
  = Packets Way Carrier Word8
    -- ^ Tox packets, by the kind byte they start with.
  | RelayLink Way
    -- ^ All bytes on our TCP relay connections, framing and relay control
    -- included.
  | Requests Purpose
  deriving (Eq, Ord, Show)

data Count = Count
  { countTimes :: Word64
  , countBytes :: Word64
  } deriving (Eq, Show)

addCount :: Count -> Count -> Count
addCount (Count t b) (Count t' b') = Count (t + t') (b + b')

-- | Only the main loop counts and reads, so neither needs a lock.
data Traffic = Traffic
  { count  :: Counted -> Int -> IO ()
  , totals :: IO [(Counted, Count)]
    -- ^ Those counted at least once.
  }

noTraffic :: Traffic
noTraffic = Traffic (\_ _ -> return ()) (return [])

newTraffic :: IO Traffic
newTraffic = do
  counts <- newArray (0, 2 * slots - 1) 0 :: IO (IOUArray Int Word64)
  let add :: Int -> Word64 -> IO ()
      add i n = readArray counts i >>= writeArray counts i . (+ n)
  return Traffic
    { count = \counted bytes -> do
        let i = 2 * slot counted
        add i 1
        add (i + 1) (fromIntegral bytes)
    , totals = fmap catMaybes . forM everything $ \counted -> do
        let i = 2 * slot counted
        times <- readArray counts i
        bytes <- readArray counts (i + 1)
        return $ if times == 0 then Nothing else Just (counted, Count times bytes)
    }

everything :: [Counted]
everything =
  [ Packets way carrier kind | way <- [minBound ..], carrier <- [minBound ..], kind <- [minBound ..] ]
  ++ map RelayLink [minBound ..]
  ++ map Requests [minBound ..]

slots :: Int
slots = length everything

-- | In the order of 'everything'.
slot :: Counted -> Int
slot = \case
  Packets way carrier kind -> (fromEnum way * carriers + fromEnum carrier) * kinds + fromIntegral kind
  RelayLink way            -> packets + fromEnum way
  Requests purpose         -> packets + ways + fromEnum purpose
  where
    kinds = fromIntegral (maxBound :: Word8) + 1
    ways = length [minBound .. maxBound :: Way]
    carriers = length [minBound .. maxBound :: Carrier]
    packets = ways * carriers * kinds

countedName :: Counted -> Text
countedName = \case
  Packets way carrier kind -> Text.unwords [carrierName carrier, wayName way, kindName kind]
  RelayLink way -> Text.unwords ["TCP relay", wayName way]
  Requests purpose -> "Requests " <> purposeName purpose
  where
    carrierName Udp   = "UDP"
    carrierName Relay = "Over TCP relays"
    wayName Sent     = "sent"
    wayName Received = "received"

-- | The packet kind's name, or its byte if it has none.
kindName :: Word8 -> Text
kindName kind = pack $ maybe ("unknown kind " <> show kind) show (PacketKind.byteToKind kind)

purposeName :: Purpose -> Text
purposeName = \case
  AnnounceUs        -> "announcing us"
  SearchFriend      -> "searching for friends"
  SearchGroup       -> "searching for groups"
  DhtKeyByOnion     -> "sending our DHT key through the onion"
  DhtKeyByDht       -> "sending our DHT key through the DHT"
  SendFriendRequest -> "sending friend requests"
