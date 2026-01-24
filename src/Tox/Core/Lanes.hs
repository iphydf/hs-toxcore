{-# LANGUAGE StrictData #-}
-- | How much time each kind of work takes, over the last few seconds. Cheap
-- enough to keep on all the time.
module Tox.Core.Lanes
  ( Lanes
  , Lane (..)
  , newLanes
  , timed
  , record
  , took
  , lanes
  , windowSeconds
  ) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.IORef             (IORef, atomicModifyIORef', newIORef)
import           Data.Map.Strict        (Map)
import qualified Data.Map.Strict        as Map
import           Data.Text              (Text)
import           Data.Word              (Word64)
import qualified System.Clock           as Clock

-- | Times are in nanoseconds.
data Lane = Lane
  { laneCount :: Int
  , laneTotal :: Word64
  , laneWorst :: Word64
  } deriving (Eq, Show)

data Window = Window
  { winStart   :: Word64
  , winCurrent :: Map Text Lane
  , winLast    :: Map Text Lane -- ^ The window before, which is complete.
  }

newtype Lanes = Lanes (IORef Window)

windowSeconds :: Int
windowSeconds = 10

windowLength :: Word64
windowLength = fromIntegral windowSeconds * 1000000000

now :: IO Word64
now = fromIntegral . Clock.toNanoSecs <$> Clock.getTime Clock.Monotonic

newLanes :: IO Lanes
newLanes = now >>= \t -> Lanes <$> newIORef (Window t Map.empty Map.empty)

-- | Starts a new window once the current one is over. After a whole window
-- with nothing in it, the last one is empty too. Another thread may have
-- started one after the time we read, so we never subtract.
rotate :: Word64 -> Window -> Window
rotate t w
  | t < winStart w + windowLength = w
  | t < winStart w + 2 * windowLength = Window t Map.empty (winCurrent w)
  | otherwise = Window t Map.empty Map.empty

record :: Lanes -> Text -> Word64 -> Word64 -> IO ()
record (Lanes ref) name start end = atomicModifyIORef' ref $ \w ->
  let w' = rotate end w
      spent = end - start
  in (w' { winCurrent = Map.insertWith add name (Lane 1 spent spent) (winCurrent w') }, ())
  where
    add (Lane c t m) (Lane c' t' m') = Lane (c + c') (t + t') (max m m')

-- | Work that just ended, after this many nanoseconds.
took :: Lanes -> Text -> Word64 -> IO ()
took ls name d = now >>= \t -> record ls name (t - min t d) t

timed :: MonadIO m => Lanes -> Text -> m a -> m a
timed ls name act = do
  start <- liftIO now
  result <- act
  liftIO $ now >>= record ls name start
  return result

-- | The last complete window.
lanes :: Lanes -> IO (Map Text Lane)
lanes (Lanes ref) = now >>= \t -> atomicModifyIORef' ref $ \w -> let w' = rotate t w in (w', winLast w')
