{-# LANGUAGE StrictData #-}
-- | When each of a set of jobs is next due. A job has one due window: it may
-- run from the first time, and must by the second. Whoever wakes for one job
-- takes the others that may run then, so jobs with room to move share wake-ups.
module Tox.Core.Schedule
  ( Schedule
  , empty
  , at
  , within
  , soonest
  , cancel
  , dueBy
  , next
  , takeDue
  , size
  ) where

import           Data.Map      (Map)
import qualified Data.Map      as Map
import           Data.Set      (Set)
import qualified Data.Set      as Set

import           Tox.Core.Time (Timestamp)

data Schedule k = Schedule
  { windows :: Map k (Timestamp, Timestamp)
  , byFrom  :: Set (Timestamp, k)
  , byLast  :: Set (Timestamp, k)
  } deriving (Eq, Read, Show)

empty :: Schedule k
empty = Schedule Map.empty Set.empty Set.empty

-- | Due at exactly that time, whenever it was due before.
at :: Ord k => Timestamp -> k -> Schedule k -> Schedule k
at time = within time time

-- | May run from the first time, and must by the second, whenever it was due
-- before.
within :: Ord k => Timestamp -> Timestamp -> k -> Schedule k -> Schedule k
within from by key s = Schedule
  { windows = Map.insert key (from, by') (windows s')
  , byFrom  = Set.insert (from, key) (byFrom s')
  , byLast  = Set.insert (by', key) (byLast s')
  }
  where
    s' = cancel key s
    by' = max from by

-- | Due at that time, unless it must run sooner already.
soonest :: Ord k => Timestamp -> k -> Schedule k -> Schedule k
soonest time key s = case Map.lookup key (windows s) of
  Just (_, by) | by <= time -> s
  _                         -> at time key s

cancel :: Ord k => k -> Schedule k -> Schedule k
cancel key s = case Map.lookup key (windows s) of
  Nothing         -> s
  Just (from, by) -> Schedule
    { windows = Map.delete key (windows s)
    , byFrom  = Set.delete (from, key) (byFrom s)
    , byLast  = Set.delete (by, key) (byLast s)
    }

-- | When the job must run by, if it's due at all.
dueBy :: Ord k => k -> Schedule k -> Maybe Timestamp
dueBy key = fmap snd . Map.lookup key . windows

-- | When the next job must run by.
next :: Schedule k -> Maybe Timestamp
next = fmap fst . Set.lookupMin . byLast

-- | Takes the jobs that may run at the time, in the order they may.
takeDue :: Ord k => Timestamp -> Schedule k -> ([k], Schedule k)
takeDue now s = (keys, foldr cancel s keys)
  where
    keys = map snd . Set.toAscList . fst $ Set.spanAntitone ((<= now) . fst) (byFrom s)

size :: Schedule k -> Int
size = Map.size . windows
