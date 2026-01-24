{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
module Tox.Core.ScheduleSpec (spec) where

import           Data.List         (foldl', sortOn)
import qualified Data.Map          as Map
import           Test.Hspec
import           Test.QuickCheck

import qualified Tox.Core.Schedule as Schedule
import           Tox.Core.Schedule (Schedule)
import qualified Tox.Core.Time     as Time
import           Tox.Core.Time     (Timestamp)

-- | Sets a window, makes a job due sooner, or cancels it, at small times so
-- they collide.
data Change = Within Int Int Int | Soonest Int Int | Cancel Int
  deriving Show

instance Arbitrary Change where
  arbitrary = oneof
    [ Within <$> key <*> time <*> time
    , Soonest <$> key <*> time
    , Cancel <$> key
    ]
    where
      key = choose (0, 9)
      time = choose (0, 20)

seconds :: Int -> Timestamp
seconds = Time.fromSeconds . fromIntegral

apply :: Schedule Int -> Change -> Schedule Int
apply s = \case
  Within k from by -> Schedule.within (seconds from) (seconds by) k s
  Soonest k t      -> Schedule.soonest (seconds t) k s
  Cancel k         -> Schedule.cancel k s

-- | The same, as a map from job to window.
model :: Map.Map Int (Int, Int) -> Change -> Map.Map Int (Int, Int)
model m = \case
  Within k from by -> Map.insert k (from, max from by) m
  Soonest k t | Just (_, by) <- Map.lookup k m, by <= t -> m
              | otherwise -> Map.insert k (t, t) m
  Cancel k -> Map.delete k m

spec :: Spec
spec = describe "Schedule" $
  it "keeps one window per job, and takes the jobs that may run, in order" $
    property $ \(changes :: [Change]) (Small now') ->
      let now = now' `mod` 21
          s = foldl' apply Schedule.empty changes
          m = foldl' model Map.empty changes
          (taken, left) = Schedule.takeDue (seconds now) s
          due = sortOn (\(k, (from, _)) -> (from, k)) [ e | e@(_, (from, _)) <- Map.toList m, from <= now ]
      in
      ( map (`Schedule.dueBy` s) [0 .. 9], Schedule.next s, taken, Schedule.size left )
      `shouldBe`
      ( map (fmap (seconds . snd) . (`Map.lookup` m)) [0 .. 9]
      , if Map.null m then Nothing else Just (seconds (minimum (map snd (Map.elems m))))
      , map fst due
      , Map.size m - length due
      )
