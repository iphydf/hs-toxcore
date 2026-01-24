{-# LANGUAGE OverloadedStrings #-}
module Tox.Core.LanesSpec (spec) where

import qualified Data.Map.Strict as Map
import qualified System.Clock    as Clock
import           Test.Hspec

import           Tox.Core.Lanes

spec :: Spec
spec =
  describe "Lanes" $ do
    it "gives the last complete window" $ do
      ls <- newLanes
      t <- fromIntegral . Clock.toNanoSecs <$> Clock.getTime Clock.Monotonic
      let second = 1000000000
          later = t + fromIntegral windowSeconds * second + second
      record ls "a" t (t + 5)
      record ls "a" t (t + 3)
      record ls "b" later later
      lanes ls `shouldReturn` Map.fromList [("a", Lane 2 8 5)]

    it "keeps a window when another thread already started a newer one" $ do
      ls <- newLanes
      t <- fromIntegral . Clock.toNanoSecs <$> Clock.getTime Clock.Monotonic
      let later = t + fromIntegral windowSeconds * 1000000000 + 1
      record ls "a" t (t + 5)
      record ls "b" later later
      _ <- lanes ls
      lanes ls `shouldReturn` Map.fromList [("a", Lane 1 5 5)]
