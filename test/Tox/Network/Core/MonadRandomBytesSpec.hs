{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Network.Core.MonadRandomBytesSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Monad.Random              (evalRand, mkStdGen)
import           Tox.Network.Core.MonadRandomBytes

spec :: Spec
spec = do
  describe "randomInt" $ do
    it "returns values in range [0, bound)" $ property $
      \(Positive bound) (seed :: Int) ->
        let g = mkStdGen seed
            res = evalRand (randomInt bound) g
        in res >= 0 && res < bound

  describe "randomIntR" $ do
    it "returns values in range [low, high]" $ property $
      \low (Positive range) (seed :: Int) ->
        let high = low + range
            g = mkStdGen seed
            res = evalRand (randomIntR (low, high)) g
        in res >= low && res <= high

  describe "uniform" $ do
    it "returns an element from the list" $ property $
      \(NonEmpty (xs :: [Int])) (seed :: Int) ->
        let g = mkStdGen seed
            res = evalRand (uniform xs) g
        in res `elem` xs
