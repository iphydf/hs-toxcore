{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tox.DHT.StampedSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import           Tox.Core.Time   (Timestamp)
import           Tox.DHT.Stamped

spec :: Spec
spec = do
  describe "Stamped" $ do
    it "can add and get elements" $ property $
      \(t :: Timestamp) (x :: Int) ->
        let s = add t x empty
        in getList s `shouldBe` [x]

    it "can delete elements" $ property $
      \(t :: Timestamp) (x :: Int) ->
        let s = add t x empty
            s' = delete t x s
        in getList s' `shouldBe` []

    it "can drop older elements" $ property $
      \(t1 :: Timestamp) (t2 :: Timestamp) (x1 :: Int) (x2 :: Int) ->
        let t_max = max t1 t2
            s = add t1 x1 $ add t2 x2 empty
            s' = dropOlder t_max s
        in if t1 < t_max && t2 < t_max
           then getList s' `shouldBe` []
           else if t1 >= t_max && t2 >= t_max
                then length (getList s') `shouldBe` 2
                else length (getList s') `shouldBe` 1

    it "popFirst returns elements in order" $ property $
      \(t1 :: Timestamp) (t2 :: Timestamp) (x1 :: Int) (x2 :: Int) ->
        let s = add t1 x1 $ add t2 x2 empty
            (res1, s1) = popFirst s
            (res2, _) = popFirst s1
        in case (res1, res2) of
             (Just (st1, _), Just (st2, _)) -> st1 <= st2
             _                              -> True -- skip for empty cases
