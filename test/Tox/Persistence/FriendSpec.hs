{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.FriendSpec (spec) where

import           Data.Proxy               (Proxy (..))
import           Test.Hspec
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.Friend   (Friend)

spec :: Spec
spec = do
  describe "Friend" $
    binarySpec (Proxy :: Proxy Friend)
