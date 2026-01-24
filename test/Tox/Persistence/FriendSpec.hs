{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.FriendSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.Core.EncodingSpec (binarySpec)
import           Tox.Persistence.Friend   (Friend)

spec :: Spec
spec = do
  describe "Friend" $
    binarySpec (Proxy :: Proxy Friend)
