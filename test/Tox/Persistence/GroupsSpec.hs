{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.GroupsSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.Groups   (Groups)

spec :: Spec
spec = do
  describe "Groups" $
    binarySpec (Proxy :: Proxy Groups)
