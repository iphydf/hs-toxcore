{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.GroupsSpec (spec) where

import           Data.Proxy               (Proxy (..))
import           Test.Hspec
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.Groups   (Groups)

spec :: Spec
spec = do
  describe "Groups" $
    binarySpec (Proxy :: Proxy Groups)
