{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.NodesSpec (spec) where

import           Data.Proxy                    (Proxy (..))
import           Test.Hspec
import           Tox.Network.Core.EncodingSpec (binarySpec)
import           Tox.Persistence.Nodes         (Nodes)

spec :: Spec
spec = do
  describe "Nodes" $
    binarySpec (Proxy :: Proxy Nodes)
