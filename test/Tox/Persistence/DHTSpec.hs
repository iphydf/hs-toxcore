{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.DHTSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.Core.EncodingSpec (binarySpec)
import           Tox.Persistence.DHT      (DHT)

spec :: Spec
spec = do
  describe "DHT" $
    binarySpec (Proxy :: Proxy DHT)
