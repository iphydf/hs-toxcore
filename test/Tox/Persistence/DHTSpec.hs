{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.DHTSpec (spec) where

import           Data.Proxy               (Proxy (..))
import           Test.Hspec
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.DHT      (DHT)

spec :: Spec
spec = do
  describe "DHT" $
    binarySpec (Proxy :: Proxy DHT)
