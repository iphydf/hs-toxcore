{-# LANGUAGE OverloadedStrings #-}
module Tox.DHT.ClientNodeSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.Core.EncodingSpec (readShowSpec)
import           Tox.DHT.ClientNode       (ClientNode)

spec :: Spec
spec = do
  describe "ClientNode" $
    readShowSpec (Proxy :: Proxy ClientNode)
