{-# LANGUAGE OverloadedStrings #-}
module Tox.DHT.ClientNodeSpec (spec) where

import           Data.Proxy                    (Proxy (..))
import           Test.Hspec
import           Tox.DHT.ClientNode            (ClientNode)
import           Tox.Network.Core.EncodingSpec (readShowSpec)

spec :: Spec
spec = do
  describe "ClientNode" $
    readShowSpec (Proxy :: Proxy ClientNode)
