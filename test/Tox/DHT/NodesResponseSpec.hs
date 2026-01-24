{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.DHT.NodesResponseSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.DHT.NodesResponse         (NodesResponse)
import           Tox.Network.Core.EncodingSpec


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy NodesResponse)
  binarySpec (Proxy :: Proxy NodesResponse)
  readShowSpec (Proxy :: Proxy NodesResponse)
