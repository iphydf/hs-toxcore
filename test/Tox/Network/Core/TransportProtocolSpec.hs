{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.Core.TransportProtocolSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.Network.Core.EncodingSpec
import           Tox.Network.Core.TransportProtocol (TransportProtocol)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy TransportProtocol)
  binarySpec (Proxy :: Proxy TransportProtocol)
  readShowSpec (Proxy :: Proxy TransportProtocol)
  bitEncodingSpec (Proxy :: Proxy TransportProtocol)
