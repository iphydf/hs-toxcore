{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.TransportProtocolSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.Network.EncodingSpec
import           Tox.Network.TransportProtocol (TransportProtocol)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy TransportProtocol)
  binarySpec (Proxy :: Proxy TransportProtocol)
  readShowSpec (Proxy :: Proxy TransportProtocol)
  bitEncodingSpec (Proxy :: Proxy TransportProtocol)
