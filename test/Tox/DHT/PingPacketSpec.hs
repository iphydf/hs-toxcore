{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.DHT.PingPacketSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.DHT.PingPacket            (PingPacket)
import           Tox.Network.Core.EncodingSpec


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy PingPacket)
  binarySpec (Proxy :: Proxy PingPacket)
  readShowSpec (Proxy :: Proxy PingPacket)
