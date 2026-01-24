{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.DHT.DhtRequestPacketSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.DHT.DhtRequestPacket      (DhtRequestPacket (..))
import           Tox.Network.Core.EncodingSpec


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy DhtRequestPacket)
  binarySpec (Proxy :: Proxy DhtRequestPacket)
  readShowSpec (Proxy :: Proxy DhtRequestPacket)
