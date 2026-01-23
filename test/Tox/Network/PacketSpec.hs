{-# LANGUAGE Trustworthy #-}
module Tox.Network.PacketSpec where

import           Test.Hspec

import           Data.Proxy               (Proxy (..))
import           Data.Word                (Word64)

import           Tox.Network.EncodingSpec
import           Tox.Network.Packet       (Packet (..))
import qualified Tox.Network.PacketKind   as PacketKind


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy (Packet Word64))
  binarySpec (Proxy :: Proxy (Packet Word64))
  readShowSpec (Proxy :: Proxy (Packet Word64))

  it "has a kind and a payload" $ do
    let packet = Packet PacketKind.NodesRequest ["heyo"]
    packetKind packet `shouldBe` PacketKind.NodesRequest
    packetPayload packet `shouldBe` ["heyo"]
