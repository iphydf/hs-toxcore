{-# LANGUAGE OverloadedStrings #-}
module Tox.OnionPacketSpec (spec) where

import           Data.Binary                        (encode, put)
import qualified Data.Binary                        as Binary
import qualified Data.Binary.Put                    as Put
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.Maybe                         (fromJust)
import           Data.Word                          (Word8)
import           Test.Hspec

import           Control.Monad.Identity             (runIdentity)
import           Control.Monad.Validate             (runValidate)
import qualified Crypto.Saltine.Class               as Sodium
import qualified Data.Map                           as Map
import qualified Tox.Core.Time                      as Time
import qualified Tox.Crypto.Core.Box                as Box
import           Tox.Crypto.Core.Key                (Key (..))
import qualified Tox.Crypto.Core.Keyed              as KeyedT
import           Tox.Crypto.Core.KeyPair            (KeyPair (..))
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Onion.Path                     as Path
import qualified Tox.Onion.RPC                      as RPC
import qualified Tox.Onion.Tunnel                   as Tunnel

import           Control.Monad.Random      (evalRandT)
import           System.Random             (mkStdGen)

spec :: Spec
spec = do
  describe "Onion Packet Encoding" $ do
    let nullPk = Key . fromJust . Sodium.decode $ BS.replicate 32 0
        nullNonce = Key . fromJust . Sodium.decode $ BS.replicate 24 0

    it "OnionRequest0 produced by wrapPath must be exactly 403 bytes" $ do
      let nullSk = Key . fromJust . Sodium.decode $ BS.replicate 32 0
          ourKp = KeyPair nullSk nullPk -- dummy
          path = Path.OnionPath (replicate 3 (NodeInfo UDP (SocketAddress (IPv4 0) (PortNumber 0)) nullPk)) (replicate 3 ourKp) False 0 (Time.fromMillis 0) Nothing 0
          destAddr = SocketAddress (IPv4 0) (PortNumber 0)
          nonce = nullNonce

          -- Standard AnnounceRequest envelope: Kind (0x83) + Nonce (24) + PK (32) + CipherText(120) = 177 bytes
          innerData = LBS.toStrict $ Put.runPut $ do
            Binary.put (0x83 :: Word8)
            Binary.put nullNonce
            Binary.put nullPk
            Put.putByteString (BS.replicate 120 0)

          wrap = Path.wrapPath ourKp path destAddr nonce innerData
          res = runIdentity $ evalRandT (KeyedT.evalKeyedT wrap Map.empty) (mkStdGen 42)
      let pkt = Packet PacketKind.OnionRequest0 res
          bs = LBS.toStrict $ Put.runPut $ do
            Binary.put (packetKind pkt)
            Binary.put (packetPayload pkt)

      -- Calculated 403.
      BS.length bs `shouldBe` 403