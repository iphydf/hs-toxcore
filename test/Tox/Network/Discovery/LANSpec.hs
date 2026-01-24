module Tox.Network.Discovery.LANSpec (spec) where

import           Control.Monad                  (foldM)
import qualified Crypto.Saltine.Class           as Sodium
import qualified Data.Set                       as Set
import           Test.Hspec

import           Tox.Application.AppTest        (runApp)
import           Tox.Application.State          (GlobalState (..), Output (..),
                                                 gets, takeOutbox)
import qualified Tox.Crypto.Core.Key            as Key
import qualified Tox.Crypto.Core.KeyPair        as KeyPair
import qualified Tox.DHT.DhtState               as DhtState
import           Tox.Network.Core.HostAddress   (HostAddress (..),
                                                 tupleToHostAddress)
import           Tox.Network.Core.SocketAddress (SocketAddress (..))
import qualified Tox.Network.Discovery.LAN      as LAN

spec :: Spec
spec = describe "LAN discovery" $ do
  it "asks a peer that announces itself on the LAN for nodes, and no one else" $ do
    peer <- KeyPair.publicKey <$> KeyPair.newKeyPair
    let at a = SocketAddress (IPv4 (tupleToHostAddress a)) 33445
        announcement = Sodium.encode
    sent <- runApp $ do
      us <- gets (KeyPair.publicKey . DhtState.dhtKeyPair . dhtState)
      LAN.handlePacket (at (192, 168, 1, 2)) (announcement peer)
      LAN.handlePacket (at (8, 8, 8, 8)) (announcement peer)
      LAN.handlePacket (at (192, 168, 1, 3)) (announcement us)
      takeOutbox
    [ to | SendUdp to _ <- sent ] `shouldBe` [at (192, 168, 1, 2)]

  it "keeps going through every port in turn" $ do
    let announcements start = foldM (const . LAN.announce False) start (replicate 100 ())
    sent <- runApp $ do
      next <- announcements (LAN.portFrom + 1)
      _ <- takeOutbox
      announcements next >> takeOutbox
    Set.fromList [ port | SendUdp (SocketAddress _ port) _ <- sent ]
      `shouldBe` Set.fromList (map fromIntegral [LAN.portFrom .. LAN.portTo - 1])
