{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
module Tox.Application.StateSpec (spec) where

import           Control.Monad                      (void)
import           Control.Monad.State                (get, modify)
import           Test.Hspec

import           Tox.Application.AppTest            (runApp)
import           Tox.Application.State              hiding (runApp)
import qualified Tox.Chat.GroupChat                 as Group
import           Tox.Core.Log                       (LogLevel (..), logInfo)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Timed                     (Timed (..))
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Evaluated                      (evaluated)
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp

spec :: Spec
spec =
  describe "App" $ do
    it "gives an evaluated time, so it holds no state" $ do
      (time, ()) <- runApp $ (, ()) <$> askTime
      evaluated time `shouldReturn` True

    it "evaluates each new state, so a step doesn't pile them up" $ do
      (gs, ()) <- runApp $ (, ()) <$> (modify (\gs -> gs { nextSocket = 1 }) >> get)
      evaluated gs `shouldReturn` True

    it "makes a log line only when something reads it" $ do
      outputs <- runApp $ logInfo (error "never read") >> takeOutbox
      [ level | Log level _ <- outputs ] `shouldBe` [LevelInfo]

    it "holds back from a busy relay until it's writable or on a new socket" $ do
      relay <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let node = NodeInfo TCP (SocketAddress (IPv4 0x0100007f) 33445) relay
      busy <- runApp $ do
        fresh <- Tcp.tcpBusy relay
        relayBusy Nothing relay
        over <- Tcp.tcpBusy relay
        relayWritable Nothing relay
        writable <- Tcp.tcpBusy relay
        relayBusy Nothing relay
        relayConnect Nothing node
        reconnected <- Tcp.tcpBusy relay
        return [fresh, over, writable, reconnected]
      busy `shouldBe` [False, True, False, False]

    it "closes a left group's relays when they're due, and not before" $ do
      relay <- KeyPair.publicKey <$> KeyPair.newKeyPair
      keys <- KeyPair.newKeyPair
      let node = NodeInfo TCP (SocketAddress (IPv4 0x0100007f) 33445) relay
          closes = closeLeftGroupTcp >> takeOutbox >>= \outputs -> return [ (owner, pk) | RelayClose owner pk <- outputs ]
      (waits, early, due) <- runApp $ do
        runGroupTcp "chat" keys (Tcp.addRelay node)
        Group.dropGroupTcp "chat"
        now <- askTime
        waits <- gets (fmap (`Time.diffTime` now) . leftGroupTcpDue)
        early <- closes
        gets leftGroupTcpDue >>= mapM_ (\t -> modify (\gs -> gs { stepTime = t }))
        (,,) waits early <$> closes
      (Time.toMilliseconds <$> waits, early, due) `shouldBe` (Just 2000, [], [(Just "chat", relay)])

    it "gives up on a relay that doesn't take our handshake in time, and tries again" $ do
      relay <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let node = NodeInfo TCP (SocketAddress (IPv4 0x0100007f) 33445) relay
          waits :: Time.Timestamp -> App (Maybe Integer)
          waits start = gets (fmap (Time.toMilliseconds . (`Time.diffTime` start)) . Tcp.nextDue . tcpState)
          ran = Tcp.runDue >> takeOutbox >>= \os -> return (length [ () | RelayClose _ _ <- os ], length [ () | RelayConnect {} <- os ])
      result <- runApp $ do
        start <- askTime
        Tcp.addRelay node >> void takeOutbox
        first <- waits start
        early <- ran
        modify (\gs -> gs { stepTime = Time.addTime start Tcp.connectTimeout })
        late <- ran
        (,,,) first early late <$> waits start
      result `shouldBe` (Just 10000, (0, 0), (1, 1), Just 20000)

    it "takes input only from a relay connection's latest socket" $ do
      relay <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let node = NodeInfo TCP (SocketAddress (IPv4 0x0100007f) 33445) relay
      current <- runApp $ do
        relayConnect Nothing node
        relayConnect Nothing node
        replaced <- mapM (currentSocket Nothing relay) [0, 1]
        relayClose Nothing relay
        closed <- currentSocket Nothing relay 1
        return (replaced, closed)
      current `shouldBe` ([False, True], False)
