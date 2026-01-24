{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Application.ToxSpec (spec) where

import           Control.Concurrent                 (forkIO, threadDelay)
import           Control.Concurrent.Chan            (getChanContents, newChan,
                                                     writeChan)
import           Control.Concurrent.STM             (atomically, newTBQueueIO,
                                                     writeTBQueue)
import           Control.Monad                      (replicateM, replicateM_,
                                                     void, when)
import qualified Data.Binary                        as Binary
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.IORef                         (atomicModifyIORef',
                                                     newIORef, readIORef)
import qualified Data.Text                          as Text
import           GHC.Clock                          (getMonotonicTime)
import qualified Network.Socket                     as Socket
import           System.Timeout                     (timeout)
import           Test.Hspec
import           Test.QuickCheck

import qualified Crypto.Saltine.Class               as Sodium
import qualified Tox.Application.Node               as Node
import           Tox.Application.State              (Output (..))
import qualified Tox.Application.Tox                as Tox
import           Tox.Core.Log                       (LogLevel (..))
import qualified Tox.Core.Time                      as Time
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.DHT.DhtPacket                  (DhtPacket (..))
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

newTox :: IO Tox.Tox
newTox = Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False } >>= either (fail . show) return

nodeOf :: Tox.Tox -> NodeInfo
nodeOf t = NodeInfo UDP
  (SocketAddress (IPv4 (tupleToHostAddress (127, 0, 0, 1))) (PortNumber (Tox.selfUdpPort t)))
  (Tox.selfDhtId t)

spec :: Spec
spec =
  describe "Tox" $ do
    it "waits for an input until the next job is due, and no longer" $ do
      queue <- newTBQueueIO 4
      now <- Time.getTime
      let soon = Time.addTime now (Time.milliseconds 100)
      started <- getMonotonicTime
      none <- Tox.nextInput queue (Just soon)
      waited <- subtract started <$> getMonotonicTime
      atomically $ writeTBQueue queue 'a'
      queued <- Tox.nextInput queue (Just now)
      _ <- forkIO $ threadDelay 50000 >> atomically (writeTBQueue queue 'b')
      later <- Tox.nextInput queue Nothing
      (none, waited >= 0.1 && waited < 1, queued, later) `shouldBe` (Nothing, True, Just 'a', Just 'b')

    it "finds the sender's key where each packet has it" $ property $ \(packet :: DhtPacket) (receiver :: PublicKey) (sender :: PublicKey) -> do
      let dht = LBS.toStrict (Binary.encode packet)
          crypto = Sodium.encode receiver <> Sodium.encode sender <> BS.replicate 24 0
      Node.senderKey PacketKind.NodesRequest dht `shouldBe` senderPublicKey packet
      Node.senderKey PacketKind.Crypto crypto `shouldBe` sender
      Node.senderKey PacketKind.CookieRequest (Sodium.encode sender) `shouldBe` sender

    it "tells the core when a send makes a relay busy" $ do
      counts <- Traffic.newTraffic
      relay <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let tcp = Tox.noTcpIo { Tox.tcpIoSend = \_ _ bytes -> return (bytes == "over") }
          shell = Tox.Shell Nothing tcp Tox.noTcpServerIo counts (\_ _ -> return ())
      learnt <- Tox.flush shell [RelaySend Nothing relay 3 "under", RelaySend Nothing relay 3 "over"]
      (length learnt, [ (owner, pk, socket) | Node.RelayBusy owner pk socket <- learnt ])
        `shouldBe` (1, [(Nothing, relay, 3)])

    it "logs what a call did before it returns" $ do
      logged <- newIORef []
      let logger level line = atomicModifyIORef' logged (\ls -> ((level, line) : ls, ()))
      tox <- Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False, Tox.optLogger = logger } >>= either (fail . show) return
      friend <- KeyPair.publicKey <$> KeyPair.newKeyPair
      Tox.friendAddNoRequest tox friend `shouldReturn` Right ()
      lines' <- readIORef logged
      Tox.kill tox
      lines' `shouldContain` [(LevelInfo, "Adding friend: " <> Text.pack (show friend))]

    it "closes a socket rather than queue more than the limit" $ do
      queue <- newChan
      counter <- newIORef 0
      let fits = Tox.maxQueuedBytes `div` 1000
      replicateM_ (2 * fits) $ Tox.queueBytes queue counter (BS.replicate 1000 0)
      writeChan queue (Just BS.empty)
      (full, rest) <- splitAt fits . map (fmap BS.length) . take (fits + 2) <$> getChanContents queue
      (all (== Just 1000) full, rest) `shouldBe` (True, [Nothing, Just 0])

    it "takes no more of a friend's data while its client is far behind" $ do
      (toxes, a, b) <- onlinePair
      deadline <- (+ 3) <$> getMonotonicTime
      let flood = getMonotonicTime >>= \t -> when (t < deadline) $ do
            void $ Tox.friendSendLosslessPacket a (Tox.selfPublicKey b) (BS.cons 160 (BS.replicate 1000 7))
            flood
      flood
      waiting <- sum . map Tox.sizeCount . filter ((== "Events not taken yet") . Tox.sizeName) <$> Tox.sizes b
      mapM_ Tox.kill toxes
      waiting `shouldSatisfy` (< 2 * Tox.maxWaitingEvents)

    it "counts what it sends and receives, by kind and purpose" $ do
      -- More than the 2 for onion paths.
      toxes <- replicateM 4 newTox
      let (a, b) = case toxes of
            x : y : _ -> (x, y)
            _         -> error "too few"
      sequence_ [Tox.bootstrap p (nodeOf q) | p <- toxes, q <- toxes, Tox.selfPublicKey p /= Tox.selfPublicKey q]
      Tox.friendAddNoRequest a (Tox.selfPublicKey b) >>= either (fail . show) (const $ return ())
      let nodes way = Tox.Packets way Tox.Udp (PacketKind.kindToByte PacketKind.NodesRequest)
          counted tox what = maybe 0 Tox.countTimes . lookup what <$> Tox.traffic tox
          seen = do
            sent <- counted a (nodes Tox.Sent)
            received <- counted b (nodes Tox.Received)
            searches <- counted a (Tox.Requests Tox.SearchFriend)
            if sent > 0 && received > 0 && searches > 0 then return () else threadDelay 100000 >> seen
      found <- timeout 30000000 seen
      mapM_ Tox.kill toxes
      found `shouldBe` Just ()

    it "reports its sizes, none over their limits" $ do
      tox <- Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False } >>= either (fail . show) return
      sizes <- Tox.sizes tox
      Tox.kill tox
      (filter Tox.overLimit sizes, "Events not taken yet" `elem` map Tox.sizeName sizes) `shouldBe` ([], True)

    it "fails calls once killed, rather than waiting for ever" $ do
      tox <- Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False } >>= either (fail . show) return
      _ <- Tox.selfGetName tox
      Tox.kill tox
      Tox.selfGetName tox `shouldThrow` (== Tox.ToxStopped)

    it "reports a taken relay port and lets go of its UDP port" $ do
      taken <- Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
      Socket.bind taken (Socket.SockAddrInet 0 0)
      Socket.listen taken 1
      tcpPort <- fromIntegral <$> Socket.socketPort taken
      probe <- Socket.socket Socket.AF_INET Socket.Datagram Socket.defaultProtocol
      Socket.bind probe (Socket.SockAddrInet 0 0)
      udpPort <- fromIntegral <$> Socket.socketPort probe
      Socket.close probe
      let opts = Tox.defaultOptions { Tox.optLocalDiscovery = False, Tox.optUdpPorts = (udpPort, udpPort) }
      refused <- Tox.new opts { Tox.optTcpPort = Just tcpPort }
      Socket.close taken
      either Just (const Nothing) refused `shouldBe` Just Tox.PortInUse
      Tox.new opts >>= either (fail . show) Tox.kill

-- | Four instances on a local network, two of them friends and online. Only
-- the first friend's client takes its events.
onlinePair :: IO ([Tox.Tox], Tox.Tox, Tox.Tox)
onlinePair = do
  -- More than the 2 for onion paths.
  toxes <- replicateM 4 newTox
  let (a, b) = case toxes of
        x : y : _ -> (x, y)
        _         -> error "too few"
  sequence_ [Tox.bootstrap p (nodeOf q) | p <- toxes, q <- toxes, Tox.selfPublicKey p /= Tox.selfPublicKey q]
  mapM_ (\(x, y) -> Tox.friendAddNoRequest x (Tox.selfPublicKey y) >>= either (fail . show) return) [(a, b), (b, a)]
  let online = Tox.nextEvent a >>= \case
        Tox.FriendConnectionChanged pk status | pk == Tox.selfPublicKey b, status /= Tox.NotConnected -> return ()
        _ -> online
  timeout 60000000 online >>= maybe (expectationFailure "not online in 60 s") return
  return (toxes, a, b)
