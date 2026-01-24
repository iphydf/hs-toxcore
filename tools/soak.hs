{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StrictData #-}
-- | Runs Tox instances on this machine through everyday work, and fails if
-- what's live after each major GC keeps rising over a workload. Prints what
-- each one costs.
--
-- A space leak may only show when optimised (with -O0, GHC keeps fields
-- boxed and its GC drops what they'd hold), so this runs in the optimised
-- cabal build too.
module Main (main) where

import           Control.Concurrent                 (forkIO, threadDelay)
import           Control.Exception                  (handleJust)
import           Control.Monad                      (forM, forM_, forever,
                                                     replicateM_, unless, void,
                                                     when)
import qualified Data.Binary                        as Binary
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.IORef                         (IORef, atomicModifyIORef',
                                                     newIORef, readIORef,
                                                     writeIORef)
import           Data.List                          (sortOn)
import qualified Data.List                          as List
import qualified Data.Map.Strict                    as Map
import           Data.Ord                           (Down (..))
import qualified Data.Text                          as Text
import qualified GHC.Stats                          as Stats
import qualified Network.Socket                     as Socket
import qualified Network.Socket.ByteString          as SocketBS
import           System.Environment                 (getArgs)
import           System.Exit                        (exitFailure)
import           System.IO                          (BufferMode (..),
                                                     hSetBuffering, stdout)
import           System.Mem                         (performMajorGC)
import           System.Timeout                     (timeout)
import           Text.Printf                        (printf)

import qualified Tox.Application.Tox                as Tox
import           Tox.Application.Tox                (Event (..), Tox)
import           Tox.Core.Lanes                     (Lane (..))
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import qualified Tox.Crypto.Core.Nonce              as Nonce
import qualified Tox.DHT.DhtPacket                  as DhtPacket
import           Tox.DHT.NodesRequest               (NodesRequest (..))
import           Tox.DHT.RpcPacket                  (RequestId (..),
                                                     RpcPacket (..))
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

-- | Seconds for the network to form, of each workload before measuring (more
-- for hostile ones, so they first fill what they can to its limit), and of
-- each workload measured (the argument, if given).
settle, warmUp, hostileWarmUp, defaultLength :: Int
settle = 20
warmUp = 5
hostileWarmUp = 90
defaultLength = 30

-- | Live memory may grow this much a second over a workload. Steady work
-- stays within 27 KB/s either way (a GC that comes late moves it), and the
-- space leak fixed on 2026-11-07 grew around 100 KB/s.
maxGrowth :: Double
maxGrowth = 30000

-- | Each instance hands its events to the running workload's handler.
data Peer = Peer
  { peerTox     :: Tox
  , peerHandler :: IORef (Event -> IO ())
  }

newPeer :: IO Peer
newPeer = do
  tox <- Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False } >>= either (fail . show) pure
  handler <- newIORef (const (pure ()))
  -- Until it stops.
  void . forkIO . handleJust stopped pure . forever $ Tox.nextEvent tox >>= \e -> readIORef handler >>= ($ e)
  pure (Peer tox handler)

stopped :: Tox.ToxStopped -> Maybe ()
stopped _ = Just ()

nodeOf :: Tox -> NodeInfo
nodeOf t = NodeInfo UDP
  (SocketAddress (IPv4 (Socket.tupleToHostAddress (127, 0, 0, 1))) (PortNumber (Tox.selfUdpPort t)))
  (Tox.selfDhtId t)

-- | Something to keep doing, given who does it. Returns how to stop.
type Workload = Peer -> Peer -> Peer -> IO (IO ())

every :: Int -> IO () -> IO (IO ())
every millis act = do
  running <- newIORef True
  void . forkIO . handleJust stopped pure $
    let go = readIORef running >>= \r -> when r (act >> threadDelay (millis * 1000) >> go) in go
  pure (writeIORef running False)

handle :: Peer -> (Event -> IO ()) -> IO ()
handle p = writeIORef (peerHandler p)

idle :: Workload
idle _ _ _ = pure (pure ())

-- | Like a device answering its home's requests.
lossless :: Workload
lossless a b _ = do
  handle b $ \case
    FriendLosslessPacket pk _ -> void $ Tox.friendSendLosslessPacket (peerTox b) pk (BS.cons 160 (BS.replicate 400 7))
    _ -> pure ()
  every 100 . void $ Tox.friendSendLosslessPacket (peerTox a) (Tox.selfPublicKey (peerTox b)) (BS.pack [160, 1, 2, 3])

messages :: Workload
messages a b _ = do
  handle b $ \case
    FriendMessage pk ty text -> void $ Tox.friendSendMessage (peerTox b) pk ty text
    _ -> pure ()
  every 50 . void $ Tox.friendSendMessage (peerTox a) (Tox.selfPublicKey (peerTox b)) Tox.MessageNormal (BS.replicate 200 65)

-- | A file of 1 MB, sent again whenever it's through.
files :: Workload
files a b _ = do
  let file = BS.replicate 1000000 7
      to = Tox.selfPublicKey (peerTox b)
      send = void $ Tox.fileSend (peerTox a) to Tox.fileKindData (fromIntegral (BS.length file)) Nothing (BS.pack [102])
  handle a $ \case
    FileChunkRequest pk _ _ 0 | pk == to -> send
    FileChunkRequest pk n position len | pk == to ->
      void $ Tox.fileSendChunk (peerTox a) pk n position (BS.take len (BS.drop (fromIntegral position) file))
    _ -> pure ()
  handle b $ \case
    FileReceive pk n _ _ _ _ -> void $ Tox.fileControl (peerTox b) pk (Tox.Incoming n) Tox.FileResume
    _ -> pure ()
  send
  pure (pure ())

-- | Three in a conference, each saying something now and then.
conference :: Workload
conference a b c = do
  forM_ [b, c] $ \p -> handle p $ \case
    ConferenceInvite friend _ cookie -> void $ Tox.conferenceJoin (peerTox p) friend cookie
    _ -> pure ()
  g <- Tox.conferenceNew (peerTox a) >>= maybe (fail "No conference") pure
  forM_ [b, c] $ \p -> Tox.conferenceInvite (peerTox a) (Tox.selfPublicKey (peerTox p)) g
  stops <- forM [a, b, c] $ \p -> every 200 $
    Tox.conferenceList (peerTox p) >>= mapM_ (\g' -> Tox.conferenceSendMessage (peerTox p) g' Tox.MessageNormal (BS.replicate 100 66))
  pure (sequence_ stops >> void (Tox.conferenceDelete (peerTox a) g))

-- | A friend sending as fast as it can, to a client that takes its events
-- slowly.
flood :: Workload
flood a b _ = do
  handle b $ const (threadDelay 10000)
  every 1 . replicateM_ 10 . void $
    Tox.friendSendLosslessPacket (peerTox a) (Tox.selfPublicKey (peerTox b)) (BS.cons 160 (BS.replicate 1000 7))

-- | Someone sending Nodes Requests as fast as it can, each from a new key,
-- as anyone can.
requests :: Workload
requests _ b _ = do
  sock <- Socket.socket Socket.AF_INET Socket.Datagram Socket.defaultProtocol
  let to = Socket.SockAddrInet (fromIntegral (Tox.selfUdpPort (peerTox b))) (Socket.tupleToHostAddress (127, 0, 0, 1))
      send = do
        keys <- KeyPair.newKeyPair
        nonce <- Nonce.newNonce
        key <- KeyPair.publicKey <$> KeyPair.newKeyPair
        let request = RpcPacket (NodesRequest key) (RequestId 0)
            packet = Packet PacketKind.NodesRequest (DhtPacket.encode keys (Tox.selfDhtId (peerTox b)) nonce request)
        void $ SocketBS.sendTo sock (LBS.toStrict (Binary.encode packet)) to
  -- The socket stays open, as a send may still be on its way.
  every 1 (replicateM_ 2 send)

-- | Live bytes after a major GC.
live :: IO Double
live = performMajorGC >> fromIntegral . Stats.gcdetails_live_bytes . Stats.gc <$> Stats.getRTSStats

-- | A second for each sample. From the first third to the last, so one GC
-- that comes late doesn't count.
growth :: [Double] -> Double
growth ys = (mean (drop (n - third) ys) - mean (take third ys)) / fromIntegral (n - third)
  where
    n = length ys
    third = max 1 (n `div` 3)
    mean xs = sum xs / fromIntegral (length xs)

-- | Whether it stayed under 'maxGrowth'.
measure :: Int -> (String, Int, Workload) -> Peer -> Peer -> Peer -> IO Bool
measure seconds (name, warm, workload) a b c = do
  stop <- workload a b c
  threadDelay (warm * 1000000)
  before <- Stats.getRTSStats
  samples <- forM [1 .. seconds] $ \_ -> threadDelay 1000000 >> live
  after <- Stats.getRTSStats
  busiest <- take 3 . sortOn (Down . laneTotal . snd) . Map.toList . Map.unionsWith add
    <$> mapM (Tox.timings . peerTox) [a, b, c]
  largest <- take 3 . sortOn (Down . Tox.sizeCount) . concat <$> mapM (Tox.sizes . peerTox) [a, b, c]
  stop
  mapM_ (\p -> handle p (const (pure ()))) [a, b, c]
  let grown = growth samples
      spent f = fromIntegral (f after - f before) :: Double
      perSecond = fromIntegral seconds :: Double
      megabytes = (/ 1e6)
      ok = grown <= maxGrowth
  printf "%-11s live %5.1f to %5.1f MB, %6.1f KB/s; allocated %6.1f MB/s; GC %4.1f%% of CPU%s\n"
    name (megabytes (sum (take 1 samples))) (megabytes (sum (take 1 (reverse samples)))) (grown / 1000)
    (megabytes (spent Stats.allocated_bytes) / perSecond)
    (100 * spent Stats.gc_cpu_ns / max 1 (spent Stats.cpu_ns))
    (if ok then "" else "  GROWS")
  -- The last 10 s, in all three.
  printf "            busiest: %s\n" $ List.intercalate ", "
    [ printf "%s %d ms in %d" (Text.unpack name') (laneTotal l `div` 1000000) (laneCount l) :: String | (name', l) <- busiest ]
  printf "            largest: %s\n" $ List.intercalate ", "
    [ printf "%s %d" (Text.unpack (Tox.sizeName z)) (Tox.sizeCount z) :: String | z <- largest ]
  pure ok
  where
    add (Lane n t w) (Lane n' t' w') = Lane (n + n') (t + t') (max w w')

-- | Until each of the two is online to the other.
befriend :: Peer -> Peer -> IO ()
befriend p q = do
  online <- newIORef (0 :: Int)
  let seen = atomicModifyIORef' online (\n -> (n + 1, ()))
  forM_ [(p, q), (q, p)] $ \(x, y) -> do
    handle x $ \case
      FriendConnectionChanged pk status | pk == Tox.selfPublicKey (peerTox y), status /= Tox.NotConnected -> seen
      _ -> pure ()
    void $ Tox.friendAddNoRequest (peerTox x) (Tox.selfPublicKey (peerTox y))
  let wait = readIORef online >>= \n -> unless (n >= 2) (threadDelay 100000 >> wait)
  timeout (60 * 1000000) wait >>= maybe (fail "The friends didn't come online") pure

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  -- How long, then which workloads (all if none are named).
  (seconds, names) <- getArgs >>= \case
    s : ns -> pure (read s, ns)
    []     -> pure (defaultLength, [])
  let chosen = [ w | w@(name, _, _) <- workloads, null names || name `elem` names ]
  enabled <- Stats.getRTSStatsEnabled
  unless enabled $ fail "Run with +RTS -T"
  helpers <- mapM (const newPeer) [1 .. 3 :: Int]
  [a, b, c] <- mapM (const newPeer) [1 .. 3 :: Int]
  let everyone = map peerTox (a : b : c : helpers)
  sequence_ [Tox.bootstrap p (nodeOf q) | p <- everyone, q <- everyone, Tox.selfPublicKey p /= Tox.selfPublicKey q]
  befriend a b
  befriend a c
  threadDelay (settle * 1000000)
  oks <- forM chosen $ \w -> measure seconds w a b c
  mapM_ Tox.kill everyone
  unless (and oks) exitFailure
  where
    workloads =
      [ ("idle", warmUp, idle)
      , ("lossless", warmUp, lossless)
      , ("messages", warmUp, messages)
      , ("files", warmUp, files)
      , ("conference", warmUp, conference)
      , ("flood", hostileWarmUp, flood)
      , ("requests", hostileWarmUp, requests)
      ]
