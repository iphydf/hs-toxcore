{-# LANGUAGE LambdaCase    #-}
{-# LANGUAGE StrictData    #-}
{-# LANGUAGE TupleSections #-}
-- | Runs many Tox instances in this process, each with its own UDP socket on
-- this machine and the real clock, to check what the simulator says. The
-- first few only serve the DHT, and everyone bootstraps from them. The others
-- run with random friends for the warm-up, then the joiners start, their
-- friends knowing their keys. It tells how long the joiners' friendships
-- take until both ends are online. Each of the three kinds can be c-toxcore
-- instead, to see that we work well with it.
module Main (main) where

import           Control.Concurrent                 (forkIO, newEmptyMVar,
                                                     putMVar, takeMVar,
                                                     threadDelay)
import           Control.Concurrent.STM             (TVar, atomically,
                                                     flushTQueue, modifyTVar',
                                                     newTQueueIO, newTVarIO,
                                                     readTVarIO, writeTQueue)
import           Control.Monad                      (filterM, foldM, forM,
                                                     forM_, forever, replicateM,
                                                     unless, void, when, (>=>))
import           Control.Monad.Random               (Rand, evalRand, getRandomR)
import           Crypto.Saltine                     (sodiumInit)
import qualified Crypto.Saltine.Class               as Saltine
import           Data.Either                        (fromRight)
import           Data.List                          (sort)
import           Data.Map.Strict                    (Map)
import qualified Data.Map.Strict                    as Map
import           Data.Maybe                         (fromMaybe, mapMaybe)
import           Data.Set                           (Set)
import qualified Data.Set                           as Set
import           Data.Text                          (Text)
import qualified Data.Text                          as Text
import qualified Network.Tox.C                      as C
import           Options.Applicative
import qualified System.Clock                       as Clock
import           System.IO                          (BufferMode (..),
                                                     hSetBuffering, stdout)
import           System.Random                      (StdGen, mkStdGen)
import           Text.Printf                        (printf)

import qualified Tox.Application.Tox                as Tox
import           Tox.Core.Log                       (LogLevel (..))
import           Tox.Crypto.Core.Key                (CryptoNumber, Key,
                                                     PublicKey, SecretKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes   (newKeyPair)
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.PortNumber        (PortNumber)
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

data Options = Options
  { optNodes   :: Int
  , optFriends :: Int
  , optSeeds   :: Int
  , optJoiners :: Int
  , optWarmup  :: Int
  , optSeconds :: Int
  , optSeed    :: Int
  , optCSeeds  :: Bool
  , optCWarm   :: Bool
  , optCJoin   :: Bool
  }

options :: Parser Options
options = Options
  <$> option auto (long "nodes" <> value 100 <> showDefault <> help "Nodes with friends")
  <*> option auto (long "friends-each" <> value 10 <> showDefault <> help "Friends per node, on average")
  <*> option auto (long "seeds" <> value 4 <> showDefault <> help "Nodes that only serve the DHT, which everyone bootstraps from")
  <*> option auto (long "joiners" <> value 10 <> showDefault <> help "Nodes that start after the warm-up, the only ones measured")
  <*> option auto (long "warmup" <> value 120 <> showDefault <> help "Seconds the others run before the joiners start")
  <*> option auto (long "seconds" <> value 60 <> showDefault <> help "Seconds to watch the joiners for")
  <*> option auto (long "seed" <> value 1 <> showDefault <> help "For the friends and the joiners' keys")
  <*> switch (long "c-seeds" <> help "The seeds run c-toxcore")
  <*> switch (long "c-warm" <> help "The nodes started before the joiners run c-toxcore")
  <*> switch (long "c-joiners" <> help "The joiners run c-toxcore")

-- | Friendships as pairs of node numbers, lower first: each node picks half
-- its friends at random, as tox-sim does.
friendPairs :: Options -> Set (Int, Int)
friendPairs opts = evalRand (foldM pick Set.empty picks) (mkStdGen (optSeed opts))
  where
    n = optNodes opts
    picks = [ i | i <- [1 .. n], _ <- [1 .. optFriends opts `div` 2] ]
    pick :: Set (Int, Int) -> Int -> Rand StdGen (Set (Int, Int))
    pick pairs i = do
      j <- getRandomR (1, n)
      let p = (min i j, max i j)
      if j == i || Set.member p pairs then pick pairs i else return (Set.insert p pairs)

-- | A node's UDP address: all are on this machine.
local :: PortNumber -> SocketAddress
local = SocketAddress (IPv4 (tupleToHostAddress (127, 0, 0, 1)))

-- | What all instances saw: when each first saw each friend online, and
-- their info log lines, by node number, newest first.
data Seen = Seen
  { seenOnline :: TVar (Map (PublicKey, PublicKey) Clock.TimeSpec)
  , seenLogs   :: TVar (Map Int [(Clock.TimeSpec, Text)])
  }

-- | When we saw the friend online.
cameOnline :: Seen -> PublicKey -> PublicKey -> IO ()
cameOnline seen us them = do
  now <- Clock.getTime Clock.Monotonic
  atomically . modifyTVar' (seenOnline seen) $ Map.insertWith (\_ old -> old) (us, them) now

-- | A Tox instance of either library.
data Node = Node
  { nodeKey       :: PublicKey
  , nodeDht       :: NodeInfo
  , nodeBootstrap :: NodeInfo -> IO ()
  , nodeBefriend  :: PublicKey -> IO ()
  , nodeOnline    :: IO Bool
    -- ^ Whether it's connected to the network.
  }

-- | An instance of the library the switch picks, bootstrapping from the
-- seeds.
start :: Bool -> Seen -> Int -> Maybe SecretKey -> [NodeInfo] -> IO Node
start c = if c then startC else startHs

startHs :: Seen -> Int -> Maybe SecretKey -> [NodeInfo] -> IO Node
startHs seen i key seeds = do
  -- Info lines, and when we tell friends our DHT key.
  let logged level line = when (level >= LevelInfo || Text.pack "Sent our DHT public key" `Text.isPrefixOf` line) $ do
        now <- Clock.getTime Clock.Monotonic
        atomically . modifyTVar' (seenLogs seen) $ Map.insertWith (++) i [(now, line)]
  tox <- Tox.new Tox.defaultOptions
    { Tox.optSaveData = maybe Tox.NoSaveData Tox.SecretKey key, Tox.optLocalDiscovery = False, Tox.optUdpPorts = (0, 0)
    , Tox.optIpv6Enabled = False, Tox.optLogger = logged }
    >>= either (fail . show) return
  mapM_ (Tox.bootstrap tox) seeds
  let us = Tox.selfPublicKey tox
  void . forkIO . forever $ Tox.nextEvent tox >>= \case
    Tox.FriendConnectionChanged pk status | status /= Tox.NotConnected -> cameOnline seen us pk
    _ -> return ()
  return Node
    { nodeKey = us
    , nodeDht = NodeInfo UDP (local (fromIntegral (Tox.selfUdpPort tox))) (Tox.selfDhtId tox)
    , nodeBootstrap = Tox.bootstrap tox
    , nodeBefriend = void . Tox.friendAddNoRequest tox
    , nodeOnline = (/= Tox.NotConnected) <$> Tox.selfConnectionStatus tox }

-- | A c-toxcore instance in its own thread, which alone calls it.
startC :: Seen -> Int -> Maybe SecretKey -> [NodeInfo] -> IO Node
startC seen i key seeds = do
  defaults <- C.defaultOptions >>= either (fail . show) return
  -- Its default ports are the ones Tox clients on this machine use.
  let from = 20000 + fromIntegral ((i + 32) * 50 `mod` 40000)
      opts = defaults
        { C.ipv6Enabled = False, C.localDiscoveryEnabled = False, C.startPort = from, C.endPort = from + 49
        , C.savedataType = maybe C.SavedataTypeNone (const C.SavedataTypeSecretKey) key
        , C.savedata = maybe mempty Saltine.encode key }
  calls <- newTQueueIO
  ready <- newEmptyMVar
  void . forkIO $ C.withTox opts (\tox -> do
    us <- fromC <$> C.toxSelfGetPublicKey tox
    dht <- fromC <$> C.toxSelfGetDhtId tox
    port <- fromRight 0 <$> C.toxSelfGetUdpPort tox
    putMVar ready (Right (us, NodeInfo UDP (local (fromIntegral port)) dht))
    forever $ do
      atomically (flushTQueue calls) >>= mapM_ ($ tox)
      events <- fromRight [] <$> C.toxEventsIterate tox
      forM_ [ C.friendConnectionStatusFriendNumber e | C.FriendConnectionStatus e <- events, C.friendConnectionStatus e /= C.ConnectionNone ] $
        C.toxFriendGetPublicKey tox >=> either (const (return ())) (cameOnline seen us . fromC)
      C.toxIterationInterval tox >>= threadDelay . (1000 *) . fromIntegral)
    >>= either (putMVar ready . Left . show) return
  (us, dht) <- takeMVar ready >>= either fail return
  let later = atomically . writeTQueue calls
      bootstrapC (NodeInfo _ (SocketAddress _ port) pk) = later $ \tox ->
        void (C.toxBootstrap tox "127.0.0.1" (fromIntegral port) (toC pk))
      online = do
        answer <- newEmptyMVar
        later $ C.toxSelfGetConnectionStatus >=> putMVar answer . (/= C.ConnectionNone)
        takeMVar answer
  mapM_ bootstrapC seeds
  -- c-toxcore never bootstraps again, so its clients do while offline.
  void . forkIO . forever $ do
    threadDelay 5000000
    online >>= flip unless (mapM_ bootstrapC seeds)
  return Node
    { nodeKey = us
    , nodeDht = dht
    , nodeBootstrap = bootstrapC
    , nodeBefriend = \pk -> later $ \tox -> void (C.toxFriendAddNorequest tox (toC pk))
    , nodeOnline = online }

-- | A c-toxcore key as ours: both are the 32 bytes.
fromC :: (C.FixedBytes a, CryptoNumber b) => a -> Key b
fromC = fromMaybe (error "not a key") . Saltine.decode . C.toBytes

toC :: (C.FixedBytes a, CryptoNumber b) => Key b -> a
toC = fromMaybe (error "not a key") . C.fromBytes . Saltine.encode

main :: IO ()
main = do
  -- c-toxcore does this too, but with only our instances nobody would.
  sodiumInit
  hSetBuffering stdout LineBuffering
  opts <- execParser $ info (options <**> helper) (fullDesc <> progDesc "Times Tox friends connecting over real UDP on this machine")
  seen <- Seen <$> newTVarIO Map.empty <*> newTVarIO Map.empty
  seedNodes <- forM [1 .. optSeeds opts] $ \s -> start (optCSeeds opts) seen (negate s) Nothing []
  let seeds = map nodeDht seedNodes
  forM_ seedNodes $ \s -> mapM_ (nodeBootstrap s) [ n | n <- seeds, n /= nodeDht s ]
  let pairs = friendPairs opts
      joiners = [1 .. optJoiners opts]
      joinerKeys = Map.fromList . zip joiners $ evalRand (replicateM (optJoiners opts) newKeyPair) (mkStdGen (optSeed opts + 1))
  warm <- Map.fromList <$> forM [optJoiners opts + 1 .. optNodes opts] (\i -> (i,) <$> start (optCWarm opts) seen i Nothing seeds)
  let keyOf i = maybe (nodeKey (warm Map.! i)) KeyPair.publicKey (Map.lookup i joinerKeys)
      friendsOf i = [ keyOf (a + b - i) | (a, b) <- Set.toList pairs, i `elem` [a, b] ]
  forM_ (Map.toList warm) $ \(i, node) -> mapM_ (nodeBefriend node) (friendsOf i)
  let lib c = if c then "c-toxcore" else "hs-toxcore" :: String
  printf "%d nodes, %d friendships, %d seeds (%s); %d join after %d s (%s, the others %s)\n"
    (optNodes opts) (Set.size pairs) (optSeeds opts) (lib (optCSeeds opts)) (optJoiners opts) (optWarmup opts)
    (lib (optCJoin opts)) (lib (optCWarm opts))
  threadDelay (optWarmup opts * 1000000)
  t0 <- Clock.getTime Clock.Monotonic
  -- Each joiner's own start, with its friends, as a client starts: starting
  -- one takes a while.
  joined <- Map.fromList <$> forM joiners (\i -> do
    started <- Clock.getTime Clock.Monotonic
    node <- start (optCJoin opts) seen i (Just (KeyPair.secretKey (joinerKeys Map.! i))) seeds
    mapM_ (nodeBefriend node) (friendsOf i)
    return (i, (started, node)))
  t1 <- Clock.getTime Clock.Monotonic
  threadDelay (optSeconds opts * 1000000)
  online <- readTVarIO (seenOnline seen)
  logs <- readTVarIO (seenLogs seen)
  let measured = [ p | p@(i, j) <- Set.toList pairs, i `elem` joiners || j `elem` joiners ]
      startOf (i, j) = maximum (t0 : [ t | k <- [i, j], Just (t, _) <- [Map.lookup k joined] ])
      after from t = fromIntegral (Clock.toNanoSecs (t - from)) / 1e9 :: Double
      both p@(i, j) = (\a b -> after (startOf p) (max a b)) <$> Map.lookup (keyOf i, keyOf j) online <*> Map.lookup (keyOf j, keyOf i) online
      times = sort (mapMaybe both measured)
      at :: Double -> Double
      at q = if null times then 0 else times !! min (length times - 1) (floor (q * fromIntegral (length times)))
  printf "the joiners took %.1f s to start\n" (after t0 t1)
  printf "connected %d of %d joiner friendships\n" (length times) (length measured)
  printf "seconds after the later end started: median %.1f, p90 %.1f, p99 %.1f, max %.1f\n"
    (at 0.5) (at 0.9) (at 0.99) (if null times then 0 else last times)
  when (length times < length measured) $
    printf "not connected: %s\n" (show [ p | p <- measured, both p == Nothing ])
  -- Nodes stuck on their own, if any.
  let nodes = Map.toList (warm <> (snd <$> joined)) <> zip (map negate [1 ..]) seedNodes
  offline <- map fst <$> filterM (fmap not . nodeOnline . snd) nodes
  printf "not connected to the network: %s\n" (show offline)
  printf "saw no friend online: %s\n" $ show
    [ i | (i, _) <- nodes, i > 0, not (any (\(a, b) -> i `elem` [a, b] && Map.member (keyOf i, keyOf (a + b - i)) online) pairs) ]
  -- Each pair's steps as each end saw them, slowest first.
  let firstAt prefix suffix i j = let from = startOf (min i j, max i j) in case [ t | (t, line) <- reverse (Map.findWithDefault [] i logs)
                                           , (Text.pack (prefix <> show (keyOf j) <> suffix)) `Text.isPrefixOf` line ] of
        []    -> "   -  "
        t : _ -> printf "%6.1f" (after from t) :: String
      side i j = unwords [ firstAt "Received DHT public key of " "" i j, firstAt "News of " ": its address" i j
                         , firstAt "Connecting to " " at " i j ]
  putStrLn "each joiner friendship, slowest first; each end: DHT key, address, handshake"
  forM_ (reverse (sort [ (t, p) | p <- measured, Just t <- [both p] ])) $ \(t, (i, j)) ->
    printf "  %4d %4d  connected %6.1f | %4d: %s | %4d: %s\n" i j t i (side i j) j (side j i)
  -- What each end of the slowest one logged about the other.
  forM_ (take 1 (reverse (sort [ (t, p) | p <- measured, Just t <- [both p] ]))) $ \(_, p@(i, j)) ->
    forM_ [(i, j), (j, i)] $ \(a, b) -> do
      printf "node %d about %d:\n" a b
      forM_ [ (t, line) | (t, line) <- reverse (Map.findWithDefault [] a logs), Text.pack (show (keyOf b)) `Text.isInfixOf` line ] $ \(t, line) ->
        printf "  %6.1f %s\n" (after (startOf p) t) (Text.unpack line)
