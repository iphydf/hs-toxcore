{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | Runs a Tox network on the simulator's virtual clock. @cost@ writes what
-- each node costs per sample as CSV (wake-ups, steps, CPU, allocation,
-- traffic and the sizes of its state), with the live heap of the whole run.
-- @connect@ starts many nodes with random friends at once, and tells how long
-- the friends take to connect and what it cost. Minutes of network time take
-- seconds.
module Main (main) where

import           Control.Exception                  (evaluate)
import           Control.Monad                      (foldM, foldM_, forM_,
                                                     replicateM, unless, when)
import           Control.Monad.Random               (Rand, evalRand, getRandomR)
import           Data.Function                      ((&))
import           Data.Int                           (Int64)
import           Data.List                          (foldl', sort, sortOn)
import           Data.Map                           (Map)
import qualified Data.Map.Strict                    as Map
import           Data.Maybe                         (mapMaybe)
import           Data.Ord                           (Down (..))
import           Data.Set                           (Set)
import qualified Data.Set                           as Set
import qualified Data.Text                          as Text
import qualified Data.Text.IO                       as Text
import           GHC.Stats                          (gc,
                                                     gcdetails_block_fragmentation_bytes,
                                                     gcdetails_large_objects_bytes,
                                                     gcdetails_live_bytes,
                                                     gcdetails_mem_in_use_bytes,
                                                     getRTSStats,
                                                     getRTSStatsEnabled)
import           Options.Applicative                hiding (command)
import qualified Options.Applicative                as Opt
import qualified System.Clock                       as Clock
import           System.Exit                        (die)
import           System.IO                          (hPutStrLn, stderr)
import           System.Mem                         (getAllocationCounter,
                                                     performMajorGC)
import           Text.Printf                        (printf)

import           System.Random                      (StdGen, mkStdGen, randomRs)
import           Tox.Application.Node               (ConnectionStatus (..),
                                                     Event (..), Setup (..),
                                                     bootstrapNode)
import qualified Tox.Application.Sizes              as Sizes
import           Tox.Application.State              (GlobalState (..), gets)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (Timestamp)
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes   (newKeyPair)
import qualified Tox.DHT.ClientList                 as ClientList
import qualified Tox.DHT.DhtState                   as DhtState
import qualified Tox.DHT.Distance                   as Distance
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Onion.Operation                as Onion
import qualified Tox.Onion.Path                     as Path
import qualified Tox.Session.Friend                 as Messenger
import           Tox.Simulator

data Run = CostRun Options | ConnectRun ConnectOptions | TraceRun ConnectOptions

data Options = Options
  { optFriends :: Int
  , optOnline  :: Int
  , optMinutes :: Integer
  , optSample  :: Integer
  }

options :: Parser Options
options = Options
  <$> option auto (long "friends" <> value 500 <> showDefault <> help "Our friends")
  <*> option auto (long "online" <> value 5 <> showDefault <> help "Of them, online")
  <*> option auto (long "minutes" <> value 10 <> showDefault <> help "Network time to run for")
  <*> option auto (long "sample" <> value 10 <> showDefault <> help "Seconds per row")

data ConnectOptions = ConnectOptions
  { connNodes      :: Int
  , connFriends    :: Int
  , connSeeds      :: Int
  , connMinutes    :: Integer
  , connSeed       :: Int
  , connJoiners    :: Int
  , connWarmup     :: Integer
  , connPairs      :: Bool
  , connJitter     :: Integer
  , connNat        :: (Mapping, Filtering)
  , connNatShare   :: Double
  , connNatTimeout :: Integer
  , connTcpOnly    :: Double
  }

-- | NAT kinds by the names people know them by.
natKind :: ReadM (Mapping, Filtering)
natKind = eitherReader $ \case
  "full-cone"       -> Right (SamePort, FromAnyone)
  "restricted"      -> Right (SamePort, FromHostsSentTo)
  "port-restricted" -> Right (SamePort, FromAddressesSentTo)
  "symmetric"       -> Right (PortPerDestination, FromAddressesSentTo)
  other             -> Left $ "no NAT kind " <> other <> ": full-cone, restricted, port-restricted or symmetric"

connectOptions :: Parser ConnectOptions
connectOptions = ConnectOptions
  <$> option auto (long "nodes" <> value 100 <> showDefault <> help "Nodes with friends")
  <*> option auto (long "friends-each" <> value 10 <> showDefault <> help "Friends per node, on average")
  <*> option auto (long "seeds" <> value 4 <> showDefault <> help "Nodes that only serve the DHT, which everyone bootstraps from")
  <*> option auto (long "minutes" <> value 5 <> showDefault <> help "Network time to run for")
  <*> option auto (long "seed" <> value 1 <> showDefault <> help "For the keys, friends and network")
  <*> option auto (long "joiners" <> value 0 <> showDefault
        <> help "Nodes that join after the others ran for the warm-up, the only ones measured; 0 to start all at once")
  <*> option auto (long "warmup" <> value 120 <> showDefault <> help "Seconds the others run before the joiners join")
  <*> switch (long "pairs" <> help "Also each friendship's steps, as each end saw them")
  <*> option auto (long "jitter" <> value 5 <> showDefault <> help "Milliseconds a packet may take more than the 20 ms delay, at random")
  <*> option natKind (long "nat" <> value (SamePort, FromAddressesSentTo) <> showDefaultWith (const "port-restricted")
        <> help "The kind of NAT nodes are behind: full-cone, restricted, port-restricted or symmetric")
  <*> option auto (long "nat-share" <> value 0 <> showDefault <> help "The share of nodes with friends behind a NAT, at random")
  <*> option auto (long "nat-timeout" <> value 60 <> showDefault <> help "Seconds a NAT keeps a mapping with nothing going out on it")
  <*> option auto (long "tcp-only-share" <> value 0 <> showDefault
        <> help "The share of nodes with friends without UDP, at random. With these or NATs the seeds run relays, and each node uses two")

runs :: Parser Run
runs = hsubparser
  ( Opt.command "cost" (info (CostRun <$> options) (progDesc "What one node with many friends costs, as CSV"))
  <> Opt.command "connect" (info (ConnectRun <$> connectOptions) (progDesc "How long many nodes' friends take to connect"))
  <> Opt.command "trace" (info (TraceRun <$> connectOptions) (progDesc "How the first node and one friend of it get there, as their state changes"))
  )

-- | In the range for examples, so nothing takes it for a LAN.
at :: Int -> SocketAddress
at n = SocketAddress (IPv4 $ tupleToHostAddress (198, 51, (100 + fromIntegral (n `div` 256)), fromIntegral (n `mod` 256))) 33445

-- | Us, our friends that are online, and nodes that only serve the DHT, by
-- the name each has in the rows.
roles :: Options -> [(SocketAddress, Text.Text)]
roles opts = (at 1, "us")
  : [ (at n, "friend-" <> tshow n) | n <- [2 .. 1 + optOnline opts] ]
  ++ [ (at n, "dht-" <> tshow n) | n <- [1000 .. 1005] ]

-- | Everyone knows the DHT nodes. We have the friends that are online and
-- the rest, whose keys no node has.
scenario :: Options -> [KeyPair.KeyPair] -> Sim
scenario opts offline = foldl' (&) base $
  [ command a (bootstrapNode (dhtNode UDP b base)) | a <- everyone, b <- servers, a /= b ]
  ++ concat [ [ command us (Messenger.addFriend (realKey f base)), command f (Messenger.addFriend (realKey us base)) ] | f <- online ]
  ++ [ command us (Messenger.addFriend (KeyPair.publicKey k)) | k <- offline ]
  where
    everyone = map fst (roles opts)
    us = at 1
    online = [ at n | n <- [2 .. 1 + optOnline opts] ]
    servers = [ at n | n <- [1000 .. 1005] ]
    base = foldr (addNode (Setup True False False)) (newSim 1 (Link (Time.milliseconds 20) 0 0)) everyone

-- | What a node's steps took over a sample.
data Cost = Cost
  { costSteps :: Int
  , costCpu   :: Integer -- ^ Nanoseconds.
  , costAlloc :: Int64   -- ^ Bytes.
  }

instance Semigroup Cost where
  Cost a b c <> Cost a' b' c' = Cost (a + a') (b + b') (c + c')

-- | Runs to the time, each step done in full before the next, so its CPU and
-- allocation are the node's (and a little of the simulator's).
measured :: Timestamp -> Sim -> IO (Sim, Map SocketAddress Cost, Map Text.Text Cost)
measured end = go Map.empty Map.empty
  where
    go costs kinds sim = do
      cpu <- Clock.getTime Clock.ThreadCPUTime
      alloc <- getAllocationCounter
      let kind = nextKind sim
      case stepUntil end sim of
        Nothing -> return (runUntil end sim, costs, kinds)
        Just (woken, sim') -> do
          _ <- evaluate sim'
          mapM_ (evaluate . (`wakeUps` sim')) woken
          cpu' <- Clock.getTime Clock.ThreadCPUTime
          alloc' <- getAllocationCounter
          let cost = Cost 1 (Clock.toNanoSecs (cpu' - cpu)) (alloc - alloc')
              costs' = maybe costs (\a -> Map.insertWith (<>) a cost costs) woken
              kinds' = maybe kinds (\k -> Map.insertWith (<>) k cost kinds) (kind <* woken)
          costs' `seq` kinds' `seq` go costs' kinds' sim'

-- | Bytes by carrier and way.
traffic :: Map Traffic.Counted Traffic.Count -> [(Text.Text, Integer)]
traffic counts = [ (name, bytes pick) | (name, pick) <- kinds ]
  where
    bytes pick = sum [ toInteger (Traffic.countBytes c) | (what, c) <- Map.toList counts, pick what ]
    kinds =
      [ ("udp sent bytes", udp Traffic.Sent)
      , ("udp received bytes", udp Traffic.Received)
      , ("relay sent bytes", (== Traffic.RelayLink Traffic.Sent))
      , ("relay received bytes", (== Traffic.RelayLink Traffic.Received))
      ]
    udp way = \case
      Traffic.Packets w Traffic.Udp _ -> w == way
      _                               -> False

main :: IO ()
main = do
  run <- execParser $ info (runs <**> helper) (fullDesc <> progDesc "Measures Tox nodes on a virtual clock")
  enabled <- getRTSStatsEnabled
  unless enabled $ die "Needs +RTS -T, for the live heap"
  case run of
    CostRun opts    -> costRun opts
    ConnectRun opts -> connectRun opts
    TraceRun opts   -> traceRun opts

costRun :: Options -> IO ()
costRun opts = do
  -- The same keys each run, so runs compare.
  let offline = evalRand (replicateM (optFriends opts - optOnline opts) newKeyPair) (mkStdGen 2)
      sim0 = scenario opts offline
      start = simTime sim0
      ends = [ Time.addTime start (Time.seconds s) | s <- [optSample opts, 2 * optSample opts .. 60 * optMinutes opts] ]
      named = Map.fromList (roles opts)
      row t node metric v = Text.putStrLn $ Text.intercalate "," [tshow (t `div` 1000), node, "\"" <> metric <> "\"", tshow v]
  Text.putStrLn "seconds,node,metric,value"
  let sample sim end = do
        (sim', costs, _) <- measured end sim
        let t = Time.toMilliseconds (Time.diffTime end start)
        forM_ (addresses sim') $ \addr -> do
          let node = Map.findWithDefault (tshow addr) addr named
              cost = Map.findWithDefault (Cost 0 0 0) addr costs
              was = Map.fromList (traffic (trafficOf addr sim))
          row t node "wake-ups" (toInteger (wakeUps addr sim' - wakeUps addr sim))
          row t node "steps" (toInteger (costSteps cost))
          row t node "cpu us" (costCpu cost `div` 1000)
          row t node "allocated bytes" (toInteger (costAlloc cost))
          forM_ (traffic (trafficOf addr sim')) $ \(metric, v) -> row t node metric (v - Map.findWithDefault 0 metric was)
          forM_ (peekAt addr (gets Sizes.stateSizes) sim') $ \s -> row t node (Sizes.sizeName s) (toInteger (Sizes.sizeCount s))
        performMajorGC
        stats <- gc <$> getRTSStats
        row t "all" "live bytes" (toInteger (gcdetails_live_bytes stats))
        row t "all" "large and pinned bytes" (toInteger (gcdetails_large_objects_bytes stats))
        row t "all" "fragmentation bytes" (toInteger (gcdetails_block_fragmentation_bytes stats))
        row t "all" "in use bytes" (toInteger (gcdetails_mem_in_use_bytes stats))
        return sim'
  foldM_ sample sim0 ends

tshow :: Show a => a -> Text.Text
tshow = Text.pack . show

-- | Nodes that only serve the DHT, in another range than 'at'.
seedAt :: Int -> SocketAddress
seedAt n = SocketAddress (IPv4 $ tupleToHostAddress (203, 0, 113, fromIntegral n)) 33445

-- | Friendships as pairs of node numbers, lower first: each node picks half
-- its friends at random, so nodes have that many on average.
friendPairs :: ConnectOptions -> StdGen -> Set (Int, Int)
friendPairs opts = evalRand (foldM pick Set.empty picks)
  where
    n = connNodes opts
    picks = [ i | i <- [1 .. n], _ <- [1 .. connFriends opts `div` 2] ]
    pick :: Set (Int, Int) -> Int -> Rand StdGen (Set (Int, Int))
    pick pairs i = do
      j <- getRandomR (1, n)
      let p = (min i j, max i j)
      if j == i || Set.member p pairs then pick pairs i else return (Set.insert p pairs)

-- | How a node with friends reaches the network.
data Reach = Public | Natted | TcpOnly
  deriving (Eq, Ord, Show)

-- | Each node's, at random by the seed.
reachOf :: ConnectOptions -> Int -> Reach
reachOf opts i = reaches Map.! i
  where
    reaches = Map.fromList . zip [1 .. connNodes opts] . map pick $ randomRs (0, 1) (mkStdGen (connSeed opts + 2))
    pick :: Double -> Reach
    pick u
      | u < connTcpOnly opts = TcpOnly
      | u < connTcpOnly opts + connNatShare opts = Natted
      | otherwise = Public

-- | Whether the seeds run relays for the nodes that need them.
withRelays :: ConnectOptions -> Bool
withRelays opts = connNatShare opts > 0 || connTcpOnly opts > 0

-- | The NAT's public host, in a range no one takes for a LAN.
natHostOf :: Int -> HostAddress
natHostOf n = IPv4 $ tupleToHostAddress (198, 18, fromIntegral (n `div` 256), fromIntegral (n `mod` 256))

-- | The network as the measured nodes start: all nodes at once, knowing
-- only the seeds and adding their friends; or, with joiners, the others
-- having run for the warm-up with their friends added, the joiners' too.
connectScenario :: ConnectOptions -> Set (Int, Int) -> Sim
connectScenario opts pairs
  | connJoiners opts == 0 = start [1 .. connNodes opts] (const Nothing) seeded
  | otherwise = start joiners (`lookup` zip joiners keys) . runUntil warm $ start others (const Nothing) seeded
  where
    joiners = [1 .. connJoiners opts]
    others = [connJoiners opts + 1 .. connNodes opts]
    keys = evalRand (replicateM (connJoiners opts) newKeyPair) (mkStdGen (connSeed opts + 1))
    seeds = map seedAt [1 .. connSeeds opts]
    seeded = foldr (if withRelays opts then addRelay udp else addNode udp) (newSim (connSeed opts) (Link (Time.milliseconds 20) (Time.milliseconds (connJitter opts)) 0)) seeds
    udp = Setup True False False
    setupOf i = if reachOf opts i == TcpOnly then Setup False False False else udp
    -- Behind its NAT before it sends anything.
    placed i sim = case reachOf opts i of
      Natted -> setNat (at i) (Nat (natHostOf i) (fst (connNat opts)) (snd (connNat opts)) (Time.seconds (connNatTimeout opts))) sim
      _      -> sim
    -- Two of the seeds' relays, a different two for the next node.
    relaysOf i = [ seeds !! ((i + k) `mod` length seeds) | withRelays opts, k <- [0, 1] ]
    warm = Time.addTime (simTime seeded) (Time.seconds (connWarmup opts))
    -- Adds the nodes, with these real keys if given, bootstraps them, and
    -- adds their friends (a joiner by its key before it joined).
    -- The seeds bootstrap from each other the first time.
    start ns given sim0 = foldl' (&) sim $
      [ command a (bootstrapNode (dhtNode UDP s sim))
      | a <- map at ns ++ (if sim0 `hasOnly` seeds then seeds else []), s <- seeds, a /= s ]
      ++ [ command (at i) (Tcp.addRelay (dhtNode TCP r sim)) | i <- ns, r <- relaysOf i ]
      ++ [ command (at i) (Messenger.addFriend (keyOf j)) | (a, b) <- Set.toList pairs, (i, j) <- [(a, b), (b, a)], i `elem` ns ]
      where
        sim = foldr (\i -> placed i . maybe (addNode (setupOf i) (at i)) (\k -> addNodeWith (setupOf i) k (at i)) (given i)) sim0 ns
        keyOf j = maybe (realKey (at j) sim) KeyPair.publicKey (lookup j (zip joiners keys))
    hasOnly sim0 ns = all (`elem` ns) (addresses sim0)

-- | When the node first saw each friend online, and how often one went
-- offline again since the start.
onlineAt :: Timestamp -> Sim -> SocketAddress -> (Map PublicKey Timestamp, Int)
onlineAt start sim addr = (Map.fromListWith min [ (pk, t) | (t, FriendConnectionChanged pk s) <- events, s /= NotConnected ], drops)
  where
    events = eventsOf addr sim
    drops = length [ () | (t, FriendConnectionChanged _ NotConnected) <- events, t >= start ]

-- | Network seconds after the start until both ends saw each other online,
-- for the pairs that did, with how often friends went offline again.
connectTimes :: Timestamp -> Set (Int, Int) -> Sim -> ([Double], Int)
connectTimes start pairs sim = (mapMaybe both (Set.toList pairs), sum (map snd seen))
  where
    seen = map (onlineAt start sim . at) [1 .. maximum (0 : concat [ [i, j] | (i, j) <- Set.toList pairs ])]
    seenBy i = fst (seen !! (i - 1))
    key i = realKey (at i) sim
    both (i, j) = do
      a <- Map.lookup (key j) (seenBy i)
      b <- Map.lookup (key i) (seenBy j)
      return $ fromIntegral (Time.toMilliseconds (Time.diffTime (max a b) start)) / 1000

-- | How far each pair got by when, the first end to get there: its friend's
-- DHT key through the onion, its address through the DHT, and the handshake
-- started. Seconds after the start, by step, as the nodes' logs tell it.
phases :: Timestamp -> Set (Int, Int) -> Sim -> [(String, [Double])]
phases start pairs sim =
  [ (name, mapMaybe (reached prefix suffix) (Set.toList pairs)) | (name, prefix, suffix) <- steps ]
  where
    steps =
      [ ("DHT key through the onion", "Received DHT public key of ", "")
      , ("address through the DHT", "News of ", ": its address")
      , ("handshake started", "Connecting to ", " at ")
      ]
    seen = Map.fromList [ (i, logOf (at i) sim) | i <- Set.toList (Set.fromList (concat [ [i, j] | (i, j) <- Set.toList pairs ])) ]
    keyText i = tshow (realKey (at i) sim)
    firstAt prefix suffix i j = [ t | (t, line) <- Map.findWithDefault [] i seen, (prefix <> keyText j <> suffix) `Text.isPrefixOf` line ]
    reached prefix suffix (i, j) = case firstAt prefix suffix i j ++ firstAt prefix suffix j i of
      [] -> Nothing
      ts -> Just $ fromIntegral (Time.toMilliseconds (Time.diffTime (minimum ts) start)) / 1000

-- | Each pair's steps as each end saw them, slowest pair first: when it got
-- the other's DHT key through the onion, its address through the DHT, and
-- started a handshake with it, and when both were online.
pairSteps :: Timestamp -> Set (Int, Int) -> Sim -> [String]
pairSteps start pairs sim = map row . sortOn (Down . fst) $ mapMaybe withTime (Set.toList pairs)
  where
    times = Map.fromList [ (p, t) | p <- Set.toList pairs, t <- fst (connectTimes start (Set.singleton p) sim) ]
    withTime p = (\t -> (t, p)) <$> Map.lookup p times
    keyText i = tshow (realKey (at i) sim)
    firstAt prefix suffix i j = case [ t | (t, line) <- logOf (at i) sim, (prefix <> keyText j <> suffix) `Text.isPrefixOf` line ] of
      [] -> "   -  "
      t : _ -> printf "%6.1f" (fromIntegral (Time.toMilliseconds (Time.diffTime t start)) / 1000 :: Double)
    side i j = unwords [ firstAt "Received DHT public key of " "" i j, firstAt "News of " ": its address" i j
                       , firstAt "Connecting to " " at " i j, firstAt "Accepting session from " " at " i j ]
    row (t, (i, j)) = printf "  %4d %4d  connected %6.1f | %4d: %s | %4d: %s" i j t i (side i j) j (side j i)

-- | When each node first got this far: enough DHT nodes to build paths from,
-- paths to announce and search through, and itself stored on an announce
-- node. Seen by looking at its state each network second.
nodeSteps :: [(String, GlobalState -> Bool)]
nodeSteps =
  [ ("8 DHT nodes", (>= 8) . DhtState.size . dhtState)
  , ("onion paths", \gs -> let p = Onion.onionPaths (onionState gs) in not (null (Path.announcePaths p) || null (Path.searchPaths p)))
  , ("announced", any ((== Onion.StoresUs) . Onion.onStatus) . Onion.selfNodes . onionState)
  ]

-- | Whether the node knows an announce node that stores the friend.
located :: PublicKey -> GlobalState -> Bool
located pk = maybe False (any (storesFriend . Onion.onStatus) . Onion.ofNodes) . Map.lookup pk . Onion.onionFriends . onionState
  where
    storesFriend = \case
      Onion.StoresFriend _ -> True
      _                    -> False

-- | What nodes and pairs reached by when: the steps of 'nodeSteps' by node,
-- and by pair when the first end located the other.
data Milestones = Milestones (Map (String, Int) Timestamp) (Map (Int, Int) Timestamp)

observe :: [Int] -> Set (Int, Int) -> Sim -> Milestones -> Milestones
observe ns pairs sim (Milestones reached found) = Milestones
  (foldl' first reached [ ((name, i), ()) | i <- ns, let gs = state i, (name, test) <- nodeSteps, not (Map.member (name, i) reached), test gs ])
  (foldl' first found [ (p, ()) | p@(i, j) <- Set.toList pairs, not (Map.member p found)
                                , located (realKey (at j) sim) (state i) || located (realKey (at i) sim) (state j) ])
  where
    state i = peekAt (at i) (gets id) sim
    first m (k, ()) = Map.insertWith (\_ old -> old) k (simTime sim) m

-- | The nodes' wake-ups, steps, CPU (nanoseconds) and bytes sent.
data Totals = Totals Int Int Integer Integer

-- | The nodes measured: the joiners, or with none, all.
measuredNodes :: ConnectOptions -> [Int]
measuredNodes opts = [1 .. if connJoiners opts == 0 then connNodes opts else connJoiners opts]

-- | The friendships of the measured nodes.
measuredPairs :: ConnectOptions -> Set (Int, Int) -> Set (Int, Int)
measuredPairs opts = Set.filter (\(i, j) -> any (`elem` measuredNodes opts) [i, j])

-- | The value below which that share of the sorted list lies.
percentile :: Double -> [Double] -> Double
percentile _ [] = 0
percentile q xs = xs !! min (length xs - 1) (floor (q * fromIntegral (length xs)))

connectRun :: ConnectOptions -> IO ()
connectRun opts = do
  let allPairs = friendPairs opts (mkStdGen (connSeed opts))
      pairs = measuredPairs opts allPairs
      total = Set.size pairs
      nodes = map at [1 .. connNodes opts]
  printf "%d nodes, %d friendships (%.1f friends each), %d seeds, seed %d\n"
    (connNodes opts) (Set.size allPairs) (2 * fromIntegral (Set.size allPairs) / fromIntegral (connNodes opts) :: Double)
    (connSeeds opts) (connSeed opts)
  unless (connJoiners opts == 0) $ printf "%d join after %d s, with %d friendships; only they are measured, from when they join\n"
    (connJoiners opts) (connWarmup opts) total
  -- Now, so the warm-up's work isn't counted as the joiners'.
  sim0 <- evaluate (connectScenario opts allPairs)
  let start = simTime sim0
      ends = [ Time.addTime start (Time.seconds s) | s <- [1 .. 60 * connMinutes opts] ]
  wall0 <- Clock.getTime Clock.Monotonic
  cpu0 <- Clock.getTime Clock.ProcessCPUTime
  let nodeSet = Set.fromList nodes
      sofar sim costs = Totals
        (sum (map (`wakeUps` sim) nodes))
        (sum [ costSteps c | (a, c) <- Map.toList costs, Set.member a nodeSet ])
        (sum [ costCpu c | (a, c) <- Map.toList costs, Set.member a nodeSet ])
        (sum [ toInteger (Traffic.countBytes c) | a <- nodes, (what, c) <- Map.toList (trafficOf a sim), sent what ])
      sent = \case
        Traffic.Packets Traffic.Sent _ _ -> True
        Traffic.RelayLink Traffic.Sent   -> True
        _                                -> False
      sample (sim, costs, peak, ms, mark, rows, kinds) end = do
        (sim', costs', kinds') <- measured end sim
        -- Now, or it holds on to each second's network until the end.
        ms' <- evaluate (observe (measuredNodes opts) pairs sim' ms)
        let secs = Time.toMilliseconds (Time.diffTime end start) `div` 1000
        live <- if secs `mod` 10 /= 0 then return peak else do
          performMajorGC
          live <- gcdetails_live_bytes . gc <$> getRTSStats
          wall <- Clock.getTime Clock.Monotonic
          hPutStrLn stderr $ printf "%4ds: %d/%d connected, %.1f s real, %d MB live, %d in flight, %d events and log lines kept"
            secs (length (fst (connectTimes start pairs sim'))) total (seconds (wall - wall0)) (live `div` 1000000)
            (inFlight sim') (kept sim')
          -- What the nodes hold, the biggest first.
          let held = Map.unionsWith (+) [ Map.fromList [ (Sizes.sizeName z, Sizes.sizeCount z) | z <- peekAt a (gets Sizes.stateSizes) sim' ] | a <- nodes ]
          hPutStrLn stderr . ("      " <>) . unwords $
            [ printf "%s %d;" (Text.unpack name) count | (name, count) <- take 8 (sortOn (Down . snd) (Map.toList held)) ]
          return live
        let costs'' = Map.unionWith (<>) costs costs'
            kinds'' = Map.unionWith (<>) kinds kinds'
        if secs `mod` 60 /= 0 then return (sim', costs'', max peak live, ms', mark, rows, kinds'') else do
          now <- evaluate (sofar sim' costs'')
          return (sim', costs'', max peak live, ms', now, rows ++ [(secs `div` 60, minus now mark)], kinds'')
      minus (Totals a b c d) (Totals a' b' c' d') = Totals (a - a') (b - b') (c - c') (d - d')
  (sim, costs, peak, Milestones reached found, _, rows, kinds) <-
    foldM sample (sim0, Map.empty, 0, Milestones Map.empty Map.empty, sofar sim0 Map.empty, [], Map.empty) ends
  wall <- Clock.getTime Clock.Monotonic
  cpu <- Clock.getTime Clock.ProcessCPUTime
  let (times, drops) = connectTimes start pairs sim
      sorted = sort times
      minutes = fromIntegral (connMinutes opts) :: Double
      nodeCpu = sum (map costCpu (Map.elems costs))
      perNode = Map.unionsWith Traffic.addCount (map (`trafficOf` sim) nodes)
      perNodeMinute :: Traffic.Count -> Double
      perNodeMinute c = fromIntegral (Traffic.countBytes c) / fromIntegral (connNodes opts) / minutes
  printf "connected %d of %d (%.1f%%), friends went offline again %d times\n"
    (length times) total (100 * fromIntegral (length times) / fromIntegral (max 1 total) :: Double) drops
  let since t = fromIntegral (Time.toMilliseconds (Time.diffTime t start)) / 1000 :: Double
  putStrLn "seconds after the start (median, p90, p99, max, how many), per node:"
  let line :: String -> [Double] -> IO ()
      line name xs = let ys = sort xs in printf "  %-28s %6.1f %6.1f %6.1f %6.1f  %d\n" name
        (percentile 0.5 ys) (percentile 0.9 ys) (percentile 0.99 ys) (if null ys then 0 else last ys) (length ys)
  forM_ nodeSteps $ \(name, _) -> line name [ since t | ((step, _), t) <- Map.toList reached, step == name ]
  putStrLn "per friendship, the first end to get there:"
  line "friend located" (map since (Map.elems found))
  forM_ (phases start pairs sim) (uncurry line)
  line "connected" sorted
  when (withRelays opts) $ do
    let reach = reachOf opts
        timed = Map.fromList [ (p, t) | p <- Set.toList pairs, t <- fst (connectTimes start (Set.singleton p) sim) ]
        lastSeen i j = [ st | (_, FriendConnectionChanged pk st) <- eventsOf (at i) sim, pk == realKey (at j) sim ]
        onUdp (i, j) = all ((== [ConnectedUdp]) . take 1 . reverse) [lastSeen i j, lastSeen j i]
        classes = Map.fromListWith (++) [ ((min (reach i) (reach j), max (reach i) (reach j)), [p]) | p@(i, j) <- Set.toList pairs ]
    putStrLn "connected, by how the ends reach the network; then how many, and on UDP at the end:"
    forM_ (Map.toList classes) $ \((a, b), ps) -> do
      let ys = sort (mapMaybe (`Map.lookup` timed) ps)
      printf "  %-28s %6.1f %6.1f %6.1f %6.1f  %d of %d, %d on UDP\n" (show a <> " with " <> show b)
        (percentile 0.5 ys) (percentile 0.9 ys) (percentile 0.99 ys) (if null ys then 0 else last ys)
        (length ys) (length ps) (length (filter onUdp ps))
  when (connPairs opts) $ do
    putStrLn "each friendship, slowest first; each end: DHT key, address, handshake, accepted"
    mapM_ putStrLn (pairSteps start pairs sim)
  printf "run: %.0f network s in %.1f s real, %.1f s CPU (nodes %.1f s, simulator %.1f s), peak live heap %d MB\n"
    (60 * minutes) (seconds (wall - wall0)) (seconds (cpu - cpu0))
    (fromIntegral nodeCpu / 1e9 :: Double) (seconds (cpu - cpu0) - fromIntegral nodeCpu / 1e9) (peak `div` 1000000)
  printf "per node per minute: %.0f wake-ups, %.0f steps, %.1f ms CPU\n"
    (fromIntegral (sum (map (`wakeUps` sim) nodes)) / fromIntegral (connNodes opts) / minutes :: Double)
    (fromIntegral (sum (map costSteps (Map.elems costs))) / fromIntegral (connNodes opts) / minutes :: Double)
    (fromIntegral nodeCpu / 1e6 / fromIntegral (connNodes opts) / minutes :: Double)
  let per :: Integral a => a -> Double
      per x = fromIntegral x / fromIntegral (connNodes opts)
  putStrLn "per node, each network minute: wake-ups, steps, ms CPU, KB sent"
  forM_ rows $ \(minute, Totals w st c b) ->
    printf "  minute %2d  %7.0f %7.0f %8.1f %8.1f\n" (minute :: Integer) (per w) (per st) (per c / 1e6) (per b / 1000)
  -- Who sends what since the start: the joiners, their friends, the rest.
  unless (connJoiners opts == 0) $ do
    let joiners = measuredNodes opts
        theirFriends = Set.toList . Set.fromList $ [ j | (a, b) <- Set.toList pairs, (i, j) <- [(a, b), (b, a)], i `elem` joiners, j `notElem` joiners ]
        rest = [ i | i <- [1 .. connNodes opts], i `notElem` joiners, i `notElem` theirFriends ]
        timesOf what sim' i = maybe 0 (toInteger . Traffic.countTimes) (Map.lookup what (trafficOf (at i) sim'))
        sentBytes sim' i = sum [ toInteger (Traffic.countBytes c) | (what, c) <- Map.toList (trafficOf (at i) sim'), sent what ]
        groupRate f ns = fromIntegral (sum [ f sim i - f sim0 i | i <- ns ]) / fromIntegral (max 1 (length ns)) / minutes :: Double
    putStrLn "per node per minute since the start: searches, announces, KB sent"
    forM_ [("joiners", joiners), ("their friends", theirFriends), ("the rest", rest)] $ \(name, ns) ->
      printf "  %-14s %4d nodes %8.1f %8.1f %8.1f\n" (name :: String) (length ns)
        (groupRate (timesOf (Traffic.Requests Traffic.SearchFriend)) ns)
        (groupRate (timesOf (Traffic.Requests Traffic.AnnounceUs)) ns)
        (groupRate sentBytes ns / 1000)
  putStrLn "CPU by what the step did: seconds, steps, us per step, GB allocated"
  forM_ (take 20 . sortOn (Down . costCpu . snd) $ Map.toList kinds) $ \(kind, Cost n c a) ->
    printf "  %8.1f %9d %8.1f %8.1f  %s\n" (fromIntegral c / 1e9 :: Double) n
      (fromIntegral c / 1e3 / fromIntegral (max 1 n) :: Double) (fromIntegral a / 1e9 :: Double) (Text.unpack kind)
  putStrLn "bytes per node per minute, by kind:"
  forM_ (take 25 . sortOn (Down . snd) $ [ (Traffic.countedName what, perNodeMinute c) | (what, c) <- Map.toList perNode ]) $ \(name, b) ->
    printf "  %10.0f  %s\n" b (Text.unpack name)
  where
    seconds t = fromIntegral (Clock.toNanoSecs t) / 1e9 :: Double

-- | Node 1's onion state each time it changes, looked at every 100 ms, with
-- its friend of the lowest number: DHT nodes, the bits our closest announce
-- node shares with our key, announce nodes answering and storing us, whether
-- we count as announced, the online count, and the friend's nodes answering
-- and storing them, and whether they're online.
traceRun :: ConnectOptions -> IO ()
traceRun opts = do
  let pairs = friendPairs opts (mkStdGen (connSeed opts))
      -- Node 1 is a joiner, if there are any.
      sim0 = connectScenario opts pairs
      start = simTime sim0
      friend = minimum [ if i == 1 then j else i | (i, j) <- Set.toList pairs, i == 1 || j == 1 ]
      steps = [ Time.addTime start (Time.milliseconds (100 * n)) | n <- [1 .. 600 * connMinutes opts] ]
      line sim =
        let gs = peekAt (at 1) (gets id) sim
            os = onionState gs
            ours = realKey (at 1) sim
            theirs = realKey (at friend) sim
            shared k n = maybe 256 (255 -) (Distance.log2 (Distance.xorDistance k (NodeInfo.publicKey (Onion.onNode n))))
            selfs = Map.elems (Onion.selfNodes os)
            fnodes = maybe [] (Map.elems . Onion.ofNodes) (Map.lookup theirs (Onion.onionFriends os))
            storing = length . filter (\n -> case Onion.onStatus n of Onion.StoresFriend _ -> True; _ -> False)
            online = not . null $ [ () | (_, FriendConnectionChanged pk st) <- eventsOf (at 1) sim, pk == theirs, st /= NotConnected ]
            holders = [ a | a <- addresses sim, Map.member theirs (peekAt a (gets (Onion.announceEntries . onionState)) sim) ]
            holderKeys = map (\a -> NodeInfo.publicKey (dhtNode UDP a sim)) holders
            theirDht = KeyPair.publicKey (peekAt (at friend) (gets (DhtState.dhtKeyPair . dhtState)) sim)
            search = Map.lookup theirDht (DhtState.dhtSearchList (dhtState gs))
            searchText = maybe "no DHT search" (\e -> printf "DHT search %d nodes, %s, %d say where"
              (length (ClientList.nodeInfos (DhtState.searchClientList e)))
              (maybe "not found" (const "found") (DhtState.searchNode e) :: String) (Map.size (DhtState.searchReturned e)) :: String) search
            requests purpose = maybe 0 Traffic.countTimes (Map.lookup (Traffic.Requests purpose) (trafficOf (at 1) sim))
        in printf "sent %3d announces, %3d searches | dht %3d | self: best %2d bits, %2d answer, %2d store us, announced %-5s count %d | friend %d: best %2d bits, %d asked, %d answer, %d store them (of %d holding, %d of ours), online %s | %s"
             (requests Traffic.AnnounceUs) (requests Traffic.SearchFriend)
             (DhtState.size (dhtState gs)) (maximum (0 : map (shared ours) selfs))
             (length (filter Onion.onAnswered selfs)) (length (filter ((== Onion.StoresUs) . Onion.onStatus) selfs))
             (show (Onion.isAnnounced (simTime sim) os)) (Onion.onionConnected os)
             friend (maximum (0 : map (shared theirs) fnodes))
             (maybe 0 (Map.size . Onion.ofAsked) (Map.lookup theirs (Onion.onionFriends os)))
             (length (filter Onion.onAnswered fnodes)) (storing fnodes) (length holders)
             (length [ () | n <- fnodes, Onion.onAnswered n, NodeInfo.publicKey (Onion.onNode n) `elem` holderKeys ])
             (show online) searchText :: String
      go _ _ [] = return ()
      go sim before (end : rest) = do
        let sim' = runUntil end sim
            now = line sim'
        unless (now == before) $
          printf "%6.1f  %s\n" (fromIntegral (Time.toMilliseconds (Time.diffTime end start)) / 1000 :: Double) now
        go sim' now rest
  go sim0 "" steps
