In order to announce itself using onion announce packets toxcore first takes
DHT peers, picks random ones and builds onion paths with them by saving 3
nodes, calling it a path, generating some keypairs for encrypting the onion
packets and using them to send onion packets.  If the peer is only connected
with TCP, the initial nodes will be bootstrap nodes and connected TCP relays
(for the first peer in the path).  Once the peer is connected to the onion he
can fill up his list of known peers with peers sent in announce responses if
needed.

Onion paths have different timeouts depending on whether the path is confirmed
or unconfirmed.  Unconfirmed paths (paths that core has never received any
responses from) have a timeout of 4 seconds with 2 tries before they are deemed
non working.  This is because, due to network conditions, there may be a large
number of newly created paths that do not work and so trying them a lot would
make finding a working path take much longer.  The timeout for a confirmed path
(from which a response was received) is 10 seconds with 4 tries without a
response.  A confirmed path has a maximum lifetime of 1200 seconds to make
possible deanonimization attacks more difficult.

Toxcore saves a maximum of 12 paths: 6 paths are reserved for announcing
ourselves and 6 others are used to search for friends.  This may not be the
safest way (some nodes may be able to associate friends together) however it is
much more performant than having different paths for each friend.  The main
benefit is that the announcing and searching are done with different paths,
which makes it difficult to know that peer with real public key X is friends
with Y and Z.  More research is needed to find the best way to do this.  At
first toxcore did have different paths for each friend, however, that meant
that each friend path was almost never used (and checked).  When using a low
amount of paths for searching there is less resources needed to find good
paths.  6 paths are used because 4 was too low and caused some performance
issues because it took longer to find some good paths at the beginning because
only 4 could be tried at a time.  A too high number meanwhile would mean each
path is used (and tested) less.  The reason why the numbers are the same for
both types of paths is for code simplification purposes.

\begin{code}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE StrictData            #-}
module Tox.Onion.Path where

import           Control.Monad                    (replicateM, replicateM_,
                                                   unless)
import           Control.Monad.State              (MonadState, gets, modify)
import qualified Data.ByteString                  as BS
import           Data.Function                    (on)
import           Data.List                        (find, nubBy)
import           Data.Word                        (Word32)
import           GHC.Generics                     (Generic)
import           Test.QuickCheck.Arbitrary        (Arbitrary (..))

import qualified Tox.Core.Time                    as Time
import           Tox.Core.Time                    (TimeDiff, Timestamp)
import           Tox.Core.Timed                   (Timed, askTime)
import qualified Tox.Crypto.Core.Box              as Box
import           Tox.Crypto.Core.Key              (Nonce)
import qualified Tox.Crypto.Core.Keyed            as Keyed
import           Tox.Crypto.Core.Keyed            (Keyed)
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import           Tox.Crypto.Core.KeyPair          (KeyPair (..))
import qualified Tox.Crypto.Core.MonadRandomBytes as MonadRandomBytes (uniformSafe)
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes, newKeyPair,
                                                   uniform)
import qualified Tox.Network.Core.NodeInfo        as NodeInfo
import           Tox.Network.Core.NodeInfo        (NodeInfo)
import           Tox.Network.Core.SocketAddress   (SocketAddress)
import qualified Tox.Onion.Tunnel                 as Tunnel


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}


class (MonadState OnionPathState m, Timed m, MonadRandomBytes m, Keyed m) => OnionPathMonad m


maxPaths :: Int
maxPaths = 6

-- | Nodes in a path: the first, and two more.
pathLength :: Int
pathLength = 3

pathLifetime :: TimeDiff
pathLifetime = Time.seconds 1200

unconfirmedPathTimeout :: TimeDiff
unconfirmedPathTimeout = Time.seconds 4

confirmedPathTimeout :: TimeDiff
confirmedPathTimeout = Time.seconds 10


data OnionPath = OnionPath
  { pathNodes       :: [NodeInfo] -- Exactly 3 nodes
  , pathKeys        :: [KeyPair]  -- Temporary keypairs for each hop
  , pathConfirmed   :: Bool
  , pathTries       :: Int
  , pathExpires     :: Timestamp
  , pathLastAttempt :: Maybe Timestamp
  , pathNum         :: Word32
  }
  deriving (Eq, Show, Read, Generic)

instance Arbitrary OnionPath where
  arbitrary = OnionPath <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    <*> arbitrary <*> arbitrary <*> arbitrary


isPathAlive :: Timestamp -> OnionPath -> Bool
isPathAlive now path =
  pathExpires path > now &&
  case pathLastAttempt path of
    Nothing -> True
    Just lastTime ->
      let timeout = if pathConfirmed path then confirmedPathTimeout else unconfirmedPathTimeout
          maxTries = if pathConfirmed path then 4 else 2
      in now `Time.diffTime` lastTime < timeout || pathTries path < maxTries


data OnionPathState = OnionPathState
  { announcePaths :: [OnionPath]
  , searchPaths   :: [OnionPath]
  , lastPathNum   :: Word32
  }
  deriving (Eq, Show, Read, Generic)

instance Arbitrary OnionPathState where
  arbitrary = OnionPathState <$> arbitrary <*> arbitrary <*> arbitrary


createPath :: MonadRandomBytes m => [NodeInfo] -> Word32 -> Timestamp -> m OnionPath
createPath nodes pNum expires = do
  keys <- replicateM pathLength newKeyPair
  return OnionPath
    { pathNodes       = nodes
    , pathKeys        = keys
    , pathConfirmed   = False
    , pathTries       = 0
    , pathExpires     = expires
    , pathLastAttempt = Nothing
    , pathNum         = pNum
    }


maintainPaths :: OnionPathMonad m => [NodeInfo] -> m ()
maintainPaths nodes = maintainPathsVia nodes nodes

-- | First nodes come from the first list. Without UDP, those are our TCP
-- relays.
maintainPathsVia :: OnionPathMonad m => [NodeInfo] -> [NodeInfo] -> m ()
maintainPathsVia firstNodes nodes = do
  now <- askTime
  modify $ \OnionPathState{..} -> OnionPathState
    { announcePaths = filter (isPathAlive now) announcePaths
    , searchPaths   = filter (isPathAlive now) searchPaths
    , ..
    }

  numAnnounce <- gets (length . announcePaths)
  replicateM_ (maxPaths - numAnnounce) $ do
    pNodes <- pickNodesVia firstNodes nodes
    unless (null pNodes) $ do
      pNum <- gets lastPathNum
      p <- createPath pNodes (pNum + 1) (now `Time.addTime` pathLifetime)
      modify $ \OnionPathState{..} -> OnionPathState
        { announcePaths = p : announcePaths
        , lastPathNum = pNum + 1
        , ..
        }

  numSearch <- gets (length . searchPaths)
  replicateM_ (maxPaths - numSearch) $ do
    pNodes <- pickNodesVia firstNodes nodes
    unless (null pNodes) $ do
      pNum <- gets lastPathNum
      p <- createPath pNodes (pNum + 1) (now `Time.addTime` pathLifetime)
      modify $ \OnionPathState{..} -> OnionPathState
        { searchPaths = p : searchPaths
        , lastPathNum = pNum + 1
        , ..
        }

-- | Select a random path for sending.
selectPath :: OnionPathMonad m => Bool -> m (Maybe OnionPath)
selectPath forAnnounce = do
  paths <- gets (if forAnnounce then announcePaths else searchPaths)
  MonadRandomBytes.uniformSafe paths

-- | If it's still in use.
findPath :: OnionPathMonad m => Word32 -> m (Maybe OnionPath)
findPath num = gets $ \s -> find ((== num) . pathNum) (announcePaths s ++ searchPaths s)

modifyPath :: OnionPathMonad m => Word32 -> (OnionPath -> OnionPath) -> m ()
modifyPath num f = modify $ \OnionPathState{..} -> OnionPathState
  { announcePaths = map update announcePaths
  , searchPaths   = map update searchPaths
  , ..
  }
  where
    update p = if pathNum p == num then f p else p

markPathUsed :: OnionPathMonad m => Word32 -> m ()
markPathUsed num = do
  now <- askTime
  modifyPath num $ \p -> p { pathTries = pathTries p + 1, pathLastAttempt = Just now }

markPathConfirmed :: OnionPathMonad m => Word32 -> m ()
markPathConfirmed num = modifyPath num $ \p -> p { pathConfirmed = True, pathTries = 0 }


pickNodes :: MonadRandomBytes m => [NodeInfo] -> m [NodeInfo]
pickNodes = pickDistinct 3

-- | @count@ distinct random nodes, or none if there are fewer.
pickDistinct :: MonadRandomBytes m => Int -> [NodeInfo] -> m [NodeInfo]
pickDistinct count nodes
  | length distinct < count = return []
  | otherwise = go count distinct
  where
    distinct = nubBy ((==) `on` NodeInfo.publicKey) nodes
    go 0 _ = return []
    go n candidates = do
      node <- uniform candidates
      (node :) <$> go (n - 1) (filter ((/= NodeInfo.publicKey node) . NodeInfo.publicKey) candidates)


-- | Pick a first node from the first list and 2 more distinct nodes.
pickNodesVia :: MonadRandomBytes m => [NodeInfo] -> [NodeInfo] -> m [NodeInfo]
pickNodesVia firstNodes nodes
  | null firstNodes = return []
  | otherwise = do
      first <- uniform firstNodes
      rest <- pickDistinct (pathLength - 1) (filter ((/= NodeInfo.publicKey first) . NodeInfo.publicKey) nodes)
      return $ if null rest then [] else first : rest

-- | Wrap data into a nested Onion Request payload, each layer encrypted with
-- the path's key for that node.
wrapPath :: Keyed m
         => OnionPath      -- ^ The path to follow (A, B, C)
         -> SocketAddress  -- ^ Final destination Node D
         -> Nonce          -- ^ Nonce for all layers
         -> BS.ByteString  -- ^ Final raw payload for Node D (e.g. 0x83 envelope)
         -> m Tunnel.OnionRequest0
wrapPath path destAddr nonce innerData = case (pathNodes path, pathKeys path) of
  (nodeA : _, kp1 : _) ->
    wrapLayers path destAddr nonce innerData >>= Tunnel.wrapOnion0 kp1 (NodeInfo.publicKey nodeA) nonce
  _ -> error "wrapPath: OnionPath must have exactly 3 nodes and 3 keys"

-- | What Node A decrypts. A TCP relay as first node gets this over its
-- encrypted connection.
wrapLayers :: Keyed m
           => OnionPath -> SocketAddress -> Nonce -> BS.ByteString -> m Tunnel.OnionRequestPayload
wrapLayers path destAddr nonce innerData =
  case (pathNodes path, pathKeys path) of
    ([_, nodeB, nodeC], [_, kp2, kp3]) -> do
      -- Layer 3, for C, holds D's address and the raw data.
      let p3 = Tunnel.OnionRequestPayloadFinal (Tunnel.OnionIPPort destAddr) innerData
      combined3 <- Keyed.getCombinedKey (KeyPair.secretKey kp3) (NodeInfo.publicKey nodeC)
      let enc3 = Box.encrypt combined3 nonce (Box.encode p3)

      -- Layer 2, for B, holds C's address and layer 3.
      let p2 = Tunnel.OnionRequestPayload (Tunnel.OnionIPPort (NodeInfo.address nodeC)) (KeyPair.publicKey kp3) enc3
      combined2 <- Keyed.getCombinedKey (secretKey kp2) (NodeInfo.publicKey nodeB)
      let enc2 = Box.encrypt combined2 nonce (Box.encode p2)

      -- Layer 1, for A, holds B's address and layer 2.
      return $ Tunnel.OnionRequestPayload (Tunnel.OnionIPPort (NodeInfo.address nodeB)) (KeyPair.publicKey kp2) enc2
    _ -> error "wrapLayers: OnionPath must have exactly 3 nodes and 3 keys"
\end{code}
