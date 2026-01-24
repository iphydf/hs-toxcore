\section{DHT node state}

\begin{code}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}
module Tox.DHT.DhtState where

import           Control.Applicative            (Const (..), getConst, (<|>))
import           Data.Functor.Compose           (Compose (..))
import           Data.Functor.Identity          (Identity (..))
import           Data.Map                       (Map)
import qualified Data.Map                       as Map
import qualified Data.Maybe                     as Maybe
import           Data.Monoid                    (All (..), Endo (..), getAll)
import           Lens.Family2                   (Lens')
import           Test.QuickCheck.Arbitrary      (Arbitrary, arbitrary, shrink)

import           Data.Word                      (Word32, Word64)
import qualified Tox.Core.Schedule              as Schedule
import           Tox.Core.Schedule              (Schedule)
import           Tox.Core.Time                  (Timestamp)
import qualified Tox.Crypto.Core.Key            as Key
import           Tox.Crypto.Core.Key            (PublicKey)
import qualified Tox.Crypto.Core.KeyPair        as KeyPair
import           Tox.Crypto.Core.KeyPair        (KeyPair)
import qualified Tox.DHT.ClientList             as ClientList
import           Tox.DHT.ClientList             (ClientList)
import qualified Tox.DHT.Distance               as Distance
import           Tox.DHT.Distance               (Distance)
import qualified Tox.DHT.KBuckets               as KBuckets
import           Tox.DHT.KBuckets               (KBuckets)
import qualified Tox.DHT.NodeList               as NodeList
import           Tox.DHT.NodeList               (NodeList)
import qualified Tox.DHT.PendingReplies         as PendingReplies
import           Tox.DHT.PendingReplies         (PendingReplies)
import qualified Tox.Network.Core.NodeInfo      as NodeInfo
import           Tox.Network.Core.NodeInfo      (NodeInfo)
import qualified Tox.Network.Core.SocketAddress as SocketAddress
import           Tox.Network.Core.SocketAddress (SocketAddress)


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}


\end{code}

Every DHT node contains the following state:

\begin{itemize}
  \item DHT Key Pair: The Key Pair used to communicate with other DHT nodes. It
    is immutable throughout the lifetime of the DHT node.
  \item DHT Close List: A set of Node Infos of nodes that are close to the
    DHT Public Key (public part of the DHT Key Pair).  The Close List is
    represented as a \href{#k-buckets}{k-buckets} data structure, with the DHT
    Public Key as the Base Key.
  \item DHT Search List: A list of Public Keys of nodes that the DHT node is
    searching for, associated with a DHT Search Entry.
\end{itemize}

\begin{code}

data ListStamp = ListStamp { listTime :: Timestamp, listBootstrappedTimes :: Int }
  deriving (Eq, Read, Show)
newListStamp :: Timestamp -> ListStamp
newListStamp t = ListStamp t 0

data DhtState = DhtState
  { dhtKeyPair        :: KeyPair
  , dhtCloseList      :: KBuckets
  , dhtSearchList     :: Map PublicKey DhtSearchEntry

  , dhtCloseListStamp :: ListStamp
  , dhtPendingReplies :: PendingReplies
  , dhtSelfAddress    :: Maybe SocketAddress -- ^ Where other nodes say we are.
  , dhtToBootstrap    :: Map PublicKey [NodeInfo]
    -- ^ Nodes responses told us of, to ask next, by the key of their list,
    -- closest first.
  , dhtBatchSent      :: Timestamp -- ^ When we last asked them, or the start.
  , dhtToPing         :: [NodeInfo] -- ^ Nodes that asked us something, to ping next, closest first.
  , dhtPinged         :: Int -- ^ Of them, how many we pinged at once since the last ping round.
  , dhtBootstrapNodes :: [NodeInfo] -- ^ The newest we were told to bootstrap from.
  , dhtBootstrapStamp :: ListStamp
    -- ^ When we last bootstrapped, and how many times we did while the Close List stayed empty.
  , dhtNodes          :: Map Integer (Int, NodeInfo)
    -- ^ Every node the lists hold, by 'Key.keyToInteger' of its key, with how
    -- many lists hold it, so finding a node or the closest ones doesn't go
    -- through every list. Kept by 'changeNodeLists'.
  , dhtNatJobs        :: Schedule PublicKey
    -- ^ When hole punching towards each searched node is next due. News of
    -- one makes it due at once, to work out when it really is.
  }
  deriving (Eq, Read, Show)

_dhtKeyPair :: Lens' DhtState KeyPair
_dhtKeyPair f d@DhtState{ dhtKeyPair = a } =
  (\a' -> d{ dhtKeyPair = a' }) <$> f a

_dhtCloseListStamp :: Lens' DhtState ListStamp
_dhtCloseListStamp f d@DhtState{ dhtCloseListStamp = a } =
  (\a' -> d{ dhtCloseListStamp = a' }) <$> f a

_dhtCloseList :: Lens' DhtState KBuckets
_dhtCloseList f d@DhtState{ dhtCloseList = a } =
  (\a' -> d{ dhtCloseList = a' }) <$> f a

_dhtSearchList :: Lens' DhtState (Map PublicKey DhtSearchEntry)
_dhtSearchList f d@DhtState{ dhtSearchList = a } =
  (\a' -> d{ dhtSearchList = a' }) <$> f a

_dhtPendingReplies :: Lens' DhtState PendingReplies
_dhtPendingReplies f d@DhtState{ dhtPendingReplies = a } =
  (\a' -> d{ dhtPendingReplies = a' }) <$> f a

\end{code}

A DHT node state is initialised using a Key Pair, which is stored in the state
as DHT Key Pair and as base key for the Close List. Both the Close and Search
Lists are initialised to be empty.

\begin{code}

empty :: Timestamp -> KeyPair -> DhtState
empty time keyPair =
  DhtState keyPair (KBuckets.empty $ KeyPair.publicKey keyPair)
    Map.empty (newListStamp time) PendingReplies.empty Nothing Map.empty time [] 0 [] (newListStamp time) Map.empty
    Schedule.empty

\end{code}

\subsection{DHT Search Entry}

A DHT Search Entry contains a Client List with base key the searched node's
Public Key.  Once the searched node is found, it is also stored in the Search
Entry.

The maximum size of the Client List is set to 8.
(Must be the same or smaller than the bucket size of the close list to make
sure all the closest peers found will know the node being searched
(TODO(zugz): this argument is unclear.)).

A DHT node state therefore contains one Client List for each bucket index in
the Close List, and one Client List for each DHT Search Entry.
These lists are not required to be disjoint - a node may be in multiple Client
Lists simultaneously.

\begin{code}

data DhtSearchEntry = DhtSearchEntry
  { searchNode       :: Maybe NodeInfo
  , searchSeen       :: Maybe Timestamp
    -- ^ When the searched node last answered us itself.
  , searchStamp      :: ListStamp
  , searchClientList :: ClientList
  , searchReturned   :: Map PublicKey (SocketAddress, Timestamp)
    -- ^ Where Client List nodes say the searched node is, by their key.
  , searchNat        :: NatState
  }
  deriving (Eq, Read, Show)

-- | Hole punching towards a searched node behind a NAT.
data NatState = NatState
  { natPingId       :: Word64
  , natPingSent     :: Maybe Timestamp
  , natPingRecv     :: Maybe Timestamp -- ^ When the node last sent us a NAT ping.
  , natPunching     :: Bool            -- ^ It answered our NAT ping.
  , natPunched      :: Maybe Timestamp
  , natTries        :: Int             -- ^ Rounds since it last answered us itself.
  , natPortIndex    :: Word32
  , natLowPortIndex :: Word32
  }
  deriving (Eq, Read, Show)

emptyNatState :: NatState
emptyNatState = NatState
  { natPingId       = 1
  , natPingSent     = Nothing
  , natPingRecv     = Nothing
  , natPunching     = False
  , natPunched      = Nothing
  , natTries        = 0
  , natPortIndex    = 0
  , natLowPortIndex = 0
  }

_searchNode :: Lens' DhtSearchEntry (Maybe NodeInfo)
_searchNode f d@DhtSearchEntry{ searchNode = a } =
  (\a' -> d{ searchNode = a' }) <$> f a

_searchStamp :: Lens' DhtSearchEntry ListStamp
_searchStamp f d@DhtSearchEntry{ searchStamp = a } =
  (\a' -> d{ searchStamp = a' }) <$> f a

_searchClientList :: Lens' DhtSearchEntry ClientList
_searchClientList f d@DhtSearchEntry{ searchClientList = a } =
  (\a' -> d{ searchClientList = a' }) <$> f a

searchEntryClientListSize :: Int
searchEntryClientListSize = 8

\end{code}

A Search Entry is initialised with the searched-for Public Key. The contained
Client List is initialised to be empty.

\begin{code}

emptySearchEntry :: Timestamp -> PublicKey -> DhtSearchEntry
emptySearchEntry time publicKey =
  DhtSearchEntry Nothing Nothing (newListStamp time)
    (ClientList.empty publicKey searchEntryClientListSize) Map.empty emptyNatState

\end{code}

\subsection{Manipulating the DHT node state}

Adding a search key to the DHT node state creates an empty entry in the Search
Nodes list. If a search entry for the public key already existed, the "add"
operation has no effect.

\begin{code}

addSearchKey :: Timestamp -> PublicKey -> DhtState -> DhtState
addSearchKey time searchKey dhtState@DhtState { dhtSearchList } =
  dhtState { dhtSearchList = updatedSearchList }
  where
    searchEntry =
      Map.findWithDefault (emptySearchEntry time searchKey) searchKey dhtSearchList
    updatedSearchList =
      Map.insert searchKey searchEntry dhtSearchList

\end{code}

Removing a search key removes its search entry and all associated data
structures from memory.

\begin{code}

removeSearchKey :: PublicKey -> DhtState -> DhtState
removeSearchKey searchKey dhtState@DhtState { dhtSearchList } =
  case Map.lookup searchKey dhtSearchList of
    Nothing    -> dhtState
    Just entry -> dhtState
      { dhtSearchList = Map.delete searchKey dhtSearchList
      , dhtNodes = reheld (searchClientList entry) (ClientList.empty searchKey 0) (dhtNodes dhtState)
      , dhtNatJobs = Schedule.cancel searchKey (dhtNatJobs dhtState)
      }


containsSearchKey :: PublicKey -> DhtState -> Bool
containsSearchKey searchKey =
  Map.member searchKey . dhtSearchList

\end{code}

\input{src/Tox/DHT/NodeList.lhs}

The iteration order over the DHT state is to first process the Close List
k-buckets, then the Search List entry Client Lists. Each of these follows the
iteration order in the corresponding specification.

\begin{code}

traverseNodeLists :: Applicative f =>
  (forall l. NodeList l => l -> f l) -> DhtState -> f DhtState
traverseNodeLists f dhtState@DhtState{ dhtCloseList, dhtSearchList } =
  (\close' search' ->
      dhtState{ dhtCloseList = close', dhtSearchList = search' }) <$>
    f dhtCloseList <*>
    traverse traverseEntry dhtSearchList
  where
    traverseEntry entry =
      (\x -> entry{ searchClientList = x }) <$> f (searchClientList entry)

foldMapNodeLists :: Monoid m =>
  (forall l. NodeList l => l -> m) -> DhtState -> m
foldMapNodeLists f = getConst . traverseNodeLists (Const . f)

-- | Nothing for a list leaves it as it is.
changeNodeLists :: forall f. Applicative f =>
  (forall l. NodeList l => l -> f (Maybe l)) -> DhtState -> f DhtState
changeNodeLists f dhtState =
  (\(Endo update, dhtState') -> dhtState' { dhtNodes = update (dhtNodes dhtState) })
    <$> getCompose (traverseNodeLists changed dhtState)
  where
    changed :: NodeList l => l -> Compose f ((,) (Endo (Map Integer (Int, NodeInfo)))) l
    changed nodeList = Compose $ maybe (mempty, nodeList) (\nodeList' -> (Endo (reheld nodeList nodeList'), nodeList'))
      <$> f nodeList

-- | What a list going from one to the other does to 'dhtNodes'. A node whose
-- address changed keeps the newer one.
reheld :: (NodeList l, NodeList l') => l -> l' -> Map Integer (Int, NodeInfo) -> Map Integer (Int, NodeInfo)
reheld old new held
  | NodeList.nodeListList old == NodeList.nodeListList new = held
  | otherwise = foldr release (foldr hold held (Map.toList after)) (Map.keys (before `Map.difference` after))
  where
    keyed nodeList = Map.fromList [ (Key.keyToInteger (NodeInfo.publicKey n), n) | n <- NodeList.nodeListList nodeList ]
    before = keyed old
    after = keyed new
    hold (k, n) = case Map.lookup k before of
      Just n' | n' == n -> id
      Just _            -> Map.adjust (\(c, _) -> (c, n)) k
      Nothing           -> Map.alter (Just . maybe (1, n) (\(c, _) -> (c + 1, n))) k
    release = Map.update (\(c, n) -> if c > 1 then Just (c - 1, n) else Nothing)

mapNodeLists :: (forall l. NodeList l => l -> Maybe l) -> DhtState -> DhtState
mapNodeLists f = runIdentity . changeNodeLists (Identity . f)

\end{code}

A node info is considered to be contained in the DHT State if it is contained
in the Close List or in at least one of the Search Entries.

The size of the DHT state is defined to be the number of node infos it
contains, counted with multiplicity: node infos contained multiple times, e.g.
in the close list and in various search entries, are counted as many times as
they appear.  Search keys do not directly count towards the state size.  So
the size of the state is the sum of the sizes of the Close List and the Search
Entries.

The state size is relevant to later pruning algorithms that decide when to
remove a node info and when to request a ping from stale nodes. Search keys,
once added, are never automatically pruned.

\begin{code}

size :: DhtState -> Int
size = NodeList.foldNodes (flip $ const (1 +)) 0

\end{code}

Adding a Node Info to the state is done by adding the node to each Node List
in the state.

When adding a node info to the state, the search entry for the node's public
key, if it exists, is updated to contain the new node info. All k-buckets and
Client Lists that already contain the node info will also be updated. See the
corresponding specifications for the update algorithms. However, a node info
will not be added to a search entry when it is the node to which the search
entry is associated (i.e. the node being search for).

\begin{code}

addNode :: Timestamp -> NodeInfo -> DhtState -> DhtState
addNode time nodeInfo =
  updateSearchNode (NodeInfo.publicKey nodeInfo) (Just (nodeInfo, time))
  . mapNodeLists addUnlessBase
  where
    publicKey = NodeInfo.publicKey nodeInfo
    addUnlessBase nodeList
      | publicKey == NodeList.baseKey nodeList = Nothing
      | NodeList.viable nodeInfo nodeList || Maybe.isJust (NodeList.lookupPublicKey publicKey nodeList) =
          Just $ NodeList.addNode time nodeInfo nodeList
      | otherwise = Nothing

removeNode :: PublicKey -> DhtState -> DhtState
removeNode publicKey =
  updateSearchNode publicKey Nothing
  . mapNodeLists (\nodeList -> NodeList.removeNode publicKey nodeList <$ NodeList.lookupPublicKey publicKey nodeList)

viable :: NodeInfo -> DhtState -> Bool
viable nodeInfo = getAll . foldMapNodeLists (All . NodeList.viable nodeInfo)

traverseClientLists ::
  Applicative f => (ClientList -> f ClientList) -> DhtState -> f DhtState
traverseClientLists f = changeNodeLists $ fmap Just . NodeList.traverseClientLists f

closeNodes :: PublicKey -> DhtState -> [ (Distance, NodeInfo) ]
closeNodes publicKey = map (fmap snd) . Distance.byDistance publicKey . dhtNodes

-- | although it is not referred to as a Node List in the spec, we make DhtState
-- an instance of NodeList so we can use the traversal and folding functions.
instance NodeList DhtState where
  addNode = addNode
  removeNode = removeNode
  viable = viable
  baseKey = KeyPair.publicKey . dhtKeyPair
  traverseClientLists = traverseClientLists
  closeNodes = closeNodes

takeClosestNodesTo :: Int -> PublicKey -> DhtState -> [ NodeInfo ]
takeClosestNodesTo n publicKey = map snd . take n . closeNodes publicKey

-- | LAN nodes only if the requester is on a LAN too, as in toxcore.
takeClosestNodesFor :: SocketAddress -> Int -> PublicKey -> DhtState -> [ NodeInfo ]
takeClosestNodesFor requester n publicKey =
  take n . filter visible . map snd . closeNodes publicKey
  where
    visible node = SocketAddress.isLan requester || not (SocketAddress.isLan $ NodeInfo.address node)

updateSearchNode :: PublicKey -> Maybe (NodeInfo, Timestamp) -> DhtState -> DhtState
updateSearchNode publicKey seen dhtState@DhtState { dhtSearchList, dhtNatJobs } =
  dhtState
    { dhtSearchList = Map.adjust update publicKey dhtSearchList
    , dhtNatJobs = case seen of
        Just (_, time) | Map.member publicKey dhtSearchList -> Schedule.soonest time publicKey dhtNatJobs
        _                                                   -> dhtNatJobs
    }
  where
    update entry = entry { searchNode = fst <$> seen, searchSeen = snd <$> seen }

\end{code}

Removing a node info from the state removes it from all k-buckets. If a search
entry for the removed node's public key existed, the node info in that search
entry is unset. The search entry itself is not removed.

\begin{code}

containsNode :: PublicKey -> DhtState -> Bool
containsNode publicKey = Maybe.isJust . findNode publicKey

findNode :: PublicKey -> DhtState -> Maybe NodeInfo
findNode publicKey = fmap snd . Map.lookup (Key.keyToInteger publicKey) . dhtNodes

-- | Where a node in the search entry's Client List says the searched node is.
recordReturned :: Timestamp -> NodeInfo -> NodeInfo -> DhtState -> DhtState
recordReturned now from node s = case Map.lookup key (dhtSearchList s) of
  Just e | inList e (NodeInfo.publicKey from) -> s
    { dhtSearchList = Map.insert key (record e) (dhtSearchList s)
    , dhtNatJobs = Schedule.soonest now key (dhtNatJobs s)
    }
  _ -> s
  where
    key = NodeInfo.publicKey node
    record e = e { searchReturned = Map.filterWithKey (const . inList e) $
      Map.insert (NodeInfo.publicKey from) (NodeInfo.address node, now) (searchReturned e) }
    inList e pk = Maybe.isJust $ ClientList.lookup pk (searchClientList e)


{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}


instance Arbitrary DhtState where
  arbitrary =
    initialise <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    where
      initialise :: Timestamp -> KeyPair -> [(Timestamp, NodeInfo)] -> [(Timestamp, PublicKey)]
                 -> DhtState
      initialise time kp nis =
        foldl (flip $ uncurry addSearchKey) (foldl (flip $ uncurry NodeList.addNode) (empty time kp) nis)

  shrink dhtState =
    Maybe.maybeToList shrunkNode ++ Maybe.maybeToList shrunkSearchKey
    where
      -- Remove the first node we can find in the state.
      shrunkNode = do
        firstPK <- NodeInfo.publicKey <$> NodeList.foldNodes (\a x -> a <|> Just x) Nothing dhtState
        return $ NodeList.removeNode firstPK dhtState

      shrunkSearchKey = Nothing

\end{code}
