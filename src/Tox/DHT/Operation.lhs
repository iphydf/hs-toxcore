\section{DHT Operation}

\begin{code}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE MultiWayIf            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}
module Tox.DHT.Operation where

import           Control.Monad                    (filterM, guard, replicateM,
                                                   unless, void, when, (<$!>))
import           Control.Monad.Identity           (Identity, runIdentity)
import           Control.Monad.Random             (RandT, evalRandT)
import           Control.Monad.State              (MonadState, StateT,
                                                   execStateT, get, put,
                                                   runStateT)
import           Control.Monad.Trans              (lift)
import           Control.Monad.Trans.Maybe        (MaybeT (..), runMaybeT)
import           Control.Monad.Writer             (MonadWriter, WriterT,
                                                   execWriterT, runWriterT,
                                                   tell)
import           Data.Binary                      (Binary)
import           Data.Foldable                    (find, for_)
import           Data.Functor                     (($>))
import           Data.List                        (insertBy)
import           Data.Map                         (Map)
import qualified Data.Map                         as Map
import           Data.Maybe                       (fromMaybe, isJust, isNothing)
import           Data.Ord                         (comparing)
import           Lens.Family2                     (Lens')
import           Lens.Family2.State               (zoom, (%=))
import           System.Random                    (StdGen, mkStdGen)
import           Test.QuickCheck.Arbitrary        (Arbitrary, arbitrary)

import           Data.Text                        (pack)
import           Tox.Core.Log                     (MonadLog, NoLog, logDebug,
                                                   runNoLog)
import qualified Tox.Core.Time                    as Time
import           Tox.Core.Time                    (TimeDiff, Timestamp)
import qualified Tox.Core.Timed                   as Timed
import           Tox.Core.Timed                   (Timed)
import           Tox.Crypto.Core.Key              (PublicKey)
import qualified Tox.Crypto.Core.Keyed            as KeyedT
import           Tox.Crypto.Core.Keyed            (Keyed, KeyedT)
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import qualified Tox.Crypto.Core.MonadRandomBytes as MonadRandomBytes
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)
import qualified Tox.DHT.ClientList               as ClientList
import           Tox.DHT.ClientList               (ClientList)
import qualified Tox.DHT.ClientNode               as ClientNode
import           Tox.DHT.ClientNode               (ClientNode)
import qualified Tox.DHT.DhtPacket                as DhtPacket
import           Tox.DHT.DhtRequestPacket         (DhtRequestPacket (..))
import qualified Tox.DHT.DhtState                 as DhtState
import           Tox.DHT.DhtState                 (DhtState)
import qualified Tox.DHT.Distance                 as Distance
import qualified Tox.DHT.NodeList                 as NodeList
import           Tox.DHT.NodeList                 (NodeList)
import           Tox.DHT.NodesRequest             (NodesRequest (..))
import           Tox.DHT.NodesResponse            (NodesResponse (..))
import qualified Tox.DHT.PendingReplies           as PendingReplies
import           Tox.DHT.PingPacket               (PingPacket (..))
import qualified Tox.DHT.RpcPacket                as RpcPacket
import           Tox.DHT.RpcPacket                (RpcPacket (..))
import qualified Tox.Network.Core.Networked       as Networked
import           Tox.Network.Core.Networked       (Networked)
import qualified Tox.Network.Core.NodeInfo        as NodeInfo
import           Tox.Network.Core.NodeInfo        (NodeInfo)
import           Tox.Network.Core.Packet          (Packet (..))
import qualified Tox.Network.Core.PacketKind      as PacketKind
import           Tox.Network.Core.PacketKind      (PacketKind)
import qualified Tox.Network.Core.SocketAddress   as SocketAddress
import qualified Tox.Network.Core.TimedT          as TimedT
import           Tox.Network.Core.TimedT          (TimedT)

{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

class
  ( Networked m
  , Timed m
  , MonadRandomBytes m
  , Keyed m
  , MonadLog m
  ) => DhtNodeMonad m where
  getDhtState :: m DhtState
  putDhtState :: DhtState -> m ()
  -- | Already decrypted, and addressed to us.
  handleDhtRequestPayload :: NodeInfo -> DhtPacket.DhtPacket -> m ()
  handleDhtRequestPayload _ _ = return ()
  -- | A node answered us, so it's where it says.
  nodeAnswered :: NodeInfo -> m ()
  nodeAnswered _ = return ()

instance (Monoid w, DhtNodeMonad m) => DhtNodeMonad (WriterT w m) where
  getDhtState = lift getDhtState
  putDhtState = lift . putDhtState
  handleDhtRequestPayload from pkt = lift $ handleDhtRequestPayload from pkt
  nodeAnswered = lift . nodeAnswered

data RequestInfo = RequestInfo
  { requestTo     :: NodeInfo
  , requestSearch :: PublicKey
  }
  deriving (Eq, Read, Show)

getDht :: DhtNodeMonad m => m DhtState
getDht = getDhtState

getsDht :: DhtNodeMonad m => (DhtState -> a) -> m a
getsDht f = f <$!> getDht

putDht :: DhtNodeMonad m => DhtState -> m ()
putDht = putDhtState

modifyDht :: DhtNodeMonad m => (DhtState -> DhtState) -> m ()
modifyDht f = getDht >>= putDht . f


sendDhtPacket :: (DhtNodeMonad m, Binary payload) =>
  NodeInfo -> PacketKind -> payload -> m ()
sendDhtPacket to kind payload = do
  keyPair <- getsDht DhtState.dhtKeyPair
  nonce <- MonadRandomBytes.randomNonce
  Networked.sendPacket to . Packet kind =<<
    DhtPacket.encodeKeyed keyPair (NodeInfo.publicKey to) nonce payload

sendRpcRequest :: (DhtNodeMonad m, Binary payload) =>
  NodeInfo -> PacketKind -> payload -> m ()
sendRpcRequest to packetKind payload = do
  requestId <- RpcPacket.RequestId <$> MonadRandomBytes.randomWord64
  time <- Timed.askTime
  modifyDht $ \s ->
    s { DhtState.dhtPendingReplies = PendingReplies.expectReply time to requestId (DhtState.dhtPendingReplies s) }
  sendDhtPacket to packetKind $
    RpcPacket payload requestId

sendNodesRequest :: DhtNodeMonad m => RequestInfo -> m ()
sendNodesRequest (RequestInfo to key) =
  sendRpcRequest to PacketKind.NodesRequest $ NodesRequest key

sendNodesResponse ::
  DhtNodeMonad m => NodeInfo -> RpcPacket.RequestId -> [NodeInfo] -> m ()
sendNodesResponse to requestId nodes =
  sendDhtPacket to PacketKind.NodesResponse $
    RpcPacket (NodesResponse nodes) requestId

sendPingRequest :: DhtNodeMonad m => NodeInfo -> m ()
sendPingRequest to =
  sendRpcRequest to PacketKind.PingRequest PingRequest

sendPingResponse ::
  DhtNodeMonad m => NodeInfo -> RpcPacket.RequestId -> m ()
sendPingResponse to requestId =
  sendDhtPacket to PacketKind.PingResponse $
    RpcPacket PingResponse requestId

modifyM :: MonadState s m => (s -> m s) -> m ()
modifyM f = get >>= f >>= put

-- | adapted from michaelt's lens-simple:
-- zoom_ is like zoom but for convenience returns an mtl style
-- abstracted MonadState state, rather than a concrete StateT, recapturing
-- a bit more of the abstractness of Control.Lens.zoom
zoom_ :: MonadState s' m => Lens' s' s -> StateT s m a -> m a
-- full signature:
-- zoom_ :: MonadState s' m =>
--   LensLike' (Zooming m a) s' s -> StateT s m a -> m a
zoom_ l f = abstract $ zoom l f
  where
    abstract :: MonadState s m => StateT s m a -> m a
    abstract st = do
      (a,s') <- runStateT st =<< get
      put s'
      return a

\end{code}

\subsection{DHT Initialisation}
A new DHT node is initialised with a DHT State with a fresh random key pair, an
empty close list, and a search list containing 2 empty search entries searching
for the public keys of fresh random key pairs.

\begin{code}

initRandomSearches :: Int
initRandomSearches = 2

initDht :: (MonadRandomBytes m, Timed m) => m DhtState
initDht = do
  dhtState <- DhtState.empty <$> Timed.askTime <*> MonadRandomBytes.newKeyPair
  time <- Timed.askTime
  (`execStateT` dhtState) $ replicateM initRandomSearches $ do
    publicKey <- KeyPair.publicKey <$> MonadRandomBytes.newKeyPair
    DhtState._dhtSearchList %=
      Map.insert publicKey (DhtState.emptySearchEntry time publicKey)

\end{code}

\subsection{Bootstrapping}
To bootstrap from a node, we send it a Nodes Request for our own DHT public key.

An implementation should keep a few of the nodes it was told to bootstrap from,
and bootstrap from them again while its Close List is empty.  Checking (below)
empties the Close List after a few minutes without a network, and then no Nodes
Request is ever sent again.

\begin{code}

-- | The newest we were told to bootstrap from, as those are picked for staying
-- up.
maxBootstrapNodes :: Int
maxBootstrapNodes = 8

firstBootstrapWait, maxBootstrapWait :: TimeDiff
firstBootstrapWait = Time.seconds 5
maxBootstrapWait   = Time.seconds 60

-- | Keeps the node to bootstrap from again.
bootstrapNode :: DhtNodeMonad m => NodeInfo -> m ()
bootstrapNode nodeInfo = do
  time <- Timed.askTime
  modifyDht $ \s -> s
    { DhtState.dhtBootstrapNodes = take maxBootstrapNodes . (nodeInfo :) . filter other $ DhtState.dhtBootstrapNodes s
    , DhtState.dhtBootstrapStamp = (DhtState.dhtBootstrapStamp s) { DhtState.listTime = time }
    }
  askCloseNodes nodeInfo
  where
    other n = NodeInfo.publicKey n /= NodeInfo.publicKey nodeInfo

askCloseNodes :: DhtNodeMonad m => NodeInfo -> m ()
askCloseNodes nodeInfo =
  sendNodesRequest . RequestInfo nodeInfo . KeyPair.publicKey =<< getsDht DhtState.dhtKeyPair

-- | While the Close List is empty, from the kept nodes again, waiting twice as
-- long each time. Checking empties it after a few minutes without a network,
-- and then no Nodes Request would ever go out again.
bootstrapAgain :: DhtNodeMonad m => m ()
bootstrapAgain = do
  s <- getDht
  time <- Timed.askTime
  let DhtState.ListStamp lastTime times = DhtState.dhtBootstrapStamp s
      wait = min maxBootstrapWait (firstBootstrapWait * 2 ^ times)
      -- Stops counting at the longest wait, so the wait can't overflow.
      times' = if wait < maxBootstrapWait then times + 1 else times
  if not . null . NodeList.nodeListList $ DhtState.dhtCloseList s
    then when (times > 0) $ putDht s { DhtState.dhtBootstrapStamp = DhtState.ListStamp lastTime 0 }
    else when (time `Time.diffTime` lastTime >= wait) $ do
      putDht s { DhtState.dhtBootstrapStamp = DhtState.ListStamp time times' }
      mapM_ askCloseNodes $ DhtState.dhtBootstrapNodes s

\end{code}

\subsection{Periodic sending of Nodes Requests}
For each Nodes List in the DHT State, every 20 seconds we send a Nodes Request
to a random node on the list, searching for the base key of the list.

When a Nodes List first becomes populated with nodes, we send 5 such random
Nodes Requests in quick succession.

Random nodes are chosen since being able to predict which node a node will
send a request to next could make some attacks that disrupt the network
easier, as it adds a possible attack vector.

\begin{code}

randomRequestPeriod :: TimeDiff
randomRequestPeriod = Time.seconds 20

maxBootstrapTimes :: Int
maxBootstrapTimes = 5

randomRequests :: DhtNodeMonad m => WriterT [RequestInfo] m ()
randomRequests = do
  s <- getDht
  let closeList = DhtState.dhtCloseList s
  ((), closeStamp') <- runStateT (doList closeList) (DhtState.dhtCloseListStamp s)

  let searchList = DhtState.dhtSearchList s
  searchList' <- traverse searchEntry searchList

  putDht $ s { DhtState.dhtCloseListStamp = closeStamp', DhtState.dhtSearchList = searchList' }
  where
    searchEntry entry = do
      ((), entryStamp') <- runStateT (doList $ DhtState.searchClientList entry) (DhtState.searchStamp entry)
      return $ entry { DhtState.searchStamp = entryStamp' }
    doList ::
      ( NodeList l
      , Timed m'
      , MonadRandomBytes m'
      , MonadState DhtState.ListStamp m'
      , MonadWriter [RequestInfo] m'
      ) => l -> m' ()
    doList nodeList =
      case NodeList.nodeListList nodeList of
        [] -> return ()
        nodes -> do
          time <- Timed.askTime
          DhtState.ListStamp lastTime bootstrapped <- get
          when (time `Time.diffTime` lastTime >= randomRequestPeriod
              || bootstrapped < maxBootstrapTimes) $ do
            node <- MonadRandomBytes.uniform nodes
            tell [RequestInfo node $ NodeList.baseKey nodeList]
            put $ DhtState.ListStamp time (bootstrapped + 1)

\end{code}

Furthermore, we periodically check every node for responsiveness by sending it a
Nodes Request: for each Nodes List in the DHT State, we send each node on the
list a Nodes Request every 60 seconds, searching for the base key of the list.
We remove from the DHT State any node from which we persistently fail to receive
Nodes Responses.

c-toxcore's implementation of checking and timeouts:
A Last Checked time is maintained for each node in each list. When a node is
added to a list, if doing so evicts a node from the list then the Last Checked
time is set to that of the evicted node, and otherwise it is set to 0. This
includes updating an already present node. Nodes from which we have not
received a Nodes Response for 122 seconds are considered Bad; they remain in the
DHT State, but are preferentially overwritten when adding to the DHT State, and
are ignored for all operations except the once-per-60s checking described above.
If we have not received a Nodes Response for 182 seconds, the node is not even
checked. So one check is sent after the node becomes Bad. In the special case
that every node in the Close List is Bad, they are all checked once more.)

\begin{code}

checkPeriod :: TimeDiff
checkPeriod = Time.seconds 60

maxChecks :: Int
maxChecks = 2

-- | Each node that's due, every 'checkPeriod'. The second check without an
-- answer in between removes it. Close to c-toxcore, but much simpler.
checkNodes :: forall m. DhtNodeMonad m => WriterT [RequestInfo] m ()
checkNodes = do
  s <- getDht
  (s', requests) <- lift $ runWriterT $ DhtState.traverseClientLists checkNodes' s
  putDht s'
  tell requests
  where
    checkNodes' :: ClientList -> WriterT [RequestInfo] m ClientList
    checkNodes' clientList =
      (\x -> clientList{ ClientList.nodes = x }) <$>
        traverseMaybe checkNode (ClientList.nodes clientList)
      where
        traverseMaybe :: Applicative f =>
          (a -> f (Maybe b)) -> Map k a -> f (Map k b)
        traverseMaybe f = (Map.mapMaybe id <$>) . traverse f

        checkNode :: ClientNode -> WriterT [RequestInfo] m (Maybe ClientNode)
        checkNode clientNode = Timed.askTime >>= \time ->
          if time `Time.diffTime` lastCheck < checkPeriod
          then pure $ Just clientNode
          else (tell [requestInfo] $>) $
            if checkCount + 1 < maxChecks
            then Just $ clientNode
              { ClientNode.lastCheck = time
              , ClientNode.checkCount = checkCount + 1
              }
            else Nothing
          where
            nodeInfo = ClientNode.nodeInfo clientNode
            lastCheck = ClientNode.lastCheck clientNode
            checkCount = ClientNode.checkCount clientNode
            requestInfo = RequestInfo nodeInfo $ NodeList.baseKey clientList

doDHT :: DhtNodeMonad m => m ()
doDHT = do
  execWriterT (randomRequests >> checkNodes) >>= mapM_ sendNodesRequest
  bootstrapAgain
  sendQueuedPings


\end{code}

\subsection{Handling Nodes Response packets}
When we receive a valid Nodes Response packet, we first check that it is a reply
to a Nodes Request which we sent within the last 60 seconds to the node from
which we received the response, and that no previous reply has been received. If
this check fails, the packet is ignored. If the check succeeds, first we add to
the DHT State the node from which the response was sent. Then, for each node
listed in the response and for each Nodes List in the DHT State which does not
currently contain the node and to which the node is viable for entry, we send a
Nodes Request to the node with the requested public key being the base key of
the Nodes List.

An implementation may choose not to send every such Nodes Request, and should
limit them, as a few nodes that keep telling each other of nodes they haven't
added yet can otherwise ask each other hundreds of times a second.  For
example, at most 8 for the Close List and 4 for each Search Entry every 50
milliseconds, the closest to the list's base key first.

\begin{code}

requireNodesResponseWithin :: TimeDiff
requireNodesResponseWithin = Time.seconds 60

handleNodesResponse ::
  DhtNodeMonad m => NodeInfo -> RpcPacket NodesResponse -> m ()
handleNodesResponse from (RpcPacket (NodesResponse nodes) requestId) = do
  isReply <- checkPending requireNodesResponseWithin from requestId
  when isReply $ do
    time <- Timed.askTime
    logDebug $ "Adding node to DHT from NodesResponse: " <> pack (show $ NodeInfo.publicKey from)
    modifyDht $ DhtState.addNode time from
    nodeAnswered from
    modifyDht $ \s -> foldr (DhtState.recordReturned time from) s nodes
    ourPk <- KeyPair.publicKey <$> getsDht DhtState.dhtKeyPair
    -- As in toxcore, only close nodes tell us our address, and a LAN one
    -- doesn't replace an internet one.
    close <- isJust . NodeList.lookupPublicKey (NodeInfo.publicKey from) <$> getsDht DhtState.dhtCloseList
    current <- getsDht DhtState.dhtSelfAddress
    for_ (find ((== ourPk) . NodeInfo.publicKey) nodes) $ \self -> do
      let lanOnly = SocketAddress.isLan (NodeInfo.address self) && maybe False (not . SocketAddress.isLan) current
      when (close && not lanOnly) $
        modifyDht $ \s -> s { DhtState.dhtSelfAddress = Just (NodeInfo.address self) }
    for_ nodes $ \node -> do
      -- A searched node never goes in the list of its own key, so we ask it
      -- for its key until the search has it there, not each time it's
      -- mentioned. A new address (as after a restart) is asked again, and so
      -- is one that hasn't answered for a check period, or we'd NAT ping a
      -- friend we reach.
      entry <- getsDht $ Map.lookup (NodeInfo.publicKey node) . DhtState.dhtSearchList
      let found = guard (answeredLately time entry) >> (DhtState.searchNode =<< entry)
      requests <- getsDht $ DhtState.foldMapNodeLists $
        \nodeList ->
          -- Viable first, as that rules most lists out before the lookup.
          guard (NodeList.viable node nodeList
            && isNothing (NodeList.lookupPublicKey
              (NodeInfo.publicKey node) nodeList)
            && (NodeInfo.publicKey node /= NodeList.baseKey nodeList || found /= Just node)) >>
          [ RequestInfo node $ NodeList.baseKey nodeList ]
      modifyDht $ \s -> s { DhtState.dhtToBootstrap = foldr (queueRequest ourPk) (DhtState.dhtToBootstrap s) requests }

-- | Whether the searched node answered us itself within a check period.
answeredLately :: Timestamp -> Maybe DhtState.DhtSearchEntry -> Bool
answeredLately now entry = any ((< checkPeriod) . Time.diffTime now) (DhtState.searchSeen =<< entry)

-- | How many c-toxcore asks at once of the nodes responses tell it of, for
-- its Close List and for each Search Entry.
maxCloseToBootstrap, maxSearchToBootstrap :: Int
maxCloseToBootstrap = 8
maxSearchToBootstrap = 4

-- | Keeps the closest to the list's key.
queueRequest :: PublicKey -> RequestInfo -> Map PublicKey [NodeInfo] -> Map PublicKey [NodeInfo]
queueRequest ourPk (RequestInfo node key) =
  Map.alter (Just . take limit . insertBy closer node . filter other . fromMaybe []) key
  where
    limit = if key == ourPk then maxCloseToBootstrap else maxSearchToBootstrap
    closer = comparing (Distance.xorDistance key . NodeInfo.publicKey)
    other n = NodeInfo.publicKey n /= NodeInfo.publicKey node

-- | c-toxcore asks them in each of its runs, at most every 50 ms, so the
-- nodes that a burst of responses tells of come down to the closest few.
batchInterval :: TimeDiff
batchInterval = Time.milliseconds 50

-- | With nodes queued, or a list still making its first quick requests,
-- 'sendQueued' is due a batch interval after the last batch.
queueDue :: DhtState -> Maybe Timestamp
queueDue s = Time.addTime (DhtState.dhtBatchSent s) batchInterval
  <$ guard (not (Map.null $ DhtState.dhtToBootstrap s) || bootstrapping s)

-- | Some list has nodes and hasn't made its first quick requests yet. They
-- go with the batches, as c-toxcore makes them in each of its runs: in the
-- DHT upkeep they would take seconds.
bootstrapping :: DhtState -> Bool
bootstrapping s = quick (DhtState.dhtCloseList s) (DhtState.dhtCloseListStamp s)
  || any (\e -> quick (DhtState.searchClientList e) (DhtState.searchStamp e)) (DhtState.dhtSearchList s)
  where
    quick :: NodeList l => l -> DhtState.ListStamp -> Bool
    quick l stamp = not (null (NodeList.nodeListList l)) && DhtState.listBootstrappedTimes stamp < maxBootstrapTimes

-- | Asks the nodes 'handleNodesResponse' kept.
sendQueued :: DhtNodeMonad m => m ()
sendQueued = do
  queued <- getsDht DhtState.dhtToBootstrap
  quick <- getsDht bootstrapping
  unless (Map.null queued && not quick) $ do
    now <- Timed.askTime
    modifyDht $ \s -> s { DhtState.dhtToBootstrap = Map.empty, DhtState.dhtBatchSent = now }
    mapM_ sendNodesRequest [RequestInfo node key | (key, nodes) <- Map.toList queued, node <- nodes]
    when quick $ execWriterT randomRequests >>= mapM_ sendNodesRequest

\end{code}

\subsection{Handling Nodes Request packets}
When we receive a Nodes Request packet from another node, we reply with a Nodes
Response packet containing the 4 nodes in the DHT State which are the closest to
the public key in the packet. If there are fewer than 4 nodes in the state, we
reply with all the nodes in the state. If there are no nodes in the state, no
reply is sent.

We also send a Ping Request when this is appropriate; see below.

\begin{code}

responseMaxNodes :: Int
responseMaxNodes = 4

handleNodesRequest ::
  DhtNodeMonad m => NodeInfo -> RpcPacket NodesRequest -> m ()
handleNodesRequest from (RpcPacket (NodesRequest key) requestId) = do
  ourPublicKey <- getsDht $ KeyPair.publicKey . DhtState.dhtKeyPair
  when (ourPublicKey /= NodeInfo.publicKey from) $ do
    nodes <- getsDht (DhtState.takeClosestNodesFor (NodeInfo.address from) responseMaxNodes key)
    -- An empty response still tells the requester about us, as in toxcore.
    sendNodesResponse from requestId nodes
    sendPingRequestIfAppropriate from

\end{code}

\subsection{Handling Ping Request packets}
When a valid Ping Request packet is received, we reply with a Ping Response.

We also send a Ping Request when this is appropriate; see below.

\begin{code}

handlePingRequest ::
  DhtNodeMonad m => NodeInfo -> RpcPacket PingPacket -> m ()
handlePingRequest from (RpcPacket PingRequest requestId) = do
  sendPingResponse from requestId
  sendPingRequestIfAppropriate from
handlePingRequest _ _ = return ()

\end{code}

\subsection{Handling Ping Response packets}
When we receive a valid Ping Response packet, we first check that it is a reply
to a Ping Request which we sent within the last 5 seconds to the node from
which we received the response, and that no previous reply has been received. If
this check fails, the packet is ignored. If the check succeeds, we add to the
DHT State the node from which the response was sent.

\begin{code}

requirePingResponseWithin :: TimeDiff
requirePingResponseWithin = Time.seconds 5

maxPendingTime :: TimeDiff
maxPendingTime = max requireNodesResponseWithin requirePingResponseWithin

checkPending :: DhtNodeMonad m =>
  TimeDiff -> NodeInfo -> RpcPacket.RequestId -> m Bool
checkPending timeLimit from requestId = do
  oldTime <- (`Time.addTime` negate maxPendingTime) <$> Timed.askTime
  modifyDht $ \s -> s { DhtState.dhtPendingReplies = PendingReplies.dropOlder oldTime (DhtState.dhtPendingReplies s) }
  recentCutoff <- (`Time.addTime` negate timeLimit) <$> Timed.askTime
  s <- getDht
  let (res, updated) = PendingReplies.checkExpectedReply recentCutoff from requestId (DhtState.dhtPendingReplies s)
  putDht $ s { DhtState.dhtPendingReplies = updated }
  return res

handlePingResponse ::
  DhtNodeMonad m => NodeInfo -> RpcPacket PingPacket -> m ()
handlePingResponse from (RpcPacket PingResponse requestId) = do
  isReply <- checkPending requirePingResponseWithin from requestId
  ourPublicKey <- getsDht $ KeyPair.publicKey . DhtState.dhtKeyPair
  when (isReply && ourPublicKey /= NodeInfo.publicKey from) $ do
    time <- Timed.askTime
    logDebug $ "Adding node to DHT from PingResponse: " <> pack (show $ NodeInfo.publicKey from)
    modifyDht $ DhtState.addNode time from
    nodeAnswered from
handlePingResponse _ _ = return ()

\end{code}

\subsection{Sending Ping Requests}
When we receive a Nodes Request or a Ping Request, in addition to the handling
described above, we sometimes send a Ping Request.
Namely, we send a Ping Request to the node which sent the packet if the node is
viable for entry to the Close List and is not already in the Close List.
An implementation should not send every such Ping Request, as anyone can send
us requests from new keys as fast as they like.  For example, ping a node being
searched for at once, and of the others at most 32 every 2 seconds: at once
while fewer went since the last round, else the 32 closest to our key at the
next.

\begin{code}

maxToPing :: Int
maxToPing = 32

-- | At once to a node we search for, as c-toxcore does, and to others while
-- fewer than 'maxToPing' went since the last 'doDHT'. A new node then joins
-- the DHT within a round trip, not at the next round, and a flood of new
-- keys still gets no more pings than before: the rest wait for the round,
-- the closest first.
sendPingRequestIfAppropriate :: DhtNodeMonad m => NodeInfo -> m ()
sendPingRequestIfAppropriate from = do
  wanted <- pingWanted from
  now <- Timed.askTime
  entry <- getsDht $ Map.lookup (NodeInfo.publicKey from) . DhtState.dhtSearchList
  pinged <- getsDht DhtState.dhtPinged
  ourPk <- getsDht $ KeyPair.publicKey . DhtState.dhtKeyPair
  -- A searched node that asks us is where it sends from, which behind some
  -- NATs is nowhere others see it, so it's worth a ping wherever it fits.
  let searched = isJust entry && not (answeredLately now entry)
  when (wanted || searched) $ if
    | searched -> sendPingRequest from
    | pinged < maxToPing -> do
        modifyDht $ \s -> s { DhtState.dhtPinged = pinged + 1 }
        sendPingRequest from
    | otherwise -> modifyDht $ \s -> s { DhtState.dhtToPing = queuePing ourPk from (DhtState.dhtToPing s) }

pingWanted :: DhtNodeMonad m => NodeInfo -> m Bool
pingWanted node = do
  closeList <- getsDht DhtState.dhtCloseList
  return $ isNothing (NodeList.lookupPublicKey (NodeInfo.publicKey node) closeList)
    && NodeList.viable node closeList

queuePing :: PublicKey -> NodeInfo -> [NodeInfo] -> [NodeInfo]
queuePing ourPk node = take maxToPing . insertBy closer node . filter other
  where
    closer = comparing (Distance.xorDistance ourPk . NodeInfo.publicKey)
    other n = NodeInfo.publicKey n /= NodeInfo.publicKey node

-- | Pings the nodes 'sendPingRequestIfAppropriate' kept, which count
-- towards the new round. Runs each 'doDHT'.
sendQueuedPings :: DhtNodeMonad m => m ()
sendQueuedPings = do
  queued <- getsDht DhtState.dhtToPing
  modifyDht $ \s -> s { DhtState.dhtToPing = [] }
  sent <- filterM pingWanted queued
  modifyDht $ \s -> s { DhtState.dhtPinged = length sent }
  mapM_ sendPingRequest sent

\end{code}

\input{src/Tox/DHT/DhtRequestPacket.lhs}
\subsection{Handling DHT Request packets}

A DHT node that receives a DHT request packet checks whether the addressee
public key is their DHT public key. If it is, they will decrypt and handle
the packet.  Otherwise, they will check whether the addressee DHT public key
is the DHT public key of one of the nodes in their Close List.  If it isn't,
they will drop the packet.  If it is they will resend the packet, unaltered, to
that DHT node.

DHT request packets are used for DHT public key packets (see
\href{#onion}{onion}) and NAT ping packets.

\begin{code}

handleDhtRequestPacket :: DhtNodeMonad m => NodeInfo -> DhtRequestPacket -> m ()
handleDhtRequestPacket from packet@DhtRequestPacket{ addresseePublicKey, dhtPacket } = do
  keyPair <- getsDht DhtState.dhtKeyPair
  if addresseePublicKey == KeyPair.publicKey keyPair
  then handleDhtRequestPayload from dhtPacket
  else void . runMaybeT $ do
    node :: NodeInfo <- MaybeT $
      NodeList.lookupPublicKey addresseePublicKey <$> getsDht DhtState.dhtCloseList
    lift . Networked.sendPacket node . Packet PacketKind.Crypto $ packet

\end{code}

\subsection{NAT ping packets}

A NAT ping packet is sent as the payload of a DHT request packet.

We use NAT ping packets to see if a friend we are not connected to directly is
online and ready to do the hole punching.

\subsubsection{NAT ping request}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0xfe) \\
  \texttt{1}         & \texttt{uint8\_t} (0x00) \\
  \texttt{8}         & \texttt{uint64\_t} random number \\
\end{tabular}

\subsubsection{NAT ping response}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0xfe) \\
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
  \texttt{8}         & \texttt{uint64\_t} random number (the same that was received in request) \\
\end{tabular}

\subsection{Effects of chosen constants on performance}
If the bucket size of the k-buckets were increased, it would increase the
amount of packets needed to check if each node is still alive, which would
increase the bandwidth usage, but reliability would go up.  If the number of
nodes were decreased, reliability would go down along with bandwidth usage.
The reason for this relationship between reliability and number of nodes is
that if we assume that not every node has its UDP ports open or is behind a
cone NAT it means that each of these nodes must be able to store a certain
number of nodes behind restrictive NATs in order for others to be able to find
those nodes behind restrictive NATs.  For example if 7/8 nodes were behind
restrictive NATs, using 8 nodes would not be enough because the chances of
some of these nodes being impossible to find in the network would be too high.

TODO(zugz): this seems a rather wasteful solution to this problem.

If the ping timeouts and delays between pings were higher it would decrease the
bandwidth usage but increase the amount of disconnected nodes that are still
being stored in the lists.  Decreasing these delays would do the opposite.

If the maximum size 8 of the DHT Search Entry Client Lists were increased
would increase the bandwidth usage, might increase hole punching efficiency on
symmetric NATs (more ports to guess from, see Hole punching) and might increase
the reliability.  Lowering this number would have the opposite effect.

The timeouts and number of nodes in lists for toxcore were picked by feeling
alone and are probably not the best values.  This also applies to the behavior
which is simple and should be improved in order to make the network resist
better to sybil attacks.

TODO: consider giving min and max values for the constants.

\begin{code}

{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}

type TestDhtNodeMonad = KeyedT (TimedT (RandT StdGen (NoLog (StateT DhtState (Networked.NetworkLogged Identity)))))
instance DhtNodeMonad TestDhtNodeMonad where
  getDhtState = get
  putDhtState = put

runTestDhtNode :: ArbStdGen -> Timestamp -> DhtState -> TestDhtNodeMonad a -> (a, DhtState)
runTestDhtNode seed time s =
  runIdentity
    . Networked.evalNetworkLogged
    . (`runStateT` s)
    . runNoLog
    . (`evalRandT` unwrapArbStdGen seed)
    . (`TimedT.runTimedT` time)
    . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)

evalTestDhtNode :: ArbStdGen -> Timestamp -> DhtState -> TestDhtNodeMonad a -> a
evalTestDhtNode seed time s = fst . runTestDhtNode seed time s
execTestDhtNode :: ArbStdGen -> Timestamp -> DhtState -> TestDhtNodeMonad a -> DhtState
execTestDhtNode seed time s = snd . runTestDhtNode seed time s

initTestDhtState :: ArbStdGen -> Timestamp -> DhtState
initTestDhtState seed time =
  runIdentity
    . (`evalRandT` unwrapArbStdGen seed)
    . (`TimedT.runTimedT` time)
    $ initDht

-- | wrap StdGen so the Arbitrary instance isn't an orphan
newtype ArbStdGen = ArbStdGen { unwrapArbStdGen :: StdGen }
  deriving (Show)

instance Arbitrary ArbStdGen
  where arbitrary = ArbStdGen . mkStdGen <$> arbitrary

\end{code}
