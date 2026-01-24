{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
{-# LANGUAGE Trustworthy         #-}
module Tox.DHT.OperationSpec where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Monad               (when)
import           Control.Monad.Identity      (runIdentity)
import           Control.Monad.Random        (evalRandT)
import           Control.Monad.State         (runStateT)
import           Control.Monad.Writer        (execWriterT)
import qualified Data.Map                    as Map

import           Tox.Core.Log                (runNoLog)
import qualified Tox.Core.Time               as Time
import qualified Tox.Crypto.Core.Keyed       as KeyedT
import qualified Tox.Crypto.Core.KeyPair     as KeyPair
import qualified Tox.DHT.DhtState            as DhtState
import qualified Tox.DHT.NodeList            as NodeList
import           Tox.DHT.NodesRequest        (NodesRequest (..))
import           Tox.DHT.NodesResponse       (NodesResponse (..))
import qualified Tox.DHT.Operation           as Operation
import qualified Tox.DHT.PendingReplies      as PendingReplies
import           Tox.DHT.PingPacket          (PingPacket (..))
import           Tox.DHT.RpcPacket           (RequestId (..), RpcPacket (..))
import qualified Tox.Network.Core.Networked  as Networked
import qualified Tox.Network.Core.NodeInfo   as NodeInfo
import           Tox.Network.Core.NodeInfo   (NodeInfo)
import           Tox.Network.Core.Packet     (Packet (..))
import qualified Tox.Network.Core.PacketKind as PacketKind
import qualified Tox.Network.Core.TimedT     as TimedT

spec :: Spec
spec = do
  describe "a newly initialised DHT node" $ do
    it "contains no nodes" $
      property $ \time seed ->
        DhtState.size (Operation.initTestDhtState seed time) `shouldBe` 0

    it "has a search list containing initRandomSearches search entries" $
      property $ \time seed ->
        (Map.size . DhtState.dhtSearchList $ Operation.initTestDhtState seed time)
        `shouldBe` Operation.initRandomSearches

  describe "periodic nodes requests" $
    it "are not generated for an empty DHT State" $
      property $ \keyPair time time' seed ->
        let
          dhtState = DhtState.empty time keyPair
          requests = Operation.evalTestDhtNode seed time' dhtState . execWriterT $
            Operation.randomRequests >> Operation.checkNodes
        in
        requests `shouldBe` []

  describe "randomRequests" $ do
    it "generates a single Nodes Request to a node in the close list after randomRequestPeriod" $
      property $ \keyPair time (nodeInfos::[NodeInfo]) seed ->
        let
          dhtState       = DhtState.empty time keyPair
          afterAdd       = foldr (DhtState.addNode time) dhtState nodeInfos
          time'          = time `Time.addTime` Operation.randomRequestPeriod
          randomRequests = Operation.evalTestDhtNode seed time' afterAdd
            . execWriterT $ Operation.randomRequests
        in
        case randomRequests of
          [] -> DhtState.size dhtState `shouldBe` 0
          Operation.RequestInfo nodeInfo publicKey : rs -> do
            rs `shouldSatisfy` null
            nodeInfo `shouldSatisfy` (`elem` nodeInfos)
            publicKey `shouldBe` KeyPair.publicKey (DhtState.dhtKeyPair dhtState)

    it "generates a Nodes Request to a node in a new search list after randomRequestPeriod" $
      property $ \time publicKey dhtState (nodeInfos::[NodeInfo]) seed ->
        let
          afterSearch       = DhtState.addSearchKey time publicKey dhtState
          afterAdd          = foldr (DhtState.addNode time) afterSearch nodeInfos
          nodeAddedToSearch = not $ all ((== publicKey) . NodeInfo.publicKey) nodeInfos
          time'             = time `Time.addTime` Operation.randomRequestPeriod
          randomRequests    = Operation.evalTestDhtNode seed time' afterAdd
            . execWriterT $ Operation.randomRequests

          requestIsForSearch (Operation.RequestInfo nodeInfo publicKey') =
            publicKey == publicKey' && nodeInfo `elem` nodeInfos &&
              NodeInfo.publicKey nodeInfo /= publicKey
        in
        when nodeAddedToSearch $
          randomRequests `shouldSatisfy` any requestIsForSearch

  describe "checkNodes" $
    it "generates a Nodes Request to a newly added node after checkPeriod" $
      property $ \time dhtState nodeInfo seed ->
        let
          viable   = DhtState.viable nodeInfo dhtState
          afterAdd = DhtState.addNode time nodeInfo dhtState
          time'    = time `Time.addTime` Operation.checkPeriod
          checks   = Operation.evalTestDhtNode seed time' afterAdd
            . execWriterT $ Operation.checkNodes
        in
        when viable $ map Operation.requestTo checks `shouldSatisfy` (nodeInfo `elem`)

  describe "bootstrapping" $ do
    it "bootstraps again while the close list is empty, waiting twice as long each time" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (node :: NodeInfo) ->
        fst (maintain seed time node (bootstrapped seed time node) [1 .. 40]) `shouldBe` [5, 15, 35]

    it "waits the shortest time again once the close list had a node" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (node :: NodeInfo) (other :: NodeInfo) ->
        NodeInfo.publicKey other /= NodeInfo.publicKey node ==>
          let (_, waited) = maintain seed time node (bootstrapped seed time node) [1 .. 15]
              (_, had) = maintain seed time node (DhtState.addNode (time `Time.addTime` Time.seconds 16) other waited) [16]
              emptied = NodeList.removeNode (NodeInfo.publicKey other) had
          in fst (maintain seed time node emptied [17 .. 29]) `shouldBe` [20]

  describe "handleNodesResponse" $ do
    it "adds the sender to the DHT state" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (from :: NodeInfo) (rid :: RequestId) (nodes :: [NodeInfo]) ->
        let dhtState = Operation.initTestDhtState seed time
            -- Only a reply we asked for adds its sender.
            expecting = DhtState.empty time (DhtState.dhtKeyPair dhtState)
            expectingWithReply = expecting { DhtState.dhtPendingReplies = PendingReplies.expectReply time from rid PendingReplies.empty }
            response = RpcPacket (NodesResponse nodes) rid
            finalState = Operation.execTestDhtNode seed time expectingWithReply (Operation.handleNodesResponse from response)
        in DhtState.containsNode (NodeInfo.publicKey from) finalState `shouldBe` True

    it "asks only the closest few of the nodes responses tell of, per list" $ withMaxSuccess 20 $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) ->
        forAll (vectorOf 20 ((,,) <$> arbitrary <*> arbitrary <*> vectorOf 4 arbitrary)) $ \responses ->
          let dhtState = Operation.initTestDhtState seed time
              expect (from, rid, _) st =
                st { DhtState.dhtPendingReplies = PendingReplies.expectReply time from rid (DhtState.dhtPendingReplies st) }
              (_, events) = runIdentity
                . Networked.runNetworkLogged
                . (`runStateT` foldr expect dhtState responses)
                . runNoLog
                . (`evalRandT` Operation.unwrapArbStdGen seed)
                . (`TimedT.runTimedT` time)
                . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
                $ mapM_ (\(from, rid, nodes) -> Operation.handleNodesResponse from (RpcPacket (NodesResponse nodes) rid))
                    responses
                  >> Operation.sendQueued
              asked = length [ () | Networked.SendPacket _ (Packet PacketKind.NodesRequest _) <- events ]
              searches = Map.size (DhtState.dhtSearchList dhtState)
              -- And one of each list's first quick requests.
          in asked `shouldSatisfy` (<= Operation.maxCloseToBootstrap + 1 + searches * (Operation.maxSearchToBootstrap + 1))

    it "asks the nodes responses tell of 50 ms after it last did, and is due no sooner" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) from rid ->
        forAll (vectorOf 4 arbitrary) $ \nodes ->
          let later = Time.addTime time (Time.milliseconds 10)
              batch = Time.addTime time (Time.milliseconds 50)
              told t st = Operation.execTestDhtNode seed t st { DhtState.dhtPendingReplies =
                  PendingReplies.expectReply t from rid (DhtState.dhtPendingReplies st) }
                (Operation.handleNodesResponse from (RpcPacket (NodesResponse nodes) rid))
              fresh = Operation.initTestDhtState seed time
              asked = Operation.execTestDhtNode seed time (told time fresh) Operation.sendQueued
              -- Lists making their first quick requests keep the batches
              -- coming, no sooner either.
              noSooner = maybe True (>= batch) (Operation.queueDue asked)
          in not (Map.null (DhtState.dhtToBootstrap (told time fresh))) ==>
               ( Operation.queueDue fresh, Operation.queueDue (told time fresh), noSooner
               , Operation.queueDue (told later asked) )
                 `shouldBe` (Nothing, Just batch, True, Just batch)

    -- Once it's quiet, as else nothing would check we still reach it.
    it "asks a searched node for itself until the search has it there, and once it's quiet" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (from :: NodeInfo) (rid :: RequestId)
       (searched :: NodeInfo) ->
        let searching = DhtState.addSearchKey time (NodeInfo.publicKey searched) (Operation.initTestDhtState seed time)
            queued at st = Map.lookup (NodeInfo.publicKey searched) . DhtState.dhtToBootstrap $
              Operation.execTestDhtNode seed at
                st { DhtState.dhtPendingReplies = PendingReplies.expectReply at from rid (DhtState.dhtPendingReplies st) }
                (Operation.handleNodesResponse from (RpcPacket (NodesResponse [searched]) rid))
            found = DhtState.updateSearchNode (NodeInfo.publicKey searched) (Just (searched, time)) searching
            quiet = time `Time.addTime` Operation.checkPeriod
        in NodeInfo.publicKey from /= NodeInfo.publicKey searched ==>
          (queued time searching, queued time found, queued quiet found) `shouldBe` (Just [searched], Nothing, Just [searched])

  describe "handleNodesRequest" $ do
    it "pings no more of the nodes that ask than a few each round, as a flood could" $ withMaxSuccess 20 $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) ->
        forAll (vectorOf 100 arbitrary) $ \requests ->
          let run st = runIdentity
                . Networked.runNetworkLogged
                . (`runStateT` st)
                . runNoLog
                . (`evalRandT` Operation.unwrapArbStdGen seed)
                . (`TimedT.runTimedT` time)
                . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
              ((_, asked), during) = run (Operation.initTestDhtState seed time) $
                mapM_ (\(from, rid, key) -> Operation.handleNodesRequest from (RpcPacket (NodesRequest key) rid)) requests
              ((_, nextRound), atRound) = run asked Operation.sendQueuedPings
              pings events = length [ () | Networked.SendPacket _ (Packet PacketKind.PingRequest _) <- events ]
          -- At once while the round has room, the rest at the next, which
          -- they count towards.
          in (pings during, pings atRound, DhtState.dhtPinged nextRound)
               `shouldSatisfy` \(now, next, counted) -> now <= Operation.maxToPing && next <= Operation.maxToPing && counted == next

    -- Behind a symmetric NAT, where it sends us from is where only we see it.
    it "pings a searched node that asks it, though it fits no list" $ withMaxSuccess 20 $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (rid :: RequestId) (searched :: NodeInfo) ->
        forAll (vectorOf 200 arbitrary) $ \nodes ->
          let full = foldr (DhtState.addNode time) (Operation.initTestDhtState seed time) nodes
              st = DhtState.addSearchKey time (NodeInfo.publicKey searched) full
              (_, events) = runIdentity
                . Networked.runNetworkLogged
                . (`runStateT` st)
                . runNoLog
                . (`evalRandT` Operation.unwrapArbStdGen seed)
                . (`TimedT.runTimedT` time)
                . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
                $ Operation.handleNodesRequest searched (RpcPacket (NodesRequest (NodeInfo.publicKey searched)) rid)
          in not (NodeList.viable searched (DhtState.dhtCloseList full)) ==>
               any (\case Networked.SendPacket to (Packet PacketKind.PingRequest _) -> to == searched; _ -> False) events

  describe "handlePingRequest" $ do
    it "sends a ping response" $ property $
      \(seed :: Operation.ArbStdGen) (time :: Time.Timestamp) (from :: NodeInfo) (rid :: RequestId) ->
        let dhtState = Operation.initTestDhtState seed time
            ((_, _), events) = runIdentity
              . Networked.runNetworkLogged
              . (`runStateT` dhtState)
              . runNoLog
              . (`evalRandT` Operation.unwrapArbStdGen seed)
              . (`TimedT.runTimedT` time)
              . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
              $ Operation.handlePingRequest from (RpcPacket PingRequest rid)
            isPingResponse (Networked.SendPacket to (Packet kind _)) =
                to == from && kind == PacketKind.PingResponse
        in events `shouldSatisfy` any isPingResponse

bootstrapped :: Operation.ArbStdGen -> Time.Timestamp -> NodeInfo -> DhtState.DhtState
bootstrapped seed time node =
  Operation.execTestDhtNode seed time (Operation.initTestDhtState seed time) (Operation.bootstrapNode node)

-- | Runs maintenance at each of the seconds after the time, and says at which
-- it asked the node for nodes.
maintain :: Operation.ArbStdGen -> Time.Timestamp -> NodeInfo -> DhtState.DhtState -> [Integer]
  -> ([Integer], DhtState.DhtState)
maintain _ _ _ dhtState [] = ([], dhtState)
maintain seed time node dhtState (t : ts) =
  let ((_, dhtState'), events) = runIdentity
        . Networked.runNetworkLogged
        . (`runStateT` dhtState)
        . runNoLog
        . (`evalRandT` Operation.unwrapArbStdGen seed)
        . (`TimedT.runTimedT` (time `Time.addTime` Time.seconds t))
        . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
        $ Operation.doDHT
      asked = or [ to == node | Networked.SendPacket to (Packet PacketKind.NodesRequest _) <- events ]
      (later, final) = maintain seed time node dhtState' ts
  in ([t | asked] ++ later, final)
