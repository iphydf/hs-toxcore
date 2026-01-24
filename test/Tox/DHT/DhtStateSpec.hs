{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
{-# LANGUAGE Trustworthy         #-}
module Tox.DHT.DhtStateSpec where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Monad                 (unless, when)
import           Data.Functor.Identity         (Identity (..))
import           Data.List                     (nub, sort, sortOn)
import qualified Data.Map                      as Map
import           Data.Proxy                    (Proxy (..))
import qualified Data.Set                      as Set

import qualified Tox.Core.Time                 as Time
import qualified Tox.Crypto.Core.Key           as Key
import qualified Tox.Crypto.Core.KeyPair       as KeyPair
import qualified Tox.DHT.ClientList            as ClientList
import qualified Tox.DHT.DhtState              as DhtState
import           Tox.DHT.DhtState              (DhtState)
import qualified Tox.DHT.Distance              as Distance
import qualified Tox.DHT.NodeList              as NodeList
import           Tox.Network.Core.EncodingSpec
import qualified Tox.Network.Core.NodeInfo     as NodeInfo


spec :: Spec
spec = do
  readShowSpec (Proxy :: Proxy DhtState)

  it "the state can never contain itself" $
    property $ \keyPair time nodeInfo ->
      let
        dhtState = DhtState.empty time keyPair
        afterAdd = DhtState.addNode time
          nodeInfo { NodeInfo.publicKey = KeyPair.publicKey keyPair }
          dhtState
      in
      afterAdd `shouldBe` dhtState

  describe "adding a node that was not yet contained" $ do
    it "should result in a different state" $
      property $ \keyPair time nodeInfo ->
        let
          dhtState = DhtState.empty time keyPair
          afterAdd = DhtState.addNode time nodeInfo dhtState
        in
        unless (DhtState.containsNode (NodeInfo.publicKey nodeInfo) dhtState) $
          afterAdd `shouldNotBe` dhtState

    it "and removing it yields the same state" $
      property $ \keyPair time nodeInfo ->
        let
          dhtState    = DhtState.empty time keyPair
          afterAdd    = DhtState.addNode time nodeInfo dhtState
          afterRemove = DhtState.removeNode (NodeInfo.publicKey nodeInfo) afterAdd
        in
        unless (DhtState.containsNode (NodeInfo.publicKey nodeInfo) dhtState) $
          afterRemove `shouldBe` dhtState

  describe "adding a node" $
    it "and adding it again does not change the state twice" $
      property $ \keyPair time nodeInfo ->
        let
          dhtState  = DhtState.empty time keyPair
          afterAdd1 = DhtState.addNode time nodeInfo dhtState
          afterAdd2 = DhtState.addNode time nodeInfo afterAdd1
        in
        afterAdd1 `shouldBe` afterAdd2

  describe "adding a search node" $ do
    it "should result in a different state" $
      property $ \keyPair time publicKey ->
        let
          dhtState = DhtState.empty time keyPair
          afterAdd = DhtState.addSearchKey time publicKey dhtState
        in
        afterAdd `shouldNotBe` dhtState

    it "and removing it yields the same state" $
      property $ \keyPair time publicKey ->
        let
          dhtState    = DhtState.empty time keyPair
          afterAdd    = DhtState.addSearchKey time publicKey dhtState
          afterRemove = DhtState.removeSearchKey publicKey afterAdd
        in
        afterRemove `shouldBe` dhtState

    it "and adding it again does not change the state twice" $
      property $ \keyPair time publicKey ->
        let
          dhtState  = DhtState.empty time keyPair
          afterAdd1 = DhtState.addSearchKey time publicKey dhtState
          afterAdd2 = DhtState.addSearchKey time publicKey afterAdd1
        in
        afterAdd1 `shouldBe` afterAdd2

    it "and adding a node info for it will not add it to the search entry's Client List" $
      property $ \keyPair time nodeInfo ->
        let
          dhtState = DhtState.empty time keyPair
          afterAddSearchKey = DhtState.addSearchKey time
            (NodeInfo.publicKey nodeInfo)
            dhtState
        in
        DhtState.size (DhtState.addNode time nodeInfo afterAddSearchKey)
        `shouldBe`
        DhtState.size (DhtState.addNode time nodeInfo dhtState)

  describe "takeClosestNodesTo" $ do
    it "returns the requested number of nodes if there are enough nodes in the state" $
      property $ \dhtState n publicKey -> n >= 0 ==>
        let
          taken = DhtState.takeClosestNodesTo n publicKey dhtState
          nodes = NodeList.foldNodes (flip Set.insert) Set.empty dhtState
        in
        when (Set.size nodes >= n) $ length taken `shouldBe` n

    it "returns distinct nodes sorted by distance from the given key" $
      property $ \dhtState n publicKey -> n >= 0 ==>
        let
          taken = DhtState.takeClosestNodesTo n publicKey dhtState
          dists = map (Distance.xorDistance publicKey . NodeInfo.publicKey) taken
        in
        dists `shouldBe` (nub . sort) dists

    it "returns the closest of all the nodes the lists hold" $
      property $ \dhtState publicKey ->
        let
          held = map NodeInfo.publicKey $ NodeList.foldNodes (flip (:)) [] dhtState
          closest = take 8 . nub $ sortOn (Distance.xorDistance publicKey) held
        in
        map NodeInfo.publicKey (DhtState.takeClosestNodesTo 8 publicKey dhtState) `shouldBe` closest

  describe "the nodes kept by key" $
    it "are the nodes the lists hold, as many times as they hold them" $
      property $ \dhtState (changes :: [(Int, Time.Timestamp, NodeInfo.NodeInfo)]) ->
        let
          changed = foldl change dhtState changes
          held = Map.fromListWith (+)
            [ (Key.keyToInteger (NodeInfo.publicKey n), 1) | n <- NodeList.foldNodes (flip (:)) [] changed ]
        in
        Map.map fst (DhtState.dhtNodes changed) `shouldBe` held

-- | Adds, removes, searches, stops searching, or checks, keeping one node per
-- list.
change :: DhtState -> (Int, Time.Timestamp, NodeInfo.NodeInfo) -> DhtState
change s (i, time, node) = case i `mod` 5 of
  0 -> DhtState.addNode time node s
  1 -> pick nodes (DhtState.removeNode . NodeInfo.publicKey)
  2 -> DhtState.addSearchKey time (NodeInfo.publicKey node) s
  3 -> pick (Map.keys (DhtState.dhtSearchList s)) DhtState.removeSearchKey
  _ -> runIdentity $ DhtState.traverseClientLists (Identity . ClientList.updateClientNodes (Map.take 1)) s
  where
    nodes = NodeList.foldNodes (flip (:)) [] s
    pick [] _ = s
    pick xs f = f (xs !! (i `div` 5 `mod` length xs)) s
