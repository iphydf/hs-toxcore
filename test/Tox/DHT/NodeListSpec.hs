{-# LANGUAGE ScopedTypeVariables #-}
module Tox.DHT.NodeListSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import qualified Tox.DHT.ClientList   as ClientList
import           Tox.DHT.NodeList
import           Tox.Network.Core.NodeInfo (NodeInfo (..))
import qualified Tox.Network.Core.NodeInfo as NodeInfo
import           Tox.Core.Time        (Timestamp)

spec :: Spec
spec = do
  describe "lookupPublicKey" $ do
    it "finds a node that exists in the list" $ property $
      \(bk, time :: Timestamp, nodeInfo :: NodeInfo) ->
        let cl = ClientList.addNode time nodeInfo $ ClientList.empty bk 10
            res = lookupPublicKey (NodeInfo.publicKey nodeInfo) cl
        in res `shouldBe` Just nodeInfo

    it "returns Nothing if the node is not in the list" $ property $
      \(bk, time :: Timestamp, nodeInfo :: NodeInfo, otherKey) ->
        NodeInfo.publicKey nodeInfo /= otherKey ==>
          let cl = ClientList.addNode time nodeInfo $ ClientList.empty bk 10
              res = lookupPublicKey otherKey cl
          in res `shouldBe` Nothing