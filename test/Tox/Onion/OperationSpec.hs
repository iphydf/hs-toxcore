{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Tox.Onion.OperationSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Monad.Identity       (Identity, runIdentity)
import           Control.Monad.Logger         (MonadLogger, NoLoggingT, runNoLoggingT)
import           Control.Monad.Random         (RandT, evalRandT)
import           Control.Monad.State          (MonadState, StateT, runStateT, gets, get, put)
import qualified Data.Map                     as Map
import qualified Data.ByteString              as BS
import           System.Random                (StdGen, mkStdGen)

import qualified Data.ByteString.Lazy         as LBS
import           Data.Maybe                   (fromJust)
import           Data.Binary                  (encode)

import           Tox.Core.Time                (Timestamp)
import qualified Tox.Core.Time                as Time
import           Tox.Core.Timed               (Timed (..))
import qualified Tox.Core.PingArray           as PingArray
import           Tox.Network.Core.TimedT           (TimedT, runTimedT)
import           Tox.Crypto.Core.Keyed             (Keyed (..))
import           Tox.Crypto.Core.Keyed            (KeyedT, evalKeyedT)
import           Tox.Crypto.Core.Key               (PublicKey, Key(..))
import           Tox.Crypto.Core.KeyPair           (KeyPair (..))
import qualified Tox.Crypto.Core.KeyPair           as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes (..), randomNonce)
import qualified Tox.Crypto.Core.Box               as Box
import qualified Crypto.Saltine.Class              as Sodium
import qualified Tox.Network.Core.Networked  as Networked
import           Tox.Network.Core.NodeInfo         (NodeInfo)
import qualified Tox.Network.Core.NodeInfo         as NodeInfo
import           Tox.Network.Core.Packet           (Packet (..))
import qualified Tox.Network.Core.PacketKind       as PacketKind
import           Tox.Onion.Operation
import qualified Tox.Onion.Path                    as Path
import qualified Tox.Onion.RPC                     as RPC

newtype TestOnionNodeMonad a = TestOnionNodeMonad 
  { unTestOnionNodeMonad :: KeyedT (TimedT (RandT StdGen (NoLoggingT (StateT OnionState (Networked.NetworkLogged Identity))))) a 
  } deriving (Functor, Applicative, Monad, MonadState OnionState, Timed, MonadRandomBytes, Keyed, Networked.Networked, MonadLogger)

instance OnionNodeMonad TestOnionNodeMonad where
  getOnionState = get
  putOnionState = put
  getDhtKeyPair = gets ourLongTermKeys

runTestOnionNode :: Timestamp -> OnionState -> TestOnionNodeMonad a -> ((a, OnionState), [Networked.NetworkAction])
runTestOnionNode time s =
  runIdentity
    . Networked.runNetworkLogged
    . (`runStateT` s)
    . runNoLoggingT
    . (`evalRandT` mkStdGen 42)
    . (`runTimedT` time)
    . (`evalKeyedT` Map.empty)
    . unTestOnionNodeMonad

spec :: Spec
spec = do
  describe "doOnion" $ do
    it "maintains paths and sends announcements" $ property $
      \(now :: Timestamp) (ourKeys :: KeyPair) (dhtNodes :: [NodeInfo]) ->
        length dhtNodes >= 3 ==>
          let s0 = initState ourKeys
              ((_, s1), events) = runTestOnionNode now s0 (doOnion dhtNodes)
              isOnionRequest (Networked.SendPacket _ (Packet kind _)) = kind == PacketKind.OnionRequest0
          in length (Path.announcePaths $ onionPaths s1) == Path.maxPaths &&
             any isOnionRequest events

  describe "handleAnnounceResponse" $ do
    it "updates announcedNodes state on successful decryption" $ property $
      \(now :: Timestamp) (ourKeys :: KeyPair) (from :: NodeInfo) (payload :: RPC.AnnounceResponsePayload) ->
        let s0 = initState ourKeys
            targetPk = NodeInfo.publicKey from
            searchKey = KeyPair.publicKey ourKeys
            
            -- Prepare state with a matching request in the tracker
            (sendback, s1) = runIdentity $ do
               let meta = OnionRequest searchKey targetPk ourKeys
               let (sid, tracker') = PingArray.addEntry now meta 0 (requestTracker s0)
               return (sid, s0 { requestTracker = tracker' })

            -- Prepare a valid response mocked from the target node
            ((res, _), _) = runTestOnionNode now s1 $ do
              combined <- getCombinedKey (KeyPair.secretKey ourKeys) targetPk
              nonce <- randomNonce
              let enc = RPC.AnnounceResponse sendback nonce (Box.encrypt combined nonce (Box.encode payload))
              return enc
            
            ((_, s2), _) = runTestOnionNode now s1 (handleAnnounceResponse from res)
        in Map.member targetPk (announcedNodes s2) `shouldBe` True

  describe "handleAnnounceRequest (Server side)" $ do
    it "stores a valid announcement and responds with nearby nodes" $ property $
      \(now :: Timestamp) (ourKeys :: KeyPair) (from :: NodeInfo) (payload :: RPC.AnnounceRequestPayload) ->
        let s0 = initState ourKeys
            senderPk = KeyPair.publicKey ourKeys -- Mock sender
            dhtNodes = [from]
            
            -- Prepare a valid request
            ((req, _), _) = runTestOnionNode now s0 $ do
               combined <- getCombinedKey (KeyPair.secretKey ourKeys) senderPk
               nonce <- randomNonce
               let enc = Box.encrypt combined nonce (Box.encode payload)
               return $ RPC.AnnounceRequest nonce senderPk enc

            ((_, s1), events) = runTestOnionNode now s0 (handleAnnounceRequest dhtNodes from req)
            isAnnounceResponse (Networked.SendPacket to (Packet kind _)) = 
              to == from && kind == PacketKind.AnnounceResponse
            
            searchKey = RPC.announceRequestSearchKey payload
            pId = RPC.announceRequestPingId payload
        in if pId /= Key (fromJust $ Sodium.decode $ BS.replicate 32 0)
           then Map.member searchKey (localAnnouncements s1) `shouldBe` True
           else events `shouldSatisfy` any isAnnounceResponse

  describe "handleDataRouteRequest" $ do
    it "peels both layers and dispatches the inner payload (DHTPKPacket)" $ property $
      \(now :: Timestamp) (ourKeys :: KeyPair) (senderKeys :: KeyPair) (from :: NodeInfo) (dhtPk :: PublicKey) ->
        let s0 = initState ourKeys
            destPk = KeyPair.publicKey ourKeys
            senderPk = KeyPair.publicKey senderKeys
            nonce = read "\"000000000000000000000000000000000000000000000000\""
            
            -- Inner data: [0x9c][DHTPKPacket]
            pkt = RPC.DHTPublicKeyPacket 0 dhtPk []
            innerPayload = Box.PlainText $ BS.singleton 0x9c <> LBS.toStrict (encode pkt)

            -- 1. Create inner layer (Node D's LT Key + Sender LT Key)
            innerCombined = runIdentity $ evalKeyedT (getCombinedKey (KeyPair.secretKey senderKeys) destPk) Map.empty
            innerEnc = Box.encrypt innerCombined nonce innerPayload
            inner = RPC.DataRouteInner senderPk innerEnc

            -- 2. Create outer layer (Node D's LT Key + Temp Key)
            tempKp = senderKeys -- dummy temp key
            outerCombined = runIdentity $ evalKeyedT (getCombinedKey (KeyPair.secretKey tempKp) destPk) Map.empty
            outerEnc = Box.encrypt outerCombined nonce (Box.encode inner)

            req = RPC.DataRouteRequest destPk nonce (KeyPair.publicKey tempKp) outerEnc

            -- 3. Mock dispatch
            ((_, s1), _) = runTestOnionNode now s0 (handleDataRouteRequest from req)
            
            -- 4. Verify discovery
            foundPk = Map.lookup senderPk (searchNodes s1)
        in case foundPk of
             Just m -> Map.member dhtPk m `shouldBe` True
             Nothing -> expectationFailure "Friend search node not created"
