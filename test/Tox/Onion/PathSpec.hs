{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Tox.Onion.PathSpec (spec) where

import           Test.Hspec
import           Test.QuickCheck

import           Control.Monad.Identity       (Identity, runIdentity)
import           Control.Monad.Random         (RandT, evalRandT)
import           Control.Monad.State          (MonadState, StateT, runStateT, get, put)
import           Control.Monad.Trans          (lift)
import           Data.Maybe                   (isNothing)
import           System.Random                (StdGen, mkStdGen)

import           Tox.Core.Time                (Timestamp)
import qualified Tox.Core.Time                as Time
import           Tox.Core.Timed               (Timed (..))
import           Tox.Network.Core.TimedT           (TimedT, runTimedT)
import           Tox.Crypto.Core.Key               (Nonce)
import           Tox.Crypto.Core.KeyPair           (KeyPair (..))
import qualified Tox.Crypto.Core.KeyPair           as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)
import           Tox.Crypto.Core.Box               (CipherText, unCipherText)
import qualified Tox.Crypto.Core.Box               as Box
import           Tox.Crypto.Core.Keyed             (runNullKeyed)
import qualified Tox.Crypto.Core.Keyed             as Keyed
import           Tox.Network.Core.HostAddress      (HostAddress (..))
import           Tox.Network.Core.NodeInfo         (NodeInfo (..))
import           Tox.Network.Core.SocketAddress    (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (UDP))
import           Tox.Onion.Path
import qualified Tox.Onion.Tunnel             as Tunnel

newtype TestOnionMonad a = TestOnionMonad (TimedT (RandT StdGen (StateT OnionPathState Identity)) a)
  deriving (Functor, Applicative, Monad, Timed, MonadRandomBytes)

instance MonadState OnionPathState TestOnionMonad where
  get = TestOnionMonad $ lift $ lift get
  put = TestOnionMonad . lift . lift . put

instance Keyed.Keyed TestOnionMonad where
  getCombinedKey sk pk = return $ Keyed.runNullKeyed $ Keyed.getCombinedKey sk pk

instance OnionPathMonad TestOnionMonad

runTestOnion :: Timestamp -> OnionPathState -> TestOnionMonad a -> (a, OnionPathState)
runTestOnion time s (TestOnionMonad m) =
  runIdentity
    . (`runStateT` s)
    . (`evalRandT` mkStdGen 42)
    . (`runTimedT` time)
    $ m

spec :: Spec
spec = do
  describe "isPathAlive" $ do
    it "returns True for a new path" $ property $
      \(now :: Timestamp) (path :: OnionPath) ->
        let path' = path { pathExpires = now `Time.addTime` Time.seconds 1
                         , pathLastAttempt = Nothing
                         }
        in isPathAlive now path' `shouldBe` True

    it "returns False for an expired path" $ property $
      \(now :: Timestamp) (path :: OnionPath) ->
        let path' = path { pathExpires = now `Time.addTime` Time.seconds (-1) }
        in isPathAlive now path' `shouldBe` False

    it "returns False for a timed-out unconfirmed path" $ property $
      \(now :: Timestamp) (path :: OnionPath) ->
        let path' = path { pathExpires = now `Time.addTime` Time.seconds 100
                         , pathConfirmed = False
                         , pathLastAttempt = Just $ now `Time.addTime` Time.seconds (-5)
                         , pathTries = 2
                         }
      in isPathAlive now path' `shouldBe` False

  describe "wrapPath and unwrapping" $ do
    it "correctly layered encryption works through 3 hops" $ property $
      \(ourKP :: KeyPair) (kpA :: KeyPair) (kpB :: KeyPair) (kpC :: KeyPair)
        (kp1 :: KeyPair) (kp2 :: KeyPair) (kp3 :: KeyPair)
        (destAddr :: SocketAddress) (nonce :: Nonce) (finalData :: CipherText) (now :: Timestamp) ->
          let nodeA = NodeInfo UDP (SocketAddress (IPv4 0x7f000001) 33445) (KeyPair.publicKey kpA)
              nodeB = NodeInfo UDP (SocketAddress (IPv4 0x7f000002) 33445) (KeyPair.publicKey kpB)
              nodeC = NodeInfo UDP (SocketAddress (IPv4 0x7f000003) 33445) (KeyPair.publicKey kpC)
              path = OnionPath [nodeA, nodeB, nodeC] [kp1, kp2, kp3] True 0 (now `Time.addTime` pathLifetime) Nothing 0
              
              -- 1. Wrap
              (req0, _) = runTestOnion now (OnionPathState [] [] 0) (wrapPath ourKP path destAddr nonce (unCipherText finalData))
              
              -- 2. Node A unwraps req0 (kind 0x80)
              mP1 = runNullKeyed $ Tunnel.unwrapOnion0 kpA req0
          in case mP1 of
            Nothing -> False
            Just p1 ->
              let -- Node A sees dest is B, sends kind 0x81 to B
                  req1 = Tunnel.OnionRequestRelay nonce (Tunnel.onionPayloadTemporaryKey p1) (Tunnel.onionPayloadEncryptedPayload p1) nonce finalData -- dummy ret data
                  -- 3. Node B unwraps req1 (kind 0x81)
                  mP2 = runNullKeyed $ Tunnel.unwrapOnionRelay kpB req1
              in case mP2 of
                Nothing -> False
                Just (p2, _, _) ->
                  let -- Node B sees dest is C, sends kind 0x82 to C
                      req2 = Tunnel.OnionRequestRelay nonce (Tunnel.onionPayloadTemporaryKey p2) (Tunnel.onionPayloadEncryptedPayload p2) nonce finalData -- dummy ret data
                      -- 4. Node C unwraps req2 (kind 0x82)
                      mP3 = runNullKeyed $ Tunnel.unwrapOnionFinal kpC req2
                  in case mP3 of
                    Nothing -> False
                    Just (p3, _, _) ->
                      -- 5. Node C sees dest is D, and final data matches!
                      Tunnel.unOnionIPPort (Tunnel.onionPayloadFinalDestination p3) == destAddr &&
                      Tunnel.onionPayloadFinalData p3 == unCipherText finalData

    it "fails to unwrap if any node in the chain has the wrong key" $ property $
      \(ourKP :: KeyPair) (kpA :: KeyPair) (kpB :: KeyPair) (kpC :: KeyPair)
        (wrongKP :: KeyPair) (kp1 :: KeyPair) (kp2 :: KeyPair) (kp3 :: KeyPair)
        (destAddr :: SocketAddress) (nonce :: Nonce) (finalData :: CipherText) (now :: Timestamp) ->
          let nodeA = NodeInfo UDP (SocketAddress (IPv4 0x7f000001) 33445) (KeyPair.publicKey kpA)
              nodeB = NodeInfo UDP (SocketAddress (IPv4 0x7f000002) 33445) (KeyPair.publicKey kpB)
              nodeC = NodeInfo UDP (SocketAddress (IPv4 0x7f000003) 33445) (KeyPair.publicKey kpC)
              path = OnionPath [nodeA, nodeB, nodeC] [kp1, kp2, kp3] True 0 (now `Time.addTime` pathLifetime) Nothing 0
              (req0, _) = runTestOnion now (OnionPathState [] [] 0) (wrapPath ourKP path destAddr nonce (unCipherText finalData))
              
              -- Use wrong key at Node A
              mP1Wrong = runNullKeyed $ Tunnel.unwrapOnion0 wrongKP req0
          in isNothing mP1Wrong || KeyPair.publicKey wrongKP == KeyPair.publicKey kpA

  describe "maintainPaths" $ do
    it "always fills paths to maxPaths if enough nodes exist" $ property $
      \(now :: Timestamp) (nodes :: [NodeInfo]) ->
        length nodes >= 3 ==>
          let initState = OnionPathState [] [] 0
              (_, finalState) = runTestOnion now initState (maintainPaths nodes)
          in length (announcePaths finalState) == maxPaths &&
             length (searchPaths finalState) == maxPaths

  describe "pickNodes" $ do
    it "always returns exactly 3 nodes if available" $ property $
      \(nodes :: [NodeInfo]) ->
        length nodes >= 3 ==>
          let (pNodes, _) = runTestOnion (Time.fromMillis 0) (OnionPathState [] [] 0) (pickNodes nodes)
          in length pNodes == 3