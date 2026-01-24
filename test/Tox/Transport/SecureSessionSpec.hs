{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE UndecidableInstances       #-}

module Tox.Transport.SecureSessionSpec where

import           Control.Monad.Random
import           Control.Monad.State
import           Data.Binary                         (decode, encode)
import qualified Data.ByteString                     as BS
import qualified Data.ByteString.Char8               as BS8
import qualified Data.ByteString.Lazy                as LBS
import           Data.Functor.Identity               (Identity (..))
import qualified Data.Map                            as Map
import qualified System.Clock                        as Clock
import           System.Random                       (StdGen, mkStdGen)
import           Test.Hspec

import qualified Tox.Core.Time                       as Time
import           Tox.Core.Time                       (Timestamp (..), getTime)
import           Tox.Core.Timed                      (Timed (..))
import qualified Tox.Crypto.Core.Box                 as Box
import qualified Tox.Crypto.Core.CombinedKey         as CombinedKey
import           Tox.Crypto.Core.Key                 (CombinedKey, PublicKey,
                                                      unKey)
import           Tox.Crypto.Core.Keyed               (KeyedT, evalKeyedT)
import qualified Tox.Crypto.Core.KeyPair             as KeyPair
import           Tox.Crypto.Core.KeyPair             (KeyPair (..))
import           Tox.Crypto.Core.MonadRandomBytes    (MonadRandomBytes (..),
                                                      randomNonce)
import qualified Tox.Crypto.Core.Nonce               as Nonce
import           Tox.Network.Core.HostAddress
import           Tox.Network.Core.Networked          (NetworkAction (..),
                                                      NetworkLogged,
                                                      Networked (..),
                                                      runNetworkLogged)
import qualified Tox.Network.Core.NodeInfo           as NodeInfo
import           Tox.Network.Core.NodeInfo           (NodeInfo (..))
import           Tox.Network.Core.Packet             (Packet (..))
import qualified Tox.Network.Core.PacketKind         as PacketKind
import           Tox.Network.Core.SocketAddress
import           Tox.Network.Core.TimedT             (TimedT, runTimedT)
import           Tox.Network.Core.TransportProtocol
import           Tox.Transport.SecureSession
import           Tox.Transport.SecureSession.Manager

-- | A monad for running a full simulation with a SessionManager.
type ManagerM = KeyedT (TimedT (RandT StdGen (StateT SessionManager (NetworkLogged Identity))))

runManagerM :: StdGen -> Timestamp -> SessionManager -> ManagerM a -> (a, SessionManager, [NetworkAction])
runManagerM gen time sm m =
  let ( (a, sm'), actions ) = runIdentity . runNetworkLogged . (`runStateT` sm) . (`evalRandT` gen) . (`runTimedT` time) . (`evalKeyedT` Map.empty) $ m
  in (a, sm', actions)

spec :: Spec
spec = do
  describe "SecureSession Handshake Simulation" $ do
    it "performs a stateless Cookie exchange" $ do
      ourRealKp <- KeyPair.newKeyPair
      ourDhtKp <- KeyPair.newKeyPair
      clientDhtKp <- KeyPair.newKeyPair
      let clientDhtPk = KeyPair.publicKey clientDhtKp
          serverDhtPk = KeyPair.publicKey ourDhtKp
          cookieK = CombinedKey.precompute (KeyPair.secretKey ourRealKp) (KeyPair.publicKey ourRealKp)
          sm = SessionManager Map.empty cookieK ourDhtKp
          peerNode = NodeInfo UDP (SocketAddress (IPv4 0) 33445) clientDhtPk

      -- Mock a CookieRequest from peer
      let crN = runIdentity . evalRandT randomNonce $ mkStdGen 1
          cri = CookieRequestInner clientDhtPk (BS.replicate 32 0) 12345
          plain = LBS.toStrict $ encode cri
          sharedK = CombinedKey.precompute (KeyPair.secretKey clientDhtKp) serverDhtPk
          encrypted = Box.encrypt sharedK crN (Box.PlainText plain)
          cr = CookieRequest clientDhtPk crN encrypted
          pkt = Packet PacketKind.CookieRequest (LBS.toStrict $ encode cr)

      -- Handle the packet via Manager
      let ((), _, actions) = runManagerM (mkStdGen 2) (Timestamp $ Clock.TimeSpec 10 0) sm (dispatchPacket peerNode pkt)

      case actions of
        [SendPacket _ (Packet kind _)] -> kind `shouldBe` PacketKind.CookieResponse
        _ -> expectationFailure $ "Expected exactly one CookieResponse packet, but got: " ++ show actions

    it "rejects an expired Cookie" $ do
      ourRealKp <- KeyPair.newKeyPair
      ourDhtKp <- KeyPair.newKeyPair
      clientDhtKp <- KeyPair.newKeyPair
      let clientDhtPk = KeyPair.publicKey clientDhtKp
          cookieK = CombinedKey.precompute (KeyPair.secretKey ourRealKp) (KeyPair.publicKey ourRealKp)
          peerNode = NodeInfo UDP (SocketAddress (IPv4 0) 33445) clientDhtPk

      -- 1. Create a cookie with time T=0
      let cookie = runIdentity . evalRandT (createCookie cookieK 0 clientDhtPk clientDhtPk) $ mkStdGen 1

      -- 2. Mock a Handshake using that cookie, but it's now T=20s
      let hN = runIdentity . evalRandT randomNonce $ mkStdGen 2
          realSharedK = CombinedKey.precompute (KeyPair.secretKey clientDhtKp) (KeyPair.publicKey ourRealKp)
          hi = HandshakeInner (Nonce.integerToNonce 0) clientDhtPk (BS.replicate 64 0) cookie
          encrypted = Box.encrypt realSharedK hN (Box.PlainText $ LBS.toStrict $ encode hi)
          h = Handshake cookie hN encrypted
          pkt = Packet PacketKind.CryptoHandshake (LBS.toStrict $ encode h)

      -- 3. Run session via Manager at T=20s
      let ss = runIdentity . evalRandT (initSession ourRealKp clientDhtPk ourDhtKp clientDhtPk peerNode) $ mkStdGen 3
      let sm = SessionManager (Map.fromList [(clientDhtPk, ss)]) cookieK ourDhtKp
          ((), _, actions) = runManagerM (mkStdGen 4) (Timestamp $ Clock.TimeSpec 20 0) sm (dispatchPacket peerNode pkt)

      actions `shouldBe` []

    it "updates peer address on mobility (Address Roaming)" $ do
      ourRealKp <- KeyPair.newKeyPair
      ourDhtKp <- KeyPair.newKeyPair
      clientDhtKp <- KeyPair.newKeyPair
      let clientDhtPk = KeyPair.publicKey clientDhtKp
          cookieK = CombinedKey.precompute (KeyPair.secretKey ourRealKp) (KeyPair.publicKey ourRealKp)
          oldPeerNode = NodeInfo UDP (SocketAddress (IPv4 0x01010101) 33445) clientDhtPk
          newPeerNode = NodeInfo UDP (SocketAddress (IPv4 0x02020202) 33445) clientDhtPk

      -- 1. Create a cookie at T=0
      let cookie = runIdentity . evalRandT (createCookie cookieK 0 clientDhtPk clientDhtPk) $ mkStdGen 1

      -- 2. Mock a Handshake from NEW address at T=1s
      let hN = runIdentity . evalRandT randomNonce $ mkStdGen 2
          realSharedK = CombinedKey.precompute (KeyPair.secretKey clientDhtKp) (KeyPair.publicKey ourRealKp)
          hi = HandshakeInner (Nonce.integerToNonce 0) clientDhtPk (BS.replicate 64 0) cookie
          encrypted = Box.encrypt realSharedK hN (Box.PlainText $ LBS.toStrict $ encode hi)
          h = Handshake cookie hN encrypted
          pkt = Packet PacketKind.CryptoHandshake (LBS.toStrict $ encode h)

      -- 3. Run session via Manager
      let ss = runIdentity . evalRandT (initSession ourRealKp clientDhtPk ourDhtKp clientDhtPk oldPeerNode) $ mkStdGen 3
      let sm = SessionManager (Map.fromList [(clientDhtPk, ss)]) cookieK ourDhtKp
          ((), sm', _) = runManagerM (mkStdGen 4) (Timestamp $ Clock.TimeSpec 1 0) sm (dispatchPacket newPeerNode pkt)

      -- 4. Verify address updated
      case Map.lookup clientDhtPk (sessionsByPk sm') of
        Just ss' -> ssPeerNodeInfo ss' `shouldBe` newPeerNode
        Nothing  -> expectationFailure "Session lost"

    it "handles out-of-order data packets and updates base nonce" $ do
      ourRealKp <- KeyPair.newKeyPair
      ourDhtKp <- KeyPair.newKeyPair
      clientDhtKp <- KeyPair.newKeyPair
      let clientDhtPk = KeyPair.publicKey clientDhtKp
          cookieK = CombinedKey.precompute (KeyPair.secretKey ourRealKp) (KeyPair.publicKey ourRealKp)
          peerNode = NodeInfo UDP (SocketAddress (IPv4 0) 33445) clientDhtPk

      -- 1. Setup established session with shared key
      let sessionSharedK = CombinedKey.precompute (KeyPair.secretKey ourRealKp) clientDhtPk -- dummy for test
          peerBaseNonce = Nonce.integerToNonce 0
      let ss = runIdentity . evalRandT (initSession ourRealKp clientDhtPk ourDhtKp clientDhtPk peerNode) $ mkStdGen 1
      let ssEst = ss { ssSharedKey = Just sessionSharedK, ssPeerBaseNonce = Just peerBaseNonce, ssStatus = Just SessionConfirmed }
          sm = SessionManager (Map.fromList [(clientDhtPk, ssEst)]) cookieK ourDhtKp

      -- 2. Receive packet with offset +10 (Out-of-order)
      let nonce10 = Nonce.integerToNonce 10
          shortNonce10 = 10
          encrypted10 = Box.encrypt sessionSharedK nonce10 (Box.PlainText "hello")
          cd10 = CryptoDataPacket shortNonce10 encrypted10
          pkt10 = Packet PacketKind.CryptoData (LBS.toStrict $ encode cd10)

      let ((), sm', _) = runManagerM (mkStdGen 2) (Timestamp $ Clock.TimeSpec 1 0) sm (dispatchPacket peerNode pkt10)

      -- 3. Verify session confirmed and received count
      case Map.lookup clientDhtPk (sessionsByPk sm') of
        Just ss' -> ssRecvPackets ss' `shouldBe` 1
        Nothing  -> expectationFailure "Session lost"
