{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StrictData                 #-}
module Tox.Network.TCP.ServerSpec (spec) where

import           Control.Monad                      (void)
import           Control.Monad.Identity             (Identity, runIdentity)
import           Control.Monad.Random               (RandT, evalRandT)
import           Control.Monad.State                (MonadState, StateT, get,
                                                     gets, modify, put,
                                                     runStateT)
import qualified Data.ByteString                    as BS
import           Data.List                          (partition)
import qualified Data.Map                           as Map
import           System.Random                      (StdGen, mkStdGen)
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Core.Log                       (MonadLog (..))
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (Timestamp)
import           Tox.Core.Timed                     (Timed)
import           Tox.Crypto.Core.Key                (Nonce)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.KeyPair            (KeyPair)
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TimedT            (TimedT, runTimedT)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import           Tox.Network.TCP.Client
import           Tox.Network.TCP.Server

data World = World
  { wServer :: TcpServer
  , wSent   :: [(ClientId, BS.ByteString)]
  , wBusy   :: [ClientId]
  }

newtype TestServer a = TestServer (TimedT (StateT World (RandT StdGen Identity)) a)
  deriving (Functor, Applicative, Monad, Timed, MonadRandomBytes, MonadState World)

instance MonadLog TestServer where
  logAt _ _ = return ()

instance TcpServerMonad TestServer where
  getTcpServer = gets wServer
  putTcpServer s = modify $ \w -> w { wServer = s }
  serverSend client bytes = modify $ \w -> w { wSent = wSent w ++ [(client, bytes)] }
  serverClose _ = return ()
  serverBusy client = gets ((client `elem`) . wBusy)

runTestServer :: Timestamp -> TcpServer -> TestServer a -> a
runTestServer now server (TestServer m) =
  fst . runIdentity . (`evalRandT` mkStdGen 42) . (`runStateT` World server [] []) $ runTimedT m now

receive :: ClientId -> RelayConnection -> TestServer (RelayConnection, [RelayEvent])
receive client rc = do
  w <- get
  let (mine, others) = partition ((== client) . fst) (wSent w)
  put w { wSent = others }
  return $ case receiveBytes (BS.concat $ map snd mine) rc of
    Right (rc', events, _) -> (rc', events)
    Left ()                -> (rc, [])

send :: ClientId -> BS.ByteString -> RelayConnection -> TestServer RelayConnection
send client packet rc = case encodePacket packet rc of
  Just (frame, rc') -> rc' <$ clientBytes client frame
  Nothing           -> return rc

-- | Keys, temporary keys and nonces for one client.
type ClientInput = (KeyPair, KeyPair, Nonce, Nonce)

-- | Clients 0 and 1 routed to each other, and what each was told.
connectPair :: KeyPair -> ClientInput -> ClientInput
            -> TestServer ((RelayConnection, [RelayEvent]), (RelayConnection, [RelayEvent]))
connectPair serverKeys (a, tempA, n1, n2) (b, tempB, n3, n4) = do
  let relay = NodeInfo TCP (SocketAddress (read "\"127.0.0.1\"") 33445) (KeyPair.publicKey serverKeys)
      (rcA0, helloA) = newRelayConnection a tempA n1 n2 relay
      (rcB0, helloB) = newRelayConnection b tempB n3 n4 relay
  clientAccepted 0
  clientAccepted 1
  _ <- clientBytes 0 helloA
  _ <- clientBytes 1 helloB
  (rcA1, _) <- receive 0 rcA0
  (rcB1, _) <- receive 1 rcB0
  rcA2 <- send 0 (routingRequest $ KeyPair.publicKey b) rcA1
  rcB2 <- send 1 (routingRequest $ KeyPair.publicKey a) rcB1
  (,) <$> receive 0 rcA2 <*> receive 1 rcB2

spec :: Spec
spec = describe "TCP server" $ do
  it "connects clients that ask for each other and tells one when the other leaves" $ property $
    \(serverKeys :: KeyPair) (inA@(a, _, _, _) :: ClientInput) (inB@(b, _, _, _) :: ClientInput) (now :: Timestamp) ->
      let pkA = KeyPair.publicKey a
          pkB = KeyPair.publicKey b
      in runTestServer now (newTcpServer serverKeys) (do
        ((rcA3, eventsA), (rcB3, eventsB)) <- connectPair serverKeys inA inB
        rcA4 <- maybe (return rcA3) (\packet -> send 0 packet rcA3) (routeData pkB "hi" rcA3)
        (rcB4, dataB) <- receive 1 rcB3
        let routeIds = [ i | (i, (pk, _)) <- Map.toList (rcRoutes rcA4), pk == pkB ]
        _ <- send 0 (BS.pack $ packetDisconnectNotification : routeIds) rcA4
        (_, leftB) <- receive 1 rcB4
        stillA <- Map.member 0 . tsClients <$> getTcpServer
        return (eventsA, eventsB, dataB, leftB, stillA))
      `shouldBe`
        ( [RelayRouteChanged pkB (Just RouteRegistered), RelayRouteChanged pkB (Just RouteOnline)]
        , [RelayRouteChanged pkA (Just RouteRegistered), RelayRouteChanged pkA (Just RouteOnline)]
        , [RelayData pkA "hi"]
        , [RelayRouteChanged pkA (Just RouteRegistered)]
        , True
        )

  it "pings clients when they're due, and drops those that don't answer in time" $ property $
    \(serverKeys :: KeyPair) (inA :: ClientInput) (inB :: ClientInput) (now :: Timestamp) ->
      let past = Time.addTime now
          run t server act = runTestServer t server ((,) <$> act <*> getTcpServer)
          (first, connected) = run now (newTcpServer serverKeys) (connectPair serverKeys inA inB >> gets (nextDue . wServer))
          ((pinged, waits), asked) = run (past pingInterval) connected $
            runDue >> (,) <$> gets (map fst . wSent) <*> gets (nextDue . wServer)
          (left, _) = run (past (pingInterval + pingTimeout)) asked $
            runDue >> (,) <$> gets (Map.size . tsClients . wServer) <*> gets (nextDue . wServer)
      in (first, pinged, waits, left)
           `shouldBe` (Just (past pingInterval), [0, 1], Just (past (pingInterval + pingTimeout)), (0, Nothing))

  it "drops data for a client that hasn't taken what we sent, but still answers it" $ property $
    \(serverKeys :: KeyPair) (inA :: ClientInput) (inB@(b, _, _, _) :: ClientInput) (now :: Timestamp) ->
      runTestServer now (newTcpServer serverKeys) (do
        ((rcA, _), (rcB, _)) <- connectPair serverKeys inA inB
        modify $ \w -> w { wBusy = [1] }
        _ <- maybe (return rcA) (\packet -> send 0 packet rcA) (routeData (KeyPair.publicKey b) "hi" rcA)
        toB <- gets (lookup 1 . wSent)
        _ <- send 1 (pingPacket packetPing 1) rcB
        pong <- gets (lookup 1 . wSent)
        return (toB, void pong))
      `shouldBe` (Nothing, Just ())
