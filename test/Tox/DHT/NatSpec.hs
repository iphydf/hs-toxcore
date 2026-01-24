{-# LANGUAGE ScopedTypeVariables #-}
module Tox.DHT.NatSpec (spec) where

import           Control.Monad.Identity             (runIdentity)
import           Control.Monad.Random               (evalRandT)
import           Control.Monad.State                (runStateT)
import           Data.List                          (foldl', nub)
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Core.Log                       (runNoLog)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (Timestamp)
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.Keyed              as KeyedT
import qualified Tox.DHT.DhtState                   as DhtState
import           Tox.DHT.DhtState                   (DhtState)
import qualified Tox.DHT.Nat                        as Nat
import qualified Tox.DHT.Operation                  as Operation
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import qualified Tox.Network.Core.Networked         as Networked
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.TimedT            as TimedT
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

-- | In the range for examples, so nothing takes it for a LAN.
at :: Int -> SocketAddress
at n = SocketAddress (IPv4 $ tupleToHostAddress (198, 51, 100, fromIntegral n)) 33445

-- | A searched node that the nodes of its Client List say is at one place.
reported :: Timestamp -> PublicKey -> [PublicKey] -> DhtState -> DhtState
reported time friend keys st0 = foldl' (\st n -> DhtState.recordReturned time n target st) added nodes
  where
    nodes = zipWith (\i pk -> NodeInfo UDP (at i) pk) [1 ..] keys
    target = NodeInfo UDP (at 100) friend
    added = foldl' (flip (DhtState.addNode time)) (DhtState.addSearchKey time friend st0) nodes

-- | The NAT pings it sends.
punch :: Operation.ArbStdGen -> Timestamp -> DhtState -> (Int, DhtState)
punch seed time st =
  let ((_, st'), sent) = runIdentity
        . Networked.runNetworkLogged
        . (`runStateT` st)
        . runNoLog
        . (`evalRandT` Operation.unwrapArbStdGen seed)
        . (`TimedT.runTimedT` time)
        . (`KeyedT.evalKeyedT` KeyedT.emptyKeyRing)
        $ Nat.runDue
  in (length [ () | Networked.SendPacket _ (Packet PacketKind.Crypto _) <- sent ], st')

spec :: Spec
spec = describe "Hole punching" $ do
  it "pings a node that others report, once they do and then every 3 s" $ property $
    \(seed :: Operation.ArbStdGen) (time :: Timestamp) (friend :: PublicKey) ->
      forAll (nub <$> vectorOf 4 arbitrary) $ \keys -> length keys == 4 && friend `notElem` keys ==>
        let st = reported time friend keys (Operation.initTestDhtState seed time)
            (pings, st') = punch seed time st
        in (Nat.nextDue st, pings > 0, Nat.nextDue st')
             `shouldBe` (Just time, True, Just (Time.addTime time (Time.seconds 3)))

  it "doesn't ping a node it reaches itself, until that runs out" $ property $
    \(seed :: Operation.ArbStdGen) (time :: Timestamp) (friend :: PublicKey) ->
      forAll (nub <$> vectorOf 4 arbitrary) $ \keys -> length keys == 4 && friend `notElem` keys ==>
        let st = DhtState.addNode time (NodeInfo UDP (at 100) friend)
               $ reported time friend keys (Operation.initTestDhtState seed time)
            (pings, st') = punch seed time st
        in (pings, Nat.nextDue st') `shouldBe` (0, Just (Time.addTime time (Time.seconds 122)))
