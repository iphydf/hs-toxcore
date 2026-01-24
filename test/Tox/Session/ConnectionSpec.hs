module Tox.Session.ConnectionSpec (spec) where

import           Control.Monad                      (replicateM, void, (<=<))
import qualified Data.Map                           as Map
import           Data.Maybe                         (isJust)
import qualified Data.Set                           as Set
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Application.AppTest            (runApp)
import qualified Tox.Core.Schedule                  as Schedule
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Timed                     (askTime)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import qualified Tox.DHT.DhtState                   as DhtState
import qualified Tox.DHT.Operation                  as DHT
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Onion.Operation                as Onion
import qualified Tox.Session.Connection             as Connection
import           Tox.Transport.SecureSession        (SessionEvent (..))

spec :: Spec
spec = describe "Connection" $ do
  it "has the onion search for a friend as soon as it's added" $ do
    pk <- KeyPair.publicKey <$> KeyPair.newKeyPair
    searched <- runApp $ do
      Connection.addFriend pk
      Onion.getsOnion (Map.member pk . Onion.onionFriends)
    searched `shouldBe` True

  it "tells the onion when a friend connects and when it goes" $ do
    pk <- KeyPair.publicKey <$> KeyPair.newKeyPair
    let online = Onion.getsOnion (fmap Onion.ofOnline . Map.lookup pk . Onion.onionFriends)
    seen <- runApp $ do
      Connection.addFriend pk
      Onion.startFriendSearch pk
      _ <- Connection.sessionEvent pk SessionEstablished
      up <- online
      _ <- Connection.dropSession Connection.TimedOut pk
      down <- online
      return (up, down)
    seen `shouldBe` (Just True, Just False)

  -- A key from a handshake on a relay too, or we never find its address.
  it "has the DHT search for a friend's current DHT key, however it came" $
    property $ \pk dhtPk newDhtPk -> dhtPk /= newDhtPk ==> ioProperty $ do
      let searched k = DhtState.containsSearchKey k <$> DHT.getDht
      runApp $ do
        Connection.addFriend pk
        void $ Connection.setFriendDhtPk pk dhtPk
        first <- searched dhtPk
        void $ Connection.setFriendDhtPk pk newDhtPk
        replaced <- (,) <$> searched dhtPk <*> searched newDhtPk
        return $ (first, replaced) === (True, (False, True))

  it "finds a session from any way its packets come, and only while it has one" $
    property $ \pk dhtPk session direct relay other -> session /= other && direct /= other ==> ioProperty $ do
      let found from = do
            cm <- Connection.getConnManager
            let rebuilt = Map.fromListWith Set.union
                  [ (route, Set.singleton k) | (k, f) <- Map.toList (Connection.friends cm), route <- Connection.routesOf f ]
            return (isJust (Connection.sessionFrom from cm), Connection.routes cm == rebuilt)
      runApp $ do
        Connection.addFriend pk
        void $ Connection.setFriendDhtPk pk dhtPk
        void $ Connection.connectThrough pk dhtPk (NodeInfo UDP session dhtPk)
        Connection.setFriendIpPort pk (NodeInfo UDP direct dhtPk)
        connected <- mapM found [NodeInfo UDP session dhtPk, NodeInfo UDP direct dhtPk, NodeInfo TCP relay dhtPk]
        stranger <- found (NodeInfo UDP other dhtPk)
        void $ Connection.dropSession Connection.TimedOut pk
        dropped <- found (NodeInfo UDP session dhtPk)
        return $ (connected, stranger, dropped) === (replicate 3 (True, True), (False, True), (False, True))

  it "costs nothing without a session until there's news of the friend, then connects" $
    property $ \pk dhtPk at -> ioProperty $ do
      let jobs = Connection.getsConn (Schedule.size . Connection.connJobs)
          hasSession = Connection.getsConn (isJust . (Connection.fcSession <=< Map.lookup pk . Connection.friends))
      runApp $ do
        Connection.addFriend pk
        added <- jobs
        void $ Connection.setFriendDhtPk pk dhtPk
        void Connection.runDue
        nowhere <- (,) <$> jobs <*> hasSession
        Connection.dhtNodeFound (NodeInfo UDP at dhtPk)
        void Connection.runDue
        found <- hasSession
        return $ (added, nowhere, found) === (0, (0, False), True)

  it "tries a failed session again a few times, then waits for news" $
    property $ \pk dhtPk at -> ioProperty $ do
      let connectDue = Connection.getsConn (Schedule.dueBy (Connection.Connect pk) . Connection.connJobs)
          failOnce = do
            void $ Connection.connect pk
            void $ Connection.dropSession Connection.TimedOut pk
            connectDue
      runApp $ do
        now <- askTime
        Connection.addFriend pk
        void $ Connection.setFriendDhtPk pk dhtPk
        Connection.setFriendIpPort pk (NodeInfo UDP at dhtPk)
        retries <- replicateM 5 failOnce
        void $ Connection.handleOnionEvent (Onion.FriendDhtPkFound pk dhtPk [])
        back <- connectDue
        let later s = Just (Time.addTime now (Time.seconds s))
        return $ (retries, back) === (map later [8, 16, 32, 64] ++ [Nothing], Just now)

  it "dials friends whose sessions timed out, once our connection is back" $
    property $ \pk other dhtPk otherDht at -> pk /= other ==> ioProperty $ do
      let connectDue k = Connection.getsConn (Schedule.dueBy (Connection.Connect k) . Connection.connJobs)
          -- Online, then gone for long enough that it gave up connecting again.
          gone why k = do
            void $ Connection.connect k
            void $ Connection.sessionEvent k SessionEstablished
            Connection.modifyFriend k $ \f -> f { Connection.fcConnectWait = Nothing }
            void $ Connection.dropSession why k
      runApp $ do
        now <- askTime
        mapM_ Connection.addFriend [pk, other]
        void $ Connection.setFriendDhtPk pk dhtPk
        void $ Connection.setFriendDhtPk other otherDht
        Connection.setFriendIpPort pk (NodeInfo UDP at dhtPk)
        Connection.setFriendIpPort other (NodeInfo UDP at otherDht)
        gone Connection.TimedOut pk
        -- The other friend said it was going.
        gone Connection.PeerKilled other
        away <- connectDue pk
        Connection.weAreBack
        back <- (,) <$> connectDue pk <*> connectDue other
        return $ (away, back) === (Nothing, (Just now, Nothing))
