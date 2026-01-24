module Tox.Chat.ConferenceSpec (spec) where

import           Control.Monad.State     (modify)
import qualified Data.Map                as Map
import           Test.Hspec

import           Tox.Application.AppTest (runApp)
import           Tox.Application.State   (App, GlobalState (..), gets)
import qualified Tox.Chat.Conference     as Conference
import qualified Tox.Core.Time           as Time
import           Tox.Core.Time           (Timestamp)
import           Tox.Core.Timed          (Timed (..))
import qualified Tox.Crypto.Core.KeyPair as KeyPair

at :: Timestamp -> App ()
at t = modify $ \gs -> gs { stepTime = t }

-- | When it's due, after what was due at that time ran.
ranAt :: Timestamp -> App (Maybe Timestamp)
ranAt t = at t >> Conference.runDue >> gets (Conference.nextDue . conferences)

spec :: Spec
spec = describe "Conference" $
  it "is due when a quiet peer must freeze, between its pings" $ do
    friend <- KeyPair.publicKey <$> KeyPair.newKeyPair
    friendDht <- KeyPair.publicKey <$> KeyPair.newKeyPair
    (dues, left) <- runApp $ do
      start <- askTime
      let past = Time.addTime start . Time.seconds
      mg <- Conference.newConference
      -- Last heard of 5 s in.
      flip mapM_ mg $ \g -> do
        _ <- Conference.addPeer g friend friendDht 1 True
        Conference.modifyConference g $ \c -> c { Conference.cfPeers = Map.map (\p ->
          if Conference.peerRealPk p == friend then p { Conference.peerLastActive = past 5 } else p) (Conference.cfPeers c) }
      dues <- mapM (ranAt . past) [0, 20, 40, 60]
      _ <- ranAt (past 65)
      left <- gets (map (Map.size . Conference.cfPeers) . Map.elems . Conference.conferences . conferences)
      return (map (fmap (Time.toMilliseconds . (`Time.diffTime` start))) dues, left)
    (dues, left) `shouldBe` ([Just 20000, Just 40000, Just 60000, Just 65000], [1])
