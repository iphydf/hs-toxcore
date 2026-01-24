-- | Monad stack for pure tests of networked code: keys, a fixed clock,
-- seeded randomness, no logging, a state, and the packets sent.
module Tox.Network.Core.TestStack
    ( TestStack
    , runTestStack
    ) where

import           Control.Monad.Random       (RandT, evalRandT)
import           Control.Monad.State        (StateT, runStateT)
import           Data.Functor.Identity      (Identity (..))
import           System.Random              (StdGen, mkStdGen)

import           Tox.Core.Log               (NoLog, runNoLog)
import           Tox.Core.Time              (Timestamp)
import           Tox.Crypto.Core.Keyed      (KeyedT, emptyKeyRing, evalKeyedT)
import           Tox.Network.Core.Networked (NetworkAction, NetworkLogged,
                                             runNetworkLogged)
import           Tox.Network.Core.TimedT    (TimedT, runTimedT)

type TestStack s = KeyedT (TimedT (RandT StdGen (NoLog (StateT s (NetworkLogged Identity)))))

runTestStack :: Int -> Timestamp -> s -> TestStack s a -> (a, s, [NetworkAction])
runTestStack seed now s m =
  let ((a, s'), actions) = runIdentity . runNetworkLogged . (`runStateT` s) . runNoLog
        . (`evalRandT` mkStdGen seed) . (`runTimedT` now) $ evalKeyedT m emptyKeyRing
  in (a, s', actions)
