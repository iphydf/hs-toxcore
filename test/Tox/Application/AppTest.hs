-- | Runs the application monad on a fresh state, for tests.
module Tox.Application.AppTest (runApp) where

import qualified Tox.Application.State   as State
import           Tox.Application.State   (App, initState)
import           Tox.Core.Time           (getTime)
import qualified Tox.Crypto.Core.KeyPair as KeyPair

runApp :: App a -> IO a
runApp app = do
  dht <- KeyPair.newKeyPair
  real <- KeyPair.newKeyPair
  now <- getTime
  fst . State.runApp app <$> initState now dht real
