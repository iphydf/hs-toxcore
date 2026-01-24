{-# LANGUAGE StrictData #-}
module Tox.Crypto.Core.KeyedSpec where

import           Control.Monad               (replicateM)
import           Data.Functor.Identity       (runIdentity)
import           Test.Hspec

import qualified Tox.Crypto.Core.CombinedKey as CombinedKey
import           Tox.Crypto.Core.Keyed
import qualified Tox.Crypto.Core.KeyPair     as KeyPair
import           Tox.Crypto.Core.KeyPair     (KeyPair (..))


spec :: Spec
spec = describe "KeyedT" $ do
  it "gives the same keys as precompute" $ do
    KeyPair sk _ <- KeyPair.newKeyPair
    pks <- map KeyPair.publicKey <$> replicateM 3 KeyPair.newKeyPair
    let got = runIdentity $ evalKeyedT (mapM (getCombinedKey sk) (pks ++ pks)) emptyKeyRing
    got `shouldBe` map (CombinedKey.precompute sk) (pks ++ pks)

  it "keeps at most 2 generations of keys" $ do
    KeyPair sk _ <- KeyPair.newKeyPair
    pks <- map KeyPair.publicKey <$> replicateM (3 * keyRingGeneration) KeyPair.newKeyPair
    let (_, ring) = runIdentity $ runKeyedT (mapM_ (getCombinedKey sk) pks) emptyKeyRing
    keyRingSize ring `shouldSatisfy` (<= 2 * keyRingGeneration)
