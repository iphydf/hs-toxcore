{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.ProtocolSpec (spec) where

import           Test.Hspec
import           Tox.Network.Protocol ()

spec :: Spec
spec = describe "Tox.Network.Protocol" $
  it "compiles" $
    True `shouldBe` True
