{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.Core.ProtocolSpec (spec) where

import           Test.Hspec
import           Tox.Network.Core.Protocol ()

spec :: Spec
spec = describe "Tox.Network.Core.Protocol" $
  it "compiles" $
    True `shouldBe` True
