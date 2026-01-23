{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.ConferencesSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.Conferences (Conferences)

spec :: Spec
spec = do
  describe "Conferences" $
    binarySpec (Proxy :: Proxy Conferences)
