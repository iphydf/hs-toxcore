{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.BytesSpec (spec) where

import           Test.Hspec
import           Data.Proxy               (Proxy (..))
import           Tox.Network.Core.EncodingSpec (binarySpec)
import           Tox.Persistence.Bytes    (Bytes)

spec :: Spec
spec = do
  describe "Bytes" $
    binarySpec (Proxy :: Proxy Bytes)
