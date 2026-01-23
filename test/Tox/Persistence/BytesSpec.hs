{-# LANGUAGE OverloadedStrings #-}
module Tox.Persistence.BytesSpec (spec) where

import           Data.Proxy               (Proxy (..))
import           Test.Hspec
import           Tox.Network.EncodingSpec (binarySpec)
import           Tox.Persistence.Bytes    (Bytes)

spec :: Spec
spec = do
  describe "Bytes" $
    binarySpec (Proxy :: Proxy Bytes)
