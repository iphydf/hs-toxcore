{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.PortNumberSpec where

import           Test.Hspec

import           Data.Proxy               (Proxy (..))
import           Tox.Network.EncodingSpec
import           Tox.Network.PortNumber   (PortNumber)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy PortNumber)
  binarySpec (Proxy :: Proxy PortNumber)
  readShowSpec (Proxy :: Proxy PortNumber)
