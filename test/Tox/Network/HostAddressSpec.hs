{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.HostAddressSpec where

import           Test.Hspec

import           Data.Proxy               (Proxy (..))
import           Tox.Network.EncodingSpec
import           Tox.Network.HostAddress  (HostAddress)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy HostAddress)
  binarySpec (Proxy :: Proxy HostAddress)
  readShowSpec (Proxy :: Proxy HostAddress)
