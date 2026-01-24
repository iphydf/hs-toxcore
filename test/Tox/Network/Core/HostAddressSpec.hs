{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.Core.HostAddressSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.Network.Core.EncodingSpec
import           Tox.Network.Core.HostAddress  (HostAddress)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy HostAddress)
  binarySpec (Proxy :: Proxy HostAddress)
  readShowSpec (Proxy :: Proxy HostAddress)
