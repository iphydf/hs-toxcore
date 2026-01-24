{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.Core.PortNumberSpec where

import           Test.Hspec

import           Data.Proxy                    (Proxy (..))
import           Tox.Network.Core.EncodingSpec
import           Tox.Network.Core.PortNumber   (PortNumber)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy PortNumber)
  binarySpec (Proxy :: Proxy PortNumber)
  readShowSpec (Proxy :: Proxy PortNumber)
