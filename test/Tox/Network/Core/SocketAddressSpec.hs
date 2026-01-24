{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.Core.SocketAddressSpec where

import           Test.Hspec

import           Data.Proxy                (Proxy (..))
import           Tox.Network.Core.EncodingSpec
import qualified Tox.Network.Core.SocketAddress as SocketAddress
import           Tox.Network.Core.SocketAddress (SocketAddress)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy SocketAddress)
  binarySpec (Proxy :: Proxy SocketAddress)
  readShowSpec (Proxy :: Proxy SocketAddress)

  binaryGetPutSpec "{get,put}SocketAddress"
    SocketAddress.getSocketAddress
    (uncurry SocketAddress.putSocketAddress)
