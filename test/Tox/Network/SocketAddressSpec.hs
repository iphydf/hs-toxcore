{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.Network.SocketAddressSpec where

import           Test.Hspec

import           Data.Proxy                (Proxy (..))
import           Tox.Network.EncodingSpec
import qualified Tox.Network.SocketAddress as SocketAddress
import           Tox.Network.SocketAddress (SocketAddress)


spec :: Spec
spec = do
  rpcSpec (Proxy :: Proxy SocketAddress)
  binarySpec (Proxy :: Proxy SocketAddress)
  readShowSpec (Proxy :: Proxy SocketAddress)

  binaryGetPutSpec "{get,put}SocketAddress"
    SocketAddress.getSocketAddress
    (uncurry SocketAddress.putSocketAddress)
