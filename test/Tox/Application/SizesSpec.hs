{-# LANGUAGE OverloadedStrings #-}
module Tox.Application.SizesSpec (spec) where

import           Control.Monad                    (replicateM_)
import           Control.Monad.State              (gets)
import           Data.Maybe                       (fromJust)
import           Test.Hspec

import           Tox.Application.AppTest          (runApp)
import           Tox.Application.Sizes
import           Tox.Chat.GroupChat               (addPeer, createGroup)
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes (newKeyPair)
import           Tox.Network.Core.HostAddress     (HostAddress (..),
                                                   tupleToHostAddress)
import           Tox.Network.Core.SocketAddress   (SocketAddress (..))

spec :: Spec
spec =
  describe "State sizes" $ do
    it "are all within their limits at the start" $ do
      over <- runApp $ gets (filter overLimit . stateSizes)
      over `shouldBe` []

    it "show a group with more peers than it may have" $ do
      let addr = SocketAddress (IPv4 $ tupleToHostAddress (127, 0, 0, 1)) 33445
      over <- runApp $ do
        g <- fromJust <$> createGroup False "group" "nick"
        replicateM_ 300 $ newKeyPair >>= \kp -> addPeer g (KeyPair.publicKey kp) (Just addr) Nothing
        gets (map sizeName . filter overLimit . stateSizes)
      over `shouldBe` ["Group 0 peers"]
