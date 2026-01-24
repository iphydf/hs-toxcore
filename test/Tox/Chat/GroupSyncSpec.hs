{-# LANGUAGE OverloadedStrings #-}
module Tox.Chat.GroupSyncSpec (spec) where

import           Control.Monad                    (replicateM)
import qualified Data.Map                         as Map
import           Data.Maybe                       (fromJust)
import           Test.Hspec

import           Tox.Application.AppTest          (runApp)
import           Tox.Chat.GroupChat
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes (newKeyPair)
import           Tox.Network.Core.HostAddress     (HostAddress (..),
                                                   tupleToHostAddress)
import           Tox.Network.Core.SocketAddress   (SocketAddress (..))
import           Tox.Onion.GroupAnnounce          (Announce (..), packAnnounce)

spec :: Spec
spec =
  describe "Group sync" $
    it "only meets the peers in sync responses we asked for, up to the peer limit" $ do
      let addr = SocketAddress (IPv4 $ tupleToHostAddress (127, 0, 0, 1)) 33445
          strangers n = map KeyPair.publicKey <$> replicateM n newKeyPair
          offer g pk stranger = handleSyncResponse g pk (packAnnounce $ Announce stranger (Just addr) Nothing)
          met g = maybe 0 (Map.size . grPeers) <$> getGroup g
      counts <- runApp $ do
        g <- fromJust <$> createGroup False "group" "nick"
        pk <- KeyPair.publicKey <$> newKeyPair
        _ <- addPeer g pk (Just addr) Nothing
        strangers 1 >>= mapM_ (offer g pk)
        metUnasked <- met g
        _ <- sendSyncRequest g pk 0
        limit <- maybe 0 peerLimit <$> getGroup g
        strangers (limit + 1) >>= mapM_ (offer g pk)
        metAsked <- met g
        return (metUnasked, metAsked - metUnasked, limit)
      let (metUnasked, added, limit) = counts
      (metUnasked, added) `shouldBe` (1, limit)
