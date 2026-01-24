{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | Groups between 2 instances on this machine, through the whole stack.
module Tox.Chat.GroupChatSpec (spec) where

import           Control.Concurrent                 (threadDelay)
import           Control.Exception                  (bracket)
import qualified Data.ByteString                    as BS
import           Data.IORef                         (IORef, atomicModifyIORef',
                                                     newIORef)
import           Data.Word                          (Word32)
import           System.Timeout                     (timeout)
import           Test.Hspec

import qualified Tox.Application.Tox                as Tox
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

-- | Instance, and its events nobody waited for yet.
data Peer = Peer
  { peerTox    :: Tox.Tox
  , peerEvents :: IORef [Tox.Event]
  }

-- | 2 friends in a private group the first founded, with their group numbers
-- and each one's peer number for the other.
data Pair = Pair
  { founder      :: Peer
  , joiner       :: Peer
  , founderGroup :: Word32
  , joinerGroup  :: Word32
  , joinerThere  :: Tox.PeerId -- ^ The joiner, as the founder numbers it.
  , founderThere :: Tox.PeerId -- ^ The founder, as the joiner numbers it.
  }

-- | First event that gives something, waiting if needed. Keeps the others
-- for later.
await :: Peer -> (Tox.Event -> Maybe a) -> IO a
await p f = timeout 30000000 go >>= maybe (expectationFailure "no such event in 30 s" >> fail "timed out") pure
  where
    go = atomicModifyIORef' (peerEvents p) (pick []) >>= \case
      Just a -> pure a
      Nothing -> Tox.nextEvent (peerTox p) >>= \e -> case f e of
        Just a  -> pure a
        Nothing -> atomicModifyIORef' (peerEvents p) (\es -> (es ++ [e], ())) >> go
    pick seen = \case
      [] -> (reverse seen, Nothing)
      e : rest -> case f e of
        Just a  -> (reverse seen ++ rest, Just a)
        Nothing -> pick (e : seen) rest

retrying :: IO Bool -> IO ()
retrying act = timeout 30000000 go >>= maybe (expectationFailure "never worked in 30 s") pure
  where go = act >>= \ok -> if ok then pure () else threadDelay 200000 >> go

newPeer :: IO Peer
newPeer = do
  tox <- Tox.new Tox.defaultOptions { Tox.optLocalDiscovery = False } >>= either (fail . show) pure
  Peer tox <$> newIORef []

nodeOf :: Peer -> NodeInfo
nodeOf p = NodeInfo UDP
  (SocketAddress (IPv4 (tupleToHostAddress (127, 0, 0, 1))) (PortNumber (Tox.selfUdpPort (peerTox p))))
  (Tox.selfDhtId (peerTox p))

-- | Extra instances for the network the 2 find each other on (onion paths
-- need nodes of their own).
helpers :: Int
helpers = 4

withPair :: (Pair -> IO a) -> IO a
withPair act = bracket (mapM (const newPeer) [1 .. helpers]) (mapM_ (Tox.kill . peerTox)) $ \network ->
  bracket (start network) (\pair -> Tox.kill (peerTox (founder pair)) >> Tox.kill (peerTox (joiner pair))) act
  where
    start network = do
      a <- newPeer
      b <- newPeer
      let ta = peerTox a
          tb = peerTox b
          everyone = a : b : network
      sequence_ [Tox.bootstrap (peerTox p) (nodeOf q) | p <- everyone, q <- everyone, Tox.selfPublicKey (peerTox p) /= Tox.selfPublicKey (peerTox q)]
      Tox.friendAddNoRequest ta (Tox.selfPublicKey tb) >>= either (fail . show) pure
      Tox.friendAddNoRequest tb (Tox.selfPublicKey ta) >>= either (fail . show) pure
      g <- Tox.groupNew ta True "Lab" "Founder" >>= maybe (fail "no group") pure
      retrying (Tox.groupInviteFriend ta g (Tox.selfPublicKey tb))
      (from, invite) <- await b $ \case
        Tox.GroupInvite pk invite _ -> Just (pk, invite)
        _                           -> Nothing
      gj <- Tox.groupInviteAccept tb from invite "Joiner" "" >>= either (fail . show) pure
      n <- await a $ \case
        Tox.GroupPeerJoin g' n _ | g' == g -> Just n
        _                                  -> Nothing
      m <- await b $ \case
        Tox.GroupPeerJoin g' m _ | g' == gj -> Just m
        _                                   -> Nothing
      pure (Pair a b g gj n m)

spec :: Spec
spec =
  -- 1 group for everything, as each needs its own network to start.
  it "carries messages, fragmented and private ones, a status, a topic and a kick between two instances" $
    withPair $ \pair -> do
      let long = BS.replicate 1372 0x61
          f = peerTox (founder pair)
          j = peerTox (joiner pair)
      _ <- Tox.groupSendMessage f (founderGroup pair) Tox.MessageNormal "hello"
      _ <- Tox.groupSendMessage f (founderGroup pair) Tox.MessageNormal long
      said <- mapM (\_ -> await (joiner pair) $ \case
        Tox.GroupMessage g _ _ text _ | g == joinerGroup pair -> Just text
        _                                                    -> Nothing) [1 :: Int, 2]
      said `shouldBe` ["hello", long]

      _ <- Tox.groupSendPrivateMessage j (joinerGroup pair) (founderThere pair) Tox.MessageNormal "psst"
      await (founder pair) (\case
        Tox.GroupPrivateMessage g n _ text _ | g == founderGroup pair -> Just (n, text)
        _                                                           -> Nothing)
        `shouldReturn` (joinerThere pair, "psst")

      Tox.groupSetStatus j (joinerGroup pair) Tox.Away `shouldReturn` True
      await (founder pair) (\case
        Tox.GroupPeerStatus g n status | g == founderGroup pair -> Just (n, status)
        _                                                      -> Nothing)
        `shouldReturn` (joinerThere pair, 1)

      Tox.groupSetTopic f (founderGroup pair) "plans" `shouldReturn` True
      await (joiner pair) (\case
        Tox.GroupTopic g _ topic | g == joinerGroup pair, topic == "plans" -> Just topic
        _                                                                  -> Nothing)
        `shouldReturn` "plans"

      Tox.groupKickPeer f (founderGroup pair) (joinerThere pair) `shouldReturn` Right ()
      await (joiner pair) (\case
        Tox.GroupModeration g _ Nothing Tox.ModKick | g == joinerGroup pair -> Just ()
        _                                                                   -> Nothing)
        `shouldReturn` ()
