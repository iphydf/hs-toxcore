{-# LANGUAGE ScopedTypeVariables #-}
-- | Garbage from peers mustn't stop us. The main loop has no handler for
-- what a packet throws, so one bad packet (or a thunk it leaves in our
-- state) would end the whole instance.
module Tox.Application.FuzzSpec (spec) where

import           Control.Exception              (ErrorCall, try)
import           Control.Monad                  (forM_, void)
import qualified Data.Binary                    as Binary
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Lazy           as LBS
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Application.AppTest        (runApp)
import qualified Tox.Application.Node           as Node
import           Tox.Application.State          hiding (runApp)
import qualified Tox.Chat.Conference            as Conference
import qualified Tox.Chat.GroupChat             as Group
import qualified Tox.Chat.GroupChatPackets      as GroupPackets
import           Tox.Crypto.Core.Box            (PlainText (..))
import           Tox.Crypto.Core.Key            (PublicKey)
import qualified Tox.Crypto.Core.KeyPair        as KeyPair
import qualified Tox.DHT.DhtPacket              as DhtPacket
import qualified Tox.DHT.DhtState               as DhtState
import qualified Tox.DHT.Node                   as DHTNode
import qualified Tox.DHT.Operation              as DHT
import           Tox.Evaluated                  (forceAll)
import           Tox.Network.Core.HostAddress   (HostAddress (..),
                                                 tupleToHostAddress)
import           Tox.Network.Core.Packet        (Packet (..), RawPayload (..))
import qualified Tox.Network.Core.PacketKind    as PacketKind
import           Tox.Network.Core.PortNumber    (PortNumber (..))
import           Tox.Network.Core.SocketAddress (SocketAddress (..))
import qualified Tox.Onion.Operation            as Onion
import qualified Tox.Session.Connection         as Connection
import qualified Tox.Session.Friend             as Messenger

-- | Bytes of any length up to a little over a UDP packet's.
newtype Garbage = Garbage BS.ByteString
  deriving Show

instance Arbitrary Garbage where
  arbitrary = Garbage . BS.pack <$> (choose (0, 1500) >>= vector)

-- | A friend's packet, with one of the IDs something handles or any.
newtype FriendPacket = FriendPacket BS.ByteString
  deriving Show

instance Arbitrary FriendPacket where
  arbitrary = do
    ident <- oneof [elements handled, arbitrary]
    -- Conference packets name the conference next, which is 0 here.
    let conference = if ident `elem` Conference.packetIds then [0, 0] else []
    Garbage rest <- arbitrary
    small <- BS.pack <$> (choose (0, 40) >>= vector)
    FriendPacket . BS.cons ident . (BS.pack conference <>) <$> elements [rest, small]
    where
      handled = Messenger.packetIds ++ Conference.packetIds ++ [GroupPackets.packetIdGroupInvite]

from :: SocketAddress
from = SocketAddress (IPv4 (tupleToHostAddress (127, 0, 0, 1))) (PortNumber 1)

-- | Then everything we hold is forced, so a thunk that throws does it here.
survives :: App () -> Property
survives act = ioProperty $ runApp (act >> gets id) >>= forceAll

-- | What a tick does with the state, apart from sockets.
periodic :: App ()
periodic = do
  DHT.sendQueued
  DHTNode.handleMaintenance
  Onion.doOnion
  Onion.runDue
  void Messenger.runDue
  void $ Connection.runDue >>= Node.connectionEvents
  void Conference.runDue
  void Group.runDue

-- | An online friend, in a conference with us.
befriend :: PublicKey -> PublicKey -> App ()
befriend friend friendDht = do
  Messenger.addFriend friend
  void $ Node.connectionEvents [Connection.FriendData friend (BS.singleton Messenger.packetIdOnline)]
  mg <- Conference.newConference
  forM_ mg $ \g -> do
    void $ Conference.addPeer g friend friendDht 1 True
    Conference.addConn g friend friendDht Conference.Introducer
    Conference.setOnline g friend 0

spec :: Spec
spec = describe "garbage from peers" $ do
  it "reaches the handlers, so the rest test something" $ property $ \friend friendDht -> ioProperty $ do
    events <- runApp $ do
      befriend friend friendDht
      Node.connectionEvents
        [ Connection.FriendData friend (BS.pack [Messenger.packetIdMessage, 104, 105])
        -- Peer 1's first chat message in conference 0.
        , Connection.FriendData friend (BS.pack [Conference.packetIdMessage, 0, 0, 0, 1, 0, 0, 0, 1, Conference.messageChat, 104, 105]) ]
    held <- try (forceAll (Just (error "thunk" :: Int)))
    return $ (length events, either (\(_ :: ErrorCall) -> True) (const False) held) === (2, True)

  it "doesn't stop us, in any UDP packet" $ withMaxSuccess 500 $
    \(kind :: PacketKind.PacketKind) (Garbage bytes) -> survives $ do
      void $ Node.handleDatagram True from (Packet kind (RawPayload bytes))
      periodic

  it "doesn't stop us, in any packet sealed to our DHT key" $ withMaxSuccess 500 $
    \(kind :: PacketKind.PacketKind) sender nonce (Garbage plain) -> survives $ do
      ours <- gets (KeyPair.publicKey . DhtState.dhtKeyPair . dhtState)
      let sealed = LBS.toStrict . Binary.encode $ DhtPacket.encrypt sender ours nonce (PlainText plain)
          -- DHT requests name who they're for first.
          bytes = if kind == PacketKind.Crypto then Conference.keyBytes ours <> sealed else sealed
      void $ Node.handleDatagram True from (Packet kind (RawPayload bytes))
      periodic

  it "doesn't stop us, from a friend" $ withMaxSuccess 200 $
    \friend friendDht (packets :: [FriendPacket]) (lossy :: [Garbage]) -> survives $ do
      befriend friend friendDht
      forM_ packets $ \(FriendPacket bytes) ->
        void $ Node.connectionEvents [Connection.FriendData friend bytes]
      forM_ lossy $ \(Garbage bytes) ->
        void $ Node.connectionEvents [Connection.FriendLossyData friend bytes]
      periodic

  it "doesn't stop us, in a friend request" $ withMaxSuccess 500 $
    \sender (Garbage bytes) -> survives . void $ Node.connectionEvents [Connection.FriendRequest sender bytes]
