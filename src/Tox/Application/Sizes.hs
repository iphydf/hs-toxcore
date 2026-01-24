{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | How big the state that others can grow is, next to how big it may get.
module Tox.Application.Sizes
  ( Size (..)
  , stateSizes
  , overLimit
  ) where

import qualified Data.Map                    as Map
import           Data.Text                   (Text)
import qualified Data.Text                   as Text

import           Tox.Application.State       (GlobalState (..))
import qualified Tox.Chat.Conference         as Conference
import qualified Tox.Chat.GroupChat          as Group
import qualified Tox.Core.PingArray          as PingArray
import           Tox.Crypto.Core.Keyed       (keyRingGeneration, keyRingSize)
import qualified Tox.DHT.DhtState            as DhtState
import qualified Tox.DHT.KBuckets            as KBuckets
import qualified Tox.DHT.Operation           as DHT
import qualified Tox.DHT.PendingReplies      as PendingReplies
import qualified Tox.Network.TCP.Connections as Tcp
import qualified Tox.Network.TCP.Server      as Server
import qualified Tox.Onion.Operation         as Onion
import qualified Tox.Session.Connection      as Connection
import qualified Tox.Session.Friend          as Messenger
import qualified Tox.Transport.SecureSession as SecureSession

-- | The limit is 'Nothing' when only we make it grow, like by adding friends.
data Size = Size
  { sizeName  :: Text
  , sizeCount :: Int
  , sizeLimit :: Maybe Int
  } deriving (Eq, Show)

overLimit :: Size -> Bool
overLimit s = maybe False (sizeCount s >) (sizeLimit s)

stateSizes :: GlobalState -> [Size]
stateSizes gs =
  [ Size "Shared keys" (keyRingSize $ keyRing gs) (Just $ 2 * keyRingGeneration)
  , Size "DHT close nodes" (length . KBuckets.getAllNodes $ DhtState.dhtCloseList dht)
      (Just $ 256 * KBuckets.defaultBucketSize)
  , Size "DHT searches" (Map.size $ DhtState.dhtSearchList dht) Nothing
  , Size "DHT replies we wait for" (PendingReplies.size $ DhtState.dhtPendingReplies dht) Nothing
  , Size "DHT nodes to ping" (length $ DhtState.dhtToPing dht) (Just DHT.maxToPing)
  , Size "Onion announcements we store" (Map.size $ Onion.announceEntries onion) (Just Onion.maxAnnounceEntries)
  , Size "Onion requests we wait for" (Map.size . PingArray.paEntries $ Onion.sendbacks onion)
      (Just . PingArray.paSize $ Onion.sendbacks onion)
  , Size "Onion path nodes" (length $ Onion.pathNodes onion) (Just Onion.maxPathNodes)
  , Size "Onion bootstrap nodes" (length $ Onion.bootstrapNodes onion) (Just Onion.maxPathNodes)
  , Size "Onion friend searches" (Map.size $ Onion.onionFriends onion) Nothing
  , Size "Groups announced to us" (Map.size $ Onion.storedGroups onion) (Just Onion.maxStoredGroups)
  , Size "TCP relays" (Map.size $ Tcp.tsRelays tcp) Nothing
  , Size "TCP peers" (Map.size $ Tcp.tsPeers tcp) Nothing
  , Size "Our relay's clients" (Map.size . Server.tsClients $ tcpServer gs) Nothing
  , Size "Friend connections" (Map.size . Connection.friends $ connManager gs) Nothing
  , Size "Packets held for the busiest friend" (Connection.busiestHeld $ connManager gs)
      (Just SecureSession.maxPacketsHeld)
  , Size "Friend requests seen" (length . Messenger.receivedRequests $ messenger gs)
      (Just Messenger.maxReceivedRequests)
  ]
  ++ concat [ conferenceSizes n c | (n, c) <- Map.toList . Conference.conferences $ conferences gs ]
  ++ concat [ groupSizes n g | (n, g) <- Map.toList . Group.groups $ groupChats gs ]
  where
    dht = dhtState gs
    onion = onionState gs
    tcp = tcpState gs

conferenceSizes :: Conference.ConferenceNumber -> Conference.Conference -> [Size]
conferenceSizes n c =
  [ Size (name "peers") (Map.size $ Conference.cfPeers c) (Just 65536)
  , Size (name "frozen peers") (Map.size $ Conference.cfFrozen c) (Just Conference.maxFrozen)
  , Size (name "connections") (Map.size $ Conference.cfConns c) (Just Conference.maxConnections)
  ]
  where name what = "Conference " <> Text.pack (show n) <> " " <> what

groupSizes :: Group.GroupNumber -> Group.Group -> [Size]
groupSizes n g =
  -- Confirmed ones, ones a sync told us about, and a burst of handshakes.
  [ Size (name "peers") (length peers) (Just $ 2 * Group.peerLimit g + Group.maxNewHandshakes)
  , Size (name "saved peers") (length $ Group.grSavedPeers g) (Just Group.maxSavedPeers)
  , Size (name "packets held for the busiest peer") (maximum (0 : map held peers)) (Just $ 2 * Group.bufferSize)
  ]
  where
    name what = "Group " <> Text.pack (show n) <> " " <> what
    peers = Map.elems (Group.grPeers g)
    held p = Map.size (Group.peerSendArray p) + Map.size (Group.peerRecvArray p)
