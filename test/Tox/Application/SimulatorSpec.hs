{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Tox.Application.SimulatorSpec (spec) where

import           Control.Exception                  (evaluate)
import           Control.Monad                      (void, (<=<))
import           Data.Function                      ((&))
import           Data.List                          (foldl')
import           Data.List.NonEmpty                 (nonEmpty)
import qualified Data.List.NonEmpty                 as NonEmpty
import qualified Data.Map                           as Map
import           Data.Maybe                         (mapMaybe)
import           Test.Hspec

import           Tox.Application.Node
import           Tox.Application.State              (conferences, connManager,
                                                     gets, groupChats)
import qualified Tox.Chat.Conference                as Conference
import qualified Tox.Chat.GroupChat                 as Group
import qualified Tox.Core.Time                      as Time
import           Tox.Evaluated                      (fullyEvaluated)
import           Tox.Network.Core.HostAddress       (HostAddress (..),
                                                     tupleToHostAddress)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import qualified Tox.Network.Core.Traffic           as Traffic
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp
import qualified Tox.Session.Connection             as Connection
import qualified Tox.Session.Friend                 as Messenger
import           Tox.Simulator
import qualified Tox.Transport.SecureSession        as SecureSession

-- | In the range for examples, so nothing takes it for a LAN.
at :: Int -> SocketAddress
at n = SocketAddress (IPv4 $ tupleToHostAddress (198, 51, 100, fromIntegral n)) 33445

udp, tcpOnly :: Setup
udp = Setup True False False
tcpOnly = Setup False False False

-- | Nodes that know each other, the first two friends.
introduced :: [SocketAddress] -> Sim -> Sim
introduced addrs sim = foldl' (&) sim $
  [ command a (bootstrapNode (dhtNode UDP b sim)) | a <- addrs, b <- addrs, a /= b ] ++
  [ command a (Messenger.addFriend (realKey b sim)) | (a, b) <- [(at 1, at 2), (at 2, at 1)] ]

-- | How the first sees the second, oldest first.
seen :: Sim -> [ConnectionStatus]
seen sim = [ status | (_, FriendConnectionChanged pk status) <- eventsOf (at 1) sim, pk == realKey (at 2) sim ]

link :: Link
link = Link (Time.milliseconds 20) 0 0

-- | Two friends online, among four nodes. More than the two other nodes it
-- takes for onion paths.
online :: Sim
online = runFor (Time.seconds 60) . introduced addrs $ foldr (addNode udp) (newSim 1 link) addrs
  where addrs = map at [1 .. 4]

-- | In a range no one takes for a LAN.
publicHost :: Int -> HostAddress
publicHost n = IPv4 $ tupleToHostAddress (198, 18, 0, fromIntegral n)

-- | Two friends, each behind a NAT of the kind, among four nodes without, one
-- of which is the friends' relay.
behindNats :: (HostAddress -> Nat) -> Sim
behindNats nat = runFor (Time.seconds 120) . introduced (friends ++ others) $ foldl' (&) nodes relays
  where
    friends = map at [1, 2]
    others = map at [3 .. 6]
    nodes = foldr (\(n, a) -> setNat a (nat (publicHost n))) relayed (zip [1 ..] friends)
    relayed = addRelay udp (at 3) . foldr (addNode udp) (newSim 1 link) $ friends ++ drop 1 others
    relays = [ command a (Tcp.addRelay (dhtNode TCP (at 3) nodes)) | a <- friends ]

spec :: Spec
spec = describe "Simulator" $ do
  it "connects two friends over the DHT" $
    take 1 (seen online) `shouldBe` [ConnectedUdp]

  -- A path from a relay takes two nodes with UDP after it. Long enough for
  -- the relay's pings and ours.
  it "connects two friends without UDP through a relay, and stays" $ do
    let friends = map at [1, 2]
        others = map at [3 .. 8]
        nodes = addRelay udp (at 3) . foldr (addNode udp) (foldr (addNode tcpOnly) (newSim 1 link) friends) $ drop 1 others
        relays = [ command a (Tcp.addRelay (dhtNode TCP (at 3) nodes)) | a <- friends ]
        sim = runFor (Time.seconds 120) . introduced (friends ++ others) $ foldl' (&) nodes relays
    seen sim `shouldBe` [ConnectedTcp]

  -- Its onion paths start at its relay, so it needn't wait for the next
  -- upkeep 2 s later.
  it "connects a friend without UDP within a second of joining" $ do
    let others = map at [3 .. 8]
        boot addrs sim = foldl' (&) sim [ command a (bootstrapNode (dhtNode UDP b sim)) | a <- addrs, b <- others, a /= b ]
        relay a sim = command a (Tcp.addRelay (dhtNode TCP (at 3) sim)) sim
        warm = runFor (Time.seconds 60) . relay (at 2) . boot (at 2 : others) . addRelay udp (at 3)
          . foldr (addNode udp) (addNode tcpOnly (at 2) (newSim 1 link)) $ drop 1 others
        joined = relay (at 1) . boot [at 1] $ addNode tcpOnly (at 1) warm
        befriended = foldl' (&) joined [ command a (Messenger.addFriend (realKey b joined)) | (a, b) <- [(at 1, at 2), (at 2, at 1)] ]
        connected = [ t | (t, FriendConnectionChanged _ ConnectedTcp) <- eventsOf (at 1) (runFor (Time.seconds 5) befriended) ]
    map ((< Time.seconds 1) . (`Time.diffTime` simTime warm)) (take 1 connected) `shouldBe` [True]

  it "tells the client when a friend moves from a relay to UDP" $ do
    let friends = map at [1, 2]
        others = map at [3 .. 6]
        nodes = setUdpCut (at 1) (at 2) True . addRelay udp (at 3) . foldr (addNode udp) (newSim 1 link) $ friends ++ drop 1 others
        relays = [ command a (Tcp.addRelay (dhtNode TCP (at 3) nodes)) | a <- friends ]
        relayed = runFor (Time.seconds 60) . introduced (friends ++ others) $ foldl' (&) nodes relays
        sim = runFor (Time.seconds 120) (setUdpCut (at 1) (at 2) False relayed)
    seen sim `shouldBe` [ConnectedTcp, ConnectedUdp]

  it "comes back once after an outage" $ do
    let outage = setDown (at 1) False . runFor (Time.seconds 300) $ setDown (at 1) True online
    seen (runFor (Time.seconds 60) outage) `shouldBe` [ConnectedUdp, NotConnected, ConnectedUdp]

  it "holds a conference with a friend, and freezes it when it goes" $ do
    let invited = runFor (Time.seconds 2) $ command (at 1)
          (Conference.newConference >>= mapM_ (void . Conference.invite (realKey (at 2) online))) online
        cookies = [ cookie | (_, ConferenceInvite _ _ cookie) <- eventsOf (at 2) invited ]
        joined = runFor (Time.seconds 30) $ foldl' (&) invited
          [ command (at 2) (void $ Conference.join (realKey (at 1) invited) cookie) | cookie <- take 1 cookies ]
        gone = runFor (Time.seconds 70) (setDown (at 2) True joined)
        peers = peekAt (at 1) (gets (maybe 0 (Map.size . Conference.cfPeers) . Map.lookup 0 . Conference.conferences . conferences))
    (length cookies, peers joined, peers gone) `shouldBe` (1, 2, 1)

  it "holds a group, and lets a peer go 58 s after it last heard from it" $ do
    let invited = runFor (Time.seconds 2) $ command (at 1)
          (Group.createGroup True "group" "one" >>= mapM_ (\g -> void $ Group.inviteFriend g (realKey (at 2) online))) online
        invites = [ invite | (_, GroupInvite _ invite _) <- eventsOf (at 2) invited ]
        joined = runFor (Time.seconds 20) $ foldl' (&) invited
          [ command (at 2) (void $ Group.acceptInvite (realKey (at 1) invited) invite "two" "") | invite <- take 1 invites ]
        heard = peekAt (at 1) (gets (maybe [] (map Group.peerLastRecv . Map.elems . Group.grPeers) . Map.lookup 0 . Group.groups . groupChats)) joined
        gone = runFor (Time.seconds 70) (setDown (at 2) True joined)
        exits = [ t | (t, GroupPeerExit 0 _ Group.ExitTimeout _ _) <- drop (length (eventsOf (at 1) joined)) (eventsOf (at 1) gone) ]
    (length invites, exits) `shouldBe` (1, map (`Time.addTime` Group.confirmedTimeout) heard)

  -- At the start, then only for DHT and onion maintenance every 2 s.
  it "sleeps while it has nothing to do" $ do
    let alone = runFor (Time.seconds 60) $ addNode udp (at 1) (newSim 1 link)
    wakeUps (at 1) alone `shouldBe` 1 + 60 `div` 2

  -- DHT and onion maintenance every 2 s, the session's keepalive as often,
  -- and a few more for pings and their answers.
  it "sleeps while a friend is online but quiet" $
    wakeUps (at 1) (runFor (Time.seconds 60) online) - wakeUps (at 1) online `shouldSatisfy` (< 120)

  -- toxcore moves us off UDP when it hears nothing from us there for 8 s,
  -- counted in whole seconds.
  it "keeps a quiet friend hearing from it over UDP, with room for two losses" $ do
    let session = Connection.fcSession <=< Map.lookup (realKey (at 1) online) . Connection.friends . connManager
        heard = peekAt (at 2) (gets (SecureSession.ssLastUdpRecv <=< session))
        times = map NonEmpty.head . NonEmpty.group . mapMaybe heard . take 600 $ iterate (runFor (Time.milliseconds 100)) online
        gaps = zipWith (flip Time.diffTime) times (drop 1 times)
    (* 3) . maximum <$> nonEmpty gaps `shouldSatisfy` maybe False (< Time.seconds 7)

  -- A packet coming in brings the next request within a quarter of a second.
  it "hears at once that a friend has its message" $ do
    let message sim = runFor spacing $ command (at 1) (void $ Messenger.sendMessage (realKey (at 2) online) Messenger.MessageNormal "hi") sim
        spacing = Time.milliseconds 770
        sent = iterate message online !! 20
        receipts = [ t | (t, FriendReadReceipt _ _) <- drop (length (eventsOf (at 1) online)) (eventsOf (at 1) sent) ]
        delays = zipWith (\i t -> Time.diffTime t (Time.addTime (simTime online) (fromIntegral i * spacing))) [0 :: Int ..] receipts
    (length receipts, maximum <$> nonEmpty delays) `shouldSatisfy` \(n, d) ->
      n == 20 && maybe False (<= Time.milliseconds 250 + 2 * linkDelay link) d

  -- It still wakes for keepalives, requests naming what it sent, and DHT
  -- maintenance.
  it "sleeps while a receipt can't come" $ do
    let gone = setDown (at 2) True online
        sent = command (at 1) (void $ Messenger.sendMessage (realKey (at 2) online) Messenger.MessageNormal "hi") gone
    wakeUps (at 1) (runFor (Time.seconds 20) sent) - wakeUps (at 1) gone `shouldSatisfy` (< 60)

  it "tells an online friend its relay as soon as it has one" $ do
    let addrs = map at [1 .. 4]
        nodes = addRelay udp (at 3) . foldr (addNode udp) (newSim 1 link) $ filter (/= at 3) addrs
        friends = runFor (Time.seconds 60) (introduced addrs nodes)
        relay = dhtNode TCP (at 3) friends
        relayed = runFor (Time.seconds 5) $ command (at 1) (Tcp.addRelay relay) friends
        told = peekAt (at 2) (gets (maybe [] (map publicKey . Connection.fcRelays) . Map.lookup (realKey (at 1) friends) . Connection.friends . connManager))
    (take 1 (seen friends), publicKey relay `elem` told relayed) `shouldBe` ([ConnectedUdp], True)

  -- Each friend added makes its work due at once, between inputs.
  it "adds many friends at once" $ do
    let added = foldl' (&) (addNode udp (at 1) (newSim 1 link)) [ command (at 1) (Messenger.addFriend pk) | pk <- keys ]
        keys = [ realKey (at n) many | n <- [2 .. 201] ]
        many = foldr (addNode udp . at) (newSim 2 link) [2 .. 201]
    wakeUps (at 1) (runFor (Time.seconds 1) added) `shouldSatisfy` (> 0)

  -- Or each count keeps the packet it counted alive.
  it "keeps its counts evaluated" $ do
    counts <- evaluate (trafficOf (at 1) online)
    fullyEvaluated counts `shouldReturn` True

  it "counts what each node sends and gets, as its core and its shell do" $ do
    let bytes addr what = sum [ Traffic.countBytes c | (w, c) <- Map.toList (trafficOf addr online), what w ]
        overUdp way = \case Traffic.Packets w Traffic.Udp _ -> w == way; _ -> False
        announcing = (== Traffic.Requests Traffic.AnnounceUs)
    [ all (\what -> bytes a what > 0) [overUdp Traffic.Sent, overUdp Traffic.Received, announcing] | a <- map at [1 .. 4] ]
      `shouldBe` replicate 4 True

  it "connects two friends behind NATs that keep their port, punching holes" $
    take 1 (reverse (seen (behindNats (\host -> Nat host SamePort FromAddressesSentTo (Time.seconds 60))))) `shouldBe` [ConnectedUdp]

  it "connects two friends behind symmetric NATs through a relay" $
    seen (behindNats (\host -> Nat host PortPerDestination FromAddressesSentTo (Time.seconds 60))) `shouldBe` [ConnectedTcp]

  -- Without it, a friend only notices after 32 s.
  it "tells a friend it's going" $ do
    let gone = setDown (at 2) True . runFor (Time.milliseconds 100) $ command (at 2) goodbye online
    seen (runFor (Time.seconds 10) gone) `shouldBe` [ConnectedUdp, NotConnected]
