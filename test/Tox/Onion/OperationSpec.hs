{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE StrictData                 #-}
module Tox.Onion.OperationSpec (spec) where

import           Test.Hspec

import           Control.Arrow                      ((&&&))
import           Control.Monad                      (replicateM)
import           Control.Monad.State                (MonadState, gets, modify)
import           Data.Binary                        (encode)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import qualified Data.Map                           as Map
import           Data.Word                          (Word64)

import           Tox.Core.Log                       (MonadLog)
import qualified Tox.Core.Schedule                  as Schedule
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Timed                     (Timed)
import qualified Tox.Crypto.Core.Box                as Box
import qualified Tox.Crypto.Core.CombinedKey        as CombinedKey
import           Tox.Crypto.Core.Key                (PublicKey)
import           Tox.Crypto.Core.Keyed              (Keyed)
import qualified Tox.Crypto.Core.KeyPair            as KeyPair
import           Tox.Crypto.Core.KeyPair            (KeyPair)
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes)
import qualified Tox.Crypto.Core.Nonce              as Nonce
import           Tox.DHT.DhtPacket                  (DhtPacket (..))
import           Tox.DHT.DhtRequestPacket           (DhtRequestPacket (..))
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.Networked         (NetworkAction (..),
                                                     Networked)
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TestStack         (TestStack, runTestStack)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import           Tox.Onion.Operation
import qualified Tox.Onion.Path                     as Path
import qualified Tox.Onion.RPC                      as RPC
import qualified Tox.Onion.Tunnel                   as Tunnel

data TestNode = TestNode
  { tnOnion   :: OnionState
  , tnDhtKeys :: KeyPair
  }

newtype TestOnionNodeMonad a = TestOnionNodeMonad
  { unTestOnionNodeMonad :: TestStack TestNode a
  } deriving (Functor, Applicative, Monad, MonadState TestNode, Timed, MonadRandomBytes, Keyed, Networked, MonadLog)

instance OnionNodeMonad TestOnionNodeMonad where
  getOnionState = gets tnOnion
  putOnionState s = modify $ \t -> t { tnOnion = s }
  getDhtKeyPair = gets tnDhtKeys
  getCloseNodes _ _ = return []
  getCloseNodesFor _ _ _ = return []

runNode :: TestNode -> TestOnionNodeMonad a -> (a, TestNode, [(SocketAddress, BS.ByteString)])
runNode = runNodeAt 1000

runNodeAt :: Integer -> TestNode -> TestOnionNodeMonad a -> (a, TestNode, [(SocketAddress, BS.ByteString)])
runNodeAt seconds node m =
  let (a, node', actions) = runTestStack 42 (Time.fromSeconds seconds) node (unTestOnionNodeMonad m)
  in (a, node', [ (address to, LBS.toStrict $ encode pkt) | SendPacket to pkt <- actions ])

newNode :: IO TestNode
newNode = do
  real <- KeyPair.newKeyPair
  dht <- KeyPair.newKeyPair
  onion <- initState real
  return $ TestNode onion dht

-- | Announced, as friends' searches wait for it.
-- | An announce node answers us, so searches work, and has stored us for
-- long enough to count as online.
connected :: TestNode -> TestNode
connected node = node { tnOnion = onion { onionConnected = connectedRuns, selfNodes = Map.singleton key storing } }
  where
    onion = tnOnion node
    key = KeyPair.publicKey (ourRealKeys onion)
    storing = (newOnionNode (NodeInfo UDP lastRelay key)) { onStatus = StoresUs, onAnswered = True }

lastRelay :: SocketAddress
lastRelay = SocketAddress (IPv4 0x0100007f) 33445

-- | As a client would.
announceTo :: TestNode -> KeyPair -> PublicKey -> PublicKey -> PublicKey -> BS.ByteString
           -> IO (RPC.AnnounceResponsePayload, TestNode)
announceTo node sender pingId searchKey dataPk ret = do
  nonce <- Nonce.newNonce
  let shared = CombinedKey.precompute (KeyPair.secretKey sender) (KeyPair.publicKey $ tnDhtKeys node)
      payload = RPC.AnnounceRequestPayload pingId searchKey dataPk 7
      request = RPC.AnnounceRequest nonce (KeyPair.publicKey sender) (Box.encrypt shared nonce (Box.encode payload))
      ((), node', sent) = runNode node $ handleAnnounceRequest lastRelay (LBS.toStrict (encode request) <> ret)
  case sent of
    [(to, bytes)] | to == lastRelay, Just (0x8c, rest) <- BS.uncons bytes
                  , BS.take (Tunnel.returnSize 3) rest == ret
                  , Just (0x84, responseBytes) <- BS.uncons (BS.drop (Tunnel.returnSize 3) rest)
                  , Just response <- Box.decode (Box.PlainText responseBytes)
                  , Just plain <- Box.decrypt shared (RPC.announceResponseNonce response) (RPC.announceResponseEncryptedPayload response)
                  , Just result <- Box.decode plain -> do
      RPC.announceResponseSendbackData response `shouldBe` 7
      return (result, node')
    _ -> expectationFailure ("unexpected response: " ++ show sent) >> fail "unreachable"

spec :: Spec
spec = do
  describe "DHT public key over the DHT" $
    it "reaches us from a friend in a DHT request packet" $ do
      node <- newNode
      friendReal <- KeyPair.newKeyPair
      friendDht <- KeyPair.newKeyPair
      let ourReal = ourRealKeys (tnOnion node)
          withFriend = node { tnOnion = (tnOnion node) { onionFriends = Map.singleton (KeyPair.publicKey friendReal) friend } }
          friend = OnionFriend (tnDhtKeys node) Map.empty Map.empty Nothing Nothing Nothing 0 False 0 Nothing 0
          announcement = BS.singleton 156 <> LBS.toStrict (encode (5 :: Word64)) <> LBS.toStrict (encode $ KeyPair.publicKey friendDht)
      innerNonce <- Nonce.newNonce
      outerNonce <- Nonce.newNonce
      let realShared = CombinedKey.precompute (KeyPair.secretKey friendReal) (KeyPair.publicKey ourReal)
          inner = LBS.toStrict (encode $ KeyPair.publicKey friendReal) <> LBS.toStrict (encode innerNonce)
            <> Box.unCipherText (Box.encrypt realShared innerNonce (Box.PlainText announcement))
          dhtShared = CombinedKey.precompute (KeyPair.secretKey friendDht) (KeyPair.publicKey $ tnDhtKeys node)
          request = DhtRequestPacket (KeyPair.publicKey $ tnDhtKeys node) $
            DhtPacket (KeyPair.publicKey friendDht) outerNonce (Box.encrypt dhtShared outerNonce (Box.PlainText $ BS.cons 156 inner))
          (events, _, _) = runNode withFriend $ handleDhtRequest (LBS.toStrict $ encode request)
      events `shouldBe` [FriendDhtPkFound (KeyPair.publicKey friendReal) (KeyPair.publicKey friendDht) []]

  describe "DHT public key over the onion" $
    it "goes out again soon the first few times, in case one is lost" $ do
      node <- newNode
      friendReal <- KeyPair.newKeyPair
      holder <- KeyPair.newKeyPair
      dataKeys <- KeyPair.newKeyPair
      let friendPk = KeyPair.publicKey friendReal
          stored = (newOnionNode (NodeInfo UDP lastRelay (KeyPair.publicKey holder)))
            { onStatus = StoresFriend (KeyPair.publicKey dataKeys) }
          ((), withFriend, _) = runNode node $ do
            startFriendSearch friendPk
            modifyOnion $ \o -> o { onionFriends = Map.adjust (\f -> f { ofNodes = Map.singleton (KeyPair.publicKey holder) stored }) friendPk (onionFriends o) }
          sentAt t n = let ((), n', _) = runNodeAt t n (sendDhtPkIfDue friendPk) in n'
          lastSent n = ofLastDhtPkSent =<< Map.lookup friendPk (onionFriends (tnOnion n))
          times = map (fmap Time.timestampToMicroseconds . lastSent) . drop 1 $
            scanl (flip sentAt) withFriend [1000, 1006, 1012, 1018, 1030, 1047]
      times `shouldBe` map (Just . (* 1000000)) [1000, 1006, 1012, 1012, 1012, 1047]

  describe "a friend's turns" $ do
    it "come at their own time, stop while it's online, and come at once when it goes" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let (dues, _, _) = runNodeAt 1000 (connected node) $ do
            startFriendSearch friendPk
            added <- searchDue'
            runDue
            searched <- searchDue'
            setFriendOnline friendPk True
            online <- searchDue'
            setFriendOnline friendPk False
            offline <- searchDue'
            return [added, searched, online, offline]
          searchDue' = getsOnion $ Schedule.dueBy (FriendSearch friendPk) . onionJobs
      dues `shouldBe` map (fmap Time.fromSeconds) [Just 1000, Just 1003, Nothing, Just 1000]

    it "don't count a search that had no path, and wait before trying again" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let near = newOnionNode (NodeInfo UDP lastRelay friendPk)
          ((pings, due), _, _) = runNodeAt 1000 (connected node) $ do
            startFriendSearch friendPk
            modifyOnion $ \o -> o { onionFriends = Map.adjust (\f -> f { ofNodes = Map.singleton friendPk near }) friendPk (onionFriends o) }
            runDue
            (,) <$> getsOnion (fmap ofPings . Map.lookup friendPk . onionFriends)
                <*> getsOnion (Schedule.dueBy (FriendSearch friendPk) . onionJobs)
      (pings, due) `shouldBe` (Just 0, Just (Time.fromSeconds 1003))

    it "wait until the onion works, then come often again" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      announceNode <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let answer = RPC.AnnounceResponsePayload 0 zeroKey []
          state = getsOnion $ \o -> (ofPings <$> Map.lookup friendPk (onionFriends o), Schedule.dueBy (FriendSearch friendPk) (onionJobs o))
          (states, _, _) = runNodeAt 1000 node $ do
            startFriendSearch friendPk
            modifyOnion $ \o -> o { onionFriends = Map.adjust (\f -> f { ofPings = 40 }) friendPk (onionFriends o) }
            runDue
            away <- state
            handleAnnounceResult Self (NodeInfo UDP lastRelay announceNode) 1 answer
            back <- state
            return (away, back)
      states `shouldBe` ((Just 40, Nothing), (Just 0, Just (Time.fromSeconds 1000)))

    it "keep only nodes that answered, and at once ask nearer ones they tell of" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      holder <- KeyPair.publicKey <$> KeyPair.newKeyPair
      told <- replicateM 4 (KeyPair.publicKey <$> KeyPair.newKeyPair)
      hops <- replicateM 3 (KeyPair.publicKey <$> KeyPair.newKeyPair)
      let answer = RPC.AnnounceResponsePayload 0 zeroKey [ NodeInfo UDP lastRelay k | k <- told ]
          (kept, _, sent) = runNodeAt 1000 node $ do
            path <- Path.createPath [ NodeInfo UDP lastRelay k | k <- hops ] 1 (Time.fromSeconds 2000)
            modifyOnion $ \o -> o { onionPaths = Path.OnionPathState [] [path] 1 }
            startFriendSearch friendPk
            handleAnnounceResult (Friend friendPk) (NodeInfo UDP lastRelay holder) 1 answer
            getsOnion $ \o -> (Map.keys . ofNodes &&& ofPings) <$> Map.lookup friendPk (onionFriends o)
      (kept, length sent) `shouldBe` (Just ([holder], 0), length told)

    it "send our DHT key once nodes store the friend" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      holder <- KeyPair.newKeyPair
      dataKeys <- KeyPair.newKeyPair
      let from = NodeInfo UDP lastRelay (KeyPair.publicKey holder)
          stored = RPC.AnnounceResponsePayload 1 (KeyPair.publicKey dataKeys) []
          dhtKeyDue' = getsOnion $ Schedule.dueBy (FriendDhtKey friendPk) . onionJobs
          (dues, _, _) = runNodeAt 1000 node $ do
            startFriendSearch friendPk
            unstored <- dhtKeyDue'
            handleAnnounceResult (Friend friendPk) from 0 stored
            storing <- dhtKeyDue'
            return (unstored, storing)
      dues `shouldBe` (Nothing, Just (Time.fromSeconds 1000))

    it "wait after a DHT key send that couldn't go, not trying again at once" $ do
      node <- newNode
      friendPk <- KeyPair.publicKey <$> KeyPair.newKeyPair
      friendDht <- KeyPair.publicKey <$> KeyPair.newKeyPair
      let (due, _, _) = runNodeAt 1000 node $ do
            startFriendSearch friendPk
            modifyOnion $ \o -> o { onionFriends = Map.adjust (\f -> f { ofDhtPk = Just friendDht }) friendPk (onionFriends o) }
            reschedule friendPk
            runDue
            getsOnion $ Schedule.dueBy (FriendDhtKey friendPk) . onionJobs
      due `shouldBe` Just (Time.fromSeconds 1020)

  describe "announce node" $
    it "stores an announcement made with its ping ID and routes data to the announcer" $ do
      node0 <- newNode
      announcer <- KeyPair.newKeyPair
      searcher <- KeyPair.newKeyPair
      dataKeys <- KeyPair.newKeyPair
      let ret = BS.replicate (Tunnel.returnSize 3) 3
          announcerPk = KeyPair.publicKey announcer
          dataPk = KeyPair.publicKey dataKeys

      (first, node1) <- announceTo node0 announcer zeroKey announcerPk dataPk ret
      RPC.announceResponseIsStored first `shouldBe` 0

      (second, node2) <- announceTo node1 announcer (RPC.announceResponsePingId first) announcerPk dataPk ret
      RPC.announceResponseIsStored second `shouldBe` 2

      (search, node3) <- announceTo node2 searcher zeroKey announcerPk zeroKey (BS.replicate (Tunnel.returnSize 3) 4)
      RPC.announceResponseIsStored search `shouldBe` 1
      RPC.announceResponsePingId search `shouldBe` dataPk

      let forwarded = BS.replicate (24 + 32 + 20) 5
          dataRequest = LBS.toStrict (encode announcerPk) <> forwarded <> BS.replicate (Tunnel.returnSize 3) 6
          ((), _, sent) = runNode node3 $ handleDataRequest dataRequest
      sent `shouldBe` [(lastRelay, BS.singleton 0x8c <> ret <> BS.singleton 0x86 <> forwarded)]
