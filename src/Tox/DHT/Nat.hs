{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | Reach searched nodes through nodes close to them, and punch holes
-- through their NATs, as toxcore's DHT does.
module Tox.DHT.Nat
    ( friendAddresses
    , routeToFriend
    , dhtRequest
    , handleNatPing
    , nextDue
    , runDue
    , packetIdNatPing
    ) where

import           Control.Monad                      (forM_, unless, void, when)
import qualified Data.Binary                        as Binary
import           Data.Binary.Put                    (putWord64le, runPut)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.List                          (sortOn)
import qualified Data.Map                           as Map
import           Data.Maybe                         (isJust)
import           Data.Ord                           (Down (..))
import           Data.Text                          (pack)
import           Data.Word                          (Word16, Word32, Word8)

import           Tox.Core.Log                       (logDebug)
import qualified Tox.Core.Schedule                  as Schedule
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import           Tox.Core.Timed                     (Timed (..))
import           Tox.Crypto.Core.Box                (PlainText (..))
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Crypto.Core.MonadRandomBytes   as MonadRandomBytes
import           Tox.Crypto.Core.MonadRandomBytes   (randomNonce, randomWord64)
import qualified Tox.DHT.ClientList                 as ClientList
import qualified Tox.DHT.DhtPacket                  as DhtPacket
import           Tox.DHT.DhtRequestPacket           (DhtRequestPacket (..))
import qualified Tox.DHT.DhtState                   as DhtState
import           Tox.DHT.DhtState                   (DhtSearchEntry (..),
                                                     NatState (..))
import           Tox.DHT.Operation                  (DhtNodeMonad, getDht,
                                                     modifyDht, sendPingRequest)
import           Tox.Network.Core.HostAddress       (HostAddress)
import           Tox.Network.Core.Networked         (Networked (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..),
                                                     RawPayload (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

packetIdNatPing, natPingRequest, natPingResponse :: Word8
packetIdNatPing = 0xfe
natPingRequest  = 0
natPingResponse = 1

maxFriendClients, maxPunchingPorts, maxNormalPunchingTries :: Int
maxFriendClients       = 8
maxPunchingPorts       = 48
maxNormalPunchingTries = 5

-- | How long a node's report of a searched node's address stays good.
badNodeTimeout :: TimeDiff
badNodeTimeout = Time.seconds 122

punchInterval :: TimeDiff
punchInterval = Time.seconds 3

-- | NATs keep a mapping at least this long (RFC 4787), so once punching
-- keeps failing, trying more often gains little.
maxPunchWait :: TimeDiff
maxPunchWait = Time.seconds 120

-- | Between rounds: the interval for the first few, which is when cone NATs
-- let us through, then twice as long each round, up to 'maxPunchWait'.
punchWait :: NatState -> TimeDiff
punchWait nat
  | natTries nat < maxNormalPunchingTries = punchInterval
  | otherwise = min maxPunchWait (punchInterval * 2 ^ min 8 (natTries nat - maxNormalPunchingTries + 1))

-- | Before @d@ has passed. A job due at exactly that time finds it passed.
within :: Timestamp -> TimeDiff -> Maybe Timestamp -> Bool
within now d = maybe False (\t -> now < Time.addTime t d)

-- | Nodes close to the searched node, and where they say it is. 'Nothing' if
-- it answered us itself lately (then we reach it ourselves).
reports :: Timestamp -> DhtSearchEntry -> Maybe [(NodeInfo, SocketAddress)]
reports now e
  | within now badNodeTimeout (searchSeen e) = Nothing
  | otherwise = Just (reported now e)

reported :: Timestamp -> DhtSearchEntry -> [(NodeInfo, SocketAddress)]
reported now e =
  [ (client, addr)
  | client <- ClientList.nodeInfos (searchClientList e)
  , Just (addr, t) <- [Map.lookup (publicKey client) (searchReturned e)]
  , within now badNodeTimeout (Just t)
  ]

friendAddresses :: Timestamp -> DhtSearchEntry -> Maybe [SocketAddress]
friendAddresses now e = map snd <$> reports now e

-- | Through the nodes that say they know the searched node. Gives how many
-- we sent it to.
routeToFriend :: DhtNodeMonad m => PublicKey -> Packet RawPayload -> m Int
routeToFriend pk packet = do
  now <- askTime
  entry <- Map.lookup pk . DhtState.dhtSearchList <$> getDht
  case entry >>= reports now of
    Just rs | length rs >= maxFriendClients `div` 4 -> do
      mapM_ ((`sendPacket` packet) . fst) rs
      return $ length rs
    _ -> return 0

-- | Through 1 random node that knows the searched node.
routeOneToFriend :: DhtNodeMonad m => PublicKey -> Packet RawPayload -> m ()
routeOneToFriend pk packet = do
  now <- askTime
  entry <- Map.lookup pk . DhtState.dhtSearchList <$> getDht
  case maybe [] (map fst . reported now) entry of
    [] -> return ()
    rs -> do
      i <- MonadRandomBytes.randomInt (length rs)
      sendPacket (rs !! i) packet

-- | Nodes close to @to@ pass it on.
dhtRequest :: DhtNodeMonad m => PublicKey -> BS.ByteString -> m (Packet RawPayload)
dhtRequest to plain = do
  keyPair <- DhtState.dhtKeyPair <$> getDht
  nonce <- randomNonce
  pkt <- DhtPacket.encryptKeyed keyPair to nonce (PlainText plain)
  return . Packet PacketKind.Crypto . RawPayload . LBS.toStrict . Binary.encode $ DhtRequestPacket to pkt

natPing :: Word8 -> BS.ByteString -> BS.ByteString
natPing ty pingId = BS.pack [packetIdNatPing, ty] <> pingId

encodePingId :: NatState -> BS.ByteString
encodePingId = LBS.toStrict . runPut . putWord64le . natPingId

modifyNat :: DhtNodeMonad m => PublicKey -> (NatState -> NatState) -> m ()
modifyNat pk f = modifyDht $ \s -> s
  { DhtState.dhtSearchList = Map.adjust (\e -> e { searchNat = f (searchNat e) }) pk (DhtState.dhtSearchList s) }

-- | A round: a NAT ping through the nodes that know the searched node,
-- counted, so the next waits longer while they keep failing.
sendNatPing :: DhtNodeMonad m => Timestamp -> PublicKey -> NatState -> m ()
sendNatPing now pk nat = do
  void $ dhtRequest pk (natPing natPingRequest (encodePingId nat)) >>= routeToFriend pk
  -- We tried, so wait whatever happened.
  modifyNat pk $ \n -> n { natPingSent = Just now, natTries = natTries n + 1 }

-- | Answer requests, and start punching when it answers ours.
handleNatPing :: DhtNodeMonad m => PublicKey -> BS.ByteString -> m ()
handleNatPing from bytes = do
  entry <- Map.lookup from . DhtState.dhtSearchList <$> getDht
  forM_ entry $ \e -> case BS.unpack (BS.take 1 bytes) of
    [ty] | BS.length bytes == 9 -> do
      let pingId = BS.drop 1 bytes
      now <- askTime
      if | ty == natPingRequest -> do
             dhtRequest from (natPing natPingResponse pingId) >>= routeOneToFriend from
             modifyNat from $ \n -> n { natPingRecv = Just now }
             -- It's trying, so we try with it, as punching takes both.
             when (isJust (friendAddresses now e) && not (within now punchInterval (natPingSent (searchNat e)))) $
               sendNatPing now from (searchNat e)
             reschedule from
         | ty == natPingResponse && pingId == encodePingId (searchNat e) -> do
             newId <- randomWord64
             logDebug $ "NAT ping answered by " <> pack (show from)
             modifyNat from $ \n -> n { natPingId = newId, natPunching = True }
             reschedule from
         | otherwise -> return ()
    _ -> return ()

-- | When the searched node's hole punching is next due. While we reach it
-- ourselves, that's once we stop.
natDue :: Timestamp -> DhtSearchEntry -> Maybe Timestamp
natDue now e
  | within now badNodeTimeout (searchSeen e) = (`Time.addTime` badNodeTimeout) <$> searchSeen e
  | length addrs < maxFriendClients `div` 2 = Nothing
  | otherwise = Just . minimum $ next (natPingSent nat) : [ next (natPunched nat) | punching ]
  where
    addrs = map snd (reported now e)
    nat = searchNat e
    next = maybe now (`Time.addTime` punchWait nat)
    punching = natPunching nat && within now (2 * punchInterval) (natPingRecv nat) && isJust (commonHost addrs)

-- | After anything that changes the searched node's entry.
reschedule :: DhtNodeMonad m => PublicKey -> m ()
reschedule pk = do
  now <- askTime
  modifyDht $ \s -> s { DhtState.dhtNatJobs = maybe (Schedule.cancel pk) (`Schedule.at` pk)
    (natDue now =<< Map.lookup pk (DhtState.dhtSearchList s)) (DhtState.dhtNatJobs s) }

nextDue :: DhtState.DhtState -> Maybe Timestamp
nextDue = Schedule.next . DhtState.dhtNatJobs

-- | NAT ping searched nodes we only know of through others, and punch holes
-- towards the ones that answer.
runDue :: DhtNodeMonad m => m ()
runDue = do
  now <- askTime
  (due, waiting) <- Schedule.takeDue now . DhtState.dhtNatJobs <$> getDht
  modifyDht $ \s -> s { DhtState.dhtNatJobs = waiting }
  forM_ due $ \pk -> do
    getDht >>= mapM_ (natWork now pk) . Map.lookup pk . DhtState.dhtSearchList
    reschedule pk

natWork :: DhtNodeMonad m => Timestamp -> PublicKey -> DhtSearchEntry -> m ()
natWork now pk e = case friendAddresses now e of
  Just addrs | length addrs >= maxFriendClients `div` 2 -> do
    -- Rounds count from when it last answered us itself.
    let answered = maybe False (\seen -> maybe True (< seen) (natPingSent (searchNat e))) (searchSeen e)
    when answered $ modifyNat pk $ \n -> n { natTries = 0, natPortIndex = 0, natLowPortIndex = 0 }
    nat <- maybe (searchNat e) searchNat . Map.lookup pk . DhtState.dhtSearchList <$> getDht
    unless (within now (punchWait nat) (natPingSent nat)) $ sendNatPing now pk nat
    when (natPunching nat && not (within now (punchWait nat) (natPunched nat))
          && within now (2 * punchInterval) (natPingRecv nat)) $
      forM_ (commonHost addrs) $ \host -> do
        let ports = [ p | SocketAddress h (PortNumber p) <- addrs, h == host ]
            (targets, nat') = punchTargets ports nat
        logDebug $ "Punching holes to " <> pack (show pk) <> " at " <> pack (show host)
          <> " ports " <> pack (show targets)
        mapM_ (\port -> sendPingRequest $ NodeInfo UDP (SocketAddress host (PortNumber port)) pk) targets
        modifyNat pk $ \n -> nat' { natPingSent = natPingSent n, natTries = natTries n, natPunched = Just now, natPunching = False }
  _ -> return ()

-- | The host most nodes report, if at least half of them do.
commonHost :: [SocketAddress] -> Maybe HostAddress
commonHost addrs = case sortOn (Down . snd) counts of
  (host, n) : _ | n >= maxFriendClients `div` 2 -> Just host
  _                                             -> Nothing
  where
    hosts = [ h | SocketAddress h _ <- addrs ]
    counts = Map.toList $ Map.fromListWith (+) [ (h, 1 :: Int) | h <- hosts ]

-- | The port if all reports agree, else guesses around the reported ones,
-- and after a few rounds a sweep from port 1024 too.
punchTargets :: [Word16] -> NatState -> ([Word16], NatState)
punchTargets [] nat = ([], nat)
punchTargets ports@(first : _) nat = (normal ++ low, nat'')
  where
    numPorts = fromIntegral (length ports) :: Word32
    (normal, nat')
      | all (== first) ports = ([first], nat)
      | otherwise =
          ( [ guess (fromIntegral i + natPortIndex nat) | i <- [0 .. maxPunchingPorts - 1] ]
          , nat { natPortIndex = natPortIndex nat + fromIntegral maxPunchingPorts } )
    guess it =
      let delta = (if odd it then negate else id) (it `div` (2 * numPorts))
      in (ports !! fromIntegral ((it `div` 2) `mod` numPorts)) + fromIntegral delta
    (low, nat'')
      | natTries nat' > maxNormalPunchingTries =
          ( [ 1024 + fromIntegral (fromIntegral i + natLowPortIndex nat') | i <- [0 .. maxPunchingPorts - 1] ]
          , nat' { natLowPortIndex = natLowPortIndex nat' + fromIntegral (maxPunchingPorts `div` 2) } )
      | otherwise = ([], nat')
