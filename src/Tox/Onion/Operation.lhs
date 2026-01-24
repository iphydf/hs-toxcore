\section{Onion Operation}

\begin{code}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}
module Tox.Onion.Operation where

import           Control.Monad                (when, forM_)
import           Control.Monad.State          (MonadState, gets, modify, StateT, runStateT)
import           Data.Binary                  (Binary, encode)
import qualified Data.Binary                  as Binary
import qualified Data.Binary.Put              as Put
import           Data.List                    (sortBy)
import           Data.Ord                     (comparing)
import           Data.Map                     (Map)
import qualified Data.Map                     as Map
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as LBS
import           Control.Monad.Validate       (runValidate)
import           Data.Maybe                   (fromJust)
import qualified Data.Maybe                   as Maybe
import           Data.MessagePack             (DecodeError)
import           Data.Word                    (Word32, Word64, Word8)

import qualified Crypto.Saltine.Class         as Sodium
import           Tox.Core.Time                (TimeDiff, Timestamp, getTime)
import qualified Tox.Core.Time                as Time
import           Tox.Core.Timed               (Timed, askTime)
import qualified Tox.Core.Timed               as Timed
import qualified Tox.Core.PingArray           as PingArray
import           Tox.Crypto.Core.Key               (PublicKey, Nonce, Key(..))
import           Tox.Crypto.Core.Keyed             (Keyed)
import qualified Tox.Crypto.Core.Keyed             as Keyed
import           Tox.Crypto.Core.KeyPair           (KeyPair)
import qualified Tox.Crypto.Core.KeyPair           as KeyPair
import           Tox.Crypto.Core.Box               (CipherText, unCipherText, unPlainText)
import qualified Tox.Crypto.Core.Box               as Box
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)
import qualified Tox.Crypto.Core.MonadRandomBytes as MonadRandomBytes
import qualified Tox.DHT.Distance             as Distance
import           Tox.Network.Core.Networked        (Networked)
import qualified Tox.Network.Core.Networked        as Networked
import           Tox.Network.Core.NodeInfo         (NodeInfo)
import qualified Tox.Network.Core.NodeInfo         as NodeInfo
import           Tox.Network.Core.Packet           (Packet (..), RawPayload(..))
import           Tox.Network.Core.PacketKind       (PacketKind)
import qualified Tox.Network.Core.PacketKind       as PacketKind
import           Tox.Network.Core.SocketAddress    (SocketAddress)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (UDP))
import           Tox.Onion.Path                    (OnionPath, OnionPathState)
import qualified Tox.Onion.Path                    as Path
import           Tox.Onion.RPC                     (AnnounceRequest (..), AnnounceResponse (..))
import qualified Tox.Onion.RPC                     as RPC
import qualified Tox.Onion.Tunnel                  as Tunnel
import qualified Tox.DHT.DhtPacket                 as DhtPacket
import           Control.Monad.Logger              (MonadLogger, logInfoN, logWarnN, logDebugN)
import           Data.Text                         (pack)

{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

class (Monad m, Timed m, MonadRandomBytes m, Keyed m, Networked m, MonadLogger m) => OnionNodeMonad m where
  getOnionState :: m OnionState
  putOnionState :: OnionState -> m ()
  getDhtKeyPair :: m KeyPair

getOnion :: OnionNodeMonad m => m OnionState
getOnion = getOnionState

getsOnion :: OnionNodeMonad m => (OnionState -> a) -> m a
getsOnion f = f <$> getOnion

putOnion :: OnionNodeMonad m => OnionState -> m ()
putOnion = putOnionState

modifyOnion :: OnionNodeMonad m => (OnionState -> OnionState) -> m ()
modifyOnion f = getOnion >>= putOnion . f

getDhtPk :: OnionNodeMonad m => m PublicKey
getDhtPk = KeyPair.publicKey <$> getDhtKeyPair

instance OnionNodeMonad m => Path.OnionPathMonad (StateT OnionPathState m)

cipherTextMaybe :: BS.ByteString -> Maybe Box.CipherText
cipherTextMaybe bs = case runValidate (Box.cipherText bs) of
  Left _   -> Nothing
  Right ct -> Just ct

data OnionState = OnionState
  { onionPaths      :: OnionPathState
  , ourLongTermKeys :: KeyPair
  , announcedNodes  :: Map PublicKey AnnouncedNode -- ^ Nodes closest to our real PK
  , searchNodes     :: Map PublicKey (Map PublicKey AnnouncedNode) -- ^ Friends we are searching for
  , friendsToSearch :: [PublicKey] -- ^ List of friend long-term PKs to search for
  , requestTracker  :: PingArray.PingArray OnionRequest -- ^ Metadata for outgoing requests
  , localAnnouncements :: Map PublicKey LocalAnnouncement -- ^ Nodes announced to us
  }

data LocalAnnouncement = LocalAnnouncement
  { laSenderRealPk :: PublicKey
  , laSenderDhtPk  :: PublicKey
  , laTimestamp    :: Timestamp
  , laPingId       :: PublicKey
  , laSendbackKey  :: PublicKey
  } deriving (Eq, Show)

data OnionRequest = OnionRequest
  { orSearchKey     :: PublicKey
  , orTargetPk      :: PublicKey
  , orSenderKeyPair :: KeyPair
  } deriving (Eq, Show)

data AnnouncedNode = AnnouncedNode
  { nodeInfo      :: NodeInfo
  , pingId        :: Maybe PublicKey -- ^ 0 if unknown
  , lastAnnounced :: Maybe Timestamp
  , pathNum       :: Word32 -- ^ Path used for this node
  } deriving (Eq, Show)

-- | Initial onion state.
initState :: KeyPair -> OnionState
initState keys = OnionState
  { onionPaths = Path.OnionPathState [] [] 0
  , ourLongTermKeys = keys
  , announcedNodes = Map.empty
  , searchNodes = Map.empty
  , friendsToSearch = []
  , requestTracker = PingArray.empty 1024 (Time.seconds 300)
  , localAnnouncements = Map.empty
  }

-- | Periodically maintain the onion layer.
doOnion :: OnionNodeMonad m => [NodeInfo] -> m ()
doOnion dhtNodes = do
  -- 1. Maintain paths
  zoomOnionPath $ Path.maintainPaths dhtNodes
  
  -- 2. Announce ourselves
  announceOurselves dhtNodes
  
  -- 3. Search for friends
  searchForFriends dhtNodes

zoomOnionPath :: OnionNodeMonad m => StateT OnionPathState m a -> m a
zoomOnionPath st = do
  s <- getOnion
  (a, s') <- runStateT st (onionPaths s)
  putOnion $ s { onionPaths = s' }
  return a


-- | Start searching for a friend.
startFriendSearch :: OnionNodeMonad m => PublicKey -> m ()
startFriendSearch friendPk = modifyOnion $ \s ->
  s { friendsToSearch = if friendPk `elem` friendsToSearch s then friendsToSearch s else friendPk : friendsToSearch s
    , searchNodes = Map.insertWith (\_ old -> old) friendPk Map.empty (searchNodes s)
    }


-- | Periodically search for friends.
searchForFriends :: OnionNodeMonad m => [NodeInfo] -> m ()
searchForFriends dhtNodes = do
  friends <- getsOnion friendsToSearch
  forM_ friends $ \friendPk -> do
    -- 1. Initial search using DHT nodes
    let closestDht = take 8 $ sortBy (comparing (Distance.xorDistance friendPk . NodeInfo.publicKey)) dhtNodes
    
    -- 2. Continue search using nodes we found via onion
    foundRelays <- getsOnion (Map.findWithDefault Map.empty friendPk . searchNodes)
    let closestOnion = take 8 $ sortBy (comparing (Distance.xorDistance friendPk . NodeInfo.publicKey . nodeInfo)) (Map.elems foundRelays)
    
    -- Combined list of nodes to ping
    let allNodes = closestDht ++ map nodeInfo closestOnion
    
    forM_ (take 8 allNodes) $ \node -> do
      mPath <- zoomOnionPath $ Path.selectPath False
      case mPath of
        Nothing -> return ()
        Just path -> sendAnnounceRequest path node friendPk Nothing


-- | Handle an Announce Response.
handleAnnounceResponse :: OnionNodeMonad m => NodeInfo -> RPC.AnnounceResponse -> m ()
handleAnnounceResponse from res = do
  ourLongTerm <- getsOnion ourLongTermKeys
  now <- Timed.askTime
  logDebugN $ "Received AnnounceResponse from " <> pack (show from)
  
  -- Use sendback data to find the original target node's PK.
  s <- getOnion
  let (mMeta, tracker') = PingArray.takeEntry now (RPC.announceResponseSendbackData res) (requestTracker s)
  putOnion $ s { requestTracker = tracker' }
  
  case mMeta of
    Nothing -> logWarnN "Received AnnounceResponse with unknown/expired sendback data"
    Just (OnionRequest searchKey targetPk kp) -> do
      -- Decrypt the payload using the keypair we used for the request
      combined <- Keyed.getCombinedKey (KeyPair.secretKey kp) targetPk
      case Box.decrypt combined (RPC.announceResponseNonce res) (RPC.announceResponseEncryptedPayload res) of
        Nothing -> logWarnN $ "Failed to decrypt AnnounceResponse from " <> pack (show from)
        Just plain -> case Box.decode plain of
          Nothing -> logWarnN $ "Failed to decode decrypted AnnounceResponse from " <> pack (show from)
          Just (payload :: RPC.AnnounceResponsePayload) -> do
            let pingId = RPC.announceResponsePingId payload
                nodes = RPC.announceResponseNodes payload
            logInfoN $ "Onion entry found/confirmed: target=" <> pack (show targetPk) <> " pingId=" <> pack (show pingId) <> ", found " <> pack (show $ length nodes) <> " nodes"
            
            -- Update state with found info (pingId, etc.)
            let newNode = AnnouncedNode
                  { nodeInfo = NodeInfo.NodeInfo UDP (NodeInfo.address from) targetPk
                  , pingId = Just pingId
                  , lastAnnounced = Just now
                  , pathNum = 0 -- TODO
                  }
            
            if searchKey == KeyPair.publicKey ourLongTerm
              then do
                modifyOnion $ \s' -> s' { announcedNodes = Map.insert targetPk newNode (announcedNodes s') }
                logInfoN $ "Confirmed announcement to " <> pack (show targetPk)
              else do
                modifyOnion $ \s' -> s' { searchNodes = Map.insertWith Map.union searchKey (Map.singleton targetPk newNode) (searchNodes s') }
                logInfoN $ "Found " <> pack (show $ length nodes) <> " potential nodes for friend " <> pack (show searchKey)


-- | Send an Announce Request through a chosen path.
sendAnnounceRequest :: OnionNodeMonad m => OnionPath -> NodeInfo -> PublicKey -> Maybe PublicKey -> m ()
sendAnnounceRequest path target searchKey mPingId = do
  ourLongTerm <- getsOnion ourLongTermKeys
  ourDht <- getDhtKeyPair
  nonce <- MonadRandomBytes.randomNonce
  innerNonce <- MonadRandomBytes.randomNonce
  
  -- Use a temporary keypair for searches, real for announcements.
  -- The spec requires this for anonymity.
  senderKeyPair <- if searchKey == KeyPair.publicKey ourLongTerm
                   then return ourLongTerm
                   else MonadRandomBytes.newKeyPair
  
  -- Store request metadata for later response handling
  now <- Timed.askTime
  seed <- MonadRandomBytes.randomWord64
  let meta = OnionRequest searchKey (NodeInfo.publicKey target) senderKeyPair
  s <- getOnion
  let (sendback, tracker') = PingArray.addEntry now meta seed (requestTracker s)
  putOnion $ s { requestTracker = tracker' }
      
  let payload = RPC.AnnounceRequestPayload
        { RPC.announceRequestPingId          = maybe (Key . Maybe.fromJust . Sodium.decode $ BS.replicate 32 0) id mPingId
        , RPC.announceRequestSearchKey       = searchKey
        , RPC.announceRequestDataSendbackKey = KeyPair.publicKey senderKeyPair
        , RPC.announceRequestSendbackData    = sendback
        }
      
  -- Encrypt the payload for the target node
  combined <- Keyed.getCombinedKey (KeyPair.secretKey senderKeyPair) (NodeInfo.publicKey target)
  let encryptedPayload = Box.encrypt combined innerNonce (Box.encode payload)
      
      -- Standard AnnounceRequest envelope: Kind (0x83) + Nonce (24) + PK (32) + CipherText
      dataToD = LBS.toStrict $ Put.runPut $ do
        Binary.put (0x83 :: Word8)
        Binary.put innerNonce
        Binary.put (KeyPair.publicKey senderKeyPair)
        Put.putByteString (unCipherText encryptedPayload)

  -- Wrap the onion request
  case (cipherTextMaybe dataToD, Path.pathNodes path) of
    (Just ct, (nodeA:_)) -> do
      onionPkt0 <- Path.wrapPath ourDht path (NodeInfo.address target) nonce (unCipherText ct)
      Networked.sendPacket nodeA $ Packet PacketKind.OnionRequest0 onionPkt0
    _ -> return ()

-- | Decrypt and dispatch a DHT request payload addressed to us.
onDhtRequestPayload :: OnionNodeMonad m => NodeInfo -> DhtPacket.DhtPacket -> m ()
onDhtRequestPayload from dhtPkt = do
  ourKeyPair <- getsOnion ourLongTermKeys
  mPlain <- DhtPacket.decryptKeyed ourKeyPair dhtPkt
  case mPlain of
    Nothing -> return ()
    Just plain -> dispatchOnionData [] Nothing from (unPlainText plain)


-- | Handle an incoming top-level onion packet.
handleOnionPacket :: OnionNodeMonad m => [NodeInfo] -> NodeInfo -> Packet BS.ByteString -> m ()
handleOnionPacket dhtNodes from (Packet kind payload) = do
  logDebugN $ "Received Onion packet from " <> pack (show from) <> ": " <> pack (show kind)
  ourKeyPair <- getsOnion ourLongTermKeys
  case kind of
    PacketKind.OnionRequest0 -> do
      case runBinary (Box.PlainText payload) of
        Nothing -> return ()
        Just (req :: Tunnel.OnionRequest0) -> do
          mInner <- Tunnel.unwrapOnion0 ourKeyPair req
          case mInner of
            Nothing -> return ()
            Just inner -> handleRelayOrDispatch dhtNodes from (Tunnel.onion0Nonce req) inner
    
    PacketKind.OnionRequest1 -> handleOnionRelay dhtNodes PacketKind.OnionRequest1 from payload
    PacketKind.OnionRequest2 -> handleOnionRelay dhtNodes PacketKind.OnionRequest2 from payload
    
    PacketKind.OnionResponse1 -> handleOnionResponse dhtNodes from payload
    PacketKind.OnionResponse2 -> handleOnionResponse dhtNodes from payload
    PacketKind.OnionResponse3 -> handleOnionResponse dhtNodes from payload
    
    PacketKind.AnnounceResponse -> dispatchOnionData dhtNodes Nothing from (BS.cons 0x84 payload)
    PacketKind.OnionDataRequest -> dispatchOnionData dhtNodes Nothing from (BS.cons 0x85 payload)
    PacketKind.OnionDataResponse -> dispatchOnionData dhtNodes Nothing from (BS.cons 0x86 payload)
    PacketKind.DHTPKPacket -> dispatchOnionData dhtNodes Nothing from (BS.cons 0x9c payload)
    -- PacketKind.AnnounceRequest (0x83) is handled if we are Node D, but usually not top-level.
    
    _ -> return ()


runBinary :: Binary a => Box.PlainText -> Maybe a
runBinary (Box.PlainText bs) = case Binary.decodeOrFail (LBS.fromStrict bs) of
  Left _ -> Nothing
  Right (_, _, a) -> Just a


-- | Handle an intermediate relay request (0x81, 0x82).
handleOnionRelay :: OnionNodeMonad m => [NodeInfo] -> PacketKind -> NodeInfo -> BS.ByteString -> m ()
handleOnionRelay dhtNodes kind from payload = do
  ourKeyPair <- getDhtKeyPair
  case kind of
    PacketKind.OnionRequest1 -> do
      -- Node B receiving from Node A
      case runBinary (Box.PlainText payload) of
        Nothing -> return ()
        Just (req :: Tunnel.OnionRequestRelay) -> do
          mInner <- Tunnel.unwrapOnionRelay ourKeyPair req
          case mInner of
            Nothing -> return ()
            Just (inner, _retNonce, _retData) ->
              handleRelayOrDispatch dhtNodes from (Tunnel.onionRelayNonce req) inner

    PacketKind.OnionRequest2 -> do
      -- Node C receiving from Node B
      case runBinary (Box.PlainText payload) of
        Nothing -> return ()
        Just (req :: Tunnel.OnionRequestRelay) -> do
          mInner <- Tunnel.unwrapOnionFinal ourKeyPair req
          case mInner of
            Nothing -> return ()
            Just (inner, _retNonce, _retData) -> do
               dispatchOnionData dhtNodes Nothing from (Tunnel.onionPayloadFinalData inner)
    _ -> return ()


-- | Handle an onion response (0x8c, 0x8d, 0x8e).
handleOnionResponse :: OnionNodeMonad m => [NodeInfo] -> NodeInfo -> BS.ByteString -> m ()
handleOnionResponse dhtNodes from bs = do
  case runBinary bs of
    Nothing -> return ()
    Just (res :: Tunnel.OnionResponse) -> do
      dispatchOnionData dhtNodes Nothing from (Tunnel.onionResponseData res)
  where
    runBinary payload = case Binary.decodeOrFail (LBS.fromStrict payload) of
      Left _ -> Nothing
      Right (_, _, a) -> Just a


-- | Handle the innermost payload of an onion request.
handleRelayOrDispatch :: OnionNodeMonad m => [NodeInfo] -> NodeInfo -> Nonce -> Tunnel.OnionRequestPayload -> m ()
handleRelayOrDispatch dhtNodes from _nonce payload = do
  dispatchOnionData dhtNodes Nothing from (unCipherText $ Tunnel.onionPayloadEncryptedPayload payload)


-- | Dispatch decrypted onion data to the appropriate service.
dispatchOnionData :: OnionNodeMonad m => [NodeInfo] -> Maybe PublicKey -> NodeInfo -> BS.ByteString -> m ()
dispatchOnionData dhtNodes mSenderPk from bs = do
  logDebugN $ "Dispatching onion data (length: " <> pack (show (BS.length bs)) <> ")"
  case BS.uncons bs of
    Nothing -> logWarnN "Received empty onion data"
    Just (kind, payload) -> case kind of
      0x83 -> case runBinary payload of
                Nothing -> logWarnN "Failed to decode AnnounceRequest"
                Just req -> handleAnnounceRequest dhtNodes from req
      0x84 -> case runBinary payload of
                Nothing -> logWarnN "Failed to decode AnnounceResponse"
                Just res -> handleAnnounceResponse from res
      0x85 -> case runBinary payload of
                Nothing -> logWarnN "Failed to decode DataRouteRequest"
                Just req -> handleDataRouteRequest from req
      0x86 -> case runBinary payload of
                Nothing -> logWarnN "Failed to decode DataRouteResponse"
                Just res -> handleDataRouteResponse from res
      0x9c -> case runBinary payload of
                Nothing -> logWarnN "Failed to decode DHTPKPacket"
                Just pkt -> handleDHTPKPacket mSenderPk from pkt
      _    -> logWarnN $ "Received unknown onion data kind: " <> pack (show kind)
  where
    runBinary payload = case Binary.decodeOrFail (LBS.fromStrict payload) of
      Left _ -> Nothing
      Right (_, _, a) -> Just a


-- | Handle an Announce Request (Server side).
handleAnnounceRequest :: OnionNodeMonad m => [NodeInfo] -> NodeInfo -> RPC.AnnounceRequest -> m ()
handleAnnounceRequest dhtNodes from req = do
  logInfoN $ "Received AnnounceRequest from " <> pack (show from)
  ourDht <- getDhtKeyPair
  
  -- 1. Decrypt the payload
  -- The payload is encrypted with our DHT keys and the sender's public key (real or temp).
  let senderPk = RPC.announceRequestSenderPublicKey req
  combined <- Keyed.getCombinedKey (KeyPair.secretKey ourDht) senderPk
  case Box.decrypt combined (RPC.announceRequestNonce req) (RPC.announceRequestEncryptedPayload req) of
    Nothing -> logWarnN $ "Failed to decrypt AnnounceRequest from " <> pack (show from)
    Just plain -> case Box.decode plain of
      Nothing -> logWarnN $ "Failed to decode AnnounceRequest payload from " <> pack (show from)
      Just (payload :: RPC.AnnounceRequestPayload) -> do
        now <- askTime
        let searchKey = RPC.announceRequestSearchKey payload
            pingId = RPC.announceRequestPingId payload
            sendbackData = RPC.announceRequestSendbackData payload
            sendbackKey = RPC.announceRequestDataSendbackKey payload
            nullPk = Key (fromJust $ Sodium.decode $ BS.replicate 32 0)

        -- 2. Process Announcement/Search
        -- If pingId is null, we generate a new one and don't store yet.
        -- If pingId matches what we sent, we store the announcement.
        
        let isStored = if pingId == nullPk 
                       then 0 
                       else 2 -- Simple implementation: always accept if they have a non-zero pingId
        
        when (isStored == 2) $ do
           let announcement = LocalAnnouncement
                 { laSenderRealPk = senderPk
                 , laSenderDhtPk  = NodeInfo.publicKey from -- Assumes direct connection or Node A
                 , laTimestamp    = now
                 , laPingId       = pingId
                 , laSendbackKey  = sendbackKey
                 }
           modifyOnion $ \s -> s { localAnnouncements = Map.insert searchKey announcement (localAnnouncements s) }
           logInfoN $ "Stored Onion announcement for " <> pack (show searchKey)

        -- 3. Construct Response
        -- Find 4 closest nodes to searchKey in the provided DHT nodes
        let foundNodes = take 4 $ sortBy (comparing (Distance.xorDistance searchKey . NodeInfo.publicKey)) dhtNodes
        
        let respPayload = RPC.AnnounceResponsePayload
              { RPC.announceResponseIsStored = isStored
              , RPC.announceResponsePingId   = if isStored == 0 then Key (fromJust $ Sodium.decode $ BS.replicate 32 1) else pingId -- Dummy pingId
              , RPC.announceResponseNodes    = foundNodes
              }
            
        newNonce <- MonadRandomBytes.randomNonce
        let encryptedResp = Box.encrypt combined newNonce (Box.encode respPayload)
            resp = RPC.AnnounceResponse
              { RPC.announceResponseSendbackData = sendbackData
              , RPC.announceResponseNonce = newNonce
              , RPC.announceResponseEncryptedPayload = encryptedResp
              }
        
        Networked.sendPacket from (Packet PacketKind.AnnounceResponse (RawPayload $ LBS.toStrict $ Binary.encode resp))


-- | Handle a received DHT Public Key packet.
handleDHTPKPacket :: OnionNodeMonad m => Maybe PublicKey -> NodeInfo -> RPC.DHTPublicKeyPacket -> m ()
handleDHTPKPacket mSenderPk from pkt = do
  logInfoN $ "Received DHTPKPacket from " <> pack (show from)
  case mSenderPk of
    Nothing -> logWarnN "Received DHTPKPacket with unknown sender (anonymous)"
    Just senderPk -> do
      let dhtPk = RPC.dhtPKPacketOurDHTKey pkt
          relays = RPC.dhtPKPacketNodes pkt
      
      nowTime <- askTime
      logInfoN $ "Discovered DHT Key for friend " <> pack (show senderPk) <> ": " <> pack (show dhtPk) <> " with " <> pack (show $ length relays) <> " relays"
      
      -- Update searchNodes so Connection layer can proceed
      let newEntry = AnnouncedNode
            { nodeInfo = NodeInfo.NodeInfo UDP (NodeInfo.address from) dhtPk
            , pingId = Nothing
            , lastAnnounced = Just nowTime
            , pathNum = 0
            }
      
      modifyOnion $ \s -> s 
        { searchNodes = Map.insertWith (Map.union) senderPk (Map.singleton dhtPk newEntry) (searchNodes s) 
        }


-- | Send a DHT Public Key packet to a friend through their discovered relays.
sendDHTPublicKeyPacket :: OnionNodeMonad m => PublicKey -> m ()
sendDHTPublicKeyPacket friendPk = do
  dhtPk <- getDhtPk
  mRelays <- getsOnion (Map.lookup friendPk . searchNodes)
  case mRelays of
    Nothing -> return ()
    Just relays | Map.null relays -> return ()
    Just relays -> do
      let dhtPkPacket = RPC.DHTPublicKeyPacket
            { RPC.dhtPKPacketNoReplay = 0
            , RPC.dhtPKPacketOurDHTKey = dhtPk
            , RPC.dhtPKPacketNodes = []
            }
      
      forM_ (Map.elems relays) $ \relay -> do
         mPath <- zoomOnionPath $ Path.selectPath False
         case mPath of
           Nothing -> return ()
           Just path -> sendDataRouteRequest path (nodeInfo relay) friendPk (Box.encode dhtPkPacket)


-- | Announce ourselves to nodes closest to our real public key.
announceOurselves :: OnionNodeMonad m => [NodeInfo] -> m ()
announceOurselves dhtNodes = do
  ourLongTerm <- getsOnion ourLongTermKeys
  let ourPk = KeyPair.publicKey ourLongTerm
      closest = take 12 $ sortBy (comparing (Distance.xorDistance ourPk . NodeInfo.publicKey)) dhtNodes
  
  logInfoN $ "Announcing ourselves to " <> pack (show $ length closest) <> " nodes"
  forM_ closest $ \node -> do
    mPath <- zoomOnionPath $ Path.selectPath True
    case mPath of
      Nothing -> logWarnN "No onion path available for announcement"
      Just path -> do
        mAnnounced <- getsOnion (Map.lookup (NodeInfo.publicKey node) . announcedNodes)
        let mPingId = mAnnounced >>= pingId
        sendAnnounceRequest path node ourPk mPingId


-- | Send an Onion Data packet to a destination peer.
sendDataRouteRequest :: OnionNodeMonad m => OnionPath -> NodeInfo -> PublicKey -> Box.PlainText -> m ()
sendDataRouteRequest path relay destPk payload = do
  ourLongTerm <- getsOnion ourLongTermKeys
  ourDht <- getDhtKeyPair
  nonce <- MonadRandomBytes.randomNonce
  tempKp <- MonadRandomBytes.newKeyPair
  
  innerCombined <- Keyed.getCombinedKey (KeyPair.secretKey ourLongTerm) destPk
  let innerEnc = Box.encrypt innerCombined nonce payload
      innerPayload = RPC.DataRouteInner (KeyPair.publicKey ourLongTerm) innerEnc
      
  relayCombined <- Keyed.getCombinedKey (KeyPair.secretKey tempKp) (NodeInfo.publicKey relay)
  let outerEnc = Box.encrypt relayCombined nonce (Box.encode innerPayload)
      routeReq = RPC.DataRouteRequest
        { RPC.dataRouteRequestDestination = destPk
        , RPC.dataRouteRequestNonce = nonce
        , RPC.dataRouteRequestTemporaryKey = KeyPair.publicKey tempKp
        , RPC.dataRouteRequestEncryptedPayload = outerEnc
        }
      
      dataToD = BS.singleton 0x85 <> LBS.toStrict (Binary.encode routeReq)

  case (cipherTextMaybe dataToD, Path.pathNodes path) of
    (Just ct, (nodeA:_)) -> do
      onionPkt0 <- Path.wrapPath ourDht path (NodeInfo.address relay) nonce (unCipherText ct)
      Networked.sendPacket nodeA $ Packet PacketKind.OnionRequest0 onionPkt0
    _ -> return ()


-- | Handle a Data Route Request (Server side).
handleDataRouteRequest :: OnionNodeMonad m => NodeInfo -> RPC.DataRouteRequest -> m ()
handleDataRouteRequest from req = do
  ourLongTerm <- getsOnion ourLongTermKeys
  let destPk = RPC.dataRouteRequestDestination req
  
  if destPk == KeyPair.publicKey ourLongTerm
  then do
    logInfoN $ "Received DataRouteRequest for ourselves from " <> pack (show from)
    -- We are the destination Node D.
    -- 1. Decrypt the outer layer using Node D's keys and the temp PK.
    let tempPk = RPC.dataRouteRequestTemporaryKey req
        nonce = RPC.dataRouteRequestNonce req
    combined <- Keyed.getCombinedKey (KeyPair.secretKey ourLongTerm) tempPk
    case Box.decrypt combined nonce (RPC.dataRouteRequestEncryptedPayload req) of
      Nothing -> logWarnN "Failed to decrypt DataRouteRequest outer layer"
      Just plain -> case Box.decode plain of
        Nothing -> logWarnN "Failed to decode DataRouteRequest inner payload"
        Just (inner :: RPC.DataRouteInner) -> do
          -- 2. Decrypt the inner layer using Node D's long-term keys and Sender's real PK.
          let senderPk = RPC.dataRouteInnerSenderPublicKey inner
          innerCombined <- Keyed.getCombinedKey (KeyPair.secretKey ourLongTerm) senderPk
          case Box.decrypt innerCombined nonce (RPC.dataRouteInnerEncryptedPayload inner) of
            Nothing -> logWarnN $ "Failed to decrypt DataRouteRequest inner layer from " <> pack (show senderPk)
            Just payload -> do
               logInfoN $ "Successfully decrypted Onion Data from " <> pack (show senderPk)
               -- The payload starts with a Kind byte.
               dispatchOnionData [] (Just senderPk) from (Box.unPlainText payload)
  else do
    logDebugN $ "Received DataRouteRequest for another node: " <> pack (show destPk)
    -- TODO: implement relaying (send 0x86 to destination if we know them)
    return ()


-- | Handle a Data Route Response.
handleDataRouteResponse :: OnionNodeMonad m => NodeInfo -> RPC.DataRouteResponse -> m ()
handleDataRouteResponse _from _res = do
  -- TODO: implement handling of responses to our own DataRouteRequests
  return ()

\end{code}