{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE UndecidableInstances       #-}
module Main where

import           Control.Concurrent            (forkIO, threadDelay)
import           Control.Monad                 (forM, forever, void, when, foldM)
import           Control.Monad.Random          (evalRandT)
import           Data.Functor.Identity         (runIdentity)
import           Data.Foldable                 (forM_)
import           Control.Monad.IO.Class        (MonadIO, liftIO)
import           Control.Monad.Reader          (MonadReader, ReaderT, ask,
                                                runReaderT)
import           Control.Monad.State           (MonadState (..), runStateT, modify)
import           Control.Monad.Trans           (lift)
import           Control.Monad.Trans.Resource  (runResourceT)
import           Data.Aeson                    (FromJSON, decode, parseJSON,
                                                withObject, (.:), (.:?))
import qualified Data.Binary                   as Binary
import           Data.Binary.Get               (runGetOrFail)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Base16        as Base16
import qualified Data.ByteString.Char8         as BS8
import qualified Data.ByteString.Lazy          as LBS
import           Data.Conduit                  (ConduitT, await, awaitForever,
                                                runConduit, yield, (.|))
import qualified Data.Conduit.List             as CL
import           Data.IORef                    (IORef, newIORef, readIORef,
                                                writeIORef)
import qualified Data.IP                       as IP
import           Data.Maybe                    (catMaybes, fromJust)
import           Data.Word                     (Word16)
import           Data.Bits                     (xor)
import           GHC.Generics                  (Generic)
import           Network.HTTP.Simple           (getResponseBody, httpLBS,
                                                parseRequest)
import qualified Network.Socket                as Socket
import           System.IO                     (BufferMode (..), hSetBuffering,
                                                stdout)
import           System.Random                 (mkStdGen, randomIO)
import           Control.Monad.Logger          (MonadLogger, runStdoutLoggingT, logInfoN, logDebugN, logWarnN, logErrorN)
import           Options.Applicative
import           Text.Read                     (readMaybe)

import qualified Crypto.Saltine.Class          as Sodium
import           Data.Map                      (Map)
import qualified Data.Map                      as Map
import           Tox.Application.State         (AppMonad (..), GlobalState (..),
                                                initState)
import           Tox.Conduit.Encoding          (decodePacket)
import           Tox.Conduit.Network           (fromSockAddr, udpSource)
import           Tox.Core.Time                 (getTime)
import           Tox.Core.Timed                (Timed (..))
import qualified Tox.Crypto.Core.Key                as Key
import           Tox.Crypto.Core.Key                (PublicKey)
import           Tox.Crypto.Core.KeyPair       (KeyPair)
import qualified Tox.Crypto.Core.KeyPair       as KeyPair
import           Tox.Crypto.Core.Keyed         (Keyed (..), KeyedT,
                                                evalKeyedT)
import           Tox.DHT.DhtPacket             (DhtPacket (..))
import qualified Tox.DHT.DhtState              as DhtState
import           Tox.DHT.DhtState              (DhtState)
import           Tox.DHT.Operation             (DhtNodeMonad (..), initDht)
import qualified Tox.DHT.Server                as DHT
import qualified Tox.Onion.Operation           as Onion
import           Tox.Onion.Operation           (OnionNodeMonad (..))
import qualified Tox.Session.Connection        as Connection
import           Tox.Session.Connection        (ConnectionMonad (..))
import qualified Tox.Session.Friend            as Messenger
import qualified Tox.Transport.SecureSession   as SecureSession
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Crypto.Core.MonadRandomBytes  (MonadRandomBytes (..))
import           Tox.Network.Core.Networked         (Networked (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.Packet            (Packet (..), RawPayload(..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TimedT            (runTimedT)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

data ToxNodeJSON = ToxNodeJSON
    { jsonIpv4      :: Maybe String
    , jsonIpv6      :: Maybe String
    , jsonPort      :: Int
    , jsonPublicKey :: String
    } deriving (Show, Generic)

instance FromJSON ToxNodeJSON where
    parseJSON = withObject "ToxNodeJSON" $ \v -> ToxNodeJSON
        <$> v .:? "ipv4"
        <*> v .:? "ipv6"
        <*> v .: "port"
        <*> v .: "public_key"

data NodesList = NodesList
    { nodes :: [ToxNodeJSON]
    } deriving (Show, Generic)

instance FromJSON NodesList

parsePublicKey :: String -> Maybe PublicKey
parsePublicKey s = do
    let bs = BS8.pack $ take 64 s
    case Base16.decode bs of
        Left _        -> Nothing
        Right decoded -> Key.Key <$> Sodium.decode decoded

resolveNode :: ToxNodeJSON -> IO [NodeInfo]
resolveNode j = do
    let mPk = parsePublicKey (jsonPublicKey j)
        port = fromIntegral (jsonPort j)
    case mPk of
        Nothing -> return []
        Just pk -> do
            let addrs = catMaybes [jsonIpv4 j]
            fmap concat $ forM addrs $ \addrStr -> do
                if addrStr == "-" then return []
                else do
                    case (readMaybe addrStr :: Maybe IP.IPv4) of
                        Just ip -> return [NodeInfo UDP (SocketAddress (IPv4 (IP.toHostAddress ip)) port) pk]
                        Nothing -> do
                            let hints = Socket.defaultHints { Socket.addrSocketType = Socket.Datagram, Socket.addrFamily = Socket.AF_INET }
                            res <- Socket.getAddrInfo (Just hints) (Just addrStr) (Just $ show (jsonPort j))
                            return $ catMaybes $ flip map res $ \ai -> do
                                sa <- fromSockAddr (Socket.addrAddress ai)
                                return $ NodeInfo UDP sa pk

newtype ToxApp m a = ToxApp { unToxApp :: AppMonad m a }
    deriving (Functor, Applicative, Monad, MonadIO, MonadRandomBytes, Keyed, MonadReader (IORef GlobalState), Timed, Networked, DhtNodeMonad, OnionNodeMonad, ConnectionMonad, MonadLogger)

instance (MonadIO m, MonadRandomBytes m) => MonadState GlobalState (ToxApp m) where
    get = ask >>= liftIO . readIORef
    put s = ask >>= liftIO . flip writeIORef s

dispatchAll :: (MonadIO m, MonadRandomBytes m) => NodeInfo -> Packet RawPayload -> ToxApp m ()
dispatchAll from pktRaw = ToxApp $ do
    gs <- get
    let pkt = fmap unRawPayload pktRaw
        cm = connManager gs
        ds = dhtState gs
        addr = NodeInfo.address from
        -- Get 32 closest nodes to use for Onion responses
        dhtNodes = DhtState.takeClosestNodesTo 32 (KeyPair.publicKey $ DhtState.dhtKeyPair ds) ds
        
        -- Fallback: search all friends for a matching address
        mFriendByAddr = 
            let matching = [ (realPk, f) 
                           | (realPk, f) <- Map.toList (Connection.friends cm)
                           , matchesAddr f ]
                matchesAddr f = case Connection.fcStatus f of
                    Connection.FriendKeyFound _ relays -> any (\r -> NodeInfo.address r == addr) relays
                    Connection.FriendConnecting ss -> NodeInfo.address (SecureSession.ssPeerNodeInfo ss) == addr
                    Connection.FriendConnected ss -> NodeInfo.address (SecureSession.ssPeerNodeInfo ss) == addr
                    _ -> False
            in case matching of
                (x:_) -> Just x
                [] -> Nothing

    case packetKind pkt of
        k | k `elem` [PacketKind.PingRequest, PacketKind.PingResponse, PacketKind.NodesRequest, PacketKind.NodesResponse, PacketKind.Crypto] -> 
            DHT.handleIncomingPacket from pkt
        
        k | k `elem` [PacketKind.OnionRequest0, PacketKind.OnionRequest1, PacketKind.OnionRequest2, PacketKind.OnionResponse1, PacketKind.OnionResponse2, PacketKind.OnionResponse3, PacketKind.AnnounceResponse, PacketKind.OnionDataRequest, PacketKind.OnionDataResponse, PacketKind.DHTPKPacket] -> 
            Onion.handleOnionPacket dhtNodes from pkt
        
        PacketKind.CookieRequest -> -- [uint8_t 24][sender_dht_pk(32)]...
            SecureSession.handleCookieRequest (Connection.cookieKey cm) (DhtState.dhtKeyPair $ dhtState gs) from (packetPayload pkt)

        k | k `elem` [PacketKind.CookieResponse, PacketKind.CryptoHandshake, PacketKind.CryptoData] -> do
            case mFriendByAddr of
                Just (realPk, fc) -> case Connection.fcStatus fc of
                    Connection.FriendConnecting ss -> do
                        ( (), ss' ) <- runStateT (SecureSession.handlePacket (Connection.cookieKey cm) from pkt) ss
                        updateFriend realPk (fc { Connection.fcStatus = Connection.FriendConnecting ss' })
                    Connection.FriendConnected ss -> do
                        ( (), ss' ) <- runStateT (SecureSession.handlePacket (Connection.cookieKey cm) from pkt) ss
                        updateFriend realPk (fc { Connection.fcStatus = Connection.FriendConnected ss' })
                    _ -> return ()
                Nothing -> return ()
        _ -> return ()

  where
    updateFriend pk fc = modify $ \gs -> 
        gs { connManager = (connManager gs) { Connection.friends = Map.insert pk fc (Connection.friends (connManager gs)) } }

data ToxOptions = ToxOptions
    { optFriendPk     :: Maybe String
    , optPort         :: Int
    , optBootstrapUrl :: String
    , optSeed         :: Maybe Int
    }

toxOptions :: Parser ToxOptions
toxOptions = ToxOptions
    <$> optional (strOption
        ( long "friend"
       <> short 'f'
       <> metavar "PUBLIC_KEY"
       <> help "Friend's public key (hex) to search for" ))
    <*> option auto
        ( long "port"
       <> short 'p'
       <> metavar "PORT"
       <> help "Local UDP port to bind to (default: 0 for random)"
       <> value 0
       <> showDefault )
    <*> strOption
        ( long "bootstrap-url"
       <> metavar "URL"
       <> help "URL to fetch bootstrap nodes from"
       <> value "https://nodes.tox.chat/json"
       <> showDefault )
    <*> optional (option auto
        ( long "seed"
       <> short 's'
       <> metavar "INT"
       <> help "Seed for deterministic identity generation" ))

main :: IO ()
main = do
    opts <- execParser optsInfo
    runToxNode opts
  where
    optsInfo = info (toxOptions <**> helper)
      ( fullDesc
     <> progDesc "Start a full Tox node in Haskell"
     <> header "tox-dht-node - a cleanroom Tox implementation" )

runToxNode :: ToxOptions -> IO ()
runToxNode opts = runResourceT $ do
    liftIO $ hSetBuffering stdout LineBuffering
    let mFriendPk = optFriendPk opts >>= parsePublicKey
        bootstrapUrl = optBootstrapUrl opts

    liftIO $ putStrLn $ "Fetching nodes from " ++ bootstrapUrl ++ "..."
    req <- parseRequest bootstrapUrl
    res <- httpLBS req
    let mNodes = decode (getResponseBody res) :: Maybe NodesList
    allNodes <- case mNodes of
        Nothing -> do
            liftIO $ putStrLn "Failed to parse nodes JSON"
            return []
        Just nl -> liftIO $ fmap concat $ mapM resolveNode (take 4 $ nodes nl)

    liftIO $ putStrLn $ "Resolved " ++ show (length allNodes) ++ " nodes"

    seed <- case optSeed opts of
        Just s -> return s
        Nothing -> liftIO randomIO
    liftIO $ putStrLn $ "Using seed: " ++ show seed
    let gen = mkStdGen seed

    sock <- liftIO $ Socket.socket Socket.AF_INET Socket.Datagram Socket.defaultProtocol
    liftIO $ Socket.bind sock (Socket.SockAddrInet (fromIntegral $ optPort opts) 0)

    now <- liftIO getTime
    let (initialState, realKp) = runIdentity $ flip evalRandT gen $ do
            rk <- newKeyPair
            dk <- newKeyPair
            gs <- initState now dk rk sock
            return (gs, rk)
    stateRef <- liftIO $ newIORef initialState

    liftIO $ putStrLn "Starting full Tox node..."
    
    let ourPk = KeyPair.publicKey realKp
        ourNospam = Messenger.selfNospam $ messenger initialState
        
        -- Tox ID: [PK(32)][Nospam(4)][Checksum(2)]
        pkBytes = Sodium.encode ourPk
        nospamBytes = LBS.toStrict $ Binary.encode ourNospam
        idBody = pkBytes <> nospamBytes
        
        calculateChecksum bs = 
            let pairs [] = []
                pairs [x] = [(x, 0)]
                pairs (x:y:xs) = (x, y) : pairs xs
                xorBS b1 b2 = BS.pack $ BS.zipWith xor b1 b2
            in foldl xorBS (BS.pack [0,0]) [BS.pack [b1, b2] | (b1, b2) <- pairs (BS.unpack bs)]
            
        checksum = calculateChecksum idBody
        fullId = idBody <> checksum
    
    liftIO $ putStrLn $ "Our Tox ID: " ++ (BS8.unpack $ Base16.encode fullId)

    let runStack (ToxApp (AppMonad m)) = evalKeyedT (runStdoutLoggingT (runReaderT m stateRef)) Map.empty

    -- Start packet handler
    void $ liftIO $ forkIO $ runStack $ runConduit $
        udpSource sock .| decodePacket .| forever (do
            mInp <- await
            case mInp of
                Nothing -> return ()
                Just (addr, pkt) -> do
                    case fromSockAddr addr of
                        Just sa -> do
                            -- Try to identify sender PK from packet header
                            let senderPk = case packetKind pkt of
                                    k | k `elem` [PacketKind.PingRequest, PacketKind.PingResponse, PacketKind.NodesRequest, PacketKind.NodesResponse] ->
                                        case Binary.decodeOrFail (LBS.fromStrict (unRawPayload $ packetPayload pkt)) of
                                            Right (_, _, dhtPkt :: DhtPacket) -> senderPublicKey dhtPkt
                                            _ -> Key.Key (fromJust $ Sodium.decode $ BS.replicate 32 0)
                                    PacketKind.Crypto -> -- [addressee_pk(32)][sender_pk(32)][nonce(24)]...
                                        case Sodium.decode (BS.take 32 $ BS.drop 32 (unRawPayload $ packetPayload pkt)) of
                                            Just pk -> Key.Key pk
                                            Nothing -> Key.Key (fromJust $ Sodium.decode $ BS.replicate 32 0)
                                    PacketKind.CookieRequest -> -- [uint8_t 24][sender_dht_pk(32)]...
                                        case Sodium.decode (BS.take 32 (unRawPayload $ packetPayload pkt)) of
                                            Just pk -> Key.Key pk
                                            Nothing -> Key.Key (fromJust $ Sodium.decode $ BS.replicate 32 0)
                                    _ -> Key.Key (fromJust $ Sodium.decode $ BS.replicate 32 0) -- Null key for others
                            lift $ dispatchAll (NodeInfo UDP sa senderPk) pkt
                        Nothing -> return ()
        )

    -- Initial bootstrap
    liftIO $ runStack $ do
        forM_ allNodes $ \node -> do
            liftIO $ putStrLn $ "Bootstrapping from " ++ show node
            DHT.handleBootstrap node
        -- Initial maintenance to start onion search
        Connection.doFriendConnections

    -- Maintenance thread (2 seconds)
    void $ liftIO $ forkIO $ runStack $ forever $ do
        DHT.handleMaintenance
        gs <- get
        let nodes' = DhtState.takeClosestNodesTo 32 (KeyPair.publicKey $ DhtState.dhtKeyPair $ dhtState gs) (dhtState gs)
        Onion.doOnion nodes'
        Connection.doFriendConnections
        liftIO $ threadDelay 2000000

    -- Session maintenance thread (1 second)
    void $ liftIO $ forkIO $ runStack $ forever $ do
        gs <- get
        let friends' = Connection.friends (connManager gs)
        forM_ (Map.toList friends') $ \(pk, fc) -> do
            case Connection.fcStatus fc of
                Connection.FriendConnecting ss -> do
                    ( (), ss' ) <- runStateT SecureSession.maintainSession ss
                    modify $ \gs' -> gs' { connManager = (connManager gs') { Connection.friends = Map.insert pk (fc { Connection.fcStatus = Connection.FriendConnecting ss' }) (Connection.friends (connManager gs')) } }
                Connection.FriendConnected ss -> do
                    ( (), ss' ) <- runStateT SecureSession.maintainSession ss
                    modify $ \gs' -> gs' { connManager = (connManager gs') { Connection.friends = Map.insert pk (fc { Connection.fcStatus = Connection.FriendConnected ss' }) (Connection.friends (connManager gs')) } }
                _ -> return ()
        liftIO $ threadDelay 1000000

    -- Add friend if PK provided
    case mFriendPk of
        Just fPk -> do
            liftIO $ runStack $ Connection.addFriend fPk
        Nothing -> return ()

    liftIO $ putStrLn "Entering main loop..."

    let loop :: Map PublicKey Connection.FriendStatus -> ToxApp IO ()
        loop lastStatusMap = do
            liftIO $ threadDelay 2000000 -- 2 seconds
            gs <- get
            let ds = dhtState gs
                cm = connManager gs
                os = onionState gs
                currentFriends = Connection.friends cm
            
            -- Print global stats occasionally
            liftIO $ putStrLn $ "[STATS] DHT Size: " ++ show (DhtState.size ds) ++ " | Onion Announced: " ++ show (Map.size $ Onion.announcedNodes os) ++ " | Onion Searching: " ++ show (Map.size $ Onion.searchNodes os)
            
            -- Check for friend status changes
            newStatusMap <- foldM checkFriendStatus lastStatusMap (Map.toList currentFriends)
            loop newStatusMap

        checkFriendStatus :: Map PublicKey Connection.FriendStatus -> (PublicKey, Connection.FriendConnection) -> ToxApp IO (Map PublicKey Connection.FriendStatus)
        checkFriendStatus lastMap (pk, fc) = do
            let status = Connection.fcStatus fc
                statusStr = case status of
                    Connection.FriendDisconnected -> "Disconnected"
                    Connection.FriendSearching -> "Searching (Onion)"
                    Connection.FriendKeyFound _ _ -> "Key Found (Starting Handshake)"
                    Connection.FriendConnecting _ -> "Connecting (Net Crypto Handshake)"
                    Connection.FriendConnected _ -> "CONNECTED (Live Session)"
            
            case Map.lookup pk lastMap of
                Just lastS | lastS == status -> return lastMap
                _ -> do
                    currTime <- askTime
                    liftIO $ putStrLn $ "[" ++ show currTime ++ "] [FRIEND] " ++ show pk ++ " changed status to: " ++ statusStr
                    return $ Map.insert pk status lastMap

    liftIO $ runStack $ loop Map.empty
