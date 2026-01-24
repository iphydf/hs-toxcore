{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StrictData                 #-}
module Tox.Application.State where

import           Control.Monad.State              (MonadState (..), gets,
                                                   modify)
import           Tox.Core.Time                    (Timestamp, getTime)
import           Tox.Crypto.Core.Key              (CombinedKey)
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import           Tox.Crypto.Core.KeyPair          (KeyPair)
import qualified Tox.DHT.DhtState                 as DhtState
import           Tox.DHT.DhtState                 (DhtState)
import qualified Tox.Onion.Operation              as Onion
import           Tox.Onion.Operation              (OnionState)
import qualified Tox.Session.Connection           as Connection
import           Tox.Session.Connection           (ConnectionManager)
import qualified Tox.Session.Friend               as Messenger
import           Tox.Session.Friend               (Messenger)

import           Control.Exception                (IOException, try)
import           Control.Monad.IO.Class           (MonadIO, liftIO)
import           Control.Monad.Logger             (LoggingT, MonadLogger,
                                                   logDebugN, runStdoutLoggingT)
import           Control.Monad.Reader             (MonadReader, ReaderT, ask,
                                                   runReaderT)
import           Control.Monad.Trans              (lift)
import qualified Data.Binary                      as Binary
import qualified Data.Binary.Put                  as Put
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Base16           as Base16
import qualified Data.ByteString.Lazy             as LBS
import           Data.IORef                       (IORef, readIORef, writeIORef)
import           Data.Text                        (pack)
import           Foreign.C.Error                  (Errno (..), eAFNOSUPPORT)
import           GHC.IO.Exception                 (IOErrorType (..), ioe_type)
import qualified Network.Socket                   as Socket
import qualified Network.Socket.ByteString        as SocketBS
import           Tox.Conduit.Network              (toSockAddr)
import           Tox.Core.Timed                   (Timed (..))
import           Tox.Crypto.Core.Keyed            (Keyed (..), KeyedT)
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes (..),
                                                   randomKey, randomWord32)
import           Tox.DHT.Operation                (DhtNodeMonad (..))
import           Tox.Network.Core.Networked       (Networked (..))
import           Tox.Network.Core.NodeInfo        (NodeInfo (..))
import           Tox.Network.Core.Packet          (Packet (..), RawPayload (..))
import qualified Tox.Onion.Operation              as Onion
import qualified Tox.Session.Connection           as Connection
import qualified Tox.Session.Friend               as Messenger

data GlobalState = GlobalState
  { dhtState    :: DhtState
  , onionState  :: OnionState
  , connManager :: ConnectionManager
  , messenger   :: Messenger
  , udpSocket   :: Socket.Socket
  }

initState :: MonadRandomBytes m => Timestamp -> KeyPair -> KeyPair -> Socket.Socket -> m GlobalState
initState now dhtKeys realKeys sock = do
  cKey <- randomKey
  nospam <- randomWord32
  return GlobalState
    { dhtState    = DhtState.empty now dhtKeys
    , onionState  = Onion.initState realKeys
    , connManager = Connection.initManager realKeys dhtKeys cKey
    , messenger   = Messenger.initMessenger nospam
    , udpSocket   = sock
    }

-- | Unified application monad.
newtype AppMonad m a = AppMonad { unAppMonad :: ReaderT (IORef GlobalState) (LoggingT (KeyedT m)) a }
    deriving (Functor, Applicative, Monad, MonadIO, MonadRandomBytes, Keyed, MonadReader (IORef GlobalState), MonadLogger)

instance MonadIO m => Timed (AppMonad m) where
    askTime = liftIO getTime

-- | Use the underlying IORef for the main MonadState.
instance (MonadIO m, MonadRandomBytes m) => MonadState GlobalState (AppMonad m) where
    get = ask >>= liftIO . readIORef
    put s = ask >>= liftIO . flip writeIORef s

-- | Instance for DHT layer.
instance (MonadIO m, MonadRandomBytes m) => DhtNodeMonad (AppMonad m) where
    getDhtState = gets dhtState
    putDhtState s = modify $ \gs -> gs { dhtState = s }
    handleDhtRequestPayload from dhtPkt = do
        Onion.onDhtRequestPayload from dhtPkt

-- | Instance for Onion layer.
instance (MonadIO m, MonadRandomBytes m) => Onion.OnionNodeMonad (AppMonad m) where
    getOnionState = gets onionState
    putOnionState s = modify $ \gs -> gs { onionState = s }
    getDhtKeyPair = gets (DhtState.dhtKeyPair . dhtState)

-- | Instance for Connection layer.
instance (MonadIO m, MonadRandomBytes m) => Connection.ConnectionMonad (AppMonad m) where
    getConnManager = gets connManager
    putConnManager s = modify $ \gs -> gs { connManager = s }

-- | Instance for Messenger layer.
instance (MonadIO m, MonadRandomBytes m) => Messenger.MessengerMonad (AppMonad m) where
    getMessenger = gets messenger
    putMessenger s = modify $ \gs -> gs { messenger = s }

-- | Implement Networked to actually send UDP packets.
instance (MonadIO m, MonadRandomBytes m) => Networked (AppMonad m) where
    sendPacket ni packet = do
        sock <- gets udpSocket
        let addr = toSockAddr (address ni)
            -- Use runPut to build the packet Kind + Payload without any prefixes
            bs = LBS.toStrict $ Put.runPut $ do
                Binary.put (packetKind packet)
                Binary.put (packetPayload packet)
        logDebugN $ "Sending packet to " <> pack (show addr) <> ": " <> pack (show $ packetKind packet) <> " (" <> pack (show $ BS.length bs) <> " bytes)"
        liftIO $ do
            res <- try $ SocketBS.sendTo sock bs addr
            case res of
                Left (e :: IOException) ->
                    -- Safely ignore "Address family not supported"
                    if ioe_type e == UnsupportedOperation
                    then return ()
                    else return () -- TODO: log other errors
                Right _ -> return ()
