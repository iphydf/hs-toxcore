{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE StrictData            #-}
{-# LANGUAGE OverloadedStrings     #-}

module Tox.Transport.SecureSession.Manager where

import           Control.Monad.State            (MonadState, gets, modify, runStateT)
import           Data.Map                       (Map)
import qualified Data.Map                       as Map
import           Data.ByteString                (ByteString)

import           Tox.Crypto.Core.Key            (PublicKey, CombinedKey)
import           Tox.Crypto.Core.KeyPair        (KeyPair)
import           Tox.Network.Core.NodeInfo      (NodeInfo)
import qualified Tox.Network.Core.NodeInfo      as NodeInfo
import           Tox.Network.Core.Packet        (Packet (..))
import qualified Tox.Network.Core.PacketKind    as PacketKind
import           Tox.Transport.SecureSession    (SecureSessionState, handlePacket, handleCookieRequest)
import           Tox.Network.Core.Networked     (Networked)
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)
import           Tox.Core.Timed                 (Timed)
import           Tox.Crypto.Core.Keyed          (Keyed)

data SessionManager = SessionManager
  { sessionsByPk :: Map PublicKey SecureSessionState
  , cookieKey    :: CombinedKey
  , ourDhtKeyPair :: KeyPair
  }

-- | Handle an incoming packet, dispatching to the correct session.
dispatchPacket :: (Timed m, MonadRandomBytes m, Keyed m, Networked m, MonadState SessionManager m)
               => NodeInfo -> Packet ByteString -> m ()
dispatchPacket from pkt@(Packet kind payload) = case kind of
  PacketKind.CookieRequest -> do
    ck <- gets cookieKey
    dk <- gets ourDhtKeyPair
    handleCookieRequest ck dk from payload
  _ -> do
    let pk = NodeInfo.publicKey from
    mSession <- gets (Map.lookup pk . sessionsByPk)
    case mSession of
      Nothing -> return ()
      Just session -> do
        ck <- gets cookieKey
        ( (), session' ) <- runStateT (handlePacket ck from pkt) session
        modify $ \s -> s { sessionsByPk = Map.insert pk session' (sessionsByPk s) }