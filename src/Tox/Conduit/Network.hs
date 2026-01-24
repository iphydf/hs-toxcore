{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes       #-}
module Tox.Conduit.Network where

import           Control.Monad                 (void)
import           Control.Monad.IO.Class        (MonadIO, liftIO)
import           Data.Binary                   (Binary)
import qualified Data.ByteString               as BS
import           Data.Conduit                  (ConduitT, await, yield)
import qualified Data.Conduit.List             as CL
import qualified Network.Socket                as Socket
import qualified Network.Socket.ByteString     as SocketBS

import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.Packet            (Packet (..))
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

-- | Convert Tox 'SocketAddress' to 'Socket.SockAddr'.
toSockAddr :: SocketAddress -> Socket.SockAddr
toSockAddr (SocketAddress (IPv4 addr) (PortNumber port)) =
    Socket.SockAddrInet (fromIntegral port) addr
toSockAddr (SocketAddress (IPv6 addr) (PortNumber port)) =
    Socket.SockAddrInet6 (fromIntegral port) 0 addr 0

-- | Convert 'Socket.SockAddr' to Tox 'SocketAddress'.
fromSockAddr :: Socket.SockAddr -> Maybe SocketAddress
fromSockAddr (Socket.SockAddrInet port addr) =
    Just $ SocketAddress (IPv4 addr) (fromIntegral port)
fromSockAddr (Socket.SockAddrInet6 port _ addr _) =
    Just $ SocketAddress (IPv6 addr) (fromIntegral port)
fromSockAddr _ = Nothing

-- | A conduit source that reads from a UDP socket.
udpSource :: MonadIO m => Socket.Socket -> ConduitT i (Socket.SockAddr, BS.ByteString) m ()
udpSource sock = do
    (bs, addr) <- liftIO $ SocketBS.recvFrom sock 4096
    yield (addr, bs)
    udpSource sock

-- | A conduit sink that writes to a UDP socket.
udpSink :: MonadIO m => Socket.Socket -> ConduitT (Socket.SockAddr, BS.ByteString) o m ()
udpSink sock = CL.mapM_ $ \(addr, bs) ->
    liftIO $ void $ SocketBS.sendTo sock bs addr
