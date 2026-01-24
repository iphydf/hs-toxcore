{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}
-- | The shell's transport through the system's sockets.
module Tox.Application.Sockets
  ( datagramsAvailable
  , openDatagrams
  , connect
  , listen
  , resolve
  , toSockAddr
  , fromSockAddr
  ) where

import           Control.Exception              (IOException, bracketOnError,
                                                 onException, throwIO, try)
import           Data.Maybe                     (mapMaybe)
import           Data.Word                      (Word16)
import qualified Network.Socket                 as Socket
import qualified Network.Socket.ByteString      as SocketBS

import           Tox.Application.Proxy          (Proxy (..), ProxyType (..),
                                                 handshake)
import           Tox.Application.Transport      (Datagrams (..), Listener (..),
                                                 Stream (..))
import           Tox.Network.Core.HostAddress   (HostAddress (..),
                                                 hostAddressToTuple,
                                                 tupleToHostAddress)
import           Tox.Network.Core.PortNumber    (PortNumber (..))
import           Tox.Network.Core.SocketAddress (SocketAddress (..))
import qualified Tox.Network.TCP.Server         as Server

datagramsAvailable :: Bool
datagramsAvailable = True

readSize :: Int
readSize = 4096

relaySendBuffer :: Int
relaySendBuffer = 65536

-- | The 'Bool' says whether the socket is dual-stack (if asked for, and the
-- system has IPv6).
openDatagrams :: Bool -> [Word16] -> IO (Maybe (Datagrams, Bool))
openDatagrams wantIpv6 ports = do
  (sock, ipv6) <- if wantIpv6
    then try (dualStackSocket Socket.Datagram) >>= \case
      Right sock              -> return (sock, True)
      Left (_ :: IOException) -> ipv4Socket
    else ipv4Socket
  let bindFirst [] = return False
      bindFirst (port : rest) = try (Socket.bind sock (anyAddress ipv6 port)) >>= \case
        Left (_ :: IOException) -> bindFirst rest
        Right ()                -> return True
  bindFirst ports >>= \case
    False -> Nothing <$ Socket.close sock
    True -> do
      Socket.setSocketOption sock Socket.Broadcast 1
      port <- Socket.socketPort sock
      let receive = SocketBS.recvFrom sock readSize >>= \(bs, from) ->
            maybe receive (return . (, bs)) (fromSockAddr from)
          send to bs = () <$ SocketBS.sendTo sock bs ((if ipv6 then toSockAddr6 else toSockAddr) to)
      return $ Just (Datagrams (fromIntegral port) send receive (Socket.close sock), ipv6)
  where
    ipv4Socket = (, False) <$> Socket.socket Socket.AF_INET Socket.Datagram Socket.defaultProtocol

anyAddress :: Bool -> Word16 -> Socket.SockAddr
anyAddress True port  = Socket.SockAddrInet6 (fromIntegral port) 0 (0, 0, 0, 0) 0
anyAddress False port = Socket.SockAddrInet (fromIntegral port) 0

dualStackSocket :: Socket.SocketType -> IO Socket.Socket
dualStackSocket ty = do
  sock <- Socket.socket Socket.AF_INET6 ty Socket.defaultProtocol
  Socket.setSocketOption sock Socket.IPv6Only 0
  return sock

streamOf :: Socket.Socket -> Stream
streamOf sock = Stream (SocketBS.recv sock readSize) (SocketBS.sendAll sock) (Socket.close sock)

connect :: Maybe Proxy -> SocketAddress -> IO Stream
connect proxy to = do
  (sock, through) <- case proxy of
    Nothing -> (\sock -> (sock, return)) <$> connected (toSockAddr to)
    Just (Proxy GatewayProxy _ _) -> throwIO (userError "Only browsers reach relays through a gateway")
    Just (Proxy kind host port) -> do
      info : _ <- Socket.getAddrInfo
        (Just Socket.defaultHints { Socket.addrSocketType = Socket.Stream })
        (Just host) (Just (show port))
      (\sock -> (sock, \stream -> handshake kind stream to)) <$> connected (Socket.addrAddress info)
  flip onException (Socket.close sock) $ do
    -- Small system buffer, so we answer the relay's pings in time on
    -- a slow link.
    Socket.setSocketOption sock Socket.SendBuffer relaySendBuffer
    through (streamOf sock)

connected :: Socket.SockAddr -> IO Socket.Socket
connected to = bracketOnError (Socket.socket family Socket.Stream Socket.defaultProtocol) Socket.close $ \sock ->
  sock <$ Socket.connect sock to
  where
    family = case to of
      Socket.SockAddrInet6 {} -> Socket.AF_INET6
      _                       -> Socket.AF_INET

-- | Dual-stack if the UDP socket is.
listen :: Bool -> Word16 -> IO Listener
listen ipv6 port = do
  listener <- if ipv6
    then dualStackSocket Socket.Stream
    else Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
  flip onException (Socket.close listener) $ do
    Socket.setSocketOption listener Socket.ReuseAddr 1
    Socket.bind listener (anyAddress ipv6 port)
    Socket.listen listener Server.maxIncoming
  return $ Listener (streamOf . fst <$> Socket.accept listener) (Socket.close listener)

resolve :: String -> Word16 -> IO [SocketAddress]
resolve host port = do
  let hints = Socket.defaultHints { Socket.addrSocketType = Socket.Datagram }
  result <- try $ Socket.getAddrInfo (Just hints) (Just host) (Just $ show port)
  return $ case result of
    Left (_ :: IOException) -> []
    Right infos             -> mapMaybe (fromSockAddr . Socket.addrAddress) infos

toSockAddr :: SocketAddress -> Socket.SockAddr
toSockAddr (SocketAddress (IPv4 addr) (PortNumber port)) =
    Socket.SockAddrInet (fromIntegral port) (Socket.tupleToHostAddress (hostAddressToTuple addr))
toSockAddr (SocketAddress (IPv6 addr) (PortNumber port)) =
    Socket.SockAddrInet6 (fromIntegral port) 0 addr 0

-- | IPv4 addresses become mapped IPv6 ones, for a dual-stack socket.
toSockAddr6 :: SocketAddress -> Socket.SockAddr
toSockAddr6 (SocketAddress (IPv4 addr) (PortNumber port)) =
    Socket.SockAddrInet6 (fromIntegral port) 0 (0, 0, 0xffff, v4) 0
  where
    (a, b, c, d) = hostAddressToTuple addr
    v4 = foldl (\acc o -> acc * 256 + fromIntegral o) 0 [a, b, c, d]
toSockAddr6 sa = toSockAddr sa

-- | Mapped IPv4 addresses come back as plain IPv4.
fromSockAddr :: Socket.SockAddr -> Maybe SocketAddress
fromSockAddr (Socket.SockAddrInet port addr) =
    Just $ SocketAddress (IPv4 (tupleToHostAddress (Socket.hostAddressToTuple addr))) (fromIntegral port)
fromSockAddr (Socket.SockAddrInet6 port _ (0, 0, 0xffff, v4) _) =
    Just $ SocketAddress (IPv4 $ tupleToHostAddress (byte 24, byte 16, byte 8, byte 0)) (fromIntegral port)
  where
    byte n = fromIntegral (v4 `div` (2 ^ (n :: Int)))
fromSockAddr (Socket.SockAddrInet6 port _ addr _) =
    Just $ SocketAddress (IPv6 addr) (fromIntegral port)
fromSockAddr _ = Nothing
