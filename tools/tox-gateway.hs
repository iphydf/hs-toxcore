{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Lets browsers reach Tox's TCP relays: a WebSocket at @/address/port@
-- for each connection, its bytes passed to and from that relay.
--
-- It's no proxy for anything else: the browser's first bytes must be a
-- relay handshake, the relay must answer with one before anything goes
-- back, and only public addresses are reached (with @--local@, also this
-- machine's and its network's, for tests). It listens on @$PORT@, or 8080.
module Main (main) where

import           Control.Concurrent.Async       (race_)
import           Control.Exception              (Handler (..), IOException,
                                                 bracket, catches)
import           Control.Monad                  (when)
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as Char8
import           Data.IORef                     (atomicModifyIORef', newIORef)
import           Data.Maybe                     (fromMaybe)
import qualified Network.Socket                 as Socket
import qualified Network.Socket.ByteString      as SocketBS
import qualified Network.WebSockets             as WS
import           System.Environment             (getArgs, lookupEnv)
import           System.IO                      (hPutStrLn, stderr)
import           System.Timeout                 (timeout)
import           Text.Read                      (readMaybe)

import qualified Tox.Application.Sockets        as Sockets
import           Tox.Network.Core.HostAddress   (HostAddress (..), isLan,
                                                 readAddress)
import           Tox.Network.Core.PortNumber    (PortNumber (..))
import           Tox.Network.Core.SocketAddress (SocketAddress (..))
import qualified Tox.Network.TCP.Client         as Client
import qualified Tox.Network.TCP.Server         as Server

-- | Connections at once. Each holds a socket and two threads.
maxConnections :: Int
maxConnections = 1024

-- | Bytes in a WebSocket message. A relay's packets are under 2 KiB.
maxMessage :: Int
maxMessage = 65536

-- | Microseconds for the relay to take the connection and answer the
-- handshake, as the client waits that long for it.
handshakeTime :: Int
handshakeTime = 10000000

readSize :: Int
readSize = 4096

main :: IO ()
main = do
  local <- elem "--local" <$> getArgs
  port <- fromMaybe 8080 . (>>= readMaybe) <$> lookupEnv "PORT"
  open <- newIORef (0 :: Int)
  let options = WS.defaultConnectionOptions
        { WS.connectionMessageDataSizeLimit = WS.SizeLimit (fromIntegral maxMessage)
        , WS.connectionFramePayloadSizeLimit = WS.SizeLimit (fromIntegral maxMessage)
        }
      taking = bracket (atomicModifyIORef' open (\n -> (n + 1, n))) (const $ atomicModifyIORef' open (\n -> (n - 1, ())))
  hPutStrLn stderr $ "Listening on " <> show port
  WS.runServerWithOptions WS.defaultServerOptions { WS.serverHost = "0.0.0.0", WS.serverPort = port, WS.serverConnectionOptions = options } $ \pending ->
    case relayOf (WS.requestPath (WS.pendingRequest pending)) of
      Just relay@(SocketAddress host _) | local || not (isLan host) -> taking $ \n ->
        if n >= maxConnections
          then WS.rejectRequest pending "Too many connections"
          else WS.acceptRequest pending >>= quietly . passing relay
      _ -> WS.rejectRequest pending "No relay there"

-- | The relay a path names.
relayOf :: BS.ByteString -> Maybe SocketAddress
relayOf path = case Char8.split '/' path of
  ["", address, port] -> SocketAddress
    <$> readAddress (Char8.unpack address)
    <*> (PortNumber <$> readMaybe (Char8.unpack port))
  _ -> Nothing

-- | A connection ends when either side goes.
quietly :: IO () -> IO ()
quietly action = action `catches`
  [ Handler $ \(_ :: IOException) -> return ()
  , Handler $ \(_ :: WS.ConnectionException) -> return ()
  ]

-- | The handshakes, then everything both ways until either side closes.
passing :: SocketAddress -> WS.Connection -> IO ()
passing relay@(SocketAddress host _) conn = do
  hello <- receiveAtLeast Server.clientHandshakeLength BS.empty
  when (BS.length hello == Server.clientHandshakeLength) $
    bracket (Socket.socket family Socket.Stream Socket.defaultProtocol) Socket.close $ \sock -> do
      answer <- timeout handshakeTime $ do
        Socket.connect sock (Sockets.toSockAddr relay)
        SocketBS.sendAll sock hello
        relayAtLeast sock Client.serverHandshakeLength BS.empty
      case answer of
        Just bytes | BS.length bytes >= Client.serverHandshakeLength -> do
          WS.sendBinaryData conn bytes
          race_ (toRelay sock) (fromRelay sock)
        _ -> return ()
  WS.sendClose conn BS.empty
  where
    family = case host of
      IPv4 _ -> Socket.AF_INET
      IPv6 _ -> Socket.AF_INET6
    -- The browser's bytes, until there are this many.
    receiveAtLeast n got
      | BS.length got >= n = return got
      | otherwise = WS.receiveData conn >>= receiveAtLeast n . (got <>)
    relayAtLeast sock n got
      | BS.length got >= n = return got
      | otherwise = SocketBS.recv sock readSize >>= \case
          chunk | BS.null chunk -> return got
                | otherwise -> relayAtLeast sock n (got <> chunk)
    toRelay sock = WS.receiveData conn >>= SocketBS.sendAll sock >> toRelay sock
    fromRelay sock = SocketBS.recv sock readSize >>= \case
      chunk | BS.null chunk -> return ()
            | otherwise -> WS.sendBinaryData conn chunk >> fromRelay sock
