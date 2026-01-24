{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | TCP relays through an HTTP CONNECT or SOCKS5 proxy without
-- authentication, as toxcore does, or through a WebSocket gateway, which is
-- how browsers reach them. Only TCP goes through it, so a client that wants
-- all its traffic there also turns UDP off.
module Tox.Application.Proxy
  ( Proxy (..)
  , ProxyType (..)
  , handshake
  , socks5Request
  , socks5ReplyLength
  , httpRequest
  , httpAccepted
  ) where

import           Control.Exception              (IOException, throwIO)
import           Control.Monad                  (unless, void)
import           Data.Bits                      (shiftR)
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as Char8
import           Data.IORef                     (modifyIORef', newIORef,
                                                 readIORef, writeIORef)
import           Data.Word                      (Word16, Word8)
import           Numeric                        (showHex)

import           Tox.Application.Transport      (Stream (..))
import           Tox.Network.Core.HostAddress   (HostAddress (..), halves,
                                                 hostAddressToTuple)
import           Tox.Network.Core.PortNumber    (PortNumber (..))
import           Tox.Network.Core.SocketAddress (SocketAddress (..))

data ProxyType
  = HttpProxy
  | Socks5Proxy
  | GatewayProxy
    -- ^ The only way browsers can reach relays.
  deriving (Eq, Show)

data Proxy = Proxy
  { proxyType :: ProxyType
  , proxyHost :: String
  , proxyPort :: Word16
  } deriving (Eq, Show)

-- | The stream we get back starts with whatever came after the proxy's
-- answer.
handshake :: ProxyType -> Stream -> SocketAddress -> IO Stream
handshake kind stream to = do
  pending <- newIORef BS.empty
  let -- More of what the proxy sent, or an error if it closed.
      more = streamReceive stream >>= \case
        chunk | BS.null chunk -> throwIO (userError "Proxy closed the connection" :: IOException)
              | otherwise -> modifyIORef' pending (<> chunk)
      -- Exactly this many bytes.
      receive n = readIORef pending >>= \got ->
        if BS.length got >= n
          then BS.take n got <$ writeIORef pending (BS.drop n got)
          else more >> receive n
      -- The HTTP reply header, up to its blank line.
      header = readIORef pending >>= \got -> case BS.breakSubstring "\r\n\r\n" got of
        (before, after)
          | not (BS.null after) -> before <$ writeIORef pending (BS.drop 4 after)
          | BS.length got > 4096 -> throwIO (userError "HTTP proxy reply too long")
          | otherwise -> more >> header
  case kind of
    Socks5Proxy -> do
      streamSend stream (BS.pack [5, 1, 0])
      method <- receive 2
      unless (method == BS.pack [5, 0]) $ refused "SOCKS5 proxy wants authentication"
      streamSend stream (socks5Request to)
      reply <- receive 5
      case socks5ReplyLength reply of
        Just rest -> void $ receive rest
        Nothing   -> refused "SOCKS5 proxy refused the connection"
    HttpProxy -> do
      streamSend stream (httpRequest to)
      reply <- header
      unless (httpAccepted reply) $ refused "HTTP proxy refused the connection"
    GatewayProxy -> refused "A gateway is no proxy for streams"
  rest <- readIORef pending
  return $ if BS.null rest then stream else stream
    { streamReceive = readIORef pending >>= \left ->
        if BS.null left then streamReceive stream else left <$ writeIORef pending BS.empty
    }
  where
    refused = throwIO . userError

-- | CONNECT to an IPv4 or IPv6 address.
socks5Request :: SocketAddress -> BS.ByteString
socks5Request (SocketAddress host (PortNumber port)) = BS.pack ([5, 1, 0] ++ address ++ port16 port)
  where
    address = case host of
      IPv4 a              -> 1 : tuple4 (hostAddressToTuple a)
      IPv6 (a, b, c, d) -> 4 : concatMap (concatMap port16 . halves) [a, b, c, d]
    tuple4 (a, b, c, d) = [a, b, c, d]

-- | Bytes of a successful reply after the first 5 (which give the address
-- kind), or Nothing if the proxy refused.
socks5ReplyLength :: BS.ByteString -> Maybe Int
socks5ReplyLength reply = case BS.unpack reply of
  [5, 0, _, 1, _] -> Just (4 + 2 - 1)
  [5, 0, _, 4, _] -> Just (16 + 2 - 1)
  [5, 0, _, 3, n] -> Just (fromIntegral n + 2)
  _               -> Nothing

httpRequest :: SocketAddress -> BS.ByteString
httpRequest (SocketAddress host (PortNumber port)) =
  "CONNECT " <> target <> " HTTP/1.1\r\nHost: " <> target <> "\r\n\r\n"
  where
    target = Char8.pack (name <> ":" <> show port)
    name = case host of
      IPv4 a -> let (b, c, d, e) = hostAddressToTuple a in
        show b <> "." <> show c <> "." <> show d <> "." <> show e
      IPv6 (a, b, c, d) ->
        "[" <> foldr1 (\x y -> x <> ":" <> y) [showHex x "" | x <- concatMap halves [a, b, c, d]] <> "]"

httpAccepted :: BS.ByteString -> Bool
httpAccepted header = case Char8.words (Char8.takeWhile (/= '\r') header) of
  version : "200" : _ -> "HTTP/1." `BS.isPrefixOf` version
  _                   -> False

port16 :: Word16 -> [Word8]
port16 p = [fromIntegral (p `shiftR` 8), fromIntegral p]
