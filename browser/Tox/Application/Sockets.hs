{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | The shell's transport in browsers, which have no sockets: TCP relays
-- through a WebSocket gateway, and no UDP. The gateway takes a WebSocket at
-- @/address/port@ for each relay connection and passes the bytes both
-- ways. Without a proxy, the page names the gateway in
-- @globalThis.toxGateway@, as a base URL like @wss://example.org@.
module Tox.Application.Sockets
  ( datagramsAvailable
  , openDatagrams
  , connect
  , listen
  , resolve
  ) where

import           Control.Exception              (evaluate, handle, throwIO)
import qualified Data.ByteString.Internal       as BS
import qualified Data.ByteString.Unsafe         as BS
import           Data.Maybe                     (maybeToList)
import           Data.Word                      (Word16, Word8)
import           Foreign.Ptr                    (Ptr, castPtr)
import           GHC.Wasm.Prim                  (JSException, JSString (..),
                                                 JSVal, fromJSString,
                                                 toJSString)

import           Tox.Application.Proxy          (Proxy (..), ProxyType (..))
import           Tox.Application.Transport      (Datagrams, Listener,
                                                 Stream (..))
import           Tox.Network.Core.HostAddress   (readAddress, showAddress)
import           Tox.Network.Core.PortNumber    (PortNumber (..))
import           Tox.Network.Core.SocketAddress (SocketAddress (..))

datagramsAvailable :: Bool
datagramsAvailable = False

openDatagrams :: Bool -> [Word16] -> IO (Maybe (Datagrams, Bool))
openDatagrams _ _ = return Nothing

-- | Sending waits once the browser holds this many of our bytes, like a
-- socket's system buffer.
sendBuffer :: Int
sendBuffer = 65536

-- Sending copies our bytes before it waits, because the call returns to
-- Haskell then. A wait only ends (and throws) once its result is evaluated.

foreign import javascript safe
  "const s = {ws: new WebSocket($1), chunks: [], closed: false, wake: () => {}};\
  \s.ws.binaryType = 'arraybuffer';\
  \const woken = () => { const wake = s.wake; s.wake = () => {}; wake(); };\
  \s.ws.onmessage = e => { s.chunks.push(new Uint8Array(e.data)); woken(); };\
  \s.ws.onclose = () => { s.closed = true; woken(); };\
  \await new Promise((resolve, reject) => {\
  \  s.ws.onopen = resolve;\
  \  s.ws.onerror = () => reject(new Error('No connection to the gateway'));\
  \});\
  \s.ws.onerror = null;\
  \return s;"
  js_open :: JSString -> IO JSVal

-- | Empty once the socket closed.
foreign import javascript safe
  "const s = $1;\
  \while (s.chunks.length === 0 && !s.closed) await new Promise(resolve => { s.wake = resolve; });\
  \return s.chunks.length > 0 ? s.chunks.shift() : new Uint8Array(0);"
  js_receive :: JSVal -> IO JSVal

foreign import javascript safe
  "const s = $1;\
  \if (s.closed) throw new Error('Closed');\
  \s.ws.send(new Uint8Array(__exports.memory.buffer, $2, $3).slice());\
  \while (s.ws.bufferedAmount > $4 && !s.closed) await new Promise(resolve => setTimeout(resolve, 10));"
  js_send :: JSVal -> Ptr Word8 -> Int -> Int -> IO ()

foreign import javascript unsafe "globalThis.toxGateway === undefined ? '' : globalThis.toxGateway"
  js_pageGateway :: IO JSString

foreign import javascript unsafe "$1.ws.close()"
  js_close :: JSVal -> IO ()

foreign import javascript unsafe "$1.length"
  js_length :: JSVal -> IO Int

foreign import javascript unsafe "new Uint8Array(__exports.memory.buffer, $2, $1.length).set($1)"
  js_copy :: JSVal -> Ptr Word8 -> IO ()

connect :: Maybe Proxy -> SocketAddress -> IO Stream
connect proxy (SocketAddress address (PortNumber to)) = do
  gateway <- case proxy of
    Just (Proxy GatewayProxy host port) ->
      let scheme = if host `elem` ["localhost", "127.0.0.1", "::1"] then "ws" else "wss"
      in return $ scheme <> "://" <> host <> ":" <> show port
    Just _ -> throwIO (userError "Browsers reach relays only through a gateway")
    Nothing -> fromJSString <$> js_pageGateway >>= \case
      ""   -> throwIO (userError "The page names no gateway")
      page -> return page
  ws <- failing $ evaluate =<< js_open (toJSString (gateway <> "/" <> showAddress address <> "/" <> show to))
  return Stream
    { streamReceive = failing $ js_receive ws >>= \chunk -> js_length chunk >>= \n -> BS.create n (js_copy chunk)
    , streamSend = \bytes -> BS.unsafeUseAsCStringLen bytes $ \(ptr, len) ->
        failing $ evaluate =<< js_send ws (castPtr ptr) len sendBuffer
    , streamClose = js_close ws
    }

-- | The shell takes an IOException as the connection failing.
failing :: IO a -> IO a
failing = handle $ \(e :: JSException) -> throwIO (userError (show e))

listen :: Bool -> Word16 -> IO Listener
listen _ _ = throwIO (userError "Browsers can't run a relay")

-- | Browsers can't look up host names.
resolve :: String -> Word16 -> IO [SocketAddress]
resolve host port = return [ SocketAddress address (fromIntegral port) | address <- maybeToList (readAddress host) ]
