{-# LANGUAGE StrictData #-}
-- | What the shell sends and receives through: datagrams, byte streams to
-- and from TCP relays, and connections to our own relay. Tox.Application.Sockets
-- makes them, with the system's sockets or, in browsers, WebSockets.
module Tox.Application.Transport
  ( Datagrams (..)
  , Stream (..)
  , Listener (..)
  ) where

import qualified Data.ByteString                as BS
import           Data.Word                      (Word16)

import           Tox.Network.Core.SocketAddress (SocketAddress)

data Datagrams = Datagrams
  { datagramsPort    :: Word16
  , datagramsSend    :: SocketAddress -> BS.ByteString -> IO ()
  , datagramsReceive :: IO (SocketAddress, BS.ByteString)
  , datagramsClose   :: IO ()
  }

data Stream = Stream
  { streamReceive :: IO BS.ByteString -- ^ Empty once the other side closed it.
  , streamSend    :: BS.ByteString -> IO ()
  , streamClose   :: IO ()
  }

-- | Connections to our own TCP relay.
data Listener = Listener
  { listenerAccept :: IO Stream
  , listenerClose  :: IO ()
  }
