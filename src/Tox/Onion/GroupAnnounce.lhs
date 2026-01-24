\begin{code}
{-# LANGUAGE StrictData #-}
-- | How to reach a group peer, as it announces itself to onion nodes (which
-- keep it for the group) and to peers in a SYNC_RESPONSE.
module Tox.Onion.GroupAnnounce
  ( Announce (..)
  , packAnnounce
  , unpackAnnounce
  , unpackAnnounces
  ) where

import           Control.Monad                      (guard)
import qualified Data.Binary                        as Binary
import           Data.Binary.Get                    (Get, getWord8,
                                                     runGetOrFail)
import           Data.Binary.Put                    (putWord8, runPut)
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as LBS
import           Data.Word                          (Word8)
import           Tox.Crypto.Core.Key                (PublicKey)
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo)
import qualified Tox.Network.Core.SocketAddress     as SocketAddress
import           Tox.Network.Core.SocketAddress     (SocketAddress)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))

-- | Peer address and a relay it uses.
data Announce = Announce
  { anPk    :: PublicKey
  , anAddr  :: Maybe SocketAddress
  , anRelay :: Maybe NodeInfo
  } deriving (Eq, Show)

maxAnnouncedRelays :: Word8
maxAnnouncedRelays = 1

packAnnounce :: Announce -> ByteString
packAnnounce a = LBS.toStrict . runPut $ do
  Binary.put (anPk a)
  putWord8 (maybe 0 (const 1) $ anAddr a)
  putWord8 (maybe 0 (const 1) $ anRelay a)
  mapM_ (SocketAddress.putSocketAddress UDP) (anAddr a)
  mapM_ Binary.put (anRelay a)

unpackAnnounce :: ByteString -> Maybe Announce
unpackAnnounce = fmap fst . unpackOne

-- | One after another, as in announce responses.
unpackAnnounces :: ByteString -> Maybe [Announce]
unpackAnnounces bs
  | BS.null bs = Just []
  | otherwise = do
      (a, rest) <- unpackOne bs
      (a :) <$> unpackAnnounces rest

unpackOne :: ByteString -> Maybe (Announce, ByteString)
unpackOne bs = case runGetOrFail getAnnounce (LBS.fromStrict bs) of
  Right (rest, _, a) -> Just (a, LBS.toStrict rest)
  Left _             -> Nothing

getAnnounce :: Get Announce
getAnnounce = do
  pk <- Binary.get
  hasAddr <- getWord8
  relays <- getWord8
  guard $ relays <= maxAnnouncedRelays
  addr <- if hasAddr /= 0 then Just <$> udpAddress else return Nothing
  relay <- if relays /= 0 then Just <$> Binary.get else return Nothing
  return $ Announce pk addr (relay >>= \n -> if NodeInfo.protocol n == TCP then Just n else Nothing)
  where
    udpAddress = do
      (protocol, addr) <- SocketAddress.getSocketAddress
      guard $ protocol == UDP
      return addr
\end{code}
