{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes       #-}
module Tox.Conduit.Encoding where

import           Control.Monad             (forever)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Data.Binary               (Binary, get, put)
import           Data.Binary.Get           (getRemainingLazyByteString,
                                            runGetOrFail)
import           Data.Binary.Put           (putByteString, runPut)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as LBS
import           Data.Conduit              (ConduitT, await, yield)
import qualified Network.Socket            as Socket

import           Tox.Conduit.Network       (toSockAddr)
import           Tox.Network.Core.NodeInfo (NodeInfo (..))
import           Tox.Network.Core.Packet   (Packet (..))

-- | Decodes raw UDP packets into Tox packets, keeping the sender's address.
decodePacket :: MonadIO m
             => ConduitT (Socket.SockAddr, BS.ByteString) (Socket.SockAddr, Packet BS.ByteString) m ()
decodePacket = forever $ do
    mInp <- await
    case mInp of
        Nothing -> return ()
        Just (addr, bs) -> do
            liftIO $ putStrLn $ "Raw packet from " ++ show addr ++ " (" ++ show (BS.length bs) ++ " bytes)"
            case runGetOrFail getPacket (LBS.fromStrict bs) of
                Right (_, _, pkt) -> yield (addr, pkt)
                Left _ -> liftIO $ putStrLn "Failed to decode packet kind"
  where
    getPacket = Packet <$> get <*> (LBS.toStrict <$> getRemainingLazyByteString)

-- | Encodes Tox packets into raw UDP packets.
encodePacket :: MonadIO m
             => ConduitT (NodeInfo, Packet BS.ByteString) (Socket.SockAddr, BS.ByteString) m ()
encodePacket = forever $ do
    mInp <- await
    case mInp of
        Nothing -> return ()
        Just (ni, Packet kind payload) -> do
            let addr = toSockAddr (address ni)
            let bs = LBS.toStrict $ runPut $ put kind >> putByteString payload
            liftIO $ putStrLn $ "Sending packet to " ++ show addr ++ " (" ++ show (BS.length bs) ++ " bytes)"
            yield (addr, bs)
