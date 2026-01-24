{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StrictData                 #-}

-- | Abstraction layer for network functionality.
--
-- The intention is to
--   (i) separate the logic of the protocol from its binary encoding, and
--   (ii) allow a simulated network in place of actual network IO.
module Tox.Network.Core.Networked where

import           Control.Monad.Random         (RandT)
import           Control.Monad.Reader         (ReaderT)
import           Control.Monad.State          (MonadState, StateT)
import           Control.Monad.Trans.Class    (lift)
import           Control.Monad.Writer         (WriterT, execWriterT, runWriterT,
                                               tell)
import           Data.Binary                  (Binary, encode)
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as LBS

import           Tox.Core.Timed               (Timed)
import           Tox.Crypto.Core.Keyed             (KeyedT)
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)
import           Tox.Network.Core.NodeInfo         (NodeInfo)
import           Tox.Network.Core.Packet           (Packet (..))

class Monad m => Networked m where
  sendPacket :: (Binary payload, Show payload) => NodeInfo -> Packet payload -> m ()

instance Networked m => Networked (KeyedT m) where
  sendPacket = (lift .) . sendPacket

-- | actual network IO
instance Networked (StateT NetworkState IO) where
  -- | TODO
  sendPacket _ _ = return ()

-- | TODO: sockets etc
type NetworkState = ()

data NetworkAction = SendPacket NodeInfo (Packet BS.ByteString)
  deriving (Show, Eq)

newtype NetworkLogged m a = NetworkLogged (WriterT [NetworkAction] m a)
  deriving (Monad, Applicative, Functor, MonadState s, MonadRandomBytes, Timed)

runNetworkLogged :: Monad m => NetworkLogged m a -> m (a, [NetworkAction])
runNetworkLogged (NetworkLogged m) = runWriterT m
evalNetworkLogged :: (Monad m, Applicative m) => NetworkLogged m a -> m a
evalNetworkLogged = (fst <$>) . runNetworkLogged
execNetworkLogged :: Monad m => NetworkLogged m a -> m [NetworkAction]
execNetworkLogged (NetworkLogged m) = execWriterT m

-- | just log network events
instance Monad m => Networked (NetworkLogged m) where
  sendPacket to packet = NetworkLogged $
    tell [SendPacket to (fmap (LBS.toStrict . encode) packet)]

instance Networked m => Networked (ReaderT r m) where
  sendPacket = (lift .) . sendPacket
instance (Monoid w, Networked m) => Networked (WriterT w m) where
  sendPacket = (lift .) . sendPacket
instance Networked m => Networked (RandT s m) where
  sendPacket = (lift .) . sendPacket
instance Networked m => Networked (StateT s m) where
  sendPacket = (lift .) . sendPacket
