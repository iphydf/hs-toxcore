{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE StrictData                 #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
module Tox.Crypto.Keyed where

import           Control.Monad.IO.Class       (MonadIO)
import           Control.Monad.State          (MonadState, StateT (..),
                                               evalStateT, gets, modify,
                                               runStateT, state)
import           Control.Monad.Trans          (MonadTrans)
import           Control.Monad.Writer         (MonadWriter)

import           Data.Map                     (Map)
import qualified Data.Map                     as Map
import           Tox.Core.Timed               (Timed)
import qualified Tox.Crypto.Core.CombinedKey       as CombinedKey
import           Tox.Crypto.Core.Key               (CombinedKey, PublicKey,
                                               SecretKey)
import           Tox.Crypto.Core.Keyed             (Keyed (..))
import           Tox.Network.Core.MonadRandomBytes (MonadRandomBytes)
import           Tox.Network.Core.Networked        (Networked)

type KeyRing = Map (SecretKey, PublicKey) CombinedKey

-- | caches computations of combined keys. Makes no attempt to delete old keys.
newtype KeyedT m a = KeyedT (StateT KeyRing m a)
  deriving (Monad, Applicative, Functor, MonadWriter w
    , MonadRandomBytes, MonadTrans, MonadIO, Networked, Timed)

runKeyedT :: Monad m => KeyedT m a -> KeyRing -> m (a, KeyRing)
runKeyedT (KeyedT m) = runStateT m

evalKeyedT :: Monad m => KeyedT m a -> KeyRing -> m a
evalKeyedT (KeyedT m) = evalStateT m

instance (MonadState s m, Applicative m) => MonadState s (KeyedT m) where
  state f = KeyedT . StateT $ \s -> (, s) <$> state f

instance (Monad m, Applicative m) => Keyed (KeyedT m) where
  getCombinedKey secretKey publicKey =
    let keys = (secretKey, publicKey)
    in KeyedT $ gets (Map.lookup keys) >>= \case
      Nothing ->
        let shared = CombinedKey.precompute secretKey publicKey
        in modify (Map.insert keys shared) >> return shared
      Just shared -> return shared
