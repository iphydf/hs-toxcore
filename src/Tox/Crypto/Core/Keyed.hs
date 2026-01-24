{-# OPTIONS_GHC -Wno-noncanonical-monad-instances #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE StrictData                 #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}

-- | Monad class for caching of combined keys
module Tox.Crypto.Core.Keyed where

import           Control.Monad.IO.Class           (MonadIO)
import           Control.Monad.Random             (RandT)
import           Control.Monad.Reader             (ReaderT)
import           Control.Monad.RWS                (RWST)
import           Control.Monad.State              (MonadState, StateT (..),
                                                   evalStateT, gets, put,
                                                   runStateT, state)
import           Control.Monad.Trans              (MonadTrans, lift)
import           Control.Monad.Writer             (MonadWriter, WriterT)

import           Data.Map.Strict                  (Map)
import qualified Data.Map.Strict                  as Map
import           Data.Maybe                       (fromMaybe)
import           Tox.Core.Log                     (MonadLog)
import           Tox.Core.Timed                   (Timed)
import qualified Tox.Crypto.Core.CombinedKey      as CombinedKey
import           Tox.Crypto.Core.Key              (CombinedKey, PublicKey,
                                                   SecretKey)
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes)

class (Monad m, Applicative m) => Keyed m where
  getCombinedKey :: SecretKey -> PublicKey -> m CombinedKey

instance Keyed m => Keyed (ReaderT r m) where
  getCombinedKey = (lift .) . getCombinedKey
instance (Monoid w, Keyed m) => Keyed (WriterT w m) where
  getCombinedKey = (lift .) . getCombinedKey
instance Keyed m => Keyed (StateT s m) where
  getCombinedKey = (lift .) . getCombinedKey
instance (Monoid w, Keyed m) => Keyed (RWST r w s m) where
  getCombinedKey = (lift .) . getCombinedKey
instance Keyed m => Keyed (RandT s m) where
  getCombinedKey = (lift .) . getCombinedKey

-- | trivial instance: the trivial monad, with no caching of keys
newtype NullKeyed a = NullKeyed { runNullKeyed :: a }
instance Functor NullKeyed where
  fmap f (NullKeyed x) = NullKeyed (f x)
instance Applicative NullKeyed where
  pure = NullKeyed
  (NullKeyed f) <*> (NullKeyed x) = NullKeyed (f x)
instance Monad NullKeyed where
  return = NullKeyed
  NullKeyed x >>= f = f x
instance Keyed NullKeyed where
  getCombinedKey = (NullKeyed .) . CombinedKey.precompute

-- | Combined keys in 2 generations. When the new one is full, the old one goes,
-- so anyone sending from new keys can't make it grow without bound.
data KeyRing = KeyRing
  { ringNew :: Map (SecretKey, PublicKey) CombinedKey
  , ringOld :: Map (SecretKey, PublicKey) CombinedKey
  }

emptyKeyRing :: KeyRing
emptyKeyRing = KeyRing Map.empty Map.empty

keyRingSize :: KeyRing -> Int
keyRingSize (KeyRing new old) = Map.size new + Map.size old

-- | Like c-toxcore's caches, which hold 1024 keys each.
keyRingGeneration :: Int
keyRingGeneration = 1024

newtype KeyedT m a = KeyedT (StateT KeyRing m a)
  deriving (Monad, Applicative, Functor, MonadWriter w
    , MonadRandomBytes, MonadTrans, MonadIO, Timed, MonadLog)

runKeyedT :: Monad m => KeyedT m a -> KeyRing -> m (a, KeyRing)
runKeyedT (KeyedT m) = runStateT m

evalKeyedT :: Monad m => KeyedT m a -> KeyRing -> m a
evalKeyedT (KeyedT m) = evalStateT m

instance (MonadState s m, Applicative m) => MonadState s (KeyedT m) where
  state f = KeyedT . StateT $ \s -> (, s) <$> state f

instance (Monad m, Applicative m) => Keyed (KeyedT m) where
  getCombinedKey secretKey publicKey = KeyedT $ do
    (shared, ring) <- gets (combinedKey secretKey publicKey)
    put $! ring
    return shared

-- | From the ring if it's there, else worked out and kept.
combinedKey :: SecretKey -> PublicKey -> KeyRing -> (CombinedKey, KeyRing)
combinedKey secretKey publicKey ring@(KeyRing new old) = maybe (shared, kept) (, ring) (Map.lookup keys new)
  where
    keys = (secretKey, publicKey)
    shared = fromMaybe (CombinedKey.precompute secretKey publicKey) (Map.lookup keys old)
    kept
      | Map.size new >= keyRingGeneration = KeyRing (Map.singleton keys shared) new
      | otherwise = ring { ringNew = Map.insert keys shared new }
