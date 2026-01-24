{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StrictData                 #-}
{-# LANGUAGE TypeOperators              #-}
-- | Log lines from any layer, for the client to keep or drop.
module Tox.Core.Log
  ( LogLevel (..)
  , MonadLog (..)
  , logDebug
  , logInfo
  , logWarn
  , logError
  , NoLog (..)
  ) where

import           Control.Monad.IO.Class     (MonadIO)
import           Control.Monad.Random       (RandT)
import           Control.Monad.Reader       (ReaderT)
import           Control.Monad.State        (MonadState)
import qualified Control.Monad.State.Lazy   as Lazy
import qualified Control.Monad.State.Strict as Strict
import           Control.Monad.Trans        (MonadTrans (..))
import           Control.Monad.Trans.Maybe  (MaybeT)
import           Control.Monad.Writer       (WriterT)
import           Data.Text                  (Text)

data LogLevel = LevelDebug | LevelInfo | LevelWarn | LevelError
  deriving (Eq, Ord, Show, Read, Bounded, Enum)

-- | Transformers pass lines on to the monad under them.
class Monad m => MonadLog m where
  logAt :: LogLevel -> Text -> m ()
  default logAt :: (MonadTrans t, MonadLog n, m ~ t n) => LogLevel -> Text -> m ()
  logAt level = lift . logAt level

instance MonadLog m => MonadLog (Lazy.StateT s m)
instance MonadLog m => MonadLog (Strict.StateT s m)
instance MonadLog m => MonadLog (ReaderT r m)
instance (Monoid w, MonadLog m) => MonadLog (WriterT w m)
instance MonadLog m => MonadLog (MaybeT m)
instance MonadLog m => MonadLog (RandT g m)

logDebug, logInfo, logWarn, logError :: MonadLog m => Text -> m ()
logDebug = logAt LevelDebug
logInfo = logAt LevelInfo
logWarn = logAt LevelWarn
logError = logAt LevelError

newtype NoLog m a = NoLog { runNoLog :: m a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState s)

instance MonadTrans NoLog where
  lift = NoLog

instance Monad m => MonadLog (NoLog m) where
  logAt _ _ = pure ()
