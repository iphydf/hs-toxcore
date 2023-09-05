{-# LANGUAGE DeriveFoldable    #-}
{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE Safe              #-}
{-# LANGUAGE StrictData        #-}
module Data.Result
    ( Result (..)
    ) where

import           Control.Applicative (Alternative (..))

data Result a
    = Success a
    | Failure String
    deriving (Read, Show, Eq, Functor, Foldable, Traversable)

instance Applicative Result where
    pure = Success

    Success f   <*> x = fmap f x
    Failure msg <*> _ = Failure msg

instance Alternative Result where
    empty = Failure "empty alternative"

    s@Success {} <|> _ = s
    _            <|> r = r

instance Monad Result where
    Success x   >>= f = f x
    Failure msg >>= _ = Failure msg

instance MonadFail Result where
    fail = Failure
