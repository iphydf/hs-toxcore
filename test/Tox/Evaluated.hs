{-# LANGUAGE LambdaCase #-}
-- | Whether a value is evaluated (without evaluating it), and evaluating all of it.
module Tox.Evaluated (evaluated, fullyEvaluated, forceAll) where

import           Control.Exception (evaluate)
import           GHC.Exts.Heap     (Box (..), GenClosure (..), asBox,
                                    getBoxedClosureData, getClosureData)

-- | Past the indirection an evaluated thunk leaves until the next GC.
settled :: GenClosure Box -> IO (GenClosure Box)
settled = \case
  IndClosure { indirectee = b }       -> getBoxedClosureData b >>= settled
  BlackholeClosure { indirectee = b } -> getBoxedClosureData b >>= settled
  c                                   -> pure c

-- | Its outer constructor is there.
evaluated :: a -> IO Bool
evaluated x = getClosureData x >>= settled >>= \case
  ConstrClosure {} -> pure True
  _                -> pure False

-- | Constructors all the way down.
fullyEvaluated :: a -> IO Bool
fullyEvaluated x = getClosureData x >>= go
  where
    go c = settled c >>= \case
      ConstrClosure { ptrArgs = ps } -> and <$> mapM (\b -> getBoxedClosureData b >>= go) ps
      _                              -> pure False

-- | Evaluates every thunk it reaches through constructors, so what one of
-- them throws, it throws here.
forceAll :: a -> IO ()
forceAll = walk . asBox
  where
    walk b = getBoxedClosureData b >>= visit b
    visit b@(Box a) = \case
      ThunkClosure {}                     -> evaluate a >> walk b
      APClosure {}                        -> evaluate a >> walk b
      SelectorClosure {}                  -> evaluate a >> walk b
      IndClosure { indirectee = i }       -> walk i
      BlackholeClosure { indirectee = i } -> walk i
      ConstrClosure { ptrArgs = ps }      -> mapM_ walk ps
      _                                   -> pure ()
