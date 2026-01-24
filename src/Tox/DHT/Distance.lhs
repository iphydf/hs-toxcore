\section{Distance}

\begin{code}
{-# OPTIONS_GHC -Wno-noncanonical-monad-instances #-}
{-# LANGUAGE MagicHash  #-}
{-# LANGUAGE StrictData #-}
module Tox.DHT.Distance where

import           Control.Arrow             (first)
import           Data.Bits                 (bit, shiftL, shiftR, testBit, xor,
                                            (.|.))
import           Data.List                 (sortOn)
import           Data.Map                  (Map)
import qualified Data.Map                  as Map
import           GHC.Exts                  (Int (I#))
import           GHC.Integer.Logarithms    (integerLog2#)
import           Numeric                   (readHex, showHex)
import           Test.QuickCheck.Arbitrary (Arbitrary, arbitrary)
import qualified Tox.Crypto.Core.Key       as Key (keyToInteger)
import           Tox.Crypto.Core.Key       (PublicKey)


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

\end{code}

A Distance is a positive integer.  Its human-readable representation is a
base-16 number.  Distance (type) is an
\href{https://en.wikipedia.org/wiki/Ordered_semigroup}{ordered monoid} with the
associative binary operator \texttt{+} and the identity element \texttt{0}.

\begin{code}

newtype Distance = Distance Integer
  deriving (Eq, Ord)


instance Semigroup Distance where
  Distance x <> Distance y = Distance (x + y)

instance Monoid Distance where
  mempty = Distance 0


instance Show Distance where
  show (Distance distance) = showHex distance ""

instance Read Distance where
  readsPrec _ string = map (first Distance) $ readHex string


log2 :: Distance -> Maybe Int
log2 (Distance 0) = Nothing
log2 (Distance x) = Just $ I# (integerLog2# x)


\end{code}

The DHT uses a
\href{https://en.wikipedia.org/wiki/Metric_(mathematics)}{metric} to determine
the distance between two nodes.  The Distance type is the co-domain of this
metric. The metric currently used by the Tox DHT is the \texttt{XOR} of the
nodes' public keys: \texttt{distance(x, y) = x XOR y}.  For this computation,
public keys are interpreted as Big Endian integers (see \href{#key-1}{Crypto
Numbers}).

When we speak of a "close node", we mean that its Distance to the node under
consideration is small compared to the Distance to other nodes.

\begin{code}

xorDistance :: PublicKey -> PublicKey -> Distance
xorDistance a b =
  Distance $ Key.keyToInteger a `xor` Key.keyToInteger b

-- | rebaseDistance a b (xorDistance a c) == xorDistance b c
rebaseDistance :: PublicKey -> PublicKey -> Distance -> Distance
rebaseDistance a b (Distance d) =
  Distance $ d `xor` Key.keyToInteger a `xor` Key.keyToInteger b

-- | The values of a map keyed by 'Key.keyToInteger', closest to the key first,
-- lazily. Keys that share their high bits split at the next bit into a nearer
-- half and a further half, so splitting down from the highest bit visits about
-- as many keys as it returns.
byDistance :: PublicKey -> Map Integer a -> [(Distance, a)]
byDistance key = go (keyBits - 1)
  where
    target = Key.keyToInteger key
    keyBits = 256
    go :: Int -> Map Integer a -> [(Distance, a)]
    go bitIndex m
      | Map.size m <= 8 || bitIndex < 0 =
          sortOn fst [ (Distance (k `xor` target), v) | (k, v) <- Map.toList m ]
      | otherwise = go (bitIndex - 1) near ++ go (bitIndex - 1) far
      where
        -- The keys here share the bits above this one, so the first key with
        -- this bit set has those bits, this bit, and zeros below.
        lowest = fst (Map.findMin m)
        middle = (lowest `shiftR` (bitIndex + 1)) `shiftL` (bitIndex + 1) .|. bit bitIndex
        (low, high) = Map.spanAntitone (< middle) m
        (near, far) = if testBit target bitIndex then (high, low) else (low, high)

{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}


instance Arbitrary Distance where
  arbitrary = Distance . abs <$> arbitrary
\end{code}

An implementation is not required to provide a Distance type, so it has no
specified binary representation.  For example, instead of computing a distance
and comparing it against another distance, the implementation can choose to
implement Distance as a pair of public keys and define an ordering on Distance
without computing the complete integral value.  This works, because as soon as
an ordering decision can be made in the most significant bits, further bits
won't influence that decision.

\input{test/Tox/DHT/DistanceSpec.lhs}
