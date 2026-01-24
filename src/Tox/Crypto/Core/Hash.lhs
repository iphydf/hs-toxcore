\section{Hash}

\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Crypto.Core.Hash
  ( hash
  ) where

import qualified Crypto.Saltine.Core.Hash as Sodium
import           Data.ByteString          (ByteString)

hash :: ByteString -> ByteString
hash = Sodium.hash
\end{code}
