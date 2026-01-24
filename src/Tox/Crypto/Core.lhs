\chapter{Crypto}

\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Crypto.Core where
\end{code}

The Crypto module contains all the functions and data types related to
cryptography.  This includes random number generation, encryption and
decryption, key generation, operations on nonces and generating random nonces.

\input{src/Tox/Crypto/Core/Key.lhs}
\input{src/Tox/Crypto/Core/KeyPair.lhs}
\input{src/Tox/Crypto/Core/CombinedKey.lhs}
\input{src/Tox/Crypto/Core/Hash.lhs}
\input{src/Tox/Crypto/Core/Nonce.lhs}
\input{src/Tox/Crypto/Core/Box.lhs}
\input{src/Tox/Crypto/Core/Keyed.hs}
\input{src/Tox/Crypto/Core/MonadRandomBytes.hs}
