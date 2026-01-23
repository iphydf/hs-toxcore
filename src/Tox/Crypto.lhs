\chapter{Crypto}

\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Crypto where
\end{code}

The Crypto module contains all the functions and data types related to
cryptography.  This includes random number generation, encryption and
decryption, key generation, operations on nonces and generating random nonces.

\input{Tox/Crypto/Key.lhs}
\input{Tox/Crypto/KeyPair.lhs}
\input{Tox/Crypto/CombinedKey.lhs}
\input{Tox/Crypto/Nonce.lhs}
\input{Tox/Crypto/Box.lhs}
