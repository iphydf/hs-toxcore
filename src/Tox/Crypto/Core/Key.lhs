\section{Key}

\begin{code}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DeriveDataTypeable  #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE MagicHash           #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# LANGUAGE StrictData          #-}
module Tox.Crypto.Core.Key
  ( CryptoNumber (..)
  , Key
  , PublicKey
  , SecretKey
  , CombinedKey
  , Nonce
  , Signature
  , toSodium
  , fromSodium
  , keyToInteger
  , decode
  ) where

import           Control.Monad                ((>=>))
import           Control.Monad.Validate       (MonadValidate, refute)
import qualified Crypto.Saltine.Class         as Sodium (IsEncoding, decode,
                                                         encode)
import qualified Crypto.Saltine.Core.Box      as Sodium (CombinedKey, Nonce,
                                                         PublicKey, SecretKey)
import qualified Crypto.Saltine.Core.Sign     as Sodium (Signature)
import qualified Crypto.Saltine.Internal.Box  as Sodium (box_beforenmbytes,
                                                         box_noncebytes,
                                                         box_publickeybytes,
                                                         box_secretkeybytes)
import qualified Crypto.Saltine.Internal.Sign as Sodium (sign_bytes)
import           Data.Array.Byte              (ByteArray (..))
import           Data.Binary                  (Binary)
import qualified Data.Binary                  as Binary (get, put)
import qualified Data.Binary.Get              as Binary (getByteString)
import qualified Data.Binary.Put              as Binary (putShortByteString)
import qualified Data.ByteString              as ByteString
import qualified Data.ByteString.Base16       as Base16
import           Data.ByteString.Short        (ShortByteString (..))
import qualified Data.ByteString.Short        as Short
import           Data.Maybe                   (fromJust)
import           Data.MessagePack             (DecodeError, MessagePack (..))
import           Data.Proxy                   (Proxy (..))
import           Data.String                  (fromString)
import           Data.Typeable                (Typeable)
import           GHC.Exts                     (int2Word#, sizeofByteArray#)
import           GHC.Num.Integer              (integerFromByteArray)
import qualified Test.QuickCheck.Arbitrary    as Arbitrary
import           Test.QuickCheck.Arbitrary    (Arbitrary, arbitrary)
import           Text.Read                    (readPrec)


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

\end{code}

A Crypto Number is a large fixed size unsigned (non-negative) integer.  Its binary
encoding is as a Big Endian integer in exactly the encoded byte size.  Its
human-readable encoding is as a base-16 number encoded as String.  The NaCl
implementation \href{https://github.com/jedisct1/libsodium}{libsodium} supplies
the functions \texttt{sodium\_bin2hex} and \texttt{sodium\_hex2bin} to aid in
implementing the human-readable encoding.  The in-memory encoding of these
crypto numbers in NaCl already satisfies the binary encoding, so for
applications directly using those APIs, binary encoding and decoding is the
\href{https://en.wikipedia.org/wiki/Identity_function}{identity function}.

\begin{code}

class Sodium.IsEncoding a => CryptoNumber a where
  encodedByteSize :: proxy a -> Int

\end{code}

Tox uses four kinds of Crypto Numbers:

\begin{tabular}{l|l|l}
  Type         & Bits & Encoded byte size \\
  \hline
  Public Key   & 256  & 32 \\
  Secret Key   & 256  & 32 \\
  Combined Key & 256  & 32 \\
  Nonce        & 192  & 24 \\
\end{tabular}

\begin{code}

instance CryptoNumber Sodium.PublicKey   where { encodedByteSize _ = Sodium.box_publickeybytes }
instance CryptoNumber Sodium.SecretKey   where { encodedByteSize _ = Sodium.box_secretkeybytes }
instance CryptoNumber Sodium.CombinedKey where { encodedByteSize _ = Sodium.box_beforenmbytes  }
instance CryptoNumber Sodium.Nonce       where { encodedByteSize _ = Sodium.box_noncebytes     }
instance CryptoNumber Sodium.Signature   where { encodedByteSize _ = Sodium.sign_bytes         }

deriving instance Typeable Sodium.PublicKey
deriving instance Typeable Sodium.SecretKey
deriving instance Typeable Sodium.CombinedKey
deriving instance Typeable Sodium.Nonce
deriving instance Typeable Sodium.Signature

-- | Unpinned, so a long-lived key holds no pinned block alive.
newtype Key a = Key ShortByteString
  deriving (Eq, Ord, Typeable)

type PublicKey   = Key Sodium.PublicKey
type SecretKey   = Key Sodium.SecretKey
type CombinedKey = Key Sodium.CombinedKey
type Nonce       = Key Sodium.Nonce
type Signature   = Key Sodium.Signature

-- | Decoding copies, so the key keeps no packet alive.
instance CryptoNumber a => Sodium.IsEncoding (Key a) where
  encode (Key bytes) = Short.fromShort bytes
  decode bytes
    | ByteString.length bytes == encodedByteSize (Proxy :: Proxy a) = Just . Key $ Short.toShort bytes
    | otherwise = Nothing

-- | For NaCl. Never fails: a key always has its type's length.
toSodium :: CryptoNumber a => Key a -> a
toSodium = fromJust . Sodium.decode . Sodium.encode

fromSodium :: CryptoNumber a => a -> Key a
fromSodium = Key . Short.toShort . Sodium.encode


-- | Straight from the bytes, as the DHT does this for every distance.
keyToInteger :: Key a -> Integer
keyToInteger (Key (ShortByteString (ByteArray bytes))) =
  -- Most significant byte first.
  integerFromByteArray (int2Word# (sizeofByteArray# bytes)) bytes 0## 1#


decode :: (CryptoNumber a, MonadValidate DecodeError m) => ByteString.ByteString -> m (Key a)
decode bytes =
  case Sodium.decode bytes of
    Just key -> return key
    Nothing  -> refute $ fromString $ "unable to decode ByteString to Key: " <> show (ByteString.length bytes)


instance CryptoNumber a => Binary (Key a) where
  put (Key bytes) =
    Binary.putShortByteString bytes

  get = do
    bytes <- Binary.getByteString $ encodedByteSize (Proxy :: Proxy a)
    decode bytes


instance CryptoNumber a => Show (Key a) where
  show = show . Base16.encode . Sodium.encode

instance CryptoNumber a => Read (Key a) where
  readPrec = do
    text <- readPrec
    case Base16.decode text of
      Left err -> fail err
      Right ok -> decode ok

instance CryptoNumber a => MessagePack (Key a) where
  toObject cfg = toObject cfg . Sodium.encode
  fromObjectWith cfg = fromObjectWith cfg >=> decode


{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}


instance CryptoNumber a => Arbitrary (Key a) where
  arbitrary = Key . Short.pack <$> Arbitrary.vector (encodedByteSize (Proxy :: Proxy a))
\end{code}
