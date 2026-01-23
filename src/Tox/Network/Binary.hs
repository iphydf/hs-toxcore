{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData          #-}
module Tox.Network.Binary
  ( encode
  , decode
  ) where

import           Data.Binary          (Binary)
import           Data.ByteString      (ByteString)

import qualified Tox.Network.Encoding as Encoding


--------------------------------------------------------------------------------
--
-- :: decode
--
--------------------------------------------------------------------------------


decode :: Binary a => ByteString -> Maybe a
decode = Encoding.decode


--------------------------------------------------------------------------------
--
-- :: encode
--
--------------------------------------------------------------------------------


encode :: Binary a => a -> ByteString
encode = Encoding.encode
