{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
-- | Saves encrypted with a password, as toxencryptsave writes them: magic,
-- salt, nonce, then the box.
module Tox.Application.EncryptedSave
  ( DecryptError (..)
  , isEncrypted
  , decryptSave
  ) where

import           Control.Monad.Validate      (runValidate)
import qualified Crypto.Saltine.Class        as Sodium
import qualified Crypto.Saltine.Internal.Box as Sodium (box_macbytes,
                                                        box_noncebytes)
import           Data.ByteString             (ByteString)
import qualified Data.ByteString             as BS

import qualified Tox.Crypto.Core.Box         as Box
import           Tox.Crypto.Core.PassKey     (passKey, saltLength)

data DecryptError
  = NotEncrypted
  | WrongPassword
  deriving (Eq, Show)

magic :: ByteString
magic = "toxEsave"

isEncrypted :: ByteString -> Bool
isEncrypted = BS.isPrefixOf magic

-- | The save, with the password it was encrypted with.
decryptSave :: ByteString -> ByteString -> Either DecryptError ByteString
decryptSave password bytes = case splits [BS.length magic, saltLength, Sodium.box_noncebytes] bytes of
  [m, salt, nonce, box] | m == magic, BS.length box > Sodium.box_macbytes -> maybe (Left WrongPassword) Right $ do
    key <- passKey password salt
    n <- Sodium.decode nonce
    sealed <- either (const Nothing) Just (runValidate (Box.cipherText box))
    Box.unPlainText <$> Box.decrypt key n sealed
  _ -> Left NotEncrypted
  where
    splits ns s = foldr (\k go rest -> let (a, b) = BS.splitAt k rest in a : go b) pure ns s
