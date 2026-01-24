{-# LANGUAGE OverloadedStrings #-}
-- | Account from another client's .tox file: keys, profile, friends and
-- pending requests. We leave out conferences and groups.
module Tox.Android.Import
  ( importSave
  ) where

import qualified Crypto.Saltine.Class    as Sodium
import qualified Data.Binary             as Binary
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base16  as Base16
import qualified Data.ByteString.Lazy    as LBS
import qualified Data.Map.Strict         as Map
import           Data.Text               (Text)
import qualified Data.Text               as Text
import qualified Data.Text.Encoding      as Text
import           Data.Word               (byteSwap32)
import qualified Tox.Application.Save    as Save
import qualified Tox.Application.Tox     as Tox
import qualified Tox.Crypto.Core.KeyPair as KeyPair

import           Tox.Android.Model
import           Tox.Android.Store       (Identity (..))

-- | Identity and initial model, or why we can't import it.
importSave :: BS.ByteString -> Either Text (Identity, Model)
importSave bytes
  | BS.take 8 bytes == "toxEsave" = Left "Profiles saved with a password can't be taken yet"
  | otherwise = case Binary.decodeOrFail (LBS.fromStrict bytes) of
      Right (_, _, saved) | Just p <- Save.fromSaveData saved -> Right (account p)
      _ -> Left "That isn't a Tox profile"
  where
    account p =
      ( Identity (Sodium.encode (KeyPair.secretKey (Save.profileKeys p)))
          -- The API gives it the other way round from how it's saved.
          (byteSwap32 (Save.profileNospam p))
      , initial
          { modelProfile = (modelProfile initial)
              { profileNickname = text (Save.profileName p)
              , profileStatus = text (Save.profileStatusMessage p)
              , profileAway = Save.profileStatus p }
          , modelContacts = Map.fromList (map friend (Save.profileFriends p))
          } )
    friend f =
      let key = hex (Sodium.encode (Save.sfPublicKey f))
      in ( ContactId key
         , Contact
             { contactName = if BS.null (Save.sfName f) then Nothing else Just (text (Save.sfName f))
             , contactOnline = False
             , contactMessages = []
             , contactUnread = 0
             , contactRequest = (\(nospam, message) -> (toxId key (hex nospam), text message)) <$> Save.sfRequest f
             , contactStatusMessage = text (Save.sfStatusMessage f)
             , contactStatus = Tox.Online
             , contactMute = Nothing
             , contactAvatar = Nothing
             , contactPictures = Nothing
             } )
    text = Text.decodeUtf8Lenient
    hex = Text.toUpper . Text.decodeUtf8 . Base16.encode
