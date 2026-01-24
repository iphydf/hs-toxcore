-- | Saves c-toxcore encrypted with a password open with that password only.
module Main (main) where

import           Control.Monad                 (unless)
import qualified Data.ByteString               as BS
import           Data.Word                     (Word8)
import           Network.Tox.C.EncryptSave     (toxPassEncrypt)
import           System.Exit                   (exitFailure)
import           Test.QuickCheck               (Args (..), NonEmptyList (..),
                                                Property, isSuccess,
                                                quickCheckWithResult, stdArgs,
                                                (==>))
import           Test.QuickCheck.Monadic       (assert, monadicIO, run)

import           Tox.Application.EncryptedSave (DecryptError (..), decryptSave,
                                                isEncrypted)

prop_Decrypt :: NonEmptyList Word8 -> [Word8] -> [Word8] -> Property
prop_Decrypt (NonEmpty save) password other = password /= other ==> monadicIO $ do
    let bytes = BS.pack save
        right = BS.pack password
    locked <- run $ either (fail . show) pure =<< toxPassEncrypt bytes right
    assert (isEncrypted locked)
    assert (decryptSave right locked == Right bytes)
    assert (decryptSave (BS.pack other) locked == Left WrongPassword)
    assert (decryptSave right (BS.take 40 locked) == Left NotEncrypted)

main :: IO ()
main = do
    -- Each one derives 2 keys with scrypt, which takes a while.
    result <- quickCheckWithResult stdArgs{maxSuccess=20} prop_Decrypt
    unless (isSuccess result) exitFailure
