{-# LANGUAGE LambdaCase #-}
module Main (main) where

import           Control.Monad           (unless)
import qualified Data.Binary             as Binary
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as LBS
import           Data.Either             (isRight)
import           Network.Tox.C           (LogCallback, LogLevel (..),
                                          Options (..), SavedataType (..),
                                          defaultOptions, withToxLogging)
import           System.Exit             (exitFailure)
import           Test.QuickCheck         (Args (..), Property, isSuccess,
                                          quickCheckWithResult, stdArgs)
import           Test.QuickCheck.Monadic (assert, monadicIO, run)
import           Tox.Persistence         (SaveData)

logLevelName :: LogLevel -> Char
logLevelName = \case
    LogLevelTrace   -> 'T'
    LogLevelDebug   -> 'D'
    LogLevelInfo    -> 'I'
    LogLevelWarning -> 'W'
    LogLevelError   -> 'E'

logHandler :: LogCallback
logHandler LogLevelTrace _ _ _ _ = return ()
logHandler level file line func msg =
    putStrLn $ logLevelName level : ' ' : file <> ":" <> show line <> "(" <> func <> "): " <> msg

prop_Save :: SaveData -> Property
prop_Save save = monadicIO $ do
    ok <- run $ do
        let saveData = LBS.toStrict (Binary.encode save)
        putStrLn $ "\nsavedata size: " <> show (BS.length saveData)
        opts <- either (fail . show) return =<< defaultOptions
        isRight <$> withToxLogging opts{savedataType=SavedataTypeToxSave, savedata=saveData} logHandler (const (return ()))
    assert ok


main :: IO ()
main = do
    result <- quickCheckWithResult stdArgs{maxSuccess=100, maxSize=30} prop_Save
    unless (isSuccess result) exitFailure
