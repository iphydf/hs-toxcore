{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}

import           Control.Concurrent          (threadDelay)
import           Control.Monad               (forever, void)
import           Data.ByteString             (ByteString)
import qualified Data.ByteString             as BS
import qualified Data.ByteString.Char8       as BSC
import           Data.Word                   (Word16, Word32, Word8)
import           Foreign.C.String            (CString, peekCString)
import           Foreign.C.Enum              (CEnum (..), fromCEnum)
import           Foreign.Ptr                 (FunPtr, Ptr, nullPtr)
import           System.IO                   (hFlush, stdout)
import           Data.ByteString.Base16      as B16

import qualified FFI.Tox.Core                as Tox
import qualified FFI.Tox.Options             as Tox
import           FFI.Tox.Types

-- | Log callback implementation
logCallback :: LogCb
logCallback _tox level file line func message _userData = do
  levelStr <- BSC.unpack <$> Tox.toxLogLevelToString (fromCEnum level)
  fileStr <- peekCString file
  funcStr <- peekCString func
  msgStr <- peekCString message
  putStrLn $ "[" ++ levelStr ++ "] " ++ fileStr ++ ":" ++ show line ++ " " ++ funcStr ++ ": " ++ msgStr
  hFlush stdout

main :: IO ()
main = do
  putStrLn "Starting E2E Test with C Tox Core..."
  
  -- 1. Create Options
  eitherOpts <- Tox.toxOptionsNew
  case eitherOpts of
    Left err -> putStrLn $ "Failed to create options: " ++ show err
    Right opts -> do
      -- 2. Set Log Callback
      cbPtr <- wrapLogCb logCallback
      Tox.toxOptionsSetLogCallback opts cbPtr
      
      -- 3. Create Tox Instance
      eitherTox <- Tox.toxNew opts
      case eitherTox of
        Left err -> putStrLn $ "Failed to create Tox instance: " ++ show err
        Right tox -> do
          putStrLn "C Tox instance created."
          
          -- 4. Get and print our address
          addr <- Tox.toxSelfGetAddress tox
          putStrLn $ "C Tox Address: " ++ BSC.unpack (B16.encode addr)
          
          -- 5. Main loop (just iterate and wait for logs)
          putStrLn "Entering main loop..."
          forever $ do
            Tox.toxIterate tox
            interval <- Tox.toxIterationInterval tox
            threadDelay (fromIntegral interval * 1000)
