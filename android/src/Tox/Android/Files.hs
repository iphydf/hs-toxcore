{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | File transfers with friends. Reports progress in steps.
module Tox.Android.Files
  ( Transfers
  , newTransfers
  , offer
  , offered
  , accept
  , cancel
  , received
  , requested
  , controlled
  , friendGone
  , flush
  , retryInterval
  , fitted
  , safeName
  ) where

import           Control.Concurrent.MVar (MVar, modifyMVar, modifyMVar_,
                                          newMVar)
import           Control.Exception       (IOException, try)
import           Control.Monad           (forM_, void)
import qualified Data.ByteString         as BS
import           Data.Char               (isAlphaNum, isAscii)
import           Data.Map.Strict         (Map)
import qualified Data.Map.Strict         as Map
import           Data.Text               (Text)
import qualified Data.Text               as Text
import qualified Data.Text.Encoding      as Text
import           Data.Time               (UTCTime)
import           Data.Time.Clock.POSIX   (utcTimeToPOSIXSeconds)
import           Data.Word               (Word32, Word64, Word8)
import           System.Directory        (removeFile)
import           System.FilePath         (splitExtension, (</>))
import           System.IO               (Handle, IOMode (..), SeekMode (..),
                                          hClose, hFileSize, hSeek,
                                          hSetFileSize, openBinaryFile)
import qualified Tox.Application.Tox     as Tox
import           Tox.Crypto.Core.Key     (PublicKey)

import           Tox.Android.Model

data Transfer = Transfer
  { trContact  :: ContactId
  , trPath     :: FilePath
  , trSize     :: Word64
  , trHandle   :: Maybe Handle
    -- ^ Open during the transfer.
  , trReported :: Word64
  , trUnsent   :: [(Word64, Int)]
    -- ^ Chunks Tox asked for but had no room for yet, in order. Tox only
    -- asks once, and only takes them in order.
  }

newtype Transfers = Transfers (MVar (Map (PublicKey, Tox.FileRef) Transfer))

newTransfers :: IO Transfers
newTransfers = Transfers <$> newMVar Map.empty

-- | How often we retry chunks Tox had no room for.
retryInterval :: Int
retryInterval = 50000

-- | Nothing if Tox refuses it.
offer :: Tox.Tox -> Transfers -> ContactId -> PublicKey -> FilePath -> Text -> Word64 -> Maybe BS.ByteString
      -> IO (Maybe FileRef)
offer tox (Transfers ts) cid pk path name size fileId =
  Tox.fileSend tox pk Tox.fileKindData size fileId (Text.encodeUtf8 name) >>= \case
    Left _ -> pure Nothing
    Right n -> do
      modifyMVar_ ts (pure . Map.insert (pk, Tox.Outgoing n) (Transfer cid path size Nothing 0 []))
      pure (Just (Sending n))

-- | Path to save it to, or Nothing for things that aren't files to keep
-- (like avatars), which we decline.
offered :: Tox.Tox -> Transfers -> FilePath -> UTCTime -> ContactId -> PublicKey -> Word8 -> Word32 -> Word64
        -> Text -> IO (Maybe FilePath)
offered tox (Transfers ts) dir now cid pk n kind size name
  | kind /= Tox.fileKindData = Nothing <$ Tox.fileControl tox pk (Tox.Incoming n) Tox.FileCancel
  | otherwise = do
      -- File number too, for 2 offers in 1 millisecond.
      let path = dir </> fitted (show (millis now) <> "-" <> show n <> "-") (safeName name)
      modifyMVar_ ts (pure . Map.insert (pk, Tox.Incoming n) (Transfer cid path size Nothing 0 []))
      pure (Just path)
  where millis = (round :: Rational -> Integer) . (* 1000) . toRational . utcTimeToPOSIXSeconds

-- | Resumes after what's already in the file.
accept :: Tox.Tox -> Transfers -> PublicKey -> FileRef -> FilePath -> IO [Event]
accept tox (Transfers ts) pk ref path = modifyMVar ts $ \known -> case Map.lookup key known of
  Just t -> do
    opened <- try (openBinaryFile path ReadWriteMode >>= \h -> (,) h <$> hFileSize h)
      :: IO (Either IOException (Handle, Integer))
    case opened of
      Right (h, had) -> do
        let going = had > 0 && had < fromIntegral (trSize t)
        if going then void (seek (fromIntegral had)) else hSetFileSize h 0
        void $ Tox.fileControl tox pk (toxRef ref) Tox.FileResume
        let done = if going then fromIntegral had else 0
        pure ( Map.insert key t { trHandle = Just h, trPath = path, trReported = done } known
             , [FileMoved (trContact t) ref done | going] )
      Left _ -> do
        void $ Tox.fileControl tox pk (toxRef ref) Tox.FileCancel
        pure (Map.delete key known, [FileEnded (trContact t) ref False])
  Nothing -> pure (known, [])
  where
    key = (pk, toxRef ref)
    seek position = case ref of
      Receiving n -> Tox.fileSeek tox pk n position
      Sending _   -> pure (Right ())

-- | Also deletes what came of theirs.
cancel :: Tox.Tox -> Transfers -> PublicKey -> FileRef -> IO ()
cancel tox ts pk ref = do
  void $ Tox.fileControl tox pk (toxRef ref) Tox.FileCancel
  void $ end ts pk (toxRef ref) False

received :: Tox.Tox -> Transfers -> PublicKey -> Word8 -> Word64 -> BS.ByteString -> IO [Event]
received tox ts@(Transfers v) pk n position bytes
  | BS.null bytes = end ts pk (Tox.Incoming n) True
  | otherwise = orCancel tox ts key $ modifyMVar v $ \known -> case Map.lookup key known of
      Just t@Transfer { trHandle = Just h } -> do
        hSeek h AbsoluteSeek (fromIntegral position)
        BS.hPut h bytes
        let (t', events) = progress (Receiving n) (position + fromIntegral (BS.length bytes)) t
        pure (Map.insert key t' known, events)
      _ -> pure (known, [])
  where key = (pk, Tox.Incoming n)

-- | Length 0 means the friend has all of it.
requested :: Tox.Tox -> Transfers -> PublicKey -> Word8 -> Word64 -> Int -> IO [Event]
requested tox ts@(Transfers v) pk n position len
  | len == 0 = end ts pk (Tox.Outgoing n) True
  | otherwise = do
      modifyMVar_ v (pure . Map.adjust (\t -> t { trUnsent = trUnsent t ++ [(position, len)] }) (pk, Tox.Outgoing n))
      flushOne tox ts (pk, Tox.Outgoing n)

controlled :: Transfers -> PublicKey -> Tox.FileRef -> Tox.FileControl -> IO [Event]
controlled ts pk ref = \case
  Tox.FileCancel -> end ts pk ref False
  _ -> pure []

-- | Tox ends a friend's transfers when they go offline.
friendGone :: Transfers -> PublicKey -> IO ()
friendGone (Transfers v) pk = modifyMVar_ v $ \known -> do
  let (gone, kept) = Map.partitionWithKey (\(p, _) _ -> p == pk) known
  mapM_ close (Map.elems gone)
  pure kept

-- | Retry chunks Tox had no room for.
flush :: Tox.Tox -> Transfers -> IO [Event]
flush tox ts@(Transfers v) = do
  waiting <- modifyMVar v $ \known -> pure (known, [ key | (key, t) <- Map.toList known, not (null (trUnsent t)) ])
  concat <$> mapM (flushOne tox ts) waiting

flushOne :: Tox.Tox -> Transfers -> (PublicKey, Tox.FileRef) -> IO [Event]
flushOne tox ts@(Transfers v) key@(pk, ref) = orCancel tox ts key $ modifyMVar v $ \known -> case Map.lookup key known of
  Nothing -> pure (known, [])
  Just t0 -> do
    t1 <- opened t0
    (t2, sent) <- go t1 Nothing
    let (t3, events) = maybe (t2, []) (\done -> progress (fromToxRef ref) done t2) sent
    pure (Map.insert key t3 known, events)
  where
    opened t = case trHandle t of
      Just _ -> pure t
      Nothing -> (\h -> t { trHandle = Just h }) <$> openBinaryFile (trPath t) ReadMode
    go t sent = case (trUnsent t, trHandle t) of
      ((position, len) : rest, Just h) -> do
        hSeek h AbsoluteSeek (fromIntegral position)
        chunk <- BS.hGet h len
        Tox.fileSendChunk tox pk (number ref) position chunk >>= \case
          Left Tox.FileSendQueueFull -> pure (t, sent)
          _ -> go t { trUnsent = rest } (Just (position + fromIntegral len))
      _ -> pure (t, sent)
    number = \case
      Tox.Outgoing n -> n
      Tox.Incoming n -> n

-- | IO errors (like a full disk) cancel the transfer instead of killing the
-- thread.
orCancel :: Tox.Tox -> Transfers -> (PublicKey, Tox.FileRef) -> IO [Event] -> IO [Event]
orCancel tox ts (pk, ref) act = try act >>= \case
  Right events -> pure events
  Left (_ :: IOException) -> do
    void $ Tox.fileControl tox pk ref Tox.FileCancel
    end ts pk ref False

-- | Deletes theirs if it's incomplete.
end :: Transfers -> PublicKey -> Tox.FileRef -> Bool -> IO [Event]
end (Transfers v) pk ref whole = modifyMVar v $ \known -> case Map.lookup (pk, ref) known of
  Nothing -> pure (known, [])
  Just t -> do
    close t
    case ref of
      Tox.Incoming _ | not whole -> void (try (removeFile (trPath t)) :: IO (Either IOException ()))
      _ -> pure ()
    pure (Map.delete (pk, ref) known, [FileEnded (trContact t) (fromToxRef ref) whole])

close :: Transfer -> IO ()
close t = forM_ (trHandle t) hClose

-- | Only reports each step.
progress :: FileRef -> Word64 -> Transfer -> (Transfer, [Event])
progress ref done t
  | done >= trReported t + step = (t { trReported = done }, [FileMoved (trContact t) ref done])
  | otherwise = (t, [])
  where step = max (trSize t `div` 100) (64 * 1024)

toxRef :: FileRef -> Tox.FileRef
toxRef = \case
  Sending n -> Tox.Outgoing n
  Receiving n -> Tox.Incoming n

fromToxRef :: Tox.FileRef -> FileRef
fromToxRef = \case
  Tox.Outgoing n -> Sending n
  Tox.Incoming n -> Receiving n

-- | Cut to what a file system takes. Keeps the extension unless it's too
-- long to be one.
fitted :: String -> FilePath -> FilePath
fitted prefix name
  | length prefix + length name <= limit = prefix <> name
  | otherwise = prefix <> take (limit - length prefix - length extension) base <> extension
  where
    limit = 255
    (base, extension) = case splitExtension name of
      (b, e) | length e <= maxExtension -> (b, e)
      _                                 -> (name, "")
    maxExtension = 16

-- | ASCII file name: no directories, not hidden, and nothing a path's
-- encoding could lose.
safeName :: Text -> FilePath
safeName name = case Text.unpack (Text.dropWhile (== '.') (Text.map plain name)) of
  "" -> "file"
  n  -> n
  where plain c = if isAscii c && (isAlphaNum c || c `elem` ['.', '_', '-']) then c else '_'
