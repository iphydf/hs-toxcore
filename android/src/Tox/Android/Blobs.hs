{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Account sync blobs to and from a linked account's home: files of their
-- own kind whose ID is the SHA-256. Stored on disk by ID in hex. We only
-- take ones we asked for, and only if the hash matches.
module Tox.Android.Blobs
  ( Blobs
  , newBlobs
  , blobKind
  , pathOf
  , store
  , storeFile
  , want
  , located
  , serve
  , offered
  , has
  , requested
  , received
  , cancelled
  , friendGone
  , flush
  ) where

import           Control.Concurrent.MVar (MVar, modifyMVar, modifyMVar_,
                                          newMVar, readMVar)
import           Control.Exception       (IOException, catch, try)
import           Control.Monad           (join, void)
import qualified Crypto.Hash.SHA256      as SHA256
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base16  as Base16
import qualified Data.ByteString.Char8   as Char8
import           Data.Map.Strict         (Map)
import qualified Data.Map.Strict         as Map
import           Data.Maybe              (fromMaybe)
import           Data.Word               (Word32, Word64, Word8)
import           System.Directory        (copyFile, createDirectoryIfMissing,
                                          doesFileExist, getFileSize,
                                          removeFile, renameFile)
import           System.FilePath         ((</>))
import           System.IO               (Handle, IOMode (..), SeekMode (..),
                                          hClose, hSeek, openBinaryFile,
                                          withBinaryFile)
import           System.Posix.Files      (createLink)
import qualified Tox.Application.Tox     as Tox
import           Tox.Crypto.Core.Key     (PublicKey)

import qualified Tox.Android.Avatars     as Avatars
import           Tox.Android.Model       (Event (..))

data Transfer
  = Sending FilePath [(Word64, Int)]
    -- ^ With the chunks Tox had no room for yet, in order.
  | Taking BS.ByteString Word64 Handle SHA256.Ctx Word64
    -- ^ Expected blob ID and size, the file, and the hash and size so far.

data Blobs = Blobs
  { blobsDir       :: FilePath
  , blobsTransfers :: MVar (Map (PublicKey, Tox.FileRef) Transfer)
  , blobsWanted    :: MVar (Map (PublicKey, BS.ByteString) (Maybe FilePath))
    -- ^ Where each goes, if not with the others.
  }

newBlobs :: FilePath -> IO Blobs
newBlobs dir = do
  createDirectoryIfMissing True dir
  Blobs dir <$> newMVar Map.empty <*> newMVar Map.empty

-- | File kind for blobs.
blobKind :: Word32
blobKind = 176

pathOf :: Blobs -> BS.ByteString -> FilePath
pathOf blobs blob = blobsDir blobs </> Char8.unpack (Base16.encode blob)

-- | Returns the blob ID.
store :: Blobs -> BS.ByteString -> IO BS.ByteString
store blobs bytes = blob <$ BS.writeFile (pathOf blobs blob) bytes
  where blob = SHA256.hash bytes

-- | Stores a copy. Returns the blob ID.
storeFile :: Blobs -> FilePath -> IO BS.ByteString
storeFile blobs path = do
  blob <- withBinaryFile path ReadMode $ \h ->
    let go ctx = BS.hGetSome h chunkSize >>= \bytes ->
          if BS.null bytes then pure (SHA256.finalize ctx) else go (SHA256.update ctx bytes)
    in go SHA256.init
  blob <$ keepAs path (pathOf blobs blob)
  where chunkSize = 64 * 1024

-- | Accept it when the friend offers it.
want :: Blobs -> PublicKey -> BS.ByteString -> Maybe FilePath -> IO ()
want blobs pk blob target = modifyMVar_ (blobsWanted blobs) (pure . Map.insert (pk, blob) target)

-- | Path if we have it. Copied to the target if it's only with the others.
located :: Blobs -> BS.ByteString -> Maybe FilePath -> IO (Maybe FilePath)
located blobs blob target = do
  let kept = pathOf blobs blob
  there <- maybe (pure False) doesFileExist target
  ours <- doesFileExist kept
  case target of
    Just path | there -> pure (Just path)
              | ours -> Just path <$ keepAs kept path
    Nothing | ours -> pure (Just kept)
    _ -> pure Nothing

-- | False if we don't have it.
serve :: Tox.Tox -> Blobs -> PublicKey -> BS.ByteString -> IO Bool
serve tox blobs pk blob = doesFileExist path >>= \case
  False -> pure False
  True -> do
    size <- getFileSize path
    Tox.fileSend tox pk blobKind (fromIntegral size) (Just blob) (Base16.encode blob) >>= \case
      Right n -> True <$ modifyMVar_ (blobsTransfers blobs) (pure . Map.insert (pk, Tox.Outgoing n) (Sending path []))
      Left _ -> pure False
  where path = pathOf blobs blob

-- | Only accepted if we asked for it.
offered :: Tox.Tox -> Blobs -> PublicKey -> Word8 -> Word64 -> BS.ByteString -> IO ()
offered tox blobs pk n size blob = do
  asked <- Map.member (pk, blob) <$> readMVar (blobsWanted blobs)
  if not asked then void $ Tox.fileControl tox pk ref Tox.FileCancel else do
    h <- openBinaryFile (partOf blobs blob) WriteMode
    modifyMVar_ (blobsTransfers blobs) (pure . Map.insert (pk, ref) (Taking blob size h SHA256.init 0))
    void $ Tox.fileControl tox pk ref Tox.FileResume
  where ref = Tox.Incoming n

partOf :: Blobs -> BS.ByteString -> FilePath
partOf blobs blob = pathOf blobs blob <> ".part"

has :: Blobs -> PublicKey -> Tox.FileRef -> IO Bool
has blobs pk ref = Map.member (pk, ref) <$> readMVar (blobsTransfers blobs)

-- | Length 0 means the friend has all of it.
requested :: Tox.Tox -> Blobs -> PublicKey -> Word8 -> Word64 -> Int -> IO ()
requested tox blobs pk n position len
  | len == 0 = modifyMVar_ (blobsTransfers blobs) (pure . Map.delete key)
  | otherwise = do
      modifyMVar_ (blobsTransfers blobs) $ pure . Map.adjust (\case
        Sending path unsent -> Sending path (unsent ++ [(position, len)])
        other -> other) key
      flushOne tox blobs key
  where key = (pk, Tox.Outgoing n)

-- | When complete, gives the blob and its file (and bytes if it's small
-- enough to be an avatar), or missing if the hash doesn't match.
received :: Tox.Tox -> Blobs -> PublicKey -> Word8 -> Word64 -> BS.ByteString -> IO [Event]
received tox blobs pk n position bytes = modifyMVar (blobsTransfers blobs) $ \known -> case Map.lookup key known of
  Just (Taking blob size h ctx got)
    | BS.null bytes -> do
        hClose h
        let whole = got == size && SHA256.finalize ctx == blob
        events <- if not whole then [BlobMissing blob] <$ removeQuietly (partOf blobs blob) else do
          target <- modifyMVar (blobsWanted blobs) $ \wanted ->
            pure (Map.delete (pk, blob) wanted, join (Map.lookup (pk, blob) wanted))
          let path = fromMaybe (pathOf blobs blob) target
          renameFile (partOf blobs blob) path
          small <- if size <= fromIntegral Avatars.maxSize then Just <$> BS.readFile path else pure Nothing
          pure [BlobArrived blob path small]
        pure (Map.delete key known, events)
    | position == got && got + fromIntegral (BS.length bytes) <= size -> do
        BS.hPut h bytes
        pure (Map.insert key (Taking blob size h (SHA256.update ctx bytes) (got + fromIntegral (BS.length bytes))) known, [])
    | otherwise -> do
        hClose h
        removeQuietly (partOf blobs blob)
        void $ Tox.fileControl tox pk (Tox.Incoming n) Tox.FileCancel
        pure (Map.delete key known, [BlobMissing blob])
  _ -> pure (known, [])
  where key = (pk, Tox.Incoming n)

cancelled :: Blobs -> PublicKey -> Tox.FileRef -> IO ()
cancelled blobs pk ref = modifyMVar_ (blobsTransfers blobs) $ \known -> do
  mapM_ (dropped blobs) (Map.lookup (pk, ref) known)
  pure (Map.delete (pk, ref) known)

-- | Tox ends a friend's transfers when they go offline. We ask again in the
-- next session.
friendGone :: Blobs -> PublicKey -> IO ()
friendGone blobs pk = do
  modifyMVar_ (blobsTransfers blobs) $ \known -> do
    let (gone, kept) = Map.partitionWithKey (\(p, _) _ -> p == pk) known
    mapM_ (dropped blobs) gone
    pure kept
  modifyMVar_ (blobsWanted blobs) (pure . Map.filterWithKey (\(p, _) _ -> p /= pk))

dropped :: Blobs -> Transfer -> IO ()
dropped blobs = \case
  Taking blob _ h _ _ -> hClose h >> removeQuietly (partOf blobs blob)
  Sending _ _ -> pure ()

-- | Hard link if the file system allows it, else a copy.
keepAs :: FilePath -> FilePath -> IO ()
keepAs from to = doesFileExist to >>= \case
  True -> pure ()
  False -> createLink from to `catch` \(_ :: IOException) -> copyFile from to

removeQuietly :: FilePath -> IO ()
removeQuietly path = void (try (removeFile path) :: IO (Either IOException ()))

-- | Retry chunks Tox had no room for.
flush :: Tox.Tox -> Blobs -> IO ()
flush tox blobs = do
  waiting <- Map.keys . Map.filter (\case Sending _ (_ : _) -> True; _ -> False) <$> readMVar (blobsTransfers blobs)
  mapM_ (flushOne tox blobs) waiting

flushOne :: Tox.Tox -> Blobs -> (PublicKey, Tox.FileRef) -> IO ()
flushOne tox blobs key@(pk, ref) = modifyMVar_ (blobsTransfers blobs) $ \known -> case (Map.lookup key known, ref) of
  (Just (Sending path unsent), Tox.Outgoing n) -> do
    left <- go n path unsent
    pure (Map.insert key (Sending path left) known)
  _ -> pure known
  where
    go n path = \case
      [] -> pure []
      unsent@((position, len) : rest) -> do
        chunk <- withBinaryFile path ReadMode $ \h -> hSeek h AbsoluteSeek (fromIntegral position) >> BS.hGet h len
        Tox.fileSendChunk tox pk n position chunk >>= \case
          Left Tox.FileSendQueueFull -> pure unsent
          _ -> go n path rest
