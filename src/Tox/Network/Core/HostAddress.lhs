\section{Host Address}

A Host Address is either an IPv4 or an IPv6 address.  The binary representation
of an IPv4 address is a Big Endian 32 bit unsigned integer (4 bytes).  For an
IPv6 address, it is a Big Endian 128 bit unsigned integer (16 bytes).  The
binary representation of a Host Address is a 7 bit unsigned integer specifying
the address family (2 for IPv4, 10 for IPv6), followed by the address itself.

Thus, when packed together with the Transport Protocol, the first bit of the
packed byte is the protocol and the next 7 bits are the address family.

\begin{code}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE StrictData         #-}
module Tox.Network.Core.HostAddress where

import           Control.Arrow             ((&&&))
import           Control.Monad             (guard)
import           Data.Binary               (Binary)
import qualified Data.Binary               as Binary (get, put)
import qualified Data.Binary.Get           as Bytes
import qualified Data.Binary.Put           as Bytes
import           Data.Bits                 (shiftL, shiftR, (.|.))
import           Data.Char                 (isDigit, isHexDigit)
import           Data.List                 (intercalate, isPrefixOf)
import           Data.MessagePack          (MessagePack)
import           Data.Typeable             (Typeable)
import           Data.Word                 (Word16, Word32, Word8)
import           GHC.Generics              (Generic)
import           Numeric                   (readHex, showHex)
import           Test.QuickCheck.Arbitrary (Arbitrary, arbitrary)
import qualified Test.QuickCheck.Gen       as Gen
import           Text.Read                 (readMaybe, readPrec)
import qualified Tox.Core.Bits.Get         as Bits
import qualified Tox.Core.Bits.Put         as Bits


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}


-- | An IPv4 address with its first octet in the lowest byte, as sockets
-- hold it on little-endian systems.
type IPv4Address = Word32

-- | An IPv6 address in four 32 bit words, the most significant first.
type IPv6Address = (Word32, Word32, Word32, Word32)

data HostAddress
  = IPv4 IPv4Address
  | IPv6 IPv6Address
  deriving (Eq, Ord, Generic, Typeable)

instance Binary HostAddress
instance MessagePack HostAddress


instance Show HostAddress where
  show = show . showAddress


instance Read HostAddress where
  readPrec = readPrec >>= maybe (fail "HostAddress") return . readAddress


hostAddressToTuple :: IPv4Address -> (Word8, Word8, Word8, Word8)
hostAddressToTuple addr = (byte 0, byte 8, byte 16, byte 24)
  where
    byte n = fromIntegral (addr `shiftR` n)

tupleToHostAddress :: (Word8, Word8, Word8, Word8) -> IPv4Address
tupleToHostAddress (a, b, c, d) = foldr (\octet rest -> rest `shiftL` 8 .|. fromIntegral octet) 0 [a, b, c, d]

-- | As inet_ntop writes it: IPv6 as RFC 5952 recommends.
showAddress :: HostAddress -> String
showAddress (IPv4 addr) = dotted (hostAddressToTuple addr)
showAddress (IPv6 (a1, a2, a3, a4))
  | a1 == 0 && a2 == 0 && a3 == 0xffff = "::ffff:" ++ dotted (wordOctets a4)
  | a1 == 0 && a2 == 0 && a3 == 0 && a4 >= 0x10000 = "::" ++ dotted (wordOctets a4)
  | end - begin > 1 = hex (take begin fields) ++ "::" ++ hex (drop end fields)
  | otherwise = hex fields
  where
    fields = concatMap halves [a1, a2, a3, a4]
    hex = intercalate ":" . map (`showHex` "")
    -- The longest run of zeros, the first of those.
    (diff, end) = minimum $ scanl (\run field -> if field == 0 then run - 1 else 0) 0 fields `zip` [0 :: Int ..]
    begin = end + diff

dotted :: (Word8, Word8, Word8, Word8) -> String
dotted (a, b, c, d) = intercalate "." $ map show [a, b, c, d]

-- | Most significant first.
wordOctets :: Word32 -> (Word8, Word8, Word8, Word8)
wordOctets w = (byte 24, byte 16, byte 8, byte 0)
  where
    byte n = fromIntegral (w `shiftR` n)

halves :: Word32 -> [Word16]
halves w = [fromIntegral (w `shiftR` 16), fromIntegral w]

-- | An address in the forms 'showAddress' writes, and the other forms
-- RFC 4291 allows.
readAddress :: String -> Maybe HostAddress
readAddress str
  | ':' `elem` str = IPv6 <$> readIPv6 str
  | otherwise = IPv4 . tupleToHostAddress <$> readOctets str

readOctets :: String -> Maybe (Word8, Word8, Word8, Word8)
readOctets str = case mapM octet (splitOn '.' str) of
  Just [a, b, c, d] -> Just (a, b, c, d)
  _                 -> Nothing
  where
    octet digits = do
      -- No leading zeros, which some read as octal.
      guard $ not (null digits) && length digits <= 3 && all isDigit digits && (digits == "0" || not ("0" `isPrefixOf` digits))
      n <- readMaybe digits
      guard $ n <= (255 :: Int)
      return $ fromIntegral n

readIPv6 :: String -> Maybe IPv6Address
readIPv6 str = do
  fields <- case breakOn "::" str of
    (whole, Nothing) -> groups whole >>= \fs -> fs <$ guard (length fs == 8)
    (before, Just after) -> do
      front <- if null before then Just [] else groups before
      back <- if null after then Just [] else groups after
      let zeros = 8 - length front - length back
      guard $ zeros >= 1
      return $ front ++ replicate zeros 0 ++ back
  case fields of
    [f1, f2, f3, f4, f5, f6, f7, f8] -> Just (word f1 f2, word f3 f4, word f5 f6, word f7 f8)
    _                                -> Nothing
  where
    word hi lo = fromIntegral hi `shiftL` 16 .|. fromIntegral (lo :: Word16)
    -- Hex fields, the last of which may be an IPv4 address.
    groups part = case splitOn ':' part of
      [] -> Nothing
      fs -> (++) <$> mapM field (init fs) <*> lastField (last fs)
    lastField f
      | '.' `elem` f = (\(a, b, c, d) -> [word8s a b, word8s c d]) <$> readOctets f
      | otherwise = pure <$> field f
    word8s hi lo = fromIntegral hi `shiftL` 8 .|. fromIntegral lo
    field f = case readHex f of
      [(n, "")] | length f <= 4 && all isHexDigit f -> Just (fromIntegral (n :: Int))
      _                                              -> Nothing

splitOn :: Char -> String -> [String]
splitOn c str = case break (== c) str of
  (part, [])       -> [part]
  (part, _ : rest) -> part : splitOn c rest

-- | The text before the first occurrence of a separator, and the text after
-- it if it's there.
breakOn :: String -> String -> (String, Maybe String)
breakOn sep str
  | sep `isPrefixOf` str = ([], Just (drop (length sep) str))
  | otherwise = case str of
      []       -> ([], Nothing)
      c : rest -> let (before, after) = breakOn sep rest in (c : before, after)


getHostAddressGetter :: Bits.BitGet (Bytes.Get HostAddress)
getHostAddressGetter =
  Bits.getWord8 7 >>= \case
    2  -> return $ IPv4 <$> getIPv4
    10 -> return $ IPv6 <$> Binary.get
    n  -> fail $ "Invalid address family: " ++ show n


putAddressFamily :: HostAddress -> Bits.BitPut ()
putAddressFamily (IPv4 _) = Bits.putWord8 7 2
putAddressFamily (IPv6 _) = Bits.putWord8 7 10


putHostAddressValue :: HostAddress -> Bytes.Put
putHostAddressValue (IPv4 addr) = putIPv4 addr
putHostAddressValue (IPv6 addr) = Binary.put addr

-- | 127.0.0.0/8 or ::1, also as an IPv4-mapped IPv6 address.
isLoopback :: HostAddress -> Bool
isLoopback (IPv4 addr) = let (a, _, _, _) = hostAddressToTuple addr in a == 127
isLoopback (IPv6 (0, 0, 0, 1)) = True
isLoopback (IPv6 (0, 0, 0xffff, v4)) = v4 `div` 0x1000000 == 127
isLoopback (IPv6 _) = False

-- | As toxcore decides which LAN discovery packets to take.
isLan :: HostAddress -> Bool
isLan addr | isLoopback addr = True
isLan (IPv4 addr) = isLanIPv4 $ hostAddressToTuple addr
isLan (IPv6 (a, _, _, d))
  | a `div` 0x1000000 == 0xff && (a `div` 0x10000) `mod` 0x100 < 3 && d `mod` 0x100 == 1 = True
  | a `div` 0x400000 == 0xfe80 `div` 0x40 = True
isLan (IPv6 (0, 0, 0xffff, v4)) =
  isLanIPv4 ( fromIntegral $ v4 `div` 0x1000000, fromIntegral $ v4 `div` 0x10000
            , fromIntegral $ v4 `div` 0x100, fromIntegral v4 )
isLan (IPv6 _) = False

isLanIPv4 :: (Word8, Word8, Word8, Word8) -> Bool
isLanIPv4 (a, b, c, _) =
  a == 10
    || (a == 172 && b >= 16 && b <= 31)
    || (a == 192 && b == 168)
    || (a == 169 && b == 254 && c /= 0 && c /= 255)
    || (a == 100 && b >= 64 && b < 128)

-- | IPv4 addresses are sent as their four octets in order.
putIPv4 :: IPv4Address -> Bytes.Put
putIPv4 addr = mapM_ Bytes.putWord8 [a, b, c, d]
  where
    (a, b, c, d) = hostAddressToTuple addr

getIPv4 :: Bytes.Get IPv4Address
getIPv4 = do
  a <- Bytes.getWord8
  b <- Bytes.getWord8
  c <- Bytes.getWord8
  d <- Bytes.getWord8
  return $ tupleToHostAddress (a, b, c, d)


putHostAddress :: HostAddress -> (Bits.BitPut (), Bytes.Put)
putHostAddress = putAddressFamily &&& putHostAddressValue


{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}


instance Arbitrary HostAddress where
  arbitrary =
    Gen.oneof
      [ IPv4 <$> arbitrary
      , IPv6 <$> arbitrary
      ]
\end{code}
