{-# LANGUAGE OverloadedStrings #-}
-- | Group packets, signed and opened again.
module Tox.Chat.GroupChatPacketsSpec (spec) where

import qualified Crypto.Saltine.Class               as Sodium
import           Data.Bits                          (complement)
import qualified Data.ByteString                    as BS
import           Data.List                          (sort)
import           Data.Maybe                         (fromJust, isNothing)
import           Data.Word                          (Word8)
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Chat.GroupChatPackets
import qualified Tox.Crypto.Core.Sign               as Sign
import           Tox.Network.Core.HostAddress       (HostAddress (..))
import           Tox.Network.Core.NodeInfo          (NodeInfo (..))
import           Tox.Network.Core.PortNumber        (PortNumber (..))
import           Tox.Network.Core.SocketAddress     (SocketAddress (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import           Tox.Onion.GroupAnnounce

keysOf :: Word8 -> Sign.SignKeyPair
keysOf = fromJust . Sign.signKeyPairFromSeed . BS.replicate 32

keyOf :: Sodium.IsEncoding a => Word8 -> a
keyOf = fromJust . Sodium.decode . BS.replicate 32

bytesUpTo :: Int -> Gen BS.ByteString
bytesUpTo n = BS.pack <$> (choose (0, n) >>= vector)

stateWith :: BS.ByteString -> BS.ByteString -> SharedState
stateWith name password = SharedState 3 (keyOf 1) (Sign.signPublicKey (keysOf 2)) 100 name 1 password
  (BS.replicate Sign.sha256Length 7) 0 2

-- | The bytes with 1 byte changed.
flipped :: Int -> BS.ByteString -> BS.ByteString
flipped i bytes = case BS.splitAt i bytes of
  (front, back) | Just (b, rest) <- BS.uncons back -> front <> BS.cons (complement b) rest
  _                                                 -> bytes

spec :: Spec
spec = do
  describe "the shared state" $ do
    let chat = keysOf 9
    it "opens as the chat signed it" $
      forAll ((,) . BS.cons 0x61 <$> bytesUpTo (maxGroupNameSize - 1) <*> bytesUpTo maxPasswordSize) $ \(name, password) ->
        (fst <$> openSharedState (Sign.signPublicKey chat) (signSharedState chat (stateWith name password)))
          === Just (stateWith name password)
    it "doesn't open changed" $ do
      let signed = signSharedState chat (stateWith "Lab" "pw")
      forAll (choose (0, BS.length signed - 1)) $ \i ->
        isNothing (openSharedState (Sign.signPublicKey chat) (flipped i signed))
    it "doesn't open signed by another" $
      openSharedState (Sign.signPublicKey (keysOf 8)) (signSharedState chat (stateWith "Lab" "pw"))
        `shouldSatisfy` isNothing

  describe "the topic" $ do
    let setter = keysOf 4
        topicOf text = TopicInfo 5 text (Sign.signPublicKey setter)
    it "opens as its setter signed it" $
      forAll (bytesUpTo maxTopicSize) $ \text ->
        ((\(info, _, _) -> info) <$> openTopic (signTopic setter (topicOf text))) === Just (topicOf text)
    it "doesn't open changed" $ do
      let signed = signTopic setter (topicOf "plans")
      forAll (choose (0, BS.length signed - 1)) $ \i -> isNothing (openTopic (flipped i signed))

  describe "the moderators" $
    it "come back sorted, and hash the same in any order" $
      forAll (choose (0, 10) >>= flip vectorOf (BS.pack <$> vector 32)) $ \mods ->
        (unpackModList (packModList mods), modListHash mods) === (Just (sort mods), modListHash (reverse mods))

  describe "the sanctions" $ do
    let founder = keysOf 5
        sanctions = [makeSanction founder sanctionTimeSet (keyOf n) | n <- [11, 12]]
        list = packSanctionsList sanctions (makeCreds founder sanctions 2)
    it "open when their setter may set them" $
      fst <$> openSanctionsList [Sign.signPublicKey founder] list `shouldBe` Just sanctions
    it "don't when their setter may not" $
      openSanctionsList [Sign.signPublicKey (keysOf 6)] list `shouldSatisfy` isNothing
    it "don't once changed" $
      forAll (choose (2, BS.length list - 1)) $ \i ->
        isNothing (openSanctionsList [Sign.signPublicKey founder] (flipped i list))

  describe "announcements" $ do
    let udp = SocketAddress (IPv4 0x0100007f) (PortNumber 33445)
        relay = NodeInfo TCP (SocketAddress (IPv4 0x0100007f) (PortNumber 3389)) (keyOf 3)
        announce = Announce (keyOf 2) (Just udp) (Just relay)
    it "read back as written" $ do
      unpackAnnounce (packAnnounce announce) `shouldBe` Just announce
      unpackAnnounces (packAnnounce announce <> packAnnounce announce { anRelay = Nothing })
        `shouldBe` Just [announce, announce { anRelay = Nothing }]
    it "name one relay at most, as toxcore reads them" $ do
      let packed = packAnnounce announce
          (start, rest) = BS.splitAt 33 packed
      unpackAnnounce (start <> BS.cons 2 (BS.drop 1 rest)) `shouldBe` Nothing
