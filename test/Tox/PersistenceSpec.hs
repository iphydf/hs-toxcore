{-# LANGUAGE StrictData  #-}
{-# LANGUAGE Trustworthy #-}
module Tox.PersistenceSpec where

import           Test.Hspec
import           Test.Hspec.QuickCheck         (modifyMaxSize)

import qualified Data.Binary                   as Binary (get)
import qualified Data.Binary.Get               as Binary (Get)
import           Data.Proxy                    (Proxy (..))
import qualified Tox.Network.Core.EncodingSpec as EncodingSpec (expectDecoderFail)
import           Tox.Network.Core.EncodingSpec (binarySpec)
import           Tox.Persistence               (SaveData)


spec :: Spec
spec = do
  -- Each kind of section has its own spec at full size. This is how they go
  -- together, which small sections show as well.
  modifyMaxSize (const 10) $ binarySpec (Proxy :: Proxy SaveData)

  it "should handle invalid magic numbers" $ do
    expectDecoderFail [0x00, 0x00, 0x00, 0x01]
      "savedata should start with 32 zero-bits"
    expectDecoderFail [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
      "wrong magic number"

  where
    expectDecoderFail =
      EncodingSpec.expectDecoderFail (Binary.get :: Binary.Get SaveData)
