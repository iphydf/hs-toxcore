module Tox.Crypto.Core.GeneratorSpec (spec) where

import qualified Data.ByteString           as BS
import           Data.List                 (mapAccumL)
import           Data.Maybe                (fromJust)
import           Test.Hspec
import           Test.QuickCheck

import           Tox.Crypto.Core.Generator

keyed :: [Int] -> Generator
keyed = fromJust . newGenerator . BS.pack . map fromIntegral . take 32 . cycle . (++ [0])

spec :: Spec
spec = describe "Generator" $ do
  it "gives the same bytes however they're taken" $ property $ \key ->
    forAll (listOf (choose (1, 3000))) $ \sizes ->
      let g = keyed key
          apart = BS.concat . snd $ mapAccumL (\g' k -> let (b, g'') = takeBytes k g' in (g'', b)) g sizes
      in apart `shouldBe` fst (takeBytes (sum sizes) g)

  it "never gives a block again, nor another key's bytes" $ property $ \key ->
    let (first, g) = takeBytes 4096 (keyed key)
        (second, _) = takeBytes 4096 g
        other = fst (takeBytes 4096 (keyed (1 : key)))
    in (first /= second, first /= other) `shouldBe` (True, True)
