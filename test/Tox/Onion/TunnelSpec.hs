{-# LANGUAGE ScopedTypeVariables #-}
module Tox.Onion.TunnelSpec (spec) where

import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Test.QuickCheck

import           Data.Binary           (decode, encode)
import qualified Data.ByteString.Lazy  as LBS

import           Tox.Onion.Tunnel

spec :: Spec
spec = do
  describe "OnionIPPort" $ do
    prop "roundtrips Binary" $ \(x :: OnionIPPort) ->
      decode (encode x) == x

    it "has fixed size of 19 bytes" $ property $ \(x :: OnionIPPort) ->
      LBS.length (encode x) == 19

  describe "OnionRequest0" $
    prop "roundtrips Binary" $ \(x :: OnionRequest0) ->
      decode (encode x) == x

  describe "OnionRequestRelay" $
    prop "roundtrips Binary" $ \(x :: OnionRequestRelay) ->
      decode (encode x) == x

  describe "OnionRequestPayload" $
    prop "roundtrips Binary" $ \(x :: OnionRequestPayload) ->
      decode (encode x) == x

  describe "OnionResponse" $
    prop "roundtrips Binary" $ \(x :: OnionResponse) ->
      decode (encode x) == x
