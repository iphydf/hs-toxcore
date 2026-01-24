module Tox.Network.Core.TrafficSpec (spec) where

import           Test.Hspec

import           Tox.Network.Core.Traffic

spec :: Spec
spec = describe "Traffic" $ do
  it "gives every counted thing its own slot" $
    map slot everything `shouldBe` [0 .. length everything - 1]

  it "adds up what it counts" $ do
    t <- newTraffic
    count t (Packets Sent Udp 2) 10
    count t (Requests SearchFriend) 5
    count t (Packets Sent Udp 2) 30
    totals t `shouldReturn` [(Packets Sent Udp 2, Count 2 40), (Requests SearchFriend, Count 1 5)]
