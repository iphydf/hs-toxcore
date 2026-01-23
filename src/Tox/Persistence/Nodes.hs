{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE StrictData                 #-}
module Tox.Persistence.Nodes
    ( Nodes (..)
    ) where

import           Data.Binary               (Binary (..))
import           Data.MessagePack          (MessagePack)
import           GHC.Generics              (Generic)
import           Test.QuickCheck.Arbitrary (Arbitrary, arbitrary)
import           Tox.Network.NodeInfo      (NodeInfo)
import qualified Tox.Persistence.Util      as Util

newtype Nodes = Nodes [NodeInfo]
    deriving (Eq, Show, Read, Generic)

instance MessagePack Nodes

instance Binary Nodes where
    get = Nodes <$> Util.getList
    put (Nodes xs) = mapM_ put xs

instance Arbitrary Nodes where
    arbitrary = Nodes <$> arbitrary
