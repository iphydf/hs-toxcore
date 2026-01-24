\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.DHT.ClientNode where

import           Test.QuickCheck.Arbitrary (Arbitrary, arbitrary)

import           Tox.Core.Time             (Timestamp)
import           Tox.Network.Core.NodeInfo      (NodeInfo)


{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

data ClientNode = ClientNode
  { nodeInfo   :: NodeInfo
  , lastCheck  :: Timestamp
  , checkCount :: Int
  }
  deriving (Eq, Read, Show)

newNode :: Timestamp -> NodeInfo -> ClientNode
newNode time node = ClientNode node time 0

{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}

instance Arbitrary ClientNode where
  arbitrary = ClientNode <$> arbitrary <*> arbitrary <*> arbitrary

\end{code}
