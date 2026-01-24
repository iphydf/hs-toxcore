\subsection{Replies to RPC requests}
A \textit{reply} to a Request packet is a Response packet with the Request ID in
the Response packet set equal to the Request ID in the Request packet.  A
response is accepted if and only if it is the first received reply to a request
which was sent sufficiently recently, according to a time limit which depends on
the service.

\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.DHT.PendingReplies
  ( PendingReplies
  , empty
  , size
  , expectReply
  , checkExpectedReply
  , dropOlder
  ) where

import           Data.Map                  (Map)
import qualified Data.Map.Strict           as Map

import           Tox.Core.Time             (Timestamp)
import qualified Tox.DHT.RpcPacket         as RpcPacket
import           Tox.Network.Core.NodeInfo (NodeInfo)

{-------------------------------------------------------------------------------
 -
 - :: Implementation.
 -
 ------------------------------------------------------------------------------}

-- | By request ID, to find a reply among many, and by time, to drop the old
-- ones without looking at the others.
data PendingReplies = PendingReplies
  { byId   :: Map RpcPacket.RequestId (NodeInfo, Timestamp)
  , byTime :: Map Timestamp [RpcPacket.RequestId]
  } deriving (Eq, Read, Show)

empty :: PendingReplies
empty = PendingReplies Map.empty Map.empty

size :: PendingReplies -> Int
size = Map.size . byId

expectReply :: Timestamp -> NodeInfo -> RpcPacket.RequestId ->
  PendingReplies -> PendingReplies
expectReply time node requestId (PendingReplies ids times) =
  PendingReplies (Map.insert requestId (node, time) ids) (Map.insertWith (++) time [requestId] times)

checkExpectedReply :: Timestamp -> NodeInfo -> RpcPacket.RequestId ->
  PendingReplies -> (Bool, PendingReplies)
checkExpectedReply cutoff node requestId pending@(PendingReplies ids times) =
  case Map.lookup requestId ids of
    Just (asked, time) | asked == node, time >= cutoff ->
      (True, PendingReplies (Map.delete requestId ids) (Map.adjust (filter (/= requestId)) time times))
    _ -> (False, pending)

-- | Forgets requests sent before then.
dropOlder :: Timestamp -> PendingReplies -> PendingReplies
dropOlder time (PendingReplies ids times) =
  let (old, kept) = Map.spanAntitone (< time) times
  in PendingReplies (foldr Map.delete ids (concat old)) kept

{-------------------------------------------------------------------------------
 -
 - :: Tests.
 -
 ------------------------------------------------------------------------------}

\end{code}
