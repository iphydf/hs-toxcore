\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Transport.Stream where

import           Data.Map                  (Map)
import qualified Data.Map                  as Map
import           Data.Word                 (Word64)
import           Tox.Core.Time             (Timestamp, TimeDiff)
import qualified Tox.Core.Time             as Time
import           Tox.Transport.Reliability (SeqNum)

-- | State for Congestion Control (CC) and RTT tracking.
data StreamState = StreamState
  { ssMinRTT             :: Maybe TimeDiff -- ^ Lowest observed RTT
  , ssLastRTT            :: Maybe TimeDiff -- ^ Most recent observed RTT
  , ssSendHistory        :: Map SeqNum Timestamp -- ^ When each lossless packet was sent
  , ssSentLastInterval   :: Int             -- ^ Packets sent in the current 1.2s window
  , ssIntervalStart      :: Timestamp       -- ^ Start of the current 1.2s window
  , ssSendQueueSizeStart :: Int             -- ^ Send queue size at start of interval
  , ssCurrentSendRate    :: Double          -- ^ Packets per second
  , ssLastCongestion     :: Maybe Timestamp -- ^ Last time a congestion event occurred
  } deriving (Eq, Show)

-- | Initial CC state.
initState :: Timestamp -> StreamState
initState now = StreamState
  { ssMinRTT             = Nothing
  , ssLastRTT            = Nothing
  , ssSendHistory        = Map.empty
  , ssSentLastInterval   = 0
  , ssIntervalStart      = now
  , ssSendQueueSizeStart = 0
  , ssCurrentSendRate    = 8.0 -- Minimum 8 packets/sec
  , ssLastCongestion     = Nothing
  }

-- | Record when a lossless packet was sent.
recordPacketSent :: SeqNum -> Timestamp -> StreamState -> StreamState
recordPacketSent s now state = state
  { ssSendHistory      = Map.insert s now (ssSendHistory state)
  , ssSentLastInterval = ssSentLastInterval state + 1
  }

-- | Record when a packet was acknowledged by the peer.
-- Updates RTT metrics.
recordPacketAcked :: SeqNum -> Timestamp -> StreamState -> StreamState
recordPacketAcked s now state =
  case Map.lookup s (ssSendHistory state) of
    Nothing -> state -- Already acked or too old
    Just sentTime ->
      let rtt = now `Time.diffTime` sentTime
          newMin = case ssMinRTT state of
            Nothing -> Just rtt
            Just oldMin -> Just (min oldMin rtt)
      in state
        { ssLastRTT     = Just rtt
        , ssMinRTT      = newMin
        , ssSendHistory = Map.delete s (ssSendHistory state)
        }

ccInterval :: Time.TimeDiff
ccInterval = Time.milliseconds 1200

congestionMemory :: Time.TimeDiff
congestionMemory = Time.seconds 2

-- | Periodically update the send rate based on throughput.
-- Should be called approximately every 1.2s.
updateSendRate :: Int -> Timestamp -> StreamState -> StreamState
updateSendRate currentQueueSize now state =
  let
    elapsed = now `Time.diffTime` ssIntervalStart state
  in
    if elapsed < ccInterval
    then state
    else
      let
        -- Formula: (N - (Q_now - Q_prev)) / 1.2
        throughput = fromIntegral (ssSentLastInterval state - (currentQueueSize - ssSendQueueSizeStart state)) / 1.2
        
        -- Apply floor of 8.0
        baseRate = max 8.0 throughput
        
        -- If no congestion in last 2s, increase rate by 25%
        hasCongestionRecently = case ssLastCongestion state of
          Nothing -> False
          Just t -> now `Time.diffTime` t < congestionMemory
          
        newRate = if hasCongestionRecently then baseRate else baseRate * 1.25
      in
        state
          { ssIntervalStart      = now
          , ssSentLastInterval   = 0
          , ssSendQueueSizeStart = currentQueueSize
          , ssCurrentSendRate    = newRate
          }

-- | Record a congestion event (e.g. when peer requests many packets).
recordCongestion :: Timestamp -> StreamState -> StreamState
recordCongestion now state = state { ssLastCongestion = Just now }
\end{code}

The ping or rtt (round trip time) between two peers can be calculated by saving
the time each packet was sent and taking the difference between the time the
latest packet confirmed received by a request packet was sent and the time the
request packet was received.  The rtt can be calculated for every request
packet.  The lowest one (for all packets) will be the closest to the real ping.

This ping or rtt can be used to know if a request packet that requests a packet
we just sent should be resent right away or we should wait or not for the next
one (to know if the other side actually had time to receive the packet).

The congestion control algorithm has the goal of guessing how many packets can
be sent through the link every second before none can be sent through anymore.
How it works is basically to send packets faster and faster until none can go
through the link and then stop sending them faster than that.

Currently the congestion control uses the following formula in toxcore however
that is probably not the best way to do it.

The current formula is to take the difference between the current size of the
send queue and the size of the send queue 1.2 seconds ago, take the total
number of packets sent in the last 1.2 seconds and subtract the previous number
from it.

Then divide this number by 1.2 to get a packet speed per second.  If this speed
is lower than the minimum send rate of 8 packets per second, set it to 8.

A congestion event can be defined as an event when the number of requested
packets exceeds the number of packets the congestion control says can be sent
during this frame.  If a congestion event occurred during the last 2 seconds,
the packet send rate of the connection is set to the send rate previously
calculated, if not it is set to that send rate times 1.25 in order to increase
the speed.

Like I said this isn't perfect and a better solution can likely be found or the
numbers tweaked.

To fix the possible issue where it would be impossible to send very low
bandwidth data like text messages when sending high bandwidth data like files
it is possible to make priority packets ignore the congestion control
completely by placing them into the send packet queue and sending them even if
the congestion control says not to.  This is used in toxcore for all non file
transfer packets to prevent file transfers from preventing normal message
packets from being sent.