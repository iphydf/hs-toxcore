\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Transport.Stream where
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
