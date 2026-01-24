\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Network.Core.Backend where
\end{code}

\chapter{network.txt}

The network module is the lowest file in toxcore that everything else depends
on.  This module is basically a UDP socket wrapper, serves as the sorting
ground for packets received by the socket, initializes and uninitializes the
socket.  It also contains many socket, networking related and some other
functions like a monotonic time function used by other toxcore modules.

Things of note in this module are the maximum UDP packet size define
(\texttt{MAX\_UDP\_PACKET\_SIZE}) which sets the maximum UDP packet size toxcore
can send and receive.  The list of all UDP packet ids: \texttt{NET\_PACKET\_*}.
UDP packet ids are the value of the first byte of each UDP packet and is how
each packet gets sorted to the right module that can handle it.
\texttt{networking\_registerhandler()} is used by higher level modules in order
to tell the network object which packets to send to which module via a
callback.

It also contains datastructures used for ip addresses in toxcore.  IP4 and IP6
are the datastructures for ipv4 and ipv6 addresses, IP is the datastructure for
storing either (the family can be set to \texttt{AF\_INET} (ipv4) or
\texttt{AF\_INET6} (ipv6).  It can be set to another value like
\texttt{TCP\_ONION\_FAMILY}, \texttt{TCP\_INET}, \texttt{TCP\_INET6} or
\texttt{TCP\_FAMILY} which are invalid values in the network modules but valid
values in some other module and denote a special type of ip) and
\texttt{IP\_Port} stores an IP datastructure with a port.

Since the network module interacts directly with the underlying operating
system with its socket functions it has code to make it work on windows, linux,
etc... unlike most modules that sit at a higher level.

The network module currently uses the polling method to read from the UDP
socket.  The \texttt{networking\_poll()} function is called to read all the
packets from the socket and pass them to the callbacks set using the
\texttt{networking\_registerhandler()} function.  The reason it uses polling is
simply because it was easier to write it that way, another method would be
better here.

The goal of this module is to provide an easy interface to a UDP socket and
other networking related functions.
