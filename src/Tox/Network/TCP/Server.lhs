\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Network.TCP.Server where
\end{code}

\chapter{TCP server}

The TCP server in tox has the goal of acting like a TCP relay between clients
who cannot connect directly to each other or who for some reason are limited to
using the TCP protocol to connect to each other.  \texttt{TCP\_server} is
typically run only on actual server machines but any Tox client could host one
as the api to run one is exposed through the tox.h api.

To connect to a hosted TCP server toxcore uses the TCP client module.

The TCP server implementation in toxcore can currently either work on epoll on
linux or using unoptimized but portable socket polling.

TCP connections between the TCP client and the server are encrypted to prevent
an outsider from knowing information like who is connecting to whom just be
looking at someones connection to a TCP server.  This is useful when someone
connects though something like Tor for example.  It also prevents someone from
injecting data in the stream and makes it so we can assume that any data
received was not tampered with and is exactly what was sent by the client.

When a client first connects to a TCP server he opens up a TCP connection to
the ip and port the TCP server is listening on.  Once the connection is
established he then sends a handshake packet, the server then responds with his
own and a secure connection is established.  The connection is then said to be
unconfirmed and the client must then send some encrypted data to the server
before the server can mark the connection as confirmed.  The reason it works
like this is to prevent a type of attack where a peer would send a handshake
packet and then time out right away.  To prevent this the server must wait a
few seconds for a sign that the client received his handshake packet before
confirming the connection.  The both can then communicate with each other using
the encrypted connection.

The TCP server essentially acts as just a relay between 2 peers.  When a TCP
client connects to the server he tells the server which clients he wants the
server to connect him to.  The server will only let two clients connect to each
other if both have indicated to the server that they want to connect to each
other.  This is to prevent non friends from checking if someone is connected to
a TCP server.  The TCP server supports sending packets blindly through it to
clients with a client with public key X (OOB packets) however the TCP server
does not give any feedback or anything to say if the packet arrived or not and
as such it is only useful to send data to friends who may not know that we are
connected to the current TCP server while we know they are.  This occurs when
one peer discovers the TCP relay and DHT public key of the other peer before
the other peer discovers its DHT public key.  In that case OOB packets would be
used until the other peer knows that the peer is connected to the relay and
establishes a connection through it.

In order to make toxcore work on TCP only the TCP server supports relaying
onion packets from TCP clients and sending any responses from them to TCP
clients.

To establish a secure connection with a TCP server send the following 128 bytes
of data or handshake packet to the server:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{32}        & DHT public key of client \\
  \texttt{24}        & Nonce for the encrypted data \\
  \texttt{72}        & Payload (plus MAC) \\
\end{tabular}

Payload is encrypted with the DHT private key of the client and public key of
the server and the nonce:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{32}        & Public key \\
  \texttt{24}        & Base nonce \\
\end{tabular}

The base nonce is the one TCP client wants the TCP server to use to decrypt the
packets received from the TCP client.

The first 32 bytes are the public key (DHT public key) that the TCP client is
announcing itself to the server with.  The next 24 bytes are a nonce which the
TCP client uses along with the secret key associated with the public key in the
first 32 bytes of the packet to encrypt the rest of this 'packet'.  The
encrypted part of this packet contains a temporary public key that will be used
for encryption during the connection and will be discarded after.  It also
contains a base nonce which will be used later for decrypting packets received
from the TCP client.

If the server decrypts successfully the encrypted data in the handshake packet
and responds with the following handshake response of length 96 bytes:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{24}        & Nonce for the encrypted data \\
  \texttt{72}        & Payload (plus MAC) \\
\end{tabular}

Payload is encrypted with the private key of the server and the DHT public key
of the client and the nonce:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{32}        & Public key \\
  \texttt{24}        & Base nonce \\
\end{tabular}

The base nonce is the one the TCP server wants the TCP client to use to decrypt
the packets received from the TCP server.

The client already knows the long term public key of the server so it is
omitted in the response, instead only a nonce is present in the unencrypted
part.  The encrypted part of the response has the same elements as the
encrypted part of the request: a temporary public key tied to this connection
and a base nonce which will be used later when decrypting packets received from
the TCP client both unique for the connection.

In toxcore the base nonce is generated randomly like all the other nonces, it
must be randomly generated to prevent nonce reuse.  For example if the nonce
used was 0 for both sides since both sides use the same keys to encrypt packets
they send to each other, two packets would be encrypted with the same nonce.
These packets could then be possibly replayed back to the sender which would
cause issues.  A similar mechanism is used in \texttt{net\_crypto}.

After this the client will know the connection temporary public key and base
nonce of the server and the server will know the connection base nonce and
temporary public key of the client.

The client will then send an encrypted packet to the server, the contents of
the packet do not matter and it must be handled normally by the server (ex: if
it was a ping send a pong response.  The first packet must be any valid
encrypted data packet), the only thing that does matter is that the packet was
encrypted correctly by the client because it means that the client has
correctly received the handshake response the server sent to it and that the
handshake the client sent to the server really came from the client and not
from an attacker replaying packets.  The server must prevent resource consuming
attacks by timing out clients if they do not send any encrypted packets so the
server to prove to the server that the connection was established correctly.

Toxcore does not have a timeout for clients, instead it stores connecting
clients in large circular lists and times them out if their entry in the list
gets replaced by a newer connection.  The reasoning behind this is that it
prevents TCP flood attacks from having a negative impact on the currently
connected nodes.  There are however much better ways to do this and the only
reason toxcore does it this way is because writing it was very simple.  When
connections are confirmed they are moved somewhere else.

When the server confirms the connection he must look in the list of connected
peers to see if he is already connected to a client with the same announced
public key.  If this is the case the server must kill the previous connection
because this means that the client previously timed out and is reconnecting.
Because of Toxcore design it is very unlikely to happen that two legitimate
different peers will have the same public key so this is the correct behavior.

Encrypted data packets look like this to outsiders:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{2}         & \texttt{uint16\_t} length of data \\
  variable           & encrypted data \\
\end{tabular}

In a TCP stream they would look like:
\texttt{[[length][data]][[length][data]][[length][data]]...}.

Both the client and server use the following (temp public and private (client
and server) connection keys) which are each generated for the connection and
then sent to the other in the handshake and sent to the other.  They are then
used like the next diagram shows to generate a shared key which is equal on
both sides.

\begin{verbatim}
Client:                                     Server:
generate_shared_key(                        generate_shared_key(
[temp connection public key of server],     [temp connection public key of client],
[temp connection private key of client])    [temp connection private key of server])
=                                           =
[shared key]                                [shared key]
\end{verbatim}

The generated shared key is equal on both sides and is used to encrypt and
decrypt the encrypted data packets.

each encrypted data packet sent to the client will be encrypted with the shared
key and with a nonce equal to: (client base nonce + number of packets sent so
for the first packet it is (starting at 0) nonce + 0, the second is nonce + 1
and so on.  Note that nonces like all other numbers sent over the network in
toxcore are numbers in big endian format so when increasing them by 1 the least
significant byte is the last one)

each packet received from the client will be decrypted with the shared key and
with a nonce equal to: (server base nonce + number of packets sent so for the
first packet it is (starting at 0) nonce + 0, the second is nonce + 1 and so
on.  Note that nonces like all other numbers sent over the network in toxcore
are numbers in big endian format so when increasing them by 1 the least
significant byte is the last one)

Encrypted data packets have a hard maximum size of 2 + 2048 bytes in the
toxcore TCP server implementation, 2048 bytes is big enough to make sure that
all toxcore packets can go through and leaves some extra space just in case the
protocol needs to be changed in the future.  The 2 bytes represents the size of
the data length and the 2048 bytes the max size of the encrypted part.  This
means the maximum size is 2050 bytes.  In current toxcore, the largest
encrypted data packets sent will be of size 2 + 1417 which is 1419 total.

The logic behind the format of the handshake is that we:

\begin{enumerate}
\item need to prove to the server that we own the private key related to the public
   key we are announcing ourselves with.
\item need to establish a secure connection that has perfect forward secrecy
\item prevent any replay, impersonation or other attacks
\end{enumerate}

How it accomplishes each of those points:

\begin{enumerate}
  \item If the client does not own the private key related to the public key they
    will not be able to create the handshake packet.
  \item Temporary session keys generated by the client and server in the encrypted
    part of the handshake packets are used to encrypt/decrypt packets during the
    session.
  \item The following attacks are prevented:
    \begin{itemize}
      \item Attacker modifies any byte of the handshake packets: Decryption fail, no
        attacks possible.
      \item Attacker captures the handshake packet from the client and replays it
        later to the server: Attacker will never get the server to confirm the
        connection (no effect).
      \item Attacker captures a server response and sends it to the client next time
        they try to connect to the server: Client will never confirm the
        connection. (See: \texttt{TCP\_client})
      \item Attacker tries to impersonate a server: They won't be able to decrypt the
        handshake and won't be able to respond.
      \item Attacker tries to impersonate a client: Server won't be able to decrypt
        the handshake.
    \end{itemize}
\end{enumerate}

The logic behind the format of the encrypted packets is that:

\begin{enumerate}
  \item TCP is a stream protocol, we need packets.
  \item Any attacks must be prevented
\end{enumerate}

How it accomplishes each of those points:

\begin{enumerate}
  \item 2 bytes before each packet of encrypted data denote the length.  We assume a
     functioning TCP will deliver bytes in order which makes it work.  If the TCP
     doesn't it most likely means it is under attack and for that see the next
     point.
  \item The following attacks are prevented:
    \begin{itemize}
      \item Modifying the length bytes will either make the connection time out
        and/or decryption fail.
      \item Modifying any encrypted bytes will make decryption fail.
      \item Injecting any bytes will make decryption fail.
      \item Trying to re order the packets will make decryption fail because of the
        ordered nonce.
      \item Removing any packets from the stream will make decryption fail because of
        the ordered nonce.
    \end{itemize}
\end{enumerate}

\section{Encrypted payload types}

The folowing represents the various types of data that can be sent inside
encrypted data packets.

\subsection{Routing request (0x00)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x00) \\
  \texttt{32}        & Public key \\
\end{tabular}

\subsection{Routing request response (0x01)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
  \texttt{1}         & \texttt{uint8\_t} rpid \\
  \texttt{32}        & Public key \\
\end{tabular}

rpid is invalid \texttt{connection\_id} (0) if refused, \texttt{connection\_id} if accepted.

\subsection{Connect notification (0x02)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x02) \\
  \texttt{1}         & \texttt{uint8\_t} \texttt{connection\_id} of connection that got connected \\
\end{tabular}

\subsection{Disconnect notification (0x03)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x03) \\
  \texttt{1}         & \texttt{uint8\_t} \texttt{connection\_id} of connection that got disconnected \\
\end{tabular}

\subsection{Ping packet (0x04)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x04) \\
  \texttt{8}         & \texttt{uint64\_t} \texttt{ping\_id} (0 is invalid) \\
\end{tabular}

\subsection{Ping response (pong) (0x05)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x05) \\
  \texttt{8}         & \texttt{uint64\_t} \texttt{ping\_id} (0 is invalid) \\
\end{tabular}

\subsection{OOB send (0x06)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x06) \\
  \texttt{32}        & Destination public key \\
  variable           & Data \\
\end{tabular}

\subsection{OOB recv (0x07)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x07) \\
  \texttt{32}        & Sender public key \\
  variable           & Data \\
\end{tabular}

\subsection{Onion packet (0x08)}

Same format as initial onion packet but packet id is 0x08 instead of 0x80.

\subsection{Onion packet response (0x09)}

Same format as onion packet but packet id is 0x09 instead of 0x8e.

\subsection{Data (0x10 and up)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} packet id \\
  \texttt{1}         & \texttt{uint8\_t} connection id \\
  variable           & data \\
\end{tabular}

The TCP server is set up in a way to minimize waste while relaying the many
packets that might go between two tox peers hence clients must create
connections to other clients on the relay.  The connection number is a
\texttt{uint8\_t} and must be equal or greater to 16 in order to be valid.
Because a \texttt{uint8\_t} has a maximum value of 256 it means that the maximum
number of different connections to other clients that each connection can have
is 240.  The reason valid \texttt{connection\_ids} are bigger than 16 is because
they are the first byte of data packets.  Currently only number 0 to 9 are
taken however we keep a few extras in case we need to extend the protocol
without breaking it completely.

Routing request (Sent by client to server): Send a routing request to the
server that we want to connect to peer with public key where the public key is
the public the peer announced themselves as.  The server must respond to this
with a Routing response.

Routing response (Sent by server to client): The response to the routing
request, tell the client if the routing request succeeded (valid
\texttt{connection\_id}) and if it did, tell them the id of the connection
(\texttt{connection\_id}).  The public key sent in the routing request is also
sent in the response so that the client can send many requests at the same time
to the server without having code to track which response belongs to which
public key.

The only reason a routing request should fail is if the connection has reached
the maximum number of simultaneous connections.  In case the routing request
fails the public key in the response will be the public key in the failed
request.

Connect notification (Sent by server to client): Tell the client that
\texttt{connection\_id} is now connected meaning the other is online and data
can be sent using this \texttt{connection\_id}.

Disconnect notification (Sent by client to server): Sent when client wants the
server to forget about the connection related to the \texttt{connection\_id} in
the notification.  Server must remove this connection and must be able to reuse
the \texttt{connection\_id} for another connection.  If the connection was
connected the server must send a disconnect notification to the other client.
The other client must think that this client has simply disconnected from the
TCP server.

Disconnect notification (Sent by server to client): Sent by the server to the
client to tell them that the connection with \texttt{connection\_id} that was
connected is now disconnected.  It is sent either when the other client of the
connection disconnect or when they tell the server to kill the connection (see
above).

Ping and Pong packets (can be sent by both client and server, both will
respond): ping packets are used to know if the other side of the connection is
still live.  TCP when established doesn't have any sane timeouts (1 week isn't
sane) so we are obliged to have our own way to check if the other side is still
live.  Ping ids can be anything except 0, this is because of how toxcore sets
the variable storing the \texttt{ping\_id} that was sent to 0 when it receives a
pong response which means 0 is invalid.

The server should send ping packets every X seconds (toxcore
\texttt{TCP\_server} sends them every 30 seconds and times out the peer if it
doesn't get a response in 10).  The server should respond immediately to ping
packets with pong packets.

The server should respond to ping packets with pong packets with the same
\texttt{ping\_id} as was in the ping packet.  The server should check that each
pong packet contains the same \texttt{ping\_id} as was in the ping, if not the
pong packet must be ignored.

OOB send (Sent by client to server): If a peer with private key equal to the
key they announced themselves with is connected, the data in the OOB send
packet will be sent to that peer as an OOB recv packet.  If no such peer is
connected, the packet is discarded.  The toxcore \texttt{TCP\_server}
implementation has a hard maximum OOB data length of 1024.  1024 was picked
because it is big enough for the \texttt{net\_crypto} packets related to the
handshake and is large enough that any changes to the protocol would not
require breaking TCP server.  It is however not large enough for the biggest
\texttt{net\_crypto} packets sent with an established \texttt{net\_crypto}
connection to prevent sending those via OOB packets.

OOB recv (Sent by server to client): OOB recv are sent with the announced
public key of the peer that sent the OOB send packet and the exact data.

OOB packets can be used just like normal data packets however the extra size
makes sending data only through them less efficient than data packets.

Data: Data packets can only be sent and received if the corresponding
\texttt{connection\_id} is connection (a Connect notification has been received
from it) if the server receives a Data packet for a non connected or existent
connection it will discard it.

Why did I use different packet ids for all packets when some are only sent by
the client and some only by the server? It's less confusing.
