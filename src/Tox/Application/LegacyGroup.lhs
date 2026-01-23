\begin{code}
{-# LANGUAGE StrictData #-}
module Tox.Application.LegacyGroup where
\end{code}

\chapter{Group}

Group chats in Tox work by temporarily adding some peers present in the group
chat as temporary \texttt{friend\_connection} friends, that are deleted when the
group chat is exited.

Each peer in the group chat is identified by their real long term public key.
Peers also transmit their DHT public keys to each other via the group chat in
order to speed up the connection by making it unnecessary for the peers to find
each other's DHT public keys with the onion, as would happen had they added each
other as normal friends.

The upside of using \texttt{friend\_connection} is that group chats do not have
to deal with things like hole punching, peers only on TCP or other low level
networking things.  The downside however is that every single peer knows each
other's real long term public key and DHT public key, meaning that these group
chats should only be used between friends.

Each peer adds a \texttt{friend\_connection} for each of up to 4 other peers in
the group. If the group chat has 5 participants or fewer, each of the peers will
therefore have each of the others added to their list of friend connections, and
a peer wishing to send a message to the group may communicate it directly to the
other peers. When there are more than 5 peers, messages are relayed along friend
connections.

Since the maximum number of peers per groupchat that will be connected to with
friend connections is 4, if the peers in the groupchat are arranged in a circle
and each peer connects to the 2 peers that are closest to the right of them and
the 2 peers that are closest to the left of them, then the peers should form a
well-connected circle of peers.

Group chats in toxcore do this by subtracting the real long term public key of
the peer with all the others in the group (our PK - other peer PK), using
modular arithmetic, and finding the two peers for which the result of this
operation is the smallest. The operation is then inversed (other peer PK - our
PK) and this operation is done again with all the public keys of the peers in
the group. The 2 peers for which the result is again the smallest are picked.

This gives 4 peers that are then added as a friend connection and associated to
the group.  If every peer in the group does this, they will form a circle of
perfectly connected peers.

Once the peers are connected to each other in a circle they relay each other's
messages.  Every time a peer leaves the group or a new peer joins, each member
of the chat will recalculate the peers they should connect to.

To join a group chat, a peer must first be invited to it by their friend.  To
make a groupchat the peer will first create a groupchat and then invite people
to this group chat.  Once their friends are in the group chat, those friends can
invite their other friends to the chat, and so on.

To create a group chat, a peer generates a random 32 byte id that is used to
uniquely identify the group chat.  32 bytes is enough so that when randomly
generated with a secure random number generator every groupchat ever created
will have a different id.  The goal of this 32 byte id is so that peers have a
way of identifying each group chat, so that they can prevent themselves from
joining a groupchat twice for example.

The groupchat will also have an unsigned 1 byte type.  This type indicates what
kind of groupchat the groupchat is. The current types are:

\begin{tabular}{l|l}
  Type number       & Type \\
  \hline
  \texttt{0}        & text \\
  \texttt{1}        & audio \\
\end{tabular}

Text groupchats are text only, while audio indicates that the groupchat supports
sending audio to it as well as text.

The groupchat will also be identified by a unique unsigned 2 byte integer, which
in toxcore corresponds to the index of the groupchat in the array it is being
stored in.  Every groupchat in the current instance must have a different
number.  This number is used by groupchat peers that are directly connected to
us to tell us which packets are for which groupchat.  Every groupchat packet
contains a 2 byte groupchat number.  Putting a 32 byte groupchat id in each
packet would increase bandwidth waste by a lot, and this is the reason why
groupchat numbers are used instead.

Using the group number as the index of the array used to store the groupchat
instances is recommended, because this kind of access is usually most efficient
and it ensures that each groupchat has a unique group number.

When creating a new groupchat, the peer will add themselves as a groupchat peer
with a peer number of 0 and their own long term public key and DHT public key.

Invite packets:

Invite packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x00) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{33}        & Group chat identifier \\
\end{tabular}

Accept Invite packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
  \texttt{2}         & \texttt{uint16\_t} group number (local) \\
  \texttt{2}         & \texttt{uint16\_t} group number to join \\
  \texttt{33}        & Group chat identifier \\
\end{tabular}

Member Information packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x02) \\
  \texttt{2}         & \texttt{uint16\_t} group number (local) \\
  \texttt{2}         & \texttt{uint16\_t} group number to join \\
  \texttt{33}        & Group chat identifier \\
  \texttt{2}         & \texttt{uint16\_t} peer number \\
\end{tabular}

A group chat identifier consists of a 1-byte type and a 32-byte id concatenated:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} type \\
  \texttt{32}        & \texttt{uint8\_t} groupchat id \\
\end{tabular}

To invite a friend to a group chat, an invite packet is sent to the friend.
These packets are sent using Messenger (if you look at the Messenger packet id
section, all the groupchat packet ids are in there).  Note that all numbers
here, like all numbers sent using Tox packets, are sent in big endian format.

The group chat number is as explained above, the number used to uniquely
identify the groupchat instance from all the other groupchat instances the peer
has.  It is sent in the invite packet because it is needed by the friend in
order to send back groupchat related packets.

What follows is the 33 byte group chat identifier.

To refuse the invite, the friend receiving it will simply ignore and discard
it.

To accept the invite, the friend will create their own groupchat instance with
the 1 byte type and 32 byte groupchat id sent in the request, and send an invite
accept packet back.  The friend will also add the peer who sent the invite as
a groupchat connection, and mark the connection as introducing the friend.

If the friend being invited is already in the group, they will respond with a
member information packet, add the peer who sent the invite as a groupchat
connection, and mark the connection as introducing both the friend and the
peer who sent the invite.

The first group number in the invite accept packet is the group number of the
groupchat the invited friend just created.  The second group number is the
group number that was sent in the invite request.  What follows is the 33 byte
group chat identifier which was sent in the invite request. The member
information packet is the same, but includes also the current peer number of
the invited friend.

When a peer receives an invite accept packet they will check if the group
identifier sent back corresponds to the group identifier of the groupchat with
the group number also sent back.  If so, a new peer number will be generated for
the peer that sent the invite accept packet.  Then the peer with their
generated peer number, their long term public key and their DHT public key will
be added to the peer list of the groupchat.  A new peer message packet will also
be sent to tell everyone in the group chat about the new peer.  The peer will
also be added as a groupchat connection, and the connection will be marked as
introducing the peer.

When a peer receives a member information packet they proceed as with an
invite accept packet, but use the peer number in the packet rather than
generating a new one, and mark the new connection as also introducing the peer
receiving the member information packet.

Peer numbers are used to uniquely identify each peer in the group chat.  They
are used in groupchat message packets so that peers receiving them can know who
or which groupchat peer sent them.  As groupchat message packets are relayed,
they must contain something that is used by others to identify the sender. Since
putting a 32 byte public key in each packet would be wasteful, a 2 byte peer
number is used instead.  Each peer in the groupchat has a unique peer number.
Toxcore generates each peer number randomly but makes sure newly generated peer
numbers are not equal to current ones already used by other peers in the group
chat. If two peers join the groupchat from two different endpoints there is a
small possibility that both will be given the same peer number, but the
probability of this occurring is low enough in practice that it is not an issue.

Peer online packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x61) \\
  \texttt{2}         & \texttt{uint16\_t} group number (local) \\
  \texttt{33}        & Group chat identifier \\
\end{tabular}

Peer introduced packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} group number (local) \\
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
\end{tabular}

For a groupchat connection to work, both peers in the groupchat must be
attempting to connect directly to each other.

Groupchat connections are established when both peers who want to connect to
each other either create a new friend connection to connect to each other or
reuse an existing friend connection that connects them together (if they are
friends or already are connected together because of another group chat).

As soon as the connection to the other peer is opened, a peer online packet is
sent to the peer.  The goal of the online packet is to tell the peer that we
want to establish the groupchat connection with them and tell them the
groupchat number of our groupchat instance.  The peer online packet contains
the group number and the 33 byte group chat identifier.  The group number is the
group number the peer has for the group with the group id sent in the packet.

When both sides send an online packet to the other peer, a connection is
established.

When an online packet is received from a peer, if the connection to the peer
is already established (an online packet has been already received), or if
there is no group connection to that peer being established, the packet is
dropped. Otherwise, the group number to communicate with the group via the
peer is saved, the connection is considered established, and an online packet
is sent back to the peer. A ping message is sent to the group. If this is the
first group connection to that group we establish, or the connection is marked
as introducing us, we send a peer query packet back to the peer.  This is so
we can get the list of peers from the group. If the connection is marked as
introducing the peer, we send a new peer message to the group announcing the
peer, and a name message reannouncing our name.

A groupchat connection can be marked as introducing one or both of the peers it
connects, to indicate that the connection should be maintained until that peer
is well connected to the group. A peer maintains a groupchat connection to a
second peer as long as the second peer is one of the four closest peers in the
groupchat to the first, or the connection is marked as introducing a peer who
still requires the connection. A peer requires a groupchat connection to a
second peer which introduces the first peer until the first peer has more than
4 groupchat connections and receives a message from the second peer via a
different groupchat connection. The first peer then sends a peer introduced
packet to the second peer to indicate that they no longer require the
connection.

Peer query packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{1}         & \texttt{uint8\_t} (0x08) \\
\end{tabular}

Peer response packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{1}         & \texttt{uint8\_t} (0x09) \\
  variable           & Repeated times number of peers: Peer info \\
\end{tabular}

The Peer info structure is as follows:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{2}         & \texttt{uint16\_t} peer number \\
  \texttt{32}        & Long term public key \\
  \texttt{32}        & DHT public key \\
  \texttt{1}         & \texttt{uint8\_t} Name length \\
  \texttt{[0, 255]}  & Name \\
\end{tabular}

Title response packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{1}         & \texttt{uint8\_t} (0x0a) \\
  variable           & Title \\
\end{tabular}

Message packets:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x63) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{2}         & \texttt{uint16\_t} peer number \\
  \texttt{4}         & \texttt{uint32\_t} message number \\
  \texttt{1}         & \texttt{uint8\_t} with a value representing id of message \\
  variable           & Data \\
\end{tabular}

Lossy Message packets:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0xc7) \\
  \texttt{2}         & \texttt{uint16\_t} group number \\
  \texttt{2}         & \texttt{uint16\_t} peer number \\
  \texttt{2}         & \texttt{uint16\_t} message number \\
  \texttt{1}         & \texttt{uint8\_t} with a value representing id of message \\
  variable           & Data \\
\end{tabular}

If a peer query packet is received, the receiver takes their list of peers and
creates a peer response packet which is then sent to the other peer.  If there
are too many peers in the group chat and the peer response packet would be
larger than the maximum size of friend connection packets (1373 bytes), more
than one peer response packet is sent back.  A Title response packet is also
sent back.  This is how the peer that joins a group chat finds out the list of
peers in the group chat and the title of the group chat right after joining.

Peer response packets are straightforward and contain the information for each
peer (peer number, real public key, DHT public key, name) appended to each
other.  The title response is also straightforward.

Both the maximum length of groupchat peer names and the groupchat title is 128
bytes.  This is the same maximum length as names in all of toxcore.

When a peer receives a peer response packet, they will add each of the
received peers to their groupchat peer list, find the 4 closest peers to them
and create groupchat connections to them as was explained previously. The DHT
public key of an already known peer is updated to one given in the response
packet if the peer is frozen, or if it has been frozen since its DHT public
key was last updated.

When a peer receives a title response packet, they update the title for the
groupchat accordingly if the title has not already been set, or if since it
was last set there has been a time at which all peers were frozen.

If the peer does not yet know their own peer number, as is the case if they
have just accepted an invitation, the peer will find themselves in the list of
received peers and use the peer number assigned to them as their own. They are
then able to send messages and invite other peers to the groupchat. They
immediately send a name message to announce their name to the group.

Message packets are used to send messages to all peers in the groupchat.  To
send a message packet, a peer will first take their peer number and the message
they want to send.  Each message packet sent will have a message number that is
equal to the last message number sent + 1.  Like all other numbers (group chat
number, peer number) in the packet, the message number in the packet will be in
big endian format.

When a Message packet is received, the peer receiving it will first check that
the peer number of the sender is in their peer list. If not, the peer ignores
the message but sends a peer query packet to the peer the packet was directly
received from. That peer should have the message sender in their peer list,
and so will send the sender's peer info back in a peer response.

If the sender is in the receiver's peer list, the receiver now checks whether
they have already seen a message with the same sender and message number. This
is achieved by storing the 8 greatest message numbers received from a given
sender peer number. If the message has lesser message number than any of those
8, it is assumed to have been received. If the message has already been
received according to this check, or if it is a name or title message and
another message of the same type from the same sender with a greater message
number has been received, then the packet is discarded. Otherwise, the
message is processed as described below, and a Message packet with the message
is sent (relayed) to all current group connections except the one that it was
received from, and also to that one if that peer is the original sender of the
message. The only thing that should change in the Message packet as it is
relayed is the group number.

Lossy message packets are used to send audio packets to others in audio group
chats.  Lossy packets work the same way as normal relayed groupchat messages in
that they are relayed to everyone in the group chat until everyone has them, but
there are a few differences. Firstly, the message number is only a 2 byte
integer. When receiving a lossy packet from a peer the receiving peer will first
check if a message with that message number was already received from that peer.
If it wasn't, the packet will be added to the list of received packets and then
the packet will be passed to its handler and then sent to the 2 closest
connected groupchat peers that are not the sender.  The reason for it to be 2
instead of 4 (or 3 if we are not the original sender) as for lossless message
packets is that it reduces bandwidth usage without lowering the quality of the
received audio stream via lossy packets, at the cost of reduced robustness
against connections failing. To check if a packet was already received, the last
256 message numbers received from each peer are stored. If video was added
meaning a much higher number of packets would be sent, this number would be
increased.  If the packet number is in this list then it was received.

\section{Message ids}

\subsection{ping (0x00)}

Sent approximately every 20 seconds by every peer.  Contains no data.

\subsection{\texttt{new\_peer} (0x10)}

Tell everyone about a new peer in the chat.

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{2}         & \texttt{uint16\_t} Peer number \\
  \texttt{32}        & Long term public key \\
  \texttt{32}        & DHT public key \\
\end{tabular}

\subsection{\texttt{kill\_peer} (0x11)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{2}         & \texttt{uint16\_t} Peer number \\
\end{tabular}

\subsection{\texttt{freeze\_peer} (0x12)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{2}         & \texttt{uint16\_t} Peer number \\
\end{tabular}

\subsection{Name change (0x30)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  variable           & Name (namelen) \\
\end{tabular}

\subsection{Groupchat title change (0x31)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  variable           & Title (titlelen) \\
\end{tabular}

\subsection{Chat message (0x40)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  variable           & Message (messagelen) \\
\end{tabular}

\subsection{Action (/me) (0x41)}

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  variable           & Message (messagelen) \\
\end{tabular}

Ping messages are sent every 20 seconds by every peer.  This is how other
peers know that the peers are still alive.

When a new peer joins, the peer which invited the joining peer will send a new
peer message to warn everyone that there is a new peer in the chat.  When a new
peer message is received, the peer in the message must be added to the peer
list if it is not there already, and its DHT public key must be set to that
in the message.

Kill peer messages are used to indicate that a peer has quit the group chat
permanently. Freeze peer messages are similar, but indicate that the quitting
peer may later return to the group. Each is sent by the one quitting the group
chat right before they quit it.

Name change messages are used to change or set the name of the peer sending it.
They are also sent by a joining peer right after receiving the list of peers in
order to tell others what their name is.

Title change packets are used to change the title of the group chat and can be
sent by anyone in the group chat.

Chat and action messages are used by the group chat peers to send messages to
others in the group chat.

\section{Timeouts and reconnection}

Groupchat connections may go down, and this may lead to a peer becoming
disconnected from the group or the group otherwise splitting into multiple
connected components. To ensure the group becomes fully connected again once
suitable connections are re-established, peers keep track of peers who are no
longer visible in the group ("frozen" peers), and try to re-integrate them
into the group via any suitable friend connections which may come to be
available. The rejoin packet is used for this.

Rejoin packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x64) \\
  \texttt{33}        & Group chat identifier \\
\end{tabular}

A peer in a groupchat is considered to be active when a group message or
rejoin packet is received from it, or a new peer message is received for it.
A peer which remains inactive for 60 seconds is set as frozen; this means it
is removed from the peer list and added to a separate list of frozen peers.
Frozen peers are disregarded for all purposes except those discussed below.

If a frozen peer becomes active, we unfreeze it, meaning that we move it from
the frozen peers list to the peer list, and we send a name message to the
group.

Whenever we make a new friend connection to a peer, we check whether the
public key of the peer is that of any frozen peer. If so, we send a rejoin
packet to the peer along the friend connection, and create a groupchat
connection to the peer, marked as introducing us, and send a peer online
packet to the peer.

If we receive a rejoin packet from a peer along a friend connection, then,
after unfreezing the peer if it was frozen, we update the peer's DHT public
key in the groupchat peer list to the key in the friend connection, and create
a groupchat connection for the peer, marked as introducing the peer, and send
a peer online packet to the peer.

When a peer is added to the peer list, any existing peer in the peer list or
frozen peers list with the same public key is first removed.
