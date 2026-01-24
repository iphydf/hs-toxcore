\chapter{DHT Group Chats}

This document details the groupchat implementation, giving a high level
overview of all the important features and aspects, as well as some
important low level implementation details. This documentation reflects
what is currently implemented at the time of writing; it is not
speculative. For detailed API docs see the groupchats section of the
tox.h header file.

\section{Features}

\begin{itemize}
  \item Plain and action messages (/me)
  \item Private messages
  \item Public groups (peers may join via a public key of group)
  \item Private groups (require a friend invite for join)
  \item Permanence (a group cannot 'die' as long as at least one peer retains
  their group credentials)
  \item Persistence across client restarts
  \item Ability to set peer limits
  \item Group roles (founder, moderators, users, observers)
  \item Moderation (kicking, silencing, controlling which roles may speak)
  \item Permanent group names (set on creation)
  \item Topics (permission to modify is set by founder)
  \item Password protection
  \item Self-repairing (auto-rejoin on disconnect, group split protection,
  state syncing)
  \item Identity separation from the Tox ID
  \item Ability to ignore peers
  \item Nicknames can be set on a per-group basis
  \item Peer statuses (online, away, busy) which can be set on a per-group basis
  \item Sending group name in invites
  \item Ability to disconnect from group and join later with the same credentials
\end{itemize}

\section{Group roles}

There are four distinct roles which are hierarchical in nature (higher roles
have all the privileges of lower roles).

\begin{itemize}
  \item \textbf{\verb'Founder'} - The group's creator. May set the role of all other
  peers to anything except founder. May modify the shared state (password,
  privacy state, topic lock, peer limit).
  \item \textbf{\verb'Moderator'} - Promoted by the founder. May kick peers below this
  role, as well as set peers with the user role to observer, and vice versa.
  May also set the topic when the topic lock is enabled.
  \item \textbf{\verb'User'} - Default non-founder role. May communicate with other
  peers normally. May set the topic when the topic lock is disabled.
  \item \textbf{\verb'Observer'} - Demoted by moderators and the founder. May observe
  the group and ignore peers; may not communicate with other peers or with the
  group.
\end{itemize}

\section{Group types}

Groups can have two types: private and public. The type can be set on
creation, and may also be toggled by the group founder at any point
after creation. (\emph{Note: password protection is independent of the
group type})

\subsection{Public}

Anyone may join the group using the Chat ID. If the group is public,
information about peers inside the group, including their IP addresses
and group public keys (but not their Tox ID's) is visible to anyone with
access to a node storing their DHT announcement.

\subsection{Private}

The only way to join a private group is by having someone in your friend
list send you an invite. If the group is private, no peer/group
information (mentioned in the Public section) is present in the DHT; the
DHT is not used for any purpose at all. If a public group is set to
private, all DHT information related to the group will expire within a
few minutes.

\section{Voice state}

The voice state, which may only be set by the founder, determines which
group roles have permission to speak. There are three voice states:

\begin{itemize}
  \item \textbf{\verb'Founder'} - Only the founder may speak.
  \item \textbf{\verb'Moderator'} - The founder and moderators may speak.
  \item \textbf{\verb'All'} - Everyone except observers may speak.
\end{itemize}

The voice state does not affect topic setting or private messages, and is
set to \textbf{\verb'All'} by default.

\section{Cryptography}

Groupchats use the
\href{https://en.wikipedia.org/wiki/NaCl_(software)}{NaCl/libsodium
cryptography library} for all cryptography related operations. All group
communication is end-to-end encrypted. Message confidentiality,
integrity, and repudability are guaranteed via
\href{https://en.wikipedia.org/wiki/Authenticated_encryption}{authenticated
encryption}, and
\href{https://en.wikipedia.org/wiki/Forward_secrecy}{perfect forward
secrecy} is also provided.

One of the most important security improvements from the old groupchat
implementation is the removal of a message-relay mechanism that uses a
group-wide shared key. Instead, connections are 1-to-1 (a complete
graph), meaning an outbound message is sent once per peer, and
encrypted/decrypted using a session key unique to each pair of peers.
This prevents MITM attacks that were previously possible. This
additionally ensures that private messages are truly private.

Groups make use of 11 unique keys in total: Two permanent keypairs
(encryption and signature), two group keypairs (encryption and
signature), one session keypair (encryption), and one shared symmetric
key (encryption).

The Tox ID/Tox public key is not used for any purpose. As such, neither
peers in a given group nor in the group DHT can be matched with their
Tox ID. In other words, there is no way of identifying a peer aside from
their IP address, nickname, and group public key. (\emph{Note: group
nicknames can be different from the client's main nickname that their
friends see}).

\subsection{Permanent keypairs}

When a peer creates or joins a group they generate two permanent
keypairs: an encryption keypair and a signature keypair, both of which
are unique to the group. The two public keys are the only guaranteed way
to identify a peer, and both keypairs will persist for as long as a peer
remains in the group (even across client restarts). If a peer exits the
group these keypairs will be lost forever.

This encryption keypair is not used for any encryption operations except
for the initial handshake when connecting to another peer. For usage
details on the signature key, see the
\href{#moderation}{\texttt{Moderation}} section.

\subsection{Session keypair/shared symmetric key}

When two peers establish a connection they each generate an ephemeral
session encryption keypair and share one another's resulting public key.
With their own session secret key and the other's session public key,
they will both generate the same symmetric encryption key. This symmetric
key, which must not be exposed to anyone else, will be used for all
further encryption and decryption operations between the two peers for
the duration of the session.

The purpose of this extra key exchange is to prevent an adversary from
decrypting messages from previous sessions in event that a secret
encryption key becomes compromised. This is known as forward secrecy.

Session keys are periodically rotated to further reduce the potential
damage in the event of a security breach, as well as to mitigate certain
types of data-based cryptography attacks.

\subsection{Group keypairs}

The group founder generates two additional permanent keypairs when the
group is created: an encryption keypair, and a signature keypair. The
public signature key is considered the \textbf{\verb'Chat ID'} and is used as
the group's permanent identifier, allowing other peers to join public
groups via the DHT. Every peer in the group holds a copy of the group's
public encryption key along with the public signature key/Chat ID.

The group secret keys are similar to the permanent keypairs in that they
will persist across client restarts, but will be lost forever if the
founder exits the group. This is particularly important as
administration related functionality will not work without these keys.

See the \href{#founders}{\texttt{Founders}} section for usage details.

\section{Founders}

The peer who creates the group is the group's founder. Founders have a
set of admin privileges, including:

\begin{itemize}
  \item Promoting and demoting moderators
  \item The ability to kick moderators along-side non-moderators
  \item Setting the peer limit
  \item Setting the group's privacy state
  \item Setting group passwords
  \item Toggling the topic lock
  \item Setting the voice state
\end{itemize}

\subsection{Shared state}

Groups contain a data structure called the \textbf{\verb'shared state'}
which is given to every peer who joins the group. Within this structure
resides all data pertaining to the group that may only be modified by
the group founder. This includes the group name, the group type, the
peer limit, the topic lock, the password, and the voice state. The shared
state holds a copy of the group founder's public encryption and signature
keys, which is how other peers in the group are able to verify the identity
of the group founder. It also contains a hash of the moderator list.

The shared state is signed by the founder using the group secret
signature key. As the founder is the only peer who holds this secret
key, the shared state can be shared with new peers and cryptographically
verified even in the absence of the founder.

When the founder modifies the shared state, he increments the shared
state version, signs the new shared state data with the group secret
signature key, and broadcasts the new shared state data along with its
signature to the entire group. When a peer receives this broadcast, he
uses the group public signature key to verify that the data was signed
with the group secret signature key, and also verifies that the new
version is not older than the current version.

\subsection{Moderation}

The founder has the ability to promote other peers to the moderator
role. Moderators have all the privileges of normal users. In addition,
they have the power to kick peers whose role is below moderator, as well
as set their roles to anything below moderator. Moderators may also modify
the group topic when it is locked. Moderators have no power over one
another; only the founder can kick or change the role of a moderator.

\subsection{Kicks}

When a peer is kicked from the group, he will be disconnected from all
group peers, his role will be set to user, and his chat instance will be
left in a disconnected state. His public key will not be lost; he will
be able to reconnect to the group with the same identity.

\subsection{Moderator list}

Each peer holds a copy of the \textbf{\verb'moderator list'}, which is
an array of public signature keys of peers who currently have the moderator
role (including those who are offline). A hash (sha256) of this list called
the \textbf{\verb'mod_list_hash'} is stored in the shared state, which is
itself signed by the founder using the group secret signature key. This
allows the moderator list to be shared between untrusted peers, even in
the absence of the founder, while maintaining moderator verifiability.

When the founder modifies the moderator list, he updates the
\verb'mod_list_hash', increments the shared state version, signs the new
shared state, broadcasts the new shared state data along with its
signature to the entire group, then broadcasts the new moderator list to
the entire group. When a peer receives this moderator list (having
already verified the new shared state), he creates a hash of the new
list and verifies that it is identical to the \verb'mod_list_hash'.

\subsection{Sanctions list}

Each peer holds a copy of the \textbf{\verb'sanctions list'}. This list
is comprised of peers who have been demoted to the observer role.

Entries contain the public key of the sanctioned peer, a timestamp of
the time the entry was made, the public signature key of the peer who
set the sanction, and a signature of the entry's data, which is signed
by the peer who created the entry using their secret signature key.
Individual entries are verified by ensuring that the entry's public
signature key belongs to the founder or is present in the moderator
list, and then verifying that the entry's data was signed by the owner
of that key.

Although each individual entry can be verified, we still need a way to
verify that the list as a whole is complete, and identical for every
peer, otherwise any peer would be able to remove entries arbitrarily, or
replace the list with an older version. Therefore each peer holds a copy
of the \textbf{\verb'sanctions list credentials'}. This is a data
structure that holds a version number, a hash (sha256) of all combined
sanctions list entries, a 16-bit checksum of the hash, the public
signature key of the last peer to have modified the list, and a signature
of the hash, which is signed by the private signature key associated with
the aforementioned public signature key.

When a moderator or founder modifies the sanctions list, he will
increment the version, create a new hash of the list, make a checksum of
the hash, sign the hash+version with his secret signature key, and
replace the old public signature key with his own. He will then
broadcast the new changes (not the entire list) to the entire group
along with the new credentials. When a peer receives this broadcast, he
will verify that the new credentials version is not older than the
current version, validate the hash and checksum, and verify that the
changes were made by a moderator or the founder. If adding an entry, he
will verify that the entry was signed by the signature key of the
entry's creator.

If a peer receives sanctions credentials with a version equal to their
own but with a different checksum, they will ignore the changes if the
new checksum is a smaller value than the checksum for their current
sanctions credentials.

When the founder kicks or demotes a moderator, he will first go through
the sanctions list and re-sign each entry made by that moderator using
the founder key, then re-broadcast the sanctions list to the entire
group. This is necessary to guarantee that all sanctions list entries
and its credentials are signed by a current moderator or the founder at
all times.

\emph{Note: The sanctions list is not saved to the Tox save file,
meaning that if the group ever becomes empty, the sanctions list will be
reset. This is in contrast to the shared state and moderator list, which
are both saved and will persist even if the group becomes empty.}

\section{Topics}

The topic is an arbitrary string of characters with a maximum length of
512 bytes. The topic has two states: locked and unlocked. When locked,
only moderators and the founder may modify it. When unlocked, all peers
except observers may modify it. The integrity of the topic is maintained
in a similar manner as sanctions entries, using a data structure called
\textbf{\verb'topic_info'}. This is a struct which contains the topic, a
version, a 16-bit checksum of the topic, and the public key of the peer
who last set the topic.

The topic lock state is kept track of in the shared state, and may only
be modified by the founder. If the topic lock is set to zero, this
indicates that the lock is enabled. If non-zero, the value is set to the
topic version of the last topic set when the lock was enabled. This
allows peers to ensure that the topic version is not modified while
the lock is disabled.

When the topic lock is \textbf{\verb'enabled'}, the topic setter will
create a new checksum of the topic and increment the topic version. They
will then sign the topic and version with their secret signature key,
replace the public key with their own, and broadcast the new topic\_info
data along with the signature to the entire group. When a peer receives
this broadcast they will check if the public signature key of the topic
setter either belongs to the founder or is in the moderator list, and
ensure that the version is not older than the current topic version.
They will then verify the signature using the setter's public signature
key and validate the checksum. If the received topic has the same version
as their own but a different checksum, they will ignore the new topic if
its checksum value is smaller than the checksum value for their current
topic.

When the topic lock is \textbf{\verb'disabled'}, the topic setter will
create a new checksum of the topic and leave the version unchanged. They
will then sign the topic and version with their secret signature key,
replace the public key with their own, and broadcast the new topic\_info
data along with the signature to the entire group. When a peer receives
this broadcast they will ensure that the topic setter is not in the
sanctions list, and ensure that the version is equal to the value that
the topic lock is set to, unless the setter has the Founder role, in
which case they will ignore the version. They will then verify the
signature using the setter's public signature key and validate the
checksum.

If the peer who set the current topic is kicked or demoted, or if the
topic lock is enabled, the peer who initiated the action will re-sign
the topic using his own signature key and rebroadcast it to the entire
group.

If the peer who set the current topic is kicked or demoted, or if the
topic lock is enabled, the peer who initiated the action will re-sign
the topic using his own signature key and rebroadcast it to the entire
group.

\section{State syncing}

Peers send four unsigned 16-bit integers and three unsigned 32-bit
integers along with their ping packets: Their peer count\footnote{We
use a "real" peer count, which is the number of confirmed peers in the
peerlist (that is, peers who you have successfully handshaked and
exchanged peer info with).}, a checksum of their peer list, their shared
state version, their sanctions credentials version, their peer roles
checksum\footnote{The peer roles checksum is calculated as follows:
Make an unsigned 16-bit sum of each confirmed peer's role plus the
first byte of their respective public key, then add to this an unsigned
16-bit sum of the sanctions credentials hash.}, their topic version,
and their topic checksum. If a peer receives a ping in which any of the
versions are greater than their own, or if their peer list checksum does
not match and their peer count is not greater than the peer count
received, this indicates that they may be out of sync with the rest of
the group. In this case they will send a sync request to the respective
peer, with the appropriate sync flags set to indicate what group
information they need.

In certain scenarios a peer may receive a topic version or sanctions
credentials version that is equal to their own, but with a different
checksum. This may occur if two or more peers in the group initiate an
action at the exact same time. If such a conflict occurs, the peer will
make the appropriate sync request if their checksum is a smaller value
than the one they received.

Peers that are connected to the DHT also occasionally append their IP
and port number to their ping packets for peers with which they do not
have a direct UDP connection established. This gives priority to direct
connections and ensures that TCP relays are used only as a fall-back, or
when a peer explicitly forces a TCP connection.

\section{DHT Announcements}

Public groupchats leverage the Tox DHT network in order to allow for
groups that can be joined by anyone who possesses the
\textbf{\verb'Chat ID'}. Group announcements have the same underlying
functionality as normal Tox friend announcements (including onion routing).

\begin{code}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE StrictData        #-}
{-# LANGUAGE TupleSections     #-}
module Tox.Chat.GroupChat where

import           Control.Applicative                ((<|>))
import           Control.Monad                      (forM, forM_, guard, unless,
                                                     void, when)
import qualified Crypto.Saltine.Class               as Sodium
import qualified Data.Binary                        as Binary
import           Data.Binary.Get                    (getWord16be, getWord32be,
                                                     getWord64be, getWord8)
import           Data.Binary.Put                    (putWord16be, putWord32be,
                                                     putWord64be)
import           Data.Bits                          (xor, (.&.))
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString                    as BS
import           Data.List                          (find)
import           Data.Map                           (Map)
import qualified Data.Map                           as Map
import           Data.Maybe                         (catMaybes, fromMaybe,
                                                     isJust, isNothing,
                                                     listToMaybe, mapMaybe)
import           Data.Text                          (pack)
import           Data.Word                          (Word16, Word32, Word64,
                                                     Word8)

import           Tox.Chat.GroupChatPackets
import           Tox.Core.Log                       (logDebug)
import qualified Tox.Core.Schedule                  as Schedule
import           Tox.Core.Schedule                  (Schedule)
import qualified Tox.Core.Time                      as Time
import           Tox.Core.Time                      (TimeDiff, Timestamp)
import           Tox.Core.Timed                     (Timed (..))
import qualified Tox.Crypto.Core.CombinedKey        as CombinedKey
import           Tox.Crypto.Core.Key                (CombinedKey, PublicKey)
import           Tox.Crypto.Core.KeyPair            (KeyPair (..))
import           Tox.Crypto.Core.MonadRandomBytes   (MonadRandomBytes (..),
                                                     randomKey, randomNonce,
                                                     randomWord32)
import qualified Tox.Crypto.Core.Sign               as Sign
import qualified Tox.DHT.DhtState                   as DhtState
import qualified Tox.DHT.Operation                  as DHT
import           Tox.Network.Core.Networked         (Networked (..))
import qualified Tox.Network.Core.NodeInfo          as NodeInfo
import           Tox.Network.Core.NodeInfo          (NodeInfo (NodeInfo))
import           Tox.Network.Core.Packet            (Packet (..),
                                                     RawPayload (..))
import qualified Tox.Network.Core.PacketKind        as PacketKind
import           Tox.Network.Core.SocketAddress     (SocketAddress)
import           Tox.Network.Core.TransportProtocol (TransportProtocol (..))
import qualified Tox.Network.TCP.Connections        as Tcp
import           Tox.Onion.GroupAnnounce            (Announce (..),
                                                     packAnnounce,
                                                     unpackAnnounce,
                                                     unpackAnnounces)
import qualified Tox.Onion.Operation                as Onion
import qualified Tox.Persistence.Groups             as PG
import qualified Tox.Session.Connection             as Connection
import           Tox.Session.Connection             (ConnectionEvent (..))
import qualified Tox.Session.Friend                 as Messenger


{-------------------------------------------------------------------------------
 -
 - :: Constants.
 -
 ------------------------------------------------------------------------------}

handshakeInterval, pingInterval, pingCheckInterval, unconfirmedTimeout, confirmedTimeout,
  syncRequestLimit, peerSyncLimit, peerListLimit, keyRotationInterval, keyRotationMinGap,
  loadPeersInterval, directTimeout, directRetry, relayShareInterval, relayCheckInterval, ackRequestInterval,
  handshakeDecay :: TimeDiff
handshakeInterval   = Time.seconds 3
pingInterval        = Time.seconds 12
pingCheckInterval   = Time.seconds 2
unconfirmedTimeout  = Time.seconds 12
confirmedTimeout    = Time.seconds 58
syncRequestLimit    = Time.seconds 13
peerSyncLimit       = Time.seconds 12
peerListLimit       = Time.seconds 3
keyRotationInterval = Time.seconds 300
keyRotationMinGap   = Time.seconds 150
loadPeersInterval   = Time.seconds 22
directTimeout       = Time.seconds 16
directRetry         = Time.seconds 1
relayShareInterval  = Time.seconds 180
relayCheckInterval  = Time.seconds 10
ackRequestInterval  = Time.seconds 1
handshakeDecay      = Time.seconds 1

maxSavedInvites, maxSavedPeers, maxPeerRelays, maxSharedRelays, bufferSize, maxNewHandshakes :: Int
maxSavedInvites = 10
maxSavedPeers   = 100
maxPeerRelays   = 6
maxSharedRelays = 3
-- | Lossless packets in flight each way, and how far ahead we buffer.
bufferSize      = 2048
-- | Handshake requests we take in a burst. 1 more each 'handshakeDecay'.
maxNewHandshakes = 32

data Role = Founder | Moderator | User | Observer
  deriving (Eq, Ord, Show, Enum, Bounded)

data ExitType = ExitQuit | ExitTimeout | ExitDisconnected | ExitSelfDisconnected | ExitKicked | ExitSyncError
  deriving (Eq, Show, Enum, Bounded)

data JoinFail = JoinFailFull | JoinFailBadPassword | JoinFailUnknown
  deriving (Eq, Show, Enum, Bounded)

data GroupState = Connecting | Connected | Disconnected
  deriving (Eq, Show)

type GroupNumber = Word32
type PeerId = Word32

-- | Others count from 1, as in toxcore.
selfPeerId :: PeerId
selfPeerId = 0


{-------------------------------------------------------------------------------
 -
 - :: State.
 -
 ------------------------------------------------------------------------------}

-- | Lossless packet waiting for the peer's ack.
data Sent = Sent
  { sentType    :: Word8
  , sentPayload :: ByteString
  , sentAdded   :: Timestamp
  , sentLastTry :: Timestamp
  } deriving (Eq, Show)

data Peer = Peer
  { peerId            :: PeerId
  , peerEncPk         :: PublicKey
  , peerSigPk         :: Maybe ByteString
  , peerAddr          :: Maybe SocketAddress
  , peerFriend        :: Maybe PublicKey   -- ^ Friend who invited us, or who we invited.
  , peerSession       :: KeyPair
  , peerShared        :: Maybe CombinedKey
  , peerHandshaked    :: Bool
  , peerPendingReply  :: Bool              -- ^ We owe the peer a handshake response.
  , peerPendingType   :: Word8
  , peerLastHandshake :: Maybe Timestamp
  , peerSendId        :: Word64
  , peerRecvId        :: Word64
  , peerSendArray     :: Map Word64 Sent
  , peerRecvArray     :: Map Word64 (Word8, ByteString)
  , peerFragments     :: Maybe [ByteString] -- ^ Chunks of a message so far, newest first.
  , peerLastRecv      :: Timestamp
  , peerLastAckReq    :: Maybe Timestamp
  , peerConfirmed     :: Bool
  , peerJoinReported  :: Bool
  , peerNick          :: ByteString
  , peerStatus        :: Word8
  , peerLastPing      :: Timestamp
  , peerLastSyncReply :: Maybe Timestamp
  , peerSelfIsCloser  :: Bool              -- ^ We start key rotations.
  , peerLastRotation  :: Timestamp
  , peerRotating      :: Maybe KeyPair     -- ^ Our next session keys, until the peer answers.
  , peerRelays        :: [NodeInfo]        -- ^ Relays the peer is on, newest first.
  , peerLastDirect    :: Maybe Timestamp   -- ^ Last packet straight from the peer's address.
  , peerLastDirectTry :: Maybe Timestamp
  , peerHandshakes    :: Int
  , peerRelaysShared  :: Maybe Timestamp
  , peerRolesAsked    :: Maybe Word16
    -- ^ Roles checksum the peer sent when we last asked for its state.
  , peerRolesSynced   :: Maybe Word16
    -- ^ Roles checksum of the last full state it sent us.
  , peerSyncResponses :: Maybe Int
    -- ^ Sync responses since we last asked the peer for a sync, if we did.
  } deriving (Eq, Show)

data Group = Group
  { grChatId        :: ByteString -- ^ Chat's signing key.
  , grChatKeys      :: Maybe Sign.SignKeyPair -- ^ Only the founder has them.
  , grSelf          :: ExtKeys
  , grNick          :: ByteString
  , grStatus        :: Word8
  , grState         :: GroupState
  , grJoinType      :: Word8
  , grPassword      :: ByteString
  , grSharedState   :: Maybe (SharedState, ByteString) -- ^ With its signed packet.
  , grTopic         :: Maybe (TopicInfo, ByteString)
  , grModList       :: [ByteString]
  , grSanctions     :: ([Sanction], Maybe Creds)
  , grPeers         :: Map PublicKey Peer
  , grInvites       :: [PublicKey] -- ^ Friends we invited.
  , grLastSync      :: Maybe Timestamp
  , grLastPeerList  :: Maybe Timestamp
  , grConnectedAt   :: Maybe Timestamp
  , grSearchKey     :: Maybe PublicKey -- ^ Onion key public groups are found under.
  , grAnnounced     :: Maybe (Announce, Timestamp)
  , grSavedPeers    :: [PG.SavedPeer] -- ^ Peers to reconnect to when we have none, last seen first.
  , grPeersLoaded   :: Maybe Timestamp
  , grRelaysChecked :: Maybe Timestamp
  , grHandshakes    :: (Int, Maybe Timestamp) -- ^ Recent handshake requests, and when we last let one go.
  , grTopicSet      :: Maybe (Word16, Timestamp) -- ^ Checksum of the previous topic, and when it changed.
  } deriving (Eq, Show)

-- | Group we're joining, before we know anything about it.
newGroup :: ByteString -> ExtKeys -> ByteString -> Word8 -> ByteString -> Group
newGroup chatId self nick joinType password = Group
  { grChatId       = chatId
  , grChatKeys     = Nothing
  , grSelf         = self
  , grNick         = nick
  , grStatus       = 0
  , grState        = Connecting
  , grJoinType     = joinType
  , grPassword     = BS.take maxPasswordSize password
  , grSharedState  = Nothing
  , grTopic        = Nothing
  , grModList      = []
  , grSanctions    = ([], Nothing)
  , grPeers        = Map.empty
  , grInvites      = []
  , grLastSync     = Nothing
  , grLastPeerList = Nothing
  , grConnectedAt  = Nothing
  , grSearchKey    = Nothing
  , grAnnounced    = Nothing
  , grSavedPeers   = []
  , grPeersLoaded  = Nothing
  , grRelaysChecked = Nothing
  , grHandshakes   = (0, Nothing)
  , grTopicSet     = Nothing
  }

data Groups = Groups
  { groups    :: Map GroupNumber Group
  , groupJobs :: Schedule GroupJob -- ^ When each group and peer next needs us.
  }

data GroupJob = GroupWork GroupNumber | PeerWork GroupNumber PublicKey
  deriving (Eq, Ord, Show)

emptyGroups :: Groups
emptyGroups = Groups Map.empty Schedule.empty

data GroupEvent
  = GroupInvite PublicKey ByteString ByteString -- ^ Friend, invite data and group name.
  | GroupSelfJoin GroupNumber
  | GroupJoinFail GroupNumber JoinFail
  | GroupPeerJoin GroupNumber PeerId PublicKey
  | GroupPeerExit GroupNumber PeerId ExitType ByteString ByteString -- ^ Name and part message.
  | GroupPeerName GroupNumber PeerId ByteString
  | GroupPeerStatus GroupNumber PeerId Word8
  | GroupMessage GroupNumber PeerId Messenger.MessageType ByteString Word32
  | GroupPrivateMessage GroupNumber PeerId Messenger.MessageType ByteString Word32
  | GroupTopic GroupNumber (Maybe PeerId) ByteString
  | GroupModeration GroupNumber (Maybe PeerId) (Maybe PeerId) Moderation -- ^ Setter and target, 'Nothing' for us.
  | GroupPrivacy GroupNumber Bool -- ^ Whether it is private now.
  | GroupPeerLimit GroupNumber Word16
  | GroupPassword GroupNumber ByteString
  | GroupTopicLock GroupNumber Bool
  | GroupVoiceState GroupNumber Voice
  | GroupCustomPacket GroupNumber PeerId ByteString
  | GroupCustomPrivatePacket GroupNumber PeerId ByteString
  deriving (Eq, Show)

-- | Numbered as in toxcore.
data Moderation = ModKick | ModObserver | ModUser | ModModerator
  deriving (Eq, Show, Enum, Bounded)

-- | Numbered as in the shared state.
data Voice = VoiceAll | VoiceModerators | VoiceFounder
  deriving (Eq, Show, Enum, Bounded)

class (Messenger.MessengerMonad m, Networked m, Onion.OnionNodeMonad m, DHT.DhtNodeMonad m, Tcp.TcpMonad m)
      => GroupMonad m where
  getGroups :: m Groups
  putGroups :: Groups -> m ()
  -- | Run on a group's own relay connections (by chat ID, with its keys).
  withGroupTcp :: ByteString -> KeyPair -> (forall t. Tcp.TcpMonad t => t a) -> m a
  dropGroupTcp :: ByteString -> m ()
  groupUdp :: m Bool

getGroup :: GroupMonad m => GroupNumber -> m (Maybe Group)
getGroup g = Map.lookup g . groups <$> getGroups

modifyGroup :: GroupMonad m => GroupNumber -> (Group -> Group) -> m ()
modifyGroup g f = getGroup g >>= mapM_ (setGroup g . Just . f)

-- | The only way to change 'groups', so the groups' own jobs stay in step.
-- Peers keep theirs with 'reschedulePeer', and all of them are rescheduled
-- when the group comes, goes or changes state.
setGroup :: GroupMonad m => GroupNumber -> Maybe Group -> m ()
setGroup g new = do
  now <- askTime
  Groups gs jobs <- getGroups
  let old = Map.lookup g gs
      peers gr = [ (PeerWork g pk, peerDue now gr p) | (pk, p) <- Map.toList (grPeers gr) ]
      again = (grState <$> old) /= (grState <$> new)
      jobs' = case new of
        Nothing -> foldr Schedule.cancel jobs (GroupWork g : maybe [] (map fst . peers) old)
        Just gr -> Schedule.at (groupDue now gr) (GroupWork g)
          $ if again then foldr (\(job, (from, by)) -> Schedule.within from by job) jobs (peers gr) else jobs
  putGroups $ Groups (Map.alter (const new) g gs) jobs'

modifyPeer :: GroupMonad m => GroupNumber -> PublicKey -> (Peer -> Peer) -> m ()
modifyPeer g pk f = modifyGroup g (\gr -> gr { grPeers = Map.adjust f pk (grPeers gr) }) >> reschedulePeer g pk

-- | After anything that changes or removes the peer.
reschedulePeer :: GroupMonad m => GroupNumber -> PublicKey -> m ()
reschedulePeer g pk = do
  now <- askTime
  Groups gs jobs <- getGroups
  let job = PeerWork g pk
      due = do
        gr <- Map.lookup g gs
        peerDue now gr <$> Map.lookup pk (grPeers gr)
  putGroups . Groups gs $ maybe (Schedule.cancel job) (\(from, by) -> Schedule.within from by job) due jobs

getPeer :: GroupMonad m => GroupNumber -> PublicKey -> m (Maybe Peer)
getPeer g pk = (>>= Map.lookup pk . grPeers) <$> getGroup g

selfEncPk :: Group -> PublicKey
selfEncPk = extEncPk . grSelf

confirmedPeers :: Group -> [Peer]
confirmedPeers = filter peerConfirmed . Map.elems . grPeers

stateVersion :: Group -> Word32
stateVersion = maybe 0 (ssVersion . fst) . grSharedState

isSynced :: Group -> Bool
isSynced = (> 0) . stateVersion

isPrivate :: Group -> Bool
isPrivate gr = maybe (grJoinType gr == joinPrivate) ((== 1) . ssPrivacy . fst) (grSharedState gr)

passwordOf :: Group -> ByteString
passwordOf gr = maybe (grPassword gr) (ssPassword . fst) (grSharedState gr)

roleOf :: Group -> PublicKey -> Maybe ByteString -> Role
roleOf gr encPk sigPk
  | maybe False ((== encPk) . ssFounderEnc . fst) (grSharedState gr) = Founder
  | maybe False (`elem` grModList gr) sigPk = Moderator
  | any ((== encPk) . snTarget) (fst $ grSanctions gr) = Observer
  | otherwise = User

selfRole :: Group -> Role
selfRole gr = roleOf gr (selfEncPk gr) (Just . extSigPk $ grSelf gr)

peerRole :: Group -> Peer -> Role
peerRole gr p = roleOf gr (peerEncPk p) (peerSigPk p)

confirmedPeer :: Group -> PeerId -> Maybe Peer
confirmedPeer gr n = find ((== n) . peerId) (confirmedPeers gr)

sanctionSetters :: Group -> [ByteString]
sanctionSetters gr = maybe [] ((: grModList gr) . ssFounderSig . fst) (grSharedState gr)

-- | Same rule as toxcore.
newerCreds :: Creds -> Maybe Creds -> Bool
newerCreds creds = maybe True $ \o ->
  crVersion creds > crVersion o || (crVersion creds == crVersion o && crChecksum creds > crChecksum o)

optionalPassword :: ByteString -> ByteString
optionalPassword pw = if BS.null pw then BS.empty else packPassword pw

hasVoice :: Group -> Role -> Bool
hasVoice gr role = case voiceOf . ssVoice . fst =<< grSharedState gr of
  Just VoiceModerators -> role <= Moderator
  Just VoiceFounder    -> role == Founder
  _                    -> role <= User

-- | Whether the group takes what the peer says. Clients check files shared
-- in custom packets themselves.
canSpeak :: Group -> Peer -> Bool
canSpeak gr p = peerRole gr p /= Observer && hasVoice gr (peerRole gr p)

isFull :: Group -> Peer -> Bool
isFull gr p = not (peerConfirmed p) && peerRole gr p /= Founder && length (confirmedPeers gr) + 1 >= peerLimit gr

peerLimit :: Group -> Int
peerLimit = maybe (fromIntegral defaultMaxPeers) (fromIntegral . ssMaxPeers . fst) . grSharedState

findGroupByChatId :: GroupMonad m => ByteString -> m (Maybe GroupNumber)
findGroupByChatId chatId = do
  gs <- groups <$> getGroups
  return $ fst <$> find ((== chatId) . grChatId . snd) (Map.toList gs)

freeNumber :: (Ord k, Enum k, Bounded k) => Map k a -> Maybe k
freeNumber m = find (`Map.notMember` m) [minBound .. maxBound]


{-------------------------------------------------------------------------------
 -
 - :: Peers.
 -
 ------------------------------------------------------------------------------}

-- | Like toxcore's peer_add.
addPeer :: GroupMonad m
        => GroupNumber -> PublicKey -> Maybe SocketAddress -> Maybe PublicKey -> m (Maybe Peer)
addPeer g pk addr friend = getGroup g >>= \case
  Nothing -> return Nothing
  Just gr | pk == selfEncPk gr -> return Nothing
  Just gr -> case Map.lookup pk (grPeers gr) of
    Just p -> return (Just p)
    Nothing -> do
      now <- askTime
      session <- newKeyPair
      let taken = (selfPeerId, ()) : [ (peerId q, ()) | q <- Map.elems (grPeers gr) ]
          n = fromMaybe selfPeerId . freeNumber $ Map.fromList taken
          closer = closerTo (grChatId gr) (keyBytes $ selfEncPk gr) (keyBytes pk)
          p = Peer
            { peerId            = n
            , peerEncPk         = pk
            , peerSigPk         = Nothing
            , peerAddr          = addr
            , peerFriend        = friend
            , peerSession       = session
            , peerShared        = Nothing
            , peerHandshaked    = False
            , peerPendingReply  = False
            , peerPendingType   = requestInvite
            , peerLastHandshake = Nothing
            , peerSendId        = 1
            , peerRecvId        = 0
            , peerSendArray     = Map.empty
            , peerRecvArray     = Map.empty
            , peerFragments     = Nothing
            , peerLastRecv      = now
            , peerLastAckReq    = Nothing
            , peerConfirmed     = False
            , peerJoinReported  = False
            , peerNick          = ""
            , peerStatus        = 0
            , peerLastPing      = Time.addTime now (Time.seconds (fromIntegral (n `mod` 6) - 6))
            , peerLastSyncReply = Nothing
            , peerSelfIsCloser  = closer
            , peerLastRotation  = now
            , peerRotating      = Nothing
            , peerRelays        = []
            , peerLastDirect    = Nothing
            , peerLastDirectTry = Nothing
            , peerHandshakes    = 0
            , peerRelaysShared  = Nothing
            , peerRolesAsked    = Nothing
            , peerRolesSynced   = Nothing
            , peerSyncResponses = Nothing
            }
      modifyGroup g $ \gr' -> gr' { grPeers = Map.insert pk p (grPeers gr') }
      reschedulePeer g pk
      return (Just p)

closerTo :: ByteString -> ByteString -> ByteString -> Bool
closerTo base a b = BS.zipWith xor base a < BS.zipWith xor base b

deletePeer :: GroupMonad m => GroupNumber -> PublicKey -> ExitType -> ByteString -> m [GroupEvent]
deletePeer g pk exit part = getPeer g pk >>= \case
  Nothing -> return []
  Just p -> do
    getGroup g >>= mapM_ (\gr -> groupTcp gr $ Tcp.removePeer pk)
    modifyGroup g $ \gr -> gr
      { grPeers = Map.delete pk (grPeers gr)
      , grSavedPeers = case reachable p of
          Just saved | peerConfirmed p ->
            take maxSavedPeers $ saved : filter ((/= pk) . PG.savedPublicKey) (grSavedPeers gr)
          _ -> grSavedPeers gr
      }
    reschedulePeer g pk
    return [ GroupPeerExit g (peerId p) exit (peerNick p) part | peerJoinReported p ]

-- | For reconnecting after a restart.
savedPeersOf :: Group -> [PG.SavedPeer]
savedPeersOf gr = take maxSavedPeers $ mapMaybe reachable (confirmedPeers gr)
  ++ filter ((`Map.notMember` grPeers gr) . PG.savedPublicKey) (grSavedPeers gr)

reachable :: Peer -> Maybe PG.SavedPeer
reachable p = case (peerAddr p, listToMaybe $ peerRelays p) of
  (Nothing, Nothing) -> Nothing
  (addr, relay)      -> Just $ PG.SavedPeer addr relay (peerEncPk p)

loadSavedPeers :: GroupMonad m => GroupNumber -> Timestamp -> m ()
loadSavedPeers g now = getGroup g >>= mapM_ (\gr ->
  when (Map.null (grPeers gr) && grState gr /= Disconnected
        && Time.due now loadPeersInterval (grPeersLoaded gr)) $ do
    modifyGroup g $ \gr' -> gr' { grPeersLoaded = Just now }
    forM_ (grSavedPeers gr) $ \(PG.SavedPeer addr relay pk) ->
      addPeer g pk addr Nothing >> mapM_ (learnRelay g pk) relay)


{-------------------------------------------------------------------------------
 -
 - :: Sending.
 -
 ------------------------------------------------------------------------------}

sendRaw :: GroupMonad m => SocketAddress -> PublicKey -> ByteString -> m ()
sendRaw addr pk bytes = case BS.uncons bytes >>= \(b, rest) -> (,) <$> PacketKind.byteToKind b <*> pure rest of
  Just (kind, rest) -> sendPacket (NodeInfo UDP addr pk) (Packet kind (RawPayload rest))
  Nothing -> return ()

-- | To the peer's address, and through a relay if there's no address, or
-- every other time in case the address doesn't work.
sendHandshake :: GroupMonad m => GroupNumber -> PublicKey -> Word8 -> Word8 -> m ()
sendHandshake g pk ty requestType = getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup pk (grPeers gr)) $ \p0 -> do
  p <- usable p0
  when (isJust (peerAddr p) || not (null $ peerRelays p)) $ do
    nonce <- randomNonce
    now <- askTime
    let joinType = if ty == handshakeResponse then 0 else grJoinType gr
        h = Handshake ty (publicKey $ peerSession p) (extSigPk $ grSelf gr) requestType joinType
              (listToMaybe $ peerRelays p)
        packet = wrapHandshake (selfEncPk gr) (extEncSk $ grSelf gr) pk nonce h
        fallback = odd (peerHandshakes p) && not (null $ peerRelays p)
    forM_ (peerAddr p) $ \addr -> unless fallback $ sendRaw addr pk packet
    when (fallback || isNothing (peerAddr p)) . void $ viaRelay gr p packet
    -- Request and response are messages 1 and 2.
    modifyPeer g pk $ \p' -> p' { peerLastHandshake = Just now, peerHandshakes = peerHandshakes p' + 1
                               , peerSendId = if ty == handshakeResponse then 3 else 2 })

transmit :: GroupMonad m => Group -> Peer -> Bool -> Word8 -> Maybe Word64 -> ByteString -> m ()
transmit gr p lossless ty msgId payload = forM_ (peerShared p) $ \shared -> do
  nonce <- randomNonce
  deliver gr p $ wrapPacket lossless (selfEncPk gr) shared nonce ty msgId payload

-- | To the peer's address while it talks to us from there, else through a
-- relay, trying the address again every second. Without a relay, always to
-- the address.
deliver :: GroupMonad m => Group -> Peer -> ByteString -> m ()
deliver gr p0 bytes = do
  p <- usable p0
  now <- askTime
  let pk = peerEncPk p
      direct = not (Time.due now directTimeout (peerLastDirect p))
      tryDirect = Time.due now directRetry (peerLastDirectTry p)
  case peerAddr p of
    Just addr | direct -> sendRaw addr pk bytes
    _ -> do
      g <- findGroupByChatId (grChatId gr)
      forM_ (peerAddr p) $ \addr -> when tryDirect $ do
        sendRaw addr pk bytes
        mapM_ (\n -> modifyPeer n pk $ \p' -> p' { peerLastDirectTry = Just now }) g
      sent <- viaRelay gr p bytes
      unless (sent || tryDirect) $ forM_ (peerAddr p) $ \addr -> sendRaw addr pk bytes

usable :: GroupMonad m => Peer -> m Peer
usable p = (\udp -> if udp then p else p { peerAddr = Nothing }) <$> groupUdp

viaRelay :: GroupMonad m => Group -> Peer -> ByteString -> m Bool
viaRelay gr p bytes = groupTcp gr $ Tcp.sendToKey (peerEncPk p) (map NodeInfo.publicKey $ peerRelays p) bytes

groupTcp :: GroupMonad m => Group -> (forall t. Tcp.TcpMonad t => t a) -> m a
groupTcp gr = withGroupTcp (grChatId gr) (KeyPair (extEncSk $ grSelf gr) (extEncPk $ grSelf gr))

-- | Join the peer's relay and ask it to connect us.
learnRelay :: GroupMonad m => GroupNumber -> PublicKey -> NodeInfo -> m ()
learnRelay g pk relay = getGroup g >>= mapM_ (\gr -> when (Map.member pk (grPeers gr)) $ do
  let tcpRelay = relay { NodeInfo.protocol = TCP }
  groupTcp gr $ Tcp.addPeerRelay pk tcpRelay
  modifyPeer g pk $ \p -> p { peerRelays = take maxPeerRelays $
    tcpRelay : filter ((/= NodeInfo.publicKey relay) . NodeInfo.publicKey) (peerRelays p) })

packRelays :: [NodeInfo] -> ByteString
packRelays = putStrict . mapM_ Binary.put . take maxSharedRelays

sendLossy :: GroupMonad m => GroupNumber -> PublicKey -> Word8 -> ByteString -> m ()
sendLossy g pk ty payload = getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup pk (grPeers gr)) $ \p ->
  when (peerHandshaked p) $ transmit gr p False ty Nothing payload)

-- | In fragments if it's long. Nothing goes if the send window has no room
-- for all of it (a partial message would hold up everything after it).
sendLossless :: GroupMonad m => GroupNumber -> PublicKey -> Word8 -> ByteString -> m ()
sendLossless g pk ty payload = getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup pk (grPeers gr)) $ \p ->
  when (Map.size (peerSendArray p) + length pieces < bufferSize) $ mapM_ sendOne pieces)
  where
    pieces
      | BS.length payload <= maxChunkSize = [(ty, payload)]
      | otherwise = map (gpFragment,) $
          BS.cons ty (BS.take (maxChunkSize - 1) payload) : chunks (BS.drop (maxChunkSize - 1) payload) ++ [BS.empty]
    chunks bs | BS.null bs = []
              | otherwise = BS.take maxChunkSize bs : chunks (BS.drop maxChunkSize bs)
    sendOne (t, bytes) = getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup pk (grPeers gr)) $ \p -> do
      now <- askTime
      let msgId = peerSendId p
      modifyPeer g pk $ \p' ->
        p' { peerSendId = msgId + 1, peerSendArray = Map.insert msgId (Sent t bytes now now) (peerSendArray p') }
      transmit gr p True t (Just msgId) bytes)

sendToConfirmed :: GroupMonad m => GroupNumber -> Word8 -> ByteString -> m Int
sendToConfirmed g ty payload = getGroup g >>= \case
  Nothing -> return 0
  Just gr -> do
    let ps = confirmedPeers gr
    mapM_ (\p -> sendLossless g (peerEncPk p) ty payload) ps
    return (length ps)

broadcast :: GroupMonad m => GroupNumber -> Word8 -> ByteString -> m Int
broadcast g bc body = sendToConfirmed g gpBroadcast (BS.cons bc body)

sendAck :: GroupMonad m => GroupNumber -> PublicKey -> Word8 -> Word64 -> m ()
sendAck g pk ty msgId = sendLossy g pk gpMessageAck (BS.singleton ty <> putStrict (putWord64be msgId))

sendPeerInfo :: GroupMonad m => GroupNumber -> PublicKey -> m ()
sendPeerInfo g pk = getGroup g >>= mapM_ (\gr -> do
  let pw = passwordOf gr
  sendLossless g pk gpPeerInfoResponse $
    optionalPassword pw <> packPeerInfo (grNick gr) (grStatus gr))

-- | Whether it went (we only send requests so often).
sendSyncRequest :: GroupMonad m => GroupNumber -> PublicKey -> Word16 -> m Bool
sendSyncRequest g pk flags = getGroup g >>= \case
  Nothing -> return False
  Just gr -> do
    now <- askTime
    let due = Time.due now syncRequestLimit (grLastSync gr)
    when due $ do
      modifyGroup g $ \gr' -> gr' { grLastSync = Just now }
      modifyPeer g pk $ \p -> p { peerSyncResponses = Just 0 }
      let pw = passwordOf gr
      sendLossless g pk gpSyncRequest $ putStrict (putWord16be flags) <> optionalPassword pw
    return due

sendInviteRequest :: GroupMonad m => GroupNumber -> PublicKey -> m ()
sendInviteRequest g pk = getGroup g >>= mapM_ (\gr -> do
  let pw = grPassword gr
  sendLossless g pk gpInviteRequest (optionalPassword pw))

sendSync :: GroupMonad m => GroupNumber -> PublicKey -> Word16 -> m ()
sendSync g pk flags = getGroup g >>= mapM_ (\gr -> do
  now <- askTime
  when (flags .&. syncState /= 0) $ forM_ (grSharedState gr) $ \(_, signed) -> do
    sendLossless g pk gpSharedState signed
    sendLossless g pk gpModList (packModList $ grModList gr)
    forM_ (snd $ grSanctions gr) $ \creds -> when (crVersion creds > 0) $
      sendLossless g pk gpSanctionsList (packSanctionsList (fst $ grSanctions gr) creds)
  when (flags .&. syncTopic /= 0 && isJust (grConnectedAt gr)) $ forM_ (grTopic gr) $ \(t, signed) ->
    when (tiVersion t > 0) $ sendLossless g pk gpTopic signed
  when (flags .&. syncPeers /= 0) $ do
    let first = maybe True (isNothing . peerLastSyncReply) (Map.lookup pk (grPeers gr))
        limited = not (Time.due now peerListLimit (grLastPeerList gr))
    when (first || not limited) $ do
      modifyGroup g $ \gr' -> gr' { grLastPeerList = Just now }
      let others = [ Announce (peerEncPk p) (peerAddr p) (listToMaybe $ peerRelays p)
                   | p <- confirmedPeers gr, peerEncPk p /= pk ]
      if null others
        then sendLossless g pk gpSyncResponse BS.empty
        else mapM_ (sendLossless g pk gpSyncResponse . packAnnounce) others
  modifyPeer g pk $ \p -> p { peerLastSyncReply = Just now })


{-------------------------------------------------------------------------------
 -
 - :: Commands.
 -
 ------------------------------------------------------------------------------}

newExtKeys :: MonadRandomBytes m => m ExtKeys
newExtKeys = do
  keys <- Sign.newSignKeyPair
  maybe newExtKeys return (extKeysFromSign keys)

createGroup :: GroupMonad m => Bool -> ByteString -> ByteString -> m (Maybe GroupNumber)
createGroup private name nick
  | BS.null name || BS.length name > maxGroupNameSize || BS.null nick || BS.length nick > maxNickSize = return Nothing
  | otherwise = do
      chat <- newExtKeys
      self <- newExtKeys
      now <- askTime
      gs <- groups <$> getGroups
      forM (freeNumber gs) $ \g -> do
        let chatKeys = extSign chat
            state = SharedState
              { ssVersion     = 1
              , ssFounderEnc  = extEncPk self
              , ssFounderSig  = extSigPk self
              , ssMaxPeers    = defaultMaxPeers
              , ssGroupName   = name
              , ssPrivacy     = if private then 1 else 0
              , ssPassword    = BS.empty
              , ssModListHash = modListHash []
              , ssTopicLock   = 0
              , ssVoice       = 0
              }
            topic = TopicInfo 1 BS.empty (extSigPk self)
            gr = (newGroup (extSigPk chat) self nick (if private then joinPrivate else joinPublic) BS.empty)
                   { grChatKeys    = Just chatKeys
                   , grState       = Connected
                   , grSharedState = Just (state, signSharedState chatKeys state)
                   , grTopic       = Just (topic, signTopic (extSign self) topic)
                   , grSanctions   = ([], Just $ emptyCreds (extSign self) 1)
                   , grConnectedAt = Just now
                   }
        setGroup g (Just gr)
        unless private $ startSearch g (extSigPk chat)
        return g

inviteFriend :: GroupMonad m => GroupNumber -> PublicKey -> m Bool
inviteFriend g friend = getGroup g >>= \case
  Just gr | grState gr == Connected, Just (s, _) <- grSharedState gr -> do
    sent <- Messenger.sendPacketId friend packetIdGroupInvite $
      BS.pack [friendInviteMarker, inviteGroup] <> grChatId gr <> keyBytes (selfEncPk gr) <> ssGroupName s
    when sent $ modifyGroup g $ \gr' -> gr' { grInvites = take maxSavedInvites (friend : grInvites gr') }
    return sent
  _ -> return False

data AcceptError = AcceptBadInvite | AcceptAlreadyJoined | AcceptBadNick | AcceptTooMany | AcceptFailed
  deriving (Eq, Show)

friendAddress :: GroupMonad m => PublicKey -> m (Maybe SocketAddress)
friendAddress friend = Connection.getsConn $ \cm ->
  NodeInfo.address <$> (Map.lookup friend (Connection.friends cm) >>= Connection.fcIpPort)

acceptInvite :: GroupMonad m
             => PublicKey -> ByteString -> ByteString -> ByteString
             -> m (Either AcceptError GroupNumber)
acceptInvite friend inviteData nick password
  | BS.length inviteData < inviteLength = return $ Left AcceptBadInvite
  | BS.null nick || BS.length nick > maxNickSize = return $ Left AcceptBadNick
  | otherwise = do
      let chatId = BS.take chatIdLength inviteData
      existing <- findGroupByChatId chatId
      gs <- groups <$> getGroups
      case (existing, keyAt chatIdLength inviteData, freeNumber gs) of
        (Just _, _, _) -> return $ Left AcceptAlreadyJoined
        (_, Nothing, _) -> return $ Left AcceptBadInvite
        (_, _, Nothing) -> return $ Left AcceptTooMany
        (Nothing, Just inviterPk, Just g) -> do
          self <- newExtKeys
          let gr = newGroup chatId self nick joinPrivate password
          setGroup g (Just gr)
          addr <- friendAddress friend
          _ <- addPeer g inviterPk addr (Just friend)
          sent <- Messenger.sendPacketId friend packetIdGroupInvite $
            BS.pack [friendInviteMarker, inviteAccepted] <> chatId <> keyBytes (selfEncPk gr)
          if sent then return (Right g) else do
            setGroup g Nothing
            return $ Left AcceptFailed

-- | We find peers through the onion, and announce ourselves there too.
joinPublicGroup :: GroupMonad m
                => ByteString -> ByteString -> ByteString -> m (Either AcceptError GroupNumber)
joinPublicGroup chatId nick password
  | BS.length chatId /= chatIdLength || isNothing (chatEncPk chatId) = return $ Left AcceptBadInvite
  | BS.null nick || BS.length nick > maxNickSize = return $ Left AcceptBadNick
  | otherwise = do
      existing <- findGroupByChatId chatId
      gs <- groups <$> getGroups
      case (existing, freeNumber gs) of
        (Just _, _) -> return $ Left AcceptAlreadyJoined
        (_, Nothing) -> return $ Left AcceptTooMany
        (Nothing, Just g) -> do
          self <- newExtKeys
          setGroup g . Just $ newGroup chatId self nick joinPublic password
          startSearch g chatId
          return $ Right g

startSearch :: GroupMonad m => GroupNumber -> ByteString -> m ()
startSearch g chatId = do
  searchKey <- randomKey
  Onion.addGroupSearch searchKey chatId
  modifyGroup g $ \gr -> gr { grSearchKey = Just searchKey }

announceSelf :: GroupMonad m => GroupNumber -> Timestamp -> m ()
announceSelf g now = getGroup g >>= mapM_ (\gr -> forM_ (grSearchKey gr) $ \searchKey -> do
  addr <- DHT.getsDht DhtState.dhtSelfAddress
  relay <- listToMaybe <$> groupTcp gr Tcp.connectedRelays
  let announce = Announce (selfEncPk gr) addr relay
      due = announceChanged addr relay gr || maybe False ((<= now) . (`Time.addTime` announceInterval) . snd) (grAnnounced gr)
  when (searchable gr && due && (isJust addr || isJust relay)) $ do
    Onion.setGroupAnnounce searchKey . Just $ grChatId gr <> packAnnounce announce
    modifyGroup g $ \gr' -> gr' { grAnnounced = Just (announce, now) })

-- | A public group, found under its search key.
searchable :: Group -> Bool
searchable gr = isJust (grSearchKey gr) && not (isPrivate gr)

announceChanged :: Maybe SocketAddress -> Maybe NodeInfo -> Group -> Bool
announceChanged addr relay gr = searchable gr && (isJust addr || isJust relay)
  && Just (Announce (selfEncPk gr) addr relay) /= (fst <$> grAnnounced gr)

announceInterval :: TimeDiff
announceInterval = Time.seconds 50

meetAnnounced :: GroupMonad m => GroupNumber -> Announce -> m ()
meetAnnounced g a = when (isJust (anAddr a) || isJust (anRelay a)) $ do
  _ <- addPeer g (anPk a) (anAddr a) Nothing
  mapM_ (learnRelay g (anPk a)) (anRelay a)

handleOnionEvent :: GroupMonad m => Onion.OnionEvent -> m [GroupEvent]
handleOnionEvent = \case
  Onion.GroupAnnouncesFound chatId bytes -> do
    mg <- findGroupByChatId chatId
    forM_ ((,) <$> mg <*> unpackAnnounces bytes) $ \(g, announces) -> getGroup g >>= mapM_ (\gr ->
      unless (isPrivate gr) $ forM_ announces $ \a ->
        when (anPk a /= selfEncPk gr && Map.notMember (anPk a) (grPeers gr)) $ meetAnnounced g a)
    return []
  _ -> return []

data GroupSendError
  = GroupSendNoGroup | GroupSendTooLong | GroupSendEmpty | GroupSendNotConnected | GroupSendNoPeer | GroupSendNoVoice
  deriving (Eq, Show)

-- | Gives the random message ID.
sendMessage :: GroupMonad m
            => GroupNumber -> Messenger.MessageType -> ByteString
            -> m (Either GroupSendError Word32)
sendMessage g ty msg = getGroup g >>= \case
  Nothing -> return $ Left GroupSendNoGroup
  Just gr
    | BS.null msg -> return $ Left GroupSendEmpty
    | BS.length msg > maxMessageSize -> return $ Left GroupSendTooLong
    | grState gr /= Connected -> return $ Left GroupSendNotConnected
    | selfRole gr == Observer || not (hasVoice gr $ selfRole gr) -> return $ Left GroupSendNoVoice
    | otherwise -> do
        msgId <- randomWord32
        let kind = if ty == Messenger.MessageNormal then bcPlainMessage else bcActionMessage
        _ <- broadcast g kind (putStrict (putWord32be msgId) <> msg)
        return $ Right msgId

sendPrivateMessage :: GroupMonad m
                   => GroupNumber -> PeerId -> Messenger.MessageType -> ByteString
                   -> m (Either GroupSendError Word32)
sendPrivateMessage g n ty msg = getGroup g >>= \case
  Nothing -> return $ Left GroupSendNoGroup
  Just gr -> case confirmedPeer gr n of
    _ | BS.null msg -> return $ Left GroupSendEmpty
    _ | BS.length msg > maxMessageSize -> return $ Left GroupSendTooLong
    _ | selfRole gr == Observer -> return $ Left GroupSendNoVoice
    Nothing -> return $ Left GroupSendNoPeer
    Just p -> do
      msgId <- randomWord32
      sendLossless g (peerEncPk p) gpBroadcast $
        BS.pack [bcPrivateMessage, if ty == Messenger.MessageNormal then 0 else 1]
          <> putStrict (putWord32be msgId) <> msg
      return $ Right msgId

sendCustomPacket :: GroupMonad m
                 => GroupNumber -> Maybe PeerId -> Bool -> ByteString
                 -> m (Either GroupSendError ())
sendCustomPacket g to lossless bytes = getGroup g >>= \case
  Nothing -> return $ Left GroupSendNoGroup
  Just gr
    | BS.null bytes -> return $ Left GroupSendEmpty
    | BS.length bytes > maxCustomPacketSize -> return $ Left GroupSendTooLong
    | grState gr == Disconnected -> return $ Left GroupSendNotConnected
    | otherwise -> case to of
        Nothing -> Right () <$ mapM_ (send gpCustomPacket) (confirmedPeers gr)
        Just n -> maybe (return $ Left GroupSendNoPeer) (fmap Right . send gpCustomPrivatePacket) (confirmedPeer gr n)
  where
    send ty p = (if lossless then sendLossless else sendLossy) g (peerEncPk p) ty bytes

-- | Anyone but observers, or only moderators while it's locked.
mayTopic :: Group -> Bool
mayTopic gr = case grSharedState gr of
  Just (s, _) | isJust (grTopic gr) -> if ssTopicLock s == 0 then selfRole gr <= Moderator else selfRole gr <= User
  _ -> False

setTopic :: GroupMonad m => GroupNumber -> ByteString -> m Bool
setTopic g topic = getGroup g >>= \case
  Just gr | BS.length topic <= maxTopicSize, mayTopic gr
          , Just (s, _) <- grSharedState gr, Just (old, _) <- grTopic gr -> do
    let version = if ssTopicLock s == 0 then tiVersion old + 1 else tiVersion old
        info = TopicInfo version topic (extSigPk $ grSelf gr)
        signed = signTopic (extSign $ grSelf gr) info
    modifyGroup g $ \gr' -> gr' { grTopic = Just (info, signed) }
    _ <- sendToConfirmed g gpTopic signed
    return True
  _ -> return False

setNick :: GroupMonad m => GroupNumber -> ByteString -> m Bool
setNick g nick
  | BS.null nick || BS.length nick > maxNickSize = return False
  | otherwise = getGroup g >>= \case
      Nothing -> return False
      Just _ -> do
        modifyGroup g $ \gr -> gr { grNick = nick }
        _ <- broadcast g bcNick nick
        return True

setStatus :: GroupMonad m => GroupNumber -> Word8 -> m Bool
setStatus g status
  | status > maxPeerStatus = return False
  | otherwise = getGroup g >>= \case
      Nothing -> return False
      Just _ -> do
        modifyGroup g $ \gr -> gr { grStatus = status }
        _ <- broadcast g bcStatus (BS.singleton status)
        return True

data ModError = ModNoGroup | ModNoPeer | ModNotAllowed | ModNoChange | ModFailed
  deriving (Eq, Show)

kickPeer :: GroupMonad m => GroupNumber -> PeerId -> m (Either ModError ())
kickPeer g n = getGroup g >>= \case
  Nothing -> return $ Left ModNoGroup
  Just gr -> case confirmedPeer gr n of
    Nothing -> return $ Left ModNoPeer
    Just p
      | selfRole gr > Moderator || role == Founder || (selfRole gr /= Founder && role == Moderator) ->
          return $ Left ModNotAllowed
      | otherwise -> do
          demoted <- if role /= User then setRole g n User else return (Right ())
          case demoted of
            Left err -> return $ Left err
            Right () -> do
              _ <- broadcast g bcKickPeer (keyBytes $ peerEncPk p)
              _ <- deletePeer g (peerEncPk p) ExitKicked ""
              return $ Right ()
      where role = peerRole gr p

-- | The founder makes moderators, and moderators make observers.
setRole :: GroupMonad m => GroupNumber -> PeerId -> Role -> m (Either ModError ())
setRole g n new = getGroup g >>= \case
  Nothing -> return $ Left ModNoGroup
  Just gr -> case confirmedPeer gr n of
    Nothing -> return $ Left ModNoPeer
    Just p
      | new == Founder || current == new -> return $ Left ModNoChange
      | current == Founder || selfRole gr > Moderator -> return $ Left ModNotAllowed
      | selfRole gr /= Founder && (new == Moderator || current == Moderator) -> return $ Left ModNotAllowed
      | otherwise -> do
          ok <- case current of
            Moderator -> setModerator g p False `andThen` when' (new == Observer) (setObserver g p True)
            Observer -> setObserver g p False `andThen` when' (new == Moderator) (setModerator g p True)
            _ -> if new == Moderator then setModerator g p True else setObserver g p True
          return $ if ok then Right () else Left ModFailed
      where current = peerRole gr p
  where
    andThen a b = a >>= \ok -> if ok then b else return False
    when' c a = if c then a else return True

setModerator :: GroupMonad m => GroupNumber -> Peer -> Bool -> m Bool
setModerator g p add = getGroup g >>= \case
  Just gr0 | selfRole gr0 == Founder, grState gr0 /= Disconnected, isJust (grChatKeys gr0)
           , Just sigPk <- peerSigPk p -> do
    room <- if add && length (grModList gr0) >= fromIntegral maxModerators then pruneModList g else return True
    gr <- fromMaybe gr0 <$> getGroup g
    if not room then return False else do
      let mods = (if add then (sigPk :) else id) (filter (/= sigPk) (grModList gr))
      modifyGroup g $ \gr' -> gr' { grModList = mods }
      unless add $ resignFor g sigPk
      ok <- updateSharedState g $ \s -> s { ssModListHash = modListHash mods }
      when ok . void $ broadcast g bcSetMod (BS.singleton (if add then 1 else 0) <> sigPk)
      return ok
  _ -> return False

-- | Sign what a former moderator signed as ours.
resignFor :: GroupMonad m => GroupNumber -> ByteString -> m ()
resignFor g sigPk = getGroup g >>= mapM_ (\gr -> do
  let (sanctions, ours) = grSanctions gr
      self = extSign (grSelf gr)
  when (any ((== sigPk) . snSetter) sanctions) $ do
    let sanctions' = [ if snSetter sn == sigPk then resignSanction self sn else sn | sn <- sanctions ]
        creds = makeCreds self sanctions' (maybe 0 crVersion ours + 1)
    modifyGroup g $ \gr' -> gr' { grSanctions = (sanctions', Just creds) }
    void $ sendToConfirmed g gpSanctionsList (packSanctionsList sanctions' creds)
  forM_ (grTopic gr) $ \(t, _) -> when (tiSetter t == sigPk) . void $ setTopic g (tiTopic t))

-- | Make room in a full moderator list as toxcore does, by removing the first
-- moderator who isn't here.
pruneModList :: GroupMonad m => GroupNumber -> m Bool
pruneModList g = getGroup g >>= \case
  Just gr | Just sigPk <- find (\k -> all ((/= Just k) . peerSigPk) (Map.elems $ grPeers gr)) (grModList gr) -> do
    let mods = filter (/= sigPk) (grModList gr)
    modifyGroup g $ \gr' -> gr' { grModList = mods }
    ok <- updateSharedState g $ \s -> s { ssModListHash = modListHash mods }
    when ok $ do
      void $ sendToConfirmed g gpModList (packModList mods)
      resignFor g sigPk
    return ok
  _ -> return False

-- | Make room in a full sanctions list as toxcore does. The first observer who
-- isn't here stops being one.
pruneSanctions :: GroupMonad m => GroupNumber -> m Bool
pruneSanctions g = getGroup g >>= \case
  Just gr | (sanctions, ours) <- grSanctions gr
          , let gone sn = snTarget sn /= selfEncPk gr && all ((/= snTarget sn) . peerEncPk) (confirmedPeers gr)
          , Just sn <- find gone sanctions -> do
    let sanctions' = filter ((/= snTarget sn) . snTarget) sanctions
        creds = makeCreds (extSign $ grSelf gr) sanctions' (maybe 0 crVersion ours + 1)
    modifyGroup g $ \gr' -> gr' { grSanctions = (sanctions', Just creds) }
    -- toxcore sends the setter's key where the target's would be.
    void . broadcast g bcSetObserver $ BS.singleton 0 <> keyBytes (snTarget sn) <> snSetter sn <> packCreds creds
    return True
  _ -> return False

-- | User to observer, or back.
setObserver :: GroupMonad m => GroupNumber -> Peer -> Bool -> m Bool
setObserver g p add = getGroup g >>= \case
  Just gr0 | selfRole gr0 <= Moderator, Just sigPk <- peerSigPk p -> do
    full <- if add && length (fst $ grSanctions gr0) >= fromIntegral maxSanctions
      then not <$> pruneSanctions g
      else return False
    gr <- fromMaybe gr0 <$> getGroup g
    -- Keep an observer's topic, signed by us.
    when (add && not full) . forM_ (grTopic gr) $ \(t, _) -> when (tiSetter t == sigPk) . void $ setTopic g (tiTopic t)
    gr' <- fromMaybe gr <$> getGroup g
    let (sanctions, ours) = grSanctions gr'
        self = extSign (grSelf gr')
        target = peerEncPk p
        sanction = makeSanction self sanctionTimeSet target
        sanctions'
          | add = sanctions ++ [sanction]
          | otherwise = filter ((/= target) . snTarget) sanctions
        creds = makeCreds self sanctions' (maybe 0 crVersion ours + 1)
    if full then return False else do
      modifyGroup g $ \gr'' -> gr'' { grSanctions = (sanctions', Just creds) }
      void . broadcast g bcSetObserver $ BS.singleton (if add then 1 else 0) <> keyBytes target <> sigPk
        <> (if add then snPacked sanction else BS.empty) <> packCreds creds
      return True
  _ -> return False

updateSharedState :: GroupMonad m => GroupNumber -> (SharedState -> SharedState) -> m Bool
updateSharedState g f = getGroup g >>= \case
  Just gr | selfRole gr == Founder, grState gr /= Disconnected
          , Just chatKeys <- grChatKeys gr, Just (s, _) <- grSharedState gr -> do
    let s' = (f s) { ssVersion = ssVersion s + 1 }
        signed = signSharedState chatKeys s'
    modifyGroup g $ \gr' -> gr' { grSharedState = Just (s', signed) }
    _ <- sendToConfirmed g gpSharedState signed
    return True
  _ -> return False

setPassword :: GroupMonad m => GroupNumber -> ByteString -> m Bool
setPassword g pw
  | BS.length pw > maxPasswordSize = return False
  | otherwise = updateSharedState g $ \s -> s { ssPassword = pw }

setPeerLimit :: GroupMonad m => GroupNumber -> Word16 -> m Bool
setPeerLimit g n = updateSharedState g $ \s -> s { ssMaxPeers = n }

setVoice :: GroupMonad m => GroupNumber -> Voice -> m Bool
setVoice g v = updateSharedState g $ \s -> s { ssVoice = fromIntegral (fromEnum v) }

-- | Public groups are announced in the onion.
setPrivacy :: GroupMonad m => GroupNumber -> Bool -> m Bool
setPrivacy g private = getGroup g >>= \case
  Just gr | Just (s, _) <- grSharedState gr -> do
    ok <- updateSharedState g $ \s' -> s' { ssPrivacy = if private then 1 else 0 }
    when ok $ do
      modifyGroup g $ \gr' -> gr' { grJoinType = if private then joinPrivate else joinPublic }
      void $ stateChanged g s (s { ssPrivacy = if private then 1 else 0 })
    return ok
  _ -> return False

-- | Locking signs the topic again with a new version.
setTopicLock :: GroupMonad m => GroupNumber -> Bool -> m Bool
setTopicLock g locked = getGroup g >>= \case
  Just gr | selfRole gr == Founder, Just (s, signed) <- grSharedState gr, Just (t, _) <- grTopic gr ->
    if locked == (ssTopicLock s == 0) then return True else if locked
      then do
        modifyGroup g $ \gr' -> gr' { grSharedState = Just (s { ssTopicLock = 0 }, signed) }
        topicSet <- setTopic g (tiTopic t)
        if topicSet then updateSharedState g id else do
          modifyGroup g $ \gr' -> gr' { grSharedState = Just (s, signed) }
          return False
      else updateSharedState g $ \s' -> s' { ssTopicLock = tiVersion t }
  _ -> return False

-- | Takes a parting message.
leave :: GroupMonad m => GroupNumber -> ByteString -> m Bool
leave g part = getGroup g >>= \case
  Nothing -> return False
  Just _ -> do
    _ <- broadcast g bcPeerExit (BS.take maxPartSize part)
    getGroup g >>= mapM_ (\gr -> mapM_ Onion.removeGroupSearch (grSearchKey gr) >> dropGroupTcp (grChatId gr))
    setGroup g Nothing
    return True


{-------------------------------------------------------------------------------
 -
 - :: Friend invites.
 -
 ------------------------------------------------------------------------------}

handleConnectionEvent :: GroupMonad m => ConnectionEvent -> m [GroupEvent]
handleConnectionEvent = \case
  FriendData friend bytes | Just (ident, rest) <- BS.uncons bytes, ident == packetIdGroupInvite -> do
    known <- Messenger.getsMessenger (Map.member friend . Messenger.messengerFriends)
    -- After the invite marker and type.
    if known && BS.length rest >= 2 + inviteLength
      then handleFriendInvite friend (BS.index rest 1) (BS.drop 2 rest)
      else return []
  _ -> return []

handleFriendInvite :: GroupMonad m => PublicKey -> Word8 -> ByteString -> m [GroupEvent]
handleFriendInvite friend ty payload
  | ty == inviteGroup = do
      existing <- findGroupByChatId chatId
      return [ GroupInvite friend (BS.take inviteLength payload) (BS.drop inviteLength payload)
             | isNothing existing, BS.length payload > inviteLength ]
  | ty == inviteAccepted = withGroup $ \g gr -> do
      addr <- friendAddress friend
      relays <- take maxSharedRelays <$> Tcp.connectedRelays
      forM_ peerPk $ \pk -> when (friend `elem` grInvites gr && grState gr /= Disconnected) $ do
        modifyGroup g $ \gr' -> gr' { grInvites = filter (/= friend) (grInvites gr') }
        _ <- addPeer g pk addr (Just friend)
        -- So the peer can find us on our relays.
        mapM_ (learnRelay g pk) relays
        when (isJust addr || not (null relays)) . void . Messenger.sendPacketId friend packetIdGroupInvite $
          BS.pack [friendInviteMarker, inviteConfirmation] <> chatId <> keyBytes (selfEncPk gr) <> packRelays relays
      return []
  | ty == inviteConfirmation = withGroup $ \g _ -> do
      addr <- friendAddress friend
      forM_ peerPk $ \pk -> do
        modifyPeer g pk $ \p -> p { peerAddr = peerAddr p <|> addr, peerFriend = Just friend }
        mapM_ (learnRelay g pk) . take maxSharedRelays . fromMaybe [] . runGetStrict NodeInfo.getNodes $
          BS.drop inviteLength payload
      return []
  | otherwise = return []
  where
    chatId = BS.take chatIdLength payload
    peerPk = keyAt chatIdLength payload
    withGroup f = findGroupByChatId chatId >>= \case
      Nothing -> return []
      Just g -> getGroup g >>= maybe (return []) (f g)


{-------------------------------------------------------------------------------
 -
 - :: Receiving.
 -
 ------------------------------------------------------------------------------}

-- | From the DHT socket (with the address), or from a relay.
handlePacket :: GroupMonad m
             => Maybe SocketAddress -> PacketKind.PacketKind -> ByteString -> m [GroupEvent]
handlePacket from kind payload
  | BS.length payload <= packetOverhead || BS.length payload > maxIncomingChunkSize + packetOverhead + keyLength =
      return []
  | kind == PacketKind.GroupHandshake = case handshakeKeys payload of
      Nothing -> return []
      Just (senderPk, receiverPk) -> do
        gs <- Map.toList . groups <$> getGroups
        case find ((== receiverPk) . selfEncPk . snd) gs of
          Just (g, gr) | grState gr /= Disconnected, Just h <- openHandshake (extEncSk $ grSelf gr) payload ->
            handleHandshake g from senderPk h
          _ -> return []
  | otherwise = case packetSender payload of
      Nothing -> return []
      Just senderPk -> do
        gs <- Map.toList . groups <$> getGroups
        case [ (g, p) | (g, gr) <- gs, Just p <- [Map.lookup senderPk (grPeers gr)] ] of
          (g, p) : _ | Just shared <- peerShared p
                     , Just (ty, msgId, body) <- unwrapPacket (kind == PacketKind.GroupLossless) shared payload -> do
            now <- askTime
            modifyPeer g senderPk $ \p' -> p' { peerLastRecv = now, peerAddr = from <|> peerAddr p'
                                             , peerLastDirect = (now <$ from) <|> peerLastDirect p' }
            case msgId of
              Just i  -> handleLossless g senderPk ty i body
              Nothing -> handleLossy g senderPk ty body
          _ -> return []

handleHandshake :: GroupMonad m
                => GroupNumber -> Maybe SocketAddress -> PublicKey -> Handshake -> m [GroupEvent]
handleHandshake g from senderPk h
  | not (validSigPk senderPk (hsSigPk h)) = return []
  | hsType h == handshakeRequest = getGroup g >>= \case
    Just gr0 | fst (grHandshakes gr0) >= maxNewHandshakes -> return []
    _ -> do
      modifyGroup g $ \gr' -> gr' { grHandshakes = (fst (grHandshakes gr') + 1, snd (grHandshakes gr')) }
      existing <- getPeer g senderPk
      mp <- maybe (addPeer g senderPk from Nothing) (return . Just) existing
      gr <- getGroup g
      case (mp, gr) of
        (Just p, Just gr')
          | hsJoinType h == joinPublic && isPrivate gr' -> [] <$ deletePeer g senderPk ExitDisconnected ""
          | otherwise -> do
              now <- askTime
              modifyPeer g senderPk $ \p' -> p'
                { peerHandshaked = False
                , peerShared = Just (CombinedKey.precompute (secretKey $ peerSession p) (hsSessionPk h))
                , peerSigPk = Just (hsSigPk h)
                , peerAddr = from <|> peerAddr p'
                , peerLastDirect = (now <$ from) <|> peerLastDirect p'
                , peerRecvId = 1
                , peerPendingReply = True
                , peerPendingType = hsRequestType h
                , peerLastHandshake = Nothing
                , peerLastRecv = now
                , peerSendArray = Map.empty
                , peerRecvArray = Map.empty
                , peerFragments = Nothing
                }
              mapM_ (learnRelay g senderPk) (hsRelay h)
              return []
        _ -> return []
  | hsType h == handshakeResponse = getPeer g senderPk >>= \case
      Nothing -> return []
      Just p -> do
        now <- askTime
        modifyPeer g senderPk $ \p' -> p'
          { peerShared = Just (CombinedKey.precompute (secretKey $ peerSession p) (hsSessionPk h))
          , peerSigPk = Just (hsSigPk h)
          , peerAddr = from <|> peerAddr p'
          , peerLastDirect = (now <$ from) <|> peerLastDirect p'
          , peerRecvId = 2
          , peerHandshaked = True
          , peerPendingReply = False
          , peerLastRecv = now
          }
        mapM_ (learnRelay g senderPk) (hsRelay h)
        sendLossless g senderPk gpHsResponseAck BS.empty
        if hsRequestType h == requestPeerInfoExchange
          then sendPeerInfo g senderPk >> sendLossless g senderPk gpPeerInfoRequest BS.empty
          else sendInviteRequest g senderPk
        return []
  | otherwise = return []

handleLossless :: GroupMonad m
               => GroupNumber -> PublicKey -> Word8 -> Word64 -> ByteString -> m [GroupEvent]
handleLossless g pk ty msgId body = getPeer g pk >>= \case
  Nothing -> return []
  Just p
    -- Until the handshake is done, only its ack counts. An invite request that
    -- crosses ours still uses up its number.
    | not (peerHandshaked p) && ty /= gpHsResponseAck && ty /= gpInviteRequest -> return []
    | not (peerHandshaked p) && ty == gpInviteRequest -> do
        when (msgId == peerRecvId p + 1) $ modifyPeer g pk $ \p' -> p' { peerRecvId = msgId }
        return []
    | msgId <= peerRecvId p -> [] <$ sendAck g pk ackRecv msgId
    | msgId > peerRecvId p + fromIntegral bufferSize -> return []
    | ty == gpFragment -> handleFragment g pk msgId body
    | msgId > peerRecvId p + 1 -> do
        modifyPeer g pk $ \p' -> p' { peerRecvArray = Map.insert msgId (ty, body) (peerRecvArray p') }
        requestMissing g pk
        return []
    | otherwise -> do
        modifyPeer g pk $ \p' -> p' { peerRecvId = msgId }
        events <- dispatchLossless g pk ty body
        sendAck g pk ackRecv msgId
        (events ++) <$> drainReceived g pk

requestMissing :: GroupMonad m => GroupNumber -> PublicKey -> m ()
requestMissing g pk = getPeer g pk >>= mapM_ (\p -> do
  now <- askTime
  when (Time.due now ackRequestInterval (peerLastAckReq p)) $ do
    modifyPeer g pk $ \p' -> p' { peerLastAckReq = Just now }
    sendAck g pk ackReq (peerRecvId p + 1))

drainReceived :: GroupMonad m => GroupNumber -> PublicKey -> m [GroupEvent]
drainReceived g pk = getPeer g pk >>= \case
  Just p | isNothing (peerFragments p), Just (ty, body) <- Map.lookup (peerRecvId p + 1) (peerRecvArray p) -> do
    let msgId = peerRecvId p + 1
    modifyPeer g pk $ \p' -> p' { peerRecvId = msgId, peerRecvArray = Map.delete msgId (peerRecvArray p') }
    events <- dispatchLossless g pk ty body
    sendAck g pk ackRecv msgId
    (events ++) <$> drainReceived g pk
  _ -> return []

handleFragment :: GroupMonad m => GroupNumber -> PublicKey -> Word64 -> ByteString -> m [GroupEvent]
handleFragment g pk msgId body = getPeer g pk >>= \case
  Nothing -> return []
  -- Each piece counts as received (as in toxcore), so what we ask for and
  -- ack next follow the pieces.
  Just p | msgId == peerRecvId p + 1 -> chunk (fromMaybe [] (peerFragments p))
         | otherwise                 -> [] <$ requestMissing g pk
  where
    chunk chunks
      | sum (map BS.length chunks) + BS.length body > maxReassembledSize = do
          modifyPeer g pk $ \p' -> p' { peerFragments = Nothing, peerRecvId = msgId }
          [] <$ sendAck g pk ackRecv msgId
      | not (BS.null body) = do
          modifyPeer g pk $ \p' -> p' { peerFragments = Just (body : chunks), peerRecvId = msgId }
          [] <$ sendAck g pk ackRecv msgId
      | otherwise = do
          modifyPeer g pk $ \p' -> p' { peerFragments = Nothing, peerRecvId = msgId }
          sendAck g pk ackRecv msgId
          let whole = BS.concat (reverse chunks)
          events <- case BS.uncons whole of
            Just (ty, rest) | BS.length whole <= maxReassembledSize -> dispatchLossless g pk ty rest
            _ -> return []
          (events ++) <$> drainReceived g pk

handleLossy :: GroupMonad m => GroupNumber -> PublicKey -> Word8 -> ByteString -> m [GroupEvent]
handleLossy g pk ty body = getPeer g pk >>= \case
  Just p | peerHandshaked p ->
    if | ty == gpMessageAck, Just ((ackType, msgId), rest) <- runGetRest ((,) <$> getWord8 <*> getWord64be) body
       , BS.null rest -> [] <$
           if ackType == ackRecv
             then modifyPeer g pk $ \p' -> p' { peerSendArray = Map.delete msgId (peerSendArray p') }
             else getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup msgId (peerSendArray p)) $ \s ->
                    transmit gr p True (sentType s) (Just msgId) (sentPayload s))
       | ty == gpPing, peerConfirmed p, Just info <- unpackPing body -> [] <$ handlePing g pk info
       | ty == gpInviteResponseReject, Just reason <- fst <$> BS.uncons body -> getGroup g >>= \case
           Just gr | grState gr /= Connected && selfRole gr /= Founder -> do
             modifyGroup g $ \gr' -> gr' { grState = Disconnected }
             return [GroupJoinFail g (toEnum . min (fromEnum (maxBound :: JoinFail)) $ fromIntegral reason)]
           _ -> return []
       | ty == gpCustomPacket || ty == gpCustomPrivatePacket -> return $ customPacket g p ty body
       | otherwise -> return []
  _ -> return []

-- | A ping tells us what the peer has that we don't.
handlePing :: GroupMonad m => GroupNumber -> PublicKey -> PingInfo -> m ()
handlePing g pk info = getGroup g >>= mapM_ (\gr -> forM_ (Map.lookup pk (grPeers gr)) $ \p -> do
  let ours = pingInfo gr
      topicLocked = maybe True ((== 0) . ssTopicLock . fst) (grSharedState gr)
      -- Only the answer to a peer list request makes us connected.
      wantPeers = grState gr == Connecting
        || piPeersChecksum info /= piPeersChecksum ours && piConfirmed info >= piConfirmed ours
      -- Only sync once per roles checksum (it covers the sender's peers too,
      -- and a sync can't change those).
      rolesDiffer = piCredsVersion info == piCredsVersion ours && piRolesChecksum info /= piRolesChecksum ours
        && peerRolesSynced p /= Just (piRolesChecksum info)
      wantState = piStateVersion info > 0
        && (piStateVersion info > piStateVersion ours || piCredsVersion info > piCredsVersion ours || rolesDiffer)
      wantTopic = if topicLocked
        then piTopicVersion info > piTopicVersion ours
          || (piTopicVersion info == piTopicVersion ours && piTopicChecksum info > piTopicChecksum ours)
        else piTopicChecksum info > piTopicChecksum ours
      flags = sum [ flag | (True, flag) <- [(wantPeers, syncPeers), (wantState, syncState), (wantTopic, syncTopic)] ]
  when (flags /= 0) $ do
    sent <- sendSyncRequest g pk flags
    when (sent && wantState) $ modifyPeer g pk $ \p' -> p' { peerRolesAsked = Just (piRolesChecksum info) })

pingInfo :: Group -> PingInfo
pingInfo gr = PingInfo
  { piPeersChecksum = fromIntegral $ sum (map (jenkinsHash . keyBytes) keys)
  , piConfirmed     = fromIntegral (length keys)
  , piStateVersion  = stateVersion gr
  , piCredsVersion  = maybe 0 crVersion (snd $ grSanctions gr)
  , piRolesChecksum = maybe 0 crChecksum (snd $ grSanctions gr)
      + sum (roleChecksum (fromIntegral . fromEnum $ selfRole gr) (selfEncPk gr)
             : [ roleChecksum (fromIntegral . fromEnum $ peerRole gr p) (peerEncPk p) | p <- confirmedPeers gr ])
  , piTopicVersion  = maybe 0 (tiVersion . fst) (grTopic gr)
  , piTopicChecksum = maybe 0 (dataChecksum . tiTopic . fst) (grTopic gr)
  }
  where
    keys = selfEncPk gr : map peerEncPk (confirmedPeers gr)

dispatchLossless :: GroupMonad m
                 => GroupNumber -> PublicKey -> Word8 -> ByteString -> m [GroupEvent]
dispatchLossless g pk ty body = getGroup g >>= \case
  Nothing -> return []
  Just gr -> if
    | ty == gpHsResponseAck -> do
        modifyPeer g pk $ \p -> p { peerHandshaked = True, peerPendingReply = False }
        [] <$ sendInviteRequest g pk
    | ty == gpInviteRequest -> do
        when (isSynced gr) $ getPeer g pk >>= mapM_ (\p -> do
          let pw = passwordOf gr
              reject reason = do
                sendLossy g pk gpInviteResponseReject (BS.singleton reason)
                void (deletePeer g pk ExitDisconnected "")
          if | isFull gr p -> reject 0
             | not (BS.null pw) && (fst <$> takePassword True body) /= Just (Just pw) -> reject 1
             | otherwise -> sendLossless g pk gpInviteResponse BS.empty)
        return []
    | ty == gpInviteResponse -> [] <$ sendSyncRequest g pk (syncPeers + syncTopic + syncState)
    | ty == gpSyncRequest -> do
        p <- getPeer g pk
        now <- askTime
        let recent = not (Time.due now peerSyncLimit (p >>= peerLastSyncReply))
            flags = fromMaybe 0 (runGetStrict getWord16be body)
            pw = passwordOf gr
            pwOk = BS.null pw || (fst <$> takePassword True (BS.drop 2 body)) == Just (Just pw)
        when (isSynced gr && not recent && pwOk) $ sendSync g pk flags
        return []
    | ty == gpSyncResponse -> handleSyncResponse g pk body
    | ty == gpTcpRelays ->
        [] <$ mapM_ (learnRelay g pk) (take maxSharedRelays . fromMaybe [] $ runGetStrict NodeInfo.getNodes body)
    | ty == gpPeerInfoRequest -> [] <$ sendPeerInfo g pk
    | ty == gpPeerInfoResponse -> handlePeerInfo g pk body
    | ty == gpSharedState -> handleSharedState g body
    | ty == gpModList -> do
        when (isSynced gr && selfRole gr /= Founder) $ forM_ (unpackModList body) $ \mods ->
          when (maybe False ((== modListHash mods) . ssModListHash . fst) (grSharedState gr)) $
            modifyGroup g $ \gr' -> gr' { grModList = mods }
        return []
    | ty == gpSanctionsList -> do
        let allowed = sanctionSetters gr
        forM_ (openSanctionsList allowed body) $ \(sanctions, creds) -> do
          let ours = snd (grSanctions gr)
          when (newerCreds creds ours) $
            modifyGroup g $ \gr' -> gr' { grSanctions = (sanctions, Just creds) }
          -- Last part of the state the peer sends.
          modifyPeer g pk $ \p ->
            p { peerRolesSynced = peerRolesAsked p <|> peerRolesSynced p, peerRolesAsked = Nothing }
        return []
    | ty == gpTopic -> handleTopic g pk body
    | ty == gpBroadcast -> handleBroadcast g pk body
    | ty == gpKeyRotation -> [] <$ handleKeyRotation g pk body
    | ty == gpCustomPacket || ty == gpCustomPrivatePacket -> maybe [] (\p -> customPacket g p ty body) <$> getPeer g pk
    | otherwise -> return []

customPacket :: GroupNumber -> Peer -> Word8 -> ByteString -> [GroupEvent]
customPacket g p ty body =
  [ (if ty == gpCustomPacket then GroupCustomPacket else GroupCustomPrivatePacket) g (peerId p) body
  | not (BS.null body), BS.length body <= maxCustomPacketSize ]

handleSyncResponse :: GroupMonad m => GroupNumber -> PublicKey -> ByteString -> m [GroupEvent]
handleSyncResponse g pk body = (,) <$> getGroup g <*> getPeer g pk >>= \case
  -- One for each of its peers, so a peer can't send more than the limit for
  -- one request. Otherwise it could make us add any number of peers.
  (Just gr, Just p) | Just n <- peerSyncResponses p, n < peerLimit gr -> do
    modifyPeer g pk $ \p' -> p' { peerSyncResponses = Just (n + 1) }
    forM_ (if BS.null body then Nothing else unpackAnnounce body) $ \a ->
      when (anPk a /= selfEncPk gr) $ do
        known <- isJust <$> getPeer g (anPk a)
        unless known $ do
          meetAnnounced g a
          modifyPeer g (anPk a) $ \q -> q { peerPendingType = requestPeerInfoExchange }
    now <- askTime
    modifyGroup g $ \gr' -> gr' { grState = Connected }
    -- In a full group, only peers already in it sync with us.
    full <- maybe True (isFull gr) <$> getPeer g pk
    if full then return [] else do
      modifyGroup g $ \gr' -> gr' { grConnectedAt = Just (fromMaybe now $ grConnectedAt gr') }
      sendPeerInfo g pk
      sendLossless g pk gpPeerInfoRequest BS.empty
      return [ GroupSelfJoin g | isNothing (grConnectedAt gr) ]
  _ -> return []

handlePeerInfo :: GroupMonad m => GroupNumber -> PublicKey -> ByteString -> m [GroupEvent]
handlePeerInfo g pk body = getGroup g >>= \case
  Nothing -> return []
  Just gr -> case takePassword (not . BS.null $ passwordOf gr) body >>= \(pw, rest) -> (,) pw <$> unpackPeerInfo rest of
    Just (pw, (nick, status)) | BS.null (passwordOf gr) || pw == Just (passwordOf gr) -> getPeer g pk >>= \case
      Just p | not (isFull gr p) -> do
        modifyPeer g pk $ \p' ->
          p' { peerConfirmed = True, peerJoinReported = True, peerNick = nick, peerStatus = status }
        return [ GroupPeerJoin g (peerId p) pk | not (peerJoinReported p) ]
      _ -> return []
    _ -> return []

handleSharedState :: GroupMonad m => GroupNumber -> ByteString -> m [GroupEvent]
handleSharedState g body = getGroup g >>= \case
  Just gr | Just (s, signed) <- openSharedState (grChatId gr) body
          , ssVersion s > 0 && ssVersion s >= stateVersion gr -> do
    modifyGroup g $ \gr' ->
      gr' { grSharedState = Just (s, signed), grJoinType = if ssPrivacy s == 1 then joinPrivate else joinPublic }
    logDebug $ "Group shared state version " <> pack (show $ ssVersion s)
    case fst <$> grSharedState gr of
      Just old | grState gr == Connected -> stateChanged g old s
      _                                  -> return []
  _ -> return []

stateChanged :: GroupMonad m => GroupNumber -> SharedState -> SharedState -> m [GroupEvent]
stateChanged g old new = do
  when (ssPrivacy old /= ssPrivacy new) $ getGroup g >>= mapM_ (\gr -> if ssPrivacy new == 1
    then do
      mapM_ Onion.removeGroupSearch (grSearchKey gr)
      modifyGroup g $ \gr' -> gr' { grSearchKey = Nothing, grAnnounced = Nothing }
    else when (isNothing $ grSearchKey gr) $ startSearch g (grChatId gr))
  return $ concat
    [ [ GroupPrivacy g (ssPrivacy new == 1) | ssPrivacy old /= ssPrivacy new ]
    , [ GroupPeerLimit g (ssMaxPeers new) | ssMaxPeers old /= ssMaxPeers new ]
    , [ GroupPassword g (ssPassword new) | ssPassword old /= ssPassword new ]
    , [ GroupTopicLock g (ssTopicLock new == 0) | (ssTopicLock old == 0) /= (ssTopicLock new == 0) ]
    , [ GroupVoiceState g v | ssVoice old /= ssVoice new, Just v <- [voiceOf (ssVoice new)] ]
    ]

voiceOf :: Word8 -> Maybe Voice
voiceOf v = if v <= fromIntegral (fromEnum (maxBound :: Voice)) then Just (toEnum $ fromIntegral v) else Nothing

handleTopic :: GroupMonad m => GroupNumber -> PublicKey -> ByteString -> m [GroupEvent]
handleTopic g pk body = getGroup g >>= \case
  Just gr | Just (info, _, signed) <- openTopic body, Just (s, _) <- grSharedState gr -> do
    now <- askTime
    let ourVersion = maybe 0 (tiVersion . fst) (grTopic gr)
        bySig = find ((== Just (tiSetter info)) . peerSigPk) (Map.elems $ grPeers gr)
        setterObserver
          | tiSetter info == extSigPk (grSelf gr) = selfRole gr == Observer
          | otherwise = maybe False ((== Observer) . peerRole gr) bySig
        senderFounder = maybe False ((== Founder) . peerRole gr) (Map.lookup pk $ grPeers gr)
        checksum = dataChecksum (tiTopic info)
        -- If the topic we just replaced comes back, a sync went wrong.
        reverted = maybe False (\(prev, t) -> prev == checksum && now < Time.addTime t confirmedTimeout) (grTopicSet gr)
        -- Only once we're in, so nobody can pin a topic version while we join.
        recentlyJoined = maybe False (\t -> now < Time.addTime t pingInterval) (grConnectedAt gr)
        ok = if ssTopicLock s == 0
          then (tiSetter info == ssFounderSig s || tiSetter info `elem` grModList gr) && tiVersion info >= ourVersion
          else not setterObserver && if tiVersion info == ssTopicLock s || recentlyJoined
            then not reverted
            else senderFounder && tiVersion info == ssTopicLock s + 1
        changed = maybe True ((/= tiTopic info) . tiTopic . fst) (grTopic gr)
    if not ok then return [] else do
      let prev = maybe 0 (dataChecksum . tiTopic . fst) (grTopic gr)
      modifyGroup g $ \gr' -> gr' { grTopic = Just (info, signed), grTopicSet = Just (prev, now) }
      when (changed && grState gr == Connected && selfRole gr == Founder) . void $ sendToConfirmed g gpTopic signed
      return [ GroupTopic g (peerId <$> bySig) (tiTopic info) | changed, grState gr == Connected ]
  _ -> return []

handleBroadcast :: GroupMonad m => GroupNumber -> PublicKey -> ByteString -> m [GroupEvent]
handleBroadcast g pk body = getGroup g >>= \case
  Just gr | Just p <- Map.lookup pk (grPeers gr), peerConfirmed p, Just (bc, rest) <- BS.uncons body -> if
    | bc == bcStatus, [status] <- BS.unpack rest, status <= maxPeerStatus -> do
        modifyPeer g pk $ \p' -> p' { peerStatus = status }
        return [GroupPeerStatus g (peerId p) status]
    | bc == bcNick, not (BS.null rest), BS.length rest <= maxNickSize -> do
        modifyPeer g pk $ \p' -> p' { peerNick = rest }
        return [GroupPeerName g (peerId p) rest]
    | bc == bcPlainMessage || bc == bcActionMessage, Just (msgId, msg) <- runGetRest getWord32be rest
    , not (BS.null msg), BS.length msg <= maxMessageSize ->
        let ty = if bc == bcPlainMessage then Messenger.MessageNormal else Messenger.MessageAction
        in return [GroupMessage g (peerId p) ty msg msgId | canSpeak gr p]
    -- As in toxcore, the type and ID count towards the length limit.
    | bc == bcPrivateMessage, Just ((kind, msgId), msg) <- runGetRest ((,) <$> getWord8 <*> getWord32be) rest
    , kind <= 1, not (BS.null msg), BS.length rest <= maxMessageSize, peerRole gr p /= Observer ->
        let ty = if kind == 0 then Messenger.MessageNormal else Messenger.MessageAction
        in return [ GroupPrivateMessage g (peerId p) ty msg msgId ]
    | bc == bcPeerExit -> deletePeer g pk ExitQuit (BS.take maxPartSize rest)
    | bc == bcKickPeer, Just target <- keyAt 0 rest -> handleKick g gr p target
    | bc == bcSetMod, Just (add, sigPk) <- BS.uncons rest, BS.length sigPk >= Sign.signPublicKeyLength ->
        handleSetMod g gr p (add /= 0) (BS.take Sign.signPublicKeyLength sigPk)
    | bc == bcSetObserver, Just (add, change) <- BS.uncons rest
    , BS.length change >= keyLength + Sign.signPublicKeyLength ->
        handleSetObserver g gr p (add /= 0) change
    | otherwise -> return []
  _ -> return []

handleKick :: GroupMonad m => GroupNumber -> Group -> Peer -> PublicKey -> m [GroupEvent]
handleKick g gr setter target
  | peerRole gr setter > Moderator = return []
  | target == selfEncPk gr = if selfRole gr /= User then return [] else do
      exits <- concat <$> mapM (\q -> deletePeer g (peerEncPk q) ExitSelfDisconnected "") (Map.elems $ grPeers gr)
      modifyGroup g $ \gr' -> gr' { grState = Disconnected }
      return $ GroupModeration g (Just $ peerId setter) Nothing ModKick : exits
  | Just t <- Map.lookup target (grPeers gr), peerRole gr t == User =
      (GroupModeration g (Just $ peerId setter) (Just $ peerId t) ModKick :) <$> deletePeer g target ExitKicked ""
  | otherwise = return []

-- | The shared state with the new mod list hash comes first.
handleSetMod :: GroupMonad m => GroupNumber -> Group -> Peer -> Bool -> ByteString -> m [GroupEvent]
handleSetMod g gr setter add sigPk
  | peerRole gr setter /= Founder = return []
  | otherwise = case targetBySigPk gr sigPk of
      Just (target, role) | role == (if add then User else Moderator) -> do
        modifyGroup g $ \gr' -> gr' { grModList = (if add then (sigPk :) else id) (filter (/= sigPk) (grModList gr')) }
        return [GroupModeration g (Just $ peerId setter) target (if add then ModModerator else ModUser)]
      _ -> return []

-- | 'Nothing' for us.
targetBySigPk :: Group -> ByteString -> Maybe (Maybe PeerId, Role)
targetBySigPk gr sigPk
  | sigPk == extSigPk (grSelf gr) = Just (Nothing, selfRole gr)
  | otherwise = (\p -> (Just $ peerId p, peerRole gr p)) <$> find ((== Just sigPk) . peerSigPk) (Map.elems $ grPeers gr)

handleSetObserver :: GroupMonad m
                  => GroupNumber -> Group -> Peer -> Bool -> ByteString -> m [GroupEvent]
handleSetObserver g gr setter add change = case keyAt 0 change of
  Just target | peerRole gr setter <= Moderator, target /= peerEncPk setter -> do
    let known
          | target == selfEncPk gr = Just (Nothing, selfRole gr)
          | otherwise = (\p -> (Just $ peerId p, peerRole gr p)) <$> Map.lookup target (grPeers gr)
        (sanctions, ours) = grSanctions gr
        allowed = sanctionSetters gr
        observed = any ((== target) . snTarget) sanctions
        rest = BS.drop (keyLength + Sign.signPublicKeyLength) change
        updated
          | add = do
              (sn, creds) <- runGetStrict ((,) <$> getSanction <*> getCreds) rest
              guard $ snTarget sn == target && not observed && length sanctions < fromIntegral maxSanctions
              return (sanctions ++ [sn], creds)
          | otherwise = do
              creds <- runGetStrict getCreds rest
              guard observed
              return (filter ((/= target) . snTarget) sanctions, creds)
    case updated of
      Just (sanctions', creds)
        | maybe True ((== (if add then User else Observer)) . snd) known
        , newerCreds creds ours, validCreds allowed sanctions' creds -> do
            modifyGroup g $ \gr' -> gr' { grSanctions = (sanctions', Just creds) }
            return [ GroupModeration g (Just $ peerId setter) t (if add then ModObserver else ModUser)
                   | Just (t, _) <- [known] ]
      _ -> return []
  _ -> return []

handleKeyRotation :: GroupMonad m => GroupNumber -> PublicKey -> ByteString -> m ()
handleKeyRotation g pk body = getPeer g pk >>= mapM_ (\p -> case (BS.unpack (BS.take 1 body), keyAt 1 body) of
  ([0], Just theirs) -> do
    now <- askTime
    unless (now < Time.addTime (peerLastRotation p) keyRotationMinGap) $ do
      keys <- newKeyPair
      -- Answer before switching, so it goes out under the old session key.
      sendLossless g pk gpKeyRotation (BS.singleton 1 <> keyBytes (publicKey keys))
      modifyPeer g pk $ \p' -> p'
        { peerSession = keys
        , peerShared = Just (CombinedKey.precompute (secretKey keys) theirs)
        , peerLastRotation = now
        }
  ([1], Just theirs) | Just keys <- peerRotating p -> do
    now <- askTime
    modifyPeer g pk $ \p' -> p' { peerSession = keys, peerShared = Just (CombinedKey.precompute (secretKey keys) theirs)
                                , peerRotating = Nothing, peerLastRotation = now }
  _ -> return ())


{-------------------------------------------------------------------------------
 -
 - :: Periodic work.
 -
 ------------------------------------------------------------------------------}

nextDue :: Groups -> Maybe Timestamp
nextDue = Schedule.next . groupJobs

-- | The groups and peers that are due, then announcing whatever our address
-- or relays changed.
runDue :: GroupMonad m => m [GroupEvent]
runDue = do
  now <- askTime
  Groups gs jobs <- getGroups
  let (due, waiting) = Schedule.takeDue now jobs
  putGroups (Groups gs waiting)
  events <- concat <$> forM due (\case
    GroupWork g -> [] <$ (groupWork g now >> getGroup g >>= mapM_ (setGroup g . Just))
    PeerWork g pk -> peerWork g pk now <* reschedulePeer g pk)
  mapM_ (`announceSelf` now) (Map.keys gs)
  return events

groupDue :: Timestamp -> Group -> Timestamp
groupDue now gr = minimum $ maybe now (`Time.addTime` relayCheckInterval) (grRelaysChecked gr) : catMaybes
  [ case grHandshakes gr of
      (n, t) | n > 0 -> Just $ maybe now (`Time.addTime` handshakeDecay) t
      _              -> Nothing
  , guard (searchable gr) >> (`Time.addTime` announceInterval) . snd <$> grAnnounced gr
  , guard (Map.null (grPeers gr) && grState gr /= Disconnected && not (null (grSavedPeers gr)))
      >> Just (maybe now (`Time.addTime` loadPeersInterval) (grPeersLoaded gr))
  ]

groupWork :: GroupMonad m => GroupNumber -> Timestamp -> m ()
groupWork g now = do
  modifyGroup g $ \gr -> case grHandshakes gr of
    (n, t) | n > 0, Time.due now handshakeDecay t -> gr { grHandshakes = (n - 1, Just now) }
    _ -> gr
  announceSelf g now
  loadSavedPeers g now
  checkRelays g now

-- | When the peer next needs us, and how much sooner it may. Pings may come a
-- ping check early, so that they share wake-ups.
peerDue :: Timestamp -> Group -> Peer -> (Timestamp, Timestamp)
peerDue now gr p = (minimum (map (`Time.addTime` negate pingCheckInterval) pings ++ deadlines), minimum (pings ++ deadlines))
  where
    deadlines = Time.addTime (peerLastRecv p) (if peerConfirmed p then confirmedTimeout else unconfirmedTimeout)
      : if peerHandshaked p then resends ++ shares ++ rotation else [maybe now (`Time.addTime` handshakeInterval) (peerLastHandshake p)]
    pings = [ Time.addTime (peerLastPing p) pingInterval | grState gr == Connected, peerConfirmed p ]
    resends = map resendDue (Map.elems (peerSendArray p))
    shares = [ maybe now (`Time.addTime` relayShareInterval) (peerRelaysShared p) | peerConfirmed p, not (null (peerRelays p)) ]
    rotation = [ Time.addTime (peerLastRotation p) keyRotationInterval | peerSelfIsCloser p ]

peerWork :: GroupMonad m => GroupNumber -> PublicKey -> Timestamp -> m [GroupEvent]
peerWork g pk now = getGroup g >>= \case
  Just gr | Just p <- Map.lookup pk (grPeers gr) ->
    let timeout = if peerConfirmed p then confirmedTimeout else unconfirmedTimeout
    in if Time.addTime (peerLastRecv p) timeout <= now
      then deletePeer g pk ExitTimeout ""
      else [] <$ (doPeer g p now >> ping g gr p now)
  _ -> return []

checkRelays :: GroupMonad m => GroupNumber -> Timestamp -> m ()
checkRelays g now = getGroup g >>= mapM_ (\gr ->
  when (Time.due now relayCheckInterval (grRelaysChecked gr)) $ do
    ours <- Tcp.connectedRelays
    groupTcp gr $ mapM_ Tcp.addRelay ours
    modifyGroup g $ \gr' -> gr' { grRelaysChecked = Just now })

shareRelays :: GroupMonad m => GroupNumber -> Peer -> Timestamp -> m ()
shareRelays g p now = getGroup g >>= mapM_ (\gr ->
  when (peerConfirmed p && not (null $ peerRelays p)
        && Time.due now relayShareInterval (peerRelaysShared p)) $ do
    ours <- take maxSharedRelays <$> groupTcp gr Tcp.connectedRelays
    mapM_ (learnRelay g (peerEncPk p)) ours
    unless (null ours) $ sendLossless g (peerEncPk p) gpTcpRelays (packRelays ours)
    modifyPeer g (peerEncPk p) $ \p' -> p' { peerRelaysShared = Just now })

doPeer :: GroupMonad m => GroupNumber -> Peer -> Timestamp -> m ()
doPeer g p now
  | not (peerHandshaked p) = do
      addr <- case (peerAddr p, peerFriend p) of
        (Nothing, Just friend) -> friendAddress friend
        (a, _)                 -> return a
      modifyPeer g (peerEncPk p) $ \p' -> p' { peerAddr = addr }
      when (Time.due now handshakeInterval (peerLastHandshake p)) $
        let ty = if peerPendingReply p then handshakeResponse else handshakeRequest
        in sendHandshake g (peerEncPk p) ty (peerPendingType p)
  | otherwise = do
      resend g p now
      shareRelays g p now
      -- Replaces an unanswered request.
      when (peerSelfIsCloser p && Time.addTime (peerLastRotation p) keyRotationInterval <= now) $ do
        keys <- newKeyPair
        modifyPeer g (peerEncPk p) $ \p' -> p' { peerRotating = Just keys, peerLastRotation = now }
        sendLossless g (peerEncPk p) gpKeyRotation (BS.singleton 0 <> keyBytes (publicKey keys))

-- | Resend what the peer hasn't acked, after 3, 5, 9, 17... seconds.
resend :: GroupMonad m => GroupNumber -> Peer -> Timestamp -> m ()
resend g p now = getGroup g >>= mapM_ (\gr -> forM_ (Map.toList $ peerSendArray p) $ \(msgId, s) ->
  when (resendDue s <= now) $ do
    transmit gr p True (sentType s) (Just msgId) (sentPayload s)
    modifyPeer g (peerEncPk p) $ \p' ->
      p' { peerSendArray = Map.adjust (\s' -> s' { sentLastTry = now }) msgId (peerSendArray p') })

-- | The first of 3, 5, 9, 17... seconds after it was added that's after we
-- last sent it.
resendDue :: Sent -> Timestamp
resendDue s = after (until ((> sentLastTry s) . after) (* 2) 2)
  where after n = Time.addTime (sentAdded s) (Time.seconds (n + 1))

-- | Up to a ping check before it's due, so that pings share wake-ups.
ping :: GroupMonad m => GroupNumber -> Group -> Peer -> Timestamp -> m ()
ping g gr p now = when (grState gr == Connected && peerConfirmed p
    && Time.addTime (peerLastPing p) pingInterval <= Time.addTime now pingCheckInterval) $ do
  sendLossy g (peerEncPk p) gpPing (packPing (pingInfo gr))
  modifyPeer g (peerEncPk p) $ \p' -> p' { peerLastPing = now }

-- | In toxcore's save format, once we have the shared state.
saveGroup :: Group -> Maybe PG.Group
saveGroup gr = do
  (s, signed) <- grSharedState gr
  chatEnc <- chatEncPk (grChatId gr)
  let self = grSelf gr
      noTopic = (TopicInfo 0 BS.empty (BS.replicate Sign.signPublicKeyLength 0), BS.replicate Sign.signatureLength 0)
      (topic, topicSigned) = fromMaybe noTopic (grTopic gr)
  sig <- Sodium.decode (BS.take Sign.signatureLength signed)
  founder <- Sodium.decode (keyBytes (ssFounderEnc s) <> ssFounderSig s)
  hash <- Sodium.decode (ssModListHash s)
  setter <- Sodium.decode (tiSetter topic)
  topicSig <- Sodium.decode (BS.take Sign.signatureLength topicSigned)
  mods <- mapM Sodium.decode (grModList gr)
  chatPk <- Sodium.decode (keyBytes chatEnc <> grChatId gr)
  selfPk <- Sodium.decode (keyBytes (extEncPk self) <> extSigPk self)
  chatSk <- maybe (Just $ BS.replicate (keyLength + Sign.secretKeyLength) 0) (fmap extSecretKey . extKeysFromSign)
    (grChatKeys gr)
  return PG.Group
    { PG.groupStateValues = PG.StateValues
        { PG.manuallyDisconnected = grState gr == Disconnected
        , PG.groupNameLen         = len (ssGroupName s)
        , PG.privacyState         = ssPrivacy s
        , PG.maxPeers             = ssMaxPeers s
        , PG.passwordLength       = len (ssPassword s)
        , PG.version              = ssVersion s
        , PG.topicLock            = ssTopicLock s
        , PG.voiceState           = ssVoice s
        }
    , PG.groupStateBin   = PG.StateBin sig founder (ssGroupName s) (ssPassword s) hash
    , PG.groupTopicInfo  = PG.TopicInfo (tiVersion topic) (len $ tiTopic topic) (dataChecksum $ tiTopic topic)
                             (tiTopic topic) setter topicSig
    , PG.groupModList    = PG.ModList mods
    , PG.groupKeys       = PG.Keys chatPk chatSk selfPk (extSecretKey self)
    , PG.groupSelfInfo   =
        PG.SelfInfo (len $ grNick gr) (fromIntegral . fromEnum $ selfRole gr) (grStatus gr) (grNick gr)
    , PG.groupSavedPeers = PG.SavedPeers (savedPeersOf gr)
    }
  where
    len = fromIntegral . BS.length
    extSecretKey keys = keyBytes (extEncSk keys) <> Sign.signSecretKey (extSign keys)

-- | If its keys are OK. It joins as private, which suits public groups too,
-- and finds its peers among the saved ones, or through the onion when it's
-- public.
loadGroup :: PG.Group -> Maybe Group
loadGroup sg = do
  let keys = PG.groupKeys sg
      values = PG.groupStateValues sg
      bin = PG.groupStateBin sg
      saved = PG.groupTopicInfo sg
      chatId = BS.drop keyLength . Sodium.encode $ PG.chatPublicKey keys
      founder = Sodium.encode $ PG.founderPublicKey bin
  self <- signKeys (PG.selfSecretKey keys) >>= extKeysFromSign
  guard $ keyBytes (extEncPk self) <> extSigPk self == Sodium.encode (PG.selfPublicKey keys)
  founderEnc <- Sodium.decode (BS.take keyLength founder)
  let state = SharedState
        { ssVersion     = PG.version values
        , ssFounderEnc  = founderEnc
        , ssFounderSig  = BS.drop keyLength founder
        , ssMaxPeers    = PG.maxPeers values
        , ssGroupName   = PG.groupName bin
        , ssPrivacy     = PG.privacyState values
        , ssPassword    = PG.password bin
        , ssModListHash = Sodium.encode $ PG.modListHash bin
        , ssTopicLock   = PG.topicLock values
        , ssVoice       = PG.voiceState values
        }
      topic = TopicInfo (PG.topicVersion saved) (PG.topic saved) (Sodium.encode $ PG.topicPublicKey saved)
      chatSk = PG.chatSecretKey keys
      chatKeys = if BS.all (== 0) chatSk then Nothing else signKeys chatSk
      signed = Sodium.encode (PG.signature bin) <> packSharedState state
      -- Saves only keep the password's own bytes, but a founder that made it
      -- shorter signed the bytes after it too. Take such a state as it is
      -- (like toxcore), and sign it again if it's ours.
      unverified = (state, maybe signed (`signSharedState` state) chatKeys)
  let shared = fromMaybe unverified (openSharedState chatId signed)
  return (newGroup chatId self (PG.selfNick $ PG.groupSelfInfo sg) joinPrivate BS.empty)
    { grChatKeys    = chatKeys
    , grState       = if PG.manuallyDisconnected values then Disconnected else Connecting
    , grStatus      = PG.selfStatus $ PG.groupSelfInfo sg
    , grSharedState = Just shared
    , grTopic       = if tiVersion topic == 0 then Nothing
                      else Just (topic, Sodium.encode (PG.topicSignature saved) <> packTopicInfo topic)
    , grModList     = map Sodium.encode . PG.modList $ PG.groupModList sg
    , grSavedPeers  = PG.savedPeers (PG.groupSavedPeers sg)
    }
  where
    -- Extended secret key ends in the signing secret key, which ends in its public key.
    signKeys = Sign.signKeyPair . BS.drop keyLength

saveGroups :: Groups -> [PG.Group]
saveGroups = mapMaybe saveGroup . Map.elems . groups

restore :: GroupMonad m => [PG.Group] -> m ()
restore = mapM_ restoreGroup

restoreGroup :: GroupMonad m => PG.Group -> m (Maybe GroupNumber)
restoreGroup sg = case loadGroup sg of
  Nothing -> return Nothing
  Just gr -> do
    gs <- groups <$> getGroups
    if any ((== grChatId gr) . grChatId) gs then return Nothing else
      forM (freeNumber gs) $ \g -> do
        setGroup g (Just gr)
        unless (isPrivate gr || grState gr == Disconnected) $ startSearch g (grChatId gr)
        return g
\end{code}
