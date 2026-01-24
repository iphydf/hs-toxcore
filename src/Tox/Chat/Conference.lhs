\chapter{Conference}

Conferences in Tox work by temporarily adding some peers present in the
conference as temporary \texttt{friend\_connection} friends, that are
deleted when the conference is exited.

Each peer in the conference is identified by their real long term public key.
Peers also transmit their DHT public keys to each other via the conference in
order to speed up the connection by making it unnecessary for the peers to find
each other's DHT public keys with the onion, as would happen had they added each
other as normal friends.

The upside of using \texttt{friend\_connection} is that conferences do not have
to deal with things like hole punching, peers only on TCP or other low level
networking things.  The downside however is that every single peer knows each
other's real long term public key and DHT public key, meaning that these
conferences should only be used between friends.

Each peer adds a \texttt{friend\_connection} for each of up to 4 other peers in
the conference. If the conference has 5 participants or fewer, each of the
peers will therefore have each of the others added to their list of friend
connections, and a peer wishing to send a message to the conference may
communicate it directly to the other peers. When there are more than 5 peers,
messages are relayed along friend connections.

Since the maximum number of peers per conference that will be connected to with
friend connections is 4, if the peers in the conference are arranged in a circle
and each peer connects to the 2 peers that are closest to the right of them and
the 2 peers that are closest to the left of them, then the peers should form a
well-connected circle of peers.

Conferences in toxcore do this by subtracting the real long term public key of
the peer with all the others in the conference (our PK - other peer PK), using
modular arithmetic, and finding the two peers for which the result of this
operation is the smallest. The operation is then inversed (other peer PK - our
PK) and this operation is done again with all the public keys of the peers in
the conference. The 2 peers for which the result is again the smallest are
picked.

This gives 4 peers that are then added as a friend connection and associated to
the conference.  If every peer in the conference does this, they will form a
circle of perfectly connected peers.

Once the peers are connected to each other in a circle they relay each other's
messages.  Every time a peer leaves the conference or a new peer joins, each
member of the chat will recalculate the peers they should connect to.

To join a conference, a peer must first be invited to it by their friend.  To
make a conference the peer will first create a conference and then invite people
to this conference.  Once their friends are in the conference, those friends can
invite their other friends to the chat, and so on.

To create a conference, a peer generates a random 32 byte id that is used to
uniquely identify the conference.  32 bytes is enough so that when randomly
generated with a secure random number generator every conference ever created
will have a different id.  The goal of this 32 byte id is so that peers have a
way of identifying each conference, so that they can prevent themselves from
joining a conference twice for example.

The conference will also have an unsigned 1 byte type.  This type indicates what
kind of conference the conference is. The current types are:

\begin{tabular}{l|l}
  Type number       & Type \\
  \hline
  \texttt{0}        & text \\
  \texttt{1}        & audio \\
\end{tabular}

Text conferences are text only, while audio indicates that the conference
supports sending audio to it as well as text.

The conference will also be identified by a unique unsigned 2 byte integer,
which in toxcore corresponds to the index of the conference in the array it is
being stored in.  Every conference in the current instance must have a
different number.  This number is used by conference peers that are directly
connected to us to tell us which packets are for which conference.  Every
conference packet contains a 2 byte conference number.  Putting a 32 byte
conference id in each packet would increase bandwidth waste by a lot, and this
is the reason why conference numbers are used instead.

Using the conference number as the index of the array used to store the
conference instances is recommended, because this kind of access is usually
most efficient and it ensures that each conference has a unique conference
number.

When creating a new conference, the peer will add themselves as a conference
peer with a peer number of 0 and their own long term public key and DHT public
key.

Invite packets:

Invite packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x00) \\
  \texttt{2}         & \texttt{uint16\_t} conference number \\
  \texttt{33}        & Conference identifier \\
\end{tabular}

Accept Invite packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
  \texttt{2}         & \texttt{uint16\_t} conference number (local) \\
  \texttt{2}         & \texttt{uint16\_t} conference number to join \\
  \texttt{33}        & Conference identifier \\
\end{tabular}

Member Information packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x60) \\
  \texttt{1}         & \texttt{uint8\_t} (0x02) \\
  \texttt{2}         & \texttt{uint16\_t} conference number (local) \\
  \texttt{2}         & \texttt{uint16\_t} conference number to join \\
  \texttt{33}        & Conference identifier \\
  \texttt{2}         & \texttt{uint16\_t} peer number \\
\end{tabular}

A conference identifier consists of a 1-byte type and a 32-byte id concatenated:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} type \\
  \texttt{32}        & \texttt{uint8\_t} conference id \\
\end{tabular}

To invite a friend to a conference, an invite packet is sent to the friend.
These packets are sent using Messenger (if you look at the Messenger packet id
section, all the conference packet ids are in there).  Note that all numbers
here, like all numbers sent using Tox packets, are sent in big endian format.

The conference number is as explained above, the number used to uniquely
identify the conference instance from all the other conference instances the
peer has.  It is sent in the invite packet because it is needed by the friend
in order to send back conference related packets.

What follows is the 33 byte conference identifier.

To refuse the invite, the friend receiving it will simply ignore and discard
it.

To accept the invite, the friend will create their own conference instance with
the 1 byte type and 32 byte conference id sent in the request, and send an
invite accept packet back.  The friend will also add the peer who sent the
invite as a conference connection, and mark the connection as introducing the
friend.

If the friend being invited is already in the conference, they will respond
with a member information packet, add the peer who sent the invite as a
conference connection, and mark the connection as introducing both the friend
and the peer who sent the invite.

The first conference number in the invite accept packet is the conference
number of the conference the invited friend just created.  The second
conference number is the conference number that was sent in the invite request.
What follows is the 33 byte conference identifier which was sent in the invite
request. The member information packet is the same, but includes also the
current peer number of the invited friend.

When a peer receives an invite accept packet they will check if the conference
identifier sent back corresponds to the conference identifier of the conference
with the conference number also sent back.  If so, a new peer number will be
generated for the peer that sent the invite accept packet.  Then the peer with
their generated peer number, their long term public key and their DHT public
key will be added to the peer list of the conference.  A new peer message
packet will also be sent to tell everyone in the conference about the new peer.
The peer will also be added as a conference connection, and the connection will
be marked as introducing the peer.

When a peer receives a member information packet they proceed as with an
invite accept packet, but use the peer number in the packet rather than
generating a new one, and mark the new connection as also introducing the peer
receiving the member information packet.

Peer numbers are used to uniquely identify each peer in the conference.  They
are used in conference message packets so that peers receiving them can know
who or which conference peer sent them.  As conference message packets are
relayed, they must contain something that is used by others to identify the
sender. Since putting a 32 byte public key in each packet would be wasteful, a
2 byte peer number is used instead.  Each peer in the conference has a unique
peer number. Toxcore generates each peer number randomly but makes sure newly
generated peer numbers are not equal to current ones already used by other
peers in the conference. If two peers join the conference from two
different endpoints there is a small possibility that both will be given the
same peer number, but the probability of this occurring is low enough in
practice that it is not an issue.

Peer online packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x61) \\
  \texttt{2}         & \texttt{uint16\_t} conference number (local) \\
  \texttt{33}        & Conference identifier \\
\end{tabular}

Peer introduced packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} conference number (local) \\
  \texttt{1}         & \texttt{uint8\_t} (0x01) \\
\end{tabular}

\begin{code}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData        #-}
module Tox.Chat.Conference where

import           Control.Monad                    (forM, forM_, unless, void,
                                                   when)
import qualified Crypto.Saltine.Class             as Sodium
import qualified Data.Binary                      as Binary
import           Data.Binary.Get                  (Get, getWord16be,
                                                   getWord32be, getWord8,
                                                   runGet)
import           Data.Binary.Put                  (putWord16be, putWord32be,
                                                   runPut)
import           Data.Bits                        (shiftL, (.|.))
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Lazy             as LBS
import           Data.List                        (find, sortOn)
import           Data.Map                         (Map)
import qualified Data.Map                         as Map
import           Data.Maybe                       (isJust)
import           Data.Set                         (Set)
import qualified Data.Set                         as Set
import           Data.Word                        (Word16, Word32, Word64,
                                                   Word8)

import           Tox.Chat.GroupChatPackets        (runGetRest)
import qualified Tox.Core.Schedule                as Schedule
import           Tox.Core.Schedule                (Schedule)
import qualified Tox.Core.Time                    as Time
import           Tox.Core.Time                    (TimeDiff, Timestamp)
import           Tox.Core.Timed                   (Timed (..))
import           Tox.Crypto.Core.Key              (PublicKey)
import qualified Tox.Crypto.Core.KeyPair          as KeyPair
import           Tox.Crypto.Core.MonadRandomBytes (randomBytes, randomWord16)
import qualified Tox.DHT.Operation                as DHT
import qualified Tox.Onion.Operation              as Onion
import qualified Tox.Persistence.Conferences      as PC
import qualified Tox.Session.Connection           as Connection
import           Tox.Session.Connection           (ConnectionEvent (..))
import qualified Tox.Session.Friend               as Messenger
import qualified Tox.Transport.Reliability        as Reliability


{-------------------------------------------------------------------------------
 -
 - :: Packets.
 -
 ------------------------------------------------------------------------------}

packetIdInvite, packetIdOnline, packetIdDirect, packetIdMessage, packetIdRejoin :: Word8
packetIdInvite  = 0x60
packetIdOnline  = 0x61
packetIdDirect  = 0x62
packetIdMessage = 0x63
packetIdRejoin  = 0x64

packetIds :: [Word8]
packetIds = [packetIdInvite, packetIdOnline, packetIdDirect, packetIdMessage, packetIdRejoin]

inviteId, inviteAcceptId, inviteMemberId :: Word8
inviteId       = 0
inviteAcceptId = 1
inviteMemberId = 2

peerIntroducedId, peerQueryId, peerResponseId, peerTitleId :: Word8
peerIntroducedId = 1
peerQueryId      = 8
peerResponseId   = 9
peerTitleId      = 10

messagePing, messageNewPeer, messageKillPeer, messageFreezePeer, messageName,
  messageTitle, messageChat, messageAction :: Word8
messagePing       = 0
messageNewPeer    = 16
messageKillPeer   = 17
messageFreezePeer = 18
messageName       = 48
messageTitle      = 49
messageChat       = 64
messageAction     = 65

typeText, typeAv :: Word8
typeText = 0
typeAv   = 1

conferenceIdLength, desiredClosest, maxConnections, maxMessageInfos, maxFrozen, maxNameLength :: Int
conferenceIdLength   = 32
desiredClosest  = 4
maxConnections  = 16
maxMessageInfos = 8
maxFrozen       = 128
maxNameLength   = 128

-- | Friend connection packet minus our headers.
maxMessageData :: Int
maxMessageData = Reliability.maxCryptoDataSize - (1 + 2 + 2 + 4 + 1)

pingInterval, freezeTimeout :: TimeDiff
pingInterval  = Time.seconds 20
freezeTimeout = Time.seconds 60

word16 :: Word16 -> ByteString
word16 = LBS.toStrict . runPut . putWord16be

word32 :: Word32 -> ByteString
word32 = LBS.toStrict . runPut . putWord32be

getW16 :: ByteString -> Word16
getW16 = runGet getWord16be . LBS.fromStrict . BS.take 2

getW32 :: ByteString -> Word32
getW32 = runGet getWord32be . LBS.fromStrict . BS.take 4

keyBytes :: PublicKey -> ByteString
keyBytes = Sodium.encode

decodeKey :: ByteString -> Maybe PublicKey
decodeKey = Sodium.decode

-- | Peer number, real key and DHT key, as in peer lists and new peer
-- messages.
getPeerKeys :: Get (Word16, PublicKey, PublicKey)
getPeerKeys = (,,) <$> getWord16be <*> Binary.get <*> Binary.get


{-------------------------------------------------------------------------------
 -
 - :: State.
 -
 ------------------------------------------------------------------------------}

type ConferenceNumber = Word16
type PeerNumber = Word16

-- | Why we keep a connection to a peer.
data Reason = Closest | Introducing | Introducer
  deriving (Eq, Ord, Show)

data ConferenceConn = ConferenceConn
  { ccOnline           :: Bool
  , ccConferenceNumber :: ConferenceNumber -- ^ Peer's number for the conference, once online.
  , ccReasons          :: Set Reason
  } deriving (Eq, Show)

data Peer = Peer
  { peerRealPk      :: PublicKey
  , peerDhtPk       :: PublicKey
  , peerDhtUpdated  :: Bool
  , peerName        :: ByteString
  , peerNameUpdated :: Bool
  , peerLastActive  :: Timestamp
  , peerSeen        :: [(Word32, Word8)] -- ^ Recent message numbers and IDs, newest first.
  } deriving (Eq, Show)

data Conference = Conference
  { cfType          :: Word8
  , cfId            :: ByteString
  , cfConnected     :: Bool        -- ^ We know our peer number.
  , cfSelf          :: PeerNumber
  , cfPeers         :: Map PeerNumber Peer -- ^ Including us.
  , cfFrozen        :: Map PeerNumber Peer
  , cfTitle         :: ByteString
  , cfTitleFresh    :: Bool
  , cfConns         :: Map PublicKey ConferenceConn -- ^ By the peer's real key.
  , cfMessageNumber :: Word32
  , cfLastPing      :: Maybe Timestamp
  , cfNeedSendName  :: Bool
  , cfReconnect     :: Bool        -- ^ Its peers or connections changed since we picked the closest.
  } deriving (Eq, Show)

-- | One we're not connected to yet, with no peers.
emptyConference :: Word8 -> ByteString -> Conference
emptyConference ty ident = Conference
  { cfType          = ty
  , cfId            = ident
  , cfConnected     = False
  , cfSelf          = 0
  , cfPeers         = Map.empty
  , cfFrozen        = Map.empty
  , cfTitle         = ""
  , cfTitleFresh    = False
  , cfConns         = Map.empty
  , cfMessageNumber = 0
  , cfLastPing      = Nothing
  , cfNeedSendName  = False
  , cfReconnect     = False
  }

-- | Its DHT key and name not sent on yet, and nothing seen from it.
newPeer :: PublicKey -> PublicKey -> ByteString -> Timestamp -> Peer
newPeer realPk dhtPk name now = Peer
  { peerRealPk      = realPk
  , peerDhtPk       = dhtPk
  , peerDhtUpdated  = False
  , peerName        = name
  , peerNameUpdated = False
  , peerLastActive  = now
  , peerSeen        = []
  }

data Conferences = Conferences
  { conferences    :: Map ConferenceNumber Conference
  , conferenceJobs :: Schedule ConferenceNumber -- ^ When each next needs us.
  }

emptyConferences :: Conferences
emptyConferences = Conferences Map.empty Schedule.empty

data ConferenceEvent
  = ConferenceInvited PublicKey Word8 ByteString -- ^ Friend, type, and the cookie to join.
  | ConferenceConnected ConferenceNumber
  | ConferenceMessage ConferenceNumber PeerNumber Messenger.MessageType ByteString
  | ConferenceTitle ConferenceNumber (Maybe PeerNumber) ByteString
  | ConferencePeerName ConferenceNumber PeerNumber ByteString
  | ConferencePeerListChanged ConferenceNumber
  deriving (Eq, Show)

class (Messenger.MessengerMonad m, Onion.OnionNodeMonad m, DHT.DhtNodeMonad m) => ConferenceMonad m where
  getConferences :: m Conferences
  putConferences :: Conferences -> m ()

getConference :: ConferenceMonad m => ConferenceNumber -> m (Maybe Conference)
getConference g = Map.lookup g . conferences <$> getConferences

modifyConference :: ConferenceMonad m => ConferenceNumber -> (Conference -> Conference) -> m ()
modifyConference g f = getConference g >>= mapM_ (setConference g . Just . f)

-- | The only way to change 'conferences', so 'conferenceJobs' stays in step.
setConference :: ConferenceMonad m => ConferenceNumber -> Maybe Conference -> m ()
setConference g new = do
  now <- askTime
  Conferences cs jobs <- getConferences
  let old = Map.lookup g cs
      new' = (\c -> c { cfReconnect = cfReconnect c || maybe True (moved c) old }) <$> new
      moved c c' = (peerDhtPk <$> cfPeers c) /= (peerDhtPk <$> cfPeers c') || Map.keysSet (cfConns c) /= Map.keysSet (cfConns c')
  putConferences $ Conferences (Map.alter (const new') g cs)
    (maybe (Schedule.cancel g) (`Schedule.at` g) (conferenceDue now =<< new') jobs)

conferenceDue :: Timestamp -> Conference -> Maybe Timestamp
conferenceDue now c
  | not (cfConnected c) = Nothing
  | cfReconnect c || cfNeedSendName c = Just now
  | otherwise = Just . minimum $ maybe now (`Time.addTime` pingInterval) (cfLastPing c)
      : [ Time.addTime (peerLastActive p) freezeTimeout | (n, p) <- Map.toList (cfPeers c), n /= cfSelf c ]

findConference :: ConferenceMonad m => Word8 -> ByteString -> m (Maybe ConferenceNumber)
findConference ty gid = do
  cs <- conferences <$> getConferences
  return $ fst <$> find (\(_, c) -> cfType c == ty && cfId c == gid) (Map.toList cs)

ourKeys :: ConferenceMonad m => m (PublicKey, PublicKey)
ourKeys = Connection.getsConn $ \cm ->
  (KeyPair.publicKey $ Connection.ourRealKeys cm, KeyPair.publicKey $ Connection.ourDhtKeys cm)

identifier :: Conference -> ByteString
identifier c = BS.cons (cfType c) (cfId c)

onlineConns :: Conference -> [(PublicKey, ConferenceConn)]
onlineConns = filter (ccOnline . snd) . Map.toList . cfConns
\end{code}

For a conference connection to work, both peers in the conference must be
attempting to connect directly to each other.

Conference connections are established when both peers who want to connect to
each other either create a new friend connection to connect to each other or
reuse an existing friend connection that connects them together (if they are
friends or already are connected together because of another conference).

As soon as the connection to the other peer is opened, a peer online packet is
sent to the peer.  The goal of the online packet is to tell the peer that we
want to establish the conference connection with them and tell them the
conference number of our conference instance.  The peer online packet contains
the conference number and the 33 byte conference identifier.  The conference
number is the conference number the peer has for the conference with the
conference id sent in the packet.

When both sides send an online packet to the other peer, a connection is
established.

When an online packet is received from a peer, if the connection to the peer is
already established (an online packet has been already received), or if there
is no conference connection to that peer being established, the packet is
dropped. Otherwise, the conference number to communicate with the conference
via the peer is saved, the connection is considered established, and an online
packet is sent back to the peer. A ping message is sent to the conference. If
this is the first conference connection to that conference we establish, or the
connection is marked as introducing us, we send a peer query packet back to the
peer.  This is so we can get the list of peers from the conference. If the
connection is marked as introducing the peer, we send a new peer message to the
conference announcing the peer, and a name message reannouncing our name.

A conference connection can be marked as introducing one or both of the peers
it connects, to indicate that the connection should be maintained until that
peer is well connected to the conference. A peer maintains a conference
connection to a second peer as long as the second peer is one of the four
closest peers in the conference to the first, or the connection is marked as
introducing a peer who still requires the connection. A peer requires a
conference connection to a second peer which introduces the first peer until
the first peer has more than 4 conference connections and receives a message
from the second peer via a different conference connection. The first peer then
sends a peer introduced packet to the second peer to indicate that they no
longer require the connection.

\begin{code}
{-------------------------------------------------------------------------------
 -
 - :: Connections.
 -
 ------------------------------------------------------------------------------}

addConn :: ConferenceMonad m => ConferenceNumber -> PublicKey -> PublicKey -> Reason -> m ()
addConn g realPk dhtPk reason = getConference g >>= mapM_ (\c -> do
  known <- Connection.getsConn (Map.member realPk . Connection.friends)
  when (Map.member realPk (cfConns c) || Map.size (cfConns c) < maxConnections) $ do
    unless known $ do
      Connection.addFriend realPk
      void $ Connection.setFriendDhtPk realPk dhtPk
    let conn = Map.findWithDefault (ConferenceConn False 0 Set.empty) realPk (cfConns c)
    modifyConference g $ \c' ->
      c' { cfConns = Map.insert realPk conn { ccReasons = Set.insert reason (ccReasons conn) } (cfConns c') }
    online <- isFriendConnected realPk
    when (online && not (ccOnline conn) && Map.notMember realPk (cfConns c)) $ sendOnline realPk g c)

isFriendConnected :: ConferenceMonad m => PublicKey -> m Bool
isFriendConnected pk = Connection.getsConn (maybe False Connection.fcOnline . Map.lookup pk . Connection.friends)

removeReason :: ConferenceMonad m => ConferenceNumber -> PublicKey -> Reason -> m ()
removeReason g pk reason = getConference g >>= mapM_ (\c -> forM_ (Map.lookup pk (cfConns c)) $ \conn ->
  when (Set.member reason (ccReasons conn)) $ do
    let reasons = Set.delete reason (ccReasons conn)
    when (reason == Introducer && ccOnline conn) $
      sendDirect pk (ccConferenceNumber conn) (BS.singleton peerIntroducedId)
    if Set.null reasons
      then dropConn g pk
      else modifyConference g $ \c' -> c' { cfConns = Map.insert pk conn { ccReasons = reasons } (cfConns c') })

dropConn :: ConferenceMonad m => ConferenceNumber -> PublicKey -> m ()
dropConn g pk = do
  modifyConference g $ \c -> c { cfConns = Map.delete pk (cfConns c) }
  releaseFriendConnection pk

releaseFriendConnection :: ConferenceMonad m => PublicKey -> m ()
releaseFriendConnection pk = do
  friend <- Messenger.getsMessenger (Map.member pk . Messenger.messengerFriends)
  used <- any (Map.member pk . cfConns) . Map.elems . conferences <$> getConferences
  unless (friend || used) $ Connection.removeFriend pk


{-------------------------------------------------------------------------------
 -
 - :: Sending.
 -
 ------------------------------------------------------------------------------}

sendOnline :: ConferenceMonad m => PublicKey -> ConferenceNumber -> Conference -> m ()
sendOnline pk g c = void . Connection.sendFriendData pk $ BS.cons packetIdOnline (word16 g) <> identifier c

sendDirect :: ConferenceMonad m => PublicKey -> ConferenceNumber -> ByteString -> m ()
sendDirect pk theirs = void . Connection.sendFriendData pk . (BS.cons packetIdDirect (word16 theirs) <>)

sendPeerQuery :: ConferenceMonad m => PublicKey -> ConferenceNumber -> m ()
sendPeerQuery pk theirs = sendDirect pk theirs (BS.singleton peerQueryId)

relay :: ConferenceMonad m => Conference -> Maybe PublicKey -> ByteString -> m Int
relay c except payload = do
  sent <- forM [ (pk, conn) | (pk, conn) <- onlineConns c, Just pk /= except ] $ \(pk, conn) ->
    Connection.sendFriendData pk (BS.cons packetIdMessage (word16 $ ccConferenceNumber conn) <> payload)
  return . length $ filter id sent

-- | Gives how many peers it went to.
sendMessage :: ConferenceMonad m => ConferenceNumber -> Word8 -> ByteString -> m Int
sendMessage g ident bytes = getConference g >>= \case
  Just c | cfConnected c, BS.length bytes <= maxMessageData, not (null $ onlineConns c) -> do
    let number = if cfMessageNumber c + 1 == 0 then 1 else cfMessageNumber c + 1
    modifyConference g $ \c' -> c' { cfMessageNumber = number }
    relay c Nothing $ word16 (cfSelf c) <> word32 number <> BS.singleton ident <> bytes
  _ -> return 0

sendNewPeer :: ConferenceMonad m => ConferenceNumber -> PeerNumber -> PublicKey -> PublicKey -> m ()
sendNewPeer g n realPk dhtPk = void $ sendMessage g messageNewPeer (word16 n <> keyBytes realPk <> keyBytes dhtPk)

sendName :: ConferenceMonad m => ConferenceNumber -> m ()
sendName g = do
  name <- Messenger.getsMessenger Messenger.selfName
  void $ sendMessage g messageName name

sendPeers :: ConferenceMonad m => PublicKey -> ConferenceNumber -> Conference -> m ()
sendPeers pk theirs c = do
  mapM_ (sendDirect pk theirs . BS.cons peerResponseId . BS.concat) (chunk [] 0 entries)
  unless (BS.null $ cfTitle c) $ sendDirect pk theirs (BS.cons peerTitleId (cfTitle c))
  where
    entries = [ word16 n <> keyBytes (peerRealPk p) <> keyBytes (peerDhtPk p)
                  <> BS.singleton (fromIntegral $ BS.length $ peerName p) <> peerName p
              | (n, p) <- Map.toList (cfPeers c) ]
    room = Reliability.maxCryptoDataSize - (1 + 2 + 1)
    chunk acc _ [] = [reverse acc | not (null acc)]
    chunk acc size (e : es)
      | size + BS.length e > room && not (null acc) = reverse acc : chunk [e] (BS.length e) es
      | otherwise = chunk (e : acc) (size + BS.length e) es
\end{code}

Peer query packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} conference number \\
  \texttt{1}         & \texttt{uint8\_t} (0x08) \\
\end{tabular}

Peer response packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x62) \\
  \texttt{2}         & \texttt{uint16\_t} conference number \\
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
  \texttt{2}         & \texttt{uint16\_t} conference number \\
  \texttt{1}         & \texttt{uint8\_t} (0x0a) \\
  variable           & Title \\
\end{tabular}

Message packets:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x63) \\
  \texttt{2}         & \texttt{uint16\_t} conference number \\
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
  \texttt{2}         & \texttt{uint16\_t} conference number \\
  \texttt{2}         & \texttt{uint16\_t} peer number \\
  \texttt{2}         & \texttt{uint16\_t} message number \\
  \texttt{1}         & \texttt{uint8\_t} with a value representing id of message \\
  variable           & Data \\
\end{tabular}

If a peer query packet is received, the receiver takes their list of peers and
creates a peer response packet which is then sent to the other peer.  If there
are too many peers in the conference and the peer response packet would be
larger than the maximum size of friend connection packets (1373 bytes), more
than one peer response packet is sent back.  A Title response packet is also
sent back.  This is how the peer that joins a conference finds out the list of
peers in the conference and the title of the conference right after joining.

Peer response packets are straightforward and contain the information for each
peer (peer number, real public key, DHT public key, name) appended to each
other.  The title response is also straightforward.

Both the maximum length of conference peer names and the conference title is 128
bytes.  This is the same maximum length as names in all of toxcore.

When a peer receives a peer response packet, they will add each of the
received peers to their conference peer list, find the 4 closest peers to them
and create conference connections to them as was explained previously. The DHT
public key of an already known peer is updated to one given in the response
packet if the peer is frozen, or if it has been frozen since its DHT public
key was last updated.

When a peer receives a title response packet, they update the title for the
conference accordingly if the title has not already been set, or if since it
was last set there has been a time at which all peers were frozen.

If the peer does not yet know their own peer number, as is the case if they
have just accepted an invitation, the peer will find themselves in the list of
received peers and use the peer number assigned to them as their own. They are
then able to send messages and invite other peers to the conference. They
immediately send a name message to announce their name to the conference.

Message packets are used to send messages to all peers in the conference.  To
send a message packet, a peer will first take their peer number and the message
they want to send.  Each message packet sent will have a message number that is
equal to the last message number sent + 1.  Like all other numbers (conference
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
number has been received, then the packet is discarded. Otherwise, the message
is processed as described below, and a Message packet with the message is sent
(relayed) to all current conference connections except the one that it was
received from, and also to that one if that peer is the original sender of the
message. The only thing that should change in the Message packet as it is
relayed is the conference number.

Lossy message packets are used to send audio packets to others in audio
conferences.  Lossy packets work the same way as normal relayed conference
messages in that they are relayed to everyone in the conference until everyone
has them, but there are a few differences. Firstly, the message number is only
a 2 byte integer. When receiving a lossy packet from a peer the receiving peer
will first check if a message with that message number was already received
from that peer. If it wasn't, the packet will be added to the list of received
packets and then the packet will be passed to its handler and then sent to the
2 closest connected conference peers that are not the sender.  The reason for
it to be 2 instead of 4 (or 3 if we are not the original sender) as for
lossless message packets is that it reduces bandwidth usage without lowering
the quality of the received audio stream via lossy packets, at the cost of
reduced robustness against connections failing. To check if a packet was
already received, the last 256 message numbers received from each peer are
stored. If video was added meaning a much higher number of packets would be
sent, this number would be increased.  If the packet number is in this list
then it was received.

\begin{code}
{-------------------------------------------------------------------------------
 -
 - :: Peers.
 -
 ------------------------------------------------------------------------------}

notePeerActive :: ConferenceMonad m
               => ConferenceNumber -> PeerNumber -> m (Maybe Peer, [ConferenceEvent])
notePeerActive g n = do
  now <- askTime
  mc <- getConference g
  case mc of
    Nothing -> return (Nothing, [])
    Just c -> case (Map.lookup n (cfPeers c), Map.lookup n (cfFrozen c)) of
      (Just p, _) -> do
        let p' = p { peerLastActive = now }
        modifyConference g $ \c' -> c' { cfPeers = Map.insert n p' (cfPeers c') }
        return (Just p', [])
      (Nothing, Just p) -> do
        let p' = p { peerLastActive = now, peerDhtUpdated = False }
        modifyConference g $ \c' -> c'
          { cfPeers = Map.insert n p' (cfPeers c'), cfFrozen = Map.delete n (cfFrozen c'), cfNeedSendName = True }
        return (Just p', [ConferencePeerListChanged g])
      _ -> return (Nothing, [])

-- | A known peer gets updated. Fresh information also updates its DHT key
-- and marks it active.
addPeer :: ConferenceMonad m
        => ConferenceNumber -> PublicKey -> PublicKey -> PeerNumber -> Bool
        -> m (Maybe PeerNumber, [ConferenceEvent])
addPeer g realPk dhtPk n fresh = do
  (active, events) <- if fresh
    then notePeerActive g n
    else (\c -> (c >>= Map.lookup n . cfPeers, [])) <$> getConference g
  mc <- getConference g
  now <- askTime
  case (mc, active) of
    (Nothing, _) -> return (Nothing, [])
    (Just _, Just p)
      | peerRealPk p /= realPk -> return (Nothing, events)
      | otherwise -> do
          when (fresh || not (peerDhtUpdated p)) $
            modifyConference g $ \c ->
              c { cfPeers = Map.adjust (\q -> q { peerDhtPk = dhtPk, peerDhtUpdated = True }) n (cfPeers c) }
          return (Just n, events)
    (Just c, Nothing)
      | not fresh, Just f <- Map.lookup n (cfFrozen c) -> do
          when (peerRealPk f == realPk) $
            modifyConference g $ \c' -> c' { cfFrozen = Map.adjust (\q -> q { peerDhtPk = dhtPk }) n (cfFrozen c') }
          return (Nothing, events)
      | otherwise -> do
          let others = Map.filter ((/= realPk) . peerRealPk)
          modifyConference g $ \c' -> c'
            { cfPeers = Map.insert n (newPeer realPk dhtPk "" now) { peerDhtUpdated = True } (others $ cfPeers c')
            , cfFrozen = others (cfFrozen c')
            }
          return (Just n, events ++ [ConferencePeerListChanged g])

deletePeer :: ConferenceMonad m => ConferenceNumber -> PeerNumber -> m [ConferenceEvent]
deletePeer g n = getConference g >>= \case
  Just c | Just p <- Map.lookup n (cfPeers c) -> do
    modifyConference g $ \c' -> c' { cfPeers = Map.delete n (cfPeers c') }
    when (Map.member (peerRealPk p) (cfConns c)) $ dropConn g (peerRealPk p)
    return [ConferencePeerListChanged g]
  _ -> return []

freezePeer :: ConferenceMonad m => ConferenceNumber -> PeerNumber -> m [ConferenceEvent]
freezePeer g n = getConference g >>= \case
  Just c | Just p <- Map.lookup n (cfPeers c) -> do
    events <- deletePeer g n
    modifyConference g $ \c' -> c' { cfFrozen = keepNewest (Map.insert n p (cfFrozen c')) }
    tryRejoin g (peerRealPk p)
    return events
  _ -> return []
  where
    keepNewest frozen
      | Map.size frozen <= maxFrozen = frozen
      | otherwise = Map.fromList . take maxFrozen
          . sortOn (negate . Time.timestampToMicroseconds . peerLastActive . snd) $ Map.toList frozen

tryRejoin :: ConferenceMonad m => ConferenceNumber -> PublicKey -> m ()
tryRejoin g pk = do
  mc <- getConference g
  mFriend <- Connection.getsConn (Map.lookup pk . Connection.friends)
  case (mc, mFriend) of
    (Just c, Just f) -> do
      sent <- Connection.sendFriendData pk (BS.cons packetIdRejoin (identifier c))
      when sent $ forM_ (Connection.fcDhtPk f) $ \dhtPk -> addConn g pk dhtPk Introducer
    _ -> return ()

setName :: ConferenceMonad m
        => ConferenceNumber -> PeerNumber -> ByteString -> m (Bool, [ConferenceEvent])
setName g n name
  | BS.length name > maxNameLength = return (False, [])
  | otherwise = getConference g >>= \case
      Just c | Just p <- Map.lookup n (cfPeers c) -> do
        modifyConference g $ \c' ->
          c' { cfPeers = Map.insert n p { peerName = name, peerNameUpdated = True } (cfPeers c') }
        return (True, [ ConferencePeerName g n name | peerName p /= name ])
      _ -> return (False, [])

setTitle :: ConferenceMonad m
         => ConferenceNumber -> Maybe PeerNumber -> ByteString -> m (Bool, [ConferenceEvent])
setTitle g by title
  | BS.null title || BS.length title > maxNameLength = return (False, [])
  | otherwise = getConference g >>= \case
      Just c -> do
        modifyConference g $ \c' -> c' { cfTitle = title, cfTitleFresh = True }
        return (True, [ ConferenceTitle g by title | cfTitle c /= title ])
      Nothing -> return (False, [])

-- | We keep connections to the 2 peers closest to us on each side, on a
-- circle of the first 8 bytes of real keys.
closestPeers :: PublicKey -> [Peer] -> [Peer]
closestPeers ours peers = Map.elems . Map.fromList $
  [ (keyBytes (peerRealPk p), p) | p <- take half (sortOn (distance ours . peerRealPk) others)
                                 ++ take half (sortOn (\p -> distance (peerRealPk p) ours) others) ]
  where
    others = filter ((/= ours) . peerRealPk) peers
    half = desiredClosest `div` 2
    distance a b = prefix a - prefix b
    prefix :: PublicKey -> Word64
    prefix = foldl' (\acc b -> acc `shiftL` 8 .|. fromIntegral b) 0 . BS.unpack . BS.take 8 . keyBytes


{-------------------------------------------------------------------------------
 -
 - :: Commands.
 -
 ------------------------------------------------------------------------------}

-- | Text conference, with us as founder and peer 0.
newConference :: ConferenceMonad m => m (Maybe ConferenceNumber)
newConference = do
  gid <- randomBytes conferenceIdLength
  (realPk, dhtPk) <- ourKeys
  name <- Messenger.getsMessenger Messenger.selfName
  now <- askTime
  mg <- freeNumber
  forM mg $ \g -> do
    let self = (newPeer realPk dhtPk name now) { peerDhtUpdated = True, peerNameUpdated = True }
    setConference g $ Just (emptyConference typeText gid) { cfConnected = True, cfPeers = Map.singleton 0 self }
    return g

freeNumber :: ConferenceMonad m => m (Maybe ConferenceNumber)
freeNumber = do
  cs <- conferences <$> getConferences
  return $ find (`Map.notMember` cs) [0 .. maxBound]

-- | The friend gets a cookie to join with.
invite :: ConferenceMonad m => PublicKey -> ConferenceNumber -> m Bool
invite friend g = getConference g >>= \case
  Just c | cfConnected c ->
    Messenger.sendPacketId friend packetIdInvite $ BS.singleton inviteId <> word16 g <> identifier c
  _ -> return False

data JoinError = JoinBadCookie | JoinWrongType | JoinFriendNotConnected | JoinAlreadyJoined | JoinTooMany
  deriving (Eq, Show)

join :: ConferenceMonad m => PublicKey -> ByteString -> m (Either JoinError ConferenceNumber)
join friend cookie
  | BS.length cookie /= 2 + 1 + conferenceIdLength = return $ Left JoinBadCookie
  -- We join audio conferences for the text (audio comes in lossy packets,
  -- which are the client's).
  | BS.index cookie 2 `notElem` [typeText, typeAv] = return $ Left JoinWrongType
  | otherwise = do
      online <- Messenger.isFriendOnline friend
      existing <- findConference (BS.index cookie 2) (BS.drop 3 cookie)
      if | not online -> return $ Left JoinFriendNotConnected
         | isJust existing -> return $ Left JoinAlreadyJoined
         | otherwise -> freeNumber >>= maybe (return $ Left JoinTooMany) (\g -> do
             setConference g $ Just (emptyConference (BS.index cookie 2) (BS.drop 3 cookie))
             sent <- sendInviteResponse g friend cookie
             if sent then return (Right g) else do
               setConference g Nothing
               return $ Left JoinFriendNotConnected)

sendInviteResponse :: ConferenceMonad m => ConferenceNumber -> PublicKey -> ByteString -> m Bool
sendInviteResponse g friend cookie = getConference g >>= \case
  Nothing -> return False
  Just c -> do
    let member = cfConnected c
        response = BS.singleton (if member then inviteMemberId else inviteAcceptId) <> word16 g <> cookie
          <> (if member then word16 (cfSelf c) else BS.empty)
        theirs = getW16 cookie
    sent <- Messenger.sendPacketId friend packetIdInvite response
    mDht <- Connection.getsConn (\cm -> Map.lookup friend (Connection.friends cm) >>= Connection.fcDhtPk)
    case mDht of
      Just dhtPk | sent -> do
        addConn g friend dhtPk Introducer
        when member $ addConn g friend dhtPk Introducing
        setOnline g friend theirs
        sendPeerQuery friend theirs
        return True
      _ -> return False

setOnline :: ConferenceMonad m => ConferenceNumber -> PublicKey -> ConferenceNumber -> m ()
setOnline g pk theirs = modifyConference g $ \c -> c
  { cfConns = Map.adjust (\conn -> conn { ccOnline = True, ccConferenceNumber = theirs }) pk (cfConns c) }

-- | Forever, or for now so we can come back.
leave :: ConferenceMonad m => ConferenceNumber -> Bool -> m Bool
leave g permanent = getConference g >>= \case
  Nothing -> return False
  Just c -> do
    _ <- sendMessage g (if permanent then messageKillPeer else messageFreezePeer) (word16 $ cfSelf c)
    setConference g Nothing
    mapM_ releaseFriendConnection (Map.keys $ cfConns c)
    return True

sendText :: ConferenceMonad m => ConferenceNumber -> Messenger.MessageType -> ByteString -> m Bool
sendText g ty msg
  | BS.null msg = return False
  | otherwise = (> 0) <$> sendMessage g (if ty == Messenger.MessageNormal then messageChat else messageAction) msg

changeTitle :: ConferenceMonad m => ConferenceNumber -> ByteString -> m Bool
changeTitle g title = getConference g >>= \case
  Nothing -> return False
  Just c -> do
    (ok, _) <- setTitle g (Just $ cfSelf c) title
    -- As in toxcore, no message for an unchanged title, or one nobody else
    -- sees.
    if | not ok -> return False
       | cfTitle c == title || Map.size (cfPeers c) == 1 -> return True
       | otherwise -> (> 0) <$> sendMessage g messageTitle title
\end{code}

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

\subsection{Conference title change (0x31)}

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

Kill peer messages are used to indicate that a peer has quit the conference
permanently. Freeze peer messages are similar, but indicate that the quitting
peer may later return to the conference. Each is sent by the one quitting the
conference right before they quit it.

Name change messages are used to change or set the name of the peer sending it.
They are also sent by a joining peer right after receiving the list of peers in
order to tell others what their name is.

Title change packets are used to change the title of the conference and can be
sent by anyone in the conference.

Chat and action messages are used by the conference peers to send messages to
others in the conference.

\begin{code}
{-------------------------------------------------------------------------------
 -
 - :: Receiving.
 -
 ------------------------------------------------------------------------------}

handleConnectionEvent :: ConferenceMonad m => ConnectionEvent -> m [ConferenceEvent]
handleConnectionEvent = \case
  FriendOnline pk -> do
    cs <- Map.toList . conferences <$> getConferences
    forM_ cs $ \(g, c) -> do
      when (Map.member pk (cfConns c)) $ sendOnline pk g c
      when (any ((== pk) . peerRealPk) (cfFrozen c)) $ tryRejoin g pk
    return []
  FriendOffline pk -> do
    cs <- Map.toList . conferences <$> getConferences
    concat <$> forM cs (\(g, c) -> if Map.member pk (cfConns c) then do
      modifyConference g $ \c' -> c' { cfConns = Map.adjust (\conn -> conn { ccOnline = False }) pk (cfConns c') }
      checkDisconnected g
      else return [])
  FriendData pk bytes -> case BS.uncons bytes of
    Just (ident, rest)
      | ident == packetIdInvite -> do
          friend <- Messenger.getsMessenger (Map.member pk . Messenger.messengerFriends)
          if friend then handleInvite pk rest else return []
      | ident == packetIdOnline -> [] <$ handleOnline pk rest
      | ident == packetIdRejoin -> handleRejoin pk rest
      | ident == packetIdDirect || ident == packetIdMessage, BS.length rest >= 3 -> do
          let g = getW16 rest
          mc <- getConference g
          case mc of
            Just c | Just conn <- Map.lookup pk (cfConns c) ->
              if ident == packetIdDirect
                then handleDirect g pk conn (BS.drop 2 rest)
                else handleMessage g pk conn (BS.drop 2 rest)
            _ -> return []
    _ -> return []
  _ -> return []

checkDisconnected :: ConferenceMonad m => ConferenceNumber -> m [ConferenceEvent]
checkDisconnected g = getConference g >>= \case
  Just c | null (onlineConns c) -> do
    (ours, _) <- ourKeys
    concat <$> mapM (freezePeer g) [ n | (n, p) <- Map.toList (cfPeers c), peerRealPk p /= ours ]
  _ -> return []

handleInvite :: ConferenceMonad m => PublicKey -> ByteString -> m [ConferenceEvent]
handleInvite friend payload = case BS.unpack (BS.take 1 payload) of
  [i] | i == inviteId, BS.length payload == 1 + 2 + 1 + conferenceIdLength -> do
    let cookie = BS.drop 1 payload
        ty = BS.index cookie 2
    if ty /= typeText && ty /= typeAv then return [] else do
      existing <- findConference ty (BS.drop 3 cookie)
      case existing of
        Nothing -> return [ConferenceInvited friend ty cookie]
        Just g -> do
          connected <- maybe False cfConnected <$> getConference g
          when connected $ void $ sendInviteResponse g friend cookie
          return []
  [i] | (i == inviteAcceptId && BS.length payload == 1 + 2 + 2 + 1 + conferenceIdLength)
        || (i == inviteMemberId && BS.length payload == 1 + 2 + 2 + 1 + conferenceIdLength + 2) -> do
    let member = i == inviteMemberId
        theirs = getW16 (BS.drop 1 payload)
        g = getW16 (BS.drop 3 payload)
        ident = BS.take (1 + conferenceIdLength) (BS.drop 5 payload)
    mc <- getConference g
    mDht <- Connection.getsConn (\cm -> Map.lookup friend (Connection.friends cm) >>= Connection.fcDhtPk)
    case (mc, mDht) of
      (Just c, Just dhtPk) | identifier c == ident -> do
        n <- if member then return (Just $ getW16 (BS.drop (5 + 1 + conferenceIdLength) payload)) else newPeerNumber c
        case n of
          Nothing -> return []
          Just peer -> do
            (_, events) <- addPeer g friend dhtPk peer True
            addConn g friend dhtPk Introducing
            when member $ do
              addConn g friend dhtPk Introducer
              sendPeerQuery friend theirs
            setOnline g friend theirs
            sendNewPeer g peer friend dhtPk
            return events
      _ -> return []
  _ -> return []
  where
    newPeerNumber c = go (32 :: Int)
      where
        go 0 = return Nothing
        go tries = do
          n <- randomWord16
          if Map.member n (cfPeers c) || Map.member n (cfFrozen c) then go (tries - 1) else return (Just n)

handleOnline :: ConferenceMonad m => PublicKey -> ByteString -> m ()
handleOnline pk payload = when (BS.length payload == 2 + 1 + conferenceIdLength) $ do
  mg <- findConference (BS.index payload 2) (BS.drop 3 payload)
  forM_ mg $ \g -> getConference g >>= mapM_ (\c -> forM_ (Map.lookup pk (cfConns c)) $ \conn ->
    unless (ccOnline conn) $ do
      let theirs = getW16 payload
      when (null (onlineConns c) || Set.member Introducer (ccReasons conn)) $ sendPeerQuery pk theirs
      setOnline g pk theirs
      sendOnline pk g c
      when (Set.member Introducing (ccReasons conn)) $ do
        forM_ (find ((== pk) . peerRealPk . snd) (Map.toList $ cfPeers c)) $ \(n, p) ->
          sendNewPeer g n pk (peerDhtPk p)
        modifyConference g $ \c' -> c' { cfNeedSendName = True }
      ping g)

handleRejoin :: ConferenceMonad m => PublicKey -> ByteString -> m [ConferenceEvent]
handleRejoin pk payload
  | BS.length payload < 1 + conferenceIdLength = return []
  | otherwise = do
      mg <- findConference (BS.index payload 0) (BS.take conferenceIdLength $ BS.drop 1 payload)
      mDht <- Connection.getsConn (\cm -> Map.lookup pk (Connection.friends cm) >>= Connection.fcDhtPk)
      case (mg, mDht) of
        (Just g, Just dhtPk) -> getConference g >>= \case
          Just c | Just n <- peerNumberOf c -> do
            (_, events) <- addPeer g pk dhtPk n True
            addConn g pk dhtPk Introducing
            online <- isFriendConnected pk
            -- As in toxcore, say we're online, unless 'addConn' just did.
            let justAdded = online && Map.notMember pk (cfConns c)
            getConference g >>= mapM_ (\c' -> when (Map.member pk (cfConns c') && not justAdded) $
              sendOnline pk g c')
            return events
          _ -> return []
        _ -> return []
  where
    peerNumberOf c = fst <$> find ((== pk) . peerRealPk . snd) (Map.toList (cfPeers c) ++ Map.toList (cfFrozen c))

handleDirect :: ConferenceMonad m
             => ConferenceNumber -> PublicKey -> ConferenceConn -> ByteString -> m [ConferenceEvent]
handleDirect g pk conn payload = case BS.uncons payload of
  Just (i, rest)
    | i == peerIntroducedId -> [] <$ removeReason g pk Introducing
    | i == peerQueryId -> do
        when (ccOnline conn) $ getConference g >>= mapM_ (sendPeers pk (ccConferenceNumber conn))
        return []
    | i == peerResponseId -> handlePeers g rest
    | i == peerTitleId -> getConference g >>= \case
        Just c | not (cfTitleFresh c) -> snd <$> setTitle g Nothing rest
        _ -> return []
  _ -> return []

handlePeers :: ConferenceMonad m => ConferenceNumber -> ByteString -> m [ConferenceEvent]
handlePeers g bytes = case runGetRest ((,) <$> getPeerKeys <*> getWord8) bytes of
      Just (((n, realPk, dhtPk), len), rest)
        | fromIntegral len <= maxNameLength, BS.length rest >= fromIntegral len -> do
        let (name, more) = BS.splitAt (fromIntegral len) rest
        (ours, _) <- ourKeys
        joined <- getConference g >>= \case
          Just c | not (cfConnected c) && realPk == ours -> do
            modifyConference g $ \c' -> c' { cfSelf = n, cfConnected = True, cfNeedSendName = True }
            return [ConferenceConnected g]
          _ -> return []
        (added, events) <- addPeer g realPk dhtPk n False
        case added of
          Nothing -> return (joined ++ events)
          Just _ -> do
            updated <- maybe False peerNameUpdated . (>>= Map.lookup n . cfPeers) <$> getConference g
            named <- if updated then return [] else snd <$> setName g n name
            ((joined ++ events ++ named) ++) <$> handlePeers g more
      _ -> return []

-- | Not one of the sender's recent messages, and names and titles aren't
-- older than the last one.
checkSeen :: Word32 -> Word8 -> [(Word32, Word8)] -> Maybe [(Word32, Word8)]
checkSeen number ident = go []
  where
    ignoreOlder = ident == messageName || ident == messageTitle
    go before [] = insertAt before []
    go before rest@((n, i) : after)
      | number - (n + 1) <= 2 ^ (31 :: Int) = insertAt before rest
      | number == n = Nothing
      | ignoreOlder && ident == i = Nothing
      | otherwise = go ((n, i) : before) after
    insertAt before rest
      | length before >= maxMessageInfos = Nothing
      | otherwise = Just . take maxMessageInfos $ reverse before ++ (number, ident) : rest

handleMessage :: ConferenceMonad m
              => ConferenceNumber -> PublicKey -> ConferenceConn -> ByteString
              -> m [ConferenceEvent]
handleMessage g from conn payload
  | BS.length payload < 2 + 4 + 1 = return []
  | otherwise = do
      let n = getW16 payload
          number = getW32 (BS.drop 2 payload)
          ident = BS.index payload 6
          bytes = BS.drop 7 payload
      (mPeer, thawed) <- if ident == messageFreezePeer
        then (\c -> (c >>= Map.lookup n . cfPeers, [])) <$> getConference g
        else notePeerActive g n
      case mPeer of
        Nothing -> do
          when (ident /= messageFreezePeer && ccOnline conn) $ sendPeerQuery from (ccConferenceNumber conn)
          return thawed
        Just peer -> do
          introduced g peer from
          case checkSeen number ident (peerSeen peer) of
            Nothing -> return thawed
            Just seen -> do
              modifyConference g $ \c -> c { cfPeers = Map.adjust (\p -> p { peerSeen = seen }) n (cfPeers c) }
              (keep, events) <- handleKind g n ident bytes
              when keep $ getConference g >>= mapM_ (\c ->
                relay c (if peerRealPk peer == from then Nothing else Just from) payload)
              return (thawed ++ events)

-- | A message from the peer through someone else shows it reaches us
-- without our introducer connection.
introduced :: ConferenceMonad m => ConferenceNumber -> Peer -> PublicKey -> m ()
introduced g peer from = getConference g >>= mapM_ (\c -> do
  let introducers = [ pk | (pk, conn) <- Map.toList (cfConns c), Set.member Introducer (ccReasons conn) ]
  when (not (null introducers) && length (onlineConns c) > desiredClosest) $
    forM_ introducers $ \pk -> when (pk /= from && pk == peerRealPk peer) $ removeReason g pk Introducer)

-- | Whether to relay it, and what to report.
handleKind :: ConferenceMonad m
           => ConferenceNumber -> PeerNumber -> Word8 -> ByteString -> m (Bool, [ConferenceEvent])
handleKind g n ident bytes
  | ident == messagePing = return (True, [])
  | ident == messageNewPeer = case runGetRest getPeerKeys bytes of
      Just ((number, realPk, dhtPk), rest) | BS.null rest -> (,) True . snd <$> addPeer g realPk dhtPk number True
      _ -> return (False, [])
  | ident == messageKillPeer || ident == messageFreezePeer =
      if BS.length bytes /= 2 || getW16 bytes /= n then return (False, []) else
        (,) True <$> (if ident == messageKillPeer then deletePeer g n else freezePeer g n)
  | ident == messageName = setName g n bytes
  | ident == messageTitle = setTitle g (Just n) bytes
  -- Peers relay ours back, and clients don't want those.
  | (ident == messageChat || ident == messageAction) && not (BS.null bytes) = do
      ours <- maybe False ((== n) . cfSelf) <$> getConference g
      let ty = if ident == messageChat then Messenger.MessageNormal else Messenger.MessageAction
      return (True, [ ConferenceMessage g n ty bytes
                    | not ours ])
  | otherwise = return (False, [])

ping :: ConferenceMonad m => ConferenceNumber -> m ()
ping g = do
  now <- askTime
  due <- maybe False (Time.due now pingInterval . cfLastPing) <$> getConference g
  when due $ do
    _ <- sendMessage g messagePing BS.empty
    -- We tried, so wait the interval whatever happened.
    modifyConference g $ \c -> c { cfLastPing = Just now }
\end{code}

\section{Timeouts and reconnection}

Conference connections may go down, and this may lead to a peer becoming
disconnected from the conference or the conference otherwise splitting into
multiple connected components. To ensure the conference becomes fully connected
again once suitable connections are re-established, peers keep track of peers
who are no longer visible in the conference ("frozen" peers), and try to
re-integrate them into the conference via any suitable friend connections which
may come to be available. The rejoin packet is used for this.

Rejoin packet:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x64) \\
  \texttt{33}        & Conference identifier \\
\end{tabular}

A peer in a conference is considered to be active when a conference message or
rejoin packet is received from it, or a new peer message is received for it.
A peer which remains inactive for 60 seconds is set as frozen; this means it
is removed from the peer list and added to a separate list of frozen peers.
Frozen peers are disregarded for all purposes except those discussed below.

If a frozen peer becomes active, we unfreeze it, meaning that we move it from
the frozen peers list to the peer list, and we send a name message to the
conference.

Whenever we make a new friend connection to a peer, we check whether the
public key of the peer is that of any frozen peer. If so, we send a rejoin
packet to the peer along the friend connection, and create a conference
connection to the peer, marked as introducing us, and send a peer online
packet to the peer.

If we receive a rejoin packet from a peer along a friend connection, then,
after unfreezing the peer if it was frozen, we update the peer's DHT public
key in the conference peer list to the key in the friend connection, and create
a conference connection for the peer, marked as introducing the peer, and send
a peer online packet to the peer.

When a peer is added to the peer list, any existing peer in the peer list or
frozen peers list with the same public key is first removed.

\begin{code}
{-------------------------------------------------------------------------------
 -
 - :: Periodic work.
 -
 ------------------------------------------------------------------------------}

nextDue :: Conferences -> Maybe Timestamp
nextDue = Schedule.next . conferenceJobs

runDue :: ConferenceMonad m => m [ConferenceEvent]
runDue = do
  now <- askTime
  Conferences cs jobs <- getConferences
  let (due, waiting) = Schedule.takeDue now jobs
  putConferences (Conferences cs waiting)
  concat <$> forM due (\g -> do
    events <- getConference g >>= maybe (return []) (\c -> if cfConnected c then work g c else return [])
    getConference g >>= mapM_ (setConference g . Just)
    return events)
  where
    work g c = do
      when (cfReconnect c) $ do
        connectToClosest g
        modifyConference g $ \c' -> c' { cfReconnect = False }
      ping g
      events <- freezeTimedOut g
      when (cfNeedSendName c) $ do
        sendName g
        modifyConference g $ \c' -> c' { cfNeedSendName = False }
      return events

connectToClosest :: ConferenceMonad m => ConferenceNumber -> m ()
connectToClosest g = getConference g >>= mapM_ (\c -> do
  (ours, _) <- ourKeys
  let closest = closestPeers ours (Map.elems $ cfPeers c)
      wanted = Set.fromList (map peerRealPk closest)
  let unwanted = [ pk | (pk, conn) <- Map.toList (cfConns c), Set.member Closest (ccReasons conn)
                      , Set.notMember pk wanted ]
  forM_ unwanted $ \pk ->
    removeReason g pk Closest
  forM_ closest $ \p -> addConn g (peerRealPk p) (peerDhtPk p) Closest)

freezeTimedOut :: ConferenceMonad m => ConferenceNumber -> m [ConferenceEvent]
freezeTimedOut g = getConference g >>= \case
  Nothing -> return []
  Just c -> do
    now <- askTime
    events <- concat <$> mapM (freezePeer g)
      [ n | (n, p) <- Map.toList (cfPeers c), n /= cfSelf c, Time.addTime (peerLastActive p) freezeTimeout <= now ]
    alone <- maybe True ((<= 1) . Map.size . cfPeers) <$> getConference g
    when alone $ modifyConference g $ \c' -> c' { cfTitleFresh = False }
    return events

-- | Everyone else is frozen until they rejoin through our friend
-- connections.
restore :: ConferenceMonad m => [PC.Conference] -> m ()
restore = mapM_ restoreConference

restoreConference :: ConferenceMonad m => PC.Conference -> m (Maybe ConferenceNumber)
restoreConference sc = do
  (realPk, dhtPk) <- ourKeys
  name <- Messenger.getsMessenger Messenger.selfName
  now <- askTime
  existing <- findConference (PC.conferenceType sc) (keyBytes $ PC.conferenceId sc)
  if isJust existing then return Nothing else freeNumber >>= mapM (\g -> do
    let self = (newPeer realPk dhtPk name now) { peerDhtUpdated = True, peerNameUpdated = True }
        frozen = Map.fromList
          [ (PC.peerNumber p, newPeer (PC.publicKey p) (PC.dhtPublicKey p) (PC.name p) now) | p <- PC.peers sc ]
        c = (emptyConference (PC.conferenceType sc) (keyBytes $ PC.conferenceId sc))
          { cfConnected     = True
          , cfSelf          = PC.selfPeerNumber sc
          , cfPeers         = Map.singleton (PC.selfPeerNumber sc) self
          , cfFrozen        = frozen
          , cfTitle         = PC.title sc
          , cfMessageNumber = PC.messageNumber sc
          }
    setConference g (Just c)
    return g)

nameChanged :: ConferenceMonad m => m ()
nameChanged = do
  cs <- Map.toList . conferences <$> getConferences
  forM_ [ g | (g, c) <- cs, cfConnected c ] sendName
  name <- Messenger.getsMessenger Messenger.selfName
  forM_ [ (g, c) | (g, c) <- cs, cfConnected c ] $ \(g, c) ->
    modifyConference g $ \c' -> c' { cfPeers = Map.adjust (\p -> p { peerName = name }) (cfSelf c) (cfPeers c') }
\end{code}
