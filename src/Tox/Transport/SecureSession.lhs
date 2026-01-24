\begin{code}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE StrictData         #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Tox.Transport.SecureSession where

import           Control.Monad (when, foldM)
import           Data.Foldable (forM_)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Control.Monad.State            (MonadState, get, gets, modify)
import           Data.Binary               (Binary)
import qualified Data.Binary               as Binary
import qualified Data.Binary.Get           as Get
import qualified Data.Binary.Put           as Put
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as LBS
import           Data.Word                 (Word64, Word16)
import           Data.Int                  (Int16)
import           GHC.Generics              (Generic)

import           Tox.Crypto.Core.Key            (PublicKey, Nonce, CombinedKey, Key(..), unKey)
import           Tox.Crypto.Core.KeyPair        (KeyPair(..))
import qualified Tox.Crypto.Core.KeyPair        as KeyPair
import           Tox.Crypto.Core.Box            (CipherText)
import qualified Tox.Crypto.Core.Box            as Box
import qualified Tox.Crypto.Core.Nonce          as Nonce
import qualified Tox.Crypto.Core.Hash           as Hash
import           Tox.Crypto.Core.Keyed          (Keyed(..))
import           Tox.Core.Time                  (Timestamp(..), timestampToMicroseconds)
import qualified Tox.Core.Time                  as Time
import           Tox.Core.Timed                 (Timed(..))
import           Tox.Crypto.Core.MonadRandomBytes (MonadRandomBytes (..), randomNonce, randomWord64)
import qualified Tox.Network.Core.PacketKind       as PacketKind
import           Tox.Network.Core.Packet           (Packet (..))
import           Tox.Network.Core.NodeInfo         (NodeInfo(..))
import qualified Tox.Network.Core.NodeInfo         as NodeInfo
import           Tox.Network.Core.Networked        (Networked (..))
import           Tox.Network.Core.TransportProtocol (TransportProtocol(UDP))

import qualified Tox.Transport.Reliability      as Reliability
import qualified Tox.Transport.Stream           as Stream

import qualified System.Clock                  as Clock
import qualified Crypto.Saltine.Class          as Sodium
\end{code}

\chapter{Net crypto}

The Tox transport protocol is what Tox uses to establish and send data securely
to friends and provides encryption, ordered delivery, and perfect forward
secrecy.  It is a UDP protocol but it is also used when 2 friends connect over
TCP relays.

The reason the protocol for connections to friends over TCP relays and direct
UDP is the same is for simplicity and so the connection can switch between both
without the peers needing to disconnect and reconnect.  For example two Tox
friends might first connect over TCP and a few seconds later switch to UDP when
a direct UDP connection becomes possible.  The opening up of the UDP route or
'hole punching' is done by the DHT module and the opening up of a relayed TCP
connection is done by the \texttt{TCP\_connection} module.  The Tox transport
protocol has the job of connecting two peers (tox friends) safely once a route
or communications link between both is found.  Direct UDP is preferred over TCP
because it is direct and isn't limited by possibly congested TCP relays.  Also,
a peer can only connect to another using the Tox transport protocol if they
know the real public key and DHT public key of the peer they want to connect
to.  However, both the DHT and TCP connection modules require this information
in order to find and open the route to the peer which means we assume this
information is known by toxcore and has been passed to \texttt{net\_crypto} when
the \texttt{net\_crypto} connection was created.

Because this protocol has to work over UDP it must account for possible packet
loss, packets arriving in the wrong order and has to implement some kind of
congestion control.  This is implemented above the level at which the packets
are encrypted.  This prevents a malicious TCP relay from disrupting the
connection by modifying the packets that go through it.  The packet loss
prevention makes it work very well on TCP relays that we assume may go down at
any time as the connection will stay strong even if there is need to switch to
another TCP relay which will cause some packet loss.

Before sending the actual handshake packet the peer must obtain a cookie.  This
cookie step serves as a way for the receiving peer to confirm that the peer
initiating the connection can receive the responses in order to prevent certain
types of DoS attacks.

The peer receiving a cookie request packet must not allocate any resources to
the connection.  They will simply respond to the packet with a cookie response
packet containing the cookie that the requesting peer must then use in the
handshake to initiate the actual connection.

The cookie response must be sent back using the exact same link the cookie
request packet was sent from.  The reason for this is that if it is sent back
using another link, the other link might not work and the peer will not be
expecting responses from another link.  For example, if a request is sent from
UDP with ip port X, it must be sent back by UDP to ip port X.  If it was
received from a TCP OOB packet it must be sent back by a TCP OOB packet via the
same relay with the destination being the peer who sent the request.  If it was
received from an established TCP relay connection it must be sent back via that
same exact connection.

When a cookie request is received, the peer must not use the information in the
request packet for anything, he must not store it, he must only create a cookie
and cookie response from it, then send the created cookie response packet and
forget them.  The reason for this is to prevent possible attacks.  For example
if a peer would allocate long term memory for each cookie request packet
received then a simple packet flood would be enough to achieve an effective
denial of service attack by making the program run out of memory.

cookie request packet (145 bytes):

\begin{verbatim}
[uint8_t 24]
[Sender's DHT Public key (32 bytes)]
[Random nonce (24 bytes)]
[Encrypted message containing:
    [Sender's real public key (32 bytes)]
    [padding (32 bytes)]
    [uint64_t echo id (must be sent back untouched in cookie response)]
]
\end{verbatim}

Encrypted message is encrypted with sender's DHT private key, receiver's DHT
public key and the nonce.

\begin{code}
-- | Cookie Request Packet (0x18 / 24).
data CookieRequest = CookieRequest
  { crSenderDhtPk      :: PublicKey
  , crNonce            :: Nonce
  , crEncryptedMessage :: CipherText -- ^ Decrypts to crInnerMessage
  } deriving (Eq, Show, Generic)

instance Binary CookieRequest where
  put cr = do
    Binary.put $ crSenderDhtPk cr
    Binary.put $ crNonce cr
    Binary.put $ crEncryptedMessage cr
  get = CookieRequest <$> Binary.get <*> Binary.get <*> Binary.get

-- | Inner message of a Cookie Request.
data CookieRequestInner = CookieRequestInner
  { criSenderRealPk :: PublicKey
  , criPadding      :: BS.ByteString -- ^ 32 bytes
  , criEchoId       :: Word64
  } deriving (Eq, Show, Generic)

instance Binary CookieRequestInner where
  put cri = do
    Binary.put $ criSenderRealPk cri
    Put.putByteString $ criPadding cri
    Put.putWord64be $ criEchoId cri
  get = CookieRequestInner <$> Binary.get <*> Get.getByteString 32 <*> Get.getWord64be
\end{code}

The packet id for cookie request packets is 24.  The request contains the DHT
public key of the sender which is the key used (The DHT private key) (along
with the DHT public key of the receiver) to encrypt the encrypted part of the
cookie packet and a nonce also used to encrypt the encrypted part of the
packet.  Padding is used to maintain backwards-compatibility with previous
versions of the protocol.  The echo id in the cookie request must be sent back
untouched in the cookie response.  This echo id is how the peer sending the
request can be sure that the response received was a response to the packet
that he sent.

The reason for sending the DHT public key and real public key in the cookie
request is that both are contained in the cookie sent back in the response.

Toxcore currently sends 1 cookie request packet every second 8 times before it
kills the connection if there are no responses.

cookie response packet (161 bytes):

\begin{verbatim}
[uint8_t 25]
[Random nonce (24 bytes)]
[Encrypted message containing:
    [Cookie]
    [uint64_t echo id (that was sent in the request)]
]
\end{verbatim}

Encrypted message is encrypted with the exact same symmetric key as the cookie
request packet it responds to but with a different nonce.

\begin{code}
-- | Cookie Response Packet (0x19 / 25).
data CookieResponse = CookieResponse
  { rsNonce            :: Nonce
  , rsEncryptedMessage :: CipherText -- ^ Decrypts to rsInnerMessage
  } deriving (Eq, Show, Generic)

instance Binary CookieResponse where
  put rs = do
    Binary.put $ rsNonce rs
    Binary.put $ rsEncryptedMessage rs
  get = CookieResponse <$> Binary.get <*> Binary.get

-- | Inner message of a Cookie Response.
data CookieResponseInner = CookieResponseInner
  { rsiCookie :: Cookie
  , rsiEchoId :: Word64
  } deriving (Eq, Show, Generic)

instance Binary CookieResponseInner where
  put rsi = do
    Binary.put $ rsiCookie rsi
    Put.putWord64be $ rsiEchoId rsi
  get = CookieResponseInner <$> Binary.get <*> Get.getWord64be
\end{code}

The packet id for cookie request packets is 25.  The response contains a nonce
and an encrypted part encrypted with the nonce.  The encrypted part is
encrypted with the same key used to decrypt the encrypted part of the request
meaning the expensive shared key generation needs to be called only once in
order to handle and respond to a cookie request packet with a cookie response.

The Cookie (see below) and the echo id that was sent in the request are the
contents of the encrypted part.

The Cookie should be (112 bytes):

\begin{verbatim}
[nonce]
[encrypted data:
    [uint64_t time]
    [Sender's real public key (32 bytes)]
    [Sender's DHT public key (32 bytes)]
]
\end{verbatim}

The cookie is a 112 byte piece of data that is created and sent to the
requester as part of the cookie response packet.  A peer who wants to connect
to another must obtain a cookie packet from the peer they are trying to connect
to.  The only way to send a valid handshake packet to another peer is to first
obtain a cookie from them.

\begin{code}
-- | Cookie structure (112 bytes).
data Cookie = Cookie
  { cookieNonce            :: Nonce
  , cookieEncryptedPayload :: CipherText -- ^ Decrypts to cookieInner
  } deriving (Eq, Show, Generic)

instance Binary Cookie where
  put c = do
    Binary.put $ cookieNonce c
    Binary.put $ cookieEncryptedPayload c
  get = Cookie <$> Binary.get <*> Binary.get

-- | Inner payload of a Cookie.
data CookieInner = CookieInner
  { ciTime        :: Word64
  , ciSenderRealPk :: PublicKey
  , ciSenderDhtPk  :: PublicKey
  } deriving (Eq, Show, Generic)

instance Binary CookieInner where
  put ci = do
    Put.putWord64be $ ciTime ci
    Binary.put $ ciSenderRealPk ci
    Binary.put $ ciSenderDhtPk ci
  get = CookieInner <$> Get.getWord64be <*> Binary.get <*> Binary.get
\end{code}

The cookie contains information that will both prove to the receiver of the
handshake that the peer has received a cookie response and contains encrypted
info that tell the receiver of the handshake packet enough info to both decrypt
and validate the handshake packet and accept the connection.

When toxcore is started it generates a symmetric encryption key that it uses to
encrypt and decrypt all cookie packets (using NaCl authenticated encryption
exactly like encryption everywhere else in toxcore).  Only the instance of
toxcore that create the packets knows the encryption key meaning any cookie it
successfully decrypts and validates were created by it.

The time variable in the cookie is used to prevent cookie packets that are too
old from being used.  Toxcore has a time out of 15 seconds for cookie packets.
If a cookie packet is used more than 15 seconds after it is created toxcore
will see it as invalid.

When responding to a cookie request packet the sender's real public key is the
known key sent by the peer in the encrypted part of the cookie request packet
and the senders DHT public key is the key used to encrypt the encrypted part of
the cookie request packet.

When generating a cookie to put inside the encrypted part of the handshake: One
of the requirements to connect successfully to someone else is that we know
their DHT public key and their real long term public key meaning there is
enough information to construct the cookie.

Handshake packet:

\begin{verbatim}
[uint8_t 26]
[Cookie]
[nonce (24 bytes)]
[Encrypted message containing:
    [24 bytes base nonce]
    [session public key of the peer (32 bytes)]
    [sha512 hash of the entire Cookie sitting outside the encrypted part]
    [Other Cookie (used by the other to respond to the handshake packet)]
]
\end{verbatim}

\begin{code}
-- | Handshake Packet (0x1a / 26).
data Handshake = Handshake
  { hCookie          :: Cookie
  , hNonce           :: Nonce
  , hEncryptedMessage :: CipherText -- ^ Decrypts to hInnerMessage
  } deriving (Eq, Show, Generic)

instance Binary Handshake where
  put h = do
    Binary.put $ hCookie h
    Binary.put $ hNonce h
    Binary.put $ hEncryptedMessage h
  get = Handshake <$> Binary.get <*> Binary.get <*> Binary.get

-- | Inner message of a Handshake.
data HandshakeInner = HandshakeInner
  { hiBaseNonce   :: Nonce
  , hiSessionPk   :: PublicKey
  , hiCookieHash  :: BS.ByteString -- ^ 64 bytes (SHA512)
  , hiOtherCookie :: Cookie
  } deriving (Eq, Show, Generic)

instance Binary HandshakeInner where
  put hi = do
    Binary.put $ hiBaseNonce hi
    Binary.put $ hiSessionPk hi
    Put.putByteString $ hiCookieHash hi
    Binary.put $ hiOtherCookie hi
  get = HandshakeInner <$> Binary.get <*> Binary.get <*> Get.getByteString 64 <*> Binary.get
\end{code}

The packet id for handshake packets is 26.  The cookie is a cookie obtained by
sending a cookie request packet to the peer and getting a cookie response
packet with a cookie in it.  It may also be obtained in the handshake packet by
a peer receiving a handshake packet (Other Cookie).

The nonce is a nonce used to encrypt the encrypted part of the handshake
packet.  The encrypted part of the handshake packet is encrypted with the long
term keys of both peers.  This is to prevent impersonation.

Inside the encrypted part of the handshake packet there is a 'base nonce' and a
session public key.  The 'base nonce' is a nonce that the other should use to
encrypt each data packet, adding + 1 to it for each data packet sent.  (first
packet is 'base nonce' + 0, next is 'base nonce' + 1, etc.  Note that for
mathematical operations the nonce is considered to be a 24 byte number in big
endian format).  The session key is the temporary connection public key that
the peer has generated for this connection and it sending to the other.  This
session key is used so that the connection has perfect forward secrecy.  It is
important to save the private key counterpart of the session public key sent in
the handshake, the public key received by the other and both the received and
sent base nonces as they are used to encrypt/decrypt the data packets.

The hash of the cookie in the encrypted part is used to make sure that an
attacker has not taken an older valid handshake packet and then replaced the
cookie packet inside with a newer one which would be bad as they could replay
it and might be able to make a mess.

The 'Other Cookie' is a valid cookie that we put in the handshake so that the
other can respond with a valid handshake without having to make a cookie
request to obtain one.

The handshake packet is sent by both sides of the connection.  If a peer
receives a handshake it will check if the cookie is valid, if the encrypted
section decrypts and validates, if the cookie hash is valid, if long term
public key belongs to a known friend.  If all these are true then the
connection is considered 'Accepted' but not 'Confirmed'.

If there is no existing connection to the peer identified by the long term
public key to set to 'Accepted', one will be created with that status.  If a
connection to such peer with a not yet 'Accepted' status to exists, this
connection is set to accepted.  If a connection with a 'Confirmed' status
exists for this peer, the handshake packet will be ignored and discarded (The
reason for discarding it is that we do not want slightly late handshake packets
to kill the connection) except if the DHT public key in the cookie contained in
the handshake packet is different from the known DHT public key of the peer.
If this happens the connection will be immediately killed because it means it
is no longer valid and a new connection will be created immediately with the
'Accepted' status.

Sometimes toxcore might receive the DHT public key of the peer first with a
handshake packet so it is important that this case is handled and that the
implementation passes the DHT public key to the other modules (DHT,
\texttt{TCP\_connection}) because this does happen.

Handshake packets must be created only once during the connection but must be
sent in intervals until we are sure the other received them.  This happens when
a valid encrypted data packet is received and decrypted.

The states of a connection:

\begin{enumerate}
  \item Not accepted: Send handshake packets.

  \item Accepted: A handshake packet has been received from the other peer but
    no encrypted packets: continue (or start) sending handshake packets because
    the peer can't know if the other has received them.

  \item Confirmed: A valid encrypted packet has been received from the other
    peer: Connection is fully established: stop sending handshake packets.
\end{enumerate}

Toxcore sends handshake packets every second 8 times and times out the
connection if the connection does not get confirmed (no encrypted packet is
received) within this time.

Perfect handshake scenario:

\begin{verbatim}
Peer 1                Peer 2
Cookie request   ->
                      <- Cookie response
Handshake packet ->
                      * accepts connection
                      <- Handshake packet
*accepts connection
Encrypted packet ->   <- Encrypted packet
*confirms connection  *confirms connection
       Connection successful.
Encrypted packets -> <- Encrypted packets

More realistic handshake scenario:
Peer 1                Peer 2
Cookie request   ->   *packet lost*
Cookie request   ->
                      <- Cookie response
                      *Peer 2 randomly starts new connection to peer 1
                      <- Cookie request
Cookie response  ->
Handshake packet ->   <- Handshake packet
*accepts connection   * accepts connection
Encrypted packet ->   <- Encrypted packet
*confirms connection  *confirms connection
       Connection successful.
Encrypted packets -> <- Encrypted packets
\end{verbatim}

The reason why the handshake is like this is because of certain design
requirements:

\begin{enumerate}
  \item The handshake must not leak the long term public keys of the peers to a
     possible attacker who would be looking at the packets but each peer must know
     for sure that they are connecting to the right peer and not an impostor.
  \item A connection must be able of being established if only one of the peers has
     the information necessary to initiate a connection (DHT public key of the
     peer and a link to the peer).
  \item If both peers initiate a connection to each other at the same time the
     connection must succeed without issues.
  \item There must be perfect forward secrecy.
  \item Must be resistant to any possible attacks.
\end{enumerate}

Due to how it is designed only one connection is possible at a time between 2
peers.

Encrypted packets:

\begin{tabular}{l|l}
  Length             & Contents \\
  \hline
  \texttt{1}         & \texttt{uint8\_t} (0x1b) \\
  \texttt{2}         & \texttt{uint16\_t} The last 2 bytes of the nonce used to encrypt this \\
  variable           & Payload \\
\end{tabular}

\begin{code}
-- | Encrypted Packet (0x1b / 27).
data CryptoDataPacket = CryptoDataPacket
  { cdNonceShort :: Word16 -- ^ Last 2 bytes of the nonce
  , cdPayload    :: CipherText
  } deriving (Eq, Show, Generic)

instance Binary CryptoDataPacket where
  put cd = do
    Put.putWord16be $ cdNonceShort cd
    Binary.put $ cdPayload cd
  get = CryptoDataPacket <$> Get.getWord16be <*> Binary.get
\end{code}

The payload is encrypted with the session key and 'base nonce' set by the
receiver in their handshake + packet number (starting at 0, big endian math).

The packet id for encrypted packets is 27.  Encrypted packets are the packets
used to send data to the other peer in the connection.  Since these packets can
be sent over UDP the implementation must assume that they can arrive out of
order or even not arrive at all.

To get the key used to encrypt/decrypt each packet in the connection a peer
takes the session public key received in the handshake and the private key
counterpart of the key it sent it the handshake and generates a shared key from
it.  This shared key will be identical for both peers.  It is important to note
that connection keys must be wiped when the connection is killed.

To create an encrypted packet to be sent to the other peer, the data is
encrypted with the shared key for this connection and the base nonce that the
other peer sent in the handshake packet with the total number of encrypted
packets sent in the connection added to it ('base nonce' + 0 for the first
encrypted data packet sent, 'base nonce' + 1 for the second, etc.  Note that
the nonce is treated as a big endian number for mathematical operations like
additions).  The 2 byte (\texttt{uint16\_t}) number at the beginning of the
encrypted packet is the last 2 bytes of this 24 byte nonce.

To decrypt a received encrypted packet, the nonce the packet was encrypted with
is calculated using the base nonce that the peer sent to the other and the 2
byte number at the beginning of the packet.  First we assume that packets will
most likely arrive out of order and that some will be lost but that packet loss
and out of orderness will never be enough to make the 2 byte number need an
extra byte.  The packet is decrypted using the shared key for the connection
and the calculated nonce.

Toxcore uses the following method to calculate the nonce for each packet:

\begin{enumerate}
  \item \texttt{diff} = (2 byte number on the packet) - (last 2 bytes of the current saved
     base nonce) NOTE: treat the 3 variables as 16 bit unsigned ints, the result
     is expected to sometimes roll over.
  \item copy \texttt{saved\_base\_nonce} to \texttt{temp\_nonce}.
  \item \texttt{temp\_nonce = temp\_nonce + diff}.  \texttt{temp\_nonce} is the correct nonce that
     can be used to decrypt the packet.
  \item \texttt{DATA\_NUM\_THRESHOLD} = (1/3 of the maximum number that can be stored in an
     unsigned 2 bit integer)
  \item if decryption succeeds and \texttt{diff > (DATA\_NUM\_THRESHOLD * 2)} then:
    \begin{itemize}
      \item \texttt{saved\_base\_nonce = saved\_base\_nonce + DATA\_NUM\_THRESHOLD}
    \end{itemize}
\end{enumerate}

\begin{code}
{-------------------------------------------------------------------------------
 -
 - :: State Definitions.
 -
 ------------------------------------------------------------------------------}

data HandshakeStatus
  = SessionCookieSent Word64 -- ^ Echo ID
  | SessionHandshakeSent Cookie
  | SessionHandshakeAccepted Cookie -- ^ Received handshake from peer
  | SessionConfirmed -- ^ Received data packet, session established
  deriving (Eq, Show, Generic)

data SecureSessionState = SecureSessionState
  { ssOurRealKeyPair      :: KeyPair
  , ssPeerRealPk          :: PublicKey
  , ssOurDhtKeyPair       :: KeyPair
  , ssPeerDhtPk           :: PublicKey
  , ssPeerNodeInfo        :: NodeInfo
  , ssStatus              :: Maybe HandshakeStatus
  , ssOurSessionKeyPair   :: KeyPair
  , ssPeerSessionPk       :: Maybe PublicKey
  , ssSharedKey           :: Maybe CombinedKey
  , ssOurBaseNonce        :: Nonce
  , ssPeerBaseNonce       :: Maybe Nonce
  , ssSentPackets         :: Word64
  , ssRecvPackets         :: Word64
  , ssLastAttempt         :: Maybe Timestamp
  , ssRetryCount          :: Int
  , ssReliability         :: Reliability.ReliabilityState
  , ssStream              :: Stream.StreamState
  } deriving (Eq, Show, Generic)


{-------------------------------------------------------------------------------
 -
 - :: Cookie Logic.
 -
 ------------------------------------------------------------------------------}

-- | Create a Cookie for a peer.
createCookie :: MonadRandomBytes m => CombinedKey -> Word64 -> PublicKey -> PublicKey -> m Cookie
createCookie cookieKey time peerRealPk peerDhtPk = do
  nonce <- randomNonce
  let inner = CookieInner time peerRealPk peerDhtPk
      plain = Box.encode inner
      encrypted = Box.encrypt cookieKey nonce plain
  return $ Cookie nonce encrypted

-- | Decrypt and validate a Cookie.
decryptCookie :: CombinedKey -> Cookie -> Maybe CookieInner
decryptCookie cookieKey (Cookie nonce encrypted) =
  Box.decrypt cookieKey nonce encrypted >>= Box.decode


{-------------------------------------------------------------------------------
 -
 - :: CryptoData Packet Logic.
 -
 ------------------------------------------------------------------------------}

-- | Threshold for base nonce rotation (1/3 of 65536).
dataNumThreshold :: Word16
dataNumThreshold = 21845

-- | Calculate the full nonce for a received packet.
calculateNonce :: Nonce -> Word16 -> Nonce
calculateNonce baseNonce shortNonce =
  let
    n = Nonce.nonceToInteger baseNonce
    baseShort = fromIntegral (n `mod` 65536)
    diff = shortNonce - baseShort
    -- treat diff as signed 16-bit to handle wrap around
    n' = n + fromIntegral (fromIntegral diff :: Int16)
  in
    Nonce.integerToNonce n'

-- | Update the base nonce after successful decryption if necessary.
updateBaseNonce :: Nonce -> Word16 -> Nonce
updateBaseNonce baseNonce shortNonce =
  let
    n = Nonce.nonceToInteger baseNonce
    baseShort = fromIntegral (n `mod` 65536)
    diff = shortNonce - baseShort
  in
    if diff > dataNumThreshold * 2
    then Nonce.integerToNonce (n + fromIntegral dataNumThreshold)
    else baseNonce


{-------------------------------------------------------------------------------
 -
 - :: Cryptographic Helpers.
 -
 ------------------------------------------------------------------------------}

getDhtSharedKey :: Keyed m => SecureSessionState -> m CombinedKey
getDhtSharedKey ss = getCombinedKey (KeyPair.secretKey $ ssOurDhtKeyPair ss) (ssPeerDhtPk ss)

getRealSharedKey :: Keyed m => SecureSessionState -> m CombinedKey
getRealSharedKey ss = getCombinedKey (KeyPair.secretKey $ ssOurRealKeyPair ss) (ssPeerRealPk ss)

getSessionSharedKey :: Keyed m => SecureSessionState -> m CombinedKey
getSessionSharedKey ss = case ssPeerSessionPk ss of
  Nothing -> error "getSessionSharedKey: peer session pk not set"
  Just pk -> getCombinedKey (KeyPair.secretKey $ ssOurSessionKeyPair ss) pk


{-------------------------------------------------------------------------------
 -
 - :: Session Handlers.
 -
 ------------------------------------------------------------------------------}

-- | Initial state for a new session.
-- | Initial state for a new session.
initSession :: MonadRandomBytes m => Timestamp -> KeyPair -> PublicKey -> KeyPair -> PublicKey -> NodeInfo -> m SecureSessionState
initSession now ourRealKp peerRealPk ourDhtKp peerDhtPk peerNode = do
  ourSessionKp <- newKeyPair
  ourBaseNonce <- randomNonce
  return SecureSessionState
    { ssOurRealKeyPair    = ourRealKp
    , ssPeerRealPk        = peerRealPk
    , ssOurDhtKeyPair     = ourDhtKp
    , ssPeerDhtPk         = peerDhtPk
    , ssPeerNodeInfo      = peerNode
    , ssStatus            = Nothing
    , ssOurSessionKeyPair = ourSessionKp
    , ssPeerSessionPk     = Nothing
    , ssSharedKey           = Nothing
    , ssOurBaseNonce      = ourBaseNonce
    , ssPeerBaseNonce       = Nothing
    , ssSentPackets       = 0
    , ssRecvPackets       = 0
    , ssLastAttempt         = Nothing
    , ssRetryCount        = 0
    , ssReliability       = Reliability.initState
    , ssStream              = Stream.initState now
    }


sendCookieRequest :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                  => m ()
sendCookieRequest = do
  ss <- get
  nonce <- randomNonce
  echoId <- randomWord64
  dhtSharedKey <- getDhtSharedKey ss
  
  let cri = CookieRequestInner (KeyPair.publicKey $ ssOurRealKeyPair ss) (BS.replicate 32 0) echoId
      plain = Box.encode cri
      encrypted = Box.encrypt dhtSharedKey nonce plain
      cr = CookieRequest (KeyPair.publicKey $ ssOurDhtKeyPair ss) nonce encrypted
      pkt = Packet PacketKind.CookieRequest (LBS.toStrict $ Binary.encode cr)
  
  sendPacket (ssPeerNodeInfo ss) pkt
  modify $ \s -> s { ssStatus = Just (SessionCookieSent echoId) }

-- | Handle an incoming packet for this session.
handlePacket :: (Timed m, MonadRandomBytes m, Keyed m, Networked m, MonadState SecureSessionState m)
             => CombinedKey -> NodeInfo -> Packet BS.ByteString -> m ()
handlePacket ck from (Packet kind payload) = case kind of
  PacketKind.CookieResponse -> handleCookieResponse from payload
  PacketKind.CryptoHandshake -> handleHandshake ck from payload
  PacketKind.CryptoData -> handleCryptoData from payload
  _ -> return ()

-- | Handle a CookieRequest (Server side).
handleCookieRequest :: (Timed m, MonadRandomBytes m, Keyed m, Networked m)
                    => CombinedKey -> KeyPair -> NodeInfo -> BS.ByteString -> m ()
handleCookieRequest cookieKey ourDhtKp from payload = do
  case Box.decode (Box.PlainText payload) of
    Nothing -> return ()
    Just (cr :: CookieRequest) -> do
      now <- askTime
      let timeInt = timestampToMicroseconds now
      
      sharedKey <- getCombinedKey (KeyPair.secretKey ourDhtKp) (crSenderDhtPk cr)
      case Box.decrypt sharedKey (crNonce cr) (crEncryptedMessage cr) of
        Nothing -> return ()
        Just plain -> case Box.decode plain of
          Nothing -> return ()
          Just (cri :: CookieRequestInner) -> do
            cookie <- createCookie cookieKey timeInt (criSenderRealPk cri) (crSenderDhtPk cr)
            nonce <- randomNonce
            
            let rsi = CookieResponseInner cookie (criEchoId cri)
                plainR = Box.encode rsi
                encryptedR = Box.encrypt sharedKey nonce plainR
                rs = CookieResponse nonce encryptedR
                pkt = Packet PacketKind.CookieResponse (LBS.toStrict $ Binary.encode rs)
            
            sendPacket from pkt

handleCookieResponse :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                     => NodeInfo -> BS.ByteString -> m ()
handleCookieResponse _from payload = do
  ss <- get
  case Box.decode (Box.PlainText payload) of
    Nothing -> return ()
    Just (rs :: CookieResponse) -> do
      sharedKey <- getDhtSharedKey ss
      case Box.decrypt sharedKey (rsNonce rs) (rsEncryptedMessage rs) of
        Nothing -> return ()
        Just plain -> case Box.decode plain of
          Nothing -> return ()
          Just (rsi :: CookieResponseInner) -> do
            case ssStatus ss of
              Just (SessionCookieSent echoId) | echoId == rsiEchoId rsi -> do
                modify $ \s -> s { ssStatus = Just (SessionHandshakeSent (rsiCookie rsi)) }
                sendHandshake (rsiCookie rsi)
              _ -> return ()

sendHandshake :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
              => Cookie -> m ()
sendHandshake cookie = do
  ss <- get
  nonce <- randomNonce
  realSharedKey <- getRealSharedKey ss
  
  let cookieBytes = LBS.toStrict $ Binary.encode cookie
      cookieHash = Hash.hash cookieBytes
      hi = HandshakeInner (ssOurBaseNonce ss) (KeyPair.publicKey $ ssOurSessionKeyPair ss) cookieHash cookie -- FIXME: hiOtherCookie
      plain = Box.encode hi
      encrypted = Box.encrypt realSharedKey nonce plain
      h = Handshake cookie nonce encrypted
      pkt = Packet PacketKind.CryptoHandshake (LBS.toStrict $ Binary.encode h)

  sendPacket (ssPeerNodeInfo ss) pkt

handleHandshake :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                => CombinedKey -> NodeInfo -> BS.ByteString -> m ()
handleHandshake cookieK from payload = do
  ss <- get
  case Box.decode (Box.PlainText payload) of
    Nothing -> return ()
    Just (h :: Handshake) -> do
      -- 1. Validate our Cookie
      now <- askTime
      case decryptCookie cookieK (hCookie h) of
        Nothing -> return () -- Not our cookie
        Just ci -> do
          let ciTimestamp = Timestamp $ Clock.TimeSpec (fromIntegral $ ciTime ci `div` 1000000) (fromIntegral $ (ciTime ci `mod` 1000000) * 1000)
              age = now `Time.diffTime` ciTimestamp
          
          if age > Time.seconds 15
          then return () -- Expired
          else do
            -- 2. Decrypt Handshake
            realSharedKey <- getRealSharedKey ss
            case Box.decrypt realSharedKey (hNonce h) (hEncryptedMessage h) of
              Nothing -> return ()
              Just plain -> case Box.decode plain of
                Nothing -> return ()
                Just (hi :: HandshakeInner) -> do
                  -- Mobility: update peer address if it changed
                  modify $ \s -> s { ssPeerNodeInfo = from }
                  
                  sharedKey <- getCombinedKey (KeyPair.secretKey $ ssOurSessionKeyPair ss) (hiSessionPk hi)
                  
                  modify $ \s -> s 
                    { ssPeerSessionPk = Just (hiSessionPk hi)
                    , ssPeerBaseNonce = Just (hiBaseNonce hi)
                    , ssSharedKey     = Just sharedKey
                    , ssStatus        = Just (SessionHandshakeAccepted (hCookie h))
                    }
                  
                  case ssStatus ss of
                    Just (SessionHandshakeSent _) -> sendHandshake (hiOtherCookie hi)
                    _ -> return ()

sendCryptoData :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
               => BS.ByteString -> m ()
sendCryptoData msg = do
  ss <- get
  case (ssSharedKey ss, ssPeerBaseNonce ss) of
    (Just sharedKey, Just _) -> do
      now <- askTime
      let (rp, rel') = Reliability.createLossless msg (ssReliability ss)
          -- Packet number for nonce calculation
          Reliability.SeqNum pktNum = Reliability.rpPacketNumber rp
          
          n = ssOurBaseNonce ss
          nonceInt = Nonce.nonceToInteger n
          fullNonce = Nonce.integerToNonce (nonceInt + toInteger pktNum)
          shortNonce = fromIntegral (Nonce.nonceToInteger fullNonce `mod` 65536)
          
          plain = Box.PlainText $ LBS.toStrict $ Binary.encode rp
          encrypted = Box.encrypt sharedKey fullNonce plain
          cd = CryptoDataPacket shortNonce encrypted
          pkt = Packet PacketKind.CryptoData (LBS.toStrict $ Binary.encode cd)
          
          stream' = Stream.recordPacketSent (Reliability.SeqNum pktNum) now (ssStream ss)
      
      sendPacket (ssPeerNodeInfo ss) pkt
      modify $ \s -> s 
        { ssReliability = rel'
        , ssStream = stream'
        , ssSentPackets = ssSentPackets s + 1 
        }
    _ -> return ()

handleCryptoData :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                 => NodeInfo -> BS.ByteString -> m ()
handleCryptoData from payload = do
  ss <- get
  case (ssSharedKey ss, ssPeerBaseNonce ss) of
    (Just sharedKey, Just peerBaseNonce) -> do
      case Box.decode (Box.PlainText payload) of
        Nothing -> return ()
        Just (cd :: CryptoDataPacket) -> do
          let nonce = calculateNonce peerBaseNonce (cdNonceShort cd)
          case Box.decrypt sharedKey nonce (cdPayload cd) of
            Nothing -> return ()
            Just plain -> do
              now <- askTime
              case Binary.decodeOrFail (LBS.fromStrict $ Box.unPlainText plain) of
                Left _ -> return ()
                Right (_, _, rp :: Reliability.ReliablePacket) -> do
                  let (rel', delivered) = Reliability.handleIncoming rp (ssReliability ss)
                      ackStart = Reliability.rpRecvBufferStart rp
                      stream' = foldr (\s st -> Stream.recordPacketAcked s now st) (ssStream ss) 
                                  [s | s <- Map.keys (Reliability.rsSendWindow (ssReliability ss)), s < ackStart]

                  -- Handle PacketRequests and other delivered payloads
                  (rel'', stream'') <- foldM (processDelivered from) (rel', stream') delivered

                  modify $ \s -> s 
                    { ssStatus = Just SessionConfirmed
                    , ssRecvPackets = ssRecvPackets s + 1
                    , ssPeerBaseNonce = Just (updateBaseNonce peerBaseNonce (cdNonceShort cd))
                    , ssPeerNodeInfo = from -- Update for mobility
                    , ssReliability = rel''
                    , ssStream = stream''
                    }
    _ -> return ()

  where
    processDelivered peer (rel, stream) delPayload = do
      ss <- get
      case BS.uncons delPayload of
        Just (1, _) -> -- Packet Request
          case Binary.decodeOrFail (LBS.fromStrict delPayload) of
            Left _ -> return (rel, stream)
            Right (_, _, pr :: Reliability.PacketRequest) -> do
              let (toResend, rel') = Reliability.handlePacketRequest pr rel
              case (ssSharedKey ss, ssPeerBaseNonce ss) of
                (Just sharedKey, Just _) -> do
                  forM_ toResend $ \rp -> do
                    let Reliability.SeqNum pktNum = Reliability.rpPacketNumber rp
                        n = ssOurBaseNonce ss
                        nonceInt = Nonce.nonceToInteger n
                        fullNonce = Nonce.integerToNonce (nonceInt + toInteger pktNum)
                        shortNonce = fromIntegral (Nonce.nonceToInteger fullNonce `mod` 65536)
                        
                        plain = Box.PlainText $ LBS.toStrict $ Binary.encode rp
                        encrypted = Box.encrypt sharedKey fullNonce plain
                        cd = CryptoDataPacket shortNonce encrypted
                        pkt = Packet PacketKind.CryptoData (LBS.toStrict $ Binary.encode cd)
                    sendPacket peer pkt
                  return (rel', stream)
                _ -> return (rel', stream)
        _ -> return (rel, stream) -- TODO: pass other packets to application layer

-- | Periodically maintain the session (handshake retries, timeouts).
maintainSession :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                => m ()
maintainSession = do
  ss <- get
  now <- askTime
  let lastAttempt = ssLastAttempt ss
      elapsed = case lastAttempt of
        Nothing -> Time.seconds 9999 -- Force first attempt
        Just t  -> now `Time.diffTime` t
  
  -- Retry every 1 second
  when (elapsed >= Time.seconds 1) $ do
    case ssStatus ss of
      Nothing -> do
        sendCookieRequest
        updateAttempt now
      
      Just (SessionCookieSent _) -> do
        if ssRetryCount ss < 8
        then sendCookieRequest >> updateAttempt now
        else resetSession -- Failed to get cookie
      
      Just (SessionHandshakeSent cookie) -> do
        if ssRetryCount ss < 8
        then sendHandshake cookie >> updateAttempt now
        else resetSession -- Failed to confirm handshake
      
      Just (SessionHandshakeAccepted cookie) -> do
        -- Peer accepted us, but we haven't seen a data packet yet.
        -- Keep sending handshake to make sure they get it.
        if ssRetryCount ss < 8
        then sendHandshake cookie >> updateAttempt now
        else resetSession
        
      Just SessionConfirmed -> do
        -- Session is live. Maintenance for reliability layer.
        sendPacketRequests
        -- Update stream send rate
        modify $ \s -> s { ssStream = Stream.updateSendRate (Map.size (Reliability.rsSendWindow (ssReliability s))) now (ssStream s) }

  where
    updateAttempt now = modify $ \s -> s { ssLastAttempt = Just now, ssRetryCount = ssRetryCount s + 1 }
    resetSession = modify $ \s -> s { ssStatus = Nothing, ssRetryCount = 0, ssLastAttempt = Nothing }

-- | Send a packet request if the reliability layer detects missing packets.
sendPacketRequests :: (MonadState SecureSessionState m, Timed m, MonadRandomBytes m, Keyed m, Networked m)
                   => m ()
sendPacketRequests = do
  ss <- get
  case Reliability.createPacketRequest (ssReliability ss) of
    Nothing -> return ()
    Just pr -> do
      now <- askTime
      -- PacketRequest is sent as a LOSSY packet (Data ID 1)
      case (ssSharedKey ss, ssPeerBaseNonce ss) of
        (Just sharedKey, Just _) -> do
          -- For lossy packets, the spec says to use 'sendbuffer buffer_end' as the second 4-byte number.
          -- In our reliability state, that's rsNextSendSeq.
          let nextSeq = Reliability.rsNextSendSeq (ssReliability ss)
              Reliability.SeqNum pktNum = nextSeq
              
              n = ssOurBaseNonce ss
              nonceInt = Nonce.nonceToInteger n
              fullNonce = Nonce.integerToNonce (nonceInt + toInteger pktNum)
              shortNonce = fromIntegral (Nonce.nonceToInteger fullNonce `mod` 65536)
              
              -- Payload for ReliablePacket: [Data ID 1][reconstructed request]
              -- Reliability.put for PacketRequest already includes the ID 1.
              prPayload = LBS.toStrict $ Binary.encode pr
              
              rp = Reliability.ReliablePacket
                { Reliability.rpRecvBufferStart = Reliability.rsNextRecvSeq (ssReliability ss)
                , Reliability.rpPacketNumber    = nextSeq
                , Reliability.rpIsLossless      = False
                , Reliability.rpPayload         = prPayload
                }
              
              plain = Box.PlainText $ LBS.toStrict $ Binary.encode rp
              encrypted = Box.encrypt sharedKey fullNonce plain
              cd = CryptoDataPacket shortNonce encrypted
              pkt = Packet PacketKind.CryptoData (LBS.toStrict $ Binary.encode cd)
          
          sendPacket (ssPeerNodeInfo ss) pkt
          -- Update congestion state
          modify $ \s -> s { ssStream = Stream.recordCongestion now (ssStream s) }
        _ -> return ()
\end{code}

First it takes the difference between the 2 byte number on the packet and the
last.  Because the 3 values are unsigned 16 bit ints and rollover is part of
the math something like diff = (10 - 65536) means diff is equal to 11.

Then it copies the saved base nonce to a temp nonce buffer.

Then it adds diff to the nonce (the nonce is in big endian format).

After if decryption was successful it checks if diff was bigger than 2/3 of the
value that can be contained in a 16 bit unsigned int and increases the saved
base nonce by 1/3 of the maximum value if it succeeded.

This is only one of many ways that the nonce for each encrypted packet can be
calculated.

Encrypted packets that cannot be decrypted are simply dropped.

The reason for exchanging base nonces is because since the key for encrypting
packets is the same for received and sent packets there must be a cryptographic
way to make it impossible for someone to do an attack where they would replay
packets back to the sender and the sender would think that those packets came
from the other peer.