\begin{code}
{-# LANGUAGE StrictData                 #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Tox.Transport.Reliability where

import           Data.Binary               (Binary, get, put)
import qualified Data.Binary.Get           as Get
import qualified Data.Binary.Put           as Put
import           Data.Word                 (Word32, Word8)
import           Data.Map                  (Map)
import qualified Data.Map                  as Map
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as LBS

-- | Sequence Number (32-bit with wrap-around).
newtype SeqNum = SeqNum Word32
  deriving (Eq, Binary, Show, Num, Enum)

-- | Custom ordering for sequence numbers to handle rollover.
-- A sequence number 'a' is considered less than 'b' if it is within
-- the first half of the 32-bit space following 'a' (circularly).
instance Ord SeqNum where
  compare (SeqNum a) (SeqNum b)
    | a == b = EQ
    | b - a < 0x80000000 = LT
    | otherwise = GT


-- | Header for reliable transport (lossy or lossless).
data ReliablePacket = ReliablePacket
  { rpRecvBufferStart :: SeqNum -- ^ Our next expected recv packet number
  , rpPacketNumber    :: SeqNum -- ^ This packet's number (lossless) or next seq (lossy)
  , rpIsLossless      :: Bool   -- ^ Discriminator for packet type
  , rpPayload         :: BS.ByteString
  } deriving (Eq, Show)

instance Binary ReliablePacket where
  put rp = do
    put $ rpRecvBufferStart rp
    put $ rpPacketNumber rp
    -- The protocol doesn't explicitly flag lossless/lossy in the header,
    -- it relies on the first byte of payload (Data ID) or context.
    -- However, the spec says: "uint32_t packet number if lossless, 
    -- sendbuffer buffer_end if lossy".
    Put.putByteString $ rpPayload rp

  get = do
    recvStart <- get
    pktNum <- get
    payload <- LBS.toStrict <$> Get.getRemainingLazyByteString
    -- Note: rpIsLossless needs to be determined by the caller based on Data ID.
    return $ ReliablePacket recvStart pktNum True payload


-- | State for the reliability layer.
data ReliabilityState = ReliabilityState
  { rsNextSendSeq     :: SeqNum            -- ^ Sequence number for next outgoing lossless packet
  , rsNextRecvSeq     :: SeqNum            -- ^ Sequence number of next expected incoming packet
  , rsPeerNextRecvSeq :: SeqNum            -- ^ Highest contiguous sequence peer has received
  , rsSendWindow      :: Map SeqNum BS.ByteString -- ^ Sent packets awaiting ACK
  , rsRecvWindow      :: Map SeqNum BS.ByteString -- ^ Out-of-order received packets
  } deriving (Eq, Show)

-- | Initial state for a new connection.
initState :: ReliabilityState
initState = ReliabilityState
  { rsNextSendSeq     = 0
  , rsNextRecvSeq     = 0
  , rsPeerNextRecvSeq = 0
  , rsSendWindow      = Map.empty
  , rsRecvWindow      = Map.empty
  }

-- | A request for missing packets.
data PacketRequest = PacketRequest
  { prMissingDeltas :: [Word32] -- ^ Deltas from the last missing packet
  } deriving (Eq, Show)

instance Binary PacketRequest where
  put pr = do
    Put.putWord8 1 -- ID for packet request
    mapM_ putDelta (prMissingDeltas pr)
    where
      putDelta d | d < 255 = Put.putWord8 (fromIntegral d)
      putDelta d = do
        Put.putWord8 0
        putDelta (d - 255)

  get = do
    _ <- Get.getWord8 -- Skip ID
    deltas <- getDeltas
    return $ PacketRequest deltas
    where
      getDeltas = do
        empty <- Get.isEmpty
        if empty then return [] else do
          d <- Get.getWord8
          if d == 0
            then do
              ds <- getDeltas
              case ds of
                []     -> return [255]
                (x:xs) -> return (x + 255 : xs)
            else (fromIntegral d :) <$> getDeltas


-- | Process an incoming reliable packet.
-- Returns the updated state and any newly deliverable payloads.
handleIncoming :: ReliablePacket -> ReliabilityState -> (ReliabilityState, [BS.ByteString])
handleIncoming pkt state =
  let
    -- 1. Peer is telling us they received everything before rpRecvBufferStart pkt
    -- Clear acknowledged packets from our send window
    (_, remainingSend) = Map.partitionWithKey (\k _ -> k < rpRecvBufferStart pkt) (rsSendWindow state)
    
    -- 2. Buffer this packet if it's new and in/after our window
    newRecvWindow = if rpPacketNumber pkt >= rsNextRecvSeq state && Map.notMember (rpPacketNumber pkt) (rsRecvWindow state)
                    then Map.insert (rpPacketNumber pkt) (rpPayload pkt) (rsRecvWindow state)
                    else rsRecvWindow state
    
    -- 3. Pull deliverable packets from the recv window
    (deliverable, finalRecvWindow, finalNextRecvSeq) = extractDeliverable (rsNextRecvSeq state) newRecvWindow
    
    newState = state
      { rsSendWindow  = remainingSend
      , rsRecvWindow  = finalRecvWindow
      , rsNextRecvSeq = finalNextRecvSeq
      }
  in
    (newState, deliverable)


-- | Generate a request for all currently missing packets in our recv window.
createPacketRequest :: ReliabilityState -> Maybe PacketRequest
createPacketRequest state =
  case Map.keys (rsRecvWindow state) of
    [] -> Nothing
    keys -> 
      let highest = maximum keys
          allExpected = [rsNextRecvSeq state .. highest]
          missing = filter (`Map.notMember` rsRecvWindow state) allExpected
      in if null missing 
         then Nothing 
         else Just $ PacketRequest $ calculateDeltas (rsNextRecvSeq state) missing
  where
    calculateDeltas _ [] = []
    calculateDeltas prev (x:xs) = 
      let SeqNum lastVal = prev
          SeqNum xVal = x
      in (xVal - lastVal) : calculateDeltas x xs


-- | Pull contiguous packets from the recv window starting at 'next'.
extractDeliverable :: SeqNum -> Map SeqNum BS.ByteString -> ([BS.ByteString], Map SeqNum BS.ByteString, SeqNum)
extractDeliverable next window =
  case Map.lookup next window of
    Nothing -> ([], window, next)
    Just payload ->
      let (rest, finalWindow, finalNext) = extractDeliverable (next + 1) (Map.delete next window)
      in (payload : rest, finalWindow, finalNext)


-- | Create a new outgoing lossless packet.
createLossless :: BS.ByteString -> ReliabilityState -> (ReliablePacket, ReliabilityState)
createLossless payload state =
  let
    pktNum = rsNextSendSeq state
    pkt = ReliablePacket
      { rpRecvBufferStart = rsNextRecvSeq state
      , rpPacketNumber    = pktNum
      , rpIsLossless      = True
      , rpPayload         = payload
      }
    newState = state
      { rsNextSendSeq = pktNum + 1
      , rsSendWindow  = Map.insert pktNum payload (rsSendWindow state)
      }
  in
    (pkt, newState)


-- | Process a packet request from the peer and identify packets to resend.
-- Returns the updated state and the list of packets that should be resent.
handlePacketRequest :: PacketRequest -> ReliabilityState -> ([ReliablePacket], ReliabilityState)
handlePacketRequest req state =
  let
    missingSeqs = reconstructMissing (rsNextRecvSeq state) (prMissingDeltas req)
    -- We use our current nextRecvSeq as the base for the resent packets' headers
    toResend = Map.filterWithKey (\k _ -> k `elem` missingSeqs) (rsSendWindow state)
    res packets = Map.foldrWithKey (\s payload acc -> 
      ReliablePacket (rsNextRecvSeq state) s True payload : acc) [] packets
  in
    (res toResend, state)
  where
    reconstructMissing _ [] = []
    reconstructMissing base (d:ds) =
      let SeqNum baseVal = base
          next = SeqNum (baseVal + d)
      in next : reconstructMissing next ds
\end{code}

Data in the encrypted packets:

\begin{verbatim}
[our recvbuffers buffer_start, (highest packet number handled + 1), (big endian)]
[uint32_t packet number if lossless, sendbuffer buffer_end if lossy, (big endian)]
[data]
\end{verbatim}

Encrypted packets may be lossy or lossless.  Lossy packets are simply encrypted
packets that are sent to the other.  If they are lost, arrive in the wrong
order or even if an attacker duplicates them (be sure to take this into account
for anything that uses lossy packets) they will simply be decrypted as they
arrive and passed upwards to what should handle them depending on the data id.

Lossless packets are packets containing data that will be delivered in order by
the implementation of the protocol.  In this protocol, the receiver tells the
sender which packet numbers he has received and which he has not and the sender
must resend any packets that are dropped.  Any attempt at doubling packets will
cause all (except the first received) to be ignored.

Each lossless packet contains both a 4 byte number indicating the highest
packet number received and processed and a 4 byte packet number which is the
packet number of the data in the packet.

In lossy packets, the layout is the same except that instead of a packet
number, the second 4 byte number represents the packet number of a lossless
packet if one were sent right after.  This number is used by the receiver to
know if any packets have been lost.  (for example if it receives 4 packets with
numbers (0, 1, 2, 5) and then later a lossy packet with this second number as:
8 it knows that packets: 3, 4, 6, 7 have been lost and will request them)

How the reliability is achieved:

First it is important to say that packet numbers do roll over, the next number
after 0xFFFFFFFF (maximum value in 4 bytes) is 0.  Hence, all the mathematical
operations dealing with packet numbers are assumed to be done only on unsigned
32 bit integer unless said otherwise.  For example 0 - 0xFFFFFFFF would equal
to 1 because of the rollover.

When sending a lossless packet, the packet is created with its packet number
being the number of the last lossless packet created + 1 (starting at 0).  The
packet numbers are used for both reliability and in ordered delivery and so
must be sequential.

The packet is then stored along with its packet number in order for the peer to
be able to send it again if the receiver does not receive it.  Packets are only
removed from storage when the receiver confirms they have received them.

The receiver receives packets and stores them along with their packet number.
When a receiver receives a packet he stores the packet along with its packet
number in an array.  If there is already a packet with that number in the
buffer, the packet is dropped.  If the packet number is smaller than the last
packet number that was processed, the packet is dropped.  A processed packet
means it was removed from the buffer and passed upwards to the relevant module.

Assuming a new connection, the sender sends 5 lossless packets to the receiver:
0, 1, 2, 3, 4 are the packet numbers sent and the receiver receives: 3, 2, 0, 2
in that order.

The receiver will save the packets and discards the second packet with the
number 2, he has: 0, 2, 3 in his buffer.  He will pass the first packet to the
relevant module and remove it from the array but since packet number 1 is
missing he will stop there.  Contents of the buffer are now: 2, 3.  The
receiver knows packet number 1 is missing and will request it from the sender
by using a packet request packet:

data ids:

\begin{tabular}{l|l}
  ID   & Data \\
  \hline
  0    & padding (skipped until we hit a non zero (data id) byte) \\
  1    & packet request packet (lossy packet) \\
  2    & connection kill packet (lossy packet) \\
  ...  & ... \\
  16+  & reserved for Messenger usage (lossless packets) \\
  192+ & reserved for Messenger usage (lossy packets) \\
  255  & reserved for Messenger usage (lossless packet) \\
\end{tabular}

Connection kill packets tell the other that the connection is over.

Packet numbers are the first byte of data in the packet.

packet request packet:

\begin{verbatim}
[uint8_t (1)][uint8_t num][uint8_t num][uint8_t num]...[uint8_t num]
\end{verbatim}

Packet request packets are used by one side of the connection to request
packets from the other.  To create a full packet request packet, the one
requesting the packet takes the last packet number that was processed (sent to
the relevant module and removed from the array (0 in the example above)).
Subtract the number of the first missing packet from that number (1 - 0) = 1.
Which means the full packet to request packet number 1 will look like:

\begin{verbatim}
[uint32_t 1]
[uint32_t 0]
[uint8_t 1][uint8_t 1]
\end{verbatim}

If packet number 4 was being requested as well, take the difference between the
packet number and the last packet number being requested (4 - 1) = 3.  So the
packet will look like:

\begin{verbatim}
[uint32_t 1]
[uint32_t 0]
[uint8_t 1][uint8_t 1][uint8_t 3]
\end{verbatim}

But what if the number is greater than 255? Let's say the peer needs to request
packets 3, 6, 1024, the packet will look like:

\begin{verbatim}
[uint32_t 1]
[uint32_t 2]
[uint8_t 1][uint8_t 3][uint8_t 3][uint8_t 0][uint8_t 0][uint8_t 0][uint8_t 253]
\end{verbatim}

Each 0 in the packet represents adding 255 until a non 0 byte is reached which
is then added and the resulting requested number is what is left.

This request is designed to be small when requesting packets in real network
conditions where the requested packet numbers will be close to each other.
Putting each requested 4 byte packet number would be very simple but would make
the request packets unnecessarily large which is why the packets look like
this.

When a request packet is received, it will be decoded and all packets in
between the requested packets will be assumed to be successfully received by
the other.

Packet request packets are sent at least every 1 second in toxcore and more
when packets are being received.

The current formula used is (note that this formula is likely sub-optimal):

\begin{verbatim}
REQUEST_PACKETS_COMPARE_CONSTANT = 50.0 double request_packet_interval =
(REQUEST_PACKETS_COMPARE_CONSTANT /
(((double)num_packets_array(&conn->recv_array) + 1.0) / (conn->packet_recv_rate
+ 1.0)));
\end{verbatim}

\texttt{num\_packets\_array(&conn->recv\_array)} returns the difference between
the highest packet number received and the last one handled.  In the toxcore
code it refers to the total size of the current array (with the holes which are
the placeholders for not yet received packets that are known to be missing).

\texttt{conn->packet\_recv\_rate} is the number of data packets successfully
received per second.

This formula was created with the logic that the higher the 'delay' in packets
(\texttt{num\_packets\_array(&conn->recv\_array)}) vs the speed of packets
received, the more request packets should be sent.

Requested packets are resent every time they can be resent as in they will obey
the congestion control and not bypass it.  They are resent once, subsequent
request packets will be used to know if the packet was received or if it should
be resent.
