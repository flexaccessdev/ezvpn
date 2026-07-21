//! Data path (unreliable QUIC datagrams) and control framing (reliable stream).
//!
//! Each IP packet maps **directly to one unreliable, unordered QUIC datagram**
//! ([`send_ip_datagrams`] / [`Connection::read_datagram`]): the datagram body is
//! the raw IP packet, with no length prefix, type byte, or offload metadata —
//! QUIC preserves datagram boundaries, and the only other traffic (server
//! address publications) rides a separate reliable stream. This is a
//! WireGuard-style data path: no retransmission, no ordering, no head-of-line
//! blocking, and no path-MTU resegmentation (an oversized packet is dropped, not
//! fragmented).
//!
//! A GSO super-frame (up to 64 KiB) cannot fit in a datagram, so offload-tagged
//! packets are software-segmented ([`materialize_offload_into`]) into per-MSS
//! plain packets before sending, each as its own datagram; GSO metadata is never
//! forwarded on the wire.
//!
//! The reliable bidirectional stream opened for the handshake stays open as the
//! **control channel**, carrying only `ServerAddrs` (0x01) publications framed as
//! `[len: u32 BE] [type: 0x01] [json]` (see [`encode_server_addrs_frame`] /
//! [`read_frame`]). Reliability matters there (add-only bypass routes), and the
//! open stream keeps QUIC keep-alive/liveness working.

use crate::error::{VpnError, VpnResult};
use crate::tunnel::offload::{VIRTIO_NET_HDR_LEN, VirtioNetHdr, materialize_offload_into};
use crate::tunnel::signaling::{DataMessageType, ServerAddrsMsg};
use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::{Connection, ReadExactError, RecvStream, SendDatagramError, SendStream};

/// Reserve granularity for the arena packets are copied into before being sent
/// as datagrams. Packets are appended to a long-lived `BytesMut` and split off
/// as refcounted `Bytes`, so the allocator is only hit once per chunk instead of
/// once per datagram.
pub const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// Size of the `u32` big-endian control-frame length prefix.
pub const FRAME_LEN_PREFIX: usize = 4;

/// Maximum control-frame body size (the length the prefix may carry).
///
/// The control channel only carries `ServerAddrs` JSON, which is small, but the
/// cap is kept generous (and the receive buffer sized to it once). A peer
/// announcing a larger frame is violating the protocol, and since stream framing
/// cannot resynchronize past a corrupt length, the connection is torn down.
pub const MAX_FRAME_BODY: usize = 2 + VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// A classified inbound control-frame body (a borrowed view into the receive
/// buffer).
#[derive(Debug)]
pub enum Frame<'a> {
    /// Server-published candidate-address message body (everything after the
    /// type byte): pass to [`ServerAddrsMsg::decode`]. Server → client only.
    ServerAddrs(&'a [u8]),
}

/// Outcome of mapping an IP packet to one or more unreliable QUIC datagrams.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DatagramSendOutcome {
    /// Datagrams successfully queued for sending.
    pub sent: u64,
    /// Packets dropped because they exceed the connection's current max
    /// datagram size (path-MTU capped). WireGuard-style: the inner flow
    /// retransmits and DPLPMTUD raises the path within a few RTTs.
    pub dropped_too_large: u64,
    /// Packets dropped for any other reason (send buffer full, peer disabled
    /// datagrams, connection lost, or an un-segmentable offload frame).
    pub dropped_other: u64,
}

impl DatagramSendOutcome {
    /// Fold another outcome into this one.
    #[inline]
    pub fn add(&mut self, other: DatagramSendOutcome) {
        self.sent += other.sent;
        self.dropped_too_large += other.dropped_too_large;
        self.dropped_other += other.dropped_other;
    }
}

/// Map one IP packet (optionally offload-tagged) to unreliable QUIC datagrams
/// and send them on `conn`, one datagram per (segmented) packet.
///
/// A GSO super-frame cannot fit in a single datagram, so an offload-tagged
/// packet is software-segmented into per-MSS plain packets first, each sent as
/// its own datagram. The datagram body is the raw IP packet — no framing.
///
/// Sending waits for room in the bounded QUIC datagram queue. This lets QUIC's
/// pacer and congestion controller regulate the TUN reader instead of silently
/// evicting old datagrams under load. `arena` amortizes the per-datagram `Bytes`
/// allocation.
pub async fn send_ip_datagrams(
    conn: &Connection,
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
) -> DatagramSendOutcome {
    let mut outcome = DatagramSendOutcome::default();
    prepare_ip_datagrams(
        conn,
        arena,
        seg_scratch,
        pending,
        offload,
        packet,
        &mut outcome,
    );
    for datagram in pending.drain(..) {
        match conn.send_datagram_wait(datagram).await {
            Ok(()) => outcome.sent += 1,
            Err(SendDatagramError::TooLarge) => outcome.dropped_too_large += 1,
            Err(_) => outcome.dropped_other += 1,
        }
    }
    outcome
}

/// Materialize a TUN packet into plain datagrams without sending them.
///
/// The server uses this to feed a bounded per-client queue, preserving client
/// isolation while each client's writer awaits its own QUIC send capacity.
pub(crate) fn prepare_ip_datagrams(
    conn: &Connection,
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    outcome: &mut DatagramSendOutcome,
) {
    pending.clear();
    match offload {
        Some(meta) => {
            let segmented = materialize_offload_into(meta, packet, seg_scratch, |seg| {
                prepare_one_datagram(conn, arena, seg, pending, outcome);
                Ok(())
            });
            if let Err(e) = segmented {
                log::warn!("Dropping offload packet that could not be segmented: {}", e);
                outcome.dropped_other += 1;
            }
        }
        None => prepare_one_datagram(conn, arena, packet, pending, outcome),
    }
}

/// Prepare a single plain IP packet for datagram transmission.
fn prepare_one_datagram(
    conn: &Connection,
    arena: &mut BytesMut,
    packet: &[u8],
    pending: &mut Vec<Bytes>,
    outcome: &mut DatagramSendOutcome,
) {
    // Datagrams are capped by the live path MTU; an oversized packet is dropped
    // (not fragmented) so TCP/PMTUD can adapt while DPLPMTUD raises the path.
    match conn.max_datagram_size() {
        Some(max) if packet.len() <= max => {}
        Some(_) => {
            outcome.dropped_too_large += 1;
            return;
        }
        // Peer disabled datagram receipt entirely — should not happen (both
        // sides enable it), so drop rather than block.
        None => {
            outcome.dropped_other += 1;
            return;
        }
    }
    pending.push(copy_packet_to_arena(arena, packet));
}

/// Classify a control-frame body by its leading message-type byte.
#[inline]
pub fn classify(body: &[u8]) -> VpnResult<Frame<'_>> {
    let Some((&type_byte, rest)) = body.split_first() else {
        return Err(VpnError::Signaling("Empty frame body".to_string()));
    };
    match DataMessageType::from_byte(type_byte) {
        Some(DataMessageType::ServerAddrs) => Ok(Frame::ServerAddrs(rest)),
        None => Err(VpnError::Signaling(format!(
            "Unknown frame message type: 0x{:02x}",
            type_byte
        ))),
    }
}

/// Append a server-addresses frame to `buf` (arena-style) and return the
/// number of bytes written. Layout: `[len: u32 BE] [type: 0x01]
/// [json(ServerAddrsMsg)]`.
pub fn encode_server_addrs_frame(buf: &mut BytesMut, msg: &ServerAddrsMsg) -> VpnResult<usize> {
    let body = msg.encode()?;
    let body_len = 1 + body.len();
    if body_len > MAX_FRAME_BODY {
        return Err(VpnError::Signaling(format!(
            "Server addrs frame too large: {} > {}",
            body_len, MAX_FRAME_BODY
        )));
    }
    let total = FRAME_LEN_PREFIX + body_len;
    buf.reserve(total);
    buf.put_u32(body_len as u32);
    buf.put_u8(DataMessageType::ServerAddrs.as_byte());
    buf.put_slice(&body);
    Ok(total)
}

/// Copy a packet out of a (reused) receive buffer into a long-lived arena and
/// hand it out as a refcounted `Bytes`.
///
/// The arena must be empty on entry: `split_to` takes from the front, so
/// residual bytes would corrupt the returned packet. The invariant holds as
/// long as the arena is used exclusively through this function, which drains
/// exactly what it appended.
#[inline]
pub fn copy_packet_to_arena(arena: &mut BytesMut, packet: &[u8]) -> Bytes {
    debug_assert!(arena.is_empty(), "packet arena must be drained on entry");
    if arena.capacity() - arena.len() < packet.len() {
        arena.reserve(FRAME_ARENA_CHUNK.max(packet.len()));
    }
    arena.extend_from_slice(packet);
    arena.split_to(packet.len()).freeze()
}

/// Read one length-prefixed control-frame body from the stream into `buf`.
///
/// `buf` must be at least [`MAX_FRAME_BODY`] bytes (allocate it once per read
/// loop). Returns the body length, or `None` on a clean end-of-stream (the
/// peer finished the stream at a frame boundary). Any other shortfall or
/// protocol violation is an error: stream framing cannot resynchronize, so the
/// caller must tear the connection down.
pub async fn read_frame(recv: &mut RecvStream, buf: &mut [u8]) -> VpnResult<Option<usize>> {
    debug_assert!(buf.len() >= MAX_FRAME_BODY);
    let mut len_buf = [0u8; FRAME_LEN_PREFIX];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        // Clean close exactly at a frame boundary.
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => {
            return Err(VpnError::ConnectionLost(format!(
                "control stream read error: {}",
                e
            )));
        }
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len == 0 || body_len > MAX_FRAME_BODY {
        return Err(VpnError::Signaling(format!(
            "Invalid frame length {} (max {})",
            body_len, MAX_FRAME_BODY
        )));
    }
    recv.read_exact(&mut buf[..body_len]).await.map_err(|e| {
        VpnError::ConnectionLost(format!("control stream read error mid-frame: {}", e))
    })?;
    Ok(Some(body_len))
}

/// Write every queued control frame to the stream.
///
/// Zero-copy: `write_all_chunks` hands the refcounted `Bytes` to QUIC. Any
/// write error is fatal for the control channel.
pub async fn write_frames(send: &mut SendStream, pending: &mut Vec<Bytes>) -> VpnResult<()> {
    send.write_all_chunks(pending)
        .await
        .map_err(|e| VpnError::ConnectionLost(format!("QUIC stream write error: {}", e)))?;
    pending.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Split an encoded frame into (body_len, body), validating the prefix.
    fn split_frame(buf: &[u8]) -> (usize, &[u8]) {
        let len = u32::from_be_bytes(buf[..4].try_into().expect("prefix")) as usize;
        assert_eq!(buf.len(), FRAME_LEN_PREFIX + len, "prefix matches body");
        (len, &buf[FRAME_LEN_PREFIX..])
    }

    #[test]
    fn test_classify_empty_and_unknown() {
        assert!(classify(&[]).is_err());
        assert!(classify(&[0x7f]).is_err());
    }

    #[test]
    fn test_server_addrs_frame_roundtrip() {
        let msg = ServerAddrsMsg::new(vec![
            "203.0.113.5".parse().expect("parse v4"),
            "2001:db8::1".parse().expect("parse v6"),
        ]);
        let mut buf = BytesMut::new();
        let written = encode_server_addrs_frame(&mut buf, &msg).expect("encode");
        assert_eq!(written, buf.len());
        let (_, body) = split_frame(&buf);
        assert_eq!(body[0], DataMessageType::ServerAddrs.as_byte());

        match classify(body).expect("classify") {
            Frame::ServerAddrs(payload) => {
                let decoded = ServerAddrsMsg::decode(payload).expect("decode body");
                assert_eq!(decoded, msg);
            }
        }
    }

    #[test]
    fn test_datagram_outcome_add() {
        let mut a = DatagramSendOutcome {
            sent: 1,
            dropped_too_large: 2,
            dropped_other: 3,
        };
        a.add(DatagramSendOutcome {
            sent: 10,
            dropped_too_large: 20,
            dropped_other: 30,
        });
        assert_eq!(a.sent, 11);
        assert_eq!(a.dropped_too_large, 22);
        assert_eq!(a.dropped_other, 33);
    }
}
