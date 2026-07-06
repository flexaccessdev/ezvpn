//! Length-prefixed framing for the reliable QUIC-stream VPN data path.
//!
//! IP packets ride the single bidirectional QUIC stream opened for the
//! handshake, which stays open as the data channel. Each frame is
//! `[len: u32 BE] [body]`, where the body's leading byte is the
//! [`DataMessageType`] and the remainder is type-specific. IP packet body
//! layout: `[type: 0x00] [offload_len: 1] [offload: 0|10 bytes] [ip_packet]`.
//!
//! The stream is reliable and ordered, so there is no path-MTU concern at this
//! layer: QUIC packetizes and retransmits the byte stream itself, and GSO
//! super-frames of any size ride whole. The only reason a super-frame is ever
//! segmented in software ([`materialize_offload_into`]) is capability, not
//! size: the peer did not negotiate GSO metadata forwarding.

use crate::error::{VpnError, VpnResult};
use crate::tunnel::offload::{
    CoalescedOutput, VIRTIO_NET_HDR_LEN, VirtioNetHdr, materialize_offload_into,
};
use crate::tunnel::signaling::{DataMessageType, ServerAddrsMsg};
use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::{ReadExactError, RecvStream, SendStream};

/// Reserve granularity for the framing arena. Frames are appended to a
/// long-lived `BytesMut` and split off as refcounted `Bytes`, so the allocator
/// is only hit once per chunk instead of once per packet.
pub const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// Size of the `u32` big-endian frame length prefix.
pub const FRAME_LEN_PREFIX: usize = 4;

/// Maximum frame body size (the length the prefix may carry).
///
/// The largest legal body is an offload-tagged IP super-frame:
/// `[type: 1] [offload_len: 1] [offload: 10] [ip_packet: 65535]` — an IP
/// packet's total length field is 16-bit, so no TUN read (kernel GRO caps
/// coalesced frames at 64 KiB) or software-GRO group can exceed it. A peer
/// announcing a larger frame is violating the protocol, and since stream
/// framing cannot resynchronize past a corrupt length, the connection is torn
/// down.
pub const MAX_FRAME_BODY: usize = 2 + VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// A classified inbound frame body (a borrowed view into the receive buffer).
#[derive(Debug)]
pub enum Frame<'a> {
    /// IP packet message body (everything after the type byte): pass to
    /// [`crate::tunnel::signaling::parse_ip_packet_v2`].
    Ip(&'a [u8]),
    /// Server-published candidate-address message body (everything after the
    /// type byte): pass to [`ServerAddrsMsg::decode`]. Server → client only.
    ServerAddrs(&'a [u8]),
}

/// Append an IP-packet frame to `buf` (arena-style) and return the number of
/// bytes written.
///
/// Layout: `[len: u32 BE] [type: 0x00] [offload_len: 1] [offload: 0|10 bytes]
/// [ip_packet]`, where `len` covers the body (everything after the prefix).
#[inline]
pub fn encode_ip_frame(
    buf: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    ip_packet: &[u8],
) -> VpnResult<usize> {
    if ip_packet.is_empty() {
        return Err(VpnError::Signaling(
            "Cannot frame empty IP packet".to_string(),
        ));
    }

    const _: () = assert!(
        VIRTIO_NET_HDR_LEN <= u8::MAX as usize,
        "VIRTIO_NET_HDR_LEN must fit in u8"
    );
    let offload_len: u8 = if offload.is_some() {
        VIRTIO_NET_HDR_LEN as u8
    } else {
        0
    };
    let body_len = 2 + usize::from(offload_len) + ip_packet.len();
    if body_len > MAX_FRAME_BODY {
        return Err(VpnError::Signaling(format!(
            "IP frame body too large: {} > {}",
            body_len, MAX_FRAME_BODY
        )));
    }

    let total = FRAME_LEN_PREFIX + body_len;
    buf.reserve(total);
    // MAX_FRAME_BODY < u32::MAX, so the cast is lossless.
    buf.put_u32(body_len as u32);
    buf.put_u8(DataMessageType::IpPacket.as_byte());
    buf.put_u8(offload_len);
    if let Some(hdr) = offload {
        buf.put_slice(&hdr.to_bytes());
    }
    buf.put_slice(ip_packet);
    Ok(total)
}

/// Framed size (prefix included) for an IP packet with the given offload state.
#[inline]
pub fn ip_frame_len(has_offload: bool, ip_len: usize) -> usize {
    FRAME_LEN_PREFIX + 2 + if has_offload { VIRTIO_NET_HDR_LEN } else { 0 } + ip_len
}

/// Append an IP frame to the arena and split it off as a refcounted `Bytes`.
#[inline]
pub fn frame_ip_packet(
    arena: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
) -> VpnResult<Bytes> {
    let size = ip_frame_len(offload.is_some(), packet.len());
    if arena.capacity() - arena.len() < size {
        arena.reserve(FRAME_ARENA_CHUNK.max(size));
    }
    let written = encode_ip_frame(arena, offload, packet)?;
    Ok(arena.split_to(written).freeze())
}

/// Frame an IP packet (and optional offload metadata) into one or more frames
/// pushed onto `pending`.
///
/// `emit_offload` is whether offload metadata may be forwarded as-is (the peer
/// negotiated GSO, or can materialize it); when false, offload super-frames are
/// software-segmented into plain per-MSS packets. The stream is reliable, so
/// size never forces segmentation — only this capability check does.
pub fn build_frames(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    emit_offload: bool,
) -> VpnResult<()> {
    match offload {
        Some(meta) if emit_offload => {
            pending.push(frame_ip_packet(arena, Some(meta), packet)?);
        }
        Some(meta) => {
            materialize_offload_into(meta, packet, seg_scratch, |seg| {
                let frame = frame_ip_packet(arena, None, seg).map_err(|e| e.to_string())?;
                pending.push(frame);
                Ok(())
            })
            .map_err(VpnError::Signaling)?;
        }
        None => {
            pending.push(frame_ip_packet(arena, None, packet)?);
        }
    }
    Ok(())
}

/// Frame software-GRO outputs into frames pushed onto `pending`.
pub fn build_gro_frames(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    outputs: &[CoalescedOutput],
    emit_offload: bool,
) -> VpnResult<()> {
    for output in outputs {
        match output {
            CoalescedOutput::Coalesced(hdr, packet) => {
                build_frames(arena, seg_scratch, pending, Some(hdr), packet, emit_offload)?;
            }
            CoalescedOutput::Single(packet) => {
                build_frames(arena, seg_scratch, pending, None, packet, emit_offload)?;
            }
        }
    }
    Ok(())
}

/// Classify a frame body by its leading message-type byte.
#[inline]
pub fn classify(body: &[u8]) -> VpnResult<Frame<'_>> {
    let Some((&type_byte, rest)) = body.split_first() else {
        return Err(VpnError::Signaling("Empty frame body".to_string()));
    };
    match DataMessageType::from_byte(type_byte) {
        Some(DataMessageType::IpPacket) => Ok(Frame::Ip(rest)),
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

/// Copy a packet out of the (reused) frame receive buffer into a long-lived
/// arena and hand it out as a refcounted `Bytes`.
///
/// The receive buffer is overwritten by the next frame, so packets bound for
/// the TUN-writer channel must be detached; the arena amortizes those copies'
/// allocations across packets, mirroring the framing arena on the send side.
#[inline]
pub fn copy_packet_to_arena(arena: &mut BytesMut, packet: &[u8]) -> Bytes {
    if arena.capacity() - arena.len() < packet.len() {
        arena.reserve(FRAME_ARENA_CHUNK.max(packet.len()));
    }
    arena.extend_from_slice(packet);
    arena.split_to(packet.len()).freeze()
}

/// Read one length-prefixed frame body from the data stream into `buf`.
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
                "data stream read error: {}",
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
        VpnError::ConnectionLost(format!("data stream read error mid-frame: {}", e))
    })?;
    Ok(Some(body_len))
}

/// Write every queued frame to the data stream.
///
/// Zero-copy: `write_all_chunks` hands the refcounted `Bytes` to QUIC, which
/// packetizes the byte stream itself (no size cap at this layer). Any write
/// error is fatal — the stream is the tunnel.
pub async fn write_frames(send: &mut SendStream, pending: &mut Vec<Bytes>) -> Result<(), String> {
    send.write_all_chunks(pending)
        .await
        .map_err(|e| format!("QUIC stream write error: {}", e))?;
    pending.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::signaling::parse_ip_packet_v2;

    /// Split an encoded frame into (body_len, body), validating the prefix.
    fn split_frame(buf: &[u8]) -> (usize, &[u8]) {
        let len = u32::from_be_bytes(buf[..4].try_into().expect("prefix")) as usize;
        assert_eq!(buf.len(), FRAME_LEN_PREFIX + len, "prefix matches body");
        (len, &buf[FRAME_LEN_PREFIX..])
    }

    fn minimal_ipv4() -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p
    }

    #[test]
    fn test_ip_frame_roundtrip_no_offload() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_frame(&mut buf, None, &packet).expect("encode");
        assert_eq!(written, buf.len());
        let (_, body) = split_frame(&buf);
        assert_eq!(body[0], DataMessageType::IpPacket.as_byte());
        assert_eq!(body[1], 0);
        assert_eq!(&body[2..], &packet[..]);

        match classify(body).expect("classify") {
            Frame::Ip(payload) => {
                let (offload, ip) = parse_ip_packet_v2(payload).expect("parse body");
                assert!(offload.is_none());
                assert_eq!(ip, &packet[..]);
            }
            other => panic!("expected Ip, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_frame_roundtrip_with_offload() {
        let mut packet = [0u8; 24];
        packet[0] = 0x45;
        let offload = VirtioNetHdr {
            flags: 1,
            gso_type: 1,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };
        let mut buf = BytesMut::new();
        encode_ip_frame(&mut buf, Some(&offload), &packet).expect("encode");
        let (_, body) = split_frame(&buf);
        assert_eq!(body[1], VIRTIO_NET_HDR_LEN as u8);

        match classify(body).expect("classify") {
            Frame::Ip(payload) => {
                let (parsed, ip) = parse_ip_packet_v2(payload).expect("parse body");
                assert_eq!(parsed, Some(offload));
                assert_eq!(ip, &packet[..]);
            }
            other => panic!("expected Ip, got {:?}", other),
        }
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
            other => panic!("expected ServerAddrs, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_frame_len_matches_encoding() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_frame(&mut buf, None, &packet).unwrap();
        assert_eq!(written, ip_frame_len(false, packet.len()));
    }

    /// Build a valid IPv4/TCP packet with `payload_len` bytes of payload.
    fn build_ipv4_tcp_packet(payload_len: usize) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 251) as u8).collect();
        let mut tcp = TcpHeader::new(12345, 443, 10_000, 65_535);
        tcp.ack = true;
        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid IPv4 header");
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &payload).expect("tcp checksum");
        ip.header_checksum = ip.calc_header_checksum();
        let mut packet = Vec::new();
        ip.write(&mut packet).expect("write ip");
        tcp.write(&mut packet).expect("write tcp");
        packet.extend_from_slice(&payload);
        packet
    }

    fn tcp_gso_header() -> VirtioNetHdr {
        VirtioNetHdr {
            flags: 0,
            gso_type: 1, // VIRTIO_NET_HDR_GSO_TCPV4
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        }
    }

    #[test]
    fn test_gso_superframe_forwarded_whole_when_negotiated() {
        let packet = build_ipv4_tcp_packet(3500); // ~3540-byte super-frame
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());

        build_frames(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
        )
        .expect("frame");

        assert_eq!(pending.len(), 1, "should forward as one offload frame");
        let (_, body) = split_frame(&pending[0]);
        assert_eq!(body[0], DataMessageType::IpPacket.as_byte());
        assert_eq!(body[1], VIRTIO_NET_HDR_LEN as u8, "offload metadata present");
    }

    #[test]
    fn test_gso_superframe_segmented_when_not_negotiated() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());

        build_frames(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            false, // peer did not negotiate GSO -> software-segment
        )
        .expect("frame");

        // gso_size 1200 over 3500 bytes -> 3 plain per-MSS segments.
        assert_eq!(pending.len(), 3);
        let mut total_payload = 0usize;
        for f in &pending {
            let (_, body) = split_frame(f);
            assert_eq!(body[1], 0, "segmented frames carry no offload metadata");
            // body = [type][offload_len=0][ip(20) + tcp(20) + payload]
            total_payload += body.len() - 2 - 40;
        }
        assert_eq!(
            total_payload, 3500,
            "segmentation must preserve the full TCP payload"
        );
    }

    #[test]
    fn test_plain_packet_framed_whole() {
        let packet = build_ipv4_tcp_packet(1240); // larger than any wire MTU
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());

        build_frames(&mut arena, &mut scratch, &mut pending, None, &packet, true)
            .expect("frame");

        // Reliable stream: no path-MTU segmentation, the packet rides whole.
        assert_eq!(pending.len(), 1);
        let (_, body) = split_frame(&pending[0]);
        assert_eq!(&body[2..], &packet[..]);
    }

    #[test]
    fn test_max_frame_body_admits_max_superframe() {
        // The largest offload-tagged super-frame an IP total-length field
        // allows must encode; one byte more must be rejected.
        assert_eq!(MAX_FRAME_BODY, 2 + VIRTIO_NET_HDR_LEN + 65535);
        let packet = vec![0x45u8; 65535];
        let offload = tcp_gso_header();
        let mut buf = BytesMut::new();
        encode_ip_frame(&mut buf, Some(&offload), &packet).expect("max super-frame encodes");

        let oversized = vec![0x45u8; 65536];
        assert!(encode_ip_frame(&mut BytesMut::new(), Some(&offload), &oversized).is_err());
    }
}
