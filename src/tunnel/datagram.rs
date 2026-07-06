//! Datagram framing for the unreliable QUIC-datagram VPN data path.
//!
//! Each iroh QUIC datagram carries exactly one VPN message, so there is no
//! length-prefix: the datagram boundary *is* the message length. The leading
//! byte is the [`DataMessageType`]; the remainder is type-specific. IP packet
//! layout: `[type: 0x00] [offload_len: 1] [offload: 0|10 bytes] [ip_packet]`.
//!
//! A QUIC datagram is capped at the connection's `max_datagram_size()` (far
//! below the 64 KiB a UDP datagram allows), so GSO super-frames whose framed
//! size would exceed that cap are segmented into plain per-MTU datagrams by
//! [`build_datagrams`]. The cap is live — it tracks the path MTU estimate and
//! can shrink below the negotiated tunnel MTU mid-connection — so oversized
//! *plain* TCP packets are likewise resegmented in software rather than
//! dropped; only oversized non-TCP packets are dropped (as any path-MTU loss).

use crate::error::{VpnError, VpnResult};
use crate::tunnel::offload::{
    CoalescedOutput, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_LEN,
    VirtioNetHdr, materialize_offload_into, segment_tcp_gso_into,
};
use crate::tunnel::signaling::{DataMessageType, ServerAddrsMsg};
use bytes::{BufMut, Bytes, BytesMut};

/// Reserve granularity for the framing arena. Frames are appended to a
/// long-lived `BytesMut` and split off as refcounted `Bytes`, so the allocator
/// is only hit once per chunk instead of once per packet.
pub const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// Datagram framing overhead prepended to a plain IP packet: `[type: 1]
/// [offload_len: 1]`. The TUN MTU must leave room for this within one QUIC
/// datagram, i.e. `mtu + DATAGRAM_FRAMING_OVERHEAD <= max_datagram_size`.
pub const DATAGRAM_FRAMING_OVERHEAD: usize = 2;

/// A classified inbound datagram (a borrowed view into the receive buffer).
#[derive(Debug)]
pub enum Datagram<'a> {
    /// IP packet message body (everything after the type byte): pass to
    /// [`crate::tunnel::signaling::parse_ip_packet_v2`].
    Ip(&'a [u8]),
    /// Server-published candidate-address message body (everything after the
    /// type byte): pass to [`ServerAddrsMsg::decode`]. Server → client only.
    ServerAddrs(&'a [u8]),
}

/// Append an IP-packet datagram to `buf` (arena-style) and return the number of
/// bytes written.
///
/// Layout: `[type: 0x00] [offload_len: 1] [offload: 0|10 bytes] [ip_packet]`.
#[inline]
pub fn encode_ip_datagram(
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
    let total = 1 + 1 + usize::from(offload_len) + ip_packet.len();

    buf.reserve(total);
    buf.put_u8(DataMessageType::IpPacket.as_byte());
    buf.put_u8(offload_len);
    if let Some(hdr) = offload {
        buf.put_slice(&hdr.to_bytes());
    }
    buf.put_slice(ip_packet);
    Ok(total)
}

/// Framed datagram size for an IP packet with the given offload state.
#[inline]
pub fn ip_datagram_len(has_offload: bool, ip_len: usize) -> usize {
    1 + 1 + if has_offload { VIRTIO_NET_HDR_LEN } else { 0 } + ip_len
}

/// Append a datagram to the arena and split it off as a refcounted `Bytes`.
#[inline]
pub fn frame_datagram(
    arena: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
) -> VpnResult<Bytes> {
    let size = ip_datagram_len(offload.is_some(), packet.len());
    if arena.capacity() - arena.len() < size {
        arena.reserve(FRAME_ARENA_CHUNK.max(size));
    }
    let written = encode_ip_datagram(arena, offload, packet)?;
    Ok(arena.split_to(written).freeze())
}

/// Frame an IP packet (and optional offload metadata) into one or more
/// datagrams pushed onto `pending`, segmenting offload super-frames whose framed
/// size would exceed `max_datagram_size`.
///
/// `emit_offload` is whether offload metadata may be forwarded as-is (the peer
/// negotiated GSO, or can materialize it); when false, offload frames are always
/// segmented into plain packets.
pub fn build_datagrams(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    emit_offload: bool,
    max_datagram_size: usize,
) -> VpnResult<()> {
    match offload {
        Some(meta)
            if emit_offload && ip_datagram_len(true, packet.len()) <= max_datagram_size =>
        {
            pending.push(frame_datagram(arena, Some(meta), packet)?);
        }
        Some(meta) => {
            // Segment the super-frame so each emitted datagram fits the path.
            //
            // The kernel sets `gso_size` to the *origin* flow's MSS — forwarded
            // internet traffic, or a jumbo-MTU datacenter path (e.g. AWS) — which
            // can exceed this connection's `max_datagram_size`. Re-segment at a
            // size that fits rather than dropping oversized segments:
            // `segment_tcp_gso_into` recomputes each segment's IP/TCP headers and
            // checksums, so smaller TCP segments are fully valid and the peer's
            // stack reassembles them transparently. Dropping instead would
            // blackhole every large segment (the origin re-sends the same MSS, so
            // inner-TCP retransmit does not recover) and stall throughput.
            let seg_meta = clamp_gso_size_to_path(*meta, max_datagram_size);
            materialize_offload_into(&seg_meta, packet, seg_scratch, |seg| {
                push_plain_or_resegment(arena, pending, seg, max_datagram_size)
            })
            .map_err(VpnError::Signaling)?;
        }
        None => {
            push_plain_or_resegment(arena, pending, packet, max_datagram_size)
                .map_err(VpnError::Signaling)?;
        }
    }
    Ok(())
}

/// Frame `packet` as one plain datagram when it fits `max_datagram_size`, or
/// resegment it in software when it does not.
///
/// The TUN MTU is negotiated against the *handshake-time* datagram cap, but the
/// live cap tracks the path MTU estimate and can shrink mid-connection (e.g.
/// QUIC black-hole detection on a sub-1500 underlay). When that happens, a
/// full-MTU plain TCP packet no longer fits one datagram; re-cutting it into
/// smaller valid TCP segments keeps the flow moving, whereas dropping would
/// blackhole it (the origin retransmits at the same size — the inner flow never
/// recovers, and the tunnel emits no ICMP Packet-Too-Big to trigger PMTUD).
/// Oversized non-TCP packets are dropped like any path-MTU loss.
fn push_plain_or_resegment(
    arena: &mut BytesMut,
    pending: &mut Vec<Bytes>,
    packet: &[u8],
    max_datagram_size: usize,
) -> Result<(), String> {
    let framed_len = ip_datagram_len(false, packet.len());
    if framed_len <= max_datagram_size {
        pending.push(frame_datagram(arena, None, packet).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let Some(meta) = synthesize_tcp_gso(packet, max_datagram_size) else {
        log::warn!(
            "Dropping IP packet ({framed_len} B framed) exceeding max_datagram_size ({max_datagram_size}); not resegmentable (non-TCP, fragmented, or cap below header size)"
        );
        return Ok(());
    };
    // Exceptional path (live cap shrank below the tunnel MTU), so a transient
    // scratch allocation is acceptable.
    let mut scratch = Vec::new();
    segment_tcp_gso_into(&meta, packet, &mut scratch, |seg| {
        pending.push(frame_datagram(arena, None, seg).map_err(|e| e.to_string())?);
        Ok(())
    })
}

/// Synthesize TCP-GSO metadata for a plain TCP packet so [`segment_tcp_gso_into`]
/// can re-cut it to fit `max_datagram_size`.
///
/// Returns `None` for anything that cannot be safely resegmented: non-TCP
/// packets, IPv4 fragments, IPv6 with extension headers, or a cap too small to
/// carry the IP/TCP headers plus at least one payload byte. Unlike
/// [`crate::tunnel::offload::parse_coalescible_tcp`], ECN-marked packets and
/// IPv4 options are accepted — segmentation copies the IP header verbatim.
fn synthesize_tcp_gso(packet: &[u8], max_datagram_size: usize) -> Option<VirtioNetHdr> {
    let (tcp_offset, gso_type) = match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 || packet[9] != 6 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl + 20 {
                return None;
            }
            // No fragments: MF flag or nonzero fragment offset means the TCP
            // header is absent or the payload is partial — cannot re-cut.
            if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                return None;
            }
            (ihl, VIRTIO_NET_HDR_GSO_TCPV4)
        }
        6 => {
            // Next header must be TCP directly (no extension-header walking).
            if packet.len() < 60 || packet[6] != 6 {
                return None;
            }
            (40, VIRTIO_NET_HDR_GSO_TCPV6)
        }
        _ => return None,
    };
    let tcp_header_len = usize::from(packet[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 || packet.len() < tcp_offset + tcp_header_len {
        return None;
    }
    let hdr_len = tcp_offset + tcp_header_len;
    let gso_size = max_datagram_size.saturating_sub(DATAGRAM_FRAMING_OVERHEAD + hdr_len);
    if gso_size == 0 || packet.len() == hdr_len {
        return None;
    }
    Some(VirtioNetHdr {
        flags: 0,
        gso_type,
        hdr_len: u16::try_from(hdr_len).ok()?,
        gso_size: u16::try_from(gso_size.min(usize::from(u16::MAX))).ok()?,
        csum_start: u16::try_from(tcp_offset).ok()?,
        csum_offset: 16,
        num_buffers: 0,
    })
}

/// Reduce a TCP-GSO super-frame's `gso_size` so each resegmented packet, once
/// framed, fits within `max_datagram_size`.
///
/// The kernel sets `gso_size` to the origin flow's MSS, which can exceed this
/// connection's datagram capacity (forwarded internet traffic, jumbo-MTU paths).
/// Lowering it makes `segment_tcp_gso_into` emit more, smaller, valid TCP
/// segments instead of oversized ones that would be dropped. Non-TCP-GSO
/// metadata is returned unchanged — it is never resegmented — as is the
/// degenerate case where the header alone exceeds the cap (the per-segment
/// safety net in `build_datagrams` drops it).
fn clamp_gso_size_to_path(mut meta: VirtioNetHdr, max_datagram_size: usize) -> VirtioNetHdr {
    if !meta.is_tcp_gso() {
        return meta;
    }
    // Largest TCP payload whose framed plain datagram (`[type][offload_len][ip]`)
    // fits the path: cap minus framing overhead minus the IP+TCP header bytes.
    let max_payload = max_datagram_size
        .saturating_sub(DATAGRAM_FRAMING_OVERHEAD)
        .saturating_sub(usize::from(meta.hdr_len));
    if max_payload > 0 && usize::from(meta.gso_size) > max_payload {
        // max_payload < max_datagram_size, comfortably within u16 in practice.
        meta.gso_size = u16::try_from(max_payload).unwrap_or(u16::MAX);
    }
    meta
}

/// Frame software-GRO outputs into datagrams pushed onto `pending`.
pub fn build_gro_datagrams(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    outputs: &[CoalescedOutput],
    max_datagram_size: usize,
) -> VpnResult<()> {
    for output in outputs {
        match output {
            CoalescedOutput::Coalesced(hdr, packet) => {
                build_datagrams(
                    arena,
                    seg_scratch,
                    pending,
                    Some(hdr),
                    packet,
                    true,
                    max_datagram_size,
                )?;
            }
            CoalescedOutput::Single(packet) => {
                build_datagrams(
                    arena,
                    seg_scratch,
                    pending,
                    None,
                    packet,
                    true,
                    max_datagram_size,
                )?;
            }
        }
    }
    Ok(())
}

/// Classify a received datagram by its leading message-type byte.
#[inline]
pub fn classify(dgram: &[u8]) -> VpnResult<Datagram<'_>> {
    let Some((&type_byte, rest)) = dgram.split_first() else {
        return Err(VpnError::Signaling("Empty datagram".to_string()));
    };
    match DataMessageType::from_byte(type_byte) {
        Some(DataMessageType::IpPacket) => Ok(Datagram::Ip(rest)),
        Some(DataMessageType::ServerAddrs) => Ok(Datagram::ServerAddrs(rest)),
        None => Err(VpnError::Signaling(format!(
            "Unknown datagram message type: 0x{:02x}",
            type_byte
        ))),
    }
}

/// Append a server-addresses datagram to `buf` (arena-style) and return the
/// number of bytes written. Layout: `[type: 0x01] [json(ServerAddrsMsg)]`.
pub fn encode_server_addrs_datagram(buf: &mut BytesMut, msg: &ServerAddrsMsg) -> VpnResult<usize> {
    let body = msg.encode()?;
    let total = 1 + body.len();
    buf.reserve(total);
    buf.put_u8(DataMessageType::ServerAddrs.as_byte());
    buf.put_slice(&body);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::signaling::parse_ip_packet_v2;

    fn minimal_ipv4() -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p
    }

    #[test]
    fn test_ip_datagram_roundtrip_no_offload() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_datagram(&mut buf, None, &packet).expect("encode");
        assert_eq!(written, buf.len());
        // No 4-byte length field: byte[1] is the offload_len (0), not a length.
        assert_eq!(buf[0], DataMessageType::IpPacket.as_byte());
        assert_eq!(buf[1], 0);
        assert_eq!(&buf[2..], &packet[..]);

        match classify(&buf).expect("classify") {
            Datagram::Ip(body) => {
                let (offload, ip) = parse_ip_packet_v2(body).expect("parse body");
                assert!(offload.is_none());
                assert_eq!(ip, &packet[..]);
            }
            other => panic!("expected Ip, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_datagram_roundtrip_with_offload() {
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
        encode_ip_datagram(&mut buf, Some(&offload), &packet).expect("encode");
        assert_eq!(buf[1], VIRTIO_NET_HDR_LEN as u8);

        match classify(&buf).expect("classify") {
            Datagram::Ip(body) => {
                let (parsed, ip) = parse_ip_packet_v2(body).expect("parse body");
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
    fn test_server_addrs_datagram_roundtrip() {
        let msg = ServerAddrsMsg::new(vec![
            "203.0.113.5".parse().expect("parse v4"),
            "2001:db8::1".parse().expect("parse v6"),
        ]);
        let mut buf = BytesMut::new();
        let written = encode_server_addrs_datagram(&mut buf, &msg).expect("encode");
        assert_eq!(written, buf.len());
        assert_eq!(buf[0], DataMessageType::ServerAddrs.as_byte());

        match classify(&buf).expect("classify") {
            Datagram::ServerAddrs(body) => {
                let decoded = ServerAddrsMsg::decode(body).expect("decode body");
                assert_eq!(decoded, msg);
            }
            other => panic!("expected ServerAddrs, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_datagram_len_matches_encoding() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_datagram(&mut buf, None, &packet).unwrap();
        assert_eq!(written, ip_datagram_len(false, packet.len()));
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
    fn test_gso_superframe_forwarded_whole_under_large_cap() {
        let packet = build_ipv4_tcp_packet(3500); // ~3540-byte super-frame
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
            65535,
        )
        .expect("frame");

        assert_eq!(pending.len(), 1, "should forward as one offload datagram");
        assert_eq!(pending[0][0], DataMessageType::IpPacket.as_byte());
        assert_eq!(
            pending[0][1], VIRTIO_NET_HDR_LEN as u8,
            "offload metadata present"
        );
    }

    #[test]
    fn test_gso_superframe_segmented_under_small_cap() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1500;

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
            cap,
        )
        .expect("frame");

        // gso_size 1200 over 3500 bytes -> 3 segments, each within the cap and
        // emitted as a plain (non-offload) datagram.
        assert_eq!(pending.len(), 3);
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
            assert_eq!(d[1], 0, "segmented datagrams carry no offload metadata");
        }
    }

    #[test]
    fn test_gso_oversized_gso_size_resegmented_to_fit() {
        // Regression: when the kernel's gso_size exceeds the path's
        // max_datagram_size (forwarded internet / jumbo-MTU traffic), segments
        // must be re-cut to fit rather than dropped. Here a 1460-MSS super-frame
        // is sent over a 1414-byte cap (smaller than even one MSS segment).
        let mut offload = tcp_gso_header();
        offload.gso_size = 1460;
        let payload_len = 3000;
        let packet = build_ipv4_tcp_packet(payload_len);
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1414;

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            false, // peer cannot take offload metadata -> must segment
            cap,
        )
        .expect("frame");

        assert!(!pending.is_empty(), "oversized gso_size must resegment, not drop");
        let mut total_payload = 0usize;
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
            assert_eq!(d[1], 0, "segmented datagrams carry no offload metadata");
            // d = [type][offload_len=0][ip(20) + tcp(20) + payload]
            total_payload += d.len() - DATAGRAM_FRAMING_OVERHEAD - 40;
        }
        assert_eq!(
            total_payload, payload_len,
            "resegmentation must preserve the full TCP payload"
        );
    }

    /// Build a valid IPv6/TCP packet with `payload_len` bytes of payload.
    fn build_ipv6_tcp_packet(payload_len: usize) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv6Header, TcpHeader};
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 251) as u8).collect();
        let mut tcp = TcpHeader::new(12345, 22, 10_000, 65_535);
        tcp.ack = true;
        let ip = Ipv6Header {
            traffic_class: 0x02, // ECT(0): resegmentation must accept ECN-marked packets
            flow_label: etherparse::Ipv6FlowLabel::ZERO,
            payload_length: u16::try_from(tcp.header_len() + payload.len())
                .expect("IPv6 payload length fits in u16"),
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0xfd; 16],
            destination: [0xfc; 16],
        };
        tcp.checksum = tcp.calc_checksum_ipv6(&ip, &payload).expect("tcp checksum");
        let mut packet = Vec::new();
        ip.write(&mut packet).expect("write ip");
        tcp.write(&mut packet).expect("write tcp");
        packet.extend_from_slice(&payload);
        packet
    }

    #[test]
    fn test_oversized_plain_tcp_ipv4_resegmented() {
        // A full-size plain TCP packet on a path whose live cap shrank below
        // the tunnel MTU must be re-cut into fitting segments, not dropped.
        let payload_len = 1360;
        let packet = build_ipv4_tcp_packet(payload_len); // 1400 B, framed 1402
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1170; // e.g. quinn at its 1200-byte path-MTU floor

        build_datagrams(&mut arena, &mut scratch, &mut pending, None, &packet, true, cap)
            .expect("frame");

        assert!(pending.len() >= 2, "must emit multiple segments");
        let mut total_payload = 0usize;
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
            assert_eq!(d[0], DataMessageType::IpPacket.as_byte());
            assert_eq!(d[1], 0, "resegmented datagrams carry no offload metadata");
            total_payload += d.len() - DATAGRAM_FRAMING_OVERHEAD - 40;
        }
        assert_eq!(total_payload, payload_len, "full TCP payload preserved");
    }

    #[test]
    fn test_oversized_plain_tcp_ipv6_resegmented() {
        let payload_len = 1340;
        let packet = build_ipv6_tcp_packet(payload_len); // 1400 B, framed 1402
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1170;

        build_datagrams(&mut arena, &mut scratch, &mut pending, None, &packet, true, cap)
            .expect("frame");

        assert!(pending.len() >= 2, "must emit multiple segments");
        let mut total_payload = 0usize;
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
            assert_eq!(d[1], 0);
            // d = [type][offload_len=0][ipv6(40) + tcp(20) + payload]
            total_payload += d.len() - DATAGRAM_FRAMING_OVERHEAD - 60;
        }
        assert_eq!(total_payload, payload_len, "full TCP payload preserved");
    }

    #[test]
    fn test_oversized_plain_non_tcp_dropped() {
        // A minimal IPv6/UDP packet larger than the cap has no safe re-cut and
        // must be dropped (like any path-MTU loss), without erroring.
        let mut packet = vec![0u8; 1400];
        packet[0] = 0x60; // IPv6
        packet[6] = 17; // next header: UDP
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());

        build_datagrams(&mut arena, &mut scratch, &mut pending, None, &packet, true, 1170)
            .expect("framing must not error when the packet is dropped");

        assert!(pending.is_empty(), "oversized non-TCP packet must be dropped");
    }

    #[test]
    fn test_oversized_checksum_only_offload_resegmented() {
        // A full-size single TCP packet arriving with checksum-only virtio
        // metadata (Linux TUN_F_CSUM) must be checksum-completed and then
        // resegmented when it no longer fits the live cap.
        let payload_len = 1360;
        let packet = build_ipv4_tcp_packet(payload_len);
        let offload = VirtioNetHdr {
            flags: 1, // VIRTIO_NET_HDR_F_NEEDS_CSUM
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1170;

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            false, // peer cannot take offload metadata
            cap,
        )
        .expect("frame");

        assert!(pending.len() >= 2, "must emit multiple segments");
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
        }
    }

    #[test]
    fn test_gso_segments_dropped_only_when_header_exceeds_cap() {
        // The sole remaining drop case: a cap so small the IP/TCP header alone
        // (plus framing) does not fit, so no payload byte can ride. gso_size
        // cannot be lowered enough, and the per-segment safety net drops it.
        let packet = build_ipv4_tcp_packet(3500);
        let offload = tcp_gso_header(); // hdr_len 40
        let (mut arena, mut scratch, mut pending) = (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 42; // == DATAGRAM_FRAMING_OVERHEAD (2) + header (40); zero payload room

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
            cap,
        )
        .expect("framing must not error when segments are dropped");

        assert!(
            pending.is_empty(),
            "segments must be dropped when the header alone exceeds the cap, got {}",
            pending.len()
        );
    }
}
