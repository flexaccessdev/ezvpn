//! Linux TUN offload metadata helpers and software fallback materialization.
//!
//! This module handles:
//! - Parsing and serializing `virtio_net_hdr` metadata (10-byte variant).
//! - Splitting/assembling TUN frames when `IFF_VNET_HDR` is enabled.
//! - Materializing offload metadata into plain packets when peer/local offload
//!   support is unavailable.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;

/// Size of the Linux virtio header used by TUN when `IFF_VNET_HDR` is enabled.
pub const VIRTIO_NET_HDR_LEN: usize = 10;

/// Offload flag: checksum field needs software/device completion.
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
/// Offload flag: packet checksum has already been validated.
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;

/// GSO type: no segmentation offload.
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
/// GSO type: TCP over IPv4.
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// GSO type: TCP over IPv6.
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// GSO type flag: ECN is present.
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Offload metadata carried by Linux TUN when `IFF_VNET_HDR` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Parse a 10-byte virtio header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr: [u8; VIRTIO_NET_HDR_LEN] = bytes.try_into().map_err(|_| {
            format!(
                "virtio_net_hdr must be {} bytes, got {}",
                VIRTIO_NET_HDR_LEN,
                bytes.len()
            )
        })?;
        Ok(Self::from(arr))
    }

    /// Serialize a virtio header to its 10-byte wire form.
    pub fn to_bytes(self) -> [u8; VIRTIO_NET_HDR_LEN] {
        let mut out = [0u8; VIRTIO_NET_HDR_LEN];
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        out
    }

    /// Return true if this header carries a TCP GSO packet (v4 or v6).
    pub fn is_tcp_gso(self) -> bool {
        matches!(
            self.gso_type & !VIRTIO_NET_HDR_GSO_ECN,
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6
        ) && self.gso_size != 0
    }

    /// Return the normalized GSO type value without ECN bit.
    pub fn normalized_gso_type(self) -> u8 {
        self.gso_type & !VIRTIO_NET_HDR_GSO_ECN
    }

    /// Return true if the packet checksum must be completed before writing as plain IP.
    pub fn needs_checksum(self) -> bool {
        (self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0
    }
}

impl From<[u8; VIRTIO_NET_HDR_LEN]> for VirtioNetHdr {
    fn from(value: [u8; VIRTIO_NET_HDR_LEN]) -> Self {
        Self {
            flags: value[0],
            gso_type: value[1],
            hdr_len: u16::from_le_bytes([value[2], value[3]]),
            gso_size: u16::from_le_bytes([value[4], value[5]]),
            csum_start: u16::from_le_bytes([value[6], value[7]]),
            csum_offset: u16::from_le_bytes([value[8], value[9]]),
            num_buffers: 0,
        }
    }
}

/// Split a TUN frame into optional offload metadata and raw IP payload.
///
/// When `vnet_hdr_enabled` is false, the frame is treated as plain IP.
/// When true, the leading 10-byte `virtio_net_hdr` is parsed and stripped.
pub fn split_tun_frame(
    frame: &[u8],
    vnet_hdr_enabled: bool,
) -> Result<(Option<VirtioNetHdr>, &[u8]), String> {
    if !vnet_hdr_enabled {
        if frame.is_empty() {
            return Err("zero-length TUN frame".to_string());
        }
        return Ok((None, frame));
    }

    if frame.len() < VIRTIO_NET_HDR_LEN {
        return Err(format!(
            "TUN frame shorter than virtio header: {} < {}",
            frame.len(),
            VIRTIO_NET_HDR_LEN
        ));
    }

    let offload = VirtioNetHdr::from_bytes(&frame[..VIRTIO_NET_HDR_LEN])?;
    let ip_packet = &frame[VIRTIO_NET_HDR_LEN..];
    if ip_packet.is_empty() {
        return Err("empty IP payload after virtio header".to_string());
    }

    if offload.gso_type == VIRTIO_NET_HDR_GSO_NONE {
        // Keep checksum-offload metadata (e.g. NEEDS_CSUM) so the peer can
        // preserve/finalize transport checksums correctly on write.
        let has_checksum_metadata =
            offload.flags != 0 || offload.csum_start != 0 || offload.csum_offset != 0;
        if has_checksum_metadata {
            return Ok((Some(offload), ip_packet));
        }
        return Ok((None, ip_packet));
    }

    if offload.is_tcp_gso() {
        return Ok((Some(offload), ip_packet));
    }

    Err(format!(
        "unsupported GSO type from TUN: 0x{:02x}",
        offload.gso_type
    ))
}

/// Compose a TUN frame for writing.
///
/// If `vnet_hdr_enabled` is true, a 10-byte virtio header is prepended. If no
/// offload header is provided, a zeroed header is used for plain packets.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn compose_tun_frame(
    out: &mut BytesMut,
    vnet_hdr_enabled: bool,
    offload: Option<&VirtioNetHdr>,
    ip_packet: &[u8],
) -> Result<(), String> {
    if ip_packet.is_empty() {
        return Err("cannot compose TUN frame with empty IP payload".to_string());
    }

    if !vnet_hdr_enabled && offload.is_some() {
        return Err(
            "received offload metadata but local TUN does not use vnet headers".to_string(),
        );
    }

    out.clear();
    out.reserve(
        ip_packet.len()
            + if vnet_hdr_enabled {
                VIRTIO_NET_HDR_LEN
            } else {
                0
            },
    );

    if vnet_hdr_enabled {
        let header = offload.copied().unwrap_or_default().to_bytes();
        out.put_slice(&header);
    }
    out.put_slice(ip_packet);
    Ok(())
}

// ---------------------------------------------------------------------------
// Write-side GRO: coalesce consecutive same-flow TCP segments into a single
// GSO super-frame so one TUN write replaces N (the kernel re-segments).
// ---------------------------------------------------------------------------

/// TCP flag bits that disqualify a segment from coalescing (FIN/SYN/RST/URG).
const TCP_FLAGS_NO_COALESCE: u8 = 0x01 | 0x02 | 0x04 | 0x20;

/// Parsed coalescing-relevant fields of a plain (no vnet header) TCP segment.
///
/// Only produced by [`parse_coalescible_tcp`] for segments that satisfy the
/// per-packet coalescing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegmentMeta {
    pub is_ipv6: bool,
    /// IP header length: always 20 (IPv4, no options) or 40 (IPv6, no
    /// extension headers).
    pub ip_header_len: usize,
    pub tcp_header_len: usize,
    pub seq: u32,
    pub payload_len: usize,
}

impl TcpSegmentMeta {
    fn header_len(&self) -> usize {
        self.ip_header_len + self.tcp_header_len
    }
}

/// Parse a plain IP packet, returning metadata only if it is a coalescible
/// pure-data TCP segment.
///
/// Returns `None` (excluding the packet from coalescing, never an error) for:
/// non-TCP packets, IPv4 with options or fragmentation, IPv6 with extension
/// headers, ECN-marked packets (avoids `VIRTIO_NET_HDR_GSO_ECN` handling),
/// segments carrying SYN/FIN/RST/URG, empty payloads, and packets whose IP
/// length fields disagree with the buffer length.
pub fn parse_coalescible_tcp(packet: &[u8]) -> Option<TcpSegmentMeta> {
    let version = *packet.first()? >> 4;
    let (is_ipv6, ip_header_len) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            // No IP options (IHL must be 5) and protocol must be TCP.
            if packet[0] & 0x0f != 5 || packet[9] != 6 {
                return None;
            }
            // No fragments: MF flag or nonzero fragment offset.
            let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
            if flags_frag & 0x3fff != 0 {
                return None;
            }
            // ECN bits in the ToS byte.
            if packet[1] & 0x03 != 0 {
                return None;
            }
            // Total length must match the buffer exactly.
            if usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len() {
                return None;
            }
            (false, 20)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            // Next header must be TCP directly (no extension-header walking).
            if packet[6] != 6 {
                return None;
            }
            // ECN bits live in the low two bits of the traffic class.
            let traffic_class = (packet[0] << 4) | (packet[1] >> 4);
            if traffic_class & 0x03 != 0 {
                return None;
            }
            // Payload length must match the buffer exactly.
            if usize::from(u16::from_be_bytes([packet[4], packet[5]])) != packet.len() - 40 {
                return None;
            }
            (true, 40)
        }
        _ => return None,
    };

    let tcp_offset = ip_header_len;
    if packet.len() < tcp_offset + 20 {
        return None;
    }
    let tcp_header_len = usize::from(packet[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_offset + tcp_header_len > packet.len() {
        return None;
    }
    if packet[tcp_offset + 13] & TCP_FLAGS_NO_COALESCE != 0 {
        return None;
    }
    let payload_len = packet.len() - tcp_offset - tcp_header_len;
    if payload_len == 0 {
        return None;
    }

    Some(TcpSegmentMeta {
        is_ipv6,
        ip_header_len,
        tcp_header_len,
        seq: u32::from_be_bytes([
            packet[tcp_offset + 4],
            packet[tcp_offset + 5],
            packet[tcp_offset + 6],
            packet[tcp_offset + 7],
        ]),
        payload_len,
    })
}

/// Return true if segment `b` can extend a coalescing group ending in `a`:
/// same flow (5-tuple, TTL/hop-limit, ToS/traffic-class), byte-identical TCP
/// header length/options/ACK/window, and contiguous sequence numbers.
///
/// Note: bulk bursts originate from our own read-side segmenter
/// ([`segment_tcp_gso_into`]), which copies one identical header (including
/// options such as timestamps) across all segments of a burst, so identical-
/// options matching re-merges exactly those bursts.
fn can_chain(a: &[u8], ma: &TcpSegmentMeta, b: &[u8], mb: &TcpSegmentMeta) -> bool {
    if ma.is_ipv6 != mb.is_ipv6 || ma.tcp_header_len != mb.tcp_header_len {
        return false;
    }

    if ma.is_ipv6 {
        // Version/traffic-class/flow-label words and src+dst addresses must
        // match; hop limit too.
        if a[0..4] != b[0..4] || a[8..40] != b[8..40] || a[7] != b[7] {
            return false;
        }
    } else {
        // ToS, TTL, and src+dst addresses must match.
        if a[1] != b[1] || a[8] != b[8] || a[12..20] != b[12..20] {
            return false;
        }
    }

    let t = ma.ip_header_len;
    // Ports, ACK number, window, and option bytes must be identical.
    if a[t..t + 4] != b[t..t + 4]
        || a[t + 8..t + 12] != b[t + 8..t + 12]
        || a[t + 14..t + 16] != b[t + 14..t + 16]
        || a[t + 20..t + ma.tcp_header_len] != b[t + 20..t + mb.tcp_header_len]
    {
        return false;
    }

    mb.seq == ma.seq.wrapping_add(ma.payload_len as u32)
}

/// Partition a drained TUN write batch into runs, preserving order.
///
/// Pushes `(start, end, coalesce)` tuples into `out` (cleared first).
/// `coalesce == true` marks a run of two or more same-flow contiguous TCP
/// segments with uniform payload size (only the final member may be smaller;
/// a smaller member closes the run) whose merged IP length stays within
/// `u16::MAX`. Every other packet becomes a `(i, i + 1, false)` passthrough.
pub fn plan_tun_write_groups(batch: &[Bytes], out: &mut Vec<(usize, usize, bool)>) {
    out.clear();
    let mut i = 0;
    while i < batch.len() {
        let Some(first) = parse_coalescible_tcp(&batch[i]) else {
            out.push((i, i + 1, false));
            i += 1;
            continue;
        };

        // Non-final members must match the first segment's payload size; a
        // shorter member is accepted as the final one and closes the run.
        let seg_size = first.payload_len;
        let mut merged_ip_len = first.header_len() + first.payload_len;
        let mut prev = first;
        let mut end = i + 1;
        while end < batch.len() {
            let Some(next) = parse_coalescible_tcp(&batch[end]) else {
                break;
            };
            if next.payload_len > seg_size
                || merged_ip_len + next.payload_len > usize::from(u16::MAX)
                || !can_chain(&batch[end - 1], &prev, &batch[end], &next)
            {
                break;
            }
            merged_ip_len += next.payload_len;
            prev = next;
            end += 1;
            if next.payload_len < seg_size {
                break;
            }
        }

        out.push((i, end, end - i >= 2));
        i = end;
    }
}

/// Compute the partial (folded, NOT complemented) TCP pseudo-header checksum
/// the kernel expects in the TCP checksum field of a `NEEDS_CSUM` frame.
///
/// `tcp_len` is the TCP header plus payload length covered by the frame.
fn tcp_pseudo_header_partial(ip_packet: &[u8], is_ipv6: bool, tcp_len: usize) -> u16 {
    let mut sum = 0u32;
    if is_ipv6 {
        sum = add_bytes(sum, &ip_packet[8..40]);
        sum = sum.wrapping_add((tcp_len as u32 >> 16) & 0xffff);
        sum = sum.wrapping_add(tcp_len as u32 & 0xffff);
    } else {
        sum = add_bytes(sum, &ip_packet[12..20]);
        sum = sum.wrapping_add(tcp_len as u32 & 0xffff);
    }
    sum = sum.wrapping_add(6u32);
    fold_checksum(sum)
}

/// Assemble a TCP GSO super-frame from a run of two or more same-flow
/// contiguous segments (as planned by [`plan_tun_write_groups`]) into `out`
/// (cleared first): 10-byte virtio header + IP/TCP headers copied from
/// `segments[0]` + concatenated payloads.
///
/// The copied header is rewritten for the merged frame: IP total length /
/// IPv6 payload length (and the IPv4 header checksum), plus the TCP checksum
/// field, which receives the partial pseudo-header sum required by
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`. The TCP sequence number stays at
/// `segments[0]`'s; the kernel renumbers per re-segmented packet. Merged
/// IPv4 segments' distinct IP IDs collapse to `segments[0]`'s — the kernel
/// assigns incrementing IDs on re-segmentation, same as real GRO/GSO.
pub fn assemble_tcp_gso_superframe(out: &mut BytesMut, segments: &[Bytes]) -> Result<(), String> {
    if segments.len() < 2 {
        return Err(format!(
            "GSO super-frame needs at least 2 segments, got {}",
            segments.len()
        ));
    }

    let first = parse_coalescible_tcp(&segments[0])
        .ok_or_else(|| "first segment is not a coalescible TCP segment".to_string())?;
    let header_len = first.header_len();

    let mut total_payload = 0usize;
    for segment in segments {
        let payload = segment
            .len()
            .checked_sub(header_len)
            .filter(|len| *len > 0)
            .ok_or_else(|| "segment shorter than flow headers".to_string())?;
        total_payload += payload;
    }
    let merged_ip_len = header_len + total_payload;
    if merged_ip_len > usize::from(u16::MAX) {
        return Err(format!(
            "merged GSO frame too large: {} bytes",
            merged_ip_len
        ));
    }

    let virtio = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: if first.is_ipv6 {
            VIRTIO_NET_HDR_GSO_TCPV6
        } else {
            VIRTIO_NET_HDR_GSO_TCPV4
        },
        hdr_len: header_len as u16,
        gso_size: first.payload_len as u16,
        csum_start: first.ip_header_len as u16,
        csum_offset: 16,
        num_buffers: 0,
    };

    out.clear();
    out.reserve(VIRTIO_NET_HDR_LEN + merged_ip_len);
    out.put_slice(&virtio.to_bytes());
    out.put_slice(&segments[0][..header_len]);
    for segment in segments {
        out.put_slice(&segment[header_len..]);
    }

    let ip_frame = &mut out[VIRTIO_NET_HDR_LEN..];
    if first.is_ipv6 {
        update_ipv6_payload_length(ip_frame, merged_ip_len)?;
    } else {
        update_ipv4_lengths_and_checksum(ip_frame, merged_ip_len)?;
    }

    let checksum_index = first.ip_header_len + 16;
    ip_frame[checksum_index] = 0;
    ip_frame[checksum_index + 1] = 0;
    let tcp_len = first.tcp_header_len + total_payload;
    let partial = tcp_pseudo_header_partial(ip_frame, first.is_ipv6, tcp_len);
    ip_frame[checksum_index..checksum_index + 2].copy_from_slice(&partial.to_be_bytes());

    Ok(())
}

/// Software fallback: segment a TCP GSO packet into plain TCP packets,
/// emitting each segment via callback without per-segment heap allocation.
///
/// Each segment is built into the caller-provided `scratch` buffer (reused
/// across segments and across calls) and handed to `emit` as a borrowed
/// slice. The single-segment fast path emits `ip_packet` directly with no
/// copy unless NEEDS_CSUM requires completing the partial checksum first.
/// An error returned by `emit` short-circuits segmentation.
///
/// This is used when offload metadata is present but the local write path or
/// remote peer cannot handle GSO metadata directly.
pub fn segment_tcp_gso_into<F>(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
    scratch: &mut Vec<u8>,
    mut emit: F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if !offload.is_tcp_gso() {
        return Err("offload header is not TCP GSO".to_string());
    }

    if ip_packet.is_empty() {
        return Err("empty IP packet".to_string());
    }

    let version = ip_packet[0] >> 4;
    let normalized_type = offload.normalized_gso_type();
    match (version, normalized_type) {
        (4, VIRTIO_NET_HDR_GSO_TCPV4) | (6, VIRTIO_NET_HDR_GSO_TCPV6) => {}
        (4, other) | (6, other) => {
            return Err(format!(
                "IP version/GSO mismatch (ip v{}, gso type 0x{:02x})",
                version, other
            ));
        }
        _ => return Err(format!("unsupported IP version {}", version)),
    }

    let header_len = usize::from(offload.hdr_len);
    if header_len == 0 || header_len > ip_packet.len() {
        return Err(format!(
            "invalid offload hdr_len {} for packet length {}",
            header_len,
            ip_packet.len()
        ));
    }

    let tcp_offset = usize::from(offload.csum_start);
    if tcp_offset + 20 > header_len {
        return Err(format!(
            "invalid csum_start {} for header_len {}",
            tcp_offset, header_len
        ));
    }

    let tcp_header_len = usize::from(ip_packet[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_offset + tcp_header_len > header_len {
        return Err(format!(
            "invalid TCP header length {} (offset {}, header_len {})",
            tcp_header_len, tcp_offset, header_len
        ));
    }

    let checksum_index = tcp_offset + usize::from(offload.csum_offset);
    if checksum_index + 2 > header_len {
        return Err(format!(
            "invalid csum_offset {} (checksum index {} beyond header_len {})",
            offload.csum_offset, checksum_index, header_len
        ));
    }

    let payload = &ip_packet[header_len..];
    let gso_size = usize::from(offload.gso_size);
    if payload.len() <= gso_size {
        // Single segment: no resegmentation needed, but a NEEDS_CSUM packet
        // still carries only the partial pseudo-header checksum, which must
        // be completed before emitting as a plain packet.
        if !offload.needs_checksum() {
            return emit(ip_packet);
        }
        scratch.clear();
        scratch.extend_from_slice(ip_packet);
        let checksum = finalize_checksum(add_bytes(0, &scratch[tcp_offset..]));
        scratch[checksum_index..checksum_index + 2].copy_from_slice(&checksum.to_be_bytes());
        return emit(scratch);
    }

    let base_seq = u32::from_be_bytes([
        ip_packet[tcp_offset + 4],
        ip_packet[tcp_offset + 5],
        ip_packet[tcp_offset + 6],
        ip_packet[tcp_offset + 7],
    ]);
    let original_tcp_flags = ip_packet[tcp_offset + 13];

    for chunk_offset in (0..payload.len()).step_by(gso_size) {
        let chunk_end = (chunk_offset + gso_size).min(payload.len());
        let chunk = &payload[chunk_offset..chunk_end];

        scratch.clear();
        scratch.reserve(header_len + chunk.len());
        scratch.extend_from_slice(&ip_packet[..header_len]);
        scratch.extend_from_slice(chunk);

        // Sequence number increments by payload bytes emitted in previous segments.
        let chunk_offset_u32 = u32::try_from(chunk_offset).map_err(|_| {
            format!(
                "TCP GSO payload offset {} exceeds u32 range for sequence number",
                chunk_offset
            )
        })?;
        let seq = base_seq.wrapping_add(chunk_offset_u32);
        scratch[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());

        // FIN/PSH belong only on the last segment.
        if chunk_end < payload.len() {
            scratch[tcp_offset + 13] = original_tcp_flags & !(0x01 | 0x08);
        }

        // Update IP length fields and checksum first.
        match version {
            4 => update_ipv4_lengths_and_checksum(scratch, header_len + chunk.len())?,
            6 => update_ipv6_payload_length(scratch, header_len + chunk.len())?,
            _ => unreachable!(),
        }

        // Recalculate TCP checksum for this segment.
        scratch[checksum_index] = 0;
        scratch[checksum_index + 1] = 0;
        let checksum = match version {
            4 => tcp_checksum_ipv4(scratch, tcp_offset)?,
            6 => tcp_checksum_ipv6(scratch, tcp_offset)?,
            _ => unreachable!(),
        };
        scratch[checksum_index..checksum_index + 2].copy_from_slice(&checksum.to_be_bytes());

        emit(scratch)?;
    }

    Ok(())
}

/// Software fallback: segment a TCP GSO packet into plain TCP packets.
///
/// Allocating wrapper around [`segment_tcp_gso_into`]; production paths use
/// the streaming variant.
#[cfg(test)]
pub fn segment_tcp_gso_packet(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut scratch = Vec::new();
    segment_tcp_gso_into(offload, ip_packet, &mut scratch, |seg| {
        out.push(seg.to_vec());
        Ok(())
    })?;
    Ok(out)
}

/// Convert offload metadata into one or more plain IP packets, emitting each
/// via callback without per-packet heap allocation.
///
/// TCP GSO packets are segmented via [`segment_tcp_gso_into`]. Checksum-only
/// packets have their partial checksum completed into `scratch` and emitted
/// once; packets needing no work are emitted directly with no copy.
pub fn materialize_offload_into<F>(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
    scratch: &mut Vec<u8>,
    mut emit: F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if offload.is_tcp_gso() {
        return segment_tcp_gso_into(offload, ip_packet, scratch, emit);
    }

    if offload.gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return Err(format!(
            "unsupported GSO type from offload metadata: 0x{:02x}",
            offload.gso_type
        ));
    }

    let Some((csum_start, checksum_index)) = validate_checksum_offload(offload, ip_packet)? else {
        return emit(ip_packet);
    };

    scratch.clear();
    scratch.extend_from_slice(ip_packet);
    let checksum = finalize_checksum(add_bytes(0, &scratch[csum_start..]));
    scratch[checksum_index..checksum_index + 2].copy_from_slice(&checksum.to_be_bytes());
    emit(scratch)
}

/// Convert offload metadata into one or more plain IP packets.
///
/// Allocating wrapper around [`materialize_offload_into`]; production paths
/// use the streaming variant.
#[cfg(test)]
pub fn materialize_offload_packet(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut scratch = Vec::new();
    materialize_offload_into(offload, ip_packet, &mut scratch, |packet| {
        out.push(packet.to_vec());
        Ok(())
    })?;
    Ok(out)
}

/// Validate checksum-only virtio metadata.
///
/// Returns `Ok(None)` when no checksum completion is needed, or
/// `Ok(Some((csum_start, checksum_index)))` when the partial checksum at
/// `checksum_index` must be finalized over `packet[csum_start..]`.
fn validate_checksum_offload(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
) -> Result<Option<(usize, usize)>, String> {
    if offload.gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return Err(format!(
            "checksum completion requires GSO_NONE, got 0x{:02x}",
            offload.gso_type
        ));
    }

    if ip_packet.is_empty() {
        return Err("empty IP packet".to_string());
    }

    if !offload.needs_checksum() {
        return Ok(None);
    }

    let unsupported_flags =
        offload.flags & !(VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID);
    if unsupported_flags != 0 {
        return Err(format!(
            "unsupported checksum offload flags: 0x{:02x}",
            unsupported_flags
        ));
    }

    let csum_start = usize::from(offload.csum_start);
    if csum_start >= ip_packet.len() {
        return Err(format!(
            "invalid csum_start {} for packet length {}",
            csum_start,
            ip_packet.len()
        ));
    }

    let checksum_index = csum_start
        .checked_add(usize::from(offload.csum_offset))
        .ok_or_else(|| {
            format!(
                "checksum index overflow (csum_start {}, csum_offset {})",
                offload.csum_start, offload.csum_offset
            )
        })?;
    if checksum_index + 2 > ip_packet.len() {
        return Err(format!(
            "invalid csum_offset {} (checksum index {} beyond packet length {})",
            offload.csum_offset,
            checksum_index,
            ip_packet.len()
        ));
    }

    Ok(Some((csum_start, checksum_index)))
}

/// Complete checksum-only virtio metadata and return a plain IP packet.
///
/// Allocating wrapper kept for tests; production paths use
/// [`materialize_offload_into`].
#[cfg(test)]
pub fn complete_checksum_offload_packet(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
) -> Result<Vec<u8>, String> {
    let Some((csum_start, checksum_index)) = validate_checksum_offload(offload, ip_packet)? else {
        return Ok(ip_packet.to_vec());
    };

    let mut out = ip_packet.to_vec();
    let checksum = finalize_checksum(add_bytes(0, &out[csum_start..]));
    out[checksum_index..checksum_index + 2].copy_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Software TCP GRO (generic receive offload)
//
// Inverse of `segment_tcp_gso_packet`: merges consecutive in-order, same-flow
// TCP segments into a single coalesced IP packet plus a synthetic
// `VirtioNetHdr`, suitable for sending as an offload-tagged frame. Used on
// the egress path when the local TUN does not provide kernel GRO/GSO.
// Semantics mirror wireguard-go's `tun/offload_linux.go`.
// ---------------------------------------------------------------------------

/// Maximum number of in-flight GRO flow groups held by a table.
const MAX_GRO_FLOWS: usize = 16;
/// Maximum number of TCP segments coalesced into a single group.
const MAX_GRO_SEGMENTS: usize = 64;
/// Maximum size of a coalesced IP packet (IPv4 total length limit).
const MAX_GRO_PACKET_SIZE: usize = 65535;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_URG: u8 = 0x20;
const TCP_FLAG_CWR: u8 = 0x80;

/// TCP options: end-of-options-list, no-op, timestamp.
const TCP_OPT_EOL: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_TIMESTAMP: u8 = 8;
const TCP_OPT_TIMESTAMP_LEN: usize = 10;

/// Identity of a TCP flow for GRO grouping.
///
/// IPv4 addresses are zero-padded to 16 bytes so both versions share one key
/// type; `is_v6` disambiguates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    is_v6: bool,
}

/// Parsed view of a TCP segment that is a candidate for coalescing.
struct TcpSegmentView<'a> {
    key: TcpFlowKey,
    ip_header_len: usize,
    tcp_header_len: usize,
    is_v6: bool,
    seq: u32,
    tcp_flags: u8,
    payload_len: usize,
    packet: &'a [u8],
}

/// Classification of a packet pushed into the GRO table.
enum GroClass<'a> {
    /// TCP segment eligible for coalescing.
    Coalescable(TcpSegmentView<'a>),
    /// Parseable TCP packet that must not be coalesced (pure ACK, SYN/RST/...).
    /// The flow key allows flushing a pending same-flow group first to
    /// preserve in-flow ordering.
    SameFlowPassThrough(TcpFlowKey),
    /// Anything else (non-TCP, fragments, parse failures).
    PassThrough,
}

/// Output emitted by the GRO table.
#[derive(Debug)]
pub enum CoalescedOutput {
    /// A plain IP packet to send without offload metadata
    /// (pass-through or a group that ended up with a single segment).
    Single(Vec<u8>),
    /// A coalesced multi-segment packet plus its synthetic offload header.
    Coalesced(VirtioNetHdr, Vec<u8>),
}

/// In-progress coalesced group for one TCP flow.
struct GroGroup {
    /// `[IP header][TCP header][concatenated payloads]`, headers from the
    /// first segment (timestamps and final FIN/PSH updated on append).
    buf: Vec<u8>,
    ip_header_len: usize,
    tcp_header_len: usize,
    is_v6: bool,
    /// Uniform segment payload size (MSS), set by the first segment.
    gso_size: usize,
    segment_count: usize,
    /// Expected sequence number of the next in-order segment.
    next_seq: u32,
    /// Monotonic creation order for stable flush ordering.
    order: u64,
}

enum AppendResult {
    /// Segment was appended; `closed` means the group must be emitted now
    /// (FIN/PSH or short final segment).
    Appended { closed: bool },
    /// Segment cannot extend this group (the group must be finalized and a
    /// new one started).
    Incompatible,
}

/// Classify an IP packet for GRO.
fn gro_classify(p: &[u8]) -> GroClass<'_> {
    if p.is_empty() {
        return GroClass::PassThrough;
    }

    let version = p[0] >> 4;
    let (ip_header_len, is_v6) = match version {
        4 => {
            if p.len() < 20 {
                return GroClass::PassThrough;
            }
            let ihl = usize::from(p[0] & 0x0f) * 4;
            if ihl < 20 || ihl > p.len() {
                return GroClass::PassThrough;
            }
            if p[9] != 6 {
                return GroClass::PassThrough;
            }
            if usize::from(u16::from_be_bytes([p[2], p[3]])) != p.len() {
                return GroClass::PassThrough;
            }
            // Fragmented packets (MF set or non-zero fragment offset) carry
            // at most a partial TCP header; never coalesce them.
            let frag = u16::from_be_bytes([p[6], p[7]]);
            if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
                return GroClass::PassThrough;
            }
            (ihl, false)
        }
        6 => {
            if p.len() < 40 {
                return GroClass::PassThrough;
            }
            // Reject extension headers: only TCP directly after the fixed header.
            if p[6] != 6 {
                return GroClass::PassThrough;
            }
            if usize::from(u16::from_be_bytes([p[4], p[5]])) != p.len() - 40 {
                return GroClass::PassThrough;
            }
            (40, true)
        }
        _ => return GroClass::PassThrough,
    };

    let tcp_offset = ip_header_len;
    if p.len() < tcp_offset + 20 {
        return GroClass::PassThrough;
    }
    let tcp_header_len = usize::from(p[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_offset + tcp_header_len > p.len() {
        return GroClass::PassThrough;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    if is_v6 {
        src.copy_from_slice(&p[8..24]);
        dst.copy_from_slice(&p[24..40]);
    } else {
        src[..4].copy_from_slice(&p[12..16]);
        dst[..4].copy_from_slice(&p[16..20]);
    }
    let key = TcpFlowKey {
        src,
        dst,
        src_port: u16::from_be_bytes([p[tcp_offset], p[tcp_offset + 1]]),
        dst_port: u16::from_be_bytes([p[tcp_offset + 2], p[tcp_offset + 3]]),
        is_v6,
    };

    let tcp_flags = p[tcp_offset + 13];
    let payload_len = p.len() - tcp_offset - tcp_header_len;
    // SYN/RST/URG never coalesce. CWR marks a congestion response boundary
    // (Linux GRO flushes on it too). Zero-payload packets (pure ACKs) pass
    // through so acknowledgments are never delayed.
    if tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_URG | TCP_FLAG_CWR) != 0
        || payload_len == 0
    {
        return GroClass::SameFlowPassThrough(key);
    }

    let seq = u32::from_be_bytes([
        p[tcp_offset + 4],
        p[tcp_offset + 5],
        p[tcp_offset + 6],
        p[tcp_offset + 7],
    ]);

    GroClass::Coalescable(TcpSegmentView {
        key,
        ip_header_len,
        tcp_header_len,
        is_v6,
        seq,
        tcp_flags,
        payload_len,
        packet: p,
    })
}

/// Compare two TCP option regions for GRO compatibility.
///
/// Returns `None` if incompatible. Otherwise returns the offset (within the
/// options region) of the timestamp TSval/TSecr data, if present: the
/// timestamp option's values may advance between segments and the latest is
/// carried into the coalesced header (everything else must be byte-identical).
fn tcp_options_compatible(a: &[u8], b: &[u8]) -> Option<Option<usize>> {
    if a.len() != b.len() {
        return None;
    }
    let mut ts_offset = None;
    let mut i = 0;
    while i < a.len() {
        let kind = a[i];
        if kind != b[i] {
            return None;
        }
        match kind {
            TCP_OPT_EOL => {
                // Remaining padding must match exactly.
                return if a[i..] == b[i..] {
                    Some(ts_offset)
                } else {
                    None
                };
            }
            TCP_OPT_NOP => i += 1,
            _ => {
                if i + 1 >= a.len() {
                    return None;
                }
                let len = usize::from(a[i + 1]);
                if a[i + 1] != b[i + 1] || len < 2 || i + len > a.len() {
                    return None;
                }
                if kind == TCP_OPT_TIMESTAMP && len == TCP_OPT_TIMESTAMP_LEN {
                    ts_offset = Some(i + 2);
                } else if a[i + 2..i + len] != b[i + 2..i + len] {
                    return None;
                }
                i += len;
            }
        }
    }
    Some(ts_offset)
}

impl GroGroup {
    fn new(seg: &TcpSegmentView<'_>, order: u64) -> Self {
        Self {
            buf: seg.packet.to_vec(),
            ip_header_len: seg.ip_header_len,
            tcp_header_len: seg.tcp_header_len,
            is_v6: seg.is_v6,
            gso_size: seg.payload_len,
            segment_count: 1,
            next_seq: seg.seq.wrapping_add(seg.payload_len as u32),
            order,
        }
    }

    /// Check that `seg`'s headers match this group's headers byte-for-byte,
    /// modulo fields that legitimately vary between consecutive segments.
    ///
    /// Returns `None` if incompatible, otherwise the timestamp option data
    /// offset (within the options region) if a timestamp option is present.
    fn headers_compatible(&self, seg: &TcpSegmentView<'_>) -> Option<Option<usize>> {
        if seg.ip_header_len != self.ip_header_len
            || seg.tcp_header_len != self.tcp_header_len
            || seg.is_v6 != self.is_v6
        {
            return None;
        }
        let g = self.buf.as_slice();
        let p = seg.packet;
        let ihl = self.ip_header_len;

        if self.is_v6 {
            // IPv6: identical except payload length (bytes 4..6).
            if g[0..4] != p[0..4] || g[6..40] != p[6..40] {
                return None;
            }
        } else {
            // IPv4: identical except total length (2..4), identification
            // (4..6) and header checksum (10..12).
            if g[0..2] != p[0..2] || g[6..10] != p[6..10] || g[12..ihl] != p[12..ihl] {
                return None;
            }
        }

        let t = ihl;
        // TCP: identical except seq (4..8), flags' FIN/PSH bits (13) and
        // checksum (16..18). Ack number, data offset, reserved bits, ECN
        // bits, window and urgent pointer must all match.
        if g[t..t + 4] != p[t..t + 4]
            || g[t + 8..t + 13] != p[t + 8..t + 13]
            || g[t + 14..t + 16] != p[t + 14..t + 16]
            || g[t + 18..t + 20] != p[t + 18..t + 20]
        {
            return None;
        }
        if g[t + 13] & !(TCP_FLAG_FIN | TCP_FLAG_PSH) != p[t + 13] & !(TCP_FLAG_FIN | TCP_FLAG_PSH)
        {
            return None;
        }

        tcp_options_compatible(
            &g[t + 20..t + self.tcp_header_len],
            &p[t + 20..t + self.tcp_header_len],
        )
    }

    fn try_append(&mut self, seg: &TcpSegmentView<'_>) -> AppendResult {
        if seg.seq != self.next_seq {
            return AppendResult::Incompatible;
        }
        // Non-final segments must all carry the group's uniform MSS; a larger
        // segment can never extend this group.
        if seg.payload_len > self.gso_size {
            return AppendResult::Incompatible;
        }
        if self.segment_count + 1 > MAX_GRO_SEGMENTS
            || self.buf.len() + seg.payload_len > MAX_GRO_PACKET_SIZE
        {
            return AppendResult::Incompatible;
        }
        let ts_offset = match self.headers_compatible(seg) {
            Some(ts) => ts,
            None => return AppendResult::Incompatible,
        };

        // Carry the latest timestamp TSval/TSecr into the coalesced header.
        if let Some(off) = ts_offset {
            let at = self.ip_header_len + 20 + off;
            self.buf[at..at + 8].copy_from_slice(&seg.packet[at..at + 8]);
        }

        self.buf
            .extend_from_slice(&seg.packet[seg.ip_header_len + seg.tcp_header_len..]);
        self.next_seq = self.next_seq.wrapping_add(seg.payload_len as u32);
        self.segment_count += 1;

        // FIN/PSH are only valid on the final segment; carrying one (or a
        // short segment, which ends the uniform-MSS run) closes the group.
        let fin_psh = seg.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);
        if fin_psh != 0 {
            self.buf[self.ip_header_len + 13] |= fin_psh;
        }
        AppendResult::Appended {
            closed: fin_psh != 0 || seg.payload_len < self.gso_size,
        }
    }

    /// Convert the group into its output form.
    ///
    /// Single-segment groups are emitted as the original plain packet.
    /// Multi-segment groups get updated IP lengths, a partial pseudo-header
    /// TCP checksum and a synthetic TCP GSO `virtio_net_hdr`.
    fn finalize(self) -> Result<CoalescedOutput, String> {
        if self.segment_count == 1 {
            return Ok(CoalescedOutput::Single(self.buf));
        }

        let mut buf = self.buf;
        let total_len = buf.len();
        if self.is_v6 {
            update_ipv6_payload_length(&mut buf, total_len)?;
        } else {
            update_ipv4_lengths_and_checksum(&mut buf, total_len)?;
        }

        // Store the folded (not complemented) pseudo-header checksum in the
        // TCP checksum field, per the Linux CHECKSUM_PARTIAL convention; the
        // kernel/NIC completes it per segment under TSO.
        let partial = tcp_pseudo_header_partial_checksum(&buf, self.is_v6, self.ip_header_len)?;
        let checksum_index = self.ip_header_len + 16;
        buf[checksum_index..checksum_index + 2].copy_from_slice(&partial.to_be_bytes());

        let hdr_len = u16::try_from(self.ip_header_len + self.tcp_header_len)
            .map_err(|_| "GRO header length exceeds u16".to_string())?;
        let gso_size = u16::try_from(self.gso_size)
            .map_err(|_| format!("GRO gso_size {} exceeds u16", self.gso_size))?;
        let csum_start = u16::try_from(self.ip_header_len)
            .map_err(|_| "GRO csum_start exceeds u16".to_string())?;
        let hdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            // CWR-marked segments are never coalesced, so the ECN GSO bit is
            // never needed here.
            gso_type: if self.is_v6 {
                VIRTIO_NET_HDR_GSO_TCPV6
            } else {
                VIRTIO_NET_HDR_GSO_TCPV4
            },
            hdr_len,
            gso_size,
            csum_start,
            csum_offset: 16,
            num_buffers: 0,
        };
        Ok(CoalescedOutput::Coalesced(hdr, buf))
    }
}

/// Result of pushing one packet into a [`TcpGroTable`].
///
/// `outputs` are finalized groups that must be emitted now, carrying data
/// older than the pushed packet. When `pass_through` is true the pushed
/// packet was not consumed and the caller must send the original packet
/// as-is, after `outputs`, preserving in-flow ordering. Pass-through packets
/// are never copied into the table.
#[derive(Debug)]
pub struct GroPush {
    pub outputs: Vec<CoalescedOutput>,
    pub pass_through: bool,
}

/// Bounded accumulator that coalesces in-order same-flow TCP segments.
///
/// `push` returns any outputs that must be emitted immediately; groups left
/// pending must be drained via `flush_all` so they never linger beyond the
/// caller's drain point (the moment the packet source goes empty).
pub struct TcpGroTable {
    groups: HashMap<TcpFlowKey, GroGroup>,
    next_order: u64,
}

impl Default for TcpGroTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpGroTable {
    pub fn new() -> Self {
        Self {
            groups: HashMap::with_capacity(MAX_GRO_FLOWS),
            next_order: 0,
        }
    }

    /// True if no groups are pending.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Push an IP packet into the table.
    ///
    /// Finalized groups (older data) are returned in `outputs` and always
    /// precede a pass-through packet carrying later data, preserving in-flow
    /// ordering. Pass-through packets (non-TCP, pure ACKs, FIN/PSH starters)
    /// are signaled via `pass_through` instead of being copied, so the common
    /// non-coalescable case allocates nothing.
    pub fn push(&mut self, ip_packet: &[u8]) -> GroPush {
        let mut out = Vec::new();
        let pass_through = match gro_classify(ip_packet) {
            GroClass::PassThrough => true,
            GroClass::SameFlowPassThrough(key) => {
                // Emit pending same-flow data first to preserve ordering.
                if let Some(group) = self.groups.remove(&key) {
                    Self::emit(group, &mut out);
                }
                true
            }
            GroClass::Coalescable(seg) => {
                if let Some(group) = self.groups.get_mut(&seg.key) {
                    match group.try_append(&seg) {
                        AppendResult::Appended { closed } => {
                            if closed {
                                let group = self
                                    .groups
                                    .remove(&seg.key)
                                    .expect("group present after append");
                                Self::emit(group, &mut out);
                            }
                            false
                        }
                        AppendResult::Incompatible => {
                            let group = self
                                .groups
                                .remove(&seg.key)
                                .expect("group present on incompatible append");
                            Self::emit(group, &mut out);
                            self.start_group(&seg, &mut out)
                        }
                    }
                } else {
                    self.start_group(&seg, &mut out)
                }
            }
        };
        GroPush {
            outputs: out,
            pass_through,
        }
    }

    /// Drain all pending groups (oldest first).
    pub fn flush_all(&mut self) -> Vec<CoalescedOutput> {
        let mut groups: Vec<GroGroup> = self.groups.drain().map(|(_, g)| g).collect();
        groups.sort_by_key(|g| g.order);
        let mut out = Vec::with_capacity(groups.len());
        for group in groups {
            Self::emit(group, &mut out);
        }
        out
    }

    /// Start a new group for `seg`, evicting the oldest group into `out` if
    /// the table is full. Returns true if the segment must instead pass
    /// through unmodified (FIN/PSH segments can never be extended).
    fn start_group(&mut self, seg: &TcpSegmentView<'_>, out: &mut Vec<CoalescedOutput>) -> bool {
        // FIN/PSH must end a group, so a segment carrying one can never be
        // extended; emit it directly without holding it back.
        if seg.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_PSH) != 0 {
            return true;
        }

        if self.groups.len() >= MAX_GRO_FLOWS {
            // Evict the oldest group to bound memory.
            if let Some(oldest) = self
                .groups
                .iter()
                .min_by_key(|(_, g)| g.order)
                .map(|(k, _)| *k)
                && let Some(group) = self.groups.remove(&oldest)
            {
                Self::emit(group, out);
            }
        }

        let order = self.next_order;
        self.next_order += 1;
        self.groups.insert(seg.key, GroGroup::new(seg, order));
        false
    }

    fn emit(group: GroGroup, out: &mut Vec<CoalescedOutput>) {
        match group.finalize() {
            Ok(output) => out.push(output),
            // Unreachable by construction (caps and header validation are
            // enforced before bytes enter a group); drop rather than emit a
            // corrupt frame — TCP retransmission recovers the data.
            Err(e) => log::warn!("Dropping malformed GRO group: {}", e),
        }
    }
}

/// Partial pseudo-header checksum stored in the TCP checksum field of a
/// TCP GSO packet (folded but NOT complemented), per the Linux
/// `CHECKSUM_PARTIAL` convention: the device sums the TCP header and payload
/// on top of it and complements the result per segment.
fn tcp_pseudo_header_partial_checksum(
    packet: &[u8],
    is_v6: bool,
    tcp_offset: usize,
) -> Result<u16, String> {
    let tcp_len = packet
        .len()
        .checked_sub(tcp_offset)
        .ok_or_else(|| "TCP length underflow".to_string())?;

    let mut sum = 0u32;
    if is_v6 {
        if packet.len() < 40 {
            return Err("IPv6 packet too short for pseudo-header".to_string());
        }
        let tcp_len_u32 = u32::try_from(tcp_len)
            .map_err(|_| format!("TCP length too large for pseudo-header: {}", tcp_len))?;
        sum = add_bytes(sum, &packet[8..40]);
        sum = sum.wrapping_add((tcp_len_u32 >> 16) & 0xffff);
        sum = sum.wrapping_add(tcp_len_u32 & 0xffff);
    } else {
        if packet.len() < 20 {
            return Err("IPv4 packet too short for pseudo-header".to_string());
        }
        let tcp_len_u16 = u16::try_from(tcp_len)
            .map_err(|_| format!("TCP length too large for pseudo-header: {}", tcp_len))?;
        sum = add_bytes(sum, &packet[12..20]);
        sum = sum.wrapping_add(u32::from(tcp_len_u16));
    }
    sum = sum.wrapping_add(6); // TCP protocol number
    Ok(fold_checksum(sum))
}

fn update_ipv4_lengths_and_checksum(packet: &mut [u8], packet_len: usize) -> Result<(), String> {
    if packet.len() < 20 {
        return Err("IPv4 packet too short".to_string());
    }

    if packet[9] != 6 {
        return Err(format!("IPv4 protocol {} is not TCP", packet[9]));
    }

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || ihl > packet.len() {
        return Err(format!("invalid IPv4 IHL {}", ihl));
    }

    let total_len = u16::try_from(packet_len)
        .map_err(|_| format!("IPv4 packet too large for total_len: {}", packet_len))?;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());

    packet[10] = 0;
    packet[11] = 0;
    let checksum = finalize_checksum(add_bytes(0, &packet[..ihl]));
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}

fn update_ipv6_payload_length(packet: &mut [u8], packet_len: usize) -> Result<(), String> {
    if packet.len() < 40 {
        return Err("IPv6 packet too short".to_string());
    }

    let payload_len = packet_len
        .checked_sub(40)
        .ok_or_else(|| "IPv6 packet length underflow".to_string())?;
    let payload_len_u16 = u16::try_from(payload_len)
        .map_err(|_| format!("IPv6 payload too large: {}", payload_len))?;
    packet[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());

    Ok(())
}

fn tcp_checksum_ipv4(packet: &[u8], tcp_offset: usize) -> Result<u16, String> {
    if packet.len() < 20 || tcp_offset >= packet.len() {
        return Err("invalid TCP offset for IPv4 checksum".to_string());
    }
    let tcp_len = packet
        .len()
        .checked_sub(tcp_offset)
        .ok_or_else(|| "TCP length underflow".to_string())?;
    let tcp_len_u16 = u16::try_from(tcp_len)
        .map_err(|_| format!("TCP segment too large for IPv4 checksum: {}", tcp_len))?;

    let mut sum = 0u32;
    sum = add_bytes(sum, &packet[12..20]);
    sum = sum.wrapping_add(u32::from(6u16));
    sum = sum.wrapping_add(u32::from(tcp_len_u16));
    sum = add_bytes(sum, &packet[tcp_offset..]);
    Ok(finalize_checksum(sum))
}

fn tcp_checksum_ipv6(packet: &[u8], tcp_offset: usize) -> Result<u16, String> {
    if packet.len() < 40 || tcp_offset >= packet.len() {
        return Err("invalid TCP offset for IPv6 checksum".to_string());
    }
    let tcp_len = packet
        .len()
        .checked_sub(tcp_offset)
        .ok_or_else(|| "TCP length underflow".to_string())?;
    let tcp_len_u32 = u32::try_from(tcp_len)
        .map_err(|_| format!("TCP segment too large for IPv6 checksum: {}", tcp_len))?;

    let mut sum = 0u32;
    sum = add_bytes(sum, &packet[8..24]);
    sum = add_bytes(sum, &packet[24..40]);
    sum = sum.wrapping_add((tcp_len_u32 >> 16) & 0xffff);
    sum = sum.wrapping_add(tcp_len_u32 & 0xffff);
    sum = sum.wrapping_add(u32::from(6u16));
    sum = add_bytes(sum, &packet[tcp_offset..]);
    Ok(finalize_checksum(sum))
}

fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn finalize_checksum(sum: u32) -> u16 {
    !fold_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{IpNumber, Ipv4Header, Ipv6Header, PacketHeaders, TransportHeader};

    fn build_ipv4_tcp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 251) as u8).collect();

        let mut tcp = etherparse::TcpHeader::new(12345, 443, 10_000, 65_535);
        tcp.ack = true;
        tcp.psh = true;
        tcp.fin = true;

        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid IPv4 header");
        tcp.checksum = tcp
            .calc_checksum_ipv4(&ip, &payload)
            .expect("valid IPv4 TCP checksum");
        ip.header_checksum = ip.calc_header_checksum();

        let mut packet = Vec::with_capacity(ip.header_len() + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv4 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(&payload);
        packet
    }

    fn build_ipv6_tcp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 253) as u8).collect();

        let mut tcp = etherparse::TcpHeader::new(12345, 443, 20_000, 65_535);
        tcp.ack = true;
        tcp.psh = true;
        tcp.fin = true;

        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: etherparse::Ipv6FlowLabel::ZERO,
            payload_length: u16::try_from(tcp.header_len() + payload.len())
                .expect("IPv6 payload length fits in u16"),
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            destination: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        tcp.checksum = tcp
            .calc_checksum_ipv6(&ip, &payload)
            .expect("valid IPv6 TCP checksum");

        let mut packet = Vec::with_capacity(40 + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv6 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(&payload);
        packet
    }

    fn assert_tcp_checksum_valid(packet: &[u8]) {
        let headers = PacketHeaders::from_ip_slice(packet).expect("packet parses");
        match (headers.net, headers.transport, headers.payload) {
            (
                Some(etherparse::NetHeaders::Ipv4(ip, _)),
                Some(TransportHeader::Tcp(tcp)),
                etherparse::PayloadSlice::Tcp(payload),
            ) => {
                let expected = tcp
                    .calc_checksum_ipv4(&ip, payload)
                    .expect("IPv4 checksum calculation succeeds");
                assert_eq!(tcp.checksum, expected, "invalid IPv4 TCP checksum");
            }
            (
                Some(etherparse::NetHeaders::Ipv6(ip, _)),
                Some(TransportHeader::Tcp(tcp)),
                etherparse::PayloadSlice::Tcp(payload),
            ) => {
                let expected = tcp
                    .calc_checksum_ipv6(&ip, payload)
                    .expect("IPv6 checksum calculation succeeds");
                assert_eq!(tcp.checksum, expected, "invalid IPv6 TCP checksum");
            }
            _ => panic!("packet is not TCP over IP"),
        }
    }

    fn make_ipv4_tcp_partial_checksum(packet: &[u8]) -> Vec<u8> {
        let tcp_offset = 20;
        let checksum_index = tcp_offset + 16;
        let tcp_len = packet.len() - tcp_offset;
        let mut partial = packet.to_vec();
        partial[checksum_index] = 0;
        partial[checksum_index + 1] = 0;

        let pseudo_header_sum = tcp_pseudo_header_partial(&partial, false, tcp_len);
        partial[checksum_index..checksum_index + 2]
            .copy_from_slice(&pseudo_header_sum.to_be_bytes());
        partial
    }

    /// Build one TCP/IPv4 segment of a fixed test flow for GRO tests.
    fn build_gro_segment_v4(seq: u32, payload: &[u8], psh: bool, fin: bool) -> Vec<u8> {
        let mut tcp = etherparse::TcpHeader::new(12345, 443, seq, 65_535);
        tcp.ack = true;
        tcp.acknowledgment_number = 55_555;
        tcp.psh = psh;
        tcp.fin = fin;

        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid IPv4 header");
        tcp.checksum = tcp
            .calc_checksum_ipv4(&ip, payload)
            .expect("valid IPv4 TCP checksum");
        ip.header_checksum = ip.calc_header_checksum();

        let mut packet = Vec::with_capacity(ip.header_len() + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv4 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(payload);
        packet
    }

    fn set_gro_segment_source_port_v4(packet: &mut [u8], source_port: u16) {
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[36..38].copy_from_slice(&0u16.to_be_bytes());
        let checksum = tcp_checksum_ipv4(packet, 20).expect("valid IPv4 TCP checksum");
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    }

    fn gro_output_source_port_v4(output: &CoalescedOutput) -> u16 {
        let packet = match output {
            CoalescedOutput::Single(packet) => packet,
            CoalescedOutput::Coalesced(_, packet) => packet,
        };
        u16::from_be_bytes([packet[20], packet[21]])
    }

    /// Build one TCP/IPv6 segment of a fixed test flow for GRO tests.
    fn build_gro_segment_v6(seq: u32, payload: &[u8], psh: bool, fin: bool) -> Vec<u8> {
        let mut tcp = etherparse::TcpHeader::new(12345, 443, seq, 65_535);
        tcp.ack = true;
        tcp.acknowledgment_number = 55_555;
        tcp.psh = psh;
        tcp.fin = fin;

        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: etherparse::Ipv6FlowLabel::ZERO,
            payload_length: u16::try_from(tcp.header_len() + payload.len())
                .expect("IPv6 payload length fits in u16"),
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            destination: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        tcp.checksum = tcp
            .calc_checksum_ipv6(&ip, payload)
            .expect("valid IPv6 TCP checksum");

        let mut packet = Vec::with_capacity(40 + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv6 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(payload);
        packet
    }

    /// Build a uniform run of same-flow segments covering `total` bytes,
    /// with PSH set on the last segment.
    fn build_gro_flow(total: &[u8], mss: usize, v6: bool) -> Vec<Vec<u8>> {
        let base_seq = 10_000u32;
        let chunks: Vec<&[u8]> = total.chunks(mss).collect();
        chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                let seq = base_seq.wrapping_add((i * mss) as u32);
                let last = i == chunks.len() - 1;
                if v6 {
                    build_gro_segment_v6(seq, chunk, last, false)
                } else {
                    build_gro_segment_v4(seq, chunk, last, false)
                }
            })
            .collect()
    }

    /// Test shim over [`TcpGroTable::push`] mirroring the old copying API:
    /// converts a pass-through signal back into an owned `Single` output so
    /// assertions can treat all results uniformly.
    fn push_owned(table: &mut TcpGroTable, packet: &[u8]) -> Vec<CoalescedOutput> {
        let result = table.push(packet);
        let mut out = result.outputs;
        if result.pass_through {
            out.push(CoalescedOutput::Single(packet.to_vec()));
        }
        out
    }

    fn push_all(table: &mut TcpGroTable, segments: &[Vec<u8>]) -> Vec<CoalescedOutput> {
        let mut out = Vec::new();
        for seg in segments {
            out.extend(push_owned(table, seg));
        }
        out
    }

    /// Assert a GRO round-trip: coalesce `segments`, re-segment via
    /// `segment_tcp_gso_packet`, and require byte-identical originals.
    fn assert_gro_roundtrip(segments: &[Vec<u8>], mss: usize, v6: bool) {
        let mut table = TcpGroTable::new();
        let mut outputs = push_all(&mut table, segments);
        outputs.extend(table.flush_all());
        assert_eq!(outputs.len(), 1, "expected a single coalesced output");

        let (hdr, super_packet) = match &outputs[0] {
            CoalescedOutput::Coalesced(hdr, packet) => (hdr, packet),
            other => panic!("expected coalesced output, got {:?}", other),
        };

        let expected_gso_type = if v6 {
            VIRTIO_NET_HDR_GSO_TCPV6
        } else {
            VIRTIO_NET_HDR_GSO_TCPV4
        };
        assert_eq!(hdr.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.gso_type, expected_gso_type);
        assert_eq!(usize::from(hdr.gso_size), mss);
        let ip_header_len = if v6 { 40 } else { 20 };
        assert_eq!(usize::from(hdr.csum_start), ip_header_len);
        assert_eq!(hdr.csum_offset, 16);
        assert_eq!(usize::from(hdr.hdr_len), ip_header_len + 20);

        // The stored partial pseudo-header checksum must complete to a valid
        // full TCP checksum (same convention as checksum-only offload).
        let csum_hdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: hdr.hdr_len,
            gso_size: 0,
            csum_start: hdr.csum_start,
            csum_offset: hdr.csum_offset,
            num_buffers: 0,
        };
        let completed = complete_checksum_offload_packet(&csum_hdr, super_packet)
            .expect("complete partial checksum");
        assert_tcp_checksum_valid(&completed);

        // Re-segmenting the coalesced packet must reproduce the originals.
        let resegmented =
            segment_tcp_gso_packet(hdr, super_packet).expect("re-segment coalesced packet");
        assert_eq!(resegmented.len(), segments.len());
        for (original, segment) in segments.iter().zip(&resegmented) {
            assert_eq!(original, segment, "round-trip mismatch");
            assert_tcp_checksum_valid(segment);
        }
    }

    #[test]
    fn test_virtio_header_roundtrip() {
        let hdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let encoded = hdr.to_bytes();
        let decoded = VirtioNetHdr::from_bytes(&encoded).expect("decode header");
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn test_split_tun_frame_with_plain_vnet_header() {
        let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
        frame.extend_from_slice(&[0x45, 0, 0, 20]);

        let (offload, payload) = split_tun_frame(&frame, true).expect("split frame");
        assert!(offload.is_none());
        assert_eq!(payload, &[0x45, 0, 0, 20]);
    }

    #[test]
    fn test_split_tun_frame_preserves_checksum_only_metadata() {
        let offload = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 40,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };
        let mut frame = offload.to_bytes().to_vec();
        frame.extend_from_slice(&[0x45, 0, 0, 20, 0, 0, 0, 0]);

        let (parsed_offload, payload) = split_tun_frame(&frame, true).expect("split frame");
        assert_eq!(parsed_offload, Some(offload));
        assert_eq!(payload, &[0x45, 0, 0, 20, 0, 0, 0, 0]);
    }

    #[test]
    fn test_compose_tun_frame_with_vnet_header() {
        let mut out = BytesMut::new();
        compose_tun_frame(&mut out, true, None, &[0x45, 1, 2, 3]).expect("compose frame");

        assert_eq!(out.len(), VIRTIO_NET_HDR_LEN + 4);
        assert!(out[..VIRTIO_NET_HDR_LEN].iter().all(|b| *b == 0));
        assert_eq!(&out[VIRTIO_NET_HDR_LEN..], &[0x45, 1, 2, 3]);
    }

    #[test]
    fn test_materialize_checksum_only_offload_completes_ipv4_tcp_checksum() {
        let packet = build_ipv4_tcp_packet(256);
        let partial = make_ipv4_tcp_partial_checksum(&packet);
        let offload = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let packets =
            materialize_offload_packet(&offload, &partial).expect("materialize checksum metadata");
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
        assert_tcp_checksum_valid(&packets[0]);
    }

    #[test]
    fn test_materialize_data_valid_offload_strips_metadata() {
        let packet = build_ipv4_tcp_packet(32);
        let offload = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_DATA_VALID,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let packets =
            materialize_offload_packet(&offload, &packet).expect("strip validated metadata");
        assert_eq!(packets, vec![packet]);
    }

    #[test]
    fn test_segment_tcp_gso_ipv4() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let segments = segment_tcp_gso_packet(&offload, &packet).expect("segment IPv4 packet");
        assert_eq!(segments.len(), 3);

        for (idx, segment) in segments.iter().enumerate() {
            assert_tcp_checksum_valid(segment);

            let headers = PacketHeaders::from_ip_slice(segment).expect("segment parses");
            let tcp = match headers.transport {
                Some(TransportHeader::Tcp(t)) => t,
                _ => panic!("not tcp"),
            };

            if idx < 2 {
                assert!(!tcp.fin, "FIN must be cleared in non-last segments");
                assert!(!tcp.psh, "PSH must be cleared in non-last segments");
            } else {
                assert!(tcp.fin, "FIN should remain set in last segment");
                assert!(tcp.psh, "PSH should remain set in last segment");
            }
        }
    }

    #[test]
    fn test_segment_tcp_gso_ipv6() {
        let packet = build_ipv6_tcp_packet(2600);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 60,
            gso_size: 1000,
            csum_start: 40,
            csum_offset: 16,
            num_buffers: 0,
        };

        let segments = segment_tcp_gso_packet(&offload, &packet).expect("segment IPv6 packet");
        assert_eq!(segments.len(), 3);

        for segment in segments {
            assert_tcp_checksum_valid(&segment);
            assert_eq!(segment[0] >> 4, 6);
        }
    }

    #[test]
    fn test_segment_tcp_gso_single_segment_completes_checksum() {
        // A NEEDS_CSUM GSO packet whose payload fits in a single segment must
        // still have its partial pseudo-header checksum completed instead of
        // being emitted as-is.
        let packet = build_ipv4_tcp_packet(800);
        let partial = make_ipv4_tcp_partial_checksum(&packet);
        let offload = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let segments = segment_tcp_gso_packet(&offload, &partial).expect("segment");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0], packet);
        assert_tcp_checksum_valid(&segments[0]);
    }

    #[test]
    fn test_segment_tcp_gso_into_scratch_reuse() {
        // Streaming output must match the collecting wrapper, including when
        // the scratch buffer is reused across packets of different sizes.
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let mut scratch = Vec::new();
        for payload_len in [3500, 800, 2401] {
            let packet = build_ipv4_tcp_packet(payload_len);
            let expected = segment_tcp_gso_packet(&offload, &packet).expect("segment");

            let mut streamed = Vec::new();
            segment_tcp_gso_into(&offload, &packet, &mut scratch, |seg| {
                streamed.push(seg.to_vec());
                Ok(())
            })
            .expect("segment into");

            assert_eq!(streamed, expected, "payload_len={}", payload_len);
        }
    }

    #[test]
    fn test_segment_tcp_gso_into_emit_error_short_circuits() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let mut scratch = Vec::new();
        let mut emitted = 0usize;
        let err = segment_tcp_gso_into(&offload, &packet, &mut scratch, |_| {
            emitted += 1;
            if emitted == 2 {
                Err("stop".to_string())
            } else {
                Ok(())
            }
        })
        .expect_err("emit error propagates");
        assert_eq!(err, "stop");
        assert_eq!(emitted, 2, "segmentation stops after emit error");
    }

    #[test]
    fn test_materialize_offload_into_checksum_only() {
        let packet = build_ipv4_tcp_packet(400);
        let partial = make_ipv4_tcp_partial_checksum(&packet);
        let offload = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let expected = complete_checksum_offload_packet(&offload, &partial).expect("complete");

        let mut scratch = Vec::new();
        let mut streamed = Vec::new();
        materialize_offload_into(&offload, &partial, &mut scratch, |pkt| {
            streamed.push(pkt.to_vec());
            Ok(())
        })
        .expect("materialize into");

        assert_eq!(streamed.len(), 1);
        assert_eq!(streamed[0], expected);
        assert_tcp_checksum_valid(&streamed[0]);
    }

    #[test]
    fn test_materialize_offload_into_no_checksum_passthrough() {
        // No NEEDS_CSUM: the packet must be emitted unchanged with no copy
        // into scratch.
        let packet = build_ipv4_tcp_packet(200);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        };

        let mut scratch = Vec::new();
        let mut streamed = Vec::new();
        materialize_offload_into(&offload, &packet, &mut scratch, |pkt| {
            streamed.push(pkt.to_vec());
            Ok(())
        })
        .expect("materialize into");

        assert_eq!(streamed, vec![packet]);
        assert!(scratch.is_empty(), "passthrough must not touch scratch");
    }

    #[test]
    fn test_gro_roundtrip_ipv4_exact_multiple() {
        // 3 x 1200-byte segments, PSH on the last closes the group.
        let total: Vec<u8> = (0..3600).map(|v| (v % 251) as u8).collect();
        let segments = build_gro_flow(&total, 1200, false);
        assert_eq!(segments.len(), 3);
        assert_gro_roundtrip(&segments, 1200, false);
    }

    #[test]
    fn test_gro_roundtrip_ipv4_short_tail() {
        // 1200 + 1200 + 600: the short tail closes the group without PSH help.
        let total: Vec<u8> = (0..3000).map(|v| (v % 251) as u8).collect();
        let mut segments = build_gro_flow(&total, 1200, false);
        // Strip PSH from the last segment and fix its checksum to prove the
        // short tail alone finalizes the group.
        let last = segments.last_mut().expect("segments");
        last[20 + 13] &= !TCP_FLAG_PSH;
        last[20 + 16] = 0;
        last[20 + 17] = 0;
        let checksum = tcp_checksum_ipv4(last, 20).expect("checksum");
        last[20 + 16..20 + 18].copy_from_slice(&checksum.to_be_bytes());

        assert_gro_roundtrip(&segments, 1200, false);
    }

    #[test]
    fn test_gro_roundtrip_ipv6() {
        let total: Vec<u8> = (0..2600).map(|v| (v % 253) as u8).collect();
        let segments = build_gro_flow(&total, 1000, true);
        assert_eq!(segments.len(), 3);
        assert_gro_roundtrip(&segments, 1000, true);
    }

    #[test]
    fn test_gro_flush_all_emits_open_group() {
        // Uniform segments without PSH stay pending until flushed.
        let total: Vec<u8> = (0..2400).map(|v| (v % 251) as u8).collect();
        let segments: Vec<Vec<u8>> = total
            .chunks(1200)
            .enumerate()
            .map(|(i, chunk)| build_gro_segment_v4(10_000 + (i * 1200) as u32, chunk, false, false))
            .collect();

        let mut table = TcpGroTable::new();
        let outputs = push_all(&mut table, &segments);
        assert!(outputs.is_empty(), "open group must not emit early");
        assert!(!table.is_empty());

        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 1);
        assert!(matches!(flushed[0], CoalescedOutput::Coalesced(_, _)));
        assert!(table.is_empty());
    }

    #[test]
    fn test_gro_flush_all_drains_groups_in_insertion_order() {
        let mut table = TcpGroTable::new();

        // Three distinct flows pushed in a known order; flush_all must emit them
        // oldest-first (by creation/insertion order).
        let mut first = build_gro_segment_v4(10_000, &[0x11; 100], false, false);
        set_gro_segment_source_port_v4(&mut first, 40_000);
        let mut second = build_gro_segment_v4(20_000, &[0x22; 100], false, false);
        set_gro_segment_source_port_v4(&mut second, 40_001);
        let mut third = build_gro_segment_v4(30_000, &[0x33; 100], false, false);
        set_gro_segment_source_port_v4(&mut third, 40_002);

        assert!(push_owned(&mut table, &first).is_empty());
        assert!(push_owned(&mut table, &second).is_empty());
        assert!(push_owned(&mut table, &third).is_empty());

        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 3);
        assert_eq!(gro_output_source_port_v4(&flushed[0]), 40_000);
        assert_eq!(gro_output_source_port_v4(&flushed[1]), 40_001);
        assert_eq!(gro_output_source_port_v4(&flushed[2]), 40_002);
        assert!(table.is_empty());
    }

    #[test]
    fn test_gro_single_segment_group_emits_plain_packet() {
        let segment = build_gro_segment_v4(10_000, &[0xaa; 1200], false, false);
        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &segment).is_empty());

        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 1);
        match &flushed[0] {
            CoalescedOutput::Single(packet) => assert_eq!(packet, &segment),
            other => panic!("expected single packet, got {:?}", other),
        }
    }

    #[test]
    fn test_gro_seq_gap_finalizes_group() {
        let seg1 = build_gro_segment_v4(10_000, &[0x11; 1200], false, false);
        // Gap: expected next seq is 11_200.
        let seg2 = build_gro_segment_v4(11_300, &[0x22; 1200], false, false);

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        let outputs = push_owned(&mut table, &seg2);
        // The out-of-order segment finalizes the old group (emitted as a
        // plain single packet) and starts a new group.
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            CoalescedOutput::Single(packet) => assert_eq!(packet, &seg1),
            other => panic!("expected single packet, got {:?}", other),
        }
        assert!(!table.is_empty());
    }

    #[test]
    fn test_gro_non_uniform_middle_segment_finalizes() {
        // 1200, then short 600 (closes a 2-segment group), then 1200 (new group).
        let seg1 = build_gro_segment_v4(10_000, &[0x11; 1200], false, false);
        let seg2 = build_gro_segment_v4(11_200, &[0x22; 600], false, false);
        let seg3 = build_gro_segment_v4(11_800, &[0x33; 1200], false, false);

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        let outputs = push_owned(&mut table, &seg2);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], CoalescedOutput::Coalesced(_, _)));

        assert!(push_owned(&mut table, &seg3).is_empty());
        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 1);
        assert!(matches!(flushed[0], CoalescedOutput::Single(_)));
    }

    #[test]
    fn test_gro_psh_mid_stream_closes_group() {
        let seg1 = build_gro_segment_v4(10_000, &[0x11; 1200], false, false);
        let seg2 = build_gro_segment_v4(11_200, &[0x22; 1200], true, false);
        let seg3 = build_gro_segment_v4(12_400, &[0x33; 1200], false, false);

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        let outputs = push_owned(&mut table, &seg2);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            CoalescedOutput::Coalesced(hdr, packet) => {
                // PSH carried into the coalesced header.
                assert_ne!(packet[20 + 13] & TCP_FLAG_PSH, 0);
                assert_eq!(usize::from(hdr.gso_size), 1200);
            }
            other => panic!("expected coalesced output, got {:?}", other),
        }
        // The next segment starts a fresh group; nothing coalesces after PSH.
        assert!(push_owned(&mut table, &seg3).is_empty());
        assert_eq!(table.flush_all().len(), 1);
    }

    #[test]
    fn test_gro_syn_rst_urg_pass_through() {
        let mut table = TcpGroTable::new();

        for set_flag in [TCP_FLAG_SYN, TCP_FLAG_RST, TCP_FLAG_URG] {
            let mut segment = build_gro_segment_v4(10_000, &[0x11; 100], false, false);
            segment[20 + 13] |= set_flag;
            let outputs = push_owned(&mut table, &segment);
            assert_eq!(outputs.len(), 1, "flag 0x{:02x}", set_flag);
            assert!(
                matches!(&outputs[0], CoalescedOutput::Single(p) if p == &segment),
                "flag 0x{:02x} must pass through unchanged",
                set_flag
            );
            assert!(
                table.is_empty(),
                "flag 0x{:02x} must not create a group",
                set_flag
            );
        }
    }

    #[test]
    fn test_gro_pure_ack_flushes_group_then_passes_through() {
        let seg1 = build_gro_segment_v4(10_000, &[0x11; 1200], false, false);
        let ack = build_gro_segment_v4(11_200, &[], false, false);

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        let outputs = push_owned(&mut table, &ack);
        // Pending same-flow data must be emitted before the pure ACK.
        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], CoalescedOutput::Single(p) if p == &seg1));
        assert!(matches!(&outputs[1], CoalescedOutput::Single(p) if p == &ack));
        assert!(table.is_empty());
    }

    #[test]
    fn test_gro_non_tcp_pass_through() {
        // Minimal IPv4 UDP packet (proto 17), total length matching.
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(28u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;

        let mut table = TcpGroTable::new();
        let outputs = push_owned(&mut table, &packet);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], CoalescedOutput::Single(p) if p == &packet));
        assert!(table.is_empty());
    }

    #[test]
    fn test_gro_ipv4_fragment_pass_through() {
        let mut segment = build_gro_segment_v4(10_000, &[0x11; 1200], false, false);
        // Set the More Fragments flag.
        segment[6] |= 0x20;

        let mut table = TcpGroTable::new();
        let outputs = push_owned(&mut table, &segment);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], CoalescedOutput::Single(p) if p == &segment));
        assert!(table.is_empty());
    }

    #[test]
    fn test_gro_interleaved_flows_coalesce_separately() {
        // Flow A: default test flow; flow B: different source port.
        let make_b = |seq: u32, payload: &[u8]| {
            let mut segment = build_gro_segment_v4(seq, payload, false, false);
            segment[20..22].copy_from_slice(&54_321u16.to_be_bytes());
            segment[20 + 16] = 0;
            segment[20 + 17] = 0;
            let checksum = tcp_checksum_ipv4(&segment, 20).expect("checksum");
            segment[20 + 16..20 + 18].copy_from_slice(&checksum.to_be_bytes());
            segment
        };

        let mut table = TcpGroTable::new();
        assert!(
            push_owned(
                &mut table,
                &build_gro_segment_v4(10_000, &[0x11; 1000], false, false)
            )
            .is_empty()
        );
        assert!(push_owned(&mut table, &make_b(20_000, &[0x22; 800])).is_empty());
        assert!(
            push_owned(
                &mut table,
                &build_gro_segment_v4(11_000, &[0x11; 1000], false, false)
            )
            .is_empty()
        );
        assert!(push_owned(&mut table, &make_b(20_800, &[0x22; 800])).is_empty());

        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 2);
        for output in &flushed {
            match output {
                CoalescedOutput::Coalesced(hdr, packet) => {
                    let mss = usize::from(hdr.gso_size);
                    assert!(mss == 1000 || mss == 800);
                    assert_eq!(packet.len(), 20 + 20 + 2 * mss);
                }
                other => panic!("expected coalesced output, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_gro_segment_count_cap_finalizes() {
        let mut table = TcpGroTable::new();
        let mut outputs = Vec::new();
        for i in 0..(MAX_GRO_SEGMENTS + 1) {
            let seq = 10_000u32.wrapping_add((i * 100) as u32);
            let segment = build_gro_segment_v4(seq, &[0x11; 100], false, false);
            outputs.extend(push_owned(&mut table, &segment));
        }
        // Segment MAX+1 exceeded the count cap: the full group was emitted
        // and a new group started.
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            CoalescedOutput::Coalesced(hdr, packet) => {
                assert_eq!(packet.len(), 40 + MAX_GRO_SEGMENTS * 100);
                assert_eq!(usize::from(hdr.gso_size), 100);
            }
            other => panic!("expected coalesced output, got {:?}", other),
        }
        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 1);
        assert!(matches!(flushed[0], CoalescedOutput::Single(_)));
    }

    #[test]
    fn test_gro_size_cap_finalizes() {
        // 9000-byte payloads: 7 segments fit (40 + 63000 <= 65535), the 8th
        // would exceed the 64KB cap and must finalize the group.
        let mut table = TcpGroTable::new();
        let mut outputs = Vec::new();
        for i in 0..8u32 {
            let segment = build_gro_segment_v4(10_000 + i * 9000, &[0x11; 9000], false, false);
            outputs.extend(push_owned(&mut table, &segment));
        }
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            CoalescedOutput::Coalesced(_, packet) => {
                assert_eq!(packet.len(), 40 + 7 * 9000);
                assert!(packet.len() <= MAX_GRO_PACKET_SIZE);
            }
            other => panic!("expected coalesced output, got {:?}", other),
        }
        assert_eq!(table.flush_all().len(), 1);
    }

    #[test]
    fn test_gro_flow_cap_evicts_oldest() {
        let mut table = TcpGroTable::new();
        for i in 0..MAX_GRO_FLOWS {
            let mut segment = build_gro_segment_v4(10_000, &[0x11; 100], false, false);
            segment[20..22].copy_from_slice(&(40_000 + i as u16).to_be_bytes());
            assert!(push_owned(&mut table, &segment).is_empty());
        }

        // One more flow evicts the oldest group.
        let mut segment = build_gro_segment_v4(10_000, &[0x11; 100], false, false);
        segment[20..22].copy_from_slice(&60_000u16.to_be_bytes());
        let outputs = push_owned(&mut table, &segment);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            CoalescedOutput::Single(packet) => {
                assert_eq!(&packet[20..22], &40_000u16.to_be_bytes());
            }
            other => panic!("expected single packet, got {:?}", other),
        }
    }

    #[test]
    fn test_gro_timestamp_option_carries_latest() {
        use etherparse::TcpOptionElement;

        let build = |seq: u32, payload: &[u8], tsval: u32| {
            let mut tcp = etherparse::TcpHeader::new(12345, 443, seq, 65_535);
            tcp.ack = true;
            tcp.acknowledgment_number = 55_555;
            tcp.set_options(&[
                TcpOptionElement::Noop,
                TcpOptionElement::Noop,
                TcpOptionElement::Timestamp(tsval, 777),
            ])
            .expect("set options");

            let mut ip = Ipv4Header::new(
                (tcp.header_len() + payload.len()) as u16,
                64,
                IpNumber::TCP,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
            )
            .expect("valid IPv4 header");
            tcp.checksum = tcp
                .calc_checksum_ipv4(&ip, payload)
                .expect("valid checksum");
            ip.header_checksum = ip.calc_header_checksum();

            let mut packet = Vec::new();
            ip.write(&mut packet).expect("serialize IPv4 header");
            tcp.write(&mut packet).expect("serialize TCP header");
            packet.extend_from_slice(payload);
            packet
        };

        let seg1 = build(10_000, &[0x11; 1000], 1_000);
        let seg2 = build(11_000, &[0x22; 1000], 1_001);

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        assert!(push_owned(&mut table, &seg2).is_empty());

        let flushed = table.flush_all();
        assert_eq!(flushed.len(), 1);
        match &flushed[0] {
            CoalescedOutput::Coalesced(_, packet) => {
                // Options: NOP NOP TS(kind 8, len 10, tsval, tsecr).
                let opts = &packet[40..52];
                assert_eq!(opts[0], TCP_OPT_NOP);
                assert_eq!(opts[1], TCP_OPT_NOP);
                assert_eq!(opts[2], TCP_OPT_TIMESTAMP);
                let tsval = u32::from_be_bytes([opts[4], opts[5], opts[6], opts[7]]);
                assert_eq!(tsval, 1_001, "latest TSval must be carried");
            }
            other => panic!("expected coalesced output, got {:?}", other),
        }
    }

    #[test]
    fn test_gro_differing_ack_finalizes_group() {
        let seg1 = build_gro_segment_v4(10_000, &[0x11; 1000], false, false);
        let mut seg2 = build_gro_segment_v4(11_000, &[0x22; 1000], false, false);
        // Bump the ack number and fix the checksum.
        seg2[20 + 8..20 + 12].copy_from_slice(&66_666u32.to_be_bytes());
        seg2[20 + 16] = 0;
        seg2[20 + 17] = 0;
        let checksum = tcp_checksum_ipv4(&seg2, 20).expect("checksum");
        seg2[20 + 16..20 + 18].copy_from_slice(&checksum.to_be_bytes());

        let mut table = TcpGroTable::new();
        assert!(push_owned(&mut table, &seg1).is_empty());
        let outputs = push_owned(&mut table, &seg2);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], CoalescedOutput::Single(p) if p == &seg1));
        assert!(!table.is_empty());
    }

    // -----------------------------------------------------------------------
    // Write-side GRO coalescing (plan_tun_write_groups /
    // assemble_tcp_gso_superframe)
    // -----------------------------------------------------------------------

    /// Build a pure-data TCP segment (ACK only, no options) suitable for
    /// coalescing, with valid checksums.
    fn build_data_segment(ipv6: bool, src_port: u16, seq: u32, payload_len: usize) -> Bytes {
        build_data_segment_with_options(ipv6, src_port, seq, payload_len, &[])
    }

    /// Same as [`build_data_segment`] but with explicit TCP options.
    fn build_data_segment_with_options(
        ipv6: bool,
        src_port: u16,
        seq: u32,
        payload_len: usize,
        options: &[etherparse::TcpOptionElement],
    ) -> Bytes {
        // Derive payload bytes from the sequence number so each segment's
        // payload is distinguishable.
        let payload: Vec<u8> = (0..payload_len)
            .map(|v| ((v as u32).wrapping_add(seq) % 251) as u8)
            .collect();

        let mut tcp = etherparse::TcpHeader::new(src_port, 443, seq, 65_535);
        tcp.ack = true;
        tcp.acknowledgment_number = 0x1122_3344;
        tcp.set_options(options).expect("valid TCP options");

        let mut packet = Vec::new();
        if ipv6 {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: etherparse::Ipv6FlowLabel::ZERO,
                payload_length: u16::try_from(tcp.header_len() + payload.len())
                    .expect("IPv6 payload length fits in u16"),
                next_header: IpNumber::TCP,
                hop_limit: 64,
                source: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                destination: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            };
            tcp.checksum = tcp
                .calc_checksum_ipv6(&ip, &payload)
                .expect("valid IPv6 TCP checksum");
            ip.write(&mut packet).expect("serialize IPv6 header");
        } else {
            let mut ip = Ipv4Header::new(
                (tcp.header_len() + payload.len()) as u16,
                64,
                IpNumber::TCP,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
            )
            .expect("valid IPv4 header");
            tcp.checksum = tcp
                .calc_checksum_ipv4(&ip, &payload)
                .expect("valid IPv4 TCP checksum");
            ip.header_checksum = ip.calc_header_checksum();
            ip.write(&mut packet).expect("serialize IPv4 header");
        }
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(&payload);
        Bytes::from(packet)
    }

    /// Build a contiguous run of equal-size segments for one flow.
    fn build_run(ipv6: bool, src_port: u16, base_seq: u32, sizes: &[usize]) -> Vec<Bytes> {
        let mut seq = base_seq;
        sizes
            .iter()
            .map(|&len| {
                let seg = build_data_segment(ipv6, src_port, seq, len);
                seq = seq.wrapping_add(len as u32);
                seg
            })
            .collect()
    }

    fn plan(batch: &[Bytes]) -> Vec<(usize, usize, bool)> {
        let mut out = Vec::new();
        plan_tun_write_groups(batch, &mut out);
        out
    }

    #[test]
    fn test_plan_groups_coalesces_contiguous_run() {
        let batch = build_run(false, 12345, 10_000, &[1000, 1000, 1000]);
        assert_eq!(plan(&batch), vec![(0, 3, true)]);
    }

    #[test]
    fn test_plan_groups_last_smaller_closes_run() {
        // The short third segment is accepted as the final member; the
        // following full-size segment starts a new (singleton) group.
        let batch = build_run(false, 12345, 10_000, &[1000, 1000, 500, 1000]);
        assert_eq!(plan(&batch), vec![(0, 3, true), (3, 4, false)]);
    }

    #[test]
    fn test_plan_groups_splits_on_seq_gap() {
        let mut batch = build_run(false, 12345, 10_000, &[1000, 1000]);
        // Third segment leaves a 1-byte hole in the sequence space.
        batch.push(build_data_segment(false, 12345, 12_001, 1000));
        assert_eq!(plan(&batch), vec![(0, 2, true), (2, 3, false)]);
    }

    #[test]
    fn test_plan_groups_splits_on_size_increase() {
        // A larger follow-up segment cannot join (non-final members must
        // match the first segment's size).
        let small = build_data_segment(false, 12345, 10_000, 500);
        let large = build_data_segment(false, 12345, 10_500, 1000);
        assert_eq!(plan(&[small, large]), vec![(0, 1, false), (1, 2, false)]);
    }

    #[test]
    fn test_plan_groups_interleaved_flows_are_singletons() {
        let a = build_run(false, 1111, 10_000, &[800, 800]);
        let b = build_run(false, 2222, 50_000, &[800, 800]);
        let batch = vec![a[0].clone(), b[0].clone(), a[1].clone(), b[1].clone()];
        assert_eq!(
            plan(&batch),
            vec![(0, 1, false), (1, 2, false), (2, 3, false), (3, 4, false)]
        );
    }

    #[test]
    fn test_plan_groups_non_tcp_splits_run() {
        let run = build_run(false, 12345, 10_000, &[1000, 1000, 1000, 1000]);
        // Turn the third segment into UDP (protocol byte only; the length
        // fields stay consistent).
        let mut udp = run[2].to_vec();
        udp[9] = 17;
        let batch = vec![
            run[0].clone(),
            run[1].clone(),
            Bytes::from(udp),
            run[3].clone(),
        ];
        assert_eq!(
            plan(&batch),
            vec![(0, 2, true), (2, 3, false), (3, 4, false)]
        );
    }

    #[test]
    fn test_plan_groups_never_merges_across_ip_versions() {
        let mut batch = build_run(false, 12345, 10_000, &[700, 700]);
        batch.extend(build_run(true, 12345, 90_000, &[700, 700]));
        assert_eq!(plan(&batch), vec![(0, 2, true), (2, 4, true)]);
    }

    #[test]
    fn test_plan_groups_rejects_flagged_segments() {
        let run = build_run(false, 12345, 10_000, &[600, 600, 600]);
        // Set FIN on the middle segment.
        let mut finned = run[1].to_vec();
        finned[20 + 13] |= 0x01;
        let batch = vec![run[0].clone(), Bytes::from(finned), run[2].clone()];
        assert_eq!(
            plan(&batch),
            vec![(0, 1, false), (1, 2, false), (2, 3, false)]
        );
    }

    #[test]
    fn test_plan_groups_rejects_ecn_marked_segments() {
        let run = build_run(false, 12345, 10_000, &[600, 600]);
        let mut ecn = run[1].to_vec();
        ecn[1] |= 0x01; // ECT(1) in the ToS byte
        let batch = vec![run[0].clone(), Bytes::from(ecn)];
        assert_eq!(plan(&batch), vec![(0, 1, false), (1, 2, false)]);
    }

    #[test]
    fn test_plan_groups_rejects_fragments_options_and_ext_headers() {
        let v4 = build_data_segment(false, 12345, 10_000, 600);

        let mut fragment = v4.to_vec();
        fragment[6] |= 0x20; // more-fragments flag
        assert_eq!(plan(&[Bytes::from(fragment)]), vec![(0, 1, false)]);

        let mut with_options = v4.to_vec();
        with_options[0] = 0x46; // IHL = 6 (IP options present)
        assert_eq!(plan(&[Bytes::from(with_options)]), vec![(0, 1, false)]);

        let v6 = build_data_segment(true, 12345, 10_000, 600);
        let mut ext_header = v6.to_vec();
        ext_header[6] = 0; // hop-by-hop extension header
        assert_eq!(plan(&[Bytes::from(ext_header)]), vec![(0, 1, false)]);
    }

    #[test]
    fn test_plan_groups_splits_on_differing_ack() {
        let run = build_run(false, 12345, 10_000, &[600, 600]);
        let mut acked = run[1].to_vec();
        acked[20 + 8] ^= 0xff; // change the ACK number
        let batch = vec![run[0].clone(), Bytes::from(acked)];
        assert_eq!(plan(&batch), vec![(0, 1, false), (1, 2, false)]);
    }

    #[test]
    fn test_plan_groups_coalesces_identical_options_and_splits_on_mismatch() {
        // Segments from one read-side GSO burst share identical option
        // bytes (including timestamps) — they must coalesce.
        let ts = etherparse::TcpOptionElement::Timestamp(123, 456);
        let a =
            build_data_segment_with_options(false, 12345, 10_000, 600, std::slice::from_ref(&ts));
        let b = build_data_segment_with_options(false, 12345, 10_600, 600, &[ts]);
        assert_eq!(plan(&[a.clone(), b]), vec![(0, 2, true)]);

        // Differing timestamp values must split.
        let ts2 = etherparse::TcpOptionElement::Timestamp(124, 456);
        let c = build_data_segment_with_options(false, 12345, 10_600, 600, &[ts2]);
        assert_eq!(plan(&[a, c]), vec![(0, 1, false), (1, 2, false)]);
    }

    #[test]
    fn test_plan_groups_caps_merged_size() {
        // Three 30000-byte segments: the third would push the merged IP
        // length past u16::MAX, so the group closes after two.
        let batch = build_run(false, 12345, 10_000, &[30_000, 30_000, 30_000]);
        assert_eq!(plan(&batch), vec![(0, 2, true), (2, 3, false)]);
    }

    #[test]
    fn test_plan_groups_empty_and_singleton_batches() {
        assert_eq!(plan(&[]), vec![]);
        let single = build_data_segment(false, 12345, 10_000, 600);
        assert_eq!(plan(&[single]), vec![(0, 1, false)]);
    }

    /// Round-trip helper: assemble a super-frame from `segments`, validate
    /// the virtio metadata, then re-segment with the read-side segmenter
    /// (which performs the same finalization the kernel does) and assert the
    /// output reproduces the original segments byte-for-byte.
    fn assert_superframe_roundtrip(segments: &[Bytes], ipv6: bool, expected_gso_size: u16) {
        let mut out = BytesMut::new();
        assemble_tcp_gso_superframe(&mut out, segments).expect("assemble super-frame");

        let hdr = VirtioNetHdr::from_bytes(&out[..VIRTIO_NET_HDR_LEN]).expect("virtio header");
        let ip_header_len: u16 = if ipv6 { 40 } else { 20 };
        assert_eq!(hdr.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(
            hdr.gso_type,
            if ipv6 {
                VIRTIO_NET_HDR_GSO_TCPV6
            } else {
                VIRTIO_NET_HDR_GSO_TCPV4
            }
        );
        assert_eq!(hdr.csum_start, ip_header_len);
        assert_eq!(hdr.csum_offset, 16);
        assert_eq!(hdr.gso_size, expected_gso_size);
        let tcp_header_len =
            usize::from(out[VIRTIO_NET_HDR_LEN + usize::from(ip_header_len) + 12] >> 4) * 4;
        assert_eq!(hdr.hdr_len, ip_header_len + tcp_header_len as u16);

        let ip_frame = &out[VIRTIO_NET_HDR_LEN..];
        let expected_len: usize = usize::from(hdr.hdr_len)
            + segments
                .iter()
                .map(|s| s.len() - usize::from(hdr.hdr_len))
                .sum::<usize>();
        assert_eq!(ip_frame.len(), expected_len);
        if !ipv6 {
            // The rewritten IPv4 header must carry the merged total length
            // and a valid header checksum.
            let ip = Ipv4Header::from_slice(ip_frame)
                .expect("IPv4 header parses")
                .0;
            assert_eq!(usize::from(ip.total_len), ip_frame.len());
            assert_eq!(ip.header_checksum, ip.calc_header_checksum());
        } else {
            let payload_len = u16::from_be_bytes([ip_frame[4], ip_frame[5]]);
            assert_eq!(usize::from(payload_len), ip_frame.len() - 40);
        }

        let resegmented = segment_tcp_gso_packet(&hdr, ip_frame).expect("re-segment");
        assert_eq!(resegmented.len(), segments.len());
        for (output, original) in resegmented.iter().zip(segments) {
            assert_eq!(output.as_slice(), original.as_ref());
            assert_tcp_checksum_valid(output);
        }
    }

    #[test]
    fn test_assemble_superframe_roundtrip_ipv4() {
        let segments = build_run(false, 12345, 10_000, &[1000, 1000, 1000]);
        assert_superframe_roundtrip(&segments, false, 1000);
    }

    #[test]
    fn test_assemble_superframe_roundtrip_ipv6() {
        let segments = build_run(true, 12345, 70_000, &[900, 900, 900, 900]);
        assert_superframe_roundtrip(&segments, true, 900);
    }

    #[test]
    fn test_assemble_superframe_roundtrip_last_smaller() {
        let segments = build_run(false, 12345, 10_000, &[1200, 1200, 333]);
        assert_superframe_roundtrip(&segments, false, 1200);
    }

    #[test]
    fn test_assemble_superframe_roundtrip_with_options() {
        let ts = etherparse::TcpOptionElement::Timestamp(7, 9);
        let a =
            build_data_segment_with_options(false, 12345, 10_000, 640, std::slice::from_ref(&ts));
        let b = build_data_segment_with_options(false, 12345, 10_640, 640, &[ts]);
        assert_superframe_roundtrip(&[a, b], false, 640);
    }

    #[test]
    fn test_assemble_superframe_scratch_reuse() {
        // The same output buffer must produce independent, correct frames
        // across runs of different sizes.
        let mut out = BytesMut::new();

        let large = build_run(false, 12345, 10_000, &[1400, 1400, 1400]);
        assemble_tcp_gso_superframe(&mut out, &large).expect("assemble large");
        let large_frame = out.to_vec();

        let small = build_run(false, 12345, 90_000, &[300, 300]);
        assemble_tcp_gso_superframe(&mut out, &small).expect("assemble small");
        assert_eq!(
            out.len(),
            VIRTIO_NET_HDR_LEN + 40 + 600,
            "small frame must not retain bytes from the larger previous frame"
        );

        assemble_tcp_gso_superframe(&mut out, &large).expect("assemble large again");
        assert_eq!(out.to_vec(), large_frame);
    }

    #[test]
    fn test_assemble_superframe_rejects_invalid_input() {
        let single = build_run(false, 12345, 10_000, &[500]);
        let mut out = BytesMut::new();
        assert!(assemble_tcp_gso_superframe(&mut out, &single).is_err());
        assert!(assemble_tcp_gso_superframe(&mut out, &[]).is_err());
    }





}
