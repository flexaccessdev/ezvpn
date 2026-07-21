//! VPN signaling protocol for tunnel establishment over iroh.
//!
//! This module defines the handshake messages exchanged between VPN
//! client and server to establish IP-over-QUIC tunnels. Clients identify
//! via a random `device_id` (allowing multiple sessions per iroh endpoint),
//! and the server responds with assigned IP addresses, route metadata, and
//! connection capabilities.

use crate::error::{VpnError, VpnResult};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// VPN protocol version.
///
/// Version 7: each IP packet maps directly to one unreliable, unordered QUIC
/// datagram (WireGuard-style — see [`crate::tunnel::stream`]). The handshake
/// bi-stream stays open only as the control channel for server-address
/// publications. This reverses version 6's reliable-stream data path.
/// MTU and QUIC transport tuning remain fixed, WireGuard/Tailscale-style: the
/// tunnel MTU is the protocol constant [`crate::config::VPN_MTU`], and the
/// transport config is [`crate::transport::build_quic_transport_config`].
pub const VPN_PROTOCOL_VERSION: u16 = 7;

/// Fixed ALPN protocol identifier for the VPN tunnel.
///
/// A peer whose advertised ALPN does not match this exact value is rejected
/// during QUIC ALPN negotiation, before any application streams are opened.
///
/// The `7` is the ALPN/format version, kept in lockstep with
/// [`VPN_PROTOCOL_VERSION`]: a peer advertising a different ALPN segment
/// (e.g. the reliable-stream `ezvpn/6` or the older datagram-based `ezvpn/5`)
/// no longer matches and QUIC negotiation rejects it before the handshake.
pub const VPN_ALPN: &[u8] = b"ezvpn/7";

/// VPN handshake request from client to server.
///
/// Sent over the iroh QUIC handshake bi-stream to initiate VPN setup; after
/// the response, the bi-stream stays open as the control channel while IP
/// packets ride unreliable datagrams. GSO is not negotiated: super-frames are
/// never forwarded on the wire (they cannot fit in a datagram), and each side's
/// TUN offload is a purely local concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshake {
    /// Protocol version.
    pub version: u16,
    /// Client's unique device ID (randomly generated per session).
    pub device_id: u64,
    /// Authentication token (optional, for token-based auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

impl VpnHandshake {
    /// Create a new handshake request.
    pub fn new(device_id: u64) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            device_id,
            auth_token: None,
        }
    }

    /// Set the authentication token.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Encode to bytes for transmission.
    pub fn encode(&self) -> VpnResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode handshake: {}", e)))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        let handshake: Self = serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode handshake: {}", e)))?;

        if handshake.version != VPN_PROTOCOL_VERSION {
            return Err(VpnError::Signaling(format!(
                "Unsupported handshake protocol version: {} (expected {})",
                handshake.version, VPN_PROTOCOL_VERSION
            )));
        }

        Ok(handshake)
    }
}

/// VPN handshake response from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshakeResponse {
    /// Protocol version.
    pub version: u16,
    /// Whether the handshake was accepted.
    pub accepted: bool,
    /// Assigned VPN IP address for the client (IPv4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<Ipv4Addr>,
    /// The server's IPv4 host prefix (`server_ip/32`) — the prefix the client
    /// routes through the tunnel by default. Only the server is advertised
    /// (never the full VPN subnet): inter-client traffic is dropped server-side
    /// anyway, so routing other clients' addresses would only invite drops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,
    /// Server's VPN IP (gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<Ipv4Addr>,
    /// Assigned IPv6 VPN address for the client (optional, for dual-stack).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip6: Option<Ipv6Addr>,
    /// The server's IPv6 host prefix (`server_ip6/128`); see [`Self::network`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network6: Option<Ipv6Net>,
    /// Server's IPv6 VPN address (gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip6: Option<Ipv6Addr>,
    /// Rejection reason (if not accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    /// Server's candidate iroh underlay addresses (`endpoint.addr().ip_addrs()`),
    /// delivered in the handshake so the client can install bypass routes for any
    /// a VPN route would capture *at onboarding* — without waiting for the first
    /// periodic data-path publication (see [`ServerAddrsMsg`]). Ongoing changes
    /// still arrive via that publication. Empty/absent when the server has not yet
    /// discovered any (or is an older build): the client falls back to publishing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_addrs: Vec<IpAddr>,
}

impl VpnHandshakeResponse {
    /// Validate handshake response invariants.
    ///
    /// An accepted response must assign at least one address family, and each
    /// assigned family must carry its full triplet (assigned IP + network +
    /// gateway) so the client can configure routes and the TUN device.
    pub fn is_valid(&self) -> bool {
        if !self.accepted {
            return true;
        }
        if self.assigned_ip.is_none() && self.assigned_ip6.is_none() {
            return false;
        }
        if self.assigned_ip.is_some() && (self.network.is_none() || self.server_ip.is_none()) {
            return false;
        }
        if self.assigned_ip6.is_some() && (self.network6.is_none() || self.server_ip6.is_none()) {
            return false;
        }
        true
    }

    /// Create an accepted response (IPv4 only).
    pub fn accepted(assigned_ip: Ipv4Addr, network: Ipv4Net, server_ip: Ipv4Addr) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
            reject_reason: None,
            server_addrs: Vec::new(),
        }
    }

    /// Create an accepted response with dual-stack (IPv4 + IPv6).
    pub fn accepted_dual_stack(
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            assigned_ip6: Some(assigned_ip6),
            network6: Some(network6),
            server_ip6: Some(server_ip6),
            reject_reason: None,
            server_addrs: Vec::new(),
        }
    }

    /// Create an accepted response with IPv6 only (no IPv4).
    ///
    /// Use this for IPv6-only VPN networks where no IPv4 address is allocated.
    pub fn accepted_ipv6_only(
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: Some(assigned_ip6),
            network6: Some(network6),
            server_ip6: Some(server_ip6),
            reject_reason: None,
            server_addrs: Vec::new(),
        }
    }

    /// Create a rejected response.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: false,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
            reject_reason: Some(reason.into()),
            server_addrs: Vec::new(),
        }
    }

    /// Attach the server's candidate underlay addresses to an accepted response.
    ///
    /// Builder-style so the per-family constructors stay unchanged; a no-op on a
    /// rejected response (the client ignores everything but `reject_reason`).
    pub fn with_server_addrs(mut self, server_addrs: Vec<IpAddr>) -> Self {
        if self.accepted {
            self.server_addrs = server_addrs;
        }
        self
    }

    /// Encode to bytes for transmission.
    pub fn encode(&self) -> VpnResult<Vec<u8>> {
        if !self.is_valid() {
            return Err(VpnError::Signaling(
                "Invalid handshake response: an accepted response must assign at least one address family, each with its network and gateway".into(),
            ));
        }
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode response: {}", e)))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        let response: Self = serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode response: {}", e)))?;

        if response.version != VPN_PROTOCOL_VERSION {
            return Err(VpnError::Signaling(format!(
                "Unsupported handshake response protocol version: {} (expected {})",
                response.version, VPN_PROTOCOL_VERSION
            )));
        }

        if !response.is_valid() {
            return Err(VpnError::Signaling(
                "Invalid handshake response: an accepted response must assign at least one address family, each with its network and gateway".into(),
            ));
        }
        Ok(response)
    }
}

/// Helper to write a length-prefixed message.
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> VpnResult<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| VpnError::Signaling(format!("Message too large: {} bytes", data.len())))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Helper to read a length-prefixed message.
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> VpnResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_size {
        return Err(VpnError::Signaling(format!(
            "Message too large: {} > {}",
            len, max_size
        )));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// Maximum handshake message size (16 KB).
pub const MAX_HANDSHAKE_SIZE: usize = 16 * 1024;

/// Message types for the reliable control channel (length-prefixed frames on
/// the handshake stream that stays open — see [`crate::tunnel::stream`]).
///
/// Each frame is `[len: u32 BE] [body]`; the body's leading byte is the message
/// type and the remainder is type-specific. Server-addresses body:
/// `[0x01] [json(ServerAddrsMsg)]`. IP packets are not framed here — they map
/// directly to unreliable QUIC datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMessageType {
    /// Server-published set of candidate iroh underlay addresses (server →
    /// client only). The client installs bypass routes for any that a VPN route
    /// would otherwise capture, pre-empting self-capture of a server address
    /// iroh has not yet selected (see [`ServerAddrsMsg`]).
    ServerAddrs = 0x01,
}

impl DataMessageType {
    /// Convert from byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ServerAddrs),
            _ => None,
        }
    }

    /// Convert to byte value.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Server → client publication of the candidate iroh underlay addresses the
/// server may be reached on (`endpoint.addr().ip_addrs()`).
///
/// The client only ever *adds* bypass routes for those covered by a VPN route
/// (see `BypassRouteManager::update`), so the server can publish its full
/// candidate set — including private/LAN addresses — without the client pinning
/// anything outside the routed range. This lets the client pre-empt the
/// self-capture of a server address iroh has discovered but not yet selected for
/// the active path, which the path-snapshot-driven discovery alone would miss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAddrsMsg {
    /// Candidate underlay IP addresses (ports stripped; bypass routes are per-IP).
    pub addrs: Vec<IpAddr>,
}

impl ServerAddrsMsg {
    /// Create a new message from a set of candidate addresses.
    pub fn new(addrs: Vec<IpAddr>) -> Self {
        Self { addrs }
    }

    /// Encode to bytes (the frame body after the message-type byte).
    pub fn encode(&self) -> VpnResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode server addrs: {}", e)))
    }

    /// Decode from bytes (the frame body after the message-type byte).
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode server addrs: {}", e)))
    }
}

/// Error returned when converting an invalid byte to `DataMessageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessageType(pub u8);

impl std::fmt::Display for InvalidMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid message type: 0x{:02x}", self.0)
    }
}

impl std::error::Error for InvalidMessageType {}

impl TryFrom<u8> for DataMessageType {
    type Error = InvalidMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_byte(value).ok_or(InvalidMessageType(value))
    }
}

impl From<DataMessageType> for u8 {
    fn from(value: DataMessageType) -> Self {
        value.as_byte()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let handshake = VpnHandshake::new(12345).with_auth_token("test-token");
        let encoded = handshake.encode().expect("encode handshake");
        let decoded = VpnHandshake::decode(&encoded).expect("decode handshake");
        assert_eq!(decoded.version, VPN_PROTOCOL_VERSION);
        assert_eq!(decoded.device_id, 12345);
        assert_eq!(decoded.auth_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_handshake_rejects_unsupported_version() {
        let raw = serde_json::to_vec(&VpnHandshake {
            version: 1,
            device_id: 7,
            auth_token: None,
        })
        .expect("serialize handshake");

        let err = VpnHandshake::decode(&raw).expect_err("v1 handshake should be rejected");
        assert!(
            err.to_string()
                .contains("Unsupported handshake protocol version")
        );
    }

    #[test]
    fn test_response_accepted_roundtrip() {
        let response = VpnHandshakeResponse::accepted(
            "10.0.0.2".parse().expect("parse IPv4"),
            "10.0.0.0/24".parse().expect("parse network"),
            "10.0.0.1".parse().expect("parse server ip"),
        );
        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert!(decoded.accepted);
        assert_eq!(
            decoded.assigned_ip,
            Some("10.0.0.2".parse().expect("parse IPv4"))
        );
    }

    #[test]
    fn test_response_accepted_dual_stack_roundtrip() {
        let assigned_ip: Ipv4Addr = "10.0.0.2".parse().expect("parse IPv4");
        let network: Ipv4Net = "10.0.0.0/24".parse().expect("parse network");
        let server_ip: Ipv4Addr = "10.0.0.1".parse().expect("parse server ip");
        let assigned_ip6: Ipv6Addr = "fd00::2".parse().expect("parse IPv6");
        let network6: Ipv6Net = "fd00::/64".parse().expect("parse network6");
        let server_ip6: Ipv6Addr = "fd00::1".parse().expect("parse server ip6");

        let response = VpnHandshakeResponse::accepted_dual_stack(
            assigned_ip,
            network,
            server_ip,
            assigned_ip6,
            network6,
            server_ip6,
        );

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");

        assert!(decoded.accepted);
        assert_eq!(decoded.assigned_ip, Some(assigned_ip));
        assert_eq!(decoded.network, Some(network));
        assert_eq!(decoded.server_ip, Some(server_ip));
        assert_eq!(decoded.assigned_ip6, Some(assigned_ip6));
        assert_eq!(decoded.network6, Some(network6));
        assert_eq!(decoded.server_ip6, Some(server_ip6));
        assert_eq!(decoded.reject_reason, None);
        assert!(decoded.server_addrs.is_empty());
    }

    #[test]
    fn test_response_server_addrs_roundtrip() {
        let addrs = vec![
            "44.230.20.120".parse::<IpAddr>().expect("parse v4"),
            "2600:1f13:adc:a0b1:feb9:cb56:f64e:b6f8"
                .parse::<IpAddr>()
                .expect("parse v6"),
        ];
        let response = VpnHandshakeResponse::accepted(
            "10.0.0.2".parse().expect("parse IPv4"),
            "10.0.0.0/24".parse().expect("parse network"),
            "10.0.0.1".parse().expect("parse server ip"),
        )
        .with_server_addrs(addrs.clone());

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert_eq!(decoded.server_addrs, addrs);
    }

    #[test]
    fn test_response_rejected_roundtrip() {
        let response = VpnHandshakeResponse::rejected("Server full");
        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert!(!decoded.accepted);
        assert_eq!(decoded.reject_reason, Some("Server full".to_string()));
    }

    #[test]
    fn test_response_accepted_ipv6_only_roundtrip() {
        let assigned_ip6: Ipv6Addr = "fd00::2".parse().expect("parse IPv6");
        let network6: Ipv6Net = "fd00::/64".parse().expect("parse network6");
        let server_ip6: Ipv6Addr = "fd00::1".parse().expect("parse server ip6");

        let response = VpnHandshakeResponse::accepted_ipv6_only(assigned_ip6, network6, server_ip6);

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");

        assert!(decoded.accepted);
        assert_eq!(decoded.assigned_ip, None);
        assert_eq!(decoded.network, None);
        assert_eq!(decoded.server_ip, None);
        assert_eq!(decoded.assigned_ip6, Some(assigned_ip6));
        assert_eq!(decoded.network6, Some(network6));
        assert_eq!(decoded.server_ip6, Some(server_ip6));
        assert_eq!(decoded.reject_reason, None);
    }

    #[test]
    fn test_response_invalid_when_accepted_without_assigned_ip() {
        let response = VpnHandshakeResponse {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
            reject_reason: None,
            server_addrs: Vec::new(),
        };

        assert!(!response.is_valid());
        assert!(response.encode().is_err());

        let raw = serde_json::to_vec(&response).expect("serialize response");
        let decoded = VpnHandshakeResponse::decode(&raw);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_response_invalid_with_incomplete_triplet() {
        // assigned_ip present but its network/gateway are missing.
        let mut response = VpnHandshakeResponse::accepted(
            "10.0.0.2".parse().expect("parse IPv4"),
            "10.0.0.0/24".parse().expect("parse network"),
            "10.0.0.1".parse().expect("parse server ip"),
        );
        response.network = None;
        assert!(!response.is_valid(), "missing network must be rejected");
        assert!(response.encode().is_err());

        response.network = Some("10.0.0.0/24".parse().expect("parse network"));
        response.server_ip = None;
        assert!(!response.is_valid(), "missing gateway must be rejected");

        // The IPv6 side of a dual-stack response must also be complete.
        let mut dual = VpnHandshakeResponse::accepted_dual_stack(
            "10.0.0.2".parse().expect("parse IPv4"),
            "10.0.0.0/24".parse().expect("parse network"),
            "10.0.0.1".parse().expect("parse server ip"),
            "fd00::2".parse().expect("parse IPv6"),
            "fd00::/64".parse().expect("parse network6"),
            "fd00::1".parse().expect("parse server ip6"),
        );
        dual.server_ip6 = None;
        assert!(!dual.is_valid(), "missing IPv6 gateway must be rejected");
    }

    #[test]
    fn test_response_rejects_old_protocol_version() {
        let mut response = VpnHandshakeResponse::rejected("nope");
        response.version = 4;
        let raw = serde_json::to_vec(&response).expect("serialize response");
        let err = VpnHandshakeResponse::decode(&raw).expect_err("v2 response should be rejected");
        assert!(
            err.to_string()
                .contains("Unsupported handshake response protocol version")
        );
    }

    #[test]
    fn test_data_message_type_roundtrip() {
        let msg_type = DataMessageType::from_byte(0x01).expect("valid message type");
        assert_eq!(msg_type, DataMessageType::ServerAddrs);
        assert_eq!(msg_type.as_byte(), 0x01);

        let msg_type: DataMessageType = 0x01u8.try_into().expect("try_from should work");
        assert_eq!(msg_type, DataMessageType::ServerAddrs);
        let back: u8 = msg_type.into();
        assert_eq!(back, 0x01);
    }

    #[test]
    fn test_data_message_type_invalid_bytes() {
        for invalid in [0x00, 0x02, 0x03, 0x10, 0x80, 0xff] {
            assert!(
                DataMessageType::from_byte(invalid).is_none(),
                "from_byte(0x{:02x}) should return None",
                invalid
            );
        }
    }

    #[test]
    fn test_server_addrs_msg_roundtrip() {
        let addrs = vec![
            "203.0.113.5".parse::<IpAddr>().expect("parse v4"),
            "2001:db8::1".parse::<IpAddr>().expect("parse v6"),
        ];
        let msg = ServerAddrsMsg::new(addrs.clone());
        let encoded = msg.encode().expect("encode server addrs");
        let decoded = ServerAddrsMsg::decode(&encoded).expect("decode server addrs");
        assert_eq!(decoded.addrs, addrs);
    }

    #[test]
    fn test_data_message_type_try_from_invalid() {
        for invalid in [0x02, 0x10, 0x80, 0xff] {
            let result: Result<DataMessageType, _> = invalid.try_into();
            assert!(result.is_err(), "TryFrom(0x{:02x}) should fail", invalid);

            let err = result.expect_err("invalid type");
            assert_eq!(err, InvalidMessageType(invalid));
            assert!(err.to_string().contains(&format!("0x{:02x}", invalid)));
        }
    }
}
