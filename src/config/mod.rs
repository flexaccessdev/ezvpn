//! VPN configuration types.

// `file_config` also defines core transport/MTU types used by the data plane
// (`TransportTuning`, `CongestionController`, `DEFAULT_VPN_MTU`), so it stays
// available on iOS. Only the on-disk TOML loading inside it (which needs
// `crate::runtime::config_dir`) is gated off iOS.
pub mod file_config;

use ipnet::{Ipv4Net, Ipv6Net};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Default MTU for VPN tunnel: the IPv6 minimum link MTU, mobile-safe on any
/// real path (see `DATAGRAM_SAFE_MTU` in the tunnel server for the rationale).
/// Must stay in sync with [`file_config::DEFAULT_VPN_MTU`].
pub const DEFAULT_MTU: u16 = 1280;

/// IPv6 address-assignment strategy for VPN clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Ip6Strategy {
    /// Sequential allocation: server gets ::1, clients get ::2, ::3, ...
    #[default]
    Sequential,
    /// Stateless deterministic addresses: host suffix derived from the iroh
    /// node id (clients from their own id, server from its id).
    /// Requires an IPv6 subnet of /64 or wider.
    NodeId,
}

/// Validate node-id strategy requirements: `network6` of /64 or wider and no
/// `server_ip6` override (the server address is derived from the node id).
///
/// A no-op for the sequential strategy.
///
/// Single source of truth shared by the TOML config layer ([`file_config`]),
/// the runtime config ([`VpnServerConfig::validate`]), and the IPv6 pool.
///
/// [`file_config`]: crate::config::file_config
pub fn validate_ip6_strategy(
    strategy: Ip6Strategy,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
) -> Result<(), String> {
    if strategy != Ip6Strategy::NodeId {
        return Ok(());
    }

    let Some(network6) = network6 else {
        return Err("ip6_strategy 'node-id' requires 'network6' to be set".to_string());
    };
    if network6.prefix_len() > 64 {
        return Err(format!(
            "ip6_strategy 'node-id' requires an IPv6 subnet of /64 or wider (got /{})",
            network6.prefix_len()
        ));
    }
    if server_ip6.is_some() {
        return Err(
            "'server_ip6' cannot be combined with ip6_strategy 'node-id' (the server address is derived from the server node id)"
                .to_string(),
        );
    }

    Ok(())
}

/// Validate the combination of VPN networks, server addresses, and IPv6
/// strategy.
///
/// Single source of truth shared by the TOML config layer ([`file_config`])
/// and the runtime config ([`VpnServerConfig::validate`]).
///
/// [`file_config`]: crate::config::file_config
pub fn validate_vpn_networks(
    network: Option<Ipv4Net>,
    server_ip: Option<Ipv4Addr>,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
    ip6_strategy: Ip6Strategy,
) -> Result<(), String> {
    // At least one network must be configured
    if network.is_none() && network6.is_none() {
        return Err(
            "At least one of 'network' (IPv4) or 'network6' (IPv6) must be configured".to_string(),
        );
    }

    // server_ip requires network
    if server_ip.is_some() && network.is_none() {
        return Err("'server_ip' requires 'network' to be set".to_string());
    }

    // server_ip must be within network
    if let (Some(server_ip), Some(network)) = (server_ip, network)
        && !network.contains(&server_ip)
    {
        return Err(format!(
            "'server_ip' {} is not within 'network' {}",
            server_ip, network
        ));
    }

    // server_ip6 requires network6
    if server_ip6.is_some() && network6.is_none() {
        return Err("'server_ip6' requires 'network6' to be set".to_string());
    }

    // server_ip6 must be within network6
    if let (Some(server_ip6), Some(network6)) = (server_ip6, network6)
        && !network6.contains(&server_ip6)
    {
        return Err(format!(
            "'server_ip6' {} is not within 'network6' {}",
            server_ip6, network6
        ));
    }

    validate_ip6_strategy(ip6_strategy, network6, server_ip6)
}

/// VPN server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServerConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24"). Optional for IPv6-only mode.
    /// Server gets .1 by default, clients get subsequent addresses.
    /// At least one of `network` (IPv4) or `network6` (IPv6) must be configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,

    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack or IPv6-only.
    /// Server gets ::1 by default, clients get subsequent addresses.
    /// At least one of `network` (IPv4) or `network6` (IPv6) must be configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network6: Option<Ipv6Net>,

    /// Server's VPN IP address (defaults to first host in network, e.g., .1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<Ipv4Addr>,

    /// Server's IPv6 VPN address (defaults to first host in network6, e.g., ::1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip6: Option<Ipv6Addr>,

    /// IPv6 address-assignment strategy (default: sequential).
    /// `NodeId` derives stateless deterministic addresses from iroh node ids
    /// and requires `network6` of /64 or wider with no `server_ip6` override.
    #[serde(default)]
    pub ip6_strategy: Ip6Strategy,

    /// MTU for the TUN device.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Maximum number of connected clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses ezvpn auth-token format (`v` + 46 Base64URL chars, no padding).
    #[serde(default)]
    pub auth_tokens: Option<HashSet<String>>,

    /// Whether to drop packets when a client's send buffer is full.
    ///
    /// When `true`: drops packets for slow clients instead of blocking,
    /// preventing one slow client from affecting packet delivery to other clients.
    /// Best for real-time traffic (VoIP, gaming) where latency matters more than
    /// guaranteed delivery.
    ///
    /// When `false` (default): applies backpressure by awaiting the send, which blocks the
    /// TUN reader and delays packets to all clients until the slow client's buffer
    /// has space. Best for bulk transfers where packet loss is unacceptable.
    #[serde(default = "default_drop_on_full")]
    pub drop_on_full: bool,

    /// Channel buffer size for outbound packets to each client (default: 1024).
    ///
    /// Controls how many packets can be queued for each client before backpressure
    /// or packet drops occur (depending on `drop_on_full` setting).
    ///
    /// **Tradeoffs:**
    /// - **Higher values (e.g., 2048-4096):** Better burst handling and throughput,
    ///   but increases memory usage per client and adds latency under congestion.
    ///   At 1 Gbps with 1500-byte packets, a 4096-packet buffer adds ~50ms latency.
    /// - **Lower values (e.g., 256-512):** Lower memory footprint and latency,
    ///   but may cause more packet drops or backpressure during traffic bursts.
    ///
    /// **Memory impact:** `client_channel_size * max_clients * ~1500 bytes`
    /// - Default (1024 * 254 clients): ~370 MB worst case
    /// - Conservative (256 * 254 clients): ~93 MB worst case
    ///
    /// **Recommendations:**
    /// - High-bandwidth server with few clients: 2048-4096
    /// - Many clients with limited memory: 256-512
    /// - Balanced default: 1024
    #[serde(default = "default_client_channel_size")]
    pub client_channel_size: usize,

    /// Channel buffer size for TUN writer task (default: 512).
    ///
    /// This is the aggregate buffer for all client -> TUN traffic. Since all
    /// clients share this channel, it should be larger than per-client buffers.
    ///
    /// **Tradeoffs:**
    /// - **Higher values (e.g., 2048-4096):** Better burst absorption from multiple clients,
    ///   prevents TUN write backpressure from affecting individual clients, but risks
    ///   high memory usage if TUN writes stall (~4096 * 1500 bytes = ~6MB).
    /// - **Lower values (e.g., 256-512):** Faster backpressure propagation to clients,
    ///   bounded memory usage, but may cause more backpressure during bursts.
    ///
    /// **Memory impact:** `tun_writer_channel_size * ~1500 bytes`
    /// - Default (512): ~750 KB worst case
    /// - High (4096): ~6 MB worst case
    ///
    /// **Recommendation:** 512 is a safe default for memory-constrained hosts.
    /// Increase to 2048-4096 for high-bandwidth servers with many active clients.
    #[serde(default = "default_tun_writer_channel_size")]
    pub tun_writer_channel_size: usize,

    /// Disable inter-client IP spoofing checks (default: false).
    ///
    /// When `false` (default): The server rejects packets whose source IP matches
    /// another client's assigned VPN IP. This prevents one client from impersonating
    /// another. Packets with non-VPN source IPs (e.g., a client's public IPv6) are
    /// still allowed, supporting dual-stack scenarios.
    ///
    /// When `true`: All source IP validation is disabled. Any source IP is accepted,
    /// which may allow clients to spoof other clients' addresses. Use with caution.
    #[serde(default)]
    pub disable_spoofing_check: bool,
}

impl VpnServerConfig {
    /// Validate the VPN server configuration.
    ///
    /// Returns an error if:
    /// - Neither `network` (IPv4) nor `network6` (IPv6) is configured
    /// - `server_ip` is set but `network` is not (orphaned IPv4 server IP)
    /// - `server_ip6` is set but `network6` is not (orphaned IPv6 server IP)
    /// - node-id strategy is set without `network6` of /64 or wider, or with
    ///   a `server_ip6` override
    pub fn validate(&self) -> Result<(), String> {
        validate_vpn_networks(
            self.network,
            self.server_ip,
            self.network6,
            self.server_ip6,
            self.ip6_strategy,
        )
    }
}

/// VPN client configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpnClientConfig {
    /// Server's iroh node ID.
    pub server_node_id: String,

    /// Authentication token (ezvpn auth-token format: `v` + Base64URL payload).
    pub auth_token: Option<String>,

    /// IPv4 routes to send through the VPN (CIDRs), e.g., 0.0.0.0/0 for full tunnel.
    /// Optional: with no routes configured, only the assigned VPN addresses are reachable.
    #[serde(default)]
    pub routes: Vec<Ipv4Net>,

    /// IPv6 routes to send through the VPN (CIDRs). Optional for dual-stack.
    #[serde(default)]
    pub routes6: Vec<Ipv6Net>,
}

impl VpnClientConfig {
    /// Validate the VPN client configuration.
    ///
    /// Returns an error if:
    /// - `server_node_id` is empty or not a valid iroh node ID
    pub fn validate(&self) -> Result<(), String> {
        if self.server_node_id.is_empty() {
            return Err("'server_node_id' is required and cannot be empty".to_string());
        }
        if self.server_node_id.parse::<EndpointId>().is_err() {
            return Err("'server_node_id' is not a valid iroh node ID".to_string());
        }

        Ok(())
    }
}

// Default value functions for serde
fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_max_clients() -> usize {
    254
}

fn default_drop_on_full() -> bool {
    false
}

fn default_client_channel_size() -> usize {
    1024
}

fn default_tun_writer_channel_size() -> usize {
    512
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_server_config() -> VpnServerConfig {
        VpnServerConfig {
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: None,
            ip6_strategy: Ip6Strategy::Sequential,
            mtu: DEFAULT_MTU,
            max_clients: 254,
            auth_tokens: None,
            drop_on_full: false,
            client_channel_size: 1024,
            tun_writer_channel_size: 512,
            disable_spoofing_check: false,
        }
    }

    fn random_server_node_id() -> String {
        let bytes: [u8; 32] = rand::random();
        let secret = iroh::SecretKey::from_bytes(&bytes);
        secret.public().to_string()
    }

    #[test]
    fn test_validate_ipv4_only_ok() {
        let config = minimal_server_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_ipv6_only_ok() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_dual_stack_ok() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_no_network_fails() {
        let mut config = minimal_server_config();
        config.network = None;
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one of"));
    }

    #[test]
    fn test_validate_server_ip_requires_network() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip = Some("10.0.0.1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("'server_ip' requires 'network'")
        );
    }

    #[test]
    fn test_validate_server_ip6_requires_network6() {
        let mut config = minimal_server_config();
        config.server_ip6 = Some("fd00::1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("'server_ip6' requires 'network6'")
        );
    }

    #[test]
    fn test_validate_server_ip_within_network() {
        let mut config = minimal_server_config();
        config.server_ip = Some("192.168.1.1".parse().unwrap()); // Not in 10.0.0.0/24
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not within 'network'"));
    }

    #[test]
    fn test_validate_server_ip6_within_network6() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip6 = Some("fd01::1".parse().unwrap()); // Not in fd00::/64
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not within 'network6'"));
    }

    #[test]
    fn test_validate_nodeid_requires_network6() {
        let mut config = minimal_server_config();
        config.ip6_strategy = Ip6Strategy::NodeId;
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires 'network6'"));
    }

    #[test]
    fn test_validate_nodeid_accepts_slash64_and_wider() {
        let mut config = minimal_server_config();
        config.ip6_strategy = Ip6Strategy::NodeId;
        config.network6 = Some("fd00::/64".parse().unwrap());
        assert!(config.validate().is_ok());

        config.network6 = Some("fd00::/56".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_nodeid_rejects_narrower_than_slash64() {
        let mut config = minimal_server_config();
        config.ip6_strategy = Ip6Strategy::NodeId;
        config.network6 = Some("fd00::/65".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("/64 or wider"));
    }

    #[test]
    fn test_validate_nodeid_rejects_server_ip6() {
        let mut config = minimal_server_config();
        config.ip6_strategy = Ip6Strategy::NodeId;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip6 = Some("fd00::1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'server_ip6'"));
    }

    #[test]
    fn test_validate_sequential_unaffected_by_nodeid_rules() {
        // Sequential allows narrower-than-/64 subnets and a custom server_ip6
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/120".parse().unwrap());
        config.server_ip6 = Some("fd00::1".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_requires_server_node_id() {
        let mut config = VpnClientConfig::default();
        config.routes.push("0.0.0.0/0".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'server_node_id' is required"));
    }

    #[test]
    fn test_validate_client_ok() {
        let config = VpnClientConfig {
            server_node_id: random_server_node_id(),
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_no_routes_ok() {
        let config = VpnClientConfig {
            server_node_id: random_server_node_id(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
