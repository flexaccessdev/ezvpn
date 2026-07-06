//! VPN configuration types.

// `file_config` stays available on iOS; only the on-disk TOML loading inside
// it (which needs `crate::runtime::config_dir`) is gated off iOS.
pub mod file_config;

use ipnet::{Ipv4Net, Ipv6Net};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Fixed VPN tunnel MTU — a protocol constant, not a configuration knob.
///
/// 1280 is the IPv6 minimum link MTU (RFC 8200) and the same fixed value
/// Tailscale uses: mobile-safe on essentially any real path. It is deliberately
/// *not* negotiated or derived from live path measurements — a fixed MTU is
/// deterministic across reconnects. The data path is a reliable QUIC stream,
/// so the wire path MTU never constrains framing (QUIC packetizes the stream);
/// the tunnel MTU only bounds per-packet overhead and inner-flow behavior.
pub const VPN_MTU: u16 = 1280;

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

    /// Maximum number of connected clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses ezvpn auth-token format (`v` + 46 Base64URL chars, no padding).
    #[serde(default)]
    pub auth_tokens: Option<HashSet<String>>,
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
fn default_max_clients() -> usize {
    254
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
            max_clients: 254,
            auth_tokens: None,
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
