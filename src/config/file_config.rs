//! TOML config-file support: file-level structs, loading, and resolution
//! into the runtime configuration ([`crate::config`]).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[serde(rename = "vpnserver")]
    VpnServer,
    #[serde(rename = "vpnclient")]
    VpnClient,
}

/// Congestion controller algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionController {
    /// CUBIC - default loss-based controller.
    #[default]
    Cubic,
    /// BBR model-based controller.
    Bbr,
    /// NewReno classic TCP-like controller.
    #[serde(alias = "new_reno")]
    NewReno,
}

pub use super::Ip6Strategy;

/// Default QUIC receive window size (8 MB).
pub const DEFAULT_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;

/// Transport tuning for QUIC connections.
///
/// Server-only configuration: the server applies it to its own endpoint and
/// dictates the resolved values to clients during the handshake.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransportTuning {
    #[serde(default)]
    pub congestion_controller: CongestionController,
    pub receive_window: Option<u32>,
    pub send_window: Option<u32>,
}

impl TransportTuning {
    /// Resolve the effective (receive, send) window sizes in bytes.
    ///
    /// Receive defaults to [`DEFAULT_RECEIVE_WINDOW`]; send defaults to the
    /// effective receive window. Shared by endpoint setup and the handshake
    /// wire values so they cannot drift.
    pub fn effective_windows(&self) -> (u32, u32) {
        let receive_window = self.receive_window.unwrap_or(DEFAULT_RECEIVE_WINDOW);
        let send_window = self.send_window.unwrap_or(receive_window);
        (receive_window, send_window)
    }
}

/// VPN network configuration (server-assigned addressing). `[network]` section.
///
/// These describe the VPN tunnel itself, not the iroh transport, so they live
/// outside `[iroh]`.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerNetworkConfig {
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    #[serde(default)]
    pub ip6_strategy: Ip6Strategy,
    pub mtu: Option<u16>,
}

/// VPN client authentication tokens accepted by the server. `[auth]` section.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerAuthConfig {
    pub auth_tokens: Option<Vec<String>>,
    pub auth_tokens_file: Option<PathBuf>,
}

/// iroh transport and identity configuration (server). `[iroh]` section.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct VpnServerIrohConfig {
    pub secret_file: Option<PathBuf>,
    #[serde(default)]
    pub transport: TransportTuning,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
}

/// VPN routes the client installs once connected. `[network]` section.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientNetworkConfig {
    pub routes: Option<Vec<String>>,
    pub routes6: Option<Vec<String>>,
}

/// Client authentication token presented to the server. `[auth]` section.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
}

/// iroh transport and identity configuration (client). `[iroh]` section.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct VpnClientIrohConfig {
    pub server_node_id: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct VpnServerConfig {
    pub role: Option<Role>,
    #[serde(default)]
    pub network: ServerNetworkConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default = "default_drop_on_full")]
    pub drop_on_full: bool,
    pub client_channel_size: Option<usize>,
    pub tun_writer_channel_size: Option<usize>,
    #[serde(default)]
    pub disable_spoofing_check: bool,
    pub iroh: Option<VpnServerIrohConfig>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct VpnClientConfig {
    pub role: Option<Role>,
    #[serde(default)]
    pub network: ClientNetworkConfig,
    #[serde(default)]
    pub auth: ClientAuthConfig,
    pub auto_reconnect: Option<bool>,
    pub max_reconnect_attempts: Option<NonZeroU32>,
    pub iroh: Option<VpnClientIrohConfig>,
}

/// Default MTU for VPN packets: the IPv6 minimum link MTU, mobile-safe on any
/// real path (see `DATAGRAM_SAFE_MTU` in the tunnel server for the rationale).
/// Must stay in sync with [`crate::config::DEFAULT_MTU`].
pub const DEFAULT_VPN_MTU: u16 = 1280;

/// Default channel buffer size for outbound packets to each client.
pub const DEFAULT_CLIENT_CHANNEL_SIZE: usize = 1024;

/// Default channel buffer size for TUN writer task.
pub const DEFAULT_TUN_WRITER_CHANNEL_SIZE: usize = 512;

/// Minimum QUIC window size (1 KB).
const MIN_WINDOW_SIZE: u32 = 1024;

/// Maximum QUIC window size (16 MB).
const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

fn validate_window_size(size: u32, field_name: &str, section: &str) -> Result<()> {
    if size < MIN_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} is below minimum of {} bytes (1KB)",
            section,
            field_name,
            size,
            MIN_WINDOW_SIZE
        );
    }
    if size > MAX_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} exceeds maximum of {} bytes (16MB)",
            section,
            field_name,
            size,
            MAX_WINDOW_SIZE
        );
    }
    Ok(())
}

pub fn validate_transport_tuning(tuning: &TransportTuning, section: &str) -> Result<()> {
    if let Some(recv) = tuning.receive_window {
        validate_window_size(recv, "receive_window", section)?;
    }
    if let Some(send) = tuning.send_window {
        validate_window_size(send, "send_window", section)?;
    }
    Ok(())
}

/// Minimum VPN tunnel MTU.
const MIN_VPN_MTU: u16 = 576;

/// Maximum VPN tunnel MTU. Jumbo frames are allowed because throughput on
/// per-packet-syscall-bound platforms (notably macOS `utun`, which has no GSO
/// and reads one packet per syscall) scales ~linearly with MTU. The transport
/// re-segments to the path MTU (TCP MSS for the dummy, QUIC datagrams for iroh),
/// so a large *inner* MTU needs no jumbo physical frames.
const MAX_VPN_MTU: u16 = 9216;

pub(crate) fn validate_mtu(mtu: u16, section: &str) -> Result<()> {
    if !(MIN_VPN_MTU..=MAX_VPN_MTU).contains(&mtu) {
        anyhow::bail!(
            "[{}] MTU {} is out of range. Valid range: {}-{}",
            section,
            mtu,
            MIN_VPN_MTU,
            MAX_VPN_MTU
        );
    }
    Ok(())
}

fn validate_channel_size(size: usize, field_name: &str, section: &str) -> Result<()> {
    if size == 0 {
        anyhow::bail!("[{}] {} must be at least 1", section, field_name);
    }
    if size > 65536 {
        anyhow::bail!(
            "[{}] {} value {} exceeds maximum of 65536",
            section,
            field_name,
            size
        );
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::IpNet>().with_context(|| {
        format!(
            "Invalid CIDR network '{}'. Expected format: 192.168.0.0/16 or ::1/128",
            cidr
        )
    })?;
    Ok(())
}

fn validate_ipv6_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::Ipv6Net>().with_context(|| {
        format!(
            "Invalid IPv6 CIDR '{}'. Expected format: fd00::/64 or ::/0",
            cidr
        )
    })?;
    Ok(())
}

fn route6_context(route: &str, section: Option<&str>) -> String {
    let msg = format!("Invalid route6 CIDR '{}' (must be IPv6, e.g., ::/0)", route);
    match section {
        Some(s) => format!("[{}] {}", s, msg),
        None => msg,
    }
}

fn validate_vpn_networks(
    network: Option<&str>,
    server_ip: Option<&str>,
    network6: Option<&str>,
    server_ip6: Option<&str>,
    ip6_strategy: Ip6Strategy,
    section: &str,
) -> Result<()> {
    // Parse the raw strings, then delegate the semantic rules to the shared
    // validator in crate::config (single source of truth with the runtime config).
    let network: Option<ipnet::Ipv4Net> = network
        .map(|n| {
            n.parse().with_context(|| {
                format!(
                    "[{}] Invalid network CIDR '{}'. Expected format: 10.0.0.0/24",
                    section, n
                )
            })
        })
        .transpose()?;

    let server_ip: Option<std::net::Ipv4Addr> = server_ip
        .map(|ip| {
            ip.parse().with_context(|| {
                format!(
                    "[{}] Invalid server_ip '{}'. Expected IPv4 address",
                    section, ip
                )
            })
        })
        .transpose()?;

    let network6: Option<ipnet::Ipv6Net> = network6
        .map(|n| {
            n.parse().with_context(|| {
                format!(
                    "[{}] Invalid network6 CIDR '{}'. Expected format: fd00::/64",
                    section, n
                )
            })
        })
        .transpose()?;

    let server_ip6: Option<std::net::Ipv6Addr> = server_ip6
        .map(|ip| {
            ip.parse().with_context(|| {
                format!(
                    "[{}] Invalid server_ip6 '{}'. Expected IPv6 address",
                    section, ip
                )
            })
        })
        .transpose()?;

    super::validate_vpn_networks(network, server_ip, network6, server_ip6, ip6_strategy)
        .map_err(|e| anyhow::anyhow!("[{}] {}", section, e))
}

fn default_drop_on_full() -> bool {
    false
}

impl VpnServerConfig {
    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnserver\"")?;
        if role != Role::VpnServer {
            anyhow::bail!("Config file has wrong role for server. Expected role = \"vpnserver\"");
        }

        let iroh = self.iroh.as_ref().context(
            "Config file missing required [iroh] section. Add a [iroh] section with 'secret_file'.",
        )?;

        if iroh.secret_file.is_none() {
            anyhow::bail!(
                "[iroh] 'secret_file' is required for server identity. Generate with: ezvpn generate-server-key -o ./vpn-server.key"
            );
        }

        let has_inline_tokens = self.auth.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
        if has_inline_tokens && self.auth.auth_tokens_file.is_some() {
            anyhow::bail!("[auth] Use only one of 'auth_tokens' or 'auth_tokens_file'.");
        }

        validate_vpn_networks(
            self.network.network.as_deref(),
            self.network.server_ip.as_deref(),
            self.network.network6.as_deref(),
            self.network.server_ip6.as_deref(),
            self.network.ip6_strategy,
            "network",
        )?;

        if let Some(mtu) = self.network.mtu {
            validate_mtu(mtu, "network")?;
        }

        Ok(())
    }
}

impl VpnClientConfig {
    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnclient\"")?;
        if role != Role::VpnClient {
            anyhow::bail!("Config file has wrong role for client. Expected role = \"vpnclient\"");
        }

        let iroh = self.iroh.as_ref().context(
            "Config file missing required [iroh] section. Add a [iroh] section with 'server_node_id'.",
        )?;

        if iroh.server_node_id.is_none() {
            anyhow::bail!("[iroh] 'server_node_id' is required for client config.");
        }

        if self.auth.auth_token.is_some() && self.auth.auth_token_file.is_some() {
            anyhow::bail!("[auth] Use only one of 'auth_token' or 'auth_token_file'.");
        }

        if let Some(ref routes) = self.network.routes {
            for route in routes {
                validate_cidr(route)
                    .with_context(|| format!("[network] Invalid route CIDR '{}'", route))?;
            }
        }

        if let Some(ref routes6) = self.network.routes6 {
            for route6 in routes6 {
                validate_ipv6_cidr(route6).with_context(|| route6_context(route6, Some("network")))?;
            }
        }

        Ok(())
    }
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    } else if path_str == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    path.to_path_buf()
}

// On-disk TOML loading is desktop-only (the iOS runtime config arrives as JSON
// through the FFI; the default paths resolve via `crate::runtime::config_dir`,
// a module not built on iOS).
#[cfg(not(target_os = "ios"))]
fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Default config path: the machine-global system config directory (see
/// [`crate::runtime::config_dir`]), not a per-user home directory — `ezvpn` runs
/// as root/LocalSystem.
#[cfg(not(target_os = "ios"))]
fn default_vpn_server_config_path() -> PathBuf {
    crate::runtime::config_dir().join("vpn_server.toml")
}

#[cfg(not(target_os = "ios"))]
fn default_vpn_client_config_path() -> PathBuf {
    crate::runtime::config_dir().join("vpn_client.toml")
}

#[cfg(not(target_os = "ios"))]
pub fn load_vpn_server_config(path: Option<&Path>) -> Result<VpnServerConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_server_config_path(),
    };
    load_config(&config_path)
}

#[cfg(not(target_os = "ios"))]
pub fn load_vpn_client_config(path: Option<&Path>) -> Result<VpnClientConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_client_config_path(),
    };
    load_config(&config_path)
}

#[derive(Debug, Clone)]
pub struct ResolvedVpnServerConfig {
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    pub ip6_strategy: Ip6Strategy,
    pub mtu: u16,
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auth_tokens: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
    pub drop_on_full: bool,
    pub client_channel_size: usize,
    pub tun_writer_channel_size: usize,
    pub transport: TransportTuning,
    pub disable_spoofing_check: bool,
}

impl ResolvedVpnServerConfig {
    pub fn from_config(cfg: &VpnServerConfig) -> Result<Self> {
        let iroh = cfg
            .iroh
            .as_ref()
            .context("Missing [iroh] section in config file")?;
        let net = &cfg.network;
        let auth = &cfg.auth;

        if iroh.secret_file.is_none() {
            anyhow::bail!(
                "[iroh] 'secret_file' is required for server identity. Generate with: ezvpn generate-server-key -o ./vpn-server.key"
            );
        }

        validate_vpn_networks(
            net.network.as_deref(),
            net.server_ip.as_deref(),
            net.network6.as_deref(),
            net.server_ip6.as_deref(),
            net.ip6_strategy,
            "network",
        )?;

        let mtu = net.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "network")?;
        if net.network6.is_some() && mtu < 1280 {
            log::warn!(
                "[network] mtu {} is below 1280, the IPv6 minimum link MTU; inner IPv6 traffic will not work",
                mtu
            );
        }

        let has_tokens = auth.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
        if has_tokens && auth.auth_tokens_file.is_some() {
            anyhow::bail!(
                "[auth] Cannot specify both auth_tokens and auth_tokens_file. Use exactly one source."
            );
        }

        let client_channel_size = cfg
            .client_channel_size
            .unwrap_or(DEFAULT_CLIENT_CHANNEL_SIZE);
        validate_channel_size(client_channel_size, "client_channel_size", "config")?;

        let tun_writer_channel_size = cfg
            .tun_writer_channel_size
            .unwrap_or(DEFAULT_TUN_WRITER_CHANNEL_SIZE);
        validate_channel_size(tun_writer_channel_size, "tun_writer_channel_size", "config")?;

        validate_transport_tuning(&iroh.transport, "iroh.transport")?;

        Ok(Self {
            network: net.network.clone(),
            server_ip: net.server_ip.clone(),
            network6: net.network6.clone(),
            server_ip6: net.server_ip6.clone(),
            ip6_strategy: net.ip6_strategy,
            mtu,
            secret_file: iroh.secret_file.clone(),
            relay_urls: iroh.relay_urls.clone().unwrap_or_default(),
            dns_server: iroh.dns_server.clone(),
            auth_tokens: auth.auth_tokens.clone().unwrap_or_default(),
            auth_tokens_file: auth.auth_tokens_file.clone(),
            drop_on_full: cfg.drop_on_full,
            client_channel_size,
            tun_writer_channel_size,
            transport: iroh.transport.clone(),
            disable_spoofing_check: cfg.disable_spoofing_check,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedVpnClientConfig {
    pub server_node_id: String,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub routes: Vec<String>,
    pub routes6: Vec<String>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

#[derive(Default)]
pub struct VpnClientConfigBuilder {
    server_node_id: Option<String>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    routes: Option<Vec<String>>,
    routes6: Option<Vec<String>>,
    relay_urls: Option<Vec<String>>,
    dns_server: Option<String>,
    auto_reconnect: Option<bool>,
    max_reconnect_attempts: Option<NonZeroU32>,
}

impl VpnClientConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_defaults(mut self) -> Self {
        self.routes = Some(vec![]);
        self.routes6 = Some(vec![]);
        self.relay_urls = Some(vec![]);
        self
    }

    pub fn apply_config(mut self, config: Option<&VpnClientConfig>) -> Self {
        if let Some(cfg) = config {
            if let Some(iroh) = cfg.iroh.as_ref() {
                if iroh.server_node_id.is_some() {
                    self.server_node_id = iroh.server_node_id.clone();
                }
                if iroh.relay_urls.is_some() {
                    self.relay_urls = iroh.relay_urls.clone();
                }
                if iroh.dns_server.is_some() {
                    self.dns_server = iroh.dns_server.clone();
                }
            }
            if cfg.auth.auth_token.is_some() {
                self.auth_token = cfg.auth.auth_token.clone();
            }
            if cfg.auth.auth_token_file.is_some() {
                self.auth_token_file = cfg.auth.auth_token_file.clone();
            }
            if cfg.network.routes.is_some() {
                self.routes = cfg.network.routes.clone();
            }
            if cfg.network.routes6.is_some() {
                self.routes6 = cfg.network.routes6.clone();
            }
            if cfg.auto_reconnect.is_some() {
                self.auto_reconnect = cfg.auto_reconnect;
            }
            if cfg.max_reconnect_attempts.is_some() {
                self.max_reconnect_attempts = cfg.max_reconnect_attempts;
            }
        }
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        mut self,
        server_node_id: Option<String>,
        auth_token: Option<String>,
        auth_token_file: Option<PathBuf>,
        routes: Vec<String>,
        routes6: Vec<String>,
        relay_urls: Vec<String>,
        dns_server: Option<String>,
        auto_reconnect: Option<bool>,
        max_reconnect_attempts: Option<NonZeroU32>,
    ) -> Self {
        if server_node_id.is_some() {
            self.server_node_id = server_node_id;
        }
        if auth_token.is_some() {
            self.auth_token = auth_token;
        }
        if auth_token_file.is_some() {
            self.auth_token_file = auth_token_file;
        }
        if !routes.is_empty() {
            self.routes = Some(routes);
        }
        if !routes6.is_empty() {
            self.routes6 = Some(routes6);
        }
        if !relay_urls.is_empty() {
            self.relay_urls = Some(relay_urls);
        }
        if dns_server.is_some() {
            self.dns_server = dns_server;
        }
        if auto_reconnect.is_some() {
            self.auto_reconnect = auto_reconnect;
        }
        if max_reconnect_attempts.is_some() {
            self.max_reconnect_attempts = max_reconnect_attempts;
        }
        self
    }

    pub fn build(self) -> Result<ResolvedVpnClientConfig> {
        let server_node_id = self.server_node_id.ok_or_else(|| {
            anyhow::anyhow!(
                "Server node ID is required. Provide --server-node-id or set server_node_id in config."
            )
        })?;

        let routes = self.routes.unwrap_or_default();
        for route in &routes {
            validate_cidr(route)
                .with_context(|| format!("Invalid route CIDR '{}' (e.g., 0.0.0.0/0)", route))?;
        }

        let routes6 = self.routes6.unwrap_or_default();
        for route6 in &routes6 {
            validate_ipv6_cidr(route6).with_context(|| route6_context(route6, Some("config")))?;
        }

        if self.auth_token.is_some() && self.auth_token_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_token and auth_token_file. Use one source for auth."
            );
        }

        Ok(ResolvedVpnClientConfig {
            server_node_id,
            auth_token: self.auth_token,
            auth_token_file: self.auth_token_file,
            routes,
            routes6,
            relay_urls: self.relay_urls.unwrap_or_default(),
            dns_server: self.dns_server,
            auto_reconnect: self.auto_reconnect.unwrap_or(true),
            max_reconnect_attempts: self.max_reconnect_attempts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_toml(network_extra: &str) -> String {
        format!(
            r#"
role = "vpnserver"

[network]
network6 = "fd00::/64"
{network_extra}

[auth]
auth_tokens = ["token"]

[iroh]
secret_file = "./vpn-server.key"
"#
        )
    }

    #[test]
    fn test_ip6_strategy_parses_node_id() {
        let config: VpnServerConfig =
            toml::from_str(&server_toml(r#"ip6_strategy = "node-id""#)).unwrap();
        assert_eq!(config.network.ip6_strategy, Ip6Strategy::NodeId);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ip6_strategy_defaults_to_sequential() {
        let config: VpnServerConfig = toml::from_str(&server_toml("")).unwrap();
        assert_eq!(config.network.ip6_strategy, Ip6Strategy::Sequential);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ip6_strategy_node_id_rejects_narrow_subnet() {
        let toml_str = server_toml(r#"ip6_strategy = "node-id""#).replace("fd00::/64", "fd00::/65");
        let config: VpnServerConfig = toml::from_str(&toml_str).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("/64 or wider"), "unexpected error: {err}");
    }

    #[test]
    fn test_ip6_strategy_node_id_rejects_server_ip6() {
        let config: VpnServerConfig = toml::from_str(&server_toml(
            "ip6_strategy = \"node-id\"\nserver_ip6 = \"fd00::1\"",
        ))
        .unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("server_ip6"), "unexpected error: {err}");
    }

    #[test]
    fn test_ip6_strategy_node_id_requires_network6() {
        let toml_str = server_toml(r#"ip6_strategy = "node-id""#)
            .replace("network6 = \"fd00::/64\"", "network = \"10.0.0.0/24\"");
        let config: VpnServerConfig = toml::from_str(&toml_str).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("requires 'network6'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_server_config_reads_mtu_and_transport() {
        let config: VpnServerConfig = toml::from_str(&server_toml(
            "mtu = 1400\n\n[iroh.transport]\ncongestion_controller = \"bbr\"\nreceive_window = 4194304",
        ))
        .unwrap();
        let resolved = ResolvedVpnServerConfig::from_config(&config).unwrap();
        assert_eq!(resolved.mtu, 1400);
        assert_eq!(
            resolved.transport.congestion_controller,
            CongestionController::Bbr
        );
        assert_eq!(resolved.transport.receive_window, Some(4194304));
        assert_eq!(resolved.transport.send_window, None);
        assert_eq!(resolved.transport.effective_windows(), (4194304, 4194304));
    }

    #[test]
    fn test_effective_windows_defaults() {
        assert_eq!(
            TransportTuning::default().effective_windows(),
            (DEFAULT_RECEIVE_WINDOW, DEFAULT_RECEIVE_WINDOW)
        );
        let tuning = TransportTuning {
            congestion_controller: CongestionController::Cubic,
            receive_window: Some(1024),
            send_window: Some(2048),
        };
        assert_eq!(tuning.effective_windows(), (1024, 2048));
    }

    #[test]
    fn test_client_config_parses_shared_fields() {
        let config: VpnClientConfig = toml::from_str(
            r#"
role = "vpnclient"

[auth]
auth_token = "token"

[iroh]
server_node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
relay_urls = ["https://relay.example.com"]
dns_server = "none"
"#,
        )
        .unwrap();
        assert_eq!(config.auth.auth_token.as_deref(), Some("token"));
        let iroh = config.iroh.as_ref().unwrap();
        assert_eq!(
            iroh.relay_urls.as_deref(),
            Some(&["https://relay.example.com".to_string()][..])
        );
        assert_eq!(iroh.dns_server.as_deref(), Some("none"));

        let resolved = VpnClientConfigBuilder::new()
            .apply_defaults()
            .apply_config(Some(&config))
            .build()
            .unwrap();
        assert_eq!(resolved.relay_urls, ["https://relay.example.com"]);
        assert_eq!(resolved.dns_server.as_deref(), Some("none"));
    }

    /// A typo in a top-level key must be rejected, not silently ignored.
    #[test]
    fn test_unknown_top_level_key_rejected() {
        let err = toml::from_str::<VpnClientConfig>(
            r#"
role = "vpnclient"
auto_reconnnect = true
"#,
        )
        .err()
        .expect("typo'd top-level key must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
        assert!(msg.contains("auto_reconnnect"), "unexpected error: {msg}");
    }

    /// A typo in the `[iroh]` section must be rejected (e.g. `relay_url` instead
    /// of `relay_urls`) — this section used to flatten shared fields, which
    /// blocked `deny_unknown_fields`.
    #[test]
    fn test_unknown_iroh_key_rejected() {
        let err = toml::from_str::<VpnClientConfig>(
            r#"
role = "vpnclient"

[iroh]
server_node_id = "x"
relay_url = ["https://relay.example.com"]
"#,
        )
        .err()
        .expect("typo'd [iroh] key must be rejected");
        assert!(
            err.to_string().contains("relay_url"),
            "unexpected error: {err}"
        );
    }

    /// A typo in a `[network]` key (`route` instead of `routes`) must be rejected.
    #[test]
    fn test_unknown_network_key_rejected() {
        let err = toml::from_str::<VpnClientConfig>(
            r#"
role = "vpnclient"

[network]
route = ["10.0.0.0/8"]
"#,
        )
        .err()
        .expect("typo'd [network] key must be rejected");
        assert!(err.to_string().contains("route"), "unexpected error: {err}");
    }

    /// Server-side: a typo under `[iroh.transport]` must be rejected too.
    #[test]
    fn test_unknown_transport_key_rejected() {
        let err = toml::from_str::<VpnServerConfig>(
            r#"
role = "vpnserver"

[iroh.transport]
recieve_window = 1048576
"#,
        )
        .err()
        .expect("typo'd [iroh.transport] key must be rejected");
        assert!(
            err.to_string().contains("recieve_window"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_server_example_config_parses_and_validates() {
        let content = include_str!("../../vpn_server.toml.example");
        let config: VpnServerConfig =
            toml::from_str(content).expect("server example must parse with current sections");
        config
            .validate()
            .expect("server example must pass validation");
        // The non-iroh sections must populate, proving the rearranged layout binds.
        assert_eq!(config.network.network.as_deref(), Some("10.0.0.0/24"));
        assert!(config.auth.auth_tokens.is_some());
        assert!(config.iroh.as_ref().unwrap().secret_file.is_some());
    }

    #[test]
    fn test_client_example_config_parses_and_validates() {
        let content = include_str!("../../vpn_client.toml.example");
        let config: VpnClientConfig =
            toml::from_str(content).expect("client example must parse with current sections");
        config
            .validate()
            .expect("client example must pass validation");
        assert!(config.auth.auth_token.is_some());
        assert!(config.iroh.as_ref().unwrap().server_node_id.is_some());
    }
}
