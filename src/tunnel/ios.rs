//! Slim iOS connect path.
//!
//! iOS VPNs run inside a `NEPacketTunnelProvider` app extension. Unlike the
//! desktop [`crate::tunnel::client::VpnClient`], this path:
//!
//! - does **not** create a `utun` or configure routes/IP/MTU — the extension
//!   owns that via `NEPacketTunnelNetworkSettings`, then hands us the tunnel's
//!   `utun` fd;
//! - does **not** install OS bypass routes itself. Instead [`IosSession::connect`]
//!   computes the server underlay addresses that overlap a routed prefix (via
//!   [`crate::tunnel::client::overlapping_underlay_excludes`]) and
//!   [`IosSession::network_config`] returns them as host routes (`/32` / `/128`)
//!   for the extension to apply as `excludedRoutes`. Full tunnel is out of scope,
//!   so the *public* iroh underlay (relays, public server addresses) never needs
//!   bypassing — only an overlapping private/ULA server address does;
//! - does **not** take the single-instance lock or open a control socket.
//!
//! It reuses the portable data plane wholesale: the same handshake
//! ([`crate::tunnel::client::perform_handshake`]) and datagram loop
//! ([`crate::tunnel::client::run_tunnel`]).
//!
//! The flow is two-phase because the extension needs the server-assigned
//! addresses (IPv4 and/or IPv6), MTU, and excluded routes to build its network
//! settings *before* it can produce the `utun` fd:
//!
//! 1. [`IosSession::connect`] — create an iroh endpoint, connect, handshake.
//! 2. read [`IosSession::network_config`], apply it as
//!    `NEPacketTunnelNetworkSettings`, obtain the `utun` fd.
//! 3. [`IosSession::run`] — drive the tunnel over that fd until it ends.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::sync::Arc;

use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;

use crate::error::{VpnError, VpnResult};
use crate::net::device::TunDevice;
use crate::transport::endpoint::create_client_endpoint;
use crate::tunnel::client::{
    ServerInfo, collect_local_iroh_udp_ports, overlapping_underlay_excludes, perform_handshake,
    run_tunnel,
};

/// Connection parameters supplied by the iOS app (built from the FFI JSON).
#[derive(Debug, Clone, Default)]
pub struct IosConfig {
    /// Server's iroh endpoint id (node id), as a string.
    pub server_node_id: String,
    /// Pre-built ALPN value (`ezvpn/<ver>/<token>`).
    pub alpn: Vec<u8>,
    /// Optional ezvpn auth token.
    pub auth_token: Option<String>,
    /// Relay URL hints. When empty, iroh uses its default relay map.
    pub relay_urls: Vec<String>,
    /// Force relay-only transport (skip hole punching). Usually false.
    pub relay_only: bool,
    /// IPv4 prefixes routed through the tunnel (the split-tunnel `includedRoutes`).
    /// Used to compute which server underlay addresses overlap and must be
    /// bypassed.
    pub routes: Vec<Ipv4Net>,
    /// IPv6 prefixes routed through the tunnel.
    pub routes6: Vec<Ipv6Net>,
}

/// The network parameters the extension needs for `NEPacketTunnelNetworkSettings`.
///
/// Each family is optional, mirroring the server's assignment: IPv4-only,
/// IPv6-only, or dual-stack.
#[derive(Debug, Clone)]
pub struct IosNetworkConfig {
    /// Assigned client VPN IPv4 address.
    pub assigned_ip: Option<Ipv4Addr>,
    /// Subnet mask for the assigned IPv4 address.
    pub netmask: Option<Ipv4Addr>,
    /// VPN IPv4 gateway (server's in-subnet address).
    pub gateway: Option<Ipv4Addr>,
    /// Assigned client VPN IPv6 address.
    pub assigned_ip6: Option<Ipv6Addr>,
    /// Prefix length for the assigned IPv6 address.
    pub prefix_len6: Option<u8>,
    /// VPN IPv6 gateway (server's in-subnet address).
    pub gateway6: Option<Ipv6Addr>,
    /// Server-dictated tunnel MTU.
    pub mtu: u16,
    /// IPv4 server underlay addresses (`/32`) to exclude from the tunnel because
    /// they overlap a routed prefix (would otherwise self-capture).
    pub excluded_routes: Vec<String>,
    /// IPv6 server underlay addresses (`/128`) to exclude, same reason.
    pub excluded_routes6: Vec<String>,
}

/// A connected, handshaked-but-not-yet-running iOS tunnel session.
pub struct IosSession {
    endpoint: Endpoint,
    connection: Connection,
    server_info: ServerInfo,
    /// IPv4 server underlay `/32`s overlapping a routed prefix (computed at
    /// connect from the handshake's `server_addrs`).
    excluded_routes: Vec<String>,
    /// IPv6 server underlay `/128`s overlapping a routed prefix.
    excluded_routes6: Vec<String>,
}

impl IosSession {
    /// Create an iroh endpoint, connect to the server, and perform the
    /// handshake. The endpoint identity is ephemeral (a fresh key per session),
    /// so the server may assign a different IP on each connect — acceptable for
    /// the MVP.
    pub async fn connect(cfg: &IosConfig) -> VpnResult<Self> {
        let endpoint = create_client_endpoint(&cfg.relay_urls, cfg.relay_only, None, None)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to create iroh endpoint: {e}")))?;

        let server_id: EndpointId = cfg
            .server_node_id
            .parse()
            .map_err(|e| VpnError::config_with_source("Invalid server node ID", e))?;

        let mut addr = EndpointAddr::new(server_id);
        for relay in &cfg.relay_urls {
            let url: RelayUrl = relay
                .parse()
                .map_err(|e| VpnError::config_with_source(format!("Invalid relay URL: {relay}"), e))?;
            addr = addr.with_relay_url(url);
        }

        let connection = endpoint
            .connect(addr, cfg.alpn.as_slice())
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {e}")))?;

        // Random per-session id, like the desktop client. The server keys IP
        // allocation by (endpoint id, device id).
        let device_id: u64 = rand::rng().random();
        let server_info =
            perform_handshake(&connection, device_id, cfg.auth_token.as_deref()).await?;

        // `perform_handshake` already guarantees at least one family was
        // assigned, so IPv4-only, IPv6-only, and dual-stack all pass here.

        // Compute the underlay bypass set: server candidate addresses that fall
        // within a routed prefix and would otherwise self-capture. Applied by
        // the extension as `excludedRoutes` (see module docs).
        let (excluded_routes, excluded_routes6) =
            overlapping_underlay_excludes(&server_info.server_addrs, &cfg.routes, &cfg.routes6);
        if !excluded_routes.is_empty() || !excluded_routes6.is_empty() {
            log::info!(
                "Bypassing overlapping server underlay addresses (reachable only off-tunnel; \
                 reach the server through the tunnel via its VPN gateway IP): v4={:?} v6={:?}",
                excluded_routes,
                excluded_routes6
            );
        }

        log::info!(
            "iOS handshake OK: ip={:?} net={:?} gw={:?} ip6={:?} net6={:?} gw6={:?} mtu={}",
            server_info.assigned_ip,
            server_info.network,
            server_info.server_ip,
            server_info.assigned_ip6,
            server_info.network6,
            server_info.server_ip6,
            server_info.mtu
        );

        Ok(Self {
            endpoint,
            connection,
            server_info,
            excluded_routes,
            excluded_routes6,
        })
    }

    /// The network parameters for the extension's tunnel settings, for whichever
    /// families the server assigned (IPv4, IPv6, or both).
    pub fn network_config(&self) -> VpnResult<IosNetworkConfig> {
        let info = &self.server_info;
        Ok(IosNetworkConfig {
            assigned_ip: info.assigned_ip,
            netmask: info.network.map(|n| n.netmask()),
            gateway: info.server_ip,
            assigned_ip6: info.assigned_ip6,
            prefix_len6: info.network6.map(|n| n.prefix_len()),
            gateway6: info.server_ip6,
            mtu: info.mtu,
            excluded_routes: self.excluded_routes.clone(),
            excluded_routes6: self.excluded_routes6.clone(),
        })
    }

    /// Drive the tunnel over the extension-provided `utun` fd until it ends
    /// (peer close, idle timeout, or a fatal I/O error). Consumes the session.
    ///
    /// The two `run_tunnel` bypass hooks are `None`: the dynamic in-data-path
    /// bypass-route manager and server-address publisher channel are not used.
    /// Overlapping server underlay addresses are instead excluded statically, up
    /// front, by the extension's `NEPacketTunnelNetworkSettings` (computed in
    /// [`Self::connect`], see module docs).
    pub async fn run(self, tun_fd: RawFd) -> VpnResult<()> {
        let tun = TunDevice::from_raw_fd(tun_fd, self.server_info.mtu)?;

        let max_datagram_size = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| VpnError::Signaling("Peer does not support QUIC datagrams".into()))?;

        let local_iroh_udp_ports: Arc<HashSet<u16>> =
            Arc::new(collect_local_iroh_udp_ports(&self.endpoint));

        run_tunnel(
            tun,
            self.connection,
            self.server_info.server_gso_enabled,
            max_datagram_size,
            None,
            None,
            local_iroh_udp_ports,
        )
        .await
    }

    /// Close the iroh endpoint, tearing down the connection. Used when the app
    /// stops the tunnel before [`Self::run`] (or to force teardown).
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}
