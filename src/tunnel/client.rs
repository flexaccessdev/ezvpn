//! VPN client implementation.
//!
//! The VPN client connects to a VPN server via iroh, performs handshake
//! to receive IP assignment, configures the TUN device, and manages the
//! IP-over-QUIC tunnel. IP packets are framed and sent directly over the
//! encrypted iroh QUIC connection for automatic NAT traversal.

// On iOS only the portable data plane (run_tunnel + the handshake) is used;
// VpnClient, routing, the bypass manager and the reconnect wrapper are all
// desktop-only (they need the gated-out control/runtime modules) and compile
// here as dead code. Silence the resulting unused-import / dead-code noise on
// iOS rather than finely gating every line.
#![cfg_attr(target_os = "ios", allow(unused_imports, dead_code))]

use crate::net::buffer::uninitialized_vec;
#[cfg(not(target_os = "ios"))]
use crate::config::VpnClientConfig;
use crate::tunnel::datagram::{
    Datagram, FRAME_ARENA_CHUNK, build_datagrams, build_gro_datagrams, classify,
};
use crate::net::device::{
    BypassRouteGuard, Route6Guard, RouteGuard, TunConfig, TunDevice, UnderlayGateway,
    add_bypass_route, add_routes, add_routes6_with_src, query_default_gateway,
};
#[cfg(not(target_os = "ios"))]
use crate::control::{ClientConnectedInfo, ClientStatusHandle};
use crate::error::{VpnError, VpnResult};
#[cfg(not(target_os = "ios"))]
use crate::runtime::{LockRole, VpnLock};
use crate::tunnel::offload::{TcpGroTable, VirtioNetHdr, materialize_offload_into};
use crate::transport::paths::{format_connection_paths, watch_connection_paths};
use crate::config::VPN_MTU;
use crate::tunnel::signaling::{
    MAX_HANDSHAKE_SIZE, ServerAddrsMsg, VPN_ALPN, VpnHandshake, VpnHandshakeResponse,
    parse_ip_packet_v2, read_message, write_message,
};
use crate::transport::endpoint::parse_relay_mode;
use bytes::{Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::{Connection, SendDatagramError};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Maximum number of inbound packets drained from the TUN-writer channel per
/// batched TUN write.
const WRITE_BATCH_SIZE: usize = 256;

/// Channel buffer size for inbound packets queued to the TUN writer task.
///
/// Decouples datagram receipt from TUN write syscalls so the inbound reader
/// keeps draining datagrams while the writer task issues per-packet TUN writes.
const INBOUND_TUN_CHANNEL_SIZE: usize = 512;

/// Channel buffer size for server-published candidate-address sets handed from
/// the inbound datagram loop to the bypass-route manager. Tiny: publications are
/// infrequent (every [`crate::transport::SERVER_ADDR_PUBLISH_INTERVAL`]) and a
/// dropped one is recovered by the next periodic publish.
const SERVER_ADDR_CHANNEL_SIZE: usize = 8;

/// Client GSO capability advertised to the server in the handshake.
///
/// Always `true`: data-channel GSO metadata is supported even when the local
/// TUN has no offload, because inbound metadata is materialized in software.
const ADVERTISED_GSO: bool = true;

/// Timeout for resolving relay URLs via DNS.
const RESOLVE_RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// A decoded inbound packet queued for the dedicated TUN writer task.
struct InboundTunWrite {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

/// Enqueue a decoded inbound packet on the TUN writer channel.
///
/// Mirrors the server's `enqueue_tun_write`: the common, uncontended case takes
/// the lock-free `try_send` fast path and only `.await`s when the channel is
/// full (backpressure), avoiding a guaranteed task wake-up per received packet.
/// Returns `false` if the channel is closed.
async fn enqueue_inbound_tun_write(tx: &mpsc::Sender<InboundTunWrite>, req: InboundTunWrite) -> bool {
    match tx.try_send(req) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(req)) => tx.send(req).await.is_ok(),
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// VPN client instance.
///
/// Desktop-only: holds the single-instance lock and the control-socket status
/// handle. On iOS the connect path lives in [`crate::tunnel::ios`] and drives an
/// OS-provided utun fd instead.
#[cfg(not(target_os = "ios"))]
pub struct VpnClient {
    /// Client configuration.
    config: VpnClientConfig,
    /// Client's unique device ID.
    device_id: u64,
    /// Single-instance lock.
    _lock: VpnLock,
    /// Live status published to the control socket.
    status: ClientStatusHandle,
    /// Network parameters established on the first successful handshake. Used to
    /// detect server config changes across reconnects (see
    /// [`VpnClient::check_config_consistency`]). Mutable because a pure
    /// assigned-IP reassignment adopts the new IP as the baseline rather than
    /// quitting.
    established_params: std::sync::Mutex<Option<NetworkParams>>,
}

/// Information received from the VPN server after successful handshake.
///
/// At least one of IPv4 or IPv6 must be configured:
/// - IPv4-only: `assigned_ip`, `network`, `server_ip` are set; IPv6 fields are None
/// - IPv6-only: `assigned_ip6`, `network6`, `server_ip6` are set; IPv4 fields are None
/// - Dual-stack: Both IPv4 and IPv6 fields are set
#[non_exhaustive]
pub struct ServerInfo {
    /// Assigned VPN IP for this client (IPv4). None for IPv6-only mode.
    pub assigned_ip: Option<Ipv4Addr>,
    /// VPN network CIDR (IPv4). None for IPv6-only mode.
    pub network: Option<Ipv4Net>,
    /// Server's VPN IP (gateway, IPv4). None for IPv6-only mode.
    pub server_ip: Option<Ipv4Addr>,
    /// Assigned IPv6 VPN address for this client. None for IPv4-only mode.
    pub assigned_ip6: Option<Ipv6Addr>,
    /// IPv6 VPN network CIDR. None for IPv4-only mode.
    pub network6: Option<Ipv6Net>,
    /// Server's IPv6 VPN address (gateway). None for IPv4-only mode.
    pub server_ip6: Option<Ipv6Addr>,
    /// Whether server-side Linux TUN GSO is enabled.
    pub server_gso_enabled: bool,
    /// Server's candidate iroh underlay addresses, delivered in the handshake so
    /// the client can bypass-route any a VPN route would capture at onboarding
    /// (rather than waiting for the first periodic data-path publication). Empty
    /// when the server has not yet discovered any, or is an older build.
    pub server_addrs: Vec<IpAddr>,
}

/// Network parameters that define the client's TUN device and routing identity.
///
/// Captured from the first successful handshake and compared against every
/// later reconnect. A change to just the assigned client IP(s) is rebuilt in
/// place (the next `connect()` builds a fresh TUN device and routes for the new
/// address); a change to any other field — network, gateway, or the IPv6 trio —
/// makes the client quit instead (see
/// [`VpnClient::check_config_consistency`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkParams {
    assigned_ip: Option<Ipv4Addr>,
    network: Option<Ipv4Net>,
    server_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
}

impl NetworkParams {
    fn from_server_info(info: &ServerInfo) -> Self {
        Self {
            assigned_ip: info.assigned_ip,
            network: info.network,
            server_ip: info.server_ip,
            assigned_ip6: info.assigned_ip6,
            network6: info.network6,
            server_ip6: info.server_ip6,
        }
    }

    /// True when every field except the assigned client IP(s) matches `other`.
    ///
    /// If this holds for two non-equal params, the only difference is the
    /// assigned IPv4/IPv6 address, which is rebuilt in place rather than treated
    /// as a fatal server config change.
    fn non_ip_fields_eq(&self, other: &Self) -> bool {
        self.network == other.network
            && self.server_ip == other.server_ip
            && self.network6 == other.network6
            && self.server_ip6 == other.server_ip6
    }
}

impl std::fmt::Display for NetworkParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
            v.as_ref().map_or_else(|| "none".to_string(), |x| x.to_string())
        }
        write!(
            f,
            "ip={} net={} gw={} ip6={} net6={} gw6={}",
            opt(&self.assigned_ip),
            opt(&self.network),
            opt(&self.server_ip),
            opt(&self.assigned_ip6),
            opt(&self.network6),
            opt(&self.server_ip6),
        )
    }
}

/// Record or compare `info`'s network parameters against `established`.
///
/// Sets the baseline on first call (returns `Ok`). On later calls:
/// - identical params → `Ok`;
/// - only the assigned client IP(s) changed → adopt the new params as the
///   baseline and return `Ok`, so the caller rebuilds the TUN device and routes
///   for the new address (this is what a server restart that reassigns the IP
///   looks like);
/// - any other field changed (network, gateway, IPv6 trio) →
///   [`VpnError::ServerConfigChanged`], a non-recoverable error that quits.
///
/// Factored out of [`VpnClient::check_config_consistency`] so the set-once /
/// compare flow can be unit-tested without a live connection.
fn check_params_against(
    established: &std::sync::Mutex<Option<NetworkParams>>,
    info: &ServerInfo,
) -> VpnResult<()> {
    let params = NetworkParams::from_server_info(info);
    let mut baseline = established.lock().expect("established_params mutex poisoned");

    let Some(prev) = baseline.as_ref() else {
        // First successful handshake: record the baseline.
        *baseline = Some(params);
        return Ok(());
    };

    if *prev == params {
        return Ok(());
    }

    if prev.non_ip_fields_eq(&params) {
        // Pure IP reassignment (e.g. server restart). Rebuild for the new
        // address instead of quitting, and adopt it as the new baseline so the
        // next reconnect compares against the address actually in use.
        log::warn!(
            "Server reassigned VPN IP on reconnect (was [{prev}], now [{params}]); \
             rebuilding TUN device and routes for the new address"
        );
        *baseline = Some(params);
        return Ok(());
    }

    Err(VpnError::ServerConfigChanged(format!(
        "VPN config changed on reconnect (was [{prev}], now [{params}]); \
         quitting to avoid inconsistent routing/TUN state"
    )))
}

#[cfg(not(target_os = "ios"))]
impl VpnClient {
    /// Create a new VPN client.
    ///
    /// Acquires a single-instance lock for the given `instance` name (only one
    /// VPN client per instance) and generates a random `device_id` (u64) for
    /// session identification. The device_id allows the server to distinguish
    /// multiple sessions from the same iroh endpoint.
    pub fn new(config: VpnClientConfig, instance: &str) -> VpnResult<Self> {
        config.validate().map_err(VpnError::config)?;

        // Acquire single-instance lock scoped to the instance name
        let lock = VpnLock::acquire(LockRole::Client, instance)?;

        // Generate random device ID (unique per session)
        let device_id: u64 = rand::rng().random();
        log::info!("Generated device ID: {:016x}", device_id);

        let status =
            ClientStatusHandle::new(instance.to_string(), config.server_node_id.clone(), device_id);

        Ok(Self {
            config,
            device_id,
            _lock: lock,
            status,
            established_params: std::sync::Mutex::new(None),
        })
    }

    /// Compare the server's network parameters against the established session.
    ///
    /// On the first successful handshake this records the baseline. On every
    /// later reconnect it compares the new parameters against that baseline:
    /// - a change to just the assigned client IP(s) — e.g. the server restarted
    ///   and handed out a different address — is allowed; the caller goes on to
    ///   build a fresh TUN device and routes for the new address, and the new
    ///   address becomes the baseline;
    /// - a change to any other field returns [`VpnError::ServerConfigChanged`]
    ///   (a non-recoverable error that quits the program) rather than silently
    ///   reconfiguring routing/TUN state for an inconsistent configuration.
    fn check_config_consistency(&self, info: &ServerInfo) -> VpnResult<()> {
        check_params_against(&self.established_params, info)
    }

    /// A cloneable handle to this client's live status, for the control socket.
    pub fn status_handle(&self) -> ClientStatusHandle {
        self.status.clone()
    }

    /// Connect to the VPN server and establish the tunnel.
    ///
    /// # Arguments
    /// * `endpoint` - The iroh endpoint to use for the connection
    /// * `relay_urls` - Optional relay URLs to use as connection hints. When DNS
    ///   discovery is disabled, relay URLs are required for the connection to succeed.
    ///   iroh will attempt hole punching for direct P2P connections, falling back
    ///   to relay transport if needed.
    pub async fn connect(&self, endpoint: &Endpoint, relay_urls: &[String]) -> VpnResult<()> {
        let endpoint_addr = self.resolve_server_addr(relay_urls)?;

        // Client and server both build the identical fixed transport config
        // (see crate::transport), so nothing is negotiated or upgraded here.
        let connection = endpoint
            .connect(endpoint_addr, VPN_ALPN)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {}", e)))?;

        log::info!("Connected to server, performing handshake...");

        // Perform handshake on first stream
        let server_info = self.perform_handshake(&connection).await?;

        // Monitor and report connection path changes (e.g., relay -> direct)
        let _path_watcher = watch_connection_paths(&connection, "Connection");

        log::info!("Handshake successful:");
        // Log IPv4 info if provided
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Assigned IP: {}", ip);
        }
        if let Some(net) = server_info.network {
            log::info!("  Network: {}", net);
        }
        if let Some(gw) = server_info.server_ip {
            log::info!("  Gateway: {}", gw);
        }
        // Log IPv6 info if provided
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Assigned IPv6: {}", ip6);
        }
        if let Some(net6) = server_info.network6 {
            log::info!("  Network6: {}", net6);
        }
        if let Some(gw6) = server_info.server_ip6 {
            log::info!("  Gateway6: {}", gw6);
        }
        // Log mode
        if server_info.assigned_ip.is_none() {
            log::info!("  Mode: IPv6-only");
        } else if server_info.assigned_ip6.is_some() {
            log::info!("  Mode: dual-stack");
        } else {
            log::info!("  Mode: IPv4-only");
        }
        log::info!("  Server GSO enabled: {}", server_info.server_gso_enabled);
        log::info!("  MTU (fixed): {}", VPN_MTU);

        // If this is a reconnect and the server's network parameters changed,
        // quit rather than rebuild for a new config — unless only the assigned
        // IP changed, in which case we fall through and rebuild the TUN device
        // and routes below for the new address. Done before creating any TUN
        // device or routes so nothing is set up on the fatal path.
        self.check_config_consistency(&server_info)?;

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Bootstrap the iroh bypasses BEFORE adding VPN routes: the relay set is
        // known up front and the server's candidate underlay addresses arrived in
        // the handshake, so both the relay fallback and the server's direct path
        // are protected the moment VPN routes go in — no blocking wait on path
        // discovery, and no 30s gap until the first periodic publish. The spawned
        // task then applies the server's ongoing published address sets; until any
        // address lands, traffic rides the already-bypassed relay, so VPN routes
        // never black-hole iroh.
        let will_add_routes = (server_info.assigned_ip.is_some() && !self.config.routes.is_empty())
            || (server_info.assigned_ip6.is_some() && !self.config.routes6.is_empty());
        // Hold the bypass-manager task in an abort-on-drop guard: route
        // installation below can early-return via `?` before `run_tunnel` takes
        // ownership, and a dropped bare handle would leak the task rather than
        // abort it. The guard is disarmed only when ownership passes onward.
        let bypass_handles = if will_add_routes {
            Some(
                self.add_iroh_bypass_routes(
                    endpoint,
                    tun_device.name(),
                    relay_urls,
                    &server_info.server_addrs,
                )
                .await,
            )
        } else {
            None
        };
        let (bypass_route_guard, server_addr_tx, bypass_collected) = match bypass_handles {
            Some(h) => (
                Some(AbortOnDropTask::new(h.task)),
                Some(h.server_addr_tx),
                Some(h.collected),
            ),
            None => (None, None, None),
        };

        // Route the advertised networks — the server's host prefixes (/32 and
        // /128) — through the TUN so the gateway is reachable on every
        // platform. The point-to-point destination already covers the IPv4
        // gateway on macOS/Linux (route-add tolerates the pre-existing route),
        // but not on Windows, and nothing else routes the IPv6 gateway.
        let _gateway_route_guard: Option<RouteGuard> = match server_info.network {
            Some(net) => Some(add_routes(tun_device.name(), &[net]).await?),
            None => None,
        };
        let _gateway_route6_guard: Option<Route6Guard> =
            match (server_info.assigned_ip6, server_info.network6) {
                (Some(ip6), Some(net6)) => {
                    Some(add_routes6_with_src(tun_device.name(), &[net6], ip6).await?)
                }
                _ => None,
            };

        // Add custom IPv4 routes through the VPN (guard ensures cleanup on drop)
        // Only add IPv4 routes if server provided IPv4 and client has routes configured
        let mut active_routes: Vec<String> = Vec::new();
        let _route_guard: Option<RouteGuard> =
            if server_info.assigned_ip.is_some() && !self.config.routes.is_empty() {
                active_routes = self.config.routes.iter().map(|r| r.to_string()).collect();
                Some(add_routes(tun_device.name(), &self.config.routes).await?)
            } else {
                None
            };

        // Add custom IPv6 routes through the VPN (guard ensures cleanup on drop)
        // Only add IPv6 routes if server provided IPv6 and client has routes6 configured
        // Use the assigned IPv6 as source to ensure correct source address selection
        // (important when client has multiple IPv6 addresses, e.g., public + VPN)
        let mut active_routes6: Vec<String> = Vec::new();
        let _route6_guard: Option<Route6Guard> =
            if let Some(assigned_ip6) = server_info.assigned_ip6 {
                if !self.config.routes6.is_empty() {
                    active_routes6 = self.config.routes6.iter().map(|r| r.to_string()).collect();
                    Some(
                        add_routes6_with_src(tun_device.name(), &self.config.routes6, assigned_ip6)
                            .await?,
                    )
                } else {
                    None
                }
            } else {
                None
            };

        // The IP data path is unreliable QUIC datagrams; verify the peer
        // supports them. The datagram cap is read live during the packet loop
        // (it tracks path-MTU discovery); this handshake-time value is
        // informational only.
        let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
            VpnError::Signaling("Peer does not support QUIC datagrams".into())
        })?;
        log::info!(
            "QUIC max datagram size at connect: {} (tracks path-MTU discovery)",
            max_datagram_size
        );

        let offload_status = tun_device.offload_status();
        let local_gso_enabled = offload_status.enabled;
        let negotiated_gso = local_gso_enabled && server_info.server_gso_enabled;
        log::info!(
            "GSO status (client): local={}, server={}, negotiated={}, advertised={}",
            local_gso_enabled,
            server_info.server_gso_enabled,
            negotiated_gso,
            ADVERTISED_GSO
        );
        if !local_gso_enabled {
            let reason = offload_status.reason.as_deref().unwrap_or("unknown reason");
            if server_info.server_gso_enabled {
                log::warn!("Local TUN GSO disabled: {}", reason);
            } else {
                log::info!("Local TUN GSO disabled: {}", reason);
            }
        }

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Client IP: {}", ip);
        }
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Client IPv6: {}", ip6);
        }

        // Publish connected status for the control socket. The probe captures a
        // clone of the connection so `status` reports live iroh path info
        // (direct/relay). A second probe reports the bypass addresses the manager
        // has collected (intended bypasses), when a manager is running.
        let status_conn = connection.clone();
        let bypass_probe: Option<crate::control::BypassRoutesProbe> =
            bypass_collected.map(|collected| {
                let probe: crate::control::BypassRoutesProbe = Arc::new(move || {
                    let set = collected.lock().expect("collected lock poisoned");
                    set.iter().map(|ip| ip.to_string()).collect()
                });
                probe
            });
        self.status.set_connected(
            ClientConnectedInfo {
                assigned_ip: server_info.assigned_ip.map(|ip| ip.to_string()),
                network: server_info.network.map(|n| n.to_string()),
                gateway: server_info.server_ip.map(|ip| ip.to_string()),
                assigned_ip6: server_info.assigned_ip6.map(|ip| ip.to_string()),
                network6: server_info.network6.map(|n| n.to_string()),
                gateway6: server_info.server_ip6.map(|ip| ip.to_string()),
                mtu: VPN_MTU,
                gso_negotiated: negotiated_gso,
                routes: active_routes,
                routes6: active_routes6,
            },
            Arc::new(move || format_connection_paths(&status_conn.paths())),
            bypass_probe,
        );

        // Drop any tunneled UDP packets that target this endpoint's own iroh
        // socket ports. This prevents recursive self-encapsulation loops.
        let local_iroh_udp_ports = Arc::new(collect_local_iroh_udp_ports(endpoint));
        if !local_iroh_udp_ports.is_empty() {
            log::info!(
                "Filtering tunneled traffic for {} local iroh UDP port(s)",
                local_iroh_udp_ports.len()
            );
        }

        // Run the VPN packet loop (tunneled over iroh datagrams). Hand the still-
        // armed guard to `run_tunnel`, which disarms it only after its own setup
        // can no longer return early (past `tun_device.split()`); until then the
        // guard keeps aborting the bypass task on any early exit. `run_tunnel`
        // aborts the task when the VPN ends.
        let result = run_tunnel(
            tun_device,
            connection,
            server_info.server_gso_enabled,
            bypass_route_guard,
            server_addr_tx,
            local_iroh_udp_ports,
        )
        .await;

        // Session ended; reflect disconnection (reconnect, if enabled, will
        // publish a fresh connected status).
        self.status.set_disconnected();
        result
    }

    /// Resolve the server's `EndpointAddr` with relay hints if available.
    ///
    /// When DNS discovery is disabled, relay URLs are required for the
    /// connection to succeed. iroh uses the relay for initial connection
    /// routing while still attempting hole punching for direct P2P.
    fn resolve_server_addr(&self, relay_urls: &[String]) -> VpnResult<EndpointAddr> {
        // Parse server endpoint ID
        let server_id: EndpointId = self.config.server_node_id.parse().map_err(|e| {
            VpnError::config_with_source(
                format!("Invalid server node ID: {}", self.config.server_node_id),
                e,
            )
        })?;

        log::info!("Connecting to VPN server: {}", server_id);

        if relay_urls.is_empty() {
            return Ok(EndpointAddr::new(server_id));
        }

        let mut addr = EndpointAddr::new(server_id);
        for relay_url_str in relay_urls {
            let relay_url: RelayUrl = relay_url_str.parse().map_err(|e| {
                VpnError::config_with_source(format!("Invalid relay URL: {}", relay_url_str), e)
            })?;
            addr = addr.with_relay_url(relay_url);
        }
        log::info!("Using {} relay hint(s) for connection", relay_urls.len());
        Ok(addr)
    }

    /// Perform VPN handshake with the server.
    async fn perform_handshake(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> VpnResult<ServerInfo> {
        perform_handshake(connection, self.device_id, self.config.auth_token.as_deref()).await
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnResult<TunDevice> {
        // Build TUN config based on what the server provided.
        // Match includes all fields explicitly to be defensive against future validation changes
        // in perform_handshake and avoid implicit assumptions about grouped fields.
        let mut tun_config = match (
            server_info.assigned_ip,
            server_info.network,
            server_info.server_ip,
            server_info.assigned_ip6,
            server_info.network6,
            server_info.server_ip6,
        ) {
            // Dual-stack: both IPv4 and IPv6
            (Some(ip4), Some(net4), Some(gw4), Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::new(ip4, net4.netmask(), gw4)
                    .with_mtu(VPN_MTU)
                    .with_ipv6(ip6, net6.prefix_len())?
            }
            // IPv4-only
            (Some(ip4), Some(net4), Some(gw4), None, None, None) => {
                TunConfig::new(ip4, net4.netmask(), gw4).with_mtu(VPN_MTU)
            }
            // IPv6-only
            (None, None, None, Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::ipv6_only(ip6, net6.prefix_len(), VPN_MTU)?
            }
            // Invalid: should be caught earlier in perform_handshake
            _ => {
                return Err(VpnError::Signaling(
                    "Invalid server info: need at least one complete IP configuration".into(),
                ));
            }
        };
        tun_config = tun_config.with_gso(server_info.server_gso_enabled);

        TunDevice::create(tun_config)
    }

    /// Eagerly bypass the iroh relay IPs, then spawn the manager fed by the
    /// server's published address set.
    ///
    /// The relay set is known up front (configured relay URLs, or the default
    /// relay map when none are configured), so it needs no path discovery: we
    /// resolve every relay (IPv4 and IPv6) and install a bypass for each address
    /// that a VPN route would otherwise capture, *before* the caller installs the
    /// VPN routes. This guarantees the relay fallback path survives VPN route
    /// installation. The server's direct underlay addresses are then learned from
    /// the set the server publishes over the data path; until they land, traffic
    /// simply rides the (already-bypassed) relay, so there is no startup race.
    ///
    /// The underlay default gateway is captured here, while the routing table is
    /// still pristine, so a server address learned later can be re-pinned via it.
    ///
    /// Returns the manager task handle (caller aborts it on shutdown; the task
    /// owns all bypass route guards and drops them when the data path ends) plus
    /// the sender the data path uses to feed published address sets in.
    async fn add_iroh_bypass_routes(
        &self,
        endpoint: &Endpoint,
        vpn_tun_name: &str,
        relay_urls: &[String],
        initial_server_addrs: &[IpAddr],
    ) -> BypassRouteHandles {
        // Bypass routes are only needed for iroh peer IPs that a VPN route would
        // otherwise capture, so hand the manager the prefixes about to be installed.
        let vpn_routes4 = self.config.routes.clone();
        let vpn_routes6 = self.config.routes6.clone();

        // Capture the underlay default gateway now, while the routing table is
        // still pristine (the caller installs VPN routes only after this returns).
        // A direct iroh path discovered later would otherwise resolve through the
        // tunnel and be impossible to bypass. Only query a family that actually
        // has VPN routes, since only those can capture an iroh peer IP.
        let underlay_gw4 = if vpn_routes4.is_empty() {
            None
        } else {
            capture_underlay_gateway(false).await
        };
        let underlay_gw6 = if vpn_routes6.is_empty() {
            None
        } else {
            capture_underlay_gateway(true).await
        };

        // Shared set of intended bypasses, surfaced in client status; the manager
        // writes it, the status probe reads it.
        let collected = Arc::new(Mutex::new(BTreeSet::new()));
        let mut manager = BypassRouteManager::new(
            vpn_tun_name.to_string(),
            HashMap::new(),
            vpn_routes4,
            vpn_routes6,
            underlay_gw4,
            underlay_gw6,
            collected.clone(),
        );

        // Eagerly bypass the bootstrap set before the caller installs VPN routes:
        // every relay IP (both families), plus the server's candidate underlay
        // addresses carried in the handshake response. Seeding the server's
        // addresses here means a direct server address a VPN route would capture
        // is pinned at onboarding, instead of waiting for the first periodic
        // data-path publication. `update` filters to addresses actually covered by
        // a VPN route, so publishing extra (e.g. private/LAN) addresses is safe.
        let mut bootstrap_ips = collect_relay_ips(endpoint, relay_urls).await;
        bootstrap_ips.extend(initial_server_addrs.iter().copied());
        if !bootstrap_ips.is_empty() {
            manager.update(bootstrap_ips).await;
        }

        // Channel feeding the manager the set the server periodically publishes
        // over the data path (see `run_server_addr_publisher` on the server). This
        // is the sole ongoing source of bypass routes: the server's own candidate
        // underlay addresses are authoritative (no DNS, no path-selection race),
        // so the client no longer watches iroh path snapshots to discover them.
        let (server_addr_tx, server_addr_rx) =
            mpsc::channel::<HashSet<IpAddr>>(SERVER_ADDR_CHANNEL_SIZE);

        // Spawn the manager: it applies each server-published address set
        // add-only (filtered to VPN-covered IPs) until the data path ends.
        let handle = tokio::spawn(async move {
            run_bypass_route_manager(manager, server_addr_rx).await;
        });

        BypassRouteHandles {
            task: handle,
            server_addr_tx,
            collected,
        }
    }
}

/// Perform the VPN handshake on `connection` and return the server-assigned
/// network parameters.
///
/// Shared by the desktop [`VpnClient`] and the iOS connect path
/// ([`crate::tunnel::ios`]): both open a bi-stream, send a [`VpnHandshake`]
/// (advertising data-channel GSO), and parse the [`VpnHandshakeResponse`]. The
/// `device_id` keys the server's idempotent IP allocation; `auth_token` is the
/// optional pre-shared credential.
pub(crate) async fn perform_handshake(
    connection: &Connection,
    device_id: u64,
    auth_token: Option<&str>,
) -> VpnResult<ServerInfo> {
    // Open bidirectional stream for handshake
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| VpnError::Signaling(format!("Failed to open stream: {}", e)))?;

    // Send handshake. The client advertises its data-channel GSO capability
    // here (the data path is datagrams, so there is no separate, racy
    // capabilities message — the reliable handshake carries it).
    let mut handshake = VpnHandshake::new(device_id).with_gso(ADVERTISED_GSO);
    if let Some(token) = auth_token {
        handshake = handshake.with_auth_token(token);
    }

    write_message(&mut send, &handshake.encode()?).await?;

    // Read response
    let response_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE).await?;
    let response = VpnHandshakeResponse::decode(&response_data)?;

    if !response.accepted {
        let reason = response
            .reject_reason
            .unwrap_or_else(|| "Unknown".to_string());
        return Err(VpnError::AuthenticationFailed(reason));
    }

    // Extract IPv4 info (optional, for IPv4-only or dual-stack)
    // All three IPv4 fields must be present together or all absent for consistency
    let (assigned_ip, network, server_ip) =
        match (response.assigned_ip, response.network, response.server_ip) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnError::Signaling(
                    "Server response has incomplete IPv4 configuration: \
                     assigned_ip, network, and server_ip must all be present or all absent"
                        .into(),
                ));
            }
        };

    // Extract IPv6 info (optional, for IPv6-only or dual-stack)
    // All three IPv6 fields must be present together or all absent for consistency
    let (assigned_ip6, network6, server_ip6) =
        match (response.assigned_ip6, response.network6, response.server_ip6) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnError::Signaling(
                    "Server response has incomplete IPv6 configuration: \
                     assigned_ip6, network6, and server_ip6 must all be present or all absent"
                        .into(),
                ));
            }
        };

    // At least one of IPv4 or IPv6 must be provided
    if assigned_ip.is_none() && assigned_ip6.is_none() {
        return Err(VpnError::Signaling(
            "Server response missing both IPv4 and IPv6 configuration".into(),
        ));
    }

    // Close handshake stream (best-effort, handshake already completed)
    if let Err(e) = send.finish() {
        log::debug!("Failed to finish handshake stream: {}", e);
    }
    Ok(ServerInfo {
        assigned_ip,
        network,
        server_ip,
        assigned_ip6,
        network6,
        server_ip6,
        server_gso_enabled: response.server_gso_enabled,
        server_addrs: response.server_addrs,
    })
}

/// Send every queued datagram over the connection.
///
/// Returns a disconnect reason on a fatal send error. A `TooLarge` datagram is
/// dropped (the inner flow retransmits, as with any path-MTU drop); a lost
/// connection ends the tunnel.
async fn flush_datagrams(connection: &Connection, pending: &mut Vec<Bytes>) -> Result<(), String> {
    for dgram in pending.drain(..) {
        let dgram_len = dgram.len();
        match connection.send_datagram_wait(dgram).await {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                log::warn!(
                    "Dropping outbound datagram ({} B) larger than QUIC max_datagram_size ({:?}); path MTU shrank mid-batch",
                    dgram_len,
                    connection.max_datagram_size()
                );
            }
            Err(e) => return Err(format!("QUIC datagram send error: {}", e)),
        }
    }
    Ok(())
}

/// Run the VPN packet processing loop over the iroh QUIC connection.
///
/// IP packets travel as unreliable QUIC datagrams; the reliable handshake was
/// already completed on a bi-stream by the caller. This function only shovels
/// framed IP packets between the TUN device and the datagram transport. Peer
/// liveness is detected by `Connection::closed()` (QUIC keep-alive + idle
/// timeout) — there is no application-level heartbeat.
///
/// `server_gso_enabled` is the server's advertised GSO capability. The
/// per-datagram cap frames are segmented to is read live from the connection
/// each loop iteration, so framing follows QUIC path-MTU discovery.
pub(crate) async fn run_tunnel(
    tun_device: TunDevice,
    connection: Connection,
    server_gso_enabled: bool,
    bypass_route_guard: Option<AbortOnDropTask>,
    server_addr_tx: Option<mpsc::Sender<HashSet<IpAddr>>>,
    local_iroh_udp_ports: Arc<HashSet<u16>>,
) -> VpnResult<()> {
    // Split TUN device. This is the last point setup can return early, so the
    // bypass guard stays armed across it; once the split succeeds we disarm it
    // into a bare handle that the cleanup path below aborts when the VPN ends.
    let (mut tun_reader, mut tun_writer) = tun_device.split()?;
    let bypass_route_task = bypass_route_guard.map(AbortOnDropTask::disarm);
    let local_gso_enabled = tun_reader.offload_status().enabled;
    debug_assert_eq!(local_gso_enabled, tun_writer.offload_status().enabled);
    let negotiated_gso = local_gso_enabled && server_gso_enabled;
    let buffer_size = tun_reader.buffer_size();

    // Spawn outbound task (TUN -> datagrams -> connection.send_datagram_wait).
    // `send_datagram` takes `&Connection`, so no writer task or channel is
    // needed: the TUN reader frames and sends datagrams inline (like a UDP
    // socket send). Returns a disconnect reason on a fatal error.
    let conn_out = connection.clone();
    let local_iroh_udp_ports_out = local_iroh_udp_ports.clone();
    let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let mut read_storage = uninitialized_vec(buffer_size);
        // Long-lived framing arena: datagrams are appended and split off as
        // refcounted Bytes views, amortizing allocations across packets.
        let mut arena = BytesMut::with_capacity(FRAME_ARENA_CHUNK);
        // Reusable scratch for software-materializing offload super-frames,
        // and the per-iteration list of datagrams to send.
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        // Software GRO: on a non-GSO local TUN, coalesce consecutive
        // same-flow TCP segments into offload-tagged super-frames so a
        // GSO-capable peer can hand them to its kernel via TSO.
        let software_gro = !tun_reader.vnet_hdr_enabled();
        if software_gro {
            log::info!(
                "Software GRO enabled for outbound TCP (local TUN has no offload support; event-driven drain-then-flush)"
            );
        }
        let mut gro_table = TcpGroTable::new();
        // Persistent ReadBuf: tracks the initialized region across
        // iterations so the TUN reader's `initialize_unfilled()` only
        // zeroes the buffer once instead of on every read.
        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            // Read the datagram cap live each iteration so framing follows
            // QUIC path-MTU discovery as it raises (or black-hole detection
            // lowers) the path MTU.
            let Some(max_datagram_size) = conn_out.max_datagram_size() else {
                return Some("QUIC datagrams no longer supported by peer".to_string());
            };
            packet_buf.clear();
            // Event-driven GRO: keep pulling segments that are already
            // queued on the TUN; the instant it drains, emit every
            // pending coalesced group and block for the next packet.
            let read_result = if software_gro && !gro_table.is_empty() {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        pending.clear();
                        if let Err(e) = build_gro_datagrams(
                            &mut arena,
                            &mut seg_scratch,
                            &mut pending,
                            &gro_table.flush_all(),
                            max_datagram_size,
                        ) {
                            log::warn!("Failed to frame coalesced packet: {}", e);
                        } else if let Err(reason) = flush_datagrams(&conn_out, &mut pending).await {
                            return Some(reason);
                        }
                        tun_reader.read_buf(&mut packet_buf).await
                    }
                }
            } else {
                tun_reader.read_buf(&mut packet_buf).await
            };
            match read_result {
                Ok(()) if !packet_buf.filled().is_empty() => {
                    let raw_packet = packet_buf.filled();
                    let (offload, packet) = match tun_reader.split_frame(raw_packet) {
                        Ok(parts) => parts,
                        Err(e) => {
                            log::warn!("Failed to parse TUN frame: {}", e);
                            continue;
                        }
                    };

                    if packet_has_local_iroh_udp_port(packet, &local_iroh_udp_ports_out) {
                        log::debug!(
                            "Dropped self-encapsulated iroh UDP packet from TUN ({} bytes)",
                            raw_packet.len()
                        );
                        continue;
                    }

                    if software_gro {
                        // Non-GSO TUN frames never carry offload metadata;
                        // push the plain IP packet through the GRO table.
                        let result = gro_table.push(packet);
                        if !result.outputs.is_empty() {
                            pending.clear();
                            if let Err(e) = build_gro_datagrams(
                                &mut arena,
                                &mut seg_scratch,
                                &mut pending,
                                &result.outputs,
                                max_datagram_size,
                            ) {
                                log::warn!("Failed to frame coalesced packet: {}", e);
                            } else if let Err(reason) =
                                flush_datagrams(&conn_out, &mut pending).await
                            {
                                return Some(reason);
                            }
                        }
                        if !result.pass_through {
                            continue;
                        }
                        // Pass-through: fall through to the plain
                        // framing below, avoiding any packet copy.
                    }

                    // Frame the packet into one or more datagrams (segmenting
                    // GSO super-frames to the datagram cap) and send them.
                    pending.clear();
                    if let Err(e) = build_datagrams(
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        offload.as_ref(),
                        packet,
                        negotiated_gso,
                        max_datagram_size,
                    ) {
                        log::warn!("Failed to frame packet: {}", e);
                        continue;
                    }
                    if let Err(reason) = flush_datagrams(&conn_out, &mut pending).await {
                        return Some(reason);
                    }
                }
                Ok(()) => {}
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    // Flush pending coalesced groups before shutting down.
                    pending.clear();
                    if build_gro_datagrams(
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        &gro_table.flush_all(),
                        max_datagram_size,
                    )
                    .is_ok()
                    {
                        let _ = flush_datagrams(&conn_out, &mut pending).await;
                    }
                    return Some(format!("TUN read error: {}", e));
                }
            }
        }
    });

    // Create channel for inbound packets to decouple datagram receipt from TUN
    // write syscalls. The TUN writer task owns the TunWriter.
    let (tun_write_tx, mut tun_write_rx) =
        mpsc::channel::<InboundTunWrite>(INBOUND_TUN_CHANNEL_SIZE);

    // Spawn dedicated TUN writer task. Batched channel receives reduce
    // task wakeups; write_batch coalesces consecutive same-flow TCP
    // segments into GSO super-frames on Linux, and otherwise issues one
    // TUN write per packet (utun/wintun have no batching API).
    let mut tun_writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        const MAX_TUN_WRITE_FAILURES: u32 = 10;
        let mut consecutive_tun_failures = 0u32;
        // Track a write result; returns the disconnect reason once too
        // many consecutive writes have failed.
        let mut note_write_result = |result: VpnResult<()>| -> Option<String> {
            match result {
                Ok(()) => {
                    consecutive_tun_failures = 0;
                    None
                }
                Err(e) => {
                    consecutive_tun_failures += 1;
                    if consecutive_tun_failures >= MAX_TUN_WRITE_FAILURES {
                        log::error!(
                            "Too many consecutive TUN write failures ({}), disconnecting: {}",
                            consecutive_tun_failures,
                            e
                        );
                        return Some(format!("TUN write failures exceeded: {}", e));
                    }
                    log::warn!(
                        "Failed to write to TUN ({}/{}): {}",
                        consecutive_tun_failures,
                        MAX_TUN_WRITE_FAILURES,
                        e
                    );
                    None
                }
            }
        };
        let mut batch: Vec<InboundTunWrite> = Vec::with_capacity(WRITE_BATCH_SIZE);
        // Run buffer of consecutive metadata-less packets, flushed
        // through write_batch so same-flow TCP segments coalesce into
        // GSO super-frames on Linux (one TUN write instead of N).
        let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
        loop {
            let count = tun_write_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
            if count == 0 {
                log::trace!("TUN writer task exiting");
                return None;
            }
            for req in batch.drain(..) {
                let Some(meta) = req.offload else {
                    plain_run.push(req.packet);
                    continue;
                };
                if !plain_run.is_empty() {
                    let result = tun_writer.write_batch(&plain_run).await;
                    plain_run.clear();
                    if let Some(reason) = note_write_result(result) {
                        return Some(reason);
                    }
                }
                let result = tun_writer.write_packet(Some(&meta), &req.packet).await;
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
            if !plain_run.is_empty() {
                let result = tun_writer.write_batch(&plain_run).await;
                plain_run.clear();
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
        }
    });

    // Spawn inbound task (connection datagrams -> TUN writer channel).
    // Returns a disconnect reason if the datagram read errors.
    let conn_in = connection.clone();
    let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        // Sink for server-published candidate addresses; `None` when no bypass
        // manager is running (the VPN installs no capturing routes).
        let server_addr_tx = server_addr_tx;
        // Reusable buffers for software-materializing offload super-frames:
        // segments are built in `seg_scratch`, copied once into `seg_arena`,
        // and handed out as refcounted Bytes.
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut seg_arena = BytesMut::new();
        let mut pending_segments: Vec<Bytes> = Vec::new();
        loop {
            let dgram = match conn_in.read_datagram().await {
                Ok(d) => d,
                Err(e) => {
                    log::debug!("Datagram read ended: {}", e);
                    return Some(format!("datagram read error: {}", e));
                }
            };

            let body = match classify(&dgram) {
                Ok(Datagram::Ip(body)) => body,
                Ok(Datagram::ServerAddrs(body)) => {
                    // The server periodically publishes its candidate underlay
                    // addresses; hand them to the bypass-route manager (add-only,
                    // filtered to VPN-covered IPs there). `try_send` so the
                    // receive hot loop never blocks — a dropped update is
                    // recovered by the next periodic publish.
                    if let Some(ref tx) = server_addr_tx {
                        match ServerAddrsMsg::decode(body) {
                            Ok(msg) => {
                                let ips: HashSet<IpAddr> = msg.addrs.into_iter().collect();
                                if let Err(e) = tx.try_send(ips) {
                                    log::trace!("Dropping server addrs update: {}", e);
                                }
                            }
                            Err(e) => log::warn!("Invalid server addrs datagram: {}", e),
                        }
                    }
                    continue;
                }
                Err(e) => {
                    log::trace!("Ignoring undecodable datagram: {}", e);
                    continue;
                }
            };

            let (offload, packet) = match parse_ip_packet_v2(body) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("Invalid IP datagram from peer: {}", e);
                    continue;
                }
            };

            if let Some(meta) = offload {
                if !local_gso_enabled {
                    let materialized =
                        materialize_offload_into(&meta, packet, &mut seg_scratch, |seg| {
                            seg_arena.extend_from_slice(seg);
                            pending_segments.push(seg_arena.split_to(seg.len()).freeze());
                            Ok(())
                        });
                    if let Err(e) = materialized {
                        pending_segments.clear();
                        log::warn!("Dropping packet with unsupported offload metadata: {}", e);
                        continue;
                    }
                    for packet in pending_segments.drain(..) {
                        let req = InboundTunWrite {
                            packet,
                            offload: None,
                        };
                        if !enqueue_inbound_tun_write(&tun_write_tx, req).await {
                            log::trace!("TUN writer channel closed");
                            return None;
                        }
                    }
                } else {
                    let req = InboundTunWrite {
                        packet: dgram.slice_ref(packet),
                        offload: Some(meta),
                    };
                    if !enqueue_inbound_tun_write(&tun_write_tx, req).await {
                        log::trace!("TUN writer channel closed");
                        return None;
                    }
                }
            } else {
                let req = InboundTunWrite {
                    packet: dgram.slice_ref(packet),
                    offload: None,
                };
                if !enqueue_inbound_tun_write(&tun_write_tx, req).await {
                    log::trace!("TUN writer channel closed");
                    return None;
                }
            }
        }
    });

    // Spawn liveness task. The data path is unreliable datagrams with no
    // application heartbeat: QUIC keep-alive + idle timeout drive
    // `Connection::closed()`, which resolves when the peer goes away.
    let conn_close = connection.clone();
    let mut liveness_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let reason = conn_close.closed().await;
        log::info!("QUIC connection closed: {}", reason);
        Some(format!("connection closed: {}", reason))
    });

    // Wait for any task to complete (or error), then clean up all tasks
    let (first_task, first_result, remaining) = tokio::select! {
        result = &mut outbound_handle => {
            ("outbound", result, vec![("inbound", inbound_handle), ("liveness", liveness_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut inbound_handle => {
            ("inbound", result, vec![("outbound", outbound_handle), ("liveness", liveness_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut liveness_handle => {
            ("liveness", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut tun_writer_handle => {
            ("tun-writer", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("liveness", liveness_handle)])
        }
    };

    // Abort remaining tasks to ensure they stop
    for (_, handle) in &remaining {
        handle.abort();
    }

    // Abort the bypass route monitoring task if it exists
    if let Some(ref task) = bypass_route_task {
        task.abort();
    }

    // Await all remaining handles to ensure cleanup (aborted tasks return Cancelled)
    let mut all_results = vec![(first_task, first_result)];
    for (name, handle) in remaining {
        all_results.push((name, handle.await));
    }

    // Wait for bypass route task to clean up (guards will be dropped)
    if let Some(task) = bypass_route_task {
        let _ = task.await;
    }

    // Build comprehensive reason from all task results
    let mut reasons = Vec::new();
    for (name, result) in &all_results {
        match result {
            Ok(Some(error_reason)) => {
                // Task exited with an error reason
                reasons.push(error_reason.clone());
            }
            Ok(None) => {
                // Task completed normally (channel closed, etc.)
                reasons.push(format!("{} task ended", name));
            }
            Err(e) if e.is_cancelled() => {
                // Expected for aborted tasks, don't include in reason
            }
            Err(e) if e.is_panic() => {
                reasons.push(format!("{} task panicked: {}", name, e));
            }
            Err(e) => {
                reasons.push(format!("{} task failed: {}", name, e));
            }
        }
    }

    let reason = if reasons.is_empty() {
        "all tasks cancelled".to_string()
    } else {
        reasons.join("; ")
    };
    log::debug!("VPN loop ended: {}", reason);

    // Any task ending means connection is lost
    Err(VpnError::ConnectionLost(reason))
}

#[cfg(not(target_os = "ios"))]
impl VpnClient {
    /// Connect to the VPN server with automatic reconnection on failure.
    ///
    /// This method wraps `connect()` with a reconnection loop that handles
    /// transient failures using exponential backoff (1s → 2s → 4s → ... → 60s max).
    ///
    /// # Arguments
    /// * `endpoint` - The iroh endpoint to use for connections
    /// * `relay_urls` - Optional relay URLs to use as connection hints. When DNS
    ///   discovery is disabled, relay URLs are required for the connection to succeed.
    /// * `max_attempts` - Maximum total connection attempts (None = unlimited).
    ///   This counts all attempts including the initial one:
    ///   - `Some(1)` = try once, exit on any failure (no retries)
    ///   - `Some(3)` = try up to 3 times total (initial + 2 retries)
    ///   - `None` = retry indefinitely on recoverable errors
    ///
    /// # Error Handling
    /// Only recoverable errors (see [`VpnError::is_recoverable`]) trigger retries:
    /// - `ConnectionLost`, `Network`, `Signaling` → retry with backoff
    /// - `AuthenticationFailed`, `Config`, `TunDevice`, `ServerConfigChanged`,
    ///   etc. → exit immediately
    ///
    /// This prevents infinite retry loops on permanent failures like invalid tokens.
    pub async fn run_with_reconnect(
        &self,
        endpoint: &Endpoint,
        relay_urls: &[String],
        max_attempts: Option<NonZeroU32>,
    ) -> VpnResult<()> {
        let mut attempt = 0u32;

        loop {
            attempt = attempt.saturating_add(1);

            if attempt == 1 {
                log::info!("Connecting to VPN server...");
            } else {
                log::info!("VPN reconnection attempt #{}", attempt);
            }

            match self.connect(endpoint, relay_urls).await {
                Ok(()) => {
                    // Graceful exit (shouldn't normally happen)
                    log::info!("VPN connection ended gracefully");
                    return Ok(());
                }
                Err(e) if e.is_recoverable() => {
                    // Reset attempt counter if this was a ConnectionLost (tunnel ran successfully)
                    if matches!(e, VpnError::ConnectionLost(_)) {
                        attempt = 0;
                    }

                    // Check max attempts (None = unlimited)
                    if let Some(max) = max_attempts
                        && attempt >= max.get()
                    {
                        log::error!("Max reconnection attempts ({}) exceeded", max);
                        return Err(VpnError::MaxReconnectAttemptsExceeded(max));
                    }

                    // Calculate backoff delay
                    let delay = calculate_backoff(attempt);
                    log::warn!(
                        "Connection lost ({}), reconnecting in {:.1}s{}",
                        e,
                        delay.as_secs_f64(),
                        if let Some(max) = max_attempts {
                            format!(" (attempt {}/{})", attempt, max)
                        } else {
                            String::new()
                        }
                    );

                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    // Fatal error - don't retry
                    log::error!("Fatal VPN error (not retrying): {}", e);
                    return Err(e);
                }
            }
        }
    }
}

// ============================================================================
// Bypass Route Management
// ============================================================================

/// Manages bypass routes dynamically based on connection path changes.
///
/// Tracks active bypass routes in a HashMap keyed by IP address (not socket address).
/// This is because bypass routes are per-IP, not per-port - multiple socket addresses
/// on the same IP should share a single bypass route.
struct BypassRouteManager {
    /// Currently active bypass route guards, keyed by IP address.
    /// Dropping a guard removes the corresponding route.
    active_routes: HashMap<IpAddr, BypassRouteGuard>,
    /// Name of the VPN TUN interface; bypass routes must never resolve through it.
    vpn_tun_name: String,
    /// IPv4 VPN route prefixes about to be (or already) installed. A bypass route
    /// is only needed for an iroh peer IP that falls within one of these prefixes;
    /// any other IP is already routed correctly by the OS.
    vpn_routes4: Vec<Ipv4Net>,
    /// IPv6 VPN route prefixes (same role as `vpn_routes4`).
    vpn_routes6: Vec<Ipv6Net>,
    /// IPv4 underlay default gateway, captured before VPN routes were installed.
    /// Used to bypass a peer IP whose route resolves through the tunnel because
    /// it was discovered only after the VPN routes went up. `None` if there are
    /// no IPv4 VPN routes or the capture failed.
    underlay_gw4: Option<UnderlayGateway>,
    /// IPv6 underlay default gateway (same role as `underlay_gw4`).
    underlay_gw6: Option<UnderlayGateway>,
    /// All VPN-covered addresses this manager has been asked to bypass this
    /// session (intended bypasses), shared with the status handle for debugging.
    /// Add-only and superset of the applied `active_routes`: an entry here may
    /// have failed to install as an OS route, so it is *collected*, not *applied*.
    collected: Arc<Mutex<BTreeSet<IpAddr>>>,
}

impl BypassRouteManager {
    fn new(
        vpn_tun_name: String,
        active_routes: HashMap<IpAddr, BypassRouteGuard>,
        vpn_routes4: Vec<Ipv4Net>,
        vpn_routes6: Vec<Ipv6Net>,
        underlay_gw4: Option<UnderlayGateway>,
        underlay_gw6: Option<UnderlayGateway>,
        collected: Arc<Mutex<BTreeSet<IpAddr>>>,
    ) -> Self {
        Self {
            active_routes,
            vpn_tun_name,
            vpn_routes4,
            vpn_routes6,
            underlay_gw4,
            underlay_gw6,
            collected,
        }
    }

    /// Update bypass routes based on a new set of required IP addresses.
    ///
    /// Add-only: a bypass route, once installed, is kept until the manager is
    /// dropped on connection close (each guard's `Drop` removes its route). iroh
    /// flaps an underlay peer in and out of successive path snapshots, so
    /// removing a route the instant a peer drops from one snapshot caused
    /// add/remove churn — between cycles the peer was self-captured into the VPN
    /// tunnel (its address falls within a VPN route prefix), which broke the very
    /// direct path the bypass exists to protect. A bypass route only pins one
    /// iroh peer's underlay address (the server's transport address) off the
    /// tunnel, so keeping a no-longer-listed one for the rest of the session is
    /// harmless; never tearing it down mid-session is what keeps the path stable.
    ///
    /// Scope: `required_ips` only ever contains the addresses iroh uses for
    /// transport (the relays resolved at startup, plus the server's candidate
    /// underlay addresses it publishes over the data path), filtered to those
    /// covered by a VPN route. So a bypass pins *only that one transport
    /// endpoint*, never other hosts in the routed prefix; the rest still tunnels.
    ///
    /// User-visible caveat: the pinned address is reachable only over the
    /// underlay, not through the VPN, so a resource on that same host must be
    /// addressed by its VPN-internal IP. Documented in `docs/ARCHITECTURE.md`
    /// ("Underlay Bypass Routes") and the README "Routing" section.
    async fn update(&mut self, required_ips: HashSet<IpAddr>) {
        // Only bypass iroh peer IPs that a VPN route would otherwise capture.
        // An IP outside every VPN route prefix is already routed correctly by
        // the OS, so a bypass route is unnecessary; on some platforms (e.g. a
        // macOS `route get` with no usable gateway) it would even install a
        // link-scope host route that black-holes the IP for all future runs.
        let required_ips: HashSet<IpAddr> = required_ips
            .into_iter()
            .filter(|ip| {
                let needed = self.ip_covered_by_vpn_routes(*ip);
                if !needed {
                    log::debug!(
                        "Skipping bypass route for {} (not covered by any VPN route)",
                        ip
                    );
                }
                needed
            })
            .collect();

        // Record the intended (VPN-covered) bypasses for status/debugging, before
        // attempting to install them — so an address that fails to apply still
        // shows up as collected. Add-only, mirroring `active_routes`.
        if !required_ips.is_empty() {
            let mut collected = self.collected.lock().expect("collected lock poisoned");
            collected.extend(required_ips.iter().copied());
        }

        let to_add: Vec<IpAddr> = required_ips
            .iter()
            .filter(|ip| !self.active_routes.contains_key(ip))
            .copied()
            .collect();

        // Best-effort, per-IP: commit each success and log-and-skip each failure.
        // A single failure must NOT abort the rest — the eager set is the whole
        // resolved relay map (both families), so one relay whose route is briefly
        // a gateway-less cloned entry during startup churn would otherwise block
        // bypassing the relay iroh actually selected (and, in a full tunnel, let
        // that live relay be captured into the tunnel, killing connectivity).
        // Add-only: a committed route is kept until the manager drops (each
        // guard's `Drop` removes it), so skipping a failure never disturbs an
        // already-working route.
        for ip in to_add {
            let socket_addr = SocketAddr::new(ip, 443); // bypass routes are per-IP
            let underlay_fallback = match ip {
                IpAddr::V4(_) => self.underlay_gw4.as_ref(),
                IpAddr::V6(_) => self.underlay_gw6.as_ref(),
            };
            match add_bypass_route(socket_addr, Some(&self.vpn_tun_name), underlay_fallback).await {
                Ok(guard) => {
                    log::info!("Added bypass route for iroh address {}", ip);
                    self.active_routes.insert(ip, guard);
                }
                Err(err) => {
                    log::warn!(
                        "Failed to add bypass route for {} (skipping; other routes unaffected): {}",
                        ip,
                        err
                    );
                }
            }
        }
    }

    /// Whether `ip` falls within any VPN route prefix and therefore needs a
    /// bypass route to keep its underlay traffic off the VPN tunnel.
    fn ip_covered_by_vpn_routes(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.vpn_routes4.iter().any(|net| net.contains(&v4)),
            IpAddr::V6(v6) => self.vpn_routes6.iter().any(|net| net.contains(&v6)),
        }
    }
}

/// Query the underlay default gateway for one address family, logging the
/// outcome. Returns `None` if there is no default route or the platform is
/// unsupported, in which case a later in-tunnel bypass simply falls back to the
/// existing refuse behavior.
async fn capture_underlay_gateway(is_ipv6: bool) -> Option<UnderlayGateway> {
    let family = if is_ipv6 { "IPv6" } else { "IPv4" };
    match query_default_gateway(is_ipv6).await {
        Ok(gw) => {
            log::debug!("Captured {} underlay default gateway for bypass fallback", family);
            Some(gw)
        }
        Err(e) => {
            log::debug!(
                "No {} underlay default gateway captured ({}); in-tunnel bypasses will be refused",
                family,
                e
            );
            None
        }
    }
}

/// Handles produced by [`VpnClient::add_iroh_bypass_routes`]: the manager task
/// (aborted on shutdown; it owns all route guards and drops them when the data
/// path ends) and the sender the data path uses to feed the server's
/// periodically published candidate addresses into the manager.
struct BypassRouteHandles {
    task: JoinHandle<()>,
    server_addr_tx: mpsc::Sender<HashSet<IpAddr>>,
    /// Shared set of VPN-covered addresses the manager has collected (intended
    /// bypasses), surfaced in client status. See `BypassRouteManager::collected`.
    collected: Arc<Mutex<BTreeSet<IpAddr>>>,
}

/// Aborts the wrapped task on drop unless it is disarmed first.
///
/// The bypass-manager task is spawned during connection setup, but its lifetime
/// is owned by `run_tunnel` (which aborts and awaits it on exit). Between the
/// spawn and that hand-off, route installation can fail and early-return;
/// dropping a bare `JoinHandle` only *detaches* the task, leaking it — along with
/// its route guards — until the data path eventually ends. This guard aborts on
/// drop so a setup error tears the task down.
pub(crate) struct AbortOnDropTask(Option<JoinHandle<()>>);

impl AbortOnDropTask {
    fn new(handle: JoinHandle<()>) -> Self {
        Self(Some(handle))
    }

    /// Take the handle, disarming the guard, to hand ownership to `run_tunnel`.
    fn disarm(mut self) -> JoinHandle<()> {
        self.0.take().expect("handle taken exactly once")
    }
}

impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Run the bypass route manager task.
///
/// The caller (`add_iroh_bypass_routes`) has already captured the underlay
/// gateway and bootstrapped the relay bypasses into `manager`. From there the
/// only source of new bypass routes is the candidate-address set the server
/// publishes over the data path: those addresses are authoritative (no DNS, no
/// path-selection race), so the client no longer watches iroh path snapshots.
///
/// Add-only: routes are kept until this task ends. It runs until the sender is
/// dropped — i.e. the data path's inbound loop exits on connection close —
/// after which `manager` is dropped and all guards (routes) are removed.
async fn run_bypass_route_manager(
    mut manager: BypassRouteManager,
    mut server_addr_rx: mpsc::Receiver<HashSet<IpAddr>>,
) {
    // Server-published candidates are authoritative, so apply each set directly;
    // `update` filters to VPN-covered IPs and only ever adds.
    while let Some(ips) = server_addr_rx.recv().await {
        manager.update(ips).await;
    }

    log::debug!("Bypass route manager task ending (data path closed)");
    // When this function returns, manager is dropped, which drops all guards
    // and removes all bypass routes.
}

/// Resolve every relay the endpoint may use to its IP addresses, for the eager
/// startup bypass. The relay set is the configured relay URLs, or — when none
/// are configured — the default relay map, so the client can bootstrap its own
/// relay bypasses without waiting on path discovery. Both IPv4 and IPv6
/// addresses are returned; the caller's `update` keeps only those a VPN route
/// would capture. Unresolvable relays are skipped; the connection still rides
/// whichever relay it selects (its IP is covered when resolvable here, and the
/// server's published address set covers the direct underlay path).
pub(crate) async fn collect_relay_ips(endpoint: &Endpoint, relay_urls: &[String]) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    let relay_map = match parse_relay_mode(relay_urls) {
        Ok(mode) => mode.relay_map(),
        Err(e) => {
            log::warn!("Could not determine relay set for eager bypass: {}", e);
            return ips;
        }
    };
    // Resolve relays concurrently so startup isn't serialized across the whole
    // (default) relay map.
    let resolved = futures::future::join_all(relay_map.urls::<Vec<_>>().into_iter().map(|url| async move {
        let result = resolve_relay_url(endpoint, &url).await;
        (url, result)
    }))
    .await;
    for (url, result) in resolved {
        match result {
            Ok(addrs) => ips.extend(addrs.into_iter().map(|addr| addr.ip())),
            Err(()) => log::debug!("Eager relay bypass: could not resolve relay {}", url),
        }
    }
    ips
}

/// Resolve a relay URL to socket addresses using the endpoint's DNS resolver.
///
/// Handles both IP-literal URLs (e.g., `https://192.168.1.1:443`) and hostname URLs.
/// IP-literals are returned directly without DNS lookup.
///
/// Returns:
/// - `Ok(addresses)` on successful resolution (may be empty if host has no addresses)
/// - `Err(())` if DNS resolution failed; the caller simply skips this relay (the
///   other relays it resolves are unaffected). There is no retry — the connection
///   still rides whichever relay it selects, and the server's published address
///   set covers the direct underlay path.
async fn resolve_relay_url(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
) -> Result<Vec<SocketAddr>, ()> {
    // Extract host from relay URL
    let Some(host) = relay_url.host_str() else {
        log::warn!("Relay URL {} has no host", relay_url);
        return Ok(Vec::new()); // Not a DNS failure, just no host
    };
    let port = relay_url.port().unwrap_or(443);

    // Handle IP-literal URLs without DNS lookup
    if let Ok(ip) = host.parse::<IpAddr>() {
        let socket_addr = SocketAddr::new(ip, port);
        log::debug!("Relay URL {} is IP-literal: {}", relay_url, socket_addr);
        return Ok(vec![socket_addr]);
    }

    // Try to resolve the hostname with a reasonable timeout
    let resolver = match endpoint.dns_resolver() {
        Ok(resolver) => resolver,
        Err(e) => {
            log::warn!(
                "DNS resolver unavailable for relay URL {}: {}",
                relay_url,
                e
            );
            return Err(()); // Signal DNS failure
        }
    };
    match resolver.lookup_ipv4_ipv6(host, RESOLVE_RELAY_TIMEOUT).await {
        Ok(addrs) => {
            let socket_addrs: Vec<SocketAddr> = addrs.map(|ip| SocketAddr::new(ip, port)).collect();
            log::debug!(
                "Resolved relay {} to {} address(es)",
                relay_url,
                socket_addrs.len()
            );
            Ok(socket_addrs)
        }
        Err(e) => {
            log::warn!("Failed to resolve relay URL {}: {}", relay_url, e);
            Err(()) // Signal DNS failure
        }
    }
}

/// Backoff constants for reconnection delay calculation.
///
/// The cap is 30s (not the more common 60s): the primary use case is mobile,
/// where Wi-Fi↔cellular transitions produce bursts of early connect failures
/// and a minute-long dead window after ~7 attempts is a poor experience.
/// Jitter keeps the retry herd spread out.
const BACKOFF_BASE_MS: u64 = 1000; // 1 second
const BACKOFF_MAX_MS: u64 = 30000; // 30 seconds
const BACKOFF_JITTER_MS: u64 = 500;

/// Calculate exponential backoff delay with jitter.
///
/// Uses exponential backoff: `base * 2^(attempt-1)`, capped at max.
/// Adds random jitter (0-500ms) to prevent thundering herd.
/// The cap is applied after adding jitter to ensure the total never exceeds MAX_MS.
fn calculate_backoff(attempt: u32) -> Duration {
    calculate_backoff_with_rng(attempt, &mut rand::rng())
}

/// Calculate exponential backoff delay with a custom RNG.
///
/// This is the testable version that accepts an RNG parameter.
/// Production code should use `calculate_backoff()` which uses `rand::rng()`.
///
/// # Arguments
/// * `attempt` - Current attempt number (1-based)
/// * `rng` - Random number generator for jitter
fn calculate_backoff_with_rng(attempt: u32, rng: &mut impl Rng) -> Duration {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
    let multiplier = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let base_delay_ms = BACKOFF_BASE_MS.saturating_mul(multiplier);

    // Add jitter to prevent thundering herd (unbiased via random_range)
    let jitter_ms = rng.random_range(0..BACKOFF_JITTER_MS);

    // Cap total delay (base + jitter) to MAX_MS
    let total_ms = base_delay_ms.saturating_add(jitter_ms).min(BACKOFF_MAX_MS);

    Duration::from_millis(total_ms)
}

/// Collect local UDP ports bound by the iroh endpoint.
pub(crate) fn collect_local_iroh_udp_ports(endpoint: &Endpoint) -> HashSet<u16> {
    endpoint.addr().ip_addrs().map(|addr| addr.port()).collect()
}

/// Server underlay addresses in `server_addrs` that fall within a routed prefix,
/// as host CIDRs. In a split tunnel these would self-capture (the tunnel would
/// route iroh's own transport packets to the server back into itself); on iOS
/// they are applied as `excludedRoutes` so the OS keeps them on the underlay.
///
/// Returns `(IPv4 /32 strings, IPv6 /128 strings)`. Uses the same
/// `ipnet::contains` membership test as the desktop `BypassRouteManager`. The
/// relay set is deliberately ignored: full tunnel is out of scope on iOS, so a
/// public relay address never overlaps the private routed prefixes.
///
/// Only the iOS connect path consumes this (desktop uses `BypassRouteManager`),
/// so it is dead code on non-iOS builds outside the unit tests.
#[cfg_attr(not(any(target_os = "ios", test)), allow(dead_code))]
pub(crate) fn overlapping_underlay_excludes(
    server_addrs: &[IpAddr],
    routes4: &[Ipv4Net],
    routes6: &[Ipv6Net],
) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in server_addrs {
        match ip {
            IpAddr::V4(a) if routes4.iter().any(|n| n.contains(a)) => v4.push(format!("{a}/32")),
            IpAddr::V6(a) if routes6.iter().any(|n| n.contains(a)) => v6.push(format!("{a}/128")),
            _ => {}
        }
    }
    (v4, v6)
}

/// Return true if packet is UDP and either source/destination port matches a blocked port.
#[inline]
fn packet_has_local_iroh_udp_port(packet: &[u8], blocked_ports: &HashSet<u16>) -> bool {
    if blocked_ports.is_empty() {
        return false;
    }
    let Some((src_port, dst_port)) = extract_udp_ports(packet) else {
        return false;
    };
    blocked_ports.contains(&src_port) || blocked_ports.contains(&dst_port)
}

/// Extract UDP source/destination ports from an IPv4/IPv6 packet.
///
/// For IPv6, only packets with UDP as the first next-header are parsed.
#[inline]
fn extract_udp_ports(packet: &[u8]) -> Option<(u16, u16)> {
    const IPV4_MIN_HEADER_BYTES: usize = 20;
    const IPV6_MIN_HEADER_BYTES: usize = 40;

    if packet.len() < IPV4_MIN_HEADER_BYTES {
        return None;
    }

    match packet[0] >> 4 {
        4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER_BYTES || packet.len() < ihl + 8 {
                return None;
            }
            if packet[9] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            Some((src, dst))
        }
        6 => {
            if packet.len() < IPV6_MIN_HEADER_BYTES + 8 {
                return None;
            }
            if packet[6] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([packet[40], packet[41]]);
            let dst = u16::from_be_bytes([packet[42], packet[43]]);
            Some((src, dst))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn overlapping_excludes_keeps_only_routed_underlay_addresses() {
        let server_addrs: Vec<IpAddr> = [
            "192.168.1.5",        // private v4, inside routed prefix -> excluded
            "44.230.20.120",      // public v4, outside routes      -> dropped
            "fd12::5",            // ULA v6, inside routed prefix    -> excluded
            "2606:4700::1",       // public v6, outside routes       -> dropped
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let routes4: Vec<Ipv4Net> = vec!["192.168.0.0/16".parse().unwrap()];
        let routes6: Vec<Ipv6Net> = vec!["fd12::/16".parse().unwrap()];

        let (v4, v6) = overlapping_underlay_excludes(&server_addrs, &routes4, &routes6);
        assert_eq!(v4, vec!["192.168.1.5/32".to_string()]);
        assert_eq!(v6, vec!["fd12::5/128".to_string()]);
    }

    #[test]
    fn overlapping_excludes_empty_when_no_routes_or_no_overlap() {
        let server_addrs: Vec<IpAddr> =
            ["192.168.1.5", "fd12::5"].iter().map(|s| s.parse().unwrap()).collect();

        // No routes at all.
        assert_eq!(
            overlapping_underlay_excludes(&server_addrs, &[], &[]),
            (Vec::new(), Vec::new())
        );

        // Routes that don't contain the server addresses.
        let routes4: Vec<Ipv4Net> = vec!["10.0.0.0/8".parse().unwrap()];
        let routes6: Vec<Ipv6Net> = vec!["fd99::/16".parse().unwrap()];
        assert_eq!(
            overlapping_underlay_excludes(&server_addrs, &routes4, &routes6),
            (Vec::new(), Vec::new())
        );
    }

    fn bypass_manager(routes4: &[&str], routes6: &[&str]) -> BypassRouteManager {
        BypassRouteManager::new(
            "utun0".to_string(),
            HashMap::new(),
            routes4.iter().map(|s| s.parse().unwrap()).collect(),
            routes6.iter().map(|s| s.parse().unwrap()).collect(),
            None,
            None,
            Arc::new(Mutex::new(BTreeSet::new())),
        )
    }

    #[test]
    fn test_ip_covered_only_when_inside_vpn_route() {
        let mgr = bypass_manager(&["172.31.0.0/16"], &["2600:1f13:adc:a000::/56"]);

        // Inside a VPN route prefix -> needs a bypass.
        assert!(mgr.ip_covered_by_vpn_routes("172.31.5.6".parse().unwrap()));
        assert!(mgr.ip_covered_by_vpn_routes("2600:1f13:adc:a001::1".parse().unwrap()));

        // Public iroh underlay addresses outside every prefix -> no bypass
        // (these are the addresses that previously got a black-holing route).
        assert!(!mgr.ip_covered_by_vpn_routes("44.230.20.120".parse().unwrap()));
        assert!(!mgr.ip_covered_by_vpn_routes("2a01:4ff:1f0:e599::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_never_covered_with_no_vpn_routes() {
        let mgr = bypass_manager(&[], &[]);
        assert!(!mgr.ip_covered_by_vpn_routes("172.31.5.6".parse().unwrap()));
        assert!(!mgr.ip_covered_by_vpn_routes("2600:1f13:adc:a001::1".parse().unwrap()));
    }

    /// Regression: `update` is add-only. A route already in `active_routes` must
    /// survive successive snapshots that omit it (no churn / premature removal);
    /// it is only dropped when the manager itself is dropped. Locks in the fix
    /// for the bypass-route add/remove churn.
    ///
    /// Snapshots use addresses *not* covered by the manager's VPN routes so
    /// `update` performs no real OS route operations (covered IPs are filtered
    /// before `add_bypass_route`); the retained entry is pre-seeded with a
    /// non-owning guard so the manager can drop without touching the system.
    #[tokio::test]
    async fn test_update_is_add_only_keeps_routes_across_snapshots() {
        let mut mgr = bypass_manager(&["172.31.0.0/16"], &["2600:1f13:adc:a000::/56"]);

        // An already-installed bypass route (e.g. the server's underlay IPv6).
        let pinned: IpAddr = "2600:1f13:adc:a0b1::1".parse().unwrap();
        mgr.active_routes
            .insert(pinned, BypassRouteGuard::test_unowned(pinned));

        // A snapshot that no longer lists the pinned peer (only uncovered IPs,
        // which are filtered out -> no real route ops): it must stay.
        mgr.update(HashSet::from(["44.230.20.120".parse().unwrap()]))
            .await;
        assert!(
            mgr.active_routes.contains_key(&pinned),
            "pinned route removed when absent from snapshot (churn regression)"
        );

        // An empty snapshot must also not remove it.
        mgr.update(HashSet::new()).await;
        assert!(
            mgr.active_routes.contains_key(&pinned),
            "pinned route removed on empty snapshot"
        );

        // Re-listing it must not duplicate or churn it; still exactly one entry.
        mgr.update(HashSet::from([pinned])).await;
        assert_eq!(mgr.active_routes.len(), 1);
        assert!(mgr.active_routes.contains_key(&pinned));
    }

    #[test]
    fn test_backoff_exponential_growth() {
        // Use seeded RNG for deterministic tests
        let mut rng = ChaCha8Rng::seed_from_u64(12345);

        // Attempt 1: base = 1000ms
        let d1 = calculate_backoff_with_rng(1, &mut rng);
        assert!(d1.as_millis() >= 1000 && d1.as_millis() < 1500);

        // Attempt 2: base = 2000ms
        let d2 = calculate_backoff_with_rng(2, &mut rng);
        assert!(d2.as_millis() >= 2000 && d2.as_millis() < 2500);

        // Attempt 3: base = 4000ms
        let d3 = calculate_backoff_with_rng(3, &mut rng);
        assert!(d3.as_millis() >= 4000 && d3.as_millis() < 4500);

        // Attempt 5: base = 16000ms
        let d5 = calculate_backoff_with_rng(5, &mut rng);
        assert!(d5.as_millis() >= 16000 && d5.as_millis() < 16500);
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);

        // Attempt 6+: base = 32000ms exceeds the cap, so the result is exactly
        // the 30s cap regardless of jitter. Hardcoded so an upward drift of
        // BACKOFF_MAX_MS fails this test.
        let d6 = calculate_backoff_with_rng(6, &mut rng);
        assert_eq!(d6, Duration::from_millis(30_000));

        let d7 = calculate_backoff_with_rng(7, &mut rng);
        assert_eq!(d7, Duration::from_millis(30_000));

        // Very high attempt still capped
        let d100 = calculate_backoff_with_rng(100, &mut rng);
        assert_eq!(d100, Duration::from_millis(30_000));
    }

    #[test]
    fn test_backoff_jitter_within_range() {
        // Run multiple times with same seed to verify jitter is applied
        for seed in 0..10 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let d = calculate_backoff_with_rng(1, &mut rng);
            // Base is 1000ms, jitter is 0-499ms
            assert!(d.as_millis() >= 1000 && d.as_millis() < 1500);
        }
    }

    #[test]
    fn test_backoff_attempt_zero_treated_as_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        // Attempt 0 uses saturating_sub(1) = 0, so multiplier = 2^0 = 1
        let d0 = calculate_backoff_with_rng(0, &mut rng);
        assert!(d0.as_millis() >= 1000 && d0.as_millis() < 1500);
    }

    /// A dual-stack `ServerInfo` for config-change tests.
    fn sample_server_info() -> ServerInfo {
        ServerInfo {
            assigned_ip: Some("10.0.0.2".parse().unwrap()),
            network: Some("10.0.0.0/24".parse().unwrap()),
            server_ip: Some("10.0.0.1".parse().unwrap()),
            assigned_ip6: Some("fd00::2".parse().unwrap()),
            network6: Some("fd00::/64".parse().unwrap()),
            server_ip6: Some("fd00::1".parse().unwrap()),
            server_gso_enabled: true,
            server_addrs: Vec::new(),
        }
    }

    #[test]
    fn network_params_maps_server_info_fields() {
        let info = sample_server_info();
        let p = NetworkParams::from_server_info(&info);
        assert_eq!(p.assigned_ip, info.assigned_ip);
        assert_eq!(p.network, info.network);
        assert_eq!(p.server_ip, info.server_ip);
        assert_eq!(p.assigned_ip6, info.assigned_ip6);
        assert_eq!(p.network6, info.network6);
        assert_eq!(p.server_ip6, info.server_ip6);
    }

    #[test]
    fn network_params_eq_ignores_gso() {
        let a = sample_server_info();
        let mut b = sample_server_info();
        // Fields not part of the routing/TUN identity must not affect equality.
        b.server_gso_enabled = !a.server_gso_enabled;
        assert_eq!(
            NetworkParams::from_server_info(&a),
            NetworkParams::from_server_info(&b)
        );
    }

    #[test]
    fn network_params_detects_each_change() {
        let base = NetworkParams::from_server_info(&sample_server_info());

        let mut net = sample_server_info();
        net.network = Some("10.0.1.0/24".parse().unwrap());
        assert_ne!(base, NetworkParams::from_server_info(&net));

        let mut net6 = sample_server_info();
        net6.network6 = Some("fd00:1::/64".parse().unwrap());
        assert_ne!(base, NetworkParams::from_server_info(&net6));

        let mut ip = sample_server_info();
        ip.assigned_ip = Some("10.0.0.3".parse().unwrap());
        assert_ne!(base, NetworkParams::from_server_info(&ip));

        let mut gw = sample_server_info();
        gw.server_ip = Some("10.0.0.254".parse().unwrap());
        assert_ne!(base, NetworkParams::from_server_info(&gw));
    }

    #[test]
    fn network_params_display_is_readable() {
        let p = NetworkParams::from_server_info(&sample_server_info());
        let s = p.to_string();
        assert!(s.contains("ip=10.0.0.2"));
        assert!(s.contains("net=10.0.0.0/24"));
        assert!(s.contains("gw=10.0.0.1"));
    }

    #[test]
    fn check_params_first_call_records_baseline() {
        let established = std::sync::Mutex::new(None);
        assert!(check_params_against(&established, &sample_server_info()).is_ok());
        assert!(established.lock().unwrap().is_some());
    }

    #[test]
    fn check_params_identical_reconnect_is_ok() {
        let established = std::sync::Mutex::new(None);
        check_params_against(&established, &sample_server_info()).expect("baseline");
        // A second identical handshake must be accepted.
        assert!(check_params_against(&established, &sample_server_info()).is_ok());
    }

    #[test]
    fn check_params_changed_reconnect_quits() {
        let established = std::sync::Mutex::new(None);
        check_params_against(&established, &sample_server_info()).expect("baseline");

        let mut changed = sample_server_info();
        changed.network = Some("10.0.9.0/24".parse().unwrap());
        let err = check_params_against(&established, &changed).expect_err("must reject");
        assert!(matches!(err, VpnError::ServerConfigChanged(_)));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn check_params_ip_reassignment_rebuilds_and_adopts_baseline() {
        let established = std::sync::Mutex::new(None);
        check_params_against(&established, &sample_server_info()).expect("baseline");

        // Only the assigned IPs change (server restart re-handing addresses).
        let mut reassigned = sample_server_info();
        reassigned.assigned_ip = Some("10.0.0.42".parse().unwrap());
        reassigned.assigned_ip6 = Some("fd00::42".parse().unwrap());
        // Must NOT quit: this rebuilds for the new address.
        check_params_against(&established, &reassigned).expect("IP reassignment is allowed");

        // The new address becomes the baseline, so reconnecting with the same
        // reassigned address is a no-op...
        check_params_against(&established, &reassigned).expect("new baseline accepted");
        // ...while reverting to the original IP is itself just another allowed
        // reassignment (not a fatal change).
        check_params_against(&established, &sample_server_info())
            .expect("reverting the IP is also a reassignment");
    }

    #[test]
    fn check_params_non_ip_change_still_quits_even_with_ip_change() {
        let established = std::sync::Mutex::new(None);
        check_params_against(&established, &sample_server_info()).expect("baseline");

        // IP changed AND gateway changed: the non-IP change makes it fatal.
        let mut changed = sample_server_info();
        changed.assigned_ip = Some("10.0.0.42".parse().unwrap());
        changed.server_ip = Some("10.0.0.254".parse().unwrap());
        let err = check_params_against(&established, &changed).expect_err("must reject");
        assert!(matches!(err, VpnError::ServerConfigChanged(_)));
    }
}
