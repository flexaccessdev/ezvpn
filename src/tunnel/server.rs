//! VPN server implementation.
//!
//! The VPN server listens for incoming client connections via iroh,
//! assigns IP addresses from a pool, and manages direct IP-over-QUIC
//! tunnels for each connected client. IP packets are framed and sent
//! directly over the encrypted iroh QUIC connection.

use crate::net::buffer::uninitialized_vec;
use crate::config::{Ip6Strategy, VpnServerConfig, validate_ip6_strategy};
use crate::tunnel::datagram::{
    Datagram, FRAME_ARENA_CHUNK, build_datagrams, build_gro_datagrams, classify,
    encode_server_addrs_datagram,
};
use crate::net::device::{TunConfig, TunDevice, TunOffloadStatus};
use crate::control::{ClientEntry, ServerStatsView, ServerStatus, StatusSnapshot};
use crate::error::{VpnError, VpnResult};
use crate::runtime::{LockRole, VpnLock};
use crate::config::file_config::TransportTuning;
use crate::tunnel::offload::{
    CoalescedOutput, TcpGroTable, VirtioNetHdr, materialize_offload_into,
};
use crate::transport::paths::{format_connection_paths, watch_connection_paths};
use crate::transport::SERVER_ADDR_PUBLISH_INTERVAL;
use crate::tunnel::signaling::{
    MAX_HANDSHAKE_SIZE, ServerAddrsMsg, VpnHandshake, VpnHandshakeResponse, WireTransport,
    parse_ip_packet_v2, read_message, write_message,
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::StreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::{Connection, SendDatagramError};
use iroh::{Endpoint, EndpointId, Watcher};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::io::ReadBuf;
use tokio::sync::{RwLock, mpsc, oneshot};

/// Maximum number of datagrams drained from a channel per batch.
const WRITE_BATCH_SIZE: usize = 256;

/// Largest TUN MTU the server advertises (and uses for its shared TUN), chosen
/// for reliability on mobile / high-latency paths.
///
/// 1280 is the IPv6 minimum link MTU (inner IPv6 forbids going lower) and the
/// same default Tailscale uses. A framed 1280-byte packet (1282 bytes) fits the
/// live QUIC datagram cap once DPLPMTUD has discovered a wire MTU of ~1318+,
/// which holds on virtually every real path. Below that — the first RTTs after
/// connect (discovery starts from the 1200 protocol minimum), a black-hole
/// cooldown, or a true ≤1200-wire path — oversized plain TCP packets are
/// software-resegmented to the live cap and only oversized non-TCP packets are
/// dropped. The advertised MTU is deliberately *not* derived from the
/// handshake-time `max_datagram_size` snapshot: that value tracks the live path
/// MTU, and pinning the TUN MTU to an optimistic snapshot black-holes full-size
/// packets when the path later shrinks.
const DATAGRAM_SAFE_MTU: u16 = 1280;

/// The MTU the server dictates to a client: the configured MTU clamped to the
/// mobile-safe [`DATAGRAM_SAFE_MTU`]. Deterministic across reconnects (never
/// derived from a live path measurement, which would make an MTU change look
/// like a fatal server-config change to the client).
fn advertised_client_mtu(config_mtu: u16) -> u16 {
    config_mtu.min(DATAGRAM_SAFE_MTU)
}

/// Performance statistics for the VPN server.
///
/// These atomic counters replace per-packet trace logging to eliminate
/// logging overhead in hot paths.
#[derive(Debug, Default)]
pub struct VpnServerStats {
    /// Total packets read from TUN device.
    pub tun_packets_read: AtomicU64,
    /// Packets successfully sent to clients.
    pub packets_to_clients: AtomicU64,
    /// Packets dropped due to unknown destination IP.
    pub packets_no_route: AtomicU64,
    /// Packets dropped due to unknown IP version.
    pub packets_unknown_version: AtomicU64,
    /// Packets dropped due to client channel full (drop_on_full=true).
    pub packets_dropped_full: AtomicU64,
    /// Packets sent via backpressure (slow path, drop_on_full=false).
    pub packets_backpressure: AtomicU64,
    /// Packets received from clients and written to TUN.
    pub packets_from_clients: AtomicU64,
    /// Packets dropped due to TUN write channel full/closed.
    pub packets_tun_write_failed: AtomicU64,
    /// Packets dropped due to invalid source IP (anti-spoofing).
    pub packets_spoofed: AtomicU64,
    /// Packets dropped because the destination was another VPN client
    /// (mandatory client isolation).
    pub packets_inter_client_blocked: AtomicU64,
}

impl VpnServerStats {
    /// Create a new stats instance with all counters zeroed.
    pub fn new() -> Self {
        Self::default()
    }
}

// Channel buffer sizes are now configurable via VpnServerConfig:
// - client_channel_size: per-client outbound buffer (default 1024)
// - tun_writer_channel_size: aggregate TUN writer buffer (default 512)
// See config.rs for detailed documentation on tradeoffs.

/// State for a connected VPN client.
struct ClientState {
    /// Unique session ID for this connection.
    /// Used to detect stale cleanup operations when a client reconnects quickly.
    session_id: u64,
    /// Client's assigned VPN IP (IPv4). None for IPv6-only mode.
    assigned_ip: Option<Ipv4Addr>,
    /// Client's assigned IPv6 VPN address (optional, for dual-stack or IPv6-only).
    assigned_ip6: Option<Ipv6Addr>,
    /// Channel to send framed datagrams to the client's dedicated writer task.
    /// The writer task owns the `Connection` and sends datagrams.
    /// Uses Bytes for zero-copy sends (freeze BytesMut instead of cloning Vec).
    packet_tx: mpsc::Sender<Bytes>,
    /// Reported client GSO capability (from the handshake).
    client_gso_enabled: bool,
    /// Effective per-connection GSO mode (server local && client reported).
    connection_gso_active: bool,
    /// The iroh connection, kept for live `max_datagram_size()` reads when
    /// framing outbound datagrams and for reporting live path info in status.
    connection: Connection,
}

/// Per-client context used by the data handler.
struct ClientContext {
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
    /// Current client's key for identifying self in spoofing checks.
    client_key: (EndpointId, u64),
    /// Reverse lookup: IPv4 address -> client key (for inter-client spoofing detection).
    ip_to_endpoint: Arc<DashMap<Ipv4Addr, (EndpointId, u64)>>,
    /// Reverse lookup: IPv6 address -> client key (for inter-client spoofing detection).
    ip6_to_endpoint: Arc<DashMap<Ipv6Addr, (EndpointId, u64)>>,
    /// Whether to disable all source IP spoofing checks.
    disable_spoofing_check: bool,
    /// Whether this client/server connection negotiated GSO metadata transport.
    connection_gso_active: bool,
    /// Whether local server TUN offload is enabled.
    local_tun_gso_enabled: bool,
}

/// Request to write an IP packet (with optional offload metadata) to the TUN writer task.
struct TunWriteRequest {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

/// IP address pool for assigning addresses to clients.
struct IpPool {
    /// Network CIDR.
    network: Ipv4Net,
    /// Server's IP (first usable address).
    server_ip: Ipv4Addr,
    /// Next IP to assign.
    next_ip: u32,
    /// Maximum IP in the range.
    max_ip: u32,
    /// IPs currently in use (mapped from (client endpoint ID, device ID)).
    in_use: HashMap<(EndpointId, u64), Ipv4Addr>,
    /// Released IPs available for reuse.
    released: Vec<Ipv4Addr>,
    /// Reserved IPs that should never be assigned to clients.
    reserved: HashSet<Ipv4Addr>,
}

impl IpPool {
    /// Create a new IP pool from a network with optional custom server IP.
    ///
    /// If `server_ip` is None, defaults to first host in network (e.g., .1).
    /// Client IPs start from the address after the server IP.
    fn new(network: Ipv4Net, server_ip: Option<Ipv4Addr>) -> Self {
        let net_addr: u32 = network.network().into();
        let broadcast: u32 = network.broadcast().into();

        // Server gets specified IP or defaults to .1
        let server_ip = server_ip.unwrap_or_else(|| Ipv4Addr::from(net_addr + 1));
        let server_ip_u32: u32 = server_ip.into();

        // Clients start from the address after server IP
        let next_ip = server_ip_u32 + 1;
        let max_ip = broadcast - 1; // Exclude broadcast address

        Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            in_use: HashMap::new(),
            released: Vec::new(),
            reserved: HashSet::new(),
        }
    }

    /// Get the server's IP address.
    fn server_ip(&self) -> Ipv4Addr {
        self.server_ip
    }

    /// Get the network CIDR.
    fn network(&self) -> Ipv4Net {
        self.network
    }

    /// Reserve a specific IP address so it will not be assigned to clients.
    #[cfg(test)]
    fn reserve_ip(&mut self, ip: Ipv4Addr, label: &str) -> Result<(), String> {
        if !self.network.contains(&ip) {
            return Err(format!(
                "{} {} is not within VPN network {}",
                label, ip, self.network
            ));
        }
        if ip == self.server_ip {
            return Err(format!(
                "{} {} must not equal server_ip {}",
                label, ip, self.server_ip
            ));
        }
        let network_addr = self.network.network();
        let broadcast = self.network.broadcast();
        if ip == network_addr || ip == broadcast {
            return Err(format!(
                "{} {} is not a usable host address in {}",
                label, ip, self.network
            ));
        }
        if self.reserved.contains(&ip) {
            return Ok(());
        }
        // O(n) scan of in_use: small in practice, avoids extra lookup map.
        if self.in_use.values().any(|assigned| *assigned == ip) {
            return Err(format!("{} {} is already assigned to a client", label, ip));
        }
        self.released.retain(|released_ip| *released_ip != ip);
        self.reserved.insert(ip);
        Ok(())
    }

    /// Reserve the next available IP address for internal use.
    #[cfg(test)]
    fn reserve_next_available(&mut self) -> Option<Ipv4Addr> {
        let ip = self.next_unreserved_ip()?;
        self.reserved.insert(ip);
        Some(ip)
    }

    /// Reserve the highest available IP address for internal use.
    #[cfg(test)]
    fn reserve_last_available(&mut self) -> Option<Ipv4Addr> {
        if self.next_ip > self.max_ip {
            return None;
        }

        let mut candidate = None;
        for ip_u32 in (self.next_ip..=self.max_ip).rev() {
            let ip = Ipv4Addr::from(ip_u32);
            if ip == self.server_ip {
                continue;
            }
            if self.reserved.contains(&ip) {
                continue;
            }
            // O(n) scan of in_use: small in practice, avoids extra lookup map.
            if self.in_use.values().any(|assigned| *assigned == ip) {
                continue;
            }
            candidate = Some(ip);
            break;
        }

        let ip = candidate?;
        self.released.retain(|released_ip| *released_ip != ip);
        self.reserved.insert(ip);
        Some(ip)
    }

    fn next_unreserved_ip(&mut self) -> Option<Ipv4Addr> {
        while self.next_ip <= self.max_ip {
            let ip = Ipv4Addr::from(self.next_ip);
            self.next_ip += 1;
            if self.reserved.contains(&ip) {
                continue;
            }
            return Some(ip);
        }
        None
    }

    /// Allocate an IP address for a client.
    fn allocate(&mut self, endpoint_id: EndpointId, device_id: u64) -> Option<Ipv4Addr> {
        let key = (endpoint_id, device_id);
        // Check if client already has an IP
        if let Some(&ip) = self.in_use.get(&key) {
            return Some(ip);
        }

        // Try to reuse a released IP first
        while let Some(ip) = self.released.pop() {
            if self.reserved.contains(&ip) {
                continue;
            }
            self.in_use.insert(key, ip);
            return Some(ip);
        }

        // Allocate new IP if available
        if let Some(ip) = self.next_unreserved_ip() {
            self.in_use.insert(key, ip);
            Some(ip)
        } else {
            None // Pool exhausted
        }
    }

    /// Release an IP address when a client disconnects.
    fn release(&mut self, endpoint_id: &EndpointId, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&(*endpoint_id, device_id)) {
            self.released.push(ip);
        }
    }
}

/// Derive a deterministic 64-bit host suffix from an iroh node id.
///
/// Stateless: first 8 bytes (big-endian) of a domain-separated SHA-256 over
/// the node id, so the same node id always maps to the same suffix.
fn derive_ip6_suffix(node_id: &EndpointId) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ezvpn ipv6 addr v1");
    hasher.update(node_id.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("sha256 digest >= 8 bytes"))
}

/// Derive a deterministic IPv6 address within `network` from an iroh node id.
///
/// The derived suffix is masked to the host bits, so the address always lands
/// in the subnet (a no-op for /64; defensive for wider prefixes).
fn derived_ip6(network: Ipv6Net, node_id: &EndpointId) -> Ipv6Addr {
    let host_bits: u32 = 128 - u32::from(network.prefix_len());
    let mask = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let net_addr: u128 = network.network().into();
    Ipv6Addr::from(net_addr | (u128::from(derive_ip6_suffix(node_id)) & mask))
}

/// The server's IPv4 host prefix (`ip/32`), as advertised to clients.
fn host_net4(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 32).expect("/32 is a valid IPv4 prefix")
}

/// The server's IPv6 host prefix (`ip/128`), as advertised to clients.
fn host_net6(ip: Ipv6Addr) -> Ipv6Net {
    Ipv6Net::new(ip, 128).expect("/128 is a valid IPv6 prefix")
}

/// Allocation strategy state for the IPv6 pool.
#[derive(Debug)]
enum Ip6Alloc {
    /// Sequential allocation: server ::1, clients ::2, ::3, ... with reuse.
    Sequential {
        /// Next IP to assign (as u128 for arithmetic).
        next_ip: u128,
        /// Maximum IP in the range.
        max_ip: u128,
        /// Released IPs available for reuse.
        released: Vec<Ipv6Addr>,
    },
    /// Stateless: addresses are derived on demand from the client node id.
    NodeId,
}

/// IPv6 address pool for assigning /128 addresses to clients.
#[derive(Debug)]
struct Ip6Pool {
    /// Network CIDR (e.g., fd00::/64).
    network: Ipv6Net,
    /// Server's IPv6 (first usable address, or node-id derived).
    server_ip: Ipv6Addr,
    /// Allocation strategy (sequential bookkeeping or stateless node-id).
    alloc: Ip6Alloc,
    /// IPs currently in use (mapped from (client endpoint ID, device ID)).
    /// In node-id mode this exists only for duplicate detection/rejection
    /// (plus idempotent re-allocate and release).
    in_use: HashMap<(EndpointId, u64), Ipv6Addr>,
}

impl Ip6Pool {
    /// Create a new IPv6 pool from a network with optional custom server IP.
    ///
    /// Sequential strategy: if `server_ip` is None, defaults to ::1 within the
    /// network; client IPs start from the address after the server IP.
    ///
    /// Node-id strategy: stateless — the server IP is derived from `server_id`
    /// and client IPs are derived from their node ids at allocation time.
    /// Requires a /64 or wider network; `server_ip` must be None.
    ///
    /// Returns an error if the prefix length is >= 127 (/127 or /128), as these
    /// networks have no usable addresses for client allocation.
    fn new(
        network: Ipv6Net,
        server_ip: Option<Ipv6Addr>,
        strategy: Ip6Strategy,
        server_id: EndpointId,
    ) -> VpnResult<Self> {
        let prefix_len = network.prefix_len();

        // /127 has only 2 addresses (server takes ::1, no room for clients)
        // /128 is a single address (unusable for server + clients)
        if prefix_len >= 127 {
            return Err(VpnError::config(format!(
                "IPv6 prefix /{} is too small for VPN pool (need at least /126 for 1 client)",
                prefix_len
            )));
        }

        // Strategy constraints (also enforced at config validation; kept here
        // for direct constructors/tests). No-op for sequential.
        validate_ip6_strategy(strategy, Some(network), server_ip).map_err(VpnError::config)?;

        let net_addr: u128 = network.network().into();

        match strategy {
            Ip6Strategy::Sequential => {
                // Server gets specified IP or defaults to ::1 within network
                let server_ip = server_ip.unwrap_or_else(|| Ipv6Addr::from(net_addr + 1));
                let server_ip_u128: u128 = server_ip.into();

                // Clients start from address after server IP
                let next_ip = server_ip_u128 + 1;

                // Calculate max_ip based on prefix length
                let host_bits: u32 = 128 - u32::from(prefix_len);
                // host_bits is guaranteed >= 2 here because prefix_len < 127, so the shift is safe
                let max_ip = net_addr + ((1u128 << host_bits) - 1) - 1; // Exclude last address

                Ok(Self {
                    network,
                    server_ip,
                    alloc: Ip6Alloc::Sequential {
                        next_ip,
                        max_ip,
                        released: Vec::new(),
                    },
                    in_use: HashMap::new(),
                })
            }
            Ip6Strategy::NodeId => {
                let server_ip = derived_ip6(network, &server_id);
                // The all-zero suffix is the subnet-router anycast address (~2^-64 chance)
                if server_ip == network.network() {
                    return Err(VpnError::config(
                        "derived server IPv6 collides with the network address; use a different server key or network6".to_string(),
                    ));
                }

                Ok(Self {
                    network,
                    server_ip,
                    alloc: Ip6Alloc::NodeId,
                    in_use: HashMap::new(),
                })
            }
        }
    }

    /// Get the server's IPv6 address.
    fn server_ip(&self) -> Ipv6Addr {
        self.server_ip
    }

    /// Get the network CIDR.
    fn network(&self) -> Ipv6Net {
        self.network
    }

    /// Allocate an IPv6 address for a client.
    fn allocate(&mut self, endpoint_id: EndpointId, device_id: u64) -> Option<Ipv6Addr> {
        let key = (endpoint_id, device_id);
        // Check if client already has an IP
        if let Some(&ip) = self.in_use.get(&key) {
            return Some(ip);
        }

        match self.alloc {
            Ip6Alloc::Sequential {
                ref mut next_ip,
                max_ip,
                ref mut released,
            } => {
                // Try to reuse a released IP first
                if let Some(ip) = released.pop() {
                    self.in_use.insert(key, ip);
                    return Some(ip);
                }

                // Allocate new IP if available
                if *next_ip <= max_ip {
                    let ip = Ipv6Addr::from(*next_ip);
                    *next_ip += 1;
                    self.in_use.insert(key, ip);
                    Some(ip)
                } else {
                    None // Pool exhausted
                }
            }
            Ip6Alloc::NodeId => {
                let ip = derived_ip6(self.network, &endpoint_id);
                // Reject the subnet-router anycast address, the server's own
                // address (incl. a client presenting the server's node id), and
                // duplicates (a second device of the same node id derives the
                // same address; hash collisions are ~2^-64).
                if ip == self.network.network()
                    || ip == self.server_ip
                    || self.in_use.values().any(|&used| used == ip)
                {
                    return None;
                }
                self.in_use.insert(key, ip);
                Some(ip)
            }
        }
    }

    /// Release an IPv6 address when a client disconnects.
    fn release(&mut self, endpoint_id: &EndpointId, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&(*endpoint_id, device_id)) {
            // Only sequential mode tracks released IPs for reuse; node-id mode
            // re-derives the same address on reconnect.
            if let Ip6Alloc::Sequential {
                ref mut released, ..
            } = self.alloc
            {
                released.push(ip);
            }
        }
    }
}

/// VPN server instance.
pub struct VpnServer {
    /// Server configuration.
    config: VpnServerConfig,
    /// IPv4 address pool (None if IPv6-only mode).
    ip_pool: Option<Arc<RwLock<IpPool>>>,
    /// IPv6 address pool (None if IPv4-only mode).
    ip6_pool: Option<Arc<RwLock<Ip6Pool>>>,
    /// Connected clients (by (endpoint ID, device ID)).
    /// Lock-free map for hot-path packet routing.
    clients: Arc<DashMap<(EndpointId, u64), ClientState>>,
    /// Reverse lookup: IPv4 address -> (endpoint ID, device ID).
    /// Lock-free map for hot-path routing lookups.
    ip_to_endpoint: Arc<DashMap<Ipv4Addr, (EndpointId, u64)>>,
    /// Reverse lookup: IPv6 address -> (endpoint ID, device ID).
    /// Lock-free map for hot-path routing lookups.
    ip6_to_endpoint: Arc<DashMap<Ipv6Addr, (EndpointId, u64)>>,
    /// TUN device for VPN traffic.
    tun_device: Option<TunDevice>,
    /// Server-local TUN offload/GSO status.
    tun_offload_status: TunOffloadStatus,
    /// Atomic counter for active connections (prevents race in max_clients check).
    active_connections: AtomicUsize,
    /// Session ID counter for unique connection identification.
    next_session_id: AtomicU64,
    /// Performance statistics (atomic counters, no locking overhead).
    stats: Arc<VpnServerStats>,
    /// Resolved transport settings dictated to clients in the handshake.
    wire_transport: WireTransport,
    /// Single-instance lock (only one VPN server per host).
    _lock: VpnLock,
}

impl VpnServer {
    /// Create a new VPN server.
    ///
    /// `server_endpoint_id` is the server's own iroh node id, used to derive
    /// the server's IPv6 address in node-id strategy mode.
    ///
    /// `transport` is the server's transport tuning, resolved and dictated to
    /// clients during the handshake.
    ///
    /// Acquires a single-instance lock so only one VPN server runs per host.
    pub async fn new(
        config: VpnServerConfig,
        server_endpoint_id: EndpointId,
        transport: &TransportTuning,
    ) -> VpnResult<Self> {
        // Validate configuration
        config.validate().map_err(VpnError::config)?;

        // Acquire single-instance lock (only one VPN server per host). The
        // server has no instance concept yet, so it always uses "default".
        let lock = VpnLock::acquire(LockRole::Server, "default")?;

        // Create IPv4 pool if configured
        let ip_pool = match config.network {
            Some(network) => Some(Arc::new(RwLock::new(IpPool::new(
                network,
                config.server_ip,
            )))),
            None => None,
        };

        // Create IPv6 pool if configured (dual-stack or IPv6-only)
        let ip6_pool = match config.network6 {
            Some(network6) => Some(Arc::new(RwLock::new(Ip6Pool::new(
                network6,
                config.server_ip6,
                config.ip6_strategy,
                server_endpoint_id,
            )?))),
            None => None,
        };

        if let Some(ref pool) = ip6_pool {
            let pool_guard = pool.read().await;
            if ip_pool.is_some() {
                log::info!("IPv6 dual-stack enabled: {}", pool_guard.network());
            } else {
                log::info!("IPv6-only mode enabled: {}", pool_guard.network());
            }
        }

        Ok(Self {
            config,
            ip_pool,
            ip6_pool,
            clients: Arc::new(DashMap::new()),
            ip_to_endpoint: Arc::new(DashMap::new()),
            ip6_to_endpoint: Arc::new(DashMap::new()),
            tun_device: None,
            tun_offload_status: TunOffloadStatus::disabled("TUN not initialized"),
            active_connections: AtomicUsize::new(0),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(VpnServerStats::new()),
            wire_transport: WireTransport::from_tuning(transport),
            _lock: lock,
        })
    }

    /// Create and configure the TUN device.
    pub async fn setup_tun(&mut self) -> VpnResult<()> {
        // Get IPv4 configuration if available
        let (server_ip, netmask) = if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            (Some(pool.server_ip()), Some(pool.network().netmask()))
        } else {
            (None, None)
        };

        // Get IPv6 configuration if available
        let (server_ip6, prefix_len6) = if let Some(ref ip6_pool) = self.ip6_pool {
            let pool6 = ip6_pool.read().await;
            (Some(pool6.server_ip()), Some(pool6.network().prefix_len()))
        } else {
            (None, None)
        };

        // The data path is QUIC datagrams: clamp the shared server TUN MTU to a
        // datagram-safe ceiling so every packet it reads fits in one datagram to
        // any client (see DATAGRAM_SAFE_MTU).
        let tun_mtu = self.config.mtu.min(DATAGRAM_SAFE_MTU);
        if tun_mtu != self.config.mtu {
            log::info!(
                "Clamping server TUN MTU from {} to {} for QUIC datagram transport",
                self.config.mtu,
                tun_mtu
            );
        }

        // Create TUN config based on available protocols
        let tun_config = match (server_ip, netmask, server_ip6, prefix_len6) {
            // Dual-stack: both IPv4 and IPv6
            (Some(ip4), Some(mask), Some(ip6), Some(pl6)) => TunConfig::new(ip4, mask, ip4)
                .with_mtu(tun_mtu)
                .with_ipv6(ip6, pl6)?,
            // IPv4-only
            (Some(ip4), Some(mask), None, None) => TunConfig::new(ip4, mask, ip4).with_mtu(tun_mtu),
            // IPv6-only
            (None, None, Some(ip6), Some(pl6)) => TunConfig::ipv6_only(ip6, pl6, tun_mtu)?,
            // Invalid: no networks configured (should be caught by validate())
            _ => {
                return Err(VpnError::config(
                    "No network configured (need at least IPv4 or IPv6)".to_string(),
                ));
            }
        };

        let device = TunDevice::create(tun_config)?;
        self.tun_offload_status = device.offload_status().clone();

        // Log what was created
        match (server_ip, server_ip6) {
            (Some(ip4), Some(ip6)) => {
                log::info!(
                    "Created TUN device: {} with IP {} and IPv6 {}",
                    device.name(),
                    ip4,
                    ip6
                );
            }
            (Some(ip4), None) => {
                log::info!("Created TUN device: {} with IP {}", device.name(), ip4);
            }
            (None, Some(ip6)) => {
                log::info!(
                    "Created TUN device: {} with IPv6 {} (IPv6-only mode)",
                    device.name(),
                    ip6
                );
            }
            (None, None) => unreachable!(), // Caught above
        }

        log::info!(
            "Server local TUN GSO status: enabled={}{}",
            self.tun_offload_status.enabled,
            self.tun_offload_status
                .reason
                .as_deref()
                .map(|r| format!(", reason={}", r))
                .unwrap_or_default()
        );

        self.tun_device = Some(device);
        Ok(())
    }

    /// Build a status snapshot from the server's live runtime state.
    ///
    /// Reads only lock-free shared state (the clients map, atomic counters, and
    /// stats), so it is cheap to call from the control-socket listener.
    fn status_snapshot(
        &self,
        node_id: String,
        uptime_secs: u64,
        bypass_addrs: Vec<String>,
    ) -> StatusSnapshot {
        let mode = if self.config.network.is_none() {
            "ipv6"
        } else if self.config.network6.is_some() {
            "dual-stack"
        } else {
            "ipv4"
        };

        let clients: Vec<ClientEntry> = self
            .clients
            .iter()
            .map(|entry| {
                let ((endpoint_id, device_id), state) = (entry.key(), entry.value());
                ClientEntry {
                    endpoint_id: endpoint_id.to_string(),
                    device_id: format!("{device_id:016x}"),
                    session_id: state.session_id,
                    assigned_ip: state.assigned_ip.map(|ip| ip.to_string()),
                    assigned_ip6: state.assigned_ip6.map(|ip| ip.to_string()),
                    connection: Some(format_connection_paths(&state.connection.paths())),
                }
            })
            .collect();
        // Derive the count from the collected entries so the reported number
        // always matches the emitted client list (a fresh map read could differ).
        let connected_clients = clients.len();

        let stats = ServerStatsView {
            tun_packets_read: self.stats.tun_packets_read.load(Ordering::Relaxed),
            packets_to_clients: self.stats.packets_to_clients.load(Ordering::Relaxed),
            packets_no_route: self.stats.packets_no_route.load(Ordering::Relaxed),
            packets_unknown_version: self.stats.packets_unknown_version.load(Ordering::Relaxed),
            packets_dropped_full: self.stats.packets_dropped_full.load(Ordering::Relaxed),
            packets_backpressure: self.stats.packets_backpressure.load(Ordering::Relaxed),
            packets_from_clients: self.stats.packets_from_clients.load(Ordering::Relaxed),
            packets_tun_write_failed: self.stats.packets_tun_write_failed.load(Ordering::Relaxed),
            packets_spoofed: self.stats.packets_spoofed.load(Ordering::Relaxed),
            packets_inter_client_blocked: self
                .stats
                .packets_inter_client_blocked
                .load(Ordering::Relaxed),
        };

        StatusSnapshot::Server(ServerStatus {
            node_id,
            uptime_secs,
            mode: mode.to_string(),
            network: self.config.network.map(|n| n.to_string()),
            network6: self.config.network6.map(|n| n.to_string()),
            connected_clients,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            clients,
            stats,
            bypass_addrs,
        })
    }

    /// Run the VPN server, accepting connections via iroh.
    pub async fn run(mut self, endpoint: Endpoint) -> VpnResult<()> {
        // Setup TUN device
        self.setup_tun().await?;

        // Drop self-encapsulated iroh UDP packets from the VPN tunnel path.
        let local_iroh_udp_ports = Arc::new(collect_local_iroh_udp_ports(&endpoint));
        if !local_iroh_udp_ports.is_empty() {
            log::info!(
                "Filtering tunneled traffic for {} local iroh UDP port(s)",
                local_iroh_udp_ports.len()
            );
        }

        log::info!("VPN Server started:");
        // Log IPv4 info if configured
        if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            log::info!("  Network: {}", pool.network());
            log::info!("  Server IP: {}", pool.server_ip());
        }
        // Log IPv6 info if configured
        if let Some(ref ip6_pool) = self.ip6_pool {
            let pool = ip6_pool.read().await;
            log::info!("  Network6: {}", pool.network());
            log::info!("  Server IP6: {}", pool.server_ip());
        }
        // Log mode
        if self.ip_pool.is_none() {
            log::info!("  Mode: IPv6-only");
        } else if self.ip6_pool.is_some() {
            log::info!("  Mode: dual-stack (IPv4 + IPv6)");
        } else {
            log::info!("  Mode: IPv4-only");
        }
        log::info!(
            "  Local TUN GSO: {}",
            if self.tun_offload_status.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        log::info!("  Node ID: {}", endpoint.id());

        // Take TUN device and split it
        let tun_device = self.tun_device.take().expect("TUN device not set up");
        let (tun_reader, mut tun_writer) = tun_device.split()?;

        // Create channel for TUN writes from all clients.
        // This replaces the Arc<Mutex<TunWriter>> with a dedicated writer task,
        // eliminating mutex contention in the hot path.
        // Channel size is configurable via VpnServerConfig::tun_writer_channel_size.
        let (tun_write_tx, mut tun_write_rx) =
            mpsc::channel::<TunWriteRequest>(self.config.tun_writer_channel_size);
        log::debug!(
            "TUN writer channel size: {}",
            self.config.tun_writer_channel_size
        );

        // Spawn dedicated TUN writer task that owns TunWriter exclusively.
        // All clients send validated packets through the channel; this task
        // performs the actual writes without any mutex contention.
        // Store JoinHandle for graceful shutdown.
        let tun_writer_stats = self.stats.clone();
        let tun_writer_handle = tokio::spawn(async move {
            log::info!("TUN writer task started");
            let mut batch = Vec::with_capacity(WRITE_BATCH_SIZE);
            // Run buffer of consecutive metadata-less packets, flushed through
            // write_batch so same-flow TCP segments coalesce into GSO
            // super-frames on Linux (one TUN write instead of N).
            let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
            // Log and count a write failure; failures shouldn't stop the writer.
            let log_write_error = |e: VpnError| {
                tun_writer_stats
                    .packets_tun_write_failed
                    .fetch_add(1, Ordering::Relaxed);
                log::warn!("Failed to write to TUN: {}", e);
            };
            loop {
                let count = tun_write_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
                if count == 0 {
                    break;
                }

                for req in batch.drain(..) {
                    let Some(meta) = req.offload else {
                        plain_run.push(req.packet);
                        continue;
                    };
                    if !plain_run.is_empty() {
                        if let Err(e) = tun_writer.write_batch(&plain_run).await {
                            log_write_error(e);
                        }
                        plain_run.clear();
                    }
                    if let Err(e) = tun_writer.write_packet(Some(&meta), &req.packet).await {
                        log_write_error(e);
                    }
                }
                if !plain_run.is_empty() {
                    if let Err(e) = tun_writer.write_batch(&plain_run).await {
                        log_write_error(e);
                    }
                    plain_run.clear();
                }
            }
            log::info!("TUN writer task exiting (channel closed)");
        });

        let server = Arc::new(self);

        // Spawn the status control-socket listener. The guard removes the
        // socket file and aborts the listener when `run` returns.
        let started_at = Instant::now();
        let node_id = endpoint.id().to_string();
        let status_server = server.clone();
        let status_endpoint = endpoint.clone();
        let status_overlay_v4 = server.config.network;
        let status_overlay_v6 = server.config.network6;
        let _status_listener =
            crate::control::spawn_status_listener(LockRole::Server, "default", move || {
                let bypass_addrs =
                    server_candidate_addrs(&status_endpoint, status_overlay_v4, status_overlay_v6)
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect();
                status_server.status_snapshot(
                    node_id.clone(),
                    started_at.elapsed().as_secs(),
                    bypass_addrs,
                )
            });
        match &_status_listener {
            Ok(_) => log::info!("Status control socket ready (ezvpn server status)"),
            Err(e) => log::warn!("Status control socket unavailable: {e}"),
        }
        let _status_listener = _status_listener.ok();

        // Spawn TUN reader task (reads from TUN, routes to clients)
        // Store JoinHandle for graceful shutdown.
        let server_tun = server.clone();
        let local_iroh_udp_ports_for_tun = local_iroh_udp_ports.clone();
        let tun_reader_handle = tokio::spawn(async move {
            if let Err(e) = server_tun
                .run_tun_reader(tun_reader, local_iroh_udp_ports_for_tun)
                .await
            {
                log::error!("TUN reader error: {}", e);
            }
        });

        // Accept incoming connections
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    let server = server.clone();
                    let tun_write_tx = tun_write_tx.clone();
                    let local_iroh_udp_ports = local_iroh_udp_ports.clone();
                    let endpoint = endpoint.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server
                            .handle_connection(
                                incoming,
                                tun_write_tx,
                                local_iroh_udp_ports,
                                endpoint,
                            )
                            .await
                        {
                            log::error!("Connection error: {}", e);
                        }
                    });
                }
                None => {
                    log::info!("Endpoint closed, shutting down");
                    break;
                }
            }
        }

        // Graceful shutdown: drop channel sender to signal TUN writer to exit,
        // then await both tasks to ensure clean termination.
        log::info!("Shutting down TUN tasks...");
        drop(tun_write_tx);

        // Abort TUN reader (it's blocked on TUN read, won't exit on its own)
        tun_reader_handle.abort();

        // Wait for TUN writer to drain any remaining packets and exit
        if let Err(e) = tun_writer_handle.await
            && !e.is_cancelled()
        {
            log::warn!("TUN writer task panicked: {}", e);
        }

        log::info!("TUN tasks shutdown complete");
        Ok(())
    }

    /// Handle an incoming VPN connection.
    async fn handle_connection(
        &self,
        incoming: iroh::endpoint::Incoming,
        tun_write_tx: mpsc::Sender<TunWriteRequest>,
        local_iroh_udp_ports: Arc<HashSet<u16>>,
        endpoint: Endpoint,
    ) -> VpnResult<()> {
        let connection = incoming
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept connection: {}", e)))?;

        let remote_id = connection.remote_id();
        log::info!("New VPN connection from {}", remote_id);

        // Accept handshake stream
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept stream: {}", e)))?;

        // Read handshake
        let handshake_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE).await?;
        let handshake = VpnHandshake::decode(&handshake_data)?;

        log::debug!(
            "Received handshake from {} for device {}",
            remote_id,
            handshake.device_id
        );

        // Validate auth token (required - server must have auth_tokens configured)
        if let Some(ref valid_tokens) = self.config.auth_tokens {
            match &handshake.auth_token {
                Some(client_token) if valid_tokens.contains(client_token) => {
                    log::debug!("Client {} provided valid auth token", remote_id);
                }
                Some(_) => {
                    log::warn!("Client {} provided invalid auth token", remote_id);
                    let response = VpnHandshakeResponse::rejected(
                        "Invalid authentication token",
                        self.tun_offload_status.enabled,
                    );
                    write_message(&mut send, &response.encode()?).await?;
                    let _ = send.finish();
                    return Err(VpnError::Signaling("Invalid authentication token".into()));
                }
                None => {
                    log::warn!("Client {} missing required auth token", remote_id);
                    let response = VpnHandshakeResponse::rejected(
                        "Authentication token required",
                        self.tun_offload_status.enabled,
                    );
                    write_message(&mut send, &response.encode()?).await?;
                    let _ = send.finish();
                    return Err(VpnError::Signaling("Authentication token required".into()));
                }
            }
        } else {
            // Server misconfigured - should always have auth_tokens
            log::error!("Server has no auth tokens configured - rejecting connection");
            let response = VpnHandshakeResponse::rejected(
                "Server misconfigured",
                self.tun_offload_status.enabled,
            );
            write_message(&mut send, &response.encode()?).await?;
            let _ = send.finish();
            return Err(VpnError::Signaling(
                "Server has no auth tokens configured".into(),
            ));
        }

        // Monitor and report connection path changes (e.g., relay -> direct)
        let _path_watcher =
            watch_connection_paths(&connection, &format!("Client {} connection", remote_id));

        // Atomically increment connection count and check max_clients
        // fetch_add returns the previous value, so if it was >= max_clients, we're over
        let prev_count = self.active_connections.fetch_add(1, Ordering::SeqCst);
        if prev_count >= self.config.max_clients {
            // We exceeded the limit - decrement and reject
            self.active_connections.fetch_sub(1, Ordering::SeqCst);
            let response =
                VpnHandshakeResponse::rejected("Server full", self.tun_offload_status.enabled);
            write_message(&mut send, &response.encode()?).await?;
            let _ = send.finish();
            return Err(VpnError::IpAssignment("Server full".into()));
        }

        // From this point on, we must decrement active_connections on any error
        let result = self
            .handle_connection_inner(
                &mut send,
                remote_id,
                connection,
                tun_write_tx,
                local_iroh_udp_ports,
                handshake,
                endpoint,
            )
            .await;

        // Always decrement on exit (success or failure)
        self.active_connections.fetch_sub(1, Ordering::SeqCst);

        result
    }

    /// Inner connection handler - separated to ensure atomic counter cleanup.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection_inner(
        &self,
        send: &mut iroh::endpoint::SendStream,
        remote_id: EndpointId,
        connection: iroh::endpoint::Connection,
        tun_write_tx: mpsc::Sender<TunWriteRequest>,
        local_iroh_udp_ports: Arc<HashSet<u16>>,
        handshake: VpnHandshake,
        endpoint: Endpoint,
    ) -> VpnResult<()> {
        let device_id = handshake.device_id;
        let client_gso_enabled = handshake.gso_enabled;
        // The IP data path is unreliable QUIC datagrams; verify the peer
        // supports them. The advertised MTU is deliberately independent of the
        // current `max_datagram_size` (a live value that tracks path-MTU
        // discovery): the data path re-reads the cap per TUN read and
        // software-resegments oversized TCP, so a fixed, deterministic MTU is
        // both reliable and reconnect-stable.
        let current_datagram_cap = connection.max_datagram_size().ok_or_else(|| {
            VpnError::Signaling("Peer does not support QUIC datagrams".into())
        })?;
        let advertised_mtu = advertised_client_mtu(self.config.mtu);
        log::info!(
            "Client {} advertised MTU={} (current datagram cap: {})",
            remote_id,
            advertised_mtu,
            current_datagram_cap
        );
        // Allocate IPv4 for client (if server has IPv4 configured)
        let assigned_ip = if let Some(ref ip_pool) = self.ip_pool {
            let mut pool = ip_pool.write().await;
            match pool.allocate(remote_id, device_id) {
                Some(ip) => Some(ip),
                None => {
                    // IPv4 pool exhausted - fatal if this is IPv4-only mode
                    if self.ip6_pool.is_none() {
                        return Err(VpnError::IpAssignment("IPv4 pool exhausted".into()));
                    }
                    // Dual-stack: continue with IPv6 only
                    log::warn!(
                        "IPv4 pool exhausted for client {}, using IPv6 only",
                        remote_id
                    );
                    None
                }
            }
        } else {
            None
        };

        // Allocate IPv6 for client (if server has IPv6 configured)
        let assigned_ip6 = if let Some(ref ip6_pool) = self.ip6_pool {
            let mut pool = ip6_pool.write().await;
            match pool.allocate(remote_id, device_id) {
                Some(ip) => Some(ip),
                None => {
                    // IPv6 pool exhausted - fatal if this is IPv6-only mode
                    if self.ip_pool.is_none() {
                        return Err(VpnError::IpAssignment("IPv6 pool exhausted".into()));
                    }
                    // Dual-stack: continue with IPv4 only
                    log::warn!(
                        "IPv6 pool exhausted for client {}, using IPv4 only",
                        remote_id
                    );
                    None
                }
            }
        } else {
            None
        };

        // Must have at least one IP assigned
        if assigned_ip.is_none() && assigned_ip6.is_none() {
            return Err(VpnError::IpAssignment("All IP pools exhausted".into()));
        }

        // Build handshake response based on what was allocated. Advertise only
        // the server's host prefix (/32, /128) as the routed network — never
        // the full VPN subnet. Inter-client traffic is dropped server-side
        // unconditionally, so the gateway is the only in-VPN destination a
        // client can reach; advertising the subnet would just route dead
        // addresses into the tunnel.
        let response = match (assigned_ip, assigned_ip6) {
            // Dual-stack: both IPv4 and IPv6
            (Some(ip4), Some(ip6)) => {
                let ip_pool = self.ip_pool.as_ref().unwrap().read().await;
                let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted_dual_stack(
                    ip4,
                    host_net4(ip_pool.server_ip()),
                    ip_pool.server_ip(),
                    ip6,
                    host_net6(ip6_pool.server_ip()),
                    ip6_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.wire_transport,
                    advertised_mtu,
                )
            }
            // IPv4-only
            (Some(ip4), None) => {
                let ip_pool = self.ip_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted(
                    ip4,
                    host_net4(ip_pool.server_ip()),
                    ip_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.wire_transport,
                    advertised_mtu,
                )
            }
            // IPv6-only
            (None, Some(ip6)) => {
                let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted_ipv6_only(
                    ip6,
                    host_net6(ip6_pool.server_ip()),
                    ip6_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.wire_transport,
                    advertised_mtu,
                )
            }
            // Should not happen - checked above
            (None, None) => unreachable!(),
        };

        // Seed the client's bypass routes at onboarding: hand it our candidate
        // underlay addresses now (reliable handshake stream) so it can pin any a
        // VPN route would capture immediately, rather than waiting for the first
        // periodic data-path publication (`run_server_addr_publisher`). The client
        // filters to VPN-covered IPs and only ever adds, so publishing the full
        // underlay set — including private/LAN addresses — is safe;
        // `server_candidate_addrs` drops our own VPN overlay addresses.
        let response = response.with_server_addrs(server_candidate_addrs(
            &endpoint,
            self.config.network,
            self.config.network6,
        ));

        write_message(send, &response.encode()?).await?;
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }

        // Log connection based on what was assigned
        match (assigned_ip, assigned_ip6) {
            (Some(ip4), Some(ip6)) => {
                log::info!(
                    "Client {} connected, assigned IP: {}, IPv6: {}",
                    remote_id,
                    ip4,
                    ip6
                );
            }
            (Some(ip4), None) => {
                log::info!("Client {} connected, assigned IP: {}", remote_id, ip4);
            }
            (None, Some(ip6)) => {
                log::info!(
                    "Client {} connected, assigned IPv6: {} (IPv6-only)",
                    remote_id,
                    ip6
                );
            }
            (None, None) => unreachable!(),
        }

        // GSO is negotiated from the handshake (the client advertised its
        // capability there); the data path is datagrams, so there is no separate
        // capabilities message.
        let connection_gso_active = self.tun_offload_status.enabled && client_gso_enabled;
        log::info!(
            "Client {} GSO status: server_local={}, client_reported={}, active={}",
            remote_id,
            self.tun_offload_status.enabled,
            client_gso_enabled,
            connection_gso_active
        );

        // Create channel for sending framed datagrams to this client's writer
        // task. The writer task owns the `Connection` and sends datagrams,
        // decoupling packet production from the send path.
        // Channel size is configurable via VpnServerConfig::client_channel_size.
        let (packet_tx, mut packet_rx) = mpsc::channel::<Bytes>(self.config.client_channel_size);

        // Create oneshot channel for writer error signaling. When the writer
        // fails, it sends the error here to trigger immediate cleanup.
        let (writer_error_tx, writer_error_rx) = oneshot::channel::<String>();

        // Spawn dedicated writer task that owns a clone of the `Connection` and
        // sends each queued datagram. Returns errors via the oneshot channel.
        // At least one of assigned_ip or assigned_ip6 must be set at this point.
        let writer_client_id = assigned_ip
            .map(|ip| ip.to_string())
            .or_else(|| assigned_ip6.map(|ip| ip.to_string()))
            .expect("at least one IP must be assigned");
        let writer_conn = connection.clone();
        let writer_handle = tokio::spawn(async move {
            let mut batch: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
            let error = loop {
                let count = packet_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
                if count == 0 {
                    // Channel closed (normal shutdown).
                    break None;
                }
                let mut fatal = None;
                for dgram in batch.drain(..) {
                    let dgram_len = dgram.len();
                    match writer_conn.send_datagram_wait(dgram).await {
                        Ok(()) => {}
                        Err(SendDatagramError::TooLarge) => {
                            log::warn!(
                                "Dropping datagram to client {} ({} B) larger than max_datagram_size ({:?}); path MTU shrank mid-batch",
                                writer_client_id,
                                dgram_len,
                                writer_conn.max_datagram_size()
                            );
                        }
                        Err(e) => {
                            log::warn!("Failed to send datagram to {}: {}", writer_client_id, e);
                            fatal = Some(format!("QUIC datagram send error: {}", e));
                            break;
                        }
                    }
                }
                if let Some(reason) = fatal {
                    break Some(reason);
                }
            };
            log::trace!("Writer task for {} exiting", writer_client_id);
            // Signal error to trigger immediate cleanup (ignore send error if receiver dropped)
            if let Some(err_msg) = error {
                let _ = writer_error_tx.send(err_msg);
            }
        });

        // Periodically publish the server's candidate iroh underlay addresses to
        // this client so it can bypass-route any that fall within its VPN range,
        // pre-empting the self-capture of a server address iroh has discovered but
        // not yet selected for the active path (which the client's path-snapshot
        // discovery alone would miss). Self-terminates when the connection closes
        // or the writer's receiver is gone (queueing via `packet_tx` fails).
        let publisher_endpoint = endpoint.clone();
        let publisher_tx = packet_tx.clone();
        let publisher_conn = connection.clone();
        let publisher_label = remote_id.to_string();
        let publisher_overlay_v4 = self.config.network;
        let publisher_overlay_v6 = self.config.network6;
        tokio::spawn(async move {
            run_server_addr_publisher(
                publisher_endpoint,
                publisher_conn,
                publisher_tx,
                publisher_label,
                publisher_overlay_v4,
                publisher_overlay_v6,
            )
            .await;
        });

        // Generate unique session ID for this connection
        // Used to detect stale cleanup when same client reconnects quickly
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        // Store client state with channel sender for TUN handler to use
        let client_state = ClientState {
            session_id,
            assigned_ip,
            assigned_ip6,
            packet_tx: packet_tx.clone(),
            client_gso_enabled,
            connection_gso_active,
            connection: connection.clone(),
        };

        // Reconnect handling: if a client with the same (EndpointId, DeviceId) exists,
        // we can safely overwrite its entry in the map with the new connection state.
        // The old ClientState's packet_tx sender is dropped, causing its writer task
        // to exit when the channel closes. The session_id check in cleanup prevents
        // stale cleanup tasks from affecting the new connection.
        let client_key = (remote_id, device_id);

        // DashMap operations are lock-free (no async needed)
        self.clients.insert(client_key, client_state);

        // Add IPv4 reverse lookup if assigned
        if let Some(ip4) = assigned_ip {
            self.ip_to_endpoint.insert(ip4, (remote_id, device_id));
        }

        // Add IPv6 reverse lookup if assigned
        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_endpoint.insert(ip6, (remote_id, device_id));
        }

        // Handle client data
        let clients = self.clients.clone();
        let ip_pool = self.ip_pool.clone();
        let ip6_pool = self.ip6_pool.clone();
        let ip_to_endpoint = self.ip_to_endpoint.clone();
        let ip6_to_endpoint = self.ip6_to_endpoint.clone();

        // Run client handler (blocks until client disconnects or writer fails).
        // writer_error_rx triggers immediate cleanup on send failures.
        let ctx = ClientContext {
            assigned_ip,
            assigned_ip6,
            client_key,
            ip_to_endpoint: ip_to_endpoint.clone(),
            ip6_to_endpoint: ip6_to_endpoint.clone(),
            disable_spoofing_check: self.config.disable_spoofing_check,
            connection_gso_active,
            local_tun_gso_enabled: self.tun_offload_status.enabled,
        };
        let result = Self::handle_client_data(
            connection,
            ctx,
            tun_write_tx,
            local_iroh_udp_ports,
            writer_error_rx,
            self.stats.clone(),
        )
        .await;

        // Abort writer task if still running (cleanup on any exit path)
        writer_handle.abort();

        if let Err(ref e) = result {
            log::error!("Client {} data error: {}", remote_id, e);
        }

        log::info!("Client {} disconnected", remote_id);

        // Cleanup - use session_id to detect stale cleanup from rapid reconnection.
        // Check-before-remove: verify session_id matches before removing anything.
        // If a newer connection replaced us, do nothing - that connection owns the resources.
        // DashMap remove_if atomically checks and removes if the predicate holds.
        let removed = clients.remove_if(&client_key, |_, state| state.session_id == session_id);

        let (endpoint_to_release, release_ipv4, release_ipv6) =
            if let Some((_, client_state)) = removed {
                // Remove IPv4 mapping if it points to us
                if let Some(ip4) = assigned_ip {
                    ip_to_endpoint
                        .remove_if(&ip4, |_, (ep, dev)| *ep == remote_id && *dev == device_id);
                }

                // Remove IPv6 mapping if it points to us
                if let Some(ip6) = assigned_ip6 {
                    ip6_to_endpoint.remove_if(&ip6, |_, (ep6, dev6)| {
                        *ep6 == remote_id && *dev6 == device_id
                    });
                }

                (
                    Some((remote_id, device_id)),
                    client_state.assigned_ip.is_some(),
                    client_state.assigned_ip6.is_some(),
                )
            } else {
                // Session_id didn't match or client already gone - do nothing
                (None, false, false)
            };

        if let Some((endpoint_id, dev_id)) = endpoint_to_release {
            // Release IPv4 if allocated for this session
            if release_ipv4 && let Some(ref ip_pool) = ip_pool {
                ip_pool.write().await.release(&endpoint_id, dev_id);
            }

            // Release IPv6 if allocated for this session
            if release_ipv6 && let Some(ref ip6_pool) = ip6_pool {
                ip6_pool.write().await.release(&endpoint_id, dev_id);
            }
        }

        result
    }

    /// Enqueue a TUN write request to be processed by the dedicated TUN writer task.
    ///
    /// Returns `true` if the request was successfully enqueued, `false` if the channel is closed.
    async fn enqueue_tun_write(
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        req: TunWriteRequest,
        stats: &Arc<VpnServerStats>,
    ) -> bool {
        match tun_write_tx.try_send(req) {
            Ok(()) => {
                stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(req)) => {
                if tun_write_tx.send(req).await.is_ok() {
                    stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    stats
                        .packets_tun_write_failed
                        .fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                stats
                    .packets_tun_write_failed
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Enqueue a framed data-stream packet for a client writer task.
    /// Enqueue a framed packet on a client's channel.
    ///
    /// `packet_count` is the number of original IP packets the frame carries
    /// (>1 for software-GRO coalesced frames) so per-packet stats stay
    /// comparable regardless of coalescing.
    async fn enqueue_client_frame(
        packet_tx: &mpsc::Sender<Bytes>,
        frame: Bytes,
        stats: &Arc<VpnServerStats>,
        drop_on_full: bool,
        packet_count: u64,
    ) {
        match packet_tx.try_send(frame) {
            Ok(()) => {
                stats
                    .packets_to_clients
                    .fetch_add(packet_count, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(frame)) => {
                if drop_on_full {
                    stats
                        .packets_dropped_full
                        .fetch_add(packet_count, Ordering::Relaxed);
                } else {
                    stats
                        .packets_backpressure
                        .fetch_add(packet_count, Ordering::Relaxed);
                    if packet_tx.send(frame).await.is_ok() {
                        stats
                            .packets_to_clients
                            .fetch_add(packet_count, Ordering::Relaxed);
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel closed during disconnect.
            }
        }
    }

    /// Frame software-GRO outputs into datagrams and enqueue them on a client's
    /// packet channel, segmenting to the client's datagram cap.
    async fn send_gro_outputs_to_client(
        &self,
        outputs: &[CoalescedOutput],
        arena: &mut BytesMut,
        seg_scratch: &mut Vec<u8>,
        pending: &mut Vec<Bytes>,
        packet_tx: &mpsc::Sender<Bytes>,
        max_datagram_size: usize,
    ) {
        pending.clear();
        if let Err(e) = build_gro_datagrams(arena, seg_scratch, pending, outputs, max_datagram_size)
        {
            log::warn!("Failed to frame coalesced packet: {}", e);
            return;
        }
        for dgram in pending.drain(..) {
            Self::enqueue_client_frame(
                packet_tx,
                dgram,
                &self.stats,
                self.config.drop_on_full,
                1,
            )
            .await;
        }
    }

    /// Drain all pending per-client software-GRO groups and evict state for
    /// disconnected clients.
    async fn flush_gro_states(
        &self,
        gro_states: &mut HashMap<(EndpointId, u64), ClientGroState>,
        arena: &mut BytesMut,
        seg_scratch: &mut Vec<u8>,
        pending: &mut Vec<Bytes>,
    ) {
        for state in gro_states.values_mut() {
            let Some(max_datagram_size) = state.connection.max_datagram_size() else {
                // Datagrams unsupported (cannot happen mid-connection: the
                // transport parameter is fixed at handshake). Drop the buffered
                // segments rather than leave them to go stale in the table.
                drop(state.table.flush_all());
                continue;
            };
            let outputs = state.table.flush_all();
            self.send_gro_outputs_to_client(
                &outputs,
                arena,
                seg_scratch,
                pending,
                &state.packet_tx,
                max_datagram_size,
            )
            .await;
        }
        // Evict GRO state for disconnected clients to avoid unbounded growth.
        gro_states.retain(|_, state| !state.packet_tx.is_closed());
    }

    /// Handle client data stream.
    ///
    /// This function reads inbound datagrams from the client and routes their IP
    /// packets to the TUN writer. It exits when either:
    /// - The client disconnects (datagram read errors / connection closes)
    /// - The writer task fails (error received via writer_error_rx)
    ///
    /// TUN writes are sent through the `tun_write_tx` channel to a dedicated writer task,
    /// eliminating mutex contention. Backpressure is applied when the channel is full.
    ///
    /// At least one of `ctx.assigned_ip` (IPv4) or `ctx.assigned_ip6` (IPv6) must be provided.
    async fn handle_client_data(
        connection: Connection,
        ctx: ClientContext,
        tun_write_tx: mpsc::Sender<TunWriteRequest>,
        local_iroh_udp_ports: Arc<HashSet<u16>>,
        writer_error_rx: oneshot::Receiver<String>,
        stats: Arc<VpnServerStats>,
    ) -> VpnResult<()> {
        // Create client identifier string for logging (used both in spawned task and select!)
        // At least one of assigned_ip or assigned_ip6 must be set (enforced by caller)
        let client_id = ctx
            .assigned_ip
            .map(|ip| ip.to_string())
            .or_else(|| ctx.assigned_ip6.map(|ip| ip.to_string()))
            .expect("at least one IP must be assigned");
        let client_id_outer = client_id.clone(); // For use in select! block

        // Spawn inbound task (connection datagrams -> TUN via channel)
        let mut inbound_handle = tokio::spawn(async move {
            // Reusable buffers for software-materializing offload super-frames:
            // segments are built in `seg_scratch`, copied once into `seg_arena`,
            // and handed out as refcounted Bytes views.
            let mut seg_scratch: Vec<u8> = Vec::new();
            let mut seg_arena = BytesMut::new();
            let mut pending_segments: Vec<Bytes> = Vec::new();
            'read_loop: loop {
                let dgram = match connection.read_datagram().await {
                    Ok(d) => d,
                    Err(e) => {
                        log::debug!("Client {} datagram read ended: {}", client_id, e);
                        break;
                    }
                };

                let body = match classify(&dgram) {
                    Ok(Datagram::Ip(body)) => body,
                    Ok(Datagram::ServerAddrs(_)) => {
                        // Server → client only; a client never sends this. Ignore.
                        log::trace!("Ignoring unexpected ServerAddrs datagram from {}", client_id);
                        continue;
                    }
                    Err(e) => {
                        log::trace!("Ignoring undecodable datagram from {}: {}", client_id, e);
                        continue;
                    }
                };

                let (offload, packet) = match parse_ip_packet_v2(body) {
                    Ok(parts) => parts,
                    Err(e) => {
                        log::warn!("Invalid IP datagram from {}: {}", client_id, e);
                        continue;
                    }
                };

                if packet_has_local_iroh_udp_port(packet, &local_iroh_udp_ports) {
                    log::debug!(
                        "Dropped self-encapsulated iroh UDP packet from client {}",
                        client_id
                    );
                    continue;
                }

                // Validate source IP to prevent inter-client IP spoofing.
                // We only reject packets if the source IP belongs to another client,
                // allowing clients to use their own public IPs (useful for dual-stack).
                let source_valid = if ctx.disable_spoofing_check {
                    // Spoofing check disabled - allow all packets
                    true
                } else {
                    match extract_source_ip(packet) {
                        Some(PacketIp::V4(src_ip)) => {
                            // Check if this IP belongs to another client
                            match ctx.ip_to_endpoint.get(&src_ip) {
                                Some(ref owner) if *owner.value() == ctx.client_key => true, // Our own assigned IP
                                Some(_) => {
                                    // IP belongs to another client - actual spoofing
                                    log::warn!(
                                        "IPv4 inter-client spoofing from client {}: source {} belongs to another client",
                                        client_id,
                                        src_ip
                                    );
                                    false
                                }
                                None => true, // Not a VPN-assigned IP - allow (e.g., client's public IP)
                            }
                        }
                        Some(PacketIp::V6(src_ip)) => {
                            // Silently drop link-local packets (fe80::/10) - these are normal
                            // OS traffic (neighbor discovery, etc.) that shouldn't be forwarded
                            let src_bytes = src_ip.octets();
                            let is_link_local =
                                src_bytes[0] == 0xfe && (src_bytes[1] & 0xc0) == 0x80;
                            if is_link_local {
                                // Link-local IPv6 packets are dropped (can't route across VPN)
                                false
                            } else {
                                // Check if this IP belongs to another client
                                match ctx.ip6_to_endpoint.get(&src_ip) {
                                    Some(ref owner) if *owner.value() == ctx.client_key => true, // Our own assigned IP
                                    Some(_) => {
                                        // IP belongs to another client - actual spoofing
                                        log::warn!(
                                            "IPv6 inter-client spoofing from client {}: source {} belongs to another client",
                                            client_id,
                                            src_ip
                                        );
                                        false
                                    }
                                    None => true, // Not a VPN-assigned IP - allow (e.g., client's public IP)
                                }
                            }
                        }
                        None => {
                            log::warn!(
                                "Failed to parse source IP from packet from client {}",
                                client_id
                            );
                            false
                        }
                    }
                };

                if !source_valid {
                    // Drop spoofed packet
                    stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Mandatory client isolation: never let one VPN client reach
                // another. Only client-assigned IPs live in these maps (the
                // server/gateway IP does not), so a hit means the destination is
                // another client (or self) - drop instead of writing to the TUN
                // and having the kernel forward it back out. This is independent
                // of the spoofing check (that gates the source; this gates the
                // destination) and needs no firewall or ip_forward.
                let to_vpn_client = match extract_dest_ip(packet) {
                    Some(PacketIp::V4(dst)) => ctx.ip_to_endpoint.contains_key(&dst),
                    Some(PacketIp::V6(dst)) => ctx.ip6_to_endpoint.contains_key(&dst),
                    None => false,
                };
                if to_vpn_client {
                    stats
                        .packets_inter_client_blocked
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                if let Some(meta) = offload {
                    if !ctx.connection_gso_active || !ctx.local_tun_gso_enabled {
                        let materialized =
                            materialize_offload_into(&meta, packet, &mut seg_scratch, |seg| {
                                seg_arena.extend_from_slice(seg);
                                pending_segments.push(seg_arena.split_to(seg.len()).freeze());
                                Ok(())
                            });
                        if let Err(e) = materialized {
                            pending_segments.clear();
                            log::warn!(
                                "Dropping packet with unsupported offload metadata from {}: {}",
                                client_id,
                                e
                            );
                            continue;
                        }
                        for packet in pending_segments.drain(..) {
                            let req = TunWriteRequest {
                                packet,
                                offload: None,
                            };
                            if !Self::enqueue_tun_write(&tun_write_tx, req, &stats).await {
                                break 'read_loop;
                            }
                        }
                    } else {
                        let req = TunWriteRequest {
                            packet: dgram.slice_ref(packet),
                            offload: Some(meta),
                        };
                        if !Self::enqueue_tun_write(&tun_write_tx, req, &stats).await {
                            break;
                        }
                    }
                } else {
                    let req = TunWriteRequest {
                        packet: dgram.slice_ref(packet),
                        offload: None,
                    };
                    if !Self::enqueue_tun_write(&tun_write_tx, req, &stats).await {
                        break;
                    }
                }
            }
        });

        // Wait for either:
        // - Inbound task completes (client disconnection or stream error)
        // - Writer task signals an error (QUIC write failure)
        // This ensures immediate cleanup on writer failure instead of waiting for heartbeat timeout.
        tokio::select! {
            inbound_result = &mut inbound_handle => {
                // Inspect JoinHandle result to catch panics
                match inbound_result {
                    Ok(()) => {
                        // Client disconnected normally or stream error
                        log::trace!("Client {} inbound task completed", client_id_outer);
                    }
                    Err(e) if e.is_panic() => {
                        log::error!("Client {} inbound task panicked: {}", client_id_outer, e);
                        return Err(VpnError::ConnectionLost(format!("inbound task panicked: {}", e)));
                    }
                    Err(e) => {
                        // Cancelled or other JoinError
                        log::debug!("Client {} inbound task failed: {}", client_id_outer, e);
                        return Err(VpnError::ConnectionLost(format!("inbound task failed: {}", e)));
                    }
                }
            }
            writer_err = writer_error_rx => {
                // Writer task failed - abort inbound task and return error
                inbound_handle.abort();
                match writer_err {
                    Ok(err_msg) => {
                        log::debug!("Client {} writer failed: {}", client_id_outer, err_msg);
                        return Err(VpnError::ConnectionLost(err_msg));
                    }
                    Err(_) => {
                        // Sender dropped without error (normal shutdown via channel close)
                        log::trace!("Client {} writer channel closed", client_id_outer);
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the TUN reader - reads packets from TUN and routes to clients.
    ///
    /// Memory note: Each packet requires a small allocation (5 bytes framing + packet length).
    /// We allocate based on actual packet size to avoid over-allocation for small packets.
    /// Most allocations are small and served from thread-local caches, making them fast.
    async fn run_tun_reader(
        &self,
        mut tun_reader: crate::net::device::TunReader,
        local_iroh_udp_ports: Arc<HashSet<u16>>,
    ) -> VpnResult<()> {
        log::info!("TUN reader started");

        let buffer_size = tun_reader.buffer_size();
        let mut read_storage = uninitialized_vec(buffer_size);
        // Long-lived framing arena: frames are appended and split off as
        // refcounted Bytes views, amortizing allocations across packets.
        let mut arena = BytesMut::with_capacity(FRAME_ARENA_CHUNK);
        // Reusable buffers for software-materializing offload super-frames
        // destined for clients without GSO support.
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut pending_frames: Vec<Bytes> = Vec::new();
        // Software GRO: when the server TUN has no offload support (macOS/
        // Windows, or Linux without vnet headers) the kernel performs no GRO,
        // so coalesce consecutive same-flow TCP segments per destination
        // client before framing. On a GSO-enabled Linux TUN this path is
        // entirely bypassed: the kernel already hands us coalesced frames.
        let software_gro = !tun_reader.vnet_hdr_enabled();
        if software_gro {
            log::info!(
                "Software GRO enabled for TUN->client TCP (server TUN has no offload support; event-driven drain-then-flush)"
            );
        }
        let mut gro_states: HashMap<(EndpointId, u64), ClientGroState> = HashMap::new();

        // Persistent ReadBuf: tracks the initialized region across iterations
        // so the TUN reader's `initialize_unfilled()` only zeroes the buffer
        // once instead of on every read.
        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            packet_buf.clear();
            let gro_pending =
                software_gro && gro_states.values().any(|state| !state.table.is_empty());
            // Event-driven GRO: keep pulling segments already queued on the
            // TUN; the instant it drains, emit every pending coalesced group
            // across all client tables and block for the next packet.
            let read_result = if gro_pending {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        self.flush_gro_states(
                            &mut gro_states,
                            &mut arena,
                            &mut seg_scratch,
                            &mut pending_frames,
                        )
                        .await;
                        tun_reader.read_buf(&mut packet_buf).await
                    }
                }
            } else {
                tun_reader.read_buf(&mut packet_buf).await
            };

            // Read packet from TUN device
            match read_result {
                Ok(()) if !packet_buf.filled().is_empty() => {}
                Ok(()) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    // Flush pending coalesced groups before shutting down.
                    self.flush_gro_states(
                        &mut gro_states,
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending_frames,
                    )
                    .await;
                    break;
                }
            }

            let raw_frame = packet_buf.filled();
            self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

            let (offload, packet_ref) = match tun_reader.split_frame(raw_frame) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("Failed to parse TUN frame from server device: {}", e);
                    continue;
                }
            };

            if packet_has_local_iroh_udp_port(packet_ref, &local_iroh_udp_ports) {
                log::debug!("Dropped self-encapsulated iroh UDP packet from server TUN");
                continue;
            }

            // Extract destination IP from packet (IPv4 or IPv6)
            // DashMap lookups are lock-free - no async await needed
            let (endpoint_id, device_id) = match extract_dest_ip(packet_ref) {
                Some(PacketIp::V4(dest_ip)) => {
                    match self.ip_to_endpoint.get(&dest_ip).map(|r| *r) {
                        Some(res) => res,
                        None => {
                            self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
                Some(PacketIp::V6(dest_ip)) => match self.ip6_to_endpoint.get(&dest_ip).map(|r| *r)
                {
                    Some(res) => res,
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                None => {
                    self.stats
                        .packets_unknown_version
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            let client_key = (endpoint_id, device_id);

            // Get client's packet channel sender (DashMap lookup is lock-free)
            let (packet_tx, client_gso_enabled, connection_gso_active, connection) =
                match self.clients.get(&client_key) {
                    Some(c) => (
                        c.packet_tx.clone(),
                        c.client_gso_enabled,
                        c.connection_gso_active,
                        c.connection.clone(),
                    ),
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

            // Read the datagram cap live so framing follows QUIC path-MTU
            // discovery as it raises (or black-hole detection lowers) the path.
            let Some(max_datagram_size) = connection.max_datagram_size() else {
                self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                continue;
            };

            if software_gro && client_gso_enabled {
                // Non-GSO TUN frames never carry offload metadata; push the
                // plain IP packet through the client's GRO table. The client
                // accepts offload-tagged frames regardless of its own TUN
                // (it software-segments when needed).
                let state = gro_states
                    .entry(client_key)
                    .or_insert_with(|| ClientGroState {
                        table: TcpGroTable::new(),
                        packet_tx: packet_tx.clone(),
                        connection: connection.clone(),
                    });
                // Keep the freshest sender in case the client reconnected.
                if !state.packet_tx.same_channel(&packet_tx) {
                    state.packet_tx = packet_tx.clone();
                    state.connection = connection.clone();
                }
                let result = state.table.push(packet_ref);
                if !result.outputs.is_empty() {
                    self.send_gro_outputs_to_client(
                        &result.outputs,
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending_frames,
                        &packet_tx,
                        max_datagram_size,
                    )
                    .await;
                }
                if !result.pass_through {
                    continue;
                }
                // Pass-through: fall through to the plain framing below,
                // avoiding any packet copy.
            }

            // Frame the packet into one or more datagrams (segmenting GSO
            // super-frames to the client's datagram cap) and enqueue them.
            pending_frames.clear();
            if let Err(e) = build_datagrams(
                &mut arena,
                &mut seg_scratch,
                &mut pending_frames,
                offload.as_ref(),
                packet_ref,
                connection_gso_active,
                max_datagram_size,
            ) {
                log::warn!(
                    "Failed to frame packet for {} dev {}: {}",
                    endpoint_id,
                    device_id,
                    e
                );
                continue;
            }
            for dgram in pending_frames.drain(..) {
                Self::enqueue_client_frame(
                    &packet_tx,
                    dgram,
                    &self.stats,
                    self.config.drop_on_full,
                    1,
                )
                .await;
            }
        }

        Ok(())
    }
}

/// Per-client software-GRO accumulation state for the server TUN reader.
struct ClientGroState {
    table: TcpGroTable,
    packet_tx: mpsc::Sender<Bytes>,
    /// The client's connection, for live `max_datagram_size()` reads when
    /// framing coalesced outputs.
    connection: Connection,
}

/// IP address extracted from a packet (source or destination).
enum PacketIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

// =============================================================================
// Optimized packet parsing functions
//
// These functions use safe slice-to-array conversions after validating packet
// length once. The compiler optimizes away redundant bounds checks when it can
// prove the slice is in bounds.
//
// Performance optimizations:
// - Single length check combines empty check + minimum header validation
// - Version byte is extracted once and reused
// - try_into() for fixed-size arrays is optimized by LLVM
// - Fast-path for IPv4 (most common) checked first
// =============================================================================

/// Minimum IPv4 header size (20 bytes, no options).
const IPV4_MIN_HEADER: usize = 20;

/// Minimum IPv6 header size (40 bytes fixed).
const IPV6_MIN_HEADER: usize = 40;

/// IPv4 version nibble.
const IP_VERSION_4: u8 = 4;

/// IPv6 version nibble.
const IP_VERSION_6: u8 = 6;

/// Extract source IP address from an IP packet (IPv4 or IPv6).
///
/// Optimized for the hot path with minimal bounds checks and direct pointer reads.
#[inline]
fn extract_source_ip(packet: &[u8]) -> Option<PacketIp> {
    // Fast-path: check for IPv4 first (most common case).
    // Combined length + version check eliminates separate empty check.
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }

    // Cache version byte to avoid repeated indexing (len >= 20 verified above).
    let version = packet[0] >> 4;

    if version == IP_VERSION_4 {
        // IPv4: source address at bytes 12-15 (len >= 20 verified above).
        let src = read_ipv4_addr(packet, 12);
        return Some(PacketIp::V4(src));
    }

    if version == IP_VERSION_6 {
        // IPv6 requires 40 bytes minimum.
        if len < IPV6_MIN_HEADER {
            return None;
        }
        // IPv6: source address at bytes 8-23 (len >= 40 verified above).
        let src = read_ipv6_addr(packet, 8);
        return Some(PacketIp::V6(src));
    }

    None
}

/// Extract destination IP address from an IP packet (IPv4 or IPv6).
///
/// Optimized for the hot path with early length checks before address reads.
#[inline]
fn extract_dest_ip(packet: &[u8]) -> Option<PacketIp> {
    // Fast-path: check for IPv4 first (most common case).
    // Combined length + version check eliminates separate empty check.
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }

    // Cache version byte to avoid repeated indexing (len >= 20 verified above).
    let version = packet[0] >> 4;

    if version == IP_VERSION_4 {
        // IPv4: destination address at bytes 16-19 (len >= 20 verified above).
        let dest = read_ipv4_addr(packet, 16);
        return Some(PacketIp::V4(dest));
    }

    if version == IP_VERSION_6 {
        // IPv6 requires 40 bytes minimum.
        if len < IPV6_MIN_HEADER {
            return None;
        }
        // IPv6: destination address at bytes 24-39 (len >= 40 verified above).
        let dest = read_ipv6_addr(packet, 24);
        return Some(PacketIp::V6(dest));
    }

    None
}

/// Read an IPv4 address from a packet at the given offset.
///
/// # Panics
/// Panics if `packet.len() < offset + 4`. Callers should verify bounds first.
#[inline(always)]
fn read_ipv4_addr(packet: &[u8], offset: usize) -> Ipv4Addr {
    // Convert slice to fixed-size array. The try_into().unwrap() pattern is
    // optimized by the compiler when bounds are provably valid (which they are
    // after our length checks). This generates the same code as unsafe pointer
    // reads but with memory safety guarantees.
    let bytes: [u8; 4] = packet[offset..offset + 4]
        .try_into()
        .expect("IPv4 address read: bounds already verified");
    Ipv4Addr::from(bytes)
}

/// Read an IPv6 address from a packet at the given offset.
///
/// # Panics
/// Panics if `packet.len() < offset + 16`. Callers should verify bounds first.
#[inline(always)]
fn read_ipv6_addr(packet: &[u8], offset: usize) -> Ipv6Addr {
    // Convert slice to fixed-size array. Same optimization applies as IPv4.
    let bytes: [u8; 16] = packet[offset..offset + 16]
        .try_into()
        .expect("IPv6 address read: bounds already verified");
    Ipv6Addr::from(bytes)
}

/// Collect local UDP ports bound by the iroh endpoint.
fn collect_local_iroh_udp_ports(endpoint: &Endpoint) -> HashSet<u16> {
    endpoint.addr().ip_addrs().map(|addr| addr.port()).collect()
}

/// The server's candidate iroh underlay addresses (deduped, sorted): the set it
/// advertises to clients for bypass routing, in the handshake and over the data
/// path. Shared by the handshake response, the periodic publisher, and `status`.
fn server_candidate_addrs(
    endpoint: &Endpoint,
    overlay_v4: Option<Ipv4Net>,
    overlay_v6: Option<Ipv6Net>,
) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = endpoint
        .addr()
        .ip_addrs()
        .map(|sa| sa.ip())
        // iroh enumerates every local interface, which includes the server's own
        // VPN tun (e.g. the overlay gateway 10.99.0.1 / fd11:…::1). Those are
        // overlay addresses, never transport underlay, so never bypass candidates;
        // publishing them would make clients pin the VPN gateway off the tunnel.
        .filter(|ip| !ip_in_overlay(*ip, overlay_v4, overlay_v6))
        // Loopback, unspecified, and link-local addresses are local-only or
        // scope-bound; they can never be a transport underlay a client reaches
        // the server on, so they must not become bypass candidates either.
        .filter(|ip| is_routable_underlay(*ip))
        .collect();
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// True if `ip` can plausibly be a transport underlay address a client reaches
/// the server on — i.e. not loopback, unspecified, or link-local (scope-bound).
fn is_routable_underlay(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        // `Ipv6Addr::is_unicast_link_local` is unstable, so match the fe80::/10
        // prefix directly.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// True if `ip` falls within the server's own VPN overlay network (the tun
/// subnet), and therefore must not be advertised as an underlay bypass candidate.
fn ip_in_overlay(ip: IpAddr, overlay_v4: Option<Ipv4Net>, overlay_v6: Option<Ipv6Net>) -> bool {
    match ip {
        IpAddr::V4(v4) => overlay_v4.is_some_and(|net| net.contains(&v4)),
        IpAddr::V6(v6) => overlay_v6.is_some_and(|net| net.contains(&v6)),
    }
}

/// Publish the server's current candidate underlay addresses to one client over
/// the data-datagram path.
///
/// Returns `Err(())` only when the client's writer receiver is gone (the
/// connection is being torn down), which tells the caller to stop publishing.
/// An empty address set, an encode error, or a full packet queue is a no-op
/// (`Ok`): the enqueue is non-blocking, so address publication never waits on
/// client data backpressure and the next tick retries.
async fn publish_server_addrs(
    endpoint: &Endpoint,
    packet_tx: &mpsc::Sender<Bytes>,
    label: &str,
    overlay_v4: Option<Ipv4Net>,
    overlay_v6: Option<Ipv6Net>,
) -> Result<(), ()> {
    let addrs = server_candidate_addrs(endpoint, overlay_v4, overlay_v6);
    if addrs.is_empty() {
        // No direct addresses discovered yet; nothing to bypass.
        return Ok(());
    }

    let msg = ServerAddrsMsg::new(addrs);
    let mut buf = BytesMut::new();
    if let Err(e) = encode_server_addrs_datagram(&mut buf, &msg) {
        log::warn!("Failed to encode server addrs for {}: {}", label, e);
        return Ok(());
    }

    // Non-blocking: address publication is best-effort and must never wait for
    // queue space behind client data backpressure. A full queue skips this tick
    // (the next one retries); only a dropped receiver is terminal.
    match packet_tx.try_send(buf.freeze()) {
        Ok(()) => {
            log::trace!(
                "Published {} candidate server underlay addrs to {}",
                msg.addrs.len(),
                label
            );
            Ok(())
        }
        // Queue full: skip this tick, the next one retries.
        Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
        // Writer's receiver dropped: the connection is gone, stop publishing.
        Err(mpsc::error::TrySendError::Closed(_)) => Err(()),
    }
}

/// Periodically publish the server's candidate iroh underlay addresses to one
/// client (see [`publish_server_addrs`]): once immediately, then every
/// [`SERVER_ADDR_PUBLISH_INTERVAL`] for loss tolerance, and promptly whenever
/// the local address set changes ([`Endpoint::watch_addr`]). Ends when the
/// connection closes or the client's writer is gone.
async fn run_server_addr_publisher(
    endpoint: Endpoint,
    connection: Connection,
    packet_tx: mpsc::Sender<Bytes>,
    label: String,
    overlay_v4: Option<Ipv4Net>,
    overlay_v6: Option<Ipv6Net>,
) {
    // The first `tick()` resolves immediately, giving the eager initial publish.
    let mut interval = tokio::time::interval(SERVER_ADDR_PUBLISH_INTERVAL);
    let mut addr_changes = endpoint.watch_addr().stream();
    let mut watcher_alive = true;

    loop {
        tokio::select! {
            _ = connection.closed() => break,
            _ = interval.tick() => {
                if publish_server_addrs(&endpoint, &packet_tx, &label, overlay_v4, overlay_v6).await.is_err() {
                    break;
                }
            }
            changed = addr_changes.next(), if watcher_alive => {
                match changed {
                    Some(_) => {
                        if publish_server_addrs(&endpoint, &packet_tx, &label, overlay_v4, overlay_v6).await.is_err() {
                            break;
                        }
                    }
                    // Watcher ended: disable this branch and rely on the interval.
                    None => watcher_alive = false,
                }
            }
        }
    }

    log::debug!("Server addr publisher for {} ending", label);
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
    if packet.len() < IPV4_MIN_HEADER {
        return None;
    }

    match packet[0] >> 4 {
        IP_VERSION_4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER || packet.len() < ihl + 8 {
                return None;
            }
            if packet[9] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            Some((src, dst))
        }
        IP_VERSION_6 => {
            if packet.len() < IPV6_MIN_HEADER + 8 {
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

    /// Helper to create a random EndpointId for testing
    fn random_endpoint_id() -> EndpointId {
        let bytes: [u8; 32] = rand::random();
        let secret = iroh::SecretKey::from_bytes(&bytes);
        secret.public()
    }

    #[test]
    fn test_advertised_networks_are_server_host_prefixes() {
        // Clients must only ever be told to route the server itself — never the
        // full VPN subnet (inter-client traffic is dropped server-side).
        let ip4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let ip6: Ipv6Addr = "fd00::1".parse().unwrap();
        assert_eq!(host_net4(ip4), "10.0.0.1/32".parse::<Ipv4Net>().unwrap());
        assert_eq!(host_net6(ip6), "fd00::1/128".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn test_advertised_client_mtu_clamped_to_datagram_safe() {
        assert_eq!(advertised_client_mtu(1500), DATAGRAM_SAFE_MTU);
        assert_eq!(advertised_client_mtu(DATAGRAM_SAFE_MTU), DATAGRAM_SAFE_MTU);
        assert_eq!(advertised_client_mtu(1200), 1200);
    }

    #[test]
    fn test_ip_pool_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        // Server should get .1
        assert_eq!(pool.server_ip(), Ipv4Addr::new(10, 0, 0, 1));

        // Allocate IPs for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1).unwrap();
        let ip2 = pool.allocate(id2, 1).unwrap();

        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Re-allocate same client should return same IP
        let ip1_again = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, ip1_again);

        // Release and reallocate
        pool.release(&id1, 1);
        let id3 = random_endpoint_id();
        let ip3 = pool.allocate(id3, 1).unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_ip_pool_reserve_next_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_next_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_ip_pool_reserve_last_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_last_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 254));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_ip_pool_reserve_last_available_slash30() {
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_last_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_none());
    }

    #[test]
    fn test_ip_pool_reserve_specific_ip_skips_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved_ip = Ipv4Addr::new(10, 0, 0, 5);
        pool.reserve_ip(reserved_ip, "reserved").unwrap();

        let mut assigned = Vec::new();
        for _ in 0..4 {
            let id = random_endpoint_id();
            assigned.push(pool.allocate(id, 1).unwrap());
        }

        assert_eq!(
            assigned,
            vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 4),
                Ipv4Addr::new(10, 0, 0, 6),
            ]
        );
    }

    #[test]
    fn test_ip_pool_reserve_ip_validation_and_idempotency() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 1), "ip").is_err());
        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 0), "ip").is_err());
        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 255), "ip").is_err());
        assert!(
            pool.reserve_ip(Ipv4Addr::new(192, 168, 1, 1), "ip")
                .is_err()
        );

        let reserved = pool.reserve_next_available().unwrap();
        let id1 = random_endpoint_id();
        let assigned = pool.allocate(id1, 1).unwrap();
        assert!(pool.reserve_ip(assigned, "ip").is_err());

        let free_ip = reserved;
        assert!(pool.reserve_ip(free_ip, "ip").is_ok());
        assert!(pool.reserve_ip(free_ip, "ip").is_ok());
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        // Use a tiny /30 network (2 usable hosts)
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        // Server uses .1, only .2 available for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2, 1);
        assert!(ip2.is_none()); // Pool exhausted
    }

    #[test]
    fn test_extract_dest_ip_v4() {
        // Valid IPv4 packet header (minimal)
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 5;

        match extract_dest_ip(&packet) {
            Some(PacketIp::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 5));
            }
            _ => panic!("Expected IPv4 destination"),
        }

        // Too short for IPv4
        assert!(extract_dest_ip(&[0x45u8; 10]).is_none());
    }

    #[test]
    fn test_extract_dest_ip_v6() {
        // Valid IPv6 packet header (40 bytes minimum)
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // Version 6
        // Destination at bytes 24-39
        packet[24..40].copy_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05,
        ]);

        match extract_dest_ip(&packet) {
            Some(PacketIp::V6(ip)) => {
                assert_eq!(ip, "fd00::5".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected IPv6 destination"),
        }

        // Too short for IPv6
        let mut short_packet = [0u8; 20];
        short_packet[0] = 0x60;
        assert!(extract_dest_ip(&short_packet).is_none());
    }

    #[test]
    fn test_extract_dest_ip_unknown_version() {
        // Empty packet
        assert!(extract_dest_ip(&[]).is_none());

        // Unknown version
        let mut packet = [0u8; 40];
        packet[0] = 0x50; // Version 5 (invalid)
        assert!(extract_dest_ip(&packet).is_none());
    }

    #[test]
    fn test_extract_source_ip_v4() {
        // Valid IPv4 packet header (minimal)
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        // Source at bytes 12-15
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;

        match extract_source_ip(&packet) {
            Some(PacketIp::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected IPv4 source"),
        }

        // Too short for IPv4
        assert!(extract_source_ip(&[0x45u8; 10]).is_none());
    }

    #[test]
    fn test_extract_source_ip_v6() {
        // Valid IPv6 packet header (40 bytes minimum)
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // Version 6
        // Source at bytes 8-23
        packet[8..24].copy_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        match extract_source_ip(&packet) {
            Some(PacketIp::V6(ip)) => {
                assert_eq!(ip, "fd00::2".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected IPv6 source"),
        }

        // Too short for IPv6
        let mut short_packet = [0u8; 20];
        short_packet[0] = 0x60;
        assert!(extract_source_ip(&short_packet).is_none());
    }

    #[test]
    fn test_extract_source_ip_unknown_version() {
        // Empty packet
        assert!(extract_source_ip(&[]).is_none());

        // Unknown version
        let mut packet = [0u8; 40];
        packet[0] = 0x50; // Version 5 (invalid)
        assert!(extract_source_ip(&packet).is_none());
    }

    #[test]
    fn test_ip6_pool_allocation() {
        let network: Ipv6Net = "fd00::/120".parse().unwrap();
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::Sequential, random_endpoint_id()).unwrap();

        // Server should get ::1
        assert_eq!(pool.server_ip(), "fd00::1".parse::<Ipv6Addr>().unwrap());

        // Allocate IPs for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1).unwrap();
        let ip2 = pool.allocate(id2, 1).unwrap();

        assert_eq!(ip1, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip2, "fd00::3".parse::<Ipv6Addr>().unwrap());

        // Re-allocate same client should return same IP
        let ip1_again = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, ip1_again);

        // Release and reallocate
        pool.release(&id1, 1);
        let id3 = random_endpoint_id();
        let ip3 = pool.allocate(id3, 1).unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_ip6_pool_exhaustion() {
        // Use a tiny /126 network (4 addresses: ::0 network, ::1 server, ::2 client, ::3 last)
        let network: Ipv6Net = "fd00::/126".parse().unwrap();
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::Sequential, random_endpoint_id()).unwrap();

        // Server uses ::1, only ::2 available for clients (::3 is excluded as last address)
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2, 1);
        assert!(ip2.is_none()); // Pool exhausted
    }

    #[test]
    fn test_ip6_pool_rejects_slash127() {
        // /127 network has only 2 addresses - too small for server + clients
        let network: Ipv6Net = "fd00::/127".parse().unwrap();
        let result = Ip6Pool::new(network, None, Ip6Strategy::Sequential, random_endpoint_id());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, VpnError::Config(_)),
            "Expected Config error, got {:?}",
            err
        );
    }

    #[test]
    fn test_ip6_pool_rejects_slash128() {
        // /128 is a single-address network - unusable for VPN pool
        let network: Ipv6Net = "fd00::/128".parse().unwrap();
        let result = Ip6Pool::new(network, None, Ip6Strategy::Sequential, random_endpoint_id());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, VpnError::Config(_)),
            "Expected Config error, got {:?}",
            err
        );
    }

    // =========================================================================
    // Ip6Pool node-id strategy tests
    // =========================================================================

    /// Helper to create a fixed (deterministic) EndpointId for testing
    fn fixed_endpoint_id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn test_ip6_nodeid_deterministic() {
        // Same node id must derive the same address across pool instances
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let server_id = fixed_endpoint_id(1);
        let client_id = fixed_endpoint_id(2);

        let mut pool1 = Ip6Pool::new(network, None, Ip6Strategy::NodeId, server_id).unwrap();
        let mut pool2 = Ip6Pool::new(network, None, Ip6Strategy::NodeId, server_id).unwrap();

        let ip1 = pool1.allocate(client_id, 1).unwrap();
        let ip2 = pool2.allocate(client_id, 99).unwrap();
        assert_eq!(ip1, ip2);
        assert_eq!(ip1, derived_ip6(network, &client_id));

        // Idempotent for the same (endpoint, device) key
        assert_eq!(pool1.allocate(client_id, 1).unwrap(), ip1);
    }

    #[test]
    fn test_ip6_nodeid_distinct_ids_distinct_ips() {
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::NodeId, fixed_endpoint_id(1)).unwrap();

        let ip_a = pool.allocate(fixed_endpoint_id(2), 1).unwrap();
        let ip_b = pool.allocate(fixed_endpoint_id(3), 1).unwrap();
        assert_ne!(ip_a, ip_b);
        assert!(network.contains(&ip_a));
        assert!(network.contains(&ip_b));
    }

    #[test]
    fn test_ip6_nodeid_server_ip_derived() {
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let server_id = fixed_endpoint_id(1);
        let pool = Ip6Pool::new(network, None, Ip6Strategy::NodeId, server_id).unwrap();

        assert_eq!(pool.server_ip(), derived_ip6(network, &server_id));
        assert!(network.contains(&pool.server_ip()));
    }

    #[test]
    fn test_ip6_nodeid_wider_prefix_in_subnet() {
        // Wider than /64 (e.g., /56) is allowed; suffix masking keeps the
        // derived address in-subnet
        let network: Ipv6Net = "fd00:aa00::/56".parse().unwrap();
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::NodeId, fixed_endpoint_id(1)).unwrap();

        let ip = pool.allocate(fixed_endpoint_id(2), 1).unwrap();
        assert!(network.contains(&ip));
        assert!(network.contains(&pool.server_ip()));
    }

    #[test]
    fn test_ip6_nodeid_rejects_narrower_than_slash64() {
        let network: Ipv6Net = "fd00::/65".parse().unwrap();
        let result = Ip6Pool::new(network, None, Ip6Strategy::NodeId, fixed_endpoint_id(1));

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("/64 or wider"));
    }

    #[test]
    fn test_ip6_nodeid_rejects_custom_server_ip() {
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let custom: Ipv6Addr = "fd00::1".parse().unwrap();
        let result = Ip6Pool::new(
            network,
            Some(custom),
            Ip6Strategy::NodeId,
            fixed_endpoint_id(1),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("server_ip6"));
    }

    #[test]
    fn test_ip6_nodeid_rejects_server_own_id() {
        // A client presenting the server's node id derives the server's
        // address and must be rejected
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let server_id = fixed_endpoint_id(1);
        let mut pool = Ip6Pool::new(network, None, Ip6Strategy::NodeId, server_id).unwrap();

        assert!(pool.allocate(server_id, 1).is_none());
    }

    #[test]
    fn test_ip6_nodeid_second_device_conflict() {
        // A second device of the same node id derives the same address ->
        // duplicate is rejected
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let client_id = fixed_endpoint_id(2);
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::NodeId, fixed_endpoint_id(1)).unwrap();

        assert!(pool.allocate(client_id, 1).is_some());
        assert!(pool.allocate(client_id, 2).is_none());
    }

    #[test]
    fn test_ip6_nodeid_release_realloc_same_ip() {
        let network: Ipv6Net = "fd00::/64".parse().unwrap();
        let client_id = fixed_endpoint_id(2);
        let mut pool =
            Ip6Pool::new(network, None, Ip6Strategy::NodeId, fixed_endpoint_id(1)).unwrap();

        let ip = pool.allocate(client_id, 1).unwrap();
        pool.release(&client_id, 1);
        assert_eq!(pool.allocate(client_id, 2).unwrap(), ip);
    }

    // =========================================================================
    // VpnServerStats tests
    // =========================================================================

    #[test]
    fn test_stats_initial_zero() {
        let stats = VpnServerStats::new();

        // All counters should be zero on initialization
        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats_counters_increment() {
        let stats = VpnServerStats::new();

        // Increment some counters
        stats.tun_packets_read.fetch_add(100, Ordering::Relaxed);
        stats.packets_to_clients.fetch_add(90, Ordering::Relaxed);
        stats.packets_no_route.fetch_add(5, Ordering::Relaxed);
        stats.packets_spoofed.fetch_add(3, Ordering::Relaxed);
        stats.packets_backpressure.fetch_add(2, Ordering::Relaxed);

        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 100);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 90);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 5);
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 2);
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats_no_route_simulation() {
        // Simulate the no-route counter being incremented when routing fails
        let stats = VpnServerStats::new();
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let ip_to_endpoint: DashMap<Ipv4Addr, (EndpointId, u64)> = DashMap::new();

        // Register one client
        let client_id = random_endpoint_id();
        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        ip_to_endpoint.insert(client_ip, (client_id, 1));

        // Create packet destined for registered client - should find route
        let mut packet_to_client = [0u8; 20];
        packet_to_client[0] = 0x45; // IPv4
        packet_to_client[16..20].copy_from_slice(&client_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_to_client)
            && ip_to_endpoint.get(&dest).is_none()
        {
            stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 0);

        // Create packet destined for unknown IP - should increment no_route
        let unknown_ip = Ipv4Addr::new(10, 0, 0, 99);
        let mut packet_to_unknown = [0u8; 20];
        packet_to_unknown[0] = 0x45; // IPv4
        packet_to_unknown[16..20].copy_from_slice(&unknown_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_to_unknown)
            && ip_to_endpoint.get(&dest).is_none()
        {
            stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 1);

        // Packet destined outside network entirely
        let external_ip = Ipv4Addr::new(192, 168, 1, 1);
        let mut packet_external = [0u8; 20];
        packet_external[0] = 0x45;
        packet_external[16..20].copy_from_slice(&external_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_external)
            && (!network.contains(&dest) || ip_to_endpoint.get(&dest).is_none())
        {
            stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_inter_client_drop_simulation() {
        // Mirrors the destination lookup performed in `handle_client_data`:
        // a packet addressed to another VPN client's assigned IP is dropped,
        // while a packet to the server/gateway IP (not in the maps) is kept.
        let stats = VpnServerStats::new();
        let ip_to_endpoint: DashMap<Ipv4Addr, (EndpointId, u64)> = DashMap::new();
        let ip6_to_endpoint: DashMap<Ipv6Addr, (EndpointId, u64)> = DashMap::new();

        // Register a peer client (IPv4 + IPv6).
        let peer_id = random_endpoint_id();
        let peer_ip4 = Ipv4Addr::new(10, 0, 0, 5);
        let peer_ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5);
        ip_to_endpoint.insert(peer_ip4, (peer_id, 1));
        ip6_to_endpoint.insert(peer_ip6, (peer_id, 1));

        let is_to_vpn_client = |packet: &[u8]| match extract_dest_ip(packet) {
            Some(PacketIp::V4(dst)) => ip_to_endpoint.contains_key(&dst),
            Some(PacketIp::V6(dst)) => ip6_to_endpoint.contains_key(&dst),
            None => false,
        };

        // IPv4 packet to another client -> dropped.
        let mut v4_to_client = [0u8; 20];
        v4_to_client[0] = 0x45;
        v4_to_client[16..20].copy_from_slice(&peer_ip4.octets());
        if is_to_vpn_client(&v4_to_client) {
            stats
                .packets_inter_client_blocked
                .fetch_add(1, Ordering::Relaxed);
        }

        // IPv6 packet to another client -> dropped.
        let mut v6_to_client = [0u8; 40];
        v6_to_client[0] = 0x60;
        v6_to_client[24..40].copy_from_slice(&peer_ip6.octets());
        if is_to_vpn_client(&v6_to_client) {
            stats
                .packets_inter_client_blocked
                .fetch_add(1, Ordering::Relaxed);
        }

        assert_eq!(
            stats.packets_inter_client_blocked.load(Ordering::Relaxed),
            2
        );

        // Packet to the server/gateway IP (never inserted into the maps) -> kept.
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut v4_to_gateway = [0u8; 20];
        v4_to_gateway[0] = 0x45;
        v4_to_gateway[16..20].copy_from_slice(&gateway_ip.octets());
        assert!(!is_to_vpn_client(&v4_to_gateway));
        assert_eq!(
            stats.packets_inter_client_blocked.load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn test_stats_unknown_version_simulation() {
        let stats = VpnServerStats::new();

        // Valid IPv4 packet - should not increment unknown_version
        let ipv4_packet = [0x45u8; 20];
        if extract_dest_ip(&ipv4_packet).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);

        // Invalid version (5) packet - should increment unknown_version
        let mut invalid_packet = [0u8; 40];
        invalid_packet[0] = 0x50; // Version 5
        if extract_dest_ip(&invalid_packet).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 1);

        // Empty packet - should increment unknown_version
        if extract_dest_ip(&[]).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stats_spoofing_detection_simulation() {
        // Simulate IP spoofing detection logic from handle_client_data
        let stats = VpnServerStats::new();

        // Client is assigned 10.0.0.2
        let assigned_ip = Ipv4Addr::new(10, 0, 0, 2);

        // Packet with correct source IP - not spoofed
        let mut valid_packet = [0u8; 20];
        valid_packet[0] = 0x45; // IPv4
        valid_packet[12..16].copy_from_slice(&assigned_ip.octets());

        let source_valid = match extract_source_ip(&valid_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 0);

        // Packet with wrong source IP - spoofed!
        let spoofed_ip = Ipv4Addr::new(10, 0, 0, 99);
        let mut spoofed_packet = [0u8; 20];
        spoofed_packet[0] = 0x45; // IPv4
        spoofed_packet[12..16].copy_from_slice(&spoofed_ip.octets());

        let source_valid = match extract_source_ip(&spoofed_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 1);

        // Packet with unparseable source - also treated as spoofed
        let bad_packet = [0x45u8; 10]; // Too short
        let source_valid = match extract_source_ip(&bad_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stats_backpressure_and_drop_simulation() {
        // Simulate the backpressure/drop logic from run_tun_reader
        let stats = VpnServerStats::new();

        // Create a tiny channel that will fill up immediately
        let (tx, mut rx) = mpsc::channel::<u8>(1);

        // First send succeeds
        if tx.try_send(1).is_ok() {
            stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 1);

        // Second send fails (channel full) - simulate drop_on_full=true
        let drop_on_full = true;
        match tx.try_send(2) {
            Ok(()) => {
                stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if drop_on_full {
                    stats.packets_dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.packets_backpressure.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 1);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 0);

        // Drain the channel
        let _ = rx.try_recv();

        // Simulate drop_on_full=false (backpressure mode)
        let _ = tx.try_send(3); // Fill the channel again

        let drop_on_full = false;
        match tx.try_send(4) {
            Ok(()) => {
                stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if drop_on_full {
                    stats.packets_dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.packets_backpressure.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 1);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_tun_write_failed_simulation() {
        let stats = VpnServerStats::new();

        // Simulate TUN write failures being tracked
        // In real code this happens in handle_client_data when tun_write_tx fails

        // Successful write (channel open)
        stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 1);

        // Failed write (channel closed)
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 1);

        // Multiple failures
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_stats_concurrent_increments() {
        use std::thread;

        // Test that atomic counters work correctly under concurrent access
        let stats = Arc::new(VpnServerStats::new());
        let mut handles = vec![];

        // Spawn multiple threads incrementing different counters
        for _ in 0..10 {
            let stats = stats.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);
                    stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
                    stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Each of 10 threads incremented 1000 times = 10000 total
        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 10000);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 10000);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 10000);
    }

    #[test]
    fn test_ip_in_overlay_excludes_only_vpn_overlay() {
        let v4: Ipv4Net = "10.99.0.0/24".parse().unwrap();
        let v6: Ipv6Net = "fd11:9a0b:1095:99::/64".parse().unwrap();

        // The server's own VPN overlay gateway must be treated as overlay.
        assert!(ip_in_overlay(
            "10.99.0.1".parse().unwrap(),
            Some(v4),
            Some(v6)
        ));
        assert!(ip_in_overlay(
            "fd11:9a0b:1095:99::1".parse().unwrap(),
            Some(v4),
            Some(v6)
        ));

        // Real underlay addresses (public or private LAN) are NOT overlay: a peer
        // on that private network legitimately uses them for transport.
        assert!(!ip_in_overlay(
            "172.31.150.233".parse().unwrap(),
            Some(v4),
            Some(v6)
        ));
        assert!(!ip_in_overlay(
            "44.230.20.120".parse().unwrap(),
            Some(v4),
            Some(v6)
        ));
        assert!(!ip_in_overlay(
            "2600:1f13:adc:a0b1:feb9:cb56:f64e:b6f8".parse().unwrap(),
            Some(v4),
            Some(v6)
        ));

        // With no overlay configured, nothing is excluded.
        assert!(!ip_in_overlay("10.99.0.1".parse().unwrap(), None, None));
    }
}
