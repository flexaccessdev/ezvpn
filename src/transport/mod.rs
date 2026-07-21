//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! All transport settings are fixed constants, WireGuard/Tailscale-style:
//! there are no tuning knobs, nothing is negotiated, and both sides build the
//! identical config from [`build_quic_transport_config`].

pub mod endpoint;
pub mod paths;

use anyhow::{Context, Result};
use iroh::endpoint::QuicTransportConfig;
use noq_proto::congestion::Bbr3Config;
use std::sync::Arc;
use std::time::Duration;

/// QUIC keep-alive interval for tunnel connections.
///
/// Active connections send pings at this interval to prevent idle timeout.
/// This value matches iroh's relay ping interval (15s), which is designed to be
/// well under half common QUIC idle timeout defaults (30s is typical in many
/// implementations and protocol discussions). This codebase sets
/// [`QUIC_IDLE_TIMEOUT`] to 30s, and 15s keep-alive remains appropriate for NAT
/// traversal and prompt dead-connection detection.
///
/// For long-running tunnels, 15s is a good balance between:
/// - Keeping NAT mappings alive (most NAT timeouts are 30-120s)
/// - Not wasting bandwidth with excessive pings
/// - Detecting dead connections reasonably quickly
///
/// Reference: iroh uses 1s for endpoint default, 15s for relay pings.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout for tunnel connections.
///
/// Connections without activity (no data or keep-alive pings) for this duration
/// are considered dead and closed. With [`QUIC_KEEP_ALIVE_INTERVAL`] enabled,
/// this timeout only triggers for truly unresponsive peers.
///
/// The data path is unreliable QUIC datagrams with no application-level
/// heartbeat: peer liveness is detected entirely by QUIC keep-alive plus this
/// idle timeout (a dead peer stops sending keep-alives and the connection
/// closes after this elapses, resolving `Connection::closed()`). 30s gives
/// prompt dead-peer detection while comfortably exceeding the 15s keep-alive
/// interval so a single lost keep-alive never trips it.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval at which the server re-publishes its candidate iroh underlay
/// addresses to each connected client (on the data stream).
///
/// The server also publishes once immediately on connect and promptly whenever
/// `Endpoint::watch_addr()` reports a change; this interval is the recovery
/// floor for a publication skipped because the client's outbound queue was
/// full. The client merges the set add-only into its bypass-route manager, so
/// a newly learned server address is pinned off the VPN tunnel within at most
/// this interval even if iroh has not yet selected it for the active path.
pub const SERVER_ADDR_PUBLISH_INTERVAL: Duration = Duration::from_secs(30);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
///
/// noq conservatively reserves at most 50 bytes for the QUIC short header,
/// connection ID, packet number, AEAD tag, and DATAGRAM frame encoding. Adding
/// that bound to the fixed inner MTU guarantees a complete VPN packet fits
/// immediately after the handshake without assuming a 1500-byte underlay.
/// Starting at QUIC's 1200-byte protocol minimum made the live datagram limit
/// smaller than the TUN MTU, dropping full-sized inner TCP packets for several
/// seconds while DPLPMTUD ramped upward.
///
/// DPLPMTUD and its 1200-byte minimum remain enabled, so a genuinely smaller
/// underlay is detected and corrected downward. Such a path cannot carry the
/// fixed 1280-byte inner MTU without fragmentation in any case.
pub const QUIC_DATAGRAM_OVERHEAD_BUDGET: u16 = 50;
pub const QUIC_INITIAL_MTU: u16 = crate::config::VPN_MTU + QUIC_DATAGRAM_OVERHEAD_BUDGET;

/// QUIC connection/stream receive window and send window (bytes).
///
/// A fixed 8 MB, enough to keep a high-bandwidth-delay-product path busy
/// without unbounded buffering. Like WireGuard's fixed internal queue sizes,
/// this is a constant, not a knob.
pub const QUIC_WINDOW_SIZE: u32 = 8 * 1024 * 1024;

/// QUIC unreliable-datagram receive buffer size (bytes).
///
/// The data path maps each IP packet directly to one unreliable QUIC datagram,
/// so datagrams must be enabled (a `None` receive buffer would tell the peer we
/// cannot receive them). A full receive buffer drops the oldest queued
/// datagrams; 4 MB gives the application enough headroom to drain scheduler
/// bursts without making the kernel socket size part of the protocol.
pub const QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// QUIC unreliable-datagram send queue size (bytes).
///
/// This is deliberately much smaller than the receive queue. The application
/// uses `send_datagram_wait`, so this is a bounded handoff to QUIC's pacer and
/// congestion controller, not a multi-megabyte reservoir of stale inner TCP
/// packets. Keeping roughly 200 MTU-sized packets absorbs scheduler jitter
/// while applying backpressure before latency and loss multiply.
pub const QUIC_DATAGRAM_SEND_BUFFER_SIZE: usize = 256 * 1024;

/// Build the fixed QUIC transport config used by both client and server.
///
/// Every setting is a constant: BBRv3 congestion control, 8 MB windows, the
/// keep-alive/idle timers above, and the protocol-minimum initial MTU. Both
/// sides applying the identical config means nothing has to be negotiated.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    // Configure transport with keep-alive and idle timeout.
    // See QUIC_KEEP_ALIVE_INTERVAL and QUIC_IDLE_TIMEOUT constants for rationale.
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);

    // BBRv3 uses a bandwidth/RTT model and explicitly paces transmissions. That
    // is important for a VPN carrying TCP inside QUIC DATAGRAMs: CUBIC reacts
    // to the same loss as the inner TCP connection, multiplying congestion-window
    // reductions, while bursty sends overflow small platform UDP socket queues.
    transport_config =
        transport_config.congestion_controller_factory(Arc::new(Bbr3Config::default()));

    // Fixed flow-control windows for connection + streams.
    transport_config = transport_config.receive_window(QUIC_WINDOW_SIZE.into());
    transport_config = transport_config.stream_receive_window(QUIC_WINDOW_SIZE.into());
    transport_config = transport_config.send_window(QUIC_WINDOW_SIZE.into());

    // Start large enough for the fixed inner MTU (see QUIC_INITIAL_MTU).
    // Discovery config and min_mtu keep their defaults, including downward
    // black-hole recovery for smaller paths.
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);

    // The data path maps each IP packet to one unreliable QUIC datagram, so
    // datagrams must be enabled in both directions (a `None` receive buffer
    // advertises to the peer that we cannot receive them).
    transport_config =
        transport_config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport_config =
        transport_config.datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_SIZE);

    Ok(transport_config.build())
}
