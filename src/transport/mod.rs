//! QUIC transport configuration shared by endpoint setup and per-connection
//! transport upgrades.
//!
//! The server applies [`TransportTuning`] to its endpoint and dictates the
//! resolved values to clients in the handshake response. Clients connect with
//! the default baseline and, on mismatch, reconnect with a per-connection
//! transport config built here.

pub mod endpoint;
pub mod paths;

use crate::config::file_config::{CongestionController, TransportTuning};
use anyhow::{Context, Result};
use iroh::endpoint::{ControllerFactory, QuicTransportConfig};
use log::info;
use noq_proto::congestion::{Bbr3Config, CubicConfig, NewRenoConfig};
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
/// addresses to each connected client (on the unreliable datagram path).
///
/// The server also publishes once immediately on connect and promptly whenever
/// `Endpoint::watch_addr()` reports a change; this interval is the loss-tolerance
/// floor (a dropped publication datagram is recovered within one tick). The
/// client merges the set add-only into its bypass-route manager, so a newly
/// learned server address is pinned off the VPN tunnel within at most this
/// interval even if iroh has not yet selected it for the active path.
pub const SERVER_ADDR_PUBLISH_INTERVAL: Duration = Duration::from_secs(30);

/// Per-direction QUIC datagram buffer size (bytes).
///
/// The QUIC-level analog of the OS socket `SO_RCVBUF`/`SO_SNDBUF`: it bounds how
/// much datagram data quinn queues before shedding. A few MiB lets the stack
/// absorb a multi-Gbit burst that briefly outpaces the userspace reader/writer
/// instead of dropping datagrams (which surface as inner-TCP retransmits).
pub const QUIC_DATAGRAM_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Kernel UDP socket buffer size that iroh's socket layer (netwatch) requests
/// for `SO_RCVBUF`/`SO_SNDBUF`. Mirrors netwatch's private `SOCKET_BUFFER_SIZE`
/// (`7 << 20`); kept here so the startup check warns against the same target.
///
/// Linux silently caps the request at `net.core.rmem_max` / `net.core.wmem_max`,
/// so iroh's buffer is only this large when those sysctls are at least this
/// value. We cannot read the applied size back (iroh owns the socket), so the
/// startup check warns when the sysctl would clamp it.
// Only the Linux startup check (`warn_if_socket_buffer_capped`) reads this, since
// the `net.core.*_max` clamp it guards against is Linux-specific.
#[cfg(target_os = "linux")]
pub const IROH_SOCKET_BUFFER_REQUEST: usize = 7 << 20; // 7 MiB

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
///
/// 1200 is the QUIC protocol minimum (and quinn's `min_mtu` default), so the
/// very first datagrams survive *any* path — cellular, tunnel-in-tunnel, PPPoE —
/// with no early black-holing. DPLPMTUD's first run happens right after the
/// handshake and binary-searches upward to its default `upper_bound` (1452), so
/// LAN/broadband paths reach full size within a few RTTs.
///
/// The primary deployment target is mobile / high-latency internet access, where
/// an optimistic initial MTU (e.g. 1452) causes persistent datagram drops on
/// paths with a smaller real MTU. Reliability from packet one is worth the brief
/// ramp-up; the data path reads the *live* `max_datagram_size` per TUN read, so
/// framing follows discovery as the path MTU rises (or falls). `min_mtu` and MTU
/// discovery keep their defaults.
pub const QUIC_INITIAL_MTU: u16 = 1200;

/// Create a congestion controller factory based on the selected algorithm.
fn create_congestion_controller_factory(
    controller: CongestionController,
) -> Arc<dyn ControllerFactory + Send + Sync> {
    match controller {
        CongestionController::Cubic => Arc::new(CubicConfig::default()),
        CongestionController::Bbr => {
            // noq-proto 1.0 removed the original BBR implementation; Bbr3 is
            // its replacement but is marked experimental upstream.
            info!("BBR congestion control is backed by the experimental Bbr3 implementation");
            Arc::new(Bbr3Config::default())
        }
        CongestionController::NewReno => Arc::new(NewRenoConfig::default()),
    }
}

/// Build a QUIC transport config with keep-alive, idle timeout, and tuning.
///
/// Shared by endpoint creation and per-connection transport upgrades so both
/// paths apply identical settings.
pub fn build_quic_transport_config(tuning: &TransportTuning) -> Result<QuicTransportConfig> {
    // Configure transport with keep-alive and idle timeout.
    // See QUIC_KEEP_ALIVE_INTERVAL and QUIC_IDLE_TIMEOUT constants for rationale.
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);

    // Set congestion controller
    let factory = create_congestion_controller_factory(tuning.congestion_controller);
    transport_config = transport_config.congestion_controller_factory(factory);
    info!(
        "Using {:?} congestion controller",
        tuning.congestion_controller
    );

    // Set receive window (flow control) for connection + streams, and send
    // window (defaults to receive window if not specified)
    let (receive_window, send_window) = tuning.effective_windows();
    transport_config = transport_config.receive_window(receive_window.into());
    transport_config = transport_config.stream_receive_window(receive_window.into());
    transport_config = transport_config.send_window(send_window.into());

    let recv_source = if tuning.receive_window.is_none() {
        "default"
    } else {
        "config"
    };
    let send_source = if tuning.send_window.is_none() {
        if tuning.receive_window.is_none() {
            "default"
        } else {
            "derived"
        }
    } else {
        "config"
    };
    info!(
        "Transport windows: stream/receive={}KB ({}), send={}KB ({})",
        receive_window / 1024,
        recv_source,
        send_window / 1024,
        send_source
    );

    // Start at the protocol-minimum path MTU so the first datagrams survive any
    // path (see QUIC_INITIAL_MTU); MTU discovery probes upward right after the
    // handshake. Discovery config and min_mtu keep their defaults.
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    info!(
        "Transport MTU: initial={} (discovery enabled)",
        QUIC_INITIAL_MTU
    );

    // Enable and size the QUIC datagram buffers (the data path is datagrams).
    // `datagram_receive_buffer_size(Some(..))` keeps datagram receipt enabled;
    // both directions get a few MiB of burst tolerance.
    transport_config =
        transport_config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER_SIZE));
    transport_config = transport_config.datagram_send_buffer_size(QUIC_DATAGRAM_BUFFER_SIZE);
    info!(
        "Transport datagram buffers: recv/send={}KB each",
        QUIC_DATAGRAM_BUFFER_SIZE / 1024
    );

    Ok(transport_config.build())
}
