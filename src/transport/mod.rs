//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! All transport settings are fixed constants, WireGuard/Tailscale-style:
//! there are no tuning knobs, nothing is negotiated, and both sides build the
//! identical config from [`build_quic_transport_config`].
//!
//! The single exception is congestion control, which the CLI can override with
//! `--congestion-control` and `--congestion-initial-window` (see
//! [`CongestionConfig`] and [`set_congestion_config`]). It exists so a different
//! controller or a different initial window can be benchmarked without
//! rebuilding, is *not* readable from a config file, and is not part of the
//! protocol: each side picks its own sender-side controller, so nothing has to
//! match across the tunnel.

pub mod endpoint;
pub mod path_selector;
pub mod paths;

use anyhow::{Context, Result};
use iroh::endpoint::{AckFrequencyConfig, QuicTransportConfig, VarInt};
use noq_proto::congestion::{Bbr3Config, ControllerFactory, CubicConfig, NewRenoConfig};
use std::fmt;
use std::sync::{Arc, OnceLock};
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
/// A dead peer stops sending keep-alives and the connection closes after this
/// elapses, resolving `Connection::closed()`. 30s gives prompt dead-peer
/// detection while comfortably exceeding the 15s keep-alive interval so a single
/// lost keep-alive never trips it. It is backed by the application heartbeat
/// ([`HEARTBEAT_INTERVAL`] / [`HEARTBEAT_TIMEOUT`]), which does not depend on
/// the QUIC layer noticing the loss.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval at which the client sends an application `Ping` on the control
/// stream; the server answers each with a `Pong`.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// How long either side waits for heartbeat traffic before declaring the
/// session dead: the client for a `Pong`, the server for a `Ping`.
///
/// QUIC keep-alive only proves that *something* acknowledges packets at the
/// transport layer, and a client has been seen sitting "connected" through the
/// relay after a server restart until the user reconnected by hand. The
/// heartbeat is answered
/// by the server's per-client session itself, so it fails whenever that session
/// is gone, however the transport behaves. Three missed intervals: a single
/// late reply on a lossy path never trips it.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Number of ack-eliciting packets the peer may receive before it must send an
/// ACK (QUIC ACK Frequency extension).
///
/// Each tunneled IP packet is one QUIC packet, so a bulk TCP flow through the
/// tunnel runs at >100k packets/s; the default threshold of 1 (ACK every other
/// packet) makes ACK generation and processing a first-order CPU cost on both
/// endpoints. 15 (one ACK per 16 packets) cuts that cost by ~8x while staying
/// small next to the congestion window on any path this VPN targets.
pub const QUIC_ACK_ELICITING_THRESHOLD: u32 = 15;

/// Number of out-of-order ack-eliciting packets that trigger an immediate ACK
/// from the peer, bypassing [`QUIC_ACK_ELICITING_THRESHOLD`].
///
/// Pinned to 1 — the behavior QUIC has without the ACK Frequency extension —
/// so any reordered packet is acknowledged immediately and the sender detects
/// loss as promptly as with per-packet ACKs. The
/// noq default of 2 would delay that signal by a packet; only in-order bulk
/// flow is meant to benefit from the reduced ACK rate.
pub const QUIC_ACK_REORDERING_THRESHOLD: u32 = 1;

/// Congestion controller for the QUIC tunnel connection.
///
/// [`CongestionControl::Cubic`] is the default and what production runs; the
/// other variants exist so alternatives can be measured on a real path without
/// recompiling. The controller only governs the local sender, so the two ends
/// of a tunnel may run different ones.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CongestionControl {
    /// Paced BBRv3: a bandwidth/RTT model that keeps the queue shorter at a
    /// deep-buffered bottleneck, but measured slower than Cubic on every path
    /// (see `build_quic_transport_config`).
    Bbr3,
    /// Loss-based CUBIC, the common TCP/QUIC default: what production runs
    /// (rationale in `build_quic_transport_config`).
    #[default]
    Cubic,
    /// Loss-based NewReno, the RFC 9002 reference controller.
    NewReno,
}

impl fmt::Display for CongestionControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Bbr3 => "bbr3",
            Self::Cubic => "cubic",
            Self::NewReno => "new-reno",
        };
        f.write_str(name)
    }
}

/// Smallest accepted `--congestion-initial-window`: two initial-MTU packets,
/// the floor RFC 9002 gives for the initial congestion window. Below this the
/// sender cannot even keep two packets in flight.
pub const CONGESTION_INITIAL_WINDOW_MIN: u64 = 2 * QUIC_INITIAL_MTU as u64;

/// Largest accepted `--congestion-initial-window`. Beyond the flow-control
/// window ([`QUIC_WINDOW_SIZE`]) the congestion window is no longer what limits
/// the sender, so a larger value would silently do nothing.
pub const CONGESTION_INITIAL_WINDOW_MAX: u64 = QUIC_WINDOW_SIZE as u64;

/// clap value parser for `--congestion-initial-window` (bytes).
///
/// Bounds live here rather than in the CLI so the accepted range stays tied to
/// the transport constants it is derived from. noq applies the value verbatim —
/// it neither clamps nor sanity-checks — so the range is enforced up front.
pub fn parse_congestion_initial_window(raw: &str) -> Result<u64, String> {
    let bytes: u64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("`{raw}` is not a byte count"))?;
    if !(CONGESTION_INITIAL_WINDOW_MIN..=CONGESTION_INITIAL_WINDOW_MAX).contains(&bytes) {
        return Err(format!(
            "must be between {CONGESTION_INITIAL_WINDOW_MIN} and \
             {CONGESTION_INITIAL_WINDOW_MAX} bytes (got {bytes})"
        ));
    }
    Ok(bytes)
}

/// The congestion-control settings the CLI may override, defaulting to what
/// production runs (Cubic with noq's stock initial window).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CongestionConfig {
    /// Which controller drives the local sender.
    pub control: CongestionControl,
    /// Initial congestion window in bytes, or `None` for the controller's
    /// stock value (noq: 14720 clamped to 2–10 base datagrams, i.e. 12000).
    /// Validated by [`parse_congestion_initial_window`].
    pub initial_window: Option<u64>,
}

impl CongestionConfig {
    /// The noq controller factory for these settings. Only the algorithm and
    /// its initial window are selectable; every other controller parameter
    /// keeps its noq default.
    fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync + 'static> {
        // Each config type has its own `initial_window` setter with no shared
        // trait, so the arms differ only in which one they build.
        match self.control {
            CongestionControl::Bbr3 => {
                let mut config = Bbr3Config::default();
                if let Some(window) = self.initial_window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
            CongestionControl::Cubic => {
                let mut config = CubicConfig::default();
                if let Some(window) = self.initial_window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
            CongestionControl::NewReno => {
                let mut config = NewRenoConfig::default();
                if let Some(window) = self.initial_window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
        }
    }
}

impl fmt::Display for CongestionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.control)?;
        match self.initial_window {
            Some(window) => write!(f, " (initial window {window} bytes)"),
            None => Ok(()),
        }
    }
}

/// Process-wide congestion-control settings, settable once by the CLI.
///
/// A global rather than a parameter because [`build_quic_transport_config`] is
/// also reached from the FFI entry points (iOS/Windows) and the relay probe,
/// none of which parse CLI arguments; threading a knob through them would put a
/// testing-only setting into every embedder's API.
static CONGESTION_CONFIG: OnceLock<CongestionConfig> = OnceLock::new();

/// Set and log the congestion-control settings for this process. Call once at
/// startup from the CLI, before any endpoint is created — the value is latched
/// on first use and a later call is ignored with a warning.
pub fn set_congestion_config(config: CongestionConfig) {
    if CONGESTION_CONFIG.set(config).is_err() {
        log::warn!(
            "congestion control already fixed to {}; ignoring override {config}",
            congestion_config()
        );
    } else {
        log::info!("QUIC congestion controller: {config}");
    }
}

/// The congestion-control settings in effect, latching the defaults on first use.
pub fn congestion_config() -> CongestionConfig {
    *CONGESTION_CONFIG.get_or_init(CongestionConfig::default)
}

/// Build the fixed QUIC transport config used by both client and server.
///
/// Every setting is a constant: Cubic congestion control, 8 MB windows, the
/// keep-alive/idle timers above, and the protocol-minimum initial MTU. Both
/// sides applying the identical config means nothing has to be negotiated. The
/// congestion controller is the one setting the CLI can change (see
/// [`set_congestion_config`]); it is sender-local, so it stays outside the
/// protocol even when the two ends differ.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    // Configure transport with keep-alive and idle timeout.
    // See QUIC_KEEP_ALIVE_INTERVAL and QUIC_IDLE_TIMEOUT constants for rationale.
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);

    // Cubic. Measured through the tunnel with one inner TCP flow, on a LAN path
    // and on emulated 40 ms paths (clean, 0.5% random loss, and a 200 Mbit/s
    // bottleneck with a ~1.4 BDP queue), Cubic moved 11-51% more than BBRv3 in
    // every case and filled the bottleneck (89% vs 75-80%). BBRv3's one gain was
    // a shorter queue at that bottleneck in the server->client direction (80 vs
    // 148 ms loaded RTT; barely any the other way, and more loaded latency than
    // Cubic on the LAN). Its premise for a tunnel, that the outer controller's
    // loss response multiplies the inner TCP's, did not show: under random loss
    // the inner TCP's own response caps the flow whichever controller runs
    // outside. `--congestion-control` / `--congestion-initial-window` can change
    // this for measurement.
    transport_config =
        transport_config.congestion_controller_factory(congestion_config().factory());

    // Fixed flow-control windows for connection + streams.
    transport_config = transport_config.receive_window(QUIC_WINDOW_SIZE.into());
    transport_config = transport_config.stream_receive_window(QUIC_WINDOW_SIZE.into());
    transport_config = transport_config.send_window(QUIC_WINDOW_SIZE.into());

    // Start large enough for the fixed inner MTU (see QUIC_INITIAL_MTU).
    // Discovery config and min_mtu keep their defaults, including downward
    // black-hole recovery for smaller paths.
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);

    // ACK frequency extension: the data path is one QUIC packet per IP packet,
    // so at high rates the default ACK-every-other-packet makes ACK generation
    // and processing a first-order CPU cost on both endpoints. Request an ACK
    // per QUIC_ACK_ELICITING_THRESHOLD ack-eliciting packets instead, with
    // the reordering threshold pinned to 1 so out-of-order packets are still
    // ACKed immediately (see the constants for rationale). Both sides run the
    // same build, so the extension always negotiates.
    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency.ack_eliciting_threshold(VarInt::from_u32(QUIC_ACK_ELICITING_THRESHOLD));
    ack_frequency.reordering_threshold(VarInt::from_u32(QUIC_ACK_REORDERING_THRESHOLD));
    transport_config = transport_config.ack_frequency_config(Some(ack_frequency));

    // The data path maps each IP packet to one unreliable QUIC datagram, so
    // datagrams must be enabled in both directions (a `None` receive buffer
    // advertises to the peer that we cannot receive them).
    transport_config =
        transport_config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport_config =
        transport_config.datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_SIZE);

    Ok(transport_config.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    // The CLI accepts exactly the names `Display` prints, so a value copied out
    // of a log line can be pasted back into `--congestion-control`.
    #[test]
    fn congestion_control_names_round_trip() {
        for choice in CongestionControl::value_variants() {
            let name = choice.to_string();
            assert_eq!(
                CongestionControl::from_str(&name, true).expect("parses its own name"),
                *choice
            );
        }
    }

    #[test]
    fn congestion_config_defaults_to_stock_cubic() {
        let config = CongestionConfig::default();
        assert_eq!(config.control, CongestionControl::Cubic);
        assert_eq!(config.initial_window, None);
        assert_eq!(config.to_string(), "cubic");
    }

    #[test]
    fn congestion_config_displays_initial_window_override() {
        let config = CongestionConfig {
            control: CongestionControl::Cubic,
            initial_window: Some(30_000),
        };
        assert_eq!(config.to_string(), "cubic (initial window 30000 bytes)");
    }

    // noq applies the initial window verbatim, so the CLI is the only place a
    // useless value (too small to keep two packets in flight, or above the
    // flow-control window) can be caught.
    #[test]
    fn initial_window_parser_enforces_bounds() {
        assert_eq!(
            parse_congestion_initial_window(" 30000 "),
            Ok(30_000),
            "whitespace is trimmed"
        );
        assert_eq!(
            parse_congestion_initial_window(&CONGESTION_INITIAL_WINDOW_MIN.to_string()),
            Ok(CONGESTION_INITIAL_WINDOW_MIN),
            "bounds are inclusive"
        );
        assert_eq!(
            parse_congestion_initial_window(&CONGESTION_INITIAL_WINDOW_MAX.to_string()),
            Ok(CONGESTION_INITIAL_WINDOW_MAX),
            "bounds are inclusive"
        );
        for rejected in [
            "0",
            "-1",
            "not-a-number",
            &(CONGESTION_INITIAL_WINDOW_MIN - 1).to_string(),
            &(CONGESTION_INITIAL_WINDOW_MAX + 1).to_string(),
        ] {
            assert!(
                parse_congestion_initial_window(rejected).is_err(),
                "{rejected} should be rejected"
            );
        }
    }
}
