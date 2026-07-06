//! ezvpn
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses ezvpn auth tokens for access control and TLS 1.3/QUIC for encryption.
//!
//! This is the library crate. The desktop CLI (`src/main.rs`) and the iOS
//! Network Extension FFI (`src/ffi.rs`, built into a `staticlib`) both consume
//! it. Desktop platforms (Linux/macOS/Windows) get the full client/server with
//! TUN creation, routing, single-instance lock, and the control socket. iOS gets
//! only the portable data plane (iroh connect + handshake + data-stream loop) and
//! drives an OS-provided `utun` fd — routing and IP configuration are owned by
//! the `NEPacketTunnelProvider`, not this crate.

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "ios"
)))]
compile_error!("ezvpn only supports Linux, macOS, Windows, and iOS");

pub mod auth;
pub mod config;
pub mod error;
pub mod net;
pub mod secret;
pub mod transport;
pub mod tunnel;

// Desktop-only modules: the single-instance lock and the Unix/Windows control
// socket are meaningless inside an iOS app extension (no filesystem lock dir, no
// long-lived control channel — the extension lifecycle is owned by the OS).
#[cfg(not(target_os = "ios"))]
pub mod control;
#[cfg(not(target_os = "ios"))]
pub mod runtime;

// iOS-only C FFI surface consumed by the Network Extension.
#[cfg(target_os = "ios")]
pub mod ffi;
