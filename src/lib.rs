//! ezvpn
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses ezvpn auth tokens for access control and TLS 1.3/QUIC for encryption.
//!
//! This is the library crate. The desktop CLI (`src/main.rs`) and the Apple
//! Network Extension FFI (`src/ffi.rs`, built into a `staticlib`) both consume
//! it. Desktop platforms (Linux/macOS/Windows) get the full client/server with
//! TUN creation, routing, single-instance lock, and the control socket. Apple
//! app extensions get the portable data plane (iroh connect + handshake +
//! data-stream loop) and drive an OS-provided `utun` fd — routing and IP
//! configuration are owned by the `NEPacketTunnelProvider`, not this crate.

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

// Desktop modules: the single-instance lock and Unix/Windows control socket are
// omitted from iOS. The gates remain broader on macOS because the same library
// crate also serves the native CLI there.
#[cfg(not(target_os = "ios"))]
pub mod control;
#[cfg(not(target_os = "ios"))]
pub mod runtime;

// Apple Network Extension C FFI surface consumed by the iOS/macOS app extension.
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod ffi;
