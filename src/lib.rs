//! ezvpn
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses ed25519 client keypairs for access control and TLS 1.3/QUIC for
//! encryption.
//!
//! This is the library crate. The desktop CLI (`src/main.rs`) and the Apple
//! Network Extension FFI (`src/ffi.rs`, built into a `staticlib`) both consume
//! it. Desktop platforms (Linux/macOS/Windows) get the full client/server with
//! TUN creation, routing, single-instance lock, and the control socket. The
//! Apple app extensions (`src/ffi.rs`) get the portable data plane (iroh
//! connect + handshake + data-stream loop) and drive an OS-provided tun fd;
//! routing and IP configuration are owned by the `NEPacketTunnelProvider`, not
//! this crate.

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "ios"
)))]
compile_error!("ezvpn only supports Linux, macOS, Windows, and iOS");

// Re-exported so downstream consumers (the FFI layers, the CLI) can name the
// shared key types without depending on the git crate themselves.
pub use flexaccess_keys;

pub mod auth;
pub mod config;
pub mod error;
pub mod net;
pub mod secret;
pub mod transport;
pub mod tunnel;

// Desktop modules: the single-instance lock and Unix/Windows control socket are
// omitted from iOS. The gates remain broader on
// macOS because the same library crate also serves the native CLI there.
#[cfg(not(target_os = "ios"))]
pub mod control;
#[cfg(not(target_os = "ios"))]
pub mod runtime;

// Key helpers shared by the two (target-disjoint) FFI surfaces below. Built
// everywhere so the desktop test run covers it.
pub mod ffi_common;

// fd-based C FFI surface consumed by the iOS/macOS Network Extension.
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod ffi;

// Windows C FFI surface consumed by the native Windows GUI (`ezvpn-windows`),
// P/Invoked from .NET. Wraps the desktop `VpnClient` (which owns the wintun
// adapter and routing table), unlike the fd-based Apple `ffi` module.
#[cfg(target_os = "windows")]
pub mod ffi_windows;
