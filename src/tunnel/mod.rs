//! The IP-over-QUIC tunnel: client and server data planes, stream framing,
//! offload handling, and the handshake signaling protocol.

pub mod client;
pub mod offload;
pub mod signaling;
pub mod stream;

// The server data plane creates a TUN, manages an IP pool, and routes between
// clients — none of which the iOS extension does. Desktop-only.
#[cfg(not(target_os = "ios"))]
pub mod server;

// The slim mobile connect path: drives an OS-provided tun fd, with routing and
// interface configuration owned by the iOS/macOS app extension.
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod mobile;

#[cfg(not(target_os = "ios"))]
pub use client::VpnClient;
#[cfg(not(target_os = "ios"))]
pub use server::VpnServer;
