//! The IP-over-QUIC tunnel: client and server data planes, stream framing,
//! offload handling, and the handshake signaling protocol.

pub mod client;
pub mod offload;
pub mod signaling;
pub mod stream;

// The server data plane creates a TUN, manages an IP pool, and routes between
// clients — none of which an iOS client app extension does. Desktop-only.
#[cfg(not(target_os = "ios"))]
pub mod server;

// The slim iOS connect path: drives an OS-provided utun fd, no routes/lock.
#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(not(target_os = "ios"))]
pub use client::VpnClient;
#[cfg(not(target_os = "ios"))]
pub use server::VpnServer;
