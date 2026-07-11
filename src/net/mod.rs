//! Host networking primitives: the TUN device and packet buffer arenas.

pub mod buffer;
pub mod device;
#[cfg(not(target_os = "ios"))]
pub mod local_networks;
