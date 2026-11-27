//! TUN device creation and management.
//!
//! This module handles creating and managing TUN network interfaces
//! for VPN traffic.

// Darwin (macOS + iOS) share the direct `utun` fd I/O path (4-byte
// address-family-prefixed frames). The discriminator is `target_vendor =
// "apple"`. The `not(target_vendor = "apple")` arms select the `tun`-crate
// reader/writer path used on Linux/Windows. The macОS-only TUN *creation*,
// route, and `ifconfig` code below stays gated on `target_os = "macos"` — iOS
// neither creates a utun nor configures routes (the NEPacketTunnelProvider
// does), so it only reuses the shared fd I/O.
//
// On iOS the device is built from an OS-provided fd
// (`TunDevice::from_raw_fd`), so the `tun`-crate creation imports are unused
// there; silence the noise.
#![cfg_attr(target_os = "ios", allow(unused_imports, dead_code))]

use crate::error::{VpnError, VpnResult};
#[cfg(not(target_vendor = "apple"))]
use crate::tunnel::offload::compose_tun_frame;
use crate::tunnel::offload::{
    VIRTIO_NET_HDR_LEN, assemble_tcp_gso_superframe, plan_tun_write_groups, split_tun_frame,
};
use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use ipnet::{Ipv4Net, Ipv6Net};
#[cfg(not(target_vendor = "apple"))]
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(not(target_vendor = "apple"))]
use std::pin::Pin;
use tokio::io::ReadBuf;
#[cfg(not(target_vendor = "apple"))]
use tokio::io::{AsyncRead, AsyncWriteExt};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::process::Command;
use tun::{AbstractDevice, AsyncDevice, Configuration};
#[cfg(not(target_vendor = "apple"))]
use tun::{DeviceReader, DeviceWriter};

// Brings `Command::creation_flags` into scope for the blocking `std::process::Command`
// spawns below (tokio's `Command` exposes the same method inherently on Windows).
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt as _;

/// `CREATE_NO_WINDOW` process-creation flag.
///
/// The tunnel runs in-process inside the WinUI GUI app, which has no console.
/// Spawning a console subprocess (`netsh`, for the TUN's IPv6 address) from a
/// windowed process otherwise flashes a transient console window on screen.
/// This flag suppresses that window.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_vendor = "apple")]
use std::io;
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use std::os::fd::AsRawFd;
#[cfg(target_vendor = "apple")]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(target_vendor = "apple")]
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_vendor = "apple")]
use tokio::io::Interest;
#[cfg(target_vendor = "apple")]
use tokio::io::unix::AsyncFd;

/// TUN device configuration.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "tun0"). If None, system assigns a name.
    pub name: Option<String>,
    /// IPv4 address for this end of the tunnel.
    pub address: Ipv4Addr,
    /// Netmask for the VPN network.
    pub netmask: Ipv4Addr,
    /// Destination/gateway IP (peer's VPN address).
    pub destination: Ipv4Addr,
    /// IPv6 address (optional, for dual-stack).
    pub address6: Option<Ipv6Addr>,
    /// IPv6 prefix length (usually 128 for /128 per client).
    pub prefix_len6: Option<u8>,
    /// MTU for the device (default: 1280, the IPv6-minimum, mobile-safe value).
    pub mtu: u16,
    /// Attempt Linux TUN GSO/offload ioctls when creating the device.
    pub enable_gso: bool,
}

/// Validate IPv6 prefix length (must be 0-128).
fn validate_prefix_len6(prefix_len6: u8) -> VpnResult<()> {
    if prefix_len6 > 128 {
        return Err(VpnError::config(format!(
            "Invalid IPv6 prefix length {}: must be 0-128",
            prefix_len6
        )));
    }
    Ok(())
}

impl TunConfig {
    /// Create a new TUN configuration.
    pub fn new(address: Ipv4Addr, netmask: Ipv4Addr, destination: Ipv4Addr) -> Self {
        Self {
            name: None,
            address,
            netmask,
            destination,
            address6: None,
            prefix_len6: None,
            mtu: 1280,
            enable_gso: true,
        }
    }

    /// Set the MTU.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable Linux GSO/offload setup for this device.
    pub fn with_gso(mut self, enable_gso: bool) -> Self {
        self.enable_gso = enable_gso;
        self
    }

    /// Add IPv6 configuration for dual-stack.
    ///
    /// # Errors
    /// Returns an error if `prefix_len6` is greater than 128.
    pub fn with_ipv6(mut self, address6: Ipv6Addr, prefix_len6: u8) -> VpnResult<Self> {
        validate_prefix_len6(prefix_len6)?;
        self.address6 = Some(address6);
        self.prefix_len6 = Some(prefix_len6);
        Ok(self)
    }

    /// Create IPv6-only TUN configuration.
    ///
    /// For IPv6-only VPN networks, this creates a TUN configuration with
    /// a unique placeholder IPv4 address in the link-local range (169.254.x.x)
    /// that satisfies the device creation requirements but won't interfere
    /// with real traffic.
    ///
    /// The placeholder IP is derived from the IPv6 address to ensure uniqueness
    /// when multiple IPv6-only TUN devices are created on the same host.
    ///
    /// # Errors
    /// Returns an error if `prefix_len6` is greater than 128.
    pub fn ipv6_only(address6: Ipv6Addr, prefix_len6: u8, mtu: u16) -> VpnResult<Self> {
        validate_prefix_len6(prefix_len6)?;
        // Use a link-local placeholder address that won't conflict with real traffic.
        // This satisfies TUN creation on platforms that require IPv4 (macOS/Windows
        // in tun 0.8.x), but won't affect IPv4 routing.
        //
        // Derive unique placeholder from IPv6 address to avoid conflicts when
        // multiple IPv6-only TUN devices exist on the same host.
        // In ipv6_only, we hash full octets so placeholder_ip/placeholder_netmask
        // are more unique than the previous last-two-bytes-only approach.
        let octets = address6.octets();
        // Hash all IPv6 bytes into two stable bytes, then ensure we stay in
        // the 169.254.1.1 - 169.254.254.254 range (avoiding reserved .0/.255
        // subnets and .0/.255 host addresses).
        let mut hash: u16 = 0x9e37;
        for (idx, byte) in octets.iter().enumerate() {
            hash = hash.rotate_left(5) ^ (*byte as u16).wrapping_add(idx as u16);
        }
        let third = ((hash as u8) % 254) + 1; // 1-254 (uniform distribution)
        let fourth = (((hash >> 8) as u8) % 254) + 1; // 1-254 (uniform distribution)
        let placeholder_ip = Ipv4Addr::new(169, 254, third, fourth);
        let placeholder_netmask = Ipv4Addr::new(255, 255, 255, 255);
        Ok(Self {
            name: None,
            address: placeholder_ip,
            netmask: placeholder_netmask,
            destination: placeholder_ip,
            address6: Some(address6),
            prefix_len6: Some(prefix_len6),
            mtu,
            enable_gso: true,
        })
    }
}

/// Linux TUN offload status for the current device.
#[derive(Debug, Clone, Default)]
pub struct TunOffloadStatus {
    /// True when Linux TUN offload ioctls were enabled successfully.
    pub enabled: bool,
    /// Reason when offload could not be enabled.
    pub reason: Option<String>,
}

impl TunOffloadStatus {
    /// Construct an enabled status.
    #[cfg(target_os = "linux")]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            reason: None,
        }
    }

    /// Construct a disabled status with a reason.
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            enabled: false,
            reason: Some(reason.into()),
        }
    }
}

#[cfg(target_vendor = "apple")]
enum DarwinBacking {
    #[cfg(target_os = "macos")]
    Device(AsyncDevice),
    Fd(OwnedFd),
}

/// A managed TUN device with async I/O.
pub struct TunDevice {
    /// The underlying async TUN device (desktop: created by the `tun` crate).
    #[cfg(not(target_vendor = "apple"))]
    device: AsyncDevice,
    /// Darwin TUN backing: a `tun`-created device for the macOS CLI, or the
    /// OS-provided `utun` fd handed to an iOS/macOS `NEPacketTunnelProvider`.
    #[cfg(target_vendor = "apple")]
    backing: DarwinBacking,
    /// Device name.
    name: String,
    /// Configured MTU.
    mtu: u16,
    /// Whether this TUN device uses vnet headers in read/write frames.
    vnet_hdr_enabled: bool,
    /// Linux GSO/offload status for this device.
    offload_status: TunOffloadStatus,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration.
    ///
    /// Desktop-only: iOS receives an already-created tun fd from the Network
    /// Extension and must use [`Self::from_raw_fd`] instead.
    #[cfg(not(target_os = "ios"))]
    pub fn create(config: TunConfig) -> VpnResult<Self> {
        let mut tun_config = Configuration::default();

        tun_config.mtu(config.mtu).up();

        // Set IP configuration. macOS configures IPv4 itself after creation
        // (see `configure_macos_ipv4`): the `tun` crate's per-field ioctls leave
        // a classful netmask, and its routing step runs `route add` with the
        // destination as gateway, which the kernel rejects when that is the
        // interface's own address (the server's case) while `route` exits 0.
        #[cfg(not(target_os = "macos"))]
        tun_config.address(config.address).netmask(config.netmask);

        // `destination` is the point-to-point peer address on Linux, but
        // the `tun` crate's Windows backend treats it as the adapter's default
        // gateway and installs a metric-0 `0.0.0.0/0` route for it
        // (CreateIpForwardEntry2 with PrefixLength=0) — silently turning a
        // split tunnel into a full IPv4 tunnel that outranks every physical
        // interface. Skip it on Windows: the gateway is reachable through the
        // explicit host route the client adds (see `add_routes` for
        // `server_info.network`), and split-tunnel prefixes are always routed
        // explicitly.
        #[cfg(target_os = "linux")]
        tun_config.destination(config.destination);

        // Set device name if specified
        if let Some(ref name) = config.name {
            #[allow(deprecated)]
            tun_config.name(name);
        }

        // Platform-specific configuration
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|platform_config| {
            platform_config.ensure_root_privileges(true);
            platform_config.vnet_hdr(true);
        });

        // Create the async device
        let device = tun::create_as_async(&tun_config)
            .map_err(|e| VpnError::tun_device_with_source("Failed to create TUN device", e))?;

        let name = device
            .tun_name()
            .map_err(|e| VpnError::tun_device_with_source("Failed to get TUN name", e))?;

        #[cfg(target_os = "linux")]
        let offload_status = configure_linux_tun_offload(&device, config.enable_gso);
        #[cfg(not(target_os = "linux"))]
        let offload_status =
            TunOffloadStatus::disabled("TUN offload not supported on this platform");

        #[cfg(target_os = "linux")]
        if offload_status.enabled {
            log::debug!("Linux TUN GSO enabled on device {}", name);
        } else {
            let reason = offload_status.reason.as_deref().unwrap_or("unknown reason");
            if config.enable_gso {
                log::warn!("Linux TUN GSO disabled on device {}: {}", name, reason);
            } else {
                log::info!("Linux TUN GSO disabled on device {}: {}", name, reason);
            }
        }

        #[cfg(target_os = "macos")]
        configure_macos_ipv4(&device, &name, &config)?;

        log::debug!("Created TUN device: {} with IP {}", name, config.address);

        // Configure IPv6 address if specified (after device creation)
        if let (Some(addr6), Some(prefix)) = (config.address6, config.prefix_len6) {
            configure_tun_ipv6(&name, addr6, prefix)?;
            log::debug!("Configured TUN IPv6: {}/{}", addr6, prefix);
        }

        Ok(Self {
            #[cfg(not(target_vendor = "apple"))]
            device,
            #[cfg(target_os = "macos")]
            backing: DarwinBacking::Device(device),
            name,
            mtu: config.mtu,
            vnet_hdr_enabled: cfg!(target_os = "linux"),
            offload_status,
        })
    }

    /// Wrap an OS-provided `utun` file descriptor (Apple Network Extension).
    ///
    /// The `NEPacketTunnelProvider` creates the tunnel interface and configures
    /// its addresses/routes/MTU via `NEPacketTunnelNetworkSettings`; it then
    /// exposes the underlying `utun` fd. This constructor takes ownership of a
    /// `dup` of that fd and drives it with the shared Darwin fast path (4-byte
    /// address-family-prefixed frames — the same format macOS `utun` uses).
    ///
    /// No offload: iOS/macOS app-extension utun paths have no kernel GSO, so
    /// the data path uses software GRO.
    #[cfg(target_vendor = "apple")]
    pub fn from_raw_fd(fd: RawFd, mtu: u16) -> VpnResult<Self> {
        // Own a private dup so our lifetime is independent of the caller's fd.
        let owned = duplicate_fd(fd)?;
        Ok(Self {
            backing: DarwinBacking::Fd(owned),
            name: "utun".to_string(),
            mtu,
            vnet_hdr_enabled: false,
            offload_status: TunOffloadStatus::disabled("Apple utun has no kernel offload"),
        })
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get local GSO/offload status for this TUN device.
    pub fn offload_status(&self) -> &TunOffloadStatus {
        &self.offload_status
    }

    /// Get the buffer size for reading packets (MTU + packet info header).
    pub fn buffer_size(&self) -> usize {
        if self.vnet_hdr_enabled {
            65535 + VIRTIO_NET_HDR_LEN
        } else {
            self.mtu as usize + tun::PACKET_INFORMATION_LENGTH
        }
    }

    /// Split the device into read and write halves.
    /// Note: The tun crate returns (writer, reader) order from split().
    pub fn split(self) -> VpnResult<(TunReader, TunWriter)> {
        // Save buffer_size before moving the device/fd.
        let buffer_size = self.buffer_size();

        #[cfg(target_vendor = "apple")]
        {
            // Source the raw fd from whichever backing store this platform uses:
            // the `tun`-crate device for the macOS CLI, or the OS-provided fd
            // in an iOS/macOS Network Extension.
            let raw_fd = match &self.backing {
                #[cfg(target_os = "macos")]
                DarwinBacking::Device(device) => device.as_raw_fd(),
                DarwinBacking::Fd(fd) => fd.as_raw_fd(),
            };

            let DarwinTunHalves { reader, writer } = DarwinTunHalves::from_raw_fd(raw_fd)?;
            // The halves hold their own dup of the fd; release our handle.
            drop(self.backing);

            Ok((
                TunReader {
                    inner: TunReaderInner::Darwin(reader),
                    buffer_size,
                    vnet_hdr_enabled: self.vnet_hdr_enabled,
                    packet_information_enabled: true,
                    offload_status: self.offload_status.clone(),
                },
                TunWriter {
                    inner: TunWriterInner::Darwin(writer),
                    vnet_hdr_enabled: self.vnet_hdr_enabled,
                    offload_status: self.offload_status,
                    scratch: BytesMut::with_capacity(buffer_size),
                    groups: Vec::new(),
                },
            ))
        }

        #[cfg(not(target_vendor = "apple"))]
        {
            let (writer, reader) = self
                .device
                .split()
                .map_err(|e| VpnError::tun_device_with_source("Failed to split TUN device", e))?;

            Ok((
                TunReader {
                    inner: TunReaderInner::Standard(reader),
                    buffer_size,
                    vnet_hdr_enabled: self.vnet_hdr_enabled,
                    packet_information_enabled: false,
                    offload_status: self.offload_status.clone(),
                },
                TunWriter {
                    inner: TunWriterInner::Standard(writer),
                    vnet_hdr_enabled: self.vnet_hdr_enabled,
                    offload_status: self.offload_status,
                    scratch: BytesMut::with_capacity(buffer_size),
                    groups: Vec::new(),
                },
            ))
        }
    }
}

/// Actionable message shown when TUN creation is denied for lack of privileges.
#[cfg(target_os = "linux")]
const TUN_PERMISSION_HELP: &str = "insufficient privileges to create a TUN device: run as root (e.g. via sudo) or grant \
     CAP_NET_ADMIN to the binary (sudo setcap cap_net_admin+ep <path-to-ezvpn>)";
#[cfg(target_os = "macos")]
const TUN_PERMISSION_HELP: &str =
    "insufficient privileges to create a utun device: run as root (e.g. via sudo)";

/// Fail fast if this process cannot create a TUN device for lack of privileges.
///
/// TUN creation needs elevated privileges (root, or `CAP_NET_ADMIN` on Linux),
/// but in the normal flow that is only discovered *late*: the client creates its
/// TUN device only after connecting to the server and completing the handshake,
/// and the server only after opening its iroh endpoint. Without this preflight a
/// privilege problem surfaces after a wasted network round trip (and, for the
/// client daemon, after the process has already forked into the background).
///
/// The `start` paths call this up front — before any network connection or
/// daemonization — so the error lands immediately in the foreground. It creates
/// a throwaway, unconfigured (nameless, address-less, not-up) TUN device and
/// drops it right away, exercising exactly the privileged syscall that gates TUN
/// creation on each platform:
/// - Linux: `open("/dev/net/tun")` + `TUNSETIFF`
/// - macOS: `connect()` on a `PF_SYSTEM` utun control socket
///
/// Only a *permission* failure is fatal here; any other failure (or Windows,
/// whose wintun driver reports privilege problems through a different path) is
/// left for [`TunDevice::create`] to report with the full device configuration.
#[cfg(not(target_os = "ios"))]
pub fn ensure_tun_permission() -> VpnResult<()> {
    // Windows (wintun) surfaces privilege problems through a driver-specific
    // error path and needs the wintun runtime just to attempt creation; skip the
    // preflight there and defer to TunDevice::create.
    #[cfg(target_os = "windows")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        match tun::create(&Configuration::default()) {
            Ok(device) => {
                // The device is non-persistent, so dropping it (closing the fd)
                // tears the ephemeral interface back down immediately.
                drop(device);
                Ok(())
            }
            Err(tun::Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(VpnError::tun_device_with_source(TUN_PERMISSION_HELP, e))
            }
            // Non-permission failures are not this check's concern: defer to the
            // real, fully-configured TunDevice::create so preflight never blocks
            // startup on an unrelated (or transient) error.
            Err(e) => {
                log::debug!(
                    "TUN privilege preflight inconclusive (non-permission error, deferring to \
                     device creation): {e}"
                );
                Ok(())
            }
        }
    }
}

/// Assign the utun's IPv4 address and route its subnet onto it, so the result
/// matches what Linux and Windows make of an address with a netmask.
///
/// The address, point-to-point destination and netmask go in with one
/// `SIOCAIFADDR`, which also installs the host route to the destination. utun
/// is point-to-point, so the kernel adds no route for the netmask; without the
/// subnet route added here a server (whose destination is its own address)
/// has no route back to its clients. The route belongs to the interface and
/// goes away with it, like the kernel-made route on Linux. IPv6 needs nothing:
/// the kernel adds the prefix route for an `inet6` address. A host mask (the
/// client's) has no subnet to route.
#[cfg(target_os = "macos")]
fn configure_macos_ipv4(device: &AsyncDevice, name: &str, config: &TunConfig) -> VpnResult<()> {
    let subnet = Ipv4Net::with_netmask(config.address, config.netmask)
        .map_err(|e| {
            VpnError::config_with_source(format!("Invalid TUN netmask {}", config.netmask), e)
        })?
        .trunc();
    macos_net::set_ipv4_address(name, config.address, config.destination, subnet.netmask())
        .map_err(|e| {
            VpnError::tun_device_with_source(
                format!("Failed to assign {} to {name}", config.address),
                e,
            )
        })?;
    if subnet.prefix_len() == 32 {
        return Ok(());
    }
    let index_error = format!("Failed to get interface index of {name}");
    let if_index = device
        .tun_index()
        .map_err(|e| VpnError::tun_device_with_source(index_error.clone(), e))?;
    let if_index =
        u16::try_from(if_index).map_err(|e| VpnError::tun_device_with_source(index_error, e))?;
    // The utun was just created, so no route through it can exist yet: EEXIST
    // means another interface already routes the subnet, and continuing would
    // leave the clients without a return route.
    macos_net::add_subnet_route(if_index, subnet).map_err(|e| {
        let message = if e.raw_os_error() == Some(libc::EEXIST) {
            format!("Failed to add route {subnet} via {name}: another interface already routes it")
        } else {
            format!("Failed to add route {subnet} via {name}")
        };
        VpnError::tun_device_with_source(message, e)
    })?;
    log::info!("Added route {} via {}", subnet, name);
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_linux_tun_offload(device: &AsyncDevice, enable_gso: bool) -> TunOffloadStatus {
    let fd = device.as_raw_fd();

    let mut vnet_hdr_size: libc::c_int =
        i32::try_from(VIRTIO_NET_HDR_LEN).expect("virtio header size must fit in c_int");
    let vnet_hdr_result = unsafe {
        libc::ioctl(
            fd,
            libc::TUNSETVNETHDRSZ as _,
            &mut vnet_hdr_size as *mut libc::c_int,
        )
    };
    if vnet_hdr_result < 0 {
        return TunOffloadStatus::disabled(format!(
            "TUNSETVNETHDRSZ failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if !enable_gso {
        return TunOffloadStatus::disabled("disabled by peer capability");
    }

    let offload_flags: libc::c_uint = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
    let offload_result = unsafe {
        // TUNSETOFFLOAD takes the bitmask value directly as ioctl arg.
        // Passing a pointer here sends the pointer address as flags.
        libc::ioctl(
            fd,
            libc::TUNSETOFFLOAD as _,
            libc::c_ulong::from(offload_flags),
        )
    };
    if offload_result < 0 {
        return TunOffloadStatus::disabled(format!(
            "TUNSETOFFLOAD(TSO4/TSO6) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    TunOffloadStatus::enabled()
}

#[cfg(target_vendor = "apple")]
struct DarwinTunHalves {
    reader: DarwinTunReader,
    writer: DarwinTunWriter,
}

#[cfg(target_vendor = "apple")]
impl DarwinTunHalves {
    /// Build async read/write halves from a `utun` raw fd. The fd is `dup`ed so
    /// the halves own their copy independently of the caller (macOS passes the
    /// `tun`-crate device's fd; iOS passes the Network Extension's fd).
    fn from_raw_fd(fd: RawFd) -> VpnResult<Self> {
        let fd = duplicate_fd(fd)?;
        set_utun_socket_buffers(&fd);
        set_utun_max_pending_packets(&fd);
        // SAFETY: `fd` is an `OwnedFd` this function just `dup`ed, so it is a
        // valid open descriptor that stays open, and keeps naming the same
        // file description, for as long as the `AsyncFd` owns it.
        let fd = Arc::new(unsafe { AsyncFd::register(fd) }.map_err(|e| {
            VpnError::tun_device_with_source("Failed to register utun fd", e.into_parts().1)
        })?);
        Ok(Self {
            reader: DarwinTunReader { fd: fd.clone() },
            writer: DarwinTunWriter { fd },
        })
    }
}

/// Size requested for the utun kernel-control socket's receive and send
/// buffers.
///
/// A utun is a kernel-control socket: packets the stack routes into it queue
/// in the socket's receive buffer (up to [`UTUN_MAX_PENDING_PACKETS`] of them)
/// until we `read` them, and `write`s queue in its send buffer. The default is 512 KiB each, about 250 full-size packets.
/// A TCP sender's burst overflows that, and XNU answers the overflow with
/// `ENOBUFS`, which the TCP stack treats as congestion: it collapses its window
/// and trickles packets out one at a time, so the reader finds the queue empty
/// after every read and the flow crawls at a fraction of what the utun can
/// carry. 4 MiB absorbs a window's worth of burst (the kernel caps requests at
/// `kern.ipc.maxsockbuf`, 8 MiB by default), so bursts queue and the reader
/// drains them in batches.
#[cfg(target_vendor = "apple")]
const UTUN_SOCKET_BUFFER_SIZE: libc::c_int = 4 * 1024 * 1024;

/// How many outbound packets the kernel may hold on the utun socket for the
/// reader, set through `UTUN_OPT_MAX_PENDING_PACKETS`.
///
/// The kernel moves a packet from the interface's send queue to the socket
/// only while fewer than this many wait there, and the default is 1. Each
/// `read` then empties the socket and has to wake the interface's starter
/// thread for the next packet, so the reader and that thread hand off once
/// per packet however many are queued behind it: on an M2 Mac VM the reader
/// found the socket empty ten times per packet while 700 packets sat in the
/// interface queue, and an upload ran at 450 Mbit/s. With a backlog allowed
/// the starter thread delivers a run of packets per wakeup and the reader
/// takes them back to back (about 700 Mbit/s there, more once the QUIC driver
/// stopped holding the connection lock across its sends).
///
/// Small on purpose: the kernel counts the waiting packets by walking the
/// socket's whole queue, under the socket lock, on every `read` and before
/// every packet it adds (`ctl_getenqueuepacketcount` in XNU).
/// 8 to 128 measured alike, 256 was slower, and at 1024 each `read` took 39 µs
/// and the upload fell to 210 Mbit/s.
#[cfg(target_vendor = "apple")]
const UTUN_MAX_PENDING_PACKETS: u32 = 32;

/// Let [`UTUN_MAX_PENDING_PACKETS`] packets wait on the utun socket; a failure
/// only logs, leaving the kernel's default of one.
#[cfg(target_vendor = "apple")]
fn set_utun_max_pending_packets(fd: &OwnedFd) {
    // From <sys/sys_domain.h> and <net/if_utun.h>: the `libc` crate exports
    // the first on macOS only and has no binding for the second.
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;
    let count = UTUN_MAX_PENDING_PACKETS;
    // SAFETY: `fd` is open for the call's duration and `count` is a live u32
    // whose exact length is passed.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_MAX_PENDING_PACKETS,
            (&count as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        log::debug!(
            "Could not set utun max pending packets to {}: {}",
            count,
            io::Error::last_os_error()
        );
    }
}

/// Raise the utun socket's receive and send buffers to
/// [`UTUN_SOCKET_BUFFER_SIZE`]; a failure only logs, leaving the defaults.
#[cfg(target_vendor = "apple")]
fn set_utun_socket_buffers(fd: &OwnedFd) {
    for (name, option) in [
        ("SO_RCVBUF", libc::SO_RCVBUF),
        ("SO_SNDBUF", libc::SO_SNDBUF),
    ] {
        let size = UTUN_SOCKET_BUFFER_SIZE;
        // SAFETY: `fd` is open for the call's duration and `size` is a live
        // c_int whose exact length is passed.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            log::debug!(
                "Could not set utun {} to {} bytes: {}",
                name,
                size,
                io::Error::last_os_error()
            );
        }
    }
}

#[cfg(target_vendor = "apple")]
fn duplicate_fd(fd: RawFd) -> VpnResult<OwnedFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(VpnError::tun_device_with_source(
            "Failed to duplicate tun fd",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(target_vendor = "apple")]
struct DarwinTunReader {
    fd: Arc<AsyncFd<OwnedFd>>,
}

#[cfg(target_vendor = "apple")]
impl DarwinTunReader {
    async fn read_buf(&mut self, buf: &mut ReadBuf<'_>) -> VpnResult<()> {
        self.fd
            .async_io(Interest::READABLE, |fd| {
                read_utun_frame_into(fd.as_raw_fd(), buf)
            })
            .await
            .map_err(VpnError::Network)
    }

    /// Read the next packet, polling the fd directly for up to `budget`
    /// before reporting that there is none.
    ///
    /// Bypasses tokio's readiness tracking: a raw nonblocking `read` costs a
    /// couple of microseconds, whereas parking on the reactor and being woken
    /// for the next packet costs tens of microseconds per packet in thread
    /// wakeups (more in a VM), and the kernel's utun output path serializes
    /// against the reader on the socket lock, so a reader that sleeps between
    /// packets caps the whole flow. Packets consumed here leave their kqueue
    /// events queued, which only costs the next `read_buf` a spurious wakeup.
    fn spin_read_buf(&mut self, buf: &mut ReadBuf<'_>, budget: Duration) -> Option<VpnResult<()>> {
        let fd = self.fd.get_ref().as_raw_fd();
        let start = std::time::Instant::now();
        loop {
            match read_utun_frame_into(fd, buf) {
                Ok(()) => return Some(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= budget {
                        return None;
                    }
                    std::hint::spin_loop();
                }
                Err(e) => return Some(Err(VpnError::Network(e))),
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
fn read_utun_frame_into(fd: RawFd, buf: &mut ReadBuf<'_>) -> io::Result<()> {
    if buf.remaining() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "utun read buffer is full",
        ));
    }

    let unfilled = unsafe { buf.unfilled_mut() };
    let read = unsafe {
        libc::read(
            fd,
            unfilled.as_mut_ptr() as *mut libc::c_void,
            unfilled.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }

    let read = usize::try_from(read).expect("non-negative read result must fit usize");
    unsafe {
        buf.assume_init(read);
    }
    buf.advance(read);
    Ok(())
}

#[cfg(target_vendor = "apple")]
struct DarwinTunWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

#[cfg(target_vendor = "apple")]
impl DarwinTunWriter {
    async fn write_packet(&mut self, ip_packet: &[u8]) -> VpnResult<()> {
        let header = darwin_packet_information(ip_packet)?;
        self.fd
            .async_io(Interest::WRITABLE, |fd| {
                write_utun_frame_vectored(fd.as_raw_fd(), &header, ip_packet)
            })
            .await
            .map_err(VpnError::Network)
    }
}

#[cfg(target_vendor = "apple")]
fn darwin_packet_information(ip_packet: &[u8]) -> VpnResult<[u8; tun::PACKET_INFORMATION_LENGTH]> {
    let Some(first_byte) = ip_packet.first() else {
        return Err(VpnError::tun_device(
            "cannot write empty IP payload to utun",
        ));
    };
    let family = match first_byte >> 4 {
        4 => libc::AF_INET,
        6 => libc::AF_INET6,
        version => {
            return Err(VpnError::tun_device(format!(
                "unsupported IP version {} for utun write",
                version
            )));
        }
    };
    Ok((family as u32).to_be_bytes())
}

#[cfg(target_vendor = "apple")]
fn write_utun_frame_vectored(
    fd: RawFd,
    header: &[u8; tun::PACKET_INFORMATION_LENGTH],
    ip_packet: &[u8],
) -> io::Result<()> {
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: ip_packet.as_ptr() as *mut libc::c_void,
            iov_len: ip_packet.len(),
        },
    ];
    let written = unsafe {
        libc::writev(
            fd,
            iov.as_ptr(),
            libc::c_int::try_from(iov.len()).expect("iov count must fit c_int"),
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }

    let written = usize::try_from(written).expect("non-negative write result must fit usize");
    let expected = header.len() + ip_packet.len();
    if written != expected {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short utun write: {} < {}", written, expected),
        ));
    }
    Ok(())
}

#[cfg(all(test, target_vendor = "apple"))]
mod darwin_io_tests {
    use super::*;
    use std::mem::MaybeUninit;

    /// A pipe in place of the utun socket, its read end non-blocking as the
    /// utun fd is. Miri emulates `pipe`, `writev` and non-blocking `read`, so
    /// these run the real read/write paths under it.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rx, tx) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let flags = unsafe { libc::fcntl(rx.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(rx.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        (rx, tx)
    }

    #[test]
    fn frame_lands_after_bytes_already_filled() {
        let (rx, tx) = pipe();
        let packet = [0x60, 0, 0, 0, 1, 2, 3, 4];
        let header = darwin_packet_information(&packet).unwrap();
        assert_eq!(header, (libc::AF_INET6 as u32).to_be_bytes());
        write_utun_frame_vectored(tx.as_raw_fd(), &header, &packet).unwrap();

        let mut storage = [MaybeUninit::<u8>::uninit(); 32];
        let mut buf = ReadBuf::uninit(&mut storage);
        buf.put_slice(&[0xaa, 0xbb]);
        read_utun_frame_into(rx.as_raw_fd(), &mut buf).unwrap();
        let expected: Vec<u8> = [&[0xaa, 0xbb][..], &header, &packet].concat();
        assert_eq!(buf.filled(), &expected[..]);
    }

    #[test]
    fn empty_socket_would_block_and_full_buffer_is_refused() {
        let (rx, _tx) = pipe();
        let mut storage = [MaybeUninit::<u8>::uninit(); 4];
        let mut buf = ReadBuf::uninit(&mut storage);
        let err = read_utun_frame_into(rx.as_raw_fd(), &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(buf.filled().is_empty());

        buf.put_slice(&[1, 2, 3, 4]);
        let err = read_utun_frame_into(rx.as_raw_fd(), &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn packet_information_needs_an_ip_version() {
        assert_eq!(
            darwin_packet_information(&[0x45]).unwrap(),
            (libc::AF_INET as u32).to_be_bytes()
        );
        assert!(darwin_packet_information(&[]).is_err());
        assert!(darwin_packet_information(&[0x50]).is_err());
    }
}

enum TunReaderInner {
    #[cfg(not(target_vendor = "apple"))]
    Standard(DeviceReader),
    #[cfg(target_vendor = "apple")]
    Darwin(DarwinTunReader),
}

enum TunWriterInner {
    #[cfg(not(target_vendor = "apple"))]
    Standard(DeviceWriter),
    #[cfg(target_vendor = "apple")]
    Darwin(DarwinTunWriter),
}

/// Read half of a split TUN device.
pub struct TunReader {
    inner: TunReaderInner,
    buffer_size: usize,
    vnet_hdr_enabled: bool,
    packet_information_enabled: bool,
    offload_status: TunOffloadStatus,
}

impl TunReader {
    /// Get the recommended buffer size.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Return true if raw TUN reads include the 10-byte Linux vnet header.
    pub fn vnet_hdr_enabled(&self) -> bool {
        self.vnet_hdr_enabled
    }

    /// Split a raw TUN frame into offload metadata and the IP packet payload.
    pub fn split_frame<'a>(
        &self,
        frame: &'a [u8],
    ) -> Result<(Option<crate::tunnel::offload::VirtioNetHdr>, &'a [u8]), String> {
        if self.packet_information_enabled {
            if frame.len() <= tun::PACKET_INFORMATION_LENGTH {
                return Err(format!(
                    "TUN frame shorter than packet information header: {} <= {}",
                    frame.len(),
                    tun::PACKET_INFORMATION_LENGTH
                ));
            }
            return split_tun_frame(&frame[tun::PACKET_INFORMATION_LENGTH..], false);
        }
        split_tun_frame(frame, self.vnet_hdr_enabled)
    }

    /// Get local offload status associated with this TUN reader.
    pub fn offload_status(&self) -> &TunOffloadStatus {
        &self.offload_status
    }

    /// Read a packet into a possibly-uninitialized buffer.
    ///
    /// The caller can inspect `buf.filled()` after this returns. This avoids
    /// zeroing large packet buffers while keeping initialized-byte tracking in
    /// Tokio's safe `ReadBuf` abstraction.
    pub async fn read_buf(&mut self, buf: &mut ReadBuf<'_>) -> VpnResult<()> {
        match &mut self.inner {
            #[cfg(not(target_vendor = "apple"))]
            TunReaderInner::Standard(reader) => {
                poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, buf))
                    .await
                    .map_err(VpnError::Network)
            }
            #[cfg(target_vendor = "apple")]
            TunReaderInner::Darwin(reader) => reader.read_buf(buf).await,
        }
    }

    /// Non-blocking single-poll read.
    ///
    /// Returns `None` when the TUN has no packet ready right now. The poll
    /// consumes no bytes (tokio caches FD readiness and only clears it after a
    /// real `read` returns `WouldBlock`), and the next `read_buf().await`
    /// re-polls and re-registers the waker, so no wakeup is lost. This lets the
    /// caller drain everything currently queued and flush when the TUN drains.
    pub fn try_read_buf(&mut self, buf: &mut ReadBuf<'_>) -> Option<VpnResult<()>> {
        self.read_buf(buf).now_or_never()
    }

    /// [`try_read_buf`](Self::try_read_buf) that, on a utun, keeps polling for
    /// up to `budget` before giving up (see `DarwinTunReader::spin_read_buf`).
    /// Elsewhere the budget is ignored.
    pub fn try_read_buf_within(
        &mut self,
        buf: &mut ReadBuf<'_>,
        budget: Duration,
    ) -> Option<VpnResult<()>> {
        #[cfg(target_vendor = "apple")]
        {
            match self.try_read_buf(buf) {
                None => {
                    let TunReaderInner::Darwin(reader) = &mut self.inner;
                    reader.spin_read_buf(buf, budget)
                }
                some => some,
            }
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let _ = budget;
            self.try_read_buf(buf)
        }
    }
}

/// Write half of a split TUN device.
pub struct TunWriter {
    inner: TunWriterInner,
    vnet_hdr_enabled: bool,
    offload_status: TunOffloadStatus,
    scratch: BytesMut,
    /// Reusable group-plan buffer for [`TunWriter::write_batch`].
    groups: Vec<(usize, usize, bool)>,
}

impl TunWriter {
    /// Get local offload status associated with this TUN writer.
    pub fn offload_status(&self) -> &TunOffloadStatus {
        &self.offload_status
    }

    /// Write an IP packet to the TUN device, optionally including offload metadata.
    pub async fn write_packet(
        &mut self,
        offload: Option<&crate::tunnel::offload::VirtioNetHdr>,
        ip_packet: &[u8],
    ) -> VpnResult<()> {
        #[cfg(target_vendor = "apple")]
        {
            let TunWriterInner::Darwin(writer) = &mut self.inner;
            if offload.is_some() {
                return Err(VpnError::tun_device(
                    "received offload metadata but local utun does not use vnet headers",
                ));
            }
            return writer.write_packet(ip_packet).await;
        }

        #[cfg(not(target_vendor = "apple"))]
        {
            if !self.vnet_hdr_enabled {
                // No header to prepend: write the packet directly, skipping the
                // scratch-buffer copy.
                if offload.is_some() {
                    return Err(VpnError::tun_device(
                        "received offload metadata but local TUN does not use vnet headers",
                    ));
                }
                if ip_packet.is_empty() {
                    return Err(VpnError::tun_device(
                        "cannot compose TUN frame with empty IP payload",
                    ));
                }
                return match &mut self.inner {
                    TunWriterInner::Standard(writer) => {
                        writer.write_all(ip_packet).await.map_err(VpnError::Network)
                    }
                };
            }
            compose_tun_frame(&mut self.scratch, self.vnet_hdr_enabled, offload, ip_packet)
                .map_err(VpnError::tun_device)?;
            match &mut self.inner {
                TunWriterInner::Standard(writer) => writer
                    .write_all(&self.scratch)
                    .await
                    .map_err(VpnError::Network),
            }
        }
    }

    /// Write a drained batch of plain IP packets to the TUN device.
    ///
    /// When vnet headers are enabled *and* GSO offload actually enabled
    /// (Linux), consecutive same-flow TCP segments are coalesced into a single
    /// `virtio_net_hdr` GSO super-frame and written in one syscall, letting the
    /// kernel re-segment (GRO-like). Everything else — and every packet when
    /// offload is unavailable — is written per-packet, identical to calling
    /// [`TunWriter::write_packet`] for each.
    pub async fn write_batch(&mut self, batch: &[Bytes]) -> VpnResult<()> {
        // `vnet_hdr_enabled` only means the device prepends a virtio header; GSO
        // can still be off (e.g. peer disabled it, or TUNSETOFFLOAD failed). The
        // kernel rejects a GSO super-frame unless offload was actually enabled,
        // so coalesce only when both hold; otherwise fall back to per-packet
        // writes (a GSO_NONE vnet frame, which is always accepted).
        if !self.vnet_hdr_enabled || !self.offload_status.enabled {
            for packet in batch {
                self.write_packet(None, packet).await?;
            }
            return Ok(());
        }

        // Take the plan buffer so `plan_tun_write_groups` can fill it while
        // `self` stays borrowable for the writes; put it back for reuse.
        let mut groups = std::mem::take(&mut self.groups);
        plan_tun_write_groups(batch, &mut groups);
        let result = self.write_planned_groups(batch, &groups).await;
        self.groups = groups;
        result
    }

    async fn write_planned_groups(
        &mut self,
        batch: &[Bytes],
        groups: &[(usize, usize, bool)],
    ) -> VpnResult<()> {
        for &(start, end, coalesce) in groups {
            if !coalesce {
                self.write_packet(None, &batch[start]).await?;
                continue;
            }
            match assemble_tcp_gso_superframe(&mut self.scratch, &batch[start..end]) {
                Ok(()) => match &mut self.inner {
                    #[cfg(not(target_vendor = "apple"))]
                    TunWriterInner::Standard(writer) => {
                        writer
                            .write_all(&self.scratch)
                            .await
                            .map_err(VpnError::Network)?;
                    }
                    #[cfg(target_vendor = "apple")]
                    TunWriterInner::Darwin(_) => unreachable!("handled by Darwin fast path"),
                },
                Err(e) => {
                    // Defensive: the planner only emits coalescible runs, so
                    // this should not happen; degrade to per-packet writes.
                    log::warn!(
                        "GSO super-frame assembly failed ({}); writing {} segments individually",
                        e,
                        end - start
                    );
                    for packet in &batch[start..end] {
                        self.write_packet(None, packet).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Check if an error message indicates that a resource already exists.
///
/// Used for idempotent route/address operations. Handles various error formats:
/// - Linux iproute2: "RTNETLINK answers: File exists"
/// - macOS route: "route: writing to routing socket: File exists"
/// - Windows netsh: "The object already exists" or "Element already exists"
fn is_already_exists_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("file exists") || lower.contains("eexist") || lower.contains("already exists")
}

// ============================================================================
// Windows IP Helper route operations
// ============================================================================

/// Windows route-table manipulation via the IP Helper API.
///
/// WireGuard and Tailscale manage routes with `CreateIpForwardEntry2` /
/// `DeleteIpForwardEntry2` rather than shelling out to `netsh` or the
/// `NetTCPIP` PowerShell cmdlets; this module does the same, for the tunnel's
/// routes (against the TUN's LUID) and for the underlay bypass host routes
/// (against the underlay interface's index), and looks routes up with
/// `GetBestRoute2` and `GetIpForwardTable2`. Beyond matching that practice,
/// the API returns typed error codes — the tools print localized text, so
/// detecting "already exists" by English string match silently breaks
/// idempotency on non-English Windows — and each call returns at once, where
/// starting `powershell.exe` cost about 1.5 s per lookup, add and removal.
#[cfg(target_os = "windows")]
mod windows_routes {
    use super::RouteAddOutcome;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, CreateIpForwardEntry2,
        DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
    };

    /// Route metric for TUN routes and bypass host routes. Matches the metric
    /// the previous `netsh interface … add route` and `New-NetRoute` calls
    /// produced (their default), so route selection is unchanged.
    const ROUTE_METRIC: u32 = 256;

    /// A route the system holds: the interface it leaves by, its next hop
    /// (`None` for an on-link route), and that interface's alias.
    pub struct RouteLookup {
        pub if_index: u32,
        pub next_hop: Option<IpAddr>,
        pub alias: String,
    }

    fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
        let mut addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match ip {
            IpAddr::V4(a) => {
                addr.Ipv4.sin_family = AF_INET;
                addr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
            }
            IpAddr::V6(a) => {
                addr.Ipv6.sin6_family = AF_INET6;
                addr.Ipv6.sin6_addr.u.Byte = a.octets();
            }
        }
        addr
    }

    /// The address in `addr`, or `None` when it is unspecified (an on-link
    /// next hop) or of another family.
    fn ip_of(addr: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: every variant of the union starts with the address family,
        // which says which variant the rest of it is.
        let ip: IpAddr = unsafe {
            match addr.si_family {
                AF_INET => Ipv4Addr::from(addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into(),
                AF_INET6 => Ipv6Addr::from(addr.Ipv6.sin6_addr.u.Byte).into(),
                _ => return None,
            }
        };
        (!ip.is_unspecified()).then_some(ip)
    }

    fn status(code: u32) -> io::Result<()> {
        match code {
            NO_ERROR => Ok(()),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// The alias of the interface `luid` names (what `Get-NetRoute` shows as
    /// `InterfaceAlias`, and what the TUN device is named by).
    fn interface_alias(luid: &NET_LUID_LH) -> io::Result<String> {
        let mut alias = [0u16; IF_MAX_STRING_SIZE as usize + 1];
        status(unsafe { ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len()) })?;
        let len = alias.iter().position(|&c| c == 0).unwrap_or(alias.len());
        Ok(String::from_utf16_lossy(&alias[..len]))
    }

    fn lookup(row: &MIB_IPFORWARD_ROW2) -> io::Result<RouteLookup> {
        Ok(RouteLookup {
            if_index: row.InterfaceIndex,
            next_hop: ip_of(&row.NextHop),
            alias: interface_alias(&row.InterfaceLuid)?,
        })
    }

    /// The route the kernel's route selection picks for `dest` right now
    /// (longest prefix, then metric), as `Find-NetRoute` reports it.
    pub fn best_route(dest: IpAddr) -> io::Result<RouteLookup> {
        let dest = sockaddr(dest);
        let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        status(unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &dest,
                0,
                &mut route,
                &mut source,
            )
        })?;
        lookup(&route)
    }

    /// The default route (`0.0.0.0/0`, or `::/0` when `ipv6`) with the lowest
    /// effective metric — the route's metric plus its interface's, as the
    /// kernel ranks them — on a connected interface. `ErrorKind::NotFound`
    /// when there is none.
    pub fn default_route(ipv6: bool) -> io::Result<RouteLookup> {
        let family = if ipv6 { AF_INET6 } else { AF_INET };
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        status(unsafe { GetIpForwardTable2(family, &mut table) })?;
        // SAFETY: on success `table` is a valid table, which stays valid
        // until `FreeMibTable` below.
        let rows = unsafe { table_rows(table) };
        let best = rows
            .iter()
            .filter(|row| row.DestinationPrefix.PrefixLength == 0)
            .filter_map(|row| {
                let interface = interface_row(row)?;
                interface
                    .Connected
                    .then_some((row.Metric.saturating_add(interface.Metric), row))
            })
            .min_by_key(|(metric, _)| *metric)
            .map(|(_, row)| lookup(row));
        unsafe { FreeMibTable(table.cast()) };
        best.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no {} default route", if ipv6 { "IPv6" } else { "IPv4" }),
            ))
        })
    }

    /// The rows of `table`, which holds `NumEntries` of them from `Table`
    /// on, past the one the struct declares.
    ///
    /// The rows are reached through the field's raw address: a pointer taken
    /// from a reference to `Table` (`Table.as_ptr()`) may only reach that
    /// declared one-row array.
    ///
    /// # Safety
    /// `table` must point at a table whose `NumEntries` rows are initialized
    /// and outlive `'a`.
    unsafe fn table_rows<'a>(table: *const MIB_IPFORWARD_TABLE2) -> &'a [MIB_IPFORWARD_ROW2] {
        unsafe {
            let first = std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
            std::slice::from_raw_parts(first, (*table).NumEntries as usize)
        }
    }

    /// The IP interface `route` leaves by, for its metric and state; `None`
    /// when it cannot be read (the interface is going away).
    fn interface_row(route: &MIB_IPFORWARD_ROW2) -> Option<MIB_IPINTERFACE_ROW> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        // SAFETY: the family is the first field of every variant.
        row.Family = unsafe { route.DestinationPrefix.Prefix.si_family };
        row.InterfaceLuid = route.InterfaceLuid;
        status(unsafe { GetIpInterfaceEntry(&mut row) }).ok()?;
        Some(row)
    }

    /// Build a route row for `dest/prefix_len` via `next_hop`, or on-link
    /// when `next_hop` is `None`. The caller names the interface.
    ///
    /// An on-link next hop is the unspecified address (`0.0.0.0` / `::`), the
    /// same shape the previous `netsh … interface=<tun>` calls (no `nexthop=`)
    /// created. Zeroing the struct leaves the remaining fields (`Loopback`,
    /// `Publish`, `Origin`, …) at their documented defaults; lifetimes are set
    /// to infinite so the route lives until explicitly deleted (`store=active`
    /// semantics — it does not survive a reboot).
    fn route_row(dest: IpAddr, prefix_len: u8, next_hop: Option<IpAddr>) -> MIB_IPFORWARD_ROW2 {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.DestinationPrefix.Prefix = sockaddr(dest);
        row.NextHop = match (next_hop, dest) {
            (Some(hop), _) => sockaddr(hop),
            (None, IpAddr::V4(_)) => sockaddr(Ipv4Addr::UNSPECIFIED.into()),
            (None, IpAddr::V6(_)) => sockaddr(Ipv6Addr::UNSPECIFIED.into()),
        };
        row.Metric = ROUTE_METRIC;
        // Administratively added — the same origin netsh and New-NetRoute
        // stamp (shows as "NetMgmt" in Get-NetRoute), and what the
        // route-cleanup key expects.
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row
    }

    fn host_prefix(ip: IpAddr) -> u8 {
        if ip.is_ipv4() { 32 } else { 128 }
    }

    /// Row for the bypass host route `dest/32` (`/128`) via `gateway`, on the
    /// underlay interface `if_index`.
    fn host_route_row(if_index: u32, dest: IpAddr, gateway: IpAddr) -> MIB_IPFORWARD_ROW2 {
        let mut row = route_row(dest, host_prefix(dest), Some(gateway));
        row.InterfaceIndex = if_index;
        row
    }

    /// Add the bypass host route for `dest` via `gateway` on `if_index`.
    pub fn add_host_route(
        if_index: u32,
        dest: IpAddr,
        gateway: IpAddr,
    ) -> io::Result<RouteAddOutcome> {
        let row = host_route_row(if_index, dest, gateway);
        match unsafe { CreateIpForwardEntry2(&row) } {
            NO_ERROR => Ok(RouteAddOutcome::Added),
            ERROR_OBJECT_ALREADY_EXISTS => Ok(RouteAddOutcome::AlreadyExisted),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// Remove a host route added by [`add_host_route`]. `Ok(false)` when it
    /// was already gone (its interface went away, say).
    pub fn delete_host_route(if_index: u32, dest: IpAddr, gateway: IpAddr) -> io::Result<bool> {
        let row = host_route_row(if_index, dest, gateway);
        match unsafe { DeleteIpForwardEntry2(&row) } {
            NO_ERROR => Ok(true),
            ERROR_NOT_FOUND => Ok(false),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// Resolve an interface alias (the TUN device name) to its LUID.
    fn interface_luid(tun_name: &str) -> io::Result<NET_LUID_LH> {
        let alias: Vec<u16> = tun_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        match unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } {
            NO_ERROR => Ok(luid),
            status => Err(io::Error::from_raw_os_error(status as i32)),
        }
    }

    /// Row for the on-link tunnel route `dest/prefix_len` on the TUN `luid`
    /// (the wintun adapter's routes go with it, so none survives a reboot).
    fn forward_row(luid: NET_LUID_LH, dest: IpAddr, prefix_len: u8) -> MIB_IPFORWARD_ROW2 {
        let mut row = route_row(dest, prefix_len, None);
        row.InterfaceLuid = luid;
        row
    }

    /// Add an on-link route through the interface.
    pub fn add_route(tun_name: &str, dest: IpAddr, prefix_len: u8) -> io::Result<RouteAddOutcome> {
        let row = forward_row(interface_luid(tun_name)?, dest, prefix_len);
        match unsafe { CreateIpForwardEntry2(&row) } {
            NO_ERROR => Ok(RouteAddOutcome::Added),
            ERROR_OBJECT_ALREADY_EXISTS => Ok(RouteAddOutcome::AlreadyExisted),
            status => Err(io::Error::from_raw_os_error(status as i32)),
        }
    }

    /// Remove a route added by [`add_route`]. `ERROR_NOT_FOUND` (already
    /// removed, e.g. the adapter is gone) is success: removal is idempotent.
    pub fn delete_route(tun_name: &str, dest: IpAddr, prefix_len: u8) -> io::Result<()> {
        let luid = match interface_luid(tun_name) {
            Ok(luid) => luid,
            // Adapter is gone — the route went with it. Idempotent cleanup.
            Err(e) if e.raw_os_error() == Some(ERROR_NOT_FOUND as i32) => return Ok(()),
            Err(e) => return Err(e),
        };
        let row = forward_row(luid, dest, prefix_len);
        match unsafe { DeleteIpForwardEntry2(&row) } {
            NO_ERROR | ERROR_NOT_FOUND => Ok(()),
            status => Err(io::Error::from_raw_os_error(status as i32)),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn forward_row_v4_is_onlink_netmgmt() {
            let luid = NET_LUID_LH { Value: 42 };
            let row = forward_row(luid, "10.1.2.0".parse().unwrap(), 24);
            unsafe {
                assert_eq!(row.InterfaceLuid.Value, 42);
                assert_eq!(row.DestinationPrefix.PrefixLength, 24);
                assert_eq!(row.DestinationPrefix.Prefix.Ipv4.sin_family, AF_INET);
                assert_eq!(
                    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                    u32::from_ne_bytes([10, 1, 2, 0])
                );
                // On-link: next hop family set, address left unspecified.
                assert_eq!(row.NextHop.Ipv4.sin_family, AF_INET);
                assert_eq!(row.NextHop.Ipv4.sin_addr.S_un.S_addr, 0);
            }
            assert_eq!(row.Metric, ROUTE_METRIC);
            assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
        }

        #[test]
        fn forward_row_v6_is_onlink_netmgmt() {
            let luid = NET_LUID_LH { Value: 7 };
            let row = forward_row(luid, "fd00::".parse().unwrap(), 8);
            unsafe {
                assert_eq!(row.DestinationPrefix.PrefixLength, 8);
                assert_eq!(row.DestinationPrefix.Prefix.Ipv6.sin6_family, AF_INET6);
                assert_eq!(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte[0], 0xfd);
                assert_eq!(row.NextHop.Ipv6.sin6_family, AF_INET6);
                assert_eq!(row.NextHop.Ipv6.sin6_addr.u.Byte, [0u8; 16]);
            }
            assert_eq!(row.Metric, ROUTE_METRIC);
        }

        #[test]
        fn sockaddr_round_trips_both_families() {
            for ip in ["104.16.230.132", "2606:4700::6810:e684"] {
                let ip: IpAddr = ip.parse().unwrap();
                assert_eq!(ip_of(&sockaddr(ip)), Some(ip));
            }
        }

        #[test]
        fn an_unspecified_or_unknown_next_hop_is_on_link() {
            assert_eq!(ip_of(&sockaddr(Ipv4Addr::UNSPECIFIED.into())), None);
            assert_eq!(ip_of(&sockaddr(Ipv6Addr::UNSPECIFIED.into())), None);
            let unknown: SOCKADDR_INET = unsafe { std::mem::zeroed() };
            assert_eq!(ip_of(&unknown), None);
        }

        #[test]
        fn table_rows_reaches_every_row_past_the_declared_one() {
            use std::alloc::{Layout, alloc_zeroed, dealloc};
            use std::mem::{align_of, size_of};
            // A table as GetIpForwardTable2 lays one out: the header, then
            // two rows where the struct declares one.
            let layout = Layout::from_size_align(
                size_of::<MIB_IPFORWARD_TABLE2>() + size_of::<MIB_IPFORWARD_ROW2>(),
                align_of::<MIB_IPFORWARD_TABLE2>(),
            )
            .unwrap();
            unsafe {
                let table = alloc_zeroed(layout).cast::<MIB_IPFORWARD_TABLE2>();
                assert!(!table.is_null(), "allocation failed");
                (*table).NumEntries = 2;
                let first = std::ptr::addr_of_mut!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
                (*first).InterfaceIndex = 7;
                (*first.add(1)).InterfaceIndex = 9;
                let rows = table_rows(table);
                let indices: Vec<u32> = rows.iter().map(|row| row.InterfaceIndex).collect();
                assert_eq!(indices, [7, 9]);
                dealloc(table.cast(), layout);
            }
        }

        #[test]
        fn host_route_row_pins_the_address_via_the_gateway_on_the_interface() {
            let dest: IpAddr = "104.16.230.132".parse().unwrap();
            let gateway: IpAddr = "10.22.32.1".parse().unwrap();
            let row = host_route_row(3, dest, gateway);
            assert_eq!(row.InterfaceIndex, 3);
            assert_eq!(
                unsafe { row.InterfaceLuid.Value },
                0,
                "named by index, not LUID"
            );
            assert_eq!(row.DestinationPrefix.PrefixLength, 32);
            assert_eq!(ip_of(&row.DestinationPrefix.Prefix), Some(dest));
            assert_eq!(ip_of(&row.NextHop), Some(gateway));
            assert_eq!(row.Metric, ROUTE_METRIC);
            assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);

            let dest6: IpAddr = "2606:4700::6810:e684".parse().unwrap();
            let gateway6: IpAddr = "fe80::1".parse().unwrap();
            let row = host_route_row(5, dest6, gateway6);
            assert_eq!(row.DestinationPrefix.PrefixLength, 128);
            assert_eq!(ip_of(&row.NextHop), Some(gateway6));
        }
    }
}

/// macOS interface IPv4 configuration through the kernel APIs `ifconfig(8)`
/// and `route(8)` themselves use: the `SIOCAIFADDR` ioctl and an `RTM_ADD`
/// message on the `PF_ROUTE` routing socket. Both return a typed errno
/// (`EEXIST`) instead of text to parse, and spare a subprocess.
#[cfg(target_os = "macos")]
mod macos_net {
    use ipnet::Ipv4Net;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// `_IOW('i', 26, struct ifaliasreq)` from `<sys/sockio.h>`; libc does
    /// not export it.
    const SIOCAIFADDR: libc::c_ulong = 0x8000_0000 // IOC_IN
        | ((size_of::<libc::ifaliasreq>() as libc::c_ulong & 0x1fff) << 16)
        | ((b'i' as libc::c_ulong) << 8)
        | 26;

    fn socket(domain: libc::c_int, ty: libc::c_int) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(domain, ty, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Assign `address` with point-to-point peer `destination` and `netmask`
    /// to the interface. The kernel installs the host route to `destination`.
    pub fn set_ipv4_address(
        name: &str,
        address: Ipv4Addr,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> io::Result<()> {
        let req = alias_request(name, address, destination, netmask)?;
        let socket = socket(libc::AF_INET, libc::SOCK_DGRAM)?;
        if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCAIFADDR, &req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The `SIOCAIFADDR` request for [`set_ipv4_address`]; `name` must leave
    /// room for its NUL in `ifra_name`.
    fn alias_request(
        name: &str,
        address: Ipv4Addr,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> io::Result<libc::ifaliasreq> {
        let mut req: libc::ifaliasreq = unsafe { zeroed() };
        if name.len() >= req.ifra_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} is too long"),
            ));
        }
        for (dst, src) in req.ifra_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        req.ifra_addr = as_sockaddr(sockaddr_in(address));
        req.ifra_broadaddr = as_sockaddr(sockaddr_in(destination));
        req.ifra_mask = as_sockaddr(sockaddr_in(netmask));
        Ok(req)
    }

    fn as_sockaddr(sin: libc::sockaddr_in) -> libc::sockaddr {
        const _: () = assert!(size_of::<libc::sockaddr_in>() == size_of::<libc::sockaddr>());
        unsafe { std::mem::transmute(sin) }
    }

    /// An `RTM_ADD` request: the header followed by the `RTA_DST`,
    /// `RTA_GATEWAY` and `RTA_NETMASK` sockaddrs in address-bit order. Every
    /// part's size is a multiple of 4, so `repr(C)` packs them exactly as the
    /// kernel's 4-byte sockaddr alignment expects.
    #[repr(C)]
    struct AddRouteMessage {
        header: libc::rt_msghdr,
        dst: libc::sockaddr_in,
        gateway: libc::sockaddr_dl,
        netmask: libc::sockaddr_in,
    }

    fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
        let mut sa: libc::sockaddr_in = unsafe { zeroed() };
        sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
        sa
    }

    fn add_route_message(if_index: u16, subnet: Ipv4Net) -> AddRouteMessage {
        let mut msg: AddRouteMessage = unsafe { zeroed() };
        msg.header.rtm_msglen = size_of::<AddRouteMessage>() as u16;
        msg.header.rtm_version = libc::RTM_VERSION as u8;
        msg.header.rtm_type = libc::RTM_ADD as u8;
        msg.header.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
        msg.header.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
        msg.header.rtm_seq = 1;
        msg.dst = sockaddr_in(subnet.network());
        msg.gateway.sdl_len = size_of::<libc::sockaddr_dl>() as u8;
        msg.gateway.sdl_family = libc::AF_LINK as u8;
        msg.gateway.sdl_index = if_index;
        msg.netmask = sockaddr_in(subnet.netmask());
        msg
    }

    /// Add an on-link route for `subnet` through the interface `if_index`.
    ///
    /// The gateway is the interface's link-level address (a `sockaddr_dl`
    /// carrying only its index) with `RTF_GATEWAY` clear — the same interface
    /// route `route add -interface <utun>` creates.
    pub fn add_subnet_route(if_index: u16, subnet: Ipv4Net) -> io::Result<()> {
        let socket = socket(libc::PF_ROUTE, libc::SOCK_RAW)?;
        let msg = add_route_message(if_index, subnet);
        let written = unsafe {
            libc::write(
                socket.as_raw_fd(),
                (&msg as *const AddRouteMessage).cast(),
                size_of::<AddRouteMessage>(),
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn siocaifaddr_matches_sockio_h() {
            assert_eq!(SIOCAIFADDR, 0x8040_691a);
        }

        #[test]
        fn alias_request_fills_name_and_addresses() {
            let address = Ipv4Addr::new(10, 77, 0, 2);
            let destination = Ipv4Addr::new(10, 77, 0, 1);
            let netmask = Ipv4Addr::new(255, 255, 255, 0);
            let req = alias_request("utun12", address, destination, netmask).unwrap();
            let name: Vec<u8> = req.ifra_name.iter().map(|&c| c as u8).collect();
            assert_eq!(&name[..7], b"utun12\0");
            for (sa, addr) in [
                (req.ifra_addr, address),
                (req.ifra_broadaddr, destination),
                (req.ifra_mask, netmask),
            ] {
                assert_eq!(sa.sa_len as usize, size_of::<libc::sockaddr_in>());
                assert_eq!(sa.sa_family as i32, libc::AF_INET);
                // sa_data holds sin_port (zero) then sin_addr.
                let data: Vec<u8> = sa.sa_data.iter().map(|&c| c as u8).collect();
                assert_eq!(
                    &data[..6],
                    &[
                        0,
                        0,
                        addr.octets()[0],
                        addr.octets()[1],
                        addr.octets()[2],
                        addr.octets()[3]
                    ]
                );
            }

            // IFNAMSIZ is 16: 15 bytes plus the NUL fit, 16 do not.
            assert!(alias_request(&"u".repeat(15), address, destination, netmask).is_ok());
            let err = alias_request(&"u".repeat(16), address, destination, netmask).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn add_route_message_is_onlink_subnet_route() {
            let msg = add_route_message(7, "10.99.0.0/24".parse().unwrap());
            assert_eq!(
                size_of::<AddRouteMessage>(),
                size_of::<libc::rt_msghdr>() + 16 + 20 + 16
            );
            assert_eq!(msg.header.rtm_msglen as usize, size_of::<AddRouteMessage>());
            assert_eq!(msg.header.rtm_type as i32, libc::RTM_ADD);
            // On-link: no RTF_GATEWAY, no RTF_HOST.
            assert_eq!(msg.header.rtm_flags, libc::RTF_UP | libc::RTF_STATIC);
            assert_eq!(
                msg.header.rtm_addrs,
                libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
            );
            assert_eq!(msg.dst.sin_addr.s_addr, u32::from_ne_bytes([10, 99, 0, 0]));
            assert_eq!(msg.gateway.sdl_family as i32, libc::AF_LINK);
            assert_eq!(msg.gateway.sdl_index, 7);
            assert_eq!(
                msg.netmask.sin_addr.s_addr,
                u32::from_ne_bytes([255, 255, 255, 0])
            );
        }
    }
}

// ============================================================================
// Generic Route Trait and Implementations
// ============================================================================

/// Abstraction over concrete route types (IPv4/IPv6) that can be
/// programmatically added to and removed from the system routing table.
///
/// This trait is implemented by types that represent a single route entry
/// (for example, an IPv4 or IPv6 network/prefix). Implementations are
/// responsible for translating a route into the appropriate platform‑specific
/// command‑line arguments used by this module when configuring the TUN
/// interface.
///
/// # Design
///
/// `Route` is used by generic helper functions to:
///
/// - Add and remove routes for both IPv4 and IPv6 in a uniform way.
/// - Perform idempotent setup and rollback/cleanup when bringing interfaces
///   up or down.
/// - Produce human‑readable log messages via the [`Display`] bound.
///
/// The [`Copy`] bound is intentional: routes are small, value‑type
/// descriptors that are frequently passed by value, stored in collections
/// for potential rollback, and cloned when constructing error messages.
/// Requiring `Copy` keeps this ergonomic and ensures that implementations
/// remain lightweight (e.g., wrappers around `Ipv4Net`/`Ipv6Net` or similar
/// address/prefix types) rather than owning heap‑allocated state.
///
/// # When to implement
///
/// Implement this trait if you introduce a new route representation that
/// should participate in the shared add/remove/rollback logic in this
/// module—for example, to support an additional IP family or a different
/// way of encoding networks. Implementors must:
///
/// - Be cheap to copy (`Copy` + `Clone` semantics).
/// - Provide platform‑specific argument builders for macOS (`route` /
///   `networksetup`) and Linux (`ip route`), and the destination prefix for
///   the Windows IP Helper forward row.
///
/// Most consumers should not need to implement `Route` directly; instead they
/// use the existing concrete route types provided by this crate.
pub trait Route: std::fmt::Display + Copy {
    /// Label for log messages (e.g., "route" or "IPv6 route").
    const LABEL: &'static str;

    /// Build command args for adding a route on macOS.
    #[cfg(target_os = "macos")]
    fn macos_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on macOS.
    #[cfg(target_os = "macos")]
    fn macos_delete_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for adding a route on Linux.
    #[cfg(target_os = "linux")]
    fn linux_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on Linux.
    #[cfg(target_os = "linux")]
    fn linux_delete_args(&self, tun_name: &str) -> Vec<String>;

    /// Destination network address and prefix length for the Windows IP
    /// Helper forward row (`MIB_IPFORWARD_ROW2`). Windows routes are managed
    /// through the API rather than command args — see [`windows_routes`].
    #[cfg(target_os = "windows")]
    fn windows_prefix(&self) -> (IpAddr, u8);
}

impl Route for Ipv4Net {
    const LABEL: &'static str = "route";

    #[cfg(target_os = "macos")]
    fn macos_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "add".into(),
            "-net".into(),
            self.network().to_string(),
            "-netmask".into(),
            self.netmask().to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "macos")]
    fn macos_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "delete".into(),
            "-net".into(),
            self.network().to_string(),
            "-netmask".into(),
            self.netmask().to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "linux")]
    fn linux_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "route".into(),
            "add".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "linux")]
    fn linux_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "route".into(),
            "del".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "windows")]
    fn windows_prefix(&self) -> (IpAddr, u8) {
        (IpAddr::V4(self.network()), self.prefix_len())
    }
}

impl Route for Ipv6Net {
    const LABEL: &'static str = "IPv6 route";

    #[cfg(target_os = "macos")]
    fn macos_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "add".into(),
            "-inet6".into(),
            self.to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "macos")]
    fn macos_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "delete".into(),
            "-inet6".into(),
            self.to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "linux")]
    fn linux_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "linux")]
    fn linux_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "-6".into(),
            "route".into(),
            "del".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    #[cfg(target_os = "windows")]
    fn windows_prefix(&self) -> (IpAddr, u8) {
        (IpAddr::V6(self.network()), self.prefix_len())
    }
}

// ============================================================================
// Generic Route Operations
// ============================================================================

/// Whether a route-add command created the route or found it already present.
///
/// Pre-existing routes must not be tracked for cleanup: deleting them when a
/// guard drops would tear down routing state this process never created (e.g. a
/// default route or a bypass route the user already had).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAddOutcome {
    /// The route was added by this process; the caller owns its cleanup.
    Added,
    /// The route already existed; ownership stays with whoever created it.
    AlreadyExisted,
}

/// Handle the output of a route add command (macOS/Linux; Windows uses the
/// typed IP Helper results in [`windows_routes`] instead of parsing output).
///
/// - On success: logs info, returns [`RouteAddOutcome::Added`]
/// - On failure with "route exists": logs warning, returns
///   [`RouteAddOutcome::AlreadyExisted`] (idempotent, not owned for cleanup)
/// - On other failure: returns error
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn handle_route_add_output<R: Route>(
    output: std::process::Output,
    route: &R,
    tun_name: &str,
) -> VpnResult<RouteAddOutcome> {
    if output.status.success() {
        log::info!("Added {} {} via {}", R::LABEL, route, tun_name);
        return Ok(RouteAddOutcome::Added);
    }

    // On Windows, netsh outputs error messages to stdout, not stderr.
    // Check both stdout and stderr for error messages.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        format!("{} {}", stderr.trim(), stdout.trim())
    };

    if is_already_exists_error(&stderr) || is_already_exists_error(&stdout) {
        log::warn!(
            "{} {} already exists (treating as success): {}",
            R::LABEL,
            route,
            combined
        );
        Ok(RouteAddOutcome::AlreadyExisted)
    } else {
        Err(VpnError::tun_device(format!(
            "Failed to add {} {}: {}",
            R::LABEL,
            route,
            combined
        )))
    }
}

/// Handle the output of a route remove command (macOS/Linux, best-effort).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn handle_route_remove_output<R: Route>(output: std::process::Output, route: &R, tun_name: &str) {
    if output.status.success() {
        log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
    } else {
        // On Windows, netsh outputs error messages to stdout, not stderr.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let error_msg = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        log::warn!("Failed to remove {} {}: {}", R::LABEL, route, error_msg);
    }
}

/// Add a route through the VPN TUN interface (generic version).
async fn add_route_generic<R: Route>(tun_name: &str, route: &R) -> VpnResult<RouteAddOutcome> {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("route")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::tun_device_with_source("Failed to execute route command", e))?;

        handle_route_add_output(output, route, tun_name)
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("ip")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| {
                VpnError::tun_device_with_source("Failed to execute ip route command", e)
            })?;

        handle_route_add_output(output, route, tun_name)
    }

    #[cfg(target_os = "windows")]
    {
        let (dest, prefix_len) = route.windows_prefix();
        match windows_routes::add_route(tun_name, dest, prefix_len) {
            Ok(RouteAddOutcome::Added) => {
                log::info!("Added {} {} via {}", R::LABEL, route, tun_name);
                Ok(RouteAddOutcome::Added)
            }
            Ok(RouteAddOutcome::AlreadyExisted) => {
                log::warn!(
                    "{} {} already exists (treating as success)",
                    R::LABEL,
                    route
                );
                Ok(RouteAddOutcome::AlreadyExisted)
            }
            Err(e) => Err(VpnError::tun_device(format!(
                "Failed to add {} {} via {}: {}",
                R::LABEL,
                route,
                tun_name,
                e
            ))),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, route);
        Err(VpnError::tun_device(
            "Route management not supported on this platform",
        ))
    }
}

/// Remove a route from the system (generic async version).
async fn remove_route_generic<R: Route>(tun_name: &str, route: &R) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("route")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::tun_device_with_source("Failed to execute route command", e))?;

        handle_route_remove_output(output, route, tun_name);
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("ip")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| {
                VpnError::tun_device_with_source("Failed to execute ip route command", e)
            })?;

        handle_route_remove_output(output, route, tun_name);
    }

    #[cfg(target_os = "windows")]
    {
        let (dest, prefix_len) = route.windows_prefix();
        match windows_routes::delete_route(tun_name, dest, prefix_len) {
            Ok(()) => log::info!("Removed {} {} via {}", R::LABEL, route, tun_name),
            Err(e) => log::warn!("Failed to remove {} {}: {}", R::LABEL, route, e),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, route);
    }

    Ok(())
}

/// Remove a route from the system (generic blocking version for Drop).
fn remove_route_sync_generic<R: Route>(tun_name: &str, route: &R) {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("route").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute route delete command: {}", e);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("ip").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute ip route del command: {}", e);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // The IP Helper call is synchronous already, so the Drop path shares
        // the exact code the async path uses.
        let (dest, prefix_len) = route.windows_prefix();
        match windows_routes::delete_route(tun_name, dest, prefix_len) {
            Ok(()) => log::info!("Removed {} {} via {}", R::LABEL, route, tun_name),
            Err(e) => log::warn!("Failed to remove {} {}: {}", R::LABEL, route, e),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, route);
    }
}

// ============================================================================
// IPv4 Route Public API (delegates to generic implementations)
// ============================================================================

/// Add a route through the VPN TUN interface.
///
/// If the route already exists, this is treated as idempotent success
/// (logs a warning and continues).
///
/// # Platform Support
/// - macOS: Uses `route add -net <cidr> -interface <tun_device>`
/// - Linux: Uses `ip route add <cidr> dev <tun_device>`
pub async fn add_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<RouteAddOutcome> {
    add_route_generic(tun_name, route).await
}

/// Expand a full-tunnel default route into two `/1` half-routes.
///
/// A configured `0.0.0.0/0` is installed as `0.0.0.0/1` + `128.0.0.0/1` (and
/// `::/0` as `::/1` + `8000::/1`). Together these cover the whole address space,
/// but each is *more specific* than the system's existing `/0` default route, so
/// the original default — and the per-IP bypass host routes — stay authoritative
/// and we never have to clobber and later restore the real default route. This
/// mirrors wg-quick and OpenVPN's `redirect-gateway def1`. Any non-default route
/// passes through unchanged.
fn expand_default_route4(route: Ipv4Net) -> Vec<Ipv4Net> {
    if route.prefix_len() != 0 {
        return vec![route];
    }
    vec![
        Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 1).expect("0.0.0.0/1 is valid"),
        Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).expect("128.0.0.0/1 is valid"),
    ]
}

/// IPv6 counterpart to [`expand_default_route4`].
fn expand_default_route6(route: Ipv6Net) -> Vec<Ipv6Net> {
    if route.prefix_len() != 0 {
        return vec![route];
    }
    vec![
        Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 1).expect("::/1 is valid"),
        Ipv6Net::new(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1).expect("8000::/1 is valid"),
    ]
}

/// Add multiple routes through the VPN TUN interface.
///
/// Returns a `RouteGuard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
pub async fn add_routes(tun_name: &str, routes: &[Ipv4Net]) -> VpnResult<RouteGuard> {
    let routes: Vec<Ipv4Net> = routes
        .iter()
        .flat_map(|r| expand_default_route4(*r))
        .collect();
    let mut added: Vec<Ipv4Net> = Vec::with_capacity(routes.len());

    for route in &routes {
        match add_route(tun_name, route).await {
            Ok(RouteAddOutcome::Added) => added.push(*route),
            Ok(RouteAddOutcome::AlreadyExisted) => {
                // Route pre-existed: do not track it for cleanup so the guard
                // never deletes a route this process did not create.
                log::debug!("Route {} already existed; not tracking for cleanup", route);
            }
            Err(e) => {
                // Rollback previously added routes
                log::warn!(
                    "Failed to add route {}, rolling back {} route(s)",
                    route,
                    added.len()
                );
                for added_route in added.iter().rev() {
                    if let Err(rollback_err) = remove_route(tun_name, added_route).await {
                        log::warn!(
                            "Rollback failed for route {}: {}",
                            added_route,
                            rollback_err
                        );
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(RouteGuard::new(tun_name.to_string(), added))
}

/// Remove a route from the system (async version).
///
/// This is called during cleanup to remove routes added by add_route.
/// Best-effort: command failures are logged as warnings but don't return errors.
pub async fn remove_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<()> {
    remove_route_generic(tun_name, route).await
}

/// Remove a route from the system (blocking version for Drop).
fn remove_route_sync(tun_name: &str, route: &Ipv4Net) {
    remove_route_sync_generic(tun_name, route);
}

/// Guard that automatically removes routes when dropped.
///
/// This ensures routes are cleaned up even if the VPN connection
/// terminates unexpectedly or the program panics.
pub struct RouteGuard {
    tun_name: String,
    routes: Vec<Ipv4Net>,
}

impl RouteGuard {
    /// Create a new RouteGuard (internal use only).
    fn new(tun_name: String, routes: Vec<Ipv4Net>) -> Self {
        Self { tun_name, routes }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if self.routes.is_empty() {
            return;
        }
        log::info!(
            "Cleaning up {} route(s) via {}",
            self.routes.len(),
            self.tun_name
        );
        for route in self.routes.iter().rev() {
            remove_route_sync(&self.tun_name, route);
        }
    }
}

// ============================================================================
// IPv6 TUN and Route Management
// ============================================================================

/// Configure IPv6 address on TUN device (platform-specific).
#[cfg(target_os = "macos")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("ifconfig")
        .args([
            tun_name,
            "inet6",
            "add",
            &addr.to_string(),
            "prefixlen",
            &prefix_len.to_string(),
        ])
        .output()
        .map_err(|e| VpnError::tun_device_with_source("Failed to configure IPv6", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_lower = stderr.to_lowercase();
        // Treat idempotent "already exists" failures as success.
        if stderr_lower.contains("already exists") || stderr_lower.contains("file exists") {
            log::warn!(
                "IPv6 address {}/{} already exists on {} (treating as success): {}",
                addr,
                prefix_len,
                tun_name,
                stderr.trim()
            );
            return Ok(());
        }
        return Err(VpnError::tun_device(format!(
            "IPv6 configuration failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Configure IPv6 address on TUN device (platform-specific).
#[cfg(target_os = "linux")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("ip")
        .args([
            "-6",
            "addr",
            "add",
            &format!("{}/{}", addr, prefix_len),
            "dev",
            tun_name,
        ])
        .output()
        .map_err(|e| VpnError::tun_device_with_source("Failed to configure IPv6", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Treat "address already exists" as idempotent success
        if is_already_exists_error(&stderr) {
            log::warn!(
                "IPv6 address {}/{} already exists on {} (treating as success)",
                addr,
                prefix_len,
                tun_name
            );
            return Ok(());
        }
        return Err(VpnError::tun_device(format!(
            "IPv6 configuration failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Configure IPv6 address on TUN device (Windows).
#[cfg(target_os = "windows")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "interface",
            "ipv6",
            "add",
            "address",
            &format!("interface={}", tun_name),
            &format!("address={}/{}", addr, prefix_len),
        ])
        .output()
        .map_err(|e| VpnError::tun_device_with_source("Failed to configure IPv6", e))?;

    if !output.status.success() {
        // netsh reports errors on stdout, not stderr, so check both for the
        // "address already exists" case to keep configuration idempotent.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if is_already_exists_error(&stderr) || is_already_exists_error(&stdout) {
            log::warn!(
                "IPv6 address {}/{} already exists on {} (treating as success)",
                addr,
                prefix_len,
                tun_name
            );
            return Ok(());
        }
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(VpnError::tun_device(format!(
            "IPv6 configuration failed: {}",
            detail
        )));
    }

    Ok(())
}

/// Configure IPv6 address on TUN device (unsupported platform stub).
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn configure_tun_ipv6(_tun_name: &str, _addr: Ipv6Addr, _prefix_len: u8) -> VpnResult<()> {
    Err(VpnError::tun_device(
        "IPv6 configuration not supported on this platform",
    ))
}

/// Add an IPv6 route with an explicit source address.
///
/// This is important when the client has multiple IPv6 addresses (e.g., a real
/// public IPv6 and a VPN-assigned IPv6). Without specifying the source, the kernel
/// may select the wrong source address for packets routed through this route.
///
/// If the route already exists, this is treated as idempotent success.
pub async fn add_route6_with_src(
    tun_name: &str,
    route: &Ipv6Net,
    src: Ipv6Addr,
) -> VpnResult<RouteAddOutcome> {
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support source address in routes the same way
        // Fall back to standard route addition
        log::debug!(
            "macOS: ignoring source address {} for IPv6 route {} via {}",
            src,
            route,
            tun_name
        );
        add_route_generic(tun_name, route).await
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args([
                "-6",
                "route",
                "add",
                &route.to_string(),
                "dev",
                tun_name,
                "src",
                &src.to_string(),
            ])
            .output()
            .await
            .map_err(|e| {
                VpnError::tun_device_with_source("Failed to execute ip route command", e)
            })?;

        if output.status.success() {
            log::info!("Added IPv6 route {} via {} src {}", route, tun_name, src);
            return Ok(RouteAddOutcome::Added);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_trimmed = stderr.trim();
        if is_already_exists_error(&stderr) {
            log::warn!(
                "IPv6 route {} already exists (treating as success): {}",
                route,
                stderr_trimmed
            );
            Ok(RouteAddOutcome::AlreadyExisted)
        } else {
            Err(VpnError::tun_device(format!(
                "Failed to add IPv6 route {}: {}",
                route, stderr_trimmed
            )))
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows doesn't support source address in routes the same way
        // Fall back to standard route addition
        log::debug!(
            "Windows: ignoring source address {} for IPv6 route {} via {}",
            src,
            route,
            tun_name
        );
        add_route_generic(tun_name, route).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, route, src);
        Err(VpnError::tun_device(
            "Route management not supported on this platform",
        ))
    }
}

/// Remove an IPv6 route from the system (async version).
pub async fn remove_route6(tun_name: &str, route: &Ipv6Net) -> VpnResult<()> {
    remove_route_generic(tun_name, route).await
}

/// Remove an IPv6 route from the system (blocking version for Drop).
fn remove_route6_sync(tun_name: &str, route: &Ipv6Net) {
    remove_route_sync_generic(tun_name, route);
}

/// Add multiple IPv6 routes through the VPN TUN interface.
///
/// Returns a `Route6Guard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
/// Add multiple IPv6 routes with an explicit source address.
///
/// This variant specifies the source address for route selection, which is
/// important when the client has multiple IPv6 addresses. Without specifying
/// the source, the kernel may select the wrong source address.
///
/// Returns a `Route6Guard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
pub async fn add_routes6_with_src(
    tun_name: &str,
    routes: &[Ipv6Net],
    src: Ipv6Addr,
) -> VpnResult<Route6Guard> {
    let routes: Vec<Ipv6Net> = routes
        .iter()
        .flat_map(|r| expand_default_route6(*r))
        .collect();
    let mut added: Vec<Ipv6Net> = Vec::with_capacity(routes.len());

    for route in &routes {
        match add_route6_with_src(tun_name, route, src).await {
            Ok(RouteAddOutcome::Added) => added.push(*route),
            Ok(RouteAddOutcome::AlreadyExisted) => {
                // Route pre-existed: do not track it for cleanup so the guard
                // never deletes a route this process did not create.
                log::debug!(
                    "IPv6 route {} already existed; not tracking for cleanup",
                    route
                );
            }
            Err(e) => {
                // Rollback previously added routes
                log::warn!(
                    "Failed to add IPv6 route {}, rolling back {} route(s)",
                    route,
                    added.len()
                );
                for added_route in added.iter().rev() {
                    if let Err(rollback_err) = remove_route6(tun_name, added_route).await {
                        log::warn!(
                            "Rollback failed for IPv6 route {}: {}",
                            added_route,
                            rollback_err
                        );
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(Route6Guard::new(tun_name.to_string(), added))
}

/// Guard that automatically removes IPv6 routes when dropped.
///
/// This ensures routes are cleaned up even if the VPN connection
/// terminates unexpectedly or the program panics.
pub struct Route6Guard {
    tun_name: String,
    routes: Vec<Ipv6Net>,
}

impl Route6Guard {
    /// Create a new Route6Guard (internal use only).
    fn new(tun_name: String, routes: Vec<Ipv6Net>) -> Self {
        Self { tun_name, routes }
    }
}

impl Drop for Route6Guard {
    fn drop(&mut self) {
        if self.routes.is_empty() {
            return;
        }
        log::info!(
            "Cleaning up {} IPv6 route(s) via {}",
            self.routes.len(),
            self.tun_name
        );
        for route in self.routes.iter().rev() {
            remove_route6_sync(&self.tun_name, route);
        }
    }
}

// ============================================================================
// Bypass Route Management (for ICE peer addresses)
// ============================================================================

/// Information about a bypass route for an ICE peer.
#[derive(Debug)]
#[allow(dead_code)] // peer_ip is used on Linux/macOS but not on Windows
struct BypassRouteInfo {
    /// The peer address to bypass.
    peer_ip: IpAddr,
    /// The device/interface to route through.
    device: String,
    /// The gateway (optional, for some routes it's direct).
    gateway: Option<IpAddr>,
    /// Raw gateway string with scope ID preserved (e.g., "fe80::1%en0").
    /// Used on macOS where link-local addresses need the scope.
    gateway_str: Option<String>,
    /// Interface index of the resolving interface. Set on Windows (used to pin
    /// the host route to that interface); `None` elsewhere.
    if_index: Option<u32>,
}

/// The system's default-route next hop for one address family, captured while
/// the routing table is still pristine (before any VPN routes are installed).
///
/// Used as a fallback by [`add_bypass_route`]: a direct iroh path is often
/// discovered *after* the VPN routes are up, so by the time we try to bypass
/// the peer's underlay IP, `route get` for it already resolves through the VPN
/// tunnel and can no longer reveal the real next hop. Re-pinning the host route
/// via this captured gateway keeps that underlay traffic off the tunnel.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are read on Linux/macOS but not on Windows
pub struct UnderlayGateway {
    /// The underlay interface (e.g. `en0`, `eth0`).
    device: String,
    /// The default-route gateway address.
    gateway: Option<IpAddr>,
    /// Raw gateway string with scope ID preserved (e.g. `fe80::1%en0`).
    gateway_str: Option<String>,
    /// Interface index of the default-route interface. Set on Windows; `None`
    /// elsewhere.
    if_index: Option<u32>,
}

/// Query the system's default-route gateway for one address family.
///
/// Must be called while the routing table is still pristine (before VPN routes
/// are installed) so the result reflects the real underlay next hop. Returns an
/// error if no default route exists or the platform is unsupported.
#[cfg(target_os = "linux")]
pub async fn query_default_gateway(is_ipv6: bool) -> VpnResult<UnderlayGateway> {
    let args: Vec<&str> = if is_ipv6 {
        vec!["-6", "route", "show", "default"]
    } else {
        vec!["-4", "route", "show", "default"]
    };
    let output = Command::new("ip")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::tun_device_with_source("Failed to query default route", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::tun_device(format!(
            "Failed to query default route: {}",
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `ip route show default` may list several routes; the first non-empty line
    // ("default via <gw> dev <dev> ...") is enough to recover the next hop.
    let line = stdout.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let placeholder = unspecified_addr(is_ipv6);
    let info = parse_linux_route_get(line, placeholder)?;
    Ok(UnderlayGateway {
        device: info.device,
        gateway: info.gateway,
        gateway_str: info.gateway_str,
        if_index: None,
    })
}

/// Query the system's default-route gateway for one address family (macOS).
#[cfg(target_os = "macos")]
pub async fn query_default_gateway(is_ipv6: bool) -> VpnResult<UnderlayGateway> {
    let args: Vec<&str> = if is_ipv6 {
        vec!["-n", "get", "-inet6", "default"]
    } else {
        vec!["-n", "get", "default"]
    };
    let output = Command::new("route")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::tun_device_with_source("Failed to query default route", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::tun_device(format!(
            "Failed to query default route: {}",
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let placeholder = unspecified_addr(is_ipv6);
    let info = parse_macos_route_get(&stdout, placeholder)?;
    Ok(UnderlayGateway {
        device: info.device,
        gateway: info.gateway,
        gateway_str: info.gateway_str,
        if_index: None,
    })
}

/// Query the system's default-route gateway for one address family (Windows).
///
/// Picks the default route (`0.0.0.0/0` / `::/0`) with the lowest *effective*
/// metric (route metric + interface metric) on a connected interface, matching
/// the kernel's route selection.
#[cfg(target_os = "windows")]
pub async fn query_default_gateway(is_ipv6: bool) -> VpnResult<UnderlayGateway> {
    let route = windows_routes::default_route(is_ipv6)
        .map_err(|e| VpnError::tun_device(format!("Failed to query default route: {e}")))?;
    Ok(UnderlayGateway {
        device: route.alias,
        gateway: route.next_hop,
        gateway_str: route.next_hop.map(|g| g.to_string()),
        if_index: Some(route.if_index),
    })
}

/// Query the system's default-route gateway (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub async fn query_default_gateway(_is_ipv6: bool) -> VpnResult<UnderlayGateway> {
    Err(VpnError::tun_device(
        "Default gateway query not supported on this platform",
    ))
}

/// The unspecified address for an address family, used as a placeholder peer IP
/// when reusing the per-IP route parsers for default-route output.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unspecified_addr(is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

/// Query the current route for a given IP address.
///
/// Returns the device and optional gateway that the OS would use to reach this IP.
#[cfg(target_os = "linux")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let ip_str = ip.to_string();
    let args: Vec<&str> = if ip.is_ipv4() {
        vec!["route", "get", &ip_str]
    } else {
        vec!["-6", "route", "get", &ip_str]
    };

    let output = Command::new("ip")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::tun_device_with_source("Failed to query route", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::tun_device(format!(
            "Failed to query route for {}: {}",
            ip,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_linux_route_get(&stdout, ip)
}

/// Validate that a gateway string contains only expected characters.
///
/// Gateway strings should only contain:
/// - Hex digits (0-9, A-F, a-f) for IPv6 addresses
/// - Decimal digits (0-9) for IPv4 addresses
/// - Colons (:) for IPv6 separators
/// - Dots (.) for IPv4 separators
/// - Percent sign (%) for scope ID delimiter (e.g., fe80::1%en0)
/// - Alphanumeric characters after % for interface names
///
/// This validation prevents command injection when the gateway string
/// is passed to route commands.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_valid_gateway_str(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Split on '%' to handle scope ID separately
    let parts: Vec<&str> = s.splitn(2, '%').collect();
    let addr_part = parts[0];
    let scope_part = parts.get(1);

    // Validate the address part: only hex digits, colons, and dots
    let addr_valid = addr_part
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');

    if !addr_valid {
        return false;
    }

    // If there's a scope part, validate it: alphanumeric and common interface chars
    if let Some(scope) = scope_part {
        // Interface names can contain alphanumeric chars, underscores, and hyphens
        let scope_valid = !scope.is_empty()
            && scope
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !scope_valid {
            return false;
        }
    }

    true
}

/// Parse the output of `ip route get` on Linux.
#[cfg(target_os = "linux")]
fn parse_linux_route_get(output: &str, peer_ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    // Example output:
    // 2600:1f13:adc:a0b1::1 from :: via fe80::1 dev eth0 proto static src 2603:8002:... metric 100
    // or for direct routes:
    // 10.0.0.1 dev eth0 src 10.0.0.2 uid 0

    let mut device: Option<String> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut gateway_str: Option<String> = None;

    let tokens: Vec<&str> = output.split_whitespace().collect();
    for i in 0..tokens.len() {
        if tokens[i] == "dev" && i + 1 < tokens.len() {
            device = Some(tokens[i + 1].to_string());
        }
        if tokens[i] == "via" && i + 1 < tokens.len() {
            let gw_str = tokens[i + 1];
            // Validate gateway string before using it
            if is_valid_gateway_str(gw_str) {
                gateway_str = Some(gw_str.to_string());
                gateway = gw_str.parse().ok();
            } else {
                log::debug!(
                    "Ignoring malformed gateway string in route output: {:?}",
                    gw_str
                );
            }
        }
    }

    let device = device.ok_or_else(|| {
        VpnError::tun_device(format!(
            "Could not determine device for route to {}",
            peer_ip
        ))
    })?;

    Ok(BypassRouteInfo {
        peer_ip,
        device,
        gateway,
        gateway_str,
        if_index: None,
    })
}

/// Query the current route for a given IP address (macOS).
#[cfg(target_os = "macos")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let ip_str = ip.to_string();
    let args: Vec<&str> = if ip.is_ipv4() {
        vec!["get", &ip_str]
    } else {
        vec!["get", "-inet6", &ip_str]
    };

    let output = Command::new("route")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::tun_device_with_source("Failed to query route", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::tun_device(format!(
            "Failed to query route for {}: {}",
            ip,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_macos_route_get(&stdout, ip)
}

/// Parse the output of `route get` on macOS.
#[cfg(target_os = "macos")]
fn parse_macos_route_get(output: &str, peer_ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    // Example output:
    //    route to: 2600:1f13:adc:a0b1::1
    // destination: default
    //        mask: default
    //     gateway: fe80::1%en0
    //   interface: en0

    let mut device: Option<String> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut gateway_str: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            device = Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("gateway:") {
            let gw_str = rest.trim();
            // Validate gateway string before using it to prevent command injection
            if is_valid_gateway_str(gw_str) {
                // Preserve raw gateway string (may include scope like fe80::1%en0)
                gateway_str = Some(gw_str.to_string());
                // Parse IpAddr by stripping scope (for non-route uses)
                let gw_clean = gw_str.split('%').next().unwrap_or(gw_str);
                gateway = gw_clean.parse().ok();
            } else {
                log::debug!(
                    "Ignoring malformed gateway string in route output: {:?}",
                    gw_str
                );
            }
        }
    }

    let device = device.ok_or_else(|| {
        VpnError::tun_device(format!(
            "Could not determine interface for route to {}",
            peer_ip
        ))
    })?;

    Ok(BypassRouteInfo {
        peer_ip,
        device,
        gateway,
        gateway_str,
        if_index: None,
    })
}

/// Query the current route for a given IP address (Windows).
///
/// `GetBestRoute2` runs the kernel's route selection (longest prefix, then
/// metric) for the address, as `route get` does elsewhere.
#[cfg(target_os = "windows")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let route = windows_routes::best_route(ip)
        .map_err(|e| VpnError::tun_device(format!("Failed to query route for {ip}: {e}")))?;
    Ok(BypassRouteInfo {
        peer_ip: ip,
        device: route.alias,
        gateway: route.next_hop,
        gateway_str: route.next_hop.map(|g| g.to_string()),
        if_index: Some(route.if_index),
    })
}

/// Query the current route for a given IP address (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn query_route_for_ip(_ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    Err(VpnError::tun_device(
        "Bypass route detection not supported on this platform",
    ))
}

/// Add a bypass route for an ICE peer address.
///
/// This ensures that traffic to the ICE peer continues to use the original
/// network path even after VPN routes are installed. This is critical because
/// the ICE peer address may fall within a VPN route prefix, which would cause
/// ICE keepalive traffic to be black-holed through the VPN tunnel.
///
/// Returns a guard that removes the bypass route when dropped.
///
/// If `disallow_device` is provided, route lookups that resolve through that
/// interface are rejected. This prevents self-capture where iroh underlay
/// traffic is accidentally routed back into the VPN TUN interface.
///
/// `underlay_fallback` is the default-route next hop captured before the VPN
/// routes were installed. When the route to `peer_addr` now resolves through
/// `disallow_device` (the VPN routes captured this underlay IP before we could
/// bypass it — typically a direct path discovered after the VPN routes went
/// up), the host route is re-pinned via this captured gateway instead of being
/// refused.
pub async fn add_bypass_route(
    peer_addr: SocketAddr,
    disallow_device: Option<&str>,
    underlay_fallback: Option<&UnderlayGateway>,
) -> VpnResult<BypassRouteGuard> {
    let peer_ip = peer_addr.ip();

    // Query current route to this IP before adding any VPN routes, then apply
    // the captured-underlay-gateway fallback if the queried route is unusable.
    let route_info = query_route_for_ip(peer_ip).await?;
    let route_info = resolve_bypass_route_info(route_info, disallow_device, underlay_fallback)?;

    log::info!(
        "Adding bypass route for ICE peer {} via {} (gateway: {:?})",
        peer_ip,
        route_info.device,
        route_info.gateway
    );

    // Add the host-specific route. The route is on the underlay interface,
    // so nothing but its guard ever removes it, and the two must not come
    // apart.
    run_uncancelled(move || {
        let outcome = add_bypass_route_impl(&route_info)?;
        Ok(BypassRouteGuard {
            peer_ip,
            device: route_info.device,
            gateway: route_info.gateway,
            gateway_str: route_info.gateway_str,
            if_index: route_info.if_index,
            // Only remove the route on drop if this process actually created it; a
            // pre-existing route belongs to the system and must be left intact.
            owned: outcome == RouteAddOutcome::Added,
        })
    })
    .await
}

/// Run `add`, which changes the system and returns the guard that undoes the
/// change, so that the change never outlives its guard: on a blocking thread,
/// to its end, whatever becomes of the caller.
///
/// A caller that is cancelled while it waits (a stop during the connect drops
/// the whole run future) would otherwise leave a command that is still
/// running to finish with nobody holding the guard. Here `add` still returns
/// its guard, to a task nobody waits for, which drops it and so undoes the
/// change. A runtime that is dropped waits for that too; one shut down
/// without waiting ([`tokio::runtime::Runtime::shutdown_background`]) does
/// not.
async fn run_uncancelled<G: Send + 'static>(
    add: impl FnOnce() -> VpnResult<G> + Send + 'static,
) -> VpnResult<G> {
    tokio::task::spawn_blocking(add)
        .await
        .map_err(|e| VpnError::tun_device(format!("Route change did not run to its end: {e}")))?
}

/// Decide the route info to use for a bypass route, applying the captured
/// underlay-gateway fallback when the freshly queried route is unusable.
///
/// Two cases need the fallback, both re-pinning via the underlay default gateway
/// captured before the VPN routes went up:
///
/// 1. **Resolves through the VPN tunnel** (`route_info.device == disallow_device`):
///    a direct iroh path discovered after the VPN routes went up, so `route get`
///    now follows the tunnel; following it would self-capture the peer's underlay
///    traffic.
/// 2. **No next-hop gateway** (`route_info.gateway.is_none()`) while resolving via
///    a physical interface: typically a transient startup state where the per-IP
///    route is a cloned entry off the default route whose next hop has not been
///    populated yet (observed on macOS as `route get` returning only
///    `interface:`). Installing a gateway-less route would create an
///    address-black-holing link-scope host route, so we re-pin via the captured
///    gateway instead — a relay/server underlay IP is reached via the default
///    route, so that gateway is the correct next hop.
///
/// Returns an error only when the route is unusable *and* there is no usable
/// captured gateway to fall back to. Pure (no I/O) so it is unit-testable.
fn resolve_bypass_route_info(
    mut route_info: BypassRouteInfo,
    disallow_device: Option<&str>,
    underlay_fallback: Option<&UnderlayGateway>,
) -> VpnResult<BypassRouteInfo> {
    let peer_ip = route_info.peer_ip;

    let repin_via_fallback = |route_info: &mut BypassRouteInfo, fb: &UnderlayGateway| {
        route_info.device = fb.device.clone();
        route_info.gateway = fb.gateway;
        route_info.gateway_str = fb.gateway_str.clone();
        route_info.if_index = fb.if_index;
    };

    if disallow_device.is_some_and(|disallowed| route_info.device == disallowed) {
        // Case 1: resolves through the VPN tunnel.
        match underlay_fallback {
            Some(fb) if fb.gateway.is_some() => {
                log::info!(
                    "Bypass route for {} resolved via VPN tunnel {}; re-pinning via captured underlay gateway {} (dev {})",
                    peer_ip,
                    route_info.device,
                    fb.gateway_str.as_deref().unwrap_or("?"),
                    fb.device
                );
                repin_via_fallback(&mut route_info, fb);
            }
            _ => {
                return Err(VpnError::tun_device(format!(
                    "Refusing bypass route for {}: route lookup resolved via VPN tunnel interface {} (no captured underlay gateway to fall back to)",
                    peer_ip, route_info.device
                )));
            }
        }
    } else if route_info.gateway.is_none() {
        // Case 2: physical interface but no next-hop gateway.
        match underlay_fallback {
            Some(fb) if fb.gateway.is_some() => {
                log::info!(
                    "Bypass route for {} resolved via {} with no next-hop gateway; \
                     falling back to captured underlay gateway {} (dev {})",
                    peer_ip,
                    route_info.device,
                    fb.gateway_str.as_deref().unwrap_or("?"),
                    fb.device
                );
                repin_via_fallback(&mut route_info, fb);
            }
            _ => {
                return Err(VpnError::tun_device(format!(
                    "Refusing bypass route for {}: no next-hop gateway resolved via {} \
                     and no captured underlay gateway to fall back to \
                     (would create a link-scope route that black-holes the address)",
                    peer_ip, route_info.device
                )));
            }
        }
    }

    Ok(route_info)
}

/// Implementation of adding a bypass route (Linux, blocking).
#[cfg(target_os = "linux")]
fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
    let prefix = if info.peer_ip.is_ipv4() { 32 } else { 128 };

    let mut args: Vec<String> = Vec::new();
    if info.peer_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        "add".to_string(),
        format!("{}/{}", info.peer_ip, prefix),
    ]);

    // `add_bypass_route` guarantees a gateway is present; refuse a `dev`-only
    // link-scope route, which would black-hole a remote underlay address.
    let Some(gw) = info.gateway else {
        return Err(VpnError::tun_device(format!(
            "Refusing link-scope bypass route for {} (no gateway)",
            info.peer_ip
        )));
    };
    args.extend(["via".to_string(), gw.to_string()]);
    args.extend(["dev".to_string(), info.device.clone()]);

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = std::process::Command::new("ip")
        .args(&args_ref)
        .output()
        .map_err(|e| VpnError::tun_device_with_source("Failed to add bypass route", e))?;

    if output.status.success() {
        log::info!(
            "Added bypass route {}/{} via {}",
            info.peer_ip,
            prefix,
            info.device
        );
        return Ok(RouteAddOutcome::Added);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_already_exists_error(&stderr) {
        log::warn!(
            "Bypass route {}/{} already exists (treating as success)",
            info.peer_ip,
            prefix
        );
        return Ok(RouteAddOutcome::AlreadyExisted);
    }

    Err(VpnError::tun_device(format!(
        "Failed to add bypass route {}/{}: {}",
        info.peer_ip,
        prefix,
        stderr.trim()
    )))
}

/// Implementation of adding a bypass route (macOS, blocking).
#[cfg(target_os = "macos")]
fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
    let mut args: Vec<String> = vec!["add".to_string()];

    if info.peer_ip.is_ipv6() {
        args.push("-inet6".to_string());
    }

    args.push("-host".to_string());
    args.push(info.peer_ip.to_string());

    // Use raw gateway_str to preserve scope ID for link-local addresses (e.g., fe80::1%en0).
    // `add_bypass_route` guarantees a gateway is present; refuse the link-scope
    // `-interface` form, which would black-hole a remote underlay address.
    let Some(ref gw_str) = info.gateway_str else {
        return Err(VpnError::tun_device(format!(
            "Refusing link-scope bypass route for {} (no gateway)",
            info.peer_ip
        )));
    };
    args.push(gw_str.clone());

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = std::process::Command::new("route")
        .args(&args_ref)
        .output()
        .map_err(|e| VpnError::tun_device_with_source("Failed to add bypass route", e))?;

    if output.status.success() {
        log::info!(
            "Added bypass route for {} via {}",
            info.peer_ip,
            info.device
        );
        return Ok(RouteAddOutcome::Added);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_already_exists_error(&stderr) {
        log::warn!(
            "Bypass route for {} already exists (treating as success)",
            info.peer_ip
        );
        return Ok(RouteAddOutcome::AlreadyExisted);
    }

    Err(VpnError::tun_device(format!(
        "Failed to add bypass route for {}: {}",
        info.peer_ip,
        stderr.trim()
    )))
}

/// Implementation of adding a bypass route (Windows, blocking).
#[cfg(target_os = "windows")]
fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
    let prefix = if info.peer_ip.is_ipv4() { 32 } else { 128 };

    // `add_bypass_route` guarantees a gateway is present; refuse the link-scope
    // form, which would black-hole a remote underlay address.
    let Some(gw) = info.gateway else {
        return Err(VpnError::tun_device(format!(
            "Refusing link-scope bypass route for {} (no gateway)",
            info.peer_ip
        )));
    };
    let Some(if_index) = info.if_index else {
        return Err(VpnError::tun_device(format!(
            "Refusing bypass route for {} (no interface index resolved)",
            info.peer_ip
        )));
    };

    match windows_routes::add_host_route(if_index, info.peer_ip, gw) {
        Ok(RouteAddOutcome::Added) => {
            log::info!(
                "Added bypass route {}/{} via if {} gw {}",
                info.peer_ip,
                prefix,
                if_index,
                gw
            );
            Ok(RouteAddOutcome::Added)
        }
        Ok(RouteAddOutcome::AlreadyExisted) => {
            log::warn!(
                "Bypass route {}/{} already exists (treating as success)",
                info.peer_ip,
                prefix
            );
            Ok(RouteAddOutcome::AlreadyExisted)
        }
        Err(e) => Err(VpnError::tun_device(format!(
            "Failed to add bypass route {}/{}: {}",
            info.peer_ip, prefix, e
        ))),
    }
}

/// Implementation of adding a bypass route (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn add_bypass_route_impl(_info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
    Err(VpnError::tun_device(
        "Bypass route not supported on this platform",
    ))
}

/// Guard that removes a bypass route when dropped.
pub struct BypassRouteGuard {
    peer_ip: IpAddr,
    device: String,
    gateway: Option<IpAddr>,
    /// Raw gateway string with scope ID preserved (e.g., "fe80::1%en0").
    gateway_str: Option<String>,
    /// Interface index of the resolving interface. Set on Windows (used to
    /// remove the host route from that interface); `None` elsewhere.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    if_index: Option<u32>,
    /// True only when this process added the route, so dropping must remove it.
    /// A pre-existing route is left untouched on drop.
    owned: bool,
}

#[cfg(test)]
impl BypassRouteGuard {
    /// Test-only constructor for a **non-owning** guard. `owned` is `false`, so
    /// `Drop` is a no-op and runs no OS route commands — letting tests pre-seed
    /// `BypassRouteManager::active_routes` without touching the system.
    pub(crate) fn test_unowned(peer_ip: IpAddr) -> Self {
        Self {
            peer_ip,
            device: String::new(),
            gateway: None,
            gateway_str: None,
            if_index: None,
            owned: false,
        }
    }
}

impl Drop for BypassRouteGuard {
    fn drop(&mut self) {
        if !self.owned {
            log::debug!(
                "Bypass route for {} pre-existed; leaving it in place",
                self.peer_ip
            );
            return;
        }
        log::info!("Removing bypass route for {}", self.peer_ip);
        remove_bypass_route_sync(
            self.peer_ip,
            &self.device,
            self.gateway,
            self.gateway_str.as_deref(),
            self.if_index,
        );
    }
}

/// Remove a bypass route (Linux, blocking).
#[cfg(target_os = "linux")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    device: &str,
    gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
    _if_index: Option<u32>,
) {
    let host_route = if peer_ip.is_ipv4() {
        format!("{}/32", peer_ip)
    } else {
        format!("{}/128", peer_ip)
    };

    let mut args: Vec<String> = Vec::new();
    if peer_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "del".to_string(), host_route.clone()]);

    if let Some(gw) = gateway {
        args.extend(["via".to_string(), gw.to_string()]);
    }
    args.extend(["dev".to_string(), device.to_string()]);

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match std::process::Command::new("ip").args(&args_ref).output() {
        Ok(output) if output.status.success() => {
            log::info!("Removed bypass route {}", host_route);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!(
                "Failed to remove bypass route {}: {}",
                host_route,
                stderr.trim()
            );
        }
        Err(e) => {
            log::warn!("Failed to execute route delete: {}", e);
        }
    }
}

/// Remove a bypass route (macOS, blocking).
#[cfg(target_os = "macos")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    _device: &str,
    _gateway: Option<IpAddr>,
    gateway_str: Option<&str>,
    _if_index: Option<u32>,
) {
    let mut args: Vec<String> = vec!["delete".to_string()];

    if peer_ip.is_ipv6() {
        args.push("-inet6".to_string());
    }

    args.push("-host".to_string());
    args.push(peer_ip.to_string());

    // Use raw gateway_str to preserve scope ID for link-local addresses (e.g., fe80::1%en0)
    if let Some(gw_str) = gateway_str {
        args.push(gw_str.to_string());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match std::process::Command::new("route").args(&args_ref).output() {
        Ok(output) if output.status.success() => {
            log::info!("Removed bypass route for {}", peer_ip);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!(
                "Failed to remove bypass route for {}: {}",
                peer_ip,
                stderr.trim()
            );
        }
        Err(e) => {
            log::warn!("Failed to execute route delete: {}", e);
        }
    }
}

/// Remove a bypass route (Windows, blocking).
#[cfg(target_os = "windows")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    _device: &str,
    gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
    if_index: Option<u32>,
) {
    let prefix = if peer_ip.is_ipv4() { 32 } else { 128 };

    // An owned route always has both: `add_bypass_route_impl` refuses one
    // without them.
    let (Some(if_index), Some(gw)) = (if_index, gateway) else {
        log::warn!(
            "Cannot remove bypass route for {}/{} (no interface index or gateway recorded)",
            peer_ip,
            prefix
        );
        return;
    };

    match windows_routes::delete_host_route(if_index, peer_ip, gw) {
        Ok(true) => log::info!("Removed bypass route {}/{}", peer_ip, prefix),
        Ok(false) => log::info!("Bypass route {}/{} was already gone", peer_ip, prefix),
        Err(e) => log::warn!(
            "Failed to remove bypass route {}/{}: {}",
            peer_ip,
            prefix,
            e
        ),
    }
}

/// Remove a bypass route (unsupported platforms, blocking).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn remove_bypass_route_sync(
    _peer_ip: IpAddr,
    _device: &str,
    _gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
    _if_index: Option<u32>,
) {
    // Not implemented
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    /// A caller cancelled while the change is being made must not leave it
    /// behind: the change still runs to its end, and its guard is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_run_uncancelled_undoes_the_change_of_a_cancelled_caller() {
        use std::sync::mpsc;
        use std::time::Duration;

        struct Undo(mpsc::Sender<&'static str>);
        impl Drop for Undo {
            fn drop(&mut self) {
                let _ = self.0.send("undone");
            }
        }

        let (events_tx, events) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let caller = tokio::spawn(run_uncancelled(move || {
            events_tx.send("started").unwrap();
            // The command is still running when the caller goes away.
            released.recv().unwrap();
            events_tx.send("changed").unwrap();
            Ok(Undo(events_tx))
        }));

        let wait = Duration::from_secs(10);
        assert_eq!(events.recv_timeout(wait), Ok("started"));
        caller.abort();
        assert!(caller.await.is_err_and(|e| e.is_cancelled()));
        release.send(()).unwrap();
        assert_eq!(events.recv_timeout(wait), Ok("changed"));
        assert_eq!(events.recv_timeout(wait), Ok("undone"));
    }

    #[test]
    fn test_expand_default_route4_splits_only_default() {
        // 0.0.0.0/0 -> two /1 halves
        let split = expand_default_route4("0.0.0.0/0".parse().unwrap());
        assert_eq!(
            split,
            vec![
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap(),
            ]
        );

        // Non-default routes pass through unchanged.
        let specific: Ipv4Net = "172.31.0.0/16".parse().unwrap();
        assert_eq!(expand_default_route4(specific), vec![specific]);
    }

    #[test]
    fn test_expand_default_route6_splits_only_default() {
        let split = expand_default_route6("::/0".parse().unwrap());
        assert_eq!(
            split,
            vec![
                "::/1".parse::<Ipv6Net>().unwrap(),
                "8000::/1".parse::<Ipv6Net>().unwrap(),
            ]
        );

        let specific: Ipv6Net = "2600:1f13:adc:a000::/56".parse().unwrap();
        assert_eq!(expand_default_route6(specific), vec![specific]);
    }

    /// Build a `BypassRouteInfo` for `resolve_bypass_route_info` tests.
    fn test_route_info(device: &str, gateway: Option<&str>) -> BypassRouteInfo {
        BypassRouteInfo {
            peer_ip: "203.0.113.7".parse().unwrap(),
            device: device.to_string(),
            gateway: gateway.map(|g| g.parse().unwrap()),
            gateway_str: gateway.map(|g| g.to_string()),
            if_index: None,
        }
    }

    /// Build an `UnderlayGateway` for `resolve_bypass_route_info` tests.
    fn test_underlay(device: &str, gateway: Option<&str>) -> UnderlayGateway {
        UnderlayGateway {
            device: device.to_string(),
            gateway: gateway.map(|g| g.parse().unwrap()),
            gateway_str: gateway.map(|g| g.to_string()),
            if_index: None,
        }
    }

    #[test]
    fn resolve_bypass_keeps_usable_route() {
        // A normal route via a physical interface with a gateway is used as-is.
        let out = resolve_bypass_route_info(
            test_route_info("en0", Some("10.0.0.1")),
            Some("utun8"),
            None,
        )
        .expect("usable route must be accepted");
        assert_eq!(out.device, "en0");
        assert_eq!(out.gateway, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn resolve_bypass_repins_tunnel_route_via_fallback() {
        // Route resolved through the VPN tunnel -> re-pinned via the captured
        // underlay gateway (the direct-path-after-routes case).
        let fb = test_underlay("en0", Some("10.0.0.1"));
        let out = resolve_bypass_route_info(
            test_route_info("utun8", Some("10.99.0.1")),
            Some("utun8"),
            Some(&fb),
        )
        .expect("tunnel route must re-pin via fallback");
        assert_eq!(out.device, "en0");
        assert_eq!(out.gateway, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn resolve_bypass_refuses_tunnel_route_without_fallback() {
        assert!(
            resolve_bypass_route_info(
                test_route_info("utun8", Some("10.99.0.1")),
                Some("utun8"),
                None
            )
            .is_err()
        );
    }

    /// Regression for the full-tunnel outage: a relay IP whose route resolves via
    /// the physical interface but has no next-hop gateway (the transient
    /// cloned-route startup state) must fall back to the captured underlay
    /// gateway, not be refused.
    #[test]
    fn resolve_bypass_falls_back_when_gateway_missing() {
        let fb = test_underlay("en8", Some("10.22.32.1"));
        let out = resolve_bypass_route_info(test_route_info("en8", None), Some("utun8"), Some(&fb))
            .expect("gateway-less route must fall back to underlay gateway");
        assert_eq!(out.device, "en8");
        assert_eq!(out.gateway, Some("10.22.32.1".parse().unwrap()));
        assert_eq!(out.gateway_str.as_deref(), Some("10.22.32.1"));
    }

    #[test]
    fn resolve_bypass_refuses_gateway_missing_without_usable_fallback() {
        // No fallback at all.
        assert!(
            resolve_bypass_route_info(test_route_info("en8", None), Some("utun8"), None).is_err()
        );
        // A fallback that itself has no gateway is not usable.
        let fb = test_underlay("en8", None);
        assert!(
            resolve_bypass_route_info(test_route_info("en8", None), Some("utun8"), Some(&fb))
                .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_linux_default_route_line() {
        // `ip route show default` output, as fed to parse_linux_route_get by
        // query_default_gateway (placeholder peer IP is irrelevant).
        let line = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100";
        let info = parse_linux_route_get(line, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap();
        assert_eq!(info.device, "eth0");
        assert_eq!(info.gateway, Some("192.168.1.1".parse().unwrap()));

        let line6 = "default via fe80::1 dev eth0 proto ra metric 1024";
        let info6 = parse_linux_route_get(line6, IpAddr::V6(Ipv6Addr::UNSPECIFIED)).unwrap();
        assert_eq!(info6.device, "eth0");
        assert_eq!(info6.gateway_str.as_deref(), Some("fe80::1"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_parse_macos_default_route_output() {
        // `route -n get default` output, as fed to parse_macos_route_get by
        // query_default_gateway.
        let output = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        let info = parse_macos_route_get(output, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap();
        assert_eq!(info.device, "en0");
        assert_eq!(info.gateway, Some("192.168.1.1".parse().unwrap()));

        // `route -n get -inet6 default` with a link-local gateway keeps its scope.
        let output6 = "   route to: default\ndestination: default\n    gateway: fe80::1%en0\n  interface: en0\n";
        let info6 = parse_macos_route_get(output6, IpAddr::V6(Ipv6Addr::UNSPECIFIED)).unwrap();
        assert_eq!(info6.device, "en0");
        assert_eq!(info6.gateway_str.as_deref(), Some("fe80::1%en0"));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_valid_ipv4_gateway() {
        assert!(is_valid_gateway_str("192.168.1.1"));
        assert!(is_valid_gateway_str("10.0.0.1"));
        assert!(is_valid_gateway_str("0.0.0.0"));
        assert!(is_valid_gateway_str("255.255.255.255"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_darwin_packet_information_header() {
        assert_eq!(
            darwin_packet_information(&[0x45]).unwrap(),
            (libc::AF_INET as u32).to_be_bytes()
        );
        assert_eq!(
            darwin_packet_information(&[0x60]).unwrap(),
            (libc::AF_INET6 as u32).to_be_bytes()
        );
        assert!(darwin_packet_information(&[]).is_err());
        assert!(darwin_packet_information(&[0x70]).is_err());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_valid_ipv6_gateway() {
        assert!(is_valid_gateway_str("fe80::1"));
        assert!(is_valid_gateway_str("2001:db8::1"));
        assert!(is_valid_gateway_str("::1"));
        assert!(is_valid_gateway_str("::"));
        assert!(is_valid_gateway_str("2600:1f13:adc:a0b1::1"));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_valid_ipv6_with_scope() {
        assert!(is_valid_gateway_str("fe80::1%en0"));
        assert!(is_valid_gateway_str("fe80::1%eth0"));
        assert!(is_valid_gateway_str("fe80::1%wlan0"));
        assert!(is_valid_gateway_str("fe80::1%bridge-br0"));
        assert!(is_valid_gateway_str("fe80::1%veth_123"));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_invalid_gateway_empty() {
        assert!(!is_valid_gateway_str(""));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_invalid_gateway_command_injection() {
        // Shell metacharacters
        assert!(!is_valid_gateway_str("192.168.1.1; rm -rf /"));
        assert!(!is_valid_gateway_str("$(whoami)"));
        assert!(!is_valid_gateway_str("`whoami`"));
        assert!(!is_valid_gateway_str("192.168.1.1 && echo pwned"));
        assert!(!is_valid_gateway_str("192.168.1.1 | cat /etc/passwd"));
        assert!(!is_valid_gateway_str("192.168.1.1\necho pwned"));
        assert!(!is_valid_gateway_str("192.168.1.1'"));
        assert!(!is_valid_gateway_str("192.168.1.1\""));
        assert!(!is_valid_gateway_str("192.168.1.1>outfile"));
        assert!(!is_valid_gateway_str("192.168.1.1<infile"));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_invalid_gateway_bad_scope() {
        // Scope with invalid characters
        assert!(!is_valid_gateway_str("fe80::1%"));
        assert!(!is_valid_gateway_str("fe80::1%en0;rm"));
        assert!(!is_valid_gateway_str("fe80::1%en0$(cmd)"));
        assert!(!is_valid_gateway_str("fe80::1%en0`cmd`"));
        assert!(!is_valid_gateway_str("fe80::1%en0 "));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_invalid_gateway_spaces() {
        assert!(!is_valid_gateway_str("192.168.1.1 "));
        assert!(!is_valid_gateway_str(" 192.168.1.1"));
        assert!(!is_valid_gateway_str("192.168 .1.1"));
    }
}
