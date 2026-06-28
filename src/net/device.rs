//! TUN device creation and management.
//!
//! This module handles creating and managing TUN network interfaces
//! for VPN traffic.

use crate::error::{VpnError, VpnResult};
#[cfg(not(target_os = "macos"))]
use crate::tunnel::offload::compose_tun_frame;
use crate::tunnel::offload::{
    VIRTIO_NET_HDR_LEN, assemble_tcp_gso_superframe, plan_tun_write_groups, split_tun_frame,
};
use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use ipnet::{Ipv4Net, Ipv6Net};
#[cfg(not(target_os = "macos"))]
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(not(target_os = "macos"))]
use std::pin::Pin;
use tokio::io::ReadBuf;
#[cfg(not(target_os = "macos"))]
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::process::Command;
use tun::{AbstractDevice, AsyncDevice, Configuration};
#[cfg(not(target_os = "macos"))]
use tun::{DeviceReader, DeviceWriter};

#[cfg(target_os = "macos")]
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use tokio::io::Interest;
#[cfg(target_os = "macos")]
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
    /// MTU for the device (default: 1440, accounts for QUIC/TLS overhead).
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
            mtu: 1440,
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

/// A managed TUN device with async I/O.
pub struct TunDevice {
    /// The underlying async TUN device.
    device: AsyncDevice,
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
    pub fn create(config: TunConfig) -> VpnResult<Self> {
        let mut tun_config = Configuration::default();

        // Set IP configuration
        tun_config
            .address(config.address)
            .netmask(config.netmask)
            .destination(config.destination)
            .mtu(config.mtu)
            .up();

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
            log::info!("Linux TUN GSO enabled on device {}", name);
        } else {
            let reason = offload_status.reason.as_deref().unwrap_or("unknown reason");
            if config.enable_gso {
                log::warn!("Linux TUN GSO disabled on device {}: {}", name, reason);
            } else {
                log::info!("Linux TUN GSO disabled on device {}: {}", name, reason);
            }
        }

        log::info!("Created TUN device: {} with IP {}", name, config.address);

        // Configure IPv6 address if specified (after device creation)
        if let (Some(addr6), Some(prefix)) = (config.address6, config.prefix_len6) {
            configure_tun_ipv6(&name, addr6, prefix)?;
            log::info!("Configured TUN IPv6: {}/{}", addr6, prefix);
        }

        Ok(Self {
            device,
            name,
            mtu: config.mtu,
            vnet_hdr_enabled: cfg!(target_os = "linux"),
            offload_status,
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
        // Save buffer_size before moving self.device
        let buffer_size = self.buffer_size();

        #[cfg(target_os = "macos")]
        {
            let DarwinTunHalves { reader, writer } = DarwinTunHalves::new(&self.device)?;
            drop(self.device);
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

        #[cfg(not(target_os = "macos"))]
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

#[cfg(target_os = "macos")]
struct DarwinTunHalves {
    reader: DarwinTunReader,
    writer: DarwinTunWriter,
}

#[cfg(target_os = "macos")]
impl DarwinTunHalves {
    fn new(device: &AsyncDevice) -> VpnResult<Self> {
        let fd = duplicate_fd(device.as_raw_fd())?;
        let fd = Arc::new(
            AsyncFd::new(fd)
                .map_err(|e| VpnError::tun_device_with_source("Failed to register utun fd", e))?,
        );
        Ok(Self {
            reader: DarwinTunReader { fd: fd.clone() },
            writer: DarwinTunWriter { fd },
        })
    }
}

#[cfg(target_os = "macos")]
fn duplicate_fd(fd: RawFd) -> VpnResult<OwnedFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(VpnError::tun_device_with_source(
            "Failed to duplicate utun fd",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(target_os = "macos")]
struct DarwinTunReader {
    fd: Arc<AsyncFd<OwnedFd>>,
}

#[cfg(target_os = "macos")]
impl DarwinTunReader {
    async fn read_buf(&mut self, buf: &mut ReadBuf<'_>) -> VpnResult<()> {
        self.fd
            .async_io(Interest::READABLE, |fd| {
                read_utun_frame_into(fd.as_raw_fd(), buf)
            })
            .await
            .map_err(VpnError::Network)
    }
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
struct DarwinTunWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

enum TunReaderInner {
    #[cfg(not(target_os = "macos"))]
    Standard(DeviceReader),
    #[cfg(target_os = "macos")]
    Darwin(DarwinTunReader),
}

enum TunWriterInner {
    #[cfg(not(target_os = "macos"))]
    Standard(DeviceWriter),
    #[cfg(target_os = "macos")]
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
            #[cfg(not(target_os = "macos"))]
            TunReaderInner::Standard(reader) => {
                poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, buf))
                    .await
                    .map_err(VpnError::Network)
            }
            #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
        {
            let TunWriterInner::Darwin(writer) = &mut self.inner;
            if offload.is_some() {
                return Err(VpnError::tun_device(
                    "received offload metadata but local utun does not use vnet headers",
                ));
            }
            return writer.write_packet(ip_packet).await;
        }

        #[cfg(not(target_os = "macos"))]
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
                    #[cfg(not(target_os = "macos"))]
                    TunWriterInner::Standard(writer) => {
                        writer
                            .write_all(&self.scratch)
                            .await
                            .map_err(VpnError::Network)?;
                    }
                    #[cfg(target_os = "macos")]
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
/// - Windows PowerShell (New-NetRoute): "...already exists"
fn is_already_exists_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("file exists") || lower.contains("eexist") || lower.contains("already exists")
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
///   `networksetup`) and Linux (`ip route`).
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

    /// Build command args for adding a route on Windows.
    #[cfg(target_os = "windows")]
    fn windows_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on Windows.
    #[cfg(target_os = "windows")]
    fn windows_delete_args(&self, tun_name: &str) -> Vec<String>;
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
    fn windows_add_args(&self, tun_name: &str) -> Vec<String> {
        // For TUN interfaces, we don't specify a nexthop - the route goes directly
        // through the interface. On Windows, nexthop=0.0.0.0 can cause errors.
        vec![
            "interface".into(),
            "ipv4".into(),
            "add".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "store=active".into(),
        ]
    }

    #[cfg(target_os = "windows")]
    fn windows_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv4".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
        ]
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
    fn windows_add_args(&self, tun_name: &str) -> Vec<String> {
        // For TUN interfaces, we don't specify a nexthop - the route goes directly
        // through the interface. On Windows, nexthop=:: can cause errors.
        vec![
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "store=active".into(),
        ]
    }

    #[cfg(target_os = "windows")]
    fn windows_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
        ]
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
pub(crate) enum RouteAddOutcome {
    /// The route was added by this process; the caller owns its cleanup.
    Added,
    /// The route already existed; ownership stays with whoever created it.
    AlreadyExisted,
}

/// Handle the output of a route add command (generic version).
///
/// - On success: logs info, returns [`RouteAddOutcome::Added`]
/// - On failure with "route exists": logs warning, returns
///   [`RouteAddOutcome::AlreadyExisted`] (idempotent, not owned for cleanup)
/// - On other failure: returns error
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

/// Handle the output of a route remove command (generic, best-effort).
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
        let args = route.windows_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("netsh")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::tun_device_with_source("Failed to execute netsh command", e))?;

        handle_route_add_output(output, route, tun_name)
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
        let args = route.windows_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("netsh")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::tun_device_with_source("Failed to execute netsh command", e))?;

        handle_route_remove_output(output, route, tun_name);
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
        let args = route.windows_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("netsh").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                // Windows netsh outputs error messages to stdout, not stderr
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let error_msg = if stderr.trim().is_empty() {
                    stdout.trim().to_string()
                } else {
                    stderr.trim().to_string()
                };
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, error_msg);
            }
            Err(e) => {
                log::warn!("Failed to execute netsh route delete command: {}", e);
            }
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
    let routes: Vec<Ipv4Net> = routes.iter().flat_map(|r| expand_default_route4(*r)).collect();
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
    let routes: Vec<Ipv6Net> = routes.iter().flat_map(|r| expand_default_route6(*r)).collect();
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
    /// the host route via `New-NetRoute -InterfaceIndex`); `None` elsewhere.
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
/// Picks the active default route (`0.0.0.0/0` / `::/0`) with the lowest
/// *effective* metric (route metric + interface metric), matching the kernel's
/// route selection.
#[cfg(target_os = "windows")]
pub async fn query_default_gateway(is_ipv6: bool) -> VpnResult<UnderlayGateway> {
    let (family, prefix) = if is_ipv6 {
        ("IPv6", "::/0")
    } else {
        ("IPv4", "0.0.0.0/0")
    };

    let script = format!(
        concat!(
            "$ErrorActionPreference='Stop'; ",
            "$r = Get-NetRoute -DestinationPrefix '{prefix}' -AddressFamily {family} ",
            "-PolicyStore ActiveStore | Select-Object InterfaceIndex,InterfaceAlias,NextHop,",
            "@{{n='Eff';e={{ $_.RouteMetric + ((Get-NetIPInterface -InterfaceIndex ",
            "$_.InterfaceIndex -AddressFamily {family} -PolicyStore ActiveStore).InterfaceMetric ",
            "| Select-Object -First 1) }}}} | Sort-Object Eff | Select-Object -First 1; ",
            "if ($null -eq $r) {{ throw 'no default route' }}; ",
            "($r.InterfaceIndex,$r.NextHop,$r.InterfaceAlias) -join [char]9"
        ),
        prefix = prefix,
        family = family
    );

    let output = run_powershell(&script).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(VpnError::tun_device(format!(
            "Failed to query default route: {}",
            detail
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_windows_route_line(&stdout)?;
    Ok(UnderlayGateway {
        device: parsed.alias,
        gateway: parsed.next_hop,
        gateway_str: parsed.next_hop.map(|g| g.to_string()),
        if_index: Some(parsed.if_index),
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

// ============================================================================
// Windows route detection / host-route management (PowerShell NetTCPIP)
// ============================================================================
//
// Windows has no direct `route get <ip>` equivalent, so we drive the in-box
// `NetTCPIP` PowerShell cmdlets (present on every Windows 8+/Server 2012+, run
// here via the always-present `powershell.exe` Windows PowerShell 5.1):
//
// - `Find-NetRoute -RemoteIPAddress <ip>` runs the kernel's route selection
//   (longest-prefix + source selection) and returns the chosen `NextHop` and
//   `InterfaceIndex` for an arbitrary destination — exactly the per-IP lookup
//   `query_route_for_ip` needs.
// - `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (or `::/0`), sorted by effective
//   metric (route metric + interface metric), gives the default-route next hop
//   captured by `query_default_gateway` before VPN routes are installed.
// - `New-NetRoute` / `Remove-NetRoute` with `-PolicyStore ActiveStore` add and
//   remove the per-IP `/32`(`/128`) host route (non-persistent, matching the
//   `store=active` semantics used by the netsh routes elsewhere).
//
// Queries are read-only and need no elevation; only add/remove require the
// elevation the app already holds to manage the TUN. Scripts are kept free of
// double quotes and backticks (output uses `-join [char]9`) so they pass cleanly
// through `Command` as a single argument without Windows quote-escaping hazards.
// All interpolated values are `IpAddr`/`u32`/static literals, so the
// single-quoted PowerShell strings cannot be broken out of.

/// Run a PowerShell script via the in-box `powershell.exe` (async).
#[cfg(target_os = "windows")]
async fn run_powershell(script: &str) -> VpnResult<std::process::Output> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .await
        .map_err(|e| VpnError::tun_device_with_source("Failed to execute PowerShell", e))
}

/// Run a PowerShell script via the in-box `powershell.exe` (blocking, for Drop).
#[cfg(target_os = "windows")]
fn run_powershell_sync(script: &str) -> std::io::Result<std::process::Output> {
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
}

/// Parse a next-hop string from PowerShell, mapping the unspecified address
/// (`0.0.0.0` / `::`, emitted for on-link routes) to `None` so callers treat it
/// as "no gateway" and refuse the link-scope host route.
#[cfg(target_os = "windows")]
fn parse_windows_next_hop(s: &str) -> Option<IpAddr> {
    let ip: IpAddr = s.parse().ok()?;
    if ip.is_unspecified() { None } else { Some(ip) }
}

/// Parsed `<InterfaceIndex>\t<NextHop>\t<InterfaceAlias>` route line.
#[cfg(target_os = "windows")]
struct WindowsRouteLine {
    if_index: u32,
    next_hop: Option<IpAddr>,
    alias: String,
}

/// Parse the single tab-delimited line emitted by the route-query scripts.
#[cfg(target_os = "windows")]
fn parse_windows_route_line(stdout: &str) -> VpnResult<WindowsRouteLine> {
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| VpnError::tun_device("PowerShell route query returned no output"))?;

    let mut parts = line.splitn(3, '\t');
    let idx_str = parts.next().unwrap_or("").trim();
    let next_hop_str = parts.next().unwrap_or("").trim();
    let alias = parts.next().unwrap_or("").trim().to_string();

    let if_index: u32 = idx_str.parse().map_err(|_| {
        VpnError::tun_device(format!(
            "Unexpected interface index in route query output: {:?}",
            idx_str
        ))
    })?;

    Ok(WindowsRouteLine {
        if_index,
        next_hop: parse_windows_next_hop(next_hop_str),
        alias,
    })
}

/// Query the current route for a given IP address (Windows).
#[cfg(target_os = "windows")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let script = format!(
        concat!(
            "$ErrorActionPreference='Stop'; ",
            "$r = Find-NetRoute -RemoteIPAddress '{ip}' ",
            "| Where-Object {{ $null -ne $_.NextHop }} | Select-Object -First 1; ",
            "if ($null -eq $r) {{ throw 'no route found for {ip}' }}; ",
            "($r.InterfaceIndex,$r.NextHop,$r.InterfaceAlias) -join [char]9"
        ),
        ip = ip
    );

    let output = run_powershell(&script).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(VpnError::tun_device(format!(
            "Failed to query route for {}: {}",
            ip, detail
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_windows_route_line(&stdout)?;
    Ok(BypassRouteInfo {
        peer_ip: ip,
        device: parsed.alias,
        gateway: parsed.next_hop,
        gateway_str: parsed.next_hop.map(|g| g.to_string()),
        if_index: Some(parsed.if_index),
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

    // Query current route to this IP before adding any VPN routes
    let mut route_info = query_route_for_ip(peer_ip).await?;

    if let Some(disallowed) = disallow_device
        && route_info.device == disallowed
    {
        // The route already resolves through the VPN tunnel. Re-pin it via the
        // underlay gateway captured before the VPN routes went up, if we have
        // one; otherwise refuse rather than pin the peer's underlay IP into the
        // tunnel (self-capture).
        match underlay_fallback {
            Some(fb) if fb.gateway.is_some() => {
                log::info!(
                    "Bypass route for {} resolved via VPN tunnel {}; re-pinning via captured underlay gateway {} (dev {})",
                    peer_ip,
                    disallowed,
                    fb.gateway_str.as_deref().unwrap_or("?"),
                    fb.device
                );
                route_info = BypassRouteInfo {
                    peer_ip,
                    device: fb.device.clone(),
                    gateway: fb.gateway,
                    gateway_str: fb.gateway_str.clone(),
                    if_index: fb.if_index,
                };
            }
            _ => {
                return Err(VpnError::tun_device(format!(
                    "Refusing bypass route for {}: route lookup resolved via VPN tunnel interface {} (no captured underlay gateway to fall back to)",
                    peer_ip, disallowed
                )));
            }
        }
    }

    // Always pin the bypass via the resolved next-hop gateway. Without a gateway
    // we would install a link-scope host route (macOS `-interface`, Linux `dev`
    // only), which tells the kernel the peer is directly on-link; for a remote
    // underlay address that black-holes it and — because the poisoned route then
    // makes future `route get` lookups return no gateway — breaks it on every
    // later run. Refuse instead; the caller keeps existing routes and retries.
    if route_info.gateway.is_none() {
        return Err(VpnError::tun_device(format!(
            "Refusing bypass route for {}: no next-hop gateway resolved via {} \
             (would create a link-scope route that black-holes the address)",
            peer_ip, route_info.device
        )));
    }

    log::info!(
        "Adding bypass route for ICE peer {} via {} (gateway: {:?})",
        peer_ip,
        route_info.device,
        route_info.gateway
    );

    // Add host-specific route
    let outcome = add_bypass_route_impl(&route_info).await?;

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
}

/// Implementation of adding a bypass route (Linux).
#[cfg(target_os = "linux")]
async fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
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
    let output = Command::new("ip")
        .args(&args_ref)
        .output()
        .await
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

/// Implementation of adding a bypass route (macOS).
#[cfg(target_os = "macos")]
async fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
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
    let output = Command::new("route")
        .args(&args_ref)
        .output()
        .await
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

/// Implementation of adding a bypass route (Windows).
#[cfg(target_os = "windows")]
async fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
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

    let script = format!(
        concat!(
            "$ErrorActionPreference='Stop'; ",
            "New-NetRoute -DestinationPrefix '{ip}/{prefix}' -InterfaceIndex {idx} ",
            "-NextHop '{gw}' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
        ),
        ip = info.peer_ip,
        prefix = prefix,
        idx = if_index,
        gw = gw
    );

    let output = run_powershell(&script).await?;
    if output.status.success() {
        log::info!(
            "Added bypass route {}/{} via if {} gw {}",
            info.peer_ip,
            prefix,
            if_index,
            gw
        );
        return Ok(RouteAddOutcome::Added);
    }

    // PowerShell errors land on stderr; check both for the idempotent case.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if is_already_exists_error(&stderr) || is_already_exists_error(&stdout) {
        log::warn!(
            "Bypass route {}/{} already exists (treating as success)",
            info.peer_ip,
            prefix
        );
        return Ok(RouteAddOutcome::AlreadyExisted);
    }

    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(VpnError::tun_device(format!(
        "Failed to add bypass route {}/{}: {}",
        info.peer_ip, prefix, detail
    )))
}

/// Implementation of adding a bypass route (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn add_bypass_route_impl(_info: &BypassRouteInfo) -> VpnResult<RouteAddOutcome> {
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
    /// target `Remove-NetRoute -InterfaceIndex`); `None` elsewhere.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    if_index: Option<u32>,
    /// True only when this process added the route, so dropping must remove it.
    /// A pre-existing route is left untouched on drop.
    owned: bool,
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

    let Some(if_index) = if_index else {
        log::warn!(
            "Cannot remove bypass route for {}/{} (no interface index recorded)",
            peer_ip,
            prefix
        );
        return;
    };

    // Include the next hop when known so we target the exact route we added.
    let mut script = format!(
        "$ErrorActionPreference='Stop'; \
         Remove-NetRoute -DestinationPrefix '{}/{}' -InterfaceIndex {}",
        peer_ip, prefix, if_index
    );
    if let Some(gw) = gateway {
        script.push_str(&format!(" -NextHop '{}'", gw));
    }
    script.push_str(" -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop | Out-Null");

    match run_powershell_sync(&script) {
        Ok(output) if output.status.success() => {
            log::info!("Removed bypass route {}/{}", peer_ip, prefix);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if stderr.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            };
            log::warn!(
                "Failed to remove bypass route {}/{}: {}",
                peer_ip,
                prefix,
                detail
            );
        }
        Err(e) => {
            log::warn!("Failed to execute PowerShell route delete: {}", e);
        }
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
