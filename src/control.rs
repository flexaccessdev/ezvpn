//! Local control endpoint for querying a running server/client's status.
//!
//! A running VPN server or client exposes a small local JSON endpoint. The
//! `status` subcommand connects to it, reads a one-shot snapshot, and prints it.
//! The single-instance lock (`crate::runtime`) guarantees at most one instance
//! per (role, instance name), so the endpoint name is derived from that same
//! role/instance pair.
//!
//! # Transport
//!
//! - Unix: a Unix domain socket (`ezvpn-{server,client}-{instance}.sock`).
//! - Windows: a named pipe (`\\.\pipe\ezvpn-{server,client}-{instance}`).
//!
//! # Protocol
//!
//! Request-free: on accept, the listener immediately writes one line of JSON
//! (the [`StatusSnapshot`]) and closes. A querier that cannot connect (no
//! socket, or connection refused) treats the instance as not running.
//!
//! # Access control
//!
//! The endpoint is deliberately world-connectable so `status`/`list` work
//! without sudo: the Unix socket is `0666` in a `0755` runtime dir, and the
//! Windows pipe's default DACL grants Everyone read (the querier opens it
//! read-only). This is safe because the protocol is request-free and read-only
//! — a connection can only receive a status snapshot; nothing mutating goes
//! over it. Mutation (`client stop`) is out-of-band via SIGTERM to the PID in
//! the lock file, which remains root-only. The accepted trade-off is that any
//! local user can read VPN status metadata.

use crate::error::{VpnError, VpnResult};
use crate::runtime::{LockRole, runtime_base_name, validate_instance_name};
// `runtime_dir` only feeds the Unix-domain-socket path; the Windows control path
// uses named pipes (`pipe_name`), so the import is Unix-only.
#[cfg(unix)]
use crate::runtime::runtime_dir;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

/// How long the querier waits to connect and read a snapshot.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum accepted status-response size. A well-formed snapshot is a few KiB;
/// this bounds buffer growth from a misbehaving or hostile local peer.
const MAX_SNAPSHOT_SIZE: usize = 1 << 20; // 1 MiB

#[cfg(unix)]
fn socket_path(role: LockRole, instance: &str) -> std::path::PathBuf {
    runtime_dir().join(format!("{}.sock", runtime_base_name(role, instance)))
}

#[cfg(windows)]
fn pipe_name(role: LockRole, instance: &str) -> String {
    format!(r"\\.\pipe\{}", runtime_base_name(role, instance))
}

// ---------------------------------------------------------------------------
// Snapshot types (wire format)
// ---------------------------------------------------------------------------

/// A status snapshot for either a server or a client instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum StatusSnapshot {
    /// Server status.
    Server(ServerStatus),
    /// Client status.
    Client(ClientStatus),
}

/// Status of a running VPN server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Server's iroh node id.
    pub node_id: String,
    /// Seconds since the server started accepting connections.
    pub uptime_secs: u64,
    /// `"ipv4"`, `"ipv6"`, or `"dual-stack"`.
    pub mode: String,
    /// IPv4 VPN network CIDR, if configured.
    pub network: Option<String>,
    /// IPv6 VPN network CIDR, if configured.
    pub network6: Option<String>,
    /// Number of connected clients.
    pub connected_clients: usize,
    /// Active connection count (atomic counter).
    pub active_connections: usize,
    /// Per-client entries.
    pub clients: Vec<ClientEntry>,
    /// Packet flow counters.
    pub stats: ServerStatsView,
    /// The server's candidate iroh underlay addresses, as published to clients
    /// for bypass routing (`endpoint.addr().ip_addrs()`). Debugging aid: these
    /// are what the server advertises, not routes installed on any client.
    #[serde(default)]
    pub bypass_addrs: Vec<String>,
}

/// A single connected client as seen by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    /// Client's iroh endpoint id.
    pub endpoint_id: String,
    /// Client's device id (hex).
    pub device_id: String,
    /// Session id for this connection.
    pub session_id: u64,
    /// Assigned IPv4 VPN address, if any.
    pub assigned_ip: Option<String>,
    /// Assigned IPv6 VPN address, if any.
    pub assigned_ip6: Option<String>,
    /// iroh connection path(s) for this client (direct/relay, addresses).
    pub connection: Option<String>,
}

/// Server packet counters (mirror of `VpnServerStats`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatsView {
    pub tun_packets_read: u64,
    pub packets_to_clients: u64,
    pub packets_no_route: u64,
    pub packets_unknown_version: u64,
    pub packets_dropped_full: u64,
    pub packets_from_clients: u64,
    pub packets_tun_write_failed: u64,
    pub packets_spoofed: u64,
    pub packets_inter_client_blocked: u64,
}

/// Status of a running VPN client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStatus {
    /// Instance name this client runs under.
    pub instance: String,
    /// `"connected"` or `"disconnected"`.
    pub state: String,
    /// Configured server node id.
    pub server_node_id: String,
    /// Client's device id (hex).
    pub device_id: String,
    /// Seconds since the current session's handshake completed (when connected).
    pub connected_since_secs: Option<u64>,
    /// `"ipv4"`, `"ipv6"`, `"dual-stack"`, or `"none"` while disconnected.
    pub mode: String,
    /// Assigned IPv4 VPN address.
    pub assigned_ip: Option<String>,
    /// IPv4 VPN network CIDR.
    pub network: Option<String>,
    /// IPv4 gateway (server VPN IP).
    pub gateway: Option<String>,
    /// Assigned IPv6 VPN address.
    pub assigned_ip6: Option<String>,
    /// IPv6 VPN network CIDR.
    pub network6: Option<String>,
    /// IPv6 gateway (server VPN IPv6).
    pub gateway6: Option<String>,
    /// Tunnel MTU (the fixed protocol constant, shown while connected).
    pub mtu: Option<u16>,
    /// Whether GSO was negotiated for the current session.
    pub gso_negotiated: Option<bool>,
    /// IPv4 routes (CIDRs) directed through the tunnel for this session.
    #[serde(default)]
    pub routes: Vec<String>,
    /// IPv6 routes (CIDRs) directed through the tunnel for this session.
    #[serde(default)]
    pub routes6: Vec<String>,
    /// iroh connection path(s) to the server (direct/relay, addresses).
    pub connection: Option<String>,
    /// Underlay bypass addresses the client has *collected* this session (relays
    /// resolved at startup + the server's published candidates), filtered to
    /// those a VPN route would capture. Debugging aid: collected ≠ applied — an
    /// entry here may have failed to install as an OS route (see the disclaimer
    /// in the printed output).
    #[serde(default)]
    pub bypass_addrs: Vec<String>,
    /// Daemon log-file path (set only when started with `--daemon`).
    #[serde(default)]
    pub log_file: Option<String>,
}

// ---------------------------------------------------------------------------
// Client status handle (shared, live state updated by the client)
// ---------------------------------------------------------------------------

/// Connection details published when a client session is established.
#[derive(Debug, Clone, Default)]
pub struct ClientConnectedInfo {
    pub assigned_ip: Option<String>,
    pub network: Option<String>,
    pub gateway: Option<String>,
    pub assigned_ip6: Option<String>,
    pub network6: Option<String>,
    pub gateway6: Option<String>,
    pub mtu: u16,
    pub gso_negotiated: bool,
    /// IPv4 routes (CIDRs) actually directed through the tunnel.
    pub routes: Vec<String>,
    /// IPv6 routes (CIDRs) actually directed through the tunnel.
    pub routes6: Vec<String>,
}

/// Probe that returns a live description of the current connection path(s).
///
/// Provided by the client (capturing its iroh `Connection`) so this module
/// stays transport-agnostic. Called on demand when a snapshot is built.
pub type ConnectionProbe = Arc<dyn Fn() -> String + Send + Sync>;

/// Probe returning the bypass addresses the client has collected this session.
///
/// Provided by the client (capturing the bypass manager's shared collected set)
/// so this module stays transport-agnostic. Called on demand when a snapshot is
/// built. The returned addresses are *collected*, not necessarily *applied*.
pub type BypassRoutesProbe = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Internal shared client state. `connected_at` is a monotonic `Instant`, so it
/// is kept here rather than in the serializable [`ClientStatus`].
struct ClientStateInner {
    instance: String,
    connected: bool,
    server_node_id: String,
    device_id: String,
    connected_at: Option<std::time::Instant>,
    info: ClientConnectedInfo,
    connection_probe: Option<ConnectionProbe>,
    bypass_routes_probe: Option<BypassRoutesProbe>,
    /// Daemon log-file path (set only when started with `--daemon`).
    log_file: Option<String>,
}

/// A cloneable handle to a client's live status, shared between the connection
/// tasks (which update it) and the control listener (which reads it).
#[derive(Clone)]
pub struct ClientStatusHandle {
    inner: Arc<std::sync::RwLock<ClientStateInner>>,
}

impl ClientStatusHandle {
    /// Create a handle for a client with the given configured server node id
    /// and device id. Starts in the disconnected state.
    pub fn new(instance: String, server_node_id: String, device_id: u64) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(ClientStateInner {
                instance,
                connected: false,
                server_node_id,
                device_id: format!("{device_id:016x}"),
                connected_at: None,
                info: ClientConnectedInfo::default(),
                connection_probe: None,
                bypass_routes_probe: None,
                log_file: None,
            })),
        }
    }

    /// Record the daemon log-file path so it appears in `status` output.
    pub fn set_log_file(&self, path: Option<String>) {
        let mut guard = self.inner.write().expect("client status lock poisoned");
        guard.log_file = path;
    }

    /// Mark the client connected with the given session details. `connection`
    /// is a probe that yields a live description of the iroh path(s); `bypass`
    /// (when present) yields the bypass addresses collected this session.
    pub fn set_connected(
        &self,
        info: ClientConnectedInfo,
        connection: ConnectionProbe,
        bypass: Option<BypassRoutesProbe>,
    ) {
        let mut guard = self.inner.write().expect("client status lock poisoned");
        guard.connected = true;
        guard.connected_at = Some(std::time::Instant::now());
        guard.info = info;
        guard.connection_probe = Some(connection);
        guard.bypass_routes_probe = bypass;
    }

    /// Mark the client disconnected (e.g. tunnel ended, awaiting reconnect).
    pub fn set_disconnected(&self) {
        let mut guard = self.inner.write().expect("client status lock poisoned");
        guard.connected = false;
        guard.connected_at = None;
        guard.info = ClientConnectedInfo::default();
        guard.connection_probe = None;
        guard.bypass_routes_probe = None;
    }

    /// Build the current snapshot wrapped for the control protocol.
    pub fn snapshot(&self) -> StatusSnapshot {
        StatusSnapshot::Client(self.client_status())
    }

    /// Build the current serializable client status.
    fn client_status(&self) -> ClientStatus {
        // Copy out everything needed under the lock and clone the probe, then
        // drop the guard before invoking the probe. The probe may call into
        // iroh and block, so it must not run while holding the lock (which
        // would stall `set_connected`/`set_disconnected`).
        let (
            instance,
            connected,
            server_node_id,
            device_id,
            connected_at,
            info,
            probe,
            bypass_probe,
            log_file,
        ) = {
            let guard = self.inner.read().expect("client status lock poisoned");
            (
                guard.instance.clone(),
                guard.connected,
                guard.server_node_id.clone(),
                guard.device_id.clone(),
                guard.connected_at,
                guard.info.clone(),
                guard.connection_probe.clone(),
                guard.bypass_routes_probe.clone(),
                guard.log_file.clone(),
            )
        };

        let mode = if !connected {
            "none"
        } else if info.assigned_ip.is_none() {
            "ipv6"
        } else if info.assigned_ip6.is_some() {
            "dual-stack"
        } else {
            "ipv4"
        };
        ClientStatus {
            instance,
            state: if connected {
                "connected".into()
            } else {
                "disconnected".into()
            },
            server_node_id,
            device_id,
            connected_since_secs: connected_at.map(|t| t.elapsed().as_secs()),
            mode: mode.into(),
            assigned_ip: info.assigned_ip,
            network: info.network,
            gateway: info.gateway,
            assigned_ip6: info.assigned_ip6,
            network6: info.network6,
            gateway6: info.gateway6,
            mtu: connected.then_some(info.mtu),
            gso_negotiated: connected.then_some(info.gso_negotiated),
            routes: info.routes,
            routes6: info.routes6,
            connection: probe.map(|probe| probe()),
            bypass_addrs: bypass_probe.map(|p| p()).unwrap_or_default(),
            log_file,
        }
    }
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// Guard for a running status listener. Aborts the listener task and removes
/// the Unix socket file (if any) on drop.
pub struct StatusListenerGuard {
    task: JoinHandle<()>,
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
}

impl Drop for StatusListenerGuard {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Spawn a status listener for `role`/`instance` that serves snapshots produced
/// by `provider` on demand. The returned guard keeps the listener alive; drop it
/// to stop serving.
pub fn spawn_status_listener<F>(
    role: LockRole,
    instance: &str,
    provider: F,
) -> VpnResult<StatusListenerGuard>
where
    F: Fn() -> StatusSnapshot + Send + Sync + 'static,
{
    // Guard against unchecked input reaching socket/pipe path construction.
    validate_instance_name(instance)?;
    let provider = Arc::new(provider);

    #[cfg(unix)]
    {
        let path = socket_path(role, instance);
        // The instance lock guarantees we are the only instance, so any
        // existing socket is stale and safe to remove before binding.
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|e| VpnError::config_with_source("Failed to bind control socket", e))?;
        // Open the socket to everyone (0666): connect(2) requires write
        // permission on the socket inode, and the endpoint is read-only and
        // request-free by design (see the module docs), so unprivileged
        // `status`/`list` can query it. The chmod after bind only ever loosens
        // the umask-derived mode and happens before the accept loop starts.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).map_err(
                |e| VpnError::config_with_source("Failed to set control socket permissions", e),
            )?;
        }
        log::debug!("Status control socket listening: {}", path.display());

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _addr)) => {
                        serve_one(&mut stream, provider.as_ref()).await;
                    }
                    Err(e) => {
                        log::warn!("Status control socket accept failed: {e}");
                        break;
                    }
                }
            }
        });

        Ok(StatusListenerGuard {
            task,
            socket_path: path,
        })
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = pipe_name(role, instance);

        // Create the first instance synchronously, before returning the guard, so
        // the pipe exists the moment the caller can observe the listener. If we
        // deferred this to the spawned task, a client that connected in the gap
        // before the task ran would see the pipe missing and treat the instance
        // as not running. `first_pipe_instance(true)` also rejects a name already
        // owned by another process (the instance lock makes us the sole owner).
        // `access_inbound(false)` (PIPE_ACCESS_OUTBOUND) matches the
        // server-writes-only protocol; unelevated queriers connect read-only,
        // which the default pipe DACL grants to Everyone.
        let mut server = ServerOptions::new()
            .access_inbound(false)
            .first_pipe_instance(true)
            .create(&name)
            .map_err(|e| VpnError::config_with_source("Failed to create control pipe", e))?;
        log::debug!("Status control pipe listening: {name}");

        let task = tokio::spawn(async move {
            loop {
                // Wait for a client to connect to the current instance.
                if let Err(e) = server.connect().await {
                    log::warn!("Status control pipe connect failed: {e}");
                    break;
                }
                let mut connected = server;

                // Create the next instance before serving so a new client can
                // connect while this one is served (and so the pipe never briefly
                // disappears between connections).
                match ServerOptions::new().access_inbound(false).create(&name) {
                    Ok(next) => {
                        server = next;
                        serve_one(&mut connected, provider.as_ref()).await;
                    }
                    Err(e) => {
                        // Serve the client we already accepted, then stop.
                        serve_one(&mut connected, provider.as_ref()).await;
                        log::warn!("Status control pipe create failed: {e}");
                        break;
                    }
                }
            }
        });

        Ok(StatusListenerGuard { task })
    }
}

/// Write one JSON snapshot line to a connected stream, then close it.
async fn serve_one<S, F>(stream: &mut S, provider: &F)
where
    S: AsyncWriteExt + Unpin,
    F: Fn() -> StatusSnapshot + ?Sized,
{
    let snapshot = provider();
    match serde_json::to_vec(&snapshot) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            if let Err(e) = stream.write_all(&bytes).await {
                log::debug!("Failed writing status snapshot: {e}");
            }
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        }
        Err(e) => log::warn!("Failed to serialize status snapshot: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// Query the status of a running instance for `role`.
///
/// Returns `Ok(None)` if no instance is running (socket missing or connection
/// refused). Returns `Err` for timeouts or malformed responses.
pub async fn query_status(role: LockRole, instance: &str) -> VpnResult<Option<StatusSnapshot>> {
    // Guard against unchecked input reaching socket/pipe path construction.
    validate_instance_name(instance)?;
    let raw = match read_snapshot_bytes(role, instance).await? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };
    let snapshot = serde_json::from_slice(&raw)
        .map_err(|e| VpnError::config_with_source("Malformed status response", e))?;
    Ok(Some(snapshot))
}

/// One instance discovered in the runtime directory, with its probed status.
///
/// The three outcomes are distinguished so a probe failure is not mistaken for a
/// stale lock:
/// - `status: Some(_)` — the instance responded with a live snapshot.
/// - `status: None`, `error: None` — nothing is listening (socket missing or
///   connection refused): a stale lock from a crashed/exited process.
/// - `status: None`, `error: Some(msg)` — the probe failed for another reason
///   (timeout, malformed response, permission error, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Instance name.
    pub instance: String,
    /// Live status, or `null`/`None` if the instance did not respond with one.
    pub status: Option<StatusSnapshot>,
    /// Why the probe failed, when it failed for a reason other than "not
    /// running". Mutually exclusive with `status`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// List instances for `role` discovered in the runtime directory, probing each
/// for a live status snapshot.
///
/// Discovery is by lock file (see [`crate::runtime::list_locked_instances`]), which
/// can include stale entries; each candidate is then probed via its control
/// socket. A probe that fails is recorded on that instance (as a stale lock when
/// nothing is listening, or via `error` otherwise) rather than failing the whole
/// listing, so one bad instance can't hide the others.
pub async fn list_instances(role: LockRole) -> VpnResult<Vec<InstanceInfo>> {
    let mut out = Vec::new();
    for instance in crate::runtime::list_locked_instances(role) {
        let (status, error) = match query_status(role, &instance).await {
            Ok(status) => (status, None),
            Err(e) => {
                log::debug!("Status probe for instance {instance} failed: {e}");
                (None, Some(e.to_string()))
            }
        };
        out.push(InstanceInfo {
            instance,
            status,
            error,
        });
    }
    Ok(out)
}

#[cfg(unix)]
async fn read_snapshot_bytes(role: LockRole, instance: &str) -> VpnResult<Option<Vec<u8>>> {
    let path = socket_path(role, instance);
    let stream = match tokio::time::timeout(
        QUERY_TIMEOUT,
        tokio::net::UnixStream::connect(&path),
    )
    .await
    {
        Err(_) => return Err(VpnError::config("Timed out connecting to control socket")),
        Ok(Err(e)) if is_not_running(&e) => return Ok(None),
        // Not folded into `is_not_running`: an instance IS running here, so
        // reporting "not running" would be wrong — surface the error instead.
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(VpnError::config_with_source(
                "Permission denied connecting to the control socket \
                 (daemon started by an older ezvpn version? restart it, or retry with sudo)",
                e,
            ));
        }
        Ok(Err(e)) => return Err(VpnError::Network(e)),
        Ok(Ok(s)) => s,
    };
    read_all(stream).await.map(Some)
}

#[cfg(windows)]
async fn read_snapshot_bytes(role: LockRole, instance: &str) -> VpnResult<Option<Vec<u8>>> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let name = pipe_name(role, instance);
    // Open read-only: the protocol never writes from this side, and the pipe's
    // default DACL grants Everyone read but not write — so dropping
    // GENERIC_WRITE is what lets an unelevated `status`/`list` connect.
    let client = match ClientOptions::new().write(false).open(&name) {
        Ok(c) => c,
        Err(e) if is_not_running(&e) => return Ok(None),
        Err(e) => return Err(VpnError::Network(e)),
    };
    read_all(client).await.map(Some)
}

/// Read the full snapshot from a connected stream with a timeout, capping the
/// buffer at `MAX_SNAPSHOT_SIZE` so an oversized response is rejected early.
async fn read_all<S>(stream: S) -> VpnResult<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    // Read at most one byte past the limit so we can detect an over-limit response.
    let mut limited = stream.take(MAX_SNAPSHOT_SIZE as u64 + 1);
    match tokio::time::timeout(QUERY_TIMEOUT, limited.read_to_end(&mut buf)).await {
        Err(_) => Err(VpnError::config("Timed out reading status response")),
        Ok(Err(e)) => Err(VpnError::Network(e)),
        Ok(Ok(_)) if buf.len() > MAX_SNAPSHOT_SIZE => {
            Err(VpnError::config("Status response exceeds maximum size"))
        }
        Ok(Ok(_)) => Ok(buf),
    }
}

/// Whether a connection error means "no instance is running".
fn is_not_running(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused
    )
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Print a status snapshot. With `json`, emit pretty JSON; otherwise an aligned
/// human-readable summary.
pub fn print_status(snapshot: &StatusSnapshot, json: bool) -> VpnResult<()> {
    if json {
        let text = serde_json::to_string_pretty(snapshot)
            .map_err(|e| VpnError::config_with_source("Failed to serialize status", e))?;
        println!("{text}");
        return Ok(());
    }
    match snapshot {
        StatusSnapshot::Server(s) => print_server_text(s),
        StatusSnapshot::Client(c) => print_client_text(c),
    }
    Ok(())
}

/// Print a list of instances. With `json`, emit the raw array; otherwise an
/// aligned, one-line-per-instance summary.
pub fn print_instances(role: LockRole, instances: &[InstanceInfo], json: bool) -> VpnResult<()> {
    if json {
        let text = serde_json::to_string_pretty(instances)
            .map_err(|e| VpnError::config_with_source("Failed to serialize instances", e))?;
        println!("{text}");
        return Ok(());
    }

    let label = match role {
        LockRole::Server => "server",
        LockRole::Client => "client",
    };
    if instances.is_empty() {
        println!("No ezvpn {label} instances found.");
        return Ok(());
    }
    println!("ezvpn {label} instances:");
    for info in instances {
        let detail = match (&info.status, &info.error) {
            (Some(StatusSnapshot::Client(c)), _) => {
                format!("{:<13} {}", c.state, fmt_opt(&c.assigned_ip))
            }
            (Some(StatusSnapshot::Server(s)), _) => {
                format!("{:<13} {} client(s)", "running", s.connected_clients)
            }
            (None, Some(msg)) => format!("error: {msg}"),
            (None, None) => "not responding (stale lock)".to_string(),
        };
        println!("  {:<16} {detail}", info.instance);
    }
    Ok(())
}

fn fmt_opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("-")
}

fn fmt_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

fn print_server_text(s: &ServerStatus) {
    println!("Role:           server");
    println!("State:          running");
    println!("Node ID:        {}", s.node_id);
    println!("Uptime:         {}", fmt_uptime(s.uptime_secs));
    println!("Mode:           {}", s.mode);
    if let Some(net) = &s.network {
        println!("Network:        {net}");
    }
    if let Some(net6) = &s.network6 {
        println!("Network6:       {net6}");
    }
    println!("Clients:        {}", s.connected_clients);
    println!("Active conns:   {}", s.active_connections);
    if s.bypass_addrs.is_empty() {
        println!("Bypass addrs:   (none discovered yet)");
    } else {
        println!("Bypass addrs:   {}", s.bypass_addrs.join(", "));
        println!("                (published to clients for bypass routing)");
    }
    if !s.clients.is_empty() {
        println!("\nConnected clients:");
        for c in &s.clients {
            println!(
                "  - {} (device {}, session {}) ipv4={} ipv6={}",
                c.endpoint_id,
                c.device_id,
                c.session_id,
                fmt_opt(&c.assigned_ip),
                fmt_opt(&c.assigned_ip6),
            );
            if let Some(conn) = &c.connection {
                println!("      connection: {conn}");
            }
        }
    }
    let st = &s.stats;
    println!("\nPacket stats:");
    println!("  tun_read={}  to_clients={}  from_clients={}", st.tun_packets_read, st.packets_to_clients, st.packets_from_clients);
    println!(
        "  no_route={}  unknown_version={}  dropped_full={}",
        st.packets_no_route, st.packets_unknown_version, st.packets_dropped_full
    );
    println!(
        "  tun_write_failed={}  spoofed={}  inter_client_blocked={}",
        st.packets_tun_write_failed, st.packets_spoofed, st.packets_inter_client_blocked
    );
}

fn print_client_text(c: &ClientStatus) {
    println!("Role:           client");
    println!("Instance:       {}", c.instance);
    println!("State:          {}", c.state);
    println!("Server:         {}", c.server_node_id);
    println!("Device ID:      {}", c.device_id);
    if let Some(log) = &c.log_file {
        println!("Log file:       {log}");
    }
    if let Some(secs) = c.connected_since_secs {
        println!("Connected for:  {}", fmt_uptime(secs));
    }
    if c.state == "connected" {
        println!("Mode:           {}", c.mode);
        println!("VPN IPv4:       {}", fmt_opt(&c.assigned_ip));
        println!("Network:        {}", fmt_opt(&c.network));
        println!("Gateway:        {}", fmt_opt(&c.gateway));
        if c.assigned_ip6.is_some() || c.network6.is_some() {
            println!("VPN IPv6:       {}", fmt_opt(&c.assigned_ip6));
            println!("Network6:       {}", fmt_opt(&c.network6));
            println!("Gateway6:       {}", fmt_opt(&c.gateway6));
        }
        if let Some(mtu) = c.mtu {
            println!("MTU:            {mtu}");
        }
        if let Some(gso) = c.gso_negotiated {
            println!("GSO negotiated: {gso}");
        }
        if c.routes.is_empty() {
            println!("Routes:         (none)");
        } else {
            println!("Routes:         {}", c.routes.join(", "));
        }
        if !c.routes6.is_empty() {
            println!("Routes6:        {}", c.routes6.join(", "));
        }
        if let Some(conn) = &c.connection {
            println!("Connection:     {conn}");
        }
        if c.bypass_addrs.is_empty() {
            println!("Bypass addrs:   (none collected)");
        } else {
            println!("Bypass addrs:   {}", c.bypass_addrs.join(", "));
            println!(
                "                (collected, not necessarily applied successfully;"
            );
            println!(
                "                 verify with the OS routing table, e.g. netstat -nr)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A per-call, filesystem-safe instance name (`[A-Za-z0-9_]`). A
    /// process-local counter keeps names unique within a run; cross-process
    /// isolation comes for free from the per-PID test `runtime_dir`, so the PID
    /// is deliberately *not* repeated here. Keeping the name short matters: the
    /// full Unix-socket path must stay under macOS's ~104-char `SUN_LEN` limit,
    /// and the temp dir already eats most of that budget.
    fn unique_instance(prefix: &str) -> String {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{n}")
    }

    #[test]
    fn server_snapshot_roundtrips() {
        let snap = StatusSnapshot::Server(ServerStatus {
            node_id: "abc123".into(),
            uptime_secs: 42,
            mode: "dual-stack".into(),
            network: Some("10.0.0.0/24".into()),
            network6: Some("fd00::/64".into()),
            connected_clients: 1,
            active_connections: 1,
            clients: vec![ClientEntry {
                endpoint_id: "node-x".into(),
                device_id: "00000000deadbeef".into(),
                session_id: 7,
                assigned_ip: Some("10.0.0.2".into()),
                assigned_ip6: None,
                connection: Some("direct 1.2.3.4:5678 (selected)".into()),
            }],
            stats: ServerStatsView {
                tun_packets_read: 1,
                packets_to_clients: 2,
                packets_no_route: 0,
                packets_unknown_version: 0,
                packets_dropped_full: 0,
                packets_from_clients: 3,
                packets_tun_write_failed: 0,
                packets_spoofed: 0,
                packets_inter_client_blocked: 0,
            },
            bypass_addrs: vec!["44.230.20.120".into()],
        });
        let bytes = serde_json::to_vec(&snap).expect("serialize");
        let back: StatusSnapshot = serde_json::from_slice(&bytes).expect("deserialize");
        match back {
            StatusSnapshot::Server(s) => {
                assert_eq!(s.node_id, "abc123");
                assert_eq!(s.connected_clients, 1);
                assert_eq!(s.clients[0].session_id, 7);
            }
            _ => panic!("expected server snapshot"),
        }
    }

    #[test]
    fn client_handle_tracks_connection_state() {
        let handle = ClientStatusHandle::new("default".into(), "server-node".into(), 0xdead_beef);
        let snap = handle.client_status();
        assert_eq!(snap.instance, "default");
        assert_eq!(snap.state, "disconnected");
        assert_eq!(snap.device_id, "00000000deadbeef");
        assert_eq!(snap.mode, "none");
        assert!(snap.mtu.is_none());

        handle.set_connected(
            ClientConnectedInfo {
                assigned_ip: Some("10.0.0.2".into()),
                network: Some("10.0.0.0/24".into()),
                gateway: Some("10.0.0.1".into()),
                mtu: 1280,
                gso_negotiated: true,
                routes: vec!["0.0.0.0/0".into()],
                ..Default::default()
            },
            Arc::new(|| "relay https://relay.example".to_string()),
            Some(Arc::new(|| vec!["198.51.100.7".to_string()])),
        );
        let snap = handle.client_status();
        assert_eq!(snap.state, "connected");
        assert_eq!(snap.mode, "ipv4");
        assert_eq!(snap.assigned_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(snap.mtu, Some(1280));
        assert_eq!(snap.gso_negotiated, Some(true));
        assert_eq!(snap.routes, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(snap.connection.as_deref(), Some("relay https://relay.example"));
        assert_eq!(snap.bypass_addrs, vec!["198.51.100.7".to_string()]);

        handle.set_disconnected();
        let snap = handle.client_status();
        assert_eq!(snap.state, "disconnected");
        assert!(snap.connection.is_none());
        assert!(snap.bypass_addrs.is_empty());
    }

    // Exercises `socket_path`, which only exists on Unix; the Windows control
    // path addresses instances by named pipe (`pipe_name`) instead.
    #[cfg(unix)]
    #[test]
    fn socket_paths_differ_by_role_and_instance() {
        // Different roles, same instance: distinct sockets.
        assert_ne!(
            socket_path(LockRole::Server, "default"),
            socket_path(LockRole::Client, "default")
        );
        // Same role, different instances: distinct sockets.
        assert_ne!(
            socket_path(LockRole::Client, "alpha"),
            socket_path(LockRole::Client, "beta")
        );
    }

    // Windows counterpart to `socket_paths_differ_by_role_and_instance`: the
    // named-pipe name must be unique per (role, instance).
    #[cfg(windows)]
    #[test]
    fn pipe_names_differ_by_role_and_instance() {
        // Different roles, same instance: distinct pipes.
        assert_ne!(
            pipe_name(LockRole::Server, "default"),
            pipe_name(LockRole::Client, "default")
        );
        // Same role, different instances: distinct pipes.
        assert_ne!(
            pipe_name(LockRole::Client, "alpha"),
            pipe_name(LockRole::Client, "beta")
        );
    }

    // Unix-only because of the final assertion: dropping the guard must make the
    // instance immediately unreachable. On Unix that is synchronous (the guard
    // removes the socket file in `Drop`), so the next query connects to nothing
    // and returns `None`. On Windows, teardown aborts the listener task
    // asynchronously, so an immediate query can still connect to the not-yet-
    // closed pipe instance and then block until the read timeout. The live
    // create/connect/serve/read pipe roundtrip is covered on Windows by
    // `list_instances_includes_a_running_client`.
    #[cfg(unix)]
    #[tokio::test]
    async fn listener_serves_a_snapshot_to_a_querier() {
        let instance = unique_instance("lstn");
        // Query before any listener exists: not running.
        assert!(
            query_status(LockRole::Server, &instance)
                .await
                .expect("query ok")
                .is_none()
        );

        let provider = || {
            StatusSnapshot::Server(ServerStatus {
                node_id: "test-node".into(),
                uptime_secs: 5,
                mode: "ipv4".into(),
                network: Some("10.0.0.0/24".into()),
                network6: None,
                connected_clients: 0,
                active_connections: 0,
                clients: vec![],
                stats: ServerStatsView {
                    tun_packets_read: 0,
                    packets_to_clients: 0,
                    packets_no_route: 0,
                    packets_unknown_version: 0,
                    packets_dropped_full: 0,
                    packets_from_clients: 0,
                    packets_tun_write_failed: 0,
                    packets_spoofed: 0,
                    packets_inter_client_blocked: 0,
                },
                bypass_addrs: vec![],
            })
        };
        let guard = spawn_status_listener(LockRole::Server, &instance, provider)
            .expect("listener spawns");

        // The socket must be world-connectable so unprivileged status/list work.
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(socket_path(LockRole::Server, &instance))
                .expect("socket exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o666);
        }

        let snapshot = query_status(LockRole::Server, &instance)
            .await
            .expect("query ok")
            .expect("instance is running");
        match snapshot {
            StatusSnapshot::Server(s) => {
                assert_eq!(s.node_id, "test-node");
                assert_eq!(s.network.as_deref(), Some("10.0.0.0/24"));
            }
            _ => panic!("expected server snapshot"),
        }

        // Dropping the guard stops the listener and removes the socket.
        drop(guard);
        assert!(
            query_status(LockRole::Server, &instance)
                .await
                .expect("query ok")
                .is_none()
        );
    }

    // Drives the live listener/probe roundtrip (`spawn_status_listener` + the
    // `list_instances` probe) on both transports (Unix socket / Windows pipe).
    #[tokio::test]
    async fn list_instances_includes_a_running_client() {
        use crate::runtime::VpnLock;

        // A running instance has both a lock file (discovery) and a listener
        // (the probe). Use a per-run-unique name so other tests' lock files and
        // concurrent runs can't matter — we assert membership, not the exact set.
        let instance = unique_instance("lok");
        let _lock = VpnLock::acquire(LockRole::Client, &instance).expect("acquire lock");
        let handle = ClientStatusHandle::new(instance.clone(), "server-node".into(), 0x1234);
        let probe = handle.clone();
        let guard = spawn_status_listener(LockRole::Client, &instance, move || probe.snapshot())
            .expect("listener spawns");

        let instances = list_instances(LockRole::Client).await.expect("list ok");
        let found = instances
            .iter()
            .find(|i| i.instance == instance)
            .expect("running instance is listed");
        match &found.status {
            Some(StatusSnapshot::Client(c)) => assert_eq!(c.state, "disconnected"),
            other => panic!("expected a client snapshot, got {other:?}"),
        }
        assert!(found.error.is_none());

        drop(guard);
        drop(_lock);
    }

    // Drives the probe by writing directly to the instance's Unix-domain-socket
    // file (`socket_path`) to simulate a malformed response; the Windows
    // named-pipe control path is not covered here.
    #[cfg(unix)]
    #[tokio::test]
    async fn list_instances_distinguishes_probe_error_from_stale_lock() {
        use crate::runtime::VpnLock;

        // An instance whose socket exists and accepts a connection but replies
        // with a malformed (non-JSON) response: this is a probe *error*, not a
        // stale lock, and must not be reported as "stale".
        let instance = unique_instance("lerr");
        let _lock = VpnLock::acquire(LockRole::Client, &instance).expect("acquire lock");
        let path = socket_path(LockRole::Client, &instance);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind raw socket");
        let serve = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"not json\n").await;
                let _ = stream.shutdown().await;
            }
        });

        let instances = list_instances(LockRole::Client).await.expect("list ok");
        let found = instances
            .iter()
            .find(|i| i.instance == instance)
            .expect("instance is listed");
        assert!(found.status.is_none(), "malformed reply yields no snapshot");
        assert!(
            found.error.is_some(),
            "probe error must be recorded distinctly, not treated as a stale lock"
        );

        serve.abort();
        let _ = std::fs::remove_file(&path);
        drop(_lock);
    }
}
