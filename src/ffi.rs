//! C FFI surface for the fd-based mobile clients: the iOS and macOS Network
//! Extension app extensions link it directly, and the Android JNI layer
//! ([`crate::ffi_android`]) wraps the same handle and lifecycle.
//!
//! The extension links `libezvpn.a` and drives the tunnel in three calls:
//!
//! 1. [`ezvpn_connect`] — parse the JSON config, create an iroh endpoint,
//!    connect, and handshake. Returns an opaque handle and writes the assigned
//!    network config (IPv4 and/or IPv6, as JSON) to the caller's buffer so the
//!    extension can build `NEPacketTunnelNetworkSettings`.
//! 2. [`ezvpn_run`] — hand back the tun fd (obtained after applying the
//!    network settings); spawns the data-stream loop on the embedded runtime.
//!    Its optional exit callback reports a loop that ends on its own (server
//!    gone, heartbeat timeout, fatal I/O error) so the extension can tear the
//!    tunnel down instead of staying "connected" over a dead session.
//! 3. [`ezvpn_stop`] — abort the loop, close the endpoint, free the handle.
//!
//! [`ezvpn_conn_path`] is an optional debug readout: an on-demand snapshot of
//! the live iroh path(s) (relay/direct), mirroring `ezvpn client status`.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the extension
//! process rather than crossing into Swift/Kotlin).
//!
//! ## Config JSON (input to `ezvpn_connect`)
//!
//! `routes`/`routes6` are the split-tunnel prefixes; they drive the
//! overlapping-server-address bypass. `auth_key` (the client's
//! `ed25519-sec:...` secret key, whose public half must be on the server's
//! authorized-keys file) and `server_node_id` are required; `relay_urls`,
//! `relay_auth_token`, `routes`, and `routes6` are all optional.
//! `relay_auth_token` is the shared bearer token for the custom relays (sent as
//! `Authorization: Bearer <token>`); it is only valid together with
//! `relay_urls` and is rejected with the default relays.
//!
//! ```json
//! {
//!   "server_node_id": "<iroh endpoint id>",
//!   "auth_key": "ed25519-sec:...",
//!   "relay_urls": ["https://relay.example/"],
//!   "relay_auth_token": "<optional shared relay bearer token>",
//!   "routes": ["10.0.0.0/8"],
//!   "routes6": ["fd00::/8"]
//! }
//! ```
//!
//! ## Result JSON (output of `ezvpn_connect` on success)
//!
//! Per-family fields are `null` when that family was not assigned (IPv4-only,
//! IPv6-only, or dual-stack). `excluded_routes`/`excluded_routes6` are the
//! server underlay host routes (`/32` / `/128`) the extension must exclude from
//! the tunnel.
//!
//! `netmask`/`prefix_len6` are host masks (`255.255.255.255` / `128`): the
//! server advertises only its own host prefix, not the VPN subnet. The
//! extension must therefore add `gateway`/`gateway6` as *included* host routes
//! (`/32` / `/128`) alongside its configured split-tunnel routes — the
//! interface subnet no longer covers the gateway.
//!
//! ```json
//! {
//!   "assigned_ip": "10.0.0.2", "netmask": "255.255.255.255", "gateway": "10.0.0.1",
//!   "assigned_ip6": "fd00::2", "prefix_len6": 128, "gateway6": "fd00::1",
//!   "mtu": 1280,
//!   "excluded_routes": ["192.168.1.5/32"], "excluded_routes6": []
//! }
//! ```

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;
use std::sync::{Arc, Mutex};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::error::{VpnError, VpnResult};
use crate::transport::endpoint::RelayConfig;
use crate::transport::paths::{ConnPathKind, connection_snapshot};
use crate::tunnel::dns_proxy::DnsProxyConfig;
use crate::tunnel::mobile::{MobileConfig, MobileSession, SessionEvent, SessionEvents};

/// Callback run on the embedded runtime when the data loop started by
/// [`EzvpnHandle::run`] ends on its own (peer close, idle timeout, fatal I/O
/// error, or — with reconnect enabled — a non-recoverable error or changed
/// network parameters). Never invoked once [`EzvpnHandle::stop`] has been called — the
/// caller initiated that and needs no notification — even if the loop happens
/// to end on its own at the same moment.
pub(crate) type ExitHook = Box<dyn FnOnce(&VpnResult<()>) + Send + 'static>;

/// Upper bound on the graceful endpoint close in [`EzvpnHandle::stop`]. The
/// CONNECTION_CLOSE goes out immediately; this only caps how long the
/// teardown thread waits for the peer's acknowledgement before dropping the
/// runtime.
const STOP_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Opaque handle owned by the app side. Created by [`ezvpn_connect`], freed by
/// [`ezvpn_stop`].
pub struct EzvpnHandle {
    runtime: tokio::runtime::Runtime,
    /// The connected session, taken by [`ezvpn_run`].
    session: Option<MobileSession>,
    /// The running tunnel task, present after [`ezvpn_run`].
    task: Option<tokio::task::JoinHandle<VpnResult<()>>>,
    /// Set by [`EzvpnHandle::stop`] before the task is aborted; the task checks
    /// it before running the [`ExitHook`], so a loop that ends concurrently
    /// with `stop` stays silent as documented.
    ///
    /// Callbacks hold the lock while they run, so `stop` (which takes it to set
    /// the flag) waits for any in-flight callback before the caller may release
    /// its context. A callback must therefore never call `stop` synchronously.
    stopped: Arc<Mutex<bool>>,
    /// The live iroh connection (replaced on each reconnect), kept so [`ezvpn_conn_path`] can
    /// snapshot its paths on demand after `ezvpn_run` consumed the session.
    connection: Arc<Mutex<iroh::endpoint::Connection>>,
    /// Clone of the session's iroh endpoint, kept so [`EzvpnHandle::stop`] can
    /// close it gracefully after `ezvpn_run` consumed the session.
    endpoint: iroh::Endpoint,
    /// Configured custom relays, retained so [`ezvpn_conn_path`] can probe their
    /// `/healthz` on demand.
    relay_config: RelayConfig,
}

#[derive(Deserialize)]
struct FfiConfig {
    server_node_id: String,
    /// The client's secret key (`ed25519-sec:...`); the app stores it in the
    /// iOS keychain and passes it here at start.
    auth_key: String,
    #[serde(default)]
    relay_urls: Vec<String>,
    /// Optional shared bearer token for the custom relays. Only valid with
    /// `relay_urls`; rejected with the default relays.
    #[serde(default)]
    relay_auth_token: Option<String>,
    /// IPv4 routed prefixes (CIDR strings); used for overlap-bypass computation.
    #[serde(default)]
    routes: Vec<String>,
    /// IPv6 routed prefixes (CIDR strings).
    #[serde(default)]
    routes6: Vec<String>,
    /// Android only: the in-tunnel split-DNS forwarder. Absent (or null) on
    /// every other platform, which get conditional forwarding from the OS.
    #[serde(default)]
    dns_proxy: Option<FfiDnsProxy>,
}

/// The `dns_proxy` object of the config JSON (see [`crate::tunnel::dns_proxy`]).
#[derive(Deserialize)]
struct FfiDnsProxy {
    /// Proxy IP literals the app points the VPN's DNS at (≤ 1 per family).
    addresses: Vec<String>,
    /// Domain suffixes resolved through the tunnel.
    #[serde(default)]
    match_domains: Vec<String>,
    /// The tunnel's resolver IP literals (port 53).
    servers: Vec<String>,
    /// The underlying network's resolver IP literals (port 53); an IPv6
    /// link-local one carries its scope as `fe80::1%<ifindex>`.
    #[serde(default)]
    fallback_servers: Vec<String>,
    /// UDP socket fds the `VpnService` has `protect()`ed, at most one per
    /// family, for the fallback upstreams. `dup`ed here; the app keeps and
    /// closes its own.
    #[serde(default)]
    fallback_fds: Vec<i32>,
}

/// Parse a resolver literal with an optional `%<scope id>` suffix into a port-53
/// socket address.
fn parse_resolver(raw: &str) -> Result<SocketAddr, String> {
    let (host, scope) = match raw.split_once('%') {
        Some((h, s)) => (
            h,
            s.trim()
                .parse::<u32>()
                .map_err(|_| format!("invalid resolver scope in {raw:?} (expected a numeric interface index)"))?,
        ),
        None => (raw, 0),
    };
    let ip: IpAddr = host
        .trim()
        .parse()
        .map_err(|_| format!("invalid resolver address {raw:?}"))?;
    Ok(match ip {
        IpAddr::V4(_) if scope != 0 => {
            return Err(format!("invalid resolver address {raw:?} (IPv4 addresses take no scope)"));
        }
        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, crate::tunnel::dns_proxy::DNS_PORT)),
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, crate::tunnel::dns_proxy::DNS_PORT, 0, scope)),
    })
}

fn parse_dns_proxy(raw: FfiDnsProxy) -> Result<DnsProxyConfig, String> {
    let addresses = raw
        .addresses
        .iter()
        .map(|a| a.trim().parse::<IpAddr>().map_err(|_| format!("invalid dns_proxy address {a:?}")))
        .collect::<Result<Vec<_>, _>>()?;
    if addresses.is_empty() {
        return Err("dns_proxy.addresses must not be empty".to_string());
    }
    let servers = raw.servers.iter().map(|s| parse_resolver(s)).collect::<Result<Vec<_>, _>>()?;
    if servers.is_empty() {
        return Err("dns_proxy.servers must not be empty".to_string());
    }
    let fallback_servers = raw
        .fallback_servers
        .iter()
        .map(|s| parse_resolver(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fallback_sockets = Vec::new();
    for fd in raw.fallback_fds {
        // SAFETY: the app passes fds of sockets it owns and keeps open across
        // this call; we only take our own dup.
        let owned = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .map_err(|e| format!("cannot dup dns_proxy fallback fd {fd}: {e}"))?;
        fallback_sockets.push(std::net::UdpSocket::from(owned));
    }
    Ok(DnsProxyConfig {
        addresses,
        match_domains: raw.match_domains,
        servers,
        fallback_servers,
        fallback_sockets,
    }
    .normalized())
}

/// Parse CIDR strings into typed prefixes, failing on the first malformed entry
/// so a typo in `routes`/`routes6` is rejected before tunnel setup.
fn parse_routes<T>(raw: &[String], label: &str) -> Result<Vec<T>, String>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    raw.iter()
        .map(|s| s.parse::<T>().map_err(|e| format!("invalid {label} '{s}': {e}")))
        .collect()
}

/// Default log filter for the mobile clients (overridable via `RUST_LOG` where
/// the platform lets the app set environment variables).
const DEFAULT_LOG_FILTER: &str = "info,iroh=warn,tracing=warn";

/// Initialize logging. Safe to call multiple times; subsequent calls are no-ops.
///
/// Reads `RUST_LOG` (defaults to `info,iroh=warn,tracing=warn`). On Apple
/// platforms the output goes to stderr, which the system captures into the
/// unified log / Console. On Android stderr is discarded, so the output goes to
/// logcat under the tag `ezvpn` instead.
///
/// # Safety
/// No arguments; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn ezvpn_init_logging() {
    #[cfg(target_os = "android")]
    {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string());
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Trace)
                .with_tag("ezvpn")
                .with_filter(android_logger::FilterBuilder::new().parse(&filter).build()),
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(DEFAULT_LOG_FILTER),
        )
        .try_init();
    }
}

/// Generate a fresh client authentication keypair. Writes
/// `{"created":"<UTC>","public_key":"ed25519-pub:...","secret_key":"ed25519-sec:..."}`
/// to `out_buf`. The app stores the secret key in the keychain and shows the
/// public key (never a secret) for the user to put on the server's
/// authorized-keys file.
///
/// Returns 1 on success, 0 if `out_buf` is too small or key generation failed
/// (the system RNG was unavailable). On the too-small return `out_buf` holds a
/// **truncated prefix of the document, secret-key material included**, so the
/// caller should zero the buffer before retrying with a larger one.
///
/// # Safety
/// `out_buf` must point to at least `out_len` writable bytes (may be null only
/// if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_generate_client_key(out_buf: *mut c_char, out_len: usize) -> c_int {
    match crate::ffi_common::generate_client_key_json() {
        Ok(json) => {
            if write_cstr(out_buf, out_len, &json) {
                1
            } else {
                0
            }
        }
        Err(msg) => {
            write_cstr(out_buf, out_len, &msg);
            0
        }
    }
}

/// Derive the public key (`ed25519-pub:...`) of a stored secret key, so the app
/// can display it unmasked without persisting it separately. Writes the public
/// key string to `out_buf` on success (returns 1), or an error message
/// (returns 0) for an invalid secret. A too-small `out_buf` also returns 0, but
/// then holds the truncated output rather than a diagnostic.
///
/// # Safety
/// - `secret_key` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null only
///   if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_client_public_key(
    secret_key: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if secret_key.is_null() {
        write_cstr(out_buf, out_len, "secret_key is null");
        return 0;
    }
    let secret = match unsafe { CStr::from_ptr(secret_key) }.to_str() {
        Ok(secret) => secret,
        Err(_) => {
            write_cstr(out_buf, out_len, "secret_key is not valid UTF-8");
            return 0;
        }
    };
    match crate::ffi_common::client_public_key(secret) {
        Ok(public) => {
            if write_cstr(out_buf, out_len, &public) {
                1
            } else {
                0
            }
        }
        Err(msg) => {
            write_cstr(out_buf, out_len, &msg);
            0
        }
    }
}

/// Connect to the server and perform the handshake.
///
/// Returns a non-null handle on success and writes the network-config JSON to
/// `out_buf`. On failure returns null and writes the error message to `out_buf`.
/// If `out_buf` is too small to hold the full network-config JSON, that is
/// treated as a failure (null is returned and no handle is leaked); the caller
/// should retry with a larger buffer.
///
/// # Safety
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null only
///   if `out_len` is 0).
/// - The returned pointer must be freed exactly once with [`ezvpn_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_connect(
    config_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> *mut EzvpnHandle {
    if config_json.is_null() {
        write_cstr(out_buf, out_len, "config_json is null");
        return ptr::null_mut();
    }
    let json = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            write_cstr(out_buf, out_len, "config_json is not valid UTF-8");
            return ptr::null_mut();
        }
    };

    match connect_inner(json) {
        Ok((handle, result_json)) => {
            // Refuse to hand back a handle if the network-config JSON did not fit:
            // a truncated config is unparseable, and silently succeeding would
            // strand the connection. The caller must retry with a larger buffer.
            if write_cstr(out_buf, out_len, &result_json) {
                Box::into_raw(Box::new(handle))
            } else {
                drop(handle);
                write_cstr(out_buf, out_len, "out_buf too small for network-config JSON");
                ptr::null_mut()
            }
        }
        Err(msg) => {
            write_cstr(out_buf, out_len, &msg);
            ptr::null_mut()
        }
    }
}

/// The shared connect path behind [`ezvpn_connect`] and the Android JNI
/// `connect`: parse the config JSON, connect + handshake on a fresh runtime, and
/// render the network-config JSON. Errors are ready-to-display messages.
pub(crate) fn connect_inner(json: &str) -> Result<(EzvpnHandle, String), String> {
    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let relay_config = RelayConfig::from_urls_with_token(&cfg.relay_urls, cfg.relay_auth_token)
        .map_err(|e| format!("{e:#}"))?;
    let client_key = crate::auth::ClientKey::from_secret_str(cfg.auth_key.trim())
        .map_err(|e| format!("invalid auth key: {e:#}"))?;
    let ios_config = MobileConfig {
        server_node_id: cfg.server_node_id,
        client_key,
        relay_config: relay_config.clone(),
        routes: parse_routes::<Ipv4Net>(&cfg.routes, "IPv4 route")?,
        routes6: parse_routes::<Ipv6Net>(&cfg.routes6, "IPv6 route")?,
        dns_proxy: cfg.dns_proxy.map(parse_dns_proxy).transpose()?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    let session = runtime
        .block_on(MobileSession::connect(ios_config))
        .map_err(|e| format!("connect failed: {e}"))?;

    let net = session
        .network_config()
        .map_err(|e| format!("network config unavailable: {e}"))?;

    // Optional fields serialize to JSON `null` when a family was not assigned,
    // letting the extension detect IPv4-only / IPv6-only / dual-stack.
    let result_json = serde_json::json!({
        "assigned_ip": net.assigned_ip.map(|x| x.to_string()),
        "netmask": net.netmask.map(|x| x.to_string()),
        "gateway": net.gateway.map(|x| x.to_string()),
        "assigned_ip6": net.assigned_ip6.map(|x| x.to_string()),
        "prefix_len6": net.prefix_len6,
        "gateway6": net.gateway6.map(|x| x.to_string()),
        "mtu": net.mtu,
        "excluded_routes": net.excluded_routes,
        "excluded_routes6": net.excluded_routes6,
    })
    .to_string();

    let connection = session.connection_cell();
    let endpoint = session.endpoint();
    Ok((
        EzvpnHandle {
            runtime,
            session: Some(session),
            task: None,
            stopped: Arc::new(Mutex::new(false)),
            connection,
            endpoint,
            relay_config,
        },
        result_json,
    ))
}

/// Snapshot the live connection's iroh path(s) as JSON into `out_buf`,
/// mirroring `ezvpn client status`:
///
/// ```json
/// { "paths": [
///     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
///     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}
/// ], "custom_relays": [
///     {"url":"https://relay.example/","working":true,"error":null}
/// ] }
/// ```
///
/// A **point-in-time** snapshot of how the client currently reaches the server,
/// showing *all* discovered paths (not just the selected one); `kind` is
/// `"direct"`, `"relay"`, or `"other"` (a forward-compatible catch-all) and
/// `selected` marks the path iroh routes over right now. The array is **empty**
/// while the connection is down.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle. `out_buf` is always NUL-terminated when usable (non-null,
/// `out_len > 0`): the null-handle return writes an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_connect`] and not yet
/// passed to [`ezvpn_stop`]. `out_buf` must point to at least `out_len`
/// writable bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_conn_path(
    handle: *const EzvpnHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    let json = handle.conn_path_json();
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

impl EzvpnHandle {
    /// The [`ezvpn_conn_path`] JSON document for this session.
    pub(crate) fn conn_path_json(&self) -> String {
        // The relay health check performs on-demand HTTP, so drive the async
        // snapshot on the embedded runtime. Called from the app's own thread
        // (never a runtime worker), so `block_on` is safe and does not stall
        // the running tunnel task.
        let connection = match self.connection.lock() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let snapshot = self
            .runtime
            .block_on(connection_snapshot(&connection, &self.relay_config));
        let paths: Vec<_> = snapshot
            .paths
            .into_iter()
            .map(|p| {
                let kind = match p.kind {
                    ConnPathKind::Direct => "direct",
                    ConnPathKind::Relay => "relay",
                    ConnPathKind::Other => "other",
                };
                serde_json::json!({ "kind": kind, "display": p.display, "selected": p.selected })
            })
            .collect();
        serde_json::json!({ "paths": paths, "custom_relays": snapshot.custom_relays }).to_string()
    }

    /// The shared body of [`ezvpn_run`]: `dup` the tun fd synchronously, then
    /// spawn the data loop on the embedded runtime. `on_exit`, when given, runs
    /// on the runtime once the loop ends on its own (see [`ExitHook`]);
    /// `events`, when given, enables the in-place reconnect loop
    /// ([`MobileSession::run`]).
    pub(crate) fn run(
        &mut self,
        tun_fd: c_int,
        on_exit: Option<ExitHook>,
        events: Option<SessionEvents>,
    ) -> Result<(), String> {
        let Some(session) = self.session.take() else {
            return Err("no pending session (already running or never connected)".to_string());
        };

        // Take our own owned dup now, on the caller's thread, so the library
        // holds a valid fd regardless of when the caller closes its copy. The
        // dup is moved into the task and closed when the tunnel ends.
        let owned_fd = match unsafe { BorrowedFd::borrow_raw(tun_fd) }.try_clone_to_owned() {
            Ok(fd) => fd,
            Err(e) => {
                // Put the session back so the handle can still be stopped/freed.
                self.session = Some(session);
                return Err(format!("failed to dup tun fd: {e}"));
            }
        };

        let stopped = self.stopped.clone();
        // Like the exit hook, events stay silent once `stop` has been called,
        // and run under the lock so `stop` waits for one in flight.
        let events = events.map(|events| {
            let stopped = stopped.clone();
            Arc::new(move |event| {
                let stopped = lock_ignoring_poison(&stopped);
                if !*stopped {
                    events(event);
                }
            }) as SessionEvents
        });
        let task = self.runtime.spawn(async move {
            // `owned_fd` is owned by this task and closed when it ends; `run`
            // dups it again into the TunDevice, so our copy outlives that
            // internal dup setup.
            let result = session.run(owned_fd.as_raw_fd(), events).await;
            drop(owned_fd);
            // `stop` sets the flag before aborting, so a loop that ends on its
            // own in the same instant still honors "stop never notifies"; the
            // hook runs under the lock so `stop` waits for it.
            if let Some(hook) = on_exit {
                let stopped = lock_ignoring_poison(&stopped);
                if !*stopped {
                    hook(&result);
                }
            }
            result
        });
        self.task = Some(task);
        Ok(())
    }

    /// The shared body of [`ezvpn_stop`]: abort the loop (if any), close the
    /// iroh endpoint gracefully, and shut the runtime down — all without
    /// blocking the caller. Consumes (frees) the handle.
    ///
    /// The graceful close matters: merely dropping the endpoint sends nothing,
    /// so the server would only notice the client is gone at the QUIC idle
    /// timeout (30 s) and keep the address lease until then. `Endpoint::close`
    /// sends CONNECTION_CLOSE, so the server frees the lease immediately. It
    /// needs the runtime alive to drive the socket, so the teardown runs on a
    /// short-lived thread that owns the runtime, bounded by
    /// [`STOP_CLOSE_TIMEOUT`].
    pub(crate) fn stop(self: Box<Self>) {
        // Silence the exit hook and events first: the abort below only lands
        // at the task's next await point, and the loop may already be past its
        // last. Taking the lock waits out a callback already running, so none
        // runs after this returns.
        *lock_ignoring_poison(&self.stopped) = true;
        let EzvpnHandle {
            runtime,
            session,
            task,
            endpoint,
            connection,
            ..
        } = *self;
        if let Some(task) = &task {
            task.abort();
        }
        // Release our own references to the connection so the close below
        // has nothing else keeping it open; the aborted task drops its own
        // copies at its next await point.
        drop(connection);
        drop(session);

        let teardown = move || {
            let started = std::time::Instant::now();
            log::info!("ezvpn stop: closing endpoint");
            // The timeout's timer must be created inside the runtime context
            // (`tokio::time::timeout` registers it eagerly), so build it in the
            // async block rather than on this plain thread.
            let close = runtime.block_on(async {
                tokio::time::timeout(STOP_CLOSE_TIMEOUT, endpoint.close()).await
            });
            match close {
                Ok(()) => log::info!("ezvpn stop: endpoint closed in {:?}", started.elapsed()),
                Err(_) => log::warn!("ezvpn stop: endpoint close timed out after {STOP_CLOSE_TIMEOUT:?}"),
            }
            drop(task);
            runtime.shutdown_background();
        };
        if let Err(e) = std::thread::Builder::new()
            .name("ezvpn-stop".into())
            .spawn(teardown)
        {
            // No thread available: give up on the graceful close rather than
            // block the caller (the server falls back to its idle timeout).
            log::warn!("ezvpn stop: cannot spawn teardown thread ({e}); closing ungracefully");
        }
    }
}

/// [`ezvpn_run`] event: the session was lost (or a reconnect attempt failed)
/// and the library is reconnecting; `message` is the reason.
pub const EZVPN_EVENT_RECONNECTING: c_int = 1;
/// [`ezvpn_run`] event: reconnected with unchanged network settings; traffic
/// flows again. `message` is null.
pub const EZVPN_EVENT_RECONNECTED: c_int = 2;
/// [`ezvpn_run`] event (final): the tunnel ended and will not reconnect —
/// a non-recoverable error such as rejected authentication. `message` is the
/// reason, or null for a clean end.
pub const EZVPN_EVENT_ENDED: c_int = 3;
/// [`ezvpn_run`] event (final): the server handed back different network
/// settings on reconnect (e.g. a restarted server re-allocated the address).
/// The applied interface settings are stale: stop this handle and connect
/// afresh. `message` describes the change.
pub const EZVPN_EVENT_RECONFIGURE: c_int = 4;

/// C event callback for [`ezvpn_run`]: `ctx` is the caller's pointer, passed
/// back verbatim; `event` is one of the `EZVPN_EVENT_*` codes; `message` is
/// NUL-terminated and valid only for the duration of the call, or null.
pub type EzvpnEventCallback = extern "C" fn(ctx: *mut c_void, event: c_int, message: *const c_char);

/// The caller's callback and opaque `ctx`, moved onto the runtime threads
/// that report events. The caller guarantees `ctx` stays valid until
/// [`ezvpn_stop`].
#[derive(Clone, Copy)]
struct EventTarget {
    callback: EzvpnEventCallback,
    ctx: *mut c_void,
}
// SAFETY: the pointer is never dereferenced here, only handed back to the
// caller's callback, whose contract covers calls from any thread.
unsafe impl Send for EventTarget {}
unsafe impl Sync for EventTarget {}

impl EventTarget {
    fn emit(self, event: c_int, message: Option<&str>) {
        match message {
            None => (self.callback)(self.ctx, event, ptr::null()),
            Some(m) => {
                // Our messages carry no interior NUL; fall back rather than drop
                // the event if one ever does.
                let msg = CString::new(m).unwrap_or_else(|_| CString::from(c"(unprintable)"));
                (self.callback)(self.ctx, event, msg.as_ptr());
            }
        }
    }
}

/// Start the tunnel data loop on `tun_fd` (the extension's `utun` fd).
///
/// Spawns the loop on the embedded runtime and returns immediately: `0` on
/// success, `-1` on error (null handle, no pending session, fd dup failure, or
/// already running).
///
/// This `dup`s `tun_fd` **synchronously before returning**, so the caller may
/// close its own copy as soon as `ezvpn_run` returns — there is no race with the
/// spawned task picking the fd up.
///
/// A lost session (server restart, heartbeat or idle timeout) is reconnected in
/// place with backoff, reusing `tun_fd`, for as long as the handle runs.
/// `on_event`, when non-null, is called from library threads with its progress
/// (`EZVPN_EVENT_*`); a final `ENDED` or `RECONFIGURE` means the loop is over.
/// No event is delivered once [`ezvpn_stop`] has returned: it waits for a
/// callback already in progress. The callback must therefore not call
/// [`ezvpn_stop`] itself (dispatch it to another thread). The handle must
/// still be passed to [`ezvpn_stop`] after a final event.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_connect`] and not yet
/// passed to [`ezvpn_stop`]. `tun_fd` must be a valid open file descriptor.
/// `ctx` must remain valid for `on_event` until [`ezvpn_stop`] is called on
/// this handle, and `on_event` must be safe to call from any thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_run(
    handle: *mut EzvpnHandle,
    tun_fd: c_int,
    on_event: Option<EzvpnEventCallback>,
    ctx: *mut c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *handle };
    let target = on_event.map(|callback| EventTarget { callback, ctx });
    let events: SessionEvents = Arc::new(move |event| {
        let Some(target) = target else { return };
        match event {
            SessionEvent::Reconnecting(reason) => {
                target.emit(EZVPN_EVENT_RECONNECTING, Some(&reason))
            }
            SessionEvent::Reconnected => target.emit(EZVPN_EVENT_RECONNECTED, None),
        }
    });
    let hook = target.map(|target| {
        Box::new(move |result: &VpnResult<()>| match result {
            Ok(()) => target.emit(EZVPN_EVENT_ENDED, None),
            Err(e @ VpnError::ServerConfigChanged(_)) => {
                target.emit(EZVPN_EVENT_RECONFIGURE, Some(&e.to_string()))
            }
            Err(e) => target.emit(EZVPN_EVENT_ENDED, Some(&e.to_string())),
        }) as ExitHook
    });
    match handle.run(tun_fd, hook, Some(events)) {
        Ok(()) => 0,
        Err(e) => {
            log::error!("ezvpn_run: {e}");
            -1
        }
    }
}

/// Stop the tunnel and free the handle.
///
/// Aborts the running loop (if any) and shuts down the embedded runtime. After
/// this call `handle` is invalid and must not be used again.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_connect`] and not
/// already freed. Passing null is a safe no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_stop(handle: *mut EzvpnHandle) {
    if handle.is_null() {
        return;
    }
    unsafe { Box::from_raw(handle) }.stop();
}

/// Lock the stop flag, recovering it from a callback that panicked (the flag
/// itself is always valid).
fn lock_ignoring_poison(stopped: &Mutex<bool>) -> std::sync::MutexGuard<'_, bool> {
    stopped.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write `s` (always NUL-terminated) into the caller buffer. Returns `true` if
/// the full string fit, `false` if it was truncated or the buffer was unusable.
fn write_cstr(buf: *mut c_char, len: usize, s: &str) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let bytes = s.as_bytes();
    // Reserve one byte for the trailing NUL.
    let copy = bytes.len().min(len - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}
