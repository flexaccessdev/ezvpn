//! C FFI surface for the native Windows GUI client (`ezvpn-windows`).
//!
//! Unlike the Apple FFI ([`crate::ffi`]), which is *fd-based* — the OS
//! (`NEPacketTunnelProvider`) creates the `utun` device and hands Rust a file
//! descriptor via [`ezvpn_run`](crate::ffi::ezvpn_run) — Windows has no
//! OS-provided TUN fd. The wintun adapter and the routing table are owned by the
//! app itself, which the desktop [`crate::tunnel::client::VpnClient`] already
//! does in full on Windows (wintun via the `tun` crate, routes via `netsh`,
//! auto-reconnect, single-instance lock). So this FFI wraps `VpnClient`, not the
//! slim fd path, and is a *start / status / stop* shape:
//!
//! 1. [`ezvpn_start`] — parse the JSON config, create an iroh endpoint and a
//!    `VpnClient`, and spawn its reconnecting run loop on a background thread.
//!    Returns an opaque handle. The tunnel keeps running until [`ezvpn_stop`].
//! 2. [`ezvpn_status`] — snapshot the live client status (assigned IPs, routes,
//!    connection path, bypass addresses) as JSON — the same [`StatusSnapshot`]
//!    the desktop control endpoint serves, read in-process (no named pipe).
//! 3. [`ezvpn_stop`] — signal the loop to stop, wait for the routes/TUN teardown
//!    to complete (the run future's `Drop` removes routes and closes wintun),
//!    then free the handle.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the host process
//! rather than crossing into .NET).
//!
//! The tunnel creates the wintun adapter and edits the routing table, so the
//! host process must run **elevated** (Administrator), and `wintun.dll` must sit
//! next to `ezvpn.dll` or on `PATH`.
//!
//! ## Config JSON (input to `ezvpn_start`)
//!
//! `auth_token`/`max_reconnect_attempts` may be null. `relay_urls`,
//! `relay_auth_token`, `routes`, `routes6`, `instance`, and `auto_reconnect` are
//! all optional (with the defaults shown). `relay_auth_token` is the shared
//! bearer token for the custom relays (sent as `Authorization: Bearer <token>`);
//! it is only valid together with `relay_urls` and is rejected with the default
//! relays.
//!
//! ```json
//! {
//!   "server_node_id": "<iroh endpoint id>",
//!   "auth_token": "<47-char ezvpn token>",
//!   "relay_urls": ["https://relay.example/"],
//!   "relay_auth_token": "<optional shared relay bearer token>",
//!   "routes": ["10.0.0.0/8"],
//!   "routes6": ["fd00::/8"],
//!   "instance": "default",
//!   "auto_reconnect": true,
//!   "max_reconnect_attempts": null
//! }
//! ```
//!
//! ## Status JSON (output of `ezvpn_status`)
//!
//! The serialized [`StatusSnapshot::Client`](crate::control::StatusSnapshot),
//! e.g. `{"role":"client","instance":"default","state":"connected",
//! "assigned_ip":"10.0.0.2","gateway":"10.0.0.1","routes":["10.0.0.1/32"],
//! "connection":"Direct 1.2.3.4:52186 (rtt 1ms)",
//! "custom_relays":[{"url":"https://relay.example/","working":true,"error":null}],
//! ...}`. `state` is
//! `"disconnected"` while connecting/reconnecting and `"connected"` once the
//! handshake succeeds.

use std::ffi::{CStr, c_char, c_int};
use std::num::NonZeroU32;
use std::ptr;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::config::VpnClientConfig;
use crate::control::ClientStatusHandle;
use crate::transport::endpoint::{RelayConfig, create_client_endpoint};
use crate::tunnel::client::VpnClient;

/// Opaque handle owned by the .NET side. Created by [`ezvpn_start`], freed by
/// [`ezvpn_stop`].
pub struct EzvpnHandle {
    /// The background thread running the tunnel's tokio runtime. Joined by
    /// [`ezvpn_stop`] after the shutdown signal so teardown completes before the
    /// handle is freed. `Option` so `stop` can take and join it.
    worker: Option<thread::JoinHandle<()>>,
    /// Signals the run loop to stop; `notify_one` is sync-callable from
    /// [`ezvpn_stop`] outside any async context.
    shutdown: Arc<Notify>,
    /// Clone of the client's live status handle, read by [`ezvpn_status`].
    status: ClientStatusHandle,
}

/// Config JSON accepted by [`ezvpn_start`]. Mirror of the Apple FFI config plus
/// the desktop-only start options (`instance`, `auto_reconnect`,
/// `max_reconnect_attempts`).
#[derive(Deserialize)]
struct FfiWinConfig {
    server_node_id: String,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    relay_urls: Vec<String>,
    /// Optional shared bearer token for the custom relays. Only valid with
    /// `relay_urls`; rejected with the default relays.
    #[serde(default)]
    relay_auth_token: Option<String>,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    routes6: Vec<String>,
    #[serde(default = "default_instance")]
    instance: String,
    #[serde(default = "default_true")]
    auto_reconnect: bool,
    #[serde(default)]
    max_reconnect_attempts: Option<u32>,
}

fn default_instance() -> String {
    "default".to_string()
}

fn default_true() -> bool {
    true
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

/// Initialize logging. Safe to call multiple times; subsequent calls are no-ops.
///
/// Reads `RUST_LOG` (defaults to `info,iroh=warn,tracing=warn`). Output goes to
/// stderr, which the host process can capture.
///
/// # Safety
/// No arguments; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn ezvpn_init_logging() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,iroh=warn,tracing=warn"),
    )
    .try_init();
}

/// Start the VPN client and its reconnecting run loop.
///
/// Returns a non-null handle once setup (iroh endpoint online + client
/// single-instance lock) succeeds; the tunnel then runs in the background until
/// [`ezvpn_stop`]. On a setup failure returns null and writes the error message
/// to `out_buf`.
///
/// This returns as soon as the client has *started* — not once it has
/// *connected*. Poll [`ezvpn_status`] for the `"connected"` state.
///
/// # Safety
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null only
///   if `out_len` is 0).
/// - The returned pointer must be freed exactly once with [`ezvpn_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_start(
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

    match start_inner(json) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(msg) => {
            write_cstr(out_buf, out_len, &msg);
            ptr::null_mut()
        }
    }
}

fn start_inner(json: &str) -> Result<EzvpnHandle, String> {
    let cfg: FfiWinConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let config = VpnClientConfig {
        server_node_id: cfg.server_node_id,
        auth_token: cfg.auth_token,
        routes: parse_routes::<Ipv4Net>(&cfg.routes, "IPv4 route")?,
        routes6: parse_routes::<Ipv6Net>(&cfg.routes6, "IPv6 route")?,
    };

    let relay_config = RelayConfig::from_urls_with_token(&cfg.relay_urls, cfg.relay_auth_token)
        .map_err(|e| format!("{e:#}"))?;
    let instance = cfg.instance;
    let auto_reconnect = cfg.auto_reconnect;
    let max_attempts = cfg.max_reconnect_attempts.and_then(NonZeroU32::new);

    let shutdown = Arc::new(Notify::new());
    let shutdown_worker = Arc::clone(&shutdown);

    // The worker thread owns a dedicated multi-thread runtime and drives the
    // whole tunnel lifetime. Separate workers keep UDP receive/QUIC pacing from
    // being starved by TUN and route-management work. Setup success/failure is
    // reported back over a one-shot channel so `ezvpn_start` can surface a
    // lock-held / offline error synchronously before returning; after that the
    // loop runs until shutdown.
    let (setup_tx, setup_rx) = mpsc::channel::<Result<ClientStatusHandle, String>>();

    let worker = thread::Builder::new()
        .name("ezvpn-tunnel".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = setup_tx.send(Err(format!("failed to build tokio runtime: {e}")));
                    return;
                }
            };

            runtime.block_on(async move {
                let endpoint = match create_client_endpoint(&relay_config, None).await {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = setup_tx.send(Err(format!("failed to create iroh endpoint: {e}")));
                        return;
                    }
                };

                let client = match VpnClient::new(config, &instance) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = setup_tx.send(Err(format!("failed to create VPN client: {e}")));
                        return;
                    }
                };

                // Hand the status handle back; setup is done from here on.
                if setup_tx.send(Ok(client.status_handle())).is_err() {
                    // The starter gave up (dropped the receiver); nothing to run.
                    return;
                }

                // Race the run loop against the shutdown signal. When shutdown
                // wins, the run future is dropped here, which runs the
                // RouteGuard / TUN `Drop`s (removing routes, closing wintun)
                // before this block returns and the runtime is torn down.
                tokio::select! {
                    result = run_client(&client, &endpoint, &relay_config, auto_reconnect, max_attempts) => {
                        if let Err(e) = result {
                            log::error!("VPN client exited: {e}");
                        } else {
                            log::info!("VPN client ended");
                        }
                    }
                    _ = shutdown_worker.notified() => {
                        log::info!("Stop requested; tearing down tunnel");
                    }
                }

                endpoint.close().await;
            });
        })
        .map_err(|e| format!("failed to spawn tunnel thread: {e}"))?;

    match setup_rx.recv() {
        Ok(Ok(status)) => Ok(EzvpnHandle {
            worker: Some(worker),
            shutdown,
            status,
        }),
        Ok(Err(msg)) => {
            // Setup failed inside the worker; it has already returned.
            let _ = worker.join();
            Err(msg)
        }
        Err(_) => {
            // Worker died before reporting (e.g. panic in debug builds).
            let _ = worker.join();
            Err("tunnel thread exited before setup completed".to_string())
        }
    }
}

/// Drive the client, with or without auto-reconnect. Factored out so the
/// `select!` arm stays readable.
async fn run_client(
    client: &VpnClient,
    endpoint: &iroh::Endpoint,
    relay_config: &RelayConfig,
    auto_reconnect: bool,
    max_attempts: Option<NonZeroU32>,
) -> crate::error::VpnResult<()> {
    if auto_reconnect {
        client.run_with_reconnect(endpoint, relay_config, max_attempts).await
    } else {
        client.connect(endpoint, relay_config).await
    }
}

/// Snapshot the live client status as JSON into `out_buf`.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle. `out_buf` is always NUL-terminated when usable (non-null,
/// `out_len > 0`); the null-handle return writes an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_start`] and not yet
/// passed to [`ezvpn_stop`]. `out_buf` must point to at least `out_len` writable
/// bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_status(
    handle: *const EzvpnHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    // The snapshot is async (custom-relay `/healthz` is checked on demand). The
    // worker thread's runtime is busy driving the tunnel and can't be reused
    // from here, so spin up a short-lived runtime to drive this one snapshot.
    // `ezvpn_status` is called on demand from the .NET side, never on a runtime
    // worker, so this does not block the tunnel.
    let snapshot = {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let json = format!("{{\"error\":\"failed to build status runtime: {e}\"}}");
                return if write_cstr(out_buf, out_len, &json) { 1 } else { 0 };
            }
        };
        rt.block_on(handle.status.snapshot())
    };
    let json = match serde_json::to_string(&snapshot) {
        Ok(j) => j,
        Err(e) => format!("{{\"error\":\"failed to serialize status: {e}\"}}"),
    };
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Stop the tunnel and free the handle.
///
/// Signals the run loop to stop and **waits** for the worker thread to finish
/// its teardown (routes removed, wintun adapter closed, single-instance lock
/// released) before returning, so a subsequent [`ezvpn_start`] for the same
/// instance does not race a half-released lock. After this call `handle` is
/// invalid and must not be used again. Passing null is a safe no-op.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_start`] and not already
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_stop(handle: *mut EzvpnHandle) {
    if handle.is_null() {
        return;
    }
    let mut handle = unsafe { Box::from_raw(handle) };
    handle.shutdown.notify_one();
    if let Some(worker) = handle.worker.take() {
        let _ = worker.join();
    }
    // `handle` (Box) drops here, freeing the allocation.
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
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}
