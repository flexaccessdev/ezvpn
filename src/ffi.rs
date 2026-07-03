//! C FFI surface for the iOS Network Extension (`aarch64-apple-ios`).
//!
//! The extension links `libezvpn.a` and drives the tunnel in three calls:
//!
//! 1. [`ezvpn_connect`] — parse the JSON config, create an iroh endpoint,
//!    connect, and handshake. Returns an opaque handle and writes the assigned
//!    network config (IPv4 and/or IPv6, as JSON) to the caller's buffer so the
//!    extension can build `NEPacketTunnelNetworkSettings`.
//! 2. [`ezvpn_run`] — hand back the `utun` fd (obtained after applying the
//!    network settings); spawns the datagram loop on the embedded runtime.
//! 3. [`ezvpn_stop`] — abort the loop, close the endpoint, free the handle.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the extension
//! process rather than crossing into Swift).
//!
//! ## Config JSON (input to `ezvpn_connect`)
//!
//! `routes`/`routes6` are the split-tunnel prefixes; they drive the
//! overlapping-server-address bypass. `auth_token` may be null; `relay_urls`,
//! `relay_only`, `routes`, and `routes6` are all optional.
//!
//! ```json
//! {
//!   "server_node_id": "<iroh endpoint id>",
//!   "auth_token": "<optional ezvpn auth token>",
//!   "relay_urls": ["https://relay.example/"],
//!   "relay_only": false,
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
//! ```json
//! {
//!   "assigned_ip": "10.0.0.2", "netmask": "255.255.255.0", "gateway": "10.0.0.1",
//!   "assigned_ip6": "fd00::2", "prefix_len6": 64, "gateway6": "fd00::1",
//!   "mtu": 1400,
//!   "excluded_routes": ["192.168.1.5/32"], "excluded_routes6": []
//! }
//! ```

use std::ffi::{CStr, c_char, c_int};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::error::VpnResult;
use crate::tunnel::ios::{IosConfig, IosSession};

/// Opaque handle owned by the Swift side. Created by [`ezvpn_connect`], freed by
/// [`ezvpn_stop`].
pub struct EzvpnHandle {
    runtime: tokio::runtime::Runtime,
    /// The connected session, taken by [`ezvpn_run`].
    session: Option<IosSession>,
    /// The running tunnel task, present after [`ezvpn_run`].
    task: Option<tokio::task::JoinHandle<VpnResult<()>>>,
}

#[derive(Deserialize)]
struct FfiConfig {
    server_node_id: String,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    relay_urls: Vec<String>,
    #[serde(default)]
    relay_only: bool,
    /// IPv4 routed prefixes (CIDR strings); used for overlap-bypass computation.
    #[serde(default)]
    routes: Vec<String>,
    /// IPv6 routed prefixes (CIDR strings).
    #[serde(default)]
    routes6: Vec<String>,
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
/// Reads `RUST_LOG` (defaults to `info,iroh=warn,tracing=warn`). On iOS the output goes to stderr,
/// which the system captures into the unified log / Console.
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

fn connect_inner(json: &str) -> Result<(EzvpnHandle, String), String> {
    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let ios_config = IosConfig {
        server_node_id: cfg.server_node_id,
        auth_token: cfg.auth_token,
        relay_urls: cfg.relay_urls,
        relay_only: cfg.relay_only,
        routes: parse_routes::<Ipv4Net>(&cfg.routes, "IPv4 route")?,
        routes6: parse_routes::<Ipv6Net>(&cfg.routes6, "IPv6 route")?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    let session = runtime
        .block_on(IosSession::connect(&ios_config))
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

    Ok((
        EzvpnHandle {
            runtime,
            session: Some(session),
            task: None,
        },
        result_json,
    ))
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
/// # Safety
/// `handle` must be a valid pointer returned by [`ezvpn_connect`] and not yet
/// passed to [`ezvpn_stop`]. `tun_fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ezvpn_run(handle: *mut EzvpnHandle, tun_fd: c_int) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *handle };
    let Some(session) = handle.session.take() else {
        return -1;
    };

    // Take our own owned dup now, on the caller's thread, so the library holds a
    // valid fd regardless of when the caller closes its copy. The dup is moved
    // into the task and closed when the tunnel ends.
    let owned_fd = match unsafe { BorrowedFd::borrow_raw(tun_fd) }.try_clone_to_owned() {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("ezvpn_run: failed to dup utun fd: {e}");
            // Put the session back so the handle can still be stopped/freed.
            handle.session = Some(session);
            return -1;
        }
    };

    let task = handle.runtime.spawn(async move {
        // `owned_fd` is owned by this task and closed when it ends; `run` dups it
        // again into the TunDevice, so our copy outlives that internal dup setup.
        let result = session.run(owned_fd.as_raw_fd()).await;
        drop(owned_fd);
        result
    });
    handle.task = Some(task);
    0
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
    let handle = unsafe { Box::from_raw(handle) };
    if let Some(task) = &handle.task {
        task.abort();
    }
    // Drop any still-pending (never-run) session and shut the runtime down
    // without blocking the caller; tasks are aborted above.
    handle.runtime.shutdown_background();
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
