/*
 * ezvpn.h — C interface to ezvpn.dll for the native Windows GUI (ezvpn-windows).
 *
 * Build the DLL with build-windows.ps1 (produces dist/windows/ezvpn.dll and a
 * copy of this header). The .NET app P/Invokes these symbols; this header is the
 * authoritative ABI + JSON-shape reference.
 *
 * Unlike the Apple FFI (ios/ezvpn.h), which hands Rust an OS-created utun fd,
 * this DLL wraps the desktop VpnClient: it creates and owns the wintun adapter
 * and the routing table itself. The host process must therefore run ELEVATED
 * (Administrator), and wintun.dll (from https://www.wintun.net/) must sit next
 * to ezvpn.dll or on PATH.
 *
 * Lifecycle:
 *
 *   1. ezvpn_init_logging()                       (optional; once at startup)
 *   2. ezvpn_start(configJson, buf, len) -> handle (or NULL on setup error;
 *        on error `buf` holds the error message). Returns once the client has
 *        STARTED, not once it has CONNECTED — poll ezvpn_status for that.
 *   3. ezvpn_status(handle, buf, len)             (poll for the status JSON)
 *   4. ezvpn_stop(handle)                          (stops the tunnel, waits for
 *        route/adapter teardown, frees the handle)
 *
 * All functions are NULL-safe and never unwind into .NET (release builds are
 * panic = "abort", so a panic terminates the host process instead).
 */
#ifndef EZVPN_H
#define EZVPN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. Created by ezvpn_start, freed by ezvpn_stop. */
typedef struct EzvpnHandle EzvpnHandle;

/*
 * Initialize logging (stderr). Honors RUST_LOG, defaults to
 * "info,iroh=warn,tracing=warn". Idempotent; safe to call more than once.
 */
void ezvpn_init_logging(void);

/*
 * Start the VPN client and its (optionally reconnecting) run loop.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","auth_token":"<47-char token>",
 *    "relay_urls":[],"relay_only":false,"dns_server":null,
 *    "routes":["10.0.0.0/8"],"routes6":["fd00::/8"],
 *    "instance":"default","auto_reconnect":true,"max_reconnect_attempts":null}
 *   auth_token / dns_server / max_reconnect_attempts may be null. relay_urls,
 *   relay_only, routes, routes6, instance, and auto_reconnect are optional.
 *   routes/routes6 are the split-tunnel prefixes routed through the tunnel; the
 *   server's advertised gateway host prefix is always routed in addition.
 * out_buf/out_len : caller buffer. On failure receives the error message
 *   (always NUL-terminated; may be truncated to fit). Untouched contents on
 *   success are irrelevant — read status via ezvpn_status.
 *
 * Returns a non-NULL handle once setup (iroh endpoint online + single-instance
 * lock acquired) succeeds; the tunnel then runs in the background until
 * ezvpn_stop. Returns NULL on a setup failure (bad config, offline endpoint, or
 * another instance already running). A non-NULL return means STARTED, not
 * CONNECTED — poll ezvpn_status until state == "connected".
 */
EzvpnHandle *ezvpn_start(const char *config_json, char *out_buf, size_t out_len);

/*
 * Snapshot the live client status as JSON into out_buf. This is the serialized
 * client StatusSnapshot (the same one `ezvpn client status` prints), e.g.:
 *   {"role":"client","instance":"default","state":"connected",
 *    "server_node_id":"<id>","device_id":"...","connected_since_secs":42,
 *    "mode":"dual-stack","assigned_ip":"10.0.0.2","network":"10.0.0.1/32",
 *    "gateway":"10.0.0.1","assigned_ip6":"fd00::2","network6":"fd00::1/128",
 *    "gateway6":"fd00::1","mtu":1280,"gso_negotiated":false,
 *    "routes":["10.0.0.1/32"],"routes6":["fd00::1/128"],
 *    "connection":"Direct 1.2.3.4:52186 (rtt 1ms)","bypass_addrs":[]}
 * `state` is "disconnected" while connecting/reconnecting and "connected" once
 * the handshake succeeds. Per-family fields are null when unassigned.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int ezvpn_status(const EzvpnHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the tunnel and free the handle. Signals the run loop to stop and WAITS
 * for the worker to finish teardown (routes removed, wintun adapter closed,
 * single-instance lock released) before returning, so a subsequent ezvpn_start
 * for the same instance does not race a half-released lock. After this call the
 * handle is invalid. Passing NULL is a safe no-op.
 */
void ezvpn_stop(EzvpnHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* EZVPN_H */
