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
 * Generate a fresh client authentication keypair.
 *
 * out_buf/out_len : caller buffer. On success receives
 *   {"created":"<UTC>","public_key":"ed25519-pub:...",
 *    "secret_key":"ed25519-sec:..."}
 *   Store the secret key and pass it back as the config's auth_key; show the
 *   public key (never a secret) so the user can put it on the server's
 *   authorized_keys file.
 *
 * Returns 1 on success, 0 if out_buf is too small or key generation failed
 * (system RNG unavailable, in which case out_buf holds the error message).
 * On the too-small return out_buf holds a TRUNCATED PREFIX OF THE DOCUMENT,
 * secret-key material included — zero the buffer before retrying with a larger
 * one so no partial secret is left in memory.
 */
int ezvpn_generate_client_key(char *out_buf, size_t out_len);

/*
 * Derive the public key ("ed25519-pub:...") of a stored secret key, so the GUI
 * can display it without persisting it separately.
 *
 * secret_key : NUL-terminated UTF-8 "ed25519-sec:..." token.
 * out_buf/out_len : receives the public key on success, or an error message on
 *   failure. Always NUL-terminated.
 *
 * Returns 1 on success, 0 on failure (invalid secret, or out_buf too small —
 * in which case out_buf holds truncated output rather than a diagnostic).
 */
int ezvpn_client_public_key(const char *secret_key, char *out_buf, size_t out_len);

/*
 * Start the VPN client and its (optionally reconnecting) run loop.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","auth_key":"ed25519-sec:...",
 *    "relay_urls":[],"relay_auth_token":null,
 *    "routes":["10.0.0.0/8"],"routes6":["fd00::/8"],
 *    "instance":"default","auto_reconnect":true,"max_reconnect_attempts":null}
 *   auth_key is the client's ed25519 secret key; its public half must be on
 *   the server's authorized_keys file. It and server_node_id are required;
 *   max_reconnect_attempts may be null. relay_urls, relay_auth_token, routes,
 *   routes6, instance, and auto_reconnect are optional.
 *   relay_auth_token is the shared bearer token sent to the custom relays as
 *   "Authorization: Bearer <token>"; it is valid ONLY together with relay_urls
 *   and is rejected with the default relays.
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
 *    "connection":"Direct 1.2.3.4:52186 (rtt 1ms)",
 *    "custom_relays":[{"url":"https://relay.example/","working":true,
 *                      "error":null}],"bypass_addrs":[]}
 * `state` is "disconnected" while connecting/reconnecting and "connected" once
 * the handshake succeeds. Per-family fields are null when unassigned. While
 * down, failed_attempts (consecutive failures in the current outage),
 * last_error, and next_attempt_secs (seconds until the reconnect loop tries
 * again; 0 while an attempt is in progress, null when none is pending) say how
 * far the retry loop has got — a backoff step can be up to 60s once a long
 * outage has pushed it to the cap.
 *
 * custom_relays reports each configured custom relay's health from an on-demand
 * GET of its /healthz endpoint (checked in parallel, only when this snapshot is
 * requested). working is true on a 2xx, false when unreachable/timed-out/non-2xx,
 * and null if the check could not run; error carries the failure detail. The
 * array is empty with the default relays. /healthz is unauthenticated: it
 * confirms the relay is up, not that a relay_auth_token is accepted.
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
