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
 *   2. ezvpn_start(configJson, on_event, ctx, buf, len) -> handle (or NULL on
 *        setup error; on error `buf` holds the error message). Returns once the
 *        client has STARTED, not once it has CONNECTED; on_event reports
 *        CONNECTED, RECONNECTING and the final ENDED as they happen.
 *   3. ezvpn_status(handle, buf, len)             (poll for live details)
 *      ezvpn_conn_path(handle, buf, len)          (on demand: paths + relay health)
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
 * ezvpn_start event codes, passed to the on_event callback.
 *
 * RECONNECTING : a connection attempt failed, or the session was lost, and the
 *                run loop will try again; message is the error. Poll
 *                ezvpn_status for the attempt count and the next try's countdown.
 * CONNECTED    : the tunnel is up (first connection or a reconnect); message
 *                is NULL.
 * ENDED        : final. The run loop has ended and will not try again —
 *                retries used up ("Gave up after N reconnect attempt(s): ..."),
 *                a non-recoverable error (e.g. rejected authentication), or a
 *                lost session with auto_reconnect off. message is the reason, or
 *                NULL for an end without an error. The tunnel is already torn
 *                down; the handle must still be passed to ezvpn_stop.
 */
#define EZVPN_EVENT_RECONNECTING 1
#define EZVPN_EVENT_CONNECTED    2
#define EZVPN_EVENT_ENDED        3

/*
 * Event callback for ezvpn_start. ctx is the caller's pointer, passed back
 * verbatim; event is an EZVPN_EVENT_* code; message is NUL-terminated and valid
 * only for the duration of the call, or NULL. Called from library threads.
 */
typedef void (*ezvpn_event_cb)(void *ctx, int event, const char *message);

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
 *    "relay_quic_addr_discovery":null,
 *    "routes":["10.0.0.0/8"],"routes6":["fd00::/8"],
 *    "instance":"default","auto_reconnect":true,"max_reconnect_attempts":null}
 *   auth_key is the client's ed25519 secret key; its public half must be on
 *   the server's authorized_keys file. It and server_node_id are required;
 *   max_reconnect_attempts may be null. relay_urls, relay_auth_token,
 *   relay_quic_addr_discovery, routes, routes6, exclude_direct_paths,
 *   instance, and auto_reconnect are optional.
 *   relay_auth_token is the shared bearer token sent to the custom relays as
 *   "Authorization: Bearer <token>"; it is valid ONLY together with relay_urls
 *   and is rejected with the default relays.
 *   relay_quic_addr_discovery says whether the custom relays serve QUIC
 *   address discovery, all of them or none (absent or null: true). Pass false
 *   for relays behind a Cloudflare Tunnel or another HTTP-only front, which
 *   otherwise delay each start by up to 3 s. Like the token, it is valid ONLY
 *   together with relay_urls, whichever value it has.
 *   routes/routes6 are the split-tunnel prefixes routed through the tunnel; the
 *   server's advertised gateway host prefix is always routed in addition.
 *   exclude_direct_paths lists networks (CIDR strings, e.g. "100.64.0.0/10")
 *   whose server addresses path selection skips as direct paths, to keep
 *   the tunnel off another VPN; it moves to another direct path or the relay.
 *   A preference, not a block: with no allowed path at all, the current one
 *   is kept.
 * on_event/ctx : optional (on_event may be NULL) state-change callback, see
 *   EZVPN_EVENT_*. No event is delivered once ezvpn_stop has been called: it
 *   waits for a callback already in progress, so the callback must not call
 *   ezvpn_stop itself nor block on a thread that might — post the event to the
 *   UI thread asynchronously. ctx must stay valid until ezvpn_stop.
 * out_buf/out_len : caller buffer. On failure receives the error message
 *   (always NUL-terminated; may be truncated to fit). Untouched contents on
 *   success are irrelevant — read status via ezvpn_status.
 *
 * Returns a non-NULL handle once setup (iroh endpoint online + single-instance
 * lock acquired) succeeds; the tunnel then runs in the background until
 * ezvpn_stop, or until the run loop ends on its own (ENDED). Returns NULL on a
 * setup failure (bad config, offline endpoint, or another instance already
 * running). A non-NULL return means STARTED, not CONNECTED — wait for the
 * CONNECTED event (or state == "connected" in ezvpn_status).
 */
EzvpnHandle *ezvpn_start(const char *config_json, ezvpn_event_cb on_event, void *ctx,
                         char *out_buf, size_t out_len);

/*
 * Snapshot the live client status as JSON into out_buf. This is the serialized
 * client StatusSnapshot (the same one `ezvpn client status` prints), e.g.:
 *   {"role":"client","instance":"default","state":"connected",
 *    "server_node_id":"<id>","device_id":"...","connected_since_secs":42,
 *    "mode":"dual-stack","assigned_ip":"10.0.0.2","network":"10.0.0.1/32",
 *    "gateway":"10.0.0.1","assigned_ip6":"fd00::2","network6":"fd00::1/128",
 *    "gateway6":"fd00::1","mtu":1280,
 *    "routes":["10.0.0.1/32"],"routes6":["fd00::1/128"],
 *    "connection":null,"custom_relays":[],"bypass_addrs":[]}
 * `state` is "disconnected" while connecting/reconnecting, "connected" once
 * the handshake succeeds, and "stopped" once the run loop has ended for good,
 * with stop_reason the same text as the ENDED event (null otherwise, or for an
 * end without an error). Per-family fields are null when unassigned. While
 * down, failed_attempts (consecutive failures in the current outage),
 * last_error, and next_attempt_secs (seconds until the reconnect loop tries
 * again; 0 while an attempt is in progress, null when none is pending) say how
 * far the retry loop has got — a backoff step can be up to 60s once a long
 * outage has pushed it to the cap.
 *
 * Cheap enough to poll: connection is always null and custom_relays always
 * empty here, because the relay health check is an HTTP request. Fetch the
 * paths and relay health on demand with ezvpn_conn_path.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int ezvpn_status(const EzvpnHandle *handle, char *out_buf, size_t out_len);

/*
 * Snapshot how the running tunnel reaches the server, as JSON into out_buf —
 * the same document as the Apple ezvpn_conn_path, for an on-demand
 * "connection path" view:
 *   {"paths":[
 *      {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
 *      {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}],
 *    "custom_relays":[{"url":"https://relay.example/","working":true,"error":null}]}
 * paths lists every discovered path; kind is "direct", "relay", or "other"
 * (forward-compatible catch-all), and selected marks the one iroh routes over
 * right now. Both arrays are empty while the tunnel is down.
 *
 * custom_relays reports each configured custom relay's health from a GET of its
 * /healthz endpoint, made (in parallel) by this call. working is true on a 2xx,
 * false when unreachable/timed-out/non-2xx, and null if the check could not
 * run; error carries the failure detail. The array is empty with the default
 * relays. /healthz is unauthenticated: it confirms the relay is up, not that a
 * relay_auth_token is accepted. Because of these requests, call this on user
 * demand, not on a polling timer.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int ezvpn_conn_path(const EzvpnHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the tunnel and free the handle. Signals the run loop to stop and WAITS
 * for the worker to finish teardown (routes removed, wintun adapter closed,
 * single-instance lock released) before returning, so a subsequent ezvpn_start
 * for the same instance does not race a half-released lock. It then waits up
 * to 5 s for the endpoint's graceful close; a close that takes longer (the
 * network is gone, say) is cut short. Nothing of the session is left running
 * once this returns. After this call the handle is invalid. Passing NULL is a
 * safe no-op.
 */
void ezvpn_stop(EzvpnHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* EZVPN_H */
