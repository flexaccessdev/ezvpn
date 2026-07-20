/*
 * ezvpn.h — C interface to libezvpn for Apple Network Extension app extensions.
 *
 * Build the library with ./build-apple.sh (produces
 * dist/apple/libezvpn.xcframework, which embeds a copy of this header).
 *
 * Lifecycle (call from your NEPacketTunnelProvider):
 *
 *   1. ezvpn_connect(configJson, buf, len)  -> handle (or NULL on error)
 *        On success `buf` holds the network-config JSON; use it to build
 *        NEPacketTunnelNetworkSettings, then setTunnelNetworkSettings.
 *        On error `buf` holds the error message.
 *   2. ezvpn_run(handle, utunFd)            -> 0 on success, -1 on error
 *        Pass the utun file descriptor obtained after the settings apply.
 *   3. ezvpn_stop(handle)                   (in stopTunnel / on teardown)
 *
 * All functions are NULL-safe and never unwind into Swift.
 */
#ifndef EZVPN_H
#define EZVPN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. Created by ezvpn_connect, freed by ezvpn_stop. */
typedef struct EzvpnHandle EzvpnHandle;

/*
 * Initialize logging (stderr -> unified log / Console). Honors RUST_LOG,
 * defaults to "info". Idempotent; safe to call more than once.
 */
void ezvpn_init_logging(void);

/*
 * Connect to the server and perform the handshake.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","auth_token":null,
 *    "relay_urls":[],
 *    "routes":["10.0.0.0/8"],"routes6":["fd00::/8"]}
 *   routes/routes6 are the split-tunnel prefixes; they are used to compute which
 *   server underlay addresses overlap and must be excluded from the tunnel.
 *   Only global-scope (public) addresses are ever excluded; the server's
 *   private/LAN addresses stay tunneled (the app must refuse to start when a
 *   routed prefix overlaps the local network, so they are unreachable
 *   off-tunnel anyway, and excluding them would blackhole tunnel destinations
 *   that share the server's LAN address, e.g. a DNS server on the VPN host).
 * out_buf/out_len : caller buffer. On success receives the network-config JSON
 *   (per-family fields are null when that family was not assigned):
 *   {"assigned_ip":"10.0.0.2","netmask":"255.255.255.255","gateway":"10.0.0.1",
 *    "assigned_ip6":"fd00::2","prefix_len6":128,"gateway6":"fd00::1","mtu":1280,
 *    "excluded_routes":["192.168.1.5/32"],"excluded_routes6":[]}
 *   netmask/prefix_len6 are host masks (the server advertises only its own
 *   host prefix, not the VPN subnet); the extension must add gateway/gateway6
 *   as included /32 + /128 routes alongside its split-tunnel routes.
 *   On failure receives an error message. Always NUL-terminated.
 *   If out_buf is too small to hold the full network-config JSON, this is
 *   treated as a failure (returns NULL, no handle leaked) — retry with a larger
 *   buffer. (Error messages may still be truncated to fit.)
 *
 * Returns a non-NULL handle on success, NULL on failure.
 */
EzvpnHandle *ezvpn_connect(const char *config_json, char *out_buf, size_t out_len);

/*
 * Start the tunnel data loop on the given utun fd. The library dups the fd
 * synchronously before returning, so the caller may close its own copy as soon
 * as this returns. Returns 0 on success, -1 on error (NULL handle, no pending
 * session, fd dup failure, or already running).
 */
int ezvpn_run(EzvpnHandle *handle, int tun_fd);

/*
 * Snapshot the live connection's iroh path(s) as JSON into out_buf, mirroring
 * `ezvpn client status`:
 *   {"paths":[
 *     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
 *     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}],
 *   "custom_relays":[{"url":"https://relay.example/","working":true,"error":null}]}
 * A point-in-time snapshot of how the client currently reaches the server,
 * showing ALL discovered paths (not just the selected one). kind is "direct",
 * "relay", or "other" (forward-compatible catch-all); selected marks the path
 * iroh routes over right now. The paths array is EMPTY while the connection is
 * down, so only offer this while the tunnel is up.
 *
 * custom_relays reports each configured custom relay's health from an on-demand
 * GET of its /healthz endpoint (checked in parallel, only when this snapshot is
 * requested). working is true on a 2xx, false when unreachable/timed-out/non-2xx,
 * and null if the check could not run; error carries the failure detail. The
 * array is empty when the default relays are used. /healthz is unauthenticated:
 * it confirms the relay is up, not that a relay_auth_token is accepted.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the
 * JSON is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int ezvpn_conn_path(const EzvpnHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the tunnel and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void ezvpn_stop(EzvpnHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* EZVPN_H */
