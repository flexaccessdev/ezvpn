/*
 * ezvpn.h — C interface to libezvpn.a for the iOS Network Extension.
 *
 * Build the static library with ./build-ios.sh (produces
 * dist/ios/libezvpn.a alongside a copy of this header).
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
 *    "relay_urls":[],"relay_only":false,
 *    "routes":["10.0.0.0/8"],"routes6":["fd00::/8"]}
 *   routes/routes6 are the split-tunnel prefixes; they are used to compute which
 *   server underlay addresses overlap and must be excluded from the tunnel.
 * out_buf/out_len : caller buffer. On success receives the network-config JSON
 *   (per-family fields are null when that family was not assigned):
 *   {"assigned_ip":"10.0.0.2","netmask":"255.255.255.255","gateway":"10.0.0.1",
 *    "assigned_ip6":"fd00::2","prefix_len6":128,"gateway6":"fd00::1","mtu":1400,
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
 * Stop the tunnel and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void ezvpn_stop(EzvpnHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* EZVPN_H */
