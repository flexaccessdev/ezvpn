# Apple App

`ezvpn` can run on iOS and native macOS as a Network Extension app extension.
It tunnels real traffic on a physical iOS device or Apple Silicon Mac and is
intentionally scoped for development-signed personal use, not App Store or
Developer ID distribution.

The Apple client is split across two repositories:

- **This repo (`ezvpn`)** — the Rust core, packaged as `libezvpn.xcframework`
  (static-library slices for `aarch64-apple-ios` and `aarch64-apple-darwin`)
  plus a small C FFI. This is where the Apple Network Extension Rust code and
  build script live.
- **[`ezvpn-ios`](https://github.com/andrewtheguy/ezvpn-ios)** — the Swift Xcode
  project: a SwiftUI container app and the `NEPacketTunnelProvider` app
  extension that links `libezvpn.xcframework` (consumed via a Swift package
  binary target). Build/sign/run instructions live in that repo's README.

## Scope

In scope:

- **Dual-stack split tunnel** — IPv4, IPv6, or both, to explicit routed
  prefixes. Both route lists are optional and independent.
- **Optional tunnel DNS** — applied in-app by the extension via `NEDNSSettings`.
  iOS additionally supports conditional forwarding with `matchDomains` because
  it ignores installed DNS profiles while a VPN is active. macOS keeps its
  system DNS profiles active, so the app exposes only global tunnel DNS there.
- **Optional underlay bypass** — automatically carves the few server underlay
  addresses that overlap a routed prefix back out of the tunnel (see below).
- **Native Apple testing** — a Packet Tunnel Provider does not run in the iOS
  Simulator; the macOS build runs natively rather than through Catalyst.

Out of scope (by design):

- **Full tunnel** (`0.0.0.0/0` / `::/0`) — not offered by the Apple app.
- **App Store / TestFlight / Developer ID** distribution and background
  reconnect polish. Development-signed macOS builds use an app extension;
  system extensions are a distribution concern, not the debug flow.

## How it reuses the core

The app-extension data plane is the **same** portable code the desktop client
uses. It differs in who owns the tunnel device and routing table:

| Concern | Desktop CLI | iOS/macOS app extension |
|---|---|---|
| TUN device | created by `ezvpn` (`TunDevice::create`) | created by the OS; `ezvpn` wraps the handed-over fd (`TunDevice::from_raw_fd`) |
| Routing / IP / MTU | `ip`/`route`/`netsh` | `NEPacketTunnelNetworkSettings` (extension) |
| Underlay bypass | `BypassRouteManager` host routes | `NEIPv4Settings`/`NEIPv6Settings` `excludedRoutes` |
| Single-instance lock, control socket | yes | not used (the OS owns the extension lifecycle) |

The Darwin `utun` fast path (4-byte address-family-prefixed frames) is shared
via the `target_vendor = "apple"` cfg, so the read/write hot path is identical.
The handshake (`perform_handshake`) and data-stream loop
(`run_tunnel`) are used verbatim.

Key source in this repo:

- `src/tunnel/ios.rs` — `IosSession` (connect → handshake → run) and the
  network-config it returns to the extension.
- `src/ffi.rs` — the C entry points.
- `src/net/device.rs` — `TunDevice::from_raw_fd` and the shared Darwin fd I/O.
- `ios/ezvpn.h` — the C header (also the authoritative JSON config/result shapes).
- `build-apple.sh` — builds the iOS device and native macOS arm64 slices and
  bundles them into `libezvpn.xcframework` (with the header) in `dist/apple`.

## C interface

The extension drives the tunnel with three calls (full signatures and JSON
shapes in [`ios/ezvpn.h`](../ios/ezvpn.h)):

1. `ezvpn_connect(config_json, out_buf, out_len)` — create an iroh endpoint,
   connect, handshake. Returns an opaque handle and writes the assigned network
   config (IPv4 and/or IPv6 addresses, gateway, MTU, and the computed
   `excluded_routes`/`excluded_routes6`) as JSON.
2. `ezvpn_run(handle, utun_fd)` — start the data-stream loop on the OS-provided
   `utun` fd (obtained after the extension applies the network settings).
3. `ezvpn_stop(handle)` — tear down and free the handle.

Plus one optional debug readout: `ezvpn_conn_path(handle, out_buf, out_len)` —
a point-in-time JSON snapshot of the live iroh path(s) (direct/relay, RTT,
which is selected), mirroring `ezvpn client status`. The app surfaces it as the
"Connection path" sheet; callable any time between connect and stop, empty
while no path is established.

```
EzvpnApp (SwiftUI)            PacketTunnel (NEPacketTunnelProvider)
  installs VPN config  ──VPN──▶  startTunnel:
  start/stop                       ezvpn_connect(json) ──▶ libezvpn
                                   setTunnelNetworkSettings   (iroh connect
                                   ezvpn_run(utun_fd) ─────▶   + handshake
                                  stopTunnel: ezvpn_stop        + data-stream loop)
```

## Underlay bypass in the Apple app

If a routed prefix covers an address iroh's own transport uses — the server's
public underlay address (e.g. its egress-only GUA IPv6 inside a routed cloud
prefix) or, with broad/full-tunnel routes, a relay IP — the OS would route iroh's
own QUIC packets into the tunnel and the connection would self-capture and
stall.

The core computes the bypass set automatically at connect, mirroring the
desktop bootstrap (`add_iroh_bypass_routes`): it resolves every relay the
endpoint may use (the configured relay URLs, or the default relay map) and adds
the server's handshake-advertised underlay candidate addresses (`server_addrs`),
then intersects that candidate set with the effective routed prefixes — the
configured routes plus the assigned interface subnets, which the extension
always routes. Each **global-scope** overlap (public IPv4, GUA IPv6 — e.g. an
AWS egress-only address) is returned as a host route (`/32` / `/128`) and the
extension applies them as `excludedRoutes`, so the OS keeps those packets on
the underlay (Wi-Fi/cellular).

Private-scope server addresses (RFC1918/ULA/link-local) are **never** bypassed:
the app refuses to start when a routed prefix overlaps the local network, so in
any session that starts they are unreachable off-tunnel — bypassing them would
only blackhole real tunnel destinations that share the server's LAN address
(e.g. a DNS server running on the VPN host). The residual self-capture risk is
handled in the data path: the tunnel loop drops TUN packets carrying a local
iroh UDP port, so a probe toward such an address dies before encapsulation and
iroh never validates that path.

This is the declarative Network Extension equivalent of the desktop
`BypassRouteManager`.
Only the static handshake-time set is used; dynamic mid-session address updates
are not handled (re-applying `NEPacketTunnelNetworkSettings` mid-session is
disruptive).

**Caveat** (same as desktop — see the README "Routing" section and
`docs/Architecture.md`): a bypassed server underlay IP is reachable only over the
underlay while connected. To reach the server *through* the tunnel, use its
VPN-internal gateway IP, not the public address that doubles as the transport
endpoint.

## Building

From this repo:

```sh
./build-apple.sh release
```

This builds the `aarch64-apple-ios` and `aarch64-apple-darwin` slices and bundles them into
`dist/apple/libezvpn.xcframework` alongside the header. The CI release workflow
zips it into the `libezvpn-apple.xcframework.zip` release asset, which `ezvpn-ios`
downloads by default (pinned by URL+checksum in its Swift package). For local
FFI dev, `ezvpn-ios` links this `dist/apple` build directly via a committed symlink
when `EZVPN_LOCAL_XCFRAMEWORK` is set — see that repo's README.

Then follow the [`ezvpn-ios`](https://github.com/andrewtheguy/ezvpn-ios) README
to generate the Xcode project, set your signing team, and run on a device or Mac. Note
that the Network Extension (`packet-tunnel-provider`) capability requires a paid
Apple Developer account.
