# Windows App

`ezvpn` can run on Windows behind a native GUI. Like the Apple client, the
Windows client is split across two repositories:

- **This repo (`ezvpn`)** — the Rust core, packaged as `ezvpn.dll` (a C-ABI
  `cdylib`) plus a small C FFI (`src/ffi_windows.rs`, header `windows/ezvpn.h`).
  This is where the Windows FFI Rust code and build script live.
- **[`ezvpn-windows`](https://github.com/andrewtheguy/ezvpn-windows)** — the .NET
  solution: a **WinUI 3** app that P/Invokes `ezvpn.dll`. Build/run/install
  instructions live in that repo's README.

It is intentionally scoped for development-signed personal use, like
`ezvpn-apple`.

## Scope

In scope:

- **Dual-stack split tunnel** — IPv4, IPv6, or both, to explicit routed
  prefixes. Both route lists are optional and independent.
- **Automatic reconnect** — reuses the desktop client's `run_with_reconnect`
  loop (exponential backoff, network-consistency check).
- **Automatic underlay bypass** — the desktop `BypassRouteManager` carves the
  few server/relay underlay addresses that overlap a routed prefix back out of
  the tunnel.

Always out of scope (never part of this project):

- **In-app split DNS** — DNS is configured outside the tunnel (see
  `docs/Architecture.md`).
- **MSIX / Microsoft Store packaging** and **code signing** — the installer is
  a plain, unsigned MSI.

## How it reuses the core — and why the FFI differs from Apple's

The data plane is the **same** portable code the desktop CLI uses. The key
difference from the Apple app is **who owns the TUN device**:

| Concern | Apple app extension | Windows GUI (`ezvpn.dll`) |
|---|---|---|
| TUN device | created by the OS; `ezvpn` wraps the handed-over `utun` fd (`TunDevice::from_raw_fd`) | created by `ezvpn` itself (wintun via `TunDevice::create`) |
| FFI shape | fd-based: `ezvpn_connect` → `ezvpn_run(utun_fd)` → `ezvpn_stop` | `VpnClient`-based: `ezvpn_start` → `ezvpn_status` → `ezvpn_stop` |
| Routing / IP / MTU | `NEPacketTunnelNetworkSettings` (extension) | `netsh` (inside `VpnClient`) |
| Underlay bypass | `excludedRoutes` computed at connect | live `BypassRouteManager` host routes |
| Single-instance lock, control socket | not used | reused from the desktop client |

There is **no Windows equivalent of `NEPacketTunnelProvider`** that hands an app
a ready TUN fd. So the Windows FFI wraps the desktop
[`VpnClient`](../src/tunnel/client.rs) — which already creates the wintun
adapter, installs routes, auto-reconnects, and publishes a status snapshot on
Windows — instead of the slim fd-driven `IosSession`. That also means the FFI is
a *start / status / stop* shape rather than *connect / run(fd) / stop*, and the
GUI reads status **in-process** rather than over the named-pipe control endpoint.

Key source in this repo:

- `src/ffi_windows.rs` — the C entry points (`ezvpn_start`, `ezvpn_status`,
  `ezvpn_stop`, `ezvpn_init_logging`).
- `src/tunnel/client.rs` — the `VpnClient` the FFI drives (`VpnClient::new`,
  `run_with_reconnect`, `status_handle`).
- `src/control.rs` — the `StatusSnapshot` / `ClientStatus` the FFI serializes.
- `windows/ezvpn.h` — the C header (also the authoritative JSON config/status
  shapes).
- `build-windows.ps1` — builds `ezvpn.dll` and stages it with the header in
  `dist/windows`.

## C interface

The app drives the tunnel with three calls (full signatures and JSON shapes in
[`windows/ezvpn.h`](../windows/ezvpn.h)):

1. `ezvpn_start(config_json, out_buf, out_len)` — parse the config, create an
   iroh endpoint and a `VpnClient`, and spawn its reconnecting run loop on a
   background thread. Returns an opaque handle once *started* (not yet
   *connected*).
2. `ezvpn_status(handle, out_buf, out_len)` — snapshot the live client status
   (state, assigned IPs, gateway, routes, connection path, bypass addresses) as
   JSON. Poll it for the `"connected"` state.
3. `ezvpn_stop(handle)` — signal the loop to stop, wait for the route/adapter
   teardown to finish, and free the handle.

```
Ezvpn.App (WinUI 3, elevated)
  create/edit profiles ──▶ ezvpn_start(json) ──▶ ezvpn.dll
  poll status         ──▶ ezvpn_status()          (iroh connect + handshake
  disconnect          ──▶ ezvpn_stop()              + wintun + routes + reconnect)
```

The whole tunnel runs **in-process** in the elevated GUI — there is no Windows
Service and no IPC.

## Prerequisites & privileges

- Runs **elevated** (Administrator): creating the wintun adapter and editing the
  routing table require it. The `ezvpn-windows` app ships an
  `app.manifest` with `requestedExecutionLevel = requireAdministrator`.
- **`wintun.dll`** (from [wintun.net](https://www.wintun.net/), the official
  WireGuard project) must sit next to `ezvpn.dll` or on `PATH`. The
  `ezvpn-windows` MSI bundles it.

## Building

From this repo, in PowerShell:

```powershell
./build-windows.ps1            # release build (default), x86_64-pc-windows-msvc
./build-windows.ps1 -Profile debug
./build-windows.ps1 -Target aarch64-pc-windows-msvc
```

This stages `dist/windows/ezvpn.dll` (+ `ezvpn.dll.lib`, `ezvpn.h`). The CI
release workflow zips it into an `ezvpn-windows.dll.zip` release asset, which
`ezvpn-windows` downloads by default (pinned by URL + checksum). For local FFI
dev, set `EZVPN_LOCAL_DLL=1` when building `ezvpn-windows` to link this
`dist/windows` build directly.

Then follow the
[`ezvpn-windows`](https://github.com/andrewtheguy/ezvpn-windows) README to build
and run the app or the MSI installer.
