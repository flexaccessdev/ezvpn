# Plan: desktop overlap refusal + network-change handling (iOS parity)

Status: **§1 and §3 implemented (2026-07-10)** — `src/net/local_networks.rs`,
`VpnError::RouteOverlapsLocalNetwork`, check in `connect()`; `private_scope`
filter in `BypassRouteManager::update`. §2 pending (§3 did not need it: the
connect-time refusal covers the startup invariant, and a mid-session network
change breaks the tunnel, so the reconnect attempt re-runs the §1 check).
Written 2026-07-10, grounded against the code as of the `improvebypass` branch
(post `ezvpn_conn_path`, post private-scope iOS bypass fix).

## Motivation

The iOS app has two behaviors the desktop CLI client lacks:

1. **Overlap refusal** — it refuses to start when a configured split-tunnel
   prefix overlaps the network the device is currently on
   (`splitTunnelConflict` in ezvpn-ios `Packages/TunnelCore`). Routing the
   local subnet into the tunnel would cut off on-link hosts, including the
   gateway carrying the tunnel's own underlay.
2. **Disconnect on network change** — an `NWPathMonitor` fingerprint of the
   physical interfaces; any change (Wi-Fi ↔ cellular, different Wi-Fi, network
   lost) cancels the tunnel instead of migrating the QUIC session.

The desktop client instead piles on bypass routes to survive the overlap case
(see the README "Routing" caveat) and has no network monitoring at all — the
reconnect loop only reacts after the tunnel actually breaks. Refusal is the
better model (it is what made the iOS private-scope bypass removal sound), and
it unlocks the same fix on desktop (see §3).

Current state, for orientation:

- `VpnClient::run_with_reconnect` (`src/tunnel/client.rs` ~line 1292): wraps
  `connect()` with exponential backoff; retries only
  `VpnError::is_recoverable()` errors; resets the attempt counter on
  `ConnectionLost` (a session that ran).
- No interface enumeration / network monitoring anywhere; `libc` is a dep,
  `ipnet` provides the prefix types.
- The TUN-side self-capture guard (`packet_has_local_iroh_udp_port` drop in
  `run_tunnel`) runs on desktop too — desktop passes
  `collect_local_iroh_udp_ports` at `client.rs` ~line 523.

## 1. Overlap refusal at connect

- New `src/net/local_networks.rs`: enumerate on-link subnets — a Rust port of
  ezvpn-ios `TunnelCore/LocalNetworks.swift`. Use the `if-addrs` crate
  (Linux/macOS/Windows in one API; `getifaddrs` via `libc` is a Unix-only
  alternative). Same filters as the Swift code: skip loopback, point-to-point,
  the client's own tun (by name), IPv6 link-local.
- Overlap test with `ipnet`: two prefixes overlap iff one contains the other's
  network address. Pure function, unit-tested with fixture subnets (mirror the
  Swift tests in `TunnelCoreTests`).
- Check inside `connect()` before TUN/route creation, so it also guards every
  reconnect attempt. New non-recoverable `VpnError::RouteOverlapsLocalNetwork`
  with the iOS-style message: `refusing to start: split-tunnel route <cidr>
  overlaps current network <cidr> on <iface>`.
- **Desktop-specific carve-out:** exempt default routes (`0.0.0.0/0`, `::/0`,
  and the `/1` half-routes the client installs for full tunnel). Full tunnel is
  a supported desktop mode that relies on connected-route specificity plus the
  global-scope bypass set; a literal port of the iOS check would refuse every
  full-tunnel session. Only a *specific* routed prefix overlapping an on-link
  subnet is refused.
- Error policy: non-recoverable → `run_with_reconnect` exits with the message
  (iOS parity: the user reconnects deliberately). Optional later flag
  `--wait-on-overlap` for service deployments (RUNNING-AS-A-SERVICE.md): park
  instead of exit, resume when the watcher (§2) reports the conflict gone.

## 2. Network-change handling

- Watcher: the `if-watch` crate — async stream of interface-address `Up`/`Down`
  events. Event-driven only on Linux (netlink), Windows, and Android; on
  **macOS/iOS it has no native backend and falls back to polling every 10s**, so
  detection there lags an address change by up to ~10 s. If immediate detection
  matters on macOS/iOS, swap in a route/link monitor instead — a `PF_ROUTE`
  socket, or `SCDynamicStore`/`NWPathMonitor` (the latter is what the iOS app
  already uses for its `pathKey`).
- Reduce events to a fingerprint like iOS `pathKey`: the set of
  (interface, subnet) for physical interfaces, **excluding the client's own
  tun** — that exclusion is what prevents a self-inflicted disconnect when the
  tunnel itself comes up. Debounce ~1–2 s; these events flap.
- Integration: spawn the watcher task in `connect()` and `select!` it against
  the tunnel future. On fingerprint change:
  - re-run the §1 overlap check against the new local networks; on conflict,
    tear down and refuse/park exactly as at startup;
  - otherwise end the session as `VpnError::ConnectionLost("network changed")`
    — the reconnect loop resets its counter for `ConnectionLost` and dials
    again on the new network.
- Reconnect-not-migrate, same reasoning as the iOS comment, plus a
  desktop-specific one: the pinned bypass routes' next hops were resolved for
  the old network (on Windows explicitly via `Find-NetRoute`), so a migrated
  session would keep stale pins.

## 3. Follow-up unlocked: private-scope bypass filter on desktop

With refusal in place, desktop gains the invariant the iOS fix (commit
`8039b69`) relied on: a private-scope server underlay address inside a routed
prefix is never reachable off-tunnel in a session that starts. Then
`BypassRouteManager` can adopt the same `private_scope` filter as
`overlapping_underlay_excludes` (never bypass RFC1918/ULA/link-local; keep
bypassing global-scope addresses — relay IPs and e.g. an AWS egress-only GUA
IPv6, which full tunnel needs). Payoff: a service sharing the VPN host's LAN
IP (e.g. a DNS server on the VPN host) becomes reachable *through* the tunnel
on desktop, matching iOS. The shared `run_tunnel` port-drop guard already
backstops residual self-capture.

Update the README "Routing" caveat (the "client inside the same private
network as the server" bullet currently documents the desktop bypass behavior
and notes the iOS difference) when this lands. *Done — README and
`docs/ARCHITECTURE.md` ("Underlay Bypass Routes") updated alongside the
filter.*

## Suggested order

1. `local_networks` enumeration + startup refusal (small, self-contained,
   unit-testable).
2. `if-watch` monitor + disconnect-on-change (+ optional `--wait-on-overlap`).
3. Private-scope filter in `BypassRouteManager` + README routing-section
   update.

## Open questions

- Exact tun-name exclusion on each OS (utunN on macOS, configurable name on
  Linux/Windows) — thread the actual device name from `TunDevice` into both
  the enumerator and the watcher fingerprint rather than pattern-matching.
  *Resolved for §1:* the enumerator excludes by the point-to-point flag, not
  by name (covers tun/utun on every OS), and the check runs before
  `create_tun_device`, so the client's own tun never exists at check time.
  Still open for §2's watcher fingerprint.
- Whether `--wait-on-overlap` should be the default under service managers
  (systemd restart policies may make exit-and-restart good enough).
- Windows CI coverage for `if-addrs`/`if-watch` behavior.
