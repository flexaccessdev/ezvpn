# Plan: desktop overlap refusal + network-change handling (iOS parity)

Status: **§1, §2, and §3 implemented (2026-07-10)** —
`src/net/local_networks.rs`, `VpnError::RouteOverlapsLocalNetwork`, check in
`connect()`; `spawn_local_network_overlap_watch` poller (overlap-driven
self-stop; the always-on park-and-resume future phase is NOT implemented);
`private_scope` filter in `BypassRouteManager::update`.
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
   lost) cancels the tunnel instead of migrating the QUIC session. On desktop
   this maps to something narrower — overlap-driven self-stop, not
   disconnect-on-any-change; see §2 for why the use cases differ.

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
  `--wait-on-overlap` for service deployments (Running-as-a-Service.md): park
  instead of exit, resume when the watcher (§2) reports the conflict gone.

## 2. Network-change handling (overlap-driven self-stop)

**What this is actually for (desktop):** the come-home scenario. You are out,
VPN'd into the home network with the home subnet as a split-tunnel route; you
arrive home and the laptop joins that subnet directly — with the VPN still up.
The routed prefix now overlaps the on-link network: the session should notice
and **stop itself** instead of hairpinning home-LAN traffic through the tunnel
until the user remembers to disconnect. (§1 only refuses at *connect*; nothing
re-checks a running session when the conflicting subnet appears underneath
it.) The AWS-style deployment is *not* the target: with a routed global IPv6
cloud prefix the client never sits inside that subnet, so the overlap can't
arise on-link.

**Desktop diverges from iOS here by design.** iOS tunnels are transient and
`NWPathMonitor` teardown on *any* path change is fine — the user redials.
Desktop sessions are long-lived (and headed toward always-on, below), so the
watcher's primary trigger is the **overlap appearing**, not network change per
se:

- **Platform priority: macOS first, then Windows; Linux optional** (Linux
  boxes are stationary in the main use case — their network doesn't change).
  This inverts the `if-watch` trade-off: its event-driven backends are Linux
  (netlink) and Windows, while on **macOS it has no native backend and just
  polls every 10s** — the prioritized platform would get the worst behavior
  from a new dependency.
- Watcher, therefore: **poll `local_networks()` directly and diff** — no new
  crate. §1 already provides the enumerator and the fingerprint is simply the
  set of `(interface, net)` it returns; poll every ~5–10 s (an `if-addrs`
  sweep is one `getifaddrs` call — cheap at this cadence) and react when the
  set changes. Identical behavior on every OS, and on macOS it matches what
  `if-watch` would have done anyway. Upgrades if detection ever needs to be
  immediate: a `PF_ROUTE` socket or `SCDynamicStore` on macOS (first),
  `NotifyIpInterfaceChange` on Windows; `if-watch`/netlink on Linux only if a
  mobile-Linux use case ever appears.
- On each poll where the set changed (the poll interval is the debounce),
  re-run the §1 check: `split_tunnel_conflict(routes, routes6,
  &local_networks())` with the same family gating as `connect()`. The
  enumerator already excludes the client's own tun by the point-to-point
  flag, so the tunnel coming up cannot self-trigger.
- On conflict: tear down the session and exit with
  `VpnError::RouteOverlapsLocalNetwork` — same non-recoverable path as the
  connect-time refusal, so `run_with_reconnect` does not redial into the
  refusal loop.
- Plain network change *without* a conflict (coffee shop A → B) needs no
  aggressive teardown on desktop: if the tunnel breaks, the reconnect loop
  already redials (and the §1 check runs again on the new network). The one
  caveat to weigh at implementation time: a QUIC session that *survives* a
  network change keeps bypass-route pins whose next hops were resolved for
  the old network (on Windows explicitly via `Find-NetRoute`). If stale pins
  prove to be a real problem, end such sessions as
  `VpnError::ConnectionLost("network changed")` — recoverable, counter reset,
  clean redial — but that is a refinement, not the goal.
- Integration: spawn the watcher task in `connect()` and `select!` it against
  the tunnel future.

**Future phase — always-on:** the same watcher is the substrate for auto
on/off. Instead of exiting on conflict, *park*: tear down the tunnel and
routes, keep the process and watcher alive, and reconnect automatically when
the conflicting subnet disappears (left home). That is `--wait-on-overlap`
from §1's error policy grown into a mode: VPN routing off while at home, back
on when away, no user action either way.

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
`docs/Architecture.md` ("Underlay Bypass Routes") updated alongside the
filter.*

## Suggested order

1. `local_networks` enumeration + startup refusal (small, self-contained,
   unit-testable).
2. `local_networks()` poller + overlap-driven self-stop (then
   `--wait-on-overlap` / always-on park-and-resume as a follow-up mode).
3. Private-scope filter in `BypassRouteManager` + README routing-section
   update.

## Open questions

- Exact tun-name exclusion on each OS (utunN on macOS, configurable name on
  Linux/Windows) — thread the actual device name from `TunDevice` into both
  the enumerator and the watcher fingerprint rather than pattern-matching.
  *Resolved:* the enumerator excludes by the point-to-point flag, not by name
  (covers tun/utun on every OS); the §1 check runs before `create_tun_device`
  so the client's own tun never exists at check time, and §2's fingerprint is
  the same `local_networks()` output, so the tunnel coming up never perturbs
  it either.
- Whether `--wait-on-overlap` should be the default under service managers
  (systemd restart policies may make exit-and-restart good enough).
- Windows CI coverage for `if-addrs` enumeration behavior (second priority
  after macOS; Linux watcher support optional — stationary network).
