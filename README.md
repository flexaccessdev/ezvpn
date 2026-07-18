# ezvpn

**Cross-platform IP-over-QUIC VPN with NAT traversal via iroh.**

`ezvpn` creates a TUN interface and routes IP packets through encrypted iroh
QUIC connections. Clients dial the server by its stable iroh `EndpointId`, so
they do not need the server's current IP address and the server does not need
open inbound ports. Relay fallback is used when a direct path is unavailable.

> [!WARNING]
> While `ezvpn` remains in the `0.0.x` series, there is no backward
> compatibility between versions. Keep clients and servers on the same release,
> refresh configs from the current examples, and regenerate the server identity
> key as a fallback if the upgraded deployment still cannot connect. Regenerating
> the key changes the server `EndpointId`, so update every client profile with the
> new ID.

> [!NOTE]
> Running `ezvpn` requires root/Administrator privileges to create TUN devices
> and routes.

## Project Scope

The goal of `ezvpn` is easy VPN setup without the configuration complexity that
has always been the bottleneck and friction point of VPN tunnels. It removes
the two classic pain points:

- **No inbound port to open on the server, and no server IP to know or keep
  stable.** Clients dial the server's stable iroh `EndpointId`, with
  hole-punching and relay fallback. An open port is a security concern, and —
  like a static, reachable IP — is difficult or impossible for home-hosted
  servers behind dynamic IPs, NAT/CGNAT, or carrier restrictions. With `ezvpn`
  no port forwarding and no dynamic-DNS setup are needed.
- **No VPN subnet IP planning.** The server assigns client VPN IPs dynamically,
  so there is nothing to keep collision-free by hand — unlike static-IP VPNs
  such as WireGuard, where making sure client subnet IPs do not collide is on
  you.

`ezvpn` is meant for temporary split-tunnel access to the server's network, not
a permanent overlay network. A typical deployment is a small `ezvpn` server
inside a private network, such as an AWS VPC, where clients need to reach
private AWS resources or instances in private/egress-only subnets.

`ezvpn` is not an anonymity network. If the default iroh relay/discovery
infrastructure is used, iroh relay operators can observe connection metadata
when relays are used for signaling or for carrying encrypted traffic. The VPN
payload remains end-to-end encrypted over QUIC/TLS 1.3, so relay operators
cannot decrypt the tunneled data.

Full-tunnel routing (`0.0.0.0/0` and `::/0`) is supported, but it is still more
experimental than routing explicit private prefixes. Full tunneling touches more
of the host routing table and depends on bypass routes that keep the iroh
underlay path to the server and relay infrastructure outside the VPN route.

## Features

- Full subnet routing, not just single-port forwarding
- End-to-end encryption via QUIC/TLS 1.3 through iroh
- NAT traversal with relay fallback
- Token-based authentication over iroh's cryptographic endpoint identity
- Optional dual-stack VPN operation with IPv4, IPv6, or both
- Optional split tunneling through repeatable `--route` and `--route6`
- Auto-reconnect using QUIC keep-alive and idle-timeout health checks
- Automatic Linux TUN GSO offload with software segmentation fallback for
  peers that do not support GSO, such as mixed-OS peers

## When To Use It

Use `ezvpn` when you need:

- Home or remote access to private cloud/VPC/LAN resources without opening
  inbound firewall ports on the VPN server
- Access to AWS resources that live behind private routes or in egress-only
  subnets, using an `ezvpn` server inside that network as the gateway
- Access to an entire remote subnet
- Stable full-network routing between peers behind NAT
- Cross-platform VPN connectivity on Linux, macOS, and Windows
- A WireGuard/OpenVPN alternative over iroh transport

`ezvpn` is a server-centered access tunnel, not a site-to-site network joiner,
and it intentionally does not provide client-to-client connectivity. Within the
VPN address pool a client can reach only the server VPN gateway; packets to
other client-assigned VPN IPs are dropped in userspace before they reach the TUN
device. Routes can still forward non-VPN destinations through the server,
subject to the server host's routing, forwarding/NAT, and firewall rules.

Ruling out client-to-client traffic is deliberate: it sidesteps the IP-conflict
pain point of conventional VPNs, which need sophisticated state management to
keep each client's assigned address stable so peers can reliably address one
another. Here every client only ever talks to the server gateway, so assigned
IPs carry no such guarantee and the whole class of stale-IP and address-collision
bookkeeping disappears. So do not use `ezvpn` for site-to-site routing between
two LANs or for direct client-to-client traffic.

This is a different principle than Tailscale, one of whose use cases is giving
every client a stable IP so peers can address one another. `ezvpn` deliberately
keeps client IPs dynamic and clients isolated, trading that capability for a
conflict-free network with zero address configuration. And for a permanent VPN
that bridges two sites with stable subnets, WireGuard is the right choice, not
`ezvpn`.

`ezvpn` also follows a single-responsibility principle: the server and desktop
client do one thing — tunneling. Firewall, forwarding/NAT, and DNS
configuration (e.g. conditional forwarding for an internal zone, see
[docs/Client-Split-DNS.md](docs/Client-Split-DNS.md)) are expected to be
managed outside the VPN connector. The iOS app is the one deliberate
exception: it applies split DNS in-app (`NEDNSSettings`), because on iOS
that is the only way to accomplish it.

Also do not use `ezvpn` when the goal is anonymity. iroh's relays can see relay
metadata when they are involved, even though the VPN payload remains encrypted.
For the most predictable routing behavior today, prefer split routes to the
private resources you need over full-tunnel default routes.

## Installation

You only need the `ezvpn` binary in your `PATH`.

### Linux and macOS

```bash
curl -sSL https://flexaccessdev.github.io/ezvpn/install.sh | sudo bash
```

Prebuilt installer assets currently support Linux `amd64`/`arm64` and Apple
Silicon macOS (`arm64`). Other macOS architectures can build from source.

### Windows

Run from an **elevated** (Administrator) PowerShell — the installer places the
binary systemwide in `%ProgramData%\ezvpn` (the same location used for config and
runtime files) and updates the machine `PATH`:

```powershell
irm https://flexaccessdev.github.io/ezvpn/install.ps1 | iex
```

Windows also requires `wintun.dll` from the official WireGuard project:
<https://www.wintun.net/>.

1. Download and extract the WinTun zip.
2. Copy `wintun/bin/amd64/wintun.dll` to either the same directory as
   `ezvpn.exe` (default: `%ProgramData%\ezvpn\`) or a directory in your system
   `PATH`.
3. Run `ezvpn.exe` as Administrator.

If you see `Failed to create TUN device: LoadLibraryExW failed`, the DLL is
missing or is not in a valid search path.

<details>
<summary>Advanced installation options</summary>

Install a specific release tag:

```bash
curl -sSL https://flexaccessdev.github.io/ezvpn/install.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
& ([scriptblock]::Create((irm https://flexaccessdev.github.io/ezvpn/install.ps1))) <RELEASE_TAG>
```

Install the latest prerelease:

```bash
curl -sSL https://flexaccessdev.github.io/ezvpn/install.sh | sudo bash -s -- --prerelease
```

```powershell
& ([scriptblock]::Create((irm https://flexaccessdev.github.io/ezvpn/install.ps1))) -PreRelease
```

</details>

### From Source

```bash
cargo install --path .
```

Or build a release binary directly:

```bash
cargo build --release
```

## Quick Start

### 1. Generate Server Identity and Tokens

```bash
ezvpn generate-server-key --output ./vpn-server.key

AUTH_TOKEN=$(ezvpn generate-auth-token)
echo "$AUTH_TOKEN"
```

Token format:

- Auth token: exactly 47 characters, `v` followed by 46 Base64URL characters
  with no padding.

`generate-server-key`, `generate-auth-token`, and `show-server-id` all accept
`--json` for machine-readable output.

The auth token identifies authorized clients. The tunnel also negotiates a
fixed ALPN over iroh's QUIC handshake, so a peer that does not speak the ezvpn
protocol is rejected before any stream is opened.

### 2. Create Server Config

Create `vpn_server.toml`, or copy from `vpn_server.toml.example`:

```toml
role = "vpnserver"

[network]
network = "10.0.0.0/24"

[auth]
auth_tokens = ["<YOUR_AUTH_TOKEN>"]

[iroh]
secret_file = "./vpn-server.key"
```

Config notes:

- `[network]` defines VPN addressing. At least one of `network` (IPv4) or
  `network6` (IPv6) is required.
- `[auth]` defines accepted client auth tokens.
- `[iroh]` defines server identity and relay/discovery settings.
- There are no performance or security knobs: MTU, QUIC transport settings,
  and queue sizes are fixed constants, and spoofing checks are always
  enforced (WireGuard/Tailscale style).
- `secret_file` is required for a stable server `EndpointId`.
- IPv6-only mode is supported but still experimental.

### 3. Start Server

```bash
sudo ezvpn server start -c vpn_server.toml
```

The server prints its `EndpointId` at startup. You can also derive it from the
server key:

```bash
ezvpn show-server-id --secret-file ./vpn-server.key
```

### 4. Connect Client

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-token "$AUTH_TOKEN"
```

### 5. Verify Connectivity

```bash
# Linux
ip addr show

# macOS
ifconfig

# Ping the server VPN IP from the client, for example:
ping 10.0.0.1
```

## Configuration Model

Use `vpn_server.toml.example` and `vpn_client.toml.example` for the full set of
tunables.

Server-side settings are authoritative for VPN network parameters:

- The server assigns client IPv4/IPv6 addresses.

The tunnel MTU and QUIC transport settings are fixed protocol constants
(WireGuard/Tailscale-style — no tuning knobs): the MTU is always 1280
(Tailscale's fixed value, the IPv6 minimum link MTU) and the transport always
uses CUBIC with fixed windows. Nothing is negotiated; both sides derive the
same values from constants.

Clients configure their server identity, auth token, routes, relay and
discovery settings, and reconnect behavior. Client CLI arguments take
precedence over client config file values.

## CLI Reference

### Server

`ezvpn server start` requires a config:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Server config path |
| `--default-config` | Use `vpn_server.toml` in the system config dir (`/etc/ezvpn` on Linux, `/usr/local/etc/ezvpn` on macOS, `%ProgramData%\ezvpn` on Windows) |

`ezvpn server status` prints the running server's uptime, mode, connected
clients with assigned IPs and iroh paths, and packet counters. Add `--json` for
machine-readable output.

`ezvpn server list` enumerates server instances on this host. Add `--json` for
machine-readable output.

### Client

`ezvpn client start` accepts:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Client config path |
| `--default-config` | Use `vpn_client.toml` in the system config dir (`/etc/ezvpn` on Linux, `/usr/local/etc/ezvpn` on macOS, `%ProgramData%\ezvpn` on Windows) |
| `-n, --server-node-id <ID>` | VPN server `EndpointId` |
| `--auth-token <TOKEN>` | Authentication token |
| `--auth-token-file <PATH>` | Read auth token from file |
| `--route <CIDR>` | Additional IPv4 route through the VPN; repeatable |
| `--route6 <CIDR>` | Additional IPv6 route through the VPN; repeatable |
| `--relay-url <URL>` | Custom relay URL; repeatable |
| `--dns-server <URL\|none>` | Custom iroh discovery server, or disable DNS discovery |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |
| `--instance <NAME>` | Instance name for lock and status socket scope; default `default` |
| `--daemon` | Fork into the background on Unix; logs to `<log_dir>/ezvpn-client-<instance>.log` |

With `--daemon`, the client validates its config and paths before forking, so
startup errors are still reported in the foreground. Stop a daemonized Unix
client with:

```bash
sudo ezvpn client stop --instance work
```

`client stop` also accepts `--json`, reporting one of `not_running`, `stopped`,
or `signal_sent` (signaled, but still shutting down after 5 s).

`ezvpn client status` prints connection state, assigned VPN IP/gateway, MTU,
negotiated GSO, live iroh path (direct or relay), and the daemon log path when
applicable. Add `--json` for machine-readable output, or `--instance <NAME>` to
query a specific instance.

`ezvpn client list` enumerates client instances on this host. Add `--json` for
machine-readable output.

## Runtime Controls and Instances

Only one `ezvpn server` runs at a time per machine. Clients are scoped by
`--instance <NAME>` (default: `default`), so multiple clients can run on one
host if each has a different instance name. Instance names may contain ASCII
letters, digits, and underscores. The instance name is a CLI flag only, not a
config option.

```bash
sudo ezvpn client start -c work.toml --instance work
sudo ezvpn client start -c home.toml
ezvpn client status --instance work
```

Each running instance exposes a local control endpoint derived from the same
role/instance name as its lock file:

- Unix: Unix domain socket in the runtime directory
- Windows: named pipe in the global pipe namespace

The runtime directory is machine-global: `/run/ezvpn` on Linux,
`/var/run/ezvpn` on macOS, and `%ProgramData%\ezvpn` on Windows. It holds lock
files on every platform and Unix control sockets on Linux/macOS. Override it
with `EZVPN_RUNTIME_DIR`.

`--default-config` reads its TOML from the machine-global system config
directory — `/etc/ezvpn` on Linux, `/usr/local/etc/ezvpn` on macOS, and
`%ProgramData%\ezvpn` on Windows — not a per-user home directory, since `ezvpn`
runs as root/LocalSystem. On Windows the `%ProgramData%` location is resolved
via the Known Folders API, so it follows the actual install drive rather than
assuming `C:\`.

On Unix, the daemon log is kept separately in the persistent log directory:
`/var/log/ezvpn` on Linux and macOS. Override it with `EZVPN_LOG_DIR`. The log
is size-capped: at 10 MiB it rotates to a single `<name>.log.1` backup
(replacing any previous one), so disk use stays bounded at roughly 20 MiB per
instance. Override the cap (in bytes) with
`EZVPN_LOG_MAX_BYTES`.

`status` and `list` work without root/Administrator: the runtime directory is
world-traversable and the control endpoint is read-only and world-connectable
(Unix sockets are `0666`; the Windows pipe is opened read-only, which its
default ACL grants to everyone). A daemon started by an older ezvpn version
keeps its restrictive permissions until restarted — query it with `sudo` or
restart it. On Unix, `stop` still requires `sudo` (it signals the root-owned
tunnel process). `client list` discovers instances by lock file and probes each
control endpoint; stopped clients may briefly show as
`not responding (stale lock)` until the lock file is reused or removed.

## Routing

The server's VPN address (`/32` / `/128`) is always routed by default: the
server advertises only its own host prefix, never the full VPN subnet, since
the gateway is the only in-VPN destination a client can reach (inter-client
traffic is dropped server-side anyway).

This always-installed gateway host route is exempt from the split-tunnel
overlap refusal described below — the check guards only configured
`--route`/`--route6` prefixes, on desktop and iOS alike. So in the very rare
case where the server's VPN gateway IP falls inside the subnet the client is
currently on (e.g. VPN `network = 10.0.0.0/24` while the client sits on a
`10.0.0.0/24` LAN), the session still starts, and the more-specific
`/32`/`/128` shadows that single LAN address for the duration of the session —
the rest of the LAN is unaffected, but if that address is the LAN router
doubling as the client's DNS server, local DNS goes into the tunnel with it.
Avoid this by picking a server VPN `network` prefix unlikely to collide with
the LANs your clients connect from.
Add extra non-VPN destinations with repeatable `--route` and `--route6`; those
routes are forwarded by the server host according to its routing,
forwarding/NAT, and firewall configuration (see
[Server NAT and Firewall](#server-nat-and-firewall)).

Split tunnel example:

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

Full tunnel example:

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 0.0.0.0/0 \
  --route6 ::/0
```

Full tunnel mode is the experimental path. It is useful for testing and for
controlled environments, but private-prefix split routing is the primary design
target because it avoids many broad-route interactions with iroh server and relay
bypass routes.

Default routes are installed as split half-routes (`0.0.0.0/1` +
`128.0.0.0/1`, and `::/1` + `8000::/1`) so the system default route is not
removed. On Linux, macOS, and Windows, `ezvpn` also installs host-specific
bypass routes for iroh underlay addresses that would otherwise be captured by
VPN routes, so full-tunnel routes keep the underlay path to the server/relay
off the tunnel automatically. On Windows the underlay next hop is resolved with
the in-box `NetTCPIP` PowerShell cmdlets (`Find-NetRoute` / `Get-NetRoute`) and
the host route is pinned with `New-NetRoute`.

### Caveat: the transport endpoint address is pinned off the tunnel

The bypass routes are installed for the addresses iroh **may use to carry the
tunnel** — the server's *candidate* underlay addresses (every address iroh
enumerates, across IPv4 *and* IPv6), plus any relay the connection can fall
back to — and **only for the global-scope ones that fall inside one of your
routed CIDRs**. Private-scope candidates (RFC1918/ULA/link-local — the
server's LAN addresses) are never bypassed, matching iOS: the overlap refusal
above means such an address is unreachable off-tunnel in any session that
starts (and in full tunnel the connected LAN route already keeps the local
subnet off the tunnel), so bypassing it would only blackhole a real tunnel
destination sharing the server's LAN IP — e.g. a DNS server on the VPN host,
which stays reachable *through* the tunnel instead. A common example is the server's AWS public
IPv6 when you route a `2600:1f13:adc::/…` prefix that contains it. `ezvpn` pins a
`/32`/`/128` bypass host route for each such address so the QUIC tunnel's own
underlay packets are not fed back into the tunnel (which would deadlock the
connection). The bypasses are installed for the lifetime of the session and are
**not** removed mid-session.

**This is the same principle as any traditional VPN** — it just has less
visibility here. A conventional client (OpenVPN, WireGuard, IPsec) must also keep
packets to the VPN *gateway's own address* off the tunnel; otherwise the
encrypted transport gets routed into the very tunnel it carries and the link
deadlocks. There it's obvious and singular: you type in one endpoint IP, and the
client pins exactly one host route to it via the physical gateway. `ezvpn` does
the identical thing, but the transport endpoint is **not** a single static IP you
configured — iroh discovers it at runtime and may use several of the server's
addresses (IPv4 *and* IPv6) and fall back to public **relay servers**. So instead
of one hand-configured bypass you can see, `ezvpn` pins a *set* of addresses: the
server's own underlay addresses, which the server **publishes to the client**
over the connection, together with the resolved IPs of the client's preconfigured
list of relays. That larger, runtime-determined set is exactly why the effect is
easy to miss and worth spelling out below.

This affects **only those transport addresses — not the rest of the prefix.**
Other hosts inside the same routed CIDR still route through the VPN normally; only
the server's candidate underlay addresses (and relays) are pinned. (In a full
tunnel, `0.0.0.0/0`/`::/0` covers everything, so the server and relay addresses
are always pinned — but those are iroh infrastructure, not resources you address
directly.)

**In a split tunnel this usually means zero bypass routes** — and when a bypass
is needed at all, it is only the server's own host address (`/32`/`/128`) for
each routed prefix that happens to contain it, never anything broader. The two
common ways a split-tunnel route overlaps a server address:

- **The client is inside the same private network as the server.** If you route
  a private prefix (e.g. `172.31.0.0/16`) and connect from within that network,
  the client **refuses to start** — like iOS, a specific routed prefix that
  overlaps a network the host is on is rejected at connect (`refusing to
  start: split-tunnel route … overlaps current network … on …`), because
  routing the local subnet into the tunnel would cut off on-link hosts,
  including the gateway carrying the tunnel's own underlay. The same check
  runs mid-session: if a conflicting network appears while connected (e.g.
  arriving home with the VPN to the home network still up), the client stops
  itself with the same message instead of hairpinning local traffic through
  the tunnel. Unlike iOS, full
  tunnel (default routes and their `/1` halves) is exempt from the refusal on
  desktop; there the connected LAN route is more specific than the `/1`
  halves, so the server's private LAN address stays reachable off-tunnel with
  no pinned route — private-scope addresses are never bypassed on either
  platform (see `docs/Apple-App.md`).
- **A routed IPv6 prefix contains the server's public IPv6.** Cloud servers
  typically sit inside the same broad IPv6 CIDR as the resources you route (e.g.
  an AWS VPC prefix), so routing that CIDR captures the server's own public
  IPv6; it gets the `/128` bypass while the rest of the prefix routes through
  the tunnel.

If none of your routed CIDRs contains a server or relay underlay address, no
bypass routes are installed at all.

The side effect is that **this one address is reachable only over the underlay,
not through the VPN**, for as long as the client is connected. If that same host
also serves resources you want to reach *through* the tunnel, do not address them
by that public IP — it will skip the VPN.

**The surprising case is the VPN server itself.** The pinned address is the
server's *own* transport endpoint, so you get an asymmetry that looks like a bug
but isn't: a given public address (e.g. an egress-only IPv6) on **any other
host** is reachable through the tunnel as normal, yet the **same kind of address
on the VPN server** is the one pinned off the tunnel and reachable only over the
underlay. "I can hit this egress-only IPv6 on host X through the VPN, but not the
identical-looking one on the VPN server" is therefore expected — the only
difference is that the server's address doubles as the tunnel's underlay
endpoint, so it must stay off the tunnel.

Instead, **access the VPN server (and any in-VPN resource) by its VPN-internal
address** (the server/peer's address inside the VPN subnet, e.g. `10.99.0.1` /
`fd11:9a0b:1095:99::1`), not its public IP. Reserving the public address purely
for tunnel transport and using VPN IPs for actual traffic avoids the ambiguity
entirely.

> Earlier versions discovered the address by watching iroh's per-connection path
> snapshots and tried to *remove* the bypass when the peer dropped out of the set.
> Because iroh flaps underlay peers in and out of those snapshots, this both
> missed addresses that appeared only briefly and churned the route (repeated
> add/remove), self-capturing the address into the tunnel between removals. The
> server now **publishes** its underlay addresses to the client directly, and the
> bypass is stable for the session; use the VPN IP for in-tunnel access. (Pinning
> the server's *direct* address requires a server built with this feature; older
> servers still bypass relays only.)

## Server NAT and Firewall

Per the single-responsibility principle, `ezvpn` never touches the server
host's firewall or NAT. To let clients reach hosts beyond the server itself,
configure the host once with your normal OS tooling:

1. Enable IP forwarding (e.g. `net.ipv4.ip_forward=1` /
   `net.ipv6.conf.all.forwarding=1` via `sysctl`).
2. NAT the VPN prefix out the egress interface, unless the surrounding network
   already routes the VPN prefix back to the server host:

   ```bash
   # iptables example, masquerading the server config's `network` prefix
   iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
   ```

Because the rules key on the VPN prefix (the server config's `network` /
`network6`), they are inert while the tunnel is down — so they can simply be
**permanent** (`sysctl.conf`, persistent nftables/iptables config, or your
distro's firewall service). There is no need for up/down lifecycle hooks that
add and remove rules with the interface, as in WireGuard's typical `wg-quick`
`PostUp`/`PostDown` pattern.

Two things you do **not** need firewall rules for:

- **Blocking client-to-client traffic.** The server unconditionally drops
  inter-client packets in userspace before they reach the TUN device, so even
  if a client widens its routed CIDR to cover the whole VPN subnet (instead of
  the default gateway-only `/32`/`/128`), packets to other clients' VPN IPs
  never leave the tunnel process. See "Client Isolation" in
  [docs/Architecture.md](docs/Architecture.md).
- **Allowing inbound connections.** No inbound port needs to be opened or
  allowed; iroh establishes the transport through NAT traversal or relay
  fallback.

On the client side, DNS is likewise managed outside the tunnel: to resolve an
internal zone through a resolver reachable over the VPN, set OS-level
conditional forwarding on each client — see
[docs/Client-Split-DNS.md](docs/Client-Split-DNS.md). The exception is iOS,
where the app applies DNS conditional forwarding in-tunnel itself (see
[docs/Apple-App.md](docs/Apple-App.md)).

## Protocol, MTU, and GSO

- Wire protocol v6 is required on both peers. Mixed-version pairs do not
  connect.
- The data path sends raw IP packets over a single reliable QUIC
  bidirectional stream (the handshake stream, kept open) protected by
  QUIC/TLS 1.3.
- IP packet frames are `[len: u32 BE][type][offload_len][offload?][ip_packet]`.
  The stream is a byte pipe, so an explicit length prefix delimits messages.
  Server address publications use their own frame type (`0x01`) with a JSON
  body.
- The initial QUIC path MTU is 1200, the QUIC protocol minimum, so the first
  packets survive any path (cellular, tunnel-in-tunnel, PPPoE). QUIC path-MTU
  discovery probes upward to 1452 right after the handshake. The path MTU only
  affects QUIC's own packetization — application framing is size-independent.
- The inner TUN MTU is fixed at 1280 on both ends (the IPv6 minimum link MTU
  and the same fixed value Tailscale uses, mobile-safe on essentially any real
  path). It is a protocol constant, not a config knob, and is not carried in
  the handshake.
- GSO super-frames ride the stream whole when both sides negotiated GSO and
  are re-coalesced into kernel-TSO super-frames on receive where supported;
  otherwise they are software-segmented into per-MSS packets. Path MTU never
  forces segmentation or drops — QUIC retransmits and packetizes the stream.

Linux GSO is automatic:

- TUN offload is attempted at startup with `vnet_hdr` and TCP GSO flags.
- No GSO config toggle is exposed.
- If Linux offload setup fails, VPN traffic continues in non-GSO mode and logs
  a warning.
- Connection setup logs include local, remote, and negotiated GSO status.

## Throughput Notes

There are no transport tuning knobs (WireGuard/Tailscale style). QUIC transport
settings are fixed constants on both ends: CUBIC congestion control and 8 MB
receive/send windows, which cover most links.

### Linux UDP Socket Buffers

Both peers run iroh. Its socket layer requests 7 MiB UDP
`SO_RCVBUF`/`SO_SNDBUF` buffers so the kernel can absorb bursty multi-Gbit
traffic instead of silently dropping datagrams. Dropped datagrams show up as
inner-TCP retransmits in tools such as `iperf3`.

Linux silently caps that request at `net.core.rmem_max` / `net.core.wmem_max`,
which default to about 208 KiB on many systems. The receive buffer is the one
that usually matters most, because a too-small `SO_RCVBUF` causes drops. Raise
both sysctls so the full request is honored:

```bash
sudo sysctl -w net.core.rmem_max=7340032
sudo sysctl -w net.core.wmem_max=7340032
```

To persist across reboots, add them to `/etc/sysctl.d/99-ezvpn.conf`. `ezvpn`
logs a startup warning with the exact command when either sysctl is below 7
MiB. This is Linux-only; macOS uses `kern.ipc.maxsockbuf`.

## Reconnect Behavior

Client auto-reconnect is enabled by default. Disable it with
`auto_reconnect = false` in config or `--no-auto-reconnect` on the CLI. Limit
attempts with `max_reconnect_attempts` or `--max-reconnect-attempts`.

Liveness is detected by QUIC:

- QUIC keep-alive runs every 15 seconds.
- QUIC idle timeout is 30 seconds.
- The client tears down and reconnects when the connection closes, peer liveness
  fails, or TUN/stream I/O fails.
- Reconnect backoff starts at 1 second, doubles up to 30 seconds, and adds
  0-500 ms of jitter.

On reconnect, the client compares the server's network parameters against the
first successful handshake:

- A change only to the assigned client IP (`assigned_ip` or `assigned_ip6`) is
  accepted. The client logs a warning, adopts the new IP as the baseline, and
  rebuilds the TUN device and routes.
- A change to any other network field (`network`, gateway, or the IPv6
  network/gateway fields) is fatal. The client exits instead of reconfiguring
  into an inconsistent routing state.

The client uses a stable per-process `device_id`, so the server normally assigns
the same IP during reconnects. Reassignment is expected mainly after server
restart or allocation state changes.

## Relay and Discovery

`ezvpn` can use custom iroh relay and discovery infrastructure:

- `relay_urls` / `--relay-url` configure custom relay servers for failover and
  connection hints.
- `dns_server` / `--dns-server` configure the iroh discovery server. This is
  not VPN DNS and does not affect client DNS resolution. The client does not push
  DNS or match domains over the tunnel; to resolve an internal zone through a
  resolver reachable over the tunnel, set OS-level conditional forwarding —
  see [docs/Client-Split-DNS.md](docs/Client-Split-DNS.md).
- Server and client relay/discovery settings must match.
- If `dns_server = "none"` disables DNS discovery, clients and server must
  connect through a common relay or same-LAN mDNS discovery.

See the relay and discovery comments in `vpn_server.toml.example` and
`vpn_client.toml.example` for exact TOML syntax.

## Running as a Service

For unattended clients under systemd, launchd, or a Windows service, see
[`docs/Running-as-a-Service.md`](docs/Running-as-a-Service.md).

That guide also covers the fixed runtime directory used by `status`, `list`,
and Unix `stop` under service managers.

## Apple App

[`ezvpn-apple`](https://github.com/flexaccessdev/ezvpn-apple) is a native SwiftUI
GUI client for iOS and macOS that connects to an `ezvpn` server built from this
repo (dual-stack split tunnel, optional tunnel DNS on iOS only including
split-DNS match domains; no full tunnel or App Store distribution). The
packet-tunnel provider ships as an app extension on iOS and a system extension
on macOS; macOS is distributed as a signed, notarized Developer ID `.dmg` (no
Apple Developer account needed to run it), while iOS must be built and signed
under your own team (no TestFlight, no Simulator). The Rust core builds into `libezvpn.xcframework` here
(`./build-apple.sh`, released as `libezvpn-apple.xcframework.zip`), which the
Swift app consumes via a Swift package binary target.

See [`docs/Apple-App.md`](docs/Apple-App.md) for scope, how it reuses the core, the C
interface, and build steps.

## Windows App

[`ezvpn-windows`](https://github.com/flexaccessdev/ezvpn-windows) is a native
WinUI 3 GUI client for Windows that connects to an `ezvpn` server built from this
repo (dual-stack split tunnel; no in-app split DNS, Store packaging, or code
signing). The Rust core builds into `ezvpn.dll` here (`./build-windows.ps1`,
released as `ezvpn-windows.dll.zip`), which the .NET app P/Invokes.
Unlike the Apple extension (which is handed a `utun` fd), the Windows FFI
wraps the desktop `VpnClient`, which creates the wintun adapter and routes
itself, so it runs elevated and needs `wintun.dll` alongside `ezvpn.dll`.

See [`docs/Windows-App.md`](docs/Windows-App.md) for scope, how it reuses the
core, the C interface, and build steps.

## Architecture

Detailed internals, flow diagrams, client isolation rules, and reconnect
consistency checks live in [`docs/Architecture.md`](docs/Architecture.md).
