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
- Public-key (ed25519) client authentication over iroh's cryptographic
  endpoint identity, in the shared
  [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) format
  (`flexaccess-keys generate-auth-key`); the server keeps the public keys in an
  ssh-`authorized_keys`-style file
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
managed outside the VPN connector. The mobile apps are the deliberate
exception: iOS applies split DNS in-app (`NEDNSSettings`) because that is the
only way to accomplish it there, and Android forwards DNS in-tunnel because the
platform has no per-domain DNS for VPNs at all.

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

### 1. Generate Server Identity and Client Keys

The server identity key is an `ezvpn` command:

```bash
ezvpn generate-server-key --output ./vpn-server.key
```

Client authentication keypairs are managed by the standalone
[`flexaccess-keys`](https://github.com/flexaccessdev/flexaccess-keys) CLI;
install it once (`curl -sSL https://flexaccessdev.github.io/flexaccess-keys/install.sh | bash`,
Windows: `irm https://flexaccessdev.github.io/flexaccess-keys/install.ps1 | iex`),
then, **on each client**:

```bash
flexaccess-keys generate-auth-key "alice laptop" -o client.key
flexaccess-keys show-auth-key --private-key-file client.key
```

The first command writes the client's secret key file; the second prints its
public authorized-key entry (`ed25519-pub:… alice laptop`), which the client
hands to the server operator. Secret keys never leave the client.

`generate-server-key` and `show-server-id` accept `--json` for machine-readable
output.

The client keypair identifies authorized clients. The tunnel also negotiates a
fixed ALPN over iroh's QUIC handshake, so a peer that does not speak the ezvpn
protocol is rejected before any stream is opened.

### 2. Create Server Config

Collect the clients' public entries into an `authorized_keys` file, ssh
`authorized_keys` style — one `ed25519-pub:…` per line, optional trailing
comment; `#` lines and blank lines ignored:

```text
# ./authorized_keys
ed25519-pub:AAAA...  alice laptop
ed25519-pub:BBBB...  build server
```

Create `vpn_server.toml`, or copy from `vpn_server.toml.example`:

```toml
role = "vpnserver"

[network]
network = "10.0.0.0/24"

[auth]
authorized_keys_file = "./authorized_keys"

[iroh]
secret_file = "./vpn-server.key"
```

Config notes:

- `[network]` defines VPN addressing. At least one of `network` (IPv4) or
  `network6` (IPv6) is required.
- `[auth]` points at the file of authorized client public keys (required).
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
  --auth-key-file ./client.key
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
(Tailscale's fixed value, the IPv6 minimum link MTU) and the transport uses
Cubic congestion control with fixed windows. Nothing is negotiated; both sides derive the
same values from constants. The one exception is congestion control, which
CLI-only testing flags can change on the local sender (see
[Throughput Notes](#throughput-notes)).

Clients configure their server identity, auth keypair, routes, relay and
discovery settings, and reconnect behavior. Client CLI arguments take
precedence over client config file values.

## CLI Reference

### Server

`ezvpn server start` requires a config:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Server config path |
| `--default-config` | Use `vpn_server.toml` in the system config dir (`/etc/ezvpn` on Linux, `/usr/local/etc/ezvpn` on macOS, `%ProgramData%\ezvpn` on Windows) |
| `--congestion-control <NAME>` | QUIC congestion controller: `cubic` (default), `bbr3`, or `new-reno`. Testing knob; CLI-only |
| `--congestion-initial-window <BYTES>` | Initial congestion window, 2660–8388608; default is the controller's own (12000). Testing knob; CLI-only |

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
| `--auth-key <SECRET>` | Inline client secret key (`ed25519-sec:…`). Prefer the key file — an inline secret is visible in the process list |
| `--auth-key-file <PATH>` | Client key file from `flexaccess-keys generate-auth-key` |
| `--route <CIDR>` | Additional IPv4 route through the VPN; repeatable |
| `--route6 <CIDR>` | Additional IPv6 route through the VPN; repeatable |
| `--relay-url <URL>` | Custom relay URL; repeatable |
| `--exclude-direct-path <CIDR>` | Keep the tunnel off direct paths to server addresses in this network whenever another path (another direct one or the relay) is available, e.g. another VPN's range; repeatable; replaces `[iroh].exclude_direct_paths` (see [Excluding Direct Paths](#excluding-direct-paths)) |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Exit on the first failed connection attempt or drop instead of retrying |
| `--max-reconnect-attempts <N>` | Cap consecutive retries before giving up (unlimited if unset) |
| `--instance <NAME>` | Instance name for lock and status socket scope; default `default` |
| `--daemon` | Fork into the background on Unix; logs to `<log_dir>/ezvpn-client-<instance>.log` |
| `--congestion-control <NAME>` | QUIC congestion controller: `cubic` (default), `bbr3`, or `new-reno`. Testing knob; CLI-only |
| `--congestion-initial-window <BYTES>` | Initial congestion window, 2660–8388608; default is the controller's own (12000). Testing knob; CLI-only |

With `--daemon`, the client validates its config and paths before forking, so
startup errors are still reported in the foreground. Stop a daemonized Unix
client with:

```bash
sudo ezvpn client stop --instance work
```

`client stop` also accepts `--json`, reporting one of `not_running`, `stopped`,
or `signal_sent` (signaled, but still shutting down after 5 s).

`ezvpn client status` prints connection state, assigned VPN IP/gateway, MTU,
negotiated GSO, live iroh path (direct or relay), configured custom relay URLs
with live health when available, and the daemon log path when
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
  --auth-key-file ./client.key \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

Full tunnel example:

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-key-file ./client.key \
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
[docs/Client-Split-DNS.md](docs/Client-Split-DNS.md). The exceptions are the
mobile apps: iOS applies DNS conditional forwarding through `NEDNSSettings`
(see [docs/Apple-App.md](docs/Apple-App.md)), and Android — which has no
split-DNS API for VPNs — runs an in-tunnel forwarder in the Rust core (see
[docs/Android-App.md](docs/Android-App.md)).

## Protocol, MTU, and GSO

- Wire protocol v7 is required on both peers. Mixed-version pairs do not
  connect.
- Each raw IP packet is one unreliable, unordered QUIC DATAGRAM protected by
  QUIC/TLS 1.3. The handshake stream stays open only for reliable server-address
  control publications (`[len: u32 BE][0x01][json]`).
- The initial QUIC UDP payload MTU is 1330: the fixed 1280-byte inner MTU plus
  noq's conservative 50-byte QUIC DATAGRAM overhead bound. A full inner packet
  therefore fits immediately without assuming a 1500-byte underlay. DPLPMTUD
  remains enabled with a 1200-byte minimum and probes toward the real PMTU.
- The inner TUN MTU is fixed at 1280 on both ends (the IPv6 minimum link MTU
  and the same fixed value Tailscale uses, mobile-safe on essentially any real
  path). It is a protocol constant, not a config knob, and is not carried in
  the handshake.
- GSO super-frames are segmented into plain per-MSS datagrams before transport
  and consecutive received TCP packets are re-coalesced into kernel-TSO
  super-frames where supported; otherwise packets are written individually.
  GSO is purely local and is not negotiated. A packet larger than the live QUIC
  datagram limit is dropped rather than fragmented.

Linux GSO is automatic:

- TUN offload is attempted at startup with `vnet_hdr` and TCP GSO flags.
- No GSO config toggle is exposed.
- If Linux offload setup fails, VPN traffic continues in non-GSO mode and logs
  a warning.
- Connection setup logs report the local GSO status only (GSO is never
  negotiated with the peer).

## Throughput Notes

There are no transport tuning knobs (WireGuard/Tailscale style). QUIC transport
settings are fixed constants on both ends: Cubic congestion control and 8 MB
receive/send windows, which cover most links. Cubic outran paced BBRv3 on every
path measured through the tunnel (LAN, and emulated 40 ms paths with and without
a bottleneck); BBRv3 only kept a shorter queue at a deep-buffered bottleneck, and
only in the server-to-client direction.

The single exception is for measurement. `server start` and `client start` both
accept:

| Flag | Effect |
|------|--------|
| `--congestion-control <cubic\|bbr3\|new-reno>` | Selects the congestion controller. `cubic` is the default and what production runs |
| `--congestion-initial-window <BYTES>` | Sets that controller's initial congestion window. Accepts 2660 (two initial-MTU packets) to 8388608 (the flow-control window); the default is the controller's own value, 12000 |

These are CLI flags only — never config-file settings — so alternatives can be
compared on a real path without rebuilding. They apply to the whole process,
including reconnects. Congestion control governs only the local sender and is
not negotiated, so the two ends may run different settings (useful for isolating
which direction a throughput change comes from):

```bash
sudo ezvpn client start -c client.toml --congestion-control bbr3 --congestion-initial-window 30000
```

The chosen settings are logged at startup whenever they differ from the defaults.

The datagram sender uses a small bounded queue and waits for QUIC's pacer during
congestion. This prevents the non-blocking iroh API from silently replacing old
inner packets with new ones. iroh still uses UDP GSO/GRO or batched socket I/O
where the platform supports it.

No Linux `net.core.rmem_max` or `net.core.wmem_max` tuning is required. iroh
asks for 7 MiB UDP socket buffers, which Linux would otherwise cap at those
sysctls (about 208 KiB by default), overflowing the receive queue under load.
Because the VPN runs as root, ezvpn's transport stack sets the buffers with
`SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`, which are not subject to the cap.

## Reconnect Behavior

Client auto-reconnect is enabled by default. Disable it with
`auto_reconnect = false` in config or `--no-auto-reconnect` on the CLI (the
client then exits on the first failed attempt or drop). Cap consecutive retries
with `max_reconnect_attempts` or `--max-reconnect-attempts`.

- A failed connection attempt — the **first one included** — or a lost
  connection is retried with exponential backoff (1 second doubling to 60
  seconds, plus 0-500 ms of jitter), indefinitely unless capped. A server that
  is down, or not up yet, is the ordinary case, not a reason to exit: the
  client waits it out and connects when the server appears.
- A long outage is cheap to sit through: once the backoff reaches its cap the
  client makes one bounded connect attempt a minute, so the server's return
  is noticed within a minute.
- A permanent error (a rejected key, a malformed config, a TUN device that
  cannot be created) never retries; that is the only kind of error the client
  exits on.
- `ezvpn client status` shows the outage's progress while down: failed
  attempts so far, the last error, and when the next attempt is due.

Liveness is detected by QUIC:

- QUIC keep-alive runs every 15 seconds.
- QUIC idle timeout is 30 seconds.
- The client tears down and reconnects when the connection closes, peer liveness
  fails, or TUN/stream I/O fails.

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

A **server** with custom relays watches its own home-relay registration: if it
has no connected home relay for 60s and iroh has not re-homed it on its own,
it takes the wedged relay out of its relay map and homes on another configured
relay in place — same node id, same sockets, nothing torn down — so clients off
the LAN (the mobile apps) are not stranded with connect timeouts until someone
restarts the service. The relay is put back once it is connectable again. See
[`docs/Architecture.md`](docs/Architecture.md#relay-failover-server-custom-relays).

## Relay and Address Lookup

The relay and address-lookup design is shared with
[tunnel-rs](https://github.com/andrewtheguy/tunnel-rs) and
[flextunnel](https://github.com/flexaccessdev/flextunnel), and is documented once
in
**[iroh-common-architecture](https://github.com/flexaccessdev/iroh-common-architecture)** —
see [relays and address lookup](https://github.com/flexaccessdev/iroh-common-architecture/blob/main/relays-and-address-lookup.md)
for the design and [self-hosting](https://github.com/flexaccessdev/iroh-common-architecture/blob/main/self-hosting.md)
for running your own relay.

The short version as it applies to `ezvpn`:

- `relay_urls` / `--relay-url` select custom relay servers. That single choice
  also decides whether [iroh address
  lookup](https://docs.iroh.computer/concepts/address-lookup) (n0 pkarr publish +
  DNS via `dns.iroh.link`) runs: **on** with the default relays, **off** with
  custom relays. It is not separately configurable.
- With custom relays, the client reaches the server through the relay URLs it
  attaches to the connection as dial hints. These are **required** for
  connectivity in that mode — with lookup off there is no published record to
  fall back on — so configure both sides with the full relay list.
- A custom relay set is **at least two distinct relays**: the server rides out
  a relay outage by moving onto another configured relay, so one relay is
  rejected at startup.
- Every configured custom relay is probed individually at startup. Startup
  fails only when **none** comes online; a relay that does not is named in a
  warning and left out of the relay map, so a relay that answers probes but
  refuses connections cannot keep the process from ever coming online. The
  server's failover puts it back once it is connectable; a client keeps it out
  for its session. `relay_auth_token` (custom relays only) is validated by the
  same probe.

iroh address lookup is endpoint-ID resolution, not real/VPN DNS: it does not
affect client DNS resolution, and the client does not push DNS or match domains
over the tunnel. To resolve an internal zone through a resolver reachable over
the tunnel, set OS-level conditional forwarding — see
[docs/Client-Split-DNS.md](docs/Client-Split-DNS.md).

See the relay comments in `vpn_server.toml.example` and
`vpn_client.toml.example` for exact TOML syntax.

### Excluding Direct Paths

The server advertises every local address it has as a direct-path candidate,
including the address of another VPN it runs. When the client is on that VPN
too, the overlay path is usually the fastest, and ezvpn ends up carried inside
the other VPN (e.g. over Tailscale's `100.x` addresses). That is sometimes the
point — reaching a private network through another private network — so it is
not blocked by default: an overlay cannot be told apart from a LAN by address.
To keep the tunnel off it, list the overlay's networks on the client:

```toml
[iroh]
exclude_direct_paths = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]  # Tailscale
```

or pass `--exclude-direct-path` (repeatable). Path selection skips direct
paths to those server addresses and moves the tunnel off one it is on, to
another direct path or else the relay. This is a selection preference, not a
block: if no allowed path is available at all (not even the relay), the
current path is kept rather than dropping the connection, even an excluded
one, and a connection that was dialed over an excluded address uses it until
the first path selection. iroh still sends its small path probes to the
excluded addresses.

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

## Android App

[`ezvpn-android`](https://github.com/flexaccessdev/ezvpn-android) is a native
Kotlin/Compose client for Android that connects to an `ezvpn` server built from
this repo (dual-stack split tunnel, optional tunnel DNS including split-DNS
match domains via an in-tunnel forwarder, always-on support; no full tunnel or
Play Store distribution). The tunnel runs in a `VpnService` that is handed the
OS tun fd, like the Apple extension. The Rust core builds into one
`libezvpn.so` per ABI here (`./build-android.sh`, released as
`libezvpn-android.zip`), which the app loads through a small JNI surface.

See [`docs/Android-App.md`](docs/Android-App.md) for scope, how it reuses the
core, the JNI interface, the split-DNS forwarder, and build steps.

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

## Related Projects

- [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) — the
  shared FlexAccess authentication key format and its `generate-auth-key` /
  `show-auth-key` CLI, where all `ezvpn` client key generation happens. `ezvpn`
  links against the library only to parse, sign, and verify; that repo is
  authoritative for the token format and file parsing rules.
