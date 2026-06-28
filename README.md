# ezvpn

**Cross-platform IP-over-QUIC VPN with NAT traversal via iroh.**

`ezvpn` creates a TUN interface and routes IP packets through encrypted iroh
QUIC connections. Clients dial the server by its stable iroh `EndpointId`, so
they do not need the server's current IP address and the server does not need
open inbound ports. Relay fallback is used when a direct path is unavailable.

> [!IMPORTANT]
> `ezvpn` is a server-centered access tunnel. It is not a site-to-site network
> joiner, and it intentionally does not provide client-to-client connectivity.
> The server drops client-to-client packets in userspace before they reach the
> TUN device.

> [!WARNING]
> While `ezvpn` remains in the `0.0.x` series, there is no backward
> compatibility between versions. Regenerate server keys and refresh configs on
> every upgrade. The current advertised ALPN is `ezvpn/4/<token>`; wire protocol
> v3 is separate from that ALPN version, and older peers are rejected during
> QUIC negotiation.

> [!NOTE]
> Running `ezvpn` requires root/Administrator privileges to create TUN devices
> and routes.

## Features

- Full subnet routing, not just single-port forwarding
- End-to-end encryption via QUIC/TLS 1.3 through iroh
- NAT traversal with relay fallback
- Token-based authentication plus a required ALPN "knock" token
- Optional dual-stack VPN operation with IPv4, IPv6, or both
- Optional split tunneling through repeatable `--route` and `--route6`
- Auto-reconnect using QUIC keep-alive and idle-timeout health checks
- Automatic Linux TUN GSO offload with software segmentation fallback for
  peers that do not support GSO, such as mixed-OS peers

## When To Use It

Use `ezvpn` when you need:

- Access to an entire remote subnet
- Stable full-network routing between peers behind NAT
- Cross-platform VPN connectivity on Linux, macOS, and Windows
- A WireGuard/OpenVPN alternative over iroh transport

Do not use it for site-to-site routing between two LANs or for direct
client-to-client traffic. The only in-VPN peer a client can reach is the server
VPN gateway.

## Installation

You only need the `ezvpn` binary in your `PATH`.

### Linux and macOS

```bash
curl -sSL https://andrewtheguy.github.io/ezvpn/install.sh | sudo bash
```

### Windows

```powershell
irm https://andrewtheguy.github.io/ezvpn/install.ps1 | iex
```

Windows also requires `wintun.dll` from the official WireGuard project:
<https://www.wintun.net/>.

1. Download and extract the WinTun zip.
2. Copy `wintun/bin/amd64/wintun.dll` to either the same directory as
   `ezvpn.exe` (default: `%LOCALAPPDATA%\Programs\ezvpn\`) or a directory in
   your system `PATH`.
3. Run `ezvpn.exe` as Administrator.

If you see `Failed to create TUN device: LoadLibraryExW failed`, the DLL is
missing or is not in a valid search path.

<details>
<summary>Advanced installation options</summary>

Install a specific release tag:

```bash
curl -sSL https://andrewtheguy.github.io/ezvpn/install.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/ezvpn/install.ps1))) <RELEASE_TAG>
```

Install the latest prerelease:

```bash
curl -sSL https://andrewtheguy.github.io/ezvpn/install.sh | sudo bash -s -- --prerelease
```

```powershell
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/ezvpn/install.ps1))) -PreRelease
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

ALPN_TOKEN=$(ezvpn generate-alpn-token)
echo "$ALPN_TOKEN"
```

Token formats:

- Auth token: exactly 47 characters, `v` followed by 46 Base64URL characters
  with no padding.
- ALPN token: exactly 14 Base64URL characters with no prefix and no padding.

The auth token identifies authorized clients. The ALPN token is a shared
pre-handshake secret embedded in the iroh ALPN value; it must match on the
server and every client.

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
alpn_token = "<YOUR_ALPN_TOKEN>"
```

Config notes:

- `[network]` defines VPN addressing. At least one of `network` (IPv4) or
  `network6` (IPv6) is required.
- `[auth]` defines accepted client auth tokens.
- `[iroh]` defines server identity, ALPN token, relay/discovery settings, and
  optional QUIC transport tuning.
- Top-level keys control server runtime behavior such as buffering,
  backpressure, and spoofing checks.
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
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN"
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
- The server dictates the VPN `mtu`.
- The server dictates QUIC transport tuning from `[iroh.transport]`, including
  congestion controller and receive/send windows.

Clients configure their server identity, auth token, ALPN token, routes, relay
and discovery settings, and reconnect behavior. Client CLI arguments take
precedence over client config file values.

## CLI Reference

### Server

`ezvpn server start` requires a config:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Server config path |
| `--default-config` | Use `~/.config/ezvpn/vpn_server.toml` |

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
| `--default-config` | Use `~/.config/ezvpn/vpn_client.toml` |
| `-n, --server-node-id <ID>` | VPN server `EndpointId` |
| `--auth-token <TOKEN>` | Authentication token |
| `--auth-token-file <PATH>` | Read auth token from file |
| `--alpn-token <TOKEN>` | ALPN token; must match the server |
| `--alpn-token-file <PATH>` | Read ALPN token from file |
| `--route <CIDR>` | Additional IPv4 route through the VPN; repeatable |
| `--route6 <CIDR>` | Additional IPv6 route through the VPN; repeatable |
| `--relay-url <URL>` | Custom relay URL; repeatable |
| `--dns-server <URL\|none>` | Custom iroh discovery server, or disable DNS discovery |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |
| `--instance <NAME>` | Instance name for lock and status socket scope; default `default` |
| `--daemon` | Fork into the background on Unix; logs to `<runtime_dir>/ezvpn-client-<instance>.log` |

With `--daemon`, the client validates its config and paths before forking, so
startup errors are still reported in the foreground. Stop a daemonized client
with:

```bash
ezvpn client stop --instance work
```

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

Each running instance exposes a local control socket next to its lock file:

- Unix: Unix domain socket
- Windows: named pipe

The runtime directory is machine-global: `/run/ezvpn` on Linux,
`/var/run/ezvpn` on macOS, and `%ProgramData%\ezvpn` on Windows. Override it
with `EZVPN_RUNTIME_DIR`.

Run `status`, `list`, and `stop` as root/Administrator so they resolve the same
runtime directory as the tunnel process. `client list` discovers instances by
lock file and probes each control socket; stopped clients may briefly show as
`not responding (stale lock)` until the lock file is reused or removed.

## Routing

The VPN subnet itself is always routed by default. Add extra routes with
repeatable `--route` and `--route6`.

Split tunnel example:

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

Full tunnel example:

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN" \
  --route 0.0.0.0/0 \
  --route6 ::/0
```

## Protocol, MTU, and GSO

- Wire protocol v3 is required on both peers. Mixed-version pairs do not
  connect.
- The data path sends raw IP packets over unreliable QUIC datagrams protected
  by QUIC/TLS 1.3.
- Each datagram carries one message:
  `[type][offload_len][offload?][ip_packet]`. Datagram boundaries provide the
  length, so there is no length prefix.
- The initial QUIC path MTU is 1452, the IPv6-safe value for a standard
  1500-byte Ethernet path. That yields `max_datagram_size` of about 1416, so
  the effective inner TUN MTU is clamped to about 1400.
- A jumbo VPN MTU has no effect when packets exceed the QUIC datagram cap. GSO
  super-frames are segmented to the datagram cap on send and re-coalesced into
  kernel-TSO super-frames on receive where supported.
- The ~1400 effective MTU assumes a path MTU of at least 1500, such as LAN or
  most broadband paths. On smaller or tunnel-in-tunnel paths, lower the server
  `mtu` setting. Keep the effective MTU at least 1280 for IPv6.

Linux GSO is automatic:

- TUN offload is attempted at startup with `vnet_hdr` and TCP GSO flags.
- No GSO config toggle is exposed.
- If Linux offload setup fails, VPN traffic continues in non-GSO mode and logs
  a warning.
- Connection setup logs include local, remote, and negotiated GSO status.

## Throughput Tuning

For maximum throughput on direct P2P paths, configure `[iroh.transport]` in the
server config. The server sends these resolved values to clients during the
handshake, so clients do not need transport configuration.

- `congestion_controller = "bbr"`: TCP inside the tunnel already reacts to its
  own congestion signals. When the underlying UDP path also drops packets,
  loss-based `cubic` can compound the backoff. BBR models the path and often
  sustains higher throughput on lossy or high-latency direct paths.
- `receive_window` / `send_window`: the 8 MB defaults cover most links. On
  high-bandwidth, high-latency paths with a large bandwidth-delay product, raise
  them toward the 16 MB maximum so `window / RTT` does not cap throughput.

`cubic` remains the default because it is the safer choice for relay paths and
general internet use.

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
  fails, or TUN/datagram I/O fails.
- Reconnect backoff starts at 1 second, doubles up to 60 seconds, and adds
  0-500 ms of jitter.

On reconnect, the client compares the server's network parameters against the
first successful handshake:

- A change only to the assigned client IP (`assigned_ip` or `assigned_ip6`) is
  accepted. The client logs a warning, adopts the new IP as the baseline, and
  rebuilds the TUN device and routes.
- A change to any other network field (`network`, gateway, IPv6 network/gateway
  fields, or `mtu`) is fatal. The client exits instead of reconfiguring into an
  inconsistent routing state.

The client uses a stable per-process `device_id`, so the server normally assigns
the same IP during reconnects. Reassignment is expected mainly after server
restart or allocation state changes.

## Relay and Discovery

`ezvpn` can use custom iroh relay and discovery infrastructure:

- `relay_urls` / `--relay-url` configure custom relay servers for failover and
  connection hints.
- `dns_server` / `--dns-server` configure the iroh discovery server. This is
  not VPN DNS and does not affect client DNS resolution.
- Server and client relay/discovery settings must match.
- If `dns_server = "none"` disables DNS discovery, clients and server must
  connect through a common relay or same-LAN mDNS discovery.

See the relay and discovery comments in `vpn_server.toml.example` and
`vpn_client.toml.example` for exact TOML syntax.

## Running as a Service

For unattended clients under systemd, launchd, or a Windows service, see
[`docs/RUNNING-AS-A-SERVICE.md`](docs/RUNNING-AS-A-SERVICE.md).

That guide also covers pinning the runtime directory so `status`, `list`, and
`stop` resolve the same location used by the service.

## Architecture

Detailed internals, flow diagrams, client isolation rules, and reconnect
consistency checks live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
