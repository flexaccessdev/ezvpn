# ezvpn

**Cross-platform IP-over-QUIC VPN with NAT traversal via iroh.**

`ezvpn` provides full-network tunneling over encrypted QUIC. It creates a TUN interface and routes IP packets directly through an iroh connection, so peers can connect without open inbound ports or public IPs.

> [!IMPORTANT]
> **Project Goal:** `ezvpn` is built for easy setup as a server-centered access tunnel. It is not meant to join two networks together like WireGuard site-to-site, and it does not provide client-to-client connectivity.

> [!WARNING]
> **No Backward Compatibility in 0.0.x:** While `ezvpn` remains in the `0.0.x` series, there is no backward compatibility between any versions. Regenerate server keys and refresh configs on every upgrade.
> The current ALPN prefix/version is `ezvpn/4` (the wire protocol is v3 — the two version numbers are independent); the actual advertised ALPN is `ezvpn/4/<token>`, and older peers are rejected at QUIC negotiation.

> [!NOTE]
> Running `ezvpn` requires root/Administrator privileges to create TUN devices and routes.

## Features

- Full subnet routing (not just single-port forwarding)
- End-to-end encryption via QUIC/TLS 1.3 (iroh transport)
- NAT traversal with relay fallback
- Token-based authentication
- Optional dual-stack VPN (IPv4 + IPv6)
- Optional split tunneling (`--route` / `--route6`)
- Auto-reconnect with QUIC keep-alive / idle-timeout health checks
- Automatic Linux TUN GSO offload with software segmentation fallback when a peer does not support GSO (e.g., mixed-OS peers)

## Protocol and Linux GSO

- Wire protocol v3 is required on both peers. Mixed-version pairs will not connect.
- On Linux, TUN offload is attempted automatically at startup (`vnet_hdr` + TCP GSO flags).
- No GSO config toggle is exposed in config files.
- If Linux offload setup fails, VPN traffic continues in non-GSO mode and logs a warning.
- Connection setup logs include local, remote, and negotiated GSO status.

## Throughput Tuning

For maximum throughput on direct P2P paths, configure the QUIC transport in the
`[iroh.transport]` section of the **server** config (see `vpn_server.toml.example`).
The server dictates these settings to clients during the handshake, so clients
need no transport configuration:

- `congestion_controller = "bbr"` — TCP carried through the tunnel reacts to its own
  congestion signals; when the underlying UDP path also drops packets, the default
  loss-based `cubic` compounds the backoff. BBR models the path instead of reacting to
  loss and typically sustains higher throughput on lossy or high-latency direct paths.
- `receive_window` / `send_window` — the 8 MB defaults cover most links. On
  high-bandwidth, high-latency paths (large bandwidth-delay product), raise them toward
  the 16 MB maximum so the window does not cap throughput at `window / RTT`.

`cubic` remains the default because it is the safer choice for relay paths and
general internet use.

### Kernel UDP Socket Buffers (Linux)

Both peers run iroh, whose socket layer requests a **7 MiB** UDP `SO_RCVBUF`/`SO_SNDBUF`
so the kernel can absorb bursty multi-Gbit traffic instead of silently dropping datagrams
(dropped datagrams show up as inner-TCP retransmits in `iperf3`). **Linux caps that request
at `net.core.rmem_max` / `net.core.wmem_max`** (default ≈ 208 KiB), and the clamp is silent.
The **receive buffer is the one that matters** — a too-small `SO_RCVBUF` is what shows up as
drops. Raise the sysctls so the full buffer is honored:

```bash
sudo sysctl -w net.core.rmem_max=7340032
sudo sysctl -w net.core.wmem_max=7340032
```

To persist across reboots, add them to `/etc/sysctl.d/99-ezvpn.conf`. `ezvpn` logs a
startup warning (with the exact command above) when either sysctl is below 7 MiB. This is
Linux-only; macOS uses a different knob (`kern.ipc.maxsockbuf`).

## When To Use It

Use `ezvpn` when you need:

- Access to an entire remote subnet
- Stable full-network routing between peers behind NAT
- Cross-platform VPN connectivity (Linux/macOS/Windows)
- A WireGuard/OpenVPN alternative over iroh transport

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

### Windows: WinTun Required

Running `ezvpn.exe` requires `wintun.dll` from <https://www.wintun.net/> (official WireGuard project site):

1. Download and extract the WinTun zip
2. Copy `wintun/bin/amd64/wintun.dll` to either:
   - The same directory as `ezvpn.exe` (default: `%LOCALAPPDATA%\\Programs\\ezvpn\\`)
   - Any directory in your system `PATH`
3. Run `ezvpn.exe` as Administrator

If you see `Failed to create TUN device: LoadLibraryExW failed`, the DLL is missing or not in a valid search path.

<details>
<summary>Advanced installation options</summary>

Install a specific release tag:

```bash
curl -sSL https://andrewtheguy.github.io/ezvpn/install.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/ezvpn/install.ps1))) <RELEASE_TAG>
```

Install latest prerelease:

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

### 1. Generate Server Identity and Auth Token

```bash
ezvpn generate-server-key --output ./vpn-server.key
AUTH_TOKEN=$(ezvpn generate-auth-token)
echo "$AUTH_TOKEN"

# ALPN token: a shared pre-handshake secret that must match on the server and
# every client.
ALPN_TOKEN=$(ezvpn generate-alpn-token)
echo "$ALPN_TOKEN"
```

Token format:
- Exactly 47 characters
- Prefix `v`
- Followed by 46 Base64URL (no padding) characters

### 2. Create Server Config

Create `vpn_server.toml` (or copy from `vpn_server.toml.example`):

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

Notes:
- Config is grouped by purpose: `[network]` (VPN addressing), `[auth]` (client
  tokens), top-level keys (server runtime), and `[iroh]` (iroh transport:
  identity, ALPN, relays, discovery, QUIC tuning).
- At least one of `network` (IPv4) or `network6` (IPv6) is required.
- `secret_file` is required for a stable server `EndpointId`.
- IPv6-only mode is supported but still experimental.

### 3. Start Server

```bash
sudo ezvpn server start -c vpn_server.toml
```

### 4. Connect Client

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN"
```

### 5. Verify Connectivity

```bash
# Linux
ip addr show

# macOS
ifconfig

# Ping server VPN IP (example)
ping 10.0.0.1
```

## CLI Reference

### Server

`ezvpn server start` requires config:

- `-c, --config <FILE>`
- `--default-config` (uses `~/.config/ezvpn/vpn_server.toml`)

`ezvpn server status` prints the status of the running server (uptime, mode,
connected clients with their assigned IPs and iroh path, packet counters). Add
`--json` for machine-readable output.

### Client

`ezvpn client start` accepts:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Client config path |
| `--default-config` | Use `~/.config/ezvpn/vpn_client.toml` |
| `-n, --server-node-id <ID>` | VPN server EndpointId |
| `--auth-token <TOKEN>` | Authentication token |
| `--auth-token-file <PATH>` | Read token from file |
| `--alpn-token <TOKEN>` | ALPN token (shared pre-handshake secret; must match the server) |
| `--alpn-token-file <PATH>` | Read ALPN token from file |
| `--route <CIDR>` | Additional IPv4 routes through VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 routes through VPN (repeatable) |
| `--relay-url <URL>` | Custom relay URL(s) |
| `--dns-server <URL|none>` | Custom iroh discovery server, or disable DNS discovery |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |
| `--instance <NAME>` | Instance name; scopes the lock and status socket so multiple clients can run at once (default: `default`) |
| `--daemon` | Fork into the background (Unix only); logs to `<runtime_dir>/ezvpn-client-<instance>.log` |

With `--daemon` the client forks into the background after its config/path
validation completes (so errors are still reported in the foreground) and
detaches from the terminal. Stop it with:

```bash
ezvpn client stop --instance work   # SIGTERM; graceful shutdown
```

`ezvpn client status` prints the status of the running client (connection
state, assigned VPN IP/gateway, MTU, negotiated GSO, the live iroh path —
direct or relay — and, when started with `--daemon`, the log-file path). Add
`--json` for machine-readable output, or `--instance <NAME>` to query a specific
instance.

Use `vpn_server.toml.example` and `vpn_client.toml.example` for full tunables. MTU and transport tuning are server-side settings dictated to clients during the handshake.

The IP data path rides **unreliable QUIC datagrams**, so each tunneled packet must fit in a single QUIC datagram (`max_datagram_size`). The initial QUIC path MTU is 1452 (the IPv6-safe maximum for a 1500-byte Ethernet path), which yields a `max_datagram_size` of ~1416, so the effective inner MTU is clamped to a datagram-safe **~1400** (the per-client advertised MTU is further clamped to that connection's datagram size). Sizing the inner MTU near the path MTU keeps packets full and avoids wasted GSO segment padding. A jumbo MTU has no effect because a packet that exceeds the datagram size cannot be sent. GSO super-frames are segmented to the datagram cap on send and re-coalesced into kernel-TSO super-frames on receive, so Linux offload still applies.

This assumes a standard **≥1500-MTU path** (LAN / most broadband). On a smaller or tunnel-in-tunnel path, QUIC discovery lowers the live path MTU but the inner TUN MTU is fixed for the connection, so lower `mtu` in the server config for those deployments. See `vpn_server.toml.example` for details.

## Split Tunneling

Route additional networks through VPN with repeatable `--route` and `--route6`:

```bash
sudo ezvpn client start \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

For full tunnel:

```bash
sudo ezvpn client start \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --alpn-token "$ALPN_TOKEN" \
  --route 0.0.0.0/0 \
  --route6 ::/0
```

## Self-Hosted Iroh Infrastructure

`ezvpn` supports self-hosted relay and discovery services. See:

- [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md)
- [`docs/iroh-relay-connection-trace.md`](docs/iroh-relay-connection-trace.md)

## Architecture

Detailed internals and flow diagrams:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Single Instance Lock

Only one `ezvpn server` runs at a time per machine, and only one
`ezvpn client` *per instance name*. Each holds its own lock to avoid route and
TUN conflicts, and a client and a server can run on the same host simultaneously.

Clients are scoped by `--instance <NAME>` (default `default`), so several can run
at once — each gets its own lock file and status socket. Names may contain ASCII
letters, digits, and underscores. The instance name is a CLI flag only (not a
config option). Query a specific one with `ezvpn client status --instance <NAME>`.

```bash
sudo ezvpn client start -c work.toml --instance work
sudo ezvpn client start -c home.toml              # instance "default"
ezvpn client status --instance work
```

## Status

Each running instance exposes a local control socket (a Unix domain socket on
Unix, a named pipe on Windows) next to its lock file. Query it with:

```bash
ezvpn server status                          # or: --json
ezvpn client status --instance work          # or: --json (default instance if omitted)
```

To enumerate instances on this host, use `list` (add `--json` for machine output):

```bash
ezvpn client list
# ezvpn client instances:
#   work     connected     10.0.0.2
#   default  disconnected  -
```

`list` discovers instances by their lock files in the runtime directory and then
probes each one's control socket. Because lock files are intentionally left
behind on exit, an instance that has stopped may briefly appear as
`not responding (stale lock)` until its lock file is reused or removed. An
instance that is present but whose probe fails (timeout, malformed reply, etc.)
is shown as `error: <reason>` instead, so it isn't mistaken for a stale lock.

No config is required to query status or list. The control socket and lock files
live in a fixed, machine-global runtime directory (`/run/ezvpn` on Linux,
`/var/run/ezvpn` on macOS, `%ProgramData%\ezvpn` on Windows; override with
`EZVPN_RUNTIME_DIR`). Run `status`/`list`/`stop` as **root** (`sudo`) — the
same privilege the tunnel itself requires — and they resolve the same place
regardless of how the server/client was started.

## Running as a Service

To run the client unattended (start at boot, restart on crash) under systemd
(Linux), launchd (macOS), or a Windows service, see:

- [`docs/RUNNING-AS-A-SERVICE.md`](docs/RUNNING-AS-A-SERVICE.md)

It also explains pinning the runtime directory so `status`/`list` resolve the
same place the service uses.
