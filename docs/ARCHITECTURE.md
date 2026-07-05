# ezvpn Architecture

`ezvpn` provides full-network tunneling using direct IP-over-QUIC. It creates a TUN device and routes IP traffic directly through encrypted iroh QUIC connections, eliminating double-encryption overhead while preserving TLS 1.3 security.

The primary deployment model is remote access to private resources without
opening inbound ports on the VPN server. In practice that usually means running
an `ezvpn` server inside a private network, such as an AWS VPC, so a home or
remote client can reach private AWS resources or hosts in private/egress-only
subnets. Split routing to explicit private prefixes is the main design target.
Full-tunnel default routing is supported, but remains more experimental because
it interacts with broad host routes and the underlay bypass routes needed for
iroh server and relay addresses.

Anonymity is not a design goal. iroh's relay/discovery infrastructure can
observe connection metadata when it is used for signaling or for carrying
encrypted traffic. The tunneled payload is still end-to-end encrypted by
QUIC/TLS 1.3, so relay operators cannot decrypt the VPN data.

## VPN Mode

> **Note:** VPN mode requires root/admin privileges. On Windows, you also need `wintun.dll` from https://www.wintun.net/ (official WireGuard project) — download the zip, extract, and copy `wintun/bin/amd64/wintun.dll` to the same directory as the executable (or any directory in the system PATH).

### Architecture Overview

```mermaid
graph TB
    subgraph "Client Side"
        A[Applications]
        B[TUN Device<br/>tun0: 10.0.0.2<br/>fd00::2]
        D[iroh Endpoint]
    end

    subgraph "Transport"
        E[iroh Connection<br/>NAT Traversal + Relay]
    end

    subgraph "Server Side"
        F[iroh Endpoint]
        H[TUN Device<br/>tun0: 10.0.0.1<br/>fd00::1]
        I[Target Network<br/>LAN / Internet]
    end

    A -->|IP packets| B
    B -->|read & frame| D
    D <-->|iroh QUIC| E
    E <-->|iroh QUIC| F
    F -->|write & unframe| H
    H -->|forward| I

    style B fill:#FFE0B2
    style H fill:#FFE0B2
    style E fill:#BBDEFB
```

**IPv6 Dual-Stack Support:**

VPN mode supports optional IPv6 alongside IPv4. When `network6` is configured on the server, clients receive both an IPv4 address and an IPv6 address. This enables:
- Native IPv6 connectivity through the VPN tunnel
- Dual-stack applications (IPv4 and IPv6 simultaneously)
- IPv4-only operation when `network6` is not configured

IPv4 is optional: the server can run IPv6-only with `network6` and no `network`.

**Note:** VPN mode is not intended for stable client-to-client communications. Client IPs are dynamically assigned and may change between sessions.

### Key Components

```mermaid
graph LR
    subgraph "ezvpn crate"
        A[VpnServer / VpnClient]
        C[TUN Device<br/>tun crate]
        D[IP Pool<br/>address management]
        E[Signaling<br/>handshake & framing]
        F[VpnLock<br/>single instance]
    end

    A --> C
    A --> D
    A --> E
    A --> F

    style C fill:#FFE0B2
    style E fill:#BBDEFB
```

### Connection Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant CI as Client iroh
    participant SI as Server iroh
    participant S as Server

    Note over S: Server startup
    S->>S: Create TUN device (tun0)
    S->>S: Assign gateway IP(s) (10.0.0.1, fd00::1 in sequential IPv6 mode)

    Note over C: User runs ezvpn client
    C->>C: Acquire VPN lock
    C->>C: Generate session device_id
    C->>CI: Create iroh endpoint

    CI->>SI: Connect via iroh (NAT traversal)
    SI-->>CI: Connection established

    Note over C,S: VPN Handshake Phase
    C->>S: VpnHandshake {device_id, auth_token}
    S->>S: Validate auth token
    S->>S: Allocate IP(s) from pool(s)
    S-->>C: VpnHandshakeResponse {assigned_ip, network, server_ip, transport, mtu, ...}
    S->>S: Store client (EndpointId, device_id)

    Note over C,S: Transport Upgrade (only if server dictates non-default tuning)
    C->>C: Compare dictated transport vs baseline
    C->>CI: Close + reconnect with per-connection transport config
    C->>S: VpnHandshake (re-handshake, same device_id → same IPs)
    S-->>C: VpnHandshakeResponse

    Note over C,S: TUN Device Setup
    C->>C: Create TUN device (tun0, server-dictated MTU)
    C->>C: Assign IP(s) (10.0.0.2, fd00::2)
    C->>C: Configure routes

    Note over C,S: Direct IP Tunnel Active
    loop Packet Flow
        C->>C: Application sends packet
        C->>C: TUN captures packet
        C->>S: Send over QUIC (encrypted)
        S->>S: Unframe IP packet
        S->>S: TUN injects packet
        S->>S: Forward to destination
    end
```

**`VpnHandshakeResponse` Fields:**

The response includes different address fields depending on the server's address configuration:

| Mode | Fields in Response |
|------|-------------------|
| IPv4-only | `assigned_ip`, `network`, `server_ip` |
| IPv6-only | `assigned_ip6`, `network6`, `server_ip6` |
| Dual-stack | All six fields when both pools allocate: `assigned_ip`, `network`, `server_ip`, `assigned_ip6`, `network6`, `server_ip6` |

When `network6` is configured on the server, clients normally receive IPv6 addresses alongside IPv4 (dual-stack) or IPv6-only if `network` is omitted. In dual-stack mode, if one address pool is exhausted, the server can still accept the client with the other address family.

Every accepted response additionally carries the server-dictated settings (see "Server-Dictated Configuration" below): `transport` (`WireTransport`: congestion controller and concrete receive/send windows) and `mtu`.

### Server-Dictated Configuration

The server is the single source of truth for QUIC transport tuning (`[iroh.transport]`: congestion controller, receive/send windows) and the VPN `mtu`. Clients do not configure these; the server sends the fully resolved values in the handshake response and the client applies them:

- **MTU**: the server clamps its shared TUN MTU to `min(config.mtu, 1400)` (`DATAGRAM_SAFE_MTU`) and clamps each client's advertised `mtu` again to that connection's `max_datagram_size - DATAGRAM_FRAMING_OVERHEAD`. `QUIC_INITIAL_MTU` is 1452 (the IPv6-safe maximum for a standard 1500-byte Ethernet path), giving a handshake-time `max_datagram_size` of about 1416 and a datagram-safe inner MTU of about 1400. This assumes a >=1500-MTU path (LAN / most broadband). The client creates its TUN device after the handshake using the already-clamped `mtu`, and that TUN MTU cannot follow later QUIC path-MTU discovery because the TUN device MTU is fixed for the connection's life. On a constrained or tunnel-in-tunnel path, QUIC black-hole detection lowers the live path MTU but the TUN MTU stays high, so full-size packets may be dropped (`SendDatagramError::TooLarge`); the workaround is to lower the server `mtu` config so the advertised value starts small enough for that path. Keep the effective MTU >= 1280 for IPv6.
- **Transport tuning**: the congestion controller (and send window) cannot be changed on a live QUIC connection, so the client always connects with the default baseline (cubic, 8 MB windows). If the dictated `transport` differs from that baseline, the client closes the connection and reconnects once with a per-connection transport config (`Endpoint::connect_with_opts`), then re-handshakes. The same `device_id` is reused, so the server's idempotent IP allocation returns the same addresses. When the server runs default tuning, no extra reconnect occurs.

The shared builder (`build_quic_transport_config` in `src/transport/mod.rs`) is used for both endpoint creation and the per-connection upgrade, so both paths apply identical keep-alive, idle-timeout, congestion-controller and window settings. The wire values are resolved via `TransportTuning::effective_windows()` on the server, guaranteeing they match what the server's own endpoint uses.

### Direct IP over QUIC Integration

The VPN mode sends raw IP packets directly over iroh's unreliable QUIC datagrams (TLS 1.3). The reliable handshake runs once on a QUIC bi-stream; all IP traffic then rides datagrams, which avoids the head-of-line blocking of a reliable stream (a lost packet does not stall later ones — the inner transport retransmits as it would over plain UDP). This removes the double encryption overhead of running WireGuard inside QUIC.

**Key Design Decisions:**
- **Framing**: each datagram carries one message — `[type][offload_len][offload?][ip_packet]` — with no length prefix (the datagram boundary is the length). IP packets may be tagged with segmentation-offload metadata (see "Segmentation Offload" below). Datagrams are capped at the connection's `max_datagram_size`, so GSO super-frames are segmented to that cap on send.
- **Security**: Relies on iroh/QUIC's built-in encryption (TLS 1.3).
- **Efficiency**: Zero-copy forwarding where possible between TUN and QUIC buffers; TCP segments travel as coalesced super-packets when offload is available on either side.
- **Identification**: Clients identify via a random `u64` `device_id` generated at startup, allowing multiple sessions per iroh endpoint.
- **Reconnects**: The server automatically manages session limits and cleanup, allowing seamless reconnects from the same device ID.

**Device ID Generation:**

The `device_id` is generated at startup with `rand::rng().random::<u64>()`. It is a random session identifier, not an authentication secret; security relies on the server's iroh endpoint identity and the configured auth token.

**Security Considerations:**

The `device_id` is used **purely for session tracking** within an already-authenticated iroh connection—it is NOT used for access control. Security relies on:
1. iroh's cryptographic server `EndpointId` authentication and QUIC/TLS encryption
2. Auth token validation

Clients are keyed by `(EndpointId, device_id)`, so an attacker cannot hijack a session by guessing a `device_id` without also possessing the victim's iroh private key and a valid auth token.

**Collision Handling:**

The 64-bit ID space provides a ~2^32 birthday bound for collisions, which is sufficient for session tracking across reasonable client counts (thousands of concurrent sessions). Unpredictability is not a security requirement since `device_id` only differentiates sessions from the same authenticated endpoint. Random generation avoids predictable collision patterns and makes accidental collisions unlikely in practice.

### Segmentation Offload (GSO/GRO)

Per-packet cost dominates tunnel throughput: every ~MTU-sized TCP segment otherwise pays its own framing, channel send and QUIC write. `ezvpn` moves whole TCP "super-packets" (up to 64 KB) through the tunnel whenever possible and segments them as late as possible — ideally in the receiving kernel.

**Offload metadata:** IP frames may carry a 10-byte `virtio_net_hdr` (the Linux TUN `IFF_VNET_HDR` format, parsed/serialized in `src/tunnel/offload.rs`) describing TCP GSO state: segment size (MSS), header length and partial-checksum position. The v2 IP frame embeds it via the `offload_len` byte.

**Capability negotiation:**
- The client always advertises GSO support in its `VpnHandshake` (it can software-segment anything it receives).
- The server reports its TUN offload capability as `server_gso_enabled` in the handshake response, and sets `connection_gso_active = server TUN offload enabled && client advertised GSO` per client.

**Data paths** (each side picks per packet, based on what its local TUN supports):

| Path | Local TUN has offload | Behavior |
|------|----------------------|----------|
| Egress, kernel GRO | yes (Linux) | Kernel hands coalesced super-frames + `virtio_net_hdr` to the TUN reader; forwarded with metadata when the peer accepts GSO, otherwise software-segmented (`materialize_offload_into`) before framing |
| Egress, software GRO | no (macOS/Windows, or Linux without vnet headers) | `TcpGroTable` (in `offload.rs`) coalesces consecutive in-order same-flow TCP segments into a super-frame with a synthetic `virtio_net_hdr`, then flushes when the TUN read side drains |
| Ingress, kernel TSO | yes (Linux) | Offload-tagged frames are written to the TUN with their metadata; the kernel segments and completes checksums |
| Ingress, software segmentation | no | `materialize_offload_into` splits the super-frame into plain per-MSS packets with recomputed checksums before the TUN write |

**Software GRO details** (`TcpGroTable`, mirrors wireguard-go's `tun/tcp_offload_linux.go` semantics):
- Coalesces only clean in-order TCP: same flow key, contiguous sequence numbers, uniform MSS, byte-identical headers (TCP timestamps may advance; the latest is carried). SYN/RST/URG/CWR, pure ACKs, fragments and non-TCP packets pass through immediately — flushing any pending same-flow group first so in-flow ordering is preserved.
- FIN/PSH are only valid on a group's final segment and finalize it.
- Bounded: ≤16 in-flight flows, ≤64 segments and ≤65535 bytes per group.
- The coalesced TCP checksum field holds the folded (not complemented) pseudo-header sum per the Linux `CHECKSUM_PARTIAL` convention, so the receiving kernel/NIC completes it per segment under TSO.
- On the server's TUN→client direction, GRO state is additionally keyed per destination client and evicted when the client disconnects.

The outbound loops drain packets already queued on the TUN and flush pending software-GRO groups as soon as the read side drains; on a GSO-capable Linux TUN the software-GRO path is bypassed entirely (the kernel already coalesces).

### Throughput Design

- **Dedicated writer tasks**: the server runs a per-client writer task that owns a `Connection` clone and sends datagrams; the client sends datagrams inline from the TUN reader (a datagram send takes `&Connection`, so no writer task is needed). The TUN writer is also a dedicated task fed over an mpsc channel (no per-packet mutex).
- **Batched receives**: the TUN writer and per-client writer drain up to `WRITE_BATCH_SIZE` (256) items per `recv_many` to amortize task wakeups; each datagram is then sent with one `send_datagram_wait`.
- **Framing arena**: datagrams are appended to a long-lived 64 KB `BytesMut` (`build_datagrams` / `encode_ip_datagram`) and split off as refcounted `Bytes` views, so the allocator is hit once per arena chunk instead of once per packet.
- **Zero-copy sends**: `Bytes` flow from framing through the channel to the QUIC write without copying.
- **macOS utun fast path**: Darwin TUN splitting duplicates the `utun` fd and drives it with `AsyncFd` directly. Reads fill the packet arena with the 4-byte address-family prefix still attached, then strip that prefix by slicing; writes use `writev([prefix, packet])` so the IP packet does not need to be copied into a temporary header-prepended buffer.

### IP Pool Management

```mermaid
graph TB
    subgraph "IPv4 Pool (Server)"
        A[Network: 10.0.0.0/24]
        B[Server IP: 10.0.0.1]
        C[Available: 10.0.0.2 - 10.0.0.254]
        D[Allocated Set<br/>tracks in-use IPs]
    end

    subgraph "IPv6 Pool (Optional)"
        A6[Network: fd00::/64]
        B6[Server IP: fd00::1]
        C6[Available: fd00::2 onwards]
        D6[Allocated Set<br/>one IPv6 per client]
    end

    subgraph "Allocation"
        E[Client connects]
        F[Find first available IPv4]
        F6[Find first available IPv6]
        G[Mark as allocated]
        H[Return to client]
    end

    subgraph "Release"
        I[Client disconnects]
        J[Return IPs to pools]
    end

    E --> F
    E -.->|if IPv6 enabled| F6
    F --> C
    F6 --> C6
    F --> G
    F6 --> G
    G --> D
    G -.-> D6
    G --> H

    I --> J
    J --> D
    J -.-> D6

    style B fill:#FFE0B2
    style B6 fill:#FFE0B2
    style D fill:#BBDEFB
    style D6 fill:#BBDEFB
```

When both `network` and `network6` are configured, each client normally receives both an IPv4 and IPv6 address. If one family is exhausted in dual-stack mode, the server can still allocate the other family; if all configured pools are exhausted, the connection is rejected. If `network` is omitted, the IPv4 pool is not created and the server runs IPv6-only. The default IPv6 strategy allocates sequential /128 client addresses with release/reuse behavior similar to IPv4; `ip6_strategy = "node-id"` instead derives stable client IPv6 addresses from client iroh node IDs, derives the server IPv6 address from the server `EndpointId`, and rejects duplicate derived addresses. With a /64, sequential IPv6 pool exhaustion is not a practical concern for normal deployments.

### Platform-Specific Details

| Platform | TUN Device | Route Configuration | Privileges |
|----------|------------|---------------------|------------|
| Linux | `/dev/net/tun` | `ip route add` | CAP_NET_ADMIN or root |
| macOS | `utunX` | `route add` | root |
| Windows | `wintun.dll` | `netsh interface route` (VPN routes); `NetTCPIP` PowerShell cmdlets `Find-NetRoute`/`New-NetRoute` (underlay bypass host routes) | Administrator |

### Underlay Bypass Routes

iroh's QUIC transport may reach the server (or a relay) over a public address
that happens to fall inside one of the client's routed VPN prefixes — most
commonly the server's public IPv6 when a broad IPv6 CIDR is routed. Without
intervention the VPN route would capture the transport's own underlay packets
and feed them back into the tunnel, deadlocking the connection. To prevent this,
`ezvpn` installs a host-specific (`/32`/`/128`) **bypass route** for each such
peer address, pinned to the underlay default gateway captured before the VPN
routes were installed (`BypassRouteManager` in `tunnel/client.rs`).

The trigger is purely topological: *any* underlay address the transport may use
that overlaps a routed prefix needs the bypass, independent of how that address
is reachable. An ingress+egress server address and an egress-only one (reached
via stateful NAT/hole-punching) both form direct paths that self-capture without
the bypass — reachability only governs whether a direct path forms at all, not
whether a candidate address needs pinning.

**Two address sources, no path-snapshot watch.** The client learns the addresses
to bypass from exactly two sources:

1. **Eager relay bootstrap (one-time, client-side).** Before the VPN routes are
   installed, the client resolves its full relay set (configured relay URLs, or
   the default relay map) for both families and pins each address a VPN route
   would capture. This guarantees the relay fallback path survives route
   installation, with no startup race to wait on (`add_iroh_bypass_routes`).
2. **Server-published candidate addresses (server-driven).** The server's own
   candidate underlay addresses (`endpoint.addr().ip_addrs()`) reach the client
   in the handshake response (seeded into the manager at onboarding, before VPN
   routes go in) and then ongoing over the data path — every
   `SERVER_ADDR_PUBLISH_INTERVAL` (30s) for loss tolerance, and promptly whenever
   `Endpoint::watch_addr()` reports a change. The client merges each set into the
   manager. These addresses are authoritative: they need no DNS and no
   path-selection race, so they pre-empt the self-capture of a server address
   iroh has discovered but not yet selected for the active path. See "Server
   Address Publication" below.

The client deliberately does **not** watch iroh's per-connection path snapshots
to discover addresses. That watch was unreliable — it blocked on inline relay
DNS and only ever saw the latest coalesced snapshot, so a server address that
appeared transiently was missed — and is fully superseded by the server's
authoritative publication. See "Server Address Publication" below.

**The bypass manager is add-only.** A bypass route, once installed, is kept until
the connection closes (each route guard's `Drop` removes it). A published set
that omits an address never removes its route: the published set can fluctuate as
the server's discovered addresses change, and removing on first absence would
cause add/remove churn, self-capturing the address into the tunnel in between —
the exact failure the bypass exists to prevent. A bypass route only pins one
peer's underlay address (the server's transport address) off the tunnel, so
keeping a no-longer-listed one for the session is harmless.

**Application is best-effort and per-address, not a transaction.**
`BypassRouteManager::update` adds each required address independently: a
committed bypass is kept, and a failure to add one address is logged and skipped
rather than aborting the rest. The required set is the full resolved relay map
(both address families) plus the server's published candidate addresses, so a
single address that transiently cannot be pinned — e.g. a relay whose per-IP
route is briefly a gateway-less cloned entry during startup — must not block
pinning the endpoint iroh actually selected. In a full tunnel an aborted batch
would leave the live transport captured into the tunnel and stall the connection.

**Gateway resolution falls back to the captured default gateway.** A bypass must
be pinned to a real next-hop gateway; a gateway-less (link-scope) host route
would black-hole the address. When the freshly queried per-IP route either
resolves through the VPN tunnel itself (a direct path discovered *after* the VPN
routes went up) or resolves via a physical interface but yields no next-hop
gateway (a transient cloned-route state), `ezvpn` re-pins via the underlay
default gateway captured while the routing table was still pristine
(`resolve_bypass_route_info` in `net/device.rs`). Only if no usable captured
gateway exists is the bypass refused.

Both the best-effort application and the gateway fallback live in the
cross-platform layer (`update` and `resolve_bypass_route_info`); the
per-platform code (`add_bypass_route_impl`) only issues the single host-route
add, so the behavior is identical on Linux, macOS, and Windows.

Only addresses iroh *may use* for transport are ever bypassed: the manager's
required set is the resolved relay set plus the server's published candidate
underlay addresses — never arbitrary destinations. That candidate set is the
server's full address enumeration (both families, **public and private** — a peer
on the same private network reaches the server over its private address), so it
legitimately includes private/LAN addresses; which one a given client actually
uses depends on where it connects from. The server **excludes its own VPN overlay
addresses** (its tun-subnet gateway, e.g. `10.99.0.1` / `fd11:…::1`) from the set:
those are overlay, never underlay transport, so pinning them off the tunnel would
be wrong (`server_candidate_addrs` in `tunnel/server.rs`). A bypass pins **only those transport
endpoints, not the rest of the routed prefix**: other hosts inside the same CIDR
still route through the VPN normally. In a full tunnel (`0.0.0.0/0`/`::/0`) the
server and relay addresses are always covered and thus always pinned; in a split
tunnel only an endpoint that overlaps a routed CIDR is — typically zero bypass
routes, or just the server's own host address per overlapping prefix. The
membership test is a pure per-IP prefix check (`ip_covered_by_vpn_routes` in
`tunnel/client.rs`), so the common split-tunnel triggers are: the client sits
inside the same private network as the server (the routed private prefix
contains the server's LAN address, which is precisely the address iroh selects
for transport there), or a routed IPv6 CIDR is broad enough to contain the
server's public IPv6.

**Caveat (user-visible).** As a consequence, the one address used for tunnel
transport is reachable only over the underlay, not through the VPN, while the
client is connected. If that same host also exposes resources meant to be reached
*through* the tunnel, those must be addressed by their **VPN-internal IP** (the
in-subnet server/peer address, e.g. `10.x` / `fd11:…`) — not by the public
address that doubles as the tunnel underlay endpoint.

The most confusing instance is the **VPN server itself**: because the pinned
address is the server's *own* transport endpoint, an identical-looking public
address (e.g. an egress-only IPv6) is reachable through the tunnel on *any other*
host but **not** on the VPN server, where it is pinned to the underlay. This
asymmetry reads as a bug but is expected — the server's address doubles as the
tunnel underlay endpoint, so reach the server by its VPN-internal subnet IP
instead. This is documented for end users in the README "Routing" section.

### Server Address Publication

The server is the authoritative source of its own underlay addresses, so it
publishes them to each connected client instead of having the client guess from
iroh path snapshots. The candidate IP set comes from `endpoint.addr()`, minus the
server's own VPN overlay addresses (iroh enumerates every local interface,
including the server's tun, so its overlay gateway is filtered out — see
`server_candidate_addrs`). It reaches the client two ways:

- **At onboarding, in the handshake response** (`VpnHandshakeResponse.server_addrs`,
  reliable bi-stream). The client seeds these into its bypass manager during
  setup — alongside the eager relay bootstrap, before VPN routes are installed —
  so a direct server address that a VPN route would capture is pinned
  immediately, with no wait for the first periodic publication.
- **Ongoing, over the data path** (`ServerAddrsMsg`, datagram type `0x01`). A
  per-connection task (`run_server_addr_publisher`) sends it once immediately on
  connect, then every `SERVER_ADDR_PUBLISH_INTERVAL` (30s) as a loss-tolerance
  floor, and promptly on any `Endpoint::watch_addr()` change. It rides the same
  unreliable datagram path as IP traffic and self-terminates when the connection
  closes.

The client feeds every received set (handshake or datagram) into its bypass
manager (add-only, filtered to VPN-covered IPs); a dropped publication is
recovered by the next tick, and addresses discovered after onboarding arrive via
the datagram path.

The feature is wire-compatible and needs no protocol-version bump: the message
is a new datagram *type*, and a peer that does not understand `0x01` simply drops
it (the client ignores it when it installs no capturing routes; an old server
never sends it). A client talking to an old server therefore falls back to the
eager relay bootstrap alone — it will not learn the server's *direct* underlay
address, so a direct path that overlaps a routed prefix would self-capture; run a
server built with this feature to bypass direct server addresses in a full tunnel.

### Security Model

The security model is private-resource access, not anonymity. Server identity,
auth tokens, and QUIC/TLS encryption protect the tunnel from unauthorized peers
and keep VPN payloads confidential from iroh relays.
Relays and discovery services may still see metadata such as participating
endpoints, timing, volume, and relay use when they are involved.

```mermaid
graph TB
    subgraph "Authentication"
        A[Auth Token<br/>ezvpn token format]
        B[Validate before IP assignment]
    end

    subgraph "Encryption"
        C[Iroh QUIC<br/>TLS 1.3]
        E[Forward Secrecy]
    end

    subgraph "Isolation"
        F[Single Instance Lock<br/>prevents conflicts]
        G[Session Keys<br/>per-connection]
    end

    A --> B
    C --> E

    style E fill:#C8E6C9
    style F fill:#FFF9C4
```

#### Local Control Endpoint

Each running instance serves a local status endpoint (Unix domain socket in the
runtime directory; Windows named pipe). The protocol is **request-free and
read-only**: on connect, the listener writes one JSON status snapshot and
closes — a connection cannot send anything the daemon acts on.

Because of that, the endpoint is deliberately **world-connectable** so
`status`/`list` work without sudo:

- Unix: the runtime directory is `0755` (world-traversable, root-writable only)
  and the socket is `0666` (`connect(2)` needs write permission on the socket
  inode).
- Windows: the pipe is created outbound-only (`PIPE_ACCESS_OUTBOUND`) and the
  querier opens it read-only, which the default pipe DACL grants to Everyone.

Mutation is out-of-band: `client stop` reads the PID from the lock file and
sends SIGTERM, which still requires root (signaling a root-owned process). The
accepted trade-off is that any local user can read VPN status metadata
(endpoint IDs, assigned IPs, connection state) — comparable to what `ifconfig`
and the routing table already reveal locally.

#### ALPN and Protocol Versioning

There are two independent version numbers, checked at two different layers:

- **ALPN/format version** — the advertised ALPN is the fixed value `ezvpn/4`, where `4` is the ALPN/format version. A peer whose ALPN does not match exactly (e.g. a different version segment, or an older token-bearing `ezvpn/4/<token>`) is rejected during QUIC ALPN negotiation, before any application streams are opened. It carries no embedded secret; access control rests on the server's iroh endpoint identity and the auth token.
- **Wire protocol version** — `VPN_PROTOCOL_VERSION` (currently `3`) is carried inside the application handshake and is independent of the ALPN version. A peer that negotiates a matching ALPN but sends a mismatched wire protocol version is rejected during the handshake exchange, not during QUIC negotiation.

### Client Isolation

Inter-client traffic is dropped unconditionally on the server, in userspace, with no config flag and no firewall / `ip_forward` dependency.

The primary reason it is mandatory: client IPs are dynamic and constantly change — dynamically assigning non-overlapping client IPs is a core feature of this VPN — so only the server's VPN IP is stable. Any allow/deny policy keyed on client IPs would be unmanageable, so the safe default is to forbid all client-to-client traffic outright.

In `handle_client_data` (`src/tunnel/server.rs`), after the anti-spoofing source check, the inbound packet's destination IP is looked up in `ip_to_endpoint` / `ip6_to_endpoint`. A hit means the destination is another VPN client (or self), so the packet is dropped (counted by `packets_inter_client_blocked`) instead of being written to the TUN for the kernel to forward back out. Only client-assigned IPs live in those maps, so the server/gateway VPN IP and all external/internet destinations are unaffected — the gateway is the only in-VPN peer a client can reach. The drop is on the inbound side, so client→client packets never reach the TUN and the TUN reader never sees them.

**Pinging your own assigned IP** behaves differently per platform, and this is
expected/accepted (not fixed):

- **Linux** answers a self-ping locally — assigning `10.x.y.z/24` to the TUN
  installs a `local`-table route so traffic to the host's own VPN address loops
  back in-kernel and never enters the tunnel. So it works.
- **macOS** makes the TUN a point-to-point `utun`
  (`inet <self> --> <gateway> netmask 0xffffff00`). A self-ping matches the
  on-link `/24` route and is sent out the tunnel to the server, where the client
  isolation check above drops it (the destination is a client-assigned IP — this
  client's own). So it does not work.

This is standard macOS VPN behavior, not something we do differently: `utun`
interfaces are inherently point-to-point, and every macOS VPN (WireGuard,
OpenVPN, etc.) sets the tunnel up this way. The self-ping difference is a
consequence of following that platform convention, so there is nothing on our
side to fix — and pinging your own VPN IP has no real use case anyway (under
normal routing that traffic goes to the server regardless). Adding a client-side
loopback route to mask it would be the non-standard move, so we don't.

### Auto-Reconnect and Connection Health

VPN mode includes automatic reconnection when the tunnel connection fails. This handles scenarios like server restarts or network partitions.

**Configuration:**
- `auto_reconnect = true` (default): Automatically reconnect on connection loss
- `auto_reconnect = false`: Exit on first disconnection
- `max_reconnect_attempts`: Limit total attempts (unlimited if not set)

**Health Monitoring:**

The data path is unreliable datagrams with no application-level heartbeat. Peer
liveness is detected entirely by QUIC:

- **QUIC keep-alive** (15s interval) keeps NAT mappings warm and exercises the path.
- **QUIC idle timeout** (30s) closes a connection whose peer has gone silent.
- The client awaits `Connection::closed()`; when it resolves (idle timeout, peer
  close, or path failure) the tunnel tears down and (if enabled) reconnects.
- TUN read/write errors and datagram read/send errors also end the tunnel.

These keep-alive / idle-timeout values live in `src/transport/mod.rs`
(`QUIC_KEEP_ALIVE_INTERVAL`, `QUIC_IDLE_TIMEOUT`).

**Datagram framing:**

Each datagram carries one message, prefixed with a 1-byte `DataMessageType`
(`src/tunnel/signaling.rs`). The datagram boundary is the message length, so
there is no length prefix:

```
  IP packet (type 0x00):
    [0x00] [1 byte: offload_len (0 or 10)]
           [offload_len bytes: virtio_net_hdr] [N bytes: raw IP packet]
```

GSO capability is negotiated in the reliable handshake (the client advertises
`gso_enabled` in `VpnHandshake`), so there is no separate capabilities message.

**Implementation locations** (search by symbol name; line numbers may shift):
- Type enum: `DataMessageType` in `signaling.rs`
- Datagram framing: `encode_ip_datagram()` / `build_datagrams()` / `classify()` in `datagram.rs`; body parsing `parse_ip_packet_v2()` in `signaling.rs`
- Client send (outbound): TUN reader task in `client.rs` - frames via `build_datagrams()` and `Connection::send_datagram_wait()`
- Client receive (inbound): inbound task in `client.rs` - `Connection::read_datagram()` then `classify()`
- Client liveness: task awaiting `Connection::closed()` in `client.rs`
- Server send: TUN reader task in `server.rs` - frames via `build_datagrams()`, sent by the per-client writer task
- Server receive: `handle_client_data()` in `server.rs` - `Connection::read_datagram()` then `classify()`

**Compatibility note:** Peers must speak the same framing version; there is no backward compatibility at 0.0.x.

**Connection Check:**

```mermaid
sequenceDiagram
    participant Q as QUIC Connection
    participant VPN as VPN Loop
    participant RC as Reconnect Logic

    loop Every 15s
        Q->>Q: Keep-alive ping
    end

    Note over Q: Peer silent past idle timeout (30s)
    Q-->>VPN: Connection::closed() resolves
    VPN-->>RC: VpnError::ConnectionLost

    alt auto_reconnect = true
        RC->>RC: Calculate backoff delay
        RC->>RC: Wait (1s, 2s, 4s... up to 60s)
        RC->>VPN: Reconnect
    else auto_reconnect = false
        RC->>RC: Exit with error
    end
```

**Reconnection Backoff:**
- Base delay: 1 second
- Exponential growth: 1s → 2s → 4s → 8s → 16s → 32s → 60s
- Maximum delay: 60 seconds
- Jitter: 0-500ms added to prevent thundering herd
- Counter reset: Resets to 0 after successful tunnel operation

### Client Network Consistency Check (Reconnect)

On reconnect the client compares the server's network params (`assigned_ip`, `network`, `gateway`, the IPv6 trio, and `mtu`) against the params established on the first successful handshake. A change to *just* the assigned client IP (`assigned_ip` / `assigned_ip6`) is not fatal: the client logs a warning, adopts the new IP as the baseline, and rebuilds the TUN device and routes for the new address (every `connect()` builds these fresh anyway). This is what a server restart that reassigns a different IP looks like. A change to any other field (`network`, `gateway`, the IPv6 trio, or `mtu`) is a fatal `VpnError::ServerConfigChanged` that quits the program instead of reconfiguring into inconsistent routing / TUN state. The stable per-process `device_id` (generated once in `VpnClient::new`) means the server normally re-assigns the same IP, so reassignment is the exception, not the norm. See `check_params_against` / `NetworkParams::non_ip_fields_eq` in `src/tunnel/client.rs`.

---
