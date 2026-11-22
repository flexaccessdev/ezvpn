# Benchmarks

Throughput measurements kept for reference: what was measured, on what, and
what each change was worth. The reasoning behind the changes is in
[Architecture](Architecture.md), "Throughput Design".

> **These numbers are not evidence that ezvpn or Tailscale is the faster VPN.**
> They come from one pair of virtual machines on one host, over a virtual
> network with no real distance, loss or NAT, with one TCP flow per test, and
> with each product at whatever version and defaults it had that day. The two
> also do different jobs on the way (ezvpn carries IP in QUIC datagrams over
> iroh; Tailscale runs WireGuard with its own userspace stack), and a change
> of kernel, NIC, CPU, or a single offload flag reorders the table, as the
> results below show. Tailscale is here as a familiar yardstick on the same
> machines, to tell whether a number is in a sensible range, and for nothing
> else. Measure on your own hardware and path before drawing conclusions.

## Setup (2026-11-22)

| | |
|---|---|
| Machines | `test1` (server, `10.22.40.61`) and `test2` (client, `10.22.40.62`): two KVM guests on the same physical host, joined by a virtual bridge |
| Host CPU | Intel Core i5-8400T (6 cores, no SMT); each guest has 6 vCPUs, so the two guests together overcommit the host 2:1 |
| Guest | Debian 13, kernel 6.12.117, 2 GB RAM |
| NIC | `virtio_net`, 6 queues (multi-queue), XPS at its default of one transmit queue per CPU, `tx-udp-segmentation` off by default |
| ezvpn | v0.0.67 and the build that follows it (connected per-peer sockets on Linux, two runtime workers); direct IPv4 path, Cubic, inner MTU 1280 |
| Tailscale | 1.104.7, direct path, `tailscale0` MTU 1280 |
| Tool | iperf3 3.18, one TCP flow, 6 s per run after a 1 s warm-up, median of 5 runs; "up" is client to server, "down" is server to client (`-R`) |

Both tunnels ran on the same pair, one test at a time. Run-to-run spread was
usually within ±5%; anything else running on the physical host moves every
row (an unrelated busy VM halved all of them for a few minutes), so the rows
of one table were always taken back to back.

## Results

Mbit/s, median of 5 runs. "Retr" is the inner TCP sender's retransmits per run.

### Default NIC settings

| | Down | Up | Retr (down / up) |
|---|---:|---:|---:|
| No tunnel (TCP with TSO over the bridge) | 21208 | 20476 | 306 / 27 |
| Tailscale 1.104.7 | 1749 | 1249 | 2201 / 1112 |
| ezvpn v0.0.67 | 1037 | 1024 | 930 / 1077 |
| ezvpn, peer sockets + two workers | 1931 | 1940 | 0 / 1 |

Tailscale's two directions were not stable from one session to the next here:
an earlier pass on the same day gave 1289 down and 1827 up.

### With `ethtool -K eth0 tx-udp-segmentation on` on both guests

| | Down | Up | Retr (down / up) |
|---|---:|---:|---:|
| No tunnel | 21261 | 20686 | 48 / 424 |
| Tailscale 1.104.7 | 3030 | 3112 | 1806 / 2494 |
| ezvpn v0.0.67 | 1215 | 1243 | 1177 / 1477 |
| ezvpn, peer sockets + two workers | 2207 | 2278 | 0 / 0 |

`virtio_net` supports UDP segmentation offload but leaves it off by default.
With it on, a UDP GSO batch crosses to the host as one buffer instead of
being segmented in the guest. It is a setting of the underlay NIC, outside
either VPN's control.

### macOS and Windows clients against the Linux server

The same day, one client at a time against the ezvpn server on `test1`
(the build with peer sockets and two workers), both ends at default NIC
settings. Unlike the Linux pair these cross a real network, and the "no
tunnel" row is what that path carries for one TCP flow, so read each tunnel
number against its own baseline. The client ran the same commit, built for
its platform.

| Client | | Down | Up |
|---|---|---:|---:|
| macOS 26.7 VM (Apple M2 Max host, 8 vCPUs, arm64), behind its host's NAT | No tunnel | 1946 | 2353 |
| | ezvpn | 1796 | 425 |
| | Tailscale 1.104.2 | 430 | 216 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2097 | 2359 |
| | ezvpn | 1473 | 1452 |

Mbit/s, median of 5 runs of 6 s, iperf3 run on the client (3.22.1 on
Windows); every tunnel run used a direct path. Retransmits were 0–2 per run
on macOS; the Windows iperf3 build does not report them. The macOS no-tunnel
figures were identical on every run, which suggests a cap in the VM's NAT
path. macOS upload is the outlier: the utun read path hands over one packet
per read with no offload (see [Architecture](Architecture.md), "macOS utun
reader"). Tailscale on the same VM, run just before a repeat ezvpn pass that
gave 1779 down and 407 up, is slower in both directions, so the VM's utun
path limits either tunnel here; its direct path was the same LAN address,
and it retransmitted 58–91 segments per run.

## What the measurements showed

### A multi-queue NIC reorders a tunnel's packets

With XPS, the kernel picks the transmit queue of a datagram sent on an
unconnected UDP socket from the CPU the sending thread is on. A tunnel's
sender moves between threads, so consecutive batches leave on different
queues and overtake each other; virtio also steers the reverse direction to
whichever queue last transmitted. The inner TCP flow reads the reordering as
loss. The NIC and tunnel show no drops; the inner TCP counters do:

| ezvpn v0.0.67, 6 s download | Mbit/s | Retransmits | `TCPSACKReorder` | `TCPOFOQueue` |
|---|---:|---:|---:|---:|
| Default (XPS on, 6 runtime workers) | 1030 | ~900 | ~12000 | ~14000 |
| Process pinned to one CPU | 1679 | 99 | 0 | 124 |
| XPS disabled on both guests | 1657 | 0 | 0 | 0 |
| Peer sockets (XPS on, not pinned) | 1619 | 0 | 5 | 8 |

Tailscale is affected the same way: disabling XPS took it from about
1290/1830 to 2173/2200 in that session. ezvpn now avoids it without touching
the NIC, by sending to a busy peer on a connected socket, whose transmit
queue the kernel keeps fixed.

### More runtime threads were slower

One tunnel, `tx-udp-segmentation` on, by Tokio worker threads on both ends:

| Workers | Down | Up |
|---:|---:|---:|
| 1 | 2419 | 2338 |
| 2 | 2303 | 2273 |
| 3 | 2030 | 2095 |
| 6 (previous default: one per core) | 1680 | 1655 |

Three clients downloading or uploading at once through one server (clients
on one worker each), aggregate Mbit/s over three runs:

| Server workers | Down | Up |
|---:|---:|---:|
| 1 | 1832–1945 | 3035–3374 |
| 2 | 2803–3058 | 3150–3317 |
| 3 | 3170–3358 | 2339–2621 |
| 4 | 2257–3087 | 2495–2716 |
| 6 | 2665–2824 | 2786–3117 |

The CLI now runs two workers. These guests overcommit their host, which
makes cross-thread wakeups dearer than on bare metal, so the penalty for
extra workers is probably larger here than on a dedicated machine;
`TOKIO_WORKER_THREADS` overrides the count to check.

### A false MTU black hole stalled long transfers

Not a throughput number, but found by these runs: before v0.0.67 a sustained
download at about 1 Gbit/s dropped to zero after 45–95 s and stayed there for
about a minute. QUIC's black hole detector misread congestion loss, reset the
path MTU to 1200, and every full-size inner packet was then too large to
send. Fixed in v0.0.67; a 180 s run now holds its rate. Short runs never
showed it, which is why the tables above use 6 s runs for both versions.

## Reproducing

Start a server on one machine and a client on the other, with `iperf3 -s` on
the server, then from the client:

```bash
iperf3 -t 6 -O 1 -c <server VPN address>        # up
iperf3 -t 6 -O 1 -c <server VPN address> -R     # down
```

The three-client rows need three tunnels and three listeners, because one
`iperf3 -s` serves one test at a time. On the server, run a listener per
port (`iperf3 -s -D -p 5201`, `-p 5202`, `-p 5203`). On the client machine,
start three clients with the same server and key, the second and third as
`--instance b` and `--instance c`; each gets its own address and TUN device
(`tun0`, `tun1`, `tun2` here). All three have a route to the server's VPN
address, so bind each test to its device and start them together:

```bash
iperf3 -t 6 -O 1 --bind-dev tun0 -p 5201 -c <server VPN address> -R &
iperf3 -t 6 -O 1 --bind-dev tun1 -p 5202 -c <server VPN address> -R &
iperf3 -t 6 -O 1 --bind-dev tun2 -p 5203 -c <server VPN address> -R &
wait
```

The aggregate is the sum of the three receiver rates (drop `-R` for up).
Worker counts were set with `TOKIO_WORKER_THREADS` on each process.

`nstat` before and after a run shows the reordering counters
(`TcpExtTCPSACKReorder` on the sender, `TcpExtTCPOFOQueue` on the receiver),
and `cat /sys/class/net/<dev>/queues/tx-*/xps_cpus` shows whether XPS is
active. `scripts/live-routed-test.sh` covers traffic routed through the
server to a LAN host, which takes a different kernel path.
