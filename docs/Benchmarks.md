# Benchmarks

Throughput measurements kept to compare ezvpn with itself: one version
against the next, and one technique against another, on the same machines.
This page records what was measured, on what, and what each change was
worth. The reasoning behind the changes is in
[Architecture](Architecture.md), "Throughput Design".

> **Tailscale is in these tables as a control, not as a competitor.** It is a
> mature VPN that runs on the same machines, so when an ezvpn number comes
> out unexpectedly low, a Tailscale run on the same pair tells the two causes
> apart: if Tailscale is low too, the host or the network is having a bad
> day; if Tailscale is where it was, ezvpn regressed.
>
> The numbers are not meant to show which of the two is the faster VPN, and
> they cannot. They come from one pair of virtual machines on one host, over
> a virtual network with no real distance, loss or NAT, with one TCP flow per
> test, and with each product at whatever version and defaults it had that
> day. The two also do different jobs on the way (ezvpn carries IP in QUIC
> datagrams over iroh; Tailscale runs WireGuard with its own userspace
> stack), and a change of kernel, NIC, CPU, or a single offload flag reorders
> the table, as the results below show. Measure on your own hardware and path
> before drawing conclusions.

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

A later change (32 datagrams per UDP send) raised ezvpn in both tables. It
was measured in a session of its own, so its numbers are under
"Ten datagrams per send" below, next to the v0.0.69 and Tailscale runs taken
with it, and not added to these rows.

### macOS and Windows clients against the Linux server

The same day, one client at a time against the ezvpn server on `test1`,
both ends at default NIC settings. Unlike the Linux pair these cross a real
network, and the "no tunnel" row is what that path carries for one TCP flow,
so read each tunnel number against its own baseline. The client ran the same
commit as the server, built for its platform.

| Client | | Down | Up |
|---|---|---:|---:|
| macOS 26.7 VM (Apple M2 Max host, 8 vCPUs, arm64), behind its host's NAT | No tunnel | 1946 | 2350 |
| | Tailscale 1.104.2 | 435 | 219 |
| | ezvpn v0.0.68 | 1777 | 410 |
| | ezvpn, utun backlog + sends outside the lock, IPv6 direct path | 1773–1798 | 650–820 |
| | ezvpn, the same, IPv4 direct path | 1774–1823 | 880–1000 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2097 | 2359 |
| | ezvpn v0.0.68 | 1473 | 1452 |

Mbit/s, median of 5 runs of 6 s, iperf3 run on the client (3.22.1 on
Windows); the ranges are the medians of several passes, each after a client
restart. Every tunnel run used a direct path. The macOS no-tunnel download
was identical on every run, which suggests a cap in the VM's NAT path.
Single macOS download runs dipped to 1200–1450 now and then on every build,
v0.0.68 included, and one IPv4 pass of five had a median of 1367.

ezvpn picks its direct path per connection. The selector counts an IPv6
path as 3 ms faster than it measures and leaves the current direct path only
for one at least 5 ms better after that bias, so at equal round trip time it
keeps whichever family it selected first, and a client restart can land on
either. On this VM an IPv4 path carried an upload about 15% faster than the
IPv6 one, so the two are listed apart; read the family off
`ezvpn client status` when reproducing a row. v0.0.68 was measured over IPv6.
Upload retransmits were 0 on most passes over IPv6 and 0–130 per run over
IPv4, which here usually went out through the router's public address and
back.
Tailscale's direct path was the server's LAN address and it retransmitted
180 segments per upload run. The Linux pair measured the same on v0.0.68 and
on the newer build (about 2.0 Gbit/s each way, alternating the two builds).

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

### Ten datagrams per send

Turning `tx-udp-segmentation` on took Tailscale from 1.7 to 3.0 Gbit/s and
ezvpn only from 1.9 to 2.2. With the offload on, a UDP GSO send reaches the
host as one buffer, so what a send costs is shared by the datagrams in it,
in the guest's stack, in the host's virtio backend and again in the
receiving guest. Tailscale's wireguard-go fills a send up to the UDP payload
limit, about 48 of its packets (from its source; not measured here). The
QUIC driver (noq, as quinn before it) capped a send at 10 datagrams whatever
the socket could take.

ezvpn by the driver's cap, `tx-udp-segmentation` on, median of 6 runs with
the variants taken in turn:

| Datagrams per send | Down | Up |
|---|---:|---:|
| 10 (v0.0.69) | 2208 | 2122 |
| 24 | 2757 | 2692 |
| 32 | 3143 | 2834 |
| As many as fit one UDP payload (about 45) | 3232 | 2986 |

A cap of 64 with no bound on the bytes fell to 430 Mbit/s with 10,000
retransmits per run: 64 datagrams do not fit a UDP payload, the send fails
with `EMSGSIZE`, and the socket layer drops the whole batch without
reporting it. ezvpn now sends up to 32, which fits at any MTU it can
discover (32 × 1452 bytes is 46 KB) and also fits a frame of iroh's relay
protocol, whose limit is a little under the UDP one.

The build with 32 against v0.0.69 and Tailscale 1.104.7, each round running
all three, median of 6 rounds:

| | Down | Up | Down, offload off | Up, offload off |
|---|---:|---:|---:|---:|
| ezvpn v0.0.69 (10 per send) | 2180 | 2170 | 1786 | 1922 |
| ezvpn, 32 per send | 2972 | 2818 | 2022 | 2167 |
| Tailscale 1.104.7 | 2952 | 3042 | 1703 | 1481 |

ezvpn's inner TCP retransmitted nothing in the offload-on runs and in the
offload-off downloads; a few offload-off uploads had 25 to 650 retransmits
on both builds alike. Tailscale's runs had 400 to 3,400 each. The last two
of the six offload-on rounds were disturbed (Tailscale fell to 1426 down in
one, both ezvpn builds to 1500–1600 down in the other), which is the case
the Tailscale rows are there to show: the host, not a build.

Both ezvpn processes used about 1.3 cores at either batch size, so the
larger sends moved a third more data for the same CPU. The pacer still
decides how many datagrams may leave at once; the cap only sets how many
sends that takes, so a slow path, whose pacer releases a few datagrams at a
time, sends as before. A relay-only path behaved the same on both builds
(the public relay's rate limit set the rate for both). The driver's other
limit, 20 datagrams built per poll, made no difference (20 against 128).

The cap is the same on every platform. The Windows client (the VM in the
table above, against `test1`) with its own cap at 10 and at 32, five rounds
taking the variants in turn:

| Windows client | Down | Up |
|---|---:|---:|
| 10 per send | 1008 | 1329 |
| 32 per send | 993 | 1640 |

A download is sent by the server, and the server's own cap made no
difference to it there (1004 with 10, 1021 with 32): the Windows receive
side is the limit. The client used 1.3 cores for an upload at 10 per send
and 1.2 at 32. macOS takes one datagram per send whatever the cap, and
measured the same before and after: against the server with 32 per send,
the v0.0.69 client moved 1800 down and 812 up and the new one 1788 and 799
(six passes each, medians; single downloads dipped to 1250–1460 on both,
as they did before).

### Releasing the connection lock cost Windows its download

The Windows runs above turned up a second difference. v0.0.69 made the QUIC
driver release the connection's lock across each UDP send, for macOS
uploads (see below). The same binary source built for Windows with and
without that change, the cap at 10 in both, five rounds in turn:

| Windows client | Down | Up |
|---|---:|---:|
| Lock held across the send (as before v0.0.69) | 1194 | 1357 |
| Lock released (v0.0.69) | 1008 | 1329 |

It was not profiled; the client's CPU was the same 1.5 cores either way.
The driver now holds the lock across the send on Windows only. Between the
Linux guests the two measured alike when the change was made, and macOS is
what it was made for. The v0.0.68 Windows client, v0.0.69, and the build
with both changes (32 per send, lock held on Windows), each against the
server with 32 per send, five rounds in turn:

| Windows client | Down | Up |
|---|---:|---:|
| v0.0.68 (the binary of the earlier table) | 1196 | 1404 |
| v0.0.69 | 1036 | 1367 |
| 32 per send, lock held on Windows | 1193 | 1726 |
| No tunnel | 2068 | 2314 |

The first row measured 1473 and 1452 in the morning's session: the path to
this VM carried less in the evening for every build, so the rows compare
with each other and not with the earlier table.

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

### macOS handed the reader one packet per wakeup

A macOS upload on v0.0.68 was not short of CPU: the client's two threads ran
at about 70% each. Three measurements located the wait, taken on the VM
above with temporary counters in the client and `netstat -qq -I utun5`:

- The utun interface's send queue held about 740 packets and dropped on
  overflow (264 drops in a 6 s run), so TCP was offering more than the
  tunnel took.
- The TUN reader, meanwhile, found the utun socket empty ten times for every
  packet it read, and a `read` that returned a packet took 7–9 µs against
  0.35 µs for an empty one.
- With two workers the reader also waited about 430 µs per 64-packet batch
  for the QUIC connection's lock, a third of its time.

The first two are one cause. The kernel moves packets from the interface
queue to the utun socket only while fewer than `UTUN_OPT_MAX_PENDING_PACKETS`
wait there, and the default is 1, so every `read` has to wake the kernel
thread that delivers the next packet. Upload by that limit, two workers,
3 runs each (the path's address family was not recorded for this table, and
it moves a row by up to 15%):

| Pending packets | 1 (default) | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 1024 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Up, Mbit/s | 459 | 637 | 709 | 808 | 738 | 782 | 664 | 678 | 554 | 213 |

Large values lose because the kernel counts the waiting packets by walking
the socket's queue on every `read` and before each packet it adds
(`ctl_getenqueuepacketcount` in XNU); at 1024 a `read` took 39 µs.
ezvpn now sets 32.

The lock wait was the QUIC driver sending under the connection's lock, one
`sendmsg` of 6–7 µs per datagram on macOS. With the noq fork's driver
releasing the lock across each send, the reader's lock wait fell from 330 ms
to 10 ms per second and the upload reached the figures in the table above.
What is left of the client's time is almost all two syscalls per packet,
the utun `read` and the UDP `sendmsg` (5–6 µs each); neither has a
batched form that saves the per-packet kernel work on macOS.

Tailscale 1.104.2 on the same VM used 2.7 cores for its 215 Mbit/s upload,
spread over eight or more threads at about a third of a core each, with
roughly one thread's worth of time blocked or running inside `sendto` (about
44 µs per packet at that rate).

### A false MTU black hole stalled long transfers

Not a throughput number, but found by these runs: before v0.0.67 a sustained
download at about 1 Gbit/s dropped to zero after 45–95 s and stayed there for
about a minute. QUIC's black hole detector misread congestion loss, reset the
path MTU to 1200, and every full-size inner packet was then too large to
send. Fixed in v0.0.67; a 180 s run now holds its rate. Short runs never
showed it, which is why the tables above use 6 s runs for both versions.

## Opportunities left

What these runs left open, with what is known about each. None of it is
scheduled work.

**macOS and iOS**

- **Two syscalls per packet.** After the changes above a macOS upload spends
  its client time in the utun `read` and the UDP `sendmsg`, 5–6 µs each, on
  two threads. The `read` wakes the utun's kernel thread every time, and
  the `sendmsg` probably does the same for the NIC's. Batching the syscalls
  (`recvmsg_x`, `sendmsg_x`) was not tried: an empty `read` costs 0.35 µs,
  so syscall entry is a small part of the 5–6. A raw `iperf3 -u` on the same
  VM handed the kernel 280,000 packets per second (about 3.5 µs each), which
  bounds what a cheaper send could give.
- **Segmentation offload on the utun.** The utun Tailscale's network
  extension gets from the system lists `TSO4`, `TSO6` and `CHANNEL_IO` among
  its options; the one ezvpn opens through the kernel-control socket hands
  over one MTU-sized packet per read. Whether a root process can get the
  channel mode, and what it would take, was not investigated; it is the only
  route seen here to fewer, larger reads.
- **IPv6 bias in path selection.** The path selector follows iroh's default:
  it counts an IPv6 direct path as 3 ms faster than it measures, and switches
  between direct paths only for a 5 ms improvement after that bias. With no
  path selected yet it therefore takes IPv6 when that is within 3 ms of IPv4,
  and at equal round trip time it stays on whichever it has. On this VM a
  connection that settled on IPv6 uploaded about 15% slower. It may be this
  VM's NAT rather than macOS; it was not measured on a Mac with native IPv6.
- **Reader polling may no longer be needed.** With the utun backlog, polling
  the utun between batches (`TUN_DRAIN_SPIN`) changed neither throughput nor
  CPU on the VM (850 Mbit/s and 9.3–9.5 s of CPU per 6 s run either way).
  It was kept because iOS shares the code and was not measured.
- **utun socket buffers.** The 4 MiB receive buffer was sized on the
  assumption that packets queue there; with the limit of 32 pending packets
  it never holds more than about 40 KiB. Whether the larger size still
  matters, for the receive or the send buffer, was not re-tested.
- **CPU at low rates.** A paced 100 Mbit/s upload cost the macOS client
  about half a core (3.1 s of CPU per 6.1 s), against 1.5 cores at full
  rate, and a `sendmsg` took about 14 µs there against 6 at full rate. The
  likely cause is a thread wakeup per packet when nothing is queued, which
  costs more in a VM; it was not measured on hardware.
- **iOS is unmeasured.** The utun backlog applies to the iOS tunnel too,
  through the same code, but nothing here ran on a device.

**Linux**

- **Sends filled to the UDP payload.** About 45 datagrams per send measured
  3% (down) and 5% (up) above the 32 ezvpn uses, and in its session put ezvpn
  ahead of Tailscale both ways (3248 and 3166 against 2939 and 2972). It
  needs the batch bounded in bytes where the path MTU is known, in noq's
  protocol layer, and the bound has to respect the relay frame limit as well
  as the UDP one; 32 needs neither.
- **The sender is one thread's worth.** With one runtime worker the sending
  side held a core at 100% for 2.2 Gbit/s (v0.0.69) with no steal time; with
  two, each worker ran at 65–70% and the guest lost half a core to a core to
  steal, for about the same throughput. What a second thread adds here is
  lock handoffs and wakeups, not capacity. Of that one thread's time on
  v0.0.69, 71% was user space and 29% the kernel: QUIC packet building and
  send-side bookkeeping in noq's protocol layer 30%, AES-GCM 18%, `memcpy`
  9% (a segment is copied into scratch, then the arena, then the QUIC send
  buffer), software segmentation and its TCP checksums 3.5%. It was not
  profiled again with 32 per send, which should shrink the kernel share.
  Tailscale spends more CPU per packet (2.0 cores a side at 3.1 Gbit/s
  against 1.3) but spreads it over seven threads.
- **Worker count off these VMs.** Two runtime workers was chosen on guests
  that overcommit their host two to one. One tunnel was fastest on one
  worker (2.4 Gbit/s against 2.3), and a server with three clients needed
  two or three. A dedicated machine, or a server with many clients, may want
  a different number; `TOKIO_WORKER_THREADS` is the knob.

**Windows**

- **Not profiled.** The Windows client moves about 1.2 Gbit/s down and 1.7
  up against 2.1 and 2.3 with no tunnel. Its download did not respond to
  either end's send batch and lost 16% to the lock change that was then
  taken back for Windows, which points at the receive side (the driver, the
  datagram reader and one Wintun write per packet), but nothing is known yet
  about where its time goes.

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
