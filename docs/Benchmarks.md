# Benchmarks

Throughput measurements kept to compare ezvpn with itself: one version
against another, on the same machines. They show proportions, not what your
hardware will do. How the data path is built, and why, is in
[Architecture](Architecture.md), "Throughput Design".

## v0.0.74 against v0.0.70

Mbit/s, down / up, one TCP flow, 2026-11-26. In each column the rows were
measured in turn, round after round; the numbers are medians of ten rounds,
twenty for the macOS client. Each ezvpn row ran that version's release
binary at both ends.

| | Linux pair, default NIC | Linux pair, UDP offload on | macOS client | Windows client |
|---|---:|---:|---:|---:|
| No tunnel | 21061 / 21219 | 21217 / 21337 | 1946 / 2353 | 2101 / 2361 |
| Tailscale (control) | 1295 / 1260 | 3211 / 3130 | 429 / 216 | not installed |
| ezvpn v0.0.70 | 2195 / 2396 | 3412 / 3083 | 1832 / 956 | 1391 / 1709 |
| **ezvpn v0.0.74** | **2181 / 2382** | **3422 / 3073** | **1832 / 917** | **1436 / 1684** |

Nothing between the two versions is meant to change how fast a tunnel
carries packets. The four releases bound the handshake (a deadline at both
ends, and a limit on how many connections may be waiting to authenticate),
grant a peer the control stream and no other, close client connections when
a server is told to stop, and rework how a client or server shuts down and
how the Windows session reports it. On the data path they add one comparison
per packet the server forwards to a client (the route's session against the
client's current one). The transport forks (iroh, noq, netwatch) are at the
same commits in both versions.

The table is here to show what all of that costs. Between the Linux pair
it is nothing that these machines can tell: the two versions are within 1%
of each other in both columns. The Windows client's medians are 3% apart on
downloads, in v0.0.74's favour, and 1.5% on uploads, in v0.0.70's, on runs
that ranged over an eighth of their value or more for either version.

The macOS client's upload is the exception. v0.0.74's median is 4% under
v0.0.70's, and over 27 rounds it was ahead in 8: small beside the quarter of
its value that an upload ranges over there, but steadier than chance would
leave it. It was not traced to a change
([Results](#macos-and-windows-clients-against-the-linux-server)).

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
> the table, as the two Linux columns show. Measure on your own hardware and
> path before drawing conclusions.

## Setup (2026-11-26)

| | |
|---|---|
| Machines | `test1` (server, `10.22.40.61`) and `test2` (client, `10.22.40.62`): two KVM guests on the same physical host, joined by a virtual bridge |
| Host CPU | Intel Core i5-8400T (6 cores, no SMT); each guest has 6 vCPUs, so the two guests together overcommit the host 2:1 |
| Guest | Debian 13, kernel 6.12.118, 2 GB RAM |
| NIC | `virtio_net`, 6 queues (multi-queue), XPS at its default of one transmit queue per CPU, `tx-udp-segmentation` off by default |
| Kernel UDP buffer limit | `net.core.rmem_max` and `wmem_max` at their default of 212992 bytes; ezvpn runs as root and sets its 7 MiB buffers past the limit |
| ezvpn | v0.0.70 and v0.0.74 as released (the binaries of their GitHub releases), the same version at both ends; direct path, Cubic, inner MTU 1280 |
| Tailscale | 1.104.7 on the Linux pair, 1.104.2 on macOS; `tailscale0` MTU 1280 |
| Tool | iperf3 3.18 (3.21 on macOS, 3.22.1 on Windows), one TCP flow, 6 s per run after a 1 s warm-up; "up" is client to server, "down" is server to client (`-R`) |

One test ran at a time, and the rows of a table were taken in turn, one
round after another: no tunnel, Tailscale, then the two ezvpn versions, in an
order that alternated by round. Server and client were both restarted for
every ezvpn run, a run being one direction. The path was read off
`ezvpn client status` before each run, five seconds after the tunnel first
answered a ping, and again after it: a run that starts before a direct path
has been selected measures the rate-limited public relay. Every ezvpn run
below was on a direct path to the server's own address, before and after;
none had to be taken again for its path.

The clients kept the Tailscale address ranges off their direct paths
(`--exclude-direct-path`), since `test1` has a Tailscale address that they
could otherwise reach it by. The macOS and Windows clients also kept IPv6
and the router's public address off theirs, so that each of their runs was
over IPv4 to `10.22.40.61`: ezvpn picks its direct path per connection, and
on the macOS VM an IPv6 path has carried uploads more slowly than an IPv4
one ([Opportunities left](#opportunities-left)). Between the Linux pair the
path was as iroh chose, IPv4 for 73 of the 80 runs and IPv6 on the same
bridge for the rest.

Anything else running on the physical host moves every row, and something
there runs on the quarter-hour (flextunnel's benchmarks on the same pair
found every row 15–60% low for two to three minutes from each one). No run
was started that would reach into the minute before a quarter-hour or the
three minutes after it.

## Results

Mbit/s, medians of ten rounds (twenty for the macOS client). "Retr" is the
median of the inner TCP sender's retransmits per run. "CPU" is the ezvpn
process's CPU time over a run divided by the run's length, in cores, on the
client and on the server. No receive was refused for want of socket buffer
(`UdpRcvbufErrors`) on either Linux machine in any run, and the server's
per-client queues dropped nothing (`dropped_full`).

### Linux pair, default NIC settings

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel (TCP with TSO over the bridge) | 21061 | 21219 | 0 / 0 | | |
| Tailscale 1.104.7 | 1295 | 1260 | 1206 / 1684 | | |
| ezvpn v0.0.70 | 2195 | 2396 | 0 / 0 | 1.17 / 1.16 | 1.16 / 1.25 |
| ezvpn v0.0.74 | 2181 | 2382 | 0 / 0 | 1.15 / 1.15 | 1.13 / 1.24 |

Downloads ranged from 2067 to 2423 for v0.0.70 and from 1863 to 2419 for
v0.0.74, uploads from 2125 to 2434 and from 2094 to 2444. v0.0.74 was ahead
in six rounds of ten on downloads and three on uploads. One upload of each
version retransmitted (429 and 819 segments); no other ezvpn run did.
Tailscale ranged from 1066 to 1807 down and from 1091 to 1904 up.

### Linux pair, `tx-udp-segmentation` on

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 21217 | 21337 | 112 / 0 | | |
| Tailscale 1.104.7 | 3211 | 3130 | 1620 / 1236 | | |
| ezvpn v0.0.70 | 3412 | 3083 | 0 / 0 | 1.30 / 1.33 | 1.28 / 1.27 |
| ezvpn v0.0.74 | 3422 | 3073 | 0 / 0 | 1.29 / 1.33 | 1.28 / 1.27 |

`virtio_net` supports UDP segmentation offload but leaves it off by default
(`ethtool -K eth0 tx-udp-segmentation on`). With it on, a UDP GSO batch
crosses to the host as one buffer instead of being segmented in the guest.
It is a setting of the underlay NIC, outside either VPN's control.

Downloads ranged from 3004 to 3489 for v0.0.70 and from 2523 to 3547 for
v0.0.74, uploads from 2994 to 3110 and from 2886 to 3151. v0.0.74 was ahead
in five rounds of ten in each direction, and no ezvpn run retransmitted.
Tailscale ranged from 2930 to 3601 down and, but for one upload of 1600,
from 3063 to 3309 up.

### macOS and Windows clients against the Linux server

One client at a time against the ezvpn server on `test1`, both ends at
default NIC settings. Unlike the Linux pair these cross a real network, and
the "no tunnel" row is what that path carries for one TCP flow, so read each
tunnel number against its own baseline.

| Client | | Down | Up | Client CPU, cores (down / up) |
|---|---|---:|---:|---:|
| macOS 26.7 VM (Apple M2 Max host, 8 vCPUs, arm64), behind its host's NAT | No tunnel | 1946 | 2353 | |
| | Tailscale 1.104.2 | 429 | 216 | |
| | ezvpn v0.0.70 | 1832 | 956 | 1.71 / 1.60 |
| | ezvpn v0.0.74 | 1832 | 917 | 1.71 / 1.59 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2101 | 2361 | |
| | ezvpn v0.0.70 | 1391 | 1709 | 1.44 / 1.15 |
| | ezvpn v0.0.74 | 1436 | 1684 | 1.46 / 1.13 |

Twenty rounds for the macOS client, in two sessions of ten, and ten for the
Windows one, taken as the Linux pair's were, with iperf3 run on the client.
Every tunnel run was over IPv4 to the server's own address, and the server's
kernel refused no receive during any of them. Tailscale is not installed on
the Windows VM. On the macOS VM it is normally stopped and was started for
the two sessions; its own path to `test1` went by the router's public
address, and its runs ranged from 426 to 432 down and from 211 to 221 up.

The macOS no-tunnel download read 1945 or 1946 on every run, which suggests
a cap in the VM's NAT path. Both versions' downloads read 1832 in most runs
(1768 at the lowest), which looks like the same cap less what the tunnel
adds to each packet, so the download column says only that both reach it.

Uploads are where the macOS client has room, and where the versions differ.
They ranged from 816 to 1018 for v0.0.70 and from 787 to 1034 for v0.0.74,
and v0.0.74 was ahead in 6 rounds of 20: the two sessions read 965 against
903 and 956 against 926. Seven more rounds of uploads alone, with Tailscale
stopped, read 922 against 894, with v0.0.74 ahead in two. Over all 27 rounds
the medians are 956 and 906, v0.0.74 was ahead in 8, and 12 of its uploads
were under 900 against 4 of v0.0.70's. A sign test puts 8 of 27 at about one
chance in twenty, so the difference is probably real and about 5%. Which
release brought it was not measured (v0.0.71 to v0.0.73 lie between), and
the client's CPU does not show it: 1.6 cores for either version. The server
is the busier end of a macOS upload, at about 1.9 cores on its two runtime
workers for either version, where a Linux client's upload at two and a half
times the rate costs it 1.25. A macOS client sends one datagram per UDP
send, so they probably reach the server unbatched; that was not checked.

Windows downloads ranged from 1294 to 1459 for v0.0.70 and from 1339 to 1572
for v0.0.74, uploads from 1603 to 1810 and from 1620 to 1783. v0.0.74 was
ahead in eight rounds of ten on downloads and five on uploads.

## Opportunities left

What is known to be left on the table, with what is known about each. None
of it is scheduled work. Where a figure from the tables above is given it
was measured in these runs; the rest was not measured again, and its
mechanisms are described in [Architecture](Architecture.md), "Throughput
Design".

**macOS and iOS**

- **v0.0.74's upload.** A macOS upload reads about 5% lower on v0.0.74
  than on v0.0.70 ([Results](#macos-and-windows-clients-against-the-linux-server)).
  The release binaries of v0.0.71 to v0.0.73, taken in turn the same way,
  would say which release moved it. The server is at 1.9 cores of its two
  workers during one, so a change to what the server does per packet is as
  likely a place as the client.
- **Two syscalls per packet.** What is left of a macOS upload's client time
  is the utun `read` and the UDP `sendmsg`, one of each per packet, on two
  threads. Batching the syscalls (`recvmsg_x`, `sendmsg_x`) was not tried:
  entering the kernel is a small part of what each costs.
- **Segmentation offload on the utun.** The utun Tailscale's network
  extension gets from the system lists `TSO4`, `TSO6` and `CHANNEL_IO` among
  its options; the one ezvpn opens through the kernel-control socket hands
  over one MTU-sized packet per read. Whether a root process can get the
  channel mode, and what it would take, was not investigated; it is the only
  route seen so far to fewer, larger reads.
- **IPv6 bias in path selection.** The path selector follows iroh's default:
  it counts an IPv6 direct path as 3 ms faster than it measures, and switches
  between direct paths only for a 5 ms improvement after that bias. With no
  path selected yet it therefore takes IPv6 when that is within 3 ms of IPv4,
  and at equal round trip time it stays on whichever it has, so a client
  restart can land on either. On this VM an IPv6 path carries uploads more
  slowly: the macOS rows here keep IPv6 off the direct path for that reason
  and so did not measure it, and flextunnel, on the same forks and the same
  VM, read a macOS upload 15–18% lower over IPv6 than over IPv4 that day (its
  [benchmarks](https://github.com/flexaccessdev/flextunnel/blob/main/docs/benchmarks.md)).
  It may be this VM's NAT rather than macOS; it was not measured on a Mac
  with native IPv6.
- **Reader polling may no longer be needed.** With the utun backlog, polling
  the utun between batches (`TUN_DRAIN_SPIN`) changed neither throughput nor
  CPU on the VM when it was tried. It was kept because iOS shares the code
  and was not measured.
- **utun socket buffers.** The 4 MiB receive buffer was sized on the
  assumption that packets queue there; with the limit of 32 pending packets
  it never holds more than about 40 KiB. Whether the larger size still
  matters, for the receive or the send buffer, was not re-tested.
- **iOS is unmeasured.** The utun backlog applies to the iOS tunnel too,
  through the same code, but nothing here ran on a device.

**Linux**

- **Sends filled to the UDP payload.** ezvpn sends up to 32 datagrams per
  UDP send; about 45 fit one UDP payload, and measured a few percent faster
  when the cap was chosen. The fork's byte bound already keeps such a batch
  inside a UDP payload; what raising the cap still needs is a bound that
  also respects the relay frame limit, a few bytes lower, which 32 datagrams
  stay under by themselves.
- **The sender is one thread's worth.** Each end used 1.15–1.25 cores for
  2.2–2.4 Gbit/s, and about 1.3 for 3.1–3.4 with the offload on, on machines
  of six: one connection's data path is a chain of tasks that hand packets
  on through the connection's lock, so a second thread adds handoffs rather
  than capacity. Where the time goes was not profiled on these versions.
- **Worker count off these VMs.** Two runtime workers was chosen on guests
  that overcommit their host two to one. A dedicated machine, or a server
  with many clients, may want a different number; `TOKIO_WORKER_THREADS` is
  the knob.

**Windows**

- **Not profiled.** The Windows client moves about 1.4 Gbit/s down and 1.7
  up on a path that carries 2.1 and 2.36, at 1.45 and 1.15 cores. The
  download is the slower direction, which points at the receive side (the
  driver, the datagram reader and one Wintun write per packet), but nothing
  is known yet about where its time goes.

## Reproducing

Start a server on one machine with `iperf3 -s` beside it, and a client on
the other (the README's quick start has both). Wait for
`ezvpn client status` to show a `Direct … (selected)` path in its
`Connection:` line, then from the client:

```bash
iperf3 -t 6 -O 1 -c <server VPN address>        # up
iperf3 -t 6 -O 1 -c <server VPN address> -R     # down
```

A run that begins on a relay measures the relay. If the machines share
another network (these are also on a tailnet), iroh may take that as its
direct path; keep it off with the client's `--exclude-direct-path`, and
check the address in the `Connection:` line after a run as well as before
it. The macOS and Windows rows used the same flag to stay on IPv4:

```bash
ezvpn client start -n <server id> --auth-key-file client.key \
  --exclude-direct-path 100.64.0.0/10 --exclude-direct-path fd7a:115c:a1e0::/48   # Tailscale's ranges
  # macOS and Windows rows: --exclude-direct-path ::/0 --exclude-direct-path <router's public address>/32
```

The offload column is a setting of each guest's NIC, and does not survive a
reboot:

```bash
sudo ethtool -K eth0 tx-udp-segmentation on
```

`nstat -az UdpRcvbufErrors Udp6RcvbufErrors` before and after a run gives
the receives the kernel refused, `ezvpn server status` the server's
`dropped_full` count, and the process's CPU time is the sum of the 14th and
15th fields of `/proc/<pid>/stat`, in clock ticks.
`scripts/live-routed-test.sh` covers traffic routed through the server to a
LAN host, which takes a different kernel path.
