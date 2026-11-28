# Benchmarks

Throughput measurements kept to compare ezvpn with itself: one version
against another, on the same machines. They show proportions, not what your
hardware will do. How the data path is built, and why, is in
[Architecture](Architecture.md), "Throughput Design".

## v0.0.76 against v0.0.75

Mbit/s, down / up, between the Linux pair, 2026-11-27. The rows of a column
were measured in turn, round after round; the numbers are medians of ten
rounds. Each ezvpn row ran that version at both ends.

| | Default NIC, one flow | Default NIC, four flows | UDP offload on, one flow | UDP offload on, four flows |
|---|---:|---:|---:|---:|
| No tunnel | 21339 / 21401 | 22062 / 21932 | 21158 / 21309 | 21843 / 21997 |
| Tailscale | 1276 / 1329 | 1391 / 1400 | 3235 / 3234 | 3807 / 3704 |
| ezvpn v0.0.75 | 2225 / 2299 | 2415 / 2388 | 3139 / 3076 | 3537 / 3069 |
| **ezvpn v0.0.76** | **2322 / 2430** | **2498 / 2507** | **3939 / 4015** | **3996 / 3992** |

v0.0.76 changes one thing on the data path. Until it, the task that drives a
connection built each packet, encrypted it and sent it, and on the sending
side of a fast tunnel that one task was saturated. On Linux, v0.0.76 hands
the encryption and the UDP send to a second task of the connection
([Architecture](Architecture.md), "Encryption and send in a task of their
own").

With the offload on, v0.0.76 is 25% faster down and 31% faster up with one
flow, and 13% and 30% with four; it was ahead in every round of all four
cells. At default NIC settings the gain is 3–6%, and it was ahead in 6 rounds
of 10 on one-flow downloads and in 9 or 10 of 10 in the other three cells.
What it costs is in [Results](#results): each end uses more CPU for the
higher rate (about 1.5–1.6 cores where it used 1.3), and with four flows and
the offload on, more of v0.0.76's runs retransmit.

The four-flow rows are there because a limit that every version has passes a
one-flow table unseen. v0.0.75's row shows one: with the offload on its
uploads read the same with four flows as with one (3069 and 3076), and its
downloads gain 13%, while Tailscale, which spreads its work over threads,
gains 15–18% and ends ahead of it by 8% down and 21% up. With one flow the
two were 3–5% apart, inside what Tailscale moves from one day to the next.
A tunnel that gains nothing from more flows where another does has a ceiling
of its own, and so has one whose upload stays below its download in every
run. v0.0.76 reads about 4 Gbit/s in all four cells of that column, so it
has a ceiling too, a higher one
([Opportunities left](#opportunities-left)).

No row transfers a file. A download or an upload of a file measures the
disk, the page cache and the copying tool along with the tunnel, and its row
would move with them.

Neither the macOS nor the Windows client sends through the new task, but a
v0.0.76 Linux server sends their downloads through it. Both clients were
measured on the two versions the same day
([below](#macos-and-windows-clients)), and neither shows a difference that
ten rounds can tell from none: every median is within 2.5% of the other
version's but the macOS four-flow upload, which is 6% higher on v0.0.76.

> **Tailscale is in these tables as a control, not as a competitor.** It is a
> mature VPN that runs on the same machines, so when an ezvpn number comes
> out unexpectedly low, a Tailscale run on the same pair tells the two causes
> apart: if Tailscale is low too, the host or the network is having a bad
> day; if Tailscale is where it was, ezvpn regressed. On the four-flow rows
> it is also a comparison of shape: what a tunnel that uses several threads
> gains from several flows on these machines.
>
> The numbers are not meant to show which of the two is the faster VPN, and
> they cannot. They come from one pair of virtual machines on one host, over
> a virtual network with no real distance, loss or NAT, with one or four TCP
> flows per test, and with each product at whatever version and defaults it
> had that day. The two also do different jobs on the way (ezvpn carries IP
> in QUIC datagrams over iroh; Tailscale runs WireGuard with its own
> userspace stack), and a change of kernel, NIC, CPU, or a single offload
> flag reorders the table, as the two halves of it show. Measure on your own
> hardware and path before drawing conclusions.

## Setup (2026-11-27)

| | |
|---|---|
| Machines | `test1` (server, `10.22.40.61`) and `test2` (client, `10.22.40.62`): two KVM guests on the same physical host, joined by a virtual bridge; both rebooted before the session |
| Host CPU | Intel Core i5-8400T (6 cores, no SMT); each guest has 6 vCPUs, so the two guests together overcommit the host 2:1 |
| Guest | Debian 13, kernel 6.12.118, 2 GB RAM |
| NIC | `virtio_net`, 6 queues (multi-queue), XPS at its default of one transmit queue per CPU, `tx-udp-segmentation` off by default |
| Kernel UDP buffer limit | `net.core.rmem_max` and `wmem_max` at their default of 212992 bytes; ezvpn runs as root and sets its 7 MiB buffers past the limit |
| ezvpn | v0.0.75 and v0.0.76, the same version at both ends; direct path, Cubic, inner MTU 1280 |
| Tailscale | 1.104.7; `tailscale0` MTU 1280 |
| Tool | iperf3 3.18, one TCP flow or four (`-P 4`), 6 s per run after a 1 s warm-up; "up" is client to server, "down" is server to client (`-R`) |

One test ran at a time, and the rows of a table were taken in turn, one
round after another: no tunnel, Tailscale, then the two ezvpn versions, in an
order that alternated by round. A row is four runs: one flow down and up,
then four flows down and up. Server and client were both restarted for every
ezvpn run. The path was read off `ezvpn client status` before each run, five
seconds after the tunnel first answered a ping, and again after it: a run
that starts before a direct path has been selected measures the rate-limited
public relay. All 160 ezvpn runs were on a direct path to the server's own
address, before and after; none had to be taken again.

The clients kept the Tailscale address ranges off their direct paths
(`--exclude-direct-path`), since `test1` has a Tailscale address that they
could otherwise reach it by. Otherwise the path was as iroh chose: IPv4 for
143 of the 160 runs, IPv6 on the same bridge for 16, and one that began on
IPv4 and ended on IPv6.

Anything else running on the physical host moves every row, and something
there runs on the quarter-hour (flextunnel's benchmarks on the same pair
found every row 15–60% low for two to three minutes from each one). No run
was started that would reach into the minute before a quarter-hour or the
three minutes after it.

## Results

Mbit/s, medians of ten rounds. "Retr" is the median of the inner TCP
senders' retransmits per run, all flows together. "CPU" is the ezvpn
process's CPU time over a run divided by the run's length, in cores, on the
client and on the server. No receive was refused for want of socket buffer
(`UdpRcvbufErrors`) on either machine in any run. The server's per-client
queues dropped nothing (`dropped_full`) except in the eight runs named
below.

### Linux pair, default NIC settings

One flow:

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel (TCP with TSO over the bridge) | 21339 | 21401 | 0 / 0 | | |
| Tailscale 1.104.7 | 1276 | 1329 | 1270 / 1068 | | |
| ezvpn v0.0.75 | 2225 | 2299 | 0 / 0 | 1.17 / 1.17 | 1.14 / 1.24 |
| ezvpn v0.0.76 | 2322 | 2430 | 0 / 0 | 1.17 / 1.17 | 1.11 / 1.29 |

Four flows:

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 22062 | 21932 | 16262 / 15069 | | |
| Tailscale 1.104.7 | 1391 | 1400 | 5062 / 4405 | | |
| ezvpn v0.0.75 | 2415 | 2388 | 0 / 28 | 1.27 / 1.16 | 1.16 / 1.29 |
| ezvpn v0.0.76 | 2498 | 2507 | 0 / 0 | 1.33 / 1.20 | 1.18 / 1.33 |

With one flow, downloads ranged from 2173 to 2422 for v0.0.75 and from 1848
to 2488 for v0.0.76, uploads from 1841 to 2454 and from 2174 to 2523.
v0.0.76 was ahead in six rounds of ten on downloads and nine on uploads. One
run of each version retransmitted in each direction (38 and 146 segments for
v0.0.75, 1 and 559 for v0.0.76). Tailscale ranged from 1033 to 1915 down and
from 1218 to 1855 up.

With four flows, downloads ranged from 2270 to 2518 for v0.0.75 and from
2410 to 2591 for v0.0.76, uploads from 1858 to 2429 and from 2406 to 2586.
v0.0.76 was ahead in nine rounds of ten on downloads, level in the other,
and ahead in all ten on uploads. About four runs in ten retransmitted for
either version: three downloads and five uploads of v0.0.75 (38 to 16586
segments), four and four of v0.0.76 (5 to 10476). The server's queues
dropped nothing in those runs and neither kernel refused a receive; where
the segments were lost was not traced. Tailscale ranged from 1235 to 2112
down and from 1335 to 2260 up.

Four flows carry 3–9% more than one through either version here, and CPU is
within a tenth of a core between the two.

### Linux pair, `tx-udp-segmentation` on

One flow:

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 21158 | 21309 | 68 / 136 | | |
| Tailscale 1.104.7 | 3235 | 3234 | 1203 / 869 | | |
| ezvpn v0.0.75 | 3139 | 3076 | 0 / 0 | 1.28 / 1.32 | 1.28 / 1.28 |
| ezvpn v0.0.76 | 3939 | 4015 | 0 / 0 | 1.46 / 1.58 | 1.55 / 1.47 |

Four flows:

| | Down | Up | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---:|---:|---:|---:|---:|
| No tunnel | 21843 | 21997 | 17754 / 16048 | | |
| Tailscale 1.104.7 | 3807 | 3704 | 3562 / 3962 | | |
| ezvpn v0.0.75 | 3537 | 3069 | 0 / 0 | 1.35 / 1.38 | 1.30 / 1.29 |
| ezvpn v0.0.76 | 3996 | 3992 | 59 / 828 | 1.50 / 1.62 | 1.63 / 1.52 |

`virtio_net` supports UDP segmentation offload but leaves it off by default
(`ethtool -K eth0 tx-udp-segmentation on`). With it on, a UDP GSO batch
crosses to the host as one buffer instead of being segmented in the guest.
It is a setting of the underlay NIC, outside either VPN's control.

With one flow, downloads ranged from 2979 to 3494 for v0.0.75 and from 3584
to 4081 for v0.0.76, uploads from 2956 to 3123 and from 3560 to 4097: the
slowest run of v0.0.76 was faster than the fastest of v0.0.75 in both
directions, and no ezvpn run retransmitted. Tailscale ranged from 1466 to
3366 down and from 1463 to 3413 up.

With four flows, downloads ranged from 3216 to 3658 for v0.0.75 and from
3862 to 4102 for v0.0.76, uploads from 2909 to 3138 and from 3200 to 4155,
and v0.0.76 was again ahead in every round. Tailscale ranged from 1551 to
3900 down and from 1603 to 3850 up.

The sending end is the one whose CPU grows most: the server's on a download
(1.32 to 1.58 cores with one flow), the client's on an upload (1.28 to
1.55). Per bit carried, every end of v0.0.76 uses less CPU than v0.0.75's or
the same, but for the server on a four-flow download, which uses 4% more.

Retransmits are what v0.0.76 pays for the rate, and only with four flows:

- **Downloads.** Three of v0.0.75's ten runs retransmitted (118, 134 and 708
  segments), and in each the server's queue for the client had dropped
  exactly that many packets. Six of v0.0.76's did (26 to 723 segments); the
  queue had dropped packets in five of them (26, 92, 159, 418 and 830). That
  queue is where a server puts what it reads from its TUN device faster than
  the tunnel takes it, so a drop there is the tunnel telling the inner TCP
  flows to slow down.
- **Uploads.** Seven of v0.0.76's ten runs retransmitted (339 to 2604
  segments, a median of 828 against about 2.4 million sent), and none of
  v0.0.75's. No counter read in these runs shows where; when the change was
  developed, the receiving end's QUIC datagram buffer was seen to overflow
  under four flows, with nothing lost by QUIC itself
  ([Architecture](Architecture.md), "Encryption and send in a task of their
  own").

## macOS and Windows clients

Mbit/s, down / up, 2026-11-27: one client at a time against the ezvpn server
on `test1`, both ends at default NIC settings and on the same version.
Medians of ten rounds, taken in turn as the Linux pair's are. Unlike the
Linux pair these cross a real network, and the "no tunnel" row is what that
path carries, so read each tunnel number against its own baseline.

| Client | | One flow | Four flows |
|---|---|---:|---:|
| macOS 26.7 VM (Apple M2 Max host, 8 vCPUs, arm64), behind its host's NAT | No tunnel | 1946 / 2354 | 1946 / 2353 |
| | Tailscale 1.104.2 | 421 / 208 | 403 / 209 |
| | ezvpn v0.0.75 | 1832 / 878 | 1831 / 857 |
| | ezvpn v0.0.76 | 1832 / 892 | 1831 / 909 |
| Windows VM (build 26100, Hyper-V, 4 vCPUs, 2 GB, 2.5 Gbit/s link, another host) | No tunnel | 2080 / 2372 | 2241 / 2371 |
| | ezvpn v0.0.75 | 1371 / 1661 | 1261 / 1685 |
| | ezvpn v0.0.76 | 1383 / 1701 | 1258 / 1674 |

| Client | | Flows | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---|---|---:|---:|---:|
| macOS | ezvpn v0.0.75 | one | 0 / 0 | 1.72 / 1.12 | 1.58 / 1.87 |
| | ezvpn v0.0.76 | one | 0 / 0 | 1.73 / 1.26 | 1.60 / 1.89 |
| | ezvpn v0.0.75 | four | 1776 / 256 | 1.72 / 1.17 | 1.60 / 1.87 |
| | ezvpn v0.0.76 | four | 186 / 320 | 1.73 / 1.29 | 1.63 / 1.89 |
| Windows | ezvpn v0.0.75 | one | 0 / – | 1.37 / 1.10 | 1.15 / 1.27 |
| | ezvpn v0.0.76 | one | 0 / – | 1.37 / 1.12 | 1.12 / 1.31 |
| | ezvpn v0.0.75 | four | 0 / – | 1.33 / 1.07 | 1.15 / 1.27 |
| | ezvpn v0.0.76 | four | 0 / – | 1.35 / 1.09 | 1.11 / 1.30 |

iperf3 ran on the client (3.21 on macOS, 3.22.1 on Windows, where it does
not report an upload's retransmits). Both clients kept IPv6 and the router's
public address off their direct paths as well as the Tailscale ranges: ezvpn
picks its direct path per connection, and on the macOS VM an IPv6 path has
carried uploads more slowly than an IPv4 one
([Opportunities left](#opportunities-left)). All 160 ezvpn runs, 80 for each
client, were over IPv4 to the server's own address, before and after, and
none had to be taken again. The server's kernel refused no receive and its
per-client queues dropped nothing in any of them. Tailscale is not installed
on the Windows VM; on the macOS VM it is normally stopped and was started
for that client's rounds.

For these two columns the container that runs the quarter-hourly jobs on
`test1`'s host was shut down, and no run was started that would overlap one
of the host's scheduled backups. That took one pause of five minutes in the
macOS rounds and one of twenty-two in the Windows rounds, in place of the
pause around each quarter-hour that the Linux pair's columns took.

### macOS

**Downloads read the same on both versions.** The no-tunnel download read
1946 on every run, a cap on the way to the server rather than in the VM's
NAT, since the VM's host reads the same with neither in the way
([below](#macos-on-the-vms-host-optional)), and both versions read 1832 in
most runs (1744 at the lowest for v0.0.75, 1813 for v0.0.76), which looks
like the same cap less what the tunnel adds to each packet. So the column says only that both reach it. The server used more CPU
for the same rate on v0.0.76: 1.26 cores against 1.12 with one flow, where
every v0.0.76 run read above every v0.0.75 one, and 1.29 against 1.17 with
four. A Windows download, at three quarters of the rate, shows two hundredths
of a core between them.

**Uploads are where the macOS client has room, and the versions are close.**
A macOS client sends one datagram per UDP send and does not use the new
task. With one flow, uploads ranged from 666 to 988 for v0.0.75 and from 781
to 970 for v0.0.76, and v0.0.76 was ahead in five rounds of ten. With four
flows they ranged from 729 to 906 and from 859 to 925, v0.0.76 was ahead in
eight rounds of ten and its median is 6% higher. Eight of ten is what two
equal versions give about one time in nine, so ten rounds do not settle
whether that is a difference, and nothing was measured that would explain
one. The server is the busier end of a macOS upload for either version, at
about 1.9 cores on its two runtime workers.

Four flows carry no more than one in either direction, for ezvpn or for
Tailscale: the download is at the path's cap, and the upload's limit is in
the tunnel, not in TCP.

With four flows most runs retransmitted, and so did the path itself: the
no-tunnel four-flow downloads retransmitted in every run (275 to 648
segments). Eight of v0.0.75's ten four-flow downloads did (1076 to 4416
segments) and all ten of v0.0.76's (1 to 3928, fewer than v0.0.75 in seven
rounds); nine of ten four-flow uploads did for either version (up to 1221
and 596). Since the server's queues dropped nothing, the segments were lost
elsewhere; where was not traced. With one flow, 6 of the 40 ezvpn runs
retransmitted at all.

Tailscale ranged from 414 to 427 down and from 206 to 210 up with one flow,
and from 392 to 406 and from 207 to 211 with four.

### Windows

**No cell separates the versions.** With one flow, downloads ranged from
1319 to 1490 for v0.0.75 and from 1216 to 1462 for v0.0.76, uploads from
1615 to 1783 and from 1582 to 1811; v0.0.76 was ahead in five rounds of ten
on downloads and seven on uploads. With four flows, downloads ranged from
1217 to 1344 and from 1090 to 1278, uploads from 1588 to 1834 and from 1606
to 1752; v0.0.76 was ahead in three rounds of ten on downloads and four on
uploads. The medians are within 2.5% of each other in all four cells.
v0.0.76's slowest download was the slowest of its cell both times (1216 and
1090, where v0.0.75's were 1319 and 1217); one run in ten does not say
whether a v0.0.76 server's downloads to this client are less steady.

No download retransmitted for either version, and CPU is within four
hundredths of a core between them at both ends.

**Four flows carry less down than one.** Downloads read 8–9% lower with four
flows than with one for either version (about 1260 against 1375), on a path
whose own download gains 8% from them (2241 against 2080), and uploads read
the same with four as with one. The limit is in the tunnel in both
directions, and the download is the slower one, at 1.35 cores on the client.

### macOS on the VM's host (optional)

Not part of the version comparison: the Mac that hosts the macOS VM, as a
client of the same server on `test1`, measured on 2026-11-28 to see what the
VM costs. Three rounds, taken in turn as the other columns' are, with the
same two versions and the same flags, and no Tailscale row, since Tailscale
is not installed there. The client is an Apple M2 Max (12 cores, 32 GB,
macOS 27.2.1, iperf3 3.21) on 2.5 Gbit/s Ethernet in the server's own LAN,
with no NAT in between; it is a desktop in use, and its apps stayed open
during the rounds.

Mbit/s, down / up, medians of three rounds, beside the VM's medians of ten
from [the table above](#macos-and-windows-clients):

| | One flow | Four flows | VM, one flow | VM, four flows |
|---|---:|---:|---:|---:|
| No tunnel | 1946 / 2345 | 1946 / 2354 | 1946 / 2354 | 1946 / 2353 |
| ezvpn v0.0.75 | 1835 / 1131 | 1834 / 1230 | 1832 / 878 | 1831 / 857 |
| ezvpn v0.0.76 | 1828 / 1157 | 1834 / 1254 | 1832 / 892 | 1831 / 909 |

| | Flows | Retr (down / up) | CPU down (client / server) | CPU up (client / server) |
|---|---|---:|---:|---:|
| ezvpn v0.0.75 | one | 0 / 52 | 1.10 / 1.27 | 1.48 / 1.90 |
| ezvpn v0.0.76 | one | 526 / 0 | 1.31 / 1.35 | 1.39 / 1.89 |
| ezvpn v0.0.75 | four | 1876 / 589 | 1.09 / 1.35 | 1.43 / 1.91 |
| ezvpn v0.0.76 | four | 2084 / 299 | 1.35 / 1.42 | 1.49 / 1.92 |

All 24 ezvpn runs were over IPv4 to the server's own address, before and
after, and none had to be taken again; the server's kernel refused no
receive and its queues dropped nothing.

**Downloads read as they do on the VM.** The no-tunnel download reads 1946
here too, without the VM or its NAT, so that cap is on the way to the
server, and both versions read just under it, as on the VM.

**Uploads read 29–44% higher.** With one flow they ranged from 1131 to 1174
for v0.0.75 and from 829 to 1237 for v0.0.76 (829 in the first round, 1237
and 1157 after it); with four, from 1118 to 1267 and from 1210 to 1356. The
client used 1.4–1.5 cores where the VM's used 1.6, and four flows carry
about 8% more than one, where on the VM they carry none. The server used
1.89–1.92 cores, as it does for the VM's uploads, so with this client the
server's two runtime workers are the likely limit; it was not profiled.
Three rounds do not separate the versions: v0.0.76 was ahead in one round
of three with one flow and in two with four.

On a download v0.0.76's server used more CPU than v0.0.75's, as with the
VM, and here its client did too (1.31 cores against 1.10 with one flow),
which on the VM it did not; three rounds are too few to say more. Four-flow
downloads retransmitted in every run for either version (1203 to 6394
segments), and 5 of the 12 one-flow runs retransmitted at all.

## Opportunities left

What is known to be left on the table, with what is known about each. None
of it is scheduled work. Where a figure from the tables above is given it
was measured in those runs; the rest was not measured again, and its
mechanisms are described in [Architecture](Architecture.md), "Throughput
Design".

**macOS and iOS**

- **v0.0.74's upload.** A macOS upload read about 5% lower on v0.0.74
  than on v0.0.70 when the two were compared on 2026-11-26 (906 against 956,
  medians of 27 rounds with one flow), and v0.0.75 and v0.0.76 read 878 and
  892 [above](#macos-and-windows-clients). The release binaries of v0.0.71 to v0.0.73,
  taken in turn the same way, would say which release moved it. The server
  is at 1.9 cores of its two workers during one, so a change to what the
  server does per packet is as likely a place as the client.
- **The upload gains nothing from more flows.** Four flows carry what one
  does, about 0.9 Gbit/s on a path that carries 2.35, so the limit is in the
  tunnel. On the VM it is most likely the client's: the VM's host, as a
  client of the same server, carries 1.13–1.25 Gbit/s up at 1.4–1.5 cores,
  gains from four flows, and leaves the server at the same 1.9 cores
  ([above](#macos-on-the-vms-host-optional)). The server is then the likely
  next limit for a fast macOS client; that was not profiled.
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
- **A ceiling near 4 Gbit/s.** With the offload on, v0.0.76 reads the same
  with four flows as with one (3996 / 3992 against 3939 / 4015), where
  Tailscale gains 15–18% from the extra flows: the limit is in the tunnel,
  not in TCP. Each end uses 1.5–1.6 cores of its two runtime workers at that
  rate. Where the time goes now was not profiled; when the change was
  developed the receiving side had become the slower one.
- **Retransmits with several flows.** With four flows and the offload on,
  seven of ten v0.0.76 uploads and six of ten downloads retransmitted, where
  none and three of v0.0.75's did
  ([Results](#linux-pair-tx-udp-segmentation-on)). On downloads most of it
  is the server's queue for the client filling; on uploads it was put down
  to the receiving end's QUIC datagram buffer, and that was not measured
  again in these runs. One flow does not show it.
- **Little gained at default NIC settings.** Without the offload v0.0.76 is
  3–6% ahead of v0.0.75 where it is 13–31% ahead with it, at the same CPU.
  What bounds the tunnel there was not profiled; the send, which then
  segments each batch in the guest, is the likely place.
- **Worker count off these VMs.** Two runtime workers was chosen on guests
  that overcommit their host two to one. A dedicated machine, or a server
  with many clients, may want a different number; `TOKIO_WORKER_THREADS` is
  the knob.

**Windows**

- **Not profiled.** The Windows client moves about 1.4 Gbit/s down and 1.7
  up on a path that carries 2.1 and 2.37, at 1.37 and 1.15 cores. The
  download is the slower direction, and it reads 8% lower with four flows
  than with one, which points at the receive side (the driver, the datagram
  reader and one Wintun write per packet), but nothing is known yet about
  where its time goes.

## Reproducing

The scripts that took the tables above, rounds and checks included, are in
[`scripts/bench`](../scripts/bench/README.md). By hand, one run is this.

Start a server on one machine with `iperf3 -s` beside it, and a client on
the other (the README's quick start has both). Wait for
`ezvpn client status` to show a `Direct … (selected)` path in its
`Connection:` line, then from the client:

```bash
iperf3 -t 6 -O 1 -c <server VPN address>        # up
iperf3 -t 6 -O 1 -c <server VPN address> -R     # down
iperf3 -t 6 -O 1 -P 4 -c <server VPN address>   # four flows; -R for down
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
