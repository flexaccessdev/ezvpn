# Roadmap

Work that is planned but not scheduled. Each entry says what the problem is
today and what the change would be.

## Benchmarks: a row with several TCP flows

[Benchmarks](Benchmarks.md) measures one TCP flow per run and compares two
ezvpn versions, with Tailscale beside them as a control for the host. A limit
that every version has, and that shows with several flows, passes it unseen.

One did. In v0.0.74 one task on the sending side built, encrypted and sent
every packet of a connection, and it was saturated. Between the two Linux
guests on 2026-11-27 that version read:

| Mbit/s, down / up | ezvpn v0.0.74 | Tailscale |
|---|---|---|
| One TCP flow | 3440 / 3075 | 3379 / 3388 |
| Four TCP flows | 3454 / 3076 | 3850 / 3686 |

With one flow the two look level on downloads, and Tailscale's throughput
moves by about 15% from one day to the next, so the 10% on uploads read as
noise. With four flows Tailscale, which spreads its work over threads, is
plainly ahead, and ezvpn does not move at all. The second is the sign of a
ceiling in ezvpn. So is an upload that stays below the download on every
run, which the one-flow table already showed.

The change:

- Add a four-flow row (`iperf3 -P 4`) to each column, measured in the same
  rounds as the one-flow rows, for ezvpn and for Tailscale.
- On that row read Tailscale as a comparison too, not only as a control: a
  tunnel that gains nothing from more flows where Tailscale gains is worth a
  profile of its tasks, whatever the two read on one flow.
- Keep it to iperf3. A file download or upload is not to be added: it measures
  the disk, the page cache and the copying tool along with the tunnel, and
  the row would move with them.
