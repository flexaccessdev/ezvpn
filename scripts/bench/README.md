# Benchmark scripts

The scripts that produce the tables in [docs/Benchmarks.md](../../docs/Benchmarks.md). The method (rows in
turn, versions alternating by round, a restart per ezvpn run, the path checked before and after) is
described there; this is how to run it.

## The rig

The machines and their addresses are not in this repo. The scripts read them from a rig directory:
`$EZVPN_BENCH_RIG`, by default `../devtools/bench/ezvpn` next to this repo (`$DEVTOOLS_DIR` overrides
`../devtools`). It holds:

- `rig.env`: `SERVER_HOST`, `SERVER_IP`, `CLIENT_HOST`, `SERVER_TS_IP` (the server's Tailscale address),
  `MAC_HOST`, `WIN_HOST`, `ROUTER_PUBLIC_IP` (kept off the macOS and Windows clients' direct paths), and
  optionally `LINUX_DIR`, the staging directory on the Linux machines.
- `heavy-jobs.txt` (optional): scheduled jobs on the machines' host that no run may overlap.
- `host-check.sh` (optional): printed at the start of each round, such as the host's load.

Results go to `$EZVPN_BENCH_WORK/results`, by default `target/bench/results`.

## Staging

Build each version as a release binary on its own OS and name it `ezvpn-<label>` (`ezvpn-<label>.exe` on
Windows); the labels are what the scripts take. Then:

| Where | Directory | Files |
|---|---|---|
| server | `LINUX_DIR` | the binaries, the server key, `authorized_keys`, `vpn_server.toml` (network `10.77.0.0/24`) |
| Linux client | `LINUX_DIR` | the binaries, `client.key`, `server_id`, `cli.sh` |
| Mac | `~/codes/staging-area/ezvpn-bench` | the binaries, `client.key`, `server_id`, `mb.sh` |
| Windows | `C:\ci-workspaces\ezvpn-bench\run` | the binaries, `client.key`, `server_id`, `wb.ps1`, `iperf3.exe`, `wintun.dll` |

`server_id` is the server's id on one line. The server and the Linux client also need `iperf3`, `jq` and
`nstat`, the Mac a `macsandbox` tmux session, and Tailscale must be up for its rows.

## Running

```bash
# a column takes about 25 minutes for ten rounds; run it detached
setsid nohup scripts/bench/columns.sh linux v0.0.75 v0.0.76 10 > target/bench/results/columns.out 2>&1 < /dev/null &
setsid nohup scripts/bench/columns.sh clients v0.0.75 v0.0.76 10 >> target/bench/results/columns.out 2>&1 < /dev/null &

uv run --python 3.13 scripts/bench/sum.py v0.0.75 v0.0.76 linux-default linux-offload mac win
```

Run the Linux and client columns one after the other, not together: both use the same server. Progress is
in `<column>.log`, one JSON line per run in `<column>.jsonl`. A run whose path was not direct to the server,
before and after, is discarded and taken again.

| | |
|---|---|
| `columns.sh` | the columns, and the Linux pair's `tx-udp-segmentation` setting for each |
| `full.py` | the driver: rounds, rows, server restarts, server-side counters, path checks |
| `cli.sh`, `mb.sh`, `wb.ps1` (with `win-run.ps1`) | one run on the Linux, macOS and Windows client |
| `sum.py` | medians, ranges, per-round comparisons and checks, from the results |
| `rig.sh`, `rig.py` | load the rig |
