#!/usr/bin/env python3
"""sum.py A B COLUMN...: medians, ranges and per-round comparisons of ezvpn-A and ezvpn-B from results/<COLUMN>.jsonl."""
import json, os, statistics, sys
from collections import Counter, defaultdict

from rig import WORK

A, B = sys.argv[1:3]
NAMES = {"none": "No tunnel", "ts": "Tailscale", A: f"ezvpn {A}", B: f"ezvpn {B}"}


def med(xs):
    return statistics.median(xs) if xs else float("nan")


for col in sys.argv[3:]:
    recs = [json.loads(l) for l in open(f"{WORK}/results/{col}.jsonl")]
    good = [r for r in recs if "discard" not in r]
    bad = [r for r in recs if "discard" in r]
    by = defaultdict(dict)
    for r in good:
        by[(r["row"], r["flows"], r["dir"])][r["round"]] = r
    rounds = sorted({r["round"] for r in good})
    print(f"\n===== {col}: rounds {rounds[0]}-{rounds[-1]}, {len(good)} runs kept, {len(bad)} discarded")
    for r in bad:
        print("  discarded:", r["round"], r["row"], r["flows"], r["dir"], r["discard"], (r.get("error") or r.get("path", ""))[:120])
    for flows in (1, 4):
        print(f"--- {flows} flow(s): median down / up | range down | range up | retr d/u | cpu down cli/srv | cpu up cli/srv | n")
        for row in NAMES:
            d, u = by.get((row, flows, "down"), {}), by.get((row, flows, "up"), {})
            if not d and not u:
                continue
            md, mu = [x["mbps"] for x in d.values()], [x["mbps"] for x in u.values()]
            line = f"{NAMES[row]:14} {med(md):6.0f} / {med(mu):6.0f} | {min(md):.0f}-{max(md):.0f} | {min(mu):.0f}-{max(mu):.0f}"
            rd = [x["retr"] for x in d.values() if x.get("retr") is not None]
            ru = [x["retr"] for x in u.values() if x.get("retr") is not None]
            line += f" | {med(rd):.0f} / {med(ru):.0f}"
            if row in (A, B):
                for runs in (d, u):
                    cc = [x["cpu_client"] for x in runs.values()]
                    cs = [x["cpu_server"] for x in runs.values() if "cpu_server" in x]
                    line += f" | {med(cc):.2f} / {med(cs):.2f}"
            print(line, f"| {len(md)},{len(mu)}")
        for d in ("down", "up"):
            a, b = by.get((A, flows, d), {}), by.get((B, flows, d), {})
            both = sorted(set(a) & set(b))
            if both:
                wins = sum(b[r]["mbps"] > a[r]["mbps"] for r in both)
                print(f"    {d}: {B} ahead in {wins} of {len(both)}; {A} {[round(a[r]['mbps']) for r in both]}  {B} {[round(b[r]['mbps']) for r in both]}")
            t = by.get(("ts", flows, d), {})
            if t:
                print(f"    {d}: tailscale {[round(t[r]['mbps']) for r in sorted(t)]}")
            n = by.get(("none", flows, d), {})
            if n:
                print(f"    {d}: none {[round(n[r]['mbps']) for r in sorted(n)]}")
    ez = [r for r in good if r["row"] in (A, B)]
    print("checks:", "versions", dict(Counter((r["row"], r.get("version"), r.get("srv_version")) for r in ez)))
    print("  rcvbuf errors: server", sum(r.get("srv_rcvbuf_err", 0) for r in ez), "client", sum(r.get("cli_rcvbuf_err", 0) for r in ez),
          "| server status:", dict(Counter(r.get("srv_status", "?") for r in ez)), "| srv errors:", sum("srv_error" in r for r in ez))
    fam = Counter(("v6" if "[" in r["path"] else "v4") + ("" if r["path"].split(":")[0] == r["path_after"].split(":")[0] else " changed") for r in ez)
    print("  paths:", dict(fam), "| retransmitting ezvpn runs:", sum(1 for r in ez if r.get("retr")), "of", len(ez))
    for flows in (1, 4):
        for d in ("down", "up"):
            for row in (A, B):
                rr = sorted(x["retr"] for x in by.get((row, flows, d), {}).values() if x.get("retr") is not None)
                if any(rr):
                    print(f"  retr {row} P{flows} {d}: {rr}")
