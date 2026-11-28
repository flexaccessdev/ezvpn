"""The benchmark rig's values, for full.py and sum.py; rig.sh is the same for the shell scripts.

The rig (hosts, addresses, the host's scheduled jobs) is not in this public repo: it is read from
$EZVPN_BENCH_RIG, by default ../devtools/bench/ezvpn next to the repo ($DEVTOOLS_DIR overrides
../devtools). Results go to $EZVPN_BENCH_WORK/results, by default target/bench/results.
"""
import os

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RIG_DIR = os.environ.get("EZVPN_BENCH_RIG") or os.path.join(
    os.environ.get("DEVTOOLS_DIR") or os.path.join(REPO, "..", "devtools"), "bench", "ezvpn")
WORK = os.environ.get("EZVPN_BENCH_WORK") or os.path.join(REPO, "target", "bench")


def _load():
    p = os.path.join(RIG_DIR, "rig.env")
    if not os.path.exists(p):
        raise SystemExit(f"no rig at {p} (set EZVPN_BENCH_RIG)")
    out = {}
    for line in open(p):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


RIG = _load()
LINUX_DIR = RIG.get("LINUX_DIR", "/home/debian/codes/staging-area/ezvpn-bench")
