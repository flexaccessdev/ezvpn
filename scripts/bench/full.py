#!/usr/bin/env python3
"""full.py COLUMN A B [ROUNDS] [FIRST]: benchmark rounds for one column of docs/Benchmarks.md.

COLUMN is linux-default, linux-offload, mac or win; A and B are the labels of the two staged ezvpn
binaries (ezvpn-A, ezvpn-B). Rows are taken in turn, round after round: no tunnel, Tailscale (not on
Windows), then the two ezvpn versions in an order that alternates by round. Each row is four runs: one
flow down and up, four flows down and up. Server and client are restarted for every ezvpn run.
One JSON line per run goes to results/<COLUMN>.jsonl in the work directory.
"""
import json, os, re, subprocess, sys, time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from rig import RIG, RIG_DIR, WORK, LINUX_DIR as D

B = os.path.dirname(os.path.abspath(__file__))
SECS = 6
col, VERSIONS = sys.argv[1], sys.argv[2:4]
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 10
first = int(sys.argv[5]) if len(sys.argv) > 5 else 1
OUT = f"{WORK}/results/{col}.jsonl"
os.makedirs(f"{WORK}/results", exist_ok=True)
# Seconds a run may take from its start (server restart included) to the end of its iperf3.
BUDGET = {"linux-default": 28, "linux-offload": 28, "mac": 36, "win": 45}[col]
SRV, CLI = RIG["SERVER_HOST"], RIG["CLIENT_HOST"]
NET = f"SERVER_IP={RIG['SERVER_IP']} SERVER_TS_IP={RIG['SERVER_TS_IP']}"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ssh(host, cmd, timeout=180):
    p = subprocess.run(["ssh", "-o", "ConnectTimeout=15", host, cmd], capture_output=True, text=True, timeout=timeout)
    return (p.stdout + p.stderr).strip()


def load_heavy():
    """The rig's heavy scheduled jobs: (timezone, HH:MM, typical minutes, weekday or None, name)."""
    p = f"{RIG_DIR}/heavy-jobs.txt"
    if not os.path.exists(p):
        return []
    jobs = []
    for line in open(p):
        f = line.split("#", 1)[0].split(None, 4)
        if f:
            jobs.append((ZoneInfo(f[0]), f[1], int(f[2]), None if f[3] == "*" else int(f[3]), f[4].strip() if len(f) > 4 else f[1]))
    return jobs


HEAVY = load_heavy()


def heavy_windows(now):
    """[start - 60 s, start + 1.25 x typical + 120 s) of every heavy job within a day of now, as epoch seconds."""
    out = []
    for tz, hhmm, mins, wday, name in HEAVY:
        h, m = map(int, hhmm.split(":"))
        today = datetime.fromtimestamp(now, tz).replace(hour=h, minute=m, second=0, microsecond=0)
        for delta in (-1, 0, 1):
            t = today + timedelta(days=delta)
            if wday is None or t.weekday() == wday:
                out.append((t.timestamp() - 60, t.timestamp() + mins * 75 + 120, f"{hhmm} ({name})"))
    return out


def wait_window(dur):
    """Keep a run of dur seconds clear of the host's heavy scheduled jobs."""
    while True:
        now = time.time()
        hit = [w for w in heavy_windows(now) if now < w[1] and now + dur + 5 > w[0]]
        if not hit:
            return
        end = max(w[1] for w in hit)
        log(f"waiting {end - now:.0f} s for the scheduled job at {hit[0][2]}")
        time.sleep(end - now)


def host_check(rnd):
    """The rig's host-check.sh (host load, the state of anything stopped for the benchmark), if it has one."""
    p = f"{RIG_DIR}/host-check.sh"
    if not os.path.exists(p):
        return
    try:
        out = subprocess.run([p], capture_output=True, text=True, timeout=30).stdout.strip()
    except subprocess.TimeoutExpired:
        out = "host-check timed out"
    log(f"round {rnd} host: {out}")


def srv_stop():
    ssh(SRV, "sudo systemctl stop ezvpn-bench-srv 2>/dev/null; sudo systemctl reset-failed ezvpn-bench-srv 2>/dev/null; true")


def cli_stop():
    if col.startswith("linux"):
        ssh(CLI, "sudo systemctl stop ezvpn-bench-cli 2>/dev/null; sudo systemctl reset-failed ezvpn-bench-cli 2>/dev/null; true")


def srv_start(v):
    srv_stop()
    ssh(SRV, f"sudo rm -f {D}/server.log; sudo systemd-run -q --unit ezvpn-bench-srv --working-directory={D} "
        f"-p StandardOutput=append:{D}/server.log -p StandardError=append:{D}/server.log "
        f"--setenv=RUST_LOG=warn,ezvpn=info {D}/ezvpn-{v} server start -c vpn_server.toml")
    time.sleep(2)


def srv_snap(v, status=False):
    """Server process CPU ticks, the kernel's refused UDP receives, and (after a run) the status counters."""
    cmd = ("p=$(systemctl show -p MainPID --value ezvpn-bench-srv); awk '{print $14+$15}' /proc/$p/stat; "
           "nstat -az UdpRcvbufErrors Udp6RcvbufErrors | awk 'NR>1{s+=$2} END{print s+0}'; "
           f"sudo grep -m1 -o 'ezvpn v[0-9.]*' {D}/server.log")
    if status:
        cmd += f"; sudo {D}/ezvpn-{v} server status 2>&1 | grep -i -o 'dropped_full[^,]*' | head -3 | tr '\\n' ' '"
    lines = ssh(SRV, cmd).splitlines()
    try:
        return {"ticks": int(lines[0]), "rcvbuf": int(lines[1]), "version": lines[2] if len(lines) > 2 else "",
                "status": lines[3] if len(lines) > 3 else ""}
    except (ValueError, IndexError):
        return {"error": " | ".join(lines)[:300]}


def client(row, d, flows):
    if col.startswith("linux"):
        return ssh(CLI, f"{NET} {D}/cli.sh {row} {d} {flows} {SECS}")
    if col == "mac":
        job = "ezb"
        env = f"{NET} ROUTER_PUBLIC_IP={RIG['ROUTER_PUBLIC_IP']}"
        return ssh(RIG["MAC_HOST"], f'/opt/homebrew/bin/tmux new-window -d -t macsandbox "{env} ~/codes/staging-area/ezvpn-bench/mb.sh {row} {d} {flows} {SECS} '
                   f'> /tmp/{job}.log 2>&1; echo \\$? > /tmp/{job}.status; /opt/homebrew/bin/tmux wait-for -S {job}-done" \\; wait-for {job}-done; cat /tmp/{job}.log')
    p = subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-File", f"{B}/win-run.ps1", RIG["WIN_HOST"], row, d, str(flows), str(SECS),
                        RIG["SERVER_IP"], RIG["ROUTER_PUBLIC_IP"]], capture_output=True, text=True, timeout=240)
    return (p.stdout + p.stderr).replace("\r", "").strip()


def selected(conn):
    m = re.search(r"((?:Direct|Relay) \S+) \(selected\)", conn or "")
    return m.group(1) if m else (conn or "")[:80]


def one(rnd, row, flows, d):
    ez = row in VERSIONS
    for attempt in (1, 2, 3):
        wait_window(BUDGET if ez else SECS + 6)
        rec = {"col": col, "round": rnd, "row": row, "flows": flows, "dir": d, "at": time.strftime("%H:%M:%S")}
        s0 = None
        if ez:
            srv_start(row)
            s0 = srv_snap(row)
        try:
            out = client(row, d, flows)
        except subprocess.TimeoutExpired:
            out = "timeout"
        line = next((l for l in reversed(out.splitlines()) if l.startswith("{")), None)
        try:
            rec.update(json.loads(line))
        except (TypeError, ValueError):
            rec["error"] = out[-400:]
        if ez:
            s1 = srv_snap(row, status=True)
            if "error" in s0 or "error" in s1:
                rec["srv_error"] = s0.get("error") or s1.get("error")
            else:
                rec["srv_rcvbuf_err"] = s1["rcvbuf"] - s0["rcvbuf"]
                rec["srv_version"] = s1["version"]
                rec["srv_status"] = s1["status"]
                if "secs" in rec:
                    rec["cpu_server"] = round((s1["ticks"] - s0["ticks"]) / 100 / rec["secs"], 3)
            cli_stop()
            srv_stop()
            if "error" not in rec:
                rec["path"], rec["path_after"] = selected(rec.get("path")), selected(rec.get("path_after"))
                want = "Direct " if col.startswith("linux") else f"Direct {RIG['SERVER_IP']}:"
                if not (rec["path"].startswith(want) and rec["path_after"].startswith(want)):
                    rec["discard"] = "path"
        if "error" in rec:
            rec["discard"] = "error"
        with open(OUT, "a") as f:
            f.write(json.dumps(rec) + "\n")
        if "discard" not in rec:
            extra = f" cpu {rec['cpu_client']:.2f}/{rec.get('cpu_server', 0):.2f} {rec['path']}" if ez else ""
            log(f"r{rnd} {row} P{flows} {d}: {rec['mbps']:.0f} retr={rec.get('retr')}{extra}")
            return
        log(f"r{rnd} {row} P{flows} {d}: DISCARDED ({rec['discard']}) try {attempt}: {json.dumps(rec)[:500]}")
        time.sleep(3)
    log(f"r{rnd} {row} P{flows} {d}: GAVE UP")


ssh(SRV, "sudo systemctl is-active -q iperf3-bench || sudo systemd-run -q --unit iperf3-bench /usr/bin/iperf3 -s")
rows = ["none"] + ([] if col == "win" else ["ts"])
for rnd in range(first, rounds + 1):
    order = VERSIONS if rnd % 2 else VERSIONS[::-1]
    log(f"round {rnd}: {' '.join(rows + order)}")
    host_check(rnd)
    for row in rows + order:
        for flows in (1, 4):
            for d in ("down", "up"):
                one(rnd, row, flows, d)
srv_stop()
log("done")
