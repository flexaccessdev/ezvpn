#!/bin/bash
# cli.sh ROW DIR FLOWS [SECS]: one benchmark run on the Linux client, printed as one JSON line.
# ROW is none (no tunnel), ts (Tailscale), or the suffix of an ezvpn-<ROW> binary here.
# SERVER_IP and SERVER_TS_IP come from the caller (full.py, from the rig).
# An ezvpn client is left running, so that the caller can read the server's counters before it stops both.
set -u
ROW=$1; DIR=$2; P=$3; SECS=${4:-6}
D=$(cd "$(dirname "$0")" && pwd); cd "$D" || exit 1
R=; [ "$DIR" = down ] && R=-R

iperf() {  # host -> iperf3 JSON, three tries
  local out a
  for a in 1 2 3; do
    out=$(iperf3 -J -t "$SECS" -O 1 -P "$P" -c "$1" $R 2>&1)
    if jq -e '.end.sum_received.bits_per_second' >/dev/null 2>&1 <<<"$out"; then echo "$out"; return 0; fi
    sleep 2
  done
  echo "iperf3 failed: $(head -c 300 <<<"$out")" >&2; return 1
}
rcvbuf() { nstat -az UdpRcvbufErrors Udp6RcvbufErrors | awk 'NR>1{s+=$2} END{print s+0}'; }

case $ROW in
  none|ts)
    host=$SERVER_IP; [ "$ROW" = ts ] && host=$SERVER_TS_IP
    out=$(iperf $host) || exit 1
    jq -c '{mbps: (.end.sum_received.bits_per_second/1e6), retr: .end.sum_sent.retransmits}' <<<"$out"
    exit 0 ;;
esac

BIN=$D/ezvpn-$ROW
sudo systemctl stop ezvpn-bench-cli 2>/dev/null; sudo systemctl reset-failed ezvpn-bench-cli 2>/dev/null
sudo rm -f client.log
sudo systemd-run -q --unit ezvpn-bench-cli --working-directory="$D" \
  -p StandardOutput=append:"$D/client.log" -p StandardError=append:"$D/client.log" --setenv=RUST_LOG=warn,ezvpn=info \
  "$BIN" client start -n "$(cat server_id)" --auth-key-file client.key \
  --exclude-direct-path 100.64.0.0/10 --exclude-direct-path fd7a:115c:a1e0::/48
ok=0
for i in $(seq 100); do ping -c1 -W1 10.77.0.1 >/dev/null 2>&1 && { ok=1; break; }; sleep 0.2; done
[ $ok = 1 ] || { echo "no ping: $(sudo tail -3 client.log)" >&2; exit 1; }
sleep 5
conn() { sudo "$BIN" client status 2>/dev/null | sed -n 's/^Connection: *//p'; }
pid=$(systemctl show -p MainPID --value ezvpn-bench-cli)
ticks() { awk '{print $14+$15}' /proc/$pid/stat; }
p0=$(conn); e0=$(rcvbuf); c0=$(ticks); t0=$(date +%s.%N)
out=$(iperf 10.77.0.1) || exit 1
c1=$(ticks); t1=$(date +%s.%N); e1=$(rcvbuf); p1=$(conn)
ver=$(sudo grep -m1 -o 'ezvpn v[0-9.]*' client.log)
jq -c --arg p0 "$p0" --arg p1 "$p1" --arg ver "$ver" --argjson c0 "$c0" --argjson c1 "$c1" \
  --argjson t0 "$t0" --argjson t1 "$t1" --argjson e0 "$e0" --argjson e1 "$e1" \
  '{mbps: (.end.sum_received.bits_per_second/1e6), retr: .end.sum_sent.retransmits, secs: ($t1-$t0),
    cpu_client: (($c1-$c0)/100/($t1-$t0)), cli_rcvbuf_err: ($e1-$e0), path: $p0, path_after: $p1, version: $ver}' <<<"$out"
