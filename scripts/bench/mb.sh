#!/bin/bash
# mb.sh ROW DIR FLOWS [SECS]: one benchmark run on the macOS client, printed as one JSON line.
# ROW is none (no tunnel), ts (Tailscale), or the suffix of an ezvpn-<ROW> binary here.
# SERVER_IP, SERVER_TS_IP and ROUTER_PUBLIC_IP come from the caller (full.py, from the rig).
set -u
export PATH=/opt/homebrew/bin:$PATH
V=$1; DIR=$2; P=$3; SECS=${4:-6}
B=$HOME/codes/staging-area/ezvpn-bench
ID=$(cat "$B/server_id")
R=""; [ "$DIR" = down ] && R="-R"

run_iperf() {  # host -> "Mbit/s retransmits"
  local out
  for attempt in 1 2 3; do
    out=$(iperf3 -J -t "$SECS" -O 1 -P "$P" -c "$1" $R 2>&1)
    if echo "$out" | grep -q '"sum_received"'; then
      local m r
      m=$(echo "$out" | /usr/bin/plutil -extract end.sum_received.bits_per_second raw -o - - | awk '{printf "%.1f", $1/1e6}')
      r=$(echo "$out" | /usr/bin/plutil -extract end.sum_sent.retransmits raw -o - - 2>/dev/null) || r=null
      case "$r" in ''|*[!0-9]*) r=null ;; esac
      echo "$m $r"
      return 0
    fi
    sleep 2
  done
  echo "iperf3 failed: $(echo "$out" | head -c 300)" >&2; return 1
}
cpu_secs() {  # cumulative CPU seconds of a pid, from ps's [[dd-]hh:]mm:ss.cc
  ps -o time= -p "$1" | awk '{ n=split($1,a,":"); s=0; for(i=1;i<=n;i++) s=s*60+a[i]; printf "%.2f", s }'
}
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }

case "$V" in
  none|ts)
    host=$SERVER_IP; [ "$V" = ts ] && host=$SERVER_TS_IP
    res=$(run_iperf $host) || exit 1
    set -- $res
    echo "{\"mbps\":$1,\"retr\":$2}"
    exit 0 ;;
esac

BIN=$B/ezvpn-$V
conn() { sudo "$BIN" client status --instance bench 2>/dev/null | sed -n 's/^Connection: *//p'; }
stop_client() {
  local i
  sudo "$BIN" client stop --instance bench >/dev/null 2>&1
  for i in $(seq 80); do pgrep -x "ezvpn-$V" >/dev/null || return 0; sleep 0.1; done
  echo "$(date -u +%FT%TZ) $V $DIR: still running 8 s after stop" >> "$B/term-retries.log"
  sudo kill -9 $(pgrep -x "ezvpn-$V") 2>/dev/null
}
pgrep -x "ezvpn-$V" >/dev/null && stop_client
sudo rm -f "$B/client.log"
# IPv6 and the router's public address are kept off the direct path, so every run is IPv4 to the server's own address.
sudo sh -c "RUST_LOG=warn,ezvpn=info nohup '$BIN' client start -n $ID --auth-key-file '$B/client.key' --instance bench \
  --exclude-direct-path 100.64.0.0/10 --exclude-direct-path ::/0 --exclude-direct-path $ROUTER_PUBLIC_IP/32 \
  > '$B/client.log' 2>&1 &"
trap stop_client EXIT
i=0
until ping -c1 -t1 10.77.0.1 >/dev/null 2>&1; do
  sleep 0.2; i=$((i+1)); [ $i -ge 60 ] && { echo "no ping: $(tail -3 "$B/client.log")" >&2; exit 1; }
done
sleep 5
pid=$(pgrep -x "ezvpn-$V" | head -1)
path=$(conn)
c0=$(cpu_secs $pid); t0=$(now)
res=$(run_iperf 10.77.0.1) || exit 1
c1=$(cpu_secs $pid); t1=$(now)
set -- $res
cpu=$(echo "$c0 $c1 $t0 $t1" | awk '{printf "%.2f", ($2-$1)/($4-$3)}')
secs=$(echo "$t0 $t1" | awk '{printf "%.3f", $2-$1}')
ver=$(grep -m1 -o 'ezvpn v[0-9.]*' "$B/client.log")
echo "{\"mbps\":$1,\"retr\":$2,\"secs\":$secs,\"cpu_client\":$cpu,\"path\":\"$path\",\"path_after\":\"$(conn)\",\"version\":\"$ver\"}"
