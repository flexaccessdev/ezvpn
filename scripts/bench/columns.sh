#!/usr/bin/env bash
# columns.sh linux|mac|win|clients|mac-host A B [ROUNDS]: the columns of docs/Benchmarks.md, logged to results/<column>.log.
#   linux    both Linux columns: ROUNDS at default NIC settings, then ROUNDS with tx-udp-segmentation on
#            (on both guests; the setting is put back off after)
#   mac|win  one client column against the server
#   clients  the Mac column, then the Windows column
#   mac-host the optional column of the macOS VM's host Mac, without a Tailscale row (not part of clients)
# Long: run it detached (see README.md). results/<column>.done marks a finished column.
set -u
. "$(dirname "$0")/rig.sh"
what=$1; A=$2; B=$3; R=${4:-10}
cd "$BENCH" || exit 1

nic() { for h in "$SERVER_HOST" "$CLIENT_HOST"; do ssh "$h" "sudo /usr/sbin/ethtool -K eth0 tx-udp-segmentation $1; /usr/sbin/ethtool -k eth0 | grep tx-udp-segmentation"; done; }
col() {  # col COLUMN: one column of the driver
  uv run --python 3.13 full.py "$1" "$A" "$B" "$R" >> "$WORK/results/$1.log" 2>&1
  echo finished > "$WORK/results/$1.done"
}

case $what in
  linux)
    ssh "$SERVER_HOST" "sudo systemctl stop ezvpn-bench-srv 2>/dev/null"; ssh "$CLIENT_HOST" "sudo systemctl stop ezvpn-bench-cli 2>/dev/null"
    nic off > "$WORK/results/linux-default.log"; col linux-default
    nic on > "$WORK/results/linux-offload.log"; col linux-offload
    nic off >> "$WORK/results/linux-offload.log" ;;
  mac|win|mac-host) : > "$WORK/results/$what.log"; col "$what" ;;
  clients) : > "$WORK/results/mac.log"; col mac; : > "$WORK/results/win.log"; col win ;;
  *) echo "usage: $0 linux|mac|win|clients|mac-host A B [ROUNDS]" >&2; exit 2 ;;
esac
