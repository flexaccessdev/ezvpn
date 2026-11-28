# shellcheck shell=bash
# Sourced by the bench shell scripts: the rig's values, as rig.py loads them for the Python ones.
BENCH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$BENCH/../.." && pwd)
RIG_DIR=${EZVPN_BENCH_RIG:-${DEVTOOLS_DIR:-$REPO/../devtools}/bench/ezvpn}
[ -f "$RIG_DIR/rig.env" ] || { echo "no rig at $RIG_DIR/rig.env (set EZVPN_BENCH_RIG)" >&2; exit 1; }
. "$RIG_DIR/rig.env"
WORK=${EZVPN_BENCH_WORK:-$REPO/target/bench}
LINUX_DIR=${LINUX_DIR:-/home/debian/codes/staging-area/ezvpn-bench}
mkdir -p "$WORK/results"
