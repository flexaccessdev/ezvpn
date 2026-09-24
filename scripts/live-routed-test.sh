#!/usr/bin/env bash
# Live test of routed traffic: a client reaching a LAN host *behind* the
# server, not just the server's own VPN address.
#
# Traffic the server forwards takes a different kernel path into the TUN than
# traffic it generates itself: it arrives GRO'd from a NIC, and the kernel's
# virtio_net_hdr.hdr_len then covers payload as well as headers. Tests against
# the server's own address never exercise that path.
#
# Topology (all routing, no NAT; the driving host is left alone):
#
#   client host ── ezvpn ── server host ── veth (GRO on) ── netns "ezlan"
#   10.77.0.x                10.77.0.1      10.99.0.1          10.99.0.2 (iperf3)
#
# The netns side has TSO/GSO off, so wire-sized segments cross the veth and
# are GRO'd on the host side, as they would be arriving from a real NIC.
#
# Usage: scripts/live-routed-test.sh <ezvpn-binary>
#
# Environment:
#   SERVER_HOST / CLIENT_HOST  ssh targets (default debian@10.22.40.61 / .62)
#   SSH_KEY                    ssh identity (default ~/.ssh/id_rsa_andrewhomelab)
#   SERVER_KEY                 server secret key on the server host
#   AUTHORIZED_KEYS            authorized_keys on the server host
#   CLIENT_AUTH_KEY            client key file on the client host
#   SERVER_NODE_ID             server EndpointId (default: derived from SERVER_KEY)
#   DURATION                   seconds per iperf3 run (default 8)
#
# The server host must not already run an ezvpn server (single instance).
# Exits non-zero when routed reverse (LAN host -> client) throughput is below
# half of routed forward throughput.
set -euo pipefail

BIN=${1:?usage: $0 <ezvpn-binary>}
SERVER_HOST=${SERVER_HOST:-debian@10.22.40.61}
CLIENT_HOST=${CLIENT_HOST:-debian@10.22.40.62}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_rsa_andrewhomelab}
SERVER_KEY=${SERVER_KEY:-codes/staging-area/ezvpn-bench/vpn-server.key}
AUTHORIZED_KEYS=${AUTHORIZED_KEYS:-codes/staging-area/ezvpn-bench/authorized_keys}
CLIENT_AUTH_KEY=${CLIENT_AUTH_KEY:-codes/staging-area/ezvpn-bench/client.key}
DURATION=${DURATION:-8}

DIR=codes/staging-area/ezvpn-routed
VPN_NET=10.77.0.0/24
SERVER_VPN_IP=10.77.0.1
LAN_NET=10.99.0.0/24
LAN_HOST_IP=10.99.0.1
LAN_PEER_IP=10.99.0.2
UNIT=ezvpn-routed

ssh_s() { ssh -o BatchMode=yes -i "$SSH_KEY" "$SERVER_HOST" "$@"; }
ssh_c() { ssh -o BatchMode=yes -i "$SSH_KEY" "$CLIENT_HOST" "$@"; }

cleanup() {
    set +e
    ssh_c "sudo systemctl stop $UNIT 2>/dev/null; sudo systemctl reset-failed $UNIT 2>/dev/null"
    ssh_s "sudo systemctl stop $UNIT 2>/dev/null; sudo systemctl reset-failed $UNIT 2>/dev/null
        sudo ip netns pids ezlan 2>/dev/null | xargs -r sudo kill
        sudo ip netns del ezlan 2>/dev/null
        [ -f ~/$DIR/iperf.pid ] && kill \$(cat ~/$DIR/iperf.pid) && rm -f ~/$DIR/iperf.pid
        if [ -f ~/$DIR/ip_forward.saved ]; then
            sudo tee /proc/sys/net/ipv4/ip_forward < ~/$DIR/ip_forward.saved >/dev/null
            rm -f ~/$DIR/ip_forward.saved
        fi"
}
trap cleanup EXIT

echo "== staging $BIN"
for h in ssh_s ssh_c; do
    $h "mkdir -p ~/$DIR && rm -f ~/$DIR/ezvpn"
done
scp -q -i "$SSH_KEY" "$BIN" "$SERVER_HOST:$DIR/ezvpn"
scp -q -i "$SSH_KEY" "$BIN" "$CLIENT_HOST:$DIR/ezvpn"

if [ -z "${SERVER_NODE_ID:-}" ]; then
    SERVER_NODE_ID=$(ssh_s "~/$DIR/ezvpn show-server-id -s ~/$SERVER_KEY --json" | jq -r '.. | strings | select(test("^[0-9a-f]{64}$"))' | head -1)
fi
echo "server node id: $SERVER_NODE_ID"

echo "== server: LAN netns + ezvpn server"
ssh_s "set -e
    cd ~/$DIR
    if sudo pgrep -x -r R,S,D ezvpn >/dev/null; then echo 'an ezvpn process is already running on the server host' >&2; exit 1; fi
    cat > server.toml <<EOF
role = \"vpnserver\"
[network]
network = \"$VPN_NET\"
[auth]
authorized_keys_file = \"\$HOME/$AUTHORIZED_KEYS\"
[iroh]
secret_file = \"\$HOME/$SERVER_KEY\"
EOF
    cat /proc/sys/net/ipv4/ip_forward > ip_forward.saved
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
    sudo ip netns add ezlan
    sudo ip link add ezlan-host type veth peer name ezlan-peer
    sudo ip link set ezlan-peer netns ezlan
    sudo ip addr add $LAN_HOST_IP/24 dev ezlan-host
    sudo ip link set ezlan-host up
    sudo /usr/sbin/ethtool -K ezlan-host gro on
    sudo ip netns exec ezlan ip link set lo up
    sudo ip netns exec ezlan ip addr add $LAN_PEER_IP/24 dev ezlan-peer
    sudo ip netns exec ezlan ip link set ezlan-peer up
    sudo ip netns exec ezlan /usr/sbin/ethtool -K ezlan-peer sg off tso off gso off
    sudo ip netns exec ezlan ip route add default via $LAN_HOST_IP
    sudo ip netns exec ezlan iperf3 -s -D -p 5301
    iperf3 -s -D -p 5302 -I \$HOME/$DIR/iperf.pid
    sudo systemd-run --quiet --unit $UNIT --working-directory=\$HOME/$DIR \
        -p StandardOutput=file:\$HOME/$DIR/server.log -p StandardError=file:\$HOME/$DIR/server.log \
        --setenv=RUST_LOG=warn,ezvpn=info ./ezvpn server start -c server.toml"

echo "== client: ezvpn client routing $LAN_NET"
ssh_c "set -e
    cd ~/$DIR
    sudo systemd-run --quiet --unit $UNIT --working-directory=\$HOME/$DIR \
        -p StandardOutput=file:\$HOME/$DIR/client.log -p StandardError=file:\$HOME/$DIR/client.log \
        --setenv=RUST_LOG=warn,ezvpn=info ./ezvpn client start --no-auto-reconnect \
        -n $SERVER_NODE_ID --auth-key-file \$HOME/$CLIENT_AUTH_KEY --route $LAN_NET
    for i in \$(seq 60); do
        ping -c1 -W1 $LAN_PEER_IP >/dev/null 2>&1 && exit 0
        sleep 1
    done
    echo 'LAN host never became reachable through the tunnel' >&2
    tail -20 client.log >&2
    exit 1"

# iperf3 from the client; prints "<Mbit/s received> <sender retransmits>".
run_iperf() {
    ssh_c "iperf3 -J -t $DURATION -c $*" |
        jq -r '"\(.end.sum_received.bits_per_second / 1e6 | floor) \(.end.sum_sent.retransmits // 0)"'
}

printf '%-36s %10s %8s\n' "direction" "Mbit/s" "retrans"
declare -A mbps
for case in "server_forward:$SERVER_VPN_IP -p 5302" "server_reverse:$SERVER_VPN_IP -p 5302 -R" \
            "routed_forward:$LAN_PEER_IP -p 5301" "routed_reverse:$LAN_PEER_IP -p 5301 -R"; do
    name=${case%%:*}
    read -r rate retrans < <(run_iperf "${case#*:}")
    mbps[$name]=$rate
    printf '%-36s %10s %8s\n' "$name" "$rate" "$retrans"
done

if (( mbps[routed_reverse] * 2 < mbps[routed_forward] )); then
    echo "FAIL: routed reverse ${mbps[routed_reverse]} Mbit/s is under half of routed forward ${mbps[routed_forward]} Mbit/s"
    exit 1
fi
echo "PASS"
