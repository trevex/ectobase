#!/usr/bin/env bash
# env/ha-smoke.sh — HA (pinned-maps) smoke test for the XDP datapath.
#
# Proves the pinned-maps HA property: with `--pin-dir`, the eBPF programs + maps are PINNED, so the datapath
# stays kernel-resident and keeps forwarding even after the control-plane process is KILLED; a
# restarted control plane re-ADOPTS the pinned CONNTRACK without re-attaching.
#
# Topology (minimal): guesta(10.0.0.5) - hypa(uA) <-> br-ul <-> hypb(uB) - guestb(10.0.0.6)
#
# Usage:  ./env/ha-smoke.sh run        (up + ha-test + down, cleanup on exit)
#         ./env/ha-smoke.sh up|down
set -euo pipefail

BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/flowplane"
PIDFILE="${TMPDIR:-/tmp}/xdp-ha-pids"
MARK="xdp-ha"
# bpffs must live OUTSIDE /sys: `ip netns exec` remounts a fresh /sys, shadowing a bpffs at
# /sys/fs/bpf. A bpffs under /run is inherited (slave mount) into the netns, so pinning works there.
BPFFS="/run/xdp-bpf"
PIN_A="$BPFFS/uA"
PIN_B="$BPFFS/uB"

TCPDUMP=""
command -v tcpdump &>/dev/null && TCPDUMP="$(command -v tcpdump)"

die() { echo "ERROR: $*" >&2; exit 1; }

cmd_up() {
    [[ -x "$BIN" ]] || die "binary not found at $BIN — run: cargo build -p flowplane"
    # bpffs must be mounted (under /run so it survives `ip netns exec`'s /sys remount).
    sudo mkdir -p "$BPFFS"
    mountpoint -q "$BPFFS" || sudo mount -t bpf bpf "$BPFFS"
    sudo rm -rf "$PIN_A" "$PIN_B" 2>/dev/null || true

    sudo ip link add br-ul type bridge 2>/dev/null || true
    sudo ip link set br-ul up
    sudo ip link set br-ul type bridge mcast_snooping 0
    for ns in hypa hypb guesta guestb; do
        sudo ip netns add "$ns" 2>/dev/null || true
        sudo ip netns exec "$ns" ip link set lo up
    done

    # hypa uplink + guesta
    sudo ip netns exec hypa ip link show uA &>/dev/null || sudo ip link add uA netns hypa type veth peer name uA-br
    sudo ip link set uA-br master br-ul 2>/dev/null || true; sudo ip link set uA-br up
    sudo ip netns exec hypa ip link set uA up
    sudo ip netns exec hypa ip -6 addr add fd00::1/64 dev uA nodad 2>/dev/null || true
    sudo ip netns exec hypa ip link show gA-h &>/dev/null || sudo ip link add gA-h netns hypa type veth peer name gA netns guesta
    sudo ip netns exec hypa ip link set gA-h up; sudo ip netns exec guesta ip link set gA up
    sudo ip netns exec guesta ip addr add 10.0.0.5/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add 10.0.0.1/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add default via 10.0.0.1 2>/dev/null || true

    # hypb uplink + guestb
    sudo ip netns exec hypb ip link show uB &>/dev/null || sudo ip link add uB netns hypb type veth peer name uB-br
    sudo ip link set uB-br master br-ul 2>/dev/null || true; sudo ip link set uB-br up
    sudo ip netns exec hypb ip link set uB up
    sudo ip netns exec hypb ip -6 addr add fd00::2/64 dev uB nodad 2>/dev/null || true
    sudo ip netns exec hypb ip link show gB-h &>/dev/null || sudo ip link add gB-h netns hypb type veth peer name gB netns guestb
    sudo ip netns exec hypb ip link set gB-h up; sudo ip netns exec guestb ip link set gB up
    sudo ip netns exec guestb ip addr add 10.0.0.6/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add 10.0.0.1/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add default via 10.0.0.1 2>/dev/null || true

    sudo ip6tables -I FORWARD 1 -i br-ul -j ACCEPT -m comment --comment "$MARK" 2>/dev/null || true

    GA_MAC=$(sudo ip netns exec guesta cat /sys/class/net/gA/address)
    GB_MAC=$(sudo ip netns exec guestb cat /sys/class/net/gB/address)

    : > "$PIDFILE"
    # Redirect-target enablers (peers of the redirect targets need an XDP program).
    sudo "$BIN" pass --iface uA-br & echo $! >> "$PIDFILE"
    sudo "$BIN" pass --iface uB-br & echo $! >> "$PIDFILE"
    sudo ip netns exec guesta "$BIN" pass --iface gA & echo $! >> "$PIDFILE"
    sudo ip netns exec guestb "$BIN" pass --iface gB & echo $! >> "$PIDFILE"
    sleep 1

    # Datapath bringup WITH --pin-dir (HA). Broadcast gateway-mac (flat-L2 flood + UNDERLAY filter).
    sudo ip netns exec hypa "$BIN" bringup \
        --uplink uA --local-underlay fd00::1 --gateway 10.0.0.1 --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --guest "gA-h=10.0.0.5=${GA_MAC}=fd00:a::5=0" --remote "10.0.0.6=fd00:b::6=0" \
        --pin-dir "$PIN_A" & echo $! >> "$PIDFILE"
    sudo ip netns exec hypb "$BIN" bringup \
        --uplink uB --local-underlay fd00::2 --gateway 10.0.0.1 --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --guest "gB-h=10.0.0.6=${GB_MAC}=fd00:b::6=0" --remote "10.0.0.5=fd00:a::5=0" \
        --pin-dir "$PIN_B" & echo $! >> "$PIDFILE"
    sleep 2
    echo "=== HA UP complete (pinned to $PIN_A / $PIN_B) ==="
}

cmd_test() {
    echo "=== HA Test: datapath survives a control-plane kill, then re-adopts ==="
    echo "--- baseline: guesta -> guestb ---"
    sudo ip netns exec guesta ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1 \
        && echo "  baseline OK" || die "baseline guesta->guestb failed"

    # Confirm the pins exist.
    echo "--- pinned objects on bpffs ---"
    sudo ls -1 "$PIN_A" "$PIN_A/links" 2>/dev/null | sed 's/^/    /' || true

    # KILL hypa's control-plane process (only hypa's bringup; the pass enablers + hypb stay).
    echo "--- SIGKILL hypa control-plane (bringup --uplink uA) ---"
    sudo pkill -9 -f 'flowplane bringup --uplink uA' 2>/dev/null || true
    sleep 1
    # Verify hypa's bringup is actually gone.
    if pgrep -f 'flowplane bringup --uplink uA' >/dev/null; then
        echo "  WARNING: hypa bringup still running after kill"
    else
        echo "  hypa control-plane is DEAD"
    fi

    # While hypa's CP is DEAD, the pinned links keep its datapath forwarding.
    echo "--- with hypa CP dead: guesta -> guestb must STILL work ---"
    if sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  HA: control-plane killed; datapath still forwarding (guesta -> guestb) -> SURVIVED"
    else
        echo "  WARNING: datapath did NOT survive the control-plane kill"
    fi

    # Restart hypa's control plane in ADOPT mode (re-acquire pinned CONNTRACK, no re-attach).
    echo "--- restart hypa control-plane with --adopt ---"
    sudo ip netns exec hypa "$BIN" bringup \
        --uplink uA --local-underlay fd00::1 --gateway 10.0.0.1 --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --pin-dir "$PIN_A" --adopt true & echo $! >> "$PIDFILE"
    sleep 2
    if sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  HA: control-plane re-adopted pinned datapath; flows intact -> OK"
    else
        echo "  WARNING: flows broken after adopt"
    fi
    echo ""
    echo "=== HA smoke passed ==="
}

cmd_down() {
    echo "=== HA teardown ==="
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do sudo kill "$pid" 2>/dev/null || true; done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    sudo pkill -f 'flowplane (bringup|pass) --' 2>/dev/null || true
    sleep 1
    # Remove the pinned datapath (so the next run is a clean first-start, not a stale adopt).
    sudo rm -rf "$PIN_A" "$PIN_B" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i br-ul -j ACCEPT -m comment --comment "$MARK" 2>/dev/null || true
    for ns in hypa hypb guesta guestb; do sudo ip netns del "$ns" 2>/dev/null || true; done
    for iface in uA-br uB-br br-ul; do sudo ip link del "$iface" 2>/dev/null || true; done
    echo "=== HA DOWN complete ==="
}

cmd_run() { trap cmd_down EXIT INT TERM; cmd_up; cmd_test; }

case "${1:-}" in
    up) cmd_up ;; test) cmd_test ;; down) cmd_down ;; run) cmd_run ;;
    *) echo "Usage: $0 {up|test|down|run}" >&2; exit 1 ;;
esac
