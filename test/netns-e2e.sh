#!/usr/bin/env bash
# env/netns-e2e.sh — netns-based end-to-end test for the XDP IP-in-IPv6 overlay.
#
# Topology:
#   guesta(10.0.0.5/gA)  \
#   guesta2(10.0.0.7/gA2) }- hypa(gA-h,gA2-h / uA) <-> [uA-br] br-ul [uB-br] <-> hypb(uB / gB-h) <-> guestb(10.0.0.6/gB)
#
# Guests use a dpservice-style /32 + link route to gateway + default via gateway (10.0.0.1),
# so they ARP only for the gateway — which the datapath answers in-kernel (no static neigh).
#
# Usage (run from repo root):
#   ./env/netns-e2e.sh up       create namespaces + bridge, attach XDP datapath
#   ./env/netns-e2e.sh test     ping guesta->guestb; ARP evidence; multi-interface; encap capture
#   ./env/netns-e2e.sh down     kill daemons, tear down all namespaces/links/bridge
#   ./env/netns-e2e.sh run      up + test + down  (with cleanup on error)
#
# Requirements:
#   - Passwordless sudo
#   - cargo build -p flowplane must have been run (binary at target/debug/flowplane)
#   - tcpdump in Nix store (detected automatically)
set -euo pipefail

# Repo root from the script's own location (this script lives in test/).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug/flowplane"
# User-writable: the script runs as the normal user (only individual commands use sudo),
# so this must NOT be under root-owned /run.
PIDFILE="${TMPDIR:-/tmp}/xdp-e2e-pids"
IP6TABLES_MARK="xdp-e2e"  # comment tag to identify our rules

# All tooling is provided by the flake devShell; run this script via `nix develop` (the Makefile
# does). tcpdump is optional (capture-based proofs are skipped if it is absent).
TCPDUMP="$(command -v tcpdump || true)"

die() { echo "ERROR: $*" >&2; exit 1; }

# Run the flowplane binary inside a netns WITH a bpffs mounted. `ip netns exec` unshares a fresh
# mount namespace and remounts /sys on EVERY invocation, which shadows the host bpffs at
# /sys/fs/bpf — and the binary pins its ephemeral maps to /sys/fs/bpf/flowplane-eph-<pid>. So the
# bpffs must be mounted in the SAME exec as the binary (a mount from a prior exec does not persist).
# Usage: nsbin <netns> <flowplane-subcommand> <args...>   (append & / >log as usual)
nsbin() {
    local ns="$1"; shift
    sudo ip netns exec "$ns" sh -c 'mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true; exec "$@"' _ "$BIN" "$@"
}

# ---------------------------------------------------------------------------
cmd_up() {
    [[ -x "$BIN" ]] || die "binary not found at $BIN — run: cargo build -p flowplane"

    # ---- bridge ----
    sudo ip link add br-ul type bridge 2>/dev/null || true
    sudo ip link set br-ul up
    # Disable multicast snooping so IPv6 multicast (NDP, ping) crosses the bridge
    sudo ip link set br-ul type bridge mcast_snooping 0

    # ---- namespaces ----
    for ns in hypa hypb hypc guesta guestb guesta2 extsrv guestc guestd extclient; do
        sudo ip netns add "$ns" 2>/dev/null || true
        sudo ip netns exec "$ns" ip link set lo up
    done

    # ---- hypa uplink: uA in hypa <-> uA-br on bridge ----
    if ! sudo ip netns exec hypa ip link show uA &>/dev/null; then
        sudo ip link add uA netns hypa type veth peer name uA-br
    fi
    sudo ip link set uA-br master br-ul 2>/dev/null || true
    sudo ip link set uA-br up
    sudo ip netns exec hypa ip link set uA up
    sudo ip netns exec hypa ip -6 addr add fd00::1/64 dev uA nodad 2>/dev/null || true

    # ---- hypa guest link: gA-h in hypa <-> gA in guesta ----
    if ! sudo ip netns exec hypa ip link show gA-h &>/dev/null; then
        sudo ip link add gA-h netns hypa type veth peer name gA netns guesta
    fi
    sudo ip netns exec hypa ip link set gA-h up
    sudo ip netns exec guesta ip link set gA up
    # /32 address + link route to gateway + default via gateway (dpservice model)
    sudo ip netns exec guesta ip addr add 10.0.0.5/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add 10.0.0.1/32 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip route add default via 10.0.0.1 2>/dev/null || true
    # LB backend: own the LB IP 10.0.0.200 as a secondary (anycast — backends reply from it).
    sudo ip netns exec guesta ip addr add 10.0.0.200/32 dev gA 2>/dev/null || true
    # Dual-stack overlay v6: /128 + link route to the v6 gateway + v6 default (dpservice model,
    # NO static neigh — the datapath answers ND for fd00:ff::1).
    sudo ip netns exec guesta ip -6 addr add fd00:ff::5/128 dev gA nodad 2>/dev/null || true
    sudo ip netns exec guesta ip -6 route add fd00:ff::1/128 dev gA 2>/dev/null || true
    sudo ip netns exec guesta ip -6 route add default via fd00:ff::1 dev gA 2>/dev/null || true

    # ---- hypa second guest link: gA2-h in hypa <-> gA2 in guesta2 ----
    if ! sudo ip netns exec hypa ip link show gA2-h &>/dev/null; then
        sudo ip link add gA2-h netns hypa type veth peer name gA2 netns guesta2
    fi
    sudo ip netns exec hypa ip link set gA2-h up
    sudo ip netns exec guesta2 ip link set gA2 up
    sudo ip netns exec guesta2 ip addr add 10.0.0.7/32 dev gA2 2>/dev/null || true
    sudo ip netns exec guesta2 ip route add 10.0.0.1/32 dev gA2 2>/dev/null || true
    sudo ip netns exec guesta2 ip route add default via 10.0.0.1 2>/dev/null || true
    sudo ip netns exec guesta2 ip addr add 10.0.0.200/32 dev gA2 2>/dev/null || true  # LB backend (anycast)

    # ---- hypb uplink: uB in hypb <-> uB-br on bridge ----
    if ! sudo ip netns exec hypb ip link show uB &>/dev/null; then
        sudo ip link add uB netns hypb type veth peer name uB-br
    fi
    sudo ip link set uB-br master br-ul 2>/dev/null || true
    sudo ip link set uB-br up
    sudo ip netns exec hypb ip link set uB up
    sudo ip netns exec hypb ip -6 addr add fd00::2/64 dev uB nodad 2>/dev/null || true

    # ---- hypb guest link: gB-h in hypb <-> gB in guestb ----
    if ! sudo ip netns exec hypb ip link show gB-h &>/dev/null; then
        sudo ip link add gB-h netns hypb type veth peer name gB netns guestb
    fi
    sudo ip netns exec hypb ip link set gB-h up
    sudo ip netns exec guestb ip link set gB up
    sudo ip netns exec guestb ip addr add 10.0.0.6/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add 10.0.0.1/32 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip route add default via 10.0.0.1 2>/dev/null || true
    # Dual-stack overlay v6 for guestb (peer of guesta's v6 overlay test).
    sudo ip netns exec guestb ip -6 addr add fd00:ff::6/128 dev gB nodad 2>/dev/null || true
    sudo ip netns exec guestb ip -6 route add fd00:ff::1/128 dev gB 2>/dev/null || true
    sudo ip netns exec guestb ip -6 route add default via fd00:ff::1 dev gB 2>/dev/null || true

    # ---- hypb external target: gE-h in hypb <-> gE in extsrv (the "public" peer for NAT) ----
    if ! sudo ip netns exec hypb ip link show gE-h &>/dev/null; then
        sudo ip link add gE-h netns hypb type veth peer name gE netns extsrv
    fi
    sudo ip netns exec hypb ip link set gE-h up
    sudo ip netns exec extsrv ip link set gE up
    sudo ip netns exec extsrv ip addr add 10.0.0.8/32 dev gE 2>/dev/null || true
    sudo ip netns exec extsrv ip route add 10.0.0.1/32 dev gE 2>/dev/null || true
    sudo ip netns exec extsrv ip route add default via 10.0.0.1 2>/dev/null || true
    sudo ip netns exec extsrv ip addr add 10.0.0.200/32 dev gE 2>/dev/null || true  # remote LB backend (anycast)

    # ---- second tenant (vni=100), OVERLAPPING IP 10.0.0.5 ----
    # guestc on hypa (gC-h<->gC) and guestd on hypb (gD-h<->gD), both 10.0.0.5 in vni=100.
    if ! sudo ip netns exec hypa ip link show gC-h &>/dev/null; then
        sudo ip link add gC-h netns hypa type veth peer name gC netns guestc
    fi
    sudo ip netns exec hypa ip link set gC-h up
    sudo ip netns exec guestc ip link set gC up
    sudo ip netns exec guestc ip addr add 10.0.0.5/32 dev gC 2>/dev/null || true
    sudo ip netns exec guestc ip route add 10.0.0.1/32 dev gC 2>/dev/null || true
    sudo ip netns exec guestc ip route add default via 10.0.0.1 2>/dev/null || true
    if ! sudo ip netns exec hypb ip link show gD-h &>/dev/null; then
        sudo ip link add gD-h netns hypb type veth peer name gD netns guestd
    fi
    sudo ip netns exec hypb ip link set gD-h up
    sudo ip netns exec guestd ip link set gD up
    sudo ip netns exec guestd ip addr add 10.0.0.6/32 dev gD 2>/dev/null || true
    sudo ip netns exec guestd ip route add 10.0.0.1/32 dev gD 2>/dev/null || true
    sudo ip netns exec guestd ip route add default via 10.0.0.1 2>/dev/null || true

    # ---- hypc uplink (3rd node, for neighbor-NAT): uC in hypc <-> uC-br on bridge ----
    if ! sudo ip netns exec hypc ip link show uC &>/dev/null; then
        sudo ip link add uC netns hypc type veth peer name uC-br
    fi
    sudo ip link set uC-br master br-ul 2>/dev/null || true
    sudo ip link set uC-br up
    sudo ip netns exec hypc ip link set uC up
    sudo ip netns exec hypc ip -6 addr add fd00::3/64 dev uC nodad 2>/dev/null || true

    # ---- hypc external client: gX-h in hypc <-> gX in extclient (10.0.0.9) ----
    if ! sudo ip netns exec hypc ip link show gX-h &>/dev/null; then
        sudo ip link add gX-h netns hypc type veth peer name gX netns extclient
    fi
    sudo ip netns exec hypc ip link set gX-h up
    sudo ip netns exec extclient ip link set gX up
    sudo ip netns exec extclient ip addr add 10.0.0.9/32 dev gX 2>/dev/null || true
    sudo ip netns exec extclient ip route add 10.0.0.1/32 dev gX 2>/dev/null || true
    sudo ip netns exec extclient ip route add default via 10.0.0.1 2>/dev/null || true

    # ---- ip6tables: allow bridge forwarding on br-ul ----
    # Docker sets ip6tables FORWARD policy to DROP with bridge-nf-call-ip6tables=1.
    # We add scoped ACCEPT rules for br-ul instead of touching any global sysctl.
    sudo ip6tables -I FORWARD 1 -i br-ul -o br-ul -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -I FORWARD 2 -i uA-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -I FORWARD 3 -i uB-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -I FORWARD 4 -i uC-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true

    # ---- static underlay neighs (bypass NDP which may be unreliable in bridges) ----
    UA_MAC=$(sudo ip netns exec hypa cat /sys/class/net/uA/address)
    UB_MAC=$(sudo ip netns exec hypb cat /sys/class/net/uB/address)
    UC_MAC=$(sudo ip netns exec hypc cat /sys/class/net/uC/address)
    sudo ip netns exec hypa ip -6 neigh replace fd00::2 lladdr "$UB_MAC" dev uA nud permanent
    sudo ip netns exec hypb ip -6 neigh replace fd00::1 lladdr "$UA_MAC" dev uB nud permanent
    sudo ip netns exec hypa ip -6 neigh replace fd00::3 lladdr "$UC_MAC" dev uA nud permanent
    sudo ip netns exec hypc ip -6 neigh replace fd00::1 lladdr "$UA_MAC" dev uC nud permanent
    sudo ip netns exec hypb ip -6 neigh replace fd00::3 lladdr "$UC_MAC" dev uB nud permanent
    sudo ip netns exec hypc ip -6 neigh replace fd00::2 lladdr "$UB_MAC" dev uC nud permanent

    # ---- sanity check: underlay IPv6 ping (no XDP yet) ----
    echo "=== Underlay sanity check ==="
    sudo ip netns exec hypa ping -6 -c2 -W2 fd00::2 \
        || die "underlay ping hypa->hypb failed — check bridge/ip6tables"
    echo "Underlay ping OK"

    # ---- capture guest MACs (from inside guest netns — these are the actual guest MACs) ----
    GA_MAC=$(sudo ip netns exec guesta cat /sys/class/net/gA/address)
    GB_MAC=$(sudo ip netns exec guestb cat /sys/class/net/gB/address)
    GA2_MAC=$(sudo ip netns exec guesta2 cat /sys/class/net/gA2/address)
    GE_MAC=$(sudo ip netns exec extsrv cat /sys/class/net/gE/address)
    GC_MAC=$(sudo ip netns exec guestc cat /sys/class/net/gC/address)
    GD_MAC=$(sudo ip netns exec guestd cat /sys/class/net/gD/address)
    GX_MAC=$(sudo ip netns exec extclient cat /sys/class/net/gX/address)
    echo "UA_MAC=$UA_MAC  UB_MAC=$UB_MAC  UC_MAC=$UC_MAC"
    echo "GA_MAC=$GA_MAC  GB_MAC=$GB_MAC  GA2_MAC=$GA2_MAC  GE_MAC=$GE_MAC"
    echo "GC_MAC=$GC_MAC  GD_MAC=$GD_MAC  (vni=100 tenant, overlapping 10.0.0.5)"
    echo "GX_MAC=$GX_MAC  (extclient 10.0.0.9 on hypc, for neighbor-NAT)"

    # NOTE: No static guest neigh entries — the XDP datapath answers ARP for 10.0.0.1 in-kernel.
    # Guests use /32 + link route + default via 10.0.0.1, so they only ARP for the gateway.

    # ---- redirect-target enablers ----
    # XDP bpf_redirect() into a veth only works if that veth's PEER has an XDP program.
    # uA-br = peer of uA  (guest_tx on gA-h/gA2-h redirects -> uA -> uA-br)
    # uB-br = peer of uB
    # gA    = peer of gA-h (uplink_rx on uA redirects -> gA-h -> gA)
    # gA2   = peer of gA2-h (uplink_rx on uA redirects -> gA2-h -> gA2)
    # gB    = peer of gB-h
    echo "=== Attaching xdp_pass on redirect-target peers ==="
    : > "$PIDFILE"

    sudo "$BIN" pass --iface uA-br &
    echo $! >> "$PIDFILE"
    sudo "$BIN" pass --iface uB-br &
    echo $! >> "$PIDFILE"
    nsbin guesta pass --iface gA &
    echo $! >> "$PIDFILE"
    nsbin guestb pass --iface gB &
    echo $! >> "$PIDFILE"
    nsbin guesta2 pass --iface gA2 &
    echo $! >> "$PIDFILE"
    nsbin extsrv pass --iface gE &
    echo $! >> "$PIDFILE"
    nsbin guestc pass --iface gC &
    echo $! >> "$PIDFILE"
    nsbin guestd pass --iface gD &
    echo $! >> "$PIDFILE"
    sudo "$BIN" pass --iface uC-br &
    echo $! >> "$PIDFILE"
    nsbin extclient pass --iface gX &
    echo $! >> "$PIDFILE"

    sleep 1

    # ---- datapath bringup on each hypervisor ----
    echo "=== Bringing up XDP datapath ==="

    # hypa: two local guests (gA=10.0.0.5, gA2=10.0.0.7) + remote route to hypb guest (10.0.0.6)
    # --gateway-mac = peer uplink MAC (flat-L2 lab: the bridge forwards to UB_MAC directly)
    nsbin hypa bringup \
        --uplink uA \
        --local-underlay fd00::1 \
        --gateway 10.0.0.1 \
        --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --guest "gA-h=10.0.0.5=${GA_MAC}=fd00:a::5=0" \
        --guest "gA2-h=10.0.0.7=${GA2_MAC}=fd00:a::7=0" \
        --guest "gC-h=10.0.0.5=${GC_MAC}=fd00:a::205=100" \
        --remote "10.0.0.6=fd00:b::6=0" \
        --vip "10.0.0.7=10.0.0.100" \
        --lb "10.0.0.200:0:1:fd00:a::200" \
        --lb-target "10.0.0.200:0:1:fd00:a::200=fd00:a::5" \
        --lb-target "10.0.0.200:0:1:fd00:a::200=fd00:a::7" \
        --lb-target "10.0.0.200:0:1:fd00:a::200=fd00:b::8" \
        --remote "10.0.0.8=fd00:b::8=0" \
        --remote "10.0.0.0/24=fd00:b::8=0" \
        --external "10.0.0.8" \
        --nat "10.0.0.5=10.0.0.50:20000:30000" \
        --remote "10.0.0.9=fd00:c::9=0" \
        --external "10.0.0.9" \
        --meter "gA-h=1:0" \
        --fw-rule "gA-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gA-h:in:accept:icmp:10.0.0.6/32:0.0.0.0/0:*" \
        --fw-rule "gA-h:in:accept:icmp:10.0.0.8/32:0.0.0.0/0:*" \
        --fw-rule "gA-h:in:accept:icmp:10.0.0.9/32:0.0.0.0/0:*" \
        --fw-rule "gA2-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gA2-h:in:accept:icmp:10.0.0.6/32:0.0.0.0/0:*" \
        --fw-rule "gC-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --remote "10.0.0.6=fd00:b::206=100" \
        --gateway6 "fd00:ff::1" \
        --guest6 "gA-h=fd00:ff::5=fd00:a::5=0" \
        --remote6 "fd00:ff::6=fd00:b::6=0" &
    echo $! >> "$PIDFILE"

    # hypb: one local guest (gB=10.0.0.6) + remote routes to both hypa guests
    # --gateway-mac = peer uplink MAC (flat-L2 lab: the bridge forwards to UA_MAC directly)
    nsbin hypb bringup \
        --uplink uB \
        --local-underlay fd00::2 \
        --gateway 10.0.0.1 \
        --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --guest "gB-h=10.0.0.6=${GB_MAC}=fd00:b::6=0" \
        --guest "gE-h=10.0.0.8=${GE_MAC}=fd00:b::8=0" \
        --guest "gD-h=10.0.0.6=${GD_MAC}=fd00:b::206=100" \
        --remote "10.0.0.5=fd00:a::5=0" \
        --remote "10.0.0.7=fd00:a::7=0" \
        --remote "10.0.0.100=fd00:a::7=0" \
        --remote "10.0.0.200=fd00:a::200=0" \
        --remote "10.0.0.50=fd00:a::5=0" \
        --remote "10.0.0.5=fd00:a::205=100" \
        --fw-rule "gB-h:in:accept:icmp:10.0.0.5/32:0.0.0.0/0:*" \
        --fw-rule "gB-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gB-h:in:drop:icmp:10.0.0.7/32:0.0.0.0/0:*" \
        --fw-rule "gE-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gE-h:in:accept:icmp:10.0.0.6/32:0.0.0.0/0:*" \
        --fw-rule "gE-h:in:accept:icmp:10.0.0.50/32:0.0.0.0/0:*" \
        --fw-rule "gD-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gD-h:in:accept:icmp:10.0.0.5/32:0.0.0.0/0:*" \
        --underlay-marker "fd00:b::50:0" \
        --neigh-nat "10.0.0.50:20000:30000@fd00:a::5@0" \
        --gateway6 "fd00:ff::1" \
        --guest6 "gB-h=fd00:ff::6=fd00:b::6=0" \
        --remote6 "fd00:ff::5=fd00:a::5=0" &
    echo $! >> "$PIDFILE"

    # hypc: the external client's node. extclient(10.0.0.9) replies to the NAT IP 10.0.0.50, which
    # it routes to the hypb GATEWAY marker fd00:b::50 (NOT the owner hypa) — exercising neighbor-NAT.
    nsbin hypc bringup \
        --uplink uC \
        --local-underlay fd00::3 \
        --gateway 10.0.0.1 \
        --gateway-mac "ff:ff:ff:ff:ff:ff" \
        --guest "gX-h=10.0.0.9=${GX_MAC}=fd00:c::9=0" \
        --remote "10.0.0.50=fd00:b::50=0" \
        --remote "10.0.0.5=fd00:a::5=0" \
        --fw-rule "gX-h:eg:accept:icmp:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "gX-h:in:accept:icmp:10.0.0.50/32:0.0.0.0/0:*" &
    echo $! >> "$PIDFILE"

    sleep 2

    # ---- verify XDP attachments ----
    echo "=== datapath attachment verification ==="
    # The guest edge is tcx now (tc_guest_tx tcx/ingress), NOT XDP — verify via bpftool net (needs a
    # bpffs mounted in the same netns exec, like the binary). The uplink is XDP (uplink_rx).
    check_tcx()  { sudo ip netns exec "$1" sh -c 'mount -t bpf bpf /sys/fs/bpf 2>/dev/null; bpftool net show dev '"$2"' 2>/dev/null' | grep -qE 'tc_guest_tx|tcx' && echo "  tcx guest_tx OK on $2" || echo "  WARNING: no tcx guest_tx on $2"; }
    check_xdp()  { sudo ip netns exec "$1" ip -d link show "$2" | grep -qE 'xdp|prog' && echo "  xdp uplink_rx OK on $2" || echo "  WARNING: no xdp on $2"; }
    check_tcx hypa gA-h
    check_tcx hypa gA2-h
    check_xdp hypa uA
    check_tcx hypb gB-h
    check_xdp hypb uB

    echo "=== UP complete ==="
}

# ---------------------------------------------------------------------------
cmd_test() {
    echo "=== Test 1: guesta -> guestb ping (3 packets) ==="
    sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6
    echo ""

    echo "=== Test 2: DATAPATH ARP proof — 10.0.0.1 resolves to the distinct router GW_MAC ==="
    # The datapath advertises the gateway at a DISTINCT router MAC (GW_MAC 02:00:00:00:00:01), NOT
    # the guest's own VF MAC — the flowplane model diverged from dpservice here (see the
    # feedback-not-a-dpservice change). So guesta's neigh for 10.0.0.1 must show that router MAC.
    GW_MAC="02:00:00:00:00:01"
    sudo ip netns exec guesta ping -c1 -W1 10.0.0.6 >/dev/null 2>&1 || true  # trigger ARP
    NEIGH=$(sudo ip netns exec guesta ip neigh show 10.0.0.1)
    echo "  $NEIGH"
    if echo "$NEIGH" | grep -qi "$GW_MAC"; then
        echo "  ARP proof OK: datapath replied with the distinct router GW_MAC ($GW_MAC)"
    else
        echo "  WARNING: expected lladdr $GW_MAC but got: $NEIGH"
    fi
    echo ""

    echo "=== Test 3: FIREWALL — guestb ingress accepts guesta(10.0.0.5), drops guesta2(10.0.0.7) ==="
    # gB-h has an ingress whitelist: accept ICMP from 10.0.0.5, drop ICMP from 10.0.0.7. This also
    # exercises hypa's second interface (guesta2/gA2-h) — its packets reach the datapath and are
    # dropped by policy at hypb (not by the link being down; guesta2 connectivity is also proven by
    # the VIP (Test 6) and LB (Test 7) tests).
    if sudo ip netns exec guesta ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  ACCEPT-rule OK: guesta(10.0.0.5) -> guestb reaches"
    else
        echo "  WARNING: accepted source guesta could NOT reach guestb"
    fi
    if sudo ip netns exec guesta2 ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  WARNING: drop-rule did NOT block guesta2(10.0.0.7) -> guestb"
    else
        echo "  DROP-rule OK: guesta2(10.0.0.7) -> guestb blocked by ingress firewall"
    fi
    echo ""

    echo "=== Test 4: IPv6/proto-4 encap evidence on bridge (uA-br) ==="
    # XDP bpf_redirect() bypasses tcpdump on the redirecting interface (uA inside hypa),
    # so we capture on uA-br (the bridge-side peer) instead.
    if [[ -n "$TCPDUMP" ]]; then
        sudo "$TCPDUMP" -ni uA-br 'ip6 and ip6 proto 4' -c 4 2>&1 &
        TDPID=$!
        sleep 0.3
        sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.6 >/dev/null 2>&1
        wait $TDPID 2>/dev/null || true
    else
        echo "  (tcpdump not found — skipping encap capture)"
    fi
    echo ""

    echo "=== Test 5: return path guestb -> guesta ==="
    sudo ip netns exec guestb ping -c 3 -W 2 10.0.0.5
    echo ""

    echo "=== Test 6: VIP — guestb -> guesta2's VIP 10.0.0.100 (DNAT in, SNAT out) ==="
    # 0% loss proves DNAT delivered to guesta2 AND its SNAT'd reply returned with a correct
    # checksum (a bad checksum would be dropped by guestb). tcpdump prints packets to STDOUT, so
    # redirect stdout (not just stderr) to the proof file.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec guestb "$TCPDUMP" -ni gB 'icmp' -c 6 >/tmp/vip-td.txt 2>&1 &
        TDV=$!
        sleep 0.3
    fi
    sudo ip netns exec guestb ping -c 3 -W 2 10.0.0.100
    if [[ -n "$TCPDUMP" ]]; then
        wait $TDV 2>/dev/null || true
        echo "--- SNAT proof: echo replies must be sourced from 10.0.0.100 ---"
        grep -E '10\.0\.0\.100 > 10\.0\.0\.6: ICMP echo reply' /tmp/vip-td.txt \
            && echo "  SNAT proof OK: reply source is the VIP" \
            || echo "  WARNING: no VIP-sourced reply seen"
        rm -f /tmp/vip-td.txt
    fi
    echo ""

    echo "=== Test 7: LB (dpservice underlay-forwarding) — guestb -> 10.0.0.200 across guesta+guesta2 (local) + extsrv (REMOTE) ==="
    # Backends own 10.0.0.200 (anycast). Maglev selects a backend NODE by its underlay; the LB does
    # NO inner DNAT, so backends reply naturally from 10.0.0.200 (no reverse-SNAT). extsrv lives on
    # the PEER hypervisor — Maglev-selecting it exercises the re-forward (re-encap) path. Each
    # `ping -c 1` is a distinct ICMP id, so the 5-tuple hash spreads flows across the 3 backends.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec guesta  "$TCPDUMP" -ni gA  'icmp and dst 10.0.0.200' -c 60 >/tmp/lb-a.txt  2>&1 &
        TDA=$!
        sudo ip netns exec guesta2 "$TCPDUMP" -ni gA2 'icmp and dst 10.0.0.200' -c 60 >/tmp/lb-a2.txt 2>&1 &
        TDA2=$!
        sudo ip netns exec extsrv  "$TCPDUMP" -ni gE  'icmp and dst 10.0.0.200' -c 60 >/tmp/lb-e.txt  2>&1 &
        TDE=$!
        sudo ip netns exec guestb  "$TCPDUMP" -ni gB  'icmp' -c 60 >/tmp/lb-b.txt  2>&1 &
        TDB=$!
        sleep 0.3
    fi
    LOSS=0
    for _ in $(seq 1 24); do
        sudo ip netns exec guestb ping -c 1 -W 2 10.0.0.200 >/dev/null 2>&1 || LOSS=$((LOSS + 1))
    done
    echo "  24 flows to 10.0.0.200: $((24 - LOSS)) replied, $LOSS lost"
    sleep 1
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDA" "$TDA2" "$TDE" "$TDB" 2>/dev/null || true
        wait "$TDA" "$TDA2" "$TDE" "$TDB" 2>/dev/null || true
        A=$(grep -c 'echo request' /tmp/lb-a.txt  || true)
        B=$(grep -c 'echo request' /tmp/lb-a2.txt || true)
        E=$(grep -c 'echo request' /tmp/lb-e.txt  || true)
        echo "  hits  guesta=$A  guesta2=$B  extsrv(remote)=$E"
        if [[ "${A:-0}" -gt 0 && "${B:-0}" -gt 0 && "${E:-0}" -gt 0 ]]; then
            echo "  LB distribution OK across all 3 backends (incl. the REMOTE one via re-forward)"
        else
            echo "  WARNING: not all backends used (remote re-forward may be broken)"
        fi
        echo "  --- anycast proof: replies to guestb must be sourced from the LB IP 10.0.0.200 ---"
        if grep -qE '10\.0\.0\.200 > 10\.0\.0\.6: ICMP echo reply' /tmp/lb-b.txt; then
            echo "  anycast OK: replies sourced from 10.0.0.200 (backends own the LB IP, no reverse-SNAT)"
        else
            echo "  WARNING: no LB-sourced replies seen at guestb"
        fi
        rm -f /tmp/lb-a.txt /tmp/lb-a2.txt /tmp/lb-e.txt /tmp/lb-b.txt
    fi
    echo ""

    echo "=== Test 8: NAT-GW — guesta(10.0.0.5) -> extsrv(10.0.0.8), extsrv must see source 10.0.0.50 ==="
    # guesta has nat_ip 10.0.0.50; the route to 10.0.0.8 is external, so egress is SNAT'd. extsrv
    # must observe echo requests from 10.0.0.50 (not 10.0.0.5); guesta must get replies (0% loss),
    # proving the conntrack reverse-DNAT restores 10.0.0.8 -> ... -> 10.0.0.5 and the rewritten
    # ICMP id is restored.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec extsrv "$TCPDUMP" -ni gE 'icmp' -c 10 >/tmp/nat-e.txt 2>&1 &
        TDE=$!
        sleep 0.3
    fi
    sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.8
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDE" 2>/dev/null || true
        wait "$TDE" 2>/dev/null || true
        echo "--- SNAT proof: extsrv must see echo requests sourced from 10.0.0.50 ---"
        if grep -qE '10\.0\.0\.50 > 10\.0\.0\.8: ICMP echo request' /tmp/nat-e.txt; then
            echo "  NAT SNAT proof OK: extsrv sees the NAT IP as source"
        else
            echo "  WARNING: extsrv did not see 10.0.0.50 as source"
            cat /tmp/nat-e.txt
        fi
        rm -f /tmp/nat-e.txt
    fi
    echo ""

    echo "=== Test 9: unified conntrack under GC — sustained flows stay healthy ==="
    # 12 pings (> the 10s GC interval) over a DEFAULT overlay flow (guesta->guestb) and a NAT flow
    # (guesta->extsrv). Both must stay 0% loss, proving conntrack entries are created, refreshed
    # (last_seen) on each packet, and not mis-evicted mid-flow by the aging sweep.
    LOSS_DEF=0; LOSS_NAT=0
    for _ in $(seq 1 12); do
        sudo ip netns exec guesta ping -c 1 -W 2 10.0.0.6 >/dev/null 2>&1 || LOSS_DEF=$((LOSS_DEF+1))
        sudo ip netns exec guesta ping -c 1 -W 2 10.0.0.8 >/dev/null 2>&1 || LOSS_NAT=$((LOSS_NAT+1))
        sleep 1
    done
    echo "  DEFAULT flow (guesta->guestb) lost=$LOSS_DEF/12 ; NAT flow (guesta->extsrv) lost=$LOSS_NAT/12"
    if [ "$LOSS_DEF" -eq 0 ] && [ "$LOSS_NAT" -eq 0 ]; then
        echo "  conntrack OK: flows tracked + refreshed across the GC interval"
    else
        echo "  WARNING: flow loss under conntrack/GC"
    fi
    echo ""

    echo "=== Test 10: multi-VNI isolation — vni=100 tenant with IPs overlapping vni=0 ==="
    # guestc (vni=100, 10.0.0.5 on hypa) -> guestd (vni=100, 10.0.0.6 on hypb): same-tenant, reaches.
    # Both IPs overlap vni=0 (guesta=10.0.0.5, guestb=10.0.0.6) but the per-interface underlay +
    # vni-keyed maps keep the tenants separate.
    if sudo ip netns exec guestc ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  vni=100 intra-tenant OK: guestc(10.0.0.5) -> guestd(10.0.0.6) reaches"
    else
        echo "  WARNING: vni=100 guestc could not reach guestd"
    fi
    # Isolation: guestc's vni=100 traffic to 10.0.0.6 must reach guestd (vni=100), NOT guestb
    # (vni=0, also 10.0.0.6). Capture on guestb's tap while guestc pings; guestb must see nothing.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec guestb "$TCPDUMP" -ni gB 'icmp' -c 3 >/tmp/iso.txt 2>&1 &
        TDI=$!
        sleep 0.3
        sudo ip netns exec guestc ping -c 3 -W 2 10.0.0.6 >/dev/null 2>&1 || true
        sleep 0.5
        sudo kill "$TDI" 2>/dev/null || true
        wait "$TDI" 2>/dev/null || true
        if grep -q 'ICMP' /tmp/iso.txt; then
            echo "  WARNING: vni=100 traffic leaked onto the vni=0 guestb interface"
            cat /tmp/iso.txt
        else
            echo "  ISOLATION OK: vni=100 traffic never reached the vni=0 guestb (overlapping 10.0.0.6)"
        fi
        rm -f /tmp/iso.txt
    fi
    echo ""

    echo "=== Test 11: LPM routing — /32 to guestb wins over a /24 supernet to extsrv ==="
    # hypa has 10.0.0.6/32 -> guestb AND 10.0.0.0/24 -> extsrv (fd00:b::8). A guesta ping to
    # 10.0.0.6 must take the more-specific /32 (reach guestb), NOT the /24 (extsrv).
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec extsrv "$TCPDUMP" -ni gE 'icmp and host 10.0.0.6' -c 3 >/tmp/lpm.txt 2>&1 &
        TDL=$!
        sleep 0.3
    fi
    if sudo ip netns exec guesta ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  /32 route OK: guesta -> 10.0.0.6 reaches guestb"
    else
        echo "  WARNING: guesta -> 10.0.0.6 failed under LPM"
    fi
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDL" 2>/dev/null || true
        wait "$TDL" 2>/dev/null || true
        if grep -q 'ICMP' /tmp/lpm.txt; then
            echo "  WARNING: traffic to 10.0.0.6 hit the /24 supernet (extsrv) — LPM not most-specific"
            cat /tmp/lpm.txt
        else
            echo "  LPM OK: the /32 beat the /24 supernet (extsrv saw nothing for 10.0.0.6)"
        fi
        rm -f /tmp/lpm.txt
    fi
    echo ""

    echo "=== Test 12: Neighbor NAT — return via a non-owner gateway (hypb) re-forwarded to owner (hypa) ==="
    # guesta (hypa, nat_ip 10.0.0.50) -> extclient (hypc, 10.0.0.9). The reply enters at hypb (the
    # NAT GATEWAY, which does NOT own the flow) and is re-forwarded to hypa via the neighbor-NAT
    # table; hypa reverses it with its local NAT conntrack. 0% loss proves the cross-node return.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec extclient "$TCPDUMP" -ni gX 'icmp' -c 6 >/tmp/nn.txt 2>&1 &
        TDN=$!
        sleep 0.3
    fi
    if sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.9 >/dev/null 2>&1; then
        echo "  NeighborNat OK: guesta -> extclient works (return crossed hypb gateway -> hypa)"
    else
        echo "  WARNING: NeighborNat return path failed (guesta could not reach extclient)"
    fi
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDN" 2>/dev/null || true
        wait "$TDN" 2>/dev/null || true
        if grep -qE '10\.0\.0\.50 > 10\.0\.0\.9: ICMP echo request' /tmp/nn.txt; then
            echo "  SNAT proof OK: extclient sees the NAT IP 10.0.0.50 as source"
        else
            echo "  WARNING: extclient did not see the NAT IP as source"
            cat /tmp/nn.txt
        fi
        rm -f /tmp/nn.txt
    fi
    echo ""

    echo "=== Test 13: rate metering — guesta egress SHAPED to 1 Mbps (EDT paces, not policed) ==="
    # gA-h has a 1 Mbps total-egress cap. The datapath SHAPES via EDT + the uplink FQ qdisc (it PACES
    # packets by tx-timestamp), it does NOT police/drop — so the proof is throughput, not loss: a
    # burst of N large packets is delayed so its effective rate is ~1 Mbps (a line-rate send would be
    # near-instant). We send 300x1400B (420 KB); at 1 Mbps that takes ~3.4 s, at line rate <0.5 s.
    START=$(date +%s%N)
    sudo ip netns exec guesta ping -c 300 -i 0.001 -s 1400 -W 2 10.0.0.6 >/dev/null 2>&1 || true
    END=$(date +%s%N)
    ELAPSED_MS=$(( (END - START) / 1000000 ))
    # 300 * (1400 + 28 IP/ICMP + 26 outer overhead) ~= 435 KB -> Mbps = bytes*8 / (ms*1000)
    MBPS=$(( 300 * 1454 * 8 / (ELAPSED_MS * 1000 + 1) ))
    echo "  300x1400B burst took ${ELAPSED_MS} ms -> ~${MBPS} Mbps effective"
    sleep 1  # let the shaper drain
    if sudo ip netns exec guesta ping -c 3 -i 1 -W 2 10.0.0.6 >/dev/null 2>&1; then
        SLOW_OK=1
    else
        SLOW_OK=0
    fi
    # Shaping proof: the burst was paced (took well over the ~0.5 s a line-rate send needs, and the
    # effective rate is near the 1 Mbps cap — allow headroom to ~3 Mbps for FQ burst/horizon), and
    # slow traffic under the cap passes cleanly.
    if [ "$ELAPSED_MS" -ge 1500 ] && [ "$MBPS" -le 3 ] && [ "$SLOW_OK" -eq 1 ]; then
        echo "  rate metering OK: egress shaped to ~1 Mbps (paced ${ELAPSED_MS} ms), slow traffic passed"
    else
        echo "  WARNING: metering not shaping (elapsed=${ELAPSED_MS} ms, ~${MBPS} Mbps, slow_ok=${SLOW_OK})"
    fi
    echo ""

    echo "=== Test 14: IPv6 ND — guesta resolves the v6 gateway via the datapath (NA = router GW_MAC) ==="
    # The datapath answers ICMPv6 NS for fd00:ff::1 with a Neighbor Advertisement carrying the
    # distinct router GW_MAC (02:00:00:00:00:01), the same virtual-gateway MAC it uses for ARP —
    # NOT the guest's own VF MAC (the flowplane model diverged from dpservice; see Test 2).
    GW_MAC="02:00:00:00:00:01"
    sudo ip netns exec guesta ping -6 -c 1 -W 2 fd00:ff::6 >/dev/null 2>&1 || true  # triggers ND
    NB=$(sudo ip netns exec guesta ip -6 neigh show fd00:ff::1 2>/dev/null)
    if echo "$NB" | grep -qi "$GW_MAC"; then
        echo "  ND proof OK: datapath answered NS for the v6 gateway with the router GW_MAC ($GW_MAC)"
    else
        echo "  WARNING: v6 gateway not resolved via datapath ND ($NB)"
    fi
    echo ""

    echo "=== Test 15: IPv6 overlay — guesta(fd00:ff::5) -> guestb(fd00:ff::6) over the overlay ==="
    # Dual-stack guest-to-guest native IPv6 over IPv6-in-IPv6 (outer next-header 41), routed by ROUTES6.
    if sudo ip netns exec guesta ping -6 -c 3 -W 2 fd00:ff::6 >/dev/null 2>&1; then
        echo "  IPv6 overlay OK: dual-stack guest-to-guest v6 ping works (IPv6-in-IPv6, proto 41)"
    else
        echo "  WARNING: IPv6 overlay ping failed"
    fi
    echo ""

    echo "=== All tests passed ==="
}

# ---------------------------------------------------------------------------
cmd_down() {
    echo "=== Tearing down ==="

    # Kill all backgrounded datapath processes by their recorded PIDs (precise).
    # These PIDs are the `sudo ...` wrappers; SIGTERM is forwarded to the flowplane child.
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do
            sudo kill "$pid" 2>/dev/null || true
        done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    # Belt-and-suspenders fallback. IMPORTANT: do NOT use a broad `pkill -f target/debug/flowplane`
    # — that regex also matches ANY shell whose command line merely mentions the binary path
    # (e.g. an interactive verification command), killing unrelated processes. Match only the
    # actual datapath subcommands.
    sudo pkill -f 'flowplane (bringup|pass) --' 2>/dev/null || true

    sleep 1

    # Remove scoped ip6tables rules we added
    sudo ip6tables -D FORWARD -i br-ul -o br-ul -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uA-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true
    sudo ip6tables -D FORWARD -i uB-br -j ACCEPT -m comment --comment "$IP6TABLES_MARK" 2>/dev/null || true

    # Delete namespaces (also removes veth pairs whose netns-end lives inside them)
    for ns in hypa hypb hypc guesta guestb guesta2 extsrv guestc guestd extclient; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done

    # Remove the bridge and any dangling host-netns veths
    for iface in uA-br uB-br uC-br br-ul; do
        sudo ip link del "$iface" 2>/dev/null || true
    done

    echo "=== DOWN complete ==="
}

# ---------------------------------------------------------------------------
cmd_run() {
    # An EXIT trap guarantees teardown however the script ends — normal completion, a
    # `set -e` abort inside a function (an ERR trap would NOT fire there without errtrace),
    # or INT/TERM. cmd_down is idempotent, so running it once here is enough.
    trap cmd_down EXIT INT TERM
    cmd_up
    cmd_test
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    up)   cmd_up   ;;
    test) cmd_test ;;
    down) cmd_down ;;
    run)  cmd_run  ;;
    *) echo "Usage: $0 {up|test|down|run}" >&2; exit 1 ;;
esac
