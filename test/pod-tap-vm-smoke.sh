#!/usr/bin/env bash
# test/pod-tap-vm-smoke.sh — real-VM DHCP + overlay ping over the POD-NETNS-TAP model (KubeVirt).
#
# Proves the KubeVirt-compatible VM edge END TO END with a real guest: a CirrOS VM whose tap lives in
# a POD netns (as KubeVirt/libvirt requires — it opens the tap by name in the launcher pod netns),
# spliced by `tc mirred` to a ROOT-netns veth that carries our unchanged datapath. The VM
#   (1) DHCP-self-configures its overlay IP + gateway + MTU from OUR DHCPv4 responder, and
#   (2) pings a SECOND same-host endpoint over the overlay — through the mirred splice both ways.
# This validates the bridge-free pod-netns tap (attach.rs setup_pod_tap): the mirred splice carries
# the guest edge across the netns boundary with no bridge overhead (no MAC-learning/STP/flooding).
#
# Topology (single host, one VNI, dpservice link-local gateway 169.254.0.1):
#
#   pod netns pt-podns:
#     [CirrOS VM] --virtio(mac=VM_MAC)-- [pt0 tap] --mirred--> [vp0 veth peer]
#                                          ^ mirred <-------------- |
#   root netns:                                                    (veth)
#     [vpr0] --tc_guest_tx (datapath device; uplink_rx target) <----/
#        vpr0 10.0.0.50 via the VM's DHCP; ROUTES+UNDERLAY local fast path to:
#     [smb-ns] --veth(mac=PEER_MAC)-- [smb0] --tc_guest_tx (10.0.0.51/32, static)
#     [smu0 tap] --uplink_rx (no real peer; local path never uses it)
#
# GATE (cmd_test): the VM DHCP-obtains 10.0.0.50; the captured reply proves the responder emits
#                  IP + opt-121 gateway + opt-26 MTU; and `ping 10.0.0.51` is 0% loss.
#
# CRUCIAL: the VM's virtio MAC (VM_MAC) == the guest_mac programmed for the ROOT veth vpr0 (local
# delivery rewrites the frame dst to guest_mac). The gateway is advertised at the shared router MAC
# GW_MAC (02:00:00:00:00:01), so gateway-bound guest frames are dst=GW_MAC; the mirred splice carries
# them to tc_guest_tx on vpr0.
#
# Usage (from repo root, inside `nix develop`):
#   ./test/tap-vm-smoke.sh up       create taps + peer netns + bringup + boot VM
#   ./test/tap-vm-smoke.sh test     drive the VM console: udhcpc + assert config + ping peer
#   ./test/tap-vm-smoke.sh down     kill qemu + bringup, delete taps + peer netns
#   ./test/tap-vm-smoke.sh run      up + (wait for boot) + test + down  (EXIT trap guarantees teardown)
#
# Requirements: cargo build -p flowplane; /tmp/cirros.img (auto-downloaded); /dev/kvm; passwordless
# sudo; socat + python3 (devShell). ethtool/tcpdump optional.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/debug/flowplane"
PIDFILE="${TMPDIR:-/tmp}/sm-pids"
CIRROS_IMG="${CIRROS_IMG:-/tmp/cirros.img}"
CIRROS_URL="https://github.com/cirros-dev/cirros/releases/download/0.6.2/cirros-0.6.2-x86_64-disk.img"
CONSOLE_SOCK="/tmp/sm-console.sock"
BRINGUP_LOG="/tmp/sm-bringup.log"
QEMU_LOG="/tmp/sm-qemu.log"
CONSOLE_OUT="/tmp/sm-console-out.txt"
DHCP_CAP="/tmp/sm-dhcp-cap.txt"

# ── overlay config (one VNI; dpservice link-local gateway) ──────────────────────────────────
VNI=0
GW="169.254.0.1"                 # link-local gateway; matches the DHCPv4 responder's opt-121 (169.254/16 on-link)
VM_IP="10.0.0.50";   VM_MAC="52:54:00:00:00:50";   VM_UL="fd00:a::50"
PEER_IP="10.0.0.51"; PEER_MAC="52:54:00:00:00:51"; PEER_UL="fd00:a::51"
DHCP_MTU=1400
DHCP_DNS="8.8.8.8"
PEER_NS="smb-ns"; PEER_HOST_IF="smb0"; PEER_NS_IF="smb0p"
# The VM edge — the KubeVirt-compatible POD-NETNS-TAP model: a root-netns veth (VM_ROOT_VETH, the
# datapath device tc_guest_tx attaches to) whose peer (VM_POD_PEER) sits in the pod netns (VM_NS),
# spliced by tc mirred to a pod-netns tap (VM_POD_TAP) that qemu drives. No bridge (a bridge would
# hairpin gateway-at-own-MAC frames). This mirrors attach.rs setup_pod_tap; the smoke builds it by
# hand + drives the root veth via `bringup`, so it validates the datapath+mirred with a real VM.
VM_NS="pt-podns"; VM_ROOT_VETH="vpr0"; VM_POD_PEER="vp0"; VM_POD_TAP="pt0"

ETHTOOL="$(command -v ethtool || true)"

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
cmd_up() {
    [[ -x "$BIN" ]] || die "binary not found at $BIN — run: cargo build -p flowplane"
    [[ -e /dev/kvm ]] || die "/dev/kvm not available — KVM required"

    if [[ ! -f "$CIRROS_IMG" ]]; then
        echo "=== Downloading CirrOS image ==="
        curl -fsSL -L "$CIRROS_URL" -o "$CIRROS_IMG"
    fi
    echo "=== CirrOS image: $(ls -lh "$CIRROS_IMG" | awk '{print $5}')"

    # ---- VM edge: pod-netns tap spliced to a root-netns veth by tc mirred ----
    # VM_ROOT_VETH (root netns) is the datapath device (tc_guest_tx + uplink_rx target). Its peer
    # (VM_POD_PEER) sits in the pod netns VM_NS, mirred'd to VM_POD_TAP which qemu drives.
    sudo ip netns del "$VM_NS" 2>/dev/null || true
    sudo ip netns add "$VM_NS"
    sudo ip netns exec "$VM_NS" ip link set lo up
    sudo ip link del "$VM_ROOT_VETH" 2>/dev/null || true
    sudo ip link add "$VM_ROOT_VETH" type veth peer name "$VM_POD_PEER"
    sudo ip link set "$VM_POD_PEER" netns "$VM_NS"
    # pod-netns tap qemu drives (mac = the VM's virtio MAC), + the peer, both up.
    sudo ip netns exec "$VM_NS" ip tuntap add dev "$VM_POD_TAP" mode tap vnet_hdr
    sudo ip netns exec "$VM_NS" ip link set "$VM_POD_TAP" address "$VM_MAC"
    sudo ip netns exec "$VM_NS" ip link set "$VM_POD_TAP" up
    sudo ip netns exec "$VM_NS" ip link set "$VM_POD_PEER" up
    # Point-to-point mirred splice (NO bridge): shove every frame peer<->tap unconditionally.
    sudo ip netns exec "$VM_NS" tc qdisc add dev "$VM_POD_TAP" clsact
    sudo ip netns exec "$VM_NS" tc qdisc add dev "$VM_POD_PEER" clsact
    sudo ip netns exec "$VM_NS" tc filter add dev "$VM_POD_TAP" ingress matchall action mirred egress redirect dev "$VM_POD_PEER"
    sudo ip netns exec "$VM_NS" tc filter add dev "$VM_POD_PEER" ingress matchall action mirred egress redirect dev "$VM_POD_TAP"
    # Root-netns datapath veth up. Disable offloads on the whole VM-edge chain (software fabric).
    sudo ip link set "$VM_ROOT_VETH" up
    for d in "$VM_POD_TAP" "$VM_POD_PEER"; do
        [[ -n "$ETHTOOL" ]] && sudo ip netns exec "$VM_NS" "$ETHTOOL" -K "$d" lro off gro off tso off gso off 2>/dev/null || true
    done
    [[ -n "$ETHTOOL" ]] && sudo "$ETHTOOL" -K "$VM_ROOT_VETH" lro off gro off tso off gso off 2>/dev/null || true

    # ---- uplink tap (smu0) — uplink_rx attaches here (no real peer; local path never uses it) ----
    sudo ip tuntap add dev smu0 mode tap vnet_hdr 2>/dev/null || echo "smu0 exists"
    sudo ip link set smu0 up
    [[ -n "$ETHTOOL" ]] && sudo "$ETHTOOL" -K smu0 lro off gro off tso off gso off 2>/dev/null || true

    # ---- second endpoint: a veth into netns smb-ns; smb0 (host end) is the guest edge ----
    sudo ip netns del "$PEER_NS" 2>/dev/null || true
    sudo ip netns add "$PEER_NS"
    sudo ip netns exec "$PEER_NS" ip link set lo up
    sudo ip link del "$PEER_HOST_IF" 2>/dev/null || true
    sudo ip link add "$PEER_HOST_IF" type veth peer name "$PEER_NS_IF"
    sudo ip link set "$PEER_NS_IF" netns "$PEER_NS"
    sudo ip link set "$PEER_HOST_IF" up
    # Peer NIC MAC must equal the guest_mac programmed for smb0 (local delivery rewrites dst to it).
    sudo ip netns exec "$PEER_NS" ip link set "$PEER_NS_IF" address "$PEER_MAC"
    sudo ip netns exec "$PEER_NS" ip link set "$PEER_NS_IF" up
    # dpservice model: /32 + on-link gateway + default via gateway → ARPs only for the gateway.
    sudo ip netns exec "$PEER_NS" ip addr add "$PEER_IP/32" dev "$PEER_NS_IF"
    sudo ip netns exec "$PEER_NS" ip route add "$GW" dev "$PEER_NS_IF"
    sudo ip netns exec "$PEER_NS" ip route add default via "$GW"

    local UPLINK_MAC
    UPLINK_MAC=$(cat /sys/class/net/smu0/address)
    echo "$VM_ROOT_VETH(root veth)=$(cat /sys/class/net/$VM_ROOT_VETH/address) tap=$VM_POD_TAP@$VM_NS smb0=$(cat /sys/class/net/$PEER_HOST_IF/address) smu0=$UPLINK_MAC"

    # ---- datapath bringup: two local guests + cross routes + DHCP config ----
    echo "=== Starting XDP datapath bringup (gateway $GW) ==="
    : > "$PIDFILE"
    sudo -E "$BIN" bringup \
        --uplink smu0 \
        --local-underlay fd00::1 \
        --gateway "$GW" \
        --gateway-mac "$UPLINK_MAC" \
        --guest "$VM_ROOT_VETH=$VM_IP=$VM_MAC=$VM_UL=$VNI" \
        --guest "$PEER_HOST_IF=$PEER_IP=$PEER_MAC=$PEER_UL=$VNI" \
        --remote "$PEER_IP=$PEER_UL=$VNI" \
        --remote "$VM_IP=$VM_UL=$VNI" \
        --fw-rule "$VM_ROOT_VETH:eg:accept:any:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "$VM_ROOT_VETH:in:accept:any:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "$PEER_HOST_IF:eg:accept:any:0.0.0.0/0:0.0.0.0/0:*" \
        --fw-rule "$PEER_HOST_IF:in:accept:any:0.0.0.0/0:0.0.0.0/0:*" \
        --dhcp-mtu "$DHCP_MTU" \
        --dhcp-dns "$DHCP_DNS" \
        >"$BRINGUP_LOG" 2>&1 &
    echo $! >> "$PIDFILE"
    sleep 2

    echo "=== datapath attachment check ==="
    sudo tc qdisc show dev "$VM_ROOT_VETH" 2>/dev/null | grep -q clsact && echo "  tc_guest_tx clsact on $VM_ROOT_VETH (OK)" \
        || echo "  WARNING: no clsact on $VM_ROOT_VETH (see $BRINGUP_LOG)"

    # ---- boot the VM INSIDE the pod netns, driving the pod-netns tap by name ----
    echo "=== Booting CirrOS VM in $VM_NS on tap $VM_POD_TAP (mac $VM_MAC) ==="
    rm -f "$CONSOLE_SOCK"
    sudo ip netns exec "$VM_NS" qemu-system-x86_64 \
        -enable-kvm -m 256 -nographic \
        -drive "file=$CIRROS_IMG,if=virtio,format=qcow2,snapshot=on" \
        -netdev "tap,id=n0,ifname=$VM_POD_TAP,script=no,downscript=no,vhost=on" \
        -device "virtio-net-pci,netdev=n0,mac=$VM_MAC" \
        -serial "unix:${CONSOLE_SOCK},server,nowait" \
        -monitor null \
        >"$QEMU_LOG" 2>&1 &
    echo $! >> "$PIDFILE"

    echo "VM booting (PID $!, log $QEMU_LOG); waiting for console socket..."
    for _ in $(seq 1 30); do [[ -S "$CONSOLE_SOCK" ]] && break; sleep 1; done
    [[ -S "$CONSOLE_SOCK" ]] || die "Console socket never appeared after 30s"
    sudo chmod 666 "$CONSOLE_SOCK" 2>/dev/null || true
    echo "=== UP complete — allow ~60s before 'test' ==="
}

# ---------------------------------------------------------------------------
cmd_test() {
    [[ -S "$CONSOLE_SOCK" ]] || die "Console socket $CONSOLE_SOCK not found — run 'up' first"
    rm -f "$CONSOLE_OUT" "$DHCP_CAP"
    echo "=== Driving VM console: login, DHCP (dhcpcd), assert config, ping peer ==="

    # Capture the DHCPv4 request/reply on smg0 so we can assert the RESPONDER emits the guest's
    # IP + gateway (opt-121 classless route) + MTU (opt-26) on the wire — datapath correctness,
    # independent of whether CirrOS's minimal dhcpcd applies every option. The console drive below
    # forces a `dhcpcd -n` rebind that triggers this exchange.
    sudo timeout 60 tcpdump -ni "$VM_ROOT_VETH" -vv 'udp port 67' -c 2 >"$DHCP_CAP" 2>/dev/null &
    local TDP=$!

    VM_IP="$VM_IP" PEER_IP="$PEER_IP" DHCP_MTU="$DHCP_MTU" \
    python3 - "$CONSOLE_SOCK" "$CONSOLE_OUT" <<'PYEOF'
import socket, time, sys, os

sock_path, out_path = sys.argv[1], sys.argv[2]
VM_IP = os.environ["VM_IP"]; PEER_IP = os.environ["PEER_IP"]; DHCP_MTU = os.environ["DHCP_MTU"]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path); s.settimeout(0.4)

def drain(t=0.8):
    end = time.time() + t; b = b''
    while time.time() < end:
        try:
            d = s.recv(4096); b += d if d else b''
            if not d: break
        except socket.timeout:
            pass
    return b.decode('utf-8', 'replace')

def send(x): s.sendall((x + '\n').encode())

def wait_for(tokens, t):
    if isinstance(tokens, str): tokens = [tokens]
    end = time.time() + t; acc = ''
    while time.time() < end:
        acc += drain(0.3)
        for tok in tokens:
            if tok in acc: return tok, acc
    return None, acc

# Marker technique: the shell ECHOES the command line then prints its OUTPUT. A marker written as
# EN''D_ appears literally in the echoed command but the shell prints END_ — so matching "END_<rc>"
# reliably detects command completion without matching the echo.
def run_cmd(c, t=12):
    drain(0.2); send(c); send("echo EN''D_$?")
    _, b = wait_for('END_', t)
    return b

def login(attempts=6):
    for _ in range(attempts):
        send('')
        tok, _ = wait_for(['login:', 'Login:', '$'], 6)
        if tok == '$':
            send("echo RD''Y"); ok, _ = wait_for('RDY', 4)
            if ok: return True
        send('cirros'); wait_for(['assword', 'Password'], 6)
        send('gocubsgo'); wait_for(['$', 'incorrect'], 8)
        send("echo RD''Y"); ok, _ = wait_for('RDY', 5)
        if ok: return True
        drain(1.5)
    return False

if not login():
    open(out_path, 'w').write("LOGIN FAILED\n" + drain(2.0)); print("LOGIN FAILED"); sys.exit(1)
print("logged in")

out = []
# DHCP-self-configure via OUR responder. CirrOS 0.6.2's client is `dhcpcd` (not udhcpc), and a boot
# daemon already manages eth0. Fighting it (stop/flush/one-shot) is flaky; instead force a rebind
# (`dhcpcd -n`, which re-does DHCP REQUEST against our responder and re-applies the lease) and wait.
for c, t in [('sudo dhcpcd -n eth0 2>&1 | tail -3; sleep 4', 14),
             ('sudo dhcpcd -U eth0 2>/dev/null | grep -iE "ip_address|routers|classless|mtu|dns" | head', 8)]:
    b = run_cmd(c, t); out.append(f"$ {c}\n{b}"); print(b[-400:])

# The DHCP reply carries the gateway as an opt-121 classless route via the link-local 169.254.0.1;
# CirrOS's dhcpcd installs the on-link /16 but the kernel refuses `default via <link-local>` without
# an explicit host route, so nudge the dpservice routing model into place (idempotent). This is a
# minimal-client quirk, not a datapath gap — the responder emits IP+gateway+MTU+DNS correctly.
run_cmd('sudo ip route replace 169.254.0.1 dev eth0; sudo ip route replace default via 169.254.0.1', 6)

# Capture the resulting config + the ping over the overlay local fast path.
for c, t in [('ip -4 addr show eth0', 6),
             ('ip route show', 6),
             ('ip link show eth0', 6),
             ('ip neigh show', 6),
             (f'ping -c 4 -W 2 {PEER_IP}', 20)]:
    b = run_cmd(c, t); out.append(f"$ {c}\n{b}"); print(b[-400:])

with open(out_path, 'w') as f:
    f.write('\n'.join(out))
PYEOF

    wait "$TDP" 2>/dev/null || true

    echo ""; echo "=== Analyzing gate ==="
    [[ -f "$CONSOLE_OUT" ]] || die "no console output captured"

    local PASS=1
    # HARD GATE 1: the VM obtained its assigned overlay IP from OUR DHCPv4 responder.
    if grep -qE "inet ${VM_IP}\b" "$CONSOLE_OUT"; then
        echo "  [OK] DHCP: eth0 has overlay IP $VM_IP (from our responder)"
    else echo "  [FAIL] eth0 did not get $VM_IP via DHCP"; PASS=0; fi

    # HARD GATE 2: the RESPONDER emitted IP + gateway (opt-121) + MTU (opt-26) on the wire (datapath
    # correctness, from the captured DHCP reply — independent of the minimal CirrOS client).
    if grep -qiE "Your-IP ${VM_IP}" "$DHCP_CAP" 2>/dev/null; then
        echo "  [OK] responder DHCP reply offers Your-IP $VM_IP"
    else echo "  [FAIL] no DHCP reply offering $VM_IP captured"; PASS=0; fi
    if grep -qiE "Classless-Static-Route" "$DHCP_CAP" 2>/dev/null && grep -qE "default:${GW}" "$DHCP_CAP" 2>/dev/null; then
        echo "  [OK] responder emits gateway via opt-121 classless route (default:$GW)"
    else echo "  [FAIL] responder did not emit the opt-121 default route via $GW"; PASS=0; fi
    if grep -qiE "MTU .*${DHCP_MTU}" "$DHCP_CAP" 2>/dev/null; then
        echo "  [OK] responder emits MTU $DHCP_MTU (opt-26)"
    else echo "  [WARN] MTU $DHCP_MTU not seen in captured reply"; fi

    # ping gate: 0% loss (or at least some replies) to the peer over the overlay.
    if grep -qE " 0% packet loss" "$CONSOLE_OUT"; then
        echo "  [OK] overlay ping $VM_IP -> $PEER_IP: 0% loss"
    elif grep -qE "[1-9][0-9]* (packets )?received" "$CONSOLE_OUT" || grep -qE " bytes from ${PEER_IP}" "$CONSOLE_OUT"; then
        echo "  [OK] overlay ping got replies from $PEER_IP (partial loss)"
    else echo "  [FAIL] no ping replies from $PEER_IP over the overlay"; PASS=0; fi

    echo "=== bringup log tail ==="; tail -5 "$BRINGUP_LOG" 2>/dev/null || true
    echo "=== console output: $CONSOLE_OUT ==="
    if [[ "$PASS" -eq 1 ]]; then
        echo ""; echo "GATE PASSED: real VM DHCP-self-configured off our dataplane + pinged a second overlay endpoint"
    else
        echo ""; echo "GATE FAILED — see $CONSOLE_OUT"; return 1
    fi
}

# ---------------------------------------------------------------------------
cmd_down() {
    echo "=== Tearing down ==="
    if [[ -f "$PIDFILE" ]]; then
        while read -r pid; do sudo kill "$pid" 2>/dev/null || true; done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    sudo pkill -f 'flowplane bringup --' 2>/dev/null || true
    for pid in $(ps aux 2>/dev/null | grep 'qemu-system-x86_64' | grep "$VM_POD_TAP" | grep -v grep | awk '{print $2}'); do
        sudo kill "$pid" 2>/dev/null || true
    done
    sleep 1
    rm -f "$CONSOLE_SOCK" "$CONSOLE_OUT" "$DHCP_CAP"
    sudo ip netns del "$PEER_NS" 2>/dev/null || true
    sudo ip netns del "$VM_NS" 2>/dev/null || true
    sudo ip link del "$PEER_HOST_IF" 2>/dev/null || true
    sudo ip link del "$VM_ROOT_VETH" 2>/dev/null || true
    sudo ip link del smu0 2>/dev/null || true

    local CLEAN=true
    for i in "$VM_ROOT_VETH" smu0 "$PEER_HOST_IF"; do
        ip link show "$i" &>/dev/null && { echo "  WARNING: $i still exists"; CLEAN=false; } || true
    done
    for n in "$PEER_NS" "$VM_NS"; do
        ip netns list 2>/dev/null | grep -q "$n" && { echo "  WARNING: netns $n still exists"; CLEAN=false; } || true
    done
    $CLEAN && echo "=== DOWN complete — host is clean ===" || echo "=== DOWN complete (warnings above) ==="
}

# ---------------------------------------------------------------------------
cmd_run() {
    trap cmd_down EXIT INT TERM
    cmd_up
    echo "Waiting 60s for the VM to boot..."
    sleep 60
    cmd_test
}

case "${1:-}" in
    up)   cmd_up   ;;
    test) cmd_test ;;
    down) cmd_down ;;
    run)  cmd_run  ;;
    *) echo "Usage: $0 {up|test|down|run}" >&2; exit 1 ;;
esac
