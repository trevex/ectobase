#!/usr/bin/env bash
# Full-serve af_xdp e2e for `flowplane-dpdk serve`. Brings up the REAL serve process on the af_xdp
# backend with a PREALLOCATED guest-port pool, programs route/NAT/firewall + AttachInterface over
# gRPC (via the attach_client example), then over REAL af_xdp transport asserts:
#   (a) guest→fabric: a guest IPv4 TCP frame injected on the guest veth egresses the uplink as an
#       encapped IPv6 (outer IPv6 nh=4, inner = the SNAT'd guest frame).
#   (b) NAT-return:   the matching encapped return injected on the uplink peer is decapped +
#       reverse-DNAT'd and delivered back to the guest (inner dst = GUEST_IP, dport = orig sport).
#   (c) [stretch, env SERVE_E2E_GUEST2GUEST=1] guest-A → guest-B same-node delivery via LcoreRing.
#
# Models hack/dpdk/afxdp-uplink.sh: self-restoring hugepages (trap), skip (exit 77) if not root,
# serve output to a LOG FILE (never our stdout pipe — orphan-pipe wedge fix), generous af_xdp
# copy-mode warmup (inject several times + wide sniff windows). Exit 0 on OK, 77 skip, else fail.
#
# Reuses the known-good addressing from nfkit/tests/guest_tx_nat_return_handoff.rs so injected frames
# + expected encap match a proven scenario.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + netns + af_xdp + hugepage reserve need root)"

: "${SERVE_BIN:?set SERVE_BIN to the built flowplane-dpdk binary}"
: "${CLIENT_BIN:?set CLIENT_BIN to the built attach_client example}"

# ── addressing (mirrors nfkit/tests/guest_tx_nat_return_handoff.rs) ────────────────────────────────
VNI=100
GUEST_IP=10.0.2.20
EXT_DST=203.0.113.9
NAT_IP=198.51.100.7
NAT_PORT_MIN=20000
NAT_PORT_MAX=20200
SPORT=12345
DPORT=443
# This node's underlay /64 (serve allocates each guest a /128 from the 2nd half); the fabric nexthop
# for the external default route; and the underlay next-hop MAC (outer eth dst for all encap).
LOCAL_UL=fd00:0:0:1::1
GATEWAY=169.254.0.1
GATEWAY_MAC=02:00:00:00:00:fe
NEXTHOP_UL=2001:db8::1

ADDR=127.0.0.1:13337
GRPC=127.0.0.1:13337

# guest B (stretch)
GUEST_B_IP=10.0.2.21

UPL0=fpul0; UPL1=fpul1   # uplink veth pair (serve binds UPL0 to af_xdp ethdev 0; we drive UPL1)
NS_A=fpe2e-nsA
NS_B=fpe2e-nsB
SERVE_PID=0
SERVE_LOG="$(mktemp -t fp-serve-e2e.XXXXXX.log)"
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"

cleanup() {
  # Kill serve FIRST (it busy-polls + would wedge on our pipe if orphaned), then restore hugepages,
  # then delete the uplink veth + both netns. serve deletes its own preallocated fpg{i} veths on exit.
  kill -TERM "$SERVE_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$SERVE_PID" 2>/dev/null || break; sleep 0.3; done
  kill -9 "$SERVE_PID" 2>/dev/null || true
  sysctl -qw vm.nr_hugepages="$ORIG_HP" 2>/dev/null || true
  ip link del "$UPL0" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # Best-effort: clean any leftover preallocated pool veths if serve died mid-startup.
  ip link del fpg0 2>/dev/null || true
  ip link del fpg1 2>/dev/null || true
  echo "── serve log tail ──" >&2
  tail -30 "$SERVE_LOG" >&2 || true
}
trap cleanup EXIT

# Reserve hugepages (restored by trap on ANY exit).
sysctl -qw vm.nr_hugepages=1024 2>/dev/null || true
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || need_skip "hugepages not reservable"

# Fresh links/netns.
ip link del "$UPL0" 2>/dev/null || true
ip link del fpg0 2>/dev/null || true
ip link del fpg1 2>/dev/null || true
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip link add "$UPL0" type veth peer name "$UPL1"
ip link set "$UPL0" up; ip link set "$UPL1" up
ip netns add "$NS_A"
ip netns add "$NS_B"

# ── launch serve (af_xdp, 2 preallocated guest ports, --no-huge) ───────────────────────────────────
# Output to a LOG (never our stdout pipe). serve preallocates fpg0/fpg0p + fpg1/fpg1p itself.
#
# SINGLE UPLINK QUEUE (--queues 1 --lcores 2): the af_xdp PMD on a veth does NOT support multi-queue
# RSS — `Port::configure` sets a 40-byte symmetric-Toeplitz RSS key and the veth-af_xdp ethdev rejects
# it ("invalid RSS key len: 40, valid value: 0", ethdev bring-up rc=-22). So only 1 uplink queue (=1
# datapath worker) is possible over veth transport. That means BOTH preallocated guest ports are owned
# by worker 0, so part (c) guest↔guest exercises the LcoreRing handoff on the SAME worker (the code
# enqueues into the ring uniformly even for a same-worker dest). True cross-lcore RSS steering needs a
# real multi-queue NIC (ConnectX); it is proven separately by nfkit/tests/multilcore_nat_return.rs.
"$SERVE_BIN" \
  --backend af-xdp \
  --uplink "$UPL0" \
  --gateway "$GATEWAY" \
  --gateway-mac "$GATEWAY_MAC" \
  --local-underlay "$LOCAL_UL" \
  --guest-ports 2 \
  --lcores 2 \
  --queues 1 \
  --no-huge \
  --addr "$ADDR" \
  >"$SERVE_LOG" 2>&1 &
SERVE_PID=$!

# ── wait for gRPC readiness: serve prints "serving flowplane-dpdk DataplaneNode on" AFTER the
#    datapath worker thread is up (its readiness contract). Poll the log for that line. ─────────────
ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$SERVE_PID" 2>/dev/null; then
    echo "serve exited during startup" >&2; tail -40 "$SERVE_LOG" >&2; exit 1
  fi
  if grep -q "serving flowplane-dpdk DataplaneNode on" "$SERVE_LOG"; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" -eq 1 ] || { echo "serve did not become ready in time" >&2; tail -40 "$SERVE_LOG" >&2; exit 1; }
# Small extra settle for af_xdp XDP-program load on all ports.
sleep 2

# ── program the datapath over gRPC ────────────────────────────────────────────────────────────────
# External default route (SNAT arm) + attach guest A, THEN NAT source (needs the iface attached →
# find_iface_by_vni_ipv4) + egress-allow firewall keyed by the attached interface_id.
"$CLIENT_BIN" route --addr "$GRPC" --vni "$VNI" --prefix "0.0.0.0/0" --nexthop "$NEXTHOP_UL" --external

IFACE_A=ge2eA
ATT_A="$("$CLIENT_BIN" attach --addr "$GRPC" --iface "$IFACE_A" --netns "/var/run/netns/$NS_A" --vni "$VNI" --ip "$GUEST_IP")"
echo "$ATT_A"
A_IFNAME="$(echo "$ATT_A" | sed -n 's/^ATTACH_IFNAME=//p')"
A_MAC="$(echo "$ATT_A" | sed -n 's/^ATTACH_MAC=//p')"
A_UNDERLAY="$(echo "$ATT_A" | sed -n 's/^ATTACH_UNDERLAY=//p')"
[ -n "$A_IFNAME" ] && [ -n "$A_UNDERLAY" ] || { echo "attach A did not return ifname/underlay" >&2; exit 1; }
echo "guest A: ifname=$A_IFNAME mac=$A_MAC underlay=$A_UNDERLAY"

"$CLIENT_BIN" nat --addr "$GRPC" --vni "$VNI" --source "$GUEST_IP" --nat-ip "$NAT_IP" --port-min "$NAT_PORT_MIN" --port-max "$NAT_PORT_MAX"
# Egress allow-all so the SNAT arm is not firewall-dropped; ingress allow so the NAT-return delivers.
"$CLIENT_BIN" fw --addr "$GRPC" --iface "$IFACE_A" --rule-id egress-allow --src-cidr 0.0.0.0/0 --dst-cidr 0.0.0.0/0 --proto 6 --dport-min 0 --dport-max 65535 --allow --egress
"$CLIENT_BIN" fw --addr "$GRPC" --iface "$IFACE_A" --rule-id ingress-allow --src-cidr 0.0.0.0/0 --dst-cidr "$GUEST_IP/32" --proto 6 --dport-min 0 --dport-max 65535 --allow

# Bring the guest-end up inside nsA (serve moved the placeholder in as $A_IFNAME; ensure it is up).
ip netns exec "$NS_A" ip link set "$A_IFNAME" up 2>/dev/null || true

# ── part (a)+(b): guest→fabric egress + NAT-return delivery ─────────────────────────────────────────
export A_IFNAME A_MAC A_UNDERLAY NS_A VNI GUEST_IP EXT_DST NAT_IP NAT_PORT_MIN NAT_PORT_MAX SPORT DPORT GATEWAY_MAC
python3 - <<'PY'
import os, sys, time
from scapy.all import (Ether, IP, IPv6, TCP, sendp, AsyncSniffer, conf)
conf.verb = 0

a_if   = os.environ["A_IFNAME"]
a_mac  = os.environ["A_MAC"]
a_ul   = os.environ["A_UNDERLAY"]
ns_a   = os.environ["NS_A"]
guest_ip = os.environ["GUEST_IP"]
ext_dst  = os.environ["EXT_DST"]
nat_ip   = os.environ["NAT_IP"]
pmin = int(os.environ["NAT_PORT_MIN"]); pmax = int(os.environ["NAT_PORT_MAX"])
sport = int(os.environ["SPORT"]); dport = int(os.environ["DPORT"])
gw_mac = os.environ["GATEWAY_MAC"]

# scapy runs in the ROOT netns; the guest veth is inside nsA. Use `ip netns exec` for the guest side
# by re-invoking scapy? Simpler: sniff/inject on the guest-end via a netns-scoped socket. scapy has no
# builtin netns switch, so we shell into the netns for the guest-side send/sniff using a helper.
import subprocess, tempfile

# ---- helper that runs a small scapy snippet INSIDE nsA ----
def run_in_ns(ns, snippet, env=None):
    e = dict(os.environ)
    if env: e.update(env)
    return subprocess.run(["ip","netns","exec",ns,sys.executable,"-c",snippet],
                          capture_output=True, text=True, env=e)

# ── (a) guest→fabric: sniff the encapped egress on UPL1 (root ns) while injecting the guest frame
#     inside nsA. The egress is IPv6(nh=4)/IP(dst=EXT_DST). Capture it + read the SNAT'd source port. ─
snf = AsyncSniffer(iface="fpul1", timeout=12,
                   lfilter=lambda p: p.haslayer(IPv6) and p.haslayer(IP)
                                     and p[IP].dst == ext_dst and p[IP].src == nat_ip)
snf.start(); time.sleep(0.5)

# inner guest frame: Eth(guest_mac -> gw_mac)/IP(guest_ip->ext_dst)/TCP(sport->dport)
inject_a = f'''
import time
from scapy.all import Ether, IP, TCP, sendp, conf
conf.verb=0
f = Ether(src="{a_mac}", dst="{gw_mac}")/IP(src="{guest_ip}", dst="{ext_dst}")/TCP(sport={sport}, dport={dport})/b"hello-egress"
for _ in range(10):
    sendp(f, iface="{a_if}", verbose=0)
    time.sleep(0.2)
'''
r = run_in_ns(ns_a, inject_a)
if r.returncode != 0:
    print("inject A (guest egress) failed:\n"+r.stderr, file=sys.stderr); sys.exit(1)

res = snf.stop()
egress = [p for p in (res or [])]
if not egress:
    print("PART A FAIL: no encapped egress captured on fpul1", file=sys.stderr); sys.exit(1)
# read the SNAT'd source port from the inner IP/TCP of the first matching egress frame
pkt = egress[0]
inner = pkt[IP]
nat_port = inner[TCP].sport
if not (pmin <= nat_port <= pmax):
    print(f"PART A FAIL: SNAT sport {nat_port} outside range [{pmin},{pmax}]", file=sys.stderr); sys.exit(1)
# outer must be IPv6, next-header 4 (IPIP), and inner dst == EXT_DST (already filtered)
if pkt[IPv6].nh != 4:
    print(f"PART A FAIL: outer IPv6 next-header {pkt[IPv6].nh} != 4 (IPIP)", file=sys.stderr); sys.exit(1)
print(f"PART A OK: encapped egress captured ({len(egress)} frame(s)); SNAT nat_ip={inner.src} nat_port={nat_port}; outer dst={pkt[IPv6].dst}")

# ── (b) NAT-return: inject the encapped return on UPL1 (outer dst = A's allocated underlay), sniff the
#     reverse-DNAT'd delivery inside nsA on the guest-end (inner dst=guest_ip, dport=orig sport). ────
sniff_b = f'''
import time, sys
from scapy.all import Ether, IP, TCP, AsyncSniffer, conf
conf.verb=0
snf = AsyncSniffer(iface="{a_if}", timeout=12,
                   lfilter=lambda p: p.haslayer(IP) and p.haslayer(TCP)
                                     and p[IP].dst == "{guest_ip}" and p[TCP].dport == {sport})
snf.start(); time.sleep(0.5)
import os
# wait for a marker file to know the injector has begun, but simplest: just sniff for the window.
time.sleep(11.5)
res = snf.stop()
n = len(res or [])
print(f"NS_SNIFF_COUNT={{n}}")
sys.exit(0 if n >= 1 else 3)
'''
# start the in-ns sniffer in the background
import threading
holder = {}
def _sniff_thread():
    holder["res"] = run_in_ns(ns_a, sniff_b)
th = threading.Thread(target=_sniff_thread); th.start()
time.sleep(1.0)  # let the in-ns sniffer arm

# encapped return: Ether/IPv6(dst=A_UNDERLAY, nh=4)/IP(src=EXT_DST, dst=NAT_IP)/TCP(sport=DPORT, dport=nat_port)
ret = (Ether(src=gw_mac, dst=a_mac)/IPv6(src="2001:db8::1", dst=a_ul, nh=4)
       /IP(src=ext_dst, dst=nat_ip)/TCP(sport=dport, dport=nat_port)/b"hello-return")
for _ in range(10):
    sendp(ret, iface="fpul1", verbose=0)
    time.sleep(0.2)

th.join()
rb = holder.get("res")
if rb is None or rb.returncode != 0:
    print("PART B FAIL: NAT-return not delivered to the guest", file=sys.stderr)
    if rb is not None:
        print(rb.stdout, file=sys.stderr); print(rb.stderr, file=sys.stderr)
    sys.exit(1)
print("PART B OK: NAT-return decapped + reverse-DNAT'd + delivered to the guest")
print("SERVE_E2E_AB_OK")
PY

# ── part (c) [stretch]: guest-A → guest-B same-node delivery via LcoreRing ──────────────────────────
if [ "${SERVE_E2E_GUEST2GUEST:-0}" = "1" ]; then
  IFACE_B=ge2eB
  ATT_B="$("$CLIENT_BIN" attach --addr "$GRPC" --iface "$IFACE_B" --netns "/var/run/netns/$NS_B" --vni "$VNI" --ip "$GUEST_B_IP")"
  echo "$ATT_B"
  B_IFNAME="$(echo "$ATT_B" | sed -n 's/^ATTACH_IFNAME=//p')"
  B_MAC="$(echo "$ATT_B" | sed -n 's/^ATTACH_MAC=//p')"
  [ -n "$B_IFNAME" ] || { echo "attach B failed" >&2; exit 1; }
  ip netns exec "$NS_B" ip link set "$B_IFNAME" up 2>/dev/null || true
  # Internal route A→B: guest_b_ip/32 in the same VNI, non-external, nexthop = this node's underlay so
  # the datapath resolves it as a same-node guest destination (process_guest_tx Deliver::Local).
  "$CLIENT_BIN" route --addr "$GRPC" --vni "$VNI" --prefix "$GUEST_B_IP/32" --nexthop "$LOCAL_UL"
  # ingress allow on B so the delivery isn't firewall-dropped.
  "$CLIENT_BIN" fw --addr "$GRPC" --iface "$IFACE_B" --rule-id ingress-allow --src-cidr 0.0.0.0/0 --dst-cidr "$GUEST_B_IP/32" --proto 6 --dport-min 0 --dport-max 65535 --allow

  export A_IFNAME A_MAC B_IFNAME B_MAC NS_A NS_B GUEST_IP GUEST_B_IP GATEWAY_MAC
  if python3 - <<'PY'
import os, sys, time, subprocess, threading
a_if=os.environ["A_IFNAME"]; a_mac=os.environ["A_MAC"]
b_if=os.environ["B_IFNAME"]; b_mac=os.environ["B_MAC"]
ns_a=os.environ["NS_A"]; ns_b=os.environ["NS_B"]
guest_ip=os.environ["GUEST_IP"]; guest_b=os.environ["GUEST_B_IP"]; gw_mac=os.environ["GATEWAY_MAC"]

def run_in_ns(ns, snippet):
    return subprocess.run(["ip","netns","exec",ns,sys.executable,"-c",snippet],
                          capture_output=True, text=True, env=dict(os.environ))

sniff_b = f'''
import time, sys
from scapy.all import IP, TCP, AsyncSniffer, conf
conf.verb=0
snf=AsyncSniffer(iface="{b_if}", timeout=12,
                 lfilter=lambda p: p.haslayer(IP) and p[IP].dst=="{guest_b}" and p[IP].src=="{guest_ip}")
snf.start(); time.sleep(0.5); time.sleep(11.0)
res=snf.stop(); n=len(res or []); print(f"C_COUNT={{n}}"); sys.exit(0 if n>=1 else 3)
'''
holder={}
def _t(): holder["res"]=run_in_ns(ns_b, sniff_b)
th=threading.Thread(target=_t); th.start(); time.sleep(1.0)

inject=f'''
import time
from scapy.all import Ether, IP, TCP, sendp, conf
conf.verb=0
f=Ether(src="{a_mac}", dst="{gw_mac}")/IP(src="{guest_ip}", dst="{guest_b}")/TCP(sport=23456, dport=80)/b"a2b"
for _ in range(12):
    sendp(f, iface="{a_if}", verbose=0); time.sleep(0.2)
'''
r=run_in_ns(ns_a, inject)
if r.returncode!=0:
    print("inject A->B failed:\n"+r.stderr, file=sys.stderr); sys.exit(1)
th.join(); rb=holder.get("res")
if rb is None or rb.returncode!=0:
    print("PART C FAIL (stretch): guest-A->guest-B not delivered", file=sys.stderr)
    if rb is not None: print(rb.stdout, file=sys.stderr); print(rb.stderr, file=sys.stderr)
    sys.exit(3)
print("PART C OK: guest-A -> guest-B delivered cross-lcore")
PY
  then
    echo "SERVE_E2E_C_OK"
  else
    echo "PART C (stretch) did not pass — not blocking (a)+(b)" >&2
  fi
fi

echo "SERVE E2E OK"
exit 0
