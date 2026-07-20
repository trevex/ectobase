#!/usr/bin/env bash
# af_xdp veth loopback e2e for the nfkit l2fwd example. Requires root + reserved hugepages.
# Exits 77 (skip) if prerequisites are missing; 0 on success; non-zero on failure.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + af_xdp need CAP_NET_ADMIN)"
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || need_skip "no hugepages reserved (sudo sysctl vm.nr_hugepages=1024)"

VV0=nfkitvv0; VV1=nfkitvv1
cleanup() { ip link del "$VV0" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip link add "$VV0" type veth peer name "$VV1"
ip link set "$VV0" up; ip link set "$VV1" up

BIN="${L2FWD_BIN:?set L2FWD_BIN to the built example path}"
"$BIN" afxdp "$VV0" &
L2FWD=$!
sleep 2

python3 - "$VV1" <<'PY'
import sys, time
from scapy.all import Ether, IP, UDP, sendp, AsyncSniffer
iface=sys.argv[1]
snf=AsyncSniffer(iface=iface, count=1, timeout=5,
                 lfilter=lambda p: p.haslayer(Ether) and p[Ether].src=="22:22:22:22:22:22")
snf.start(); time.sleep(0.3)
sendp(Ether(src="11:11:11:11:11:11",dst="22:22:22:22:22:22")/IP(dst="10.0.0.2")/UDP()/b"x", iface=iface, verbose=0)
res=snf.stop()
assert res and len(res)==1, "did not receive the MAC-swapped frame back"
print("LOOPBACK OK")
PY
RC=$?
kill "$L2FWD" 2>/dev/null || true
exit $RC
