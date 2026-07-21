#!/usr/bin/env bash
# af_xdp veth e2e for the nfkit uplink_fwd datapath. RESERVES hugepages and RESTORES the original
# vm.nr_hugepages on exit (trap). Injects the encapped fixture on the veth peer, captures the frame
# uplink_fwd tx's back (the decapped delivery), and writes it to $OUT_PCAP for the Rust test to
# byte-compare against the sim. Exits 77 (skip) if unprivileged / hugepages not reservable; 0 on OK.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + af_xdp + hugepage reserve need root)"

VV0=nfkitvv0; VV1=nfkitvv1
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"
restore() {
  sysctl -qw vm.nr_hugepages="$ORIG_HP" 2>/dev/null || true
  ip link del "$VV0" 2>/dev/null || true
}
trap restore EXIT
# Reserve hugepages (idempotent); restored to $ORIG_HP by the trap on ANY exit.
sysctl -qw vm.nr_hugepages=1024 2>/dev/null || true
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || need_skip "hugepages not reservable"

: "${UPLINK_BIN:?set UPLINK_BIN to the built uplink_fwd example}"
: "${IN_PCAP:?set IN_PCAP to the encapped input fixture pcap}"
: "${OUT_PCAP:?set OUT_PCAP to the capture destination}"

ip link del "$VV0" 2>/dev/null || true
ip link add "$VV0" type veth peer name "$VV1"
ip link set "$VV0" up; ip link set "$VV1" up

"$UPLINK_BIN" afxdp "$VV0" &
APP=$!
sleep 2

# Inject the encapped fixture on the peer; capture the decapped delivery (eth dst = GUEST_MAC
# 66:66:66:66:66:00) uplink_fwd tx's back out vv0. Write it to $OUT_PCAP.
python3 - "$VV1" "$IN_PCAP" "$OUT_PCAP" <<'PY'
import sys, time
from scapy.all import rdpcap, sendp, wrpcap, Ether, AsyncSniffer
iface, in_pcap, out_pcap = sys.argv[1], sys.argv[2], sys.argv[3]
frame = bytes(rdpcap(in_pcap)[0])
snf = AsyncSniffer(iface=iface, count=1, timeout=6,
                   lfilter=lambda p: p.haslayer(Ether) and p[Ether].dst == "66:66:66:66:66:00")
snf.start(); time.sleep(0.3)
sendp(Ether(frame), iface=iface, verbose=0)
res = snf.stop()
assert res and len(res) == 1, "did not capture the decapped delivery frame"
wrpcap(out_pcap, res[0])
print("AFXDP UPLINK OK")
PY
RC=$?
kill "$APP" 2>/dev/null || true
exit $RC
