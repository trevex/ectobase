#!/usr/bin/env bash
# af_xdp veth e2e for the nfkit uplink_fwd datapath. RESERVES hugepages and RESTORES the original
# vm.nr_hugepages on exit (trap). Injects the encapped fixture on the veth peer, captures the frame
# uplink_fwd tx's back (the decapped delivery), and writes it to $OUT_PCAP for the Rust test to
# byte-compare against the sim. Exits 77 (skip) if unprivileged / hugepages not reservable; 0 on OK.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + af_xdp + hugepage reserve need root)"

VV0=nfkitvv0; VV1=nfkitvv1
APP=0
APP_LOG="$(mktemp -t nfkit-afxdp-uplink.XXXXXX.log)"
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"
restore() {
  # Kill the (busy-polling) app FIRST — it inherits our stdout pipe; leaving it orphaned would
  # hang the parent forever (it never closes the pipe). Then restore hugepages + delete the veth.
  kill -9 "$APP" 2>/dev/null || true
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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETPROBE="${ROOT}/test/e2e/netprobe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$NETPROBE" ./cmd/netprobe )

ip link del "$VV0" 2>/dev/null || true
ip link add "$VV0" type veth peer name "$VV1"
ip link set "$VV0" up; ip link set "$VV1" up

# Redirect the app's output to a log (NOT our stdout pipe) so an orphan can't wedge the parent.
"$UPLINK_BIN" afxdp "$VV0" >"$APP_LOG" 2>&1 &
APP=$!
sleep 3  # EAL init + af_xdp XDP-program load on the veth

# Inject the encapped fixture on the peer SEVERAL times (af_xdp copy-mode on veth drops the first
# frame(s) during socket warmup), capture ALL decapped deliveries uplink_fwd tx's back out vv0, and
# write them to $OUT_PCAP. The Rust test asserts the exact sim-expected frame is among them (robust
# to a warmup artifact / af_xdp duplicates).
"$NETPROBE" pcap-replay \
  --in                "$IN_PCAP" \
  --iface             "$VV1" \
  --sniff-iface       "$VV1" \
  --out               "$OUT_PCAP" \
  --timeout           8 \
  --count-expect      1 \
  --repeat            8 \
  --repeat-interval-ms 200
echo "AFXDP UPLINK OK"
