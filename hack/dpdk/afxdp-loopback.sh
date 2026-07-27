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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETPROBE="${ROOT}/test/e2e/netprobe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$NETPROBE" ./cmd/netprobe )

BIN="${L2FWD_BIN:?set L2FWD_BIN to the built example path}"
"$BIN" afxdp "$VV0" &
L2FWD=$!
sleep 2

# Craft the loopback probe frame (Eth/IPv4/UDP/"x") as a temp pcap without sending,
# then replay it via pcap-replay which sniffs on the same veth for the MAC-swapped echo.
TMP_IN="$(mktemp /tmp/loopback-in-XXXXXX.pcap)"
TMP_OUT="$(mktemp /tmp/loopback-out-XXXXXX.pcap)"
# Extend the cleanup trap to also remove temp pcaps (TMP_IN/TMP_OUT now defined).
trap 'ip link del "$VV0" 2>/dev/null || true; rm -f "$TMP_IN" "$TMP_OUT"' EXIT

"$NETPROBE" send \
  --iface    "$VV1" \
  --eth-src  "11:11:11:11:11:11" \
  --eth-dst  "22:22:22:22:22:22" \
  --ip-dst   "10.0.0.2" \
  --l4       udp \
  --payload  "x" \
  --count    0 \
  --write-pcap "$TMP_IN"

"$NETPROBE" pcap-replay \
  --in          "$TMP_IN" \
  --iface       "$VV1" \
  --sniff-iface "$VV1" \
  --out         "$TMP_OUT" \
  --timeout     5 \
  --count-expect 1
RC=$?

[ $RC -eq 0 ] && echo "LOOPBACK OK"
kill "$L2FWD" 2>/dev/null || true
exit $RC
