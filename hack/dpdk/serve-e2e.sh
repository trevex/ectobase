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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Build netprobe (pure-Go, cgo-free injector+sniffer).
NETPROBE="${ROOT}/test/e2e/netprobe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$NETPROBE" ./cmd/netprobe ) \
  || { echo "failed to build netprobe" >&2; exit 1; }

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
SNIFF_PID=0
SERVE_LOG="$(mktemp -t fp-serve-e2e.XXXXXX.log)"
SNIFF_OUT="$(mktemp -t fp-serve-e2e-sniff.XXXXXX.out)"
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"

cleanup() {
  # Kill serve FIRST (it busy-polls + would wedge on our pipe if orphaned), then restore hugepages,
  # then delete the uplink veth + both netns. serve deletes its own preallocated fpg{i} veths on exit.
  kill -TERM "$SERVE_PID" 2>/dev/null || true
  kill -TERM "$SNIFF_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$SERVE_PID" 2>/dev/null || break; sleep 0.3; done
  kill -9 "$SERVE_PID" 2>/dev/null || true
  sysctl -qw vm.nr_hugepages="$ORIG_HP" 2>/dev/null || true
  ip link del "$UPL0" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # Best-effort: clean any leftover preallocated pool veths if serve died mid-startup.
  ip link del fpg0 2>/dev/null || true
  ip link del fpg1 2>/dev/null || true
  rm -f "$SNIFF_OUT"
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
# External route for the exact destination (SNAT arm) + attach guest A, THEN NAT source (needs the
# iface attached → find_iface_by_vni_ipv4) + egress-allow firewall keyed by the attached interface_id.
#
# The route table is EXACT-match /32 on BOTH backends (eBPF + DPDK `route4_insert`/`route4_get` key on
# the full 4-byte address; the control-plane drops prefix_len for v4 — see `DpdkMapWriter::route_upsert`
# / the eBPF ROUTES map). A `0.0.0.0/0` prefix therefore inserts key `(vni, 0.0.0.0)` and NEVER matches
# a real destination → `process_guest_tx` returns `Pass` (route miss) and nothing egresses. Program the
# EXACT external dst `$EXT_DST/32`, mirroring the proven nfkit `guest_tx_datapath.rs` fixture
# (`add_route4(VNI, EXT_DST, ..)`).
"$CLIENT_BIN" route --addr "$GRPC" --vni "$VNI" --prefix "$EXT_DST/32" --nexthop "$NEXTHOP_UL" --external

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

# ── part (a): guest→fabric egress + SNAT port-range assertion ────────────────────────────────────────
# TX is inside NS_A; RX (fpul1) is in the root netns — cross-netns split:
#   1. Start sniff-only (--count 0) on fpul1 in the ROOT netns (background).
#   2. Inject the guest frame inside NS_A via a separate "send" invocation.
#   3. Wait for the sniffer; read its output (it prints the extracted SNAT'd sport).
echo "── part (a): guest→fabric egress ──"
"$NETPROBE" send-sniff \
  --count 0 \
  --rx-iface "$UPL1" \
  --rx-outer-ipv6 \
  --rx-inner-ip-dst "$EXT_DST" \
  --rx-l4 tcp \
  --want-outer-ipv6-nh 4 \
  --extract inner-tcp-sport \
  --sport-range "${NAT_PORT_MIN}-${NAT_PORT_MAX}" \
  --count-min 1 \
  --timeout 14 \
  >"$SNIFF_OUT" 2>&1 &
SNIFF_PID=$!

# Allow the sniffer to arm (mirrors the original 0.5 s sleep before injection).
sleep 0.7

ip netns exec "$NS_A" "$NETPROBE" send \
  --iface "$A_IFNAME" \
  --eth-src "$A_MAC" \
  --eth-dst "$GATEWAY_MAC" \
  --ip-src "$GUEST_IP" \
  --ip-dst "$EXT_DST" \
  --l4 tcp \
  --sport "$SPORT" \
  --dport "$DPORT" \
  --payload hello-egress \
  --count 10 \
  --interval-ms 200

wait "$SNIFF_PID"; SNIFF_RC=$?; SNIFF_PID=0
if [ "$SNIFF_RC" -ne 0 ]; then
  echo "PART A FAIL: no encapped egress captured on $UPL1 (or SNAT port out of range)" >&2
  cat "$SNIFF_OUT" >&2
  exit 1
fi
# Extract the SNAT'd sport from the sniffer output line (e.g. "OK: captured 1 frame(s); inner-tcp-sport=20042").
NAT_PORT="$(grep -oE 'inner-tcp-sport=[0-9]+' "$SNIFF_OUT" | head -1 | cut -d= -f2)"
[ -n "$NAT_PORT" ] || { echo "PART A FAIL: could not extract nat_port from sniffer output" >&2; cat "$SNIFF_OUT" >&2; exit 1; }
echo "PART A OK: encapped egress captured; SNAT nat_ip=$NAT_IP nat_port=$NAT_PORT"
cat "$SNIFF_OUT"

# ── part (b): NAT-return delivery ────────────────────────────────────────────────────────────────────
# TX is on fpul1 in the root netns; RX is inside NS_A — cross-netns split:
#   1. Start sniff-only (--count 0) inside NS_A (background).
#   2. Inject the encapped return on fpul1 in the root netns.
#   3. Wait; assert at least 1 candidate frame arrived.
echo "── part (b): NAT-return delivery ──"
# The encapped return is an IP-in-IPv6 frame: outer IPv6 (dst=A_UNDERLAY, nh=4) / inner IPv4 (dst=NAT_IP).
# We sniff inside NS_A for a plain inner IPv4 TCP arriving at GUEST_IP (after decap+DNAT reversal).
ip netns exec "$NS_A" "$NETPROBE" send-sniff \
  --count 0 \
  --rx-iface "$A_IFNAME" \
  --rx-inner-ip-dst "$GUEST_IP" \
  --rx-l4 tcp \
  --count-min 1 \
  --timeout 14 \
  >"$SNIFF_OUT" 2>&1 &
SNIFF_PID=$!

sleep 1.0  # let the in-ns sniffer arm

# encapped return: outer IPv6(src=NEXTHOP_UL, dst=A_UNDERLAY, nh=4) / inner IPv4(src=EXT_DST, dst=NAT_IP)
# TCP(sport=DPORT, dport=NAT_PORT).  Uses --encap ipip so netprobe builds the IP-in-IPv6 outer.
"$NETPROBE" send \
  --iface "$UPL1" \
  --eth-src "$GATEWAY_MAC" \
  --eth-dst "$A_MAC" \
  --encap ipip \
  --outer-ipv6-src "$NEXTHOP_UL" \
  --outer-ipv6-dst "$A_UNDERLAY" \
  --ip-src "$EXT_DST" \
  --ip-dst "$NAT_IP" \
  --l4 tcp \
  --sport "$DPORT" \
  --dport "$NAT_PORT" \
  --payload hello-return \
  --count 10 \
  --interval-ms 200

wait "$SNIFF_PID"; SNIFF_RC=$?; SNIFF_PID=0
if [ "$SNIFF_RC" -ne 0 ]; then
  echo "PART B FAIL: NAT-return not delivered to the guest" >&2
  cat "$SNIFF_OUT" >&2
  exit 1
fi
echo "PART B OK: NAT-return decapped + reverse-DNAT'd + delivered to the guest"
cat "$SNIFF_OUT"
echo "SERVE_E2E_AB_OK"

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

  echo "── part (c): guest-A → guest-B (LcoreRing) ──"
  # TX inside NS_A; RX inside NS_B — cross-netns split (same pattern as A+B).
  ip netns exec "$NS_B" "$NETPROBE" send-sniff \
    --count 0 \
    --rx-iface "$B_IFNAME" \
    --rx-inner-ip-src "$GUEST_IP" \
    --rx-inner-ip-dst "$GUEST_B_IP" \
    --rx-l4 tcp \
    --count-min 1 \
    --timeout 14 \
    >"$SNIFF_OUT" 2>&1 &
  SNIFF_PID=$!

  sleep 1.0

  ip netns exec "$NS_A" "$NETPROBE" send \
    --iface "$A_IFNAME" \
    --eth-src "$A_MAC" \
    --eth-dst "$GATEWAY_MAC" \
    --ip-src "$GUEST_IP" \
    --ip-dst "$GUEST_B_IP" \
    --l4 tcp \
    --sport 23456 \
    --dport 80 \
    --payload a2b \
    --count 12 \
    --interval-ms 200

  wait "$SNIFF_PID"; SNIFF_RC=$?; SNIFF_PID=0
  if [ "$SNIFF_RC" -ne 0 ]; then
    echo "PART C FAIL (stretch): guest-A->guest-B not delivered" >&2
    cat "$SNIFF_OUT" >&2
    echo "PART C (stretch) did not pass — not blocking (a)+(b)" >&2
  else
    echo "PART C OK: guest-A -> guest-B delivered cross-lcore"
    cat "$SNIFF_OUT"
    echo "SERVE_E2E_C_OK"
  fi
fi

echo "SERVE E2E OK"
exit 0
