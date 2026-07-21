#!/usr/bin/env bash
# net_tap rte_flow e2e for nfkit: run the `nettap_flow` example, which programs a 5-tuple→DROP
# rte_flow rule on the DPDK net_tap PMD. net_tap lowers rte_flow to a kernel tc-flower filter on the
# backing Linux tap device (the `iface=` value, e.g. nfkittap0), so we assert a `flower` filter with
# the matched dst-ip/dst-port key appears via `tc filter show`.
#
# RESERVES hugepages and RESTORES the original vm.nr_hugepages on exit (trap) — the M7 self-restoring
# pattern. The app's output goes to a LOGFILE (never our stdout pipe); the app is kill -9'd in the
# trap (the M7 pipe-hang lesson). The DPDK-created tap is deleted in the trap too.
#
# Exit 0 = flower filter with the matched key observed; 77 (skip) = not root / hugepages not
# reservable / app printed FLOW UNSUPPORTED / no flower filter (missing kernel cls_flower or net_tap
# flow lowering); other = a hard failure.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (net_tap creation + tc + hugepage reserve need root)"

: "${NETTAP_BIN:?set NETTAP_BIN to the built nettap_flow example}"

IFACE="${NETTAP_IFACE:-nfkittap0}"
APP=0
APP_LOG="$(mktemp -t nfkit-nettap-flow.XXXXXX.log)"
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"
restore() {
  # Kill the app FIRST — it holds the rule alive in a sleep and inherits our stdout pipe; leaving it
  # orphaned would wedge the parent (it never closes the pipe). Then restore hugepages + delete the
  # DPDK-created tap.
  kill -9 "$APP" 2>/dev/null || true
  sysctl -qw vm.nr_hugepages="$ORIG_HP" 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
}
trap restore EXIT
# Reserve hugepages (idempotent); restored to $ORIG_HP by the trap on ANY exit. net_tap uses
# --no-huge (software backend), but reserve anyway to keep the harness uniform with M7.
sysctl -qw vm.nr_hugepages=1024 2>/dev/null || true

# Run the example; output to the log (NOT our stdout pipe) so an orphan can't wedge the parent.
"$NETTAP_BIN" tap "$IFACE" >"$APP_LOG" 2>&1 &
APP=$!

# Wait (bounded) for the app to either program the rule (RULE OK) or bail (FLOW UNSUPPORTED / error /
# early death). net_tap creates the "$IFACE" Linux tap during EAL vdev probe.
deadline=$(( SECONDS + 20 ))
while :; do
  if grep -q "RULE OK" "$APP_LOG" 2>/dev/null; then
    break
  fi
  if grep -q "FLOW UNSUPPORTED" "$APP_LOG" 2>/dev/null; then
    echo "----- app log -----" >&2; cat "$APP_LOG" >&2
    need_skip "net_tap/kernel reports rte_flow unsupported (no cls_flower / flow lowering)"
  fi
  if grep -q "RULE ERROR" "$APP_LOG" 2>/dev/null; then
    echo "----- app log -----" >&2; cat "$APP_LOG" >&2
    echo "FAIL: rule creation errored" >&2; exit 1
  fi
  if ! kill -0 "$APP" 2>/dev/null; then
    echo "----- app log -----" >&2; cat "$APP_LOG" >&2
    echo "FAIL: nettap_flow exited before programming the rule" >&2; exit 1
  fi
  [ "$SECONDS" -lt "$deadline" ] || { echo "----- app log -----" >&2; cat "$APP_LOG" >&2; \
    echo "FAIL: timed out waiting for RULE OK" >&2; exit 1; }
  sleep 0.3
done

echo "----- app log -----" >&2; cat "$APP_LOG" >&2

# Inspect the tc-flower filter net_tap installed on the backing tap. net_tap attaches its flow
# filters to the `multiq` root qdisc at `parent 1:` (NOT the ingress qdisc) — check that plus the
# ingress/`parent ffff:` forms for robustness across DPDK/kernel versions.
TC_OUT="$( { tc filter show dev "$IFACE" parent 1: 2>/dev/null; \
             tc filter show dev "$IFACE" root 2>/dev/null; \
             tc filter show dev "$IFACE" ingress 2>/dev/null; \
             tc filter show dev "$IFACE" parent ffff: 2>/dev/null; } )"
echo "----- tc filter show dev $IFACE -----" >&2
echo "$TC_OUT" >&2

if ! grep -q "flower" <<<"$TC_OUT"; then
  need_skip "no flower filter on $IFACE (missing kernel cls_flower or net_tap flow lowering)"
fi

# Assert the flower filter carries BOTH match keys the app programmed: the dst ip (in the CORRECT
# byte order — 10.0.0.9, not the byte-reversed 9.0.0.10) AND the dst port. Requiring the exact ip
# locks in the network-order fix in Match5Drop.
if grep -q "dst_ip 10\.0\.0\.9" <<<"$TC_OUT" \
   && grep -Eq "dst_port 443|dst_port 0x01bb" <<<"$TC_OUT"; then
  echo "NETTAP FLOW OK (flower filter dst_ip 10.0.0.9 + dst_port 443 present on $IFACE)"
  exit 0
fi

echo "FAIL: flower filter present but missing the exact keys (dst_ip 10.0.0.9 + dst_port 443)" >&2
exit 1
