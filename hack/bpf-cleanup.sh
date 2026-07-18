#!/usr/bin/env bash
# bpf-cleanup.sh — free leaked flowplane BPF pins so clab destroy/recreate cycles
# and host-run netns scenarios don't accumulate kernel memory.
#
# WHY THIS EXISTS
#   flowplane pins its state maps to bpffs. The CONNTRACK map alone is an
#   LruHashMap with 1_048_576 pre-allocated entries (~100-150 MB of *kernel*
#   RAM per instance). Two pin locations leak:
#     * /sys/fs/bpf/flowplane            persistent `serve` dir (maps + links/)
#     * /sys/fs/bpf/flowplane-eph-<pid>  per-PID dir for bringup/tc-bringup/debug
#   A pinned map outlives the process that created it, and nothing sweeps these.
#   Every host-run scenario (test/*.sh run ./target/debug/flowplane directly on
#   the host) and every crash-restart leaves a full conntrack map behind. Over a
#   debugging session this reached ~30 GB and OOM-crashed the box. `clab destroy`
#   removes the kind/clab CONTAINERS but never touches host-side pins.
#
# WHAT IT DOES (idempotent; a no-op when nothing is leaked)
#   1. kills stray host flowplane processes (serve/bringup/tc-bringup)
#   2. rm -rf host /sys/fs/bpf/flowplane and /sys/fs/bpf/flowplane-eph-*
#      (removing the link pins detaches programs; removing the map pins drops the
#       last refcount, so the kernel frees the map memory)
#   3. repeats the sweep inside every still-running kind/clab node container
#
# USAGE
#   hack/bpf-cleanup.sh              # host + node containers
#   HOST_ONLY=1 hack/bpf-cleanup.sh  # skip the container sweep
#   make bpf-clean
set -euo pipefail

# --- privilege: bpffs pins and root-owned flowplane procs need root. On NixOS the
# real setuid sudo is /run/wrappers/bin/sudo; PATH-shadowing can break a bare `sudo`.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif [ -x /run/wrappers/bin/sudo ]; then
  SUDO=/run/wrappers/bin/sudo
else
  SUDO=sudo
fi

BPFFS="${BPFFS:-/sys/fs/bpf}"

# sweep_local: run inside whatever mount namespace we're invoked in (host, or a
# container via `docker exec`). $1 is a label for logging. Uses the caller's shell.
sweep_local_body() {
  bpffs="$1"
  # Kill stray flowplane processes so their held map FDs close before we unpin.
  # pkill returns 1 when nothing matched — not an error here.
  pkill -TERM -f 'flowplane (serve|bringup|tc-bringup)' 2>/dev/null || true
  # give them a moment to release; then hard-kill leftovers
  for _ in 1 2 3 4 5; do
    pgrep -f 'flowplane (serve|bringup|tc-bringup)' >/dev/null 2>&1 || break
    sleep 0.2 2>/dev/null || sleep 1
  done
  pkill -KILL -f 'flowplane (serve|bringup|tc-bringup)' 2>/dev/null || true

  removed=0
  if [ -d "$bpffs/flowplane" ]; then
    rm -rf "$bpffs/flowplane" && removed=$((removed + 1))
  fi
  for d in "$bpffs"/flowplane-eph-*; do
    [ -e "$d" ] || continue
    rm -rf "$d" && removed=$((removed + 1))
  done
  echo "  removed $removed flowplane pin dir(s)"
}
# Serialize the body so it can be shipped into `docker exec sh -c`.
SWEEP_BODY="$(declare -f sweep_local_body)"

echo "bpf-cleanup: host sweep ($BPFFS)"
$SUDO sh -c "$SWEEP_BODY; sweep_local_body '$BPFFS'"

if [ "${HOST_ONLY:-0}" = "1" ]; then
  echo "bpf-cleanup: HOST_ONLY set — skipping container sweep"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "bpf-cleanup: docker not on PATH — skipping container sweep"
  exit 0
fi

# Target the kind node containers (k0N-control-plane / k0N-worker) and the clab
# fabric containers (clab-xdp-ipv6-fabric-*). Match by name so we never touch an
# unrelated container.
mapfile -t CONTAINERS < <(docker ps --format '{{.Names}}' 2>/dev/null \
  | grep -E '^(clab-xdp-ipv6-fabric-|k[0-9]+-(control-plane|worker))' || true)

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "bpf-cleanup: no kind/clab node containers running — host sweep only"
  exit 0
fi

for c in "${CONTAINERS[@]}"; do
  echo "bpf-cleanup: container sweep ($c)"
  # Each kind node has its own /sys/fs/bpf; clean it while the container still exists.
  docker exec "$c" sh -c "$SWEEP_BODY; sweep_local_body '/sys/fs/bpf'" 2>/dev/null \
    || echo "  (skipped: $c has no shell or bpffs)"
done

echo "bpf-cleanup: done"
