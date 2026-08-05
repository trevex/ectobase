#!/usr/bin/env bash
set -euo pipefail
# Create the RBD pool on the shared clab ceph/demo fabric node + emit external-cluster
# connection params (fsid, mon, client key) for external ceph-csi. Dev-only, NOT production.
#
# Usage:
#   hack/ceph-demo-up.sh [--out params.env]   # create pool, print/emit params
#   hack/ceph-demo-up.sh --help
#
# Env overrides:
#   CEPH_CTR  ceph container name (default clab-xdp-ipv6-fabric-ceph)
#   MON       v6 mon endpoint     (default [fd00:db8:0:5::1]:3300 — the msgr-v2 port)
#   POOL      RBD pool            (default replicapool)
# NOTE: this ceph/demo mon is msgr-v2 ONLY (bound [fd00:db8:0:5::1]:3300; `ceph mon dump` shows no
# v1 addr — the demo pins the monmap to the :3300 endpoint under IPv6). librados/ceph-csi connect to
# :3300 as v2. Using the legacy v1 port 6789 gets connection-refused (nothing listens there).
CEPH_CTR="${CEPH_CTR:-clab-xdp-ipv6-fabric-ceph}"
MON="${MON:-[fd00:db8:0:5::1]:3300}"
POOL="${POOL:-replicapool}"
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,15p' "$0"; exit 0; fi

# --- host + kind-node prep so the ceph-csi RBD nodeplugin can `rbd map` (krbd) at ATTACH time ---
# A PVC *provisions* via librbd in the provisioner without any of this; it is ONLY needed when a pod
# or VM ATTACHES the RBD (NodeStage -> krbd map + mkfs), e.g. the tier2 VM boot. Three kind gotchas:
#   1. modprobe rbd (+nbd) on the HOST: kind nodes ship no modules but share the host kernel, so
#      loading once makes krbd available to every node (else "Module rbd not found").
#   2. remount /sys rw in each kind node: kind mounts /sys ro, but krbd maps by writing
#      /sys/bus/rbd/add -> EROFS "rbd: sysfs write failed" otherwise.
#   3. mount devtmpfs over /dev in each kind node: kind's /dev is a small tmpfs, so the kernel's
#      dynamically-created /dev/rbd0 node never appears -> mkfs.ext4 fails "not a block device".
#      devtmpfs surfaces all kernel device nodes. (NOTE: both remounts revert if a node restarts —
#      the tier2 gate restarts the killed pool AFTER the VM has moved off it, so that is fine.)
for m in rbd nbd; do sudo modprobe "$m" 2>/dev/null || modprobe "$m" 2>/dev/null || true; done
echo "== host rbd/nbd modules loaded =="
for n in $(docker ps --format '{{.Names}}' | grep -E 'control-plane|worker'); do
  docker exec "$n" sh -c 'mount -o remount,rw /sys 2>/dev/null; mountpoint -q /dev && grep -q "devtmpfs /dev" /proc/mounts || mount -t devtmpfs devtmpfs /dev 2>/dev/null' 2>/dev/null \
    && echo "== kind node $n prepped for krbd (/sys rw + devtmpfs /dev) ==" || echo "WARN: krbd prep on $n failed"
done
OUT=""; [ "${1:-}" = "--out" ] && OUT="${2:-}"
ex() { docker exec "$CEPH_CTR" "$@"; }
# Readiness = mon responsive + the OSD up+in. We do NOT gate on HEALTH_OK/WARN: the ceph/demo node
# runs a single v6 OSD and Squid's OSD_UNREACHABLE health check FALSE-POSITIVES on IPv6 (it claims
# the osd's [fd00:db8:0:5::1] public addr "is not in fd00:db8:0:5::/64 subnet" though it plainly is),
# leaving the cluster HEALTH_ERR forever. RBD provisions fine regardless; we mute the bogus check
# below so `ceph -s` reports HEALTH_WARN.
echo "== waiting for ceph mon + osd =="
for i in $(seq 1 60); do ex ceph osd stat 2>/dev/null | grep -qE '1 up|[1-9][0-9]* up' && break; sleep 5; done
# Mute the known-cosmetic v6 reachability false-positive (sticky: stays muted if it re-fires).
ex ceph health mute OSD_UNREACHABLE --sticky 2>/dev/null || true
ex ceph osd pool create "$POOL" 8 8 2>/dev/null || true
ex rbd pool init "$POOL" || true
KEY=$(ex ceph auth get-or-create-key client.rbd mon 'profile rbd' osd "profile rbd pool=$POOL")
FSID=$(ex ceph fsid)
printf 'CEPH_FSID=%s\nCEPH_MON=%s\nCEPH_POOL=%s\nCEPH_RBD_KEY=%s\n' "$FSID" "$MON" "$POOL" "$KEY" | tee "${OUT:-/dev/stdout}"
