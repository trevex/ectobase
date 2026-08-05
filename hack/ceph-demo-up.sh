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
#   MON       v6 mon endpoint     (default [fd00:db8:0:5::1]:6789)
#   POOL      RBD pool            (default replicapool)
CEPH_CTR="${CEPH_CTR:-clab-xdp-ipv6-fabric-ceph}"
MON="${MON:-[fd00:db8:0:5::1]:6789}"
POOL="${POOL:-replicapool}"
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,15p' "$0"; exit 0; fi
OUT=""; [ "${1:-}" = "--out" ] && OUT="${2:-}"
ex() { docker exec "$CEPH_CTR" "$@"; }
echo "== waiting for ceph health =="
for i in $(seq 1 60); do ex ceph -s 2>/dev/null | grep -qE 'HEALTH_OK|HEALTH_WARN' && break; sleep 5; done
ex ceph osd pool create "$POOL" 8 8 2>/dev/null || true
ex rbd pool init "$POOL" || true
KEY=$(ex ceph auth get-or-create-key client.rbd mon 'profile rbd' osd "profile rbd pool=$POOL")
FSID=$(ex ceph fsid)
printf 'CEPH_FSID=%s\nCEPH_MON=%s\nCEPH_POOL=%s\nCEPH_RBD_KEY=%s\n' "$FSID" "$MON" "$POOL" "$KEY" | tee "${OUT:-/dev/stdout}"
