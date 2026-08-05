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

# The ceph-csi RBD nodeplugin does `modprobe rbd` at NodeStage (rbd map) time; kind nodes ship no
# kernel modules, so it fails ("Module rbd not found") unless rbd is already loaded in the HOST
# kernel the kind containers share. Load it once here (this is the host-side ceph enablement step).
# Harmless if already loaded; best-effort (a PVC still *provisions* without it — only pod/VM ATTACH
# needs the module).
( sudo modprobe rbd 2>/dev/null || modprobe rbd 2>/dev/null ) && echo "== host rbd module loaded ==" \
  || echo "WARN: could not modprobe rbd on the host — RBD volume ATTACH (VM boot) will fail until it is"
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
