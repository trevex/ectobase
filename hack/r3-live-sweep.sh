#!/usr/bin/env bash
# R3 live clab sweep: rebuild the R3-affected app images (:dev), then bring up the
# fabric and run the live suite. flowplane (Rust) is unaffected by the api group
# split, so it is NOT rebuilt. Run from the repo root inside `nix develop`.
set -uo pipefail
cd "$(dirname "$0")/.."
log() { echo "=== [r3-sweep $(date +%H:%M:%S)] $* ==="; }

log "build hub images (apiserver/controller/broker)"
( cd hub \
  && GOWORK=off CGO_ENABLED=0 go build -o hub-apiserver ./cmd/apiserver \
  && GOWORK=off CGO_ENABLED=0 go build -o hub-controller ./cmd/controller \
  && GOWORK=off CGO_ENABLED=0 go build -o hub-broker ./cmd/broker \
  && docker build -f Dockerfile.apiserver  -t ghcr.io/trevex/ectobase/hub-apiserver:dev  . \
  && docker build -f Dockerfile.controller -t ghcr.io/trevex/ectobase/hub-controller:dev . \
  && docker build -f Dockerfile.broker     -t ghcr.io/trevex/ectobase/hub-broker:dev     . ; \
  rm -f hub-apiserver hub-controller hub-broker ) || { log "hub image build FAILED"; exit 1; }

log "build netplane + cni images"
make image-netplane || { log "image-netplane FAILED"; exit 1; }
make image-cni      || { log "image-cni FAILED"; exit 1; }

log "lab up (pushes :dev images to the in-fabric mirror + deploys the chart)"
sudo -E env "PATH=$PATH" make lab-up      || { log "lab-up FAILED"; exit 1; }
log "lab ceph"
sudo -E env "PATH=$PATH" make lab-ceph     || { log "lab-ceph FAILED"; exit 1; }
log "lab tier2-up"
sudo -E env "PATH=$PATH" make lab-tier2-up || { log "lab-tier2-up FAILED"; exit 1; }
log "lab test (the live suite — the per-group RBAC gate)"
sudo -E env "PATH=$PATH" make lab-test     || { log "lab-test FAILED"; exit 2; }

log "R3 LIVE SWEEP PASSED"
