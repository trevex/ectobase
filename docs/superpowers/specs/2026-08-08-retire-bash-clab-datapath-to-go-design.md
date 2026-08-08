# Retire the bash `hack/clab` fabric; port the datapath e2e to the Go lab — Design

**Date:** 2026-08-08
**Status:** approved (brainstorming)

## Goal

Leave `hack/` containing only genuine utilities + production artifacts; run the flowplane **datapath** end-to-end suite on the Go `test/lab` kind fabric; remove the bash containerlab fabric (`hack/clab` + `clab-up.sh`/`clab-down.sh`); and guarantee `lab down` leaves **zero host leftovers**.

This follows the completed Talos→kind substrate switch for `test/lab` (kindnet CNI, Ceph + the Tier-2 gate — all green). That effort deliberately did **not** touch `hack/clab`, because `hack/clab` is a *different* fabric serving a *different* test suite.

## Background: two fabrics, one to keep

- **`hack/clab`** — a lean *single-cluster* IPv6-BGP fabric (one kind cluster, cp+worker) whose purpose is the flowplane **datapath**: guest overlay ping, guest NAT egress, DHCPv6 leases, LB. Consumed by the `test/e2e` suite (all skip-gated live tests; **not** in CI).
- **`test/lab`** — the *multi-cluster* control-plane fabric (central + k02 + k03, kind + kindnet) for the ectobase substrate + Ceph + Tier-2. This is the strategic harness.

They share building blocks (containerlab, the `kind-node-fabric` image, VyOS/FRR), so the datapath scenarios can be re-homed onto `test/lab` and `hack/clab` retired.

## `hack/` disposition (from the audit)

| Script | Consumer | Disposition |
|---|---|---|
| `bpf-cleanup.sh` | Makefile | **keep** (utility) |
| `sync-chart-crds.sh` | Makefile | **keep** (utility) |
| `cni-install.sh` | Dockerfile.cni + CNI DaemonSet | **keep** (production artifact, not a lab script) |
| `kind-fabric-node/`, `dpdk/` | image sources | **keep** |
| `ceph-demo-up.sh`, `ceph-external-up.sh`, `csi-addons-up.sh`, `install-stack.sh`, `tier2-failover-e2e.sh`, `rook-ceph-up.sh` | only "port of" **comments** in `test/lab/internal/deploy/*.go` | **delete** (already ported to Go) |
| `kubevirt-vm-e2e.sh` | none | **delete** (dead) |
| `medik8s-up.sh`, `tier1-failover-e2e.sh` | chart README only | **delete** (Tier-1 dormant; revive via Go later if needed) |
| `kind-up.sh`, `kind-down.sh` | `test/e2e/kind_test.go` | **delete** (tests kind itself, not our code) |
| `clab-up.sh`, `clab-down.sh`, `clab/` (29 files), `multicluster-e2e.sh` | `test/e2e/{routebus,smoke_datapath,smoke_lb_dhcp,fabric}_test.go` + `env.go` | **migrate → delete** (Phase 2/3) |

## Plan (phased; one spec)

### Phase 1 — safe deletions (no behavior to re-prove)

Delete the already-ported, dead, Tier-1, and bare-kind scripts + `test/e2e/kind_test.go`. Update the `// port of <script>` comments in `test/lab/internal/deploy/{ceph,csiaddons,kubevirt}.go` to drop the file references (the Go code is the source of truth now) and remove the `medik8s-up`/`tier1-failover-e2e` mentions from `deploy/charts/ectobase/README.md`. Purely subtractive; `make chart-test` + the build stay green. **Do NOT touch `hack/clab`, `clab-up.sh`, `clab-down.sh`, or the datapath `test/e2e/*` yet.**

### Phase 2 — port the datapath e2e onto `test/lab` (the substance)

Add a datapath group under `test/lab/livetest` (live-tagged), reusing the machinery `TestCrossClusterOverlayPing` already proves: the flowplane DaemonSet, guest-netns setup, `grpcurl AttachInterface` @`127.0.0.1:1337` via the flowplane pod, and a static (`CGO_ENABLED=0`) Go probe `docker cp`'d into the node at `/` (kind `/tmp` is tmpfs — a documented gotcha).

Tests to land, each validated live on the kind fabric:
1. **`TestDhcpLeaseSmoke`** — a guest gets a real DHCPv6 lease from the flowplane responder (`cmd/tap-dhcp-probe`). The sole DHCPv6 conformance; highest value.
2. **`TestNatEgressSmoke`** — a guest endpoint egresses to an external v4 via the WAN edge (guest SNAT/NAT64), distinct from the node-level `TestNAT64Egress`.
3. **`TestUnderlayInferenceOnFabric`** — assert a kind node infers its fabric `/64` underlay (an explicit assertion, or folded into an existing test if redundant).
4. **`TestLbDistributeSmoke` (NEW)** — LB VIP distribution across backends. No existing test to port; **risk:** the in-node `flowplane serve` LB path had pre-existing rot, so this may surface real datapath work, not just a test port. If it proves to need datapath fixes beyond scope, land the test `t.Skip`ped with a documented reason + a follow-up, rather than blocking the phase.

Cross-node scenarios map to **cross-cluster** (k02↔k03) or same-node-on-k02, since kindnet forces 1 node/cluster. `TestCrossNodeOverlayPing` is already covered by `TestCrossClusterOverlayPing` → dropped.

Probe binaries (`tap-dhcp-probe`, `netprobe`/`netpkt`) are built by the test via `go build ./cmd/...` and copied in — no new images.

### Phase 3 — remove the bash clab fabric

Once Phase 2 tests are green: `git rm` `hack/clab/`, `hack/clab-up.sh`, `hack/clab-down.sh`, `hack/multicluster-e2e.sh`, `test/e2e/env.go`, and the migrated `test/e2e/{routebus,smoke_datapath,smoke_lb_dhcp,fabric}_test.go`. If `test/e2e` is left empty, remove the package. Update `README.md` (drop the `hack/clab` bring-up section; point at `test/lab`).

### Phase 4 — verify + harden `lab down`

- Full `lab test` sweep incl. the new datapath tests green on the kind fabric.
- **`lab down` leaves zero host leftovers** — the just-landed `cleanupHostRBD` + `<name>-mgmt` network removal become an explicit acceptance criterion, *validated on a real ceph+tier2 up→down*: after `lab down`, assert no `/dev/rbd*` / empty `/sys/bus/rbd/devices`, no `<name>-mgmt` docker network, no `fd00:cafe::/32` host route, and no lab `ip6tables` MASQUERADE rules. Add a small `livetest` (or a `lab down` self-check log) documenting the clean state.
- `make chart-test` + central envtests green; `git grep hack/clab` empty (outside docs/memory).

## Testing / acceptance criteria

- Phase 1: repo builds, `make chart-test` green, no dangling script references (`git grep` the deleted names → only docs/memory).
- Phase 2: each ported datapath test passes live on the `test/lab` kind fabric (LB may be a documented skip if it hits the known `flowplane serve` rot).
- Phase 3: `hack/clab` gone; `go vet ./test/e2e/...` (if the package remains) clean; README updated.
- Phase 4: full `lab test` green; a real ceph+tier2 `up`→`down` leaves zero host leftovers (rbd/network/route/iptables all clear).

## Out of scope

- Wiring `lab test` into CI (the datapath tests remain live/manual, as `test/e2e` was).
- Reviving Tier-1 (medik8s) in Go — deleted now; a future effort if needed.
- The unrelated stale `xdp-clab` docker network (a manual `docker network rm`; not created by `test/lab`).
- Any flowplane datapath feature work beyond what LB coverage minimally requires.

## Notes on isolation

Each datapath test is a self-contained `livetest` with one purpose, driven through the existing `AttachInterface`/probe seam — no shared mutable state between tests, and they run against the same fabric `lab up` produced. The probe binaries are the well-defined interface between the Go test and the in-node datapath.
