# kind as the node substrate for the Go `test/lab` harness — Design

**Date:** 2026-08-07
**Status:** Approved (brainstorming)

## Problem

The Go `test/lab` harness runs its clusters as **Talos** containers (clab `kind: linux` nodes booting Talos from USERDATA). Talos container nodes on this host are **unstable**: they have no init to reap/forward signals, so they zombie and wedge — `lab down` hangs on the VyOS/Talos containers, and during the Tier-2 failover run a compute node spontaneously zombied (init died, API unreachable), so `docker kill` refused it (`"PID is zombie … use --init"`) and a restart did not rejoin. That instability blocks the Tier-2 fenced-failover gate (`TestTier2Failover`), which depends on a reliable node-down simulation.

Everything else in the harness works: Phase 6 proved cross-cluster overlay, RBD PVC binding, and KubeVirt/CDI/materializer bring-up on the Talos fabric. The blocker is specifically the Talos-container runtime instability.

## Goal

Make the Go-driven clab test env use **kind** clusters as its node substrate instead of Talos. kind nodes have a proper init (containerd/systemd), so `docker kill` and node-failure simulation are reliable and there is no zombie/wedge. This is a **test** harness, so we want **one** substrate that works — not a Talos/kind toggle. Talos is a worse fit here and is removed.

Success = `lab up` (kind) → `lab ceph` → `lab tier2 up` → the full `//go:build live` `livetest` suite green, **including `TestTier2Failover`**, on a stable fabric.

## Why kind works here

- **Stable node lifecycle:** kind nodes run a real init; no zombie/wedge, so `docker kill <node>` (the failover trigger) works and `down` doesn't hang.
- **Fabric-identity parity already exists:** the `ghcr.io/trevex/ectobase/kind-node-fabric:dev` image (built via the Makefile `KINDNODE_IMAGE` target, already present) runs a pre-kubelet `fabric-preboot` that reads `/etc/fabric/prefix`, puts the node `/64` identity `::1` on `dummy0`, pins `kubelet --node-ip` to it, and runs FRR unnumbered eBGP (AS 65100) announcing the node `/64` on the uplinks. That is the exact model Talos provided via GoBGP + `KubeNodeConfig.nodeIP`.
- **The deploy + test layers are substrate-agnostic:** `deploy.Ectobase`, `lab ceph`, `lab tier2`, and the whole `livetest` suite only run `kubectl`/`helm`/`grpcurl` against kubeconfigs. They are reused unchanged.
- **The guest VM does not need to fully boot for the gate:** the Tier-2 gate is fence + reschedule + RBD-follows; kind's CDI-import/boot limits don't block it.

## Architecture

The clab fabric (VyOS switches sw1/sw2, VyOS edges + NAT64/DNS64, WAN sim, in-fabric registry, optional ceph node) and the `fabric.View` derivation (per-cluster `/48`/`/64`, node identities, RA/BGP addressing, registry/egress addresses) are **unchanged**. Only the *cluster nodes* change from Talos to kind, and the bring-up path branches accordingly.

### Reused unchanged
- `internal/config` (per-cluster FNV `/48` derivation), `internal/fabric` (`View`), the VyOS/edge/NAT64/WAN/registry templates + `internal/vyos`, `internal/render` core, `internal/clab`, `internal/exec`, `internal/wait`, `internal/registry`.
- `internal/deploy` (`Ectobase`, `CephDemo`/`CephCSI`/`CSIAddons`/`EnsureNodeKrbd`, `KubeVirtCDI`/`VMMaterializer`/`PatchCentralCSIClusterID`, `k8s` helpers) — substrate-agnostic.
- `topology.Ceph`, `topology.Tier2`, `topology.Deploy`, and the whole `livetest` suite (`overlay_test`, `ceph_test`, `tier2_test`, the fabric/apivip/egress/registry checks).
- The `kind-node-fabric` image + its `fabric-preboot`.
- The flowplane datapath fixes from Phase 6 (`bpf_fib_lookup` egress, `--underlay-within`, accept_ra) — those are dataplane, not harness substrate.

### Changed
- **`internal/config`:** the substrate is kind. No `driver` toggle (a test env needs one working substrate). Node topology stays "N nodes per cluster", default 1; kind maps node-1 → control-plane, nodes 2..N → workers (see Node topology).
- **`internal/render`:** for each cluster, emit a clab `k8s-kind` node (image `kind-node-fabric:dev`, `startup-config: <cluster>-kind.yaml`, a boot-wait) instead of the Talos node + USERDATA. Render the per-cluster kind `Cluster` config: `ipFamily: ipv6`, `disableDefaultCNI: true`, `kubeProxyMode: none`, control-plane + `(nodes-1)` workers, each with `extraMounts` for the node's `prefix` + shared `uplinks`, **and `containerdConfigPatches` pointing at the in-fabric registry mirror** (fabric-parity, mirroring Talos `machine.registries.mirrors`). Render the per-node `prefix` file (= the node's derived `/64`) + the `uplinks` file (the fabric uplink ifaces).
- **`topology` bring-up:** branch to a kind path — clab's `k8s-kind` deploy creates/owns the kind clusters (no `talosctl gen`/`bootstrap`); collect each kind kubeconfig into `build/<name>/<cluster>.kubeconfig` (where the harness already expects it); then the **existing** Cilium install (`disableDefaultCNI` + kube-proxy-replacement, same values as today) + `deploy.Ectobase`. Host→fabric route + host egress setup reused.
- **Fabric-only egress for kind (the one genuinely new networking bit):** the VyOS switches already send RA on the node uplinks; the kind node must take that as its default route and not let docker's default win — the analog of the Talos harness's `accept_ra=2` + docker-default-demote. Implemented in the `kind-node-fabric` `fabric-preboot` (accept RA on the uplinks + demote/raise-metric the docker default) and validated live, exactly as the Talos egress was iterated. Registry reachability (`fd00:29::5`) rides the same fabric routing.

### Removed (cleanup)
- Talos substrate: `internal/talos`, `templates/talos/**` (cluster-patch, node-patch, bgp-peer), the Talos clab node + USERDATA rendering, the Talos bring-up branch (bootstrap loop, API-VIP wait), the `taints:{}` post-gen strip, and any Talos-only config/derivation.
- The bash `hack/clab` fabric (`hack/clab/**`, `hack/clab-up.sh`, `hack/clab-down.sh`) and the tier2/ceph/csi bash scripts the Go `lab` already replaces (`hack/tier2-failover-e2e.sh`, `hack/ceph-demo-up.sh`, `hack/ceph-external-up.sh`, `hack/csi-addons-up.sh`, `hack/install-stack.sh`, `hack/multicluster-e2e.sh`, `hack/rook-ceph-up.sh`) — audited before deletion so no live test still references them.

## Node topology

Default **1 node per cluster** → one kind control-plane node whose `/64` = the cluster's derived `NodeNet64`, identity `::1` (matches `kind-node-fabric`'s convention and the derivation's node-index-1 identity). Multi-node kind (control-plane + workers, each needing a distinct `/64`) is **out of scope** (YAGNI — the lab runs 1 node/cluster).

## Data flow (bring-up)

`lab up` → render (clab topo with `k8s-kind` nodes + kind `Cluster` configs + `prefix`/`uplinks` files) → clab deploy (VyOS/edges/NAT64/WAN/registry + kind clusters created by clab; `kind-node-fabric` preboot puts dummy0 identity + `kubelet --node-ip` + FRR `/64` BGP + fabric egress) → collect kubeconfigs → Cilium per cluster → `deploy.Ectobase` (central + reflector + compiler + brokers + pools) → pools Ready.

## Error handling / live-iteration risks

- **Fabric-only egress for kind:** RA-default-vs-docker-default is the known-hard bit (the Talos harness needed several iterations). Treated as a live checkpoint; fallback is to demote the docker default explicitly in preboot.
- **Registry mirror reachability from kind containerd:** the kind node must reach `fd00:29::5:5000` over the fabric; validated by a successful `:dev` + upstream pull during `lab up`.
- **Cilium on kind:** same values as today (ipv6-only, tunnel, kube-proxy-replacement); kind's `disableDefaultCNI` makes nodes NotReady until Cilium lands (bring-up waits accordingly).
- **krbd on kind:** kind nodes give the kubelet a usable `/dev` (unlike Talos's tmpfs `/dev` with no `mount` binary); `EnsureNodeKrbd`'s node-side approach may Just Work on kind, else the nodeplugin-devtmpfs approach (already implemented) applies. Verified at `lab ceph`.

## Testing

- **Unit (CI-safe, TDD):** config/derivation, the kind render (golden `Cluster` configs + clab topo with `k8s-kind` nodes), any pure helpers — `go test ./internal/... ./topology/...`.
- **Live checkpoints (fabric host):** `lab up` (kind) all clusters Ready; `lab ceph` + `TestRBDPVCBinds`; `lab tier2 up` + `TestTier2Failover`; the full `livetest` suite (overlay ping, apivip, egress, registry, BGP/ECMP).

## Success criteria

1. `lab up` brings up the kind fabric — all clusters Ready, cross-cluster overlay + NAT64 egress work.
2. `lab ceph` + `TestRBDPVCBinds` green.
3. `lab tier2 up` + **`TestTier2Failover` green** — the fenced cross-cluster VM reschedule, reliably (kind `docker kill` works).
4. The Talos substrate + bash `hack/clab` are removed; `make chart-test`, central envtests, and the lab unit tests stay green.

## Non-goals

- Multi-node kind clusters (>1 node/cluster).
- A Talos/kind driver toggle or retaining the Talos substrate.
- Changing the deploy pipeline or the `livetest` assertions (substrate-agnostic; reused).
- Full guest-OS boot of the Tier-2 VM (the gate is fence + reschedule + RBD-follows).
