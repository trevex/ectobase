# Tier-2 Live Gate (Two-Cluster Reschedule) — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-05
**Context:** The live validation deferred by Phase 5b (`2026-08-05-tier2-failover-fencing-design.md` §8/§9). Proves the Tier-2 fence-gated failover **for real** on the existing clab fabric: a stateful KubeVirt VM reschedules from a lost compute pool to a healthy one, fenced from outside via a shared Ceph `NetworkFence` + reflector route-withdrawal, with its RBD disk following.

## 1. Goal

Stand up the missing prerequisites and a best-effort live gate that exercises the real Tier-2 path end-to-end: `poolLost` → whole-pool fence (storage + network, from outside the dead pool) → cross-pool re-bind → the VM boots on the healthy pool with the **same** RBD disk → recovery releases the fence. Behavioral proof: the Ceph `osd blocklist` actually contains the fenced pool's client, the network route is actually withdrawn, and the disk's sentinel data survives the move.

## 2. What already exists (reused, not built)

The exploration confirmed the multi-cluster substrate is **done**:
- **3-cluster clab fabric** (`hack/clab/ipv6-fabric.clab.yml`, `hack/clab-up.sh`): **k01 = central** (aggregated apiserver + controller + kine + the single shared **reflector** on `[fd00:db8:0:1::1]:1338`), **k02 / k03 = compute pools**, on one IPv6 BGP-unnumbered fabric (FRR ToRs sw1/sw2; each node announces a /64 via a baked-in fabric-preboot). Cross-cluster overlay routing is proven by `hack/multicluster-e2e.sh`.
- **Broker binary** (`central/cmd/broker/main.go`) with `--central-kubeconfig` / `--downstream-kubeconfig` / `--cluster-name` + a Heartbeater (ClusterPool lease + capacity) + `SyncCompiledVMs` + `ReportStatus` (NodePrefixes). Cross-cluster auth via minted ServiceAccount tokens (the `multicluster-e2e.sh` pattern).
- **Failover reconciler + real `StorageFencer`/`NetworkFencer`**, **reflector `RouteBusAdmin`**, **agent /64 Node annotation**, **vm-materializer** (RBD DataVolume *and* containerDisk), **volume-materializer** + `CompiledVolumeAttachment` reconciler, **`hack/kubevirt-vm-e2e.sh`** (real VM boot on the overlay), **`hack/rook-ceph-up.sh`** — all merged.

So the effort is only: shared Ceph on the fabric, external ceph-csi + csi-addons placement, the broker Deployment, controller flag-wiring, VM/Volume fixtures, and the gate script.

## 3. Architecture

```
        clab IPv6 BGP fabric (existing hack/clab/ipv6-fabric.clab.yml)
 ┌──────────────┬───────────────────┬───────────────────┬────────────────────┐
 │ k01 CENTRAL  │ k02  POOL A       │ k03  POOL B       │ ceph  (NEW fabric   │
 │ apiserver    │ broker+agent+dp   │ broker+agent+dp   │ node, /64           │
 │ controller   │ ceph-csi(ext)─────┼── ceph-csi(ext)───┼─► fd00:db8:0:5::1    │
 │ reflector◄───┤                   │                   │   mon 6789          │
 │ ceph-csi(ext)│                   │                   │   replicapool (RBD) │
 │ + csi-addons │  (fence executor: k01 creates NetworkFence CRs here)        │
 └──────┬───────┴───────────────────┴───────────────────┴────────────────────┘
        │ central fences from OUTSIDE k02 (both reachable without k02):
        │   NetworkFencer → reflector(k01).SetFence(k02 /64s)   → routes withdrawn
        │   StorageFencer → NetworkFence CR (k01) → csi-addons → ceph osd blocklist(k02 client)
```

**Why csi-addons lives in k01 (not the compute clusters):** the storage fence must execute even when the fenced pool is **dead**. The central controller's `StorageFencer` creates the `NetworkFence` CR against its own client (`mgr.GetClient()` = k01), so csi-addons + an external ceph-csi instance run in **k01** as a **fence executor** (k01 runs no VMs; this ceph-csi exists only to drive `NetworkFence` against the shared Ceph). Compute clusters (k02/k03) run external ceph-csi only, to attach VM RBDs.

**Why the Ceph node is on the fabric:** the `NetworkFence` blocklists the node's Ceph-client IP, which must fall inside the /64 the fence targets. So Ceph must be reachable over the v6 fabric — a **dedicated clab node** with its own /64 (`fd00:db8:0:5::/64`, mon `fd00:db8:0:5::1`) and the fabric-preboot/FRR sidecar, so each compute node's client connection is seen from its **/64 underlay** (the exact fence coordinate). A standalone `docker run` on a v4 network would make the blocklist never match.

## 4. Components

### 4.1 Shared Ceph fabric node
- Add a `ceph` node to `hack/clab/ipv6-fabric.clab.yml`: image `quay.io/ceph/demo:latest`, dual-homed `eth1→sw1`/`eth2→sw2`, the same fabric-preboot/BGP-unnumbered mechanism the kind nodes use (sidecar in its netns or a `ceph/demo`+fabric-preboot image), announcing `fd00:db8:0:5::/64`. Env: `MON_IP=fd00:db8:0:5::1`, `CEPH_PUBLIC_NETWORK` covering the fabric v6 space, persistent `ceph-etc`/`ceph-data` volumes.
- `hack/ceph-demo-up.sh` (post-deploy): create `replicapool`; emit external-cluster params (fsid/clusterID, `[fd00:db8:0:5::1]:6789` mon, admin/client cephx key) to a small artifact the ceph-csi installs consume.

### 4.2 External ceph-csi + csi-addons
- `hack/ceph-external-up.sh <cluster>`: install ceph-csi in **external-cluster mode** (clusterID=fsid, monitors=the fabric mon) + the provisioner/node cephx Secret + a `ceph-rbd` StorageClass. Called for **k01, k02, k03**.
- On **k01 only**, additionally install the **csi-addons controller + `NetworkFence` CRD** (`hack/csi-addons-up.sh`, pinned version) — the fence executor. Wire into `hack/install-stack.sh` behind `INSTALL_CEPH_EXTERNAL=1` / `INSTALL_CSI_ADDONS=1`.

### 4.3 Broker Deployment (ectobase chart)
- `deploy/charts/ectobase/templates/broker.yaml` (gated `{{- if .Values.broker.enabled }}`): runs `central-broker:dev` with `--cluster-name={{ .Values.broker.clusterName }}`, `--central-kubeconfig=/secrets/central/kubeconfig` (mounted Secret, minted-token pattern), downstream = in-cluster.
- RBAC: a downstream SA/ClusterRole (write `Compiled*` CRDs; read `nodes`, KubeVirt `VirtualMachineInstance`); the central token identity needs `patch clusterpools/status` + read `Compiled*` on k01 (central-side ClusterRole).
- Chart values: `broker.enabled`, `broker.clusterName`, `broker.centralKubeconfigSecret`, `images.centralBroker`.
- Build+load the `central-broker` image (extend `central/hack/smoke.sh`'s host-build of central images).

### 4.4 Central controller flag-wiring
- `central/config/controller.yaml` `args: []` → `-reflector-admin=[fd00:db8:0:1::1]:1338`, `-csi-driver=<rbd provisioner>`, `-csi-secret-name`/`-csi-secret-namespace` (the k01 cephx secret csi-addons uses). Now the deployed failover controller runs the **real** `StorageFencer` (NetworkFence in k01 → csi-addons → shared Ceph) + `NetworkFencer` (dials the k01 reflector admin). Absent flags still default to `DenyFencer` (fail-safe).

### 4.5 VM + Volume fixtures
- `test/e2e/fixtures/multicluster-tier2/`: a `VirtualMachine` (central, bound k02) + a `Volume` (RBD, `storageClass: ceph-rbd`) → compiler emits `CompiledVM` + `CompiledVolumeAttachment` (`clusterName=k02`) → k02 broker → materializer boots the RBD-backed VM. Reuses the existing compiler/scheduler/materializer.

## 5. The gate — `hack/tier2-failover-e2e.sh`

Best-effort, dev-only (`--help`), not CI-wired (needs the full clab fabric + Ceph). Mirrors `tier1-failover-e2e.sh` / `multicluster-e2e.sh`. Assumes `clab-up.sh` fabric + the stacks deployed.

1. **Bring-up:** central (k01); ectobase chart on k02/k03 with `broker.enabled` (clusterName k02/k03) + external ceph-csi everywhere; csi-addons in k01. `ClusterPool` k02 & k03 registered (broker heartbeat → Ready). Assert both pools Ready + `NodePrefixes` populated (agent-stamped /64s).
2. **Boot stateful VM on k02:** apply the VM + RBD Volume → VMI Running on k02 → write a **sentinel file** onto the RBD disk → a peer (k03) reaches the VM's overlay IP.
3. **Kill k02:** `docker kill` the k02 node → its ClusterPool lease goes stale.
4. **Assert fence bit:** (a) a `NetworkFence` CR in k01 for each k02 /64 → `status.result=Succeeded`; (b) `docker exec <ceph-node> ceph osd blocklist ls` contains k02's client; (c) the reflector withdrew k02's routes → the peer can no longer reach the old overlay IP; (d) the VM re-bound to `spec.clusterName=k03`.
5. **Assert reschedule:** k03 broker materializes the VM → k03 ceph-csi attaches the **same RBD** (released from fenced k02) → VMI Running on k03 → the **sentinel file is intact** → reachable.
6. **Recovery/release:** restart the k02 node → broker returns → GC's the rebound CompiledVM → drain confirmed → central releases k02's fence → assert the `ceph osd blocklist` entry for k02 is **gone** + k02's routes re-announce.

## 6. Testing

- **Automated (CI-safe):** `make chart-test` render coverage for the broker template + RBAC + ceph-csi values + controller flags; the `central-broker` image builds. The already-green **multi-envtest Tier-2** remains the authoritative logic gate.
- **Best-effort (manual):** the `hack/tier2-failover-e2e.sh` script is the live gate — run on a dev host with the clab fabric.

## 7. Scope & build order

**In scope:** ceph/demo fabric node + `ceph-demo-up.sh`; external ceph-csi (`ceph-external-up.sh`) + csi-addons-in-k01 (`csi-addons-up.sh`) + `install-stack.sh` wiring; broker chart Deployment + RBAC + `central-broker` image; controller flag-wiring; VM/Volume fixtures; the `hack/tier2-failover-e2e.sh` gate.

**Build order (each independently checkpointed):**
1. **Ceph fabric node + external ceph-csi** — prove an RBD PVC binds cross-cluster from the shared Ceph (k02 and k03).
2. **csi-addons-in-k01** — prove a hand-applied `NetworkFence` CR reaches `Succeeded` and the client lands in `ceph osd blocklist`.
3. **Broker deploy + controller flags** — prove ClusterPool lease + `NodePrefixes` + the real fencers are wired (a manual stale-lease triggers a fence).
4. **The e2e script** — tie it together (boot → kill k02 → fence → reschedule → recover).

**Deferred:** reflector redundancy (single k01 reflector is a SPOF — acceptable for the gate); a `test/e2e/multicluster_tier2_test.go` Go wrapper (CI-gating the live path); the anti-affinity recovery rebalancer.

## 8. Success criteria

- A stateful RBD-backed VM boots on pool k02; killing k02 fences it from outside (NetworkFence `Succeeded` + `ceph osd blocklist` contains k02's client + reflector routes withdrawn) and the VM **reschedules to k03 with its disk (sentinel intact) and overlay reachability**.
- On k02 recovery, the fence releases (blocklist entry gone, routes re-announced) via the real drain path.
- Chart/config changes render green (`make chart-test`); no dataplane/eBPF/Rust changes; the multi-envtest Tier-2 gate stays green.
