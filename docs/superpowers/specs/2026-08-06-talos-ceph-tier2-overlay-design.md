# Phase 6 — Ceph + Tier-2 + cross-cluster overlay on the Talos fabric — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-06
**Branch:** off `main` (the Talos lab harness landed at `4235272`).

## 1. Motivation

The Talos lab harness (`test/lab/`, merged to `main`) stands up a 3-cluster Talos IPv6-BGP
fabric with fabric-only egress, a local registry mirror, and the ectobase substrate (central +
brokers + both compute ClusterPools `Ready`). Its live suite passes 10/11; the one gap is the
full cross-cluster **overlay** endpoint ping (`TestCrossClusterOverlayPing` is skipped). Separately,
the entire storage + Tier-2-failover stack was already proven on the **kind** fabric
(`feat/tier2-live-gate`): shared Ceph, external ceph-csi, csi-addons `NetworkFence`, the central
`StorageFencer`, reflector route-withdrawal, and an RBD-backed KubeVirt VM rescheduling from a
killed pool to a healthy one.

This phase (a) closes the overlay datapath through the *real* control-plane pipeline, and (b) ports
the proven Ceph/CSI/Tier-2 mechanics onto the Talos fabric so the fenced VM-reschedule gate runs on
the harness the user actually wants to keep. It reuses the existing committed artifacts
(`central/config`, `deploy/charts/ectobase`, `config/deploy/*`, the `central` fencer/broker code, the
`hack/ceph-*`/`csi-addons-up.sh` logic) — porting behaviour into the Go `lab` harness, not rewriting
it.

## 2. Scope

**In scope:** three sequential sub-phases, one spec, built in order on the Talos harness:
- **6a** — cross-cluster overlay datapath via the full `NetworkInterface → CompiledNIC → broker →
  agent → dataplane` pipeline (deploy the netplane compiler on central), and un-skip
  `TestCrossClusterOverlayPing`.
- **6b** — Ceph (single-OSD demo on the fabric) + external ceph-csi-rbd + csi-addons on Talos; an
  RBD PVC binds on both compute clusters.
- **6c** — the Tier-2 fenced failover gate: an RBD-backed KubeVirt VM pinned to k02 reschedules to
  k03 on `docker kill`, fenced from outside via `NetworkFence` + reflector withdrawal, disk following.

**Out of scope (follow-on):** migrating `test/*.sh` onto Talos; retiring `hack/clab`; blue-green
DPDK upgrade; multi-OSD/production Ceph; a fully-booted guest OS if KVM nested-virt is unavailable
in the container environment (the failover *logic* is the gate, per §6c).

## 3. Coexistence & non-goals

Additive: the existing kind/`hack/clab` fabric, `make chart-test`, and central envtests stay green
and untouched. No `flowplane/`/`.rs` changes. New `lab` subcommands and live tests only; existing
`lab up/down/render/deploy/test` behaviour is preserved (6a folds the compiler into `lab deploy`).

## 4. Phase 6a — Cross-cluster overlay datapath (full pipeline)

**Gap:** `deploy.Ectobase` brings up central control-plane + reflector + brokers + agents, but not
the **netplane compiler** (`controller` cmd, `config/deploy/controller.yaml`), which compiles
`net.ectobase.dev/NetworkInterface` → `platform`-synced `CompiledNIC` stamped with `clusterName`.
Without it, no CompiledNIC reaches the compute agents, so no endpoint policy/VNI is programmed.

**Design:**
- Extend the central-cluster steps of `deploy.Ectobase` to apply the netplane compiler +
  its RBAC (`config/deploy/controller.yaml`, and the `netplane-controller` ClusterRole in
  `config/deploy/rbac.yaml` — verify it grants `net.ectobase.dev` read on
  `vpcs/networkinterfaces/virtualmachines` and write on `compilednics`; widen live if the compiler
  logs RBAC-forbidden). The compiler namespace `ectobase-system` is already PSA-privileged (6-fix).
- `TestCrossClusterOverlayPing` (`//go:build live`, un-skipped):
  1. Apply to central a `VPC` (`vni` patched Ready) + two `NetworkInterface`s — `nic-a` labelled for
     workload on k02, `nic-c` for k03 — so the compiler stamps `spec.clusterName`.
  2. Poll each compute cluster until its `CompiledNIC` exists (broker sync), and the agent is Ready.
  3. Attach the endpoint on each node's flowplane over the *real* dataplane API: create a netns on
     the node, `grpcurl AttachInterface` at `127.0.0.1:1337` (VNI from the CompiledNIC), address the
     netns (`10.0.0.1` / `10.0.0.3` dpservice-style: `/32` + `169.254.0.1` default), and record the
     allocated underlay `/128` into the NetworkInterface status so the agent announces it via the
     reflector. This mirrors `hack/multicluster-e2e.sh attach_endpoint` but the *policy* flows
     through the compiler/broker (the "full pipeline" the ping proves).
  4. Arbiter: overlay ping `nic-a ↔ nic-c` in both directions (cross-cluster, encapsulated), via the
     reflector distributing the two underlay `/128`s across clusters.
- **Firewall note:** the overlay uses v4 (`10.0.0.0/24`); the CompiledNIC must carry a VPC/firewall
  posture that admits same-VPC traffic (deny-by-default is v6; confirm v4 posture live and add an
  explicit allow rule to the NIC fixture if the ping is dropped — see [[lb-firewall-dsr-gotcha]]).

## 5. Phase 6b — Ceph + ceph-csi + csi-addons on Talos

**Topology:** add a `ceph` + `ceph-net` pair to the Talos clab topology (`fabric.clab.yml.tmpl`),
ported from the tier2 node:
- `ceph-net` (FRR sidecar) *owns* the netns + the sw1/sw2 uplinks + a `dummy0` on a dedicated fabric
  `/64` `fd00:cafe:<h>::/64` where `<h> = hash48("ceph")` (the same FNV `/48` derivation the clusters
  use, so it never collides; mon at `::1`, exposed via a `fabric.View` accessor); `ceph`
  (`quay.io/ceph/demo`) joins via
  `network-mode: container:<ceph-net>` + `startup-delay`. This netns-inversion is required (ceph/demo
  exits if the `/64` isn't already on an iface; the sidecar can only route after ceph runs → invert
  ownership). The mon on the fabric means each compute node's Ceph client is seen from its own node
  `/64` = the fence coordinate.
- ceph/demo v6 knobs (proven in tier2, carry verbatim): `MON_IP="[fd00:cafe:ceph::1]"` (bracketed —
  else the demo's `mon host = v2:${MON_IP}:${MON_PORT}` swallows the port), `IP_VERSION=6`,
  `CEPH_ARGS="--ms-bind-ipv4=false --osd-pool-default-size=1"`, `DEMO_DAEMONS=osd`. Gate bring-up on
  mon+osd-up and `ceph health mute OSD_UNREACHABLE --sticky` (Squid false-positives on v6).

**Deploy (`lab ceph`, new Go subcommand porting `hack/ceph-demo-up.sh` + `ceph-external-up.sh` +
`csi-addons-up.sh`):**
- Create the RBD pool + read the FSID/mon/key into a `build/<name>/ceph.env`-equivalent.
- `modprobe rbd` on the **host** (nodes share the host kernel; module confirmed present at
  `/run/booted-system/kernel-modules/.../rbd.ko.xz`).
- External **ceph-csi-rbd Helm chart** on k02/k03 (`provisioner.replicaCount=1`, mon
  `[fd00:cafe:ceph::1]:3300` msgr-v2-only, secret + `StorageClass` with `mapOptions=ms_mode=prefer-crc`).
- **csi-addons** controller into central (`csi-addons-system` ns first) + inject the csi-addons
  sidecar into the ceph-csi provisioner (image tag == csi-addons version) + the RBAC the sidecar
  needs (`csiaddonsnodes`, `pods`, `replicasets/deployments` owner-ref walk, `system:auth-delegator`).
- **Talos delta (resolve live):** the CSI node plugin needs writable `/sys` + a `/dev/rbd` node; kind
  needed `mount -o remount,rw /sys` + `mount -t devtmpfs devtmpfs /dev` per node. Validate what
  Talos-in-docker provides and apply per-node fixups only if the attach fails (a privileged
  DaemonSet/`nsenter` step, gated behind `lab ceph`). Talos may need none.

**Success:** an RBD PVC `Bound` on k02 *and* k03 (cross-cluster provisioning), the central
provisioner serving as fence executor. PSA: `ceph-csi` / `csi-addons` namespaces labelled
`privileged` (Talos baseline enforcement — the 6-fix pattern).

## 6. Phase 6c — Tier-2 fenced failover gate

**Deploy:** KubeVirt + CDI on k02/k03 (port `hack/install-stack.sh`), the netplane `vm-materializer`
(chart already ships it), and confirm the central controller args (`-csi-cluster-id=<fsid>`,
`-reflector-admin=[<central-identity>]:1338`, `-csi-driver=rbd.csi.ceph.com`, `-csi-secret-*`) — these
already exist in `central/config/controller.yaml`; the `lab ceph`/deploy step patches the live fsid.

**`TestTier2Failover` (`//go:build live`):**
1. Apply a `VirtualMachine` (`net.ectobase.dev`) with `spec.clusterName: k02`, an RBD DataVolume, and
   a flowplane NIC. The compiler emits `CompiledVM`/`CompiledNIC`/`CompiledVolumeAttachment`
   (clusterName k02); the broker syncs; the materializer boots a KubeVirt VM + provisions the RBD PVC
   on k02.
2. Assert the VM materialized on k02 (VMI present; RBD PVC `Bound` + mapped).
3. `docker kill clab-ectobase-k02-1` → pool k02 lost → central whole-pool fence: `NetworkFence`
   result `Succeeded` + `ceph osd blocklist ls` shows the node `/64` cidr; reflector withdraws k02's
   routes.
4. Assert the VM rebinds `spec.clusterName: k03` (scheduler) → materializer boots it on k03 with the
   **same RBD** (disk follows) → recovery release once k02 genuinely drained.
- **Boot image:** with fabric egress working, the **CDI importer pod can reach the internet over the
  fabric** (the kind blocker — pods had no egress). First attempt a real `pullMethod` import; if the
  environment still blocks it, fall back to a **containerDisk boot + a blank RBD data disk** (librbd
  provision + krbd attach both proven) — a valid "RBD follows the VM" demonstration.
- **KVM caveat:** nested virt on Talos-in-docker may be absent (same limit as kind). The **fence
  actuator + reschedule + RBD map/mount** are the provable Tier-2 core and pass without a fully
  booted guest; a booted guest is a bonus if `/dev/kvm` is available.

## 7. Testing

- **Live** (`lab test`, `//go:build live`): `TestCrossClusterOverlayPing` (6a), `TestRBDPVCBinds`
  cross-cluster (6b), `TestTier2Failover` (6c) join the existing suite. Each self-skips when its
  prerequisite (`lab up` / `lab ceph`) hasn't run.
- **Unit** (CI-safe): golden renders for the new ceph clab node + any new templates; a compile/render
  check for the `lab ceph` manifests.
- **Regression:** `make chart-test`, central envtests, and the existing `lab test` assertions stay
  green.

## 8. New surface

- `lab ceph` — deploy Ceph + ceph-csi + csi-addons (6b) on an up fabric (idempotent; `lab ceph
  --purge` tears the CSI stack down).
- `deploy.Ectobase` gains the netplane compiler on central (6a).
- Topology gains the `ceph`/`ceph-net` nodes (rendered only when enabled, to keep the base fabric
  lean — a `lab.yaml` `ceph: {enabled: bool}` toggle, default off; `lab ceph` requires it on).
- `internal/deploy/{ceph.go,csiaddons.go}`, `internal/deploy/kubevirt.go`, `livetest/*` additions.

## 9. Success criteria

- `lab up` (compiler included) → `TestCrossClusterOverlayPing` passes: two endpoints in different
  clusters ping over the encapsulated overlay via the compiler/broker/reflector pipeline.
- `lab ceph` → an RBD PVC binds on both k02 and k03; `NetworkFence` reconciles `Succeeded` with a
  Ceph blocklist entry.
- `TestTier2Failover` → an RBD-backed VM pinned to k02 reschedules to k03 after `docker kill`, fenced
  via `NetworkFence` + reflector withdrawal, the RBD disk following; recovery released on real drain.
- Additive/green: kind fabric, `make chart-test`, central envtests, prior `lab test` assertions.
