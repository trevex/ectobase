# First-class Container workload CRD (symmetric to VirtualMachine) — Design (follow-up)

**Date:** 2026-08-08
**Status:** deferred follow-up (user chose "defer" 2026-08-08). Tracked; build after the retire-bash-clab effort's remaining work (restart port, Phase 3/4).

## Motivation

The platform models a VM as a first-class **schedulable workload** (`net.ectobase.dev/VirtualMachine`): the Phase-3 cluster-scheduler binds `spec.clusterName` (capacity fit + pool selection + anti-affinity + Tier-2 failover), the workload owns its NICs via `spec.interfaceRefs`, the compiler derives NIC placement from it and emits a `CompiledVM`, and the **vm-materializer** turns `CompiledVM` → a real `kubevirt.io/VirtualMachine` on the bound cluster.

There is **no container equivalent**. To unblock control-plane-driven pod tests, `NetworkInterface.spec.clusterName` was added (commit df9a4b7) so a standalone NIC schedules itself (compiler precedence: owning VM > `nic.spec.clusterName` > `--cluster-name` default). That's a pragmatic shortcut — the NIC does double duty (network config + placement), and tests create the real Pod directly (`kubectl apply` on the compute cluster) rather than from a workload object. Container workloads are therefore NOT first-class citizens of the disaggregated-pool platform (no workload-level scheduling / capacity / anti-affinity / failover).

## Design — a `Container` workload CRD mirroring `VirtualMachine`

Add `net.ectobase.dev/Container` (naming TBD: `Container` vs `Pod` vs generic `Workload`) with a spec that mirrors `VirtualMachineSpec` (api/v1alpha1/virtualmachine_types.go):
- `ClusterName string` — bound by the Phase-3 scheduler (like VM); the placement anchor.
- `InterfaceRefs []LocalObjectReference` — the NICs this container owns.
- `Resources corev1.ResourceRequirements` — capacity fit.
- `PoolSelector *metav1.LabelSelector`, `AntiAffinity *…` — scheduling constraints (reuse the VM types/logic).
- `Image string`, `Command/Args/Env`, `RestartPolicy` — the pod template essentials.
- (Optional) `VolumeRefs` — if container volumes are ever needed.

Pipeline (mirror the VM path):
1. **Scheduler** (`central/internal/scheduler`): schedule `Container` like `VirtualMachine` — bind `spec.clusterName` from ClusterPool health + capacity fit + spread. Reuse the existing scheduler; generalize it over "workload" (VM|Container) or add a parallel reconciler.
2. **Compiler** (`netplane/controllers/compilednic.go` `resolvePlacement`): check owning `Container`s alongside `VirtualMachine`s → `CompiledNIC.spec.clusterName` from the owning Container's placement. With this, `NetworkInterface.spec.clusterName` reverts to a FALLBACK (or is removed) — placement comes from the owning workload, exactly like VMs.
3. **CompiledContainer** (`api/v1alpha1/compiledcontainer_types.go`): per-cluster compiled object (like `CompiledVM`) stamped with `spec.clusterName`; the broker syncs it to the bound compute cluster (broker already selects on `spec.clusterName`).
4. **pod-materializer** (`netplane/controllers/podmaterializer.go`, mirror `vmmaterializer.go`): turns a broker-synced `CompiledContainer` → a real `v1.Pod` on the compute cluster, with the Multus NAD annotation (`k8s.v1.cni.cncf.io/networks: flowplane-overlay`) + `net.ectobase.dev/network-interface: <ns>/<nic>` + `nodeSelector`. flowplane-cni then attaches it from the broker-synced `CompiledNIC` (the CP.2 seam). Deployed on compute clusters like the vm-materializer (test/lab/internal/deploy).
5. **Tests**: rework `TestPodOverlayPing` / `TestVPCPeering` to create a `Container` on central (scheduled → compiled → materialized → CNI-attached), instead of `kubectl apply` of a raw Pod + a hand-set `NetworkInterface.spec.clusterName`.

## Scope / effort
New CRD + deepcopy/CRD-gen + central internal+external types + hand-written conversions + fuzzer (like CP.2a) ; scheduler generalization ; compiler placement ; CompiledContainer ; pod-materializer + its deploy step ; test rework. Substantial, but each piece closely mirrors the existing VM code.

## Open questions
- Naming: `Container` vs `Workload` (generic over pod/vm) vs `Pod`.
- Whether to keep `NetworkInterface.spec.clusterName` as a fallback (NIC-only, no workload) or remove it once Containers exist.
- Does a Container need `runStrategy`-like semantics (restartPolicy) + Tier-1/Tier-2 failover parity with VMs?

## Reference
Effort context: [[retire-bash-clab-datapath-to-go]], [[feedback-tests-through-control-plane]]. VM path: [[phase4-kubevirt-vm-lifecycle]] (materializer + Multus tap), [[phase3-scheduler-failover]] (scheduler), [[phase1b-net-types-central]] (central conversions). The CP.2 CNI→CompiledNIC seam (df9a4b7/daa236c) is the attach mechanism the pod-materializer relies on.
