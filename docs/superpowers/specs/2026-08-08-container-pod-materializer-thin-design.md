# Container workloads (no-scheduler slice) — `Container` + compiler + `CompiledContainer` + pod-materializer — Design

**Date:** 2026-08-08
**Status:** approved (brainstorm 2026-08-08). Implement next.
**Relation:** a slice of `docs/superpowers/specs/2026-08-08-container-workload-crd-design.md`. That spec
(the full path incl. the Phase-3 scheduler + Tier-1/2 failover) remains the north star; this slice
builds everything **except** the scheduler and failover.

## Motivation

The platform models a container's placement with a shortcut: `NetworkInterface.spec.clusterName`
(commit df9a4b7). The control-plane-driven pod tests (`TestPodOverlayPing`, `TestVPCPeering`) create the
real `v1.Pod` by **raw `kubectl apply` on the compute cluster** — the workload never flows through the
central → compile → broker → materialize control plane the way a `VirtualMachine` does. That is the one
place the datapath tests bypass the control plane.

This slice closes that gap and fixes the ownership direction: the **container owns its NICs**, so
placement flows container → NIC (exactly how a `VirtualMachine` places its NICs today). It builds the
full workload path **minus the scheduler and failover**: `clusterName`/`nodeName` are set by hand on the
`Container` (not bound by a scheduler), and there is no Tier-1/2 recovery.

## Scope

**In:** a spec-tier `Container` CRD (the placement authority, no scheduler); a compiler reconciler that
(1) derives each owned NIC's placement from the `Container` and (2) emits a `CompiledContainer`; the
`CompiledContainer` compiled type + its central plumbing + broker sync; a `pod-materializer` on compute
clusters; reworking the pod tests to create a `Container`.

**Out (non-goals):** the Phase-3 scheduler auto-binding `clusterName`/`nodeName`; Tier-1/2 failover;
anti-affinity; pool selection; volumes. When the scheduler is added later, it simply binds
`Container.spec.clusterName`/`nodeName`; nothing else here changes.

## Placement model (the point of this revision)

`Container` is the single placement authority. The compiler's `resolvePlacement`
(`netplane/controllers/compilednic.go`) gains an owning-`Container` branch, giving the precedence:

> owning `Container` > owning `VirtualMachine` > `nic.spec.clusterName` > `--cluster-name` default

(A NIC is owned by at most one workload, so `Container`/`VM` don't collide; `Container` is listed first
for symmetry.) The same derivation applies to `spec.nodeName` (the agent firewall reconcile gate). So a
NIC referenced by a `Container` inherits that `Container`'s `clusterName` + `nodeName`;
`NIC.spec.clusterName`/`nodeName` remain as the **fallback** for NIC-only workloads (kept, not removed).

## Design

### 1. `api/v1alpha1/Container` (spec tier)

The container analogue of `VirtualMachine`, minus the scheduler/failover knobs:

```go
type ContainerSpec struct {
    // ClusterName + NodeName are the placement (set by hand in this slice; a later scheduler binds them).
    ClusterName string `json:"clusterName,omitempty"`
    NodeName    string `json:"nodeName,omitempty"`
    // InterfaceRefs names the NetworkInterfaces (same namespace) this container owns.
    InterfaceRefs []LocalObjectReference `json:"interfaceRefs,omitempty"`
    // Pod template essentials.
    Image         string                      `json:"image,omitempty"`
    Command       []string                    `json:"command,omitempty"`
    Args          []string                    `json:"args,omitempty"`
    Env           []corev1.EnvVar             `json:"env,omitempty"`
    Resources     corev1.ResourceRequirements `json:"resources,omitempty"`
    RestartPolicy corev1.RestartPolicy        `json:"restartPolicy,omitempty"` // default Always
}
```

Served by the central aggregated apiserver (like `VirtualMachine`); stays on central (not broker-synced).

### 2. `api/v1alpha1/CompiledContainer` (compiled tier)

Per-cluster compiler output, the analogue of `CompiledVM`, targeting a `v1.Pod`:

```go
type CompiledContainerSpec struct {
    ClusterName   string                       `json:"clusterName,omitempty"` // broker selector (from the Container)
    NodeName      string                       `json:"nodeName,omitempty"`    // pod nodeSelector
    Image         string                       `json:"image,omitempty"`
    Command       []string                     `json:"command,omitempty"`
    Args          []string                     `json:"args,omitempty"`
    Env           []corev1.EnvVar              `json:"env,omitempty"`
    Resources     corev1.ResourceRequirements  `json:"resources,omitempty"`
    RestartPolicy corev1.RestartPolicy         `json:"restartPolicy,omitempty"`
    Interfaces    []CompiledContainerInterface `json:"interfaces,omitempty"`
}

type CompiledContainerInterface struct {
    NetworkName         string `json:"networkName,omitempty"`         // Multus NAD (as in CompiledVMInterface)
    NetworkInterfaceRef string `json:"networkInterfaceRef,omitempty"` // "<ns>/<nic>" for the pod annotation
    MAC                 string `json:"mac,omitempty"`                 // pinned L2 (from the NetworkInterface)
}
```

Both types get deepcopy + CRD generation (`make generate`).

### 3. Compiler (netplane)

- **`resolvePlacement`** (`compilednic.go`): add the owning-`Container` branch (precedence above), for
  both `clusterName` and `nodeName`, so owned NICs are placed on the `Container`'s cluster/node.
- **`compiledcontainer.go`** (new reconciler): watch `Container`; emit a `CompiledContainer` stamped
  with the `Container`'s `clusterName`/`nodeName` + pod template, and one `Interfaces[]` entry per owned
  NIC derived from that NIC's `CompiledNIC` (`networkName` = the overlay NAD, `mac` = the NIC's MAC,
  `networkInterfaceRef` = `<ns>/<nic>`). Reconcile on `Container` and owned-`CompiledNIC` changes.

### 4. Central plumbing

For **both** `Container` and `CompiledContainer`: an internal type in `central/apis/net/`, the external
`v1alpha1` alias, **hand-written conversions + roundtrip fuzz** (conversion-gen can't do
alias-to-external — the CP.2a caveat, df9a4b7), and REST registration in `central/cmd/apiserver/main.go`.

### 5. Broker sync

Add `&netv1.CompiledContainer{}` to the broker's sync map (`central/cmd/broker/main.go`) — synced to the
cluster named by `spec.clusterName`, with GC + partition-survival from the existing generic sync. Install
the `CompiledContainer` CRD on compute clusters. `Container` and `CompiledContainer` (spec-tier) stay on
central and are **not** synced.

### 6. `pod-materializer`

`netplane/controllers/podmaterializer.go` + `netplane/cmd/pod-materializer/main.go`, mirroring
`vmmaterializer.go`: watch the broker-synced `CompiledContainer` on the compute cluster and
**server-side-apply** a `v1.Pod`:

- annotations: `k8s.v1.cni.cncf.io/networks: <iface.NetworkName>` +
  `net.ectobase.dev/network-interface: <iface.NetworkInterfaceRef>`,
- `spec.nodeSelector: kubernetes.io/hostname: <NodeName>`, `spec.restartPolicy`, a single container from
  `image`/`command`/`args`/`env`/`resources`, `terminationGracePeriodSeconds: 0`, broad tolerations.

SSA with a dedicated field owner (as vm-materializer). Deployed on compute clusters via
`config/deploy/pod-materializer.yaml` + a `deploy.PodMaterializer(...)` step in `test/lab/internal/deploy`.
The materialized Pod matches today's `podManifest` (`test/lab/livetest/pod_test.go`) — only the authoring
path changes.

### 7. Tests

Rework `TestPodOverlayPing` and `TestVPCPeering` to, instead of `kubectl apply` of a raw Pod:
1. apply a `VPC` + `NetworkInterface`(s) on central — **without** `spec.clusterName`/`nodeName` (now
   derived from the owning `Container`),
2. apply a `Container` on central (`clusterName` + `nodeName` + `interfaceRefs` + image/command),
3. assert the Pod appears on the compute cluster (compile → broker → materialize) and the overlay works,
   exactly as today.

The NAD (`flowplane-overlay`) is still applied per compute cluster.

## Testing

- Central: conversion roundtrip fuzz for `Container` and `CompiledContainer`; existing central envtests
  stay green.
- Compiler: an envtest that a `Container` + owned NICs yields `CompiledNIC`s placed on the `Container`'s
  cluster/node and a `CompiledContainer` with the expected `Interfaces[]`.
- pod-materializer: an envtest that a `CompiledContainer` produces the expected `v1.Pod`.
- Live: `TestPodOverlayPing` + `TestVPCPeering` green through the new path; the full `lab test` sweep
  stays green.

## Files (approx.)

- `api/v1alpha1/container_types.go`, `compiledcontainer_types.go` (+ deepcopy, CRD yaml via `make generate`)
- `central/apis/net/{container,compiledcontainer}_types.go` + external aliases + `conversion.go` +
  roundtrip fuzz + REST registration in `central/cmd/apiserver/main.go`
- `netplane/controllers/compilednic.go` (resolvePlacement), `netplane/controllers/compiledcontainer.go` (new),
  `netplane/controllers/podmaterializer.go`, `netplane/cmd/pod-materializer/main.go`
- `central/cmd/broker/main.go` (sync map) + compute-cluster CRD install
- `config/deploy/pod-materializer.yaml` + `test/lab/internal/deploy` wiring
- `test/lab/livetest/pod_test.go`, `vpcpeering_test.go` (rework)

## Open questions

None blocking. (`RestartPolicy` default `Always`; the smoke pods run `sleep`, so restart semantics are
irrelevant to the tests. `nodeName` is set by hand — kind compute clusters have a single node.)
