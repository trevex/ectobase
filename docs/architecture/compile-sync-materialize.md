# Compile, sync, materialize

ectobase never programs the datapath directly from user intent. Intent CRDs are
first **compiled** into small, pool-scoped `Compiled*` objects, then **synced**
down to the owning pool, then **materialized** into real Kubernetes/KubeVirt
objects and **programmed** onto the dataplane. This is the single pipeline every
workload flows through:

> **intent** (authored on the dispatch) → **`Compiled*`** (compiled on the dispatch, stamped
> per pool) → **synced down** to the pool → **materialized / programmed** on the pool.

!!! success "Status: Implemented"
    The compiler, the broker sync, the pod-materialize path, and the agent's
    dataplane programming are implemented and exercised on the lab fabric. The
    VM-materialize path is partial — see the badge under
    [The materializers and the agent](#the-materializers-and-the-agent).

## VNI allocation

Before a NIC can be compiled, its VPC needs a VNI. A **VPC VNI allocator**
(`VPCReconciler`, `mesh/controllers/vpc.go`) runs on the dispatch and assigns every
VPC a globally-unique VNI, published to `VPC.status.vni` alongside
`status.state: Ready`. Creating a VPC with **no `spec.vni`** auto-allocates the
lowest free VNI in `[1000, 2^24-1]`; setting `spec.vni` **pins** that value. No
manual status patch is ever needed — the allocation is automatic, collision-free,
and reused once a VPC is deleted (a deleted VPC simply drops out of the used-set).

!!! success "Status: Implemented"
    The allocator serializes reconciles (`MaxConcurrentReconciles: 1`) and builds
    its used-set from a strong, non-cached read of every VPC, so it never
    double-allocates. Contested pins resolve deterministically to exactly one
    `Ready` VPC; the losers go `Conflict`, and an exhausted range goes `Exhausted`.

The `CompiledNICReconciler` gates on a **`Ready` VPC with a non-zero VNI** and
propagates that VNI onto every `CompiledNIC` it lowers, so the datapath is
programmed with the allocated overlay identity.

## The compiler

The compiler is the set of **mesh controller reconcilers**
(`mesh/controllers/`), which run on the dispatch against the aggregated apiserver
(`charts/ectobase-dispatch/templates/compiler.yaml`, the `mesh-controller`
Deployment). Each reconciler lowers one intent type into its `Compiled*` twin and
stamps the target pool (and, where applicable, node) onto it:

- **`CompiledNICReconciler`** (`compilednic.go`) — the richest one. Its `Compile`
  function lowers a `NetworkInterface` **together with** the `FirewallPolicy`,
  `LoadBalancer`, `VPCPeering`, and `NATGateway` allocations that apply to it into a
  single per-NIC `CompiledNIC` of **static central policy**: the firewall rules
  whose selector matches the NIC, its LB memberships, its resolved peer-import
  prefixes, and its NAT sources. (Node-local facts like the underlay are *not*
  compiled in — the agent reads those from the local dataplane.)
- **`CompiledVMReconciler`** (`compiledvm.go`) — `VirtualMachine` → `CompiledVM`.
- **`CompiledContainerReconciler`** (`compiledcontainer.go`) — `Container` →
  `CompiledContainer` (the pod template plus its overlay interfaces).
- **`CompiledVolumeAttachmentReconciler`** (`compiledvolumeattachment.go`) — a
  `VirtualMachine` plus its referenced `Volume`s → one `CompiledVolumeAttachment`
  per `VolumeRef`.

### How placement is resolved

Placement happens in two independent steps: the **dispatch picks the pool**, and the
**pool picks the node**.

The pool binding is a `spec.clusterName` on the workload. Both `Container` and
`VirtualMachine` are **pool-scheduled by the dispatch** (`dispatch/pkg/scheduler`): a
workload authored with an empty `spec.clusterName` is bound to a `Ready` pool by
resource fit and spread, exactly the same for containers and VMs. An explicit
`spec.clusterName` pins the pool and the scheduler leaves it alone.

Every compiled object then carries `spec.clusterName` — the pool it is bound to —
and this is what the broker selects on. For NICs, the binding is resolved by
`resolvePlacement` (`compilednic.go`) with a clear precedence:

1. **Owning `Container`** — supplies the cluster binding (and, if the Container
   sets an optional `spec.nodeName`, that node pin is carried down to the Pod).
2. **Owning `VirtualMachine`** — supplies the cluster binding.
3. **The NIC's own `spec.clusterName`** — for a standalone NIC with no owning
   workload.
4. **The compiler default** — the `mesh-controller`'s configured default
   cluster.

The *node* within the chosen pool is picked on the pool cluster — by
kube-scheduler for Pods, by KubeVirt for VMs — not by the dispatch. `spec.nodeName` is
an **optional pin**, not a requirement; when it is empty the pool schedules the
workload freely. Crucially, a `CompiledNIC` carries **no** node field at all: the
agent self-locates its policy by the interface's `(VNI, overlay IP)` key wherever
the interface actually attaches (see
[Self-locating agent](#agent--dataplane) below), so auto-placed and
rescheduled/live-migrated workloads need no node write-back.

`CompiledContainer`, `CompiledVM`, and `CompiledVolumeAttachment` inherit
`clusterName` from their owning workload's `spec.clusterName` directly. When a
workload owns the compiled objects, the compiler also stamps a `workload` label
onto them; the vm-materializer relies on it to join a VM to its volume
attachments.

## The broker sync

The **broker** (`dispatch/pkg/broker`, `dispatch/cmd/broker/main.go`) syncs each compiled
type from the dispatch down to the owning pool's local CRDs — a declarative
set-reconcile filtered by `spec.clusterName == this pool`, with create / update /
delete + GC. It is idempotent and restart-safe. This seam is described in full in
[Multi-cluster control plane → Broker sync](./multi-cluster-control-plane.md#broker-sync);
here it is simply the middle stage: the compiled objects the dispatch produced become
real CRDs in the pool that hosts the workload.

## The materializers and the agent

On each pool, the synced compiled objects are consumed by three independent
executors.

### pod-materializer → Pod

`PodMaterializerReconciler` (`podmaterializer.go`) turns a `CompiledContainer`
into a `v1.Pod` on the overlay. It applies (server-side) a Pod built from the
compiled pod template. `spec.nodeName` is an **optional** node pin: when set it
becomes a `kubernetes.io/hostname` node selector; when empty (the common case for
an auto-scheduled Container) the Pod is left for **kube-scheduler** on the pool to
place. The Pod is attached to the
flowplane overlay via the **Multus** secondary-network annotation
(`k8s.v1.cni.cncf.io/networks`) plus the **flowplane-cni** NIC-ref annotation
(`net.ectobase.dev/network-interface`), which the CNI plugin resolves to the
broker-synced `CompiledNIC`.

### vm-materializer → KubeVirt VirtualMachine

`VMMaterializerReconciler` (`vmmaterializer.go`) plus
`VolumeMaterializerReconciler` (`volumematerializer.go`) turn a `CompiledVM` and
its `CompiledVolumeAttachment`s into a KubeVirt `VirtualMachine` with pinned-MAC
overlay interfaces on the flowplane Multus network. When volume attachments are
present the VM boots from persistent CDI `DataVolume` disks (boot attachment first,
then the rest by name); with none it falls back to an ephemeral `containerDisk`
from the compiled image. The overlay is attached via the KubeVirt `flowplane`
network-binding plugin (a tap device).

!!! warning "Status: Partial"
    The VM-materialize path depends on KubeVirt and CDI being installed on the pool
    and on the `flowplane` network-binding plugin being registered in the pool's
    KubeVirt CR. The materializer builds the correct KubeVirt objects, but the
    surrounding KubeVirt/tap wiring is still being hardened, so treat the VM path as
    partial relative to the fully-proven Pod path. See
    [KubeVirt integration](./kubevirt-integration.md).

### agent → dataplane

The mesh **agent** (`mesh/agent`) consumes `CompiledNIC` as its **central
policy** and programs the local `flowplane` datapath from it: firewall rules
(`fwreconcile.go`), LB memberships (`lbreconcile.go`), NAT sources
(`natreconcile.go`), and peering imports (`importreconcile.go`). It applies a
`CompiledNIC`'s policy **iff that NIC's interface is locally attached**, matched by
the unique `(VNI, overlay IP)` key the dataplane reports for its attached
interfaces — not by any declared node. The agent deliberately reads **only**
`CompiledNIC` for policy — never the raw `NetworkInterface`/`VPC`/`NATGateway` —
and gets node-local facts (overlay IPs, underlay) from the dataplane itself. The
dynamic overlay routes it programs come from the [route bus](./route-bus.md), not
from the compiled objects.

Because policy is keyed by `(VNI, overlay IP)` rather than a `nodeName`, **policy
follows the interface**: wherever the CNI attaches a NIC, that node's agent
programs its firewall/NAT/LB/QoS, and no other node's does. This is what lets
auto-placed workloads, rescheduling, and live migration "just work" with no
control-plane node write-back — the `CompiledNIC` has no node field at all. See
[CNI integration → Self-locating agent](./cni-integration.md#self-locating-agent).

## The full pipeline

```mermaid
flowchart TB
    subgraph hubbox["Dispatch — compiler (mesh-controller)"]
        nic["NetworkInterface<br/>+ FirewallPolicy / LoadBalancer<br/>+ VPCPeering / NATGateway"]
        ctr["Container"]
        vm["VirtualMachine<br/>+ Volume"]
        cnic["CompiledNIC"]
        ccont["CompiledContainer"]
        cvm["CompiledVM"]
        catt["CompiledVolumeAttachment"]
        nic --> cnic
        ctr --> ccont
        vm --> cvm
        vm --> catt
    end

    broker["broker<br/>set-reconcile by spec.clusterName"]
    cnic --> broker
    ccont --> broker
    cvm --> broker
    catt --> broker

    subgraph poolbox["Pool — synced compiled CRDs + executors"]
        agent["mesh agent"]
        dp["dataplane (flowplane)"]
        podmat["pod-materializer"]
        vmmat["vm-materializer"]
        pod["v1.Pod (overlay)"]
        kvm["KubeVirt VirtualMachine"]
        agent --> dp
        podmat --> pod
        vmmat --> kvm
    end

    broker -->|CompiledNIC| agent
    broker -->|CompiledContainer| podmat
    broker -->|"CompiledVM + CompiledVolumeAttachment"| vmmat
```

## Intent → compiled → executor

| Intent (dispatch) | Compiled (dispatch, pool-stamped) | Executor (pool) | Result |
|---|---|---|---|
| `NetworkInterface` (+ `FirewallPolicy`, `LoadBalancer`, `VPCPeering`, `NATGateway`) | `CompiledNIC` | mesh **agent** | dataplane programmed (firewall / LB / NAT / imports) |
| `Container` | `CompiledContainer` | **pod-materializer** | `v1.Pod` on the overlay |
| `VirtualMachine` | `CompiledVM` | **vm-materializer** | KubeVirt `VirtualMachine` |
| `VirtualMachine` + `Volume` | `CompiledVolumeAttachment` | **vm-materializer** | CDI `DataVolume` disk(s) |

## See also

- [Multi-cluster control plane](./multi-cluster-control-plane.md) — the dispatch/pool split and the broker seam.
- [Control/data split & the route bus](./route-bus.md) — how the agent learns dynamic overlay routes.
- [KubeVirt integration](./kubevirt-integration.md) — the VM materialize path in depth.
