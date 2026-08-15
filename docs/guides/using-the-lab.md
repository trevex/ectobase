# Using the lab

This is a hands-on walkthrough of driving a live ectobase fabric: you author
**intent** on the dispatch, watch it compile and sync into a compute pool, and see the
overlay come up inside a real Pod and a real KubeVirt VM. It assumes the local
lab fabric from [Local fabric](./local-fabric.md) is up.

By the end you will have created a VPC (with an **auto-allocated VNI**), attached a
**pool-auto-scheduled** Container to it and pinged across the overlay, and — with
the storage add-ons — booted a stateful VM in the same VPC.

## Prerequisites

Bring the fabric up and deploy both charts:

```sh
make lab-up
```

`lab-up` stands up the clab + kind fabric and deploys the two Helm charts
(`ectobase-dispatch` on the dispatch cluster, `ectobase-pool` on each compute pool). See
[Deploy with Helm](./deploy-helm.md) for what the charts contain and
[Local fabric](./local-fabric.md) for the fabric itself.

The **VM** section additionally needs Ceph and the Tier-2 prerequisites
(KubeVirt + CDI + the vm-materializer):

```sh
make lab-ceph        # ceph-csi + csi-addons (needs fabric.ceph.enabled)
make lab-tier2-up    # KubeVirt + CDI + vm-materializer
```

The Container section needs only `make lab-up`.

## Accessing & inspecting the clusters

The fabric is three kind clusters — the **dispatch** (fleet control plane / aggregated
apiserver) plus two compute pools, **k02** and **k03**. `lab up` chowns each
per-cluster kubeconfig back to your user, so `kubectl` works **without sudo**. Set
one alias per cluster:

```sh
alias khub='kubectl --kubeconfig test/lab/build/ectobase/dispatch.kubeconfig'
alias k02='kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig'
alias k03='kubectl --kubeconfig test/lab/build/ectobase/k03.kubeconfig'
```

Orient yourself. The pools register with the dispatch as `ClusterPool`s and converge to
`Ready` with their node `/64`s:

```sh
khub get clusterpools.platform.ectobase.dev
```

All **intent** is authored on the dispatch, so that is where you list workloads:

```sh
khub get vpc,networkinterface,container,virtualmachine -A
```

Each pool runs the `ectobase-pool` executors in the `ectobase-system` namespace —
the mesh agent, the broker, the CNI installer, the dataplane, and the
materializers:

```sh
k02 -n ectobase-system get pods
```

and it holds the **synced compiled** objects (never raw intent):

```sh
k02 get compilednics,compiledcontainers,compiledvms -A
```

## The flow in one paragraph

You author intent on the **dispatch**; the mesh compiler lowers it into small
pool-scoped `Compiled*` objects and stamps the pool a dispatch scheduler chose; the
**broker** syncs each `Compiled*` down to that pool; on the pool the
**materializers** turn a `CompiledContainer` into a `Pod` and a `CompiledVM` into a
KubeVirt `VirtualMachine`, while the **mesh agent** programs the dataplane for
whichever overlay interfaces actually attach on its node. The full picture is in
[Compile, sync, materialize](../architecture/compile-sync-materialize.md).

## Create a VPC + NetworkInterface

Author a VPC with **just a name** — no `spec.vni` — plus a NetworkInterface that
references it and carries the endpoint's overlay IP and MAC. Apply on the dispatch:

```yaml
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata:
  name: demo
spec:
  defaultPolicy: Allow      # so guest egress isn't deny-by-default dropped
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: demo-nic-a
spec:
  vpcRef:
    name: demo
  ips: ["10.0.9.1"]
  mac: "52:54:00:00:09:0a"
```

```sh
khub apply -f vpc.yaml
```

A **VPC VNI allocator** on the dispatch assigns the VNI automatically and marks the VPC
`Ready` — you never patch status by hand:

```sh
khub get vpc demo -o yaml
```

```yaml
# ...
status:
  vni: 1000          # lowest free VNI in [1000, 2^24-1], assigned automatically
  state: Ready
```

!!! success "Status: Implemented"
    A VPC created without `spec.vni` is auto-allocated a globally-unique VNI,
    published to `status.vni` with `status.state: Ready`. No manual status patch is
    needed. Setting `spec.vni` instead **pins** that value. The allocation is
    collision-free and the VNI is reused once the VPC is deleted. The compiler
    gates on a `Ready` VPC with a non-zero VNI and propagates it to the NICs. See
    [Compile, sync, materialize → VNI allocation](../architecture/compile-sync-materialize.md#vni-allocation).

## Run a Container workload

Now attach a Container to that NIC. The Container **owns** the NIC via
`interfaceRefs`, and it sets **no `clusterName` and no `nodeName`** — so the dispatch
scheduler binds it to a pool, and kube-scheduler on that pool picks the node.
Apply on the dispatch:

```yaml
apiVersion: compute.ectobase.dev/v1alpha1
kind: Container
metadata:
  name: demo-ctr-a
spec:
  interfaceRefs:
    - name: demo-nic-a
  image: busybox:1.36
  command: ["sleep", "3600"]
```

```sh
khub apply -f container.yaml
```

!!! success "Status: Implemented"
    A `Container` with no `spec.clusterName` is pool-scheduled by the dispatch (resource
    fit + spread, sharing pool capacity with VMs), exactly like a VM. `spec.nodeName`
    stays an **optional** pin — leave it empty and the node is chosen by
    kube-scheduler on the pool.

Watch the objects appear. First the scheduler stamps the chosen pool onto the
Container's `spec.clusterName`:

```sh
khub get container demo-ctr-a -o jsonpath='{.spec.clusterName}{"\n"}'   # e.g. k02
```

The compiler lowers the intent into a `CompiledNIC` and a `CompiledContainer` on
the dispatch, both bound to that pool:

```sh
khub get compilednic,compiledcontainer -A
```

The broker syncs both down to the bound pool. Point your pool alias at whatever
`clusterName` was stamped (below assumes `k02`):

```sh
k02 get compilednic,compiledcontainer -A
```

The **pod-materializer** on the pool then turns the `CompiledContainer` into a real
`Pod`, attached to the overlay via a **Multus secondary network**. The Pod carries
the `k8s.v1.cni.cncf.io/networks` annotation selecting the overlay
`NetworkAttachmentDefinition` the pool chart installs — named `flowplane` in the
`ectobase-system` namespace — plus the `net.ectobase.dev/network-interface`
annotation the CNI resolves back to the `CompiledNIC`:

```sh
k02 get networkattachmentdefinition -n ectobase-system flowplane
k02 get pods -A -l net.ectobase.dev/container=default-demo-ctr-a
POD=$(k02 get pod -A -l net.ectobase.dev/container=default-demo-ctr-a \
        -o jsonpath='{.items[0].metadata.name}')
NS=$(k02 get pod -A -l net.ectobase.dev/container=default-demo-ctr-a \
        -o jsonpath='{.items[0].metadata.namespace}')
k02 -n "$NS" get pod "$POD" \
  -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/networks}{"\n"}'
```

Confirm the overlay interface landed inside the pod with the IP you assigned
(`net1`, the secondary interface), then exec in:

```sh
k02 -n "$NS" exec "$POD" -- ip -o addr        # 10.0.9.1 on net1
k02 -n "$NS" exec "$POD" -- ping -c3 10.0.9.3  # ping another endpoint in the VPC
```

!!! note
    The `busybox:1.36` image must be reachable from the pool. The lab fabric runs a
    pull-through registry mirror (see [Local fabric](./local-fabric.md#registry-mirror)),
    so the first pull is fetched and cached through it.

To ping a second endpoint, create another NetworkInterface (e.g. `demo-nic-c` with
`10.0.9.3`) in the same VPC and a second Container owning it — the two can be
auto-scheduled onto different pools and still reach each other over the
encapsulated overlay.

## Run a VM in a VPC

!!! warning "Status: Partial"
    The VM path needs Ceph (`make lab-ceph`) and the Tier-2 prerequisites
    (`make lab-tier2-up`): KubeVirt, CDI, and the vm-materializer. The materializer
    builds the correct KubeVirt objects, but the surrounding KubeVirt/tap wiring is
    still being hardened — treat the VM path as partial relative to the fully-proven
    Pod path. See [KubeVirt integration](../architecture/kubevirt-integration.md).

A VM in a VPC is the same shape as a Container, plus a persistent boot disk. Author
a NetworkInterface, an RBD-backed `Volume` with a `bootImage`, and a
`VirtualMachine` that owns both — again with **no `clusterName`** (auto-scheduled).
Apply on the dispatch:

```yaml
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: demo-vm-nic
spec:
  vpcRef:
    name: demo
  ips: ["10.0.9.20"]
  mac: "52:54:00:00:09:20"        # the VMI's virtio NIC MUST carry this MAC
---
apiVersion: storage.ectobase.dev/v1alpha1
kind: Volume
metadata:
  name: demo-vm-disk
spec:
  size: 1Gi
  storageClass: ceph-rbd
  # bootImage makes the RBD bootable (imported via CDI). Without a bootImage
  # volume the materializer falls back to an ephemeral containerDisk.
  bootImage: "quay.io/containerdisks/fedora:41"
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata:
  name: demo-vm
spec:
  interfaceRefs:
    - name: demo-vm-nic
  volumeRefs:
    - name: demo-vm-disk
  runStrategy: RerunOnFailure
  resources:
    requests:
      cpu: "1"
      memory: 1Gi
```

```sh
khub apply -f vm.yaml
```

The scheduler binds the VM to a pool (`spec.clusterName`), then the compiler emits
a `CompiledVM` and a `CompiledVolumeAttachment`:

```sh
khub get virtualmachine demo-vm -o jsonpath='{.spec.clusterName}{"\n"}'
khub get compiledvm,compiledvolumeattachment -A
```

On the bound pool, the **vm-materializer** turns those into a KubeVirt
`VirtualMachine` and a CDI `DataVolume`; KubeVirt then runs a
`VirtualMachineInstance` in a `virt-launcher` pod. Inspect the VMI, see which node
KubeVirt placed it on, and open its console:

```sh
k02 get datavolume,virtualmachine,virtualmachineinstance -A
k02 get pod -A -l kubevirt.io=virt-launcher -o wide     # the node it landed on
virtctl --kubeconfig test/lab/build/ectobase/k02.kubeconfig console demo-vm
```

The VMI's overlay interface attaches via the KubeVirt `flowplane` network-binding
plugin (a tap), and — as with the Pod — the node agent programs the datapath for
it wherever it lands.

## Trace the objects end-to-end

The same intent shows up at four stages. Author on the dispatch; the compiled twin is
produced on the dispatch and pool-stamped; the broker syncs it into the bound pool; the
materializer produces the concrete Pod/VMI. Run each `get` on the cluster in its
column.

| Stage | Object | Where | Command |
|---|---|---|---|
| Intent | `VPC` / `NetworkInterface` / `Container` / `VirtualMachine` / `Volume` | **dispatch** | `khub get vpc,networkinterface,container,virtualmachine,volume -A` |
| Compiled | `CompiledNIC` / `CompiledContainer` / `CompiledVM` / `CompiledVolumeAttachment` | **dispatch** | `khub get compilednic,compiledcontainer,compiledvm,compiledvolumeattachment -A` |
| Synced | the same `Compiled*` (broker-selected by `spec.clusterName`) | **pool** | `k02 get compilednic,compiledcontainer,compiledvm,compiledvolumeattachment -A` |
| Materialized | `Pod` (+ NAD) / KubeVirt `VirtualMachine` + `VirtualMachineInstance` + `DataVolume` | **pool** | `k02 get pod,networkattachmentdefinition -n ectobase-system; k02 get virtualmachine,virtualmachineinstance,datavolume -A` |

The mesh **agent** on each pool node then programs the dataplane for whichever
overlay interfaces attach locally — matched by the unique `(VNI, overlay IP)` key,
so policy follows the interface wherever it lands. See
[CNI integration → Self-locating agent](../architecture/cni-integration.md#self-locating-agent).

## Cleanup

Deleting the workload on the dispatch cascades through the pipeline — GC removes the
`Compiled*` twins and the materialized Pod/VM on the pool:

```sh
khub delete container demo-ctr-a
khub delete virtualmachine demo-vm
```

Delete the VPC, its NICs, and any Volumes when you no longer need them; the VPC's
VNI returns to the free pool for reuse:

```sh
khub delete networkinterface demo-nic-a demo-vm-nic
khub delete volume demo-vm-disk
khub delete vpc demo
```

## See also

- [Compile, sync, materialize](../architecture/compile-sync-materialize.md) — the pipeline every workload flows through, including VNI allocation and scheduling.
- [Multi-cluster control plane](../architecture/multi-cluster-control-plane.md) — the dispatch/pool split, the broker, and the scheduler.
- [CNI integration](../architecture/cni-integration.md) — how a Pod joins the overlay and how the agent self-locates.
- [Rescheduling & failover](../architecture/rescheduling-and-failover.md) — why moving a workload's pool is enough.
- [Local fabric](./local-fabric.md) and [Deploy with Helm](./deploy-helm.md) — the fabric and the charts.
