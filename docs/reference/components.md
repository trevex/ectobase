# Components

ectobase is a fleet control plane (the **dispatch**) driving many workload clusters
(**pools**), with a per-node dataplane on every pool node. This page lists each
binary/image: what it is, where it runs, and what it talks to.

The dispatch components ship in the [`ectobase-dispatch`](helm-values.md#ectobase-dispatch)
chart; the pool components ship in [`ectobase-pool`](helm-values.md#ectobase-pool).

## Dispatch components

Run once per fleet, in the dispatch cluster.

### dispatch-apiserver

The aggregated extension apiserver that serves every ectobase API group
(`net`, `compute`, `storage`, `compiled`, `platform`). It is the single source
of truth users write intent into and controllers write compiled objects into. It
is backed by kine over PostgreSQL. Deployed by the dispatch chart; talks to kine.

### dispatch-controller

The central control-plane reconciler. Today it runs the **ClusterPool**
reconciler (seeding a new pool's lifecycle phase); the fleet scheduler and
failover reconcilers register on the same manager. Deployed by the dispatch chart;
talks to the dispatch apiserver.

### dispatch-broker

The per-cluster broker (a kubelet-analog). It watches the compiled objects
(CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment) in the dispatch
apiserver **filtered by `spec.clusterName`** and set-reconciles them onto a
downstream pool cluster's apiserver. Although logically owned by a pool, it runs
against two apiservers: the dispatch (source) and the pool (destination). The dispatch
chart provisions the broker's dispatch-side identity; the pool chart deploys the
running broker (see below).

### netplane controller (compiler)

The `netplane-controller` binary — the **compiler**. It watches the authored
`net`/`compute`/`storage` groups and lowers them into `compiled.ectobase.dev`
objects (NetworkInterface + FirewallPolicy + LoadBalancer + VPCPeering →
CompiledNIC; VirtualMachine → CompiledVM; Container → CompiledContainer; Volume →
CompiledVolumeAttachment). It also resolves central NAT allocations onto
NATGateway status. Runs hostNetwork in the dispatch cluster (agent namespace); talks
to the dispatch apiserver. Shares the `netplane` image with the reflector.

### reflector

The central route reflector. It accepts `routebus.v1` Session streams from the
per-node agents and reflects per-VNI overlay routes between them — this is how
overlay reachability is distributed (not BGP). Deployed by the dispatch chart as a
Deployment fronted by a Service; the dispatch-controller passes its address to agents
via `reflectorAdmin`. Shares the `netplane` image with the compiler.

## Pool components

Deployed once per pool cluster (some as DaemonSets, one instance per node).

### netplane agent

The per-node control plane. It dials the node-local flowplane dataplane and the
central reflector, then reconciles the node's CompiledNICs into route
announcements while programming learned remote routes into the datapath. Reads
only CompiledNIC for policy plus node-local facts from the dataplane. Runs as a
DaemonSet (one per node); talks to the pool apiserver, the reflector, and the
local flowplane.

### flowplane-cni

The primary-UDN CNI plugin (`flowplane-cni`). It is the Multus default delegate
for a workload pod: on ADD it resolves the pod's overlay `{vni, ips}` from the
`net.ectobase.dev` CRDs and calls the node-local flowplane dataplane to attach
the interface. Installed on every node; talks to the pool apiserver and the local
flowplane.

### pod-materializer

The downstream controller that materializes local **CompiledContainer** objects
into `v1.Pod` objects, attached to the flowplane overlay via Multus and the
flowplane-cni annotation and pinned to a node. Targets the plain downstream k8s
cluster (not the dispatch aggregated apiserver). Deployed by the pool chart.

### vm-materializer

The downstream controller that materializes local **CompiledVM** objects (and
**CompiledVolumeAttachment**) into KubeVirt `VirtualMachine` objects
(containerDisk boot, pinned-MAC overlay interfaces on the flowplane Multus
network, runStrategy). Targets a downstream cluster with KubeVirt installed.
Opt-in via the pool chart (`vmMaterializer.enabled`).

### flowplane (eBPF dataplane)

The default node dataplane. It runs the eBPF tc/XDP datapath and exposes a
`DataplaneNode` gRPC service that the agent and CNI drive (interface attach,
route programming, firewall/NAT/LB state). Runs as a DaemonSet (one per node);
talks to the local kernel datapath and serves gRPC to the local agent and CNI.
Selected when `dataplane: ebpf`.

### flowplane-dpdk (DPDK dataplane)

The DPDK sibling of flowplane: same `DataplaneNode` gRPC contract and control
core, but the datapath runs over DPDK (EAL → maps → datapath workers) instead of
eBPF, for hosts with hugepages/vfio. Runs as a DaemonSet; drop-in replacement
selected when `dataplane: dpdk`, with its own knobs (`dpdk.lcores`, hugepages,
`vfioDevices`).

## Deployment map

| Component | Image | Chart | Scope |
| --- | --- | --- | --- |
| dispatch-apiserver | `dispatch-apiserver` | dispatch | dispatch cluster |
| dispatch-controller | `dispatch-controller` | dispatch | dispatch cluster |
| dispatch-broker | `dispatch-broker` | dispatch (identity) + pool (runtime) | per pool |
| netplane controller (compiler) | `netplane` | dispatch | dispatch cluster |
| reflector | `netplane` | dispatch | dispatch cluster |
| netplane agent | `netplane` | pool | per node (DaemonSet) |
| flowplane-cni | `cni` | pool | per node |
| pod-materializer | `netplane` | pool | per pool |
| vm-materializer | `netplane` | pool | per pool (opt-in) |
| flowplane (eBPF) | `flowplane` | pool | per node (DaemonSet) |
| flowplane-dpdk (DPDK) | `flowplane-dpdk` | pool | per node (DaemonSet) |
