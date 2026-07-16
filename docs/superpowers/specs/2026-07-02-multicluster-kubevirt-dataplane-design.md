# Multi-Cluster KubeVirt on a Custom eBPF Dataplane — Vision & Architecture

**Status:** Draft / Vision (brainstorm output) — architecture agreed at a high level; each sub-project below gets its own detailed spec + plan.
**Date:** 2026-07-02
**Related:** `docs/iep-ebpf-tc-dataplane.md` (the eBPF XDP/tc dataplane this builds on)

---

## 1. Summary

Build an **ironcore-inspired, centrally-managed, multi-cluster platform** that runs **KubeVirt VMs exclusively on our metalnet-inspired eBPF SDN dataplane** — the VM has **no pod network**, only a custom dataplane network. A single **central aggregated API** holds desired state and brokers it onto **attached, specialized pools**: compute (KubeVirt), storage (rook-ceph/CSI), and **dataplane** (host software / SmartNIC / DPU). One logical VM can be **composed across up to three different clusters** (host compute · DPU dataplane · ceph storage), all rendezvousing through central.

The datapath already exists — it is the eBPF XDP/tc dataplane from the IEP. **This project is the control plane, the KubeVirt/CNI integration, and the multi-cluster brokering built around it.**

## 2. Goals / Non-goals

**Goals**
- KubeVirt VM attaches to the custom dataplane as its **primary** interface; no pod network involved (OpenShift primary-UDN pattern, our dataplane instead of ovn-kubernetes).
- **Single global overlay**: a tenant's virtual network (VNI) spans every compute cluster; VM↔VM reachability is independent of cluster/node placement.
- **Disaggregated pools**: compute, storage, and dataplane are independently placeable; cross-cluster composition is first-class.
- **Dataplane realization is polymorphic**: host software (normal NIC), SmartNIC offload, or DPU split (dataplane on the DPU's own cluster).
- **VM mobility**: cold reschedule across compute pools; live-migrate within a pool; the VM's IP follows it (global overlay).
- **Single-cluster works flawlessly** as the degenerate case of the same design (see §5).

**Non-goals (for now)**
- Replacing DPDK dpservice in ironcore (that is the IEP's scope; this is a different consumer of the same dataplane).
- *Building* cross-pool **live** migration ourselves — we **integrate** KubeVirt's upstream Decentralized/Storage Live Migration instead (cold reschedule first; §4.7).
- A bespoke storage backend — we consume rook-ceph/CSI, we do not build storage.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Greenfield control plane, ironcore as inspiration** | Design freedom for KubeVirt/CNI/CSI-native semantics; borrow ironcore's proven patterns (poollet brokering, apinet network model) without coupling to ironcore APIs. |
| D2 | **Disaggregated specialized pools** (compute / storage / dataplane) | A logical VM composes references realized in different clusters; matches ironcore and enables the DPU split. |
| D3 | **Single global overlay** across all clusters | True multi-cluster tenant networks + IP mobility; the metalnet/apinet problem at cross-cluster scale. |
| D4 | **Primary-UDN VM attach** (no pod network) | Purest "not in the pod network"; mirrors OpenShift primary-UDN + KubeVirt. |
| D5 | **Central = aggregated API server** (via `apiserver-kit`) | Best scale ceiling and cleanest typed API; the usual "too heavy to build" objection is removed by `apiserver-kit` (github.com/opendefensecloud/apiserver-kit). |
| D6 | **Uniform pull poollets; central rendezvous, direct data path** | Central holds no write-creds into attached clusters; N clusters never become an N² credential/control mesh — only *data paths* are direct. |
| D7 | **Storage: separate provision from attach; movable attachment; portable, self-contained, typed access bundle** | Enables cross-cluster mount and reschedule; compute nodes hold no standing storage config. |
| D8 | **Dataplane is itself a disaggregated pool** with `realizationPoint ∈ {host, smartnic, dpu}` | Supports the OpenShift two-clusters-per-machine DPU split *and* normal/Smart NICs under one control API. |

## 4. Architecture

### 4.1 Component map

```
╔══════════════ CENTRAL (aggregated API server — desired state) ══════════════╗
║ Logical API: VirtualMachine ─refs─► NetworkInterface ─► Network(VNI)          ║
║                    └─refs─► Volume        Image                               ║
║ Pools: ComputePool · StoragePool · NetworkPool (+ host↔DPU pairing)          ║
║ Schedulers: place each ref onto a pool                                       ║
║ NetPlane: global IPAM, VNI alloc, endpoint+route registry (scoped watches)   ║
╚══════▲════════════════════════▲═════════════════════════▲═══════════════════╝
   pull│reconcile           pull│reconcile           watch│(endpoints/routes)
       │                        │                          │
 ┌─────┴───────────┐   ┌────────┴──────────┐               │
 │ COMPUTE POOL     │   │ STORAGE POOL       │              │
 │ compute-poollet  │   │ storage-poollet    │              │
 │  → KubeVirt VMI   │   │  → CSI/rook provision│            │
 │ primary-UDN CNI   │   │  → publish access    │            │
 │ + KubeVirt binding│   │    bundle (rbd|nvme) │            │
 └─────┬────────────┘   └────────┬───────────┘              │
       │                          │                          │
 ┌─────┴───────────── DATAPLANE POOL (realizationPoint) ─────┴──────┐
 │ host: agent + eBPF tc/XDP on the KubeVirt host (same cluster)     │
 │ smartnic: agent on host programs NIC eswitch (tc-flower)           │
 │ dpu: agent + eBPF on the DPU's OWN cluster, programs DPU eswitch    │
 └──────────────────── UNDERLAY FABRIC (routed IPv6) ─────────────────┘
             carries the global overlay AND storage traffic
```

### 4.2 Logical resource model (central)

- **`VirtualMachine`** — references `NetworkInterface`(s) and `Volume`(s); scheduled to a `ComputePool`.
- **`Volume`** — scheduled to a `StoragePool`; `.status.access` carries a **portable, self-contained, typed connection bundle** (`rbd | nvme-of`), including endpoints, identifiers, and **tenant-scoped credentials**.
- **`VolumeAttachment`** — a **movable** binding of a Volume to the compute node currently running the VM; created/destroyed on attach/detach/reschedule.
- **`NetworkInterface`** — a VM endpoint: overlay IP(s), MAC, VNI, and **current underlay location** (host/cluster). Realized by a dataplane agent that may live in a different cluster.
- **`Network`** — a tenant virtual network (VNI), global across clusters.
- **Pools** — `ComputePool` / `StoragePool` / `NetworkPool` (the **dataplane pool** of D8/§4.5), each backed by an attached cluster running a poollet; plus a **host↔DPU pairing** object registering the physical association.

### 4.3 Brokering: pull poollets, central rendezvous

Each attached cluster runs a **pull agent (poollet)** that watches central for objects assigned to *its* pool and reconciles locally (KubeVirt API / CSI+rook / dataplane). Compute and storage clusters **never talk control-plane to each other** — they rendezvous through central (e.g. `compute-poollet` reads the referenced `Volume.status.access` from central), and only the **data path** is direct cluster-to-cluster. This keeps credentials and coupling out of an N² mesh.

### 4.4 Networking core

Three layers, one control API (**NetPlane**):

1. **NetPlane (central)** — `Network`/`NetworkInterface`/IPAM + a route/endpoint registry mapping each VM's overlay IP → its current underlay location. **Scoped watches**: a node/agent subscribes only to the VNIs it actually hosts.
2. **Dataplane agent (per realization point)** — registers local VM endpoints on attach, deregisters on detach, and programs the eBPF datapath: overlay encap/decap (IP-in-IPv6), ARP/ND/DHCP, conntrack/NAT/VIP/LB, NAT64 (the IEP code).
3. **Primary-UDN CNI + KubeVirt binding** — on VMI launch, wires the VM's **primary** interface into the dataplane. Backing is **polymorphic**: tap→tc-BPF (host software) or VF/SF passthrough (SmartNIC/DPU).

**IP mobility:** on reschedule, the new node's agent re-registers the endpoint with the new underlay location; NetPlane propagates; other agents update their encap target — **the VM's IP follows it across clusters** on the same VNI.

**Scalability risk (the hard problem):** global endpoint/route distribution. Mitigations: scoped/filtered watches (host learns only its VNIs) and likely **regional route-reflection**. This is where design effort concentrates and must be validated at scale.

### 4.5 Dataplane realization topologies (D8)

- **(a) Host software (normal NIC), same cluster** — agent + eBPF tc/XDP on the KubeVirt host; primary-UDN tap-backed. *This is the current PoC path.*
- **(b) SmartNIC offload, same host/cluster** — agent on host programs the NIC eswitch via tc-flower; primary-UDN VF/SF-backed; datapath in silicon.
- **(c) DPU split, two clusters per machine** — the DPU runs its **own** Kubernetes + our eBPF/tc-flower dataplane (programming the DPU eswitch); the x86 host runs a **separate** Kubernetes + KubeVirt, and the VM gets an **SR-IOV VF** that traverses the DPU. The **dataplane agent runs on the DPU cluster**, not the host. A registered **host↔DPU pairing** tells central that a VM landing on that host has its `NetworkInterface` realized by the DPU cluster's agent. Rendezvous stays central (no direct host-cluster↔DPU-cluster control link beyond the pairing).

Our eBPF code runs in all three: software tc/XDP (a), programming the NIC eswitch from the host (b), or on the DPU's ARM Linux (c) — the IEP's "eBPF on the DPU" endgame as a first-class topology.

### 4.6 Storage: provision vs attach (D7)

- **Provision once** in a `StoragePool` (rook-ceph via CSI/rook); publish a **portable typed access bundle** to `Volume.status.access`.
- **Attach = movable**: the compute node currently hosting the VM consumes the bundle and maps the volume locally (`rbd map` / `nvme connect`) over the underlay fabric. Compute nodes hold **no standing storage config** — everything needed (endpoints, identifiers, **tenant-scoped credentials**) is delivered at attach time and **torn down + revoked on detach**.
- **RBD and NVMe-oF are both first-class**; access bundle is a pluggable typed union.
- **Reuse CSI at the driver layer, not as the cross-cluster source of truth.** Provision via **ceph-csi (external-cluster mode)** and reuse its node ops (`NodeStage`/`NodePublish` = `rbd map`/`nvme connect`); central owns the source of truth and projects a Volume into whichever cluster currently hosts the VM. CSI's cluster-scoped PV/PVC/VolumeAttachment are **not** the multi-cluster contract — the portable access bundle is.
- **Safe RWO handoff via `csi-addons` NetworkFence.** On reschedule, before attaching an RWO RBD volume at the new node, **fence the old node/cluster's IPs from the Ceph backend** so the prior client cannot write, then attach. Production-proven in OpenShift Data Foundation Metro-DR (RBD today; CephFS in progress).

### 4.7 End-to-end walkthroughs

**VM in compute-B, volume in storage-A, network X (global VNI):**
1. User creates `VirtualMachine` (refs `Network X`, `Volume`) in central.
2. Schedulers: VM→compute-B, Volume→storage-A, NIC→VNI(X).
3. `storage-poollet-A` provisions the volume; publishes access bundle + underlay route.
4. NetPlane allocates the VM's IP on VNI(X), registers the endpoint globally.
5. `compute-poollet-B` creates the VMI; primary-UDN CNI wires it to the dataplane; the agent programs endpoints/routes.
6. VMI boots, attaches the remote volume over the storage network, joins the global overlay — no pod network.

**Reschedule B → C (cold):** detach on B (unmap, deregister endpoint) → **fence B from the storage backend (NetworkFence)** → attach on C (map with same access bundle, boot) → NetPlane re-registers the **same VNI IP** at C → IP follows the VM.

**Live cross-cluster migration is not something we build.** We **consume** KubeVirt **Decentralized Live Migration** + **Storage Live Migration** (upstream, VEP-24, Alpha). Our job is the two things that feature requires from the environment: **network identity** (global-overlay IP mobility, so the VM keeps its IP across clusters) and **storage handoff** (shared-backend re-attach with fencing, or letting QEMU block-migrate copy the disk when there is no shared backend).

**DPU split:** the VM's `NetworkInterface` on a DPU-paired host is realized by the **DPU cluster's** agent programming the DPU eswitch for the VM's VF; central coordinates via the pairing.

## 5. Single-cluster invariant (cross-cutting)

**Single-cluster is the degenerate case of the same design, never a separate mode.**

- Central + a compute pool + a storage pool + the dataplane may all be **co-located in one cluster**; poollets then watch the **local** apiserver (loopback) via the identical pull mechanism.
- "Rendezvous through central" and "direct data path" **collapse cleanly** when central == compute == storage.
- Multi-cluster capability (cross-cluster fabric, extra kubeconfigs, host↔DPU pairing) is strictly **additive** — never a prerequisite. Nothing in ①–④ may hard-require a second cluster.
- **Standing acceptance test:** every sub-project must pass in a **one-cluster kind lab** before any multi-cluster wiring.

## 6. Relationship to existing projects

- **KubeVirt** — the compute runtime; consumed via its API + network-binding/primary-UDN.
- **Multus / CNI / primary-UDN** — the VM-attach plumbing; we provide the CNI + binding that targets our dataplane instead of ovn-kubernetes.
- **rook-ceph / CSI** — the storage pool backend; we consume it and add cross-cluster attach + portable access bundles.
- **ironcore** — inspiration for pools/poollets/disaggregation and the apinet network model; no code/API dependency (D1).
- **`apiserver-kit`** — the aggregated-apiserver substrate (D5).
- **Our eBPF dataplane (IEP)** — the datapath, in all three realization topologies.
- **OpenShift DPU (ovn-kubernetes + KubeVirt + SR-IOV VF)** — the reference for the DPU split (§4.5c); we replace ovn-kubernetes with our dataplane.
- **KubeVirt Decentralized + Storage Live Migration** (VEP-24, Alpha, gate `DecentralizedLiveMigration`) — upstream cross-cluster VM mobility we **consume** for §4.7/⑥; it explicitly requires "migrate without IP change", which our global overlay provides.
- **`csi-addons` NetworkFence** — the fencing primitive for safe cross-cluster RWO volume handoff (§4.6); proven in OpenShift Data Foundation Metro-DR.
- **KubeVirt stretched-L2 / EVPN migration networks** — the community solving the same global-overlay problem; our eBPF dataplane is an alternative implementation of it.

## 7. Security

- **No central write-creds into attached clusters** (pull model, D6) — smaller blast radius.
- **Storage secrets are tenant-scoped and dynamic** — Ceph keyrings / NVMe secrets flow to compute nodes only at attach time and are **revoked on detach** (D7).
- Tenant isolation is enforced by the VNI/overlay + per-tenant IPAM; the dataplane's conntrack/NAT/VIP logic already exists.
- **Fencing on handoff** — RWO volume moves fence the prior node/cluster from the storage backend (`csi-addons` NetworkFence) before re-attach, preventing split-brain writes (D7).

## 8. Sub-project decomposition & build order

Each is its own spec → plan → implementation cycle; each must satisfy the single-cluster invariant (§5) first.

1. **VM↔dataplane attach — single cluster, host-software.** primary-UDN CNI + KubeVirt binding wiring the VM's only interface into the existing eBPF tc/XDP datapath, no pod network. *Builds directly on the PoC; proves the novel core.* **← first to detail.**
2. **Central aggregated API + logical model — single cluster.** `apiserver-kit` types (VirtualMachine, Volume, Network, NetworkInterface, pools); reconcile in one cluster.
3. **Compute pool + poollet — multi-cluster compute.** ComputePool + pull compute-poollet; central schedules VMs onto attached KubeVirt clusters.
4. **NetPlane global overlay — multi-cluster networking.** endpoint/route registry, scoped watches, IP mobility.
5. **Storage pool + cross-cluster attach.** StoragePool + storage-poollet; **reuse ceph-csi external-cluster mode** + portable typed access bundle; movable VolumeAttachment; compute-side dynamic client; **`csi-addons` NetworkFence** for safe RWO handoff.
6. **Reschedule / mobility.** cold reschedule across compute pools (fence + re-attach, IP follows); live-migrate within a pool; **integrate KubeVirt Decentralized/Storage Live Migration** for cross-pool (consume upstream, don't build) — our part is network identity + storage handoff.
7. **Dataplane topologies — SmartNIC offload + DPU split.** VF/SF-backed primary-UDN; tc-flower offload; DPU-cluster agent + host↔DPU pairing.
8. **Productionization (cross-cutting).** cluster attach lifecycle (manual → Cluster-API), north-south gateways, tenant-scoped dynamic secrets, observability, conformance.

## 9. Open questions / deferred decisions

- **Global endpoint distribution at scale** — flat scoped-watch vs regional route-reflection; the central scalability risk (§4.4).
- **Cluster attachment lifecycle** — manual registration (PoC) vs Cluster-API-provisioned/managed (later).
- **Cross-pool live migration** — requires simultaneous volume reach + KubeVirt live-migration spanning clusters; deferred.
- **North-south gateways** — external/internet, VIP/LB, NAT64 termination placement.
- **host↔DPU pairing discovery** — static registration vs auto-discovery (DPU operator equivalent).
- **KubeVirt Decentralized/Storage Live Migration maturity** — Alpha as of 2025; track Alpha→GA and gate cross-pool live migration on it (§4.7).
- **NetworkFence coverage** — RBD-only today; CephFS handoff fencing is in progress (affects non-RBD backends).

## 10. Glossary

- **Pool / poollet** — a placeable capacity domain (compute/storage/dataplane) backed by an attached cluster; a poollet is the cluster-local *pull* agent that reconciles assigned objects.
- **NetPlane** — the central network control plane (IPAM, VNI, endpoint/route registry).
- **Primary-UDN** — a VM whose *primary* (only) interface is a user-defined network, not the pod network.
- **Access bundle** — a portable, self-contained, typed (`rbd|nvme-of`) set of connection info + credentials in `Volume.status.access`.
- **Realization point** — where a `NetworkInterface`'s datapath executes: `host | smartnic | dpu`.
- **Rendezvous through central** — cross-cluster references resolve via central; only data paths are direct cluster-to-cluster.
