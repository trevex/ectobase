# Sub-project ① — KubeVirt VM on the eBPF Dataplane (single cluster, host-software)

**Status:** Draft (brainstorm output) — design agreed; next step is `writing-plans`.
**Date:** 2026-07-02
**Parent vision:** `docs/superpowers/specs/2026-07-02-multicluster-kubevirt-dataplane-design.md` (sub-project ①)

---

## 1. Goal

A KubeVirt VM whose **only** network interface is our eBPF dataplane — **true primary-UDN, no pod network on the virt-launcher pod at all** — boots, gets **DHCP from the dataplane**, and reaches **another such VM** over the overlay, in a **single kind cluster**, proven by an **e2e test**. This is the tracer bullet that de-risks the entire platform's novel core.

## 2. Scope / non-goals

**In scope:** the `cni/` primary-UDN plugin (Go); a clean node-agent gRPC service on the extended Rust `flowplane`; minimal IPAM; the monorepo + kind/envtest harness (built to scale 1→N clusters); the e2e acceptance test.

**Out of scope (later sub-projects):** aggregated API / pools / poollets (②–③), NetPlane global overlay & cross-cluster endpoint distribution (④), storage (⑤), mobility (⑥), SmartNIC/DPU realization (⑦). Realization is **host-software only** here. IPAM is trivial (static VNI + per-network subnet); no cross-node/cross-cluster route distribution.

## 3. Key decisions carried in

- **Node agent = the extended Rust `flowplane` daemon** (reuses the working aya datapath: overlay encap/decap, ARP/ND, DHCP, conntrack/NAT).
- **Clean, purpose-built gRPC** for the CNI↔dataplane interaction, in `api/proto/dataplane/v1` (package named **`dataplane`**, not `dpservice`). The legacy DPDKironcore proto moves into the same package transitionally (still used by the IEP `serve` path) and is absorbed/retired over time — no separate `dpservice` naming.
- **True primary-UDN from the first green e2e** (no interim guest-only-NIC rung). Because this is the newest/riskiest KubeVirt+CNI plumbing, **task 1 is a feasibility spike**.
- **Single-cluster** honors the platform's single-cluster invariant; harness helpers are written multi-cluster-ready.

## 4. Monorepo layout (changes)

```
Cargo.toml  flowplane/ flowplane-common/ flowplane-ebpf/   # Rust dataplane (extended: new gRPC service)
api/
  proto/
    dataplane/v1/            # THE dataplane gRPC package (tonic + protoc-gen-go)
      dataplane.proto        #   NEW clean node-agent service (DataplaneNode)
      dpdk.proto             #   moved legacy proto, retained transitionally for the IEP build
go.work                      # NEW Go workspace
cni/                         # NEW primary-UDN CNI plugin (Go)
test/e2e/                    # NEW kind-based e2e (Go); existing netns/conformance stay
hack/                        # NEW kind-up + install kubevirt/multus/cdi + image-load
```

## 5. Components

### 5.1 Node-agent gRPC (`api/proto/dataplane/v1`)
A minimal, clean interface programmed by the CNI on each node:
```
service DataplaneNode {
  rpc AttachInterface(AttachRequest) returns (AttachReply);   // wire a VM iface into the dataplane
  rpc DetachInterface(DetachRequest) returns (Empty);
  rpc ConfigureNetwork(NetworkConfig) returns (Empty);        // VNI, gateway, DHCP opts (minimal)
}
// AttachRequest{ interface_id, netns_path, vni, mac?, requested_ips? }
// AttachReply{ ifname, ips[], mac, gateway }
```
Served by `flowplane` alongside (not replacing) the existing dpservice-compat service. Implementation reuses the existing eBPF datapath modules.

### 5.2 `flowplane` extension (Rust)
Add the `DataplaneNode` service; on `AttachInterface`, set up the VM's tap/veth in the target netns and program the eBPF maps/endpoints for that interface (local-only endpoint registration for ①). Reuse `flowplane-common` (dhcp, arp_nd) and the egress/overlay logic.

### 5.3 CNI plugin (`cni/`, Go)
A CNI ADD/DEL plugin that, on VMI launch, dials the local `flowplane` `DataplaneNode` socket, calls `AttachInterface`, and returns the CNI IPAM result. Wired as the virt-launcher pod's **primary** network (mechanism confirmed by the spike — see §7).

### 5.4 IPAM (minimal)
Static per-`Network` subnet + a simple in-memory/CRD-less allocator for ①; the datapath already answers DHCP from allocated leases.

## 6. Test strategy (testing is a first-class deliverable)

- **Feasibility spike (task 1):** one VM, primary interface on our CNI, **no pod network**; assert it boots and the launcher pod has no default pod-network interface. Resolves the primary-UDN mechanism before building around it.
- **envtest:** integration tests for the CNI/agent control logic and any controllers (fast, no kind).
- **kind e2e (`test/e2e`, Go) — the acceptance gate:** create a kind cluster; install KubeVirt + Multus + CDI; deploy `flowplane` DaemonSet + the CNI; apply a `Network`(VNI) + **two VMs** with primary-UDN; assert **both boot**, **get DHCP from the dataplane**, **ping each other** over the overlay, and **have no pod-network interface**. Helpers accept `clusters=[…]` so ③–④ reuse them.
- **Existing** `test/netns-*` + `test/conformance` datapath tests stay as-is.

## 7. Open questions (spike resolves the first)

- **Exact true-primary-UDN mechanism** — Multus default-network delegation (`v1.multus-cni.io/default-network`) vs a KubeVirt network-binding plugin vs the KubeVirt primary-UDN API path. Version-sensitive; the spike picks the concrete path.
- **VM image / CDI in kind** — which small guest image + boot method keeps the e2e fast and offline-friendly.
- **`flowplane` socket exposure** — host unix socket path + how the CNI (running in the kubelet/CNI context) reaches it.

## 8. Task outline (for `writing-plans`)

1. **Primary-UDN research + feasibility spike:** properly research the exact KubeVirt primary-UDN mechanism (Multus default-network delegation vs a KubeVirt network-binding plugin vs the KubeVirt primary-UDN API; version constraints); document the chosen path; then a throwaway spike — one VM, no pod net, boots on our CNI.
2. **Monorepo skeleton:** `api/` move (+ build.rs path), `go.work`, `cni/` + `test/e2e/` stubs, `hack/` kind-up & installs.
3. **Clean node-agent proto** (`api/proto/dataplane/v1`) + `flowplane` service stub (returns canned reply) + Rust/Go codegen wired.
4. **CNI plugin** ADD/DEL calling `AttachInterface`; envtest.
5. **Minimal IPAM**.
6. **Real datapath attach** in `flowplane` (program eBPF for the interface; DHCP+overlay).
7. **Two-VM e2e green** (boot + DHCP + ping + no-pod-net assertion).
8. **envtest coverage** for control logic; CI wiring for kind e2e.
```
