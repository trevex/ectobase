# Design: `flowplaneservice` — an eBPF/XDP drop-in dataplane for IronCore

**Date:** 2026-06-15
**Status:** Approved design, pre-implementation
**Author:** Niklas Voss (with Claude)

## 1. Background & motivation

IronCore (https://github.com/ironcore-dev) provides a hypervisor environment across
multiple Kubernetes clusters. Its network stack layers as follows:

- **ironcore-net** — aggregated K8s API server + controller-manager. Models high-level
  constructs (Networks, NetworkInterfaces, LoadBalancers, NATGateways, VirtualIPs).
  `metalnetlet` projects ironcore-net "Nodes" onto metalnet clusters; `apinetlet`
  realizes ironcore objects.
- **metalnet** — per-cluster K8s controllers. Owns CRDs (NetworkInterface, Network, …),
  performs the sysfs/hardware wiring of SR-IOV VFs, drives **dpservice over gRPC**, and
  subscribes to metalbond for routes.
- **metalbond** — a route reflector. Hypervisors announce local overlay routes; metalbond
  distributes them to subscribed peers, which program them (netlink today).
- **dpservice** — the **dataplane**. An L3 virtual router with IP-in-IPv6 overlay tunneling
  for uplink traffic, running on SR-IOV VFs as virtual ports. Built on **DPDK's Graph
  Framework + `rte_flow`** for hardware offload. Implements LB (maglev), NAT gateway, VIP,
  IPv4/IPv6 overlay, plus DHCP/ND/ARP. Exposes a **gRPC API** (`DPDKironcore` service) and a
  Go CLI (`dpservice-cli`).

dpservice relies on DPDK. The goal of this project is an **offload-capable alternative based
on eBPF/XDP** (written in Rust with `aya`), able in the future to leverage hardware offload
including xfrm/IPsec and kTLS offload. This document scopes a **PoC** that proves XDP can
replace DPDK behind the existing IronCore control-plane contract.

**Key architectural insight:** the natural drop-in seam is **dpservice's `DPDKironcore`
gRPC API**. If a Rust/aya XDP dataplane speaks the same gRPC contract metalnet expects, the
control plane above is unaffected and the DPDK→XDP swap becomes invisible to it.

## 2. Goal & success criteria

Build a Rust/aya eBPF-XDP dataplane that is a **drop-in replacement for dpservice's
`DPDKironcore` gRPC contract**, proving DPDK can be swapped for offload-ready XDP without
disturbing the IronCore control plane.

**The PoC is "done" when:** on two hypervisor VMs, a guest in netns-A reaches a guest in
netns-B (ping + iperf3); traffic is **IP-in-IPv6 encapsulated by an XDP program**, carried
over the host underlay, and decapsulated by XDP on B — and the interfaces/routes were
programmed by the **real Go `dpservice-cli`** talking to our Rust gRPC server. VIP, LB
(maglev), and NAT each get a working demo built on that base.

## 3. Scope decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Control-plane fidelity | Real `DPDKironcore` gRPC; willing to change metalnet where justified; tap interfaces substitute for SR-IOV VFs |
| Datapath features (eventual) | Overlay L3 + IP-in-IPv6, VirtualIP (1:1 DNAT/SNAT), LB (maglev), NAT gateway (SNAT + port mgmt) |
| Offload | **Offload-ready design, software XDP PoC** — code kept within the XDP-offloadable subset; no actual hardware offload in the PoC |
| Workload model | Real KVM VMs as hypervisors; guests are netns + tap |
| Topology | Two hypervisor VMs on a host underlay bridge, no nested virt |
| Datapath architecture | **Approach A — pure XDP, ingress + egress redirect** |
| eBPF framework | Rust + `aya` / `aya-ebpf` |

## 4. Components

- **`flowplane` (control plane, Rust):** `tonic` gRPC server implementing the `DPDKironcore`
  service; loads/attaches XDP programs via `aya`; owns and writes the BPF maps; small local
  CLI for ops/debug.
- **`flowplane-ebpf` (datapath, Rust / `aya-ebpf`):** XDP programs for the guest-tap and uplink
  interfaces.
- **`flowplane-common` (shared crate):** map key/value structs (`#[repr(C)]`, `Pod`) shared
  between userspace and eBPF; tunnel/header constants.
- **Environment tooling:** scripts / `just` targets to build the two KVM hypervisor VMs, the
  host underlay bridge, k3s, and netns/tap guests.

## 5. Datapath design (Approach A — pure XDP)

- **Guest tap, XDP ingress (traffic leaving a guest):** parse inner L2/L3 → lookup
  `interfaces`/`routes` maps by VNI + destination → `bpf_xdp_adjust_head` to prepend the
  outer IPv6 header (with IronCore tunnel semantics) → `bpf_redirect` to the uplink ifindex.
- **Uplink, XDP ingress (traffic arriving from another hypervisor):** match outer IPv6 dst +
  VNI → strip outer header (`bpf_xdp_adjust_head`) → `bpf_redirect` to the destination guest
  tap.
- **Feature stages layered on the base:**
  - **VIP:** 1:1 DNAT/SNAT performed in the same XDP pass.
  - **LB:** maglev backend-table lookup → backend rewrite.
  - **NAT-GW:** SNAT + port-range map. This is the single feature permitted a **carve-out**
    (TC clsact egress or a userspace-assist path) if pure XDP proves too painful for the PoC;
    the core overlay/VIP/LB datapath stays pure XDP.
- **Offload-readiness rule (reviewed against, per change):** restrict to the XDP-offloadable
  subset — fixed-shape map lookups, `bpf_xdp_adjust_head`, `bpf_redirect`, `bpf_fib_lookup`;
  no unbounded loops; avoid offload-hostile helpers. The intent is that the same programs
  could later be JIT-offloaded to a SmartNIC (the `rte_flow`-equivalent path).

## 6. State (BPF maps, written by the control plane)

| Map | Key → Value (conceptual) |
|---|---|
| `interfaces` | VNI + guest IP → tap ifindex, underlay endpoint |
| `routes` | VNI + prefix → next-hop IPv6 (underlay) |
| `vips` | VIP ↔ interface IP (1:1) |
| `lb` | service (IP+port+proto) → maglev backend table |
| `nat` | local IP → external IP + port range |
| `firewall` | (later) rule set |

gRPC handlers translate `DPDKironcore` messages into map updates. Userspace owns the
authoritative state; maps are the kernel-visible projection.

## 7. Control-plane fidelity & sequencing

- **Conformance driver:** the genuine Go `dpservice-cli` drives our `tonic` server. If the
  real client works against us, drop-in fidelity is proven cheaply. The real
  `DPDKironcore` `.proto` is consumed via `tonic-build`.
- **`DPDKironcore` surface (target):** `Initialize`/`CheckInitialized`/`GetVersion`;
  interfaces (`Create/Get/List/DeleteInterface`); routes (`Create/Delete/ListRoutes`);
  prefixes; `CreateVip`/`GetVip`/`DeleteVip`; load balancers + targets; NAT
  (`CreateNat`/…/`CreateNeighborNat`); firewall rules; capture. The PoC implements the
  subset needed per milestone, returning sane stubs elsewhere.
- **Deferred integrations:**
  - **metalbond** (dynamic route reflection): the PoC injects routes via gRPC `CreateRoute`
    first; a metalbond client is a stretch milestone.
  - **metalnet**: its sysfs/VF wiring assumes SR-IOV hardware the PoC doesn't have;
    integration is a stretch milestone, changing metalnet only where justified.

## 8. Environment

Host bridge as the underlay network ↔ two KVM VMs (`hypA`, `hypB`), each running k3s +
`flowplane` + the XDP programs, each with a guest netns/tap. KVM confirmed available on the host
(AMD-V, 16 cores, ~30 GB RAM). Built reproducibly via `just` + the Nix flake toolchain
(already provides Rust stable + rust-src + Go); add `aya`/`bpf-linker` and qemu/libvirt.

```
host (underlay bridge)
  ├─ hypervisorVM-A (k3s, flowplane, XDP programs)
  │    └─ guest netns A  (tap0)
  └─ hypervisorVM-B (k3s, flowplane, XDP programs)
       └─ guest netns B  (tap0)

A.guest --tap--> XDP encap --IPv6 underlay--> XDP decap --tap--> B.guest
```

## 9. Milestones (each independently demoable)

1. **Scaffold:** cargo workspace (`flowplane`, `flowplane-ebpf`, `flowplane-common`), aya XDP
   "hello", flake + `just` additions, bpf-linker.
2. **gRPC skeleton:** `tonic` server exposing `DPDKironcore` with in-memory state; real
   `dpservice-cli` connects and lists interfaces/routes.
3. **Overlay base (core proof):** `CreateInterface` + `CreateRoute` → BPF maps → XDP
   encap/decap → **guest-A ⇄ guest-B ping + iperf3 across the two VMs.**
4. **VIP** (1:1 DNAT/SNAT).
5. **LB** (maglev).
6. **NAT gateway** (SNAT + port management; carve-out allowed here only).
7. *(stretch)* metalbond client for dynamic routes.
8. *(stretch)* metalnet integration.

## 10. Out of scope (PoC)

Actual hardware offload; xfrm/IPsec and kTLS offload; deep firewall enforcement; full
`DPDKironcore` proto coverage; DHCP/ND/ARP completeness; HA and performance tuning.

## 11. Testing & verification

- **Unit:** aya userspace tests for map encode/decode and control-plane logic.
- **Datapath:** XDP program tests via `BPF_PROG_RUN` where feasible.
- **End-to-end:** ping + iperf3 between guest-A and guest-B is the **acceptance gate for each
  datapath milestone**; the `dpservice-cli` round-trip is the acceptance gate for the gRPC
  contract.
