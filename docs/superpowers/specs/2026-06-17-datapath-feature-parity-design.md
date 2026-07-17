# Design: VIP / LB / NAT-GW datapath feature parity

**Date:** 2026-06-17
**Status:** Approved design, pre-implementation
**Author:** Niklas Voss (with Claude)
**Builds on:** `docs/superpowers/specs/2026-06-15-flowplaneservice-design.md` (foundation PoC, complete)

## 1. Background & goal

The foundation PoC (Tasks 1–14) proved a Rust/aya XDP dataplane that speaks the real
dpservice `DPDKironcore` gRPC contract and carries guest-to-guest traffic over an IP-in-IPv6
overlay (validated end-to-end in a netns lab). That datapath is **CONFIG-driven single-peer**
(one guest, one peer per hypervisor).

This sub-project adds the remaining dpservice dataplane features — **VirtualIP (VIP), Load
Balancer (Maglev), and NAT Gateway** — with **functional + wire-compatible** parity: the same
gRPC contract metalnet / `dpservice-cli` already drive, and functionally-equivalent behavior.
Internal algorithms (exact Maglev table construction, exact NAT port-allocation scheme) need
**not** be byte-identical to dpservice's C implementation.

This is **sub-project 1 of two**. Sub-project 2 (separate spec) forks
`ironcore-dev/ironcore-in-a-box` and uses this `flowplane` as a drop-in replacement for the DPDK
tap-device dev setup. Sub-project 2 is out of scope here.

## 2. Architecture — map-driven, multi-interface pipeline

Replace the single CONFIG entry with a **dpservice-style packet pipeline** resolved from BPF
maps. One `guest_tx` program (attached on every guest tap) and one `uplink_rx` (on the
uplink) serve all interfaces; a `port_meta` map (`ingress ifindex → interface metadata`)
identifies which interface/VNI an ingress packet belongs to.

**Egress pipeline — `guest_tx` (packet leaving a guest):**
1. ARP / IPv6-ND for the gateway → answer in-datapath (responder).
2. conntrack lookup (established flow → apply stored translation).
3. VIP SNAT (if the source has a VIP, rewrite src → VIP).
4. NAT-GW SNAT (if dst is external, rewrite src → NAT IP + allocated port; insert conntrack).
5. route lookup (`routes`/`interfaces`): overlay peer, LB, or external nexthop.
6. IP-in-IPv6 encap → `bpf_redirect` to the uplink.

**Ingress pipeline — `uplink_rx` (packet arriving from the underlay):**
1. decap outer Eth+IPv6.
2. conntrack reverse lookup (un-SNAT / un-DNAT for return traffic).
3. VIP DNAT (dst is a VIP → rewrite to the interface IP).
4. LB (dst is an LB IP → Maglev pick backend → DNAT + encap to the backend's hypervisor; pin
   the flow in conntrack).
5. deliver to the local guest tap (`interfaces` lookup by VNI + inner dst IP).

The pipeline stays **pure XDP** (offload-aligned) on both hooks.

## 3. Maps (control-plane ↔ datapath contract)

| Map | Key → Value |
|---|---|
| `port_meta` | ifindex → { vni, local_ipv4, gateway_mac, flags } |
| `interfaces` | (vni, ipv4) → { tap_ifindex, underlay_ipv6 } (local or remote) |
| `routes` | (vni, ipv4 prefix) → underlay IPv6 nexthop |
| `vips` | vip_ipv4 ↔ (vni, interface ipv4) — bidirectional (forward + reverse) |
| `lb` | (vni, lb_ipv4, port, proto) → maglev_table_id |
| `maglev_tables` | table_id → backend array (each backend: overlay IP + underlay endpoint) |
| `nat` | (vni, local_ipv4) → { nat_ipv4, port_min, port_max } |
| `neighbor_nat` | (nat_ipv4, port range) → underlay endpoint (distributed-NAT return) |
| `conntrack` | 5-tuple → { translation, flags, last_seen } — `BPF_MAP_TYPE_LRU_HASH` |

All POD key/value types live in `flowplane-common` (shared, `#[repr(C)]`, layout-tested).

## 4. Per-feature mechanics (functional parity)

- **ARP / ND responder (M1):** `guest_tx` detects an ARP request (or IPv6 Neighbor
  Solicitation) for the gateway / an overlay address we own and crafts the reply (swap
  src/dst, fill our MAC) returning `XDP_TX`. VMs resolve their gateway with no host-side neigh
  config — required for a clean ioiab drop-in.
- **VIP (M2):** 1:1 NAT. Inbound: DNAT vip → interface IP. Outbound: SNAT interface IP → vip.
  `CreateVip` / `GetVip` / `DeleteVip` program the `vips` map and return the underlay route
  (as dpservice does).
- **LB / Maglev (M3):** userspace builds the Maglev lookup table from the registered targets
  and writes it to `maglev_tables`; `uplink_rx` hashes the packet 5-tuple → table slot →
  backend, DNATs to the backend overlay IP, encaps to the backend's hypervisor, and pins the
  flow in `conntrack` for symmetric return. `CreateLoadBalancer` / `CreateLoadBalancerTarget`
  / `CreateLoadBalancerPrefix`.
- **NAT-GW (M4):** outbound SNAT guest IP → NAT IP with a port allocated from the configured
  range, plus a `conntrack` entry; inbound reverse-translate using `conntrack`. `CreateNat` /
  `ListLocalNats`. **`CreateNeighborNat` (distributed multi-node return) is a stretch goal** —
  single-node NAT-GW is the core M4 deliverable.

## 5. Control plane

Implement the per-feature gRPC RPCs (proto already vendored) to program the maps, and finally
wire `CreateInterface` / `CreateRoute` to program `interfaces` / `routes` (deferred in
foundation Task 12). Userspace additionally owns:
- **Maglev table construction** (build the lookup table from targets; rebuild on target
  add/remove).
- **NAT port bookkeeping** (track allocated port ranges/blocks per local IP).
- **conntrack GC** — a periodic task that sweeps idle entries by `last_seen` (explicit
  idle-timeout on top of the `LRU_HASH` auto-eviction).

The gRPC server now owns the loaded eBPF object + map handles (so handlers can write maps);
serving therefore requires CAP_BPF (dpservice runs privileged too).

## 6. Code organization

The eBPF datapath grows, so split `flowplane-ebpf/src` into focused modules: `parse` (header
bounds-checked parsing), `arp_nd`, `vip`, `lb`, `nat`, `conntrack`, `encap`. Userspace
(`flowplane/src`) gains per-feature map writers, a `maglev` builder module, and a `conntrack_gc`
task. Each file keeps one clear responsibility; the monolithic `main.rs` datapath from the
foundation is decomposed as part of M1.

## 7. Testing — extended netns lab

Extend `env/netns-e2e.sh` (keeping its reliable up/test/down/run + EXIT-trap teardown) with an
`extclient` netns (an external peer reachable over the underlay) and ≥2 `backendN` netns.
Per-milestone acceptance gates:
- **M1:** a guest resolves its gateway via datapath ARP/ND (no static neigh) and multi-guest
  overlay ping works (≥2 guests, map-driven).
- **M2:** `extclient → VIP` reaches the guest, and the guest's egress is seen with the VIP as
  source.
- **M3:** `extclient → LB IP` is distributed across ≥2 backends (both observed), and a single
  flow is sticky to one backend.
- **M4:** `guest → extclient` is seen by extclient as the NAT IP, and return traffic works
  (conntrack reverse).

Plus userspace unit tests: Maglev table correctness/even distribution, NAT port allocation,
and proto→map translation. eBPF programs continue to be gated by a verifier-load test.

**Tap-based test mode (cross-cutting).** Beyond the netns+veth lab, add a **tap-based guest
mode** to the harness so the datapath is exercised on real tap devices
(`IFF_TAP|IFF_VNET_HDR`), matching the production VM environment (vnet_hdr stripping, native XDP
attach, redirect-into-tap delivery — proven in the XDP-on-tap spike). Introduce this as an early
enabling task in the first feature plan (VIP/M2) so VIP/LB/NAT are all validated on taps, not
only veth. (Shared with sub-project 2, which uses the same tap harness.)

## 8. Milestones

1. **M1 — Generalize datapath**: map-driven multi-interface pipeline; in-datapath ARP/ND
   responder; `port_meta`; `CreateInterface`/`CreateRoute` program maps; decompose the eBPF
   datapath into modules; extend the lab; multi-guest overlay ping.
2. **M2 — VIP**: `vips` map + 1:1 DNAT/SNAT + `Create/Get/DeleteVip`.
3. **M3 — LB/Maglev**: `lb` + `maglev_tables` + userspace Maglev builder + 5-tuple hash DNAT
   + conntrack pin + `CreateLoadBalancer/...Target/...Prefix`.
4. **M4 — NAT-GW**: `nat` + `conntrack` SNAT/reverse + port bookkeeping + GC + `CreateNat`/
   `ListLocalNats`. Stretch: `CreateNeighborNat` distributed return.

Each milestone is independently demoable and likely gets its own implementation plan.

## 9. Out of scope

ironcore-in-a-box integration (sub-project 2); firewall rule enforcement; IPv6-tenant
overlays (overlay stays IPv4 over an IPv6 underlay); byte-exact algorithm parity with
dpservice; performance/HA tuning; `CreateNeighborNat` multi-node return (stretch within M4).
