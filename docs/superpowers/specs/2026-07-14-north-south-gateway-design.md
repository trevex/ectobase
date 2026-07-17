# North-South Gateway — Design

**Status:** Draft (brainstorm output) — design agreed; next step is `writing-plans`.
**Date:** 2026-07-14
**Parent vision:** `docs/superpowers/specs/2026-07-02-multicluster-kubevirt-dataplane-design.md`; builds on the route-distribution control plane (`2026-07-02-route-distribution-control-plane-design.md`) and the realistic fabric (`docs/superpowers/research/2026-07-14-realistic-bgp-fabric-node-identity.md`).
**Research:** two spikes on N-S gateway models + drain-safe HA (in-conversation; sources: IronCore metalnet/dpservice/ironcore-net, Katran, Google Maglev/Cloud NAT, OVN, Cilium/Calico egress). Key memory: [[dpservice-dual-homing-egress]].

---

## 1. Summary

Give tenant overlay endpoints **north-south** connectivity — **egress** (VM → internet, SNAT), **ingress** (internet → service, L4 load-balanced), and **floating IPs** (1:1 public IP → VM) — via a **centralized fleet of `flowplane` gateway nodes**. The overriding requirement is **HA under maintenance: any gateway node can be drained at any time with ~zero impact on active connections**, behind ECMP, **without cross-fleet state sync**.

The design achieves this by making **correctness stateless in both directions** (conntrack is a cache, never required for correctness): ingress uses **Maglev consistent-hash + DSR**; egress uses **deterministic `(public-IP, port-block)` allocation** (GCP Cloud NAT model) with a dynamic overflow pool. Any gateway recomputes the same mapping, so a drain is a stateless ECMP reshuffle. This reuses the existing `flowplane` datapath (Maglev LB, NAT, VIP, conntrack, encap/decap) almost verbatim and inherits IronCore's deterministic NATGateway allocation concept. VyOS/ToRs reduce to WAN peering + BGP.

## 2. Goals / Non-goals

**Goals**
- Egress SNAT, ingress L4 LB, and floating IPs for overlay tenants.
- **Drain-safe fleet**: any node down for maintenance anytime → minimal impact, no state sync.
- Reuse the existing datapath; the fleet is `flowplane` in a **gateway role**.
- Scale-out ingress (ECMP + Maglev) and IP-efficient egress (deterministic + overflow).
- Single-cluster works; multi-cluster is additive (gateways in a pool/edge).

**Non-goals (now)**
- Cross-fleet per-flow conntrack sync (nobody does it at scale; the design avoids needing it).
- L7 / TLS termination (L4 only; L7 is a future upstream tier).
- Replacing VyOS's WAN/BGP role.
- The IPv4-thrifty egress fallback (graceful-drain + reset the tail) is documented (§9) but not the primary path.

## 3. Key decisions (rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Centralized `flowplane` gateway fleet** (not metalnet's fully-distributed N-S) | Concentrates public exposure + scarce IPv4 on a few nodes — fits the multi-cluster central/compute split and security posture. metalnet distributes N-S onto every hypervisor; we deliberately don't. |
| D2 | **Correctness is stateless in both directions; conntrack = cache** | The only way to make a fleet drain-safe without state sync (Katran/Maglev/GCP Cloud NAT all do this). A mid-flow ECMP reshuffle to another node stays correct. |
| D3 | **Ingress = Maglev consistent-hash + DSR** | Deterministic backend selection → any node picks the same backend; DSR keeps return off the fleet → no ingress return-state. Reuses our Maglev datapath. |
| D4 | **Egress = deterministic `(public-IP, port-block)` per source + dynamic overflow** (GCP model) | Any gateway computes the same SNAT mapping AND the reverse mapping for return traffic → drain-safe; overflow pool keeps IPv4 efficient. Inherits IronCore NATGateway's RFC-7422 allocation. |
| D5 | **Dedicated PublicVNI** the gateways subscribe to | One well-known VNI carries public traffic (VIPs, NAT IPs, floating IPs); gateways subscribe via routebus; hypervisors encap N-S into it. Mirrors metalnet's PublicVNI. |
| D6 | **VyOS/ToRs = WAN peering + BGP only** | The gateway `flowplane` owns overlay N-S; VyOS does physical WAN uplink + BGP redistribution of public prefixes. Least coupling. |
| D7 | **Deterministic reverse mapping distributed to ALL gateways** | For stateless egress return, every gateway must map `(public-IP, dst-port-block) → {source private IP, source hypervisor underlay, VNI}`. This is the allocator's output, distributed via the control plane (not per-flow state). |

## 4. Architecture

```
        internet ── WAN ── VyOS/ToR (BGP: announce public prefixes, ECMP to fleet)
                              │  ECMP (resilient hashing: drain-safe on removal)
        ┌─────────────────────┼─────────────────────┐
   ┌────┴─────┐         ┌─────┴────┐          ┌──────┴───┐   flowplane GATEWAY FLEET (gateway role)
   │ gw-1     │         │ gw-2     │   …      │ gw-N     │   • subscribe PublicVNI (routebus)
   │ Maglev   │         │ Maglev   │          │ Maglev   │   • ingress: Maglev→encap to backend; DSR
   │ det-SNAT │         │ det-SNAT │          │ det-SNAT │   • egress: det (pubIP,port-block)+overflow
   │ conntrack│         │ conntrack│          │ conntrack│   • conntrack = CACHE ONLY
   └────┬─────┘         └─────┬────┘          └────┬─────┘
        └───────── overlay fabric (IP-in-IPv6, PublicVNI) ──┴──────────┐
                              │                                         │
                   ┌──────────┴───────┐                     ┌───────────┴────────┐
                   │ hypervisor A     │  …                  │ hypervisor B       │
                   │ flowplane + VM(s)   │                     │ flowplane + backend VM │
                   │ (egress default  │                     │ (ingress backend;   │
                   │  route→PublicVNI)│                     │  DSR reverse-SNAT)  │
                   └──────────────────┘                     └─────────────────────┘
```

### 4.1 Gateway node (`flowplane`, gateway role)
Same binary, a `--role gateway` (or a serve flag) that: subscribes to the **PublicVNI** via routebus; attaches `uplink_rx` to the WAN-facing + fabric-facing interfaces; programs Maglev tables (ingress LBs), the deterministic SNAT port-block maps (egress), and floating-IP DNAT. No local VM interfaces. Conntrack runs but is treated as a cache.

### 4.2 Hypervisor (`flowplane`, node role — existing)
- **Egress:** a VPC default route (`0.0.0.0/0` / `::/0`) → PublicVNI → the gateway fleet (ECMP). The VM's frame is encapped to a gateway underlay.
- **Ingress backend (DSR):** for each LB it backs, the hypervisor gets a **VIP reverse-SNAT** rule so replies leave sourced from the VIP (DSR), bypassing the ingress gateway's return path.
- **Floating IP:** unchanged from the existing per-interface VIP (may stay distributed OR move to the gateway — see §10).

### 4.3 Control plane (Go, extends the route-distribution stack)
- **CRDs (flesh out the scaffolds):** `LoadBalancer{vip, ports, backendSelector}`, `NATGateway{publicIPs, portsPerSource}`, `VirtualIP{vip, targetInterface}`.
- **Gateway agent** (like the node agent): reconciles the N-S CRDs on gateway nodes → programs the local gateway `flowplane` (Maglev via `create_lb`/`add_lb_target`, SNAT maps, VIP DNAT).
- **Deterministic port-block allocator** (central controller, à la ironcore NATGateway): assigns `(public-IP, port-block)` per source (interface/VPC); publishes the `port-block → {source private IP, source underlay, VNI}` reverse map to **all** gateways via routebus (a new PublicVNI record type). The overflow pool is a small dynamically-allocated range (per-flow state; the acceptable non-drain-safe tail).
- **routebus:** gateways subscribe to PublicVNI; the reflector distributes: LB VIP routes (→ which gateways announce the VIP), NAT public-IP routes, floating-IP routes, and the deterministic reverse-map records.
- **BGP:** gateways (or VyOS on their behalf) announce public prefixes (VIP `/32`s, NAT IP `/32`s, floating IPs) to the WAN so the fabric ECMPs them across the fleet.

## 5. Data flows

**Egress (VM → internet):**
1. VM sends to a public dst; VPC default route → PublicVNI → ECMP to gw-k.
2. gw-k looks up the source's deterministic `(public-IP, port-block)` (control-plane fact), SNATs, forwards to WAN. Conntrack cached (optimization).
3. Return (internet → public-IP:port) → BGP-ECMP to **any** gw-j.
4. gw-j maps `(public-IP, dst-port ∈ block) → {source private IP, source underlay, VNI}` (distributed reverse map), reverse-SNATs, re-encaps to the source hypervisor. **Stateless — gw-j need not be gw-k.**
- *Overflow:* if the source exhausts its port-block, gw-k allocates from the dynamic pool (per-flow state on gw-k); those flows reset if gw-k drains (the accepted tail).

**Ingress (internet → LB VIP):**
1. All gateways announce the VIP `/32` → WAN ECMPs across the fleet.
2. gw-k Maglev-hashes the 5-tuple → backend VM → IP-in-IPv6 encap to the backend's hypervisor (PublicVNI). Deterministic → any gateway picks the same backend.
3. Backend hypervisor delivers to the VM; the reply is **DSR**: hypervisor reverse-SNATs source→VIP and sends toward the client (via its egress path → a gateway forwards VIP-sourced traffic to WAN, no SNAT). The ingress gateway holds no return state.

**Floating IP (internet ↔ 1:1 VM):** deterministic DNAT `VIP → VM private IP` (and SNAT on egress); any gateway computes it identically.

**Drain gw-k:** withdraw its BGP/health → ECMP removes it (FRR resilient hashing: surviving flows undisturbed). In-flight egress/ingress flows reshuffle to other gateways that **recompute the same deterministic mapping** → survive. Only dynamic-overflow egress flows pinned to gw-k reset (bounded tail).

## 6. Why this is drain-safe (the core property)
No gateway holds state required for correctness: ingress backend selection (Maglev) and egress SNAT mapping (deterministic `(public-IP, port-block)` + distributed reverse map) are pure functions any node computes. Conntrack is a per-node cache; losing it on drain costs a recompute, not a connection. This is the Katran / Google Maglev / GCP Cloud NAT property, applied to both directions. Cross-fleet state sync — which nobody does at scale (OVN/Cilium/AWS all reset the tail) — is not needed.

## 7. Reuse vs new
- **Reuse (already in `flowplane`):** Maglev LB (`create_lb`/`add_lb_target`, `maglev.rs`), NAT SNAT (`create_nat`/`add_neighbor_nat`), VIP DNAT/SNAT (`create_vip`/`vip.rs`), encap/decap, `uplink_rx`, conntrack.
- **New:** the gateway **role** (serve mode + WAN interface handling); the **deterministic port-block allocator** + its reverse-map distribution (extends NATGateway CRD + routebus); **DSR** reverse-SNAT on backend hypervisors; **PublicVNI** subscription + public-prefix BGP announcement; the gateway agent reconciling the N-S CRDs.

## 8. Multi-cluster fit
Gateways live in a dedicated **edge/gateway pool** (central cluster or a per-region edge), announcing public prefixes to the WAN. Compute clusters' hypervisors encap N-S into the PublicVNI toward the gateway pool over the fabric (the same cross-cluster routebus + fabric already built). Single-cluster is the degenerate case (a small gateway set co-located).

## 9. IPv4-thrifty fallback (documented, not primary)
If deterministic port-block pre-commit is too costly, egress can fall back to **graceful-drain + reset the tail** (Cloud-NAT-IP-drain / AWS-350s / Cilium semantics): conntrack per gateway, on drain withdraw BGP + hold established for a window + reset stragglers. Chosen per-NATGateway; the deterministic+overflow model (D4) is the default.

## 10. Open questions / spikes
- **DSR-in-IPv6-overlay feasibility:** the exact mechanics of the backend hypervisor sourcing replies from the VIP and getting them to the WAN (does the reply transit an egress gateway as VIP-sourced pass-through?). The highest-risk spike.
- **Deterministic reverse-map scale:** distributing `port-block → source` records to all gateways via routebus — volume, update rate, and the PublicVNI record schema.
- **Overflow pool semantics:** how much dynamic range, and confirming the overflow tail is the only non-drain-safe part.
- **Floating IP placement:** keep per-hypervisor (metalnet, distributed) or move to the gateway (centralized) — the former is simpler and already exists.
- **ECMP add-reshuffle:** confirm FRR resilient hashing + the deterministic datapath fully absorb a scale-*up* (add) event (research says resilient hashing only protects removals; the datapath must cover adds).
- **conntrack-as-cache correctness:** verify the datapath treats a conntrack miss as "recompute" (Maglev / deterministic map), not "drop".

## 11. v1 scope & acceptance
- Gateway role + PublicVNI subscription; the three CRDs fleshed out + the gateway agent.
- **Egress:** deterministic `(public-IP, port-block)` + overflow; a VM reaches the internet; drain a gateway mid-flow → deterministic flows survive (verified on the containerlab fabric with a WAN bridge).
- **Ingress:** a Maglev LB VIP announced from ≥2 gateways, ECMP'd; external client → backend VM; drain a gateway → flows survive; DSR return.
- **Floating IP:** 1:1 public ↔ VM.
- **Acceptance e2e:** on the fabric (add a WAN/edge like the icn/sandbox VyOS+clabwan), external reachability both directions through a ≥2-node gateway fleet, and a **mid-flow gateway drain with ~zero impact** on deterministic flows.
