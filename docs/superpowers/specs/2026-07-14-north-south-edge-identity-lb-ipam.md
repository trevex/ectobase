# North-South Edge: PublicVNI Identity, External LB, and IPAM — Design

**Status:** Design (consider-and-decide). Follows the shipped egress e2e (D8, NAT44 to the real internet, live).
**Date:** 2026-07-14
**Parent:** `docs/superpowers/specs/2026-07-14-north-south-gateway-design.md` (§3 D5 PublicVNI, D7 reverse-map); `docs/superpowers/plans/2026-07-14-north-south-egress-d8-fabric-e2e.md`.

## 1. Why these three together

The D8 egress e2e works, but live bring-up surfaced three loose ends that turn out to be **one problem seen three ways** — they all want a **PublicVNI** (a well-known overlay VNI carrying public-facing control records) plus a coherent **public-IP IPAM**:

1. **Edge identity (blocker for control-plane-driven edges).** The egress e2e still programs the edge NEIGHBOR_NAT + external default via `grpcurl` because the edge agents can't broker to the central apiserver/reflector: the edge's datapath underlay is the **anycast** `fd00:db8:0:9::e`, so replies to edge-originated control traffic ECMP to *either* edge. The edge needs a **unique control-plane identity** distinct from the anycast datapath address, and sources need to **learn** the (anycast) edge underlay rather than have it hardcoded on `NATGateway.Spec.EdgeUnderlay`.
2. **External L4 load balancing (the deferred ingress arc).** Internet→VIP ingress needs the edge to announce VIP `/32`s to the WAN, Maglev-select a backend, and encap to it (with DSR return). VIPs are just another class of **public prefix** the edge advertises — the same distribution channel as the edge underlay and the NAT IPs.
3. **IPAM.** Today overlay IPs are user-specified, `NATGateway.Spec.PublicIPs` is a hand-typed list, VIPs would be too, and there is no allocation authority. NAT IP pools, VIP pools, and floating IPs are all **public-IP allocations** from shared, scarce ranges — they need one IPAM.

**Thesis:** introduce a **PublicVNI** carrying typed *public-prefix records* over the existing routebus reflector, and a **PublicIPPool** IPAM that allocates every public IP (NAT, VIP, floating) + tags each with its owner. Edge identity, LB, and floating IPs then all fall out of the same two primitives.

## 2. Primitive A — PublicVNI + public-prefix records (routebus)

A reserved VNI (e.g. `VNI 0` or a configured `spec.publicVNI`) that gateways/edges **subscribe** to and the reflector fans out globally (like the existing NAT-block fan-out, which is already global). Records are typed:

```proto
message PublicPrefix {
  enum Kind { EDGE_UNDERLAY=0; NAT_IP=1; LB_VIP=2; FLOATING_IP=3; }
  Kind   kind            = 1;
  string prefix          = 2;   // 203.0.113.1/32, a VIP /32, 64:ff9b::/96, an edge /128 …
  string owner_underlay  = 3;   // the announcing node's UNIQUE underlay (NOT an anycast)
  uint32 vni             = 4;   // the overlay VNI this public prefix serves
  bytes  attributes      = 5;   // kind-specific (Maglev table id, port-block, backend set …)
  RouteOp op             = 6;
}
```

- **Edge announces `EDGE_UNDERLAY`** for its anycast datapath `/128` (kind=EDGE_UNDERLAY, prefix=fd00:db8:0:9::e/128, owner_underlay=its **unique** loopback). Source hypervisors learn it → the external default route's nexthop becomes **discovered**, not configured. `NATGateway.Spec.EdgeUnderlay` becomes optional/derived. New edges joining the anycast pool need no CRD edit.
- **NAT reverse-map** (already exists as the NatBlock stream) folds in as `NAT_IP` records.
- **LB VIPs** ride as `LB_VIP` records (§4). **Floating IPs** as `FLOATING_IP`.

This is exactly spec §3 **D5** ("dedicated PublicVNI the gateways subscribe to") + **D7** ("deterministic reverse mapping distributed to ALL gateways"), generalized to one typed channel.

## 3. Primitive B — Public-IP IPAM (`PublicIPPool`)

```yaml
kind: PublicIPPool            # cluster- or VPC-scoped
spec:
  ranges: ["203.0.113.0/24", "2001:db8:100::/48"]   # real, BGP-advertised public ranges
  purpose: nat | vip | floating | any
status:
  allocations: [{ip/block, owner: <NATGateway|LoadBalancer|VirtualIP ref>, ...}]
```

A central **IPAM controller** is the single allocator of public IPs; the deterministic port-block allocator (D5, already built) becomes IPAM's *sub-allocator* for NAT (many sources share one `nat_ip` via disjoint port-blocks). Then:
- `NATGateway.Spec.PublicIPs` (hand-typed) → `Spec.poolRef` (IPAM assigns the `nat_ip`s). The existing `Status.Allocations` stays.
- `LoadBalancer` / `VirtualIP` get their VIP from the same IPAM (`Status.vip`), so NAT/VIP/floating never collide (fixing the T4-class collision *by construction*, not by convention).
- **Overlay IPAM** (separate, lower priority): optionally allocate NIC overlay IPs from a VPC subnet pool instead of user-specified — reuses the same controller pattern. Underlay `/128`s already auto-allocate (`UnderlayIpam`); no change.

**Why one authority:** NAT IPs, VIPs, and floating IPs are drawn from the *same scarce, BGP-advertised* ranges; independent hand-typing is how you get overlaps and un-advertised addresses. IPAM also produces the exact prefix set the edge/VyOS must **BGP-announce to the WAN** (close the loop: IPAM allocation → PublicPrefix record → edge announces `/32` to the WAN).

## 4. External L4 LB — how it composes

LB ingress is its own build arc (new verifier-sensitive edge eBPF + the LB control-plane stack — the `LoadBalancer` CRD is still an empty scaffold), but it **reuses both primitives** and the same VyOS edge:

- **Control plane:** flesh out `LoadBalancer{poolRef, ports, backendSelector}`; a controller builds the Maglev backend table from the selector + IPAM-assigns the VIP; announces an `LB_VIP` PublicPrefix (VIP `/32`, attributes = Maglev table id + backend underlays). The edge learns it (subscribed to PublicVNI) and its VyOS BGP-advertises the VIP `/32` to the WAN (ECMP across edges).
- **Datapath (new eBPF):** a WAN-ingress VIP path (sibling to `wan_rx`): a *plain* IPv4/IPv6 packet from the internet to a registered VIP → Maglev-select a backend (reuse `lb.rs` `lb_select_forward`'s selection, but from a plain-packet entry, not the encapped `uplink_rx` entry) → encap to the backend's underlay. **DSR return:** the backend hypervisor reverse-SNATs source→VIP so replies bypass the edge (spec D3) — new per-backend VIP-SNAT, distributed like egress NAT.
- **Drain-safe:** Maglev is a pure function of the VIP+5-tuple + the (distributed) backend set, so any edge picks the same backend — the same statelessness that makes egress drain-safe (spec D2/D6).

So the edge becomes: **`uplink_rx`** (egress decap) + **`wan_rx`** (NAT return) + **`vip_rx`** (LB ingress) + VyOS (BGP/forward), all fed by the PublicVNI.

## 5. Edge identity — the concrete near-term fix (unblocks the e2e's edge agents)

Minimal slice, independent of the full PublicVNI/IPAM build, that makes the egress e2e fully control-plane-driven:
1. Give each edge a **unique loopback `/128`** (e.g. `fd00:db8:0:9f::1/2`) on a second dummy, BGP-announced, distinct from the anycast `fd00:db8:0:9::e`. The edge agent binds control traffic to it (`--underlay <anycast>` for datapath identity stays; add a control-plane source or a route so replies return to the *specific* edge).
2. Run the edge agents (`--node-id edge{1,2}`, brokered to k01 like k02) so `applyNat` learns NEIGHBOR_NAT and `DesiredExternalRoutes` (A3) announces the external default — replacing the `grpcurl` steps in `test/egress-fabric-e2e.sh`.
3. Then generalize (1) into the `EDGE_UNDERLAY` PublicPrefix record so sources learn the anycast nexthop and `NATGateway.Spec.EdgeUnderlay` becomes derived.

## 6. Sequencing (proposed)

1. **Edge identity slice (§5)** — small; unblocks control-plane-driven egress + removes the e2e's grpcurl. *(next)*
2. **PublicVNI record type (§2)** — the typed channel; migrate the NatBlock stream onto it; add `EDGE_UNDERLAY`.
3. **PublicIPPool IPAM (§3)** — pool CRD + controller; `NATGateway`/`LoadBalancer` take `poolRef`; wire IPAM→PublicPrefix→edge BGP announce.
4. **External LB arc (§4)** — `vip_rx` eBPF + DSR + the LB controller/agent, on top of 2–3.
5. **NAT64 interop e2e (Phase D)** and the deferred multi-homing egress ECMP round it out.

## 7. Non-goals / open questions
- NAT66 (no v6 egress SNAT) — still out of scope.
- Overlay-IP IPAM is optional (user-specified works); low priority vs public-IP IPAM.
- PublicVNI = reserved `VNI 0` vs a configured value — decide when building §2 (dpservice uses `ALL_VNI=0` for the VNI-agnostic lookups; the `neighbor_nat_lookup_any` we shipped already keys VNI-agnostically, which fits `VNI 0`).
- DSR-in-IPv6-overlay mechanics remain the highest-risk LB spike (spec §10).
