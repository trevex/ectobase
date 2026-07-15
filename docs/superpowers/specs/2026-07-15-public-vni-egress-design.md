# Public-VNI Egress (control-plane route-import) — Design

**Status:** Approved for planning
**Date:** 2026-07-15
**Depends on:** the shipped N/S egress (NATGateway → `DesiredExternalRoutes`), the LoadBalancer wiring + DSR fix (this session), the PublicPrefix/EDGE_UNDERLAY channel.
**Supersedes:** the per-tenant-VNI `/0` origination — both `DesiredExternalRoutes`'s per-NATGateway announce and the LB DSR `/0`-per-LB-VNI announce (this session's `natreconcile.go` change) — with one import mechanism.

## 1. Goal

Stop the WAN edge from enumerating which tenant VNIs need egress. Instead the edge announces the default route **once** into a **public VNI**, and any node that needs egress **imports** it into its own tenant VNI. This is the metalnet/dpservice model (verified: peering + PublicVNI are control-plane route-import, not a datapath VNI-rewrite) and it is the reusable foundation for VPC peering.

## 2. Core model (validated against metalnet/dpservice)

- **Cross-VNI is control-plane route-import.** A node installs a route into its *own* VNI's table whose nexthop is the target's underlay `/128`. On the wire it is plain IP-in-IPv6 with **no VNI tag**; the receiver derives the delivery VNI from `UNDERLAY[outer_dst]` (dpservice `ipip_decap_node.c`: `dp_get_vnf(outer_dst) → {vni,port}`). So `RouteValue.nexthop_vni` stays **control-plane metadata**; the datapath is unchanged.
- **The public VNI is a control-plane aggregation/subscription VNI, not a wire VNI** (dpservice: "the public VNI has no corresponding VNI"). It carries public routes (the default; later VIP/NAT records) that tenant nodes import.
- **Public VNI number = `0`** (reserved). Matches dpservice `ALL_VNI=0` and our existing VNI-agnostic `neighbor_nat_lookup_any`. A tenant node hosts no VNI-0 guests, so learned VNI-0 routes are *recorded, not installed into a VNI-0 dataplane table*.
- **Firewall is orthogonal.** The NIC's ingress/egress NetworkPolicy applies regardless of import (unchanged).

## 3. Architecture

```
edge agent (edgeLoopback set)                every agent (always)
  originate into PUBLIC_VNI(0):                subscribe to PUBLIC_VNI(0)
    0.0.0.0/0      -> edge_underlay   ───────►  learn -> learnedPublic{prefix: nexthop}
    64:ff9b::/96   -> edge_underlay              (recorded, NOT AddRoute'd into vni 0)
    ::/0           -> edge_underlay                     │
                                                        ▼
                                          import reconcile (per local NIC needing egress):
                                            AddRoute(nic.VNI, <learned prefix>, edge_underlay, external=true)
```

- **Edge origination** is tenant-agnostic (no NATGateway/LoadBalancer list).
- **Import** is decided at the tenant node from local facts (does this NIC's VPC have a NATGateway / is this NIC an LB backend), and installs the learned default into that NIC's VNI.

## 4. Components

### 4.1 Edge origination — `DesiredExternalRoutes` (simplified)

`netplane/agent/natreconcile.go`: when `edgeLoopback != ""`, return the external routes with **`Vni: PUBLIC_VNI` (0)** and nexthop = the edge's own underlay:
```
[]ExternalRoute{
  {Vni: 0, Prefix: "0.0.0.0/0",     Nexthop: underlay, External: true},
  {Vni: 0, Prefix: "64:ff9b::/96",  Nexthop: underlay, External: true},
  {Vni: 0, Prefix: "::/0",          Nexthop: underlay, External: true},
}
```
Remove the NATGateway enumeration AND the LoadBalancer enumeration added this session. The edge no longer reads NATGateway/LoadBalancer to decide VNIs — it just owns the public defaults. (`LoadBalancer.Spec.VPCRef` and the DSR test added this session are removed with it.)

### 4.2 Subscription — always include the public VNI

`netplane/agent/reconcile.go` `Desired`: add `PUBLIC_VNI (0)` to `subs` unconditionally (every node subscribes to the public VNI to learn the defaults), alongside the hosted VNIs.

### 4.3 Egress VNIs — computed per reconcile from local facts

`netplane/agent/reconcile.go` `Desired` computes an `egressVNIs []uint32` set: the VNIs of local NICs that need egress —
- the NIC's VPC has a `NATGateway` (list NATGateways, resolve VPCRef→VNI), OR
- the NIC is an LB backend (`CompiledNIC.Spec.LB` non-empty).

Deduped. Passed to `bus.Run` alongside `subs`/`announce` (like the other desired sets). Recomputed each loop iteration, so adding/removing a NATGateway or LB backing converges on the next reconnect.

### 4.4 Import — reactive, when the public default is learned

The import must react to routes learned **during** the session (unlike the k8s-only `ReconcileFirewall`, which runs pre-session). So it lives in the `Bus`, keyed by the pre-computed `egressVNIs`:

`netplane/agent/bus.go` `apply(RouteUpdate)`: when `ru.Vni == PUBLIC_VNI (0)`:
- record into `learnedPublic map[string]string` (prefix→nexthop) for reconnect idempotency, and
- **for each `vni` in `egressVNIs`**, on ADD `dp.AddRoute(vni, ru.Prefix, nexthop, external=true)`; on WITHDRAW `dp.WithdrawRoute(vni, ru.Prefix)`. Do **not** `AddRoute(vni:0,…)` — a tenant node has no VNI-0 table.

All other VNIs keep the existing `AddRoute`/`WithdrawRoute` behavior. On reconnect the reflector replays the public-VNI routes, so the import re-installs idempotently. NAT source SNAT (`AddNatSource`) is unchanged; the imported `/0` (External:true) is what SNAT'd traffic follows, and LB-backend VIP replies miss SNAT → stay public.

### 4.5 Wiring

`netplane/cmd/agent/main.go`: `Desired` now also returns `egressVNIs`; pass it into `bus.Run` so the Bus's `apply` can import on learning the public default. No separate pre-session import reconcile (it would run before the routes are learned).

## 5. Peering foundation (design-for, do NOT build here)

The import primitive is *"subscribe to VNI X, install X's (allow-listed) prefixes into my table with X's `/128` nexthop."* Keep `ReconcileImport` shaped so VPC peering reuses it:
- Public VNI = the special case "every egress-needing node imports the public defaults."
- VPC peering (future) = "a network with `PeeredIDs`/`PeeredPrefixes` imports the peer VNI's NIC prefixes (allow-list gated) with the peer's `/128` nexthop."
Same subscribe→learn→import path; only the *source VNI* and *prefix set* differ. No datapath work for either.

## 6. Non-goals

- Public-IP IPAM (`PublicIPPool`) — separate slice.
- Floating IPs — separate feature.
- Datapath `nexthop_vni` recursion — explicitly NOT needed (control-plane import; datapath unchanged).
- Removing `RouteValue.nexthop_vni` — **intentionally kept** as the cross-VNI metadata slot (== metalnet `NextHop.targetVNI`) for future VPC peering. It is unused by *our* datapath (delivery VNI is derived from the underlay /128), but dropping it churns the eBPF map layout + BPF anchors + sim + proto for a 4-byte field we'd re-add for peering; not worth it, and out of scope for this pure-control-plane slice.
- Making the public VNI a real wire VNI — it is control-plane only.
- VPC peering implementation — only shaped for.

## 7. Testing

Datapath is unchanged → existing sim/anchor coverage holds; the live clab run already proved `/0`-in-tenant-VNI egresses to the edge.

New Go unit tests (`netplane/agent`):
- **Edge origination:** `DesiredExternalRoutes` (edge) returns the defaults with `Vni == 0` and nexthop = edge underlay; and returns nothing NATGateway/LoadBalancer-specific.
- **Learn:** `apply(RouteUpdate{Vni:0, 0.0.0.0/0, nh})` records into `learnedPublic` and does NOT call `dp.AddRoute`; a non-zero VNI still calls `AddRoute`.
- **Import:** a node with a NATGateway-VPC NIC imports `/0`(+NAT64) into that NIC's VNI (`AddRoute(vni, …, external=true)`); a node with an LB-backend NIC imports `/0` into its VNI; a node with neither imports nothing; withdrawal removes the import.
- **Subscription:** `Desired` includes VNI 0 in `subs`.

## 8. File map (for the plan)

- `netplane/agent/natreconcile.go` — `DesiredExternalRoutes` → public-VNI-only origination (Vni 0); drop NATGateway+LoadBalancer enumeration.
- `api/v1alpha1/loadbalancer_types.go` (+ CRD + deepcopy) — revert `LoadBalancer.Spec.VPCRef` added this session (superseded by import); remove `TestDesiredExternalRoutesLoadBalancerDSR`.
- `netplane/agent/reconcile.go` — subscribe to VNI 0; compute + return `egressVNIs`.
- `netplane/agent/bus.go` — `learnedPublic` + `LearnedPublic()`; `egressVNIs` param on `Run`; special-case `apply` for VNI 0 (record + import into `egressVNIs`).
- `netplane/cmd/agent/main.go` — thread `egressVNIs` from `Desired` into `bus.Run`.
- Tests: `netplane/agent/{external_route_test.go, bus_test.go, reconcile_test.go}` (egress-VNIs compute, learn+import in apply, subscription includes 0).
- A `PublicVNI` const (0) in one place (agent).
