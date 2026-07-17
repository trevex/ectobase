# LoadBalancer Wiring (Subproject B) — Design

**Status:** Approved for planning
**Date:** 2026-07-15
**Depends on:** Subproject A (CompiledNIC firewall pipeline), PublicPrefix typed channel (`PUBLIC_KIND_LB_VIP` reserved), edge `vip_rx`/`wan_rx` maglev datapath (already committed).

## 1. Goal

Wire the `LoadBalancer` CRD end-to-end so LB traffic actually reaches backends, with the
firewall unchanged. LB membership is **forwarding data only** — it never grants firewall
permission. A packet delivered via an LB is allowed **iff** an explicit `NetworkPolicy` admits
it (e.g. ingress `port 443 via ::/0`). The datapath (maglev, `lb_select_forward`, DSR reforward)
already exists; this subproject is control-plane wiring plus one small datapath parameterization.

## 2. Core invariants (do not violate)

- **The firewall pipeline from Subproject A is untouched.** `Compile()`'s firewall/NAT paths are
  byte-for-byte unchanged; `CompiledLB` carries **no** firewall fields. LB membership generates
  **no** firewall rule. Permission comes solely from `NetworkPolicy`.
- **The only control-plane IPAM is the VIP.** Every underlay `/128` (NIC backend address, edge
  underlay) is node-local — allocated by the per-host agent from the node's `/64` and announced
  via routebus. No underlay address appears in any CRD.
- **The dataplane is always-on deny-by-default** (from Subproject A). LB delivery is subject to
  the destination NIC's ingress firewall like any other inbound flow.
- **VIPs are v4 or v6.** Nothing assumes IPv4. All prefixes use the existing `hostPrefix(ip)`
  helper (→ `/32` or `/128` by family); the dataplane already has `lb_select_forward_v6` and
  `create_lb`'s `LbIpBytes::Ipv4|Ipv6`.

## 3. Data model

### 3.1 LoadBalancer CRD (flesh out the stub)

```go
type LoadBalancerSpec struct {
    // VIP is the virtual IP (v4 or v6). Control-plane IPAM allocates it; it is the LB's identity.
    VIP string `json:"vip"`
    // Ports are the LB service (port, proto) tuples.
    Ports []LoadBalancerPort `json:"ports"`
    // Exactly one of TargetSelector / TargetRefs selects the backend NetworkInterfaces.
    // +optional
    TargetSelector *metav1.LabelSelector `json:"targetSelector,omitempty"`
    // +optional
    TargetRefs []LocalObjectReference `json:"targetRefs,omitempty"`
}

type LoadBalancerPort struct {
    Port  int32  `json:"port"`
    Proto string `json:"proto"` // "TCP" | "UDP"
}

type LoadBalancerStatus struct {
    // State is the lifecycle state (Pending | Ready).
    // +optional
    State string `json:"state,omitempty"`
}
```

Note: the VIP is provided in `Spec` for this slice (IPAM allocation of the VIP is an orthogonal
concern handled where NIC/NAT IPs are allocated; a follow-up can move VIP allocation to a
controller and echo it in status). No relay/underlay field exists on the LB — that was rejected
during design as node-local, not CP state.

### 3.2 CompiledNIC changes

```go
// on CompiledNICSpec:
//   LB []CompiledLB `json:"lb,omitempty"`   // ADD
//   UnderlayRoute string                    // REMOVE (dead: no consumer reads Spec.UnderlayRoute)

type CompiledLB struct {
    VIP   string          `json:"vip"`   // v4 or v6
    Ports []CompiledLBPort `json:"ports"`
}
type CompiledLBPort struct {
    Port  int32  `json:"port"`
    Proto string `json:"proto"`
}
```

`CompiledLB` is pure membership: "this NIC backs VIP X on these ports." Everything else is
agent-derived — the backend `/128` from `nic.Status.UnderlayRoute` (the agent already knows it),
the edge LB-VNI from a flag, `id` from the VIP.

**Remove `CompiledNICSpec.UnderlayRoute`.** reconcile.go:86 reads `nic.Status.UnderlayRoute`
(the NetworkInterface status), never `CompiledNIC.Spec.UnderlayRoute`; the compiler copies it in
(compilednic.go:53) but nothing reads it back. Dead field from Subproject A. The sim serde mirror
(`compilednic.rs`) drops the field via serde default.

## 4. Distribution

Split by "who knows it": E/W reuses plain routes; N/S uses the LB_VIP public channel to feed the
edge's maglev.

### 4.1 East-West (guest → VIP, same fabric) — anycast route, no new mechanism

The agent already announces each NIC IP as `Route{vni, prefix: hostPrefix(ip), nexthop: nic /128}`
(reconcile.go:90-97). LB backing is identical: for each `CompiledLB` on a local NIC, the agent
**additionally** announces `Route{vni, prefix: hostPrefix(VIP), nexthop: nic underlay, External:false}`.

Multiple backend NICs announcing the same VIP prefix → the fabric ECMPs across them (the dataplane
already does per-flow WCMP). A guest resolves the VIP → encaps to a backend `/128` → that node's
`lb_select_forward` returns None (the LB is not registered there) → base path → **destination NIC
ingress firewall** → deliver to the backend tap. DSR: inner dst stays the VIP; the guest owns/answers
it. **No maglev, no relay address, no LB-VNI on nodes for E/W.** Selection is per-flow-stable ECMP.

Cross-VPC E/W (a guest in VPC-A reaching a VIP backed by NICs in VPC-B) works when the VIP route is
present in the consumer VPC's VNI; scoping the VIP route to consumer VNIs beyond the backends' own
VNI is deferred (out of scope for this slice — same-VNI E/W and N/S cover the primary cases).

### 4.2 North-South (WAN → VIP) — LB_VIP PublicPrefix + edge maglev

Unchanged datapath: the edge runs maglev in `wan_rx` and encaps to the selected backend `/128`.
Wiring:

- **Backend agent announces** one `LB_VIP` PublicPrefix per VIP:
  `{kind: PUBLIC_KIND_LB_VIP, prefix: hostPrefix(VIP), owner_underlay: nic /128, vni: 0}`. The
  backend agent does **not** know the edge LB-VNI (an edge-only flag) and `AddLbBackend` does not
  need a VNI, so the record's `vni` is unset (0); the edge supplies its LB-VNI at `AddLbVip` time.
- **Edge `applyPublic` LB_VIP case** (today `default: not yet handled`): diff-based
  `AddLbBackend(VIP, owner_underlay)` / `DelLbBackend`.
- **Edge `AddLbVip`/`DelLbVip`** driven by a `LoadBalancer` cache lister keyed by VIP:
  `AddLbVip(id=VIP, vni=edgeLBVni, relay=edge underlay, ports)`. Ports/proto come from the
  `LoadBalancer` cache read (a cached informer read, not an apiserver round-trip).
- **Edge announces the VIP to WAN via BGP** (existing edge announcement path).

### 4.3 Datapath change (minimal)

Under model A no node ever registers an LB (E/W is a plain anycast route), so there is **no overlay
"LB VNI" to configure** — the edge keeps `vni=0` as the WAN sentinel, which `wan_rx` already uses. No
eBPF change and no edge LB-VNI flag are needed. The **only** datapath change is in `create_lb`: it
must **skip the `UNDERLAY[lb_underlay]` write when `vni==0`**. The edge passes its own anycast
underlay as `lb_underlay`; `wan_rx` never resolves it (it maglev-selects from a raw WAN frame), but
`attach_edge` already registered `UNDERLAY[edge_underlay] = LOCAL_DELIVER` for fabric→WAN egress, so
an unconditional write would clobber it. Guarding the write on `vni!=0` leaves the overlay relay path
(if ever used) intact while making the edge registration safe.

## 5. Compiler + controller

### 5.1 Compile (pure)

`Compile(nic, policies, lbs)` gains an `lbs []LoadBalancer` argument (a **bounded, pre-filtered**
set — the LBs relevant to this NIC). For each `lb`, if `lb.TargetSelector` matches the NIC's labels
or `lb.TargetRefs` names it, append `CompiledLB{VIP: lb.Spec.VIP, Ports: …}`. Firewall/NAT
compilation is unchanged. `Compile` performs no I/O.

### 5.2 Reconciler — fine-grained, change-gated

- **Watches with mapfuncs + predicates** (mirror the existing `nicsForPolicy` wiring):
  - `For(&NetworkInterface{})`, `Owns(&CompiledNIC{})` — existing.
  - `Watches(&NetworkPolicy{}, EnqueueRequestsFromMapFunc(r.nicsForPolicy), WithPredicates(pred))` — existing, add predicate.
  - `Watches(&LoadBalancer{}, EnqueueRequestsFromMapFunc(r.nicsForLB), WithPredicates(pred))` — NEW.
    `nicsForLB` resolves the changed LB's `TargetSelector`/`TargetRefs` to the specific NIC
    reconcile.Requests. One LB change requeues only its targets.
  - Predicate: `GenerationChangedPredicate` (or field-scoped) so status-only / no-op updates do not
    enqueue.
- **`Reconcile(nic)`** gathers only the LBs relevant to this NIC via a cached list (a field index on
  target refs and/or a label-matched cache list), not an unbounded fetch, and passes that bounded
  set to `Compile`.
- **Write only on actual diff** — compute desired `Spec`, and `Update` only when
  `!equality.Semantic.DeepEqual(existing.Spec, desired)`. Fixes compilednic.go:137-138's current
  unconditional `existing.Spec = compiled.Spec; Update()` (which writes and bumps resourceVersion on
  every reconcile). No-op reconciles cost one cached read and zero writes.

## 6. Agent reconcile

- **Route reconcile** (`Desired`): for each local CompiledNIC, emit the existing NIC-IP routes plus,
  per `CompiledLB`, `Route{vni, prefix: hostPrefix(VIP), nexthop: nic underlay, External:false}`.
- **Public reconcile** (`DesiredPublic`): for each local CompiledNIC's `CompiledLB`, emit
  `PublicPrefix{Kind: LB_VIP, Prefix: hostPrefix(VIP), OwnerUnderlay: nic underlay, Vni: 0}` (the
  edge LB-VNI is not the backend agent's to know; the edge sets it at `AddLbVip`).
- **`applyPublic`** (edge): add the `LB_VIP` case → level-triggered, idempotent
  `AddLbBackend`/`DelLbBackend` diff against applied state (the dataplane rejects duplicate ids →
  skip-if-applied, same shape as the firewall reconcile). `AddLbVip`/`DelLbVip` from the LoadBalancer
  cache keyed by VIP.

## 7. Testing

- **Sim (`flowplane-sim`):**
  - Extend the Fabric LB scenario to prove **E/W ECMP-direct**: guest → VIP → backend base-deliver;
    with no NetworkPolicy the ingress firewall drops it (deny-by-default), with `port 443 via ::/0`
    (or `/0`) it is delivered — proving LB needs explicit FW.
  - Prove **N/S**: edge `wan_rx` maglev → backend deliver (extend existing coverage; both v4 and v6
    VIP).
  - Add a `CompiledLB` case to the `compilednic.rs` serde mirror (and drop `underlayRoute` from the
    fixture).
- **Go unit:**
  - Compiler: `TargetSelector` and `TargetRefs` resolution → `CompiledLB`; unrelated NIC gets none.
  - Reconciler: diff-before-write (no Update when unchanged); `nicsForLB` mapfunc requeues only
    targets.
  - Agent: route reconcile emits the VIP anycast route (v4 and v6); `DesiredPublic` emits LB_VIP;
    `applyPublic` LB_VIP → `AddLbBackend` diff (fake dataplane, models ALREADY_EXISTS).
- **Conformance:** not extended. An E/W LB is inherently multi-node (anycast across backend nodes),
  which the single-instance conformance harness cannot express; the `flowplane-sim` Fabric is the
  correct multi-node coverage. The firewall-gating property (LB not exempt) is proven there.

## 8. Non-goals / deferred

- VIP IPAM allocation by a controller (VIP is `Spec`-provided this slice).
- Cross-VPC E/W VIP route scoping beyond the backends' own VNI.
- Relay/maglev for E/W (explicitly rejected in favor of ECMP-direct).
- LB health checking / backend readiness gating.
- v6 firewall completeness (a pre-existing separate gap, unchanged here).

## 9. File map (for the plan)

- `api/v1alpha1/loadbalancer_types.go` — flesh out Spec/Status.
- `api/v1alpha1/compilednic_types.go` — add `LB []CompiledLB`; remove `UnderlayRoute`.
- `netplane/controllers/compilednic.go` — `Compile(…, lbs)`, `nicsForLB`, LoadBalancer watch +
  predicates, diff-before-write.
- `netplane/agent/reconcile.go` — VIP anycast route emission.
- `netplane/agent/public.go` — `DesiredPublic` LB_VIP emission; `applyPublic` LB_VIP case.
- `netplane/agent/bus.go` — `AddLbBackend`/`DelLbBackend`/`AddLbVip`/`DelLbVip` on the Dataplane
  interface + adapter (proto RPCs already exist).
- `flowplane/src/main.rs` / control plane — edge LB-VNI flag; `wan_rx`/`create_lb` vni parameterization.
- `flowplane-sim/src/compilednic.rs` + LB scenario tests.
- `test/conformance/` — E/W LB test.
