# VPC Peering — Design

**Status:** Approved (design); pending spec review
**Date:** 2026-07-18

## Summary

VPC peering lets guests in two different VPCs (overlay networks, each identified by a VNI)
reach each other under policy. It is a **pure control-plane feature**: no eBPF / `flowplane-core`
datapath change, and no routebus protocol change. It generalizes the existing Public-VNI-egress
import primitive — *"subscribe to VNI X, install its allow-listed prefixes into my table with X's
nexthop"* — from the single well-known VNI 0 to arbitrary peer VNIs.

Reachability is established by importing the peer VPC's overlay routes into the local VPC's route
table (keyed by the local VNI); the datapath's underlay-derived delivery does the rest. Security is
**orthogonal**: peering grants reachability only — the deny-by-default ingress firewall still drops
cross-VPC traffic until a `NetworkPolicy` explicitly allows the peer's CIDRs.

## Current state (what peering builds on)

- **VPC / VNI model** (`api/v1alpha1/vpc_types.go`): a `VPC` is an isolation domain keyed by a VNI
  (pinned via `spec.vni` or centrally allocated → `status.vni`). A `NetworkInterface` references its
  VPC (`spec.vpcRef`) and resolves to a VNI.
- **`VPCPeering` CRD** (`api/v1alpha1/vpcpeering_types.go`): exists but is a **scaffold-only** empty
  struct today (placeholder for the Network API §3.3). This design fleshes it out.
- **routebus** (`api/proto/routebus/v1/routebus.proto`, `netplane/agent/{reconcile,bus}.go`): a
  custom pub/sub, keyed by VNI, that distributes overlay reachability. Agents `subscribe(vni)` and
  learn `RouteUpdate{vni, prefix, nexthops, op, external}`. **Public-VNI egress already imports
  learned routes for a well-known VNI (0) into local egress VNIs' tables** — the exact primitive
  peering generalizes. No protocol change is needed.
- **`CompiledNIC`** (`api/v1alpha1/compilednic_types.go`): the lowered, node-local, per-NIC config
  bundle — *the single CRD the node agent reads*. It carries VNI, firewall (resolved from
  NetworkPolicy), NAT, and LB membership. It deliberately **excludes** anything routebus learns
  dynamically. Precedent: `CompiledLB` is a *"pure forwarding membership — grants NO firewall
  permission (that comes solely from NetworkPolicy)."* Peering follows that precedent exactly.
- **Datapath VNI isolation** (`flowplane-core/src/egress.rs` `route4`/`route6`): routes are looked up
  keyed by `(vni, dst)`; a route under VNI-B is invisible to a lookup under VNI-A (proven by
  `flowplane-sim/src/vni_test.rs`). Delivery VNI is derived from the underlay `/128` at the receiver
  (`UNDERLAY[outer_dst]`), **not** from any VNI carried in the packet — so importing a route under
  VNI-A that points at a VNI-B guest's underlay Just Works, with no datapath change.

## Architecture

**Central cluster is authoritative and compiles NICs.** Peering is authored/validated centrally and
compiled into `CompiledNIC` (as *policy*); dynamic reachability continues to flow through routebus.
The node agent reads one CRD (`CompiledNIC`) plus the routebus feed.

Pieces:
1. **`VPCPeering` CRD** — mutual-consent, one-directional objects (a pair forms a peering), each
   declaring what its side exposes.
2. **Central `VPCPeering` controller** — validates mutual consent + well-formed prefixes, resolves
   each side's peer VNI + `exposedPrefixes`, and stamps peer-import directives into the affected
   `CompiledNIC`s.
3. **Node agent** — from `CompiledNIC`, subscribes to peer VNIs on routebus and imports their routes
   (filtered to the peer's `exposedPrefixes`) into the local VNI's route table, with **local routes
   taking precedence** over imports.
4. **routebus + datapath** — unchanged.

### Design decision: `exposedPrefixes` enforced importer-side

Each side's `exposedPrefixes` (its declaration of what it offers) is carried *centrally* into the
peer's `CompiledNIC`, and the peer's agent drops any imported route outside that list. The
alternative — advertiser-side filtering in routebus — would hide topology better but requires a
routebus protocol change for marginal benefit. **Chosen: importer-side** (zero routebus change;
central is the trust anchor regardless).

## §1 — The `VPCPeering` CRD

One-directional objects; a **pair** (`A→B` + `B→A`) forms a mutual-consent peering.

```go
type VPCPeeringSpec struct {
    // VPCRef is this side's VPC (same namespace).
    VPCRef LocalObjectReference `json:"vpcRef"`
    // PeerVPCRef references the other VPC (namespace + name; may be another tenant namespace,
    // since peering is central-authored).
    PeerVPCRef ObjectReference `json:"peerVpcRef"`
    // ExposedPrefixes is the CIDR allow-list THIS side offers to the peer: only local routes
    // within these CIDRs become reachable to peerVPC. Empty = expose nothing (fail-closed).
    // Reachability scope only — never a firewall grant.
    // +optional
    ExposedPrefixes []string `json:"exposedPrefixes,omitempty"`
}

type VPCPeeringStatus struct {
    // State: Pending (awaiting the reciprocal peering) | Ready (both sides consent) |
    // Invalid (validation failed).
    // +optional
    State string `json:"state,omitempty"`
    // Conditions carry the reason (e.g. AwaitingReciprocal, MalformedPrefix).
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

Semantics:
- **Mutual consent:** `A→B` becomes `Ready` only when the reciprocal `B→A` also exists (and is itself
  consistent). Either side deleting its object tears the peering down (routes withdrawn).
- **`exposedPrefixes` is per-side and fail-closed:** an empty list exposes nothing. It controls
  reachability scope / route-table size / topology visibility — it is *never* a firewall grant.
- **Cross-namespace `peerVpcRef`** is allowed (central sees all tenants).

## §2 — Central compiler: `VPCPeering` → `CompiledNIC`

A new central controller watches `VPCPeering` + `VPC` (+ `CompiledNIC` ownership). On a `Ready` pair
it stamps a reachability directive into **every `CompiledNIC` of each side's VPC** (mirroring how
`CompiledLB` rides on `CompiledNIC`):

```go
// added to CompiledNICSpec:
// PeerImports lists peer VPCs whose routes this NIC imports (reachability only — grants NO
// firewall permission; that comes solely from NetworkPolicy). Populated from Ready VPCPeerings
// involving this NIC's VPC.
// +optional
PeerImports []CompiledPeerImport `json:"peerImports,omitempty"`

type CompiledPeerImport struct {
    // PeerVNI is the peer VPC's VNI to subscribe to on routebus.
    PeerVNI int32 `json:"peerVni"`
    // ImportPrefixes is the PEER's exposedPrefixes: only peer routes within these CIDRs are
    // imported (filter applied importer-side).
    ImportPrefixes []string `json:"importPrefixes"`
}
```

- For VPC-B's NICs: `PeerImports += {peerVni: A.vni, importPrefixes: (A→B).exposedPrefixes}`.
  Symmetrically for VPC-A's NICs using `(B→A).exposedPrefixes`.
- Same-VPC NICs receive identical directives; the agent dedups by VNI.
- **Validation is minimal:** the reciprocal exists (consent) and prefixes are well-formed CIDRs. There
  is **no overlap rejection** — overlapping guest ranges are permitted and resolved at the agent by
  local precedence (§3). Malformed input → `State: Invalid` with a condition; no directive stamped.
- Directives are removed when the peering leaves `Ready` (reciprocal deleted, or the peering object
  deleted), which drives the agent to withdraw the imported routes.

## §3 — Node agent: subscribe, import, precedence

Generalizes the existing Public-VNI import path in `netplane/agent/bus.go`:

1. **Aggregate:** union `PeerImports` across all local `CompiledNIC`s → `(localVNI → [{peerVNI,
   importPrefixes}])`.
2. **Subscribe:** add each `peerVNI` to the routebus subscription set (alongside local VNIs +
   PublicVNI). Unsubscribe when no remaining directive needs it.
3. **Import on `RouteUpdate` for a `peerVNI`:** for each learned peer route `(prefix, nexthop)`,
   install `AddRoute(localVNI, prefix, nexthop, external=false)` **iff** `prefix` is within
   `importPrefixes` **and** no *own-origin* route already holds that exact `(localVNI, prefix)`.
4. **Local precedence (the overlap rule):** every route in a VNI table is tagged by **origin** —
   *own* (a locally-hosted guest, or a routebus route learned on that same VNI) vs *imported* (learned
   on a peer VNI). Invariants:
   - an imported route never overwrites an own route for the same prefix;
   - when an own route appears for a prefix currently held by an import, the own route evicts the
     import;
   - LPM longest-prefix specificity handles different-length prefixes naturally — only exact-key
     collisions need the origin tie-break.
5. **Withdraw / prune:** peer-route withdraws and prune-on-`EndOfRIB` reuse the existing per-VNI
   `markInstalled` bookkeeping, now origin-aware. Removing a `PeerImport` unsubscribes + withdraws its
   imported routes.

No routebus protocol change, no datapath change.

## §4 — End-to-end data flow

1. Operator (or central) creates `VPCPeering A→B` + `B→A`, each with its `exposedPrefixes`.
2. The central controller marks both `Ready` and stamps `PeerImports` into every `CompiledNIC` of A
   and B; the sync pipeline pushes the updated CompiledNICs to nodes.
3. VPC-B's agent subscribes to VNI-A and imports A's exposed prefixes into VNI-B's `ROUTES` table
   (local precedence honored).
4. **Datapath (unchanged):** a VPC-B guest sends to an exposed A-address → `route4(vni_B, dst)` now
   *hits* the imported route → encap to the A-guest's underlay → A's node underlay-derives VNI-A →
   delivers to the A guest.
5. **Return path is symmetric** (A imports B's exposed prefixes) — but the destination NIC's
   deny-by-default ingress firewall drops it **until a `NetworkPolicy` allows the peer's CIDR.**
   Reachability without policy = no connectivity (the deliberate two-step).

## §5 — Testing

- **Go / netplane (primary — the new logic lives here):**
  - *Compiler:* a `VPCPeering` pair produces the correct `PeerImports` on both VPCs' CompiledNICs;
    `Pending` when the reciprocal is missing; `exposedPrefixes` carried through; teardown on delete;
    malformed prefixes → `Invalid`.
  - *Agent:* given `PeerImports` + a fake routebus feed → subscribes to the peer VNI, imports only
    prefixes within `importPrefixes`, and **enforces local precedence** (own route not overwritten;
    import evicted when an own route appears; import restored if the own route later withdraws). Uses
    the existing `recordingDP` fake.
- **Sim (`flowplane-sim`):** a focused test that a VNI-B `ROUTES` table containing an imported
  cross-VNI route *resolves + delivers* (contrast with `vni_test`'s isolation case where the same
  send `Pass`es), and that a local route shadows a same-prefix import. The datapath is unchanged, so
  this pins the route-table semantics peering relies on rather than new datapath behavior.
- **clab (privileged scenario):** two VPCs + a peering + a guest in each → cross-VPC ping works **only
  after** a `NetworkPolicy` allows the peer CIDR (proves reachability + the firewall two-step); plus
  an overlap case showing the local guest shadows the peer.

## Non-goals

- **No datapath / routebus-protocol change.** Peering is control-plane only.
- **No firewall coupling.** Peering never grants firewall permission; `NetworkPolicy` is the sole
  security gate (consistent with `CompiledLB`).
- **No IPAM unification / overlap rejection.** Overlap is allowed; own-VNI routes win.
- **No transitive peering.** `A↔B` and `B↔C` do not make `A↔C` reachable; each peering is an explicit
  mutual pair (peer-of-peer routes are not re-exported).
- **No aggregate-CIDR advertising change.** routebus keeps advertising per-guest host routes;
  `exposedPrefixes` filters them importer-side.

## Risks

- **Local-precedence bookkeeping correctness.** The own-vs-imported origin tag + eviction/restore
  transitions are the subtle part. Mitigated by dedicated agent unit tests covering the collision
  transitions (own-then-import, import-then-own, own-withdraw-restores-import).
- **Route-table growth under broad `exposedPrefixes`.** A VPC exposing large ranges to many peers
  multiplies imported routes per node. `exposedPrefixes` (fail-closed) is the operator's lever;
  document the scale implication. Not bounded in code in v1.
- **Silent no-connectivity if the operator forgets the `NetworkPolicy`.** The reachability/policy
  two-step is deliberate but is a footgun; surface it via `VPCPeering` status/events documenting that
  policy is still required, and cover it explicitly in the clab test.
- **Consent races** (one side created before the other) are expected and handled by the `Pending`
  state; the controller must be level-triggered and converge when the reciprocal appears.

## Coverage / lineage

Verified against the in-repo prior art: the Public-VNI-egress design (`docs/superpowers/specs/
2026-07-15-public-vni-egress-design.md` §5) explicitly frames its import primitive as the peering
building block, and `RouteValue` already reserves `nexthop_vni` as control-plane metadata for
peering. This design is the generalization of that primitive from VNI 0 to arbitrary peer VNIs, and
aligns with metalnet's control-plane route-import model (delivery VNI underlay-derived, not
packet-carried).
