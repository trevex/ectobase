# Compiled NIC + Synthetic Datapath Testing — Design

**Status:** Draft (brainstorm output) — design agreed 2026-07-15.
**Date:** 2026-07-15
**Parent context:** replaces the endless clab/netns debug loop with a lightweight, in-process test path.
**Related:**
- `docs/superpowers/specs/2026-07-02-network-api-design.md` (the high-level CRD set this compiles from)
- `docs/superpowers/specs/2026-07-14-north-south-edge-identity-lb-ipam.md` (the N-S edge datapath the skeleton exercises)
- Tiered-multicluster vision: the `CompiledNIC` is a concrete step toward the "central compiles CRDs → scheduled/compiled object → synced to pools" model.

---

## 1. Summary

Two pillars change how we test this stack:

1. **`CompiledNIC`** — a first-class, persisted **lowered object** that bundles *everything statically derivable* for one `NetworkInterface` (vni, overlay IPs, underlay `/128`, concrete firewall rules, NAT source block, LB membership, VIP DNAT, local routes) — and **nothing that routebus learns dynamically**. This makes control-plane behavior assertable: CRDs → `CompiledNIC` is a clean, testable lowering.

2. **Synthetic datapath harness** — an in-process, no-root, no-clab test path. The **real datapath code** is extracted into a `no_std` pure-core crate generic over a `Maps` trait and a `Pkt` trait. A native test harness crafts a packet, runs `wan_rx`/`uplink_rx`/… on it, and asserts the output bytes — feeding map state from the *same* `CompiledNIC`. A small `BPF_PROG_TEST_RUN` **fidelity anchor** asserts the native core stays byte-identical to the real compiled bytecode.

This spec delivers a **walking skeleton**: one North-South path end-to-end through the new machinery, proving the architecture. Feature breadth (NAT, LB, NAT64, DHCP, ARP/ND) fills in behind it in follow-ups.

## 2. Goals / Non-goals

**Goals**
- A `CompiledNIC` CRD + a minimal compiler controller producing it from the high-level CRDs.
- Extract the N-S datapath subset into `flowplane-core` behind `Maps`/`Pkt` traits, with the eBPF programs re-expressed as thin glue over the core (existing conformance suite stays green — regression guard).
- An `flowplane-sim` crate that runs the core natively and lets a test express: *external packet → edge encap → host decap → guest deliver*, asserting at each hop.
- One `BPF_PROG_TEST_RUN` anchor asserting native/bytecode byte-parity for that path.

**Non-goals (this spec)**
- Full datapath coverage (NAT/NAT64, LB/Maglev, DHCP, ARP/ND) — follow-ups.
- The full compiler (all selectors, all resources) — only what the slice needs.
- Replacing the netns/clab e2e — they remain until sim coverage supersedes them.
- Any routebus-learned state in `CompiledNIC` (by definition excluded).

## 3. Architecture

```
 CRDs (VPC, NIC, NetworkPolicy,        ┌─────────────────────────┐
 NATGateway, LoadBalancer, VirtualIP)  │  compiler controller     │  pillar 1
        │                              │  (pure fn + reconcile)   │
        ▼                              └───────────┬─────────────┘
   [ selectors resolved,                           │ writes
     underlay /128 allocated ]                     ▼
                                        ┌─────────────────────────┐
                                        │  CompiledNIC  (CRD)      │  ← the "lowered" object
                                        │  everything static;      │
                                        │  NOTHING routebus-learned│
                                        └─────┬──────────────┬─────┘
                            agent consumes ───┘              └─── sim harness consumes
                                        │                            │
                        gRPC → real dataplane maps      apply → native Maps (HashMap)
                                                                     │
                                          craft pkt → flowplane-core → pkt out   pillar 2
```

Three test seams fall out of this shape:
1. **CRDs → `CompiledNIC`** — the compiler is a pure function; assert with Go unit/envtest.
2. **`CompiledNIC` → gRPC call set / map writes** — the agent's lowering; assert independently.
3. **`CompiledNIC` → datapath behavior** — the sim harness; assert packet-in/packet-out.

## 4. Pillar 1 — the `CompiledNIC` object

New CRD kind **`CompiledNIC`** (API group `net.ectobase.dev/v1alpha1`), node-scoped by `spec.nodeName`. A **compiler controller** watches the high-level CRDs, resolves all label selectors, allocates/reads the underlay `/128`, and emits **one `CompiledNIC` per `NetworkInterface`**. The node agent watches `CompiledNIC`s for its own node and drives the dataplane gRPC from them.

### 4.1 What it bundles (statically derivable)

- **identity:** `nicRef`, `vni`, `nodeName`, `port { type, name }`
- **overlay IPs:** user-specified v4/v6 (`spec.ips` on the NIC)
- **underlay:** the allocated `/128` (`status.underlayRoute`)
- **firewall:** a concrete `FwRule` list — `NetworkPolicy` selectors already resolved to CIDRs/ports/directions
- **NAT:** the SNAT source block (`nat_ip` + port range) assigned from its `NATGateway`
- **LB:** whether this NIC is a VIP backend and/or hosts a local VIP definition
- **VIP:** the DNAT mapping if a `VirtualIP` currently targets it
- **routes:** its local overlay routes

### 4.2 What it explicitly excludes (routebus's job — learned dynamically)

- remote NIC underlay routes (other nodes' `/128`s)
- remote NAT neighbor entries
- edge-underlay discovery (`EDGE_UNDERLAY` via the PublicPrefix channel)
- off-node LB backends

This exclusion line **is** the pillar-1 boundary: `CompiledNIC` = "everything a node needs to program locally without talking to peers"; routebus = "everything learned from peers."

### 4.3 Shape (illustrative)

```yaml
kind: CompiledNIC
metadata: { name: web-0-nic0, labels: { node: nodeA } }
spec:
  nodeName: nodeA
  nicRef: { name: web-0-nic0 }
  vni: 100
  port: { type: tap, name: dtapvf_0 }
  overlayIPs: ["10.0.0.10", "2001:db8::10"]
  underlayRoute: "2001:db8:fefe::a1b2"
  firewall:
    ingress: [{ cidr: "10.0.0.0/24", proto: TCP, port: 443, action: Allow }]
    egress:  [{ cidr: "0.0.0.0/0", action: Allow }]
  nat:  { natIP: "203.0.113.5", portMin: 1024, portMax: 3071 }   # optional
  lb:   { backendOfVIPs: ["10.0.100.1"] }                        # optional
  vip:  { dnat: "10.0.200.1" }                                   # optional
  routes: [ ... ]                                                # local overlay routes
status: { state: Ready, generationApplied: 7 }
```

## 5. Pillar 2 — pure-core extraction + the harness

### 5.1 Crates

- **`flowplane-core`** *(new, `no_std`, natively testable)* — the extracted datapath functions, generic over `Maps` + `Pkt`. Depends on `flowplane-common` for the POD key/value types (already the shared home for `IfaceKey`, `RouteValue`, `CtKey`, `CtEntry`, `NatKey`, `FwRule`, …).
- **`flowplane-ebpf`** — depends on `flowplane-core`; provides the aya impls (`Maps` = wrappers over the existing `#[map]` statics in `maps.rs`; `Pkt` = over `ctx.data()/data_end()`). The `#[xdp]`/`#[classifier]` fns shrink to glue: build the impls, call core.
- **`flowplane-sim`** *(new, `std`, dev/test)* — native `Maps` (HashMaps + tiny LPM/LRU stand-ins), native `Pkt` (over a `Vec<u8>`), `SimNode`, `apply(&CompiledNIC)`, and packet crafting via `etherparse`.

### 5.2 The two traits

**`Maps`** — typed accessors, one method per logical map operation the core needs, e.g.:

```rust
pub trait Maps {
    fn config(&self) -> Config;
    fn local(&self) -> Local;
    fn iface_get(&self, k: &IfaceKey) -> Option<IfaceValue>;
    fn port_meta(&self, ifindex: u32) -> Option<PortMeta>;
    fn route6_lookup(&self, k: &RouteLpmData6) -> Option<RouteValue>;
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue>;
    fn fw_rule_get(&self, k: &FwRuleKey) -> Option<FwRule>;
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta>;
    fn fw_config(&self) -> u32;
    fn conntrack_get(&self, k: &CtKey) -> Option<CtEntry>;
    fn conntrack_insert(&mut self, k: CtKey, v: CtEntry);
    // …extended per-feature in follow-ups
}
```

Monomorphized — the eBPF impl is zero-cost wrappers over the globals; the native impl is `HashMap`-backed. Generics (not `dyn`) so eBPF stays verifier-friendly.

**`Pkt`** — bounds-checked byte access. **Deliberately a trait, not `&mut [u8]`**: eBPF requires raw-pointer + manual bounds checks to satisfy the verifier, so forcing a slice into the eBPF path would break it. The native impl wraps a `Vec<u8>`/slice.

```rust
pub trait Pkt {
    fn len(&self) -> usize;
    fn read<T: Pod>(&self, off: usize) -> Option<T>;
    fn slice(&self, off: usize, len: usize) -> Option<&[u8]>;
    fn write(&mut self, off: usize, bytes: &[u8]) -> bool;
    fn grow_head(&mut self, delta: usize) -> bool;   // encap headroom (xdp_adjust_head analog)
    fn shrink_head(&mut self, delta: usize) -> bool; // decap
}
```

`grow_head`/`shrink_head` model `bpf_xdp_adjust_head`; the native impl mutates the `Vec`, the eBPF impl calls the helper + re-derives bounds.

### 5.3 Scope of the port (skeleton)

Only the N-S subset of maps/functions is ported in this spec: `INTERFACES`/`PORT_META`, `ROUTES6`, `UNDERLAY`, `CONFIG`/`LOCAL`, `FW_RULES`/`FW_META`/`FW_CONFIG`, `CONNTRACK`, and the `wan_rx` (encap) + `uplink_rx` (decap + firewall + conntrack) entry paths. The remaining maps/functions stay as-is behind the old direct-global access until their features are ported.

### 5.4 The harness API

```rust
let mut edge = SimNode::edge(edge_underlay);
let mut host = SimNode::host();
host.apply(&compiled_nic);          // CompiledNIC -> native Maps (fw rules, underlay, iface…)

let wan_in = PacketBuilder::ethernet2(..).ipv6(wan_src, vip, 64).tcp(..).build(payload);

let out = edge.run(Prog::WanRx, &wan_in);            // -> XDP_REDIRECT + encapsulated bytes
assert_encapsulated(&out, edge_underlay, host_underlay);
let delivered = host.run(Prog::UplinkRx, &out.pkt);  // decap + FW + conntrack
assert_delivered_to_guest(&delivered, overlay_ip);
```

- **`SimNode`** owns a native `Maps` + config and exposes `run(Prog, &[u8]) -> SimOutput { verdict, pkt }` by calling the `flowplane-core` entry fns with the native impls.
- **`apply(&CompiledNIC)`** is the shared lowering (`CompiledNIC → map writes`), factored so the sim exercises the *real* wiring rather than a parallel reimplementation. Where practical, the agent's gRPC-handler map writes and `apply` share this lowering.
- Packet crafting is **`etherparse`** (pure Rust, in-process) — no scapy/Python/FFI on the fast path. Scapy remains only in the existing conformance suite.

### 5.5 `BPF_PROG_TEST_RUN` fidelity anchor

A privileged, separately-gated test: load the real compiled programs, populate the real maps from the *same* `CompiledNIC` fixture, run `BPF_PROG_TEST_RUN` on the *same* crafted packet, and assert the output bytes **equal the native sim's output**. This is the guarantee that the pure core has not drifted from the real bytecode. Kept few (one per representative path); runs in privileged CI, skipped locally. `BPF_PROG_TEST_RUN` is currently unused in the repo — this introduces it.

## 6. Walking-skeleton slice (what ships in this spec)

The one N-S path, end to end:

1. `CompiledNIC` CRD type + deepcopy/registration + a **minimal compiler** covering only the slice (identity, underlay, one ingress FW allow rule).
2. `flowplane-core` crate with `Maps`/`Pkt` traits + the N-S subset ported: `wan_rx` (encap) and `uplink_rx` (decap + FW + conntrack). eBPF wrappers wired.
3. `flowplane-sim` crate: native impls, `SimNode`, `apply(&CompiledNIC)`, `etherparse` crafting.
4. **The green test:** external → `wan_rx` encap → `uplink_rx` decap → guest-deliver, asserting encap headers, FW allow, and a conntrack entry created.
5. **One** `BPF_PROG_TEST_RUN` anchor asserting byte-parity for that path.

## 7. Verification

- `cargo test -p flowplane-core -p flowplane-sim` — fast, no root; the feature-coverage home.
- `cargo build` + existing `test/conformance` — the real datapath is unchanged in behavior and stays green (regression guard on the extraction).
- `make sim-anchor` (privileged) — the `BPF_PROG_TEST_RUN` byte-parity anchor.
- Go unit/envtest — the compiler produces the expected `CompiledNIC` from CRDs.

## 8. Risks & mitigations

- **Verifier regressions from the refactor.** Extracting to generics + a `Pkt` trait could shift what the verifier accepts. *Mitigation:* port the N-S subset only; keep `Pkt` a trait (not a slice) so eBPF retains raw-ptr bounds checks; the conformance suite + the load step in the anchor test catch verifier breakage immediately.
- **Native/bytecode drift.** The whole point of the sim is fidelity. *Mitigation:* the `BPF_PROG_TEST_RUN` anchor asserts byte-parity; every ported feature adds one anchor case.
- **Lowering duplication (agent vs sim).** Two `CompiledNIC → maps` paths would defeat the purpose. *Mitigation:* factor a single shared lowering used by both where practical; where the agent must go through gRPC, keep the map-write body shared.
- **`CompiledNIC` scope creep.** Temptation to model routebus-learned state. *Mitigation:* the exclusion list in §4.2 is normative; learned state never enters `CompiledNIC`.

## 9. Out of scope / follow-ups

- Port + sim coverage for NAT, NAT64, LB/Maglev, DHCP, ARP/ND (each: extend `Maps`, port the fns, add sim scenarios + one anchor case).
- Full compiler: all selectors and all resources (`VPCPeering`, multi-policy merge, `VirtualIP` failover).
- Retiring the netns/clab e2e once sim coverage supersedes each feature.
