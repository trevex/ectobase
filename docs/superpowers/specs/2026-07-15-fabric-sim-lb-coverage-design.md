# Fabric Sim + Comprehensive LB Coverage (E/W + N/S) — Design

**Status:** Draft (brainstorm output) — design agreed 2026-07-15.
**Date:** 2026-07-15
**Builds on:** `docs/superpowers/specs/2026-07-15-compiled-nic-synthetic-datapath-testing-design.md` (the pure-core `Pkt`/`Maps` sim + `CompiledNIC` pipeline).
**Motivation:** Unravel, synthetically, why load-balancing "never worked" in clab, and stand up comprehensive East-West + North-South LB coverage — without clab debug loops.

---

## 1. Summary

Two things:

1. **`Fabric` multi-node sim abstraction** — extend `xdp-dp-sim` so a test can run a packet across *multiple* nodes (edge → fabric → backend host, and LB reforward origin → LB-home → backend), modelling `bpf_redirect` across the underlay. Returns a `Trace` of every hop for precise assertions.
2. **Full LB datapath port + comprehensive E/W + N/S LB coverage** — port the LB selection/relay path into `xdp-dp-core` (chiefly one new pure function, `lb_select_forward`, plus `reforward`), then drive both complete flows through the `Fabric` and assert delivery vs. firewall-drop.

**Corrected firewall philosophy (normative):** the distributed firewall is **explicit-only**. LB membership MUST NOT auto-generate firewall allow rules (auto-whitelisting backends is a security anti-pattern). LB traffic is subject to the backend's **explicit** `NetworkPolicy` like any other traffic; coverage proves that an explicit policy is what permits (or correctly denies) LB.

## 2. Root cause this reproduces (from the debugging investigation)

- **Datapath (correct behavior):** LB is DSR — `lb_select_forward` does "No DNAT, no conntrack — the backend VF owns the LB IP." Inner dst stays the **VIP**. `try_uplink_rx` skips conntrack for LB, so *every* LB packet is a fresh flow at the ingress-firewall check, evaluated on `(src → VIP:port)` against the **backend tap's** rules. `fw_enforcing()` defaults to `true`; `fw_eval_dir` drops only when the tap has rules (`ingress_count > 0`) that don't match.
- **The clab failure:** the moment a backend NIC is selected by *any* `NetworkPolicy`, its LB VIP traffic matches no rule → default DROP. LB "worked" only on unfirewalled backends.
- **Right fix = explicit rules, not bypass:** the `239036a` "skip firewall for LB" was correctly reverted by `d40037c`. The operator writes an explicit policy permitting the VIP traffic. This spec's coverage proves that path end to end and exposes any *genuine* datapath drop (see §5).

## 3. `Fabric` multi-node abstraction (`xdp-dp-sim`)

```rust
pub struct Fabric {
    nodes: HashMap<NodeId, SimNode>,
    routes: HashMap<[u8; 16], NodeId>, // underlay /128 -> owning node
}

pub struct Hop { pub node: NodeId, pub prog: Prog, pub action: Action, pub pkt: Vec<u8> }
pub struct Trace { pub hops: Vec<Hop>, pub outcome: Outcome } // Delivered{node,tap} | Dropped{node} | Passed{node}

impl Fabric {
    pub fn add_node(&mut self, id: NodeId, node: SimNode);
    pub fn route(&mut self, underlay: [u8; 16], id: NodeId); // register an underlay -> node
    /// Run `prog` on `ingress`, then follow encap/redirect across the fabric until the packet is
    /// delivered to a guest tap, dropped, or passed. Caps hops (default 8) to catch reforward loops.
    pub fn deliver(&mut self, ingress: NodeId, prog: Prog, pkt: &[u8]) -> Trace;
}
```

**Routing rule:** when a node's program returns `Action::Redirect(_)` on a frame whose outer IPv6 dst is an underlay in `routes`, the `Fabric` re-runs that target node's `uplink_rx` on the output bytes. Delivery to a guest tap (`Action::Redirect(tap)` where the frame is decapped) terminates with `Delivered`. `Drop`/`Pass` terminate immediately. Exceeding the hop cap is a test failure (`reforward loop`).

Each `SimNode` keeps its own `MemMaps` (its interfaces, LB/MAGLEV tables, firewall rules from its backends' `CompiledNIC`s, underlay identity).

## 4. LB datapath port into `xdp-dp-core`

- **`lb::lb_select_forward<P: Pkt, M: Maps>(pkt, ip_off, vni) -> Option<[u8; 16]>`** — faithful port of the eBPF `lb.rs` primary path: read inner src/dst + L4 ports, `LbKey{vni,dst,port,proto}` lookup, `hash5 % size`, `MaglevKey{table_id,slot}` lookup → backend underlay. (ICMP-error and v6 variants deferred.)
  - **`Maps` additions:** `lb_get(&LbKey) -> Option<LbValue>`, `maglev_get(&MaglevKey) -> Option<[u8; 16]>`. `MemMaps` gains `lb: HashMap<LbKey, LbValue>`, `maglev: HashMap<MaglevKey, [u8; 16]>`; `GlobalMaps` wraps the `LB`/`MAGLEV` statics.
  - **`parse`:** move `hash5` into `xdp-dp-core::parse` (already pure).
- **`encap::reforward<P: Pkt>(pkt, local: &Local, lb_underlay: &[u8;16], backend: &[u8;16]) -> Action`** — port the outer Eth+IPv6 rewrite + `Redirect(uplink_ifindex)` from eBPF `encap.rs` (no decap).
- **Uplink LB branch** — extend the uplink seam: after resolving `(vni, u)` from `UNDERLAY[outer_dst]`, call `lb_select_forward`; if `Some(bul)` and `bul` is local → deliver via the existing firewall+decap seam using the backend tap; if `Some(bul)` remote → `reforward` to `bul`; if `None` → the existing base path.
- **Edge `wan_rx` VIP seam** — composes `lb_select_forward(vni=0)` + the existing `encap::write_outer_v6` path (edge encaps the plain WAN IPv4 IP-in-IPv6 to the selected backend underlay). No new logic beyond the two existing pieces.
- **E/W origin (`guest_tx`)** — egress encap already routes via `ROUTES`; the VIP resolves to its home underlay and that node's `uplink_rx` LB-selects. Minimal/no new core; the sim populates the origin's route to the VIP-home underlay.

eBPF programs keep delegating to these core fns (so `test_lb.py` conformance stays green).

## 5. Explicit-firewall verification & the reproduction

The firewall is populated **only** from `NetworkPolicy` via the real pipeline `NetworkPolicy → Compile() → CompiledNIC → apply() → MemMaps`. No LB→rule generation anywhere.

Per flow, two poles:
- **Positive:** backend `NetworkPolicy` permits the VIP traffic (`from` covers the source, `ports` = VIP port) → **delivered**.
- **Negative:** backend policy selects it but does not cover the VIP (e.g. allows only an internal CIDR while the N/S source is external) → **dropped** at the backend firewall — the exact clab failure as a one-line assertion.

**The coverage is the reproduction.** If a flow with a *correct explicit allow rule* still drops in the `Fabric`, that is a genuine datapath bug (firewall evaluating the wrong tuple on the reforwarded/DSR packet, or an edge/reforward hop mangling the frame), not operator error — and the `Trace` names the hop that dropped it.

## 6. E/W + N/S test matrix

Nodes: `edge`, `hostA`, `hostB` (backend). Built on `Fabric`.

| # | Flow | Path asserted | Firewall state | Expected |
|---|------|---------------|----------------|----------|
| 1 | N/S external → WAN VIP | `edge.wan_rx` → `hostB.uplink_rx` | explicit allow (`0.0.0.0/0`:port) | delivered to backend tap |
| 2 | N/S same | same | policy selects backend, no VIP rule | **drop** at backend FW |
| 3 | N/S same | same | no policy (`ingress_count == 0`) | delivered (open-until-selected) |
| 4 | E/W guestA → VIP, backend on hostB | `hostA.guest_tx` → VIP-home → **reforward** → `hostB.uplink_rx` | explicit allow (from guestA CIDR) | delivered; `Trace` shows the reforward hop |
| 5 | E/W same, VIP-home == backend | `hostB.uplink_rx` local-deliver | explicit allow | delivered, **no** reforward hop |
| 6 | Maglev determinism | same 5-tuple → same backend across nodes | — | reforward converges (no loop; hop cap not hit) |

Each asserts the final `Outcome` **and** the `Trace` path.

## 7. Fidelity, tooling, scope

- **Conformance `test_lb.py`** is the real-datapath regression guard — must stay green after the port.
- **One `BPF_PROG_TEST_RUN` anchor** for the LB path (e.g. `uplink_rx` LB local-deliver): native `Fabric`/sim output == real bytecode output, per the established "each ported feature adds one anchor case" discipline.
- **`make sim`** runs the whole matrix, no root.

**In scope (this spec):** the `Fabric` abstraction + full LB port + the §6 matrix.

**Out of scope — follow-on slices (own spec each, reusing `Fabric`):**
- SNAT/NAT-gateway egress (backend → edge → WAN).
- NAT64 cross-family (IPv6 guest ↔ IPv4 external).
- `VirtualIP`/floating-IP failover (re-point DNAT).
- DHCP / ARP-ND responders.
- LB ICMP-error relay + IPv6-in-IPv6 LB (`lb_select_forward_icmp_error`, `_v6`).

## 8. Risks & mitigations

- **Fabric routing fidelity.** The auto-delivery rule (outer-dst underlay → node) must match real `bpf_redirect` semantics. *Mitigation:* the `BPF_PROG_TEST_RUN` anchor + `test_lb.py` conformance pin the per-node behavior; the `Fabric` only stitches hops, and the `Trace` makes stitching visible/assertable.
- **Reforward loop.** Deterministic Maglev should converge, but a bug could loop. *Mitigation:* hop cap → explicit test failure (matrix #6 asserts convergence).
- **Verifier regressions from the port.** *Mitigation:* port the LB subset only; eBPF keeps delegating; `test_lb.py` fails fast at load if the verifier rejects a rewire.
- **Scope creep into NAT/VIP.** *Mitigation:* §7 fixes the boundary; those are separate specs.
