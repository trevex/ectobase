# Unified tcx Guest Edge + EDT Traffic Shaping

Date: 2026-07-18
Status: Design (approved for planning)

## Summary

Two coupled changes to the guest datapath, in one spec:

1. **Unify the guest edge on a single tcx datapath** for both container veth and VM tap.
   Retire the legacy XDP `guest_tx` variant, the `FLOWPLANE_GUEST_TC` fork, and
   `GuestLink::Xdp`. One guest program, one attach path, both port types.
2. **Add EDT (Earliest Departure Time) traffic shaping** as a first-class enterprise
   feature: true egress shaping (smoothing/pacing via the FQ qdisc), plus token-bucket
   policing for the external-egress sub-cap and for ingress.

The uplink edge stays XDP. The two changes are coupled: shaping requires the guest egress
path to traverse an egress qdisc, which is only possible on the tc/skb path — so committing
the guest edge to tcx is what unlocks shaping. XDP `bpf_redirect`/devmap uses `ndo_xdp_xmit`,
which bypasses the qdisc entirely, making shaping structurally impossible on the XDP path.

## Motivation

- The current `meter.rs` token bucket **polices** (drops over-rate). Real QoS wants
  **shaping** (pace/delay, no loss) for egress bandwidth caps — the model Cilium's
  Bandwidth Manager adopted (EDT + FQ) after moving off TBF policing.
- The guest edge already defaults to tcx (`tc_guest_tx`, `FLOWPLANE_GUEST_TC=1`); the XDP
  `guest_tx` is a legacy fallback held over from before the tc-tap port. tcx works cleanly
  under vhost-net (guest→host traverses `netif_receive_skb`→tcx ingress; host→guest traverses
  the tap qdisc→tcx egress), whereas native XDP on the tun is blocked (vhost/XDP_TX issues).
  Consolidating removes a dual-variant fork and unblocks shaping.
- The bandwidth API (`InterfaceBandwidth{TotalMbps, PublicMbps}`) is a metalnet-derived
  *policing* shape. Shaping deserves a native API expressing direction and shaped-vs-policed.

## Architecture

Two independent edges; the split is unchanged, the guest edge is consolidated:

- **Uplink edge (N-S underlay):** stays **XDP** (`uplink_rx`/`wan_rx`) — RX-side decap, LB,
  ingress firewall, redirect. Gains an **FQ qdisc** on the uplink so egress traffic redirected
  onto it is paced by `skb->tstamp`. XDP-ingress and FQ-egress coexist on the same NIC.
- **Guest edge (veth + tap):** collapses to a single **tcx** datapath (`tc_guest_tx`).

Three traffic-control lanes, all keyed by interface ifindex, all driven by the new
`InterfaceQoS`:

| Lane           | Direction     | Mechanism                  | Where                                   |
|----------------|---------------|----------------------------|-----------------------------------------|
| Egress total   | VM → out      | **EDT shaping** (smoothed) | stamp in `tc_guest_tx`, pace at uplink FQ |
| Egress public  | VM → external | token-bucket **police**    | `tc_guest_tx`, on `is_external`         |
| Ingress        | out → VM      | token-bucket **police**    | `uplink_rx`, after resolving dest tap   |

## Datapath mechanics

### Egress shaping (headline)

In `tc_guest_tx`, after the forward decision resolves the source-VM egress rate, compute the
departure time via a new pure-core function and stamp it on the skb:

- `flowplane_core::meter::edt_departure(rate_bps, wire_len, t_last, now) -> (tstamp, new_t_last)`
  — a faithful sibling of `meter::take`: same saturating math, no 128-bit ops (bpf-linker
  rejects `__multi3`/`__udivti3`), pure, clock passed in as a parameter (eBPF passes `now()`,
  sim passes a controlled clock).
- Glue calls `bpf_skb_set_tstamp(skb, tstamp, BPF_SKB_TSTAMP_DELIVERY_MONO)`.
- The existing encap (`bpf_skb_adjust_room`) + `bpf_redirect(uplink)` preserve `tstamp`.
  Because a **tc** redirect goes through `dev_queue_xmit`, the packet hits the uplink's **FQ**,
  which holds it until its timestamp. No new program — reuse the hook where source-VM identity
  (ifindex) is already known.

Notes:
- FQ hashes encapped uplink traffic by the outer (per-peer-node) header, so per-flow *fairness*
  degrades to per-dest-node buckets — but EDT *pacing* honors `tstamp` regardless of the flow
  bucket, which is what we need. Acceptable; documented.
- `skb->tstamp` must be set as delivery-time (mono) via `bpf_skb_set_tstamp`; FQ uses the
  monotonic clock, matching `bpf_ktime_get_ns`.

### Egress public + ingress policing

Keep the `meter::take` token bucket:
- **Public** runs in `tc_guest_tx` on `is_external` (as today) — an additional drop cap on
  external egress layered on top of the EDT total shaping.
- **Ingress** runs in `uplink_rx` after decap resolves `tap_ifindex`, keyed by that tap.
  Policing (drop) works fine in XDP.

### MeterState / QoS map

Restructure the per-ifindex map entry into the three lanes (one map, one entry per ifindex,
read by the egress hook via src key and the ingress hook via dst-tap key):

- `total`  (egress, EDT):   `{ bps, t_last }`
- `public` (egress, TB):    `{ bps, burst, tokens, last_ns }`
- `ingress`(ingress, TB):   `{ bps, burst, tokens, last_ns }`

Update the `size_of::<MeterState>()`/align asserts in `flowplane-common` accordingly. No
entry for an ifindex ⇒ all lanes unlimited (pass).

### Accepted v1 limitation

Same-node VM→VM (the `Deliver::Local` fast path) redirects tap→tap directly, bypassing the
uplink FQ, so it is **not** egress-shaped. Cross-node egress (encap→uplink) and all external
egress **are** shaped. Documented, acceptable for v1.

## Control plane & API

### CRD (replaces InterfaceBandwidth)

Both the Go type **and** its hand-maintained deepcopy must be edited (CRD convention):

```go
// NetworkInterfaceSpec.Bandwidth *InterfaceBandwidth  ->  QoS *InterfaceQoS
type InterfaceQoS struct {
    Egress  *EgressQoS `json:"egress,omitempty"`
    Ingress *RateLimit `json:"ingress,omitempty"`
}
type EgressQoS struct {
    RateMbps   uint32 `json:"rateMbps,omitempty"`   // EDT-shaped total egress; 0 = unlimited
    BurstKB    uint32 `json:"burstKB,omitempty"`    // optional; default derived from rate
    PublicMbps uint32 `json:"publicMbps,omitempty"` // optional external sub-cap (policed); 0 = unlimited
}
type RateLimit struct {
    RateMbps uint32 `json:"rateMbps,omitempty"`
    BurstKB  uint32 `json:"burstKB,omitempty"`      // optional
}
```

### gRPC

`ConfigureMeter(iface, total, public)` → `ConfigureQoS(iface, EgressQoS, IngressRateLimit)`
on `DataplaneNode`. The agent lowers `EgressQoS.RateMbps`→EDT total lane,
`EgressQoS.PublicMbps`→public TB lane, `Ingress`→ingress TB lane, all into the one QoS map
entry. Burst defaults: if `BurstKB == 0`, derive a sane default (e.g.
`max(rate_bps/1000, ~64KB)`), matching how the current TB burst is seeded.

### Reconciler

`metereconcile.go` → `qosreconcile.go`: same diff-against-applied structure
(`r.appliedQoS map[string]InterfaceQoS`), same idempotent clear-to-unlimited on spec removal
or NIC deletion. Only the payload widens from two scalars to the structured QoS.

### Uplink FQ provisioning

The loader's uplink attach ensures `mq` root + `fq` leaves (or a single `fq` on a 1-queue NIC)
on the uplink, idempotently — a sibling of `qdisc_add_clsact`. This is what makes the EDT
stamps actually pace.

## Retiring XDP guest_tx

Concrete deletions:
- `#[xdp] guest_tx` program in `flowplane-ebpf`.
- `GuestLink::Xdp` arm + its attach/reattach/pin call sites in `control.rs`.
- The `FLOWPLANE_GUEST_TC` env branch.
- `load_program("guest_tx")` and the XDP-side `GUEST_PROGS` DHCP tail-call registration
  (the tc path's `GUEST_PROGS_TC` stays).
- The XDP DHCP entry wrappers (`try_dhcpv4_reply`/`try_dhcpv6_reply` on `XdpContext`) — the
  tc responders (`tc_guest_dhcp`, `tc_dhcpv6_respond`) stay.

`forward_decision_v4` and the `EgressVerdict` glue are unchanged — only the XDP entry wrapper
goes. Net: one guest program, one attach path, less env-driven branching.

Not affected: DHCPv6 stays a hand-written eBPF responder (already has a tc path,
`tc_dhcpv6_respond`). Its option block is genuinely runtime-variable-length, which the
const-generic `Pkt` trait cannot express; the verifier's variable-offset limitation is
identical for tc and XDP, so going tcx-only does not, on its own, let DHCPv6 move to
`flowplane-core`. See Future Work.

## Testing (HARD rule: production eBPF calls the pure-core seam)

- **`flowplane-core/src/meter.rs`:** add `edt_departure(...)` next to `take()`, same
  verifier-friendly discipline. `tc_guest_tx` and the sim both call it. In-module unit tests
  (like `take`'s), plus a `flowplane-sim` scenario proving departure spacing over a controlled
  clock.
- **Ingress + public policing:** reuse `take()` unchanged; add sim coverage for the ingress
  lane at the `uplink_rx` delivery point.
- **No tstamp anchor (infeasible):** `xdp_md` has no `tstamp` field and there is no tc
  `BPF_PROG_TEST_RUN` precedent for reading `skb->tstamp` in this repo (all anchors are XDP).
  So the EDT *computation* is covered by pure-core unit tests + a sim departure-spacing test;
  the tstamp *wiring* in `tc.rs` is covered by the existing `verify_tc_guest.rs` load check
  plus live validation. Byte-parity anchors for the non-shaping guest_tx path stay as-is.
- **Controller:** envtest for `qosreconcile` (desired/applied diff, clear-on-removal),
  mirroring the existing meter reconcile test.
- **Cannot be unit-tested:** FQ actually pacing packets is kernel qdisc behavior → live
  validation.

## Limitations & validation

- **clab cannot validate shaping.** Nested netns + veth means no real FQ pacing (the reason
  Cilium disables its Bandwidth Manager in Kind). Therefore: egress/ingress **policing** + the
  `tstamp`-is-set anchor validate in clab; **true FQ shaping validates only on real fabric/VMs**
  (per the N-S real-range testing preference). Do not claim shaping works from a clab run.
- **Same-node VM→VM egress is unshaped** (Local fast path bypasses uplink FQ) — documented,
  acceptable v1.
- **Kernel floor:** tcx links need ≥6.6 (already the pin path); `bpf_skb_set_tstamp`
  delivery-mono needs a recent kernel — a documented requirement.

## Future work (explicitly out of scope for this spec)

1. **`Pkt` trait v2 on skb helpers.** With the guest edge exclusively skb/tc, the packet
   abstraction could be redesigned around `bpf_skb_load_bytes`/`bpf_skb_store_bytes`, which
   permit verifiable **variable-offset** access (the helper bounds-checks internally,
   sidestepping the raw-pointer provenance wall). This could bring DHCPv6 (and other
   variable-length parsing) into `flowplane-core`. Trade-off: loses the clean const-generic
   model, likely slower per-access. Its own project; does not need shaping and shaping does not
   need it.
2. **Pod/VM-level BBR.** BBR pacing rides the same EDT/FQ machinery this spec builds. Follow-up
   to evaluate whether guest-side BBR benefits from host FQ given the VM's TCP socket lives
   inside the guest and we forward the encapped frame at L2/L3 (Cilium requires eBPF
   host-routing to preserve the socket association; our topology differs).

## Non-goals

- No changes to the uplink XDP datapath beyond adding the FQ qdisc.
- No ingress *shaping* (ingress is policed only in v1).
- No L7/DSCP/priority QoS.
