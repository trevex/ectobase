# nfkit Milestone 5 — Edge WAN-VIP ingress (`wan_rx`) on DPDK, byte-parity

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M3 (`MbufPkt`/`DpdkMaps` + `process_uplink`/`process_guest_tx`), M4 (NAT-family). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Port `SimNode::wan_rx` — the **edge WAN-VIP ingress** datapath (a plain WAN frame → Maglev VIP select → IP-in-IPv6 encap toward the backend) — into a shared generic `process_wan_rx` in `flowplane-core/src/datapath.rs`, and prove it runs **byte-identically on DPDK** vs the sim. This extends the `DPDK ==(shared orchestrator)== sim ==(BPF_PROG_TEST_RUN anchors)== eBPF` chain to the **N-S edge role** and, notably, to the **v6-inner encap path** (`inner_proto = 41`/IPPROTO_IPV6) that no prior anchor exercises. The eBPF dataplane is not modified.

This is the second "port remaining datapaths" follow-on (after M4). The last group — control-plane responders (`guest_arp_nd` + `guest_dhcp4`) — remains a separate milestone (it needs new `MbufPkt::set_tail` work for DHCP's `adjust_tail`, plus the reply-generation pattern).

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Orchestration seam | **Shared generic `process_wan_rx`** in `flowplane-core/src/datapath.rs`; sim wrapper calls it; eBPF untouched |
| Maps borrow | **`&M` (read-only)** — `wan_rx` is `&self`, only LB/Maglev select; no `&mut`, no new trait method |
| Scope | **`wan_rx` only** (v4 + v6 VIP + Pass) |
| Encap seam | **In-place `grow_head(IPV6_LEN)`+`write_outer_v6`** on `pkt` (not the `edge_encap` `Vec`-builder helper); `Drop` on grow/write failure |
| DpdkMaps | **No changes** — reuses `add_lb`/`add_maglev` (LB VIP + Maglev backend), same `LbKey`/`MaglevKey` for v4 and v6 |

## 3. Components

```
flowplane-core/src/datapath.rs  + process_wan_rx<P,M>, + WanRxIn
flowplane-sim/src/sim.rs         SimNode::wan_rx → thin wrapper
flowplane/nfkit/tests/
  parity_wan_rx.rs   DPDK-vs-sim byte anchor (v4 VIP encap, v6 VIP encap, no-VIP Pass)
```

### 3.1 The orchestrator (`flowplane-core/src/datapath.rs`)

```rust
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Edge WAN-VIP ingress, in place on `pkt`. Mirrors `ingress.rs::try_wan_rx` VIP branch: dispatch on
/// ethertype (offset 12) — 0x86DD → v6 core select (`inner_proto = 41`/IPPROTO_IPV6), else v4 core
/// select (`inner_proto = 4`/IPIP); on a VIP hit, encap the inner packet IP-in-IPv6 toward the
/// Maglev-selected backend (`grow_head(IPV6_LEN)` + `write_outer_v6`) → `Redirect(uplink_ifindex)`;
/// otherwise `Pass` (pkt untouched).
pub fn process_wan_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &WanRxIn) -> Action;
```

Body (a near-verbatim move of `SimNode::wan_rx`, `flowplane-sim/src/sim.rs:311-345`, adapted to in-place):
1. `ethertype = pkt.read_array::<2>(12)` → `u16::from_be_bytes`, defaulting to `0` when the frame is shorter than 14 bytes (preserves the current `plain.get(12/13).unwrap_or(0)` semantics → falls to the v4 branch).
2. `selected = match ethertype { 0x86DD => lb_select_forward_v6(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 41u8)), _ => lb_select_forward(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 4u8)) }`.
3. `Some((backend, inner_proto))` → build `EncapParams { gateway_mac: in_.local.gateway_mac, uplink_mac: in_.local.uplink_mac, uplink_ifindex: in_.local.uplink_ifindex, src_underlay: in_.local.underlay_ipv6, nexthop_ipv6: backend, inner_proto, flow_label: 0 }`; `if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) { return Action::Drop }`; `Action::Redirect(in_.local.uplink_ifindex)`.
4. `None` → `Action::Pass`.

`SimNode::wan_rx` becomes: `let mut pkt = VecPkt::from_bytes(plain); let action = process_wan_rx(&mut pkt, &self.maps, &WanRxIn { local: &self.local }); SimOut { action, pkt: pkt.into_bytes() }`.

### 3.2 The one controlled deviation from strict-verbatim

The current `wan_rx` produces output via `self.edge_encap(plain, e)`, which **asserts** `inner_frame.len() >= ETH_LEN` and returns a freshly-built `Vec`. The generic instead does `grow_head`+`write_outer_v6` **in place** and returns `Drop` on failure — matching every other encap path in `datapath.rs` (e.g. `process_guest_tx_nat64`). For every valid VIP-selected WAN frame (always ≥ `ETH_LEN` + an IP header) the emitted bytes are **identical**; the trade is `edge_encap`'s panic-on-malformed → a graceful datapath `Drop`. The sim-suite-green gate (§5) confirms byte-preservation on all real inputs.

## 4. Parity harness

`flowplane/nfkit/tests/parity_wan_rx.rs`, modelled on the M3/M4 anchors (EAL-once, `--test-threads=1`, `mp_bytes`/`run_dpdk`/`run_sim` helpers; here `run_dpdk`/`run_sim` pass `maps: &M`). Populate `MemMaps` and `DpdkMaps` **identically** with a WAN LB VIP (`vni = 0`) + a Maglev backend underlay (`add_lb`/`add_maglev` / the sim equivalents). Three scenarios in one `#[test]`:
- **v4 VIP → IPIP encap:** a plain `[Eth(0x0800)][IPv4][L4]` frame to the VIP; assert `Redirect(uplink_ifindex)` (positive, before byte-compare) + byte-identical encapped output (outer IPv6 + `inner_proto = 4`); sanity: outer version nibble 6, outer dst == backend.
- **v6 VIP → IPPROTO_IPV6 encap:** a plain `[Eth(0x86DD)][IPv6][L4]` frame to the VIP; assert `Redirect(uplink_ifindex)` + byte parity of the encapped output with `inner_proto = 41`. This is the new inner-v6 encap path.
- **no-VIP → Pass:** a frame with no matching VIP; assert `Action::Pass` + output bytes == input on both sides (pkt untouched).

## 5. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: `parity_wan_rx` (v4/v6/pass) + all M3/M4 anchors pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim` passes **unchanged** — the `wan_rx` refactor is byte-preserving (the fabric N-S / WAN-VIP sim tests are the witnesses).
- The `flowplane` `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained one fn + one In-struct, still `no_std`, still no DPDK dep; **no new `Maps` trait method** → no `GlobalMaps`/eBPF change this milestone.
- Default host build + existing tests untouched.

## 6. Phasing (for the plan)

Single task: extract `process_wan_rx` + rewire the `SimNode::wan_rx` wrapper (sim suite green — the acceptance gate) → then the `parity_wan_rx.rs` DPDK anchor (v4/v6/pass). One commit.

## 7. Risks / open questions

- **Near-verbatim, not strict-verbatim** (the `edge_encap`→in-place change, §3.2). Acceptance = full `flowplane-sim` suite green; if a WAN/fabric sim test changes bytes, the move diverged — fix it. The deviation only changes malformed-input behavior (panic→Drop), which no valid test exercises.
- **`read_array::<2>(12)` short-frame semantics** — must default to ethertype 0 (v4 branch) on a <14-byte frame, matching `plain.get(..).unwrap_or(0)`. `read_array` returns `None` on OOB → map to 0 explicitly.
- **v6 inner encap coverage** — the v6 VIP scenario is the first anchor to exercise `inner_proto = 41`; confirm `write_outer_v6` + `MbufPkt` handle the v6-inner frame identically to `VecPkt` (they should — the outer header write is inner-proto-agnostic bytes).
- **`lb_select_forward_v6` key derivation** — it forms an `LbKey`/`MaglevKey` from the v6 frame (same types as v4). The anchor must populate the LB/Maglev maps with the key the v6 select computes; read `flowplane-core/src/lb.rs:42-72` for the exact derivation so `DpdkMaps` + `MemMaps` are seeded identically.
