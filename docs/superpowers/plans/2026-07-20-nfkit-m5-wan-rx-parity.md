# nfkit M5 — Edge WAN-VIP ingress (`wan_rx`) on DPDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `SimNode::wan_rx` into a shared generic `process_wan_rx` in `flowplane-core`, and prove DPDK byte-parity (v4 VIP encap, v6 VIP encap, no-VIP Pass).

**Architecture:** Same seam as M3/M4 — near-verbatim move of the `SimNode::wan_rx` body into `flowplane-core/src/datapath.rs` (adapted to in-place `grow_head`+`write_outer_v6` instead of the `edge_encap` `Vec`-builder); the `SimNode` method becomes a thin wrapper; eBPF untouched. Maps borrow is read-only (`&M`) — no new trait method.

**Tech Stack:** Rust, `dpdk-sys`/`nfkit` (M1/M2), `flowplane-core` traits+fns, `rte_hash`. Run all cargo inside `nix develop`.

**Context (grounded — I read these):**
- Spec: `docs/superpowers/specs/2026-07-20-nfkit-m5-wan-rx-parity-design.md`.
- Current `SimNode::wan_rx` body: `flowplane/flowplane-sim/src/sim.rs` lines ~311-345. Signature `(&self, plain: &[u8]) -> SimOut`. Uses `lb_select_forward_v6`/`lb_select_forward` + `self.local` + `self.edge_encap`.
- `lb_select_forward<P,M>` / `lb_select_forward_v6<P,M>` are in `flowplane-core/src/lb.rs` (lines 10/42); both use `maps.lb_get(&LbKey{..})` + `maps.maglev_get(&MaglevKey{..})` — read 42-72 for the exact v6 `LbKey`/`MaglevKey` derivation so the anchor seeds maps identically. They already work over any `M: Maps`.
- `datapath.rs` (M3/M4) already imports `EncapParams`, `write_outer_v6`, `ETH_LEN`, `IPV6_LEN`, `Action`, `Pkt`, `Maps`, and `lb_select_forward` (used in `process_uplink`). Add `use crate::lb::lb_select_forward_v6;` if not present.
- Anchor model: `flowplane/nfkit/tests/parity_uplink.rs` (LB scenario shows `add_lb`/`add_maglev` population + `mp_bytes`/`run_dpdk`/`run_sim`). `nfkit/Cargo.toml` already has `etherparse` + `flowplane-sim` dev-deps. `DpdkMaps` already has `add_lb`/`add_maglev`.

**Absolute rules:**
- Run cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook active; if the rustup `cargo fmt` shim prints usage, format touched files with `rustfmt --edition 2021 <files>`.
- Near-verbatim move — acceptance = full `flowplane-sim` suite (69 tests) stays green. If a WAN/fabric sim test changes, fix the move (the only intended behavior change is `edge_encap` panic-on-malformed → graceful `Drop`, which no valid test hits).

---

## File Structure
- `flowplane/flowplane-core/src/datapath.rs` — `+ process_wan_rx`, `+ WanRxIn`.
- `flowplane/flowplane-sim/src/sim.rs` — `SimNode::wan_rx` → thin wrapper.
- `flowplane/nfkit/tests/parity_wan_rx.rs` — new anchor.

---

## Task 1: Extract `process_wan_rx` + DPDK parity anchor

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; create `flowplane/nfkit/tests/parity_wan_rx.rs`.

- [ ] **Step 1: Extract the orchestrator** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_wan_rx`]. `local` supplies the outer MACs/ifindex + this node's underlay src.
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Edge WAN-VIP ingress, in place on `pkt`. Mirrors `ingress.rs::try_wan_rx` VIP branch: dispatch on
/// ethertype (offset 12) — 0x86DD → v6 core select (`inner_proto = 41`), else v4 core select
/// (`inner_proto = 4`); on a VIP hit, encap the inner packet IP-in-IPv6 toward the Maglev-selected
/// backend (`grow_head(IPV6_LEN)` + `write_outer_v6`) → `Redirect(uplink_ifindex)`; else `Pass`.
pub fn process_wan_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &WanRxIn) -> Action {
    let ethertype = match pkt.read_array::<2>(12) {
        Some(b) => u16::from_be_bytes(b),
        None => 0, // frame < 14 bytes → v4 branch (matches plain.get(..).unwrap_or(0))
    };
    let selected = match ethertype {
        0x86DD => lb_select_forward_v6(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 41u8)),
        _ => lb_select_forward(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 4u8)),
    };
    match selected {
        Some((backend, inner_proto)) => {
            let e = EncapParams {
                gateway_mac: in_.local.gateway_mac,
                uplink_mac: in_.local.uplink_mac,
                uplink_ifindex: in_.local.uplink_ifindex,
                src_underlay: in_.local.underlay_ipv6,
                nexthop_ipv6: backend,
                inner_proto,
                flow_label: 0,
            };
            if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) {
                return Action::Drop;
            }
            Action::Redirect(in_.local.uplink_ifindex)
        }
        None => Action::Pass,
    }
}
```
Add `use crate::lb::lb_select_forward_v6;` to the imports if not already present (`lb_select_forward` is already imported from M3). Build: `cargo build -p flowplane-core`.

- [ ] **Step 2: Rewire `SimNode::wan_rx`** — replace its body (`flowplane-sim/src/sim.rs`) with the wrapper (keep the doc comment + exact signature `(&self, plain: &[u8]) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(plain);
        let action = flowplane_core::datapath::process_wan_rx(
            &mut pkt,
            &self.maps,
            &flowplane_core::datapath::WanRxIn { local: &self.local },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove any now-unused imports in `sim.rs` (e.g. the inner `use flowplane_core::encap::ETH_LEN;` in the old method, and `lb_select_forward_v6`/`lb_select_forward` if they become unused there — clippy will flag). Do NOT change any other method.

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim 2>&1 | tail -5` → ALL 69 pass (the fabric N-S / WAN-VIP tests that drive `wan_rx` are the witnesses). If any differ, fix the move (the only intended change is malformed-input panic→Drop).

- [ ] **Step 4: DPDK parity anchor `flowplane/nfkit/tests/parity_wan_rx.rs`** — model on `parity_uplink.rs` (EAL-once, `--test-threads=1`, `--file-prefix nfkit_pwr`, `mp_bytes` helper). Adapt `run_dpdk`/`run_sim` to call `process_wan_rx` with `maps: &M` and a `WanRxIn`. Populate `MemMaps` + `DpdkMaps` identically with a WAN LB VIP (`vni = 0`) + a Maglev backend underlay via `add_lb`/`add_maglev` (sim: `lb.insert`/`maglev.insert`) — READ `flowplane-core/src/lb.rs:42-72` first so the v6 `LbKey`/`MaglevKey` you seed match what `lb_select_forward_v6` computes (and `:10-31` for v4). Three scenarios in ONE `#[test]`:
  - **(a) v4 VIP → IPIP encap:** build a plain `[Eth(0x0800)][IPv4][TCP]` frame to the VIP (etherparse `PacketBuilder::ethernet2(...).ipv4(...).tcp(...)`); assert `a_sim == Action::Redirect(uplink_ifindex)` (positive, before the byte-compare), `a_dpdk == a_sim`, `out_dpdk == out_sim`; sanity: `out_dpdk[ETH_LEN] >> 4 == 6` and `out_dpdk[ETH_LEN+24..ETH_LEN+40] == backend`.
  - **(b) v6 VIP → IPPROTO_IPV6 encap:** build a plain `[Eth(0x86DD)][IPv6][TCP]` frame to the v6 VIP; seed the LB/Maglev entries for the v6 select; assert `Redirect(uplink_ifindex)` + byte parity of the encapped output. (This is the first anchor exercising `inner_proto = 41`.)
  - **(c) no-VIP → Pass:** a frame whose dst/port is not a VIP (empty LB maps, or a non-matching dst); assert `Action::Pass` on both sides and `out_dpdk == out_sim == input frame` (pkt untouched).

Run: `cargo test -p nfkit --test parity_wan_rx -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` + `-p flowplane-sim` clean; fmt clean.

- [ ] **Step 5: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_wan_rx.rs
git commit -m "feat: extract process_wan_rx orchestrator (sim+DPDK share) + DPDK edge WAN-VIP byte-parity anchor"
```

---

## Definition of Done (M5)
- `cargo test -p nfkit -- --test-threads=1`: `parity_wan_rx` (v4/v6/pass) + all M3/M4 anchors pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim` passes UNCHANGED — the `wan_rx` refactor is byte-preserving.
- The `flowplane` `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained one fn + one In-struct, still `no_std`, still no DPDK dep; no new `Maps` trait method (no eBPF/`GlobalMaps` change).
- Default host build + existing tests untouched.

## Risks / notes
- **Byte-preservation gate** — Step 3 (69 sim tests green) is the acceptance test. The only intended behavioral change vs the old `edge_encap` path is malformed-input panic → graceful `Drop`; no valid sim test exercises that.
- **v6 key derivation** — seed the LB/Maglev maps with exactly what `lb_select_forward_v6` (`lb.rs:42-72`) computes from the v6 frame; a mismatch makes scenario (b) miss → Pass instead of Redirect (the positive-Action assert catches this).
- **`&M` read-only borrow** — `process_wan_rx` takes `maps: &M` (unlike the `&mut M` of `process_uplink`/`process_guest_tx`); the wrapper passes `&self.maps`.
