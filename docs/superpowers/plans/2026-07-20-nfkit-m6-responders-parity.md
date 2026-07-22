# nfkit M6 (final datapath) — ARP/ND + DHCPv4 responders on DPDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `MbufPkt::set_tail`, then port `SimNode::guest_arp_nd` + `guest_dhcp4` into shared generic `process_*` fns in `flowplane-core`, proving DPDK byte-parity — completing the datapath port.

**Architecture:** Same seam as M3-M5. One new `Pkt` primitive (`MbufPkt::set_tail`, the DHCP `adjust_tail` path), then verbatim moves of the two responder methods into `flowplane-core/src/datapath.rs`; sim methods become thin wrappers; eBPF untouched. `arp_nd` needs no maps; `dhcp4` takes read-only `&M`. No new `Maps` trait method.

**Tech Stack:** Rust, `dpdk-sys`/`nfkit` (M1/M2), `flowplane-core` traits+fns. Run all cargo inside `nix develop`.

**Context (grounded — I read these):**
- Spec: `docs/superpowers/specs/2026-07-20-nfkit-m6-responders-parity-design.md`.
- `Pkt::set_tail(&mut self, new_len: usize) -> bool` default `false` at `flowplane-core/src/pkt.rs:53`. `VecPkt::set_tail` (`flowplane-sim/src/pkt.rs:70`) = `self.buf.resize(new_len, 0); self.logical_len = new_len; true` (zero-fills grown bytes).
- `MbufPkt` (`flowplane/nfkit/src/mbuf_pkt.rs`) has `data_len()` (`:28`) and `base() -> *mut u8` (`:34`); the `impl Pkt for MbufPkt` block ends ~`:91`. `grow_head`/`shrink_head` already call `dpdk_sys::nfkit_pktmbuf_prepend`/`_adj` on `self.raw` — mirror that style. Shim (M2): `nfkit_pktmbuf_append(m, len) -> *mut u8` (ptr to new region, NULL on no-tailroom), `nfkit_pktmbuf_trim(m, len) -> i32` (0 on success).
- `guest_arp_nd` body: `flowplane-sim/src/sim.rs:332-350`. `(&self, frame, meta, ingress_ifindex) -> SimOut`. Uses `flowplane_core::arp_nd::{arp_reply, nd_reply}` + `GW_MAC`; no maps, no set_tail.
- `guest_dhcp4` body: `flowplane-sim/src/sim.rs:360-391`. `(&self, frame, meta, ingress_ifindex) -> SimOut`. `dhcp::parse(&pkt)` (None→Pass) → `pkt.set_tail(dhcp::REPLY_LEN)` → `dhcp::write(&mut pkt, &req, meta.guest_ipv4, meta.gateway_ipv4, GW_MAC, &self.maps, ingress_ifindex)` → `Redirect(ingress_ifindex)` if ok else `Pass`.
- `dhcp::write<P: Pkt, M: Maps>` (`flowplane-core/src/dhcp.rs:204`) reads `maps.dhcp_config()` + `maps.dhcp_meta(ifindex)`. `dhcp::REPLY_LEN` is a `pub const` (`dhcp.rs:78`). `dhcp::parse<P>` (`:103`).
- `datapath.rs` (M3-M5) already imports `GW_MAC`, `Action`, `Pkt`, `Maps`. Add `use crate::arp_nd::{arp_reply, nd_reply};` and `use crate::dhcp;` as needed.
- `DpdkMaps` already supports DHCP: `set_dhcp_config`/`add_dhcp_meta` setters + `dhcp_config()`/`dhcp_meta()` trait impls (`flowplane/nfkit/src/dpdk_maps.rs`).
- Fixtures: `flowplane-sim/src/arp_nd_test.rs` (`arp_request_frame()`, `ns_frame()`, `port_meta()`, `INGRESS_IFINDEX`); `flowplane-sim/src/dhcp_test.rs` (the DISCOVER frame builder, `port_meta()`, `INGRESS_IFINDEX`, and how it seeds `DHCP_CONFIG`/`DHCP_META`). Anchor model: `flowplane/nfkit/tests/parity_uplink.rs`. `nfkit/Cargo.toml` has `etherparse` + `flowplane-sim` dev-deps.

**Absolute rules:**
- Run cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook active; if the rustup `cargo fmt` shim prints usage, format touched files with `rustfmt --edition 2021 <files>`.
- Tasks 2/3 extractions are **VERBATIM MOVES**. Acceptance = full `flowplane-sim` suite (69 tests) stays green. If any sim test changes, fix the move, never the test.

---

## File Structure
- `flowplane/nfkit/src/mbuf_pkt.rs` — `+ MbufPkt::set_tail`.
- `flowplane/nfkit/tests/mbuf_pkt.rs` — `+ set_tail` byte-parity case.
- `flowplane/flowplane-core/src/datapath.rs` — `+ process_guest_arp_nd`, `+ process_guest_dhcp4` (+ In-structs).
- `flowplane/flowplane-sim/src/sim.rs` — the two methods → thin wrappers.
- `flowplane/nfkit/tests/parity_arp_nd.rs`, `flowplane/nfkit/tests/parity_dhcp4.rs` — new anchors.

---

## Task 1: Implement `MbufPkt::set_tail` (grow zero-fill / shrink)

**Files:** Modify `flowplane/nfkit/src/mbuf_pkt.rs`; modify `flowplane/nfkit/tests/mbuf_pkt.rs`.

- [ ] **Step 1: Write the failing test** — append to `flowplane/nfkit/tests/mbuf_pkt.rs` a case (add to the existing `#[test]` that already inits EAL + a Mempool, OR a new test — but EAL inits once, so prefer extending the existing test; check the file). Assert `MbufPkt::set_tail` matches `VecPkt::set_tail` byte-for-byte:
```rust
    // set_tail parity vs VecPkt: grow zero-fills, shrink truncates, equal is a no-op.
    // Build an mbuf with 8 known bytes, and a VecPkt with the same, then resize both identically.
    let mut vp = flowplane_sim::VecPkt::from_bytes(&[10, 11, 12, 13, 14, 15, 16, 17]);
    // grow to 16: new tail must be zero on BOTH.
    assert!(p.set_tail(16));       // p is the MbufPkt over an 8-byte mbuf
    assert!(vp.set_tail(16));
    assert_eq!(p.len(), 16);
    let mut got = [0u8; 16];
    for i in 0..16 { got[i] = p.read_array::<1>(i).unwrap()[0]; }
    assert_eq!(&got[..8], &[10, 11, 12, 13, 14, 15, 16, 17]);
    assert_eq!(&got[8..], &[0u8; 8], "grown tail is zero-filled (matches VecPkt)");
    assert_eq!(got.to_vec(), vp.into_bytes());
    // shrink to 4.
    assert!(p.set_tail(4));
    assert_eq!(p.len(), 4);
    assert_eq!(p.read_array::<4>(0), Some([10, 11, 12, 13]));
```
(Adapt to how the existing `mbuf_pkt.rs` test builds `p`/the mbuf — it loads 8 bytes via `mb.append(8)` + copy. Build the MbufPkt over a fresh 8-byte mbuf for this case so the offsets match. `flowplane-sim` is already a dev-dep.) Run to FAIL (set_tail currently returns the default `false`).

- [ ] **Step 2: Implement `MbufPkt::set_tail`** — in the `impl Pkt for MbufPkt` block (`flowplane/nfkit/src/mbuf_pkt.rs`), override the default:
```rust
    #[inline]
    fn set_tail(&mut self, new_len: usize) -> bool {
        let cur = self.data_len();
        match new_len.cmp(&cur) {
            core::cmp::Ordering::Greater => {
                let delta = new_len - cur;
                // SAFETY: append returns a pointer to `delta` new bytes within the (single-segment)
                // dataroom, or NULL if there's no tailroom. Zero-fill them to match VecPkt::set_tail
                // (buf.resize(_, 0)) — mbuf tailroom holds stale mempool bytes.
                let p = unsafe { dpdk_sys::nfkit_pktmbuf_append(self.raw, delta as u16) };
                if p.is_null() {
                    return false;
                }
                unsafe { core::ptr::write_bytes(p, 0u8, delta) };
                true
            }
            core::cmp::Ordering::Less => {
                let delta = cur - new_len;
                // SAFETY: trim removes `delta` bytes off the tail; returns 0 on success.
                unsafe { dpdk_sys::nfkit_pktmbuf_trim(self.raw, delta as u16) == 0 }
            }
            core::cmp::Ordering::Equal => true,
        }
    }
```
(If `nfkit_pktmbuf_trim`'s bindgen return type differs, match it — grep the generated bindings; it's declared `int` in the shim. If `std` is unavailable in this crate use `core::`; nfkit is `std`, so `std::ptr::write_bytes` is fine too.) Run: `cargo test -p nfkit --test mbuf_pkt -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` clean; fmt clean.

- [ ] **Step 3: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/nfkit/src/mbuf_pkt.rs flowplane/nfkit/tests/mbuf_pkt.rs
git commit -m "feat(nfkit): MbufPkt::set_tail (grow zero-fill / shrink) — the DHCP adjust_tail primitive"
```

---

## Task 2: Extract `process_guest_arp_nd` + DPDK parity

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; create `flowplane/nfkit/tests/parity_arp_nd.rs`.

- [ ] **Step 1: Extract the orchestrator (verbatim move, no maps)** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_guest_arp_nd`]. Gateway is advertised at the shared router MAC `GW_MAC`.
pub struct GuestArpNdIn {
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub ingress_ifindex: u32,
}

/// Guest-facing ARP/ND gateway responder, in place on `pkt`. Mirrors the eBPF `try_guest_tx` head:
/// ARP request for the gateway → ARP reply, else ICMPv6 NS for the gateway → NA, both from `GW_MAC`;
/// on a hit `Redirect(ingress_ifindex)`, else `Pass`.
pub fn process_guest_arp_nd<P: Pkt>(pkt: &mut P, in_: &GuestArpNdIn) -> Action {
    if arp_reply(pkt, in_.gateway_ipv4, GW_MAC) || nd_reply(pkt, in_.gateway_ipv6, GW_MAC) {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}
```
Add `use crate::arp_nd::{arp_reply, nd_reply};` to the imports. Build `cargo build -p flowplane-core`.

- [ ] **Step 2: Rewire `SimNode::guest_arp_nd`** — replace its body (`flowplane-sim/src/sim.rs`) with the wrapper (keep doc + exact signature `(&self, frame: &[u8], meta: &PortMeta, ingress_ifindex: u32) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_arp_nd(
            &mut pkt,
            &flowplane_core::datapath::GuestArpNdIn {
                gateway_ipv4: meta.gateway_ipv4,
                gateway_ipv6: meta.gateway_ipv6,
                ingress_ifindex,
            },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove the now-unused inner `use flowplane_core::arp_nd::{arp_reply, nd_reply};`.

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim 2>&1 | tail -5` → ALL 69 pass (`arp_nd_test.rs` cases are the witnesses). Fix the move if any differ.

- [ ] **Step 4: DPDK parity anchor `flowplane/nfkit/tests/parity_arp_nd.rs`** — model on `parity_uplink.rs` (EAL-once, `--test-threads=1`, `--file-prefix nfkit_pan`, `mp_bytes` helper; NO maps needed — write map-less runners calling `process_guest_arp_nd(&mut pkt, &in_)`). Reuse the `arp_nd_test.rs` fixtures (`arp_request_frame()`, `ns_frame()`, `port_meta()`, `INGRESS_IFINDEX`) — read that file for the exact frame builders + the gateway IPs in `port_meta`. Three scenarios in one `#[test]`:
  - (a) ARP request → reply: assert `Action::Redirect(INGRESS_IFINDEX)` (positive, before byte-compare) + `out_dpdk == out_sim`.
  - (b) ND NS → NA: assert `Redirect(INGRESS_IFINDEX)` + byte parity.
  - (c) a plain non-ARP/ND frame (e.g. an IPv4 UDP frame): assert `Action::Pass` + `out_dpdk == out_sim == input`.

Run: `cargo test -p nfkit --test parity_arp_nd -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` + `-p flowplane-sim` clean; fmt clean.

- [ ] **Step 5: Commit**
```bash
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_arp_nd.rs
git commit -m "feat: extract process_guest_arp_nd (sim+DPDK share) + DPDK ARP/ND byte-parity anchor"
```

---

## Task 3: Extract `process_guest_dhcp4` + DPDK parity (exercises set_tail)

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; create `flowplane/nfkit/tests/parity_dhcp4.rs`.

- [ ] **Step 1: Extract the orchestrator (verbatim move, read-only maps)** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_guest_dhcp4`]. The assigned/gateway IPv4 + reply MTU/DNS/host come from
/// `meta` + the node's `DHCP_CONFIG`/`DHCP_META[ingress_ifindex]`.
pub struct GuestDhcp4In {
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub ingress_ifindex: u32,
}

/// Guest DHCPv4 responder, in place on `pkt`. Mirrors the eBPF `guest_dhcp` glue: parse the
/// DISCOVER/REQUEST (Pass on non-DHCP), resize to the constant `dhcp::REPLY_LEN` (`adjust_tail`), then
/// write the fixed OFFER/ACK; `Redirect(ingress_ifindex)` on success else `Pass`.
pub fn process_guest_dhcp4<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &GuestDhcp4In) -> Action {
    let req = match dhcp::parse(&*pkt) {
        Some(r) => r,
        None => return Action::Pass,
    };
    pkt.set_tail(dhcp::REPLY_LEN);
    let ok = dhcp::write(
        pkt,
        &req,
        in_.guest_ipv4,
        in_.gateway_ipv4,
        GW_MAC,
        maps,
        in_.ingress_ifindex,
    );
    if ok {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}
```
Add `use crate::dhcp;` to the imports. Build `cargo build -p flowplane-core`. (Confirm the exact `dhcp::write` arg order against `dhcp.rs:204` — the plan mirrors `sim.rs:374`; if it differs, match the real signature.)

- [ ] **Step 2: Rewire `SimNode::guest_dhcp4`** — replace its body with the wrapper (keep doc + exact signature `(&self, frame: &[u8], meta: &PortMeta, ingress_ifindex: u32) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_dhcp4(
            &mut pkt,
            &self.maps,
            &flowplane_core::datapath::GuestDhcp4In {
                guest_ipv4: meta.guest_ipv4,
                gateway_ipv4: meta.gateway_ipv4,
                ingress_ifindex,
            },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove the now-unused inner `use flowplane_core::dhcp;`.

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim 2>&1 | tail -5` → ALL 69 pass (`dhcp_test.rs` cases are the witnesses; they assert the full OFFER/ACK bytes). Fix the move if any differ.

- [ ] **Step 4: DPDK parity anchor `flowplane/nfkit/tests/parity_dhcp4.rs`** — model on `parity_uplink.rs` (EAL-once, `--test-threads=1`, `--file-prefix nfkit_pd4`, `mp_bytes`; runners take `maps: &M`). READ `flowplane-sim/src/dhcp_test.rs` for the DISCOVER frame builder + the `DHCP_CONFIG`/`DHCP_META` contents it installs + `port_meta()`/`INGRESS_IFINDEX`. Seed `MemMaps` + `DpdkMaps` IDENTICALLY (`set_dhcp_config` + `add_dhcp_meta(INGRESS_IFINDEX, ...)`). Scenario: DISCOVER (shorter than `REPLY_LEN`) → OFFER — assert `Action::Redirect(INGRESS_IFINDEX)` (positive, before byte-compare) + **full-frame byte parity** `out_dpdk == out_sim` (this forces `MbufPkt::set_tail`'s zero-filling grow and compares the whole `REPLY_LEN` frame, catching any tail-padding divergence). Optionally add a non-DHCP → `Pass` case.

Run: `cargo test -p nfkit --test parity_dhcp4 -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` + `-p flowplane-sim` clean; fmt clean.

- [ ] **Step 5: Commit**
```bash
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_dhcp4.rs
git commit -m "feat: extract process_guest_dhcp4 (sim+DPDK share) + DPDK DHCPv4 byte-parity anchor (exercises set_tail)"
```

---

## Definition of Done (M6)
- `cargo test -p nfkit -- --test-threads=1`: `mbuf_pkt` (with set_tail), `parity_arp_nd`, `parity_dhcp4`, + all M3-M5 anchors pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim` passes UNCHANGED — the two refactors are byte-preserving.
- The `flowplane` `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained two fns + two In-structs, still `no_std`, still no DPDK dep; no new `Maps` trait method (no eBPF change).
- `MbufPkt::set_tail` implemented + parity-tested.
- **Datapath fully ported to DPDK** (uplink, guest-egress, NAT return, NAT64 egress/ingress, WAN-VIP, ARP/ND, DHCPv4).

## Risks / notes
- **set_tail zero-fill** (Task 1) is the parity-critical detail — the `parity_dhcp4` full-frame compare (Task 3) is its real integration witness; the `mbuf_pkt.rs` unit test is the direct one.
- **Verbatim moves** — Tasks 2/3 Step 3 (69 sim tests green) is the acceptance test.
- **DHCP fixture reuse** — seed `DHCP_CONFIG`/`DHCP_META` exactly as `dhcp_test.rs` does; the writer pulls MTU/DNS/hostname from them, so a mismatch changes bytes → the anchor would fail (correctly).
