# nfkit M4 — NAT-family datapath on DPDK (NAT return + NAT64) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `uplink_nat_return`, `uplink_nat64_ingress`, and `guest_tx_nat64` from `SimNode` into shared generic `process_*` fns in `flowplane-core`, and prove each runs byte-identically on DPDK (`MbufPkt`+`DpdkMaps`) vs the sim (`VecPkt`+`MemMaps`).

**Architecture:** Same seam as M3 — extract each `SimNode` method body VERBATIM into a generic `flowplane-core/src/datapath.rs` fn; the `SimNode` method becomes a thin wrapper; the eBPF dataplane is untouched (still anchored to the sim). One new `Maps` trait method (`is_nat_ip`) unblocks `uplink_nat_return`. Parity is reduced to "does `MbufPkt`/`DpdkMaps` behave like `VecPkt`/`MemMaps`", tested directly.

**Tech Stack:** Rust (repo nightly), `dpdk-sys`/`nfkit` (M1/M2/M3), `flowplane-core` traits+fns, `rte_hash`. Run all cargo inside `nix develop`.

**Context (grounded — I read these):**
- Spec: `docs/superpowers/specs/2026-07-20-nfkit-m4-nat-family-parity-design.md`.
- M3 established `flowplane-core/src/datapath.rs` with `process_uplink`/`process_guest_tx` + `UplinkIn`/`GuestTxIn`/`GuestTxOut`. It imports `GW_MAC`, `ETH_LEN`, `IPV6_LEN`, `write_outer_v6`, `EncapParams`, `route4`, `ct_key`, `ct_create_default`, `decap_and_rewrite`, `fw_eval_dir`, etc. **Reuse those imports; add only what's new.**
- The three `SimNode` methods to extract (`flowplane-sim/src/sim.rs`): `uplink_nat_return` (143-179), `uplink_nat64_ingress` (349-397), `guest_tx_nat64` (265-330). Read each in full before moving it.
- `nat64_egress_parse`/`nat64_ingress_parse`/`nat64_egress_write`/`nat64_ingress_write` live in `flowplane-core/src/nat64.rs`; `ct_apply` in `flowplane-core/src/conntrack.rs`; `CT_REWRITE_DST` in `flowplane-common`.
- `nat64_egress_parse<P,M: Maps>` uses ONLY trait methods (`nat_get`/`conntrack_get`/`conntrack_insert`) — verified (`nat64.rs:333`). `route4(&M, vni, dst)` is a core free fn (already used inside the M3 `process_guest_tx`).
- Fixtures: DNAT return in `flowplane-sim/src/nat_test.rs` (`DNAT_VNI`/`DNAT_TAP`/`DNAT_GUEST_MAC`/`DNAT_NAT_IP`, `dnat_reverse_ct_entry()`, `dnat_reverse_ct_key(proto)`, the returning-frame builder + `nat_ips.insert`). NAT64 in `flowplane-sim/src/nat64_test.rs` (`tcp_frame()`/`udp_frame()`/`port_meta()` for egress; `rev_ct(SPORT)`/`TAP_IFINDEX`/`GUEST_MAC`/`GUEST_IP6` + the `[Eth][outerIPv6][innerIPv4][L4]` frame builder for ingress).
- M3 anchors to model on: `flowplane/nfkit/tests/parity_uplink.rs`, `parity_guest_tx.rs` (the `mp_bytes`/`run_dpdk`/`run_sim` helpers, EAL-once, `--test-threads=1`, identical-map population). `nfkit/Cargo.toml` already has `etherparse` + `flowplane-sim` dev-deps.
- `DpdkMaps` (`flowplane/nfkit/src/dpdk_maps.rs`) already has `conntrack`/`nat`/`route4`/`underlay`/`fw_*` hashes + setters (`add_route4`/`add_underlay`/`add_nat`/`set_local`/…) and compile-time key-size asserts. It will gain a `nat_ips` hash + `is_nat_ip` + `add_nat_ip`.

**Absolute rules (all tasks):**
- Run cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook is active; if the rustup `cargo fmt` shim misbehaves, format touched files with `rustfmt --edition 2021 <files>`.
- Every extraction (Tasks 2-4) is a **VERBATIM MOVE**. Acceptance = the full `flowplane-sim` suite stays green. If any sim test changes result, the move was not verbatim — fix the move, never the test.

---

## File Structure
- `flowplane/flowplane-core/src/maps.rs` — `+ fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool;` on the `Maps` trait.
- `flowplane/flowplane-core/src/datapath.rs` — `+ process_uplink_nat_return`, `+ process_uplink_nat64_ingress`, `+ process_guest_tx_nat64` (+ their In-structs).
- `flowplane/flowplane-sim/src/maps.rs` — `MemMaps::is_nat_ip` delegates to `nat_ips`.
- `flowplane/flowplane-sim/src/sim.rs` — the three methods become thin wrappers.
- `flowplane/nfkit/src/dpdk_maps.rs` — `NatIpKey`, `nat_ips: DpdkHash<NatIpKey,u8>`, `is_nat_ip`, `add_nat_ip`.
- `flowplane/nfkit/tests/parity_nat_return.rs`, `flowplane/nfkit/tests/parity_nat64.rs` — new anchors.
- `flowplane/nfkit/tests/dpdk_maps.rs` — extend with an `is_nat_ip` assertion.

---

## Task 1: `Maps::is_nat_ip` trait method + MemMaps + DpdkMaps backing

**Files:** Modify `flowplane-core/src/maps.rs`, `flowplane-sim/src/maps.rs`, `flowplane/nfkit/src/dpdk_maps.rs`, `flowplane/nfkit/tests/dpdk_maps.rs`.

- [ ] **Step 1: Add the trait method** — in `flowplane-core/src/maps.rs`, add to the `Maps` trait (after `nat_get`):
```rust
    /// Is `(vni, ip)` a registered public NAT IP (the `NAT_IPS` set)? NAT returns are demuxed
    /// peer-independently: when the inner dst is a registered nat_ip, the external src ip+port are
    /// zeroed so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)` reverse entry.
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool;
```
Build: `cargo build -p flowplane-core` — FAILS to compile (`MemMaps` no longer satisfies `Maps`). Expected.

- [ ] **Step 2: Implement `MemMaps::is_nat_ip`** — in `flowplane-sim/src/maps.rs`, inside `impl Maps for MemMaps`:
```rust
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.nat_ips.contains(&(vni, *ip))
    }
```
Build: `cargo build -p flowplane-sim` passes; `cargo test -p flowplane-sim` — all still green (new method, no new call site).

- [ ] **Step 3: Write the failing DpdkMaps test** — append to `flowplane/nfkit/tests/dpdk_maps.rs` a case inside a fresh `#[test]` (or extend an existing one that already inits EAL — check the file; EAL inits once, so add an assertion block to the existing test rather than a second `Eal::init`):
```rust
    // is_nat_ip: add → hit; wrong vni/ip → miss.
    assert!(!m.is_nat_ip(7, &[100, 64, 0, 1]));
    m.add_nat_ip(7, [100, 64, 0, 1]);
    assert!(m.is_nat_ip(7, &[100, 64, 0, 1]));
    assert!(!m.is_nat_ip(8, &[100, 64, 0, 1]), "wrong vni misses");
    assert!(!m.is_nat_ip(7, &[100, 64, 0, 2]), "wrong ip misses");
```
(Use the `Maps` trait import already in the file; `m` is the `DpdkMaps` the test builds.) Run to FAIL (`add_nat_ip`/`is_nat_ip` don't exist).

- [ ] **Step 4: Implement in `DpdkMaps`** — in `flowplane/nfkit/src/dpdk_maps.rs`:
  1. Add the key type near the other composite keys (e.g. `Route4Key`):
```rust
#[derive(Copy, Clone)]
#[repr(C)]
struct NatIpKey {
    vni: u32,
    ipv4: [u8; 4],
}
const _: () = assert!(core::mem::size_of::<NatIpKey>() == 8); // no padding
```
  2. Add the field to the `DpdkMaps` struct: `nat_ips: DpdkHash<NatIpKey, u8>,`.
  3. In `DpdkMaps::new(...)`, create it with a sensible capacity (e.g. `DpdkHash::new("nat_ips", 4096, socket_id)?`) alongside the other hashes.
  4. Add the trait method inside `impl Maps for DpdkMaps`:
```rust
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.nat_ips.get(&NatIpKey { vni, ipv4: *ip }).is_some()
    }
```
  5. Add the test-only setter (near the other `add_*` setters):
```rust
    /// Register `(vni, ip)` as a public NAT IP (mirrors `MemMaps.nat_ips.insert`).
    pub fn add_nat_ip(&mut self, vni: u32, ip: [u8; 4]) {
        self.nat_ips.insert(&NatIpKey { vni, ipv4: ip }, 1);
    }
```
Run: `cargo test -p nfkit --test dpdk_maps -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` clean; fmt clean.

- [ ] **Step 5: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/flowplane-core/src/maps.rs flowplane/flowplane-sim/src/maps.rs flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/tests/dpdk_maps.rs
git commit -m "feat: Maps::is_nat_ip trait method (MemMaps + DpdkMaps NAT_IPS-backed)"
```

---

## Task 2: Extract `process_uplink_nat_return` + DPDK parity

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; create `flowplane/nfkit/tests/parity_nat_return.rs`.

- [ ] **Step 1: Extract the orchestrator (verbatim move)** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_uplink_nat_return`]. `u`'s base tap becomes the delivery ifindex.
pub struct UplinkNatReturnIn {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
}

/// Host NAT reverse-DNAT return path, in place on `pkt`. Mirrors the eBPF `try_uplink_rx` NAT branch:
/// build the inner 5-tuple key (demuxed peer-independently when the inner dst is a registered nat_ip);
/// reverse-DNAT apply when the matched CT entry carries `CT_REWRITE_DST`; decap + inner-Eth rewrite.
pub fn process_uplink_nat_return<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &UplinkNatReturnIn,
) -> Action {
    // <<< VERBATIM body of SimNode::uplink_nat_return (sim.rs:153-178), with substitutions:
    //     - `let inner_off = ETH_LEN + IPV6_LEN;` (imports already present)
    //     - drop `let mut pkt = VecPkt::from_bytes(encapped);` (pkt is a param)
    //     - `self.maps.nat_ips.contains(&(vni, key.dst_ip))` -> `maps.is_nat_ip(in_.vni, &key.dst_ip)`
    //     - `self.maps.conntrack_get(&key)` -> `maps.conntrack_get(&key)`
    //     - `ct_key(&pkt, inner_off, vni)` -> `ct_key(&*pkt, inner_off, in_.vni)`
    //     - `ct_apply(&mut pkt, inner_off, &e)` -> `ct_apply(pkt, inner_off, &e)`
    //     - `decap_and_rewrite(&mut pkt, u.tap_ifindex, guest_mac)` -> `decap_and_rewrite(pkt, in_.tap_ifindex, in_.guest_mac)`
    //     - return `Action` (not SimOut). >>>
}
```
Add the imports it needs at the top of `datapath.rs` if not already present: `use crate::conntrack::ct_apply;` and `use flowplane_common::CT_REWRITE_DST;` (`ct_key`/`decap_and_rewrite`/`ETH_LEN`/`IPV6_LEN` are already imported from M3). Build `cargo build -p flowplane-core`.

- [ ] **Step 2: Rewire `SimNode::uplink_nat_return`** — replace its body (`flowplane-sim/src/sim.rs`) with the thin wrapper (keep the doc comment + the exact signature `(&mut self, encapped: &[u8], vni: u32, u: UnderlayValue, guest_mac: [u8; 6]) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(encapped);
        let action = flowplane_core::datapath::process_uplink_nat_return(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::UplinkNatReturnIn {
                vni,
                tap_ifindex: u.tap_ifindex,
                guest_mac,
            },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove the now-unused `use flowplane_common::CT_REWRITE_DST; use flowplane_core::conntrack::ct_apply;` from inside the method (clippy will flag).

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim` → ALL pass (the `nat_test.rs` DNAT-return cases are the witnesses). If any differ, fix the move.

- [ ] **Step 4: DPDK parity anchor `flowplane/nfkit/tests/parity_nat_return.rs`** — model on `parity_uplink.rs`. Build the returning encapped frame + reverse CT + nat_ip from the `nat_test.rs` DNAT fixture values (`DNAT_VNI`/`DNAT_TAP`/`DNAT_GUEST_MAC`/`DNAT_NAT_IP`/`DNAT_ORIG_SPORT`/`DNAT_NAT_PORT`/`DNAT_EXT_IP`/`DNAT_EXT_PORT`; the reverse entry has `flags = CT_REWRITE_DST | CT_F_SRC_NAT`, `xlate_ip = DNAT_GUEST_IP`, `xlate_port = DNAT_ORIG_SPORT`). Populate BOTH `MemMaps` and `DpdkMaps` identically: the reverse CT entry under the peer-independent key `(vni=DNAT_VNI, src_ip=0, src_port=0, dst_ip=DNAT_NAT_IP, dst_port=DNAT_NAT_PORT, proto=6)` via `conntrack_insert`, plus `add_nat_ip(DNAT_VNI, DNAT_NAT_IP)` (sim: `nat_ips.insert`). Build the inner returning IPv4 frame (ext_ip:443 → nat_ip:nat_port) with etherparse, encap it via `SimNode::edge_encap` toward a host underlay. Assert `process_uplink_nat_return` over `MbufPkt`+`DpdkMaps` == over `VecPkt`+`MemMaps`: byte-identical output + `Action::Redirect(DNAT_TAP)` (a POSITIVE delivery — assert it before the byte-compare, guarding against a trivial both-drop). Reuse `mp_bytes`/`run_dpdk`/`run_sim` (copy the helper pattern from parity_uplink, adapted to `process_uplink_nat_return`/`UplinkNatReturnIn`). EAL init once, `--test-threads=1`, `--file-prefix nfkit_pnr`.

Run: `cargo test -p nfkit --test parity_nat_return -- --test-threads=1` → PASS. clippy/fmt clean.

- [ ] **Step 5: Commit**
```bash
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_nat_return.rs
git commit -m "feat: extract process_uplink_nat_return (sim+DPDK share) + DPDK NAT-return byte-parity anchor"
```

---

## Task 3: Extract `process_uplink_nat64_ingress` (no-maps) + DPDK parity (ingress)

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; create `flowplane/nfkit/tests/parity_nat64.rs`.

- [ ] **Step 1: Extract the orchestrator (verbatim move, NO `Maps`)** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_uplink_nat64_ingress`]. `rev` is the reverse `CT_F_NAT64` conntrack entry the
/// caller already resolved (restores the guest IPv4 dst + orig L4 port); this fn takes no `Maps`.
pub struct UplinkNat64IngressIn<'a> {
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
    pub guest_ipv6: [u8; 16],
    pub rev: &'a flowplane_common::CtEntry,
}

/// Host NAT64 ingress reply path, in place on `pkt`. Mirrors the eBPF ingress `nat64_ingress`:
/// reverse `ct_apply` → `nat64_ingress_parse` (Pass on miss) → `shrink_head(20)` → `nat64_ingress_write`.
pub fn process_uplink_nat64_ingress<P: Pkt>(pkt: &mut P, in_: &UplinkNat64IngressIn) -> Action {
    // <<< VERBATIM body of SimNode::uplink_nat64_ingress (sim.rs:359-396), with substitutions:
    //     - `let inner_off = ETH_LEN + IPV6_LEN;`
    //     - drop `let mut pkt = VecPkt::from_bytes(encapped);`
    //     - `let orig_sport = rev.xlate_port;` -> `let orig_sport = in_.rev.xlate_port;`
    //     - `ct_apply(&mut pkt, inner_off, rev)` -> `ct_apply(pkt, inner_off, in_.rev)`
    //     - `nat64_ingress_parse(&pkt, inner_off, guest_ipv6, guest_mac, orig_sport)` ->
    //       `nat64_ingress_parse(&*pkt, inner_off, in_.guest_ipv6, in_.guest_mac, orig_sport)`
    //     - `pkt.shrink_head(20)` unchanged
    //     - `nat64_ingress_write(&mut pkt, ETH_LEN, GW_MAC, &xlate)` -> `nat64_ingress_write(pkt, ETH_LEN, GW_MAC, &xlate)`
    //     - `Action::Redirect(tap_ifindex)` -> `Action::Redirect(in_.tap_ifindex)`
    //     - return `Action` (not SimOut). >>>
}
```
Add imports if missing: `use crate::nat64::{nat64_ingress_parse, nat64_ingress_write};` (`ct_apply`/`GW_MAC`/`ETH_LEN`/`IPV6_LEN` already present after Task 2 / M3). Build `cargo build -p flowplane-core`.

- [ ] **Step 2: Rewire `SimNode::uplink_nat64_ingress`** — replace its body with the wrapper (keep doc + signature `(&self, encapped: &[u8], tap_ifindex: u32, guest_mac: [u8; 6], guest_ipv6: [u8; 16], rev: &CtEntry) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(encapped);
        let action = flowplane_core::datapath::process_uplink_nat64_ingress(
            &mut pkt,
            &flowplane_core::datapath::UplinkNat64IngressIn {
                tap_ifindex,
                guest_mac,
                guest_ipv6,
                rev,
            },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove the now-unused inner `use flowplane_core::nat64::{...}` import.

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim` → ALL pass (`nat64_test.rs` ingress cases at 543/584/629/672 are the witnesses).

- [ ] **Step 4: DPDK parity anchor — ingress scenario in `flowplane/nfkit/tests/parity_nat64.rs`** — create the file with EAL-once + `mp_bytes`/`run_dpdk`/`run_sim` helpers adapted to the NAT64 fns. For the INGRESS scenario, replicate `nat64_test.rs`'s ingress fixture: build the `[Eth][outerIPv6][innerIPv4][L4]` returning frame + the reverse `CtEntry` via `rev_ct(SPORT)`, with `TAP_IFINDEX`/`GUEST_MAC`/`GUEST_IP6`. Since `process_uplink_nat64_ingress` takes NO maps, `run_dpdk`/`run_sim` for this scenario call it with just the pkt + In-struct (construct a `DpdkMaps`/`MemMaps` only if your shared helper signature needs one — the fn ignores it; simplest is a NAT64-specific pair of tiny runners that skip maps). Assert byte-identical output + `Action::Redirect(TAP_IFINDEX)` (positive) between `MbufPkt` and `VecPkt`. `--file-prefix nfkit_pn64`.

Run: `cargo test -p nfkit --test parity_nat64 -- --test-threads=1` → PASS (ingress scenario). clippy/fmt clean.

- [ ] **Step 5: Commit**
```bash
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_nat64.rs
git commit -m "feat: extract process_uplink_nat64_ingress (sim+DPDK share) + DPDK NAT64-ingress byte-parity anchor"
```

---

## Task 4: Extract `process_guest_tx_nat64` + DPDK parity (egress, port-alloc parity)

**Files:** Modify `flowplane-core/src/datapath.rs`, `flowplane-sim/src/sim.rs`; extend `flowplane/nfkit/tests/parity_nat64.rs`.

- [ ] **Step 1: Extract the orchestrator (verbatim move)** — add to `flowplane-core/src/datapath.rs`:
```rust
/// Inputs for [`process_guest_tx_nat64`]. `local` supplies the outer MACs/ifindex for the encap;
/// `meta` supplies the vni + guest IPv4 (NAT key) + underlay src.
pub struct GuestTxNat64In<'a> {
    pub meta: &'a flowplane_common::PortMeta,
    pub local: &'a flowplane_common::Local,
}

/// Guest NAT64 egress path, in place on `pkt`. Mirrors the eBPF `nat64_egress`: parse (config +
/// port-alloc + CT_F_NAT64 pins) → `shrink_head(20)` (v6→v4) → `nat64_egress_write` → route4 (Pass on
/// miss) → `grow_head(IPV6_LEN)`+`write_outer_v6` encap toward the nexthop.
pub fn process_guest_tx_nat64<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &GuestTxNat64In,
) -> Action {
    // <<< VERBATIM body of SimNode::guest_tx_nat64 (sim.rs:268-329), with substitutions:
    //     - `let ip6_off = ETH_LEN;`
    //     - drop `let mut pkt = VecPkt::from_bytes(frame);`
    //     - `nat64_egress_parse(&pkt, &mut self.maps, ip6_off, meta.vni, meta.guest_ipv4, 0)` ->
    //       `nat64_egress_parse(&*pkt, maps, ip6_off, in_.meta.vni, in_.meta.guest_ipv4, 0)`
    //     - `nat64_egress_write(&mut pkt, ETH_LEN, true, &xlate)` -> `nat64_egress_write(pkt, ETH_LEN, true, &xlate)`
    //     - `route4(&self.maps, meta.vni, &xlate.ipv4_dst)` -> `route4(&*maps, in_.meta.vni, &xlate.ipv4_dst)`
    //     - EncapParams: `self.local.gateway_mac/uplink_mac/uplink_ifindex` -> `in_.local.*`;
    //       `meta.underlay_ipv6` -> `in_.meta.underlay_ipv6`; `route.nexthop_ipv6` unchanged.
    //     - `pkt.grow_head(IPV6_LEN) || write_outer_v6(&mut pkt, &e)` -> `... || write_outer_v6(pkt, &e)`
    //     - `Action::Redirect(self.local.uplink_ifindex)` -> `Action::Redirect(in_.local.uplink_ifindex)`
    //     - return `Action` (not SimOut). >>>
}
```
Add imports if missing: `use crate::nat64::{nat64_egress_parse, nat64_egress_write};` (`route4`/`EncapParams`/`write_outer_v6`/`IPPROTO_IPIP`/`IPV6_LEN`/`ETH_LEN` already present from M3). Build `cargo build -p flowplane-core`.

- [ ] **Step 2: Rewire `SimNode::guest_tx_nat64`** — replace its body with the wrapper (keep doc + signature `(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut`):
```rust
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_tx_nat64(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::GuestTxNat64In { meta, local: &self.local },
        );
        SimOut { action, pkt: pkt.into_bytes() }
```
Remove the now-unused inner `use flowplane_core::nat64::{...}` import.

- [ ] **Step 3: Prove byte-preserving** — `cargo test -p flowplane-sim` → ALL pass (`nat64_test.rs` egress cases at 211/275/320/374 — TCP/UDP/ICMPv6/no-route — are the witnesses; they assert the allocated source port `EXPECTED_SPORT`, so a byte-preserving move keeps port allocation identical).

- [ ] **Step 4: DPDK parity anchor — egress scenario, extend `flowplane/nfkit/tests/parity_nat64.rs`** — add a second scenario (same EAL init) replicating the `nat64_test.rs` egress fixture: a guest `[Eth][IPv6][UDP or TCP]` frame with dst in `64:ff9b::/96` (`tcp_frame()`/`udp_frame()` layout + `port_meta()`), NAT config via `nat_get`/`add_nat`, a route4 with a nexthop underlay, `set_local`. Populate `MemMaps` and `DpdkMaps` IDENTICALLY (both start empty so the hash-probe port allocator lands on the same port). Assert byte-identical FULL encapped output (which embeds the allocated source port + exercises `shrink_head` AND `grow_head`) + `Action::Redirect(uplink_ifindex)` (positive) between `MbufPkt`+`DpdkMaps` and `VecPkt`+`MemMaps`. Add a sanity assert on the outer IPv6 version nibble + dst == nexthop (like parity_guest_tx).

Run: `cargo test -p nfkit --test parity_nat64 -- --test-threads=1` → PASS (both ingress + egress). clippy/fmt clean.

- [ ] **Step 5: Commit**
```bash
git add flowplane/flowplane-core/src/datapath.rs flowplane/flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_nat64.rs
git commit -m "feat: extract process_guest_tx_nat64 (sim+DPDK share) + DPDK NAT64-egress byte-parity anchor"
```

---

## Definition of Done (M4)
- `cargo test -p nfkit -- --test-threads=1`: existing M3 anchors + `dpdk_maps` (with is_nat_ip) + `parity_nat_return` + `parity_nat64` (ingress+egress) all pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim` passes UNCHANGED — the three `SimNode` refactors + `MemMaps::is_nat_ip` are byte-preserving (`nat_test.rs` + `nat64_test.rs` are the witnesses).
- The `flowplane` `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained one trait method + three fns, still `no_std`, still no DPDK dep.
- Default host build + existing tests untouched.

## Risks / notes
- **Verbatim extraction is mandatory** — each Task's Step 3 (sim suite green) is the acceptance test. If a `nat_test.rs`/`nat64_test.rs` case changes, the move was not verbatim.
- **`NatIpKey` layout** — 8 bytes, no padding; compile-time size assert added.
- **NAT64 egress source-port parity** — both map impls must start empty and be populated identically before `process_guest_tx_nat64`; asserting the full encapped frame catches any allocator divergence.
- **`process_uplink_nat64_ingress` is map-less** (`<P: Pkt>`, no `M`); its anchor must not require any `DpdkMaps` entries.
- **Fixture reuse** — read `nat_test.rs` (DNAT) + `nat64_test.rs` (NAT64) for exact frame builders + map contents so `DpdkMaps` populates identically; if a `DpdkMaps` setter is missing, adding a test-only one mirroring `MemMaps` is in scope; changing `Maps`-trait logic is not.
