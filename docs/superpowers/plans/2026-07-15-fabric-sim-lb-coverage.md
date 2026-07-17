# Fabric Sim + Comprehensive LB Coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the LB datapath into `flowplane-core`, add a `Fabric` multi-node sim abstraction, make `Compile()` synthesize allow-all for unpolicied NICs (deny-by-default posture), and drive the full E/W + N/S LB test matrix in-process — reproducing and pinning the "LB dropped by the backend firewall" behavior.

**Architecture:** One new pure core fn (`lb_select_forward`) + a ported `reforward` + a consolidated `uplink_dispatch` seam (fw + conntrack + LB-select + decap/reforward/deliver) that BOTH the eBPF `try_uplink_rx` and the sim call. A `Fabric` owns N `SimNode`s and an underlay→node table, auto-following encap/redirect across hops and returning a `Trace`. Firewall stays explicit-only; the control plane (`Compile()`) generates allow-all when unpolicied.

**Tech Stack:** Rust (`no_std` core, `flowplane-sim` std, `etherparse`), Go (controller-runtime), aya eBPF. Guards: `test/conformance/test_lb.py` + `test_flows.py`, a `BPF_PROG_TEST_RUN` anchor, `cargo test -p flowplane-sim`.

**Parent spec:** `docs/superpowers/specs/2026-07-15-fabric-sim-lb-coverage-design.md`

---

## Key existing facts (verified)

- `LbKey { vni:u32, ipv4:[u8;4], port:u16, proto:u8, _pad:u8 }`, `LbValue { table_id:u32, size:u32 }`, `MaglevKey { table_id:u32, slot:u32 }` — in `flowplane-common`. `MAGLEV` map value is **`[u8;16]`** (backend underlay; the `[u8;4]` doc comment is stale).
- eBPF `lb::lb_select_forward(ctx, ip_off, vni)`: reads inner dst@`ip_off+16`, src@`ip_off+12`, `l4_ports`; `lookup_port = if proto==1 {0} else {dport}`; `LB.get(LbKey{vni,dst,lookup_port,proto})`; if `size==0` → None; `slot = hash5(src,dst,sport,dport,proto) % size`; `MAGLEV.get(MaglevKey{table_id,slot})` → backend `[u8;16]`.
- eBPF `encap::reforward(ctx, local, lb_underlay, backend) -> u32`: bounds-check ETH+IPv6; rewrite outer eth (dst=`local.gateway_mac`, src=`local.uplink_mac`) + outer IPv6 (src=`lb_underlay`@`ETH_LEN+8`, dst=`backend`@`ETH_LEN+24`); `bpf_redirect(local.uplink_ifindex,0)`.
- `hash5(src:&[u8;4],dst:&[u8;4],sport:u16,dport:u16,proto:u8)->u32` in eBPF `parse.rs` (FNV; unrolled for the verifier — pure).
- eBPF `try_uplink_rx` (`ingress.rs`): resolves `u = UNDERLAY[outer_dst]` → `vni`; `lb_ul = lb_select_forward(...)`; branches (NAT64, neighbor-NAT, ICMP-echo) then base FW (245-262, already `flowplane_core::firewall::fw_eval_dir`) + conntrack (264-289, skipped for LB) + `decap_and_rewrite` (already `flowplane_core::uplink`).
- Sim today: `SimNode { maps: MemMaps }`, `SimOut { action, pkt }`, `edge_encap`, `host_uplink` (composes fw_eval_dir + ct_create_default + decap_and_rewrite). `MemMaps` public fields `local, underlay, fw_meta, fw_rules, conntrack, fw_enforcing`.
- `Compile(nic, policies)` (`netplane/controllers/compilednic.go`): copies identity; per matching `NetworkPolicy` appends ingress/egress `CompiledFwRule`s.

---

## File Structure

- `flowplane-core/src/maps.rs` — add `lb_get`/`maglev_get` to `Maps`.
- `flowplane-core/src/parse.rs` — add `hash5` (move canonical here; eBPF re-exports).
- `flowplane-core/src/lb.rs` (NEW) — `lb_select_forward<P,M>`.
- `flowplane-core/src/encap.rs` — add `reforward<P>`.
- `flowplane-core/src/uplink.rs` — add the consolidated `uplink_dispatch<P,M>` seam (fw+ct+lb+decap/reforward).
- `flowplane-ebpf/src/{coreimpl,parse,lb,encap,ingress}.rs` — `GlobalMaps` lb/maglev; re-export hash5; delegate `lb_select_forward`/`reforward`/`uplink_dispatch`.
- `flowplane-sim/src/maps.rs` — `MemMaps` gains `lb`, `maglev`.
- `flowplane-sim/src/fabric.rs` (NEW) — `Fabric`, `Hop`, `Trace`, `Outcome`, `NodeId`, `Prog`.
- `flowplane-sim/src/sim.rs` — `SimNode` gains `uplink_dispatch`-driven `uplink()` + underlay identity.
- `flowplane-sim/src/lb_scenario_test.rs` (NEW) — the §6 matrix.
- `netplane/controllers/compilednic.go` — default-allow generation.
- `flowplane/tests/anchor_lb.rs` (NEW) — LB path anchor.

---

## Task 1: `Maps` LB/MAGLEV accessors + sim/eBPF impls

**Files:** Modify `flowplane-core/src/maps.rs`, `flowplane-sim/src/maps.rs`, `flowplane-ebpf/src/coreimpl.rs`. Test: `flowplane-sim/src/maps.rs`.

- [ ] **Step 1: Extend the `Maps` trait** — in `flowplane-core/src/maps.rs` add to `use` (`LbKey, LbValue, MaglevKey`) and to the trait:
```rust
    fn lb_get(&self, key: &LbKey) -> Option<LbValue>;
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]>;
```

- [ ] **Step 2: Write the failing MemMaps test** — append to `flowplane-sim/src/maps.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_common::{LbKey, LbValue, MaglevKey};

    #[test]
    fn lb_and_maglev_roundtrip() {
        let mut m = MemMaps::default();
        let lk = LbKey { vni: 100, ipv4: [10, 0, 100, 1], port: 443, proto: 6, _pad: 0 };
        m.lb.insert(lk, LbValue { table_id: 7, size: 3 });
        m.maglev.insert(MaglevKey { table_id: 7, slot: 2 }, [0x20; 16]);
        assert_eq!(m.lb_get(&lk).map(|v| v.size), Some(3));
        assert_eq!(m.maglev_get(&MaglevKey { table_id: 7, slot: 2 }), Some([0x20; 16]));
        assert_eq!(m.maglev_get(&MaglevKey { table_id: 7, slot: 9 }), None);
    }
}
```

- [ ] **Step 3: Run — verify fail.** `cargo test -p flowplane-sim lb_and_maglev_roundtrip` → FAIL (fields/methods missing).

- [ ] **Step 4: Implement in `MemMaps`** — add fields + impl in `flowplane-sim/src/maps.rs`:
```rust
// in `use`: add LbKey, LbValue, MaglevKey
// in struct MemMaps:
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
// in impl Maps for MemMaps:
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> { self.lb.get(key).copied() }
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> { self.maglev.get(key).copied() }
```

- [ ] **Step 5: Implement in `GlobalMaps`** — in `flowplane-ebpf/src/coreimpl.rs` add to `use` (`LbKey, LbValue, MaglevKey`) and to `impl Maps for GlobalMaps`:
```rust
    #[inline(always)]
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> { unsafe { crate::maps::LB.get(key).copied() } }
    #[inline(always)]
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> { unsafe { crate::maps::MAGLEV.get(key).copied() } }
```

- [ ] **Step 6: Run.** `cargo test -p flowplane-sim lb_and_maglev_roundtrip` → PASS. `cargo build -p flowplane` → compiles.

- [ ] **Step 7: Commit.** `git add flowplane-core flowplane-sim flowplane-ebpf && git commit -m "feat(core): Maps lb_get/maglev_get accessors + sim/eBPF impls"`

---

## Task 2: Move `hash5` into core `parse`

**Files:** Modify `flowplane-core/src/parse.rs`, `flowplane-ebpf/src/parse.rs`.

- [ ] **Step 1: Add `hash5` to `flowplane-core/src/parse.rs`** — copy the eBPF `hash5` body verbatim (it is pure; keep the unrolled form and the comment about the verifier):
```rust
/// FNV-1a hash of the IPv4 5-tuple. Unrolled (iterator loops confuse the BPF verifier).
#[inline(always)]
pub fn hash5(src: &[u8; 4], dst: &[u8; 4], sport: u16, dport: u16, proto: u8) -> u32 {
    // ... EXACT body copied from flowplane-ebpf/src/parse.rs::hash5 ...
}
```
(Read `flowplane-ebpf/src/parse.rs:95` and copy the full function body.)

- [ ] **Step 2: Re-export from eBPF `parse.rs`** — delete the eBPF `hash5` body and replace with `pub use flowplane_core::parse::hash5;`. Verify no other name clash.

- [ ] **Step 3: Run.** `cargo test -p flowplane-core -p flowplane-sim` → PASS. `cargo build -p flowplane` → compiles.

- [ ] **Step 4: Commit.** `git add flowplane-core flowplane-ebpf && git commit -m "refactor(core): move hash5 into flowplane-core::parse; eBPF re-exports"`

---

## Task 3: Port `lb_select_forward` into core

**Files:** Create `flowplane-core/src/lb.rs` (+`pub mod lb;`). Modify `flowplane-ebpf/src/lb.rs`. Test: `flowplane-sim/src/lb_select_test.rs`.

- [ ] **Step 1: Write the core fn** `flowplane-core/src/lb.rs`:
```rust
use crate::maps::Maps;
use crate::parse::{hash5, l4_ports};
use crate::pkt::Pkt;
use flowplane_common::{LbKey, MaglevKey};

/// Maglev backend select for an LB service. Faithful port of eBPF `lb::lb_select_forward` (primary
/// TCP/UDP/ICMP path). Reads the inner IPv4 at `ip_off`; returns the backend underlay /128, or None
/// if `(vni, dst, port, proto)` is not an LB service (or the table is empty).
pub fn lb_select_forward<P: Pkt, M: Maps>(pkt: &P, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    let dst = pkt.read_array::<4>(ip_off + 16)?;
    let src = pkt.read_array::<4>(ip_off + 12)?;
    let (proto, sport, dport) = l4_ports(pkt, ip_off)?;
    let lookup_port = if proto == 1 { 0 } else { dport };
    let lb = maps.lb_get(&LbKey { vni, ipv4: dst, port: lookup_port, proto, _pad: 0 })?;
    if lb.size == 0 {
        return None;
    }
    let slot = hash5(&src, &dst, sport, dport, proto) % lb.size;
    maps.maglev_get(&MaglevKey { table_id: lb.table_id, slot })
}
```
Add `pub mod lb;` to `flowplane-core/src/lib.rs`.

- [ ] **Step 2: Write the failing sim test** `flowplane-sim/src/lb_select_test.rs` (`#[cfg(test)] mod lb_select_test;` in sim lib.rs). Uses the `tcp_v4` helper (`pub(crate)` in `firewall_test.rs`):
```rust
use crate::firewall_test::tcp_v4;
use crate::{MemMaps, VecPkt};
use flowplane_common::{LbKey, LbValue, MaglevKey};
use flowplane_core::lb::lb_select_forward;

#[test]
fn lb_select_returns_maglev_backend() {
    let vni = 100u32;
    let vip = [10, 0, 100, 1];
    let backend_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
    let mut m = MemMaps::default();
    m.lb.insert(LbKey { vni, ipv4: vip, port: 443, proto: 6, _pad: 0 }, LbValue { table_id: 1, size: 1 });
    m.maglev.insert(MaglevKey { table_id: 1, slot: 0 }, backend_ul); // size 1 => slot 0

    let pkt = VecPkt::from_bytes(&tcp_v4([203, 0, 113, 9], vip, 5000, 443));
    assert_eq!(lb_select_forward(&pkt, 0, vni), Some(backend_ul));
    // non-VIP dst → None
    let pkt2 = VecPkt::from_bytes(&tcp_v4([203, 0, 113, 9], [10, 0, 0, 5], 5000, 443));
    assert_eq!(lb_select_forward(&pkt2, 0, vni), None);
}
```

- [ ] **Step 3: Run — verify pass.** `cargo test -p flowplane-sim lb_select` → PASS (size 1 forces slot 0, so the test is deterministic regardless of hash).

- [ ] **Step 4: Rewire eBPF `lb.rs`** — replace the body of `lb_select_forward(ctx, ip_off, vni)` with a delegation:
```rust
pub fn lb_select_forward(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    flowplane_core::lb::lb_select_forward(&crate::coreimpl::CtxPkt { ctx }, ip_off, vni)
}
```
Keep `lb_select_forward_icmp_error` and `lb_select_forward_v6` as-is (deferred). Remove now-unused imports (`LbKey`/`MaglevKey`/`hash5`/`l4_ports`) if the linter flags them.

- [ ] **Step 5: Verify.** `cargo test -p flowplane-sim lb_select` → PASS. `cargo build -p flowplane` → compiles. `nix develop -c bash -c 'CONF_TESTS=test_lb.py ./test/conformance/run.sh'` → PASS (LB datapath unchanged).

- [ ] **Step 6: Commit.** `git add flowplane-core flowplane-ebpf flowplane-sim && git commit -m "refactor(core): port lb_select_forward to core; rewire eBPF"`

---

## Task 4: Port `reforward` into core

**Files:** Modify `flowplane-core/src/encap.rs`, `flowplane-ebpf/src/encap.rs`. Test: `flowplane-sim/src/reforward_test.rs`.

- [ ] **Step 1: Add `reforward` to `flowplane-core/src/encap.rs`**:
```rust
use crate::pkt::{Action, Pkt};
use flowplane_common::Local;

/// Re-forward an already-encapped frame to a new backend underlay (LB remote backend): rewrite the
/// outer Ethernet (dst=gateway_mac, src=uplink_mac) + outer IPv6 src=lb_underlay / dst=backend, and
/// return Redirect(uplink_ifindex) WITHOUT decap. Faithful port of eBPF `encap::reforward`.
#[inline(always)]
pub fn reforward<P: Pkt>(pkt: &mut P, local: &Local, lb_underlay: &[u8; 16], backend: &[u8; 16]) -> Action {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return Action::Drop;
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &local.gateway_mac);
    ok &= pkt.write_bytes(6, &local.uplink_mac);
    ok &= pkt.write_bytes(ETH_LEN + 8, lb_underlay);
    ok &= pkt.write_bytes(ETH_LEN + 24, backend);
    if !ok {
        return Action::Drop;
    }
    Action::Redirect(local.uplink_ifindex)
}
```
(`ETH_LEN`/`IPV6_LEN` already imported/re-exported in this module.)

- [ ] **Step 2: Write the failing sim test** `flowplane-sim/src/reforward_test.rs` (`#[cfg(test)] mod reforward_test;`):
```rust
use crate::VecPkt;
use flowplane_core::encap::{reforward, ETH_LEN};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_common::Local;

#[test]
fn reforward_rewrites_outer_to_backend() {
    // 14 + 40 + 40-byte inner placeholder = a valid encapped frame length.
    let mut p = VecPkt::from_bytes(&[0u8; ETH_LEN + 40 + 40]);
    let local = Local {
        uplink_ifindex: 9,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: [0; 16],
    };
    let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
    let backend = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
    assert_eq!(reforward(&mut p, &local, &lb_ul, &backend), Action::Redirect(9));
    assert_eq!(&p.bytes()[0..6], &[1u8; 6]); // outer eth dst = gateway_mac
    assert_eq!(&p.bytes()[6..12], &[2u8; 6]); // outer eth src = uplink_mac
    assert_eq!(&p.bytes()[ETH_LEN + 8..ETH_LEN + 24], &lb_ul); // outer v6 src
    assert_eq!(&p.bytes()[ETH_LEN + 24..ETH_LEN + 40], &backend); // outer v6 dst
}
```

- [ ] **Step 3: Run — verify pass.** `cargo test -p flowplane-sim reforward` → PASS.

- [ ] **Step 4: Rewire eBPF `encap.rs::reforward`** — replace its body to delegate:
```rust
pub fn reforward(ctx: &XdpContext, local: &Local, lb_underlay: &[u8; 16], backend: &[u8; 16]) -> u32 {
    match flowplane_core::encap::reforward(&mut crate::coreimpl::CtxPkt { ctx }, local, lb_underlay, backend) {
        Action::Redirect(ifindex) => unsafe { bpf_redirect(ifindex, 0) } as u32,
        _ => xdp_action::XDP_DROP,
    }
}
```
(Add `use flowplane_core::pkt::Action;` as needed. `bpf_redirect` is already imported.)

- [ ] **Step 5: Verify.** `cargo test -p flowplane-sim reforward` → PASS. `cargo build -p flowplane`. `nix develop -c bash -c 'CONF_TESTS=test_lb.py ./test/conformance/run.sh'` → PASS.

- [ ] **Step 6: Commit.** `git add flowplane-core flowplane-ebpf flowplane-sim && git commit -m "refactor(core): port reforward to core; rewire eBPF"`

---

## Task 5: Consolidated `uplink_dispatch` seam (DELICATE)

**Files:** Modify `flowplane-core/src/uplink.rs`, `flowplane-ebpf/src/ingress.rs`, `flowplane-sim/src/sim.rs`. Guard: full `test_lb.py` + `test_flows.py`.

**Goal:** one core seam that both eBPF `try_uplink_rx` and the sim call for the LB+base decision, so they cannot diverge. It encompasses: LB-select → (LB-local: ingress FW on inner=VIP with the backend tap, **no** conntrack, decap+rewrite → Redirect(backend tap)) | (LB-remote: reforward) | (non-LB: ingress FW on new flow + conntrack + decap+rewrite → Redirect(base tap)). This CONSOLIDATES the base FW+conntrack that currently lives in the eBPF wrapper (ingress.rs:245-289) AND the sim's `host_uplink` composition into ONE place.

- [ ] **Step 1: Read the source of truth.** Read `flowplane-ebpf/src/ingress.rs:100-311` fully — the `lb_ul` computation, the FW block (245-262, gated by `ct miss && DROP && fw_enforcing`), the conntrack block (264-289, `if lb_ul.is_none()`), and the `decap_and_rewrite` delegation (290-310). The seam must reproduce this exactly for the LB-local, LB-remote, and non-LB cases. NAT64/neighbor-NAT/ICMP-echo branches stay in the wrapper BEFORE the seam call.

- [ ] **Step 2: Define the seam** in `flowplane-core/src/uplink.rs`:
```rust
use crate::encap::{reforward, ETH_LEN, IPV6_LEN};
use crate::firewall::fw_eval_dir;
use crate::lb::lb_select_forward;
use crate::conntrack::{ct_create_default, ct_key};
use flowplane_common::{FW_ACTION_DROP, FW_DIR_INGRESS, Local, UnderlayValue};

/// Result carrying the deliver tap so the caller (eBPF) can also run DNAT before redirecting.
pub enum UplinkOutcome { Deliver { tap: u32, action: Action }, Reforwarded(Action), Dropped, Bail }

/// Full uplink LB+base decision on a decapped-pending frame whose outer dst resolved to `u`
/// (vni + local tap). `outer_dst` is the current outer IPv6 dst (= this node's underlay or the LB
/// underlay). `now` feeds conntrack. Byte-identical to the try_uplink_rx tail.
pub fn uplink_dispatch<P: Pkt, M: Maps>(
    pkt: &mut P, maps: &mut M, vni: u32, u: UnderlayValue, outer_dst: [u8; 16], local: &Local, now: u64,
) -> UplinkOutcome {
    let inner_off = ETH_LEN + IPV6_LEN;
    let lb_ul = lb_select_forward(pkt, inner_off, vni);
    // Resolve the deliver target: LB backend (local) or reforward (remote), else base tap.
    let (deliver_tap, guest_mac, is_lb) = match lb_ul {
        Some(bul) => match maps.underlay_get(&bul) {
            Some(bu) => (bu.tap_ifindex, bu.guest_mac, true),   // LB backend local
            None => return match reforward(pkt, local, &outer_dst, &bul) {
                Action::Drop => UplinkOutcome::Dropped,
                a => UplinkOutcome::Reforwarded(a),
            },
        },
        None => (u.tap_ifindex, u.guest_mac, false),            // non-LB base
    };
    // Ingress firewall on the inner 5-tuple (inner dst = VIP for LB) against the deliver tap.
    // New-flow gate mirrors the wrapper: ct miss && DROP && enforcing.
    if let Some(key) = ct_key(pkt, inner_off, vni) {
        if maps.conntrack_get(&key).is_none()
            && fw_eval_dir(pkt, maps, inner_off, deliver_tap, FW_DIR_INGRESS) == FW_ACTION_DROP
            && maps.fw_enforcing()
        {
            return UplinkOutcome::Dropped;
        }
    }
    // Conntrack: only for non-LB (LB is DSR, no ct — matches lb.rs + ingress.rs:266).
    if !is_lb {
        if let Some(key) = ct_key(pkt, inner_off, vni) {
            if maps.conntrack_get(&key).is_none() {
                ct_create_default(pkt, maps, inner_off, vni, now);
            }
        }
    }
    // Decap + inner-eth rewrite (existing seam).
    match decap_and_rewrite(pkt, deliver_tap, guest_mac) {
        Ok(action) => UplinkOutcome::Deliver { tap: deliver_tap, action },
        Err(()) => UplinkOutcome::Bail,
    }
}
```
Notes: `UnderlayValue` must expose `tap_ifindex` + `guest_mac` (verify field names in `flowplane-common`). `decap_and_rewrite` already exists in this module.

- [ ] **Step 3: Rewire eBPF `try_uplink_rx`** — replace the inline FW (245-262) + conntrack (264-289) + `decap_and_rewrite` (290-310) block with a single `uplink_dispatch` call, mapping the result:
```rust
match flowplane_core::uplink::uplink_dispatch(
    &mut crate::coreimpl::CtxPkt { ctx }, &mut crate::coreimpl::GlobalMaps, vni, u, outer_dst, local, now(),
) {
    UplinkOutcome::Reforwarded(Action::Redirect(i)) => Ok(unsafe { bpf_redirect(i, 0) } as u32),
    UplinkOutcome::Deliver { action: Action::Redirect(tap), .. } => {
        // DNAT still in the wrapper (non-LB VIP path); LB skips it.
        if lb_ul.is_none() && nat_guest.is_none() { crate::vip::dnat_ingress(ctx, ETH_LEN, vni); }
        Ok(unsafe { bpf_redirect(tap, 0) } as u32)
    }
    UplinkOutcome::Dropped => Ok(xdp_action::XDP_DROP),
    UplinkOutcome::Bail | _ => Err(()),
}
```
IMPORTANT: the wrapper still computes `lb_ul`/`nat_guest` earlier for the NAT64/neighbor branches; keep those. The seam recomputes `lb_select_forward` internally — that's fine (deterministic, cheap) and keeps the seam self-contained. If the borrow/move of `u`/`outer_dst`/`local` needs adjustment, read the surrounding code and adapt. This is the delicate rewrite — preserve behavior exactly.

- [ ] **Step 4: Refactor the sim `SimNode::host_uplink`** to call the seam (replacing its hand-composed fw+ct+decap):
```rust
pub fn uplink(&mut self, encapped: &[u8], vni: u32, u: UnderlayValue, outer_dst: [u8;16], local: &Local) -> UplinkResult {
    let mut pkt = VecPkt::from_bytes(encapped);
    let outcome = uplink_dispatch(&mut pkt, &mut self.maps, vni, u, outer_dst, local, 0);
    UplinkResult { outcome_kind..., pkt: pkt.into_bytes() }
}
```
Keep the existing `host_uplink(encapped, vni, tap, guest_mac)` as a thin wrapper over `uplink` (build a base `UnderlayValue{vni, tap_ifindex:tap, guest_mac, ..}`) so the existing `ns_scenario_test` stays green. (Read `UnderlayValue`'s fields; fill the rest with zeros.)

- [ ] **Step 5: Verify — the critical guard.** `cargo test -p flowplane-sim` (all, incl. `ns_scenario_test`) → PASS. `cargo build -p flowplane`. `nix develop -c bash -c './test/conformance/run.sh'` (FULL) → must be **93 passed / 2 skipped** (LB + base + everything byte-identical). If conformance regresses, the seam diverged — fix before committing.

- [ ] **Step 6: Commit.** `git add flowplane-core flowplane-ebpf flowplane-sim && git commit -m "feat(core): consolidated uplink_dispatch seam (LB+base); rewire eBPF + sim"`

---

## Task 6: `Fabric` multi-node abstraction

**Files:** Create `flowplane-sim/src/fabric.rs` (+`pub mod fabric;`, re-export). Test: in `fabric.rs`.

- [ ] **Step 1: Define the types + `deliver`** in `flowplane-sim/src/fabric.rs`:
```rust
use std::collections::HashMap;
use crate::sim::SimNode;
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::Action;

pub type NodeId = &'static str;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Prog { WanRx, UplinkRx }

#[derive(Debug)]
pub enum Outcome { Delivered { node: NodeId, tap: u32 }, Dropped { node: NodeId }, Passed { node: NodeId }, LoopHalted }

pub struct Hop { pub node: NodeId, pub prog: Prog, pub action: Action, pub pkt: Vec<u8> }
pub struct Trace { pub hops: Vec<Hop>, pub outcome: Outcome }

pub struct Fabric {
    nodes: HashMap<NodeId, SimNode>,
    routes: HashMap<[u8; 16], NodeId>, // underlay /128 -> owning node
}

impl Fabric {
    pub fn new() -> Self { Self { nodes: HashMap::new(), routes: HashMap::new() } }
    pub fn add_node(&mut self, id: NodeId, node: SimNode) { self.nodes.insert(id, node); }
    pub fn node_mut(&mut self, id: NodeId) -> &mut SimNode { self.nodes.get_mut(id).unwrap() }
    pub fn route(&mut self, underlay: [u8; 16], id: NodeId) { self.routes.insert(underlay, id); }

    /// Run `prog` on `ingress`, then follow encap/redirect across the fabric (outer IPv6 dst ->
    /// owning node's uplink_rx) until Delivered/Dropped/Passed, or the hop cap (8) trips.
    pub fn deliver(&mut self, ingress: NodeId, prog: Prog, pkt: &[u8]) -> Trace { /* see Step 3 */ }
}
```

- [ ] **Step 2: Write the failing 2-node N/S test** (in `fabric.rs` `#[cfg(test)]`): build `edge` + `backend` nodes, register `backend`'s underlay → `backend`, craft an external→VIP frame, `fabric.deliver("edge", Prog::WanRx, &pkt)`, assert `Outcome::Delivered { node: "backend", .. }` and that `trace.hops` has 2 entries (edge wan_rx redirect, backend uplink deliver). (Fill LB maps + an allow rule on the backend so it delivers.) The exact fixture mirrors `lb_scenario_test` Task 8 row 1 — keep it minimal here (single assertion that multi-hop routing works).

- [ ] **Step 3: Implement `deliver`** — loop: run the program on the current node; inspect the returned `Action` + output bytes:
  - `Action::Redirect(tap)` where the frame is **decapped** (outer ethertype at 12 == 0x0800 or len shrank by IPV6_LEN vs input) → `Delivered { node, tap }`.
  - `Action::Redirect(_)` where the frame is still **encapped** (outer ethertype 0x86DD) → read outer IPv6 dst (`ETH_LEN+24..ETH_LEN+40`), look up `routes`; if found, set current node = that node, prog = `UplinkRx`, pkt = output, continue; else `Passed`.
  - `Action::Drop` → `Dropped { node }`. `Action::Pass` → `Passed { node }`.
  - Cap at 8 hops → `LoopHalted`.
  `SimNode` must expose a uniform `run(Prog, &[u8]) -> (Action, Vec<u8>)`; add it (WanRx → the edge VIP seam, UplinkRx → `uplink`). Record each `Hop`.

- [ ] **Step 4: Run.** `cargo test -p flowplane-sim fabric` → PASS.

- [ ] **Step 5: Commit.** `git add flowplane-sim && git commit -m "feat(sim): Fabric multi-node abstraction (underlay routing + Trace)"`

---

## Task 7: `Compile()` default-allow generation (Go)

**Files:** Modify `netplane/controllers/compilednic.go`, `compilednic_test.go`. Regenerate the fixture.

- [ ] **Step 1: Write the failing test** in `compilednic_test.go`:
```go
func TestCompile_UnpoliciedGetsAllowAll(t *testing.T) {
	nic := testNIC() // labels {role: frontend}
	// No policies selecting it.
	c := Compile(nic, nil)
	if len(c.Spec.Firewall.Ingress) != 1 || c.Spec.Firewall.Ingress[0].Action != "Allow" ||
		c.Spec.Firewall.Ingress[0].CIDR != "0.0.0.0/0" || c.Spec.Firewall.Ingress[0].Port != 0 {
		t.Fatalf("expected a single allow-all ingress rule, got %+v", c.Spec.Firewall.Ingress)
	}
	if len(c.Spec.Firewall.Egress) != 1 || c.Spec.Firewall.Egress[0].Action != "Allow" {
		t.Fatalf("expected a single allow-all egress rule, got %+v", c.Spec.Firewall.Egress)
	}
	// A policied NIC keeps ONLY its policy rules (no allow-all appended).
	c2 := Compile(nic, []netv1.NetworkPolicy{testPolicy()})
	for _, r := range c2.Spec.Firewall.Ingress {
		if r.CIDR == "0.0.0.0/0" && r.Port == 0 {
			t.Fatalf("policied NIC must not get allow-all: %+v", c2.Spec.Firewall.Ingress)
		}
	}
}
```

- [ ] **Step 2: Run — verify fail.** `nix develop -c bash -c 'cd netplane && go test ./controllers/ -run TestCompile_Unpolicied'` → FAIL.

- [ ] **Step 3: Implement** — in `Compile()`, after the policy loop, track whether any policy matched; if none, append allow-all:
```go
	matched := false
	for _, policy := range policies {
		// ... existing selector match; on match set matched = true before appending rules ...
	}
	if !matched {
		// k8s default-allow, materialized explicitly (dataplane is deny-by-default).
		allowAll := netv1.CompiledFwRule{CIDR: "0.0.0.0/0", Action: "Allow"} // Proto "" = any, Port 0 = any
		compiled.Spec.Firewall.Ingress = append(compiled.Spec.Firewall.Ingress, allowAll)
		compiled.Spec.Firewall.Egress = append(compiled.Spec.Firewall.Egress, allowAll)
	}
```
(Set `matched = true` inside the existing loop right after `sel.Matches(nicLabels)` passes.)

- [ ] **Step 4: Run — verify pass.** `nix develop -c bash -c 'cd netplane && go test ./controllers/ -run TestCompile -v'` → PASS. The golden-guard `TestCompile_WritesFixture` still uses a policied NIC (unchanged fixture).

- [ ] **Step 5: Commit.** `git add netplane && git commit -m "feat(compiledNIC): Compile() synthesizes allow-all for unpolicied NICs (deny-by-default posture)"`

---

## Task 8: The E/W + N/S LB test matrix

**Files:** Create `flowplane-sim/src/lb_scenario_test.rs` (`#[cfg(test)] mod lb_scenario_test;`). Uses `Fabric` + `apply()`.

- [ ] **Step 1: Build a topology helper** — a fn constructing a `Fabric` with `edge`, `hostB` (backend) nodes: register `hostB` underlay → `hostB`; on `hostB` set `LB[vni,vip,port,proto]=size1` + `MAGLEV[table,0]=hostB_underlay` + `UNDERLAY[hostB_underlay]={vni, tap, guest_mac}`; on `edge` set the WAN-VIP LB maps (`vni=0`) + `MAGLEV → hostB_underlay` + `LOCAL`. Firewall via `apply(&CompiledNic, ...)` per test.

- [ ] **Step 2: Write the matrix tests** (one `#[test]` each), asserting `Trace.outcome` **and** hop path:
  - `ns_lb_delivered_with_allow` (row 1): `hostB` gets an allow rule covering `0.0.0.0/0:port` → `Delivered { node:"hostB" }`, 2 hops.
  - `ns_lb_dropped_no_vip_rule` (row 2): `hostB` policy allows only an internal CIDR (e.g. `10.0.0.0/8`) on the port → `Dropped { node:"hostB" }`. **This is the clab reproduction.**
  - `ns_lb_delivered_unpolicied` (row 3): `hostB` `CompiledNic` from `Compile(nic, nil)` (allow-all) → `Delivered`.
  - `ew_lb_reforward_delivered` (row 4): add `hostA` + a `relay` node owning the LB relay underlay; origin routes `vip→relay_ul`; `deliver("hostA", UplinkRx, encapped-to-relay)` → Trace shows relay reforward hop then `hostB` deliver. (If modeling `guest_tx` origin is heavy, inject the already-encapped-to-relay frame at the relay and assert reforward→deliver; note the reduced origin modeling.)
  - `ew_lb_local_deliver` (row 5): relay node == backend → single `uplink_rx`, no reforward hop.
  - `lb_maglev_deterministic` (row 6): same 5-tuple selects the same backend on both relay and backend nodes → converges (no `LoopHalted`).

- [ ] **Step 3: Run.** `cargo test -p flowplane-sim lb_scenario` → all PASS. **If `ns_lb_delivered_with_allow` (a correct explicit rule) unexpectedly DROPS, that is a genuine datapath bug — stop and investigate via the Trace before "fixing" the test.**

- [ ] **Step 4: Commit.** `git add flowplane-sim && git commit -m "test(sim): E/W + N/S LB coverage matrix via Fabric (incl. clab drop reproduction)"`

---

## Task 9: `BPF_PROG_TEST_RUN` anchor for the LB path

**Files:** Create `flowplane/tests/anchor_lb.rs`. Modify `Makefile` (extend `sim-anchor` or add `sim-anchor-lb`).

- [ ] **Step 1: Write the anchor** (model on `flowplane/tests/anchor_uplink.rs`): load the eBPF object; populate `UNDERLAY`, `LB`, `MAGLEV`, `FW_META`/`FW_RULES`/`FW_CONFIG`, `LOCAL` for an LB-local-deliver fixture (same as sim row 1); craft the encapped-to-backend frame; run `uplink_rx` via the raw `BPF_PROG_TEST_RUN` syscall; build the SAME fixture in a `Fabric`/`SimNode`; assert `out.data == native_pkt` (byte-parity) + action == redirect to the backend tap. `#[ignore]` (privileged).

- [ ] **Step 2: Makefile** — add the LB anchor to the `sim-anchor` target (run both `anchor_uplink` and `anchor_lb`), or a sibling target. Match the existing style.

- [ ] **Step 3: Run.** `nix develop -c bash -c 'make sim-anchor'` → PASS (LB native == bytecode). A byte diff = a real divergence; investigate.

- [ ] **Step 4: Commit.** `git add flowplane Makefile && git commit -m "test(anchor): BPF_PROG_TEST_RUN byte-parity anchor for the LB uplink path"`

---

## Task 10: Docs + regression sweep

**Files:** Modify `README.md`.

- [ ] **Step 1: Extend the README "Synthetic datapath testing" section** — document `Fabric` (multi-node, Trace) and that LB E/W + N/S coverage now runs under `make sim`; note the deny-by-default posture (dataplane deny-by-default, control-plane allow-all-when-unpolicied). Keep it to a short paragraph.

- [ ] **Step 2: Full regression sweep.**
  - `make sim` → all sim tests PASS.
  - `cargo test` (workspace) → PASS.
  - `nix develop -c bash -c './test/conformance/run.sh'` → 93 passed / 2 skipped.
  - `make sim-anchor` → PASS.

- [ ] **Step 3: Commit.** `git add README.md && git commit -m "docs: Fabric + LB coverage in the synthetic-testing workflow"`

---

## Self-Review notes (for the executor)

- **Task 5 is the delicate one.** `uplink_dispatch` MUST reproduce `try_uplink_rx`'s LB/base behavior byte-for-byte (FW gate `ct miss && DROP && enforcing`, conntrack skipped for LB, decap+rewrite). Full conformance (esp. `test_lb.py`, `test_flows.py`, `test_pf_to_vf.py`) is the guard — it must stay 93/2. Read ingress.rs:100-311 before writing.
- **Verify field names before use:** `UnderlayValue` (`tap_ifindex`, `guest_mac`, `vni`), `Local` (`gateway_mac`, `uplink_mac`, `uplink_ifindex`), `LbKey`/`LbValue`/`MaglevKey`. Fix the plan's stubs to the real names.
- **The reproduction is Task 8 `ns_lb_dropped_no_vip_rule`** — it encodes "explicit rule that doesn't cover the VIP ⇒ drop." If a *covering* rule (row 1) drops, that's the genuine datapath bug the whole exercise hunts; the `Trace` localizes it.
- **No auto-whitelist:** firewall rules come only from `Compile()` (policy or default-allow). Never from LB membership.
- **Follow-ons (own specs):** SNAT egress, NAT64, VirtualIP/floating, DHCP/ARP-ND, LB ICMP-error + v6.
