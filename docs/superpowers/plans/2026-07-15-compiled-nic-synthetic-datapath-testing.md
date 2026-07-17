# Compiled NIC + Synthetic Datapath Testing (Walking Skeleton) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a walking skeleton that proves both pillars end-to-end: a first-class `CompiledNIC` CRD compiled from the high-level CRDs, and an in-process native harness that runs the *real* datapath code (behind `Pkt`/`Maps` traits) on crafted packets — external → edge encap → host decap → firewall allow → conntrack create — with a `BPF_PROG_TEST_RUN` byte-parity anchor.

**Architecture:** Extract the leaf datapath units (encap header write, firewall eval, conntrack create) plus one base-path orchestration seam into a new `no_std` `flowplane-core` crate generic over a `Pkt` trait (bounds-checked byte access) and a `Maps` trait (typed map access). The real `#[xdp]` programs become thin glue that builds the aya-backed impls and calls core; a new `std` `flowplane-sim` crate provides `Vec`/`HashMap`-backed impls and drives scenarios. A Go compiler controller emits `CompiledNIC` objects; the sim consumes the same object (via a JSON fixture) through a shared `apply()` lowering.

**Tech Stack:** Rust (aya-ebpf 0.1, aya 0.13, `no_std` core, `etherparse` for packet crafting, `serde_json` for fixtures), Go (controller-runtime, envtest), protobuf-free CRDs under `net.ectobase.dev/v1alpha1`.

**Parent spec:** `docs/superpowers/specs/2026-07-15-compiled-nic-synthetic-datapath-testing-design.md`

---

## File Structure

- `flowplane-core/Cargo.toml`, `flowplane-core/src/lib.rs` — **Create**: `no_std` crate. `pub mod pkt` (`Pkt` trait + `Action`), `pub mod maps` (`Maps` trait), `pub mod parse` (pure `l4_ports`/`icmp_type_code`/`PacketSelectors` on `Pkt`), `pub mod firewall` (`fw_eval_dir`), `pub mod encap` (`write_outer_v6`, `EncapParams`), `pub mod conntrack` (`ct_key`/`ct_create`), `pub mod uplink` (base-path seam). Depends on `flowplane-common`.
- `flowplane-ebpf/src/coreimpl.rs` — **Create**: `CtxPkt` (`Pkt` for `XdpContext`) + `GlobalMaps` (`Maps` over the `#[map]` statics).
- `flowplane-ebpf/src/encap.rs`, `firewall.rs`, `ingress.rs`, `main.rs`, `maps.rs` — **Modify**: call `flowplane_core::*` instead of local copies; delegate `try_uplink_rx` base path to `core::uplink`.
- `flowplane-sim/Cargo.toml`, `flowplane-sim/src/lib.rs` — **Create**: `std` crate. `VecPkt`, `MemMaps`, `SimNode`, `apply(&CompiledNic)`, `CompiledNic` (serde mirror), scenario tests.
- `Cargo.toml` (workspace) — **Modify**: add `flowplane-core`, `flowplane-sim` to members.
- `api/v1alpha1/compilednic_types.go` — **Create**: `CompiledNIC` CRD types.
- `api/v1alpha1/register.go`, `zz_generated.deepcopy.go` — **Modify**: register + deepcopy.
- `netplane/controllers/compilednic.go`, `compilednic_test.go` — **Create**: the compiler (pure `Compile()` fn + reconciler) + envtest.
- `Makefile` — **Modify**: `sim-anchor` target.

---

## Task 1: `flowplane-core` crate + `Pkt`/`Maps` traits

**Files:**
- Create: `flowplane-core/Cargo.toml`, `flowplane-core/src/lib.rs`, `flowplane-core/src/pkt.rs`, `flowplane-core/src/maps.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Create the crate manifest**

`flowplane-core/Cargo.toml`:
```toml
[package]
name = "flowplane-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
flowplane-common = { path = "../flowplane-common" }
```

- [ ] **Step 2: Add to the workspace**

In `Cargo.toml`, add `"flowplane-core"` to `members` AND to `default-members` (so `cargo build`/`cargo test` build it natively):
```toml
members = ["flowplane-common", "flowplane-core", "flowplane-ebpf", "flowplane"]
default-members = ["flowplane-common", "flowplane-core", "flowplane"]
```

- [ ] **Step 3: Define the `Pkt` trait + `Action`** in `flowplane-core/src/pkt.rs`

```rust
//! Packet access abstraction. eBPF impl uses raw ptr + manual bounds checks (verifier-safe);
//! native impl uses a Vec. Typed access is FIXED-SIZE (const-generic N) so the eBPF impl stays
//! verifier-friendly — no runtime-length slices cross the trait boundary.

/// What the glue should do with the packet after core returns.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Action {
    Pass,
    Drop,
    /// Redirect out this ifindex.
    Redirect(u32),
}

pub trait Pkt {
    /// Current frame length in bytes.
    fn len(&self) -> usize;
    /// Copy `N` bytes at `off`, bounds-checked. None if out of range.
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]>;
    /// Overwrite `src.len()` bytes at `off`, bounds-checked. false if out of range.
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool;
    /// Prepend `delta` bytes of headroom (encap). Models bpf_xdp_adjust_head(-delta).
    fn grow_head(&mut self, delta: usize) -> bool;
    /// Remove `delta` bytes from the front (decap). Models bpf_xdp_adjust_head(+delta).
    fn shrink_head(&mut self, delta: usize) -> bool;

    #[inline(always)]
    fn read_u16_be(&self, off: usize) -> Option<u16> {
        self.read_array::<2>(off).map(u16::from_be_bytes)
    }
    #[inline(always)]
    fn read_u8(&self, off: usize) -> Option<u8> {
        self.read_array::<1>(off).map(|b| b[0])
    }
}
```

- [ ] **Step 4: Define the `Maps` trait** in `flowplane-core/src/maps.rs`

```rust
use flowplane_common::{CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue};

/// Typed access to the datapath maps the core needs. eBPF impl wraps the `#[map]` statics
/// (zero-cost); native impl is HashMap-backed. Monomorphized — no `dyn`.
pub trait Maps {
    fn local(&self) -> Option<Local>;
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue>;
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta>;
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule>;
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry>;
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry);
}
```

- [ ] **Step 5: Wire `lib.rs`** in `flowplane-core/src/lib.rs`

```rust
#![no_std]

pub mod maps;
pub mod pkt;
```

- [ ] **Step 6: Build**

Run: `cargo build -p flowplane-core`
Expected: PASS (compiles clean, no warnings about unused — traits are `pub`).

- [ ] **Step 7: Commit**

```bash
git add flowplane-core Cargo.toml
git commit -m "feat(core): flowplane-core crate with Pkt + Maps traits"
```

---

## Task 2: `flowplane-sim` crate — native `VecPkt` + `MemMaps`

**Files:**
- Create: `flowplane-sim/Cargo.toml`, `flowplane-sim/src/lib.rs`, `flowplane-sim/src/pkt.rs`, `flowplane-sim/src/maps.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Create the crate manifest**

`flowplane-sim/Cargo.toml`:
```toml
[package]
name = "flowplane-sim"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
flowplane-core = { path = "../flowplane-core" }
flowplane-common = { path = "../flowplane-common", features = ["user"] }

[dev-dependencies]
etherparse = "0.15"
serde_json = "1"
```

Add `"flowplane-sim"` to workspace `members` and `default-members`.

- [ ] **Step 2: Write the failing test for `VecPkt`** in `flowplane-sim/src/pkt.rs`

```rust
use flowplane_core::pkt::Pkt;

/// Native packet backing: a Vec the core mutates in place. `head` tracks the logical front
/// after grow/shrink so bytes aren't copied on every adjust.
pub struct VecPkt {
    buf: alloc_vec(),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut p = VecPkt::from_bytes(&[0u8; 32]);
        assert!(p.write_bytes(4, &[0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(p.read_array::<4>(4), Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(p.read_u16_be(4), Some(0xdead));
        assert_eq!(p.read_array::<4>(30), None); // out of range
    }

    #[test]
    fn grow_then_shrink_head() {
        let mut p = VecPkt::from_bytes(&[1, 2, 3, 4]);
        assert!(p.grow_head(2));
        assert_eq!(p.len(), 6);
        assert!(p.write_bytes(0, &[9, 9]));
        assert!(p.shrink_head(2));
        assert_eq!(p.len(), 4);
        assert_eq!(p.read_array::<4>(0), Some([1, 2, 3, 4]));
    }
}
```

(Delete the `buf: alloc_vec()` placeholder — it is illustrative; real field is `Vec<u8>`.)

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p flowplane-sim`
Expected: FAIL (does not compile — `VecPkt` unimplemented).

- [ ] **Step 4: Implement `VecPkt`**

```rust
use flowplane_core::pkt::Pkt;

pub struct VecPkt {
    buf: Vec<u8>,
}

impl VecPkt {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self { buf: b.to_vec() }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl Pkt for VecPkt {
    fn len(&self) -> usize {
        self.buf.len()
    }
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let end = off.checked_add(N)?;
        if end > self.buf.len() {
            return None;
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[off..end]);
        Some(out)
    }
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        let end = match off.checked_add(src.len()) {
            Some(e) => e,
            None => return false,
        };
        if end > self.buf.len() {
            return false;
        }
        self.buf[off..end].copy_from_slice(src);
        true
    }
    fn grow_head(&mut self, delta: usize) -> bool {
        let mut prefix = vec![0u8; delta];
        prefix.extend_from_slice(&self.buf);
        self.buf = prefix;
        true
    }
    fn shrink_head(&mut self, delta: usize) -> bool {
        if delta > self.buf.len() {
            return false;
        }
        self.buf.drain(0..delta);
        true
    }
}
```

- [ ] **Step 5: Write + implement `MemMaps`** in `flowplane-sim/src/maps.rs`

```rust
use std::collections::HashMap;
use flowplane_common::{CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue};
use flowplane_core::maps::Maps;

#[derive(Default)]
pub struct MemMaps {
    pub local: Option<Local>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub fw_rules: HashMap<(u32, u32), FwRule>, // (ifindex, idx)
    pub conntrack: HashMap<CtKey, CtEntry>,
}

impl Maps for MemMaps {
    fn local(&self) -> Option<Local> {
        self.local
    }
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        self.underlay.get(addr).copied()
    }
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta.get(&ifindex).copied()
    }
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.fw_rules.get(&(key.ifindex, key.idx)).copied()
    }
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        self.conntrack.get(key).copied()
    }
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        self.conntrack.insert(key, entry);
    }
}
```

Note: `CtKey` must derive `Hash + Eq` for the HashMap key — verify in `flowplane-common`; if absent, add `#[derive(Hash, Eq, PartialEq)]` to `CtKey` (it is `#[repr(C)]` POD, safe to derive) as part of this step and commit that change with it.

- [ ] **Step 6: `lib.rs`**

```rust
pub mod maps;
pub mod pkt;

pub use maps::MemMaps;
pub use pkt::VecPkt;
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p flowplane-sim`
Expected: PASS (both `VecPkt` tests green).

- [ ] **Step 8: Commit**

```bash
git add flowplane-sim Cargo.toml flowplane-common
git commit -m "feat(sim): native VecPkt + MemMaps impls"
```

---

## Task 3: Port the encap header writer to core; rewire eBPF

**Files:**
- Create: `flowplane-core/src/encap.rs`
- Modify: `flowplane-core/src/lib.rs`, `flowplane-ebpf/src/encap.rs`, `flowplane-ebpf/src/coreimpl.rs` (create), `flowplane-sim/src/lib.rs`
- Test: `flowplane-sim/src/encap_test.rs`

- [ ] **Step 1: Move `EncapParams` + `write_outer_v6` into core** as `flowplane-core/src/encap.rs`, rewritten against `Pkt`

```rust
use crate::pkt::Pkt;

/// Parameters for the outer Eth+IPv6 encap header. (Moved from flowplane-ebpf egress.rs.)
#[derive(Copy, Clone)]
pub struct EncapParams {
    pub gateway_mac: [u8; 6],
    pub uplink_mac: [u8; 6],
    pub uplink_ifindex: u32,
    pub src_underlay: [u8; 16],
    pub nexthop_ipv6: [u8; 16],
    pub inner_len: u16,
    pub inner_proto: u8,
}

pub const ETH_LEN: usize = 14;
pub const IPV6_LEN: usize = 40;
pub const ETH_P_IPV6: u16 = 0x86DD;

/// Write outer Eth+IPv6 into a frame that already has IPV6_LEN bytes of front room. Pure byte
/// writes via `Pkt` — no resize, no redirect. Returns false on bounds failure.
#[inline(always)]
pub fn write_outer_v6<P: Pkt>(pkt: &mut P, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &ETH_P_IPV6.to_be_bytes());
    // IPv6 fixed header at ETH_LEN.
    let ip = ETH_LEN;
    ok &= pkt.write_bytes(ip, &[0x60, 0, 0, 0]);
    ok &= pkt.write_bytes(ip + 4, &e.inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]);
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}
```

Add `pub mod encap;` to `flowplane-core/src/lib.rs`.

- [ ] **Step 2: Write the failing sim test** `flowplane-sim/src/encap_test.rs` (declare `mod encap_test;` in `lib.rs` under `#[cfg(test)]`)

```rust
use flowplane_common as common;
use flowplane_core::encap::{write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Pkt;
use crate::VecPkt;

#[test]
fn encap_writes_outer_v6_header() {
    // 34-byte inner frame placeholder; grow front by IPV6_LEN to make room.
    let mut p = VecPkt::from_bytes(&[0u8; 34]);
    assert!(p.grow_head(IPV6_LEN));
    let e = EncapParams {
        gateway_mac: [1, 1, 1, 1, 1, 1],
        uplink_mac: [2, 2, 2, 2, 2, 2],
        uplink_ifindex: 7,
        src_underlay: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb],
        inner_len: 34,
        inner_proto: 4, // IPPROTO_IPIP
    };
    assert!(write_outer_v6(&mut p, &e));
    // ethertype
    assert_eq!(p.read_u16_be(12), Some(0x86DD));
    // version/traffic-class nibble
    assert_eq!(p.read_u8(ETH_LEN), Some(0x60));
    // payload length
    assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(34));
    // next header + hop limit
    assert_eq!(p.read_array::<2>(ETH_LEN + 6), Some([4, 64]));
    // src + dst underlay
    assert_eq!(p.read_array::<16>(ETH_LEN + 8), Some(e.src_underlay));
    assert_eq!(p.read_array::<16>(ETH_LEN + 24), Some(e.nexthop_ipv6));
}
```

- [ ] **Step 3: Run — verify fail then pass**

Run: `cargo test -p flowplane-sim encap_writes_outer_v6_header`
Expected: FAIL first (module not declared) → after wiring `mod encap_test;`, PASS.

- [ ] **Step 4: Create the eBPF `Pkt`/`Maps` impls** `flowplane-ebpf/src/coreimpl.rs`

```rust
use aya_ebpf::{helpers::bpf_xdp_adjust_head, programs::XdpContext};
use flowplane_core::pkt::Pkt;

/// `Pkt` over an XDP context. read/write are bounds-checked against data_end (verifier-safe).
pub struct CtxPkt<'a> {
    pub ctx: &'a XdpContext,
}

impl Pkt for CtxPkt<'_> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.ctx.data_end() - self.ctx.data()
    }
    #[inline(always)]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let start = self.ctx.data() + off;
        if start + N > self.ctx.data_end() {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(start as *const [u8; N]) })
    }
    #[inline(always)]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        let start = self.ctx.data() + off;
        if start + src.len() > self.ctx.data_end() {
            return false;
        }
        // Fixed-size writes only (callers pass const-size arrays); copy byte-wise.
        for (i, b) in src.iter().enumerate() {
            unsafe { *((start + i) as *mut u8) = *b };
        }
        true
    }
    #[inline(always)]
    fn grow_head(&mut self, delta: usize) -> bool {
        unsafe { bpf_xdp_adjust_head(self.ctx.ctx, -(delta as i32)) == 0 }
    }
    #[inline(always)]
    fn shrink_head(&mut self, delta: usize) -> bool {
        unsafe { bpf_xdp_adjust_head(self.ctx.ctx, delta as i32) == 0 }
    }
}
```

Add `mod coreimpl;` to `flowplane-ebpf/src/main.rs`. (The `Maps` impl `GlobalMaps` is added in Task 4.)

- [ ] **Step 5: Rewire eBPF `encap.rs`** to call the core writer. In `flowplane-ebpf/src/encap.rs`, delete the local `write_outer_v6` body and replace its uses. `encap_and_redirect` becomes:

```rust
use crate::coreimpl::CtxPkt;
use flowplane_core::encap::{write_outer_v6, EncapParams, IPV6_LEN};

#[inline(always)]
pub fn encap_and_redirect(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_len: u16,
    inner_proto: u8,
) -> Result<u32, ()> {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return Err(());
    }
    let e = EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: *src_underlay,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_len,
        inner_proto,
    };
    let mut pkt = CtxPkt { ctx };
    if write_outer_v6(&mut pkt, &e) {
        Ok(unsafe { bpf_redirect(e.uplink_ifindex, 0) } as u32)
    } else {
        Err(())
    }
}
```

Update the other `write_outer_v6` caller (the `guest_tx` glue that calls it after its own `adjust_head`) to build a `CtxPkt` and call the core fn. Remove the now-unused `EncapParams` definition from `egress.rs` and `use flowplane_core::encap::EncapParams;` everywhere it was referenced (`egress.rs`, `encap.rs`).

- [ ] **Step 6: Build the eBPF + confirm no behavior change via conformance encap test**

Run: `cargo build -p flowplane` (builds the eBPF via aya-build)
Expected: PASS (compiles + verifier-clean at load; the load happens in conformance).
Run: `nix develop -c bash -c 'CONF_TESTS=test_encap.py ./test/conformance/run.sh'`
Expected: PASS (encap datapath unchanged).

- [ ] **Step 7: Commit**

```bash
git add flowplane-core flowplane-ebpf flowplane-sim
git commit -m "refactor(core): move encap header writer to flowplane-core behind Pkt; rewire eBPF"
```

---

## Task 4: Port firewall eval to core; rewire eBPF

**Files:**
- Create: `flowplane-core/src/parse.rs`, `flowplane-core/src/firewall.rs`
- Modify: `flowplane-core/src/lib.rs`, `flowplane-ebpf/src/firewall.rs`, `flowplane-ebpf/src/coreimpl.rs`
- Test: `flowplane-sim/src/firewall_test.rs`

- [ ] **Step 1: Port the pure parse helpers to `flowplane-core/src/parse.rs`**, rewritten on `Pkt`: `l4_ports<P: Pkt>(pkt, ip_off) -> Option<(u8,u16,u16)>`, `icmp_type_code<P: Pkt>(pkt, ip_off) -> (u16,u16)`, and `PacketSelectors` + `fw_rule_matches`. These are faithful moves of the existing `flowplane-ebpf/src/parse.rs` / `firewall.rs` bodies with raw `read_unaligned(p.add(off))` replaced by `pkt.read_array::<N>(off)` / `pkt.read_u16_be(off)`. Keep the exact field offsets and matching logic (they define behavior).

- [ ] **Step 2: Port `fw_eval_dir` to `flowplane-core/src/firewall.rs`**

```rust
use crate::maps::Maps;
use crate::parse::{icmp_type_code, l4_ports, fw_rule_matches, PacketSelectors};
use crate::pkt::Pkt;
use flowplane_common::{FwRuleKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_MAX_RULES};

/// Firewall verdict for one direction. Faithful port of flowplane-ebpf::firewall::fw_eval_dir,
/// generic over Pkt + Maps. Returns FW_ACTION_ACCEPT / FW_ACTION_DROP.
pub fn fw_eval_dir<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    ifindex: u32,
    dir: u8,
) -> u8 {
    let meta = match maps.fw_meta(ifindex) {
        Some(m) => m,
        None => return FW_ACTION_ACCEPT,
    };
    let count = if dir == FW_DIR_EGRESS { meta.egress_count } else { meta.ingress_count };
    if count == 0 {
        return FW_ACTION_ACCEPT;
    }
    let src = match pkt.read_array::<4>(ip_off + 12) {
        Some(v) => v,
        None => return FW_ACTION_ACCEPT,
    };
    let dst = match pkt.read_array::<4>(ip_off + 16) {
        Some(v) => v,
        None => return FW_ACTION_ACCEPT,
    };
    let (proto, sport, dport) = match l4_ports(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 9).unwrap_or(0), 0u16, 0u16),
    };
    let (itype, icode) = icmp_type_code(pkt, ip_off);
    let sel = PacketSelectors { src, dst, proto, sport, dport, icmp_type: itype, icmp_code: icode };
    let mut idx: u32 = 0;
    while idx < FW_MAX_RULES {
        if let Some(r) = maps.fw_rule(&FwRuleKey { ifindex, idx }) {
            if r.direction == dir && fw_rule_matches(&r, &sel) {
                return r.action;
            }
        }
        idx += 1;
    }
    FW_ACTION_DROP
}
```

(Verify the exact names `FW_ACTION_ACCEPT`/`FW_ACTION_DROP`/`FW_DIR_EGRESS`/`FW_MAX_RULES`/`PacketSelectors`/`fw_rule_matches` in `flowplane-common`/`flowplane-ebpf`; move any that live in the ebpf crate into `flowplane-common` or `flowplane-core` so both sides share them.) Add `pub mod parse; pub mod firewall;` to `lib.rs`.

- [ ] **Step 3: Add `GlobalMaps` `Maps` impl** for the eBPF side in `flowplane-ebpf/src/coreimpl.rs`

```rust
use flowplane_core::maps::Maps;
use flowplane_common::{CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue};

pub struct GlobalMaps;

impl Maps for GlobalMaps {
    fn local(&self) -> Option<Local> {
        crate::maps::LOCAL.get(0).copied()
    }
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        unsafe { crate::maps::UNDERLAY.get(addr).copied() }
    }
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        unsafe { crate::maps::FW_META.get(&ifindex).copied() }
    }
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        unsafe { crate::maps::FW_RULES.get(key).copied() }
    }
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        unsafe { crate::maps::CONNTRACK.get(key).copied() }
    }
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        let _ = crate::maps::CONNTRACK.insert(&key, &entry, 0);
    }
}
```

- [ ] **Step 4: Rewire eBPF `firewall.rs`** — delete the local `fw_eval_dir`/`l4_ports`/`icmp_type_code`/`fw_rule_matches`/`PacketSelectors` bodies; re-export from core. All existing callers (`ingress.rs`, `egress.rs`) change from `crate::firewall::fw_eval_dir(data, data_end, ip_off, ifindex, dir)` to `flowplane_core::firewall::fw_eval_dir(&CtxPkt{ctx}, &GlobalMaps, ip_off, ifindex, dir)`.

- [ ] **Step 5: Write the failing sim test** `flowplane-sim/src/firewall_test.rs`

```rust
use etherparse::PacketBuilder;
use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
use flowplane_core::firewall::fw_eval_dir;
use crate::{MemMaps, VecPkt};

fn tcp_v4(src: [u8;4], dst: [u8;4], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn ingress_allow_rule_matches() {
    let ifindex = 42u32;
    let mut m = MemMaps::default();
    m.fw_meta.insert(ifindex, FwMeta { ingress_count: 1, egress_count: 0 });
    m.fw_rules.insert((ifindex, 0), FwRule {
        src_ip: [10,0,0,0], src_mask: [255,255,255,0],
        dst_ip: [0,0,0,0], dst_mask: [0,0,0,0],
        src_port_min: 0, src_port_max: 65535,
        dst_port_min: 443, dst_port_max: 443,
        icmp_type: 0xffff, icmp_code: 0xffff,
        proto: 6, action: FW_ACTION_ACCEPT, direction: FW_DIR_INGRESS, enabled: 1,
    });
    let pkt = VecPkt::from_bytes(&tcp_v4([10,0,0,5], [10,0,0,10], 5000, 443));
    assert_eq!(fw_eval_dir(&pkt, &m, 0, ifindex, FW_DIR_INGRESS), FW_ACTION_ACCEPT);
    // wrong port -> default drop (count>0, no match)
    let pkt2 = VecPkt::from_bytes(&tcp_v4([10,0,0,5], [10,0,0,10], 5000, 80));
    assert_eq!(fw_eval_dir(&pkt2, &m, 0, ifindex, FW_DIR_INGRESS), FW_ACTION_DROP);
}
```

(`ip_off` = 0 here because the builder emits an IPv4 frame with no Ethernet header; if `PacketBuilder::ipv4` emits from the IP header, ip_off is 0. If you prepend Ethernet, set ip_off=14. Confirm by asserting `pkt.read_u8(9)` == 6 for the L4 proto offset.)

- [ ] **Step 6: Run — verify pass**

Run: `cargo test -p flowplane-sim firewall`
Expected: PASS.
Run: `nix develop -c bash -c 'CONF_TESTS=test_flows.py ./test/conformance/run.sh'`
Expected: PASS (firewall datapath unchanged).

- [ ] **Step 7: Commit**

```bash
git add flowplane-core flowplane-ebpf flowplane-sim
git commit -m "refactor(core): move firewall eval + parse helpers to core; rewire eBPF"
```

---

## Task 5: Port conntrack key + create to core; rewire eBPF

**Files:**
- Create: `flowplane-core/src/conntrack.rs`
- Modify: `flowplane-core/src/lib.rs`, `flowplane-ebpf/src/conntrack.rs`
- Test: `flowplane-sim/src/conntrack_test.rs`

- [ ] **Step 1: Port `ct_key` + a `ct_create_default` to core** (`flowplane-core/src/conntrack.rs`), generic over `Pkt` + `Maps`. `ct_key<P: Pkt>(pkt, ip_off, vni) -> Option<CtKey>` is a faithful move of the existing `flowplane-ebpf::conntrack::ct_key` (raw reads → `pkt.read_array`). `ct_create_default<P, M>(pkt, maps, ip_off, vni)` builds the forward key, and if `maps.conntrack_get(&key).is_none()` inserts a default `CtEntry` (mirror `ct_ensure_default`). Keep `invert_key`, `tcp_advance` pure moves.

- [ ] **Step 2: Rewire eBPF `conntrack.rs`** — the existing functions call `crate::maps::CONNTRACK` directly; refactor them to take `&mut impl Maps` OR keep the eBPF versions as thin wrappers that construct `GlobalMaps` and call core. Pick the wrapper approach to bound churn: eBPF `ct_ensure_default(data, data_end, ip_off, key)` → builds `CtxPkt` + `GlobalMaps` and calls `flowplane_core::conntrack::ct_create_default`. Verify verifier-clean.

- [ ] **Step 3: Write the failing sim test** `flowplane-sim/src/conntrack_test.rs`

```rust
use flowplane_core::conntrack::{ct_key, ct_create_default};
use crate::{MemMaps, VecPkt};
// reuse tcp_v4 helper via `use crate::firewall_test::tcp_v4;` (make it pub(crate))

#[test]
fn conntrack_entry_created_for_new_flow() {
    let vni = 100u32;
    let mut m = MemMaps::default();
    let pkt = VecPkt::from_bytes(&tcp_v4([10,0,0,5], [10,0,0,10], 5000, 443));
    let key = ct_key(&pkt, 0, vni).expect("ct key");
    assert!(m.conntrack_get(&key).is_none());
    ct_create_default(&pkt, &mut m, 0, vni);
    assert!(m.conntrack_get(&key).is_some(), "forward CT entry inserted");
}
```

- [ ] **Step 4: Run — verify pass + conformance**

Run: `cargo test -p flowplane-sim conntrack`
Expected: PASS.
Run: `nix develop -c bash -c 'CONF_TESTS=test_flows.py ./test/conformance/run.sh'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add flowplane-core flowplane-ebpf flowplane-sim
git commit -m "refactor(core): move conntrack key+create to core; rewire eBPF"
```

---

## Task 6: The base-path seam + full N-S sim scenario

**Files:**
- Create: `flowplane-core/src/uplink.rs`
- Modify: `flowplane-core/src/lib.rs`, `flowplane-ebpf/src/ingress.rs`, `flowplane-sim/src/lib.rs` (`SimNode`)
- Test: `flowplane-sim/src/ns_scenario_test.rs`

- [ ] **Step 1: Extract the uplink base path into a core seam** `flowplane-core/src/uplink.rs`

```rust
use crate::maps::Maps;
use crate::pkt::Pkt;
use crate::encap::{ETH_LEN, IPV6_LEN};
use crate::firewall::fw_eval_dir;
use crate::conntrack::ct_create_default;
use crate::pkt::Action;
use flowplane_common::{FW_ACTION_DROP, FW_DIR_INGRESS};

/// Base (non-LB, non-NAT) decap+deliver: the packet is an encapped IPv4-in-IPv6 frame whose
/// outer dst resolved to a LOCAL tap `u`. Strips the outer v6, runs the ingress firewall on the
/// inner IPv4, creates a conntrack entry, and returns the deliver Action (Redirect to the tap).
/// This is the exact code the real `try_uplink_rx` runs once its LB/NAT64/neighbor branches fall
/// through — it is called by BOTH the eBPF wrapper and the sim, so they never diverge.
pub fn uplink_base_deliver<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    vni: u32,
    tap_ifindex: u32,
    guest_mac: [u8; 6],
) -> Action {
    // Ingress firewall on the INNER IPv4 (still at ETH_LEN + IPV6_LEN before decap).
    let inner_off = ETH_LEN + IPV6_LEN;
    if fw_eval_dir(pkt, maps, inner_off, tap_ifindex, FW_DIR_INGRESS) == FW_ACTION_DROP {
        return Action::Drop;
    }
    ct_create_default(pkt, maps, inner_off, vni);
    // Decap: drop outer IPv6 (keep outer Ethernet? — match the real datapath: it rewrites the
    // inner eth dst = guest_mac and redirects to the tap). Faithful to try_uplink_rx delivery.
    if !pkt.shrink_head(IPV6_LEN) {
        return Action::Drop;
    }
    // Rewrite inner Ethernet dst to the guest MAC (delivery).
    let _ = pkt.write_bytes(0, &guest_mac);
    Action::Redirect(tap_ifindex)
}
```

Add `pub mod uplink;`. NOTE: match the *exact* delivery semantics of the existing `try_uplink_rx` base path (inner eth handling, which ifindex, whether outer eth is reused) — read `flowplane-ebpf/src/ingress.rs:230-317` and mirror it precisely. The sim scenario test (Step 3) + the BPF anchor (Task 8) pin this.

- [ ] **Step 2: Delegate the eBPF base path** — in `flowplane-ebpf/src/ingress.rs`, after the LB/NAT64/neighbor-NAT branches fall through (the point where today it computes `tap_ifindex`/`guest_mac` and delivers), replace the inline delivery with a call to `flowplane_core::uplink::uplink_base_deliver(&mut CtxPkt{ctx}, &mut GlobalMaps, vni, tap_ifindex, guest_mac)` and translate the returned `Action` into `XDP_REDIRECT`/`XDP_DROP`/`XDP_PASS`. Leave the branchy prefix untouched.

- [ ] **Step 3: Add `SimNode`** to `flowplane-sim/src/lib.rs`

```rust
use flowplane_core::pkt::Action;
use flowplane_core::encap::{write_outer_v6, EncapParams, IPV6_LEN};
use flowplane_core::uplink::uplink_base_deliver;

pub struct SimNode {
    pub maps: MemMaps,
}

pub struct SimOut {
    pub action: Action,
    pub pkt: Vec<u8>,
}

impl SimNode {
    pub fn new() -> Self { Self { maps: MemMaps::default() } }

    /// Edge: encapsulate an inner IPv4 frame toward `nexthop` from `src_underlay`.
    pub fn edge_encap(&self, inner_v4_frame: &[u8], e_base: EncapParams) -> Vec<u8> {
        let mut p = VecPkt::from_bytes(inner_v4_frame);
        assert!(p.grow_head(IPV6_LEN));
        let mut e = e_base;
        e.inner_len = inner_v4_frame.len() as u16;
        assert!(write_outer_v6(&mut p, &e));
        p.into_bytes()
    }

    /// Host: run the uplink base deliver path on an encapped frame.
    pub fn host_uplink(&mut self, encapped: &[u8], vni: u32, tap: u32, guest_mac: [u8;6]) -> SimOut {
        let mut p = VecPkt::from_bytes(encapped);
        let action = uplink_base_deliver(&mut p, &mut self.maps, vni, tap, guest_mac);
        SimOut { action, pkt: p.into_bytes() }
    }
}
```

- [ ] **Step 4: Write the failing full-path scenario** `flowplane-sim/src/ns_scenario_test.rs`

```rust
use etherparse::PacketBuilder;
use flowplane_core::pkt::Action;
use flowplane_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use crate::SimNode;

fn inner_v4_eth(src: [u8;4], dst: [u8;4], dport: u16) -> Vec<u8> {
    // Ethernet + IPv4 + TCP (inner frame as it rides inside the tunnel).
    let b = PacketBuilder::ethernet2([0;6records], [0;6]) // placeholder MACs
        .ipv4(src, dst, 64).tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn external_to_guest_encap_decap_fw_ct() {
    let vni = 100u32;
    let tap = 42u32;
    let guest_mac = [0x66,0x66,0x66,0x66,0x66,0x00];
    let src_underlay = [0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0xaa];
    let host_underlay = [0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0xbb];

    // Edge encapsulates an external->VIP inner frame.
    let edge = SimNode::new();
    let inner = inner_v4_eth([203,0,113,9], [10,0,0,10], 443);
    let e = EncapParams {
        gateway_mac: [1;6], uplink_mac: [2;6], uplink_ifindex: 7,
        src_underlay, nexthop_ipv6: host_underlay, inner_len: 0, inner_proto: 4,
    };
    let encapped = edge.edge_encap(&inner, e);
    // outer dst underlay is the host.
    assert_eq!(&encapped[ETH_LEN+24..ETH_LEN+40], &host_underlay);

    // Host: install an ingress allow rule for the guest, then run uplink.
    let mut host = SimNode::new();
    host.maps.fw_meta.insert(tap, FwMeta { ingress_count: 1, egress_count: 0 });
    host.maps.fw_rules.insert((tap, 0), FwRule {
        src_ip: [0;4], src_mask: [0;4], dst_ip: [10,0,0,10], dst_mask: [255,255,255,255],
        src_port_min: 0, src_port_max: 65535, dst_port_min: 443, dst_port_max: 443,
        icmp_type: 0xffff, icmp_code: 0xffff, proto: 6,
        action: FW_ACTION_ACCEPT, direction: FW_DIR_INGRESS, enabled: 1,
    });
    let out = host.host_uplink(&encapped, vni, tap, guest_mac);
    assert_eq!(out.action, Action::Redirect(tap));           // delivered
    assert_eq!(&out.pkt[0..6], &guest_mac);                  // inner eth dst rewritten
    assert_eq!(out.pkt.len(), inner.len());                  // outer v6 stripped
    // conntrack entry created for the inner flow
    assert_eq!(host.maps.conntrack.len(), 1);
}
```

(Fix the `[0;6records]` typo to `[0u8;6]`; it is a placeholder to remind you to set inner MACs. Confirm inner IPv4 offset inside the decapped frame — if the inner frame carries its own Ethernet, the FW `inner_off` in `uplink_base_deliver` must account for it; align the test's frame layout with the real tunnel payload format documented in `flowplane-ebpf/src/ingress.rs`.)

- [ ] **Step 5: Run — verify pass + conformance regression**

Run: `cargo test -p flowplane-sim external_to_guest`
Expected: PASS.
Run: `nix develop -c bash -c './test/conformance/run.sh'` (full suite)
Expected: PASS (whole datapath still green after the base-path delegation).

- [ ] **Step 6: Commit**

```bash
git add flowplane-core flowplane-ebpf flowplane-sim
git commit -m "feat(core): uplink base-path seam; full N-S sim scenario green"
```

---

## Task 7: `CompiledNIC` CRD + compiler + `apply()` bridge

**Files:**
- Create: `api/v1alpha1/compilednic_types.go`, `netplane/controllers/compilednic.go`, `netplane/controllers/compilednic_test.go`
- Modify: `api/v1alpha1/register.go`, `api/v1alpha1/zz_generated.deepcopy.go`
- Create: `flowplane-sim/src/compilednic.rs` + test fixture `flowplane-sim/testdata/compilednic.json`
- Modify: `flowplane-sim/src/lib.rs` (`apply`)

- [ ] **Step 1: Define the `CompiledNIC` Go types** `api/v1alpha1/compilednic_types.go` (mirror the `NetworkInterface` file's conventions: `TypeMeta`/`ObjectMeta`, `+kubebuilder` markers, `List` type)

```go
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// CompiledNICSpec is the lowered, node-local dataplane config for one NetworkInterface.
// It bundles everything statically derivable; nothing routebus learns dynamically.
type CompiledNICSpec struct {
	NodeName      string          `json:"nodeName"`
	NICRef        LocalObjectReference `json:"nicRef"`
	VNI           int32           `json:"vni"`
	Port          PortStatus      `json:"port"`
	OverlayIPs    []string        `json:"overlayIPs,omitempty"`
	UnderlayRoute string          `json:"underlayRoute"`
	Firewall      CompiledFirewall `json:"firewall"`
	// +optional
	NAT *CompiledNAT `json:"nat,omitempty"`
}

type CompiledFirewall struct {
	Ingress []CompiledFwRule `json:"ingress,omitempty"`
	Egress  []CompiledFwRule `json:"egress,omitempty"`
}

type CompiledFwRule struct {
	CIDR   string `json:"cidr"`
	Proto  string `json:"proto,omitempty"`  // TCP/UDP/ICMP/"" (any)
	Port   int32  `json:"port,omitempty"`   // 0 = any
	Action string `json:"action"`           // Allow/Deny
}

type CompiledNAT struct {
	NATIP   string `json:"natIP"`
	PortMin int32  `json:"portMin"`
	PortMax int32  `json:"portMax"`
}

type CompiledNICStatus struct {
	State            string `json:"state,omitempty"`
	GenerationApplied int64 `json:"generationApplied,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type CompiledNIC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec   CompiledNICSpec   `json:"spec,omitempty"`
	Status CompiledNICStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type CompiledNICList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CompiledNIC `json:"items"`
}
```

- [ ] **Step 2: Register + deepcopy.** Add `&CompiledNIC{}, &CompiledNICList{}` to `addKnownTypes` in `register.go`. Generate deepcopy: run `make generate` (or the repo's controller-gen path) and confirm `zz_generated.deepcopy.go` gains `CompiledNIC` methods. If codegen is not wired, hand-write `DeepCopyObject`/`DeepCopyInto` mirroring an existing type in that file.

Run: `cd api && go build ./...`
Expected: PASS.

- [ ] **Step 3: Write the failing compiler test** `netplane/controllers/compilednic_test.go`

```go
func TestCompile_ProducesCompiledNIC(t *testing.T) {
	nic := &v1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0"},
		Spec:       v1alpha1.NetworkInterfaceSpec{IPs: []string{"10.0.0.10"}, NodeName: ptr("nodeA")},
		Status:     v1alpha1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8:fefe::bb",
			Port: &v1alpha1.PortStatus{Type: "tap", Name: "dtapvf_0"}},
	}
	pol := &v1alpha1.NetworkPolicy{ /* ingress allow 10.0.0.0/24 -> TCP 443, selects role=frontend */ }
	got := Compile(nic, []v1alpha1.NetworkPolicy{*pol})
	if got.Spec.VNI != 100 || got.Spec.UnderlayRoute != "2001:db8:fefe::bb" {
		t.Fatalf("identity/underlay not carried: %+v", got.Spec)
	}
	if len(got.Spec.Firewall.Ingress) != 1 ||
		got.Spec.Firewall.Ingress[0].Port != 443 ||
		got.Spec.Firewall.Ingress[0].Action != "Allow" {
		t.Fatalf("firewall not compiled: %+v", got.Spec.Firewall)
	}
}
```

- [ ] **Step 4: Implement `Compile()`** (pure fn) in `netplane/controllers/compilednic.go`: map NIC identity/underlay/port into `CompiledNICSpec`; for each `NetworkPolicy` whose `interfaceSelector` matches the NIC labels, translate `ingress`/`egress` rules into `CompiledFwRule`s (CIDR/proto/port/action). Add a thin `Reconciler` that watches `NetworkInterface`+`NetworkPolicy` and writes the `CompiledNIC` (the reconciler wiring can be minimal; the pure `Compile()` is what the test pins).

Run: `cd netplane && go test ./controllers/ -run TestCompile`
Expected: PASS.

- [ ] **Step 5: Emit a fixture + add the Rust `apply()` bridge.** Add a Go test (or `go run` helper) that marshals the compiled object to `flowplane-sim/testdata/compilednic.json`. Then in `flowplane-sim/src/compilednic.rs` define a serde mirror + `apply`:

```rust
use serde::Deserialize;
use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
use crate::MemMaps;

#[derive(Deserialize)]
pub struct CompiledNic { pub spec: Spec }
#[derive(Deserialize)]
pub struct Spec {
    pub vni: i32,
    #[serde(rename = "underlayRoute")] pub underlay_route: String,
    pub firewall: Firewall,
}
#[derive(Deserialize)]
pub struct Firewall { #[serde(default)] pub ingress: Vec<Rule> }
#[derive(Deserialize)]
pub struct Rule { pub cidr: String, #[serde(default)] pub proto: String,
                  #[serde(default)] pub port: i32, pub action: String }

/// Lower a CompiledNIC into native maps for `tap` — the sim analog of the agent's gRPC lowering.
pub fn apply(m: &mut MemMaps, c: &CompiledNic, tap: u32) {
    let n = c.spec.firewall.ingress.len() as u32;
    m.fw_meta.insert(tap, FwMeta { ingress_count: n, egress_count: 0 });
    for (idx, r) in c.spec.firewall.ingress.iter().enumerate() {
        m.fw_rules.insert((tap, idx as u32), rule_to_fw(r));
    }
}
// rule_to_fw: parse CIDR -> dst_ip/dst_mask, proto string -> num, port -> min=max, action -> const.
```

- [ ] **Step 6: Write the failing bridge test** (in `compilednic.rs` `#[cfg(test)]`): load `testdata/compilednic.json`, `apply()` into a `MemMaps`, craft a matching TCP/443 packet, assert `fw_eval_dir == FW_ACTION_ACCEPT`; craft TCP/80, assert DROP. Run `cargo test -p flowplane-sim compilednic`. Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add api netplane flowplane-sim
git commit -m "feat(compiledNIC): CRD + Compile() + sim apply() bridge"
```

---

## Task 8: `BPF_PROG_TEST_RUN` fidelity anchor

**Files:**
- Create: `flowplane/tests/anchor_encap.rs` (integration test, privileged, `#[ignore]` by default)
- Modify: `Makefile` (`sim-anchor` target)

- [ ] **Step 1: Write the anchor test** `flowplane/tests/anchor_encap.rs`

Load the compiled eBPF object (the same artifact `flowplane` embeds), populate the maps for a single-NIC N-S fixture (LOCAL, UNDERLAY, FW_META/FW_RULES from the same `compilednic.json`), then for the `uplink_rx` program call `aya`'s test-run:

```rust
// Gated: requires CAP_BPF + a kernel. Ignored unless run explicitly.
#[test]
#[ignore = "privileged: run via `make sim-anchor`"]
fn uplink_rx_bytecode_matches_native_sim() {
    // 1. Craft the SAME encapped packet the sim uses (reuse a shared builder or embed bytes).
    let encapped = fixtures::encapped_ns_frame();
    // 2. Native sim output.
    let mut host = flowplane_sim::SimNode::new();
    flowplane_sim::compilednic::apply(&mut host.maps, &fixtures::compiled_nic(), TAP);
    let native = host.host_uplink(&encapped, VNI, TAP, GUEST_MAC);
    // 3. Real bytecode via BPF_PROG_TEST_RUN.
    let mut bpf = load_flowplane_object();
    populate_maps_from_compiled(&mut bpf, &fixtures::compiled_nic());
    let prog: &mut aya::programs::Xdp = bpf.program_mut("uplink_rx").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let out = prog.test_run(&encapped).unwrap(); // aya XDP test_run: returns (action, out_bytes)
    // 4. Assert byte-parity + action-parity.
    assert_eq!(out.action_as_redirect_ifindex(), Some(TAP));
    assert_eq!(out.data(), native.pkt.as_slice(),
        "native pure-core output diverged from real bytecode");
}
```

If the installed `aya` version lacks an XDP `test_run` wrapper, call `libbpf`/the `BPF_PROG_TEST_RUN` syscall directly via `aya`'s `SyscallError` path or the `bpf_prog_test_run` helper; document the exact API used. Keep this the ONLY privileged test.

- [ ] **Step 2: Add the `Makefile` target**

```make
.PHONY: sim-anchor
sim-anchor: ## Run the privileged BPF_PROG_TEST_RUN byte-parity anchor
	cargo build -p flowplane
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_encap -- --ignored --exact \
		uplink_rx_bytecode_matches_native_sim
```

- [ ] **Step 3: Run it**

Run: `make sim-anchor`
Expected: PASS (native pure-core output == real bytecode output). If it fails with a byte diff, that IS the anchor doing its job — reconcile `uplink_base_deliver` with the real `try_uplink_rx` delivery until they match.

- [ ] **Step 4: Commit**

```bash
git add flowplane/tests Makefile
git commit -m "test(anchor): BPF_PROG_TEST_RUN byte-parity anchor for the N-S path"
```

---

## Task 9: Docs + fast-path make target

**Files:**
- Modify: `Makefile`, `README.md`

- [ ] **Step 1: Add a fast sim target** to `Makefile`:

```make
.PHONY: sim
sim: ## Fast in-process datapath tests (no root, no clab)
	cargo test -p flowplane-core -p flowplane-sim
```

- [ ] **Step 2: Document the harness** — a short README section: what `make sim` covers, what `make sim-anchor` guarantees, and the rule "new datapath feature ⇒ port the fn behind `Maps`/`Pkt`, add a sim scenario, add one anchor case."

- [ ] **Step 3: Run + commit**

Run: `make sim`
Expected: PASS.
```bash
git add Makefile README.md
git commit -m "docs: sim + sim-anchor targets and the port-a-feature workflow"
```

---

## Self-Review notes (for the executor)

- **Spec coverage:** Task 1–2 = crates + traits (§5.1–5.2); Task 3–5 = leaf ports (§5.3); Task 6 = base-path seam + the §6 green test; Task 7 = pillars-1↔2 bridge (§4, §5.4 `apply`); Task 8 = anchor (§5.5); Task 9 = verification ergonomics (§7).
- **The delicate task is 6** — `uplink_base_deliver` MUST mirror the real `try_uplink_rx` delivery byte-for-byte; the conformance suite (Step 5) and the anchor (Task 8) are the guards. Read `flowplane-ebpf/src/ingress.rs:100-317` fully before writing it.
- **Verifier risk** surfaces at eBPF load (conformance `serve` startup). If a `Pkt`/`Maps` rewire breaks the verifier, it fails immediately at Task 3/4/5 Step 6 — fix before moving on.
- **Names to verify against the codebase before use:** `FW_ACTION_ACCEPT/DROP`, `FW_DIR_INGRESS/EGRESS`, `FW_MAX_RULES`, `PacketSelectors`, `fw_rule_matches`, `UnderlayValue` fields (`vni`, `tap_ifindex`, `guest_mac`), `CtKey`/`CtEntry` fields, `PortStatus`/`LocalObjectReference` Go types. Where a symbol lives in `flowplane-ebpf` but is needed by core, move it to `flowplane-common` (POD/consts) or `flowplane-core` (logic).
