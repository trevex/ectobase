# nfkit M3 — flowplane-core on DPDK (uplink + guest-egress) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the existing `flowplane-core` datapath (uplink-ingress + guest-egress) on DPDK via `MbufPkt: Pkt` + `DpdkMaps: Maps` (over real `rte_hash`), composed through shared generic orchestrators, and prove byte-parity with the sim.

**Architecture:** Extract the orchestration inside `SimNode::uplink`/`guest_tx` into generic `process_uplink<P:Pkt,M:Maps>` / `process_guest_tx<P:Pkt,M:Maps>` in `flowplane-core`. The sim AND the DPDK path both call them; the eBPF dataplane is untouched (already anchored to the sim). Parity is then reduced to "does `MbufPkt` behave like `VecPkt` and `DpdkMaps` like `MemMaps`" — tested directly.

**Tech Stack:** Rust (rustup nightly per repo), `dpdk-sys`/`nfkit` (from M1/M2), DPDK 25.11.2 `rte_hash`, `flowplane-core` traits (`Pkt`/`Maps`) + fns. Run cargo inside `nix develop`.

**Context (grounded):**
- `Pkt` trait (`flowplane-core/src/pkt.rs`): `len`, `logical_len`, `read_array::<N>`, `write_bytes`, `write_array::<N>` (default→write_bytes), `grow_head`, `shrink_head`, `set_tail` (default false), `read_u16_be`/`read_u8` (defaults). `Action { Pass, Drop, Redirect(u32) }`.
- `Maps` trait (`flowplane-core/src/maps.rs`): `local`, `underlay_get`, `fw_meta`, `fw_rule`, `conntrack_get`, `conntrack_insert(&mut)`, `lb_get`, `maglev_get`, `nat_get`, `route4_get`, `route6_get`, `dhcp_config`, `dhcp_meta`, `meter_get`, `meter_update(&mut)`.
- The sim's `MemMaps` (`flowplane-sim/src/maps.rs`) is the reference `Maps` impl; `VecPkt` (`flowplane-sim/src/pkt.rs`) the reference `Pkt`.
- `SimNode::uplink` and `SimNode::guest_tx` (`flowplane-sim/src/sim.rs`) hold the orchestrations to extract. `guest_tx` body is lines ~290-420; `uplink` ~107-180.
- Key structs (`flowplane-common`): `CtKey`, `CtEntry`, `NatKey`, `NatValue`, `LbKey`, `LbValue`, `MaglevKey`, `FwRuleKey`, `FwRule`, `FwMeta`, `UnderlayValue`, `RouteValue`, `MeterState`, `DhcpMeta`, `Local`, `DhcpConfig`, `PortMeta` — used as eBPF map keys/values, so `#[repr(C)]` POD.
- `dpdk-sys` bindgen allowlists `rte_.*` → `rte_hash_*` fns come free once `rte_hash.h` is in `wrapper.h`. `nfkit` depends on `dpdk-sys`; this milestone adds a dep on `flowplane-core` (a `no_std`, trait-only crate — must NOT pull DPDK into flowplane-core).

---

## File Structure
- `flowplane/dpdk-sys/wrapper.h` — `+#include <rte_hash.h>`.
- `flowplane/nfkit/Cargo.toml` — `+ flowplane-core = { path = "../flowplane-core" }`, `+ flowplane-common = { path = "../flowplane-common" }`.
- `flowplane/nfkit/src/dpdk_hash.rs` — `DpdkHash<K,V>` (safe typed rte_hash).
- `flowplane/nfkit/src/dpdk_maps.rs` — `DpdkMaps: Maps`.
- `flowplane/nfkit/src/mbuf_pkt.rs` — `MbufPkt: Pkt`.
- `flowplane-core/src/datapath.rs` — `process_uplink`, `process_guest_tx` (+ their `In`/`Out` types).
- `flowplane-sim/src/sim.rs` — `SimNode::uplink`/`guest_tx` become thin wrappers over the extracted fns.
- `flowplane/nfkit/src/lib.rs` — re-exports.
- `flowplane/nfkit/tests/{dpdk_hash.rs, mbuf_pkt.rs, parity_uplink.rs, parity_guest_tx.rs, datapath_pcap.rs}`.

---

## Task 1: rte_hash bindings + safe `DpdkHash<K,V>`

**Files:** Modify `flowplane/dpdk-sys/wrapper.h`; modify `flowplane/nfkit/Cargo.toml`; create `flowplane/nfkit/src/dpdk_hash.rs`; modify `flowplane/nfkit/src/lib.rs`; test `flowplane/nfkit/tests/dpdk_hash.rs`.

- [ ] **Step 1: Expose rte_hash to bindgen**

In `flowplane/dpdk-sys/wrapper.h`, add `#include <rte_hash.h>` (with the other includes). Rebuild check: `nix develop --command bash -c 'cd flowplane && cargo build -p dpdk-sys'` (cache hit; fast) — the crate still builds and `rte_hash_create`/`rte_hash_free`/`rte_hash_add_key`/`rte_hash_lookup`/`rte_hash_parameters` now appear in the generated bindings (grep the OUT_DIR bindings.rs if unsure).

- [ ] **Step 2: Add nfkit deps**

In `flowplane/nfkit/Cargo.toml` `[dependencies]`:
```toml
flowplane-core = { path = "../flowplane-core" }
flowplane-common = { path = "../flowplane-common" }
```

- [ ] **Step 3: Write the failing test `flowplane/nfkit/tests/dpdk_hash.rs`**
```rust
// Typed rte_hash: add/lookup/miss/overwrite over a POD key + Copy value. Requires EAL; --test-threads=1.
use nfkit::{DpdkHash, Eal};

#[derive(Copy, Clone)]
#[repr(C)]
struct K {
    a: u32,
    b: u32,
}

#[test]
fn dpdk_hash_add_lookup_overwrite() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_hash",
    ])
    .expect("EAL init");
    let mut h: DpdkHash<K, u64> = DpdkHash::new("t", 1024, 0).expect("hash");
    assert_eq!(h.get(&K { a: 1, b: 2 }), None);
    h.insert(&K { a: 1, b: 2 }, 42);
    assert_eq!(h.get(&K { a: 1, b: 2 }), Some(42));
    assert_eq!(h.get(&K { a: 1, b: 3 }), None, "different key misses");
    h.insert(&K { a: 1, b: 2 }, 99); // overwrite same key
    assert_eq!(h.get(&K { a: 1, b: 2 }), Some(99));
}
```
Run to FAIL: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test dpdk_hash -- --test-threads=1'`.

- [ ] **Step 4: Implement `flowplane/nfkit/src/dpdk_hash.rs`**
```rust
//! Safe typed wrapper over a DPDK `rte_hash`. Key = the raw bytes of `K` (K must be `#[repr(C)]`
//! POD with no padding — key_len = size_of::<K>()). Values live in a companion slab indexed by the
//! stable position `rte_hash_add_key` returns. Any hash function is fine — correctness is the exact
//! key->value mapping, not the hash values.
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_void;
use std::ptr::NonNull;

#[derive(Debug)]
pub struct HashError;

pub struct DpdkHash<K: Copy, V: Copy> {
    raw: NonNull<dpdk_sys::rte_hash>,
    slab: Vec<Option<V>>,
    _k: PhantomData<K>,
}

impl<K: Copy, V: Copy> DpdkHash<K, V> {
    /// Create a hash with capacity `entries` on NUMA `socket_id`.
    ///
    /// # Errors
    /// Returns `HashError` if `rte_hash_create` fails (name clash / out of memory).
    pub fn new(name: &str, entries: u32, socket_id: i32) -> Result<Self, HashError> {
        let cname = CString::new(name).map_err(|_| HashError)?;
        let mut params: dpdk_sys::rte_hash_parameters = unsafe { std::mem::zeroed() };
        params.name = cname.as_ptr();
        params.entries = entries;
        params.key_len = std::mem::size_of::<K>() as u32;
        params.socket_id = socket_id;
        // hash_func = None -> DPDK default (jhash). hash_func_init_val = 0.
        // SAFETY: params fully initialized; name lives for the call.
        let raw = unsafe { dpdk_sys::rte_hash_create(&params) };
        let raw = NonNull::new(raw).ok_or(HashError)?;
        Ok(Self { raw, slab: vec![None; entries as usize], _k: PhantomData })
    }

    /// Insert/overwrite `k -> v`.
    pub fn insert(&mut self, k: &K, v: V) {
        // SAFETY: k points to size_of::<K>() bytes (== key_len); the hash copies the key.
        let pos = unsafe { dpdk_sys::rte_hash_add_key(self.raw.as_ptr(), k as *const K as *const c_void) };
        if pos >= 0 {
            self.slab[pos as usize] = Some(v);
        }
    }

    /// Look up `k`.
    #[must_use]
    pub fn get(&self, k: &K) -> Option<V> {
        // SAFETY: k points to key_len bytes; read-only lookup.
        let pos = unsafe { dpdk_sys::rte_hash_lookup(self.raw.as_ptr(), k as *const K as *const c_void) };
        if pos >= 0 {
            self.slab[pos as usize]
        } else {
            None
        }
    }
}

impl<K: Copy, V: Copy> Drop for DpdkHash<K, V> {
    fn drop(&mut self) {
        // SAFETY: sole owner; frees the hash.
        unsafe { dpdk_sys::rte_hash_free(self.raw.as_ptr()) }
    }
}
```
Wire lib.rs: `mod dpdk_hash; pub use dpdk_hash::{DpdkHash, HashError};`

Note: if `rte_hash_add_key` for an EXISTING key returns the SAME position (DPDK guarantees this — a key's position is stable until deleted), overwrite works. Confirm via the test's overwrite assertion. If the bindgen field names on `rte_hash_parameters` differ (e.g. `socket_id` vs `socket`), grep the generated bindings and adjust.

- [ ] **Step 5: Run → PASS.** `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test dpdk_hash -- --test-threads=1'`. clippy `-p nfkit --all-targets` clean; fmt clean.

- [ ] **Step 6: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/dpdk-sys/wrapper.h flowplane/nfkit/Cargo.toml flowplane/nfkit/src/dpdk_hash.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/dpdk_hash.rs
git commit -m "feat(nfkit): rte_hash bindings + safe typed DpdkHash<K,V>"
```

---

## Task 2: `DpdkMaps: Maps`

**Files:** Create `flowplane/nfkit/src/dpdk_maps.rs`; modify lib.rs; test `flowplane/nfkit/tests/dpdk_maps.rs`.

- [ ] **Step 1: Write the failing test**
```rust
// DpdkMaps implements flowplane_core::maps::Maps over DpdkHash. Spot-check a getter + a mut inserter.
use flowplane_common::{CtEntry, CtKey, RouteValue};
use flowplane_core::maps::Maps;
use nfkit::{DpdkMaps, Eal};

#[test]
fn dpdk_maps_route_and_conntrack() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_maps",
    ])
    .expect("EAL init");
    let mut m = DpdkMaps::new(0).expect("maps");
    // route4
    let rv = RouteValue { nexthop_vni: 0, nexthop_ipv6: [0x20; 16], is_external: 0, _pad: [0; 3] };
    m.add_route4(7, [10, 0, 0, 5], rv);
    assert_eq!(m.route4_get(7, &[10, 0, 0, 5]), Some(rv));
    assert_eq!(m.route4_get(7, &[10, 0, 0, 6]), None);
    // conntrack insert via the trait (mut)
    let k = CtKey::default();
    assert!(m.conntrack_get(&k).is_none());
    let e = CtEntry::default();
    m.conntrack_insert(k, e);
    assert!(m.conntrack_get(&k).is_some());
}
```
(If `CtKey`/`CtEntry`/`RouteValue` lack `Default`/`PartialEq`, construct explicit literals matching their fields — read `flowplane-common/src/lib.rs` for the exact fields. Keep the test asserting: add→get hit, wrong-key miss, conntrack insert→get.)

Run to FAIL.

- [ ] **Step 2: Implement `flowplane/nfkit/src/dpdk_maps.rs`**

Implement a `DpdkMaps` struct holding one `DpdkHash<K,V>` per keyed map plus single cells for `local`/`dhcp_config`, and `impl flowplane_core::maps::Maps for DpdkMaps`. Read `flowplane-sim/src/maps.rs` (`MemMaps`) for the exact key derivation each `Maps` method uses (e.g. `route4_get(vni,dst)` builds a composite key; `fw_rule(key)` uses `FwRuleKey`), and mirror them with `DpdkHash`. Skeleton:
```rust
//! `Maps` over DPDK rte_hash. One DpdkHash per keyed map; single cells for local/dhcp_config.
use crate::dpdk_hash::DpdkHash;
use flowplane_common::*;
use flowplane_core::maps::Maps;

pub struct DpdkMaps {
    conntrack: DpdkHash<CtKey, CtEntry>,
    nat: DpdkHash<NatKey, NatValue>,
    underlay: DpdkHash<[u8; 16], UnderlayValue>,
    route4: DpdkHash<Route4Key, RouteValue>, // Route4Key = {vni:u32, ipv4:[u8;4]} #[repr(C)]
    route6: DpdkHash<Route6Key, RouteValue>, // Route6Key = {vni:u32, ipv6:[u8;16]} #[repr(C)]
    lb: DpdkHash<LbKey, LbValue>,
    maglev: DpdkHash<MaglevKey, [u8; 16]>,
    fw_rules: DpdkHash<FwRuleKey, FwRule>,
    fw_meta: DpdkHash<u32, FwMeta>,
    dhcp_meta: DpdkHash<u32, DhcpMeta>,
    meter: DpdkHash<u32, MeterState>,
    local: Option<Local>,
    dhcp_config: Option<DhcpConfig>,
}
```
Define small `#[repr(C)] Route4Key`/`Route6Key` (or reuse existing composite key types if `flowplane-common` already exposes them — check first; `route4_get`/`route6_get` in `MemMaps` show how the key is formed). `DpdkMaps::new(socket_id)` creates each hash with a sensible capacity (e.g. 4096; conntrack 65536). Add test-only setters mirroring `MemMaps` (`add_route4`, `add_nat`, `.underlay`/`.lb`/`.maglev` inserts, etc.) so tests + the parity anchors can populate it identically to `MemMaps`. Implement each `Maps` method by delegating to the matching `DpdkHash` (`conntrack_get(k)=self.conntrack.get(k)`, `conntrack_insert(k,e)=self.conntrack.insert(&k,e)`, `route4_get(vni,dst)=self.route4.get(&Route4Key{vni,ipv4:*dst})`, `local()=self.local`, `meter_update(i,s)=self.meter.insert(&i,s)`, etc.).

Wire lib.rs: `mod dpdk_maps; pub use dpdk_maps::DpdkMaps;`

- [ ] **Step 3: Run → PASS.** clippy/fmt clean.

- [ ] **Step 4: Commit**
```bash
git add flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/dpdk_maps.rs
git commit -m "feat(nfkit): DpdkMaps — flowplane-core Maps over rte_hash"
```

---

## Task 3: `MbufPkt: Pkt`

**Files:** Create `flowplane/nfkit/src/mbuf_pkt.rs`; modify lib.rs; test `flowplane/nfkit/tests/mbuf_pkt.rs`.

- [ ] **Step 1: Write the failing test** — assert `MbufPkt` and `VecPkt` produce identical results for read/write/grow/shrink on the same bytes.
```rust
use flowplane_core::pkt::Pkt;
use nfkit::{Eal, MbufPkt, Mempool};

#[test]
fn mbufpkt_matches_vecpkt_ops() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_mp3",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mp3", 1023, 250, 0).expect("pool");
    let mut mb = pool.alloc().expect("alloc");
    // Load 8 bytes into the mbuf.
    let tail = mb.append(8).unwrap();
    tail.copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17]);
    let mut p = MbufPkt::new(&mut mb);

    assert_eq!(p.len(), 8);
    assert_eq!(p.read_array::<4>(2), Some([12, 13, 14, 15]));
    assert!(p.write_bytes(0, &[0xaa, 0xbb]));
    assert_eq!(p.read_array::<2>(0), Some([0xaa, 0xbb]));
    // grow_head 2, write a header
    assert!(p.grow_head(2));
    assert!(p.write_bytes(0, &[1, 2]));
    assert_eq!(p.len(), 10);
    assert_eq!(p.read_array::<4>(0), Some([1, 2, 0xaa, 0xbb]));
    // shrink_head 2 -> back to 8, original front restored
    assert!(p.shrink_head(2));
    assert_eq!(p.len(), 8);
    assert_eq!(p.read_array::<2>(0), Some([0xaa, 0xbb]));
    // out-of-range reads/writes are safe
    assert_eq!(p.read_array::<4>(6), Some([14, 15, 16, 17]));
    assert_eq!(p.read_array::<4>(7), None);
    assert!(!p.write_bytes(7, &[1, 2, 3, 4]));
}
```
Run to FAIL.

- [ ] **Step 2: Implement `flowplane/nfkit/src/mbuf_pkt.rs`**
```rust
//! `flowplane_core::pkt::Pkt` over an `Mbuf` (single-segment). Thin wrappers over the mbuf shim.
use crate::mbuf::Mbuf;
use flowplane_core::pkt::Pkt;
use std::marker::PhantomData;
use std::slice;

/// A `Pkt` view over a borrowed mutable `Mbuf`. The mbuf stays owned by the caller (e.g. an rx
/// burst); `MbufPkt` provides read/write/grow/shrink for the flowplane-core datapath.
pub struct MbufPkt<'a> {
    raw: *mut dpdk_sys::rte_mbuf,
    _m: PhantomData<&'a mut Mbuf>,
}

impl<'a> MbufPkt<'a> {
    #[inline]
    #[must_use]
    pub fn new(m: &'a mut Mbuf) -> Self {
        Self { raw: m.as_raw(), _m: PhantomData }
    }
    #[inline]
    fn data_len(&self) -> usize {
        // SAFETY: live mbuf borrowed for 'a.
        unsafe { dpdk_sys::nfkit_pktmbuf_data_len(self.raw) as usize }
    }
    #[inline]
    fn base(&self) -> *mut u8 {
        // SAFETY: live mbuf; mtod points at the data start within the dataroom.
        unsafe { dpdk_sys::nfkit_pktmbuf_mtod(self.raw) }
    }
}

impl Pkt for MbufPkt<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.data_len()
    }
    #[inline]
    fn logical_len(&self) -> usize {
        // Single-segment: pkt_len == data_len.
        unsafe { dpdk_sys::nfkit_pktmbuf_pkt_len(self.raw) as usize }
    }
    #[inline]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        if off.checked_add(N)? > self.data_len() {
            return None;
        }
        let mut out = [0u8; N];
        // SAFETY: off+N <= data_len, so base+off..+N is within the packet data.
        unsafe { slice::from_raw_parts(self.base().add(off), N) }.clone_into(&mut out.as_mut_slice()[..]);
        Some(out)
    }
    #[inline]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        match off.checked_add(src.len()) {
            Some(end) if end <= self.data_len() => {
                // SAFETY: off+len <= data_len; exclusive &mut self.
                unsafe { slice::from_raw_parts_mut(self.base().add(off), src.len()) }.copy_from_slice(src);
                true
            }
            _ => false,
        }
    }
    #[inline]
    fn grow_head(&mut self, delta: usize) -> bool {
        // SAFETY: DPDK bounds-checks headroom, NULL on overflow.
        !unsafe { dpdk_sys::nfkit_pktmbuf_prepend(self.raw, delta as u16) }.is_null()
    }
    #[inline]
    fn shrink_head(&mut self, delta: usize) -> bool {
        // SAFETY: DPDK returns NULL if delta > data_len.
        !unsafe { dpdk_sys::nfkit_pktmbuf_adj(self.raw, delta as u16) }.is_null()
    }
    // set_tail default (false) is fine — uplink/guest-egress paths do not resize the tail.
}
```
(If `clone_into` on the array is awkward, use `out.copy_from_slice(unsafe { slice::from_raw_parts(self.base().add(off), N) })`.) Wire lib.rs: `mod mbuf_pkt; pub use mbuf_pkt::MbufPkt;`

- [ ] **Step 3: Run → PASS.** clippy/fmt clean.

- [ ] **Step 4: Commit**
```bash
git add flowplane/nfkit/src/mbuf_pkt.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/mbuf_pkt.rs
git commit -m "feat(nfkit): MbufPkt — flowplane-core Pkt over an Mbuf"
```

---

## Task 4: Extract `process_uplink` + DPDK uplink parity (the gate)

**Files:** Create `flowplane-core/src/datapath.rs`; modify `flowplane-core/src/lib.rs`; modify `flowplane-sim/src/sim.rs` (`SimNode::uplink` → wrapper); test `flowplane/nfkit/tests/parity_uplink.rs`.

- [ ] **Step 1: Extract the orchestrator (pure move — must not change behaviour)**

Create `flowplane-core/src/datapath.rs`. Move the BODY of `SimNode::uplink` (currently in `flowplane-sim/src/sim.rs`, ~lines 107-180) into a generic free function, with these mechanical substitutions ONLY (no logic change):
- `self.maps` → `maps` (a `&mut M`), `&self.maps` → `&*maps`.
- inputs the method took as fields/args (`vni`, `u: UnderlayValue`, `outer_dst`, `local: &Local`) → parameters of an `UplinkIn` input struct.
- return `SimOut { action, pkt: pkt.into_bytes() }` → return `Action` (the caller repackages); the function mutates `pkt: &mut P` in place.

```rust
//! Shared datapath orchestrators over the Pkt/Maps traits. The sim and the DPDK backend both call
//! these; the eBPF wrapper mirrors them and is guarded by BPF_PROG_TEST_RUN anchors against the sim.
use crate::maps::Maps;
use crate::pkt::{Action, Pkt};
use flowplane_common::{Local, UnderlayValue};

/// Inputs to the uplink-ingress path (what SimNode::uplink took).
pub struct UplinkIn<'a> {
    pub vni: u32,
    pub u: UnderlayValue,
    pub outer_dst: [u8; 16],
    pub local: &'a Local,
}

/// Run the uplink-ingress datapath in place; returns the delivery Action. Mirrors eBPF try_uplink_rx.
pub fn process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> Action {
    // <<< the exact body of SimNode::uplink, s/self.maps/maps/, using in_.vni/in_.u/in_.outer_dst/in_.local,
    //     returning Action instead of SimOut >>>
}
```
Add `pub mod datapath;` to `flowplane-core/src/lib.rs`. The exact body is a verbatim move; do not rewrite the logic.

- [ ] **Step 2: Rewire `SimNode::uplink` to call it (thin wrapper)**

Replace the body of `SimNode::uplink` in `flowplane-sim/src/sim.rs` with:
```rust
    pub fn uplink(&mut self, encapped: &[u8], vni: u32, u: UnderlayValue, outer_dst: [u8; 16], local: &Local) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let in_ = flowplane_core::datapath::UplinkIn { vni, u, outer_dst, local: &*local };
        let action = flowplane_core::datapath::process_uplink(&mut pkt, &mut self.maps, &in_);
        SimOut { action, pkt: pkt.into_bytes() }
    }
```
(Match the CURRENT `SimNode::uplink` signature exactly — read it first; keep the same params/order. If it also did ingress metering that mutated `last_tstamp`/returned data, thread that through `UplinkIn`/an out value identically — do NOT drop any step.)

- [ ] **Step 3: Prove the refactor is byte-preserving**

Run the FULL sim suite + the eBPF anchors:
`nix develop --command bash -c 'cd flowplane && cargo test -p flowplane-sim'`
and `nix develop --command bash -c 'cd flowplane && cargo test -p flowplane --tests 2>&1 | tail -20'` (the `anchor_*` tests — they compile; the privileged ones ignore). Expected: **all sim tests still pass** (esp. `lb_scenario_test`, `ns_scenario_test`, `vni_test`, `peering_test` which drive `uplink`). If any differ, the extraction changed behaviour — fix the move to be verbatim. This is the acceptance gate for the refactor.

- [ ] **Step 4: DPDK uplink parity anchor `flowplane/nfkit/tests/parity_uplink.rs`**

For a crafted encapped input frame + identical map contents in `DpdkMaps` and `MemMaps`, assert `process_uplink` over `MbufPkt`+`DpdkMaps` == over `VecPkt`+`MemMaps` (same output bytes + Action). One test, EAL once.
```rust
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::Pkt;
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};
// plus flowplane_sim::{MemMaps, VecPkt} and flowplane_common types

#[test]
fn uplink_parity_dpdk_vs_sim() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_pu",
    ]).expect("EAL init");

    // 1. Craft an encapped input frame (OuterEth+OuterIPv6+innerIP...) as Vec<u8> (reuse a sim
    //    fixture builder — see lb_scenario_test / the sim's encap helpers for the exact wire layout).
    let frame: Vec<u8> = /* build a base (non-LB) encapped frame destined to a LOCAL tap */;
    let vni = 100u32;
    let outer_dst = /* the /128 in the frame's outer dst */;
    let u = /* UnderlayValue{vni, tap_ifindex, guest_mac} for a local delivery */;
    let local = /* Local{...} */;

    // 2. Populate BOTH maps identically (underlay entry, any fw allow, etc.) — factor a helper.
    let mut mem = flowplane_sim::MemMaps::default();
    let mut dpk = DpdkMaps::new(0).unwrap();
    populate(&mut mem); populate_dpdk(&mut dpk); // same entries

    // 3. Run the sim side.
    let mut vp = flowplane_sim::VecPkt::from_bytes(&frame);
    let a_sim = process_uplink(&mut vp, &mut mem, &UplinkIn{ vni, u, outer_dst, local: &local });
    let out_sim = vp.into_bytes();

    // 4. Run the DPDK side: mbuf loaded with the same frame.
    let pool = Mempool::new("pu", 1023, 250, 0).unwrap();
    let mut mb = pool.alloc().unwrap();
    mb.append(frame.len() as u16).unwrap();
    mb.data_mut().copy_from_slice(&frame);
    let a_dpdk;
    let out_dpdk;
    {
        let mut mp = MbufPkt::new(&mut mb);
        a_dpdk = process_uplink(&mut mp, &mut dpk, &UplinkIn{ vni, u, outer_dst, local: &local });
        out_dpdk = mp_bytes(&mp); // read mp.len() bytes via read_array in a loop, or expose a helper
    }

    assert_eq!(a_sim, a_dpdk, "Action parity");
    assert_eq!(out_sim, out_dpdk, "output byte parity");
}
```
Fill the `/* ... */` from the sim's existing fixtures (read `lb_scenario_test.rs`/`ns_scenario_test.rs` for how they build encapped frames + populate maps). Add a small `mp_bytes(&MbufPkt)` helper (read `len()` bytes). Cover at least: base decap→local delivery, and one LB reforward case.

- [ ] **Step 5: Run → PASS.** clippy/fmt clean. Commit:
```bash
git add flowplane-core/src/datapath.rs flowplane-core/src/lib.rs flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_uplink.rs
git commit -m "feat: extract process_uplink orchestrator (sim+DPDK share) + DPDK uplink byte-parity anchor"
```

---

## Task 5: Extract `process_guest_tx` + DPDK guest-egress parity

**Files:** Modify `flowplane-core/src/datapath.rs`; modify `flowplane-sim/src/sim.rs` (`SimNode::guest_tx` → wrapper); test `flowplane/nfkit/tests/parity_guest_tx.rs`.

- [ ] **Step 1: Extract `process_guest_tx`**

Add to `flowplane-core/src/datapath.rs`. Move the BODY of `SimNode::guest_tx` (`flowplane-sim/src/sim.rs` ~lines 290-420) verbatim with substitutions: `self.maps`→`maps`, `self.src_ifindex`→`in_.src_ifindex`, `self.now`→`in_.now`, `self.last_tstamp = X` → set a local `edt_tstamp = X`, and `return SimOut{action, pkt:pkt.into_bytes()}` → `return GuestTxOut{ action, edt_tstamp }` (the function mutates `pkt` in place). Signature:
```rust
pub struct GuestTxIn<'a> {
    pub meta: &'a flowplane_common::PortMeta,
    pub src_ifindex: u32,
    pub now: u64,
}
pub struct GuestTxOut {
    pub action: Action,
    pub edt_tstamp: Option<u64>,
}
/// Guest-egress datapath in place. Mirrors eBPF forward_decision_v4 + tc_guest_tx. `ip_off = ETH_LEN`.
pub fn process_guest_tx<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &GuestTxIn) -> GuestTxOut {
    let ip_off = crate::encap::ETH_LEN;
    // <<< verbatim body of SimNode::guest_tx (steps 1-7), s/self.maps/maps/, s/self.src_ifindex/in_.src_ifindex/,
    //     s/self.now/in_.now/, meta -> in_.meta, edt_tstamp instead of self.last_tstamp, returning GuestTxOut >>>
}
```

- [ ] **Step 2: Rewire `SimNode::guest_tx`**
```rust
    pub fn guest_tx(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        let mut pkt = VecPkt::from_bytes(frame);
        let out = flowplane_core::datapath::process_guest_tx(
            &mut pkt, &mut self.maps,
            &flowplane_core::datapath::GuestTxIn { meta, src_ifindex: self.src_ifindex, now: self.now },
        );
        self.last_tstamp = out.edt_tstamp;
        SimOut { action: out.action, pkt: pkt.into_bytes() }
    }
```

- [ ] **Step 3: Prove byte-preserving.** `cargo test -p flowplane-sim` — ALL pass (esp. `meter_test`, `nat_test`, `encap_test`, `flow_label_test`, `vni_test` which drive `guest_tx`). Fix the move if any differ.

- [ ] **Step 4: DPDK guest-egress parity anchor `flowplane/nfkit/tests/parity_guest_tx.rs`**

Same pattern as Task 4 Step 4 but calling `process_guest_tx`. Cover: guest→external ENCAP (asserts outer IPv6 + flow-label bytes identical), guest→internal LOCAL delivery, SNAT case, firewall-drop. Assert `out.action`, `out.edt_tstamp`, and output bytes all equal between `MbufPkt`+`DpdkMaps` and `VecPkt`+`MemMaps`. Build the guest frame + maps from the existing `nat_test`/`meter_test` fixtures.

- [ ] **Step 5: Run → PASS.** clippy/fmt clean. Commit:
```bash
git add flowplane-core/src/datapath.rs flowplane-sim/src/sim.rs flowplane/nfkit/tests/parity_guest_tx.rs
git commit -m "feat: extract process_guest_tx (sim+DPDK share) + DPDK guest-egress byte-parity anchor"
```

---

## Task 6: net_pcap datapath e2e

**Files:** Create `flowplane/nfkit/examples/uplink_fwd.rs`; test `flowplane/nfkit/tests/datapath_pcap.rs`; fixture `flowplane/nfkit/tests/data/uplink_in.pcap`.

- [ ] **Step 1: Example `examples/uplink_fwd.rs`** — like the M2 l2fwd, but the per-packet body wraps each rx'd `Mbuf` in `MbufPkt`, calls `process_uplink` with a fixed `DpdkMaps`/`UplinkIn` (populated at startup to deliver to a known tap → the packet is decapped), and tx's the result. Accept `pcap <in> <out>`.

- [ ] **Step 2: Generate the input pcap fixture** with scapy (an encapped frame matching the map config), like M2 Task 8 Step 1.

- [ ] **Step 3: Test `tests/datapath_pcap.rs`** — build + run the `uplink_fwd` example on `net_pcap`, then assert the output pcap equals the sim's `process_uplink` output for the same input frame (run the sim side in the test, compare bytes). Run the built binary directly (avoid nested cargo lock), inside `nix develop`.

- [ ] **Step 4: Run → PASS.** Commit:
```bash
git add flowplane/nfkit/examples/uplink_fwd.rs flowplane/nfkit/tests/datapath_pcap.rs flowplane/nfkit/tests/data/uplink_in.pcap
git commit -m "test(nfkit): net_pcap uplink datapath e2e (rx->process_uplink->tx) matches sim"
```

---

## Definition of Done (M3)
- `cargo test -p nfkit -- --test-threads=1`: dpdk_hash, dpdk_maps, mbuf_pkt, `parity_uplink`, `parity_guest_tx` (byte-identical DPDK-vs-sim), and `datapath_pcap` e2e all pass.
- `cargo test -p flowplane-sim` and the `flowplane` `anchor_*` tests pass UNCHANGED — the `SimNode` refactor to call the shared orchestrators preserved behaviour exactly (the parity chain `DPDK==sim==eBPF` holds).
- `flowplane-core` gained `datapath.rs` (generic, `no_std`, no DPDK dep); `dpdk-sys` gained rte_hash; nfkit gained MbufPkt/DpdkHash/DpdkMaps.
- Default host build + existing tests untouched.

**Next milestone (M4+, separate):** multi-lcore + symmetric-RSS flow pinning + the established-flow offload seam (rte_flow RAW_DECAP + REPRESENTED_PORT) and HW-EDT wiring (mbuf tx-timestamp) — the performance/offload phase. Remaining datapath paths (NAT64, edge/WAN, DHCP/ARP/ND) as they're needed.

## Risks / notes
- **Verbatim extraction is mandatory** — Tasks 4/5 Step 3 (full sim suite green) is the acceptance test. If a sim test changes, the move was not verbatim.
- **Key POD layout:** verify each rte_hash key type is `#[repr(C)]` with `size_of == sum of fields` (no padding). If a key has padding, hashing raw bytes includes uninitialized padding → nondeterministic. `CtKey` etc. are BPF keys so should be tight; add `const _: () = assert!(size_of::<CtKey>() == ...)` guards in `DpdkMaps`.
- **`MemMaps` reference:** read `flowplane-sim/src/maps.rs` to mirror exact key derivation + the test setters, so `DpdkMaps` populates identically for the anchors.
- **rte_hash position stability:** `rte_hash_add_key` returns the same position for an existing key (overwrite path). Confirmed by the Task 1 overwrite test.
