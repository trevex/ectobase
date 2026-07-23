# flowplane-dpdk B1b: serve binary + both images — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable, image-able `flowplane-dpdk serve` binary that runs the `flowplane-core` datapath on the `nfkit` DPDK runtime AND serves the `DataplaneNode` gRPC by programming DPDK config maps through the shared `flowplane-control` orchestration — plus a `Dockerfile.dpdk` + CI so we ship two binaries and two images.

**Architecture:** Split the monolithic per-lcore `DpdkMaps` into a process-wide `SharedConfigMaps` (one `rte_hash` per config table, `RW_CONCURRENCY_LF` + QSBR RCU, single tokio writer) and per-lcore `PerLcoreFlowMaps` (conntrack + meter, shared-nothing). A `DpdkMapWriter` implements `flowplane_control::MapWriter` over `SharedConfigMaps` (the DPDK sibling of `AyaWriter`), so the exact same `ControlCore` orchestration drives both backends. A new `flowplane-dpdk` bin crate hosts EAL init → maps → busy-poll workers → a tokio tonic `DataplaneNode` server, mirroring `flowplane serve`.

**Tech Stack:** Rust, DPDK 25.11.2 (via `dpdk-sys`, static build), `nfkit`, `flowplane-core`, `flowplane-control`, `flowplane-common`, `tonic`/`prost`/`tokio`/`tonic-health`, `clap`, `anyhow`, `parking_lot`. Multi-stage Debian Docker image; GitHub Actions matrix.

**Parent spec:** `docs/superpowers/specs/2026-07-23-flowplane-dpdk-b1b-serve-and-images-design.md` (and B1 `2026-07-22-flowplane-dpdk-b1-serve-control-seam-design.md`).

**Baseline invariants (must hold after every task):**
- Default build stays DPDK-free: `cargo build` (default-members) unaffected; DPDK work builds via `cargo build -p <crate>`.
- `cargo test -p flowplane` = 44 passed; 3 ignored (eBPF path untouched).
- `cargo test -p flowplane-control --features mem-writer` = 14 passed (orchestration untouched).
- DPDK tests run with `--no-huge` (no hugepages in CI/dev): `cargo test -p nfkit -- --test-threads=1` (EAL is process-global; nfkit tests already serialize via file-prefix).
- Do NOT run `cargo build --workspace` (fails pre-existingly on `flowplane-ebpf`; unrelated).

---

## File Structure

**dpdk-sys (FFI foundation):**
- Modify `flowplane/dpdk-sys/wrapper.h` — add `rte_rcu_qsbr.h`; ensure `rte_hash.h` RCU hooks in scope.
- Modify `flowplane/dpdk-sys/shim.c` + `shim.h` — QSBR helpers (size/init/register/quiescent/check) that wrap static-inline `rte_rcu_qsbr_*`.
- (bindings regenerate automatically via `build.rs` bindgen.)

**nfkit (map split + RCU):**
- Modify `flowplane/nfkit/src/dpdk_hash.rs` — LF+RCU constructor variant + QSBR registration.
- Create `flowplane/nfkit/src/shared_config.rs` — `SharedConfigMaps` (14 config tables, LF+RCU, single writer) + `config_generation`.
- Create `flowplane/nfkit/src/per_lcore_flow.rs` — `PerLcoreFlowMaps` (conntrack + meter) + `ComposedMaps<'a>` implementing the datapath `Maps` trait.
- Modify `flowplane/nfkit/src/lib.rs` — export the new modules.
- Modify `flowplane/nfkit/src/runtime.rs` — QSBR reader register + per-loop quiescence hook.
- Create `flowplane/nfkit/tests/rcu_writer_reader_anchor.rs` — the §5b concurrency anchor.
- Create `flowplane/nfkit/tests/shared_config_parity.rs` — the B1b vertical-slice parity test.

**flowplane-dpdk (new bin crate):**
- Create `flowplane/flowplane-dpdk/Cargo.toml`
- Create `flowplane/flowplane-dpdk/src/main.rs` — clap + serve.
- Create `flowplane/flowplane-dpdk/src/writer.rs` — `DpdkMapWriter: MapWriter`.
- Create `flowplane/flowplane-dpdk/src/node.rs` — `DataplaneNode` gRPC service (agnostic → ControlCore; device → stub).
- Create `flowplane/flowplane-dpdk/src/serve.rs` — EAL→maps→workers→tonic wiring.
- Create `flowplane/flowplane-dpdk/build.rs` — `tonic_build` for the reused proto.
- Modify root `Cargo.toml` — add member (NOT default-member).

**Imaging:**
- Create `Dockerfile.dpdk`
- Modify `.github/workflows/docker.yml` — matrix over both images.

**flowplane-core (generation-tag support, if not present):**
- Modify `flowplane/flowplane-core/src/*` — conntrack entry generation stamp + recheck hook (Task 8; verify current state first).

---

## Task 1: Bind RCU/QSBR + LF flag in dpdk-sys

**Files:**
- Modify: `flowplane/dpdk-sys/wrapper.h`
- Modify: `flowplane/dpdk-sys/shim.c`, `flowplane/dpdk-sys/shim.h`
- Verify: `flowplane/dpdk-sys/src/lib.rs` (re-exports generated bindings)

**Context:** `rte_rcu_qsbr_*` are static-inline in DPDK headers, so bindgen alone won't emit callable symbols — they need C shim wrappers (the same pattern `shim.c` already uses for `rte_pktmbuf_*`). `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` is a `#define` (bindgen emits it as a const if `rte_hash.h` is in `wrapper.h` — confirm). `rte_hash_rcu_qsbr_add` is a real (non-inline) function → bindgen emits it directly once `rte_hash.h` is included with RCU support.

- [ ] **Step 1: Read the current wrapper/shim to match style.**

Run: `sed -n '1,40p' flowplane/dpdk-sys/wrapper.h; echo ---; sed -n '1,40p' flowplane/dpdk-sys/shim.c; echo ---; cat flowplane/dpdk-sys/shim.h 2>/dev/null`
Note the include list and the `nfkit_*` wrapper convention.

- [ ] **Step 2: Add the RCU header + confirm rte_hash RCU hooks.**

In `flowplane/dpdk-sys/wrapper.h`, add (after the existing `#include <rte_hash.h>`):
```c
#include <rte_rcu_qsbr.h>
```
`rte_hash.h` already declares `rte_hash_rcu_qsbr_add` and `struct rte_hash_rcu_config`; including `rte_rcu_qsbr.h` brings the QSBR type + inline ops into scope for the shim.

- [ ] **Step 3: Add QSBR shim wrappers.**

In `flowplane/dpdk-sys/shim.h` add declarations, and in `shim.c` add definitions (wrapping the static-inline QSBR API so Rust gets real symbols):
```c
// shim.h
size_t   nfkit_rcu_qsbr_get_memsize(uint32_t max_threads);
int      nfkit_rcu_qsbr_init(struct rte_rcu_qsbr *v, uint32_t max_threads);
int      nfkit_rcu_qsbr_thread_register(struct rte_rcu_qsbr *v, unsigned int thread_id);
void     nfkit_rcu_qsbr_thread_online(struct rte_rcu_qsbr *v, unsigned int thread_id);
void     nfkit_rcu_qsbr_quiescent(struct rte_rcu_qsbr *v, unsigned int thread_id);
```
```c
// shim.c
#include <rte_rcu_qsbr.h>
size_t nfkit_rcu_qsbr_get_memsize(uint32_t m){ return rte_rcu_qsbr_get_memsize(m); }
int    nfkit_rcu_qsbr_init(struct rte_rcu_qsbr *v, uint32_t m){ return rte_rcu_qsbr_init(v, m); }
int    nfkit_rcu_qsbr_thread_register(struct rte_rcu_qsbr *v, unsigned int t){ return rte_rcu_qsbr_thread_register(v, t); }
void   nfkit_rcu_qsbr_thread_online(struct rte_rcu_qsbr *v, unsigned int t){ rte_rcu_qsbr_thread_online(v, t); }
void   nfkit_rcu_qsbr_quiescent(struct rte_rcu_qsbr *v, unsigned int t){ rte_rcu_qsbr_quiescent(v, t); }
```
(If `shim.h` is not `#include`d by `shim.c`, add `#include "shim.h"` or place decls directly in `shim.c` — match the existing file's convention discovered in Step 1.)

- [ ] **Step 4: Build dpdk-sys and confirm the symbols exist.**

Run: `cargo build -p dpdk-sys 2>&1 | tail -5`
Expected: PASS. Then confirm the bindings were emitted:
Run: `F=$(find target -name bindings.rs -path '*dpdk-sys*' | head -1); grep -c 'rte_hash_rcu_qsbr_add\|RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF\|nfkit_rcu_qsbr_init\|rte_rcu_qsbr' "$F"`
Expected: a non-zero count for each. If `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` is absent, add `-Dallowlist_var="RTE_HASH_.*"` to the bindgen invocation in `build.rs` (check the existing allowlist) and rebuild.

- [ ] **Step 5: Commit.**

```bash
git add flowplane/dpdk-sys
git commit -m "feat(dpdk-sys): bind rte_rcu_qsbr + rte_hash RCU/LF flags via shim

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: LF+RCU constructor on `DpdkHash`

**Files:**
- Modify: `flowplane/nfkit/src/dpdk_hash.rs`

**Context:** `DpdkHash::new(name, entries, socket_id)` today builds a plain `rte_hash` (no `extra_flags`, no RCU). Add a second constructor that sets `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` and attaches a caller-provided QSBR variable via `rte_hash_rcu_qsbr_add`. Keep `new` untouched (per-lcore tables keep using it).

- [ ] **Step 1: Write the failing test** at the bottom of `dpdk_hash.rs`:

```rust
#[cfg(test)]
mod lf_rcu_tests {
    use super::*;
    // A minimal repr(C) key/val for the test.
    #[repr(C)] #[derive(Clone, Copy)] struct K { v: u32 }
    #[repr(C)] #[derive(Clone, Copy)] struct V { v: u64 }

    #[test]
    #[ignore = "requires EAL; run under the nfkit EAL harness"]
    fn lf_rcu_hash_add_get() {
        // This asserts the constructor + add/get path compiles and runs under an
        // already-initialized EAL. The EAL-bringup anchor (Task 3) exercises it live;
        // here we only pin the API shape so later tasks compile against it.
        let _ = DpdkHash::<K, V>::new_lf_rcu; // symbol exists with the intended signature
    }
}
```

Run: `cargo test -p nfkit lf_rcu_hash_add_get -- --ignored 2>&1 | tail -5`
Expected: FAIL to compile — `new_lf_rcu` not found.

- [ ] **Step 2: Add the LF+RCU constructor.**

In `dpdk_hash.rs`, add alongside `new`:
```rust
/// Create a lock-free-reader (`RW_CONCURRENCY_LF`) hash with QSBR RCU attached to `qsbr`.
/// Caller owns the `rte_rcu_qsbr` (see `SharedConfigMaps`), passing a stable pointer that
/// outlives this hash. Single-writer model: no `MULTI_WRITER_ADD`.
///
/// # Safety
/// `qsbr` must point to an initialized `rte_rcu_qsbr` that outlives the returned hash.
pub unsafe fn new_lf_rcu(
    name: &str,
    entries: u32,
    socket_id: i32,
    qsbr: *mut dpdk_sys::rte_rcu_qsbr,
) -> Result<Self, HashError> {
    let cname = std::ffi::CString::new(name).map_err(|_| HashError::BadName)?;
    let mut params: dpdk_sys::rte_hash_parameters = std::mem::zeroed();
    params.name = cname.as_ptr();
    params.entries = entries;
    params.key_len = std::mem::size_of::<K>() as u32;
    params.socket_id = socket_id;
    params.extra_flag = dpdk_sys::RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
    let raw = dpdk_sys::rte_hash_create(&params);
    let raw = NonNull::new(raw).ok_or(HashError::Create)?;
    // Attach QSBR RCU so freed key-store slots are reclaimed only after readers quiesce.
    let mut cfg: dpdk_sys::rte_hash_rcu_config = std::mem::zeroed();
    cfg.v = qsbr;
    let rc = dpdk_sys::rte_hash_rcu_qsbr_add(raw.as_ptr(), &mut cfg);
    if rc < 0 {
        dpdk_sys::rte_hash_free(raw.as_ptr());
        return Err(HashError::Create);
    }
    Ok(Self { raw, slab: Vec::new(), _k: PhantomData })
}
```
Notes: the exact field name may be `extra_flag` or `extra_flags` and the const name may differ slightly — match what the Task-1 bindings emitted (grep `bindings.rs`). Add `BadName`/`Create` to `HashError` if not present. If `rte_hash_rcu_config` has more required fields (e.g. `mode`, `dq_size`), zero-init is the default-mode path; set `mode = RTE_HASH_QSBR_MODE_SYNC` only if the anchor (Task 3) shows reclamation issues.

- [ ] **Step 3: Run the test.**

Run: `cargo build -p nfkit 2>&1 | tail -5`
Expected: PASS (compiles; the `#[ignore]`d test is a compile anchor).

- [ ] **Step 4: Commit.**

```bash
git add flowplane/nfkit/src/dpdk_hash.rs
git commit -m "feat(nfkit): DpdkHash::new_lf_rcu — RW_CONCURRENCY_LF + QSBR RCU

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: §5b concurrency anchor — external writer + QSBR reader (GATE)

**Files:**
- Create: `flowplane/nfkit/tests/rcu_writer_reader_anchor.rs`

**Context:** Spec §5b flags the risk that the config writer is a **non-EAL tokio thread**, not an EAL lcore, while readers are lcores. QSBR tracks *readers*; a single external writer should be safe, but this must be PROVEN before the design relies on it. This anchor is the gate: it must pass before Tasks 4–10 build on the direct-writer model. If it cannot be made to pass, the fallback is the rte_ring-drained-by-a-control-lcore path (documented in the design §6); STOP and report so the plan can pivot.

- [ ] **Step 1: Write the anchor test.**

```rust
//! §5b gate: a non-EAL (std::thread) writer doing rte_hash add/del on an LF+RCU table
//! concurrently with an lcore-style reader that reports QSBR quiescence each loop.
//! Proves the external-writer model is safe before the serve process relies on it.
//! Run: cargo test -p nfkit --test rcu_writer_reader_anchor -- --ignored --test-threads=1
#![cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[repr(C)] #[derive(Clone, Copy)] struct K { v: u32 }
#[repr(C)] #[derive(Clone, Copy)] struct V { hits: u64 }

#[test]
#[ignore = "requires EAL --no-huge; serialized"]
fn external_writer_qsbr_reader_no_corruption() {
    // 1. EAL init (mirror multilcore_datapath.rs args, unique file-prefix).
    let _eal = nfkit::eal::Eal::init(
        ["nfkit_rcu_anchor", "-l", "0-1", "--no-huge", "-m", "512", "--no-pci",
         "--file-prefix", "nfkit_rcu_anchor"].iter().copied(),
    ).expect("eal init");

    // 2. Allocate + init a QSBR for 1 reader thread (use nfkit_rcu_qsbr_* shim).
    //    Allocate memsize bytes, init, register+online the reader thread id 0.
    //    (Exact helper wrapping lives in shared_config.rs in Task 4; inline here for the gate.)
    // 3. Build an LF+RCU DpdkHash<K,V> over that QSBR.
    // 4. Spawn a std::thread reader: loop { lookup a rotating key; report quiescent(0); } until stop.
    // 5. On the main (writer) thread: 100k iterations of add(key i % N) then del(key (i+7) % N).
    // 6. Signal stop, join. Assert: no crash/segfault, final table count within [0, N],
    //    and a post-run scan (for_each) returns only well-formed values (hits field readable).
    let stop = Arc::new(AtomicBool::new(false));
    // ... (implement per steps 2-6; the reader uses nfkit_rcu_qsbr_quiescent each iteration)
    stop.store(true, Ordering::Relaxed);
    // assert no panic reached here == success
}
```
Fill in steps 2–6 concretely using `DpdkHash::new_lf_rcu` (Task 2) and the `nfkit_rcu_qsbr_*` shim (Task 1). Keep the reader in a plain `std::thread` (NOT an EAL lcore) to specifically exercise the external-reader concern; the WRITER on the main thread is likewise non-lcore, which is the §5b case.

- [ ] **Step 2: Run the anchor.**

Run: `cargo test -p nfkit --test rcu_writer_reader_anchor -- --ignored --test-threads=1 2>&1 | tail -20`
Expected: PASS (no corruption/segfault; assertions hold).
**GATE:** If it segfaults or corrupts, do NOT proceed. Report BLOCKED with the failure; the plan pivots to the rte_ring fallback (writer enqueues ops on an `rte_ring` drained by a control-owned lcore — the tables stay LF+RCU for multi-reader safety, but the actual `rte_hash_add/del` executes on an EAL lcore).

- [ ] **Step 3: Commit.**

```bash
git add flowplane/nfkit/tests/rcu_writer_reader_anchor.rs
git commit -m "test(nfkit): §5b anchor — external writer + QSBR reader on LF+RCU hash

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `SharedConfigMaps` — process-wide LF+RCU config tables

**Files:**
- Create: `flowplane/nfkit/src/shared_config.rs`
- Modify: `flowplane/nfkit/src/lib.rs` (add `pub mod shared_config;`)

**Context:** One instance for the whole process. Holds the 14 config tables, owns the QSBR variable readers register against, and holds the `AtomicU64 config_generation`. It is the single-writer side. The 14 tables mirror the config half of `DpdkMaps` (dpdk_maps.rs) using the SAME key wrapper types (`Route4Key`, `Route6Key`, `NatKey`, `NatIpKey`, `LbKey`, `MaglevKey`, `FwRuleKey`, `U32Key` for fw_meta/dhcp_meta/meter-is-per-lcore, `Ipv6Key` for underlay, plus ports/ifaces/iface_meta/neigh_nat/vips/dhcp_config). Reuse the key types from `dpdk_maps.rs` (make them `pub(crate)` or move shared key defs to a small `keys.rs` if needed).

> **UPDATED after Task 3 (the RCU gate).** Two things the earlier snippets in this task got wrong — follow these, not the stale code below:
> 1. **Use `nfkit::rcu_hash::RcuHash<K,V>`, NOT `DpdkHash::new_lf_rcu`.** T3 proved the `DpdkHash` value slab is NOT RCU-safe (torn reads / UAF under a concurrent writer) and replaced it with `RcuHash<K,V>`, which stores values in the rte_hash C data pointer with RCU-deferred free (verified against DPDK source). `DpdkHash::new_lf_rcu` was reverted/removed. API: `unsafe RcuHash::<K,V>::new_lf_rcu(name, entries, socket_id, qsbr: *mut rte_rcu_qsbr) -> Result<Self,HashError>`, then `insert(&K,V)->bool`, `get(&K)->Option<V>`, `remove(&K)->bool`, `count()`, `for_each(|&K,&V|)`. Each config table is an `RcuHash`.
> 2. **QSBR allocation must be 64-BYTE ALIGNED — do NOT use `Box<[u8]>`.** `rte_rcu_qsbr` requires 64-byte alignment (`align_of == 64`); a `Box<[u8]>` does not guarantee it (UB). Hand-allocate: `let sz = nfkit_rcu_qsbr_get_memsize(MAX_READERS) as usize; let layout = std::alloc::Layout::from_size_align(sz, 64).unwrap(); let p = std::alloc::alloc_zeroed(layout) as *mut rte_rcu_qsbr; nfkit_rcu_qsbr_init(p, MAX_READERS);` — store the raw `*mut rte_rcu_qsbr` + the `Layout`, and `dealloc` it in `Drop` AFTER all tables (which reference it) are dropped. The QSBR pointer must be stable for the whole process and outlive every `RcuHash`.
> 3. **ALL-ZERO-KEY AUDIT (load-bearing — release builds won't catch violations).** rte_hash's `EMPTY_SLOT == 0`, so an all-zero key aliases the reserved dummy slot 0 and, with RCU auto-free, DOUBLE-FREES. `RcuHash::insert` has a `debug_assert` non-zero-key guard, but that's compiled out in release. Audit EVERY one of the 14 key types: any key whose bytes could be entirely zero (e.g. a genuinely-zero interface id / VNI 0 with a zero IP, a zeroed IPv6 underlay key) MUST be given a non-zero sentinel/base or is forbidden. Document per-table why its key can never be all-zero. VNI/interface-id/IP-tuple keys are non-zero in practice, but PROVE it for each; do not rely on the debug_assert.
> 4. **Size each table with headroom (~2×).** Deferred RCU reclaim leaves overwritten/deleted slots occupying the table until a grace period drains them (T3 observed live `count` running ~10-50% above the working set, bounded by capacity). Size `entries` at ~2× steady-state working set so config churn doesn't hit spurious `-ENOSPC`.
> 5. **Reader lifecycle (used by T5/T8):** each datapath lcore must `nfkit_rcu_qsbr_thread_register` + `_thread_online` on this QSBR before its first `get`, and call `nfkit_rcu_qsbr_quiescent` once per poll-loop iteration, or deferred frees never reclaim. `register_reader()` here should do register+online and return the token; `report_quiescent(&tok)` wraps the quiescent call.

- [ ] **Step 1: Write the failing test** in `shared_config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires EAL --no-huge"]
    fn shared_config_new_and_generation_bump() {
        let _eal = nfkit::eal::Eal::init(
            ["nfkit_sc", "-l","0-1","--no-huge","-m","512","--no-pci","--file-prefix","nfkit_sc"]
              .iter().copied()).unwrap();
        let mut sc = SharedConfigMaps::new(0, 8).expect("shared config");
        assert_eq!(sc.generation(), 0);
        sc.bump_generation();
        assert_eq!(sc.generation(), 1);
        // reader registration returns a token
        let _tok = sc.register_reader();
    }
}
```

Run: `cargo test -p nfkit shared_config_new_and_generation_bump -- --ignored 2>&1 | tail -5`
Expected: FAIL — `SharedConfigMaps` undefined.

- [ ] **Step 2: Implement `SharedConfigMaps`.**

```rust
//! Process-wide, single-writer config maps: one LF+RCU rte_hash per config table.
//! The tokio control thread is the sole writer; datapath lcores are QSBR readers.
use std::sync::atomic::{AtomicU64, Ordering};
use crate::dpdk_hash::DpdkHash;
use crate::dpdk_maps::{Route4Key, Route6Key, NatIpKey, Ipv6Key, U32Key}; // reuse existing key types
use flowplane_common::{ /* RouteValue, NatKey, NatValue, LbKey, LbValue, MaglevKey, FwRuleKey,
    FwRule, FwMeta, UnderlayValue, PortMeta, IfaceKey, IfaceValue, IfaceMetaKey, IfaceMetaVal,
    VipKey, NeighborNatEntry, DhcpConfig */ };

pub struct ReaderToken { pub(crate) id: u32 }

pub struct SharedConfigMaps {
    // QSBR variable readers register against (heap box; stable address).
    qsbr: Box<[u8]>,                 // sized via nfkit_rcu_qsbr_get_memsize
    next_reader: u32,
    generation: AtomicU64,
    // config tables (LF+RCU)
    route4: DpdkHash<Route4Key, flowplane_common::RouteValue>,
    route6: DpdkHash<Route6Key, flowplane_common::RouteValue>,
    nat: DpdkHash<flowplane_common::NatKey, flowplane_common::NatValue>,
    nat_ips: DpdkHash<NatIpKey, u8>,
    lb: DpdkHash<flowplane_common::LbKey, flowplane_common::LbValue>,
    maglev: DpdkHash<flowplane_common::MaglevKey, [u8; 16]>,
    fw_rules: DpdkHash<flowplane_common::FwRuleKey, flowplane_common::FwRule>,
    fw_meta: DpdkHash<U32Key, flowplane_common::FwMeta>,
    underlay: DpdkHash<Ipv6Key, flowplane_common::UnderlayValue>,
    ports: DpdkHash<U32Key, flowplane_common::PortMeta>,
    ifaces: DpdkHash<flowplane_common::IfaceKey, flowplane_common::IfaceValue>,
    iface_meta: DpdkHash<flowplane_common::IfaceMetaKey, flowplane_common::IfaceMetaVal>,
    neigh_nat: DpdkHash<U32Key, flowplane_common::NeighborNatEntry>,
    vips: DpdkHash<flowplane_common::VipKey, [u8; 4]>,
    dhcp_config: Option<flowplane_common::DhcpConfig>,
    // dhcp_meta/neigh_nat_count are singletons/small; add as needed to satisfy MapWriter.
}

impl SharedConfigMaps {
    const MAX_READERS: u32 = 64;

    pub fn new(socket_id: i32, entries: u32) -> Result<Self, crate::dpdk_hash::HashError> {
        unsafe {
            let sz = dpdk_sys::nfkit_rcu_qsbr_get_memsize(Self::MAX_READERS) as usize;
            let mut qsbr = vec![0u8; sz].into_boxed_slice();
            let vp = qsbr.as_mut_ptr() as *mut dpdk_sys::rte_rcu_qsbr;
            let rc = dpdk_sys::nfkit_rcu_qsbr_init(vp, Self::MAX_READERS);
            if rc < 0 { return Err(crate::dpdk_hash::HashError::Create); }
            // Build each table with new_lf_rcu(name, entries, socket_id, vp). Names must be unique.
            let route4 = DpdkHash::new_lf_rcu("sc_route4", entries, socket_id, vp)?;
            // ... construct all 14 tables similarly with distinct names ...
            Ok(Self { qsbr, next_reader: 0, generation: AtomicU64::new(0),
                      route4, /* ... */ dhcp_config: None })
        }
    }

    /// The QSBR variable pointer (readers register + report quiescence against it).
    pub(crate) fn qsbr_ptr(&self) -> *mut dpdk_sys::rte_rcu_qsbr {
        self.qsbr.as_ptr() as *mut dpdk_sys::rte_rcu_qsbr
    }

    /// Register a datapath reader thread; returns its token (thread id for quiescence calls).
    pub fn register_reader(&mut self) -> ReaderToken {
        let id = self.next_reader;
        self.next_reader += 1;
        unsafe {
            dpdk_sys::nfkit_rcu_qsbr_thread_register(self.qsbr_ptr(), id);
            dpdk_sys::nfkit_rcu_qsbr_thread_online(self.qsbr_ptr(), id);
        }
        ReaderToken { id }
    }

    #[inline] pub fn report_quiescent(&self, tok: &ReaderToken) {
        unsafe { dpdk_sys::nfkit_rcu_qsbr_quiescent(self.qsbr_ptr(), tok.id); }
    }

    #[inline] pub fn generation(&self) -> u64 { self.generation.load(Ordering::Acquire) }
    #[inline] pub fn bump_generation(&self) { self.generation.fetch_add(1, Ordering::Release); }

    // Config getters used by the composed datapath Maps view (Task 5) + MapWriter reads (Task 6):
    // route4_get / route6_get / nat_get / is_nat_ip / lb_get / maglev_get / fw_rule / fw_meta /
    // underlay_get / ifaces_get / vips_get / dhcp_config — each a thin self.<table>.get(&key).
}
```
Fill in ALL 14 table constructions + the getters. Where `MapWriter` needs a table not in the current `DpdkMaps` (e.g. `ifaces`, `iface_meta`, `vips`, `neigh_nat`, `ports`, `dhcp_meta`), add it here (these are the interface-domain tables the datapath already reads or will read). Confirm the exact `flowplane_common` value types against `writer.rs` (Task 6 depends on them matching).

- [ ] **Step 3: Run the test.**

Run: `cargo test -p nfkit shared_config_new_and_generation_bump -- --ignored 2>&1 | tail -8`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add flowplane/nfkit/src/shared_config.rs flowplane/nfkit/src/lib.rs
git commit -m "feat(nfkit): SharedConfigMaps — process-wide LF+RCU config tables + generation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `PerLcoreFlowMaps` + composed `Maps` view

**Files:**
- Create: `flowplane/nfkit/src/per_lcore_flow.rs`
- Modify: `flowplane/nfkit/src/lib.rs`

**Context:** The per-lcore, shared-nothing half (conntrack + meter), extracted from `DpdkMaps`. Plus `ComposedMaps<'a>` = `&SharedConfigMaps` (config getters) + owned `PerLcoreFlowMaps` (flow-state getters + the two mutators), implementing the datapath `Maps` trait (`flowplane-core/src/maps.rs`) so a worker lcore runs the datapath over it.

- [ ] **Step 1: Write the failing test** in `per_lcore_flow.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_core::maps::Maps; // the datapath trait
    #[test]
    #[ignore = "requires EAL --no-huge"]
    fn composed_maps_routes_getters_to_halves() {
        let _eal = nfkit::eal::Eal::init(
            ["nfkit_plf","-l","0-1","--no-huge","-m","512","--no-pci","--file-prefix","nfkit_plf"]
              .iter().copied()).unwrap();
        let shared = crate::shared_config::SharedConfigMaps::new(0, 8).unwrap();
        let flow = PerLcoreFlowMaps::new(0).unwrap();
        let mut composed = ComposedMaps { cfg: &shared, flow };
        // a conntrack insert lands in the per-lcore half and reads back:
        let key = /* build a CtKey */ unimplemented!();
        let entry = /* build a CtEntry */ unimplemented!();
        composed.conntrack_insert(key, entry);
        assert!(composed.conntrack_get(&key).is_some());
    }
}
```
(Replace the `unimplemented!()` with real `CtKey`/`CtEntry` construction using the same fixtures `multilcore_datapath.rs` uses.)

Run: `cargo test -p nfkit composed_maps_routes_getters_to_halves -- --ignored 2>&1 | tail -5`
Expected: FAIL — types undefined.

- [ ] **Step 2: Implement `PerLcoreFlowMaps` + `ComposedMaps`.**

```rust
//! Per-lcore shared-nothing flow state (conntrack + meter) + the composed datapath Maps view.
use std::cell::Cell;
use crate::dpdk_hash::DpdkHash;
use crate::dpdk_maps::U32Key;
use crate::shared_config::SharedConfigMaps;
use flowplane_common::{CtKey, CtEntry, MeterState};
use flowplane_core::maps::Maps;

pub struct PerLcoreFlowMaps {
    conntrack: DpdkHash<CtKey, CtEntry>,
    meter: DpdkHash<U32Key, MeterState>,
    dropped_ct_inserts: Cell<u64>,
}

impl PerLcoreFlowMaps {
    pub fn new(socket_id: i32) -> Result<Self, crate::dpdk_hash::HashError> {
        Ok(Self {
            conntrack: DpdkHash::new("plf_ct", 65536, socket_id)?,   // unique per-lcore name (M8: append instance)
            meter: DpdkHash::new("plf_meter", 4096, socket_id)?,
            dropped_ct_inserts: Cell::new(0),
        })
    }
}

pub struct ComposedMaps<'a> {
    pub cfg: &'a SharedConfigMaps,
    pub flow: PerLcoreFlowMaps,
}

impl<'a> Maps for ComposedMaps<'a> {
    // Config getters delegate to self.cfg.*  (route4_get, route6_get, nat_get, is_nat_ip,
    // lb_get, maglev_get, fw_rule, fw_meta, underlay_get, dhcp_config, dhcp_meta, local).
    // Flow getters/mutators delegate to self.flow.*  (conntrack_get, conntrack_insert,
    // meter_get, meter_update).
    // Copy the exact method set + signatures from flowplane-core/src/maps.rs.
}
```
Implement EVERY `Maps` method (from the cheat-sheet: `local`, `underlay_get`, `fw_meta`, `fw_rule`, `conntrack_get`, `conntrack_insert`, `lb_get`, `maglev_get`, `nat_get`, `is_nat_ip`, `route4_get`, `route6_get`, `dhcp_config`, `dhcp_meta`, `meter_get`, `meter_update`), routing each to the correct half. `conntrack_insert` keeps the saturation-drop-counter behavior from the old `DpdkMaps`.

- [ ] **Step 3: Run the test.**

Run: `cargo test -p nfkit composed_maps_routes_getters_to_halves -- --ignored 2>&1 | tail -8`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add flowplane/nfkit/src/per_lcore_flow.rs flowplane/nfkit/src/lib.rs
git commit -m "feat(nfkit): PerLcoreFlowMaps + ComposedMaps (datapath Maps over shared+per-lcore)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `DpdkMapWriter` — implement `flowplane_control::MapWriter`

**Files:**
- Create: `flowplane/flowplane-dpdk/Cargo.toml` (crate scaffold — minimal, deps grow in Task 9)
- Create: `flowplane/flowplane-dpdk/src/lib.rs`
- Create: `flowplane/flowplane-dpdk/src/writer.rs`
- Modify: root `Cargo.toml` (add member, NOT default-member)

**Context:** The DPDK sibling of `AyaWriter`. Each of the 35 `MapWriter` methods maps to an `rte_hash` add/del/lookup on the matching `SharedConfigMaps` table; `conntrack_flush` bumps `config_generation`. The writer holds `&mut SharedConfigMaps` (single writer). Because `SharedConfigMaps` lives in `nfkit`, and `MapWriter` in `flowplane-control`, the writer crate depends on both.

- [ ] **Step 1: Scaffold the crate + register it.**

Create `flowplane/flowplane-dpdk/Cargo.toml`:
```toml
[package]
name = "flowplane-dpdk"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
flowplane-common = { path = "../flowplane-common", features = ["user"] }
flowplane-control = { path = "../flowplane-control" }
flowplane-core = { path = "../flowplane-core" }
nfkit = { path = "../nfkit" }
anyhow = { workspace = true }

[[bin]]
name = "flowplane-dpdk"
path = "src/main.rs"
```
Create `flowplane/flowplane-dpdk/src/lib.rs`:
```rust
//! DPDK dataplane serve binary internals: MapWriter, gRPC node service, serve wiring.
pub mod writer;
```
Create a placeholder `flowplane/flowplane-dpdk/src/main.rs` so the bin target builds:
```rust
fn main() -> anyhow::Result<()> { Ok(()) }
```
In the root `Cargo.toml`, add `"flowplane/flowplane-dpdk"` to `members` ONLY (NOT `default-members`).

Run: `cargo build -p flowplane-dpdk 2>&1 | tail -5`
Expected: PASS (empty binary).

- [ ] **Step 2: Write the failing test** in `writer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_control::MapWriter;
    #[test]
    #[ignore = "requires EAL --no-huge"]
    fn dpdk_writer_route_upsert_then_get_via_shared() {
        let _eal = nfkit::eal::Eal::init(
            ["fp_dpdk_w","-l","0-1","--no-huge","-m","512","--no-pci","--file-prefix","fp_dpdk_w"]
              .iter().copied()).unwrap();
        let mut sc = nfkit::shared_config::SharedConfigMaps::new(0, 8).unwrap();
        {
            let mut w = DpdkMapWriter::new(&mut sc);
            w.route_upsert(7, [10,0,0,1], 32, flowplane_common::RouteValue::default()).unwrap();
            w.conntrack_flush(flowplane_control::CtFlushScope{
                vni:7, guest_ip:[10,0,0,1], nat_ip:[0;4], port_min:0, port_max:0}).unwrap();
        }
        assert!(sc.route4_get(7, &[10,0,0,1]).is_some());
        assert_eq!(sc.generation(), 1); // conntrack_flush bumped it
    }
}
```

Run: `cargo test -p flowplane-dpdk dpdk_writer_route_upsert_then_get_via_shared -- --ignored 2>&1 | tail -5`
Expected: FAIL — `DpdkMapWriter` undefined.

- [ ] **Step 3: Implement `DpdkMapWriter`.**

```rust
//! `MapWriter` over `SharedConfigMaps` — the DPDK sibling of the eBPF `AyaWriter`.
use flowplane_control::{CtFlushScope, MapWriter};
use flowplane_common::{ /* all the POD types the trait uses */ };
use nfkit::shared_config::SharedConfigMaps;

pub struct DpdkMapWriter<'a> { sc: &'a mut SharedConfigMaps }

impl<'a> DpdkMapWriter<'a> {
    pub fn new(sc: &'a mut SharedConfigMaps) -> Self { Self { sc } }
}

impl<'a> MapWriter for DpdkMapWriter<'a> {
    fn route_upsert(&mut self, vni: u32, ipv4: [u8;4], _p: u32, val: RouteValue) -> anyhow::Result<()> {
        self.sc.route4_insert(vni, ipv4, val); Ok(())
    }
    fn route_remove(&mut self, vni: u32, ipv4: [u8;4], _p: u32) -> anyhow::Result<()> {
        self.sc.route4_remove(vni, ipv4); Ok(())
    }
    // ... implement ALL 35 methods, each a thin add/del/lookup on the matching SharedConfigMaps table.
    fn conntrack_flush(&mut self, _scope: CtFlushScope) -> anyhow::Result<()> {
        self.sc.bump_generation(); Ok(())   // §5a: no cross-lcore writes; lcores lazily re-validate
    }
}
```
Add the corresponding `route4_insert`/`route4_remove`/... writer-side methods to `SharedConfigMaps` (Task 4) as thin `self.<table>.insert(&key, val)` / `self.<table>.del(&key)` — keep the datapath getters and the writer setters colocated on `SharedConfigMaps`. Map each `MapWriter` method to its table exactly as `AyaWriter` (flowplane/src/control/aya_writer.rs) maps to aya maps — same key/value construction, prefix-len handling (exact /32,/128 only, matching the eBPF route model), `nat_ips` dummy-value insert, `neigh_nat_count_set` semantics, etc. Cross-check every method against `aya_writer.rs` so the two writers are semantically identical.

- [ ] **Step 4: Run the test.**

Run: `cargo test -p flowplane-dpdk dpdk_writer_route_upsert_then_get_via_shared -- --ignored 2>&1 | tail -8`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane-dpdk Cargo.toml flowplane/nfkit/src/shared_config.rs
git commit -m "feat(flowplane-dpdk): DpdkMapWriter implementing MapWriter over SharedConfigMaps

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Generation-tag conntrack invalidation (§5a)

**Files:**
- Verify/Modify: `flowplane/flowplane-core/src/*` (conntrack entry + datapath recheck)
- Modify: `flowplane/nfkit/src/per_lcore_flow.rs` (thread generation through the composed view)

**Context:** §5a: on NAT/LB/route change, `conntrack_flush` bumps `config_generation` (Task 6). Each conntrack entry must carry the generation it was resolved under; on lookup, if `entry.gen != config_generation`, the lcore re-validates the cached binding against `SharedConfigMaps` before forwarding. **First verify what exists:** the datapath conntrack entry may already carry a generation/version field (M9/M11 work), or this may be net-new. Adapt accordingly.

- [ ] **Step 1: Investigate current conntrack entry shape.**

Run: `grep -rn 'struct CtEntry\|gen\|generation\|version' flowplane/flowplane-common/src/*.rs flowplane/flowplane-core/src/*.rs | grep -i 'ct\|gen\|version' | head -20`
Determine whether `CtEntry` has a generation field and whether the datapath already re-validates. Record findings. If a full generation field + recheck already exists, this task reduces to wiring `config_generation` into it (and the test still applies).

- [ ] **Step 2: Write the failing test** (extends the nfkit datapath harness) in a new `flowplane/nfkit/tests/generation_invalidation.rs`:

```rust
//! §5a: after a NAT binding is withdrawn (config_generation bumped), the next datapath packet
//! on a previously-established flow must NOT emit under the withdrawn binding.
#![cfg(test)]
#[test]
#[ignore = "requires EAL --no-huge"]
fn withdrawn_nat_binding_not_emitted_after_generation_bump() {
    // 1. EAL init (unique file-prefix).
    // 2. Build SharedConfigMaps + one PerLcoreFlowMaps + ComposedMaps.
    // 3. Program a NAT binding via DpdkMapWriter; run a packet -> establishes a conntrack entry
    //    stamped with generation G0; assert it forwards (Redirect/expected action).
    // 4. Withdraw the NAT binding via DpdkMapWriter (delete_nat path) -> conntrack_flush bumps to G1.
    // 5. Run the next packet on the same flow. Assert: the datapath re-validates (entry.gen != G1),
    //    finds the binding gone, and does NOT emit under the withdrawn source (drop or re-resolve) —
    //    i.e. zero stale emission.
}
```
Fill in with the same fixtures the parity tests use.

Run: `cargo test -p nfkit --test generation_invalidation -- --ignored 2>&1 | tail -5`
Expected: FAIL (either recheck not wired, or entry lacks gen).

- [ ] **Step 3: Wire the generation stamp + recheck.**

- Ensure `CtEntry` carries a `gen: u64` (add to `flowplane-common` if absent; keep `#[repr(C)]` layout + update any size asserts).
- In the datapath (flowplane-core), on conntrack insert stamp `entry.gen = maps.config_generation()`; add a `Maps::config_generation(&self) -> u64` method (default `0` for backends without generations — eBPF/sim return 0, so their behavior is unchanged) and, before applying a cached conntrack decision, if `entry.gen != maps.config_generation()` re-derive the binding from the config getters: valid → refresh `entry.gen` (a local per-lcore write); gone/changed → fall through to re-resolution/drop.
- Implement `ComposedMaps::config_generation` to return `self.cfg.generation()`. eBPF `GlobalMaps` and sim `MemMaps` return `0` (no-op path — verify their `Maps` impls compile with the new method; add the default or explicit `0`).

- [ ] **Step 4: Run the test + confirm eBPF/sim unaffected.**

Run: `cargo test -p nfkit --test generation_invalidation -- --ignored 2>&1 | tail -8`
Expected: PASS.
Run: `cargo test -p flowplane-control --features mem-writer 2>&1 | grep 'test result'; cargo test -p flowplane 2>&1 | grep 'test result' | head -1`
Expected: 14 passed; 44 passed/3 ignored (unchanged — the `config_generation` default is a no-op for eBPF/sim).

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane-common flowplane/flowplane-core flowplane/nfkit
git commit -m "feat(dpdk): generation-tag conntrack invalidation (§5a); no-op for eBPF/sim

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: `flowplane-dpdk` serve scaffold — clap + EAL + maps + workers + tonic

**Files:**
- Modify: `flowplane/flowplane-dpdk/Cargo.toml` (add tonic/tokio/clap/etc)
- Create: `flowplane/flowplane-dpdk/build.rs`
- Create: `flowplane/flowplane-dpdk/src/serve.rs`
- Modify: `flowplane/flowplane-dpdk/src/main.rs`

**Context:** Mirror `flowplane serve` (main.rs:383–571) structurally but swap the datapath (eBPF→nfkit) and drop all eBPF/device-attach specifics. This task stands up the process skeleton: parse args → EAL init → build `SharedConfigMaps` + N `PerLcoreFlowMaps` → launch workers (QSBR readers, per-loop quiescence) → tokio tonic server with health, listener opens after datapath is up. The gRPC service impl is Task 9 (here, wire an empty/placeholder service so the server binds).

- [ ] **Step 1: Add deps + proto build.**

Append to `flowplane/flowplane-dpdk/Cargo.toml`:
```toml
tonic = { workspace = true }
tonic-health = "0.12"
prost = { workspace = true }
tokio = { workspace = true }
clap = { workspace = true }
parking_lot = { workspace = true }

[build-dependencies]
tonic-build = "0.12"
```
Create `flowplane/flowplane-dpdk/build.rs` (compile the SAME proto the eBPF binary uses — find its path from Task deps; the eBPF crate compiles `api/proto/dataplane/v1/dataplane.proto`):
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .compile_protos(&["../../api/proto/dataplane/v1/dataplane.proto"], &["../../api/proto"])?;
    Ok(())
}
```
(Confirm the proto path against the eBPF crate's `build.rs`; match its include dirs exactly.)

- [ ] **Step 2: Write the failing test** (a smoke test that serve args parse) in `serve.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serve_args_parse_minimal() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk","--uplink","eth0","--gateway","169.254.0.1",
            "--gateway-mac","02:00:00:00:00:01","--backend","af-xdp","--no-huge",
        ]);
        assert_eq!(a.uplink, "eth0");
        assert!(a.no_huge);
    }
}
```

Run: `cargo test -p flowplane-dpdk serve_args_parse_minimal 2>&1 | tail -5`
Expected: FAIL — `ServeArgs` undefined.

- [ ] **Step 3: Implement the serve scaffold.**

In `serve.rs` define `ServeArgs` (clap `Parser`) with the DPDK-relevant subset of the eBPF args + DPDK specifics:
```rust
use clap::Parser;
#[derive(Parser, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:1337")] pub addr: String,
    #[arg(long)] pub uplink: String,
    #[arg(long)] pub gateway: String,
    #[arg(long)] pub gateway_mac: String,
    #[arg(long)] pub gateway6: Option<String>,
    #[arg(long)] pub local_underlay: Option<String>,
    #[arg(long, value_enum, default_value_t = BackendArg::AfXdp)] pub backend: BackendArg,
    #[arg(long, default_value_t = 4)] pub lcores: u16,
    #[arg(long, default_value_t = false)] pub no_huge: bool,
    #[arg(long)] pub dhcp_dns: Vec<String>,
    #[arg(long)] pub dhcpv6_dns: Vec<String>,
    #[arg(long)] pub guest_mtu: Option<u32>,
}
#[derive(clap::ValueEnum, Clone, Debug)] pub enum BackendArg { AfXdp, Nic, Pcap, Tap, Null }
```
Then `pub async fn run(args: ServeArgs) -> anyhow::Result<()>` that:
1. Maps `BackendArg`+uplink → `nfkit::backend::Backend`; builds EAL argv via `Backend::eal_args("flowplane-dpdk")` (append `--no-huge` when `args.no_huge`); `nfkit::eal::Eal::init(argv)`.
2. Mempool + `Port::configure(0, args.lcores, &pool)` (RSS symmetric-Toeplitz).
3. `let shared = Arc::new(Mutex::new(SharedConfigMaps::new(socket, ENTRIES)?));` — single-writer lives behind a `parking_lot::Mutex` for the tokio handler; the datapath reads through a `*const SharedConfigMaps` snapshot (RCU-safe reads don't need the lock — document this: readers use the raw shared pointer, the mutex serializes only the writer). NOTE: resolve the shared-vs-mutex ownership precisely against the Task 3 anchor result; if the anchor mandated the rte_ring path, wire that here instead.
4. `LcoreRuntime::for_each_worker(args.lcores, |q| { register QSBR reader; build ComposedMaps{cfg:&shared, flow: PerLcoreFlowMaps::new(sock)}; poll loop: rx → flowplane_core datapath → tx; report_quiescent each iteration })`. Because `for_each_worker` blocks until join, run it on a dedicated std thread (or spawn_blocking) so the tokio server runs concurrently.
5. tokio: build `tonic_health` reporter, set Serving AFTER the datapath is up; `Server::builder().add_service(health).add_service(<Task-9 service>).serve_with_shutdown(addr, shutdown)` where `shutdown` awaits SIGTERM/SIGINT (mirror main.rs:546–563).

For THIS task, add a temporary empty tonic service (or gate the `.add_service(node)` line behind a `todo` that Task 9 fills) so the binary compiles and binds. In `main.rs`:
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = flowplane_dpdk::serve::ServeArgs::parse();
    flowplane_dpdk::serve::run(args).await
}
```

- [ ] **Step 4: Run the test + build.**

Run: `cargo test -p flowplane-dpdk serve_args_parse_minimal 2>&1 | tail -5 && cargo build -p flowplane-dpdk 2>&1 | tail -3`
Expected: PASS + builds.

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane-dpdk
git commit -m "feat(flowplane-dpdk): serve scaffold — clap + EAL + maps + workers + tonic skeleton

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: DPDK gRPC node service — agnostic RPCs → ControlCore; device half stubbed

**Files:**
- Create: `flowplane/flowplane-dpdk/src/node.rs`
- Modify: `flowplane/flowplane-dpdk/src/serve.rs` (wire the service)
- Modify: `flowplane/flowplane-dpdk/src/lib.rs`

**Context:** The DPDK binary can't reuse `flowplane/src/node.rs` (it's bound to `Control`/`attach.rs`/aya). It implements the generated `DataplaneNode` trait itself. The ~13 agnostic RPCs build a `DpdkMapWriter` over the shared maps and call `ControlCore<DpdkMapWriter>` (same orchestration the eBPF path runs); `AttachInterface`/`DetachInterface` program the agnostic maps (ports/ifaces/underlay via `ControlCore::program_interface`/`register_iface_meta`) and return `Unimplemented` for the physical device step (B2). The service holds `Arc<Mutex<(ControlCore<DpdkMapWriter over shared>)>>` — but `DpdkMapWriter` borrows `&mut SharedConfigMaps`, so the service holds `Arc<Mutex<SharedConfigMaps>>` + a `Arc<Mutex<ControlCoreState>>`, and each handler locks, constructs a transient `DpdkMapWriter`, wraps a transient `ControlCore`, and calls it. Simplest correct shape: keep the `ControlCore` shadow state and the `SharedConfigMaps` together behind one `Mutex` so a handler builds `ControlCore::new(DpdkMapWriter::new(&mut sc))` per call — BUT `ControlCore` owns shadow state that must persist across calls. Resolve by storing a persistent `ControlCore` whose writer is swapped: store `ControlCore<DpdkMapWriter<'static>>`? Not possible with a borrow. **Chosen shape:** store `SharedConfigMaps` + the `ControlCore` *shadow state* separately is awkward; instead make `DpdkMapWriter` own an `Arc<Mutex<SharedConfigMaps>>` (not a borrow) so `ControlCore<DpdkMapWriter>` can be stored persistently. Adjust Task 6's `DpdkMapWriter` to hold `Arc<Mutex<SharedConfigMaps>>` and lock per method (single-writer, so lock is uncontended by other writers; datapath readers don't take it). Update Task 6's test accordingly.

> IMPLEMENTER NOTE: Before starting, reconcile the ownership decision with Task 6. If Task 6 built `DpdkMapWriter<'a>` (borrow), refactor it here to own `Arc<Mutex<SharedConfigMaps>>` (or `Arc<SharedConfigMaps>` with interior-mutable tables) so a long-lived `ControlCore<DpdkMapWriter>` can be stored in the service. Keep the datapath read path lock-free (readers use a raw `*const SharedConfigMaps`; the mutex serializes writers only). This is the one genuinely fiddly ownership decision in the plan — get it right here.

- [ ] **Step 1: Write the failing test** in `node.rs` (unit-level: a handler programs a route through ControlCore into the shared maps):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires EAL --no-huge"]
    async fn add_route_programs_shared_maps() {
        let _eal = nfkit::eal::Eal::init(
            ["fp_dpdk_node","-l","0-1","--no-huge","-m","512","--no-pci","--file-prefix","fp_dpdk_node"]
              .iter().copied()).unwrap();
        let svc = DpdkNodeService::new_for_test(); // builds shared maps + ControlCore
        let resp = svc.add_route(tonic::Request::new(/* AddRouteRequest for vni 7, 10.0.0.1/32 */)).await;
        assert!(resp.is_ok());
        assert!(svc.debug_route4_present(7, [10,0,0,1]));
    }
}
```

Run: `cargo test -p flowplane-dpdk add_route_programs_shared_maps -- --ignored 2>&1 | tail -5`
Expected: FAIL — `DpdkNodeService` undefined.

- [ ] **Step 2: Implement `DpdkNodeService`.**

Implement `pb::dataplane_node_server::DataplaneNode for DpdkNodeService`. For each RPC, mirror the request/response marshalling from `flowplane/src/node.rs` (same proto types) but replace the `Control` call with the `ControlCore` call. Map (from the cheat-sheet):
- `add_route`/`withdraw_route` → `core.delete_route(...)` + `core.create_route(...)` (and v6 variants).
- `add_nat_source`/`withdraw_nat_source` → resolve interface_id (the DPDK equivalent of `find_interface_id` — reads `core`'s iface meta / ifaces table), `core.create_nat`/`core.delete_nat`.
- `add_neighbor_nat`/`withdraw_neighbor_nat` → `core.del_neighbor_nat` + `core.add_neighbor_nat`.
- `add_lb_vip`/`add_lb_backend`/`del_lb_vip`/`del_lb_backend` → `core.create_lb`/`add_lb_target`/`delete_lb`/`del_lb_target`.
- `add_fw_rule`/`del_fw_rule` → `core.add_fw_rule`/`core.del_fw_rule`.
- `configure_qo_s` → `core.set_qos`.
- `configure_network` → Ok stub (matches eBPF).
- `list_interfaces` → read the DPDK iface meta (`core`/shared) into the `InterfaceRow` proto.
- `attach_interface` → program the agnostic half (`core.program_interface(IfaceParams{..})` + `core.register_iface_meta`) using the request's vni/ips/underlay, then return `Status::unimplemented("DPDK host-device attach is B2")` OR return success with the agnostic maps programmed and a logged warning that the device step is stubbed. **Decision:** return `Unimplemented` so callers don't believe an interface stood up (safer); the agnostic-map programming is still exercised by the parity test via the writer directly. Document this in a code comment referencing B2.
- `detach_interface` → `core.purge_vni(...)` + `core.forget_iface_meta(...)` for the agnostic half, then `Unimplemented` for the device teardown (symmetry with attach).

Handlers use `tokio::task::spawn_blocking` around the locked `ControlCore` call (mirror the eBPF handler pattern), returning `Status::internal(e.to_string())` on error.

Then in `serve.rs`, replace the placeholder service with `.add_service(pb::dataplane_node_server::DataplaneNodeServer::new(DpdkNodeService::new(shared.clone(), core_state)))`.

- [ ] **Step 3: Run the test + build the binary.**

Run: `cargo test -p flowplane-dpdk add_route_programs_shared_maps -- --ignored 2>&1 | tail -8 && cargo build -p flowplane-dpdk 2>&1 | tail -3`
Expected: PASS + binary builds.

- [ ] **Step 4: Commit.**

```bash
git add flowplane/flowplane-dpdk
git commit -m "feat(flowplane-dpdk): DataplaneNode gRPC — agnostic RPCs via ControlCore, device half stubbed (B2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Multi-lcore parity test — the B1b vertical slice

**Files:**
- Create: `flowplane/nfkit/tests/shared_config_parity.rs`

**Context:** The headline correctness proof: program routes/nat/lb/fw through the DPDK `MapWriter` (the exact calls the gRPC handlers make), run the `flowplane-core` datapath on N lcores over `SharedConfigMaps` + per-lcore `PerLcoreFlowMaps`, and assert byte-parity with the sim AND conntrack isolation across lcores. Extends `multilcore_datapath.rs` but drives config through the writer instead of hand-populating `DpdkMaps`.

- [ ] **Step 1: Write the test.**

```rust
//! B1b vertical slice: config programmed via DpdkMapWriter (the gRPC path), datapath run on N
//! lcores over SharedConfigMaps + per-lcore flow state, asserted byte-identical to the sim and
//! conntrack-isolated across lcores. Run: cargo test -p nfkit --test shared_config_parity -- --ignored --test-threads=1
#![cfg(test)]
#[test]
#[ignore = "requires EAL --no-huge"]
fn multilcore_config_via_writer_parity_and_isolation() {
    // 1. EAL init (-l 0-4 --no-huge, unique file-prefix), 4 workers, 4 flows/worker.
    // 2. Build SharedConfigMaps; program the SAME fixture config as multilcore_datapath.rs
    //    (routes/nat/fw/underlay/ifaces) THROUGH DpdkMapWriter + ControlCore — i.e. call
    //    ControlCore::create_route/create_nat/add_fw_rule exactly as the handlers do.
    // 3. Build the equivalent MemMaps sim config the same way (via the mem-writer ControlCore).
    // 4. for_each_worker: each worker gets ComposedMaps{cfg:&shared, flow: PerLcoreFlowMaps::new}
    //    and runs process_uplink on its distinct flows; capture output frames.
    // 5. Assert: (a) every worker's output frame == the sim's output frame byte-for-byte;
    //    (b) each worker's conntrack contains ONLY its own flows (isolation), zero foreign.
}
```
Fill in using the exact fixtures + assertions from `multilcore_datapath.rs` (flow_src `[10,9,worker,flow+1]`, GUEST_IP, DST_PORT, TAP redirect, the `MemMaps`/`VecPkt` sim comparison). The KEY difference: config is written via `ControlCore<DpdkMapWriter>` (proving the control path is byte-identical), not by direct `DpdkMaps` population.

- [ ] **Step 2: Run it.**

Run: `cargo test -p nfkit --test shared_config_parity -- --ignored --test-threads=1 2>&1 | tail -20`
Expected: PASS — DPDK-via-writer == sim, conntrack isolated. This extends the DPDK == sim == eBPF chain through the control path.

- [ ] **Step 3: Commit.**

```bash
git add flowplane/nfkit/tests/shared_config_parity.rs
git commit -m "test(nfkit): multi-lcore parity via DpdkMapWriter — control path byte-identical to sim

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 11: `Dockerfile.dpdk` + CI matrix

**Files:**
- Create: `Dockerfile.dpdk`
- Modify: `.github/workflows/docker.yml`

**Context:** Mirror the existing `Dockerfile` shape (multi-stage Debian) but with the DPDK build toolchain instead of LLVM-21/bpf-linker. `dpdk-sys/build.rs` downloads + statically builds DPDK 25.11.2 (meson/ninja), so the builder needs meson, ninja, python3-pyelftools, libnuma-dev, clang/libclang (bindgen), pkg-config, libbpf/libxdp-dev (af_xdp PMD), protobuf-compiler (tonic). Runtime = debian-slim + runtime shared libs.

- [ ] **Step 1: Write `Dockerfile.dpdk`.**

```dockerfile
# syntax=docker/dockerfile:1
# Container image for the `flowplane-dpdk` DPDK datapath binary.
# dpdk-sys/build.rs downloads + statically builds DPDK 25.11.2 (meson/ninja) at build time.
FROM debian:bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential pkg-config \
        meson ninja-build python3-pyelftools \
        libnuma-dev clang libclang-dev llvm-dev \
        libbpf-dev libxdp-dev \
        libpcap-dev \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
# Pinned Rust toolchain (rust-toolchain.toml is honored by rustup).
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH=/root/.cargo/bin:${PATH}
WORKDIR /src
COPY . .
RUN cargo build --release -p flowplane-dpdk \
    && cp target/release/flowplane-dpdk /flowplane-dpdk \
    && strip /flowplane-dpdk

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ethtool libnuma1 libbpf1 libxdp1 libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /flowplane-dpdk /usr/local/bin/flowplane-dpdk
ENTRYPOINT ["/usr/local/bin/flowplane-dpdk"]
```
NOTE: the exact runtime package names for libxdp/libbpf on bookworm may differ (`libxdp1`/`libbpf1` vs versioned). After the first build, run `ldd /flowplane-dpdk` inside the builder and install the exact shared-lib closure (libelf1, libbsd0 may be pulled by the af_xdp PMD). Adjust the runtime `apt-get` list to match.

- [ ] **Step 2: Build the image locally (or dry-run the build stage).**

Run: `docker build -f Dockerfile.dpdk -t flowplane-dpdk:local . 2>&1 | tail -30`
Expected: builds through to the runtime stage. (This is slow — the DPDK build takes minutes. If Docker isn't available in the execution env, at minimum `cargo build --release -p flowplane-dpdk` locally to prove the release build works, and note the image build must be verified in CI.)

- [ ] **Step 3: Smoke-test the binary in the image.**

Run: `docker run --rm flowplane-dpdk:local --help 2>&1 | tail -20`
Expected: clap help prints (proves the binary is the entrypoint and links/loads).

- [ ] **Step 4: Extend CI to a matrix.**

Modify `.github/workflows/docker.yml`: convert the single build job to a matrix over
`[{ image: flowplane, dockerfile: Dockerfile }, { image: flowplane-dpdk, dockerfile: Dockerfile.dpdk }]`,
using `${{ matrix.image }}` in the `docker/metadata-action` images field and `${{ matrix.dockerfile }}`
in the `docker/build-push-action` `file:` field. Keep the eBPF job's behavior identical; the DPDK job is additive. Example matrix header:
```yaml
    strategy:
      fail-fast: false
      matrix:
        include:
          - { image: flowplane,      dockerfile: Dockerfile }
          - { image: flowplane-dpdk, dockerfile: Dockerfile.dpdk }
```
and downstream: `images: ghcr.io/${{ github.repository }}/${{ matrix.image }}`, `file: ${{ matrix.dockerfile }}`.

- [ ] **Step 5: Commit.**

```bash
git add Dockerfile.dpdk .github/workflows/docker.yml
git commit -m "build(dpdk): Dockerfile.dpdk + CI matrix — publish flowplane-dpdk image

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 12: Cleanup + final verification

**Files:**
- Verify across the new crates + nfkit.

**Context:** Confirm the seam is single-source, the baselines hold, no stray `unimplemented!` outside the deliberate B2 stubs, and the two binaries + two images are coherent.

- [ ] **Step 1: Baseline invariants.**

Run:
```
cargo build 2>&1 | tail -1
cargo test -p flowplane-control --features mem-writer 2>&1 | grep 'test result' | head -1
cargo test -p flowplane 2>&1 | grep 'test result' | head -1
cargo build -p flowplane-dpdk 2>&1 | tail -1
cargo clippy -p flowplane-dpdk -p nfkit 2>&1 | grep -E 'warning:|error:' | grep -v 'generated' | head
```
Expected: default build clean; 14 passed; 44 passed/3 ignored; flowplane-dpdk builds; no NEW clippy warnings (pre-existing nfkit warnings, if any, noted not fixed).

- [ ] **Step 2: EAL-gated DPDK suite.**

Run: `cargo test -p nfkit -p flowplane-dpdk -- --ignored --test-threads=1 2>&1 | tail -30`
Expected: the §5b anchor, SharedConfigMaps, ComposedMaps, DpdkMapWriter, generation-invalidation, node add_route, and the multi-lcore parity test all PASS. (If the execution env lacks `--no-huge` EAL capability, note which tests could not run and require a privileged/CI run.)

- [ ] **Step 3: Seam check — orchestration single-source.**

Run: `grep -rn 'fn create_route\|fn create_nat\|fn create_lb\|fn add_fw_rule\|fn set_qos' flowplane/flowplane-dpdk/src/ flowplane/flowplane-control/src/`
Expected: the orchestration BODIES appear ONLY in `flowplane-control`; `flowplane-dpdk` has only handler call-sites (`core.create_route(...)`), never a reimplementation. This is the [[seam-not-duplicate-for-tests]] check for the DPDK side.

- [ ] **Step 4: Confirm the deliverables exist.**

Run:
```
ls flowplane/flowplane-dpdk/src/{main,serve,node,writer}.rs
ls Dockerfile Dockerfile.dpdk
grep -c 'flowplane-dpdk' .github/workflows/docker.yml
```
Expected: all present; CI references the DPDK image.

- [ ] **Step 5: Confirm stubs are intentional + logged.**

Run: `grep -rn 'unimplemented!\|B2\|Unimplemented' flowplane/flowplane-dpdk/src/node.rs`
Expected: only the AttachInterface/DetachInterface device-half stubs, each clearly referencing B2. No stray stubs elsewhere.

- [ ] **Step 6: Commit (if any cleanup).**

```bash
git add -A
git commit -m "chore(flowplane-dpdk): final verification — seam single-source, baselines green

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Manual checkpoint (before B2 / deploy)

Two live validations the unit/anchor suite cannot cover, to run on real hardware/CI before building B2 or wiring the DaemonSet:
1. **CI image build** — the `Dockerfile.dpdk` DPDK-from-source build only fully runs in CI (slow, needs the full apt closure); confirm the `flowplane-dpdk` image publishes to GHCR and `docker run … --help` works on the pushed image.
2. **AF_XDP boot on a real (or clab) node** — start `flowplane-dpdk serve --backend af-xdp --uplink <veth> --no-huge …`, confirm the gRPC listener opens (`ss -ltn | grep 1337`), program a route via grpcurl, and observe the datapath forwarding — the deployable readiness contract the DaemonSet probe relies on.

Also: run the **eBPF clab regression sweep** (still outstanding from the B1a merge) so both backends are fabric-validated before the two images ship together.
