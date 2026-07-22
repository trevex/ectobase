# nfkit M11 — hitless upgrade: conntrack/NAT snapshot round-trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The `DpdkHash` iteration is FFI/unsafe — explicit `// SAFETY:` on every `unsafe`.

**Goal:** Deliver the reusable state-handoff primitive for a blue-green hitless DPDK upgrade: iterate rte_hash, serialize a per-lcore `DpdkMaps` conntrack+NAT snapshot, restore it into a fresh instance, and prove established-flow continuity across a simulated binary swap. `--no-huge`, no NIC. nfkit-only.

**Architecture:** (1) add `DpdkHash::for_each` via `rte_hash_iterate`. (2) `snapshot` module: versioned blob serialize/restore of `conntrack`/`nat`/`nat_ips`. (3) round-trip + continuity tests. The full blue-green orchestration (atomic RSS/rte_flow flip, two-instance drain, ct_sync delta stream) is DESIGN-ONLY in the spec — not this milestone.

**Tech Stack:** Rust FFI over DPDK `rte_hash`; `nfkit` (M3 `DpdkHash`, M8 per-lcore `DpdkMaps`); `flowplane-core` datapath + `flowplane-common` POD types (read-only reuse). Tests `--no-huge`, `--test-threads=1`, inside `nix develop`.

**Context (grounded — I read these):**
- `DpdkHash<K: Copy, V: Copy>` (`nfkit/src/dpdk_hash.rs`): `raw: NonNull<rte_hash>`, `slab: Vec<Option<V>>` (V indexed by the position `rte_hash_add_key` returns; values are NOT stored in rte_hash — only keys). `insert` uses `rte_hash_add_key` → `slab[pos]=Some(v)`; `get` uses `rte_hash_lookup` → `slab[pos]`. So iteration must map the iterate-returned POSITION back through `slab` for the value.
- `rte_hash_iterate(h, const void **key, void **data, uint32_t *next) -> int32_t` returns the entry POSITION (>=0) or `-ENOENT` at end. `key` is set to the stored key ptr (valid until next mutation); `data` is the in-hash data ptr (unused here — we use the returned position to index `slab`). Verify the exact bindgen signature/const-ness in the generated `bindings.rs`.
- `DpdkMaps` (`nfkit/src/dpdk_maps.rs`): private `conntrack: DpdkHash<CtKey,CtEntry>`, `nat: DpdkHash<NatKey,NatValue>`, `nat_ips: DpdkHash<NatIpKey,u8>`. Restore setters: `Maps::conntrack_insert` (trait — `use flowplane_core::maps::Maps`), `add_nat(NatKey,NatValue)`, `add_nat_ip(vni,[u8;4])` (rebuilds `NatIpKey`). `NatIpKey { vni:u32, ipv4:[u8;4] }` is a nfkit-local composite (dpdk_maps.rs:38). `CtKey/CtEntry/NatKey/NatValue` are `#[repr(C)]` POD in `flowplane-common` (all `Copy`, exact byte layout — usable as raw bytes).
- Snapshot the FLOW tables only: `conntrack` + `nat` + `nat_ips`. Config maps (routes/fw/lb/maglev/underlay/dhcp/meter) are re-derived from the control plane on the new instance — NOT snapshotted. (`meter` EDT cursors are transient pacing state — documented out of scope.)
- `process_guest_tx` creates a NAT binding via `snat_egress` (external route) + conntrack via `ct_create_default` on CT miss (M8/M4 findings). `parity_nat_return.rs` (M4) has the NAT-return fixtures for the behavioral continuity check.

**Absolute rules:**
- Cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root. rustfmt hook active (fallback `rustfmt --edition 2021 <files>`).
- Every `unsafe` gets a `// SAFETY:` comment. No `flowplane-core`/`flowplane-common`/eBPF edits — M11 walks `DpdkMaps` via the new iteration + reuses existing datapath fns. Run FULL `cargo test -p nfkit -- --test-threads=1` before the final commit.

---

## File Structure
- `flowplane/nfkit/src/dpdk_hash.rs` — `+ for_each`.
- `flowplane/nfkit/tests/dpdk_hash.rs` — `+ iteration test`.
- `flowplane/nfkit/src/dpdk_maps.rs` — `+ conntrack/nat/nat_ips iteration accessors` (or the serialize/restore methods directly — implementer's choice).
- `flowplane/nfkit/src/snapshot.rs` — new (`serialize_maps`, `restore_maps`, `SnapshotError`, `RestoreStats`, format consts).
- `flowplane/nfkit/src/lib.rs` — re-export.
- `flowplane/nfkit/tests/snapshot_roundtrip.rs` — new.

---

## Task 1: `DpdkHash::for_each` (rte_hash iteration)

**Files:** `nfkit/src/dpdk_hash.rs`, `nfkit/tests/dpdk_hash.rs`.

- [ ] **Step 1: Failing iteration test** — append to the existing `dpdk_hash.rs` test (it already inits EAL once): insert N=5 distinct `(K,V)` into a `DpdkHash`, collect via `for_each` into a `Vec`, assert the collected set equals the inserted set (order-independent — rte_hash iteration order is unspecified). Use a simple `K=u32`-ish key + `V` the file already uses. Run → FAILS to compile (`for_each` absent).

- [ ] **Step 2: Implement `for_each`** in `impl<K: Copy, V: Copy> DpdkHash<K,V>`:
```rust
/// Visit every live (key, value) entry. Order is unspecified. The value comes from the companion
/// slab (rte_hash stores only keys). Copies K out per entry (Copy POD) — safe against the borrow.
pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
    let mut next: u32 = 0;
    let mut key_ptr: *const c_void = std::ptr::null();
    let mut data_ptr: *mut c_void = std::ptr::null_mut();
    loop {
        // SAFETY: valid handle + valid out-params; returns the entry position (>=0) or -ENOENT.
        let pos = unsafe {
            dpdk_sys::rte_hash_iterate(self.raw.as_ptr(), &mut key_ptr, &mut data_ptr, &mut next)
        };
        if pos < 0 {
            break;
        }
        // SAFETY: key_ptr points to key_len (== size_of::<K>()) bytes, valid until the next table
        // mutation; K is Copy POD. Read a copy so f can't hold the borrow.
        let k: K = unsafe { std::ptr::read(key_ptr.cast::<K>()) };
        if let Some(Some(v)) = self.slab.get(pos as usize) {
            f(&k, v);
        }
    }
}
```
Match the exact `rte_hash_iterate` bindgen signature (the `data` param may be `*mut *mut c_void` or `*mut *const c_void` — adjust). Run the test → PASS. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 3: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/nfkit/src/dpdk_hash.rs flowplane/nfkit/tests/dpdk_hash.rs
git commit -m "feat(nfkit): DpdkHash::for_each (rte_hash_iterate) — enables conntrack/NAT snapshot"
```

---

## Task 2: `snapshot` serialize/restore + round-trip + continuity

**Files:** `nfkit/src/dpdk_maps.rs` (iteration accessors), `nfkit/src/snapshot.rs`, `nfkit/src/lib.rs`, `nfkit/tests/snapshot_roundtrip.rs`.

- [ ] **Step 1: Expose flow-table iteration on `DpdkMaps`** — add (dpdk_maps.rs, field access):
```rust
pub fn conntrack_for_each(&self, f: impl FnMut(&CtKey, &CtEntry)) { self.conntrack.for_each(f); }
pub fn nat_for_each(&self, f: impl FnMut(&NatKey, &NatValue)) { self.nat.for_each(f); }
pub fn nat_ips_for_each(&self, f: impl FnMut(&NatIpKey, &u8)) { self.nat_ips.for_each(f); }
```
(Restore uses the existing `Maps::conntrack_insert` / `add_nat` / `add_nat_ip`.)

- [ ] **Step 2: `flowplane/nfkit/src/snapshot.rs`** — versioned blob over the POD types (use `bytemuck` if already a dep, else manual `to_ne_bytes`/`copy_from_slice` over `#[repr(C)]` structs via `std::slice::from_raw_parts` with SAFETY):
```rust
//! Serialize/restore a DpdkMaps conntrack+NAT snapshot for a blue-green hitless upgrade: the OLD
//! binary exports flow state, the NEW binary restores it into a fresh DpdkMaps so established flows
//! survive the swap. Config maps (routes/fw/lb/maglev/underlay) are re-derived from the control
//! plane and NOT snapshotted. Host-endian, same-arch/host handoff (a local upgrade) — versioned so
//! a layout-incompatible snapshot is REFUSED rather than corrupting state.
const MAGIC: [u8; 4] = *b"NFKS";
const VERSION: u16 = 1;
#[derive(Debug)] pub struct SnapshotError(pub &'static str);
#[derive(Debug, Default, PartialEq, Eq)] pub struct RestoreStats { pub conntrack: usize, pub nat: usize, pub nat_ips: usize }

/// Serialize conntrack + nat + nat_ips into a versioned blob.
pub fn serialize_maps(maps: &DpdkMaps) -> Vec<u8> { /* MAGIC, VERSION, then per table: u32 count, count×(key_bytes,value_bytes) via for_each */ }
/// Restore a blob into a FRESH DpdkMaps. Refuses magic/version mismatch.
pub fn restore_maps(maps: &mut DpdkMaps, blob: &[u8]) -> Result<RestoreStats, SnapshotError> { /* validate header; parse each table; conntrack_insert/add_nat/add_nat_ip; return counts */ }
```
Serialize each entry as `size_of::<K>()` key bytes + `size_of::<V>()` value bytes (POD structs → raw bytes; SAFETY: `#[repr(C)]` Copy, no padding-sensitive interpretation since same-arch round-trip). `restore` bounds-checks every read (a truncated/garbage blob → `Err`, never a panic/OOB). Re-export in `lib.rs`: `mod snapshot; pub use snapshot::{serialize_maps, restore_maps, SnapshotError, RestoreStats};`.

- [ ] **Step 3: `flowplane/nfkit/tests/snapshot_roundtrip.rs`** (`--no-huge`, `--test-threads=1`):
  - **Round-trip byte parity:** build instance A `DpdkMaps`; populate conntrack (several `CtKey/CtEntry`), nat (`NatKey/NatValue`), nat_ips directly via the setters (deterministic, no datapath needed). `serialize_maps(&A)` → blob. Build FRESH B (`DpdkMaps::new`). `restore_maps(&mut B, &blob)` → `RestoreStats` equal to the inserted counts. Assert every A entry is present+equal in B (collect both via `*_for_each` into sorted `Vec`s, assert equal) and B has NO extra entries.
  - **Header validation:** `restore_maps` on a bad magic and on a bad version each returns `Err(SnapshotError)` (no panic).
  - **Behavioral continuity (the real proof):** reuse `parity_nat_return.rs` fixtures — instance A processes a guest-egress NAT flow (or directly installs the same NAT binding + conntrack A would create), serialize→restore into fresh B, then run the flow's RETURN packet through B's datapath (`process_uplink`/nat-return path) and assert B translates it correctly using the RESTORED binding — i.e. identical output to running the return on A. This proves an established NAT flow survives the simulated binary swap on the NEW instance. (If wiring the full return path is heavy, at minimum assert `B.nat_get(key)`/`conntrack_get(key)` match A for the flow AND one return-path datapath call on B produces the expected un-NAT — do NOT reduce it to only a map-presence check without a datapath call.)
  - Run → PASS. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 4: Full suite + commit** — `cargo test -p nfkit -- --test-threads=1` (all M3–M11 green).
```bash
git add flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/src/snapshot.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/snapshot_roundtrip.rs
git commit -m "feat(nfkit): conntrack+NAT snapshot serialize/restore round-trip (blue-green state handoff primitive)"
```

---

## Definition of Done (M11)
- `DpdkHash::for_each` added + unit-tested; `snapshot` serialize/restore round-trip (byte parity + count) + header validation + behavioral NAT-flow continuity pass `--no-huge`; all M3–M10 anchors green.
- Snapshot is versioned + refuses magic/version mismatch + bounds-checks (no panic on garbage); scope (CT+NAT+nat_ips only, config re-derived, meter out) documented in the module.
- `cargo test -p flowplane-sim` + `anchor_*` unchanged (nfkit-only).
- The full blue-green orchestration remains design-only (spec §5); this milestone proves the STATE-HANDOFF layer.
- Default host build untouched.

## Risks / notes
- **rte_hash_iterate signature** — match the generated bindgen types exactly (`data` param ptr-const-ness, `next` as `*mut u32`). The return value is the POSITION → index `slab` for the value.
- **Iteration vs mutation** — `for_each` borrows live key pointers; copy `K` out per step (done). The snapshot runs on a quiescent table (single-threaded test; the live orchestration exports while the old instance is paused/draining — documented).
- **POD raw-bytes safety** — `CtKey/CtEntry/NatKey/NatValue`/`NatIpKey` are `#[repr(C)] Copy`; serialize via `size_of` byte copies; restore bounds-checks every field read. Same-arch/host handoff (host-endian) — documented, not a cross-arch wire format.
- **Continuity must be behavioral** — assert a datapath return-path call on the restored instance B, not merely map presence, so the test proves the flow actually WORKS post-swap.
- **Version gating is load-bearing** — a real upgrade loads an OLD binary's blob; `restore` MUST refuse an incompatible version and let the caller fall back (accept flow loss) rather than corrupt. Tested.
- **Scope honesty** — DoD is the state-handoff primitive; the atomic RSS/rte_flow flip + two-instance af_xdp drain are HW/privileged and design-only (spec §5).
