# nfkit review-hardening follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development / test-driven-development. Checkbox (`- [ ]`) steps. FFI/unsafe → explicit `// SAFETY:`.

**Goal:** Address the code-review findings on the merged nfkit DPDK backend. Make `DpdkHash` **deterministic + observable** (no cap-alignment-dependent OOB footgun; fallible insert), make map capacities **configurable**, make snapshot restore **observable**, and close the flagged **test-coverage gaps** + polish. Branch `hardening/nfkit-review-followups` (off main). nfkit-only — do NOT change the `flowplane-core` `Maps` trait, eBPF, or sim.

**Context (grounded — verified against DPDK 25.11.2 source + the review):**
- `DpdkHash<K:Copy,V:Copy>` (`nfkit/src/dpdk_hash.rs`): `slab: Vec<Option<V>>` sized `entries` (line 35), indexed by the position `rte_hash_add_key`/`_lookup`/`_iterate` return. **`rte_hash` with the default (local-cache) config allocates `num_key_slots = entries + (RTE_MAX_LCORE-1)*(LCORE_CACHE_SIZE-1) + 1` and returns positions in `[0, num_key_slots-2]` — which CAN exceed `entries`.** Today it doesn't OOB only because `CAP_CT=65536`/`CAP_STD=4096` are exact multiples of `LCORE_CACHE_SIZE=64` and each hash is single-writer — a fragile coincidence. `insert` (line 47) and `get` (line 92) index `self.slab[pos]` UNCHECKED; `insert` silently drops on `pos<0` (table full).
- `insert` callers (`dpdk_maps.rs`): all `add_*` setters + the `Maps` impl `conntrack_insert` (line 238) + `meter_update` (281). `Maps::conntrack_insert` returns `()` (trait — shared w/ MemMaps + eBPF GlobalMaps; do NOT change its signature).
- `HashError` (dpdk_hash.rs:10) derives only `Debug` — the lone error type in the crate WITHOUT `Display`+`std::error::Error` (mirror `MempoolError`'s impls).
- `restore_maps` (`snapshot.rs`) re-inserts via `conntrack_insert`/`add_nat`/`add_nat_ip` and returns the blob's CLAIMED counts as `RestoreStats` — a capacity-exceeding restore over-reports success.
- Caps: `CAP_CT=65_536`/`CAP_STD=4_096` consts (`dpdk_maps.rs:76-77`); `DpdkMaps::new(socket_id)` has no cap arg.

**Absolute rules:** cargo inside `nix develop`; commit from repo root; rustfmt hook (fallback `rustfmt --edition 2021`); every `unsafe` gets `// SAFETY:`; run full `cargo test -p nfkit -- --test-threads=1` before each commit. No `flowplane-core`/`flowplane-common`/eBPF/sim edits.

---

## Task 1: `DpdkHash` deterministic + observable + `HashError: Error`

**Files:** `nfkit/src/dpdk_hash.rs`, `nfkit/tests/dpdk_hash.rs`.

- [ ] **Step 1 (TDD): capacity/observability test** — add to the existing single-EAL `#[test]`:
  - create `DpdkHash<u64,u64>` with a small `entries` (e.g. 64); insert distinct keys `0..300`; collect the per-insert `bool` results. Assert: (a) NO panic, (b) at least one insert returns `false` once the table is full (observable saturation — deterministic), (c) `for_each` yields EXACTLY the set of keys whose insert returned `true`, (d) every true-inserted key round-trips via `get`, and (e) a key whose insert returned `false` is absent from `get`/`for_each` (no partial/corrupt slot). Run → FAILS to compile (`insert` returns `()`).
- [ ] **Step 2: make `insert` fallible + slab grow-on-demand (deterministic, never OOB)**:
```rust
/// Insert (or overwrite) key -> value. Returns false if the table is full (rte_hash_add_key < 0);
/// the value is then NOT stored. Deterministic: the value slab grows to fit whatever position
/// rte_hash returns, so it can never index out of range regardless of capacity alignment or writers.
pub fn insert(&mut self, k: &K, v: V) -> bool {
    // SAFETY: k points to size_of::<K>()==key_len bytes; add_key copies the key.
    let pos = unsafe { dpdk_sys::rte_hash_add_key(self.raw.as_ptr(), (k as *const K).cast::<c_void>()) };
    if pos < 0 {
        return false; // table full (-ENOSPC) — observable to the caller
    }
    let idx = pos as usize;
    if idx >= self.slab.len() {
        self.slab.resize(idx + 1, None); // grow to fit; V: Copy, no pointers into slab
    }
    self.slab[idx] = Some(v);
    true
}
```
  Change `get` (line ~92) to checked: `self.slab.get(pos as usize).copied().flatten()`. (`for_each` already uses `.get()`.) Optionally add `pub fn count(&self) -> usize` via `rte_hash_count` for observability.
- [ ] **Step 3: `HashError: Display + Error`** — mirror `MempoolError`:
```rust
impl std::fmt::Display for HashError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "rte_hash operation failed") } }
impl std::error::Error for HashError {}
```
- [ ] **Step 4: fix `insert` callers** — the `add_*` config setters in `dpdk_maps.rs` now get a `bool`; keep their `()` return but on a `false` from a CONFIG map insert (should never be full at populate-time) `debug_assert!` or a rate-limited `eprintln!`. For `conntrack_insert` (hot path, trait returns `()`): add a per-`DpdkMaps` `dropped_ct_inserts: Cell<u64>`/`AtomicU64` counter incremented on `false`, exposed via `pub fn dropped_conntrack_inserts(&self) -> u64` (observability without changing the trait). `meter_update`/`add_nat`/`add_nat_ip` similarly ignore-or-count as appropriate (a full nat table = a real problem — count it).
- [ ] **Step 5:** run the test → PASS; full `cargo test -p nfkit -- --test-threads=1`; clippy `-p nfkit --all-targets` + fmt clean. Commit:
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/nfkit/src/dpdk_hash.rs flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/tests/dpdk_hash.rs
git commit -m "fix(nfkit): DpdkHash deterministic (grow-on-demand slab, no OOB) + observable (fallible insert, drop counters) + HashError: Error"
```

---

## Task 2: configurable capacities + snapshot restore observability

**Files:** `nfkit/src/dpdk_maps.rs`, `nfkit/src/snapshot.rs`, `nfkit/tests/snapshot_roundtrip.rs`.

- [ ] **Step 1: configurable caps** — add `pub fn with_capacities(socket_id: i32, ct_cap: u32, std_cap: u32) -> Result<Self, HashError>` (the current `new` body, parameterized) and make `new(socket_id) = Self::with_capacities(socket_id, CAP_CT, CAP_STD)`. Keep `CAP_CT`/`CAP_STD` as the documented defaults. Backward-compatible (all callers use `new`). Add a quick test that `with_capacities` builds + a tiny ct_cap is honored (insert-past-tiny-cap returns false via the new fallible path).
- [ ] **Step 2: restore observability** — `restore_maps`: since `conntrack_insert`/`add_nat`/`add_nat_ip` now surface fullness (via the Task-1 counters / fallible inserts), make restore DETERMINISTIC + OBSERVABLE: if any entry fails to insert (capacity exceeded), return `Err(SnapshotError("capacity exceeded during restore"))` rather than silently over-reporting `RestoreStats`. Document that on `Err` the target map may be partially populated and the caller should discard it + fall back (a failed handoff must be known). `RestoreStats` on `Ok` reflects actual inserts (== blob counts when it fits). (Use `add_nat` returning bool if you made it so; for `conntrack_insert` compare the dropped-counter before/after, or add a fallible internal `try_conntrack_insert`.)
- [ ] **Step 2b (TDD) restore tests** — add to `snapshot_roundtrip.rs` (ONE `#[test]`, single EAL): (a) **empty-maps round-trip** — serialize a fresh DpdkMaps (0/0/0), restore into another fresh, assert `RestoreStats{0,0,0}` + no entries. (b) **restore into a NON-empty map** (warm-standby) — B already holds a flow; restore A's blob over it; assert A's entries present (overwrite/last-writer-wins is fine) + no panic. (c) **restore exceeding a tiny ct_cap** (build B via `with_capacities` with ct_cap small) → `restore_maps` returns `Err` (observable), no panic.
- [ ] **Step 3:** full suite green; clippy+fmt. Commit:
```bash
git add flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/src/snapshot.rs flowplane/nfkit/tests/snapshot_roundtrip.rs
git commit -m "feat(nfkit): configurable DpdkMaps capacities + observable snapshot restore (Err on capacity-exceeded, not silent over-report)"
```

---

## Task 3: test-coverage gaps

**Files:** `nfkit/tests/parity_uplink.rs`, `nfkit/tests/mbuf_pkt.rs`, `nfkit/tests/multilcore_datapath.rs`, `nfkit/tests/rss_symmetry.rs`, `nfkit/tests/edt_pacer.rs`.

- [ ] **Step 1: uplink ingress-firewall DENY parity** (`parity_uplink.rs`) — add a scenario mirroring an existing one but with NO ingress allow rule installed → assert `process_uplink` yields `Action::Drop` AND byte-parity DPDK-vs-sim (frame untouched before drop). This covers the N-S ingress security boundary on the DPDK substrate (currently only egress-deny is tested).
- [ ] **Step 2: MbufPkt boundary false-returns** (`mbuf_pkt.rs`) — through the `Pkt` trait on a small `MbufPkt`: `set_tail(huge)` (beyond tailroom) → `false` (hits the `p.is_null()` guard, `mbuf_pkt.rs:102`); `grow_head(huge)` (beyond headroom) → `false`. Assert no panic + the packet length is unchanged on the false path.
- [ ] **Step 3: multilcore isolation at N≥4** (`multilcore_datapath.rs`) — bump EAL to `-l 0-4`, `N_WORKERS=4`; each worker asserts NONE of the OTHER THREE workers' flow keys are present (loop over all `other != q`, not just `(q+1)%N`). Strengthens the shared-nothing proof.
- [ ] **Step 4: RSS symmetry for IPv6** (`rss_symmetry.rs`) — add v6 5-tuple cases (16-byte src/dst) asserting `toeplitz_softrss(fwd) == toeplitz_softrss(rev)` (swap src/dst addr + port) → same queue. Covers the WAN-edge/NAT64 v6 flows the per-lcore model also relies on.
- [ ] **Step 5: EdtPacer large-N ordering stress** (`edt_pacer.rs`) — enqueue ~100 mbufs with shuffled edts (id-tagged), `drain_due(u64::MAX)`, assert released in non-decreasing edt order (departure order holds at scale + all-due-at-once).
- [ ] **Step 6:** full suite green; clippy+fmt. Commit:
```bash
git add flowplane/nfkit/tests/parity_uplink.rs flowplane/nfkit/tests/mbuf_pkt.rs flowplane/nfkit/tests/multilcore_datapath.rs flowplane/nfkit/tests/rss_symmetry.rs flowplane/nfkit/tests/edt_pacer.rs
git commit -m "test(nfkit): close review gaps — ingress-deny parity, MbufPkt boundary false-returns, multilcore N=4, RSS v6, EdtPacer large-N"
```

---

## Task 4: polish

**Files:** `nfkit/src/flow.rs`, `nfkit/src/mbuf_pkt.rs`, `nfkit/src/edt.rs`, `nfkit/tests/common/mod.rs` (+ test files).

- [ ] **Step 1: unify RAW-holder field naming** (`flow.rs`) — `RawDecap` and `RawEncap` name their liveness-only owned buffer inconsistently (`_data: Vec<u8>` vs `data: Box<[u8]>`). Pick one (`_data: Box<[u8]>` for both, underscore = held-for-liveness) + keep the `#[allow(dead_code)]` justification comment.
- [ ] **Step 2: MbufPkt delta guard** (`mbuf_pkt.rs`) — where a `usize` delta is cast `as u16` (grow_head/shrink_head/set_tail, ~line 83), add `debug_assert!(delta <= u16::MAX as usize, "single-segment delta exceeds u16")` to document the invariant (silent truncation → explicit in debug).
- [ ] **Step 3: `EdtPacer::drain_due_into(&mut Vec<Mbuf>)`** (`edt.rs`) — a zero-alloc variant for the hot pacing loop (`drain_due` keeps calling it with a fresh Vec). Keep `drain_due` as a convenience wrapper. Add a one-line test that it appends due mbufs to a reused buffer.
- [ ] **Step 4 (optional, mechanical): dedup test fixtures** — extract the copy-pasted `inner_frame`/`encap_to`/consts (`GUEST_MAC`/`GUEST_IP`/…) into `nfkit/tests/common/mod.rs` (the subdir-`mod.rs` form Cargo does NOT compile as its own test binary) and `mod common;` in the ~7 consumers. Keep it a pure move (byte-identical fixtures) so the parity anchors are unchanged. If this proves churny/risky, SKIP it and note so — it's cosmetic (test-only duplication).
- [ ] **Step 5:** full suite green; clippy+fmt. Commit:
```bash
git add -A flowplane/nfkit
git commit -m "chore(nfkit): polish — unify RAW-holder naming, MbufPkt delta debug_assert, EdtPacer::drain_due_into, dedup test fixtures"
```

---

## Definition of Done
- `DpdkHash` never indexes the slab OOB (grow-on-demand) and `insert` is fallible (`-> bool`) + saturation is observable (drop counters); `HashError: Display+Error`; a capacity/observability test proves it.
- `DpdkMaps` capacities configurable via `with_capacities`; `restore_maps` returns `Err` on capacity-exceeded (no silent over-report); empty-round-trip + restore-into-nonempty + restore-overflow tested.
- Test gaps closed: ingress-deny parity, MbufPkt boundary false-returns, multilcore N=4, RSS v6, EdtPacer large-N.
- Polish landed (or the fixture-dedup explicitly deferred with a note).
- Full `cargo test -p nfkit -- --test-threads=1` green; `make check`/`build`/`test`/`sim` still green; no `flowplane-core`/eBPF/sim changes.

## Risks / notes
- **Trait boundary:** `Maps::conntrack_insert` stays `()` — observability is nfkit-local (counters + fallible `DpdkHash::insert`). Do NOT change the trait (would churn eBPF + sim).
- **Slab grow determinism:** `resize` may reallocate — fine, `slab` holds `Option<V>` (V: Copy, no self-referential pointers). Grow-on-demand is version/cap-independent (no reliance on the 64-alignment coincidence).
- **restore Err leaves partial state:** documented — caller discards the target map + falls back on `Err` (a failed handoff must be observable, not silently partial).
- **multilcore N=4** needs ≥5 lcores (`-l 0-4`); this host has 16. Guard/skip if `worker_lcore_count() < 4`.
- Keep every change nfkit-local; run `make build` (eBPF) once at the end to confirm no accidental cross-crate breakage.
