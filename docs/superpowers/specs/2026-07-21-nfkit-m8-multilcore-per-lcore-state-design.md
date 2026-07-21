# nfkit Milestone 8 — multi-lcore datapath + per-lcore shared-nothing state + symmetric RSS

**Date:** 2026-07-21
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M2 (`LcoreRuntime`, `Port`, `Mempool`), M3 (`DpdkMaps`, `process_uplink`). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Realize and prove the **shared-nothing per-lcore state model** — N worker lcores each running `process_uplink` over their **own** `DpdkMaps` (conntrack/nat/meter), concurrently, with zero shared mutable state — plus the **symmetric-Toeplitz RSS** key whose symmetry guarantee (both directions of a flow hash to the same lcore) is what makes per-lcore state correct on real hardware. This is the concurrency foundation the DPDK design rests on. Everything here is testable **without a smartNIC** (`--no-huge`, in-process per-lcore batches); only the actual NIC-driven RSS *spreading* is deferred to the hardware/offload phase.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| RSS scope | **Include** symmetric-Toeplitz RSS key + a pure-Rust Toeplitz **symmetry unit test** (fwd/rev inner-5-tuple → same queue) |
| Multi-lcore drive | **In-process per-lcore batches** — each worker processes a pre-loaded batch through its own `DpdkMaps` (no rx queues; the NIC-spreading part needs hardware, deferred) |
| Per-lcore `DpdkMaps` | **Unique rte_hash names per instance** via a process-global `AtomicU32` suffix — no API change, no caller churn, every instance is collision-free |
| Mempool | **One shared `Mempool`** (MT-safe `rte_pktmbuf_alloc`); workers alloc concurrently — avoids a second naming fix |
| Isolation proof | Per-lcore conntrack snapshot: worker A's map holds exactly A's flows, none of B's |
| Test env | `--no-huge`, `-l 0-2` (main + 2 workers); no new `Maps` trait method; eBPF untouched |

## 3. Components

```
flowplane/nfkit/src/dpdk_maps.rs   DpdkMaps hash names get a unique per-instance suffix (AtomicU32)
flowplane/nfkit/src/port.rs        Port::configure sets the symmetric-Toeplitz rss_key
flowplane/nfkit/src/rss.rs         const SYMMETRIC_RSS_KEY + toeplitz_softrss() (pure Rust)
flowplane/nfkit/src/lib.rs         re-exports
flowplane/nfkit/tests/
  dpdk_maps.rs        += two coexisting DpdkMaps instances are isolated (naming fix witness)
  multilcore_datapath.rs   N lcores × per-lcore DpdkMaps × process_uplink: byte-parity + CT isolation
  rss_symmetry.rs     toeplitz_softrss(fwd 5-tuple) == toeplitz_softrss(rev 5-tuple) → same queue
```

### 3.1 Per-lcore-instantiable `DpdkMaps` (the prerequisite fix)

`DpdkMaps::new(socket_id)` currently creates hashes with **fixed** names (`"dm_ct"`, `"dm_underlay"`, …). rte_hash names are process-global and must be unique, so a second coexisting instance (per-lcore) fails `rte_hash_create`. Fix: a `static NEXT_INSTANCE: AtomicU32` fetched-and-incremented in `new`; every hash name gets the instance suffix (`dm_ct_<n>`, …, within `RTE_HASH_NAMESIZE`=32). No signature change → existing callers (all the parity anchors) are unaffected and become strictly safer (sequential create/drop no longer relies on name reuse). Witness test: build two `DpdkMaps`, insert different conntrack flows into each, assert each sees only its own (add→hit in A, miss in B).

### 3.2 Multi-lcore datapath test (in-process per-lcore batches)

`tests/multilcore_datapath.rs` (`--no-huge`, `-l 0-2`, `--test-threads=1`): a shared `Mempool` + a stack `Vec<Mutex<WorkerOut>>` sized `n_workers`. `LcoreRuntime::for_each_worker(n_workers, |q| { ... })`:
- worker `q` builds its **own** `DpdkMaps` (unique names, auto), populates it identically for the base decap path (fw allow on the delivery tap), and processes its **own batch** of crafted encapped frames (each worker gets a distinct set of flows — e.g. distinct inner src IPs/ports) through `process_uplink` over `MbufPkt` (mbufs from the shared pool);
- writes the decapped output bytes + a conntrack-membership snapshot (which of the batch's CT keys are present) into `results[q]` (locking only its own slot — no contention).

Main thread (after join) asserts: **(a)** each worker's outputs are byte-identical to the sim (`process_uplink` over `VecPkt`+`MemMaps` for the same frames+config), and **(b) conntrack isolation** — worker A's `DpdkMaps` conntrack contains A's flow keys and NOT B's (shared-nothing proven end-to-end concurrently; the separate maps make cross-talk structurally impossible, and the test confirms each worker actually created its own entries). A worker panic aborts (the M2 trampoline contract), so a failure can't silently pass.

### 3.3 Symmetric-Toeplitz RSS (`rss.rs`)

- `pub const SYMMETRIC_RSS_KEY: [u8; 40]` — the well-known symmetric key (repeating `0x6d 0x5a`), for which `Toeplitz(A‖B) == Toeplitz(B‖A)`.
- `pub fn toeplitz_softrss(input: &[u8], key: &[u8]) -> u32` — the standard Toeplitz bit-walk (pure Rust, no new bindings). Helper `rss_queue(hash, n_queues) -> u16`.
- `Port::configure` sets `rss_conf.rss_key = SYMMETRIC_RSS_KEY.as_ptr()` + `rss_key_len = 40` (the key outlives the call). On real HW this pins both flow directions to one queue/lcore; on vdev it's a no-op but wired.
- `tests/rss_symmetry.rs`: for several inner 5-tuples, assert `toeplitz_softrss(fwd_tuple, KEY) == toeplitz_softrss(rev_tuple, KEY)` where `rev` swaps (src_ip,src_port)↔(dst_ip,dst_port) — hence the same `rss_queue` for any `n_queues`. This proves the "both directions → same lcore" guarantee the per-lcore state model depends on, with no hardware.

## 4. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: the `DpdkMaps` coexistence test, `multilcore_datapath` (byte-parity per lcore + conntrack isolation), and `rss_symmetry` all pass `--no-huge`; all M3–M7 anchors still pass.
- `cargo test -p flowplane-sim` + the eBPF `anchor_*` crate still pass unchanged (no core/eBPF changes — M8 is nfkit-only).
- Per-lcore `DpdkMaps` instantiation works (unique names); `Port::configure` sets the symmetric RSS key; no new `Maps` trait method.
- Default host build + existing tests untouched. Optionally also validated under reserved hugepages (reuses the M7 self-restoring harness pattern), but the DoD is `--no-huge`.

## 5. Phasing (for the plan)

1. **`DpdkMaps` unique naming** (AtomicU32 suffix) + coexistence unit test.
2. **`multilcore_datapath.rs`** — N-lcore per-lcore-`DpdkMaps` `process_uplink`, byte-parity + CT isolation (reuse the `parity_uplink`/`datapath_pcap` fixture builders).
3. **`rss.rs`** (symmetric key + `toeplitz_softrss`) + `Port::configure` wiring + `rss_symmetry.rs`.

## 6. Risks / open questions

- **rte_hash name length** — `dm_conntrack_<u32>` must fit `RTE_HASH_NAMESIZE` (32); keep prefixes short (`dm_ct_<n>`). Add a debug assert.
- **Shared `Mempool` MT-safety** — `rte_pktmbuf_alloc` is MT-safe (per-lcore cache); confirm `Mempool` is `Sync` (M2 made it `Send+Sync`). If not, fall back to per-lcore pools (also unique-named).
- **`for_each_worker` result collection** — the closure is `Fn + Sync`; a stack `Vec<Mutex<_>>` referenced by the closure is valid because `for_each_worker` joins (mp_wait_lcore) before returning (same lifetime contract as the M2 `WorkerArg`s). Each worker locks only its own index → no real contention.
- **Worker panic safety** — the M2 trampoline aborts on a worker panic (no unwind across the C boundary); a failed assertion inside a worker must therefore be surfaced via the result slot + checked on the main thread (don't `assert!` inside the worker; record and assert after join).
- **Symmetric key correctness** — verify the chosen key actually yields `hash(fwd)==hash(rev)` for the RSS input ordering (src_ip‖dst_ip‖src_port‖dst_port); the `rss_symmetry` test IS that verification. IPv4 vs IPv6 tuple widths differ — test the v4 inner tuple (the uplink path); note v6 as a follow-up.
- **`--no-huge` multi-lcore** — `-l 0-2` + `--no-huge -m` works (M2 runtime + M3 hash tests prove EAL multi-lcore without hugepages); the in-process batch model needs no NIC/queues.
