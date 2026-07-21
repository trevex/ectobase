# nfkit Milestone 9 — software EDT calendar queue + non-None edt_tstamp parity

**Date:** 2026-07-21
**Status:** Design — approved in brainstorming ("continue"), pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M3 (`process_guest_tx`, `DpdkMaps`, `parity_guest_tx`), M2 (`Mbuf`). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Provide **software EDT (Earliest Departure Time) pacing** for DPDK backends that have no hardware pacing (af_xdp/tap/pcap): a calendar queue that holds mbufs stamped with a departure time and releases them in time order — the software equivalent of HW-EDT (NIC tx-timestamp). And close the last datapath parity gap: `process_guest_tx`'s `edt_tstamp` is only `Some` on the metered Encap-shaping arm, which the M3 `parity_guest_tx` anchor never exercises (all its scenarios yield `None`). Both are testable without a smartNIC (`--no-huge`, deterministic synthetic clock). nfkit-only — no `flowplane-core`/eBPF change.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Pacer structure | **Min-heap** of `(edt, seq, Mbuf)` now (correct, simple); hashed **timing-wheel** documented as the O(1) perf swap later |
| Clock | **Clock-agnostic** — `drain_due(now)` takes `now` as a param (deterministic tests); a `monotonic_ns()` helper wraps the real clock for the live loop |
| Tie-break | FIFO within equal `edt` (insertion `seq`) — deterministic release order |
| edt parity | Add `parity_guest_tx` scenario (d): a `METER` entry → `edt_egress` returns `Some` → assert `edt_dpdk == edt_sim` and `is_some()` |
| Wiring | Build + unit-test the pacer; DOCUMENT the guest-egress integration seam + clock-domain caveat; full backend tx-loop deferred to the perf phase |

## 3. Components

```
flowplane/nfkit/src/edt.rs         new: EdtPacer (min-heap pacer) + monotonic_ns() helper
flowplane/nfkit/src/lib.rs         re-export EdtPacer
flowplane/nfkit/tests/edt_pacer.rs new: deterministic pacer tests (synthetic now)
flowplane/nfkit/tests/parity_guest_tx.rs  += scenario (d): METER entry → edt_tstamp Some parity
```

### 3.1 `EdtPacer` (`src/edt.rs`)

```rust
/// Software Earliest-Departure-Time pacer for backends without HW-EDT. Holds mbufs stamped with a
/// departure time and releases them in time order when `drain_due(now)` is called from the poll loop.
/// Clock-agnostic: `edt` and `now` share the caller's monotonic domain (nanoseconds — see monotonic_ns).
pub struct EdtPacer { heap: BinaryHeap<Scheduled>, seq: u64 }
struct Scheduled { edt: u64, seq: u64, mbuf: Mbuf } // Ord: min-heap on (edt, seq) via Reverse
impl EdtPacer {
    pub fn new() -> Self;
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    /// Queue `mbuf` for departure at `edt` (monotonic ns). FIFO among equal edt.
    pub fn enqueue(&mut self, mbuf: Mbuf, edt: u64);
    /// Pop every mbuf with edt <= now, in (edt, seq) order. Not-yet-due mbufs stay queued.
    pub fn drain_due(&mut self, now: u64) -> Vec<Mbuf>;
    /// The earliest queued departure time, if any (for the loop to compute a sleep/poll budget).
    pub fn next_departure(&self) -> Option<u64>;
}
/// CLOCK_MONOTONIC nanoseconds — the domain edt_tstamp is expressed in; used by the live loop as `now`.
pub fn monotonic_ns() -> u64;
```
`Scheduled` implements `Ord` as a **min-heap** (`BinaryHeap` is a max-heap → order by `Reverse((edt, seq))`). `Mbuf` is carried, never compared. `drain_due`: `while let Some(top) = heap.peek()` with `top.edt <= now` → pop and collect; else break (heap ordering guarantees all remaining are later). Ownership of released `Mbuf`s transfers to the returned `Vec`.

### 3.2 Non-None edt parity (`parity_guest_tx.rs` scenario d)

Mirror the existing scenarios' `run_dpdk`/`run_sim` harness. Populate a `METER` entry (`meter_update`/`MemMaps` equiv) on the egress ifindex so the Encap arm's `edt_egress` computes + records `Some(tstamp)`. Build a guest frame that takes the SNAT+Encap shaping path (same as scenario (c) but with the meter present). Assert: `out_dpdk == out_sim` (frame bytes), `a_dpdk == a_sim`, `edt_dpdk == edt_sim`, and `edt_sim.is_some()` — the first non-None `edt_tstamp` DPDK-vs-sim parity, exercising `DpdkMaps::meter_get/meter_update` + `edt_egress` over rte_hash.

## 4. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: `edt_pacer` (ordering, due-release, FIFO tie-break, not-due-stays, empty/`next_departure`) + `parity_guest_tx` scenario (d) (`Some` edt parity) pass `--no-huge`; all M3–M8 anchors still green.
- `cargo test -p flowplane-sim` + the `anchor_*` crate unchanged (M9 is nfkit-only; no new `Maps` method — `meter_*` already exist).
- `EdtPacer` exported; integration seam + clock-domain caveat documented in the module.
- Default host build untouched.

## 5. Phasing (for the plan)

1. **`parity_guest_tx` scenario (d)** — non-None edt parity (small, reuses the file's harness).
2. **`EdtPacer`** (`src/edt.rs`) + `monotonic_ns()` + `edt_pacer.rs` deterministic tests + lib re-export + module doc (seam + timing-wheel note).

## 6. Risks / open questions

- **`Mbuf` ownership in the heap** — `Scheduled` owns each `Mbuf` until drained; on `EdtPacer` drop, queued mbufs free via `Mbuf`'s RAII (no leak). Confirm `Mbuf` is movable into/out of the heap (it is — M2 RAII wrapper).
- **edt_tstamp clock domain** — `edt_egress`/`tc.rs` `edt_stamp` unit must match `now`. The pacer is unit-agnostic (compares u64s); `monotonic_ns()` documents the intended domain (CLOCK_MONOTONIC ns). The live loop must feed `now` in the same domain — a DOC caveat, not exercised by the unit test (which uses synthetic `now`).
- **Scenario (d) meter setup** — must reproduce the exact `edt_egress` inputs on BOTH sides (DpdkMaps `meter_update` and MemMaps equivalent) so the computed `tstamp` matches; read `edt_egress` + `MeterState` to set identical meter fields. If the tstamp depends on a wall-clock/`now` input, feed a FIXED `now` via `GuestTxIn` so both sides are deterministic (the harness already threads `now`).
- **Heap determinism** — equal `edt` must release FIFO; the `seq` tie-break guarantees it. Test explicitly with two same-edt mbufs.
- **Not building the live loop** — the pacer's correctness is fully covered by the synthetic-clock unit test; wiring it into a real backend tx loop (+ real `monotonic_ns` cadence) is perf-phase work and is only documented here.
