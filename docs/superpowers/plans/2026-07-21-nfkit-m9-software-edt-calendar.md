# nfkit M9 — software EDT calendar queue + non-None edt parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Close the non-None `edt_tstamp` DPDK-vs-sim parity gap; (2) provide a software EDT pacer (calendar queue) for backends without HW-EDT. nfkit-only, `--no-huge`, no `flowplane-core`/eBPF change.

**Architecture:** `edt_egress` (flowplane-core) returns `Some(tstamp)` only on the metered Encap arm — the M3 `parity_guest_tx` anchor never sets a `METER` entry, so that arm is untested for DPDK. Add scenario (d) with a meter. Separately, `EdtPacer` (a min-heap of `(edt, seq, Mbuf)`) holds stamped mbufs and releases them in departure order via `drain_due(now)` — clock-agnostic for deterministic tests.

**Tech Stack:** Rust, `nfkit` (M2/M3), `flowplane-core::meter::{edt_egress, edt_departure}`, `flowplane_common::MeterState`. Tests `--no-huge`, `--test-threads=1`, inside `nix develop`.

**Context (grounded — I read these):**
- `flowplane-core/src/meter.rs:70` `edt_egress<M:Maps>(maps, ifindex, wire_len, now) -> Option<u64>`: returns `None` if no `METER[ifindex]` or `total_bps==0`; else `edt_departure(total_bps, wire_len, total_last_ns, now)` → `t_sched = max(total_last_ns, now)`, writes back `total_last_ns = t_sched + delay`, returns `Some(t_sched)`.
- `flowplane_common::MeterState` (`flowplane-common/src/lib.rs:192`): fields `total_bps,total_burst,total_tokens,total_last_ns, public_bps,public_burst,public_tokens,public_last_ns, ingress_*` (all `u64`). `Default` derived. `public_pass` only gates when `is_external && public_bps>0` → keep `public_bps=0` so the frame isn't policed.
- `GuestTxOut { action, edt_tstamp: Option<u64> }`; `GuestTxIn { meta, src_ifindex, now }` (`flowplane-core/src/datapath.rs:104`).
- `parity_guest_tx.rs` scenario (a) (`nfkit/tests/parity_guest_tx.rs:~156`) is the ENCAP path with `edt=None`: route `is_external=1` to `NEXTHOP_UL`, `node_local()`, egress allow meta+rule, `guest_frame(EXT_DST,443)`, `in_.now=0` → `Action::Redirect(UPLINK_IFINDEX)`. `run_dpdk(&pool,&mut dm,&frame,&in_)`/`run_sim(&mut sim,&frame,&in_)` return `(bytes, Action, Option<u64>)`. Consts `VNI/SRC_IFINDEX/UPLINK_IFINDEX/EXT_DST/NEXTHOP_UL/ETH_LEN`, helpers `node_local()/egress_allow_meta()/egress_allow_rule()/guest_frame()/port_meta()` are in the file.
- `DpdkMaps` implements `Maps` → `meter_update(ifindex,state)` / `meter_get` (`nfkit/src/dpdk_maps.rs:254`). `MemMaps` meter setter: VERIFY the name (likely a public `meter` map field `sim.meter.insert(ifindex, ms)` or `add_meter`) — grep `flowplane-sim` before writing.
- `Mbuf` load pattern (from `parity_guest_tx.rs` `run_dpdk`): `pool.alloc()`, `mb.append(len)`, `mb.data_mut().copy_from_slice(..)`, read via the file's `mp_bytes`/`read_array`. `Mempool::new("name", n, cache, socket)`.
- No existing pacer scaffolding in nfkit.

**Absolute rules:**
- Cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook active; if the rustup `cargo fmt` shim prints usage, format touched files with `rustfmt --edition 2021 <files>`.
- No `flowplane-core`/`flowplane-common`/eBPF edits — `edt_egress`/`meter_*` already exist. Run FULL `cargo test -p nfkit -- --test-threads=1` before the final commit.

---

## File Structure
- `flowplane/nfkit/tests/parity_guest_tx.rs` — `+ scenario (d)` (non-None edt parity).
- `flowplane/nfkit/src/edt.rs` — new (`EdtPacer`, `monotonic_ns`).
- `flowplane/nfkit/src/lib.rs` — `mod edt; pub use edt::EdtPacer;` (+ `monotonic_ns` if public).
- `flowplane/nfkit/tests/edt_pacer.rs` — new (deterministic pacer tests).

---

## Task 1: Non-None `edt_tstamp` parity (`parity_guest_tx` scenario d)

**Files:** Modify `flowplane/nfkit/tests/parity_guest_tx.rs`.

- [ ] **Step 1: Verify the `MemMaps` meter setter** — `grep -nE "meter|MeterState" flowplane/nfkit/../flowplane-sim/src/*.rs` (the crate is `flowplane-sim`). Find how to install a `MeterState` for an ifindex into `MemMaps` (field `.meter` insert, or an `add_meter`/setter). Note the exact call.

- [ ] **Step 2: Add scenario (d)** — after scenario (c) in `dpdk_guest_tx_matches_sim`, append a new block. Same encap setup as (a) PLUS an identical `MeterState` on both sides so `edt_egress` returns a deterministic non-zero stamp:
```rust
    // ───────────── Scenario (d): metered ENCAP → non-None edt_tstamp parity ─────────────
    // Same encap path as (a), but a METER entry with total_bps>0 and a FUTURE schedule cursor
    // (total_last_ns=5000 > now=0) makes edt_egress return Some(t_sched=5000). public_bps=0 so the
    // public lane doesn't police. Exercises DpdkMaps::meter_get/meter_update + edt_egress over rte_hash
    // — the first non-None edt_tstamp DPDK-vs-sim parity (all of a/b/c were None).
    {
        let frame = guest_frame(EXT_DST, 443);
        let route = RouteValue { nexthop_vni: 0, nexthop_ipv6: NEXTHOP_UL, is_external: 1, _pad: [0; 3] };
        let meter = MeterState { total_bps: 1_000_000_000, total_last_ns: 5000, ..MeterState::default() };

        let mut sim = MemMaps::default();
        sim.local = Some(node_local());
        sim.add_route4(VNI, EXT_DST, route);
        sim.fw_meta.insert(SRC_IFINDEX, egress_allow_meta());
        sim.fw_rules.insert((SRC_IFINDEX, 0), egress_allow_rule());
        /* VERIFIED setter */ sim.meter.insert(SRC_IFINDEX, meter); // adjust to the real MemMaps API
        let (out_sim, a_sim, edt_sim) = run_sim(&mut sim, &frame, &in_);

        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (d)");
        dm.set_local(node_local());
        dm.add_route4(VNI, EXT_DST, route);
        dm.add_fw_meta(SRC_IFINDEX, egress_allow_meta());
        dm.add_fw_rule(SRC_IFINDEX, 0, egress_allow_rule());
        flowplane_core::maps::Maps::meter_update(&mut dm, SRC_IFINDEX, meter);
        let (out_dpdk, a_dpdk, edt_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(a_dpdk, a_sim, "(d) action parity");
        assert_eq!(a_sim, Action::Redirect(UPLINK_IFINDEX), "(d) encapped + redirected");
        assert_eq!(edt_dpdk, edt_sim, "(d) edt_tstamp parity");
        assert_eq!(edt_sim, Some(5000), "(d) metered encap → deterministic edt = max(total_last_ns, now)");
        assert_eq!(out_dpdk, out_sim, "(d) encapped frame byte parity (metering doesn't touch bytes)");
    }
```
Add `use flowplane_common::MeterState;` (+ `RouteValue` already imported). If `Maps::meter_update` isn't easily callable that way, add `use flowplane_core::maps::Maps;` at file top and call `dm.meter_update(...)`.

- [ ] **Step 3: Run → PASS** — `cargo test -p nfkit --test parity_guest_tx -- --test-threads=1 --nocapture`. All four scenarios green; (d) asserts `Some(5000)` parity. If `edt_sim` isn't `Some(5000)`, recompute from `edt_departure` (`t_sched = max(total_last_ns, now)` with the values used) and set the expected literal to match — do NOT change to `None` or drop the `is_some` intent. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 4: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/nfkit/tests/parity_guest_tx.rs
git commit -m "test(nfkit): parity_guest_tx (d) — non-None edt_tstamp parity (metered encap arm)"
```

---

## Task 2: `EdtPacer` software calendar queue

**Files:** Create `flowplane/nfkit/src/edt.rs`, `flowplane/nfkit/tests/edt_pacer.rs`; modify `flowplane/nfkit/src/lib.rs`.

- [ ] **Step 1: Write `flowplane/nfkit/src/edt.rs`**
```rust
//! Software Earliest-Departure-Time (EDT) pacer for DPDK backends without hardware pacing
//! (af_xdp / net_tap / net_pcap). `process_guest_tx` returns `Some(edt_tstamp)` on the metered
//! encap arm; a backend with HW-EDT sets the NIC tx-timestamp, but a software backend must hold the
//! mbuf until its departure time. `EdtPacer` is that hold-and-release calendar queue.
//!
//! INTEGRATION SEAM (guest-egress poll loop, wired in the perf phase — not built here):
//!   match out.edt_tstamp { Some(edt) => pacer.enqueue(mbuf, edt), None => tx_now(mbuf) }
//!   for mbuf in pacer.drain_due(monotonic_ns()) { tx_now(mbuf) }
//! CLOCK DOMAIN: `edt_tstamp` is CLOCK_MONOTONIC ns (the eBPF path uses bpf_ktime_get_ns); the loop
//! must feed `now` from the SAME domain — see `monotonic_ns`. The pacer itself is unit-agnostic.
//!
//! Structure: a min-heap ordered by (edt, seq). A hashed timing-wheel is the O(1)-per-op swap for
//! line-rate pacing — a documented future optimization; the heap is correct and simple for now.
use crate::Mbuf;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

struct Scheduled { edt: u64, seq: u64, mbuf: Mbuf }
impl PartialEq for Scheduled { fn eq(&self, o: &Self) -> bool { self.edt == o.edt && self.seq == o.seq } }
impl Eq for Scheduled {}
impl Ord for Scheduled {
    // Reverse so BinaryHeap (a max-heap) yields the EARLIEST (edt, seq) first.
    fn cmp(&self, o: &Self) -> Ordering { (o.edt, o.seq).cmp(&(self.edt, self.seq)) }
}
impl PartialOrd for Scheduled { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }

/// Holds mbufs stamped with a departure time and releases them in time order.
#[derive(Default)]
pub struct EdtPacer { heap: BinaryHeap<Scheduled>, seq: u64 }

impl EdtPacer {
    #[must_use] pub fn new() -> Self { Self::default() }
    #[must_use] pub fn len(&self) -> usize { self.heap.len() }
    #[must_use] pub fn is_empty(&self) -> bool { self.heap.is_empty() }
    /// Queue `mbuf` to depart at `edt` (monotonic ns). FIFO among equal `edt`.
    pub fn enqueue(&mut self, mbuf: Mbuf, edt: u64) {
        let seq = self.seq; self.seq += 1;
        self.heap.push(Scheduled { edt, seq, mbuf });
    }
    /// The earliest queued departure time, if any (for the loop's poll/sleep budget).
    #[must_use] pub fn next_departure(&self) -> Option<u64> { self.heap.peek().map(|s| s.edt) }
    /// Remove and return every mbuf whose `edt <= now`, in (edt, seq) order.
    pub fn drain_due(&mut self, now: u64) -> Vec<Mbuf> {
        let mut out = Vec::new();
        while let Some(top) = self.heap.peek() {
            if top.edt <= now { out.push(self.heap.pop().unwrap().mbuf); } else { break; }
        }
        out
    }
}

/// CLOCK_MONOTONIC nanoseconds — the domain `edt_tstamp` is expressed in. Used by the live loop as
/// `now`. (Not exercised by the unit tests, which pass a synthetic `now`.)
#[must_use]
pub fn monotonic_ns() -> u64 {
    // SAFETY: clock_gettime with a valid clock id + out-param.
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}
```
If `libc` is not already a `nfkit` dep, either add it (`libc = "0.2"` in `flowplane/nfkit/Cargo.toml`) OR implement `monotonic_ns` via an existing DPDK time binding (`rte_get_timer_cycles`/`rte_get_timer_hz`) — pick whichever avoids a new dep; `monotonic_ns` is not unit-tested so exact source is flexible, but it MUST be a monotonic ns clock. Verify `crate::Mbuf` is the correct path (grep `lib.rs`).

- [ ] **Step 2: Re-export** — `flowplane/nfkit/src/lib.rs`: `mod edt; pub use edt::{EdtPacer, monotonic_ns};`. `cargo build -p nfkit`.

- [ ] **Step 3: Write `flowplane/nfkit/tests/edt_pacer.rs`** — deterministic, needs EAL only for the mbuf pool:
```rust
//! EdtPacer: out-of-order enqueue releases in departure order; not-yet-due mbufs stay queued; FIFO
//! among equal edt; empty/next_departure. Synthetic `now` — no real clock. Run --test-threads=1.
use nfkit::{Eal, EdtPacer, Mempool};
// tag each mbuf with a 1-byte id so we can assert WHICH mbuf was released.
fn tagged(pool: &Mempool, id: u8) -> nfkit::Mbuf {
    let mut mb = pool.alloc().expect("alloc");
    mb.append(1).expect("append");
    mb.data_mut()[0] = id;
    mb
}
fn id_of(mb: &nfkit::Mbuf) -> u8 { mb.data()[0] } // verify Mbuf read accessor name

#[test]
fn pacer_releases_in_departure_order() {
    let _eal = Eal::init(["nfkit-test","-l","0","--no-huge","-m","512","--no-pci","--file-prefix","nfkit_edt"]).expect("EAL");
    let pool = Mempool::new("edt_pool", 1023, 250, 0).expect("pool");
    let mut p = EdtPacer::new();
    // enqueue OUT of order: edt 300(id=3), 100(id=1), 200(id=2)
    p.enqueue(tagged(&pool, 3), 300);
    p.enqueue(tagged(&pool, 1), 100);
    p.enqueue(tagged(&pool, 2), 200);
    assert_eq!(p.len(), 3);
    assert_eq!(p.next_departure(), Some(100));
    // nothing due before 100
    assert!(p.drain_due(99).is_empty());
    // now=150 → only id=1 (edt 100)
    let due = p.drain_due(150);
    assert_eq!(due.iter().map(id_of).collect::<Vec<_>>(), vec![1]);
    // now=300 → id=2 then id=3, in departure order
    let due = p.drain_due(300);
    assert_eq!(due.iter().map(id_of).collect::<Vec<_>>(), vec![2, 3]);
    assert!(p.is_empty());
    assert_eq!(p.next_departure(), None);
}

#[test]
fn pacer_fifo_within_equal_edt() {
    let _eal_ok = true; // EAL already inited by the other test in this binary? NO — separate binary needs its own.
    // (If both tests share one binary, init EAL once; DPDK EAL init is process-global and single-shot.)
}
```
IMPORTANT: EAL init is process-global/single-shot — a test BINARY may init it once. Put BOTH test cases in ONE `#[test]` (or gate a shared init) to avoid a double-init panic, OR structure as a single test exercising order + FIFO-tie + not-due + empty. Simplest: ONE `#[test]` that: enqueues two mbufs at equal edt=100 (ids 10 then 11) and asserts `drain_due(100)` yields `[10,11]` (FIFO), plus the out-of-order + not-due + empty assertions above. Verify the `Mbuf` read accessor (`data()` vs `read_array`) against `nfkit/src/mbuf.rs`.

- [ ] **Step 4: Run → PASS** — `cargo test -p nfkit --test edt_pacer -- --test-threads=1 --nocapture`. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 5: Full suite + commit** — `cargo test -p nfkit -- --test-threads=1` (all M3–M9 green).
```bash
git add flowplane/nfkit/src/edt.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/edt_pacer.rs
git commit -m "feat(nfkit): EdtPacer software EDT calendar queue (min-heap pacer) + deterministic tests"
```

---

## Definition of Done (M9)
- `cargo test -p nfkit -- --test-threads=1`: `parity_guest_tx` (d) (`Some` edt parity) + `edt_pacer` (order/due/FIFO/empty) pass `--no-huge`; all M3–M8 anchors green.
- `cargo test -p flowplane-sim` + `anchor_*` unchanged (nfkit-only; `edt_egress`/`meter_*` reused).
- `EdtPacer` + `monotonic_ns` exported; integration seam + clock-domain caveat documented in `edt.rs`.
- Default host build untouched.

## Risks / notes
- **`MemMaps` meter setter name** — verify in `flowplane-sim` (Task 1 Step 1) before writing the literal.
- **EAL single-shot per test binary** — `edt_pacer.rs` must init EAL exactly once; keep the assertions in one `#[test]`.
- **`Mbuf` accessors** — confirm `data()`/`data_mut()`/`append` names against `nfkit/src/mbuf.rs` (the parity tests use them).
- **`libc` dep for `monotonic_ns`** — add it or use a DPDK timer binding; not unit-tested, but must be a monotonic ns clock.
- **Do not weaken (d)** — it must assert a NON-None (`Some(_)`) edt with byte + value parity; recompute the expected literal from `edt_departure` if needed, never fall back to `None`.
- **Heap vs wheel** — heap is the correct-and-simple choice for M9; the timing-wheel is a documented perf follow-up, not this milestone.
