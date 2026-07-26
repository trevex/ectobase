# DPDK Guest Egress — Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (fresh subagent per task + two-stage spec/quality review). Steps use `- [ ]` checkboxes.

**Goal:** Complete the documented follow-ups of the merged DPDK guest-egress first slice (main @b0fa50b): NAT64 egress wiring, a shared_ct concurrent-writer stress test, multi-worker guest-port partitioning, guest↔guest same-node local delivery (incl. a cross-lcore ring primitive), and detach/reuse hardening.

**Architecture:** The DPDK `flowplane-dpdk serve` loop already polls a VF-style preallocated per-guest af_xdp port pool (host-end `fpg{i}` bound to ethdev ports 1..=N; worker polls guest ports → `process_guest_tx` → SNAT+encap → uplink). These follow-ups generalize it: branch the guest block on inner ethertype for NAT64 egress; partition guest ports across worker lcores; deliver guest↔guest frames (same-worker direct tx, cross-worker via a new `nfkit::LcoreRing` over `rte_ring`); and detect/exclude dead pool slots.

**Tech Stack:** Rust, DPDK (nfkit `Port`/af_xdp/`MbufPkt`/`rte_ring`), `flowplane-core::datapath` (`process_guest_tx`, `process_guest_tx_nat64`, `process_uplink_rx`), `flowplane-device` veth, in-process EAL `--no-huge` tests (sudo).

**Source of truth (verify against current code — cite drift):**
- Worker guest block: `flowplane-dpdk/src/serve.rs` `worker_loop` (the `// ── GUEST block` region ~ line 700). Currently: for each owned guest port (`guest_qs: Vec<(u32 host_ifindex, RxQueue, TxQueue)>`), rx → `ports_get(host_ifindex)` → `process_guest_tx` → verdict routing. `Redirect(uplink_ifindex)` → `tx_burst.try_push`; `Redirect(_)` (guest↔guest) → **dropped with a TODO**; `Pass`/`Drop` → dropped. Guest ports assigned worker-0-owns-all: `let owned: &[GuestPort] = if q == 0 { &guest_ports } else { &[] };` in the `for_each_worker` closure (~ line 465). `struct GuestPort { port: Port, host_ifindex: u32 }` (serve.rs:72).
- `process_guest_tx<P,M>(pkt, maps, &GuestTxIn{meta:&PortMeta, src_ifindex:u32, now:u64}) -> GuestTxOut{action,edt_tstamp}` (datapath.rs:154). IPv4 path.
- `process_guest_tx_nat64<P,M>(pkt, maps, &GuestTxNat64In{meta:&PortMeta, local:&Local}) -> Action` (datapath.rs:423). v6→v4. `nat64_egress_parse` returns `None` (→ `Action::Pass`) when the dst is NOT in the NAT64 prefix / no NAT config. Encap arm → `Redirect(local.uplink_ifindex)`. Seeds `CT_F_NAT64 | CT_REWRITE_DST` reverse entries.
- Ethertype at inner-frame offset 12: `pkt.read_array::<2>(12)` → `u16::from_be_bytes`; `0x0800` = IPv4, `0x86DD` = IPv6 (see `process_wan_rx` datapath.rs:487 for the exact idiom).
- `for_each_worker<F: Fn(u16)+Sync>(n_workers, func)` (nfkit/src/runtime.rs:39) — runs `func(q)` on worker lcore `q`, joins before return. `worker_lcore_count()` available.
- shared_ct: `SharedConfigMaps::shared_ct_insert(key, entry)->bool` / `shared_ct_get(&key)->Option<CtEntry>` / `shared_ct_remove(&key)->bool` / `shared_ct_for_each(f)` (shared_config.rs:758+). Single-writer behind a `std::sync::Mutex` (writes), lock-free RCU reads. `register_reader()`/`report_quiescent(&tok)`.
- NAT64 handoff test model: `nfkit/tests/guest_tx_nat_return_handoff.rs` (real guest_tx write → uplink_rx read) + `flowplane-sim/src/nat64_test.rs` `uplink_rx_dispatches_nat64_return_to_v6_expansion` + `SimNode::guest_tx_nat64` (sim.rs:281).
- Multi-lcore test harness: `nfkit/tests/multilcore_datapath.rs` / `multilcore_nat_return.rs` (`for_each_worker`, per-lcore `PerLcoreFlowMaps`, one `SharedConfigMaps`, `--no-huge`).
- `Mbuf`: `nfkit/src/mbuf.rs` — `Mbuf::from_raw(NonNull)`, `into_raw()->*mut rte_mbuf`, `as_raw()`. `MbufBurst = ArrayVec<Mbuf, BURST>` (BURST=32).
- dpdk-sys wrapper: `dpdk-sys/wrapper.h` + `dpdk-sys/src/shim.c` (add `rte_ring.h` + any inline-macro shims here, as done for `nfkit_eth_rx_burst`/`nfkit_rss_ip_hf`).

---

## Task 1: NAT64 egress wiring — worker branches on inner ethertype (closes backlog #3)

**Goal:** The worker guest block runs `process_guest_tx_nat64` for IPv6 guest frames so NAT64 egress (v6 guest → v4 external) seeds `CT_F_NAT64` reverse entries on the live serve loop, making backlog item #3 (NAT64 ingress) end-to-end reachable.

**Files:**
- Modify: `flowplane-dpdk/src/serve.rs` (worker guest block, ~line 700).
- Create: `nfkit/tests/guest_tx_nat64_handoff.rs` (mirror `guest_tx_nat_return_handoff.rs`).

- [ ] **Step 1: Write the failing component test** — `nfkit/tests/guest_tx_nat64_handoff.rs`. Model it on `guest_tx_nat_return_handoff.rs` (Task 5 of the first slice) but for NAT64: over ONE `ComposedMaps`, (a) build a guest IPv6 TCP frame `[InnerEth(ethertype 0x86DD)][IPv6 guest_v6→nat64_prefix::v4dst][TCP]`, program the NAT64 fixture (reuse `flowplane-sim/src/nat64_test.rs` + `SimNode::guest_tx_nat64` fixture constants: NAT64 prefix, nat config, route4 for the embedded v4 dst, PortMeta with guest_ipv4+guest_ipv6, LOCAL), call the REAL `process_guest_tx_nat64(&mut pkt, &mut composed, &GuestTxNat64In{meta:&pm, local:&local})`; assert `Redirect(uplink_ifindex)` and that a `CT_F_NAT64 | CT_REWRITE_DST` reverse entry landed in `shared_ct` at `(vni,0,nat_ip,0,nat_port)` (discover nat_ip/nat_port from the post-translation frame bytes, as the sibling test does). (b) Build the matching encapped v4 WAN return (inner `[IPv4 ext→nat_ip][TCP ext_port→nat_port]`) toward this node's underlay, resolve the uplink input exactly as the worker does, call `process_uplink_rx`; assert `Redirect(guest_tap)` AND the delivered frame is v6-expanded (inner ethertype 0x86DD, inner IPv6 dst == guest_ipv6) — proving the `CT_F_NAT64` dispatch to `process_uplink_nat64_ingress`. This closes the loop the first-slice handoff test does for plain SNAT.
- [ ] **Step 2: Run it — expect FAIL to compile / then FAIL** — `sudo -E $(command -v cargo) test -p nfkit --test guest_tx_nat64_handoff -- --test-threads=1 2>&1 | tail`. (The test itself doesn't need the serve change — it drives the core fns directly — so it should PASS once written IF the core NAT64 dispatch works. Its real purpose is to lock the NAT64 handoff; write it first as the correctness anchor. If it passes immediately, good — proceed to wire the worker in Step 3.)
- [ ] **Step 3: Wire the worker guest block** — in `serve.rs` `worker_loop`, the guest per-mbuf block currently always calls `process_guest_tx`. Branch on the inner ethertype BEFORE building the action:
  ```rust
  let ethertype = pkt.read_array::<2>(12).map(u16::from_be_bytes);
  let action = match (&local, composed.cfg.ports_get(*host_ifindex)) {
      (Some(l), Some(pm)) => match ethertype {
          Some(0x86DD) => {
              // IPv6 guest frame → NAT64 egress (v6→v4). Passes (→ drop below) if the dst is
              // not NAT64-bound / no NAT config. Native v6→v6 guest egress is a separate
              // follow-up (no shared-core orchestrator yet); note it in a comment.
              process_guest_tx_nat64(&mut pkt, &mut composed, &GuestTxNat64In { meta: &pm, local: l })
          }
          _ => {
              // IPv4 (0x0800) / default → the existing SNAT+encap path.
              process_guest_tx(&mut pkt, &mut composed, &GuestTxIn { meta: &pm, src_ifindex: *host_ifindex, now }).action
          }
      },
      _ => Action::Drop, // no LOCAL or unbound port
  };
  ```
  Keep the existing verdict routing (`Redirect(uplink_ifindex)` → `tx_burst.try_push`; `Redirect(_)` guest↔guest → drop TODO; `Pass`/`Drop` → drop). Import `process_guest_tx_nat64` + `GuestTxNat64In` from `flowplane_core::datapath`. Add a comment: native v6→v6 guest egress is NOT wired (no core orchestrator); only NAT64 v6→v4 is.
- [ ] **Step 4: Build + verify no regression** — `cargo build -p flowplane-dpdk -p nfkit 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `make -C /home/nik/Development/ironcore-net-xdp sim 2>&1 | tail`; re-run the Step 2 sudo test (PASS) + the first-slice handoff `sudo -E $(command -v cargo) test -p nfkit --test guest_tx_nat_return_handoff -- --test-threads=1` (PASS, no regression).
- [ ] **Step 5: Update backlog doc** — in `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` #3, change "Remaining (latent)" to note NAT64 egress is now wired into the serve loop (IPv6 guest frames dispatch to `process_guest_tx_nat64`), so `CT_F_NAT64` reverse entries are seeded and NAT64 ingress is END-TO-END reachable; the handoff is proven by `nfkit/tests/guest_tx_nat64_handoff.rs`.
- [ ] **Step 6: Commit** — `feat(dpdk): worker branches on ethertype → NAT64 egress (v6 guest), closes B2b #3`. End with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

## Task 2: shared_ct concurrent-writer stress test (validates the single-writer Mutex fix)

**Goal:** Prove the `shared_ct` `RcuHash` holds under REAL concurrent multi-lcore writers (the earlier B2b review fix serialized writes behind a `std::sync::Mutex`; the existing `multilcore_nat_return.rs` drives lcores sequentially). No datapath change.

**Files:**
- Create: `nfkit/tests/shared_ct_concurrent_writers.rs`.

- [ ] **Step 1: Write the test** — one `SharedConfigMaps`; `for_each_worker(n_workers, |q| {...})` where n_workers = `worker_lcore_count()` (run EAL with `-l 0-4`, `--no-huge`, unique `--file-prefix`). Each worker lcore concurrently inserts K distinct `shared_ct` entries keyed by a per-worker disjoint keyspace (e.g. `nat_ip = [10, 9, q as u8, i as u8]`, the peer-independent reverse shape `(vni,0,nat_ip,0,nat_port)`), each via `composed.cfg.shared_ct_insert(key, entry)` — the EXACT call `snat_egress` makes. Interleave `shared_ct_get` reads of both own and other workers' keys (readers must never see a torn entry: either absent or the exact inserted `CtEntry`). Register/quiesce each worker as a reader. After `for_each_worker` joins (barrier), on the main thread assert: (a) ALL `n_workers * K` entries are present via `shared_ct_get`, byte-exact; (b) `shared_ct_for_each` counts exactly `n_workers * K` entries; (c) no duplicate/missing keys. Add a concurrent `shared_ct_remove` sub-phase if cheap (each worker removes half its keys; assert the survivors). Module doc: explains this exercises the concurrent-writer path the single-writer `Mutex` serializes (the review fix) — before that fix, concurrent `RcuHash` writes from multiple lcores would corrupt (data race); this asserts they don't.
- [ ] **Step 2: Run under sudo** — `sudo -E $(command -v cargo) test -p nfkit --test shared_ct_concurrent_writers -- --test-threads=1 --nocapture 2>&1 | tail -20`. Expected PASS. If it FAILS/corrupts, that's a REAL finding about the writer serialization — STOP and report BLOCKED with evidence (do not weaken the assertion).
- [ ] **Step 3: Build + clippy** — `cargo build -p nfkit --tests 2>&1 | tail`; `cargo clippy -p nfkit --tests 2>&1 | tail`.
- [ ] **Step 4: Commit** — `test(dpdk): shared_ct concurrent multi-lcore writer stress (validates single-writer Mutex)`. Co-Authored-By trailer.

---

## Task 3: Multi-worker guest-port partitioning across lcores

**Goal:** Distribute the preallocated guest ports across ALL worker lcores (round-robin) instead of worker-0-owns-all, so guest egress scales and cross-lcore NAT-return demux (`shared_ct`) is exercised on the live loop.

**Files:**
- Modify: `flowplane-dpdk/src/serve.rs` (`for_each_worker` closure ~line 465).

- [ ] **Step 1: Partition assignment** — replace `let owned: &[GuestPort] = if q == 0 { &guest_ports } else { &[] };` with a round-robin filter by port index: worker `q` owns `guest_ports[i]` where `i % n_workers == q as usize`. Since `worker_loop` takes `&[GuestPort]` (a contiguous slice) but a strided subset isn't contiguous, change the ownership handoff: build, per worker, a `Vec<&GuestPort>` (or pass the full `&[GuestPort]` + `(q, n_workers)` and let `worker_loop` stride-filter when constructing `guest_qs`). Cleanest: pass `worker_loop(q, n_workers, &shared_for_workers, &port, &guest_ports, &stop_w)` and inside, build `guest_qs` from `guest_ports.iter().enumerate().filter(|(i,_)| i % n_workers as usize == q as usize)`. Update `worker_loop`'s signature to take `n_workers: u16` and `guest_ports: &[GuestPort]` (the full slice) instead of the pre-filtered `&[GuestPort]`. The `for_each_worker` closure captures `&guest_ports` by ref (Sync — `GuestPort` is Send+Sync).
- [ ] **Step 2: Comment the model** — note that per-lcore flow state stays shared-nothing; a guest's SNAT reverse entry lands in its owning lcore's per-lcore CT + `shared_ct`; a NAT return RSS-steered to a different uplink worker resolves via `shared_ct` (the mechanism proven by `multilcore_nat_return.rs`).
- [ ] **Step 3: Build + verify** — `cargo build -p flowplane-dpdk 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `make sim`; re-run the sudo handoff tests (no regression). Add/adjust a `serve` unit test only if the partition math is cheaply testable as a pure fn (e.g. extract `fn owns(port_index, q, n_workers) -> bool` + unit-test it: with n_workers=2, port 0→worker0, port1→worker1, port2→worker0).
- [ ] **Step 4: Commit** — `feat(dpdk): partition preallocated guest ports round-robin across worker lcores`. Co-Authored-By trailer.

---

## Task 4: `nfkit::LcoreRing` — an `rte_ring` MPSC primitive for inter-lcore mbuf handoff

**Goal:** Add a safe nfkit wrapper over DPDK `rte_ring` to move `Mbuf` ownership between lcores (needed for cross-worker guest↔guest delivery in Task 5). Multi-producer / single-consumer (MP/SC): any worker enqueues; the owning worker dequeues.

**Files:**
- Modify: `dpdk-sys/wrapper.h` (add `#include <rte_ring.h>`), `dpdk-sys/src/shim.c` (inline-macro shims if `rte_ring_enqueue_bulk`/`_dequeue_bulk` are macros/inlines — expose `nfkit_ring_enqueue_bulk`/`nfkit_ring_dequeue_bulk` returning counts, mirroring `nfkit_eth_rx_burst`).
- Create: `nfkit/src/lcore_ring.rs`; export from `nfkit/src/lib.rs`.
- Test: `nfkit/tests/lcore_ring.rs`.

- [ ] **Step 1: dpdk-sys binding** — add `#include <rte_ring.h>` to `wrapper.h`. Check whether `rte_ring_create`, `rte_ring_enqueue_bulk`, `rte_ring_dequeue_bulk`, `rte_ring_free` are bindgen-visible; the `*_bulk` ops are `static inline` → NOT bindgen-visible, so add C shims in `shim.c`:
  ```c
  unsigned nfkit_ring_enqueue_bulk(struct rte_ring *r, void **objs, unsigned n) {
      return rte_ring_enqueue_bulk(r, objs, n, NULL);
  }
  unsigned nfkit_ring_dequeue_bulk(struct rte_ring *r, void **objs, unsigned n) {
      return rte_ring_dequeue_bulk(r, objs, n, NULL);
  }
  ```
  Declare them in `wrapper.h` so bindgen emits them.
- [ ] **Step 2: `LcoreRing` safe wrapper** — `nfkit/src/lcore_ring.rs`:
  ```rust
  /// A DPDK rte_ring carrying Mbuf OWNERSHIP between lcores (MP enqueue / SC dequeue). Producers
  /// (any lcore) `enqueue` an Mbuf (ownership → the ring, as a raw ptr); the single consumer lcore
  /// `dequeue`s them back into owned Mbufs. Created before the workers launch; freed on drop.
  pub struct LcoreRing { raw: *mut dpdk_sys::rte_ring }
  // SAFETY: rte_ring MP/SC ops are internally synchronized for multi-producer; the handle may be
  // shared (&LcoreRing) across lcores for enqueue. We mark Sync (shared-ref enqueue is MT-safe);
  // the single consumer calls dequeue. NOT Send of the consumer role — enforce SC by construction
  // (only the owning worker calls dequeue).
  unsafe impl Sync for LcoreRing {}
  unsafe impl Send for LcoreRing {}
  ```
  - `LcoreRing::new(name: &str, size_pow2: u32, socket: i32) -> Result<LcoreRing, RingError>` via `rte_ring_create(name, count, socket, RING_F_SC_DEQ)` (MP default, SC deq flag). `count` must be a power of two.
  - `fn enqueue(&self, m: Mbuf) -> Result<(), Mbuf>` — `let p = m.into_raw(); if nfkit_ring_enqueue_bulk(raw, &p as *const _ as *mut *mut c_void, 1) == 1 { Ok(()) } else { Err(Mbuf::from_raw(p)) }` (on full ring, return the Mbuf back to the caller so it can drop/free it — never leak). Ownership transfers into the ring on success.
  - `fn dequeue_burst(&self, out: &mut MbufBurst) -> usize` — bulk-dequeue up to `out.remaining_capacity()` raw ptrs, wrap each as `Mbuf::from_raw` (ownership back to the consumer), push to `out`. Mirror `RxQueue::rx`'s pattern.
  - `impl Drop` → `rte_ring_free(raw)`.
- [ ] **Step 3: Test** — `nfkit/tests/lcore_ring.rs` (EAL `--no-huge`, unique `--file-prefix`): create a ring; from `for_each_worker` producers, each lcore enqueues K distinct mbufs (allocate from a `Mempool`, stamp a per-(worker,i) marker byte); after the barrier, the main thread dequeues ALL and asserts every marker is present exactly once (no loss, no dup, no torn ptr). Also test the full-ring path: fill a small ring, assert `enqueue` returns `Err(mbuf)` (the mbuf comes back, is dropped, no leak — verify via mempool free-count if accessible, else just that it returns Err). Run: `sudo -E $(command -v cargo) test -p nfkit --test lcore_ring -- --test-threads=1`.
- [ ] **Step 4: Build + clippy + regression** — `cargo build -p nfkit -p dpdk-sys 2>&1 | tail`; `cargo clippy -p nfkit 2>&1 | tail`; `cargo test -p nfkit --lib 2>&1 | tail`.
- [ ] **Step 5: Commit** — `feat(nfkit): LcoreRing — rte_ring MP/SC primitive for inter-lcore Mbuf handoff`. Co-Authored-By trailer.

---

## Task 5: Guest↔guest same-node local delivery (same-worker direct + cross-worker via LcoreRing)

**Goal:** Deliver `process_guest_tx` `Redirect(dest_tap_ifindex)` (the `Deliver::Local` arm — guest A → guest B on the same node) to the destination guest port, instead of dropping it. Same-worker → tx directly; cross-worker → hand off via the owning worker's `LcoreRing`.

**Files:**
- Modify: `flowplane-dpdk/src/serve.rs` (`run` — build per-worker rings + an ifindex→worker/ring routing table; `worker_loop` — deliver local + drain inbound ring).

- [ ] **Step 1: Build the routing table + per-worker rings in `run`** — after configuring guest ports, build: (a) a `Vec<LcoreRing>` (one MP/SC inbound ring per worker lcore, sized e.g. 1024); (b) a static `ifindex → owning_worker` map derived from the SAME round-robin partition as Task 3 (`host_ifindex → i % n_workers`). Wrap both in `Arc`s captured by the `for_each_worker` closure (rings shared for enqueue; a worker owns dequeue of `rings[q]`). Pass `worker_loop(q, n_workers, &shared, &port, &guest_ports, &rings, &route_table, &stop)`.
- [ ] **Step 2: Deliver local in `worker_loop`** — change the guest-block verdict routing for `Action::Redirect(ix)` where `ix != uplink_ifindex` (a guest-tap redirect):
  - Look up `ix` in the routing table → `owning_worker`.
  - If `owning_worker == q` (this worker owns the dest port): tx the mbuf DIRECTLY out that dest port's `TxQueue` (this worker holds all its owned ports' tx handles in `guest_qs`; find the entry with `host_ifindex == ix` and push to a per-dest local tx burst, flushed after the guest loop).
  - Else: `rings[owning_worker].enqueue(mbuf)` (ownership → ring; on `Err(mbuf)` full-ring, drop). Tag the enqueued mbuf's dest — since the ring is per-worker but a worker owns multiple ports, the consumer must know WHICH port to tx out of. Options: (a) one ring per GUEST PORT (keyed by ifindex) rather than per worker → the consumer maps ring→port directly (simpler; more rings but N is small); **prefer (a)** — build `rings: HashMap<u32 ifindex, LcoreRing>` (or `Vec` parallel to guest_ports), enqueue to `rings[ix]`, and each worker drains the rings of the ports IT owns. This removes the "which port" ambiguity.
  - If `ix` is unknown in the table (not a local guest port): drop (unknown dest).
- [ ] **Step 3: Drain inbound rings each iteration** — in `worker_loop`, after the guest rx block, for each guest port this worker owns, `rings[port.ifindex].dequeue_burst(&mut ring_burst)` and tx each dequeued mbuf out that port's `TxQueue`. These are already-processed frames (the source worker ran `process_guest_tx` and rewrote the inner Ethernet for the dest guest in the `Deliver::Local` arm) → tx as-is, no re-processing. Bound by tx capacity (`try`-style / drop on full). Poll rings EVERY iteration (even when this worker's guest rx is idle) so cross-worker delivery isn't starved.
- [ ] **Step 4: Same-worker fast path test seam** — add a pure-fn `fn owning_worker(ifindex, table) -> Option<u16>` and unit-test the routing decision in isolation (no EAL). The full cross-worker delivery is proven by an in-process EAL test IF tractable: two guest ports assigned to two different lcores (`-l 0-2`, n_workers=2), inject a guest-A→guest-B frame on A's port, assert it egresses B's port (via the ring). If a full two-port af_xdp e2e is too heavy, add a component test that drives `process_guest_tx` to the `Deliver::Local` arm (internal route, dest = another local guest) over one `ComposedMaps` and asserts `Redirect(dest_tap)` + the inner-Eth rewrite (dst=dest guest_mac), then exercises `LcoreRing` enqueue→dequeue delivery directly — proving the two halves compose. Note the full two-lcore af_xdp e2e as a follow-up if deferred.
- [ ] **Step 5: Build + verify** — `cargo build -p flowplane-dpdk -p nfkit 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `make sim`; the new sudo test(s); no regression on the handoff tests.
- [ ] **Step 6: Commit** — `feat(dpdk): guest↔guest same-node delivery (same-worker direct + cross-worker via LcoreRing)`. Co-Authored-By trailer.

---

## Task 6: Detach/reuse hardening — dead pool-slot detection + safe exclusion

**Goal:** A pod netns destroyed WITHOUT a preceding DetachInterface kills the guest-end and (veth pairs die together) the host-end `fpg{i}` — breaking that pool slot's ethdev. Detect such dead slots and EXCLUDE them from the free pool so attach never hands out a blackhole slot; log loudly. Full live recovery (recreate veth + DPDK hotplug rebind of the af_xdp ethdev) is documented as a further follow-up.

**Files:**
- Modify: `flowplane-dpdk/src/attach_state.rs` (`GuestPortSlot` add a `dead: bool` or reuse `bound` sentinel), `flowplane-dpdk/src/node.rs` (attach reservation + detach).

- [ ] **Step 1: Dead-slot detection helper** — add `flowplane_device::link_exists(ifname: &str) -> bool` (stat `/sys/class/net/<name>/ifindex`) — or reuse an existing `ifindex_of` and treat `Err` as gone. In `attach_interface`, when reserving a free slot, SKIP (and mark `dead`) any slot whose `host_ifname` no longer exists in the root netns (`!link_exists(&slot.host_ifname)`), continuing to the next free slot. Add a `dead: bool` field to `GuestPortSlot` (default false); a dead slot is neither reused nor counted as free. Log `warn!`/`eprintln!` naming the dead slot + the netns-destroyed-without-detach cause.
- [ ] **Step 2: Detach robustness** — in `detach_interface`, after the best-effort `unbind_preallocated_guest_end`, verify the pool host-end still exists (`link_exists`); if gone, mark the slot `dead` instead of free (so it isn't handed out). Keep the map/IPAM reclaim unconditional (already best-effort).
- [ ] **Step 3: Startup dead-slot log** — (optional, cheap) in `serve.rs::run`, after preallocation, this is moot (freshly created). No change needed; the detection is runtime.
- [ ] **Step 4: Document the limitation** — comment in `node.rs` + update `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` or the serve module doc: dead slots are detected + excluded (attach returns `resource_exhausted` when the free pool is drained by dead slots, rather than binding a blackhole); LIVE RECOVERY (recreate the veth + `rte_dev` hotplug detach/attach the af_xdp vdev + reconfigure the ethdev port) is a further follow-up (the static-pool model deliberately avoids runtime device churn; hotplug is the "real" fix).
- [ ] **Step 5: Test** — extend `flowplane-dpdk/tests/attach_veth.rs` (privileged): after a successful attach, `delete_link` the pool host veth out from under it (simulating the pod-netns-destroyed case), then attempt a second attach — assert it does NOT bind the dead slot (returns `resource_exhausted` when it's the only slot, or binds a DIFFERENT live slot when >1 seeded). Also assert `link_exists` returns false for the deleted slot. Add a `link_exists` unit test in flowplane-device (a real + a bogus name).
- [ ] **Step 6: Build + verify** — `cargo build -p flowplane-dpdk -p flowplane-device 2>&1 | tail`; clippy; `cargo test -p flowplane-dpdk --lib`; `cargo test -p flowplane-device`; `sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1`.
- [ ] **Step 7: Commit** — `feat(dpdk): detect + exclude dead guest pool slots (netns-destroyed-without-detach)`. Co-Authored-By trailer.

---

## Task 7: Final verification + backlog/memory update

- [ ] `make check` (0), `make sim`/`make test` green, `cargo build -p flowplane-dpdk -p nfkit -p flowplane-device` clean; all new + existing privileged tests pass under sudo (`multi_afxdp_port`, `guest_tx_datapath`, `guest_tx_nat_return_handoff`, `guest_tx_nat64_handoff`, `shared_ct_concurrent_writers`, `lcore_ring`, `attach_veth`).
- [ ] Update `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md`: #3 NAT64 now end-to-end reachable (egress wired); #1 cross-lcore demux now exercised on the live loop (multi-worker partitioning); note the remaining follow-ups (full-serve af_xdp e2e; native v6→v6 guest egress; DPDK-hotplug live dead-slot recovery).
- [ ] Commit; then finish the branch (superpowers:finishing-a-development-branch) per the usual pattern (merge to main + push).

## Notes / risks
- **rte_ring FFI + cross-lcore mbuf ownership (Task 4/5)** is the highest-risk new primitive: an mbuf must be owned by exactly one party at all times — `into_raw` on enqueue, `from_raw` on dequeue, and returned-on-full must not double-free or leak. Review this adversarially.
- **NAT64 egress (Task 1)** wires only v6→v4; native v6→v6 guest egress has no shared-core orchestrator yet (a separate follow-up).
- **Detach hardening (Task 6)** delivers detection + safe-exclusion only; live device recovery (DPDK hotplug) is explicitly deferred.
- **Do NOT run git-mutating subagents in parallel** (one worktree). One task at a time, sequential.
- Each task ends with a commit; the branch is finished (merge+push) after Task 7.
