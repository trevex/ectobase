# DPDK Guest-Egress Polish Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (fresh subagent per task + two-stage review). Steps use `- [ ]` checkboxes.

**Goal:** Consolidate the small remaining DPDK guest-egress follow-ups (no new hardware/VM, no new design): reject silently-broken non-host routes, close the startup-teardown-after-spawn leak, verify native v6→v6 guest↔guest already works, and de-stale the backlog.

**Architecture:** Three small, independent cleanups from `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` "Remaining follow-ups". No datapath redesign — validation, a startup-ordering fix, a verification test, and doc de-staling.

**Tech Stack:** Rust, `flowplane-dpdk` (writer/serve), nfkit EAL `--no-huge` component test.

**Anchors (verify against current code):**
- `flowplane-dpdk/src/writer.rs`: `route_upsert(vni, ipv4, prefix_len, val)` (line ~76) + `route6_upsert(vni, ipv6, prefix_len, val)` (~90) — both currently take `_prefix_len` and DROP it (`SharedConfigMaps` stores exact `/32`(v4)/`/128`(v6) host keys). Comment at writer.rs:72.
- `flowplane-dpdk/src/serve.rs`: `let addr = args.addr.parse().context("parse --addr")?;` at ~line 924 — AFTER `guard.disarm()` (~914) and the worker `.spawn(...)` (~880). The shutdown teardown block (delete pool devices via `backend.teardown`) runs after `workers.join()` near the end; a `?` between disarm and that block leaks the spawned workers + pool devices.
- `flowplane-core/src/datapath.rs`: `process_guest_tx_v6` `Deliver::Local` arm returns `Redirect(tap_ifindex)` (~line 360) after inner-Eth rewrite (dst=guest_mac, src=GW_MAC, ethertype stays IPv6). The worker's guest↔guest routing (`Redirect(ix) where ix != uplink_ifindex → rings[ifindex_to_index[ix]].enqueue`) is ETHERTYPE-AGNOSTIC — so v6-native same-node delivery should already work.
- Test templates: `nfkit/tests/guest_tx_v6_datapath.rs` (v6 datapath component), `nfkit/tests/guest_local_delivery.rs` (guest↔guest `Deliver::Local` + ring handoff), `flowplane-dpdk/src/writer.rs` `#[cfg(test)]` (writer unit tests, e.g. `route_upsert(7,[10,0,0,1],32,rv)`).
- Backlog: `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` — section #1 "Remaining: a GC/eviction sweep over shared_ct ... is not built yet" is STALE (G4 built it); the "Remaining follow-ups (after hardening + tap slice)" section lists native v6→v6 guest↔guest.

**Env note:** commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Sudo tests: chown `target/` back after. No merge/push per-task.

---

## Task 1: Reject non-host routes with a clear error (DPDK exact-match table)

**Goal:** The DPDK route table is exact-match (`/32` v4, `/128` v6); a non-host prefix (e.g. `/0`) is silently dropped to a host key that never matches → silent Pass. Fail loudly instead.

**Files:** `flowplane-dpdk/src/writer.rs`.

- [ ] **Step 1: Failing test** in writer.rs `#[cfg(test)]`: `route_upsert(7, [10,0,0,1], 24, rv)` returns `Err` (non-/32 rejected); `route_upsert(7, [10,0,0,1], 32, rv)` returns `Ok`; `route6_upsert(7, ip6, 64, rv)` → `Err`; `route6_upsert(7, ip6, 128, rv)` → `Ok`. Run `cargo test -p flowplane-dpdk --lib writer 2>&1 | tail` → FAIL.
- [ ] **Step 2: Implement** — in `route_upsert`, before inserting: `if prefix_len != 32 { anyhow::bail!("DPDK route table is exact-match (/32 host routes only); got /{prefix_len} for {}.{}.{}.{} — non-host prefixes (e.g. a /0 default route) are not supported (would silently never match). Use per-dest /32 routes or add LPM support.", ipv4[0],ipv4[1],ipv4[2],ipv4[3]); }`. Same for `route6_upsert` with `!= 128`. Rename `_prefix_len` → `prefix_len`. Update the writer.rs:72 comment: the prefix is now VALIDATED (must be host) rather than silently dropped. (route_remove/route6_remove may keep ignoring prefix_len — removal is by host key; note it.)
- [ ] **Step 3: Run — PASS.** `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo build -p flowplane-dpdk 2>&1 | tail`.
- [ ] **Step 4: Commit** — `feat(dpdk): reject non-host routes at the writer (exact-match table; no more silent /0 drop)`.

**Note:** scope to the DPDK writer only. Do NOT change the shared `flowplane-node` add_route or the eBPF writer (out of scope; the DPDK writer is where the exact-match constraint lives). If an existing test/caller passes a non-/32, update it to /32 (the serve_e2e harness already uses /32).

---

## Task 2: Close the startup-teardown-after-spawn leak + de-stale the backlog

**Goal:** `--addr` parse (and any fallible setup) must happen BEFORE the worker spawn, so no `?` returns between `guard.disarm()` and the shutdown-teardown block (which would leak the spawned workers + pool devices). Plus de-stale two backlog notes.

**Files:** `flowplane-dpdk/src/serve.rs`, `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md`.

- [ ] **Step 1: Move the `--addr` parse before the worker spawn.** In `serve.rs::run()`, move `let addr: std::net::SocketAddr = args.addr.parse().context("parse --addr")?;` to BEFORE the `std::thread::Builder...spawn(...)` (~line 880) — e.g. right after args validation / near the top of `run()`, so a bad `--addr` fails before any worker/pool device exists (the StartupGuard still covers prealloc→spawn; nothing fallible now runs between disarm and the shutdown block except the tonic serve, whose error goes through `serve_result.context(...)` AFTER the teardown block). Add a comment: `--addr` parsed up-front so a parse error can't leak spawned workers/pool devices. Confirm `addr` is still in scope at the `serve_with_shutdown(addr, ...)` site.
- [ ] **Step 2: Build + verify** — `cargo build -p flowplane-dpdk 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail` (ServeArgs tests still pass); `sudo -E $(command -v cargo) test -p flowplane-dpdk --test serve_e2e -- --test-threads=1 2>&1 | tail -6` (serve still starts + forwards — no regression from the reordering). Chown target/ back.
- [ ] **Step 3: De-stale the backlog** in `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md`: (a) section #1 "**Remaining (follow-ups):** a GC/eviction sweep over `shared_ct` ... is not built yet" → update to note the GC sweep IS built (G4, `shared_ct_sweep_expired`, worker-0 ~1Hz); (b) in the "Remaining follow-ups (after hardening + tap slice)" list, the "startup-teardown-after-worker-spawn" item → mark FIXED (—addr parsed up-front).
- [ ] **Step 4: Commit** — `fix(dpdk): parse --addr before worker spawn (no leaked workers/pool devices on a bad addr) + de-stale backlog`.

---

## Task 3: Verify native v6→v6 guest↔guest local delivery already works

**Goal:** Confirm (with a test) that a native v6 same-node guest→guest frame is delivered — `process_guest_tx_v6`'s `Deliver::Local` returns `Redirect(dest_tap)` and the worker's ethertype-agnostic ring routing delivers it — then de-stale the backlog note.

**Files:** Create `nfkit/tests/guest_local_delivery_v6.rs` (mirror `guest_local_delivery.rs` but v6). Modify the backlog note.

- [ ] **Step 1: Write the test** (sudo, `--no-huge`, unique `--file-prefix`): over one `ComposedMaps`, program an INTERNAL same-node v6 route (`route6`, is_external=0, nexthop = this node so `deliver` → `Deliver::Local`) for a dest that is another LOCAL guest (program its `PortMeta` + v6 dest ifindex), egress+ingress v6 firewall allow. Build a native v6 guest-A→guest-B frame `[Eth 0x86DD][IPv6 srcA→dstB][TCP]`, run the REAL `process_guest_tx_v6(&mut pkt, &mut composed, &GuestTxIn{meta:&pmA, src_ifindex, now})`; assert `action == Redirect(DEST_TAP)` AND the inner Ethernet was rewritten (inner eth dst == dest guest_mac, src == GW_MAC, ethertype still 0x86DD, IPv6 payload untouched, length unchanged — no encap). THEN exercise `LcoreRing` enqueue→dequeue on that mbuf (as `guest_local_delivery.rs` does) → byte-identical, proving the v6 `Deliver::Local` output composes with the ring handoff. Model on `nfkit/tests/guest_local_delivery.rs` + `guest_tx_v6_datapath.rs` (the v6 fixture: route6, conntrack6, v6 firewall). If this test reveals a REAL gap (v6 Local not produced / not delivered), STOP and report — that turns this from a verification into a fix (escalate before changing the datapath).
- [ ] **Step 2: Run — PASS.** `sudo -E $(command -v cargo) test -p nfkit --test guest_local_delivery_v6 -- --test-threads=1 2>&1 | tail -12`. Chown target/ back. `cargo clippy -p nfkit --tests 2>&1 | tail`.
- [ ] **Step 3: De-stale the backlog** — the "Native v6→v6 guest↔guest local delivery" follow-up → mark VERIFIED WORKING (process_guest_tx_v6 Local + ethertype-agnostic worker ring routing; proven by `guest_local_delivery_v6.rs`).
- [ ] **Step 4: Commit** — `test(dpdk): verify native v6 guest↔guest local delivery (Deliver::Local + ring handoff)`.

---

## Task 4: Final verification + finish

- [ ] `make check` (0), `make sim`/`make test` green, `cargo build -p flowplane-dpdk -p nfkit` clean; the sudo suite (serve_e2e, guest_local_delivery_v6, + no regression on attach_veth/the existing tests) passes. Chown target/ back.
- [ ] Finish the branch (superpowers:finishing-a-development-branch) — merge to main + push per the usual pattern.

## Notes / risks
- Task 1 is DPDK-writer-scoped — do NOT touch shared flowplane-node/eBPF route handling.
- Task 3 is a VERIFICATION (expected: already works). If it fails, escalate (it becomes a real datapath fix, out of polish scope).
- All items are small + independent; sequence 1→2→3→4.
