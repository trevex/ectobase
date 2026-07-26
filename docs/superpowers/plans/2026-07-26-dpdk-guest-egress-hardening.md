# DPDK Guest Egress — Hardening & Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (fresh subagent per task + two-stage spec/quality review). Steps use `- [ ]` checkboxes.

**Goal:** Close the five open DPDK guest-egress gaps (startup-rollback, shared_ct GC, full-serve af_xdp e2e, native v6→v6 egress, dead-slot live recovery), unified behind a backend-agnostic `GuestPortBackend` lifecycle seam (veth implemented; tap/VF as documented seams).

**Architecture:** The DPDK `flowplane-dpdk serve` loop runs a VF-style preallocated per-guest af_xdp port pool. A new `GuestPortBackend` trait abstracts the pool-port lifecycle (preallocate/assign/release/is_alive/recover/teardown) so software (veth), VM (tap), and real-NIC (VF) modes share one control path; only `VethBackend` is built now. On top of the seam we land: an RAII startup-rollback guard (G5), a shared_ct idle-timeout sweep (G4), a full-serve e2e harness (G1), a shared-core v6 egress orchestrator + eBPF re-point (G2), and true rte-hotplug dead-slot recovery via an atomic generation handshake (G3).

**Tech Stack:** Rust, DPDK (nfkit `Port`/af_xdp/`MbufPkt`/`LcoreRing`/`rte_eal_hotplug_*`), `flowplane-core::datapath`, `flowplane-device` veth, `flowplane-ebpf` (verifier-sensitive), in-process EAL `--no-huge` tests + a privileged full-serve harness (sudo).

**Spec:** `docs/superpowers/specs/2026-07-26-dpdk-guest-egress-hardening-design.md`.

**Source-of-truth anchors (verify against current code; cite drift):**
- `flowplane-dpdk/src/serve.rs`: `run()` — prealloc §2a (`create_preallocated_veth` loop building `Vec<GuestPortSlot>`), guest-`Port::configure` loop building `Vec<GuestPort>`, rings/`ifindex_to_index` build (§3b), `for_each_worker` closure (worker owns `owns(i,q,n_workers)` subset), the datapath-thread spawn. `worker_loop(q, n_workers, shared, port, guest_ports, rings, ifindex_to_index, stop)` — uplink block, guest block (ethertype branch: `0x86DD`→`process_guest_tx_nat64`, else `process_guest_tx`; `Redirect(uplink)`→`tx_burst.try_push`; `Redirect(other)`→`rings[pi].enqueue`; else drop), ring-drain block, `owns()` helper + unit test.
- `flowplane-dpdk/src/node.rs`: `attach_interface` (reserve free non-dead slot under `guest_pool` lock; `bind_preallocated_guest_end`; `program_interface(tap=slot.host_ifindex)`; register; rollback), `detach_interface` (`ports_remove(tap)`, `unbind_preallocated_guest_end`, `link_exists`→ free-or-mark-dead slot).
- `flowplane-dpdk/src/attach_state.rs`: `GuestPortSlot { host_ifname:String, host_ifindex:u32, port_id:u16, bound:Option<String>, dead:bool }`, `DpdkAttachState { ipam, registry, guest_mtu, gateway_ipv4/6, guest_pool: Mutex<Vec<GuestPortSlot>> }`, `mac_for`, `host_veth_name`.
- `flowplane-device/src/veth.rs`: `create_preallocated_veth(host,mac,mtu)->DeviceInfo`, `bind_preallocated_guest_end(peer,netns,guest,mac,mtu,csum)`, `unbind_preallocated_guest_end(netns,guest,peer)`, `link_exists(name)->bool`, `delete_link(name)`, `DeviceInfo{host_ifindex,host_name,mac}`, private `ifindex_of`. Exported from `flowplane-device/src/lib.rs`.
- `flowplane-core`: `datapath::process_guest_tx` (v4, returns `GuestTxOut{action,edt_tstamp}`), `datapath::process_guest_tx_nat64` (v6→v4, returns `Action`), `egress::{route4,route6,deliver,Deliver{Local{tap_ifindex,guest_mac},Encap(EncapParams-ish e),Pass}}`, `conntrack::{ct_key6, ct_refresh}` + `Maps::{conntrack6_get,conntrack6_insert,route6_get}`, `firewall::{fw_eval_dir, fw_eval_dir6}`, `encap::{write_outer_v6, ETH_LEN, IPV6_LEN}`, `nat::snat_egress`.
- `flowplane-ebpf/src/egress.rs`: `forward_decision_v6` (composes `egress_fw_ct_v6` + `route_decision_v6`, staged `#[inline(never)]`, uses the shared-core primitives above). `tc.rs`: `tc_guest_egress_v6` tail-call target calls `crate::egress::forward_decision_v6`.
- `nfkit`: `LcoreRing`, `Port::configure(id,nq,pool)`/`queue(q)`, `shared_config.rs::{shared_ct_get,shared_ct_insert,shared_ct_remove,shared_ct_for_each}`, `dpdk-sys/{wrapper.h,shim.h,shim.c}` shim pattern (see `nfkit_ring_*`).
- Test templates: `nfkit/tests/{guest_tx_nat_return_handoff,guest_tx_nat64_handoff,guest_local_delivery,lcore_ring,shared_ct_concurrent_writers,multilcore_datapath}.rs`; `flowplane-dpdk/tests/attach_veth.rs`; `hack/dpdk/afxdp-uplink.sh`; `flowplane-sim/src/{nat64_test,ct_refresh_test}.rs`.

**Environment note (ALL tasks):** prior sudo test runs may leave `target/` root-owned. If a plain `cargo build` hits permission errors: `sudo chown -R "$(id -un):$(id -gn)" /home/nik/Development/ironcore-net-xdp/target`; chown back after any `sudo cargo` run. Commit trailer for every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Do NOT run git-mutating subagents in parallel. Do NOT merge/push per-task; finish the branch at the end.

---

## Task 1: `GuestPortBackend` seam — trait + `VethBackend` (behavior-preserving refactor)

**Goal:** Introduce the lifecycle trait and route the existing veth pool mechanics through it, with ZERO behavior change (pure refactor). Foundational for G5/G3.

**Files:**
- Create: `flowplane-dpdk/src/port_backend.rs`; export from `flowplane-dpdk/src/lib.rs`.
- Modify: `flowplane-dpdk/src/serve.rs` (prealloc via backend), `flowplane-dpdk/src/node.rs` (attach `assign`/detach `release`/`is_alive`), `flowplane-dpdk/src/attach_state.rs` (hold the backend).

- [ ] **Step 1: Define the trait + types** in `port_backend.rs`:
```rust
//! Backend-agnostic guest-port pool lifecycle. One impl per device kind — VethBackend (containers,
//! implemented), TapBackend (VMs) + VfBackend (SR-IOV real NIC) are documented SEAMS (see the spec).
//! The lifecycle (preallocate/assign/release/is_alive/recover/teardown) is IDENTICAL across kinds;
//! only the device mechanics differ. This keeps software mode and real-NIC VFs structurally the same.
use anyhow::Result;
use crate::attach_state::GuestPortSlot;

/// Where a slot's guest-facing device is assigned. Container/VF: a pod netns + the in-netns ifname.
/// (A future tap variant carries the VM/tap handle instead.)
pub struct AssignTarget { pub netns_path: String, pub guest_ifname: String }

/// Resolved facts of a preallocated pool HOST device (backs one af_xdp ethdev port).
pub struct HostDevice { pub host_ifname: String, pub host_ifindex: u32 }

pub trait GuestPortBackend: Send + Sync {
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice>;
    fn assign(&self, slot: &GuestPortSlot, target: &AssignTarget, mac: [u8; 6], mtu: u32) -> Result<()>;
    fn release(&self, slot: &GuestPortSlot, target: &AssignTarget);
    fn is_alive(&self, slot: &GuestPortSlot) -> bool;
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32>; // Task 6 fills this in
    fn teardown(&self, slot: &GuestPortSlot);
}
```
- [ ] **Step 2: Implement `VethBackend`** in `port_backend.rs`, delegating to the existing `flowplane_device` fns (behavior-identical to today):
```rust
pub struct VethBackend;
impl GuestPortBackend for VethBackend {
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice> {
        let host = format!("fpg{index}");
        // placeholder MAC exactly as serve.rs prealloc does today: 02:00:00:00:0e:<index as u8>
        let mac = [0x02, 0x00, 0x00, 0x00, 0x0e, index as u8];
        let d = flowplane_device::create_preallocated_veth(&host, mac, mtu)?;
        Ok(HostDevice { host_ifname: d.host_name, host_ifindex: d.host_ifindex })
    }
    fn assign(&self, slot: &GuestPortSlot, t: &AssignTarget, mac: [u8;6], mtu: u32) -> Result<()> {
        let peer = format!("{}p", slot.host_ifname);
        flowplane_device::bind_preallocated_guest_end(&peer, &t.netns_path, &t.guest_ifname, mac, mtu, false)
    }
    fn release(&self, slot: &GuestPortSlot, t: &AssignTarget) {
        let peer = format!("{}p", slot.host_ifname);
        let _ = flowplane_device::unbind_preallocated_guest_end(&t.netns_path, &t.guest_ifname, &peer);
    }
    fn is_alive(&self, slot: &GuestPortSlot) -> bool { flowplane_device::link_exists(&slot.host_ifname) }
    fn recover(&self, _slot: &mut GuestPortSlot, _pool_port_id: u16) -> Result<u32> {
        anyhow::bail!("VethBackend::recover not implemented until Task 6") // filled in by G3
    }
    fn teardown(&self, slot: &GuestPortSlot) { flowplane_device::delete_link(&slot.host_ifname); }
}
```
Add a `TapBackend`/`VfBackend` doc-comment stub in the module header noting they are follow-ups (do NOT create structs for them).
- [ ] **Step 3: Route serve prealloc + attach/detach through the backend.** In `serve.rs` prealloc §2a, replace the direct `create_preallocated_veth("fpg{i}",...)` with `backend.preallocate(i, guest_mtu)`. Hold the backend as `Arc<dyn GuestPortBackend>` (shared between serve startup, `DpdkAttachState` for node.rs, and — Task 6 — the recovery path): construct `let backend: Arc<dyn GuestPortBackend> = Arc::new(VethBackend);` once in `run()` and store a clone in `DpdkAttachState` as `pub backend: Arc<dyn GuestPortBackend>`. In `node.rs` attach, replace the `bind_preallocated_guest_end(...)` call with `attach.backend.assign(&slot, &AssignTarget{netns_path, guest_ifname}, mac, guest_mtu)`; the `link_exists` dead-slot checks with `attach.backend.is_alive(&slot)`; detach `unbind_preallocated_guest_end(...)` with `attach.backend.release(&slot, &target)`. Keep the placeholder-peer / slot-ifindex semantics IDENTICAL. Update `DpdkAttachState` construction (+ every test constructor) to include `backend: Arc::new(VethBackend)`.
- [ ] **Step 4: Build + verify NO behavior change** — `cargo build -p flowplane-dpdk 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `make -C /home/nik/Development/ironcore-net-xdp sim 2>&1 | grep "test result"`; `sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1 2>&1 | tail -10` (all 5 still PASS — proves the refactor preserved behavior). Chown target/ back.
- [ ] **Step 5: Commit** — `refactor(dpdk): GuestPortBackend seam + VethBackend (veth/tap/vf lifecycle, behavior-unchanged)`.

---

## Task 2: G5 — Startup-rollback consistency (RAII teardown guard)

**Goal:** No leaked pool host devices if `serve` startup fails after preallocation.

**Files:** Modify `flowplane-dpdk/src/serve.rs`.

- [ ] **Step 1: Add an armed cleanup guard.** After building the backend, before the prealloc loop, create `let mut created: Vec<GuestPortSlot> = Vec::new();`. Wrap the whole startup-from-prealloc-to-worker-spawn so that on any early `Err`, each `created` slot is `backend.teardown(&slot)`-ed. Cleanest: a small local RAII type:
```rust
struct StartupGuard<'a> { backend: &'a dyn GuestPortBackend, slots: Vec<GuestPortSlot>, armed: bool }
impl<'a> StartupGuard<'a> {
    fn disarm(&mut self) { self.armed = false; }
}
impl Drop for StartupGuard<'_> {
    fn drop(&mut self) {
        if self.armed { for s in &self.slots { self.backend.teardown(s); } }
    }
}
```
Populate `guard.slots` as each slot is preallocated. Keep the existing per-prealloc-failure rollback OR replace it with the guard (the guard subsumes it). After the datapath worker thread is successfully spawned (it now owns the ports/rings), call `guard.disarm()` (the workers own teardown-on-shutdown from here). Ensure `guard` is in scope across every `?` between prealloc and the spawn (mempool, `Port::configure`, `LcoreRing::new`, `SharedConfigMaps::new`, `ControlCore`, `attach_state`, the `spawn`).
- [ ] **Step 2: Move `guard.slots` into the pool after disarm.** The slots must still populate `attach_state.guest_pool` (as today). Order: build slots into `guard.slots`; on success, `let slots = std::mem::take(&mut guard.slots); guard.disarm();` then move `slots` into `guest_pool` as today. Confirm the guest `Port`s + rings + `ifindex_to_index` are still built from the same slot order.
- [ ] **Step 3: Unit-test the guard** (no EAL): a fake `GuestPortBackend` recording `teardown` calls; build a `StartupGuard` with 3 slots, drop it armed → asserts 3 teardowns; build another, `disarm()`, drop → asserts 0 teardowns.
- [ ] **Step 4: Build + verify** — `cargo build/clippy -p flowplane-dpdk`; `cargo test -p flowplane-dpdk --lib` (incl. the guard test); `make sim`. (No sudo needed — the guard is unit-tested; the happy-path startup is covered by attach_veth/e2e.)
- [ ] **Step 5: Commit** — `feat(dpdk): RAII startup-rollback guard — no leaked pool devices on serve startup failure`.

---

## Task 3: G4 — `shared_ct` idle-timeout GC sweep

**Goal:** Reclaim stale reverse-conntrack entries from `shared_ct` on an idle timeout, mirroring the eBPF CT-timeout model.

**Files:** Modify `nfkit/src/shared_config.rs` (sweep helper), `flowplane-dpdk/src/serve.rs` (throttled worker-0 call). Test: `nfkit/tests/shared_ct_gc.rs`.

- [ ] **Step 1: Find the CT timeout constants** the eBPF/core use (grep `flowplane-core`/`flowplane-common` for `CT_TIMEOUT`, `ESTABLISHED`, `30`, `86400`, `tcp_state`). Reuse them (do NOT invent new numbers). The entry carries `last_seen` + `tcp_state` (maintained by `ct_refresh`); the timeout is state-dependent (short for NEW/SYN, long for ESTABLISHED).
- [ ] **Step 2: Write the failing test** `nfkit/tests/shared_ct_gc.rs` (EAL `--no-huge`, unique `--file-prefix nfkit_ctgc`): insert into `shared_ct` (a) an ESTABLISHED entry with `last_seen = now - 60s` (should SURVIVE, < 24h), (b) a NEW/SYN entry with `last_seen = now - 60s` (should be EVICTED, > 30s), (c) a fresh entry `last_seen = now` (SURVIVES). Call the new `shared.shared_ct_sweep_expired(now)`; assert (a),(c) present via `shared_ct_get`, (b) gone, and the returned evicted-count == 1.
- [ ] **Step 3: Implement `shared_ct_sweep_expired`** in `shared_config.rs`:
```rust
/// Evict shared_ct reverse entries idle past their state-dependent timeout (eBPF CT model:
/// short for NEW/SYN, long for ESTABLISHED — reuses the core CT_TIMEOUT consts). Returns the
/// count evicted. Runs off the per-packet path; writes go through the single-writer Mutex.
pub fn shared_ct_sweep_expired(&self, now: u64) -> usize {
    let mut expired: Vec<CtKey> = Vec::new();
    self.shared_ct_for_each(|k, e| {
        let timeout = /* established_timeout if e.tcp_state == ESTABLISHED else new_timeout */;
        if now.saturating_sub(e.last_seen) > timeout { expired.push(*k); }
    });
    let mut n = 0;
    for k in &expired { if self.shared_ct_remove(k) { n += 1; } }
    n
}
```
(Collect-then-remove: do not remove inside `for_each` — the RCU iterator must not be mutated mid-walk.)
- [ ] **Step 4: Wire a throttled call in `worker_loop`** (worker 0 only): keep a `last_gc_ns` local; each iteration, if `now - last_gc_ns > 1_000_000_000` (1s) and `q == 0`, call `shared.shared_ct_sweep_expired(now)` and update `last_gc_ns`. Comment: only worker 0 sweeps (single sweeper avoids redundant work; writes are Mutex-serialized anyway). No new timer — reuses the per-burst `now`.
- [ ] **Step 5: Run + build** — `sudo -E $(command -v cargo) test -p nfkit --test shared_ct_gc -- --test-threads=1 2>&1 | tail` (PASS); `cargo build -p nfkit -p flowplane-dpdk`; `cargo clippy`; `cargo test -p flowplane-dpdk --lib`; `make sim`. Chown target/ back.
- [ ] **Step 6: Commit** — `feat(dpdk): shared_ct idle-timeout GC sweep (eBPF CT-timeout model, worker-0 throttled)`.

---

## Task 4: G1 — Full-serve af_xdp e2e harness

**Goal:** Prove the whole `serve` process over real af_xdp: guest→fabric, NAT-return, cross-lcore guest↔guest.

**Files:** Create `hack/dpdk/serve-e2e.sh`, `flowplane-dpdk/tests/serve_e2e.rs`, and (if needed) a gRPC-client example `flowplane-dpdk/examples/attach_client.rs`.

- [ ] **Step 1: Harness script** `hack/dpdk/serve-e2e.sh` modeled on `hack/dpdk/afxdp-uplink.sh` (read it): reserve+restore hugepages; skip (exit 77) if unprivileged; create the uplink veth pair + one netns per guest + the guest veths are the pool's `fpg{i}` (the serve process preallocates them — so the script creates only the UPLINK veth + the guest NETNS, and lets serve create `fpg0..`). Launch `flowplane-dpdk serve --backend af-xdp --uplink <vv0> --guest-ports 2 --lcores 3 --queues 2 --no-huge --gateway ... --gateway-mac ... --local-underlay ...` in the background (log to a file, not the pipe — see afxdp-uplink.sh's orphan-pipe fix). `sleep` for EAL + af_xdp load.
- [ ] **Step 2: Drive attach + traffic** via a Python block (scapy, like afxdp-uplink.sh) + a gRPC client. For the gRPC calls (AddRoute/AddNatSource/AddFwRule/AttachInterface) either write a tiny `attach_client.rs` example (uses `flowplane_node::pb` + tonic) the script invokes, or use `grpcurl` if available. Attach guest A (netns nsA, requested IP), program an external default route + NAT source + egress/ingress firewall allow. Then: (a) inject a guest IPv4 TCP frame on nsA's guest veth peer, sniff the uplink veth peer for the encapped IPv6 frame → assert present (guest→fabric); (b) inject the matching encapped NAT-return on the uplink, sniff nsA's guest veth for the reverse-DNAT delivery → assert; (c) attach guest B (nsB) on the second pool port, program an internal route A→B, inject a guest-A→guest-B frame on nsA, sniff nsB's guest veth → assert delivery (cross-lcore guest↔guest via LcoreRing). Use generous sniff windows + multiple injections (af_xdp copy-mode warmup drops), as afxdp-uplink.sh does.
- [ ] **Step 3: Rust test** `flowplane-dpdk/tests/serve_e2e.rs` that builds the serve binary + attach_client, runs `serve-e2e.sh`, maps exit 0→pass / 77→skip / else→panic (mirror `nfkit/tests/afxdp_datapath.rs`).
- [ ] **Step 4: Run** — `sudo -E $(command -v cargo) test -p flowplane-dpdk --test serve_e2e -- --test-threads=1 2>&1 | tail -30`. Iterate on timing/warmup until the three assertions pass reliably. If cross-lcore guest↔guest (c) proves too flaky in one run, split it into its own assertion with retries and note it; (a)+(b) are the primary bar. Chown target/ back.
- [ ] **Step 5: Commit** — `test(dpdk): full-serve af_xdp e2e — guest→fabric, NAT-return, cross-lcore guest↔guest`.

---

## Task 5: G2 — Native v6→v6 guest egress (shared-core extraction + eBPF re-point + worker wire)

**Goal:** Extract the v6 egress composition into shared core (seam-not-duplicate), wire it into the DPDK worker for native v6 frames, and prove the eBPF verifier still passes.

**Files:** `flowplane-core/src/{datapath.rs,egress.rs}` (stages + `process_guest_tx_v6`), `flowplane-ebpf/src/egress.rs` (delegate), `flowplane-dpdk/src/serve.rs` (worker branch), `flowplane-sim/src/sim.rs` (`guest_tx_v6`), tests + a verifier anchor.

- [ ] **Step 1: Study the eBPF v6 composition.** Read `flowplane-ebpf/src/egress.rs` `forward_decision_v6`, `egress_fw_ct_v6` (fw_eval_dir6 + ct_key6/conntrack6 firewall-track), `route_decision_v6` (route6 + deliver → Local/Encap/Pass + write_outer_v6), and how `tc.rs::tc_guest_egress_v6` calls it. Identify which parts are already shared-core primitives vs eBPF-local composition.
- [ ] **Step 2: Extract stage fns into `flowplane-core`.** Add to `flowplane-core/src/egress.rs` (or a new `egress_v6.rs`) generic `Pkt`/`Maps` stage fns mirroring the eBPF ones EXACTLY (byte-relevant order/gates): `egress_fw_ct_v6<P,M>(pkt, ip6_off, ifindex, vni, maps) -> EgressFwCtV6` and `route_decision_v6<P,M>(pkt, ip6_off, meta, maps) -> Deliver`. Keep them as SEPARATE fns (so the eBPF can keep each in its own `#[inline(never)]`/tail-called frame for the 512B budget). Reuse `fw_eval_dir6`, `ct_key6`, `conntrack6_get/insert`, `route6`, `deliver`.
- [ ] **Step 3: Add `datapath::process_guest_tx_v6`** in `flowplane-core/src/datapath.rs` composing the stages (single fn, off-eBPF), returning `GuestTxOut` (mirror `process_guest_tx`): fw/ct-v6 (deny-by-default drop on fresh) → route_decision_v6 → on `Deliver::Encap(e)` do `grow_head(IPV6_LEN)` + `write_outer_v6` (+ EDT stamp like the v4 path) → `Redirect(e.uplink_ifindex)`; `Deliver::Local` → inner-Eth rewrite → `Redirect(tap)`; `Deliver::Pass` → `Pass`. NO NAT64 here (native v6 encap only). Document scope.
- [ ] **Step 4: Sim byte-parity test.** Add `SimNode::guest_tx_v6` (sim.rs) calling `process_guest_tx_v6`, and a `flowplane-sim/src/` test: a native v6 guest frame with an external v6 route → encap (outer IPv6, inner-proto 41/IPPROTO_IPV6) → assert the encapped bytes + that `conntrack6` firewall-track landed. Model on `nat64_test.rs`/`flow_label_test.rs`.
- [ ] **Step 5: Re-point the eBPF** `forward_decision_v6` (and its `egress_fw_ct_v6`/`route_decision_v6` wrappers) to CALL the extracted core stage fns — the eBPF wrappers stay (tail-called / `#[inline(never)]`, preserving per-frame budget) but their BODIES become thin delegations to the core stages. This is the seam-not-duplicate requirement (the eBPF must run the SAME code the tests run).
- [ ] **Step 6: BPF verifier anchor.** Run `make -C /home/nik/Development/ironcore-net-xdp sim-anchor` (and/or the verifier target — grep the Makefile for `anchor`/`verifier`) to confirm `tc_guest_egress_v6` still loads (512B combined stack). If it FAILS (stack overflow from the delegation), keep each eBPF stage body calling the core stage with identical locals / mark `#[inline(never)]`, or (last resort per the seam rule) move the divergent assertion to goscapy — NEVER keep a parallel eBPF-only core. This is the HIGH-RISK gate; iterate here.
- [ ] **Step 7: Wire the DPDK worker.** In `serve.rs` guest block, change the `0x86DD` arm: try NAT64 first (`nat64_egress_parse` matches / dst in NAT64 prefix) → `process_guest_tx_nat64`; else → `process_guest_tx_v6`. Simplest without duplicating the prefix check: call `process_guest_tx_nat64`; if it returns `Action::Pass` (not NAT64-bound), fall through to `process_guest_tx_v6` on the SAME (unmodified) frame — BUT verify `process_guest_tx_nat64` does not mutate the frame before returning Pass (read it: it Passes at `nat64_egress_parse`→None BEFORE `shrink_head`, so the frame is untouched → safe to fall through). If it DID mutate before Pass, instead branch on an explicit prefix check. Route the verdicts as today (Redirect uplink → tx; Redirect tap → ring; Pass/Drop → drop).
- [ ] **Step 8: DPDK component test** `nfkit/tests/guest_tx_v6_datapath.rs`: over one `ComposedMaps`, native v6 guest frame + external v6 route → `process_guest_tx_v6` → assert encap + `conntrack6` landed; byte-parity vs the sim. (Mirror `guest_tx_datapath.rs`.)
- [ ] **Step 9: Build + full verify** — `cargo build -p flowplane-core -p flowplane-dpdk -p nfkit`; `cargo clippy`; `make sim` (v6 sim test green); `sudo -E ... test -p nfkit --test guest_tx_v6_datapath`; the verifier anchor (Step 6); re-run existing handoff tests (no regression). Chown target/ back.
- [ ] **Step 10: Commit** — `feat(v6): shared-core process_guest_tx_v6 + eBPF re-point + DPDK worker native-v6 egress`.

---

## Task 6: G3 — Dead-slot live recovery (rte hotplug rebind + generation handshake)

**Goal:** Recover a pool slot whose veth pair died (ungraceful teardown): recreate the device, hotplug-rebind the af_xdp ethdev, and have the owning worker rebuild its queue handles — the veth backend's `recover()`.

**Files:** `dpdk-sys/{wrapper.h,shim.h,shim.c}` (hotplug FFI), `nfkit/src/port.rs` (rebuild path) + maybe `nfkit/src/lib.rs`, `flowplane-dpdk/src/port_backend.rs` (`VethBackend::recover`), `flowplane-dpdk/src/attach_state.rs` (`generation`), `flowplane-dpdk/src/serve.rs` (worker generation check + queue rebuild), `flowplane-dpdk/src/node.rs` (recovery trigger). Tests: `flowplane-dpdk/tests/attach_veth.rs` (recover case) + an nfkit hotplug test.

- [ ] **Step 1: dpdk-sys hotplug FFI.** `rte_eal_hotplug_add(busname, devname, devargs)` and `rte_eal_hotplug_remove(busname, devname)` are real (non-inline) symbols — add `#include <rte_dev.h>` (or `<rte_bus.h>`/`<rte_eal.h>` — grep DPDK headers for the decls) to `dpdk-sys/wrapper.h` so bindgen emits them. If they turn out to be macros/inlines, add `nfkit_hotplug_add/remove` shims (mirror the `nfkit_ring_*` shim pattern in `shim.h`/`shim.c`). Build `cargo build -p dpdk-sys` and confirm the symbols land in `bindings.rs`.
- [ ] **Step 2: nfkit hotplug test** `nfkit/tests/hotplug.rs` (EAL `--no-huge`, sudo, unique `--file-prefix`): create a veth `fphp0`; `Eal::init`; `rte_eal_hotplug_add("vdev","net_af_xdp9","iface=fphp0,start_queue=0,queue_count=1")`; `Port::configure(<probed id>,1,&pool)` → up; `rte_eal_hotplug_remove("vdev","net_af_xdp9")`; assert add→configure→remove round-trips without error. This de-risks runtime af_xdp hotplug on this host BEFORE wiring recover(). If hotplug of an af_xdp vdev fails here, STOP and report — fall back to the soft-recovery (new-port-id) contingency from the spec.
- [ ] **Step 3: `GuestPortSlot.generation`.** Add `pub generation: u32` to `GuestPortSlot` (plain field; the cross-thread signal is a separate `Arc<[AtomicU32]>` — see Step 5). Default 0. Update all constructors.
- [ ] **Step 4: `VethBackend::recover`.** Implement (replacing the Task-1 `bail!`):
```rust
fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32> {
    flowplane_device::delete_link(&slot.host_ifname); // remove any stale remnant
    let d = flowplane_device::create_preallocated_veth(&slot.host_ifname,
        [0x02,0,0,0,0x0e, /* index from port_id */ (pool_port_id - 1) as u8], /*mtu*/ slot_mtu)?;
    let vdev = format!("net_af_xdp{pool_port_id}");
    nfkit::hotplug_remove("vdev", &vdev)?;                       // drop the dead vdev
    nfkit::hotplug_add("vdev", &vdev, &format!("iface={},start_queue=0,queue_count=1", slot.host_ifname))?;
    // NOTE: Port::configure is done by the CALLER on the pool (needs &Mempool); recover returns the
    // new ifindex + leaves the ethdev re-added. OR pass the pool in. Decide + document.
    slot.host_ifindex = d.host_ifindex;
    slot.dead = false;
    Ok(d.host_ifindex)
}
```
(Resolve the `&Mempool`/`Port::configure` ownership: either `recover` takes the pool + does `Port::configure` and returns the new `Port` to swap into the worker-thread-held `Vec`, or the serve control path does the `Port::configure` after `recover` re-adds the vdev. Pick the cleaner split; the worker must end up with a rebuilt `Port`+queues for `pool_port_id`. Keep all `Send` control-plane work OFF the worker lcore.)
- [ ] **Step 5: Generation handshake.** Add `Arc<Vec<AtomicU32>>` (one per pool port, index = port_index) shared between the control side and the workers (captured in the `for_each_worker` closure like `rings`). Recovery (control thread) does the veth+hotplug+Port::configure, swaps the new `Port` into a shared slot the worker reads, then `generation[pi].fetch_add(1, Release)`. The worker, at the top of each poll iteration, for each owned port compares `generation[pi].load(Acquire)` to its cached copy; on a bump it rebuilds that port's `(RxQueue,TxQueue)` (via `port.queue(0)` on the possibly-new Port) + re-derives its ring drain handle, and updates its cache. The control thread NEVER touches the worker's `!Send` queue handles — it only recreates the ethdev + bumps the generation; the worker does the rebuild on its own lcore. Document this as the ONE sanctioned mutation to the static poll set.
- [ ] **Step 6: Recovery trigger.** In `node.rs`, when attach would otherwise `resource_exhausted` because the only free slots are `dead`, attempt `attach.backend.recover(&mut slot, slot.port_id)` for one dead slot (off the tokio worker via `spawn_blocking`; then the serve-side `Port::configure` + generation bump), and if it succeeds bind it. (Or: a periodic reconciler — but on-demand-at-attach is simplest + sufficient.) Keep the pool lock discipline (no lock across await).
- [ ] **Step 7: Test the recover path** in `attach_veth.rs` (privileged): NOTE this test does NOT run the serve worker loop, so it can validate `VethBackend::recover` + the hotplug round-trip + slot fields (new ifindex, `dead` cleared, generation bumped) directly, and that a subsequent attach binds the recovered slot. The full worker-rebuild-on-generation-bump is covered by extending the G1 serve e2e (Task 4): kill a bound guest's pool veth, trigger recovery, assert egress resumes — add this as a follow-on assertion or a note if too heavy for one run.
- [ ] **Step 8: Build + verify** — `cargo build -p dpdk-sys -p nfkit -p flowplane-dpdk`; `cargo clippy`; `cargo test -p flowplane-dpdk --lib`; `make sim`; `sudo -E ... test -p nfkit --test hotplug`; `sudo -E ... test -p flowplane-dpdk --test attach_veth -- --ignored` (incl. recover case). Chown target/ back.
- [ ] **Step 9: Commit** — `feat(dpdk): dead-slot live recovery — rte hotplug rebind + generation handshake (VethBackend::recover)`.

---

## Task 7: Final verification + docs + finish

- [ ] `make check` (0), `make sim`/`make test` green, `cargo build -p flowplane-dpdk -p nfkit -p flowplane-device -p dpdk-sys -p flowplane-core` clean; the BPF verifier anchor passes; ALL privileged tests pass under sudo (attach_veth incl. recover, serve_e2e, shared_ct_gc, hotplug, guest_tx_v6_datapath, plus the existing suite). Chown target/ back.
- [ ] Update `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` "Open follow-ups": mark G1–G5 done; note the remaining ones (TapBackend/VfBackend datapath impls, rte_flow/ConnectX perf, M11 upgrade). Note the `GuestPortBackend` seam as the extension point for tap/VF.
- [ ] Commit the docs. Then finish the branch (superpowers:finishing-a-development-branch) — merge to main + push per the usual pattern.

## Notes / risks
- **Task 5 (G2)** is the verifier-sensitive one — the eBPF re-point (Step 5) + anchor (Step 6) is the gate; budget iteration there.
- **Task 6 (G3)** — Step 2 (nfkit hotplug de-risk test) MUST pass before wiring recover; if af_xdp-vdev hotplug is unreliable on this host, fall back to the spec's soft-recovery (new-port-id) contingency and document it.
- **Task 1** is a pure refactor — its bar is "attach_veth 5/5 still pass" (behavior unchanged). Everything else builds on the seam.
- Sequence is dependency-ordered: Task 1 (seam) → 2 (G5) → 3 (G4) → 4 (G1) → 5 (G2) → 6 (G3) → 7 (finish). Tasks 3 and 4 are independent of 5/6 and could reorder, but keep 1 first and 5/6 last (highest risk).
