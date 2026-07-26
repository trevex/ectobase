# DPDK Guest Egress — Hardening & Completion Design

**Date:** 2026-07-26
**Status:** Approved (brainstorming)
**Predecessors:** first slice (main @b0fa50b), follow-ups (main @2247161). Backlog: `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` ("Open follow-ups").

## Overview

The DPDK `flowplane-dpdk serve` datapath now wires guest egress over a VF-style preallocated per-guest af_xdp port pool (multi-worker partitioning, NAT64 egress, guest↔guest via `LcoreRing`, dead-slot detection). Five gaps remain. This design closes all five, and — per user direction — introduces a **backend-agnostic guest-port lifecycle** so the software mode (veth), the VM mode (tap), and the real-NIC mode (SR-IOV VF passthrough) share ONE control path. That way "assign a pool port to a guest / release it / recover it" is the same code regardless of the underlying device, mirroring how a CNI re-homes an SR-IOV VF between the PF and a pod.

## Goals

1. **G5** — Startup-rollback consistency: no leaked pool veths on a failed `serve` startup.
2. **G4** — `shared_ct` GC/eviction: reclaim stale reverse-conntrack entries (idle-timeout, eBPF CT-timeout model).
3. **G1** — Full-serve af_xdp e2e: prove the whole datapath (guest→fabric, NAT-return, cross-lcore guest↔guest) over a real `serve` process + gRPC attach + real af_xdp transport.
4. **G2** — Native v6→v6 guest egress: extract the eBPF v6 egress composition into shared core (seam-not-duplicate) and wire it into the DPDK worker; lights up v6 firewall/`conntrack6` on the DPDK loop.
5. **G3** — Dead-slot live recovery: true hotplug rebind of a pool port whose veth pair died (pod netns destroyed without detach), expressed as the veth backend's `recover()`.

Non-goal (this spec): implementing the VF or tap backends' datapath — only the **seam** (trait + veth impl); VF is hardware-gated, tap is the likely-next follow-up.

## Unifying architecture: the `GuestPortBackend` seam

Today attach/detach call `flowplane_device::{create_preallocated_veth, bind_preallocated_guest_end, unbind_preallocated_guest_end, link_exists}` directly. We refactor these behind a trait so the *lifecycle* is device-agnostic and the *device kind* is pluggable:

```
/// A pooled guest-port device backing one af_xdp ethdev port. Preallocated before EAL init;
/// assigned to a guest at attach, released at detach, recovered after an ungraceful teardown.
/// Implementations: VethBackend (containers, THIS spec), TapBackend (VMs, follow-up),
/// VfBackend (SR-IOV real NIC, seam/follow-up). The lifecycle is IDENTICAL across all three —
/// only the device mechanics differ.
trait GuestPortBackend {
    /// Create the pool host device for slot `index` BEFORE EAL init; return the host netdev name
    /// (passed as `--vdev=net_af_xdp<n>,iface=<name>`) + resolved ifindex. veth: create pair,
    /// host-end up, guest-end parked. tap: create persistent tap. vf: bind a VF, return its netdev.
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice>;

    /// Assign the slot's guest-facing device into the consumer (pod netns for veth/vf; VM/tap fd
    /// for tap). veth: move guest-end into netns + rename + mac/up/mtu. vf: `ip link set <vf> netns`.
    fn assign(&self, slot: &GuestPortSlot, target: &AssignTarget, mac: [u8;6], mtu: u32) -> Result<()>;

    /// Release the slot's guest-facing device back to the pool's idle/holding state. veth: move
    /// guest-end back to the holding location (root-netns placeholder `<host>p`). vf: move VF back
    /// to the PF netns. Best-effort (the netns may already be gone).
    fn release(&self, slot: &GuestPortSlot, target: &AssignTarget) -> Result<()>;

    /// Is the slot's HOST device still alive (the af_xdp ethdev's backing netdev)? veth: link_exists
    /// (a dead pair takes the host-end with it). tap/vf: near-always alive (persistent device).
    fn is_alive(&self, slot: &GuestPortSlot) -> bool;

    /// Recover a slot whose host device died (ungraceful teardown). Returns the NEW host ifindex.
    /// veth: recreate the pair + hotplug-rebind the af_xdp ethdev (G3). vf: near-no-op (the kernel
    /// re-homes a VF on netns destruction; the ethdev never died) → just re-preallocate/rebind if
    /// needed. This is the ONE method whose cost differs materially by backend.
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32>;

    /// Destroy a preallocated host device (startup rollback G5 + normal shutdown cleanup).
    /// veth: `delete_link` (removes the pair). Idempotent / best-effort.
    fn teardown(&self, slot: &GuestPortSlot);
}
```

`AssignTarget` = `{ netns_path, guest_ifname }` for veth/vf; a tap variant carries the tap/VM handle. The DPDK serve owns a `Box<dyn GuestPortBackend>` (default `VethBackend`); attach/detach call `assign`/`release`; the recovery trigger calls `recover`. `GuestPortSlot` gains a `dead: bool` (already added) and a `generation: AtomicU32` (G3). The eBPF backend is unaffected (this is DPDK-serve control-plane only).

**Why:** keeps software (veth), VM (tap), and hardware (VF) modes structurally identical — the same assign/release/recover control path, differing only in device mechanics — so the real-NIC path is the same code with a cheaper `recover()`. YAGNI: only `VethBackend` is implemented; tap/VF are documented seams.

---

## Workstreams

Ordered low-risk → high-risk; each is an independently mergeable increment. G2 and G3 are large enough to merge as their own branches.

### G5 — Startup-rollback consistency  *(smallest; do first)*

**Problem:** `serve.rs::run()` tears down created guest veths on a guest-port *configure* failure, but a later fallible startup call (`LcoreRing::new`, `SharedConfigMaps::new`, mempool, etc.) `?`-returns leaving the already-created veths on the host (startup-only leak; restart is idempotent but messy).

**Design:** collect the created pool host-device names into a cleanup guard (a small RAII `struct StartupVeths(Vec<String>)` whose `Drop` `delete_link`s each) armed as soon as the first device is preallocated and `.disarm()`-ed once the worker thread takes ownership of the ports (i.e. after the worker spawn succeeds). Every `?` between prealloc and hand-off then tears down cleanly. With the `GuestPortBackend` seam, teardown routes through a `backend.teardown(slot)` (veth: `delete_link`).

**Files:** `flowplane-dpdk/src/serve.rs` (+ the backend trait's teardown). **Test:** unit test the guard arms/disarms + deletes on drop (no EAL). **Risk:** trivial.

### G4 — `shared_ct` GC/eviction sweep

**Problem:** reverse-conntrack entries in `shared_ct` are never reclaimed; a long-running node leaks them as flows end.

**Design:** idle-timeout eviction mirroring the eBPF CT model — `ct_refresh` already maintains `last_seen` + `tcp_state`, so eviction reuses the same thresholds (NEW/SYN ~30s, ESTABLISHED ~24h; the exact constants come from the eBPF CT timeout consts in flowplane-core). Add `SharedConfigMaps::shared_ct_sweep_expired(now, &mut evicted_count)` that iterates via `shared_ct_for_each`, collects keys whose `last_seen` is older than the state-dependent timeout, and `shared_ct_remove`s them (writes already Mutex-serialized; the sweep runs off the per-packet path). One designated worker (worker 0) calls it on a throttle (~1s wall-clock, gated off the existing per-burst `monotonic_ns()` read, no new timer). Emit an eviction counter for observability.

**Files:** `nfkit/src/shared_config.rs` (sweep helper), `flowplane-dpdk/src/serve.rs` (worker-0 throttled call). **Test:** nfkit EAL test — insert entries with old vs fresh `last_seen` across NEW/ESTABLISHED states, sweep, assert only the genuinely-expired ones are removed and live flows survive. **Risk:** low-moderate (must not evict active flows — the state-dependent timeout is the guard).

### G1 — Full-serve af_xdp e2e

**Problem:** every datapath seam is unit/component-proven, but the whole `serve` process (EAL + pool + gRPC attach + worker poll) over real af_xdp transport is not exercised end-to-end.

**Design:** a privileged harness modeled on `hack/dpdk/afxdp-uplink.sh` (self-restoring hugepages, veth setup, skip-if-unprivileged exit 77). It: (1) launches the real `flowplane-dpdk serve` binary with `--backend af-xdp`, N preallocated guest ports, `--no-huge`, on a veth uplink + a netns per guest; (2) drives `AttachInterface` (routes/NAT/firewall/attach) via a tiny gRPC client (reuse `flowplane_node::pb`); (3) injects a guest IPv4 frame on guest A's veth peer and captures the encapped frame on the uplink (guest→fabric); (4) injects the matching NAT-return on the uplink and captures reverse-DNAT delivery on guest A; (5) with two guest ports on two lcores, injects a guest-A→guest-B frame and captures it on guest B (cross-lcore guest↔guest via `LcoreRing`). Byte-compare against the sim oracle where applicable.

**Files:** `hack/dpdk/serve-e2e.sh` (+ a Rust gRPC-client helper or an example binary), `flowplane-dpdk/tests/serve_e2e.rs`. **Test:** IS the test. **Risk:** moderate (harness/timing/scapy-on-veth flakiness — mitigate with retries + generous sniff windows, as `afxdp-uplink.sh` does).

### G2 — Native v6→v6 guest egress  *(core extraction; seam-not-duplicate; verifier-sensitive)*

**Problem:** the DPDK worker dispatches v4 (`process_guest_tx`) and NAT64 v6→v4 (`process_guest_tx_nat64`); a **native v6→v6** guest frame (dst not in the NAT64 prefix) has no shared-core orchestrator — the composition (`forward_decision_v6` + its stages `egress_fw_ct_v6`, `route_decision_v6`) lives ONLY in `flowplane-ebpf/src/egress.rs`. So a v6-native guest egress silently drops on DPDK, and v6 firewall/`conntrack6` are unexercised on the loop.

**Design (honors [[seam-not-duplicate-for-tests]]):** extract the v6 egress composition into `flowplane-core` as **stage functions** — `egress_fw_ct_v6` (egress firewall + `conntrack6` firewall-only track) and `route_decision_v6` (route6 + `deliver` → Local/Encap/Pass) — generic over `Pkt`/`Maps`. Add `flowplane_core::datapath::process_guest_tx_v6` that composes the stages (single fn, off-eBPF, no stack limit) returning `GuestTxOut`, mirroring `process_guest_tx`. Re-point the eBPF `forward_decision_v6` to call the SAME extracted stage fns from its existing tail-called/`#[inline(never)]` staged wrappers (preserving the 512B-per-frame budget: each stage stays its own frame; the shared code is the stage bodies, not a single inflated fn). Wire the DPDK worker: `0x86DD` → if `nat64_egress_parse` matches (dst in NAT64 prefix) → `process_guest_tx_nat64`, else → `process_guest_tx_v6` (native encap). This lights up v6 deny-by-default firewall + `conntrack6` on the DPDK datapath.

**Files:** `flowplane-core/src/{datapath,egress}.rs` (stages + `process_guest_tx_v6`), `flowplane-ebpf/src/egress.rs` (delegate to the stages), `flowplane-dpdk/src/serve.rs` (worker v6 branch). **Tests:** sim test (`SimNode::guest_tx_v6` byte-parity), DPDK component test (MbufPkt/ComposedMaps native-v6 encap + `conntrack6` landed), and a **BPF verifier anchor** (`make sim-anchor`) proving `tc_guest_egress_v6` still passes the verifier after the re-point (the flow-label/ipv6-firewall stack lesson: only the privileged anchor runs the verifier). **Risk:** HIGH — verifier-sensitive; the re-point must not inflate the combined BPF stack. Fallback if the verifier rejects a shared stage: keep the eBPF stage bodies as thin wrappers that call the core stage with the exact same locals, or move the divergent test to goscapy (per the seam rule) — NEVER keep a parallel eBPF-only core guarded by an anchor.

### G3 — Dead-slot live recovery (veth backend `recover()`; true hotplug rebind)  *(highest risk; do last)*

**Problem:** a pod netns destroyed WITHOUT a preceding detach kills the guest-end and (veth pairs die together) the host-end `fpg{i}` + its af_xdp ethdev — breaking that slot until serve restart. Today: detected + excluded. VFs don't have this problem (the device persists / is re-homed by the kernel); this is the veth backend's inherent cost, so recovery is the veth `recover()`.

**Design:** add `rte_eal_hotplug_add`/`rte_eal_hotplug_remove` FFI to dpdk-sys. `VethBackend::recover(slot, pool_port_id)`: (1) `delete_link` any stale remnant; (2) `create_preallocated_veth(fpg{i})` fresh (new host ifindex); (3) `rte_eal_hotplug_remove("vdev", "net_af_xdp{n}")` for the dead vdev; (4) `rte_eal_hotplug_add("vdev", "net_af_xdp{n}", "iface=fpg{i},...")`; (5) `Port::configure(pool_port_id, 1, &pool)` to re-setup the ethdev; (6) update the slot's `host_ifindex`, clear `dead`, and **bump the slot's `generation: AtomicU32`**. The owning worker, at the top of each poll iteration, checks each owned slot's generation vs its cached copy; on a bump it **rebuilds that port's `RxQueue`/`TxQueue`/`LcoreRing` drain handle** — the ONE sanctioned mutation to the otherwise-static poll set. The generation handshake is the safety mechanism: control thread never touches the worker's `!Send` queue handles; it only recreates the ethdev + signals; the worker does the queue rebuild on its own lcore. Recovery is triggered by the control plane (a reconciler, or on the next attach that would otherwise `resource_exhaust`).

**Concurrency safety:** the control thread does the veth/hotplug/`Port::configure` (all `Send`, off-lcore); the worker does only its own queue rebuild (on-lcore). The generation counter (`Acquire`/`Release`) is the sole cross-thread signal. A packet in flight on the old (now-removed) ethdev during the swap window is dropped (the af_xdp socket is gone) — acceptable; recovery is a rare event.

**Files:** `dpdk-sys/{wrapper.h,shim.h,shim.c}` (hotplug FFI), `nfkit/src/port.rs` (a reconfigure/rebuild path), `flowplane-dpdk/src/serve.rs` (generation handshake + worker rebuild), `flowplane-dpdk/src/node.rs` (recovery trigger), `attach_state.rs` (`generation` field). **Test:** privileged — attach a guest, `delete_link` its pool host veth (simulate ungraceful teardown), trigger `recover`, assert the slot's ethdev is live again (new ifindex, `dead` cleared, generation bumped) and guest egress resumes over the rebuilt port. **Risk:** HIGHEST — runtime ethdev churn mid-poll; the generation handshake + off-lcore/on-lcore split is the safety design. If DPDK hotplug of an af_xdp vdev proves unreliable on this host, fall back to the generation-flag *soft* recovery (add a NEW ethdev port id, retire the dead one) — documented as the contingency.

---

## Testing strategy

- **Unit** (no EAL): the `GuestPortBackend` trait seam, G5 cleanup guard, G4 timeout predicate, the v6 stage decisions where pure.
- **In-process EAL (`--no-huge`, sudo):** G4 sweep, G2 DPDK component (native-v6 encap + conntrack6), G3 recover (veth recreate + hotplug + rebuild).
- **Sim byte-parity:** G2 `SimNode::guest_tx_v6` vs the DPDK MbufPkt path.
- **BPF verifier anchor (`make sim-anchor`, privileged):** G2 `tc_guest_egress_v6` after the seam re-point.
- **Full-serve privileged e2e:** G1.
- Each task ends with a commit; per-task spec+quality review (subagent-driven-development); final holistic review; merge per increment.

## Out of scope / documented follow-ups

- **TapBackend** (VMs) and **VfBackend** (SR-IOV real NIC) datapath impls — only the trait seam lands here (tap is the likely-next follow-up; VF is hardware-gated).
- rte_flow hardware offload / ConnectX perf phase.
- M11 hitless-upgrade orchestration.

## Risks & mitigations (summary)

| Gap | Risk | Mitigation |
|-----|------|------------|
| G2 | BPF verifier rejects the shared stage (stack) | Keep eBPF stages as own frames delegating to core stage bodies; verifier anchor gates it; goscapy fallback per seam rule |
| G3 | Runtime ethdev churn corrupts the poll loop | Off-lcore control work + on-lcore queue rebuild via atomic generation handshake; soft-recovery (new port id) contingency |
| G1 | e2e harness flakiness | retries + generous sniff windows + skip-if-unprivileged, mirroring afxdp-uplink.sh |
| G4 | evicting live flows | state-dependent timeout from the eBPF CT model; test asserts survivors |
