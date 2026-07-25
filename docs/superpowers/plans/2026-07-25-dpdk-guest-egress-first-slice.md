# DPDK Guest Egress — First Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Prove guest egress (guest→fabric) through the DPDK serve loop over a per-guest af_xdp port — one preallocated guest port, single worker — so `process_guest_tx` runs on the DPDK backend end-to-end and the latent shared-CT/NAT fixes go live.

**Architecture:** Per-guest af_xdp, VF-style preallocated pool. Guest veths (host-ends) are created BEFORE EAL init so they can be passed as `--vdev=net_af_xdp<i>,iface=<veth>`; each becomes a `nfkit::Port`. The serve worker polls the uplink + the guest port; guest-RX frames resolve the port's `PortMeta` (by host ifindex) and drive `process_guest_tx` → encap+redirect out the uplink. Attach *assigns* a preallocated pool port to a guest (move guest-end into the pod netns + program `PortMeta`), detach releases it. Poll set is STATIC (no fd churn).

**Tech Stack:** Rust, DPDK (nfkit `Port`/af_xdp/`MbufPkt`), `flowplane-core::datapath::process_guest_tx`, `flowplane-device` veth, af_xdp-on-veth (`--no-huge`, sudo).

**Spec:** `docs/superpowers/specs/2026-07-25-dpdk-guest-egress-serve-loop-design.md`.

**Key facts (from investigation):**
- `nfkit::Port::configure(id: u16, n_queues: u16, pool: &Mempool) -> Result<Port, PortError>` (port.rs:33); `Port::queue(q) -> (RxQueue, TxQueue)` (port.rs:99); `rx(&mut MbufBurst)`/`tx(&mut MbufBurst)`.
- `serve.rs` uplink build: `Mempool::new(...)` + `Port::configure(0, queues, &pool)` (serve.rs:207); `Backend::AfXdp{iface,queues}` → `--vdev=net_af_xdp0,iface=<iface>,...` EAL arg.
- `worker_loop(q, shared, port, stop)` (serve.rs:363): single port/queue, `port.queue(q)` → rx→`process_uplink_rx`→tx. `LcoreRuntime::for_each_worker` (serve.rs:294).
- `process_guest_tx<P,M>(pkt, maps, in_: &GuestTxIn) -> GuestTxOut` (datapath.rs:154). `GuestTxIn{ meta: &PortMeta, src_ifindex: u32, now: u64 }` (datapath.rs:111). `GuestTxOut{ action: Action, edt_tstamp: Option<u64> }` (datapath.rs:122). Encap arm: `grow_head(IPV6_LEN)` + `write_outer_v6` → `Action::Redirect(e.uplink_ifindex)`.
- `PortMeta` keyed by **host veth ifindex**; `ports_upsert(ifindex, meta)` (writer.rs:207) via `program_interface`; `ports_get(ifindex) -> Option<PortMeta>` (serve.rs:428).
- `DpdkAttachState.registry: HashMap<interface_id, AttachedDevice{host_ifindex, host_name, netns_path}>` (attach_state.rs:24); attach = `create_veth_pair` → `program_interface` (writes PortMeta) → register (node.rs:87).
- `MbufPkt::grow_head/shrink_head/set_tail` (mbuf_pkt.rs:80) — encap-capable.
- Templates: `nfkit/tests/multilcore_datapath.rs:156` (MbufPkt-over-DpdkMaps datapath call), `flowplane/tests/anchor_guest_tx.rs` (guest-tx fixture: PortMeta/routes/firewall/LOCAL), `nfkit/tests/afxdp_datapath.rs` (af_xdp-on-veth harness).

---

## Task 1: `process_guest_tx` over MbufPkt/DpdkMaps datapath test (proves the datapath half; no serve changes)

**Files:** Create `flowplane/nfkit/tests/guest_tx_datapath.rs` (mirror `multilcore_datapath.rs` structure + `anchor_guest_tx.rs` fixture).

Prove the DPDK Pkt/Maps backend runs `process_guest_tx` correctly: a guest IPv4 frame with an external route → SNAT + encap (outer IPv6) + `Action::Redirect(uplink_ifindex)`, and the forward SNAT conntrack reverse entry lands in the **shared_ct** table (the just-merged fix), byte-identical to the sim.

- [ ] **Step 1: Write the test** — EAL `--no-huge` (mirror `multilcore_datapath.rs` `init_eal_once`), build `SharedConfigMaps` + a `PerLcoreFlowMaps`/`ComposedMaps`, program via `DpdkMapWriter`+`ControlCore`: a `PortMeta` for the guest (vni, guest_ipv4, underlay), an external `route4` (0.0.0.0/0 → external), a NAT source, `LOCAL`, an egress-allow firewall rule. Allocate an mbuf, write a guest IPv4 TCP frame (inner eth + IPv4 + TCP), wrap `MbufPkt`, call `process_guest_tx(&mut pkt, &mut composed, &GuestTxIn{ meta: &portmeta, src_ifindex: guest_ifindex, now })`. Assert: `action == Redirect(uplink_ifindex)`, `pkt.len()` grew by 40 (outer v6), the outer/inner bytes match the sim `SimNode::guest_tx` output for the same input (byte-parity), and `composed.cfg.shared_ct_get(reverse_key).is_some()` (the peer-independent `(vni,0,nat_ip,0,nat_port)` reverse entry).
- [ ] **Step 2: Run** — `sudo -E $(command -v cargo) test -p nfkit --test guest_tx_datapath -- --test-threads=1 2>&1 | tail`. Expected PASS. (If EAL global-init collides with other nfkit EAL tests in one binary, keep it its own `--test` file, as the others are.)
- [ ] **Step 3: Commit** — `git add flowplane/nfkit/ && git commit -m "test(dpdk): process_guest_tx over MbufPkt — SNAT+encap byte-parity + shared_ct reverse entry"`.

## Task 2: Preallocate a guest veth + af_xdp Port at serve startup (nfkit + serve)

**Files:** `flowplane-dpdk/src/serve.rs` (EAL argv + port build); possibly `nfkit/src/port.rs`/`backend` (multi-vdev). Add a `--guest-ports N` serve arg (first slice: default/allow 1).

- [ ] **Step 1** — Before EAL init, create N (=1) guest veth pair(s) via `flowplane_device::create_veth_pair` (host-end in root netns, a placeholder guest-end name; MTU = guest_mtu). Record the host-end ifname/ifindex in a preallocated-pool structure (`Vec<GuestPortSlot{ host_ifname, host_ifindex, bound: Option<PortMeta-key/interface_id> }>`).
- [ ] **Step 2** — Extend the EAL argv / `Backend` so the af_xdp backend emits `--vdev=net_af_xdp0,iface=<uplink>` AND `--vdev=net_af_xdp<i+1>,iface=<guest_veth_i>` for each pool veth. After EAL init, `Port::configure(port_id, 1, &pool)` for each (uplink = id 0, guest ports = 1..=N). Confirm `Port` has no hard single-port assumption (investigation: none, but each `Port` owns its ethdev).
- [ ] **Step 3** — Build; run the existing af_xdp/uplink tests to confirm no regression (`make dpdk-afxdp-datapath` or the afxdp test under sudo, if runnable). Commit.

## Task 3: Serve worker polls the guest port → `process_guest_tx` (the integration)

**Files:** `flowplane-dpdk/src/serve.rs` `worker_loop`.

- [ ] **Step 1** — Change `worker_loop` to take the uplink port + the guest port(s) this worker owns (first slice: worker 0 owns the 1 guest port). After the uplink rx→process_uplink_rx→tx block, add a guest-port rx block: `rx` the guest port; for each mbuf, resolve `composed.cfg.ports_get(guest_host_ifindex)` → `PortMeta`; if `Some`, `process_guest_tx(&mut pkt, &mut composed, &GuestTxIn{ meta: &m, src_ifindex: guest_host_ifindex, now })`; on `Action::Redirect(ifindex)` where ifindex == uplink → push to the UPLINK tx burst (encap→fabric); `Redirect` to a guest tap (local guest↔guest, out of first-slice scope → drop w/ TODO); `Pass`/`Drop` → free. Flush the uplink tx burst. An unbound guest port (`ports_get` None) → drop.
- [ ] **Step 2** — Build clean; `make sim` green (core untouched). Commit.

## Task 4: Attach assigns a preallocated pool port (not create-on-attach)

**Files:** `flowplane-dpdk/src/node.rs` `attach_interface`, `attach_state.rs`.

- [ ] **Step 1** — Add the preallocated pool (from Task 2) into `DpdkAttachState` (or a sibling shared with serve). `attach_interface` for a veth guest: instead of `create_veth_pair`, ASSIGN an idle pool slot: move the pool veth's guest-end into `netns_path` + rename to the requested guest ifname + `configure_guest_netns`; `program_interface` with `tap = pool_slot.host_ifindex` (so `PortMeta` is keyed by the pool port's host ifindex the serve loop polls); mark the slot bound to `interface_id`. Detach: `forget_iface_meta`/`ports_remove`, move the guest-end back to root netns, mark the slot idle.
- [ ] **Step 2** — Build; the existing `attach_veth` EAL test still passes (or is updated for the pool model). Commit.

## Task 5: End-to-end af_xdp guest-egress test + NAT-return (shared_ct live)

**Files:** `flowplane-dpdk/tests/` (new, mirror `afxdp_datapath.rs` harness).

- [ ] **Step 1** — Under sudo + af_xdp (`--no-huge`, self-restoring hugepage harness): bring up the serve datapath with 1 preallocated guest port; attach a guest; inject a guest IPv4 frame on the guest veth (via its netns peer); assert an encapped IPv6 frame egresses the uplink (SNAT+encap correct). Then inject the matching NAT return on the uplink and assert reverse-DNAT delivery back to the guest — exercising the `shared_ct` write (guest-tx) + read (uplink-rx) across the two paths.
- [ ] **Step 2** — Run under sudo; commit. If full serve-loop e2e is too heavy for one test, split: (a) a component test that drives both `process_guest_tx` and `process_uplink_rx` over one `ComposedMaps` proving the shared_ct handoff, and (b) note the full-serve e2e as a follow-up.

## Task 6: Final verification + backlog update

- [ ] `make check`/`sim`/`test` green; `cargo build -p flowplane-dpdk` clean; the new EAL/af_xdp tests pass under sudo. Update `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` to note the shared_ct/NAT64 fixes are now END-TO-END reachable (guest egress wired). Commit.

## Notes / risks
- **af_xdp on veth host-end while peer moves to netns:** confirmed byte-transparent (afxdp_datapath.rs); verify the af_xdp socket stays live across the peer's netns move (should — af_xdp binds the host-end, which doesn't move).
- **EAL multi-vdev:** the biggest unknown — that N af_xdp vdevs init cleanly in one EAL. De-risk in Task 2 first.
- **This is the FIRST SLICE.** Multi-guest, multi-worker port partitioning, guest↔guest local delivery, detach/reuse hardening, and a multi-threaded concurrent-writer stress test for `shared_ct` are follow-ups.
