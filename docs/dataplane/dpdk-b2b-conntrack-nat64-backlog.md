# DPDK B2b datapath backlog — conntrack + NAT64 gaps

Status: **all three RESOLVED + END-TO-END reachable on the DPDK serve loop**
(2026-07-25). #1 + #2 became reachable when guest egress was wired in (branch
`feat/dpdk-guest-egress`). #3 (NAT64 ingress) is now reachable too: NAT64 *egress*
is wired via the worker's inner-ethertype branch (branch
`feat/dpdk-guest-egress-followups`, Task 1), so `CT_F_NAT64` reverse entries are
seeded on the live loop.

These three findings came out of the 2026-07-25 datapath correctness sweep. All
three were **latent when found** — not reachable on the shipping eBPF datapath, and
not reachable on the DPDK `serve` loop *at the time* because it wired only uplink
RX. They were fixed in the shared core + `nfkit` and validated in software (the
in-process sim + a multi-lcore `--no-huge` EAL test) — **no ConnectX hardware was
needed**; only the *rte_flow hardware-offload steering* alternative for #1 (which we
did not take) would have.

**Update (2026-07-25, `feat/dpdk-guest-egress`):** the DPDK serve loop now wires
per-guest af_xdp guest egress (VF-style preallocated port pool → static poll set;
worker polls each guest port → `process_guest_tx` → SNAT+encap → uplink tx). This
lights up the previously-latent fixes: a guest's outbound SNAT now really seeds the
peer-independent reverse entry into `shared_ct` on the serve datapath, and the WAN
return really resolves it via `process_uplink_rx` — so **#1 and #2 are exercised
end-to-end on DPDK, not just in the sim**. The real write→read handoff is proven by
`nfkit/tests/guest_tx_nat_return_handoff.rs` (the REAL `process_guest_tx` write →
the REAL `process_uplink_rx` reverse-DNAT read over one `ComposedMaps`). See the
spec `docs/superpowers/specs/2026-07-25-dpdk-guest-egress-serve-loop-design.md` and
plan `docs/superpowers/plans/2026-07-25-dpdk-guest-egress-first-slice.md`.

The eBPF backend never had any of these gaps (single shared conntrack map;
`ct_touch` on every hit; full NAT64 ingress path).

---

## 1. Per-lcore NAT/LB return demux misses under RSS steering — RESOLVED

**Fixed** (`9270fb3` + `6bd68fc`). The peer-independent reverse entries
(`src_ip==0 && src_port==0`, i.e. `(vni,0,nat_ip,0,nat_port)`) now live in a
SHARED reverse-conntrack table `SharedConfigMaps::shared_ct` (an `RcuHash<CtKey,
CtEntry>`), while regular forward CT stays per-lcore. `ComposedMaps` routes
conntrack by key shape (`is_reverse_shape`), so a WAN reply resolves the
reverse-DNAT on whichever lcore its outer-header RSS steered it to.

**Concurrency (review fix `6bd68fc`):** `RcuHash` is SINGLE-WRITER
(`rcu_hash.rs:30` — `RW_CONCURRENCY_LF` gives ONE writer + N lock-free readers, NOT
concurrent writers). The datapath writes `shared_ct` from every lcore, so the
per-new-flow writes (`shared_ct_insert`/`_remove`) are serialized behind a
`std::sync::Mutex` (RcuHash's documented "sole writer behind a Mutex" model);
reads (`shared_ct_get`) stay lock-free + RCU-covered. The write is off the
per-packet hot path (NAT/LB reverse entries are created once per new flow).

**Root cause (for context):** DPDK conntrack is per-lcore shared-nothing; a
SNAT/NAT64 egress installed the reverse entry on the guest-egress lcore, but the
WAN reply is RSS-steered by OUTER/underlay headers — unrelated to the inner tuple —
so it often landed on a different lcore → `conntrack_get(rev)` miss → treated as a
new inbound flow (firewall drop / no reverse-DNAT).

**Tested:** `nfkit/tests/multilcore_nat_return.rs` (cross-lcore return resolves via
the shared table; same-lcore still resolves; normal forward CT stays per-lcore
isolated — the M8 isolation test still passes).

**End-to-end reachable (2026-07-25, `feat/dpdk-guest-egress`):** guest egress is now
wired into the serve loop, so the reverse entry is really written by
`process_guest_tx` on the serve datapath and read back by `process_uplink_rx` — the
handoff is proven by `nfkit/tests/guest_tx_nat_return_handoff.rs` (real write → real
read over one `ComposedMaps`), on top of the existing `multilcore_nat_return.rs`
cross-lcore demux proof.

**Now exercised cross-lcore on the live loop (2026-07-25, `feat/dpdk-guest-egress-followups`):**
guest ports are partitioned round-robin across ALL worker lcores (Task 3, `owns(i,q,n_workers)`),
so a guest's SNAT reverse entry lands in its owning lcore's per-lcore CT + `shared_ct`, and a
WAN return RSS-steered to a *different* uplink worker resolves via `shared_ct` — the cross-lcore
demux this fix exists for now runs on the live serve loop, not just the sim. Concurrent
multi-lcore writer safety is proven by `nfkit/tests/shared_ct_concurrent_writers.rs` (Task 2:
N lcores × K disjoint inserts through the single-writer `Mutex`, zero torn reads / dup / loss).

**Remaining (follow-ups):** the GC/eviction sweep over `shared_ct` IS built (G4:
`shared_ct_sweep_expired`, run by worker-0 at ~1Hz, reusing the core expiry predicate — see the
Hardening section below), so expired reverse entries no longer accumulate. The only thing NOT taken
is the rte_flow `MARK` hardware-steering alternative (needs ConnectX) — intentionally so: the
shared-table software fix is correct without it.

---

## 2. `ct_touch` (last_seen / TCP-state refresh) not in the shared-core seam — RESOLVED

**Fixed** (`74fd95a`). Added `ct_refresh`/`ct_refresh6` to
`flowplane-core/src/conntrack.rs` (generic over `Pkt`/`Maps`, faithful ports of the
eBPF `ct_touch`/`ct_touch6`: bump `last_seen = now`, advance `tcp_state`). The
`datapath.rs` `process_uplink` + `process_guest_tx` conntrack sites now **refresh
on a hit** (`ct_refresh`) and **create with the real `now`** on a miss (the calls
had hardcoded `now = 0`). Map-only — emitted packet bytes are unchanged, so the
byte-parity anchors stay valid. eBPF is unaffected (it uses its own ingress/egress,
not these `process_*` fns, so no double-refresh).

**Root cause (for context):** `ct_touch` was eBPF-only; the shared orchestrators
(sim + DPDK) only created entries, never refreshed, and created them with `now=0`,
so an established TCP conntrack kept `tcp_state=0` forever → the 30s idle timeout
never became the 24h ESTABLISHED timeout → a GC would evict active NAT'd flows at
30s and free/reuse the SNAT port mid-flow.

**Tested:** `flowplane-sim/src/ct_refresh_test.rs` — an established TCP flow whose
second packet arrives at `now+40s` keeps its entry (24h timeout), plus a
`ct_refresh` unit test (NEW_SYN + ACK → ESTABLISHED).

---

## 3. NAT64 ingress (v4→v6 reply) unreachable on the DPDK serve loop — RESOLVED

**Fixed** (`8e336a8`). Added `guest_ipv6: [u8;16]` to `UplinkIn` (the guest's own
overlay v6, needed to reconstruct the reply's IPv6 dst; the `Maps` trait has no
`port_meta` accessor). `process_uplink_rx` now dispatches a `CT_REWRITE_DST`
reverse hit carrying `CT_F_NAT64` to `process_uplink_nat64_ingress` (v4→v6
expansion) instead of falling through to plain IPv4 delivery. The DPDK `serve.rs`
caller sources `guest_ipv6` via a real `SharedConfigMaps::ports_get(ifindex)`
lookup.

**Root cause (for context):** the unified dispatch fired only for
`CT_F_NAT64 == 0`; NAT64 reverse entries fell through and were delivered as bare
truncated IPv4. The sim reached `process_uplink_nat64_ingress` directly (bypassing
the unified dispatch), so sim tests passed while the DPDK path did not exercise it.

**Tested:** `flowplane-sim/src/nat64_test.rs`
`uplink_rx_dispatches_nat64_return_to_v6_expansion` drives the unified
`process_uplink_rx` (not the direct fn) with a `CT_F_NAT64 | CT_REWRITE_DST`
reverse CT and asserts the v6-expanded delivery (Redirect, ethertype 0x86DD, dst =
guest overlay v6). Existing NAT64 byte-parity tests unchanged.

**Remaining (latent): NOW WIRED — END-TO-END reachable.** NAT64 egress is wired
into the serve loop (`feat/dpdk-guest-egress-followups`, Task 1): the worker guest
block branches on the inner frame's ethertype (offset 12) — an IPv6 frame
(`0x86DD`) dispatches to `process_guest_tx_nat64` (v6→v4 SNAT + translate + encap),
while everything else stays on the IPv4 `process_guest_tx` SNAT path. NAT64 egress
therefore seeds the `CT_F_NAT64 | CT_REWRITE_DST` reverse entries into `shared_ct`,
so the NAT64 ingress return path (the fixed dispatch above) is now reachable on the
live serve loop. Native v6→v6 guest egress is still NOT wired (no shared-core
orchestrator for it yet); only NAT64 v6→v4 is.

**Proven by** `nfkit/tests/guest_tx_nat64_handoff.rs`: over ONE `ComposedMaps` (the
exact structure a serve worker holds), the real `process_guest_tx_nat64` WRITE
seeds the discovered `CT_F_NAT64` reverse entry in `shared_ct`, then the real
`process_uplink_rx` READ (uplink input resolved exactly as the worker does) resolves
it and v4→v6-EXPANDS the reply to the guest tap (asserts `Redirect(guest_tap)`,
inner ethertype `0x86DD`, inner IPv6 dst = guest overlay v6) — the NAT64 analogue of
`guest_tx_nat_return_handoff.rs`.

---

## 4. Dead guest pool slots (pod netns destroyed WITHOUT detach) — DETECTED + EXCLUDED (live recovery is a follow-up)

**Fixed** (`feat/dpdk-guest-egress-followups`, Task 6). The DPDK attach model binds a
PREALLOCATED guest af_xdp pool slot (`GuestPortSlot { host_ifname, host_ifindex,
port_id, bound, dead }`): attach reserves a free slot and moves its placeholder
guest-end into the pod netns; detach moves it back + frees the slot.

**The hazard:** veth pairs die together. If a pod's netns is destroyed WITHOUT a
preceding `DetachInterface`, the slot's guest-end vanishes and takes the host-end
(`fpg{i}`, bound to the af_xdp ethdev port) with it — leaving the slot free
(`bound.is_none()`) but its ethdev BROKEN. Previously attach could then hand out that
DEAD slot → the new guest's traffic silently BLACKHOLED.

**What this does:** dead slots are now DETECTED and EXCLUDED from the free pool.
`flowplane_device::link_exists(host_ifname)` (a cheap sysfs `ifindex` stat) is the
probe. On the attach reservation path (`node.rs::attach_interface`, under the
`guest_pool` lock) a first pass marks any free-but-not-yet-dead slot whose host-end no
longer exists as `dead = true`; the reserve then binds only a LIVE free slot
(`bound.is_none() && !s.dead`). On detach (`node.rs::detach_interface`), after the
best-effort unbind, the slot is freed (`bound = None`) only if its host-end still
exists; if the host-end is GONE it is marked `dead = true` instead. A pool drained by
dead slots therefore correctly surfaces as `resource_exhausted` ("increase
--guest-ports") rather than binding a blackhole. All other detach reclaim (purge_vni,
ports_remove, forget_iface_meta, IPAM release) stays unconditional/best-effort.

**Tested:** `flowplane-dpdk/tests/attach_veth.rs`
`attach_skips_dead_pool_slot_and_exhausts_when_only_dead_left` (privileged, `#[ignore]`):
seeds TWO pool slots, attaches guest A (binds slot 0), `delete_link`s slot 0's HOST
veth out from under it (simulating netns-destroyed — deleting the host-end kills its
peer too), then attaches guest B and asserts it binds the LIVE slot 1 (NOT the dead
slot 0), and finally that a third attach with only a dead slot free returns
`resource_exhausted`. Plus a `flowplane_device::link_exists` unit test.

**Remaining (follow-up): LIVE RECOVERY not implemented.** A dead slot is permanently
excluded until the serve process restarts. Full recovery — recreate the veth +
`rte_dev` hotplug detach/attach the af_xdp vdev + reconfigure the ethdev port — is the
"real" fix but is deliberately deferred: the static-pool model avoids runtime device
churn, and hotplug is the proper mechanism. Detection-and-exclude is the safe
first step (never blackhole).

---

## Hardening — DONE (`feat/dpdk-guest-egress-hardening`, 2026-07-26)

All five open follow-ups are RESOLVED, unified behind a backend-agnostic `GuestPortBackend`
lifecycle seam (veth impl; tap/VF are documented seams). Spec/plan:
`docs/superpowers/specs/2026-07-26-dpdk-guest-egress-hardening-design.md` +
`docs/superpowers/plans/2026-07-26-dpdk-guest-egress-hardening.md`.

- **G5 startup-rollback** — RAII `StartupGuard` tears down preallocated pool devices on any
  early return before the worker spawn; disarmed once workers own the ports.
- **G4 `shared_ct` GC** — worker-0 ~1Hz `shared_ct_sweep_expired(now)` reusing the core
  `ct_is_expired` (30s NEW / 24h ESTABLISHED); off the hot path, single-writer Mutex removes.
- **G1 full-serve af_xdp e2e** — `hack/dpdk/serve-e2e.sh` + `tests/serve_e2e.rs` launch the REAL
  serve on af_xdp, gRPC-attach, and prove guest→fabric encap + NAT-return over real transport.
  It UNCOVERED that the serve datapath was totally inert (never programmed `LOCAL`) — fixed,
  plus 3 more it surfaced (uplink NAT-return mis-routed to the fabric; `process_guest_tx`
  `snat_egress(..,0)` → GC evicted the reverse entry instantly; `/0` route never matched an
  exact-/32 table). See [[dpdk-guest-egress-serve-loop]] memory for the full four-bug writeup.
- **G2 native v6→v6 egress** — extracted the eBPF v6 egress stages into shared core
  (`egress_fw_ct6`/`route_decision6` + `datapath::process_guest_tx_v6`, inner-proto 41); eBPF
  re-pointed at the seam (BPF verifier anchor PASSES, 512B stack held); worker dispatches
  `0x86DD` → NAT64 else native v6. Lights up v6 deny-by-default fw + `conntrack6` on the loop
  (also incidentally closed the ct_touch6 seam). Fixed: `ComposedMaps` was defaulting v6
  fw/conntrack6 to deny-all/no-op.
- **G3 dead-slot live recovery** — `rte_eal_hotplug_add/remove` FFI + `VethBackend::recover`
  (recreate veth + hotplug-rebind the af_xdp ethdev); control thread does all `Send` work
  off-lcore + swaps the new `Port` into a `Mutex<Option<Port>>` cell + bumps an atomic
  generation; the owning worker rebuilds its `!Send` rx/tx handles on-lcore on the bump (the
  one sanctioned mutation to the static poll set). Hotplug de-risk gate proven on this host.

### TapBackend (VMs) — DATAPATH SLICE DONE (`feat/dpdk-tap-backend`, 2026-07-26)

`TapBackend` implements the `GuestPortBackend` seam for VMs: af_xdp binds the tap's kernel
netdev (pool port, serve netns); qemu holds the char-device fd (guest edge). More VF-like than
veth — a persistent tap survives the VM, so `recover()` is a near-no-op (no hotplug). Selected
via `--guest-backend veth|tap`. Spec/plan: `docs/superpowers/specs+plans/2026-07-26-dpdk-tap-backend-datapath-slice*`.
De-risk gate proved af_xdp binds a tap netdev + fd round-trips (`nfkit/tests/afxdp_tap.rs`);
`flowplane-device` tap helpers (`create_persistent_tap`/`open_tap_fd`/`delete_tap`); the datapath
proof `nfkit/tests/tap_guest_datapath.rs` runs the REAL `process_guest_tx` over af_xdp-on-tap
driven by a raw `/dev/net/tun` fd (guest→fabric encap + return-transport to the fd). Datapath is
backend-agnostic (keys on the pool host ifindex). **Deferred:** the KubeVirt binding-plugin
(`domainAttachmentType=tap`) + CNI/Multus wiring + real fd-handoff-to-qemu-in-a-pod-netns +
real-qemu e2e; `attach_interface` still rejects an explicit `device_type="tap"` RPC (control-plane
wiring for the KubeVirt path); mixed veth+tap pools in one process.

### Remaining follow-ups (after hardening + tap slice)
1. **VfBackend (SR-IOV real NIC)** datapath impl — only the `GuestPortBackend` trait seam exists
   (hardware-gated). The **KubeVirt control-plane wiring for TapBackend** (binding plugin + CNI +
   fd-handoff + real-qemu e2e) is the next tap increment.
2. **Native v6→v6 guest↔guest local delivery** — VERIFIED WORKING (2026-07-26). No fix was
   needed: `process_guest_tx_v6`'s `Deliver::Local` arm already returns
   `Redirect(dest_tap_ifindex)` with the inner Eth rewritten (dst=guest_mac, src=GW_MAC, ethertype
   left at 0x86DD/IPv6, no encap), and the worker's guest↔guest routing
   (`Redirect(ix != uplink) → rings[ifindex_to_index[ix]]`) is ETHERTYPE-AGNOSTIC — so a v6-native
   same-node `Deliver::Local` composes with the ring handoff exactly as the v4 one does. Proven by
   `nfkit/tests/guest_local_delivery_v6.rs` (INTERNAL v6 route + dest PortMeta → real
   `process_guest_tx_v6` asserts `Redirect(DEST_TAP)` + inner-Eth rewrite + unchanged length/IPv6
   payload, then `LcoreRing` enqueue→dequeue asserts byte-identical delivery).
3. **Live worker-rebuild-under-traffic e2e for G3** — the control-level recover is proven
   (attach_veth); killing+recovering a slot mid-serve-run is a serve_e2e follow-on.
4. **`/0` (non-/32) route validation** — FIXED: `route_upsert`/`route6_upsert` now `bail!` on a
   non-host prefix (exact-match table → a non-`/32`(v4)/`/128`(v6) prefix never matches → silent
   Pass), so the control plane sees a clear error instead of silently accepting it. LPM support is
   still the alternative if wildcard routes are ever needed.
5. **Startup teardown after worker spawn** — FIXED: `--addr` is now parsed UP-FRONT (top of `run`),
   before any pool device is created or worker spawned, so a bad `--addr` can't leak
   workers/veths. The StartupGuard covers prealloc→spawn, and nothing fallible now runs between
   `guard.disarm()` and the shutdown block except the tonic serve — whose error routes through
   `serve_result` (handled AFTER the teardown), not an early `?`.
6. rte_flow / ConnectX perf phase; M11 hitless-upgrade orchestration (hardware-gated).

## Cross-refs

- DPDK per-lcore shared-nothing model: M8 (`design/flowplane-dpdk`).
- Externalized conntrack for upgrades: M11 hitless-upgrade slice (the shared_ct
  table + `for_each`/`remove` are a step toward it).
- None of these affect the eBPF datapath or the sim byte-parity guarantees.
