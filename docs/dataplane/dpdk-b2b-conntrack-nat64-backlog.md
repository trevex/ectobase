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

**Remaining (follow-ups):** a GC/eviction sweep over `shared_ct` (via `shared_ct_for_each`/`_remove`)
is not built yet. The rte_flow `MARK` hardware-steering alternative (needs ConnectX) was
intentionally not taken — the shared-table software fix is correct without it.

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

## Open follow-ups (DPDK guest-egress, after `feat/dpdk-guest-egress-followups`)

The four gaps above are resolved + end-to-end reachable, and multi-worker partitioning,
guest↔guest same-node delivery, NAT64 egress, and dead-slot exclusion are all wired
(`feat/dpdk-guest-egress-followups`). What remains, in rough priority order:

1. **Full-serve af_xdp e2e** — bring up `flowplane-dpdk serve` + preallocated guest ports
   + gRPC attach + bidirectional packet injection over REAL af_xdp (incl. a two-lcore
   two-guest guest↔guest delivery). Each datapath seam is independently proven (the handoff
   tests, `afxdp_datapath.rs`, `attach_veth.rs`, `guest_local_delivery.rs`, `lcore_ring.rs`);
   the only unproven layer is real-transport polling/timing under the live partition.
2. **Native v6→v6 guest egress** — the worker guest block dispatches IPv4 (`process_guest_tx`)
   and NAT64 v6→v4 (`process_guest_tx_nat64`); a native v6→v6 encap path has NO shared-core
   orchestrator yet, so a v6-native `Deliver::Local`/encap is never produced. Core gap, not
   serve wiring.
3. **DPDK-hotplug live dead-slot recovery** — recreate the veth + `rte_dev` hotplug
   detach/attach the af_xdp vdev + reconfigure the ethdev port, so a slot killed by a
   netns-destroyed-without-detach recovers without a serve restart (today: detected + excluded).
4. **`shared_ct` GC/eviction sweep** — periodic reclaim of stale reverse entries via
   `shared_ct_for_each`/`_remove` (the primitives exist; the sweep does not).
5. **Startup-rollback consistency** — the serve `run()` startup sequence tears down created
   guest veths on a guest-port *configure* failure, but a later fallible startup call
   (`LcoreRing::new`, `SharedConfigMaps::new`) `?`-returns without that teardown, leaking the
   already-created veths on a rare startup failure. Wrap the whole startup in teardown-on-error
   for consistency (startup-only, rare).

## Cross-refs

- DPDK per-lcore shared-nothing model: M8 (`design/flowplane-dpdk`).
- Externalized conntrack for upgrades: M11 hitless-upgrade slice (the shared_ct
  table + `for_each`/`remove` are a step toward it).
- None of these affect the eBPF datapath or the sim byte-parity guarantees.
