# DPDK B2b datapath backlog — conntrack + NAT64 gaps

Status: **all three RESOLVED** (2026-07-25); **#1 + #2 now END-TO-END reachable on
the DPDK serve loop** since guest egress was wired in (2026-07-25, branch
`feat/dpdk-guest-egress`). #3 (NAT64 ingress) stays latent pending NAT64 *egress*
wiring (the first guest-egress slice is IPv4 SNAT only).

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

**Remaining (follow-ups):** the first slice is SINGLE guest port + SINGLE worker
(worker 0 owns the pool), so cross-lcore RSS demux is not yet exercised on the *live*
serve loop — that needs guest egress with `n_queues > 1` and multi-worker guest-port
partitioning (`multilcore_nat_return.rs` already proves the shared-table demux logic
itself). True concurrent-writer stress still needs a multi-threaded EAL test (current
tests drive lcores sequentially); a GC/eviction sweep over `shared_ct` (via
`shared_ct_for_each`/`_remove`) is not built yet. The rte_flow `MARK` hardware-steering
alternative (needs ConnectX) was intentionally not taken — the shared-table software
fix is correct without it.

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

**Remaining (latent):** still not reachable on the live serve loop. The first
guest-egress slice (`feat/dpdk-guest-egress`) wires only the IPv4 SNAT path
(`process_guest_tx`), which seeds plain `CT_REWRITE_DST` reverse entries — NOT
`CT_F_NAT64` ones. NAT64 ingress becomes end-to-end reachable once NAT64 *egress*
(v6 guest → v4 external) is wired into the serve loop to seed the `CT_F_NAT64`
reverse entries; the ingress dispatch itself is fixed + covered (sim) and ready.

---

## Cross-refs

- DPDK per-lcore shared-nothing model: M8 (`design/flowplane-dpdk`).
- Externalized conntrack for upgrades: M11 hitless-upgrade slice (the shared_ct
  table + `for_each`/`remove` are a step toward it).
- None of these affect the eBPF datapath or the sim byte-parity guarantees.
