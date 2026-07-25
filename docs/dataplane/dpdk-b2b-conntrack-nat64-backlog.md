# DPDK B2b datapath backlog — conntrack + NAT64 gaps

Status: **tracked, not yet fixed** (2026-07-25)

These three findings came out of the 2026-07-25 datapath correctness sweep. All
three are **latent**: they are NOT reachable on the shipping eBPF datapath, and
they do not bite the DPDK backend *today* because the DPDK `serve` loop wires only
uplink RX — guest egress (which creates the forward SNAT conntrack), multi-queue
guest egress, and NAT64 are not in the serve loop yet. Each becomes reachable at a
specific DPDK B2b milestone (noted per item). They need real ConnectX hardware to
validate, so they are captured here to be actioned when B2b is picked up rather
than fixed blind now.

The eBPF backend has none of these gaps (single shared conntrack map; `ct_touch`
called on every CT hit; full NAT64 ingress path).

---

## 1. Per-lcore NAT/LB return demux misses under RSS steering (HIGH, architectural)

**Where:** `flowplane/nfkit/src/per_lcore_flow.rs` (`PerLcoreFlowMaps` — per-lcore
shared-nothing conntrack), `flowplane/nfkit/src/rss.rs` / `port.rs` (RSS key +
`RSS_IP`-only steering), return demux in
`flowplane/flowplane-core/src/datapath.rs` `process_uplink_rx` →
`process_uplink_nat_return`.

**Root cause:** DPDK conntrack is per-lcore shared-nothing. A SNAT/NAT64 egress
installs the peer-independent reverse entry `(vni,0,nat_ip,0,nat_port)` into the
conntrack table of the lcore that processed the guest's *outbound* packet. The
external reply arrives on the uplink and is steered to a queue/lcore by the NIC's
RSS over the **outer/underlay** headers, which has no relationship to the inner
flow tuple the reverse entry was keyed under. The symmetric-Toeplitz key only makes
a *mirror-tuple* land on the same lcore — it does not bind an encapped egress
packet and a bare-IPv4 WAN reply. If the reply lands on a different lcore,
`conntrack_get(rev)` misses → the return is treated as a new inbound flow
(ingress-firewall drop / wrong-or-no reverse-DNAT).

**Reachable when:** guest egress is wired into the DPDK serve loop AND
`n_queues > 1` (multi-lcore). Blocked today because guest egress isn't in the serve
loop, so no forward SNAT CT is created in-process at all.

**Fix direction:** externalize conntrack to a shared table for NAT/LB flows, OR
steer returns by a flow-affinity mechanism that accounts for the NAT rewrite
(rte_flow `MARK` / a flow-director rule keyed on `nat_ip:nat_port`), not raw
outer-IP RSS. Ties into the M11 hitless-upgrade externalized-conntrack work.

**Confirm with:** a two-lcore DPDK test — create a forward SNAT CT on lcore 0's
`PerLcoreFlowMaps`, feed the matching WAN reply whose outer dst RSS-hashes to
lcore 1, assert the reverse-DNAT fires (it won't today).

---

## 2. `ct_touch` (last_seen / TCP-state refresh) is not in the shared-core seam (HIGH)

**Where:** `ct_touch`/`ct_touch6` exist ONLY in the eBPF backend
(`flowplane/flowplane-ebpf/src/conntrack.rs:57,145`). The shared orchestrators in
`flowplane/flowplane-core/src/datapath.rs` only ever *create* conntrack entries;
they never refresh an existing entry on a hit — documented as a deliberate seam
boundary at `datapath.rs:125,144` ("ct_apply/ct_touch is NOT ported... map/refresh-
only... does not change the emitted bytes", so the byte-parity anchor doesn't need
it).

**Root cause / impact:** on the sim and DPDK backends, a conntrack entry created for
a NAT reverse mapping keeps `tcp_state = 0` forever, so `timeout_ns` always returns
the 30s idle timeout, never the 24h ESTABLISHED-TCP timeout; and `last_seen` is
never bumped on established traffic. A GC keyed on `ct_is_expired` evicts active
NAT'd TCP flows after 30s idle → the SNAT port is freed/reused mid-flow →
reverse-mapping loss.

**Reachable when:** the DPDK serve loop runs a conntrack GC over flows it created
(i.e. once guest egress + a GC sweep are wired). The eBPF backend is unaffected (it
calls `ct_touch` on every CT hit from `ingress.rs`/`egress.rs`).

**Fix direction:** port a `ct_touch`-equivalent into `flowplane-core` (generic over
`Pkt`/`Maps`) and call it from the `datapath.rs` `process_*` paths on a CT hit
(refresh `last_seen` + `tcp_advance`). Since it changes no emitted bytes, the
byte-parity anchors stay valid; add a sim test that advances `now` past 30s on an
established TCP flow and asserts the entry survives (24h ESTABLISHED timeout).

**Confirm with:** the sim test above — today the entry expires at 30s; with the fix
it survives.

---

## 3. NAT64 ingress (v4→v6 reply) is unreachable on the DPDK serve loop (MEDIUM, documented)

**Where:** `flowplane/flowplane-core/src/datapath.rs` `process_uplink_rx`
(line ~334): the NAT-return branch fires only when
`CT_REWRITE_DST != 0 && CT_F_NAT64 == 0`. NAT64 reverse entries carry `CT_F_NAT64`,
so they fall through to the plain LB+base path (`process_uplink`) — delivering the
frame as a bare truncated IPv4 packet instead of expanding it back to IPv6 via
`process_uplink_nat64_ingress`. Explicitly acknowledged in the comment at
`datapath.rs:317-318` ("the DPDK serve loop does not model NAT64 yet").

**Root cause:** the unified DPDK dispatch does not route NAT64 returns to
`process_uplink_nat64_ingress`. The sim reaches that fn directly via
`SimNode::uplink_nat64_ingress`, so sim tests pass while the DPDK serve dispatch
does not exercise it.

**Reachable when:** DPDK serve is expected to handle NAT64 return traffic (a
functional-NAT64-on-DPDK milestone). Not silent corruption of a working path — a
known-incomplete path.

**Fix direction:** in `process_uplink_rx`, when the reverse CT entry has
`CT_F_NAT64`, dispatch to `process_uplink_nat64_ingress` (v4→v6 expansion) instead
of falling through to `process_uplink`.

**Confirm with:** drive `process_uplink_rx` with a frame whose reverse CT has
`CT_F_NAT64` set and assert v6 expansion (today it delivers plain IPv4).

---

## Cross-refs

- The DPDK per-lcore shared-nothing model: M8 (`design/flowplane-dpdk`).
- Externalized conntrack for upgrades: M11 hitless-upgrade slice.
- These do not affect the eBPF datapath or the sim byte-parity guarantees.
