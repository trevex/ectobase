# Dataplane design review — 2026-09-17

Scope: the whole networking stack against the stated goal — GCP-like cloud networking
(VPCs, peering, network policies, VMs/containers, public connectivity) that is resilient
and scalable across multiple Kubernetes clusters. Five parallel deep-reads (overlay
datapath, multi-cluster control plane, intent model, N/S edge, workload attach/offload),
with the highest-impact claims re-verified by hand.

## Verdict

The architecture is coherent. The core decisions compose cleanly and are consistently
applied:

- **Routed L3 Geneve overlay, pure eBPF (netkit/tcx), host-routes only** — one delivery
  model (`INTERFACES[(vni, ip)]`) shared by E/W, peering (via `nexthop_vni` in the tunnel
  key — zero datapath code for peering), LB DSR, and NAT return.
- **Stateless-where-it-matters edge** — Maglev ingress + peer-independent NAT reverse keys
  make any-edge-can-handle-any-packet true by construction; edge loss costs a recompute,
  not connections.
- **Intent → compile → broker-pull → agent materialize** — single write surface, per-pool
  namespaces, declarative re-converging sync at every layer; pools keep forwarding through
  central partition.
- **Two distribution planes** (CRD sync for policy, route bus for reachability) with
  per-VNI subscription scoping on the route side.
- Fail-safe instincts throughout: deny-by-default firewall, fence-before-reschedule,
  port-exhaustion drops instead of misdemux, exact-match underlay announce authz
  (`mesh/reflector/underlayauthz.go:65`), zero-drop graceful restart.

The problems are not architectural. They fall into five buckets: (1) a handful of real
correctness bugs, (2) hard scale ceilings that contradict the multi-cluster ambition,
(3) control-plane resilience gaps (every central component is a SPOF today), (4) a policy
model too thin for the GCP-like goal, and (5) accumulating v4/v6 and VM/container
asymmetries plus doc drift.

---

## Status at a glance (verified against `main`, 2026-09-19)

| Section | Done | Open |
|---|---|---|
| §1 Correctness (P0) | all seven (`0e2e601f`) | — |
| §2 Scale ceilings | firewall rule cap (firewall redesign, `acd0d55b` + `ec23ad68`); neighbor-NAT keyed tries (NAT return scaling Inc. 1, `f681d367`); NAT/public broadcast (NAT return scaling Inc. 3, `04d1fe52`) | map ceilings, conntrack pressure, IPAM + peering list costs, sizing doc |
| §3 Control-plane resilience | NAT/public prune (`a334ef8`), route-prune guard (`cb4188e6`), fence completeness (`a4dd915`), dispatch-controller leader election (`54dda54c`), lossless route-bus snapshots (NAT return scaling Inc. 2, `545ae93a`) | edge `/readyz` not consumed, `replicas: 1` everywhere, `GenerationApplied`, broker sync ordering, NAT/public record ownership (4b), a reconnect torn down by its own stale session (4c) |
| §4 Policy model | priorities, `defaultPolicy`, FirewallPolicy validation, revocation (`b19cbb3`, `99d3880`, `acd0d55b`) | Route intent, source selectors, remaining validation, peering-overlap warning |
| §5 Symmetry | — | all items |
| §6 Doc drift | overlay MTU, NAT return wording | the rest of the list |

## Status: the P0 batch is done (2026-09-17)

All of §1 is fixed, each with a failing test written first (`make ci` green; 185 sim/core
tests), and merged to `main` in `0e2e601f`. Two findings did not survive scrutiny and are
corrected in place below — 1.3's IPv6 half and part of 1.4.

Privileged gates run and passing: `make verifier` **and** `make sim-anchor` (all five
`BPF_PROG_TEST_RUN` byte-parity anchors — uplink/LB/DNAT fail-safe, `guest_tx` encap
byte-identical to the native sim, DHCP against both the native sim and the original golden).

One coverage note found while checking that the DHCP golden legitimately did NOT move: that anchor
seeds `DHCP_CONFIG` with an explicit MTU, so it covers the CONFIGURED path only. The fallback MTU
fixed in §1.7 has no bytecode anchor and is covered by the sim oracle alone. Production always
writes `DHCP_CONFIG`, so this is acceptable — but it belongs on the Makefile's "NOT YET ANCHORED"
list alongside DHCPv6, ARP/ND and the NAT64 translation.

`make verifier` caught a real regression the non-privileged gate could not see: `xdp_uplink_v6` stopped loading ("combined stack size of 3 calls is 640"),
bisected to the v6 LB key fix — a 24-byte `LbKey6` plus two 16-byte arrays for `hash_v6` where the
old code hashed 4-byte truncations. Fixed by streaming the hash from the packet, restructuring the
v6 ICMP rewrite to hold one address at a time, and out-of-lining the packet-free helpers. Both
program groups now load in ~1s (was 12s at 984k of the 1M insn limit).

**Two lessons worth carrying:**

- `make verifier` belongs in the definition of done for any datapath change. `make ci` cannot
  see stack or insn-limit regressions at all.
- These programs sit close enough to the verifier's limits that the next feature on the v6 uplink
  path probably needs a **tail call**, not more inline-attribute shaving. Note also that
  out-of-lining is NOT uniformly safe: `wan_rx`'s glue passes raw `data`/`data_end`, so a
  packet-reading callee there fails with "R3 pointer arithmetic on pkt_end prohibited". Packet-free
  helpers out-line safely anywhere; packet-reading ones only off `process_uplink*`.

## 1. Correctness bugs (P0) — FIXED

### 1.1 SNAT is dead for auto-allocated NICs *(verified)*
`NATGatewayReconciler.Sync` collects NAT sources from `nic.Spec.IPs`
(`mesh/controllers/natgateway.go:75`), but the compiler matches allocations against
`nic.Status.AllocatedIPs` (`mesh/controllers/compilednic.go:209`) — and the whole rest of
the system treats status as the only truth for overlay IPs. A NIC that auto-allocates
(spec.IPs empty — the normal path) produces zero NAT sources: no SNAT. The unit test
masks it by always setting `Spec.IPs` (`natgateway_test.go:20`).
**Fix:** collect sources from `Status.AllocatedIPs` gated on `State == Allocated`; add an
auto-allocation test case.

### 1.2 v6 LB keying collides on the last 4 address bytes
The v6 LB/Maglev key uses only the final 4 bytes of the IPv6 LB address
(`flowplane-core/src/lb.rs:53-67`). Two LB addresses in the same `/64` sharing a `last4`
silently share one backend table.
**Fix:** key on the full 16 bytes (or a proper hash of them) in `LbKey`/`MaglevKey`.

### 1.3 IPv4 fragments poison firewall + conntrack keys — v6 half WITHDRAWN
`l4_ports` read L4 at `ip_off + ihl` off the protocol byte alone with no `frag_off`/MF
check (`flowplane-core/src/parse.rs`). Every IPv4 fragment carries the original protocol
number but only the first carries an L4 header, so non-first fragments had payload bytes
returned as ports — feeding firewall matching, conntrack keys, Maglev hashing and NAT
demux, and `snat_egress` wrote a "source port" into the payload.
**Fixed:** non-first fragments key as `(proto, 0, 0)` (so fragments of one datagram share a
key and no payload is read or written as a port); paths that require an L4 translation drop
via a new `SnatOutcome::Untranslatable`. Limitation documented in `docs/features/nat.md`.

**The IPv6 extension-header half of this finding was wrong.** Every fixed-offset v6 L4 read
is already gated on `nexthdr ∈ {TCP, UDP, ICMPv6}` (`parse.rs` `l4_ports_v6`,
`inner_flow_hash_v6`, `icmp_type_code_v6`; `lb.rs` v6 select). An EH-bearing packet has
`nexthdr` = the EH number, so all of them bail out and it keys consistently as
`(eh_proto, 0, 0)`. Such traffic is unsupported (a port-specific rule won't match it) but it
was never misparsed. Nothing to fix.

### 1.4 Firewall fails open on unkeyable frames — real on egress, not on ingress
`ct_key`/`ct_key6` return `None` only for a frame too short to hold an IP header (an
unrecognised L4 still keys as `(proto, 0, 0)`), and keying is what gates the firewall.
**On guest egress this was a real leak:** the firewall ran only inside the `ct_key == Some`
branch and the route step then returned `Action::Pass`, so a guest could truncate its own
frame, skip a deny-by-default policy, and have it passed into the host stack. Fixed in both
`process_guest_tx` and the shared `egress_fw_ct6`.
**On uplink ingress it was unreachable**, not exploitable: the caller resolves the inner dst
(needing strictly more bytes than `ct_key` does) and drops first. Both arms were still
changed to `true` so the "unkeyable ⇒ dropped" invariant holds locally rather than depending
on call ordering.

### 1.5 NAT has no ICMP-error handling (PMTUD broken for SNAT flows)
LB has a dedicated embedded-packet ICMP-error relay (`lb.rs:78-230`); NAT has none.
Inbound ICMP errors addressed to a `nat_ip` are demuxed via `l4_ports`' echo-id heuristic
(`parse.rs:28-31`) and fail; guest-originated ICMP errors get bytes 4–6 rewritten by
`snat_egress`'s echo arm (`nat.rs:213-221`), corrupting the embedded packet. Path-MTU
discovery and unreachables are effectively broken for all SNAT traffic, both families.
**Fix:** port the LB relay pattern to NAT — parse the embedded original packet, reverse
the SNAT on both outer dst and embedded header, forward to the owner.

### 1.6 IP-options packets skip NAT/LB rewrites but are still forwarded
`ct_apply` returns without rewriting when `IHL != 5` (`conntrack.rs:203-205`; same in
`nat.rs`). Such packets continue un-translated — wrong addresses on the wire instead of a
drop.
**Fix:** drop when a required rewrite can't be applied.

### 1.7 DHCP fallback MTU misses the DSR reserve *(verified)*
The configured guest MTU correctly reserves 80 bytes (Geneve 56 + DSR option 24;
`ENCAP_OVERHEAD_V6 == 80`, `flowplane/src/cli/serve.rs:526-536`), but the DHCP responder's
no-config fallback advertises `1500 − 56 = 1444` (`flowplane-core/src/dhcp.rs:268`).
`docs/concepts/overlay.md` also still says 56.
**Fix:** fallback should subtract `ENCAP_OVERHEAD_V6`; fix the doc. Related residual gap:
inbound full-size **UDP** from internet clients (which never saw the guest MTU) can exceed
the underlay MTU on the DSR path with no ICMP-too-big generated anywhere — worth an
explicit edge-side check + ICMP reply (TCP is saved by guest MSS).

---

## 2. Scale ceilings vs the multi-cluster ambition (P1/P2)

These are all fine for the current lab; none survive a fleet. Each needs either a raise, a
redesign, or an explicit documented budget.

| Ceiling | Where | Why it breaks |
|---|---|---|
| **16 firewall rules** per interface per family, shared across directions | `FW_MAX_RULES`, `fw.rs:11`; linear scan `firewall.rs:173-181` | Cloud policy sets are routinely 10–100× this. The sharpest expressiveness limit in the system. NOTE: this row originally said "per direction", copying `FW_MAX_RULES`' own doc comment, which is also wrong — the handler partitions by family and each family's 16 slots are shared between ingress and egress (doc comment fixed in `1dea63d`). **PARTLY ADDRESSED (firewall redesign increment A):** the cap still stands, but it is no longer silent — the compiler enforces it, drops shadowed rules before counting, keeps the last good rule set and reports `FirewallCompiled=False/RuleBudgetExceeded` on the NIC (`99d3880`); the dataplane answers an over-cap replace with `ResourceExhausted` and no longer half-commits v4 before refusing v6 (`1dea63d`). The cap itself goes with the LPM classifier (increment B). **RESOLVED (firewall redesign B + C2):** the datapath evaluates a two-stage LPM classifier whose cost is constant in the rule count; the slot table and its 16-per-family check are deleted (C2), and the compiler's budget is a 256-per-family quota under the dataplane's per-scope limits (4096 classes / 16384 policy entries). |
| **64 neighbor-NAT entries fleet-wide**, linear scan per WAN-return packet | `maps.rs:96-113` | Caps the whole fleet at ~64 advertised NAT port-blocks per family. **RESOLVED (datapath; NAT return scaling Increment 1, merged in `f681d367`)**: the 64-slot linear-scan `NEIGHBOR_NAT{,6}` maps are gone, replaced by keyed LPM tries `NAT_OWNERS{,6}` (65,536 prefixes per family; a default 1024-port block is one prefix), giving constant-cost lookup regardless of block count. Errors are now typed: overlap with another block on the same `nat_ip` in any VNI is `AlreadyExists`, a full trie is `ResourceExhausted`, an empty range is `InvalidArgument` (before: every error was `Internal`). `adopt_nat_owners()` rebuilds the block list from the trie after a restart and repairs a partial block — before, nothing rebuilt the list. `purge_vni` now purges v6 blocks too (it purged only v4). Upgrade caveat: the loader unpins the old slot maps without converting their blocks, so an edge's existing remote NAT blocks go unrelayed until its mesh agent reconnects and replays them — restart the edge's agent after the dataplane upgrade. **Known gap (found in the final review) — CLOSED** by Increment 3's declarative replace (`ReplaceNeighborNats`, pinned by `make ha`'s third adopt incarnation): if the dataplane and the agent both restarted while a block was withdrawn or reassigned, the adopted block used to stay listed forever — the new agent pruned only what it had installed itself — kept relaying to the old owner, and refused an overlapping successor as `AlreadyExists`; the old slot table instead hid every still-valid block at the first add after a dataplane-only restart (nothing rebuilt its list, and the rewrite reset the count). DISTRIBUTION is no longer fleet-wide either: Increment 3 registers only WAN edges for the NAT/public feed (see the next row, now RESOLVED). |
| **NAT/public route-bus records broadcast to every node** | `mesh/reflector/nattable.go:23-93` | O(blocks × nodes) fanout; the dominant term at fleet scale. Route records are per-VNI-scoped — NAT/public should be too (edges + owning nodes only). **RESOLVED (NAT return scaling Increment 3, merged in `04d1fe52`)**: `Hello.global_feed` lets a session opt out of the GLOBAL channel; only WAN edges register for the NAT/public fanout, and a compute node holds no neighbor-NAT blocks at all, so fanout is now O(records × edges), not O(records × nodes). The edge keeps its table in sync with one declarative `ReplaceNeighborNats` per complete snapshot, rather than incremental per-block programming. |
| 1024 interfaces / 1024 taps per node | `INTERFACES`, `PORT_META` | Dense container nodes exceed this. |
| 65,536 routes per family per node | `ROUTES{,6}` | Every guest is a host route; peering imports multiply it; multi-cluster growth is linear in fleet size. |
| MAGLEV 65,536 slots shared ÷ 1021/table | `maps.rs:57` | ≈64 LB services per node/edge. |
| 1M-entry LRU conntrack, silent eviction | `maps.rs:61-111` | Evicting a SNAT reverse entry breaks the flow with no fallback demux. Needs pressure metrics + sizing story. |
| IPAM: uncached list-all-siblings per allocation, single-threaded | `nicipam.go:224-225`, `lbip.go:159` | O(N²) API work to fill a subnet. Cache the used-set per pool, invalidate on events. |
| Cluster-wide `VPCPeering` list on **every NIC reconcile** | `compilednic.go:267` | Index by VPC, or watch-driven cache. |
| Single apiserver + kine + reflector + compiler, all `replicas: 1` | charts | See §3. |

**Proposed direction for the two worst:** (a) replace the per-iface 16-slot firewall
encoding with an LPM/array-map program-per-policy or rule-batch layout sized in the
thousands, and (b) make NAT/public route-bus records subscription-scoped with a proper
keyed map (`(nat_ip, port_block)` hashmap, not a 64-slot scanned array) — both are
self-contained increments.

**Found later (2026-09-19, firewall redesign increment B): same-node conntrack bypass — FIXED**
(`fix(datapath): a flow the destination refuses must not ride conntrack`). Same-node delivery
enforced the destination's ingress firewall only on a NEW flow, after the flow's conntrack entries
(forward + pre-seeded reverse) had already been created; a refused flow's later packets were CT hits
and were delivered, and the destination could reach the source along the reverse entry past both
firewalls. v4 and v6, sim and eBPF. The refusal now removes the entries the flow created.

## 3. Control-plane resilience gaps (P1)

1. ~~**NAT/public channel has no snapshot-prune.**~~ **FIXED** (`a334ef8`). The reflector
   closes its global replay with a new `EndOfGlobal` marker and the agent prunes unreplayed
   NAT blocks and LB backends against it, dropping a load balancer whose last backend is gone.
   The marker carries the replayed record count and the agent prunes only on an exact match:
   a sink drops on overflow, so pruning against a lossy snapshot would withdraw LIVE state —
   strictly worse than the staleness (the reflector no longer drops snapshots: Increment 2). This
   exposed a pre-existing sibling hazard:
   prune-on-EndOfRIB had the same lossy-snapshot exposure for routes and no count guard.
   **Fixed since** (`cb4188e6`, merged in `379dd45`): `EndOfRIB` carries the replayed record
   count, counted from when the Subscribe is sent, and the agent prunes routes only on an exact
   match.
2. ~~**Edge anycast has no readiness gating.**~~ **HALF FIXED** (`c7f779b`). `Bus.Converged`
   (global snapshot + EndOfRIB for every subscribed VNI, latching) is exposed over
   `--health-addr` `/readyz`. But nothing consumes it yet: the lab advertises the public
   prefixes from static VyOS `network` statements, so a lab edge still attracts ECMP before
   converging. **Remaining:** gate a real deployment's advertisement on `/readyz`.
3. ~~**Tier-2 fence completeness depends on stale broker state.**~~ **FIXED** (`a4dd915`),
   and the finding was only CONDITIONALLY real. Each node stamps its own underlay masked to a
   `/64`, so in the single-`/64`-per-cluster topology every node's identity is a `/128` inside
   one shared prefix and fencing it already covered nodes central never observed. The real
   exposure was a cluster spanning several `/64`s, which nothing enforced or documented.
   Central now decides explicitly: a new `ClusterPool.spec.underlayPrefix` declares the
   cluster's underlay aggregate (complete by construction, central config rather than
   broker-reported — a fence coordinate must not come from the entity being fenced); with it
   unset, one distinct reported `/64` still counts complete, and several do not. The
   unprovable case fences what is known and blocks the **rebind** — containment is free,
   reattaching the disk is the step that corrupts. Also note: a placement cross-check was
   considered and rejected — `CompiledVM.status.placement` comes from the same broker, so it
   freezes at the same instant and cannot see the node either.
4a. **Found 2026-09-19 (NAT return scaling research) — route-bus snapshots are lossy by
   construction.** `Session` (`mesh/reflector/server.go`) creates a 1024-slot non-blocking sink and
   registers it — which replays the NAT/public snapshot into it under the RIB lock — BEFORE the
   goroutine that drains it starts; `chanSink.Send` drops on a full channel. A global snapshot of
   ≥1024 records therefore always loses records and usually the `EndOfGlobal` marker itself, so the
   session never prunes and never reports converged. Per-VNI `Subscribe` replays use the same sink:
   a VNI with more routes than the drain keeps up with loses records the same way (the count guard
   prevents a wrong prune, not the non-convergence). Planned: NAT return scaling, Increment 2.
   **RESOLVED** (NAT return scaling Increment 2, merged in `545ae93a`): a session
   queue keeps every snapshot whole — global and per-VNI, each handed over to the sink as one
   batch under the RIB lock — so a session always converges; only live deltas past 1024 queued and
   not yet taken by the drain are dropped (the reflector logs each drop episode and the total when
   the session ends). Pinned by 5000-record global and VNI snapshots delivered through a real
   `Session`. Still open: a dropped live delta is repaired only by the consumer's next reconnect,
   which nothing forces.
4b. **Found 2026-09-19 — NAT/public record ownership is not enforced.** `WithdrawNat` /
   `WithdrawPublic` carry no certificate guard and no ownership check, so any authenticated session
   can withdraw any record; `AnnounceNat` on a key another origin holds overwrites it without moving
   it out of the old origin's set, so the old origin's disconnect later withdraws the new owner's
   block. `Hello.node_id` is also self-asserted and not bound to the certificate. Planned (all but
   the node_id binding): NAT return scaling, Increment 4.
4c. **Found 2026-09-19 (Increment 2 review) — a reconnect can be torn down by its own stale
   session.** Sinks, subscriptions and origins are keyed only by `Hello.node_id` (`r.sinks`,
   `r.subscribers[vni]`, `r.byOrigin`, `r.natByOrigin`, `r.publicByOrigin`), and `Session`'s
   deferred cleanup (`mesh/reflector/server.go`) removes by that id — `RIB.UnregisterSink`
   (`nattable.go`) and `RIB.DropOrigin` (`rib.go`) both delete unconditionally, with no notion of
   which session instance registered the entry. If a node reconnects before its old session's
   `Recv` fails (silent path loss: the reflector's keepalive is a 2 s ping + 3 s timeout, so the old
   session lingers ~5 s), the new session registers under the same id, and the old session's
   eventual cleanup unregisters the NEW session's sink, drops its subscriptions from every VNI, and
   `DropOrigin` withdraws its freshly announced routes and NAT/public records fabric-wide. The new
   session is left connected but deaf, its announced state withdrawn; the agent sends only
   changes, so it re-announces nothing until its next reconnect.
   Related to the self-asserted `node_id` (4b). Not fixed; candidate for Increment 4 (a per-session
   generation/token so cleanup only removes what that session itself registered).
4. ~~**dispatch-controller has no leader election**~~ **FIXED** (`42c6ea1d`, merged in
   `54dda54c`): the manager takes a Lease (`ectobase-dispatch-controller`, host
   kube-apiserver, `ReleaseOnCancel`) before starting any reconciler, with lease RBAC in the
   generated ClusterRole and a chart test pinning it. An envtest test builds two managers from
   the binary's own options and asserts one leader and a handover inside the lease duration
   (mutation-checked: without the release it waits out the 15 s lease). The chart stays at
   `replicas: 1`; scaling it for a standby is now safe. Original finding: no election while the
   compiler has one — safe only at `replicas: 1`, and even then a rolling restart overlaps two
   pods, so Tier-2 failover could double-fire.
5. **Every central component is a SPOF** (apiserver, kine, reflector, compiler,
   dispatch-controller — all `replicas: 1` in the charts). The design degrades correctly
   (pools keep forwarding), but convergence stops fleet-wide. The reflector is the
   sharpest: in-memory RIB, no persistence — restart = full fabric re-announce storm
   (mitigated by jittered backoff, but still a fleet-wide convergence event).
   At minimum: reflector active/standby with session-handoff, HA kine/Postgres.
6. **`CompiledNIC.status.GenerationApplied` is dead** — never written or read
   (`api/compiled/.../compilednic_types.go:146`). Either wire generation tracking through
   broker → agent (useful for "is my intent live yet?" UX and for debugging partial
   sync), or delete the field.
7. **Broker multi-type sync is sequential without ordering guarantees** — a failure
   mid-sequence leaves e.g. updated CompiledVMs against stale CompiledVolumeAttachments
   until requeue (`dispatch/cmd/broker/main.go:424-435`). Converges eventually; worth a
   note in the docs and ideally a per-type error budget/metric.

## 4. Policy/intent model vs the GCP bar (P2, but decide now)

- ~~**Firewall ordering across policies is undefined.**~~ **FIXED** (`b19cbb3`, `99d3880`).
  Policies and rules carry a GCP-style `priority` (0-65535, lower wins, unset = 32768); the
  compiler ranks by `(policy priority, rule priority, namespace, name, index)` and drops rules
  a higher-ranked rule fully covers. Output is byte-identical under shuffled list order. Ties
  (and the deliberate choice that equal-priority ties break by name, not deny-wins) are
  documented in `docs/features/firewall.md`. Original finding: datapath is first-match-wins, but
  multiple FirewallPolicies matching one NIC were concatenated in API list order.
- ~~**`VPCSpec.DefaultPolicy` is dead**~~ **FIXED** (`99d3880`): `Allow` appends an implicit
  lowest-priority allow-all per family (so a lone Deny denies only its match), `Deny`
  synthesizes nothing (unselected interfaces close too), unset keeps per-direction
  NetworkPolicy semantics; the VPC reports the posture on a `FirewallDefault` condition.
  The lone-Deny trap remains, by definition, under the unset posture only (documented).
  Original finding: a VPC set to `Deny` silently got default-allow.
- **No Route intent at all** — no custom routes, no priorities, no next-hop steering.
  Fine to defer, but it's the largest single semantic gap vs a GCP VPC; the route-bus +
  LPM machinery could carry it.
- **Firewall sources are CIDR-only, targets label-selector-only** — no tag/service-account
  analog for source matching. The label-selector direction is right; extend it to source
  matching (compile source-selector → the matching NICs' IPs, updated on churn).
- ~~**FirewallPolicy is entirely unvalidated**~~ **FIXED** (`b19cbb3`): create AND update
  admission checks selector, action/proto enums, port range and port-needs-TCP/UDP, CIDR syntax
  and canonical form, priorities; VPC `defaultPolicy` is enum-checked. Pinned by an aggregated-
  apiserver integration test (markers never run there). Still open: VPC VNI pin range-check and
  NATGateway validation. Also still open, found on the way: the other `Validate` hooks
  (Subnet, NIC, LB, LBPool) implement create only — an update bypasses them.
- ~~**Policy revocation doesn't reach established flows for up to 24 h**~~ **FIXED**
  (firewall redesign increment B5, `fb3966e7`, merged in `acd0d55b`) — not by a sweep: a node-wide
  firewall epoch (`FW_EPOCH`), bumped after every `FW_BIND` change, is stamped into each
  conntrack entry (`CtEntry.policy_epoch`, carved from the pad; 24 B unchanged). A FORWARD
  entry hit under an older epoch meets the firewall again at that hook (guest egress v4/v6
  incl. the same-node destination check, uplink ingress v4/v6); a refusal drops and forgets
  the flow. Pre-seeded reverse entries carry `CT_F_REPLY` and, like NAT reverse entries, are
  never re-evaluated. A bare TCP SYN on a tracked tuple is always re-evaluated (Calico's
  port-reuse rule). The stamp is the epoch read BEFORE the evaluation, and the dataplane
  writes the binding before it bumps, so a racing change can only cause an extra
  re-evaluation, never a stale verdict marked current. Hardware-offloaded flows: a stale
  forward entry stops being offload-eligible, so the manager withdraws it within one
  reconcile interval. Contract documented in `docs/features/firewall.md` ("Connections and
  policy changes"). Correction to the plan: it put a per-scope generation in `FwMeta`; a
  per-interface or per-scope stamp cannot cover the same-node path (two interfaces'
  policies, one u8/u32 slot), and a node-wide epoch costs one array read per packet instead
  of a hash lookup — every forward flow on the node re-evaluates once per change.
- **Upgrade caveat (B5 + C2):** `CONNTRACK{,6}` are pinned and survive a restart-upgrade.
  Entries written by a pre-classifier dataplane carry no `CT_F_REPLY` and a zero epoch; the
  first epoch bump after the upgrade (the agent's first re-push binds every interface) makes
  their reverse entries look like stale FORWARD entries, so replies of pre-upgrade connections
  are re-evaluated as new flows in the reply direction and dropped where policy does not allow
  that direction. Pre-production, so not engineered around; an upgrade that must keep
  connections would flush conntrack or mark pinned reverse entries first. The retired
  `FW_RULES`/`FW_META{,6}` pins are removed at load (C2), covered by `make ha`.
- **Found in C2, not by any gate:** the classifier (B4) refuses a rule that matches the
  interface's own address, and the live lab LB tests (`test/lab/livetest/lb_test.go`) opened
  their backends with exactly such a rule (`dst_cidr: <backend IP>` on an ingress rule), so
  their firewall setup would have failed from B4 on. The lab can't run in the gates, so nothing
  noticed. Fixed in C2 when the live tests moved from the removed `AddFwRule` to the declarative
  `ReplaceInterfaceFirewall`: the LB rules now name the client peer (`::/0` / `0.0.0.0/0`,
  TCP/80). Compiled under the `live` tag; **not run** — the next lab run is their check.
- Peering: non-transitivity is enforced structurally (good — matches GCP); overlap
  non-rejection is a deliberate deviation (local-precedence). Fine, but surface a warning
  condition on the peering when exposed prefixes overlap the local VPC's subnets.

## 5. Symmetry/coherence debt

The single biggest *pattern* across all five reviews: features land on one axis and don't
get mirrored, and each gap is individually "known" but the set is growing.

- **v4 vs v6:** conntrack idle-aging sweeps v4 only (`serve.rs:210-213` — `CONNTRACK6`,
  `NAT_CT6`, `DSR6` are LRU-only, never idle-aged); v6 ingress policing missing
  (`uplink.rs:464-468`); floating IP v4-only; ICMPv6 echo intercept missing.
- **Same-node vs cross-node:** local delivery bypasses *both* QoS lanes (no EDT shaping,
  no ingress policing — `tc.rs:173-196`); qos.md documents only the shaping half.
- **VM vs container:** VMs get no `bpf_redirect_peer` fast path (understood — mirred
  incompatibility) and netkit-L2 vs L3; fine, but multi-NIC is broken on **both** paths —
  the container materializer writes only `Interfaces[0]` into the single-valued
  annotation, so a two-NIC pod resolves both ADDs to the same CompiledNIC
  (`podmaterializer.go:42-57`), while docs frame multi-NIC as a VM-only gap.
- **Offload vs conntrack:** offloaded flows never refresh `last_seen`; a busy offloaded
  flow is GC'd at the 24 h established timeout, tearing down the HW filter and forcing a
  fresh firewall evaluation mid-flow (`offload.rs` vs `conntrack_gc.rs`). **Fix:** have
  the offload manager write back liveness to the CT entry when HW counters advance.
  (Since B5 the manager also withdraws flows whose conntrack epoch is stale, so a policy
  change reaches offloaded flows within one reconcile interval; liveness is still open.)
- **Sim-oracle coverage:** floating-IP egress SNAT/DNAT lives only in raw eBPF
  (`flowplane-ebpf/src/floatingip.rs`), outside `flowplane-core` — it is invisible to the
  sim oracle, violating the project's own "sim must test all cases" rule. Move it into
  core.
- **No live migration story:** Tier-2 is cold failover only; in-cluster KubeVirt live
  migration would strand the netkit/tap plumbing, per-node conntrack, and offloaded
  filters. If live migration is on the roadmap, the conntrack-portability question decides
  the design; decide it before more per-node flow state accretes.
- No BUM/multicast in the overlay (consistent with the routed-L3 model — keep it, but
  state it as a product boundary).

## 6. Doc drift (quick sweep, all low-effort)

- ~~`docs/concepts/overlay.md` — 56-byte overhead → effective reserve is 80.~~ **FIXED**
  (`59c46c15`): the page now gives the 56-byte header and the 80-byte advertised reserve.
- `docs/features/qos.md` — presents ingress policing with no family caveat; the v6 uplink
  (`xdp_uplink_v6`) has none. Same-node bypass of ingress policing undocumented (the page
  covers only the shaping half).
- `docs/features/ns-edge.md:165-168` + `mesh/agent/public.go:80` — `learnedEdge`
  return-path pinning described as live; `LearnedEdge()` has no production caller (dead
  code — delete or wire).
- `docs/architecture/kubevirt-integration.md` / `cni-integration.md` — say veth + literal
  `tap0`; code uses netkit-L2 and derives/rejects `tap0` (`attach/naming.rs:77-89`).
- `attach/mod.rs:44-45` — stale "fails ... until B.4 lands" comment on the *default* container
  path (B.4 landed); would misdirect an incident.
- `mesh/reflector/admin.go:19-21` — stale `TODO(authz)`; CN-gating is implemented.
- Broker `main.go:6-7,180` — says "filtered by spec.clusterName"; it's namespace-scoped.
- `docs/features/nat.md` — ~~v4-only return wording~~ **FIXED** (`a3f5089a`: the return path
  now covers both families over `NEIGHBOR_NAT`/`NEIGHBOR_NAT6`); still open: `:159` says NAT64
  "reuses" the egress path — it's a separate subsystem. `routing-vni.md:4` "VXLAN" → Geneve.
- "Scaffold-only" markers on FirewallPolicy/LoadBalancer types that are fully compiled.
  (FirewallPolicy's fixed in `b19cbb3`; LoadBalancer's remains.)
- `Subnet.status.V4Total/V6Total` include network/broadcast the allocator excludes
  (`subnet.go` `totalHosts`), while the API field doc says "allocatable".
- `docs/features/loadbalancer.md` "Direct server return" says the inner destination stays the LB
  address all the way to the backend; the edge's N/S DSR encode (`datapath::process_wan_rx`)
  rewrites it to the backend's overlay IP. Verify per LB path and correct. (Its firewall section
  was rewritten in firewall redesign C2 — the old "`LB address:port` rule" advice was wrong
  for `FirewallPolicy`, whose rules name the peer, never the local address.)

## 7. Suggested sequencing

1. ~~**P0 correctness batch**~~ — **DONE**, see the status note at the top. The carried-over
   `make verifier` run against the ICMP-relay rewrite windows is done too (`b4662df`, which
   also brought `xdp_uplink_v6` back under the stack limit); the verifier has passed on every
   datapath merge since.
2. **N/S resilience pair:** ~~NAT/public snapshot-prune~~ (done, `a334ef8`) + edge readiness
   gating (half done, `c7f779b`: `/readyz` exists, nothing gates an advertisement on it yet).
   These two close the only "silent traffic loss with no self-healing" paths in the system.
3. ~~**Failover safety:** fence completeness + dispatch-controller leader election.~~ Both done.
4. **Scale groundwork:** ~~firewall rule-storage redesign~~ (done: the LPM classifier,
   `acd0d55b` + `ec23ad68`), NAT/public subscription scoping + keyed neighbor-NAT map. Write
   a sizing doc making every remaining map ceiling an explicit budget.
5. **Policy semantics:** ~~firewall priority field, DefaultPolicy wire-or-delete,
   FirewallPolicy admission validation~~ (done, firewall redesign increment A),
   ~~revocation-vs-established-flows contract~~ (done, increment B5: CT epoch).
6. **Symmetry debt:** v6 conntrack aging, v6 ingress policing, floating-IP into core (sim
   coverage), offload liveness write-back, multi-NIC container fix.
7. **Docs sweep** (one PR, list above).
