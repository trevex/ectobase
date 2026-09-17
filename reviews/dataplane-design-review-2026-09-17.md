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

## 1. Correctness bugs (P0)

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

### 1.3 Fragments and v6 extension headers poison firewall + conntrack keys
`l4_ports` reads L4 at a fixed offset with no IPv4 `frag_off`/MF check
(`flowplane-core/src/parse.rs:15-34`), and the v6 path assumes L4 at `ip_off + 40` with no
extension-header walk (`parse.rs:40-55`). Non-first fragments and EH-bearing v6 packets
get garbage ports fed into firewall matching, conntrack keys, LB hashing, and NAT demux —
fragments of one flow can land on different LB backends or different NAT verdicts.
**Fix:** parse `frag_off`/MF; for non-first fragments either drop (documented) or key on
`(src, dst, proto, ipid)`; walk the v6 EH chain (bounded) or explicitly drop packets with
EHs. Whatever the choice, make it explicit and fail-closed, and add sim-oracle cases.

### 1.4 Firewall fails open on unkeyable frames
When a conntrack key can't be built, the uplink ingress gate returns "don't drop"
(`flowplane-core/src/datapath/uplink.rs:183-189`), and the egress firewall is only reached
inside the `ct_key(..) == Some` branch (`egress.rs:51`). Frames too short/odd to key
bypass a deny-by-default firewall. Combined with 1.3, a crafted fragment/EH packet is a
policy-bypass primitive.
**Fix:** unkeyable → drop, matching `fw_eval_dir`'s own fail-closed contract.

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
| **16 firewall rules** per direction per interface | `FW_MAX_RULES`, `fw.rs:11`; linear scan `firewall.rs:173-181` | Cloud policy sets are routinely 10–100× this. The sharpest expressiveness limit in the system. |
| **64 neighbor-NAT entries fleet-wide**, linear scan per WAN-return packet | `maps.rs:96-113` | Caps the whole fleet at ~64 advertised NAT port-blocks per family. |
| **NAT/public route-bus records broadcast to every node** | `mesh/reflector/nattable.go:23-93` | O(blocks × nodes) fanout; the dominant term at fleet scale. Route records are per-VNI-scoped — NAT/public should be too (edges + owning nodes only). |
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

## 3. Control-plane resilience gaps (P1)

1. **NAT/public channel has no snapshot-prune.** Routes get `EndOfRIB` + prune; NAT
   blocks, public prefixes, and LB backends do not (`mesh/agent/bus.go:143-150,361-384`).
   A record withdrawn while an edge was disconnected lingers forever — Maglev keeps
   hashing flows to a gone backend. Acknowledged in-code; it's the direct N/S analog of a
   blackhole. **Fix:** extend the EndOfRIB/prune contract to the global channel.
2. **Edge anycast has no readiness gating.** An edge attracts ECMP the moment BGP is up,
   before its LB/NAT tables are programmed → blackhole window on every edge
   deploy/restart (`docs/features/ns-edge.md:3-12`). The lever (EndOfRIB-gated readiness)
   already exists — wire it to the health signal that gates the anycast announce.
3. **Tier-2 fence completeness depends on stale broker state.** Failover fences exactly
   `pool.Status.NodePrefixes` as last reported before the partition
   (`dispatch/pkg/failover/failover.go:67-85`). A node added *during* the partition is
   never fenced, yet may run VMs whose disks are about to be re-attached elsewhere —
   a split-brain disk-corruption path through the one mechanism meant to prevent it.
   **Fix:** fence the pool as a unit (cluster-level prefix aggregate, or refuse failover
   when the prefix set could be stale — e.g. compare against the scheduler's placement
   view and block on mismatch).
4. **dispatch-controller has no leader election** (`dispatch/cmd/controller/main.go:83-89`)
   while the compiler does. Safe only at `replicas: 1`; the day someone scales it for HA,
   Tier-2 failover double-fires. Add election now, while it's free.
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

- **Firewall ordering across policies is undefined.** Datapath is first-match-wins, but
  multiple FirewallPolicies matching one NIC are concatenated in API list order
  (`compilednic.go:126`) — which Allow/Deny wins depends on object names. **Fix:** add a
  `priority` field (GCP-style integer), sort at compile, document ties.
- **`VPCSpec.DefaultPolicy` is dead** *(verified — zero consumers)*: a VPC set to `Deny`
  silently gets default-allow (`compilednic.go:166` hardcodes it). Wire it or delete it.
  Related trap: today a single Deny rule in a direction silently flips that direction to
  default-deny by suppressing the synthesized allow-all (`compilednic.go:168`).
- **No Route intent at all** — no custom routes, no priorities, no next-hop steering.
  Fine to defer, but it's the largest single semantic gap vs a GCP VPC; the route-bus +
  LPM machinery could carry it.
- **Firewall sources are CIDR-only, targets label-selector-only** — no tag/service-account
  analog for source matching. The label-selector direction is right; extend it to source
  matching (compile source-selector → the matching NICs' IPs, updated on churn).
- **FirewallPolicy is entirely unvalidated** — `Action`, `Proto`, `Port`, and `CIDR` are
  never checked; garbage flows to the agent (`compilednic.go:141-156`). Add an admission
  `Validate` like Subnet/NIC have. Same for VPC VNI pins (range-check 24-bit) and
  NATGateway.
- **Policy revocation doesn't reach established flows for up to 24 h** — firewall changes
  never touch conntrack (`handlers.rs:415-453`), and established TCP ages at 24 h. GCP
  applies rule changes to established flows. **Fix:** on rule revocation, sweep conntrack
  for entries the new rule-set would deny (userspace walk is fine at 5s cadence), or at
  least make the behavior an explicit documented contract.
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

- `docs/concepts/overlay.md` — 56-byte overhead → effective reserve is 80.
- `docs/features/qos.md` — claims v6 ingress policing exists; doesn't. Same-node bypass of
  ingress policing undocumented.
- `docs/features/ns-edge.md:165-168` + `mesh/agent/public.go:80` — `learnedEdge`
  return-path pinning described as live; `LearnedEdge()` has no production caller (dead
  code — delete or wire).
- `docs/architecture/kubevirt-integration.md` / `cni-integration.md` — say veth + literal
  `tap0`; code uses netkit-L2 and derives/rejects `tap0` (`attach/naming.rs:77-89`).
- `attach/mod.rs:44-46` — stale "fails until B.4 lands" comment on the *default* container
  path (B.4 landed); would misdirect an incident.
- `mesh/reflector/admin.go:19-21` — stale `TODO(authz)`; CN-gating is implemented.
- Broker `main.go:6-7,180` — says "filtered by spec.clusterName"; it's namespace-scoped.
- `docs/features/nat.md:73` (v4-only return wording), `:125` (NAT64 "reuses" egress path —
  it's a separate subsystem); `routing-vni.md:2` "VXLAN" → Geneve.
- "Scaffold-only" markers on FirewallPolicy/LoadBalancer types that are fully compiled.
- `Subnet.status.V4Total/V6Total` include network/broadcast the allocator excludes.

## 7. Suggested sequencing

1. **P0 correctness batch** (each small, testable, sim-coverable): 1.1 NAT source field;
   1.2 v6 LB key; 1.4 fail-closed unkeyable frames; 1.6 drop-on-unrewritable; 1.7 DHCP
   fallback MTU. Then 1.3 (frag/EH policy — needs a design decision first) and 1.5 (NAT
   ICMP relay — pattern exists in `lb.rs`).
2. **N/S resilience pair:** NAT/public snapshot-prune + edge readiness gating. These two
   close the only "silent traffic loss with no self-healing" paths in the system.
3. **Failover safety:** fence completeness + dispatch-controller leader election.
4. **Scale groundwork:** firewall rule-storage redesign (kills the 16-rule cap and sets up
   priorities), NAT/public subscription scoping + keyed neighbor-NAT map. Write a sizing
   doc making every remaining map ceiling an explicit budget.
5. **Policy semantics:** firewall priority field, DefaultPolicy wire-or-delete,
   FirewallPolicy admission validation, revocation-vs-established-flows contract.
6. **Symmetry debt:** v6 conntrack aging, v6 ingress policing, floating-IP into core (sim
   coverage), offload liveness write-back, multi-NIC container fix.
7. **Docs sweep** (one PR, list above).
