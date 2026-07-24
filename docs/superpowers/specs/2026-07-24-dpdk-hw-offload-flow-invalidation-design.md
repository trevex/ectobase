# DPDK HW-offload flow invalidation — design

**Date:** 2026-07-24
**Status:** Design (research-grounded; awaiting review)
**Parent / motivation:** §3.5 + §9 of `2026-07-23-flowplane-dpdk-b1b-serve-and-images-design.md`. B1b shipped the
software datapath + the §5a generation-tag conntrack invalidation. The next phase offloads established
flows to mlx5 `rte_flow` transfer rules; **this spec decides how offloaded flows are invalidated** so that
phase can be built correct-by-construction. No offload code exists yet — this is the invalidation
contract the offload seam must honor.

---

## 1. Problem

Phase-4 offload (per `2026-07-20-flowplane-dpdk-nfkit-design.md` §12): on the **first packet** of an
established flow, after `flowplane-core` resolves it, install an mlx5 `rte_flow` transfer rule
`match {outer_underlay_dst, inner 5-tuple} → [decap, (NAT rewrite), steer→VF]`. **Subsequent packets of
that flow are processed entirely in hardware and never reach the CPU.**

The §5a software invalidation (control withdraws a NAT/LB binding → bump `config_generation` → each lcore
re-validates a cached conntrack entry **before forwarding** the next packet) is correct ONLY because the
CPU sees every packet. **It structurally cannot invalidate an offloaded flow: there is no CPU packet, so
the before-forward recheck never runs.** A NAT-source or LB-VIP whose `rte_flow` rules are still installed
would keep emitting under the withdrawn binding — the exact stale-emission the security model forbids.

An offloaded flow's HW rule embeds a forwarding decision derived from **every config input the datapath
read to resolve it** — not just a NAT/LB binding, but the **route** lookup, the **interface / virtual NIC**
(its ifindex, overlay IPs, underlay /128, firewall meta), the underlay entry, etc. If **any** of those
inputs changes or is removed, the offloaded rule is stale and must be torn down. Route withdrawal and
interface (vNIC) detach are first-class triggers, exactly like NAT/LB withdrawal.

**Requirement (absolute control):** whenever the control plane changes ANY config the datapath consults —
a route removed/changed, a NAT/LB binding withdrawn, a firewall rule changed, an **interface/vNIC
detached**, an underlay entry removed — every offloaded flow that depended on that config must be
**installed AND removed under the control plane's precise control**, with **zero stale emission**, under
our model: a **single control-plane writer thread** + **per-lcore shared-nothing datapath** (no global
barrier à la VPP).

## 2. Mechanism decision (research-grounded)

Researched the concrete `rte_flow`/mlx5 options (DPDK rte_flow prog guide, mlx5 PMD guide, the HWS CT
patch series, OVS-DPDK/Cilium prior art). Findings:

| Mechanism | Verdict for binding-withdrawal invalidation |
|---|---|
| **Eager per-rule `rte_flow_async_destroy` + `binding → [rule handles]` index** | **PRIMARY.** Correct granularity, hard zero-stale, fits single-writer. |
| Indirect shared action, one per binding, single `handle_update` | Accelerator/fallback. Only mlx5 *stateful* actions are indirect (count/age/**conntrack**); no generic "indirect drop". A shared **CONNTRACK** context `enable=0` disables all its rules in one write — elegant but a semantic stretch (CT is per-connection) + FW-gated. |
| mlx5 HW conntrack (`RTE_FLOW_ACTION_TYPE_CONNTRACK`) invalidation | Right for *per-connection* invalidation, wrong granularity for a *binding*. ConnectX-6 Dx + `dv_flow_en=2`, FW-gated. |
| Generation-register match (HW analog of the software gen-tag) | **Rejected.** mlx5 has no mutable *global* register all rules compare against; a TAG/META is a per-packet field set by a prior-stage rule, so "bump" means *replacing the prior-stage stamp rule* per binding — not a free single write, and offloaded flows that skip re-classification never see the new gen. |
| `RTE_FLOW_ACTION_TYPE_AGE` + `rte_flow_get_aged_flows` | **GC backstop only** — reclaims IDLE flows on timeout; never invalidates an actively-forwarding flow on policy change. |

**Decision: two-tier invalidation with FULL config-dependency tracking.**
1. **Software conntrack (non-offloaded flows):** unchanged — the §5a generation-tag lazy recheck. The CPU is
   in the loop, so lazy is correct and cheap.
2. **HW-offloaded flows:** **eager, dependency-tracked teardown.** Every offloaded flow records, at install
   time, the **complete set of config keys** its forwarding decision read — its *dependency set*. The
   control thread keeps a reverse index `config_key → {flow handles}` (a flow is indexed under EACH of its
   dependency keys). On ANY control-plane mutation of a config key (upsert OR remove), the control thread
   looks up the dependents and destroys them via the mlx5 HWS **async** flow API (`rte_flow_async_destroy`)
   on a **dedicated control-owned flow queue**. Paired with an **AGE** action on every offloaded rule as an
   idle-flow GC backstop (bounds the index independent of any config change).

**The dependency set spans every config table the datapath reads**, so removing/changing any of these
tears down the flows that used it:
`route4[vni,dst]` / `route6[vni,dst]`, `nat[vni,ip]` / `nat_ips`, `lb[key]` / `maglev`,
`fw_rules[ifindex,idx]` / `fw_meta[ifindex]`, `ifaces[key]` / `iface_meta` (the **virtual NIC**),
`underlay[/128]`, `vips`, `neigh_nat`. An **interface/vNIC detach** tears down every flow indexed under
that interface's `ifindex`/`ifaces`/`iface_meta`/`fw_meta`/`underlay` keys (the `purge_vni` path also
tears down the VNI's route/nat/underlay-dependent flows). A **route change** (upsert with a new nexthop),
not just a delete, invalidates flows that used the old route — so both upsert and remove trigger teardown.

Optional future accelerator: model a config object as one shared **indirect CONNTRACK** action so a single
`rte_flow_action_handle_update(enable=0)` invalidates all flows referencing it in one op — adopt only where
the object maps cleanly to one stateful object and the ConnectX FW validates the `enable=0 →
CONNTRACK_FLAG_DISABLED → downstream miss` path.

## 3. Why this fits the single-writer model (the key architectural choice)

`rte_flow` is **per-port**, mlx5 sets `RTE_ETH_DEV_FLOW_OPS_THREAD_SAFE`, and the HWS async API is
**queue-based** (one queue driven by one thread). This lets us make the **control thread the SOLE owner of
the flow table** — it both installs and destroys rules on its dedicated async queue — so we need **no
per-lcore destroy ring** and no cross-lcore state sync. This mirrors the discipline that already works in
B1b: single writer to `SharedConfigMaps`, lcores are readers.

But offload is triggered on a **first packet seen by a datapath lcore**. To keep the control thread the
sole flow-table owner:

- **Offload request path:** on a first-packet offload candidate, the lcore ENQUEUES a compact
  offload-request (the resolved rule spec: match tuple + actions + **the flow's full dependency set** — the
  config keys it read) onto a lock-free **lcore→control ring**. The lcore keeps software-forwarding that
  flow until the rule lands (offload warmup — a handful of CPU packets, then hardware). The control thread
  drains the ring, calls `rte_flow_async_create`, and records the returned handle in the reverse index
  under EACH dependency key.
- **Invalidation path:** on ANY config mutation of key `K`, the control thread: (1) `rte_flow_async_destroy`
  every handle in `index[K]` and `rte_flow_pull` the completions; (2) applies the config change to
  `SharedConfigMaps`; (3) bumps `config_generation` (for the software CT tier). **Ordering is load-bearing**
  — HW rules are destroyed BEFORE the config change is visible. After (1) no offloaded packet can emit under
  the stale decision (they now miss → CPU); (2)+(3) make the CPU re-resolution see the new config →
  re-resolve or drop. **Zero stale emission — for any config change, not just NAT/LB.**

**The `MapWriter` surface is the choke point — this is what gives "absolute control".** EVERY config change
already flows through the single control-thread `DpdkMapWriter` (its 35 methods: `route_upsert`/`_remove`,
`nat_*`, `lb_*`, `fw_rules_*`, `ifaces_*`/`iface_meta_*`, `underlay_*`, `vips_*`, `neigh_nat_*`, …). So the
teardown hooks are exactly those methods: each `*_upsert`/`*_remove` first tears down `index[that key]`,
then writes the map. `program_interface`/`purge_vni`/`forget_iface_meta` (interface attach/detach) tear
down every flow indexed under the interface's keys. Nothing changes config without passing through this
surface, so no offloaded flow can outlive the config it depended on. (`conntrack_flush` remains the
software-tier generation bump; the HW teardown is now driven by the individual config-key mutations, which
is strictly more precise.)

## 4. New components (phase-4, not built here)

- **`OffloadTable`** (control-owned, in `flowplane-dpdk` or `nfkit`): the dedicated HWS flow queue + a
  **multi-key reverse index** `ConfigKey → Vec<FlowHandle>` (a `ConfigKey` enum over every config table:
  `Route4(vni,dst)`, `Route6(...)`, `Nat(vni,ip)`, `Lb(key)`, `FwMeta(ifindex)`, `Iface(key)`,
  `Underlay(/128)`, …) plus the forward map `FlowHandle → {dependency keys}` so a torn-down flow is removed
  from all its index buckets. API: `install(spec, dep_set) -> FlowHandle` (async create + index under each
  dep key) and `invalidate(ConfigKey)` (async destroy all handles under that key, pull completions, and
  scrub them from their other buckets). Uses the existing `nfkit::flow::FlowRule` RAII wrapper (M10),
  extended to the async HWS API.
- **Dependency-set capture:** the datapath decision path records which config keys it read (route lookup,
  nat/lb/fw/iface/underlay gets) into a small `dep_set` carried with the offload-request. This is the
  load-bearing addition — precise removal requires knowing precisely what each flow depended on.
- **`MapWriter` teardown hooks:** each `DpdkMapWriter::*_upsert`/`*_remove` calls
  `offload.invalidate(ConfigKey::from(that key))` before writing the map; `program_interface`/`purge_vni`/
  `forget_iface_meta` invalidate every `ConfigKey` for the affected interface/VNI.
- **lcore→control offload-request ring** (one `rte_ring` per lcore, drained by the control thread).
- **First-packet offload hook** in the datapath: `flowplane-core` already computes the forwarding decision;
  add a backend hook that, when `offload_mode == HwRawFlow` (the existing `nfkit::flow::offload_mode`
  probe) and the decision is offloadable, emits the offload-request WITH its dependency set. eBPF/sim/
  software-DPDK backends no-op the hook (unchanged behavior).
- **AGE wiring:** every offloaded rule carries `RTE_FLOW_ACTION_TYPE_AGE`; a periodic control-thread sweep
  calls `rte_flow_get_aged_flows` and drops aged handles from the index (GC backstop).

The seam is `MapWriter`-adjacent: the software `MapWriter` path is untouched; the HW teardown hangs off the
same control-thread withdrawal that already bumps the generation. eBPF stays entirely unaffected (no rte_flow).

## 5. Correctness argument (zero stale emission)

For ANY config key K that is changed/removed (a route, a NAT/LB binding, a firewall rule, an
interface/vNIC, an underlay entry) and any packet p whose decision depended on K:
- If p's flow is **software** (not offloaded): p reaches an lcore; the §5a recheck sees `entry.gen !=
  config_generation` → re-derives against `SharedConfigMaps` where K changed → does not emit the stale
  decision. ✓ (unchanged)
- If p's flow is **offloaded**: because the flow was indexed under K at install, K's mutation
  `rte_flow_async_destroy`'d its rule + pulled completions BEFORE the config change became visible. So at
  the instant K changes, no HW rule that depended on K exists → p misses in HW → goes to the CPU default
  rule → treated as a fresh flow → re-resolved against the updated `SharedConfigMaps` → not emitted under
  the stale decision. ✓
This holds for **every** dependency, so removing a route or detaching a vNIC is as safe as withdrawing a
NAT binding — a flow cannot outlive ANY config it read. The only window is between destroy-issue and
completion-pull; pulling completions before the map write closes it. In-flight HW packets already past the
(now-destroyed) rule are bounded by the async completion latency and carry no new decision. AGE
independently reclaims idle offloaded flows so the index cannot grow without bound. Install and removal are
thus both under the control plane's precise, exhaustive control — the "absolute control" requirement.

## 6. Scope / non-goals

This spec is the **invalidation contract only**. It does NOT build offload (the first-packet→rule
translation, the async `OffloadTable`, the ring) — that is the offload phase, which must be built to this
contract. It requires real ConnectX-6 Dx + `dv_flow_en=2` HWS to validate on hardware; the software/af_xdp
backends never offload and keep the §5a path. NAT64 offload inherits the same contract (and the NAT64
software gen-gap noted in B1b §9 should be closed at the same time).

## 7. Open items for hardware validation

- Async-destroy completion latency + the per-queue single-writer requirement under load (drives the
  destroy→pull window in §5).
- Whether to adopt the indirect-CONNTRACK accelerator (§2) — needs the `enable=0 → DISABLED → downstream
  miss → CPU default` path validated on the exact ConnectX FW/OFED.
- AGE timeout tuning vs the index memory bound.
