# flowplane-dpdk B1: deployable serve + control seam — design

**Date:** 2026-07-22
**Status:** Design (approved in brainstorm; awaiting written-spec review)
**Parent:** Thread B of `docs/superpowers/specs/2026-07-22-dpdk-dataplane-helm-blue-green-design.md`
**Scope:** Make the DPDK dataplane a runnable process: a `flowplane-dpdk serve` binary that runs the
datapath on the nfkit runtime AND serves the `DataplaneNode` gRPC that programs the DPDK maps, with
the control-plane orchestration SHARED (not duplicated) with the eBPF `flowplane`.

---

## 1. Context and problem

The DPDK datapath (`flowplane-dpdk` on the `nfkit` substrate) is proven byte-identical to eBPF for
packet processing (M1–M11, via the shared generic orchestrators in `flowplane-core/datapath.rs`).
But it is **not deployable**: `nfkit` is a library with no `serve` binary, no gRPC server, no `main`.
Thread A shipped a Helm chart whose DPDK DaemonSet references an image that does not exist yet.
Thread B makes that image real; **B1** is its first, architecture-deciding slice.

**The core finding that shapes B1.** The datapath `Maps` trait
(`flowplane/flowplane-core/src/maps.rs`) is **read-oriented** — getters (`route4_get`, `nat_get`,
`fw_rule`, `lb_get`, `maglev_get`, …) plus two datapath mutators (`conntrack_insert`,
`meter_update`). The **control plane** is entirely separate: the eBPF `Control`
(`flowplane/flowplane/src/control/mod.rs`) programs maps via **concrete aya map wrappers**
(`g.routes.upsert(...)`, `g.nat.upsert(...)`, `g.lb.upsert(...)`, `g.fw_rules.upsert(...)`,
`g.meter.upsert(...)`), and `Control` is **hardcoded to eBPF map types**, not generic. So reusing
the datapath (done) does NOT give control-plane reuse. `NodeService`
(`flowplane/flowplane/src/node.rs`) is a thin gRPC wrapper over `AttachState` → `Arc<Control>`; of
its 15 RPC handlers ~13 are backend-agnostic map programming and ~2 (`AttachInterface`,
`DetachInterface`) are host-device lifecycle.

**Two design axes B1 must settle:** (1) where the control-plane extraction seam lives, and (2) how
the tokio gRPC control thread safely publishes into maps that busy-poll datapath lcores read every
packet — while keeping M8's per-lcore shared-nothing model.

## 2. Decisions (locked in brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Control-plane seam | **Extract shared orchestration into a new `flowplane-control` crate, generic over a `MapWriter` trait.** `flowplane` (eBPF) and `flowplane-dpdk` each implement `MapWriter`; both call one orchestration. Honors [[seam-not-duplicate-for-tests]]. |
| 2 | Multi-core | **Support multi-lcore from the start** (not single-lcore-only). |
| 3 | Config-table concurrency | **One shared `rte_hash` per config table with `RW_CONCURRENCY_LF` + integrated RCU** (`rte_hash_rcu_qsbr_add`); tokio thread is the single writer, lcores are QSBR readers reporting quiescence once per poll loop. |
| 4 | Flow-state concurrency | **Conntrack (+ per-packet meter) stays per-lcore shared-nothing** (M8), with the existing symmetric-Toeplitz RSS for flow affinity. Never RCU/rwlock on per-packet writes. |
| 5 | Slicing | **B1a** = extract `flowplane-control`, make eBPF `flowplane` call it (pure refactor, existing tests are the net). **B1b** = DPDK `MapWriter` + map split + `flowplane-dpdk serve` + multi-lcore parity test. |
| 6 | Boundaries | B1 programs every RPC incl. `AttachInterface`'s agnostic half (ports/ifaces/underlay). Real host-device attach = **B2**; image + DaemonSet = **B3**. |

**Grounding (research, 2026-07-22).** dpservice does NOT solve multi-core: hard-capped at one
worker (`dp_graph.c:165` `rte_lcore_count() != 2`), global rte_hash with `extra_flag = 0` (no
concurrency/RCU), gRPC writes funneled through an rte_ring the single worker drains and applies
(`rx_periodic_node.c:50`) — writer==reader by construction, does not extend to N workers. The DPDK
Hash + RCU libraries recommend, for one-writer/many-reader read-mostly tables,
`RW_CONCURRENCY_LF` + QSBR RCU (readers report quiescence at the poll-loop boundary — the docs call
the begin/end of a `while(1)` loop "perfect quiescent states"), and per-lcore shared-nothing for
hot per-packet flow state. Decisions 3–4 follow this directly.

## 3. Architecture

```
                       flowplane-control  (NEW crate)
                       backend-agnostic programming, generic over MapWriter:
                       routes/nat/lb+maglev/fw/qos/neigh/dhcp orchestration,
                       conflict checks, Maglev rebuild
                          ▲                                   ▲
             impl MapWriter for                    impl MapWriter for
             aya wrappers (eBPF)                    DPDK SharedConfigMaps
                          │                                   │
   flowplane (eBPF)  ─────┘                                   └───── flowplane-dpdk (NEW bin crate)
   Control now delegates                                     serve: EAL → maps → workers → tonic
   agnostic programming to                                   DataplaneNode over flowplane-control
   flowplane-control; keeps                                  + nfkit datapath (flowplane-core)
   loader/attach/device glue
```

### 3.1 `flowplane-control` crate (B1a)

- Holds the ~13 backend-agnostic control operations currently on `Control`
  (`create_route`/`delete_route`, `create_nat`/`delete_nat`, `create_lb`/`add_lb_target`/…,
  `add_fw_rule`/`del_fw_rule`, `set_qos`, `add_neighbor_nat`/…, dhcp config), plus the pure logic
  they call (Maglev table build, route/nat/lb conflict + shadow-state checks).
- Generic over a **`MapWriter` trait** = the write surface these operations need:
  `routes.upsert/remove`, `routes6.*`, `nat.upsert/remove`, `nat_ips.*`, `lb.upsert/remove`,
  `maglev.upsert`, `fw_rules.upsert/remove`, `fw_meta.upsert`, `underlay.upsert`, `ports.upsert`,
  `ifaces.upsert`, `meter.upsert`, `neigh_nat.upsert/remove`, `dhcp_config/dhcp_meta.upsert`, and a
  `conntrack_flush(scope)` hook (see §5 open item). Exact method set is enumerated from the current
  `Control` `.upsert(...)` call sites (`control/mod.rs`).
- **No device logic, no aya, no DPDK** — pure orchestration + `MapWriter`. Depends only on
  `flowplane-common` (POD types) / `flowplane-core`.

### 3.2 eBPF `flowplane` after extraction (B1a)

- Implements `MapWriter` for its existing aya map wrappers (thin: each trait method forwards to the
  concrete `.upsert/.remove` it already calls).
- `Control` keeps the eBPF-specific parts: `bring_up()` (loader), device attach/detach, ifindex/MAC
  sysfs reads, XDP/tc attach, conntrack GC. Its agnostic methods become thin delegations into
  `flowplane-control`. **Behavior is unchanged** — the existing `flowplane` unit tests + the clab
  regression sweep are the safety net; this slice must not alter any eBPF output.

### 3.3 DPDK maps split (B1b)

`nfkit`'s M8 `DpdkMaps` (all-per-lcore) splits by access pattern:
- **`SharedConfigMaps`** — one instance for the whole process. Each config table is an
  `rte_hash` created with `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` and RCU enabled via
  `rte_hash_rcu_qsbr_add`. Tables: routes, routes6, nat, nat_ips, lb, maglev, fw_rules, fw_meta,
  underlay, ports, ifaces, neigh_nat, dhcp_config, dhcp_meta. Implements `MapWriter` (writer side)
  and the datapath read side of `Maps`. Writer = the tokio control thread (single writer → no
  `MULTI_WRITER_ADD`).
- **`PerLcoreFlowMaps`** — per-lcore, shared-nothing (unchanged M8 model): conntrack + per-packet
  meter state. Written and read only by the owning lcore.
- Each worker lcore's `Maps` view = `SharedConfigMaps` (shared, RCU-read) + its own
  `PerLcoreFlowMaps`. A small composed type implements the datapath `Maps` trait by routing getters
  to the right half.

### 3.4 `flowplane-dpdk serve` process (B1b)

Mirrors `flowplane serve` (`flowplane/flowplane/src/main.rs`) structurally:
1. Parse args (uplink, gateway, gateway-mac, lcores, backend, `--no-huge`) — same surface the Helm
   DaemonSet passes.
2. EAL init (`nfkit::eal`), port/queue setup (`Backend::AfXdp` clab / `Backend::Nic` hw), RSS with
   the existing symmetric-Toeplitz key.
3. Build `SharedConfigMaps` (LF+RCU) + one `PerLcoreFlowMaps` per worker lcore.
4. `LcoreRuntime::for_each_worker(n_queues, …)` launches busy-poll datapath workers; each **registers
   a QSBR reader thread** and **reports quiescence once per poll-loop iteration**, running the same
   `flowplane-core` datapath over its composed `Maps` view.
5. On the main thread, run a tokio runtime hosting the tonic `DataplaneNode` server on
   `127.0.0.1:1337` + the gRPC health service (Serving after datapath is up). Handlers build a
   DPDK `MapWriter` over `SharedConfigMaps` and call `flowplane-control`.
6. Graceful shutdown (SIGTERM/SIGINT): stop accepting, quiesce workers, exit.

The readiness contract is identical to eBPF: the gRPC listener opens only after datapath load, so
`ss -ltn | grep 127.0.0.1:1337` (the DaemonSet probe) means "ready to AttachInterface".

## 4. Testing

- **B1a (refactor safety):** existing `flowplane` control unit tests pass unchanged; add tests that
  `flowplane-control` orchestration produces the same map writes via a mock `MapWriter`
  (`flowplane-sim`'s `MemMaps` can back it). The clab regression sweep (manual) confirms eBPF
  behavior is intact before merge.
- **B1b (vertical slice):** a multi-lcore test that (a) starts `SharedConfigMaps` + N
  `PerLcoreFlowMaps`, (b) programs routes/nat/lb/fw through the DPDK `MapWriter` (the same calls the
  gRPC handlers make), (c) runs the `flowplane-core` datapath on N lcores over a fixture, and (d)
  asserts byte-parity with the sim AND conntrack isolation across lcores (extends the existing
  `multilcore_datapath` + parity harnesses, `--no-huge`). Plus an **anchor** exercising a non-EAL
  (tokio) writer doing `rte_hash_add/del` on an LF+RCU table concurrently with an lcore reader
  reporting quiescence (validates open item §5b).
- **Parity preserved end to end:** because eBPF now calls `flowplane-control`, the chain stays
  DPDK == sim == eBPF for both datapath (existing) and control-plane map contents (new).

## 5. Open items (resolve in the plan)

- **(a) Conntrack flush on NAT change is per-lcore now — RESOLVED (research-grounded).** The eBPF
  `create_nat`/`delete_nat` flush the (shared) conntrack map. With per-lcore conntrack the tokio
  writer must not reach into lcore-private tables. Chosen mechanism: **config-generation tag + lazy
  re-validation at lookup**, leveraging the shared RCU config the lcores already read every packet.
  - A process-global `AtomicU64 config_generation`; the single tokio writer bumps it (Release) as
    part of the same RCU publish it does to `SharedConfigMaps` on any NAT/LB/route change.
    `MapWriter::conntrack_flush(scope)` becomes "bump `config_generation`" (no cross-lcore writes).
  - Each conntrack entry is stamped at creation with the generation it was resolved under (and the
    rule/binding key it depends on).
  - On the per-lcore datapath lookup, **before applying the cached decision**, if
    `entry.gen != config_generation` the lcore re-validates the cached binding against
    `SharedConfigMaps`: still valid → refresh the entry's gen (fast path, no rebind, that lcore's
    own local write); binding gone/changed → drop or re-resolve. Because the check is
    before-forward, the next packet on a stale flow never emits under a withdrawn binding — **zero
    stale emission** for the security-sensitive NAT-source-withdrawal case, with no cross-lcore
    writes and one-packet-bounded table lingering.
  - Requires the decision be re-derivable from `SharedConfigMaps` (it is — that is what the config
    tables are for) and the entry to carry its dependency key.
  - **Why not explicit deletion?** dpservice sweeps its single shared flow table on config delete
    (`dp_flow.c:440-513`); VPP nat44-ed walks every/owning per-worker session pool
    (`nat44_ed.c:573-593`, `:1226`) — but VPP can only do that safely under its global API barrier
    that stops all workers, which our tokio-writer model has no equivalent of. The generation-tag
    path is the idiom that fits shared-nothing lcores + a shared RCU config (the Cilium
    re-validation model). A per-lcore invalidate-ring drained at the loop top (VPP-style, adapted)
    stays as a **future option only if eager table reclamation is ever needed** — not for
    correctness.
- **(b) Non-EAL tokio writer on an LF+RCU rte_hash.** Research flagged that the writer thread is a
  tokio thread, not an EAL lcore. QSBR tracks *readers*, so a single external writer is likely fine,
  but this needs the anchor test in §4 before we rely on it. Fallback if it isn't: keep the tokio
  handler enqueueing ops on an rte_ring that a control-owned lcore drains (dpservice's pattern) while
  still using LF+RCU for the multi-reader safety.
- **(c) `MapWriter` exact method set** — enumerate from the `.upsert(...)` call sites in
  `control/mod.rs` so the trait is neither over- nor under-specified.

## 6. Non-goals (B1)

Real host-device attach (tap/veth/netns creation, the eBPF-loader-coupled `attach.rs` glue) — **B2**.
Container image + finalized Helm DaemonSet + AF_XDP-under-`--no-huge` validation + `-l` lcore config
finalization — **B3**. Blue-green upgrade RPCs (`ExportState`/`ImportState`/`Steer`/`WatchStatus`) —
**thread C**. This spec is the deployable-process foundation those build on.
