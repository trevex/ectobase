# flowplane-dpdk on `nfkit` — a Rust DPDK network-function substrate

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Related:** `2026-07-20-dataplane-substrate-ovs-afxdp-design.md` (this is the DPDK thread, now scoped as a real build); `2026-07-20-geneve-overlay-design.md` (designed-not-scheduled).

## 1. Summary

Build a **DPDK version of flowplane** as a *conforming node role* of the existing dataplane compatibility contract, on top of a new **flowplane-agnostic Rust DPDK network-function substrate crate, `nfkit`**. The datapath logic is reused wholesale from `flowplane-core` via a fourth `Pkt`/`Maps` backend — DPDK provides the I/O, memory, offload, and run-to-completion runtime, not the packet logic.

**The key enabler (from research, grounded):** DPDK's `ethdev` abstraction + EAL `--vdev` lets one binary run on a real NIC, `net_af_xdp` (laptop), `net_tap`, or `net_pcap` (deterministic CI) selected **by config, zero code change** — which directly satisfies the "local debugging without a smartNIC" requirement.

## 2. Goals / non-goals

**Goals:** a highly-scalable run-to-completion DPDK dataplane with functional parity to eBPF flowplane; **peak performance via hardware offload** (established-flow eSwitch offload as the primary lever, plus symmetric RSS, checksum/TSO, `rte_flow`); one binary that runs on NIC / af_xdp / tap / pcap; container (memif) and VM (vhost-user) edges; maximum reuse of `flowplane-core` *without* blocking offload; and a **`nfkit` that is a genuinely safe, zero-cost abstraction** over DPDK.

**Non-goals (now):** replacing the eBPF dataplane (both coexist on one fabric via the compatibility contract); HW encap-offload of our custom IPIP overlay (not offloadable — see §7); the Geneve migration (separate, parked); betting on DPDK's not-yet-merged upstream Rust crate (we converge toward it, don't depend on it).

## 3. Research grounding (truth, cited)

- **Capsule (capsule-rs) is DEAD** — last release 2021-03, DPDK **19.11** (EOL), `bindgen 0.57`, **no `rte_flow`/offload surface**, no vhost-user/memif, needs DPDK+hugepages even for `cargo test`. Excellent API (NetBricks lineage) — mine for inspiration, don't build on. No live fork. ([github.com/capsule-rs/capsule](https://github.com/capsule-rs/capsule), crates.io)
- **The Rust-DPDK framework layer is stale.** Live crates are young/narrow: `rust-dpdk-net` (a smoltcp stack), `dpdk-stdlib-rust` (best-designed safe wrapper, UDP-only, **no rte_flow**). None expose `rte_flow`. ([survey])
- **Emerging official path:** DPDK upstream **`buildtools/rust` RFC (2025-04, Richardson/Intel + Etelson/NVIDIA)** — whole-DPDK-as-a-crate, bindgen + hand-written wrappers for `static inline` fast-path fns (`rte_eth_rx_burst` — bindgen can't emit it). Active, **not merged**; only `rte_eal_init/cleanup` wrapped. Track and converge; don't depend. ([inbox.dpdk.org RFC](https://inbox.dpdk.org/dev/20250408145838.2501034-1-bruce.richardson@intel.com/))
- **`ethdev` + `--vdev` = write-once-run-anywhere** (testpmd proves it): real NIC / `net_af_xdp` / `net_tap` / `net_pcap` / `net_ring` by EAL args alone. ([doc.dpdk.org build_and_test, tap, af_xdp, pcap_ring])
- **`mlx5` DOES inner-RSS over IP-in-IP** (supported inner list: "VXLAN, GRE, …, IP-in-IP, Geneve, GTP") → our IPv6+IPIP overlay **can** HW-spread on ConnectX at the inner 5-tuple. Fabric ECMP + HW encap-offload still want flow-label/UDP encap. ([doc.dpdk.org mlx5 23.11])
- **Run-to-completion + symmetric RSS → lock-free per-lcore state** is DPDK best practice for per-flow NFs, and maps 1:1 onto flowplane's per-CPU-map model. ([DPDK Writing Efficient Code; Toeplitz Hash Library])

## 4. Locked decisions

| Decision | Choice |
|---|---|
| Layering | **Two layers:** `nfkit` (agnostic substrate) + `flowplane-dpdk`; `dpdk-sys` internal to `nfkit` |
| Datapath | **4th `Pkt`/`Maps` backend**, conforming impl of the compatibility contract (same IPIP-in-IPv6 wire + CompiledNIC + routebus) |
| Bindings | **Own `dpdk-sys`** (bindgen + C shim for inline fast-path) on DPDK **23.11/24.x LTS**, shaped to converge with the upstream RFC |
| Edges | **All three** (uplink, memif container, vhost-user + tap VM) — in spec; implementation phased & gated |
| Substrate name | **`nfkit`** (placeholder-ish, easily renamed) |
| VM edge | **vhost-user (perf) + tap (universal/dev fallback)** |
| Phasing | Phases 3–6 **hard-gated** behind phase-2 parity + a real-NIC perf number |
| Core model | Run-to-completion, one lcore per RX/TX queue, shared-nothing, symmetric RSS |
| Perf strategy | **Offload-first, batch what's hot:** peak = eSwitch offload of established flows; `flowplane-core` = reference + slow path + un-offloadable flows; batch only measured-hot stages, byte-parity-guarded |
| `nfkit` safety | **Safe, zero-cost abstraction is the primary goal:** `unsafe` confined to `dpdk-sys` + audited core; consumers write zero `unsafe`; safety via compile-time invariants (ownership/`!Send` type-state/RAII), not runtime checks |

## 5. Crate architecture

```
dpdk-sys        (internal to nfkit)  bindgen over DPDK 23.11 LTS public API + a small
                                     C shim exposing the static-inline hot path
                                     (rte_eth_rx_burst/tx_burst, rte_pktmbuf_*). FFI only.
   │
nfkit           (flowplane-AGNOSTIC substrate; publishable)
   │  Eal            EAL lifecycle (init/cleanup), lcore enumeration, hugepage/socket-mem
   │  Vdev/PortSpec  build EAL --vdev / port args → same API for NIC/af_xdp/tap/pcap
   │  Port(ethdev)   configure/start; queues; offload capability query; safe RAII
   │  Mempool        per-NUMA pktmbuf pools, per-lcore cache sizing
   │  Mbuf/MbufMut   safe zero-copy view; prepend/adjust/append; single-segment
   │  RxQueue/TxQueue burst rx/tx over the shim
   │  Flow           rte_flow builder: symmetric-Toeplitz RSS action, checksum, MARK, steer
   │  LcoreRuntime   run-to-completion executor: spawn a closure per lcore, per-lcore state
   │  (test) PcapHarness  packet-in-file → packet-out-file for deterministic integration tests
   │
flowplane-dpdk  (binds flowplane-core to nfkit)
      MbufPkt: Pkt          Pkt over rte_mbuf (see §6)
      DpdkMaps: Maps         per-lcore rte_hash + shared read-mostly tables (see §6)
      datapath loop          composes flowplane-core: parse→decap/conntrack/fw/nat/lb/encap→tx
      edges                  uplink (ethdev), memif (container), vhost-user+tap (VM)
      control                consumes CompiledNIC + routebus via a map-programming abstraction
```

Each unit has one purpose and a testable interface: `nfkit` knows nothing about overlays/VNIs; `flowplane-dpdk` knows nothing about DPDK ABI details (only `nfkit`'s safe API + `flowplane-core`).

### 5.1 `nfkit` is a safe, zero-cost abstraction (primary design goal)

`nfkit`'s reason to exist is **safe DPDK for Rust NFs with no runtime cost** — the gap dead Capsule and the young safe-wrapper crates leave open. Safety comes from **compile-time invariants, not runtime checks** (runtime checks on the per-packet hot path would defeat DPDK's purpose).

- **`unsafe` is confined** to `dpdk-sys` + a thin, audited `nfkit` core. **Consumers of `nfkit` write zero `unsafe`.** Every `unsafe` block carries a `// SAFETY:` invariant.
- **Mbuf ownership via RAII + move semantics:** an owned `Mbuf` frees on `Drop`; **`TxQueue::send` consumes the `Mbuf` (moves it)** so use-after-transmit and double-free are *compile errors*. Zero-copy header views borrow the `Mbuf` with a bound lifetime (no dangling).
- **Type-state for the shared-nothing model:** per-lcore resources (`RxQueue`/`TxQueue`/per-lcore tables) are **`!Send`**, so handing a queue to the wrong lcore does not compile. Shared read-only resources (`Mempool`) are `Sync`.
- **EAL as a once-only token:** `Eal::init()` returns a guard that gates port/mempool creation; the type system prevents use-before-init and re-init.
- **Zero-cost:** burst `rx`/`tx`, mbuf data access, and the `MbufPkt` ops are `#[inline]` over the `dpdk-sys` shim; invariants are established once (at configure time), not re-checked per packet. `dpdk-stdlib-rust`'s `Port`/`Mbuf`/`Mempool`/`Queue` layering is the reference model.
- **RAII resource ordering:** `Drop` order enforces stop-before-close for ports and EAL-outlives-everything (guard lifetimes), so teardown can't segfault.

## 6. The reuse crux — `Pkt`/`Maps` fourth backend

- **`MbufPkt: Pkt`** over `rte_mbuf`: `grow_head`/`shrink_head` → `rte_pktmbuf_prepend`/`rte_pktmbuf_adjust`; `len`/`logical_len` → `data_len`/`pkt_len`; bounded reads/writes over the mbuf data pointer. **Single-segment mbufs** (dataroom sized for MTU + IPIP-in-IPv6 overhead); multi-segment/jumbo is a seg-aware follow-up (the mbuf-compatible `Pkt` frame model we already committed to).
- **`DpdkMaps: Maps`**: conntrack + NAT state in **per-lcore `rte_hash`** (owned, lock-free); read-mostly tables (Maglev LB, firewall rules, routes, PORT_META) shared with **RCU-style pointer swap** on control-plane update. Per-lcore ownership is sound **because** symmetric RSS pins both directions of a flow to the same lcore (§7).
- **Result:** `flowplane-core`'s `encap`, `conntrack`, `nat`/`nat64`, `lb` (Maglev DSR), `firewall`, `meter` (EDT/policing), and the just-shipped `inner_flow_label` run **unchanged**. Same IPIP-in-IPv6 wire format ⇒ a flowplane-dpdk node and an eBPF node interoperate on one fabric.

## 7. Run-to-completion runtime + scaling

- **One lcore per RX/TX queue, shared-nothing.** Each lcore polls its queues, runs a packet through the full chain, TXes — no cross-core handoff on the fast path.
- **Symmetric Toeplitz RSS via `rte_flow`** so a flow and its return hash to the same queue → **lock-free per-lcore conntrack/NAT/LB tables**. (Asymmetric RSS would split directions across cores.)
- **`mlx5` inner-RSS over IP-in-IP** to spread post-decap overlay flows across cores.
- Per-NUMA mempools; per-lcore mempool cache; 1 GB hugepages; `--socket-mem`; pinned lcores; NUMA-local RX/TX/state. Burst-oriented rx/tx.
- Packet graph per lcore: `rx_burst → parse (outer IPv6? decap IPIP : native) → conntrack → firewall → nat/nat64 → lb(Maglev DSR) → encap (+flow label) → tx_burst`. Optionally expressed via `rte_graph` later; hand-rolled first.

## 8. Performance & offloading model

**Peak throughput comes from hardware offload, not from a fast software path** — even a perfect scalar/SIMD software datapath loses to the eSwitch carrying elephant flows at ~0 CPU. Strategy (locked): **offload-first, batch what's hot.**

### 8.1 What reusing `flowplane-core` means for offload (three kinds, resolved)

| Offload kind | Interaction with reuse | Handling |
|---|---|---|
| **Stateless per-packet** (RX/TX checksum, TSO/GSO) | Backend-level, *not* a conflict | The `MbufPkt` backend sets mbuf `ol_flags` (`RTE_MBUF_F_TX_*_CKSUM`, TSO) instead of `flowplane-core` folding checksums in software. Same `Pkt` op → "mark for HW" on DPDK, "incremental fold" on eBPF. Faster on DPDK. |
| **Flow steering / RSS** | Orthogonal | `nfkit`/`rte_flow` (symmetric Toeplitz) runs before the datapath; `flowplane-core` untouched. |
| **Established-flow full offload** (eSwitch: decap/CT/NAT/count/mark) | **Complementary — the core is the brain** | `flowplane-core` processes the *first* packet and creates the state; a `flowplane-dpdk` **translation seam** turns that CT/NAT/LB decision into an `rte_flow` rule so subsequent packets bypass the CPU. Reuse *drives* offload; it is not bypassed. |

**Reuse does NOT block offload.** The only un-offloadable operations are our **custom IPIP encap** (only VXLAN/GRE/MPLS are HW-encap-offloadable) and **Maglev DSR** (not an eSwitch primitive) — a property of the wire/LB design, independent of code reuse. Those always run in software.

### 8.2 The scalar-vs-batched tension (honest)

`flowplane-core` is verifier-shaped: scalar, one-packet-at-a-time, unrolled loops, per-packet `Maps` calls. DPDK peak wants **bursts of 32 + prefetch + `rte_hash_lookup_bulk` + SIMD parse** — the biggest gap being per-packet hash lookups vs. bulk-lookup-with-prefetch to hide memory latency.

**Resolution — offload-first, batch what's hot:**
- **Peak = eSwitch offload** of established flows (§8.1 row 3).
- **`flowplane-core` = correctness reference + first-packet/slow-path + un-offloadable flows** (custom encap, DSR, NAT64).
- **Batch only the software slow-path stages profiling shows are hot** (burst parse, bulk CT lookup) as DPDK-native code *behind the same semantics*, **guarded by byte-parity against the core** (extends the `net_pcap` anchor). We never diverge from the reference; we only accelerate hot stages we've measured.

### 8.3 Offload enablement (best practices)

- Enable RX/TX checksum, tunnel-aware TSO, symmetric-Toeplitz RSS; query `dev_info` and **degrade gracefully** so `net_pcap`/`tap`/`af_xdp` (no HW offload) run the *same* code.
- `rte_flow`: symmetric-RSS action + `MARK` + steering; the established-flow **offload seam** (decap/CT/NAT/count/mark on the mlx5 E-Switch) is a first-class phase, not an afterthought — it's where the perf is.
- **Fabric ECMP:** the outer IPv6 **flow label** (already in `flowplane-core`) carries per-flow entropy for ToR ECMP without inner parsing.

## 9. Write-once, run-anywhere + two-tier testing

The datapath sees a **port id**; the PMD is chosen by EAL `--vdev` — zero datapath code change:

| Backend | Use | Note |
|---|---|---|
| `mlx5`/`ice` | prod | full offload, inner-RSS |
| `net_af_xdp` (veth/netns) | laptop dev / full-stack e2e | real kernel path, near-line-rate |
| `net_pcap` | **deterministic CI** (packet-in-file → out-file) | the DPDK analogue of `BPF_PROG_TEST_RUN` |
| `net_tap` | kernel-netns wiring | L2 loopback |

**Two-tier testing (fixes capsule's fatal weakness — DPDK required for unit tests):**
1. **Pure logic:** `flowplane-core` sim (`VecPkt`/`MemMaps`) — **no EAL, no hugepages** — byte-parity conformance. *Unchanged; already exists.*
2. **DPDK integration:** `nfkit` + `net_pcap` — feed a pcap, assert the emitted pcap. Byte-parity vs the sim extends the existing anchor concept to the DPDK path.

## 10. Edges

| Edge | Mechanism | Notes |
|---|---|---|
| **Uplink** | ethdev (NIC / af_xdp / pcap / tap) | one code path, `--vdev`-selected |
| **Container** | **memif** (`net_memif`, zero-copy DPDK-to-DPDK) | analogue of veth/tcx; virtio-user as alt; Multus/Userspace-CNI-style orchestration |
| **VM** | **vhost-user** (shared hugepages) **+ tap fallback** | vhost-user = perf tier (KubeVirt); tap = universal/dev path (reuses proven tap datapath); server-owns-socket lifecycle caveat |

## 11. Control-plane reuse

flowplane-dpdk consumes the **same CompiledNIC + routebus**. Introduce a **map-programming abstraction** in the agent (`trait DataplaneProgrammer`) with two impls: eBPF (BPF maps) and DPDK (`DpdkMaps` + `rte_flow`). Most control logic is shared; per-lcore DPDK state means the programmer **fans updates out to all lcores** (or uses a shared RCU table + per-lcore handles). Same wire format ⇒ a **mixed eBPF+DPDK fabric** is valid (the compatibility contract realized).

## 12. Phased implementation plan (writing-plans will expand)

1. **`dpdk-sys` + `nfkit` core** — Eal/Vdev/Port/Mempool/Mbuf/Rx-Tx/LcoreRuntime + `net_pcap` & `net_af_xdp` backends; `PcapHarness`. Deliverable: an l2fwd-equivalent runs on NIC/af_xdp/pcap by config.
2. **`MbufPkt` + `DpdkMaps` + uplink RTC datapath** — compose `flowplane-core`; **byte-parity vs sim via `net_pcap`**; a real-NIC pps number. **← HARD GATE**
3. **Stateless offload + steering** — checksum/TSO via mbuf `ol_flags` in `MbufPkt`; symmetric-Toeplitz RSS; inner-RSS on mlx5; `rte_flow` builder in `nfkit`. Establish a per-lcore-scaling perf baseline.
4. **Established-flow offload seam** — the CT/NAT/LB-decision → `rte_flow` rule translation (elephant flows to the eSwitch). *This is the peak-perf phase.* Measure offloaded-flow CPU.
5. **Batch hot software stages** — profile the slow path; add burst parse + `rte_hash_lookup_bulk`/prefetch where hot, **byte-parity-guarded** against `flowplane-core`. Only what profiling justifies.
6. **Container edge** — memif.
7. **VM edge** — vhost-user + tap fallback.
8. **Control-plane `DataplaneProgrammer`** — CompiledNIC/routebus → DpdkMaps/rte_flow; mixed-fabric validation.

Phases 3–8 start only after phase 2 proves byte-parity + an acceptable real-NIC perf number.

## 13. Risks / open questions

- **Binding maintenance:** we own `dpdk-sys` + the inline-fn C shim across DPDK LTS churn. Mitigation: keep the FFI boundary shaped like the upstream RFC to swap later.
- **`rte_mbuf` single-segment assumption** (jumbo/scatter) — accept single-segment v1; seg-aware `Pkt` is a follow-up.
- **DPDK requires hugepages/EAL for its tests** — mitigated by keeping pure logic in the DPDK-free `flowplane-core` sim; only `nfkit`/integration tests need EAL (CI with hugepages or a DPDK container).
- **vhost-user + KubeVirt** wiring is non-trivial (hugepage-backed VMs, socket lifecycle) — tap fallback de-risks.
- **Per-lcore control-plane fan-out** — programming N lcores per CompiledNIC update; define the RCU/handle model in phase 6.
- **`nfkit` naming / open-sourcing** — placeholder; decide before publish.
- **Symmetric RSS on non-mlx5 / vdev backends** — af_xdp/tap/pcap won't offer HW RSS; single-lcore or software steering in dev is acceptable (perf only matters on real NICs).
- **Scope:** "all edges" is large; the phase-2 gate + strict phase ordering is the control.
- **Scalar-core vs DPDK-batch gap:** the verifier-shaped `flowplane-core` won't hit DPDK's per-packet peak on the software path. Mitigation = offload carries elephants (phase 4) + batch only measured-hot stages (phase 5), byte-parity-guarded. Accept the software slow-path is not SIMD-optimal by default.
- **`nfkit` safety vs zero-cost:** the hard part is a safe `Mbuf` lifecycle (RX→process→TX-consumes / free) with no runtime overhead. Mitigation = ownership/move semantics + `!Send` type-state (compile-time), `#[inline]` hot path, `unsafe` confined + `// SAFETY`-documented. Validate zero-cost by inspecting codegen on the burst loop.
- **Established-flow offload seam correctness:** the "CT/NAT decision → `rte_flow` rule" translation must stay consistent with the software path (a flow offloaded to HW must behave identically to one handled in software). Needs its own conformance tests + eviction/sync handling when state changes.
