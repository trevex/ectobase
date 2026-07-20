# flowplane-dpdk on `nfkit` — a Rust DPDK network-function substrate

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Related:** `2026-07-20-dataplane-substrate-ovs-afxdp-design.md` (this is the DPDK thread, now scoped as a real build); `2026-07-20-geneve-overlay-design.md` (designed-not-scheduled).

## 1. Summary

Build a **DPDK version of flowplane** as a *conforming node role* of the existing dataplane compatibility contract, on top of a new **flowplane-agnostic Rust DPDK network-function substrate crate, `nfkit`**. The datapath logic is reused wholesale from `flowplane-core` via a fourth `Pkt`/`Maps` backend — DPDK provides the I/O, memory, offload, and run-to-completion runtime, not the packet logic.

**The key enabler (from research, grounded):** DPDK's `ethdev` abstraction + EAL `--vdev` lets one binary run on a real NIC, `net_af_xdp` (laptop), `net_tap`, or `net_pcap` (deterministic CI) selected **by config, zero code change** — which directly satisfies the "local debugging without a smartNIC" requirement.

## 2. Goals / non-goals

**Goals:** a highly-scalable run-to-completion DPDK dataplane with functional parity to eBPF flowplane; best-practice offload (symmetric RSS, checksum/TSO, `rte_flow`); one binary that runs on NIC / af_xdp / tap / pcap; container (memif) and VM (vhost-user) edges; maximum reuse of `flowplane-core`; a publishable, maintained `nfkit` substrate.

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

## 8. Offload strategy (DPDK best practices)

- **Enable:** RX/TX checksum, tunnel-aware TSO, symmetric RSS. Query `dev_info` and degrade gracefully (so `net_pcap`/`tap`/`af_xdp` — which lack HW offload — still run the same code).
- **`rte_flow`:** symmetric-RSS action + `MARK`; steering. Established-flow **offload seam** (future): decap/CT/NAT/count/mark on the mlx5 **E-Switch** for elephant flows; first-packet/slow-path stays in the RTC lcore. **Our custom IPIP encap is NOT HW-encap-offloadable** (only VXLAN/GRE/MPLS) → encap stays in software; CT/NAT/steer are offloadable. This is the same established-flow seam the CompiledNIC design anticipates.
- **Fabric ECMP:** the outer IPv6 **flow label** (already implemented in `flowplane-core`) carries per-flow entropy for ToR ECMP without inner parsing.

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
3. **Offload** — symmetric RSS, checksum/TSO, `rte_flow` builder; inner-RSS on mlx5.
4. **Container edge** — memif.
5. **VM edge** — vhost-user + tap fallback.
6. **Control-plane `DataplaneProgrammer`** — CompiledNIC/routebus → DpdkMaps/rte_flow; mixed-fabric validation.

Phases 3–6 start only after phase 2 proves byte-parity + an acceptable real-NIC perf number.

## 13. Risks / open questions

- **Binding maintenance:** we own `dpdk-sys` + the inline-fn C shim across DPDK LTS churn. Mitigation: keep the FFI boundary shaped like the upstream RFC to swap later.
- **`rte_mbuf` single-segment assumption** (jumbo/scatter) — accept single-segment v1; seg-aware `Pkt` is a follow-up.
- **DPDK requires hugepages/EAL for its tests** — mitigated by keeping pure logic in the DPDK-free `flowplane-core` sim; only `nfkit`/integration tests need EAL (CI with hugepages or a DPDK container).
- **vhost-user + KubeVirt** wiring is non-trivial (hugepage-backed VMs, socket lifecycle) — tap fallback de-risks.
- **Per-lcore control-plane fan-out** — programming N lcores per CompiledNIC update; define the RCU/handle model in phase 6.
- **`nfkit` naming / open-sourcing** — placeholder; decide before publish.
- **Symmetric RSS on non-mlx5 / vdev backends** — af_xdp/tap/pcap won't offer HW RSS; single-lcore or software steering in dev is acceptable (perf only matters on real NICs).
- **Scope:** "all edges" is large; the phase-2 gate + strict phase ordering is the control.
