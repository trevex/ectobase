# nfkit Milestone 3 — flowplane-core on DPDK (uplink + guest-egress), byte-parity gate

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md` (§6 the Pkt/Maps 4th backend; §8 offload). **Builds on:** M1 (`dpdk-sys` + `Eal`), M2 (`Mempool`/`Mbuf`/`Port`/`LcoreRuntime`). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Compose the existing **`flowplane-core`** datapath onto DPDK for the **uplink-ingress and guest-egress** paths, backed by a real **`rte_hash`** `Maps` implementation, and prove **byte-parity with the sim** (and, transitively via the sim's anchors, with the eBPF dataplane). This is the Phase-2 gate: after M3, the flowplane datapath provably runs on DPDK producing identical output to the eBPF version — the compatibility-contract thesis demonstrated, not asserted.

**Parity chain:** `DPDK ==(shared generic orchestrator)== sim ==(existing BPF_PROG_TEST_RUN anchors)== eBPF`. The eBPF dataplane is **not modified** — it stays anchored to the sim.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Orchestration seam | **Shared generic orchestrator** (`process_uplink`/`process_guest_tx` in flowplane-core); sim + DPDK call it; eBPF untouched |
| `DpdkMaps` backing | **Real `rte_hash`** (per-lcore-capable), via a safe typed `DpdkHash<K,V>` |
| Scope | **Uplink ingress + guest egress** (both paths) |
| `MbufPkt` | **Single-segment** (matches M2 `Mbuf`) |
| EDT departure time | **Computed** (`meter::edt_egress`) but **not yet wired to the mbuf tx-timestamp** (that HW-shaping integration is a later milestone); M3 checks datapath *bytes* + `Action` |
| RSS | basic (symmetric-Toeplitz = offload phase) |
| Test lcore model | single-lcore for parity/e2e; `DpdkMaps`/rte_hash built per-lcore-capable |

## 3. Components

```
flowplane/dpdk-sys/           rte_hash bindings (+ tiny shim only if a helper is inline)
flowplane/nfkit/src/
  mbuf_pkt.rs   MbufPkt: flowplane_core::pkt::Pkt over an Mbuf
  dpdk_hash.rs  DpdkHash<K,V> — safe typed rte_hash (key bytes + companion value slab)
  dpdk_maps.rs  DpdkMaps: flowplane_core::maps::Maps over DpdkHash + single cells
flowplane-core/src/
  datapath.rs   process_uplink<P,M>, process_guest_tx<P,M> (extracted from SimNode)
flowplane-sim/src/sim.rs      SimNode::uplink/guest_tx call the extracted fns (behaviour identical)
flowplane/nfkit/tests/
  parity_uplink.rs / parity_guest_tx.rs   DPDK-vs-sim byte anchors
  datapath_pcap.rs                        net_pcap rx->process->tx e2e
```

### 3.1 `MbufPkt: Pkt`
Wraps an `Mbuf` (owned, from M2). Implements the `Pkt` trait entirely via M2 shim ops:
- `len` → `nfkit_pktmbuf_data_len`; `logical_len` → `nfkit_pktmbuf_pkt_len` (single-seg: equal).
- `read_array::<N>(off)` → bounds-check `off+N <= len`, copy from `mtod+off`.
- `write_bytes(off, src)` → bounds-check, copy into `mtod+off`. `write_array::<N>` default is fine.
- `grow_head(delta)` → `nfkit_pktmbuf_prepend(delta)` (returns new front); `shrink_head(delta)` → `nfkit_pktmbuf_adj(delta)`.
- `set_tail` → default `false` (uplink/guest-egress paths don't resize the tail; DHCP does, out of scope).
All `unsafe` confined here with `// SAFETY:` (pointer validity within dataroom, `off+N` bound). Consumers write none.

### 3.2 `DpdkHash<K, V>` + `DpdkMaps`
- **`DpdkHash<K: Copy, V: Copy>`**: safe wrapper over `rte_hash`. Key = the raw bytes of `K` (`K` must be `#[repr(C)]` POD with a stable, padding-free layout — the flowplane-common key structs already are, since eBPF uses them as BPF-map keys). Values live in a companion `Vec<V>` (or `Vec<Option<V>>`) indexed by the `int32` position `rte_hash_add_key` returns; `lookup` returns the position → `vec[pos]`. `insert`/`get`; RAII `rte_hash_free` on drop. Any DPDK hash function is fine — parity is about the key→value mapping, not hash values.
- **`DpdkMaps`**: one `DpdkHash` per keyed map — `conntrack: DpdkHash<CtKey,CtEntry>` (mutable), `nat`, `underlay`, `route4`, `route6`, `lb`, `maglev`, `fw_rules`, `fw_meta`, `dhcp_meta`, `meter` (mutable) — plus `local`/`dhcp_config` as single cells. Implements every `Maps` method by delegating to the right `DpdkHash`. Per-lcore-capable (each lcore builds its own for the mutable conntrack/nat/meter; read-mostly maps can be shared).

### 3.3 Shared generic orchestrators (`flowplane-core/src/datapath.rs`)
Extract the composition currently inside `SimNode::uplink` and `SimNode::guest_tx` into:
- `process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in: UplinkIn) -> UplinkOut` — LB-dispatch (`lb_select_forward`) → reforward (remote LB) | ingress firewall (new-flow) → conntrack create (non-LB) → `decap_and_rewrite` → ingress meter. Mirrors `try_uplink_rx`.
- `process_guest_tx<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in: GuestTxIn) -> GuestTxOut` — conntrack + egress firewall → VIP snat/dnat → route4 → network SNAT → conntrack-track → deliver (local vs encap) → EDT stamp + encap (`write_outer_v6` with the inner-flow `flow_label`). Mirrors `forward_decision_v4` + `tc_guest_tx`.

`UplinkIn`/`GuestTxIn` carry exactly what `SimNode` passes today (vni, underlay value, outer_dst, `Local`, `PortMeta`, `now`, `src_ifindex`). `*Out` returns `{ action: Action, edt_tstamp: Option<u64> }`. `SimNode::uplink`/`guest_tx` become thin wrappers that call these and repackage into `SimOut` — **existing sim tests + anchors must remain byte-identical and green** (this is the refactor's acceptance test). The eBPF wrapper is not touched; it remains anchored to the sim.

## 4. Parity harness

**DPDK anchor (unit, deterministic, `--no-huge`):** for a crafted input frame + a fixed set of map contents populated identically into `DpdkMaps` and `MemMaps`, assert `process_uplink`/`process_guest_tx` over **`MbufPkt`+`DpdkMaps`** returns byte-identical output frame + `Action` (+ `edt_tstamp`) to **`VecPkt`+`MemMaps`**. Because the orchestration is shared, this precisely isolates "does `MbufPkt` behave like `VecPkt` and `DpdkMaps` like `MemMaps`." Cover: uplink base decap, uplink LB reforward, guest-egress local delivery, guest-egress encap (with flow-label), SNAT, firewall drop.

**net_pcap e2e:** a small runner (like the M2 l2fwd but calling `process_uplink`) that rx's a crafted encapped frame from `net_pcap`, runs the datapath, and tx's the result; assert the output pcap matches the sim's output for the same input — proving the datapath works through real DPDK rx/tx.

## 5. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: `MbufPkt` unit tests, `DpdkHash`/`DpdkMaps` tests, and the uplink + guest-egress DPDK-vs-sim parity anchors all pass (byte-identical); `datapath_pcap` e2e passes.
- `cargo test -p flowplane-sim` + the eBPF anchors still pass unchanged — the `SimNode` refactor to call the shared orchestrators preserved behaviour exactly.
- Default host build + existing tests untouched (nfkit/dpdk-sys opt-in).
- `dpdk-sys` gains rte_hash bindings; DPDK cache still hits.

## 6. Phasing (for the plan)

1. **`rte_hash` bindings** (dpdk-sys) + safe **`DpdkHash<K,V>`** + unit tests (add/lookup/miss/overwrite; RAII free).
2. **`DpdkMaps`** implementing `Maps` over `DpdkHash` + single cells; unit test a few getters/inserters.
3. **`MbufPkt: Pkt`** + unit tests (read/write/grow/shrink parity vs VecPkt on the same bytes).
4. **Extract `process_uplink`** into flowplane-core; refactor `SimNode::uplink` to call it; **all sim tests + `anchor_uplink` stay green**. Then the **DPDK uplink parity anchor**. ← natural gate.
5. **Extract `process_guest_tx`**; refactor `SimNode::guest_tx`; sim tests + anchors green. Then the **DPDK guest-egress parity anchor** (encap + flow-label + SNAT).
6. **`net_pcap` e2e** runner + test.

## 7. Risks / open questions

- **The `SimNode` refactor must be byte-preserving.** Extracting the orchestration into generic fns must not change the composed order/gates. Acceptance = the full `flowplane-sim` suite + the `anchor_*` tests stay green. Do the extraction as a pure move (same calls, same order), not a rewrite.
- **Key layout for rte_hash.** `CtKey`/`NatKey`/`LbKey`/etc. must be `#[repr(C)]` with no padding so hashing their raw bytes is stable and matches lookups. Verify each key type's layout (they're already BPF-map keys, so this should hold); add `static_assertions`-style size checks in `DpdkHash`.
- **`DpdkHash` value slab.** `rte_hash_add_key` returns a stable position for the lifetime of the key; store values in a `Vec` sized to `entries`. Handle delete/overwrite (conntrack updates re-insert the same key → same position → overwrite the slab slot). Confirm rte_hash position stability semantics.
- **EDT `edt_tstamp` threading.** M3 returns it but does not write it to the mbuf; ensure the parity anchor compares it as metadata (not in the packet bytes). Wiring EDT → mbuf tx-timestamp is a later shaping milestone.
- **Single-lcore assumption.** The parity/e2e tests run on one lcore; the per-lcore conntrack/nat model (symmetric-RSS pinning both flow directions to one lcore) is exercised for real only in a later multi-lcore/perf milestone.
- **`nfkit` depends on `flowplane-core`** now (for the traits + orchestrators + `MbufPkt`). Confirm the dependency direction is clean (flowplane-core is `no_std` + trait-only; nfkit adds the DPDK backend) and doesn't pull DPDK into flowplane-core.
