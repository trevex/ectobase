# nfkit Milestone 2 — multi-queue packet-I/O core → RSS l2fwd on pcap/af_xdp

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent design:** `2026-07-20-flowplane-dpdk-nfkit-design.md` (§5/§5.1 — nfkit substrate + safety model). **Builds on:** Milestone 1 (`dpdk-sys` + `nfkit::Eal`), branch `design/flowplane-dpdk`.

## 1. Goal

Build the rest of `nfkit`'s **safe, zero-cost packet-I/O core** — `Mempool`, `Mbuf`, multi-queue `Port`/`RxQueue`/`TxQueue`, and a per-lcore run-to-completion `LcoreRuntime` — and prove it with an **RSS l2fwd** running across lcores, validated on `net_pcap` (deterministic CI) and `net_af_xdp` (automated veth loopback). Still **flowplane-agnostic**: no `flowplane-core` coupling (that is Milestone 3, the datapath gate).

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Burst container | **`ArrayVec<Mbuf, 32>`** (heapless; zero heap alloc) |
| Datapath surface | **Multi-queue + RSS + per-lcore runtime** (shared-nothing RTC) |
| af_xdp validation | **Automated veth+af_xdp loopback test** (privileged; auto-skips unprivileged) |
| RSS | **Basic RSS** (`RTE_ETH_MQ_RX_RSS`, `rss_hf & dev_info`); symmetric-Toeplitz deferred to M3 |
| Lcore launch | **`rte_eal_remote_launch`** (idiomatic DPDK RTC), not `std::thread` |
| Scope boundary | No `flowplane-core`, no offload/rte_flow, no MbufPkt/DpdkMaps (all M3+) |

## 3. Components (all new; each a focused file)

```
flowplane/nfkit/src/
  mempool.rs   Mempool — RAII pktmbuf pool, one per NUMA socket
  mbuf.rs      Mbuf — owned rte_mbuf handle; data views; head/tail ops; burst type alias
  port.rs      Port (ethdev RAII) + RxQueue/TxQueue (!Send, burst rx/tx)
  runtime.rs   LcoreRuntime — per-lcore worker launch via rte_eal_remote_launch
  backend.rs   Backend enum + PortSpec → EAL args + port config (write-once-run-anywhere)
  lib.rs       re-exports (Eal already present)
flowplane/dpdk-sys/
  shim.{h,c}   += nfkit_pktmbuf_{prepend,append,adj,trim,mtod,data_len,pkt_len}
  build.rs     DRIVERS += net/af_xdp
flowplane/nfkit/
  examples/l2fwd.rs        RSS l2fwd across lcores (runnable on any backend)
  tests/l2fwd_pcap.rs      deterministic pcap DoD + Mbuf unit tests
  tests/afxdp_loopback.rs  gated veth+af_xdp e2e (skips if unprivileged/no hugepages)
hack/dpdk/afxdp-loopback.sh  veth setup + scapy inject/assert harness
Cargo.toml (nfkit)          += heapless dep
```

## 4. The safe `Mbuf` ownership model (the crux)

- **`Mbuf` owns exactly one `rte_mbuf`.** `Drop` calls `nfkit_pktmbuf_free`. Move-only (no `Clone`).
- **Data access:** `len() -> usize` (data_len), `data(&self) -> &[u8]` / `data_mut(&mut self) -> &mut [u8]` — slices bound to the mbuf's lifetime (built from `nfkit_pktmbuf_mtod` + `data_len`). `prepend/append/adjust/trim(&mut self, n) -> Result<&mut [u8], MbufError>` via the new shim wrappers (bounds-checked in DPDK; NULL → `Err`).
- **Alloc:** `Mempool::alloc(&self) -> Option<Mbuf>` (`nfkit_pktmbuf_alloc`, `None` on pool exhaustion).
- **Tx ownership transfer:** `TxQueue::tx(&mut self, burst: &mut ArrayVec<Mbuf, 32>) -> usize` sends a prefix; **sent mbufs are `mem::forget`-ed into DPDK** (DPDK frees them post-transmit — no double free), and **un-sent mbufs remain owned in the ArrayVec** (caller retries or drops → frees). Never leaks, never double-frees.
- **Rx:** `RxQueue::rx(&mut self, out: &mut ArrayVec<Mbuf, 32>)` fills `out` with owned mbufs from `nfkit_eth_rx_burst`.
- All `unsafe` confined to `mbuf.rs`, each with a `// SAFETY:` invariant (mtod pointer validity within the mbuf's dataroom, exclusive `&mut` for `data_mut`, ownership transfer on tx).

## 5. Multi-queue / RSS + `LcoreRuntime`

- **`Port::configure(spec)`**: `rte_eth_dev_configure` with `nb_rx/tx_q = n_workers`, `mq_mode = RTE_ETH_MQ_RX_RSS`, `rss_hf = DEFAULT & dev_info.flow_type_rss_offloads`; one `rx_queue_setup`/`tx_queue_setup` per worker (socket-local mempool); `rte_eth_dev_start`. RAII `Drop` → stop + close. Backends without HW RSS (pcap/tap/null) degrade to a single queue (query `dev_info.max_rx_queues`).
- **`Port::take_queues() -> Vec<(RxQueue, TxQueue)>`**: hands each worker its own `!Send` queue pair (moved onto the worker's lcore — misuse across lcores is a compile error).
- **`LcoreRuntime`**: `launch(worker: impl Fn(WorkerCtx) + Send)` runs the closure on every worker lcore via `rte_eal_remote_launch` (an `extern "C"` trampoline over a `Box<dyn Fn>`), joins with `rte_eal_mp_wait_lcore` on drop. `WorkerCtx` gives the worker its lcore id, queue index, and its `(RxQueue, TxQueue)`. Each worker owns a socket-local `Mempool`.
- **RTC model:** RSS spreads flows to per-lcore rx queues; each lcore polls its queue and processes to completion. Shared-nothing — no cross-lcore locking. (Symmetric-Toeplitz to pin both flow directions to one lcore is the M3 offload-phase upgrade.)

## 6. Backends — write-once-run-anywhere (`backend.rs`)

`enum Backend { Nic { pci }, AfXdp { iface, queues }, Pcap { rx, tx }, Tap { name }, Null }` → produces the EAL `--vdev`/args and the port config. The l2fwd + LcoreRuntime code is **identical** across backends; only `Backend` differs:
- `Null`/`Pcap`/`Tap` → `--no-huge`, single queue (functional/CI).
- `AfXdp` → hugepages, up to `queues` rx/tx queues.
- `Nic` → real device, full multi-queue/RSS.

## 7. Testing

**Tier 1 — deterministic, CI on this host today (`--no-huge`, no NIC):**
- `Mbuf` unit tests: alloc → prepend/append/adjust/trim byte-exact + bounds errors; `Drop` frees (pool count returns to full); tx ownership (sent forgotten, un-sent retained).
- `tests/l2fwd_pcap.rs`: `Backend::Pcap` — feed `in.pcap` (a few Ethernet frames), run l2fwd, assert `out.pcap` frames have src/dst MAC swapped and payload intact.

**Tier 2 — automated af_xdp e2e (privileged; auto-skips):**
- `hack/dpdk/afxdp-loopback.sh`: create veth pair `vv0<->vv1`, reserve hugepages if possible, run the l2fwd example on `Backend::AfXdp{iface:vv0}`, inject a frame on `vv1` via scapy (in devShell), capture on `vv1`, assert the swapped-MAC frame returns.
- `tests/afxdp_loopback.rs`: drives the script; **skips with a clear message when not root / no hugepages / af_xdp PMD absent**, so `cargo test` stays green everywhere and the full e2e runs in a privileged CI job (or locally after `sudo sysctl vm.nr_hugepages=1024`).

## 8. Definition of Done

- `cargo test -p nfkit` (inside `nix develop`): Mbuf unit tests + `l2fwd_pcap` pass with `--no-huge` (no NIC), and `afxdp_loopback` runs (or cleanly skips when unprivileged).
- `cargo run -p nfkit --example l2fwd -- <backend args>` forwards packets on `net_pcap` and (privileged) `net_af_xdp`.
- With reserved hugepages + privileges (CI job or local sudo), the af_xdp veth loopback forwards a real frame end-to-end.
- Default host build + `flowplane-sim` tests still untouched (nfkit stays opt-in).
- `dpdk-sys` shim extended + `net/af_xdp` in the DPDK build; cache still hits (new drivers change the cache key → one rebuild, then cached).

## 9. Risks / open questions

- **`rte_eal_remote_launch` trampoline** is the one genuinely delicate `unsafe`: a `Box<dyn Fn>` must outlive the C worker; `LcoreRuntime` must `mp_wait_lcore`-join before dropping the closure. Design + test this carefully (a worker that panics must not unwind across the C boundary — catch + abort or set a flag).
- **af_xdp on veth** needs the veth end up + XDP-capable; net_af_xdp zero-copy won't apply on veth (copy mode) — fine for a functional loopback. Needs `CAP_NET_ADMIN` + hugepages; the gated-skip keeps CI green.
- **Re-enabling `net/af_xdp`** in the DPDK build requires libbpf/libxdp at DPDK-build time — the devShell has `libbpf` + `xdp-tools.lib`; verify the meson build picks up the af_xdp PMD (it may need the include/lib paths; adjust the `dpdk-sys` build if the driver is silently skipped).
- **Partial-tx semantics** under load (tx ring full) — the ArrayVec-retain path must be correct; unit-test it with a `net_null` tx that accepts fewer than offered (or a small tx ring).
- **`heapless::Vec`/`ArrayVec`** vs the `arrayvec` crate — pick one small, well-maintained fixed-cap vec; both fine.
