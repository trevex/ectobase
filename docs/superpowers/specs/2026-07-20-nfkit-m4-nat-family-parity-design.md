# nfkit Milestone 4 — NAT-family datapath on DPDK (NAT return + NAT64 egress/ingress), byte-parity

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M1 (`dpdk-sys`+`Eal`), M2 (`Mempool`/`Mbuf`/`Port`/`LcoreRuntime`), **M3** (`MbufPkt`/`DpdkHash`/`DpdkMaps` + the shared `process_uplink`/`process_guest_tx` orchestrators + the parity-anchor discipline). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Extend the M3 parity chain to the **NAT family**: port the three remaining NAT/NAT64 datapath orchestrations from `SimNode` into shared generic `process_*` functions in `flowplane-core`, and prove each runs **byte-identically on DPDK** (`MbufPkt`+`DpdkMaps`) vs the sim (`VecPkt`+`MemMaps`). After M4 the overlay NAT forwarding story is covered by the same **`DPDK ==(shared orchestrator)== sim ==(existing BPF_PROG_TEST_RUN anchors)== eBPF`** chain M3 established. The eBPF dataplane is **not modified**.

This is the first of the "port remaining datapaths" follow-on milestones (the others — edge/WAN N-S, and the guest control-plane responders ARP/ND + DHCPv4 — are separate specs).

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Orchestration seam | **Shared generic orchestrators** in `flowplane-core/src/datapath.rs` (same file as M3); sim wrappers call them; eBPF untouched |
| Scope | **NAT return** (`uplink_nat_return`) + **NAT64 egress** (`guest_tx_nat64`) + **NAT64 ingress** (`uplink_nat64_ingress`) |
| `nat_ips` membership | **New `Maps::is_nat_ip(vni, ip) -> bool` trait method** (option a below) |
| `uplink_nat64_ingress` maps | **None** — it takes `rev: &CtEntry` as input and calls only pure core fns; its orchestrator is `<P: Pkt>` with no `Maps` bound |
| Extraction style | **Verbatim move** (same calls/order/gates); acceptance = full `flowplane-sim` suite stays green |
| Test model | unit parity anchors, `--no-huge`, EAL-once per test file, `--test-threads=1` (identical to M3) |

### 2.1 The `nat_ips` design decision (the only genuine fork)

`uplink_nat_return` calls `self.maps.nat_ips.contains(&(vni, key.dst_ip))` (`flowplane-sim/src/sim.rs:158`) to demux NAT returns peer-independently: if the inner dst is a registered public NAT IP, it zeroes the external src ip+port so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)` reverse entry. `nat_ips` is a `HashSet<(u32,[u8;4])>` **field on `MemMaps`**, not a `Maps`-trait method — so a generic `process_*<M: Maps>` cannot reach it.

- **(a) CHOSEN — add `Maps::is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool`.** `MemMaps` implements it by delegating to `nat_ips` → **byte-preserving** (the sim computes the exact same predicate, suite stays green). `DpdkMaps` backs it with a `DpdkHash<NatIpKey, u8>` populated identically in the anchor. The eBPF program does **not** implement the `Maps` trait (it calls BPF map helpers directly), so this is a MemMaps+DpdkMaps-only change — zero eBPF blast radius. Mirrors how the eBPF path already point-looks-up a NAT_IPS map.
- (b) Reject: fold into `nat_get`. `nat_get` is keyed `(vni, guest_ipv4)`; this predicate is on the *public* nat_ip — different key space, not byte-preserving.
- (c) Reject: compute membership in the wrapper and pass a bool into the In-struct. Pushes a map-dependent decision out of the datapath (diverges from the eBPF structure; obscures the anchor).

## 3. Components

```
flowplane-core/src/maps.rs      + trait method: is_nat_ip(&self, vni, ip) -> bool
flowplane-core/src/datapath.rs  + process_uplink_nat_return<P,M>, + process_guest_tx_nat64<P,M>,
                                + process_uplink_nat64_ingress<P>  (+ their In-structs)
flowplane-sim/src/maps.rs        MemMaps::is_nat_ip delegates to `nat_ips`
flowplane-sim/src/sim.rs         uplink_nat_return / guest_tx_nat64 / uplink_nat64_ingress → thin wrappers
flowplane/nfkit/src/dpdk_maps.rs + DpdkMaps::is_nat_ip over DpdkHash<NatIpKey,u8> + add_nat_ip setter
flowplane/nfkit/tests/
  parity_nat_return.rs   DPDK-vs-sim byte anchor (reverse-DNAT apply + decap)
  parity_nat64.rs        DPDK-vs-sim byte anchors: NAT64 egress + NAT64 ingress
```

### 3.1 The three orchestrators (verbatim moves)

- **`process_uplink_nat_return<P: Pkt, M: Maps>(pkt, maps, &UplinkNatReturnIn) -> Action`** where `UplinkNatReturnIn { vni: u32, tap_ifindex: u32, guest_mac: [u8; 6] }`. Body = the current `uplink_nat_return`: build inner 5-tuple key; if `maps.is_nat_ip(vni, &key.dst_ip)` zero `src_ip`/`src_port`; `conntrack_get` → if `CT_REWRITE_DST` apply `ct_apply`; `decap_and_rewrite(pkt, tap_ifindex, guest_mac)` → Action. (Substitution: `self.maps.nat_ips.contains(&(vni, key.dst_ip))` → `maps.is_nat_ip(in_.vni, &key.dst_ip)`; `u.tap_ifindex` → `in_.tap_ifindex`.)
- **`process_guest_tx_nat64<P: Pkt, M: Maps>(pkt, maps, &GuestTxNat64In) -> Action`** where `GuestTxNat64In { meta: &PortMeta, local: &Local }`. Body = the current `guest_tx_nat64`: `nat64_egress_parse` (dst-prefix check + `nat_get` config + hash-probe source-port alloc reusing/pinning forward+reverse `CT_F_NAT64` conntrack — **already 100% `Maps`-trait**, verified in `flowplane-core/src/nat64.rs:333`) → Pass on miss; `shrink_head(20)` (v6→v4); `nat64_egress_write` (write_eth=true); `route4_get` → Pass on miss; `grow_head(IPV6_LEN)`+`write_outer_v6` encap toward the nexthop with `EncapParams` from `in_.local` + `in_.meta.underlay_ipv6` → `Redirect(uplink_ifindex)`. No new trait method.
- **`process_uplink_nat64_ingress<P: Pkt>(pkt, &UplinkNat64IngressIn) -> Action`** where `UplinkNat64IngressIn { tap_ifindex: u32, guest_mac: [u8; 6], guest_ipv6: [u8; 16], rev: &CtEntry }`. Body = the current `uplink_nat64_ingress`: `ct_apply(pkt, inner_off, rev)`; `nat64_ingress_parse` → Pass on miss; `shrink_head(20)`; `nat64_ingress_write(pkt, ETH_LEN, GW_MAC, &xlate)` → Drop on fail; `Redirect(tap_ifindex)`. **No `Maps` parameter** — it consumes the reverse `CtEntry` the caller supplies and otherwise runs pure core fns.

Each `SimNode` method becomes a thin wrapper: build `VecPkt::from_bytes(frame)`, construct the In-struct from its args + `self` fields, call the orchestrator, repackage `SimOut { action, pkt: pkt.into_bytes() }`. (Note: none of the three touch `last_tstamp` — NAT64 egress does not run the EDT `edt_egress` step in the current sim; a verbatim move preserves that, so there is no `edt_tstamp` out-value for these fns. If the verbatim move reveals otherwise, thread it identically — do not add a step.)

### 3.2 `Maps::is_nat_ip` + `DpdkMaps` backing

- Trait: `fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool;` added to `flowplane-core/src/maps.rs`.
- `MemMaps`: `self.nat_ips.contains(&(vni, *ip))`.
- `DpdkMaps`: a `DpdkHash<NatIpKey, u8>` where `#[repr(C)] NatIpKey { vni: u32, ipv4: [u8; 4] }` (padding-free — compile-time size assert, like the M3 `Route4Key`); `is_nat_ip` = `self.nat_ips.get(&NatIpKey{vni, ipv4: *ip}).is_some()`; test-only `add_nat_ip(&mut self, vni, ip)` = `insert(&NatIpKey{..}, 1)`, mirroring `MemMaps.nat_ips.insert`.

## 4. Parity harness

Same shape as the M3 anchors (`parity_uplink.rs`/`parity_guest_tx.rs`): reuse the `mp_bytes` helper + `run_dpdk`/`run_sim` pattern; populate `MemMaps` and `DpdkMaps` **identically** via mirrored setters; assert **byte-identical output frame + identical `Action`** between `MbufPkt`+`DpdkMaps` and `VecPkt`+`MemMaps`. Every scenario asserts a **positive** delivery Action (`Redirect(tap)` / `Redirect(uplink)`) before the byte-compare, guarding against a trivially-passing both-drop.

- **`parity_nat_return.rs`** — a returning fabric frame `[OuterEth][OuterIPv6][inner IPv4]` to a NAT'd guest; install a reverse `CT_REWRITE_DST` conntrack entry + `add_nat_ip` on both map impls (reuse the `nat_test.rs` DNAT fixture: `DNAT_VNI`/`DNAT_NAT_IP`). Assert reverse-DNAT'd + decapped bytes + `Redirect(tap)` match.
- **`parity_nat64.rs`** — two scenarios, one EAL init:
  - **egress:** a guest `[Eth][IPv6][L4]` frame with dst in `64:ff9b::/96`; install NAT config (`nat_get`) + route4 + `set_local` identically. Asserts the v6→v4 translate + encap (`shrink_head` **and** `grow_head` both exercised), `Redirect(uplink_ifindex)`, and full encapped-frame byte parity **including the source-port allocation** (the hash-probe allocator must land on the same port on both sides — it will, because it probes `conntrack_get` over identically-populated maps).
  - **ingress:** a returning `[OuterEth][OuterIPv6][inner IPv4]` frame + a crafted reverse `CtEntry` (`xlate_port`, guest v4); assert reverse `ct_apply` + v4→v6 rebuild + `Redirect(tap)` byte parity. (No maps needed — still populate a `DpdkMaps`/`MemMaps` pair for symmetry, but the fn ignores them.)

## 5. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: existing M3 anchors + the new `parity_nat_return` and `parity_nat64` (egress+ingress) all pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim`: all tests still pass **unchanged** (the three `SimNode` refactors + the `MemMaps::is_nat_ip` addition are byte-preserving — the acceptance gate). The `nat_test.rs` scenarios that drive these methods are the load-bearing witnesses.
- The eBPF `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained one trait method + three fns, still `no_std`, still **no DPDK dependency**.
- Default host build + existing tests untouched (nfkit/dpdk-sys stay opt-in).

## 6. Phasing (for the plan)

1. **`Maps::is_nat_ip`** trait method + `MemMaps` impl + `DpdkMaps` impl (`DpdkHash<NatIpKey,u8>` + `add_nat_ip`) + a `DpdkMaps` unit test (add→hit, miss). Sim suite stays green (new method, no call site yet).
2. **Extract `process_uplink_nat_return`** + rewire the `SimNode` wrapper; sim suite green; then `parity_nat_return.rs`. ← first gate.
3. **Extract `process_uplink_nat64_ingress`** (no-maps, simplest) + wrapper; sim suite green; then the ingress scenario of `parity_nat64.rs`.
4. **Extract `process_guest_tx_nat64`** + wrapper; sim suite green; then the egress scenario of `parity_nat64.rs` (the source-port-allocation-parity case).

Order rationale: the trait method first (unblocks nat_return); nat64_ingress before nat64_egress (no-maps → simplest to land + validates the `MbufPkt` shrink+rebuild path before the more complex egress port-allocator).

## 7. Risks / open questions

- **Verbatim extraction is mandatory** (as M3). Each Step "sim suite green" is the acceptance test; if a `nat_test.rs` case changes, the move was not verbatim — fix the move, never the test.
- **`NatIpKey` POD layout** — `{ vni: u32, ipv4: [u8; 4] }` is 8 bytes, no padding; add a compile-time size assert in `DpdkMaps` (same as M3's `Route4Key`).
- **Source-port allocation parity (NAT64 egress).** `nat64_egress_parse` picks the port by `hash5(...)` then probes `conntrack_get` for a free candidate. Parity holds only if both map impls start empty and are populated identically before the call — the anchor must build both from the same fixture and run the allocator once. Assert the full encapped frame (which embeds the allocated port) is byte-identical, catching any allocator divergence.
- **`uplink_nat64_ingress` map-less orchestrator.** Its signature is `<P: Pkt>` with no `M`. Confirm the wrapper still compiles cleanly and the anchor doesn't need a `DpdkMaps` (it may construct one for symmetry but must not require any entries).
- **`nat_test.rs` fixture reuse.** The plan must read `flowplane-sim/src/nat_test.rs` for the exact DNAT + NAT64 frame builders and map contents so `DpdkMaps` populates identically; if a needed `DpdkMaps` setter is missing (e.g. for the reverse CT entry), adding a test-only setter mirroring `MemMaps` is in scope — changing `Maps`-trait *logic* is not.
