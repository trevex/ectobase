# nfkit Milestone 6 (final datapath) — control-plane responders (ARP/ND + DHCPv4) on DPDK, byte-parity

**Date:** 2026-07-20
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M3 (`MbufPkt`/`DpdkMaps` + `datapath.rs`), M4 (NAT), M5 (WAN edge). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Port the last two `SimNode` datapaths — **`guest_arp_nd`** (ARP/ND gateway responder) and **`guest_dhcp4`** (DHCPv4 OFFER/ACK responder) — into shared generic orchestrators in `flowplane-core/src/datapath.rs`, implement the one missing `Pkt` primitive **`MbufPkt::set_tail`** (DHCP's `bpf_xdp_adjust_tail`), and prove DPDK byte-parity. **This completes the datapath port:** after M6 every `SimNode` forwarding + responder path runs on DPDK byte-identically to the eBPF version, via the `DPDK ==(shared orchestrator)== sim ==(BPF_PROG_TEST_RUN anchors)== eBPF` chain. The eBPF dataplane is not modified.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Orchestration seam | Shared generic `process_guest_arp_nd` / `process_guest_dhcp4` in `datapath.rs`; sim wrappers call them; eBPF untouched |
| `MbufPkt::set_tail` | **Implement it** — grow via `nfkit_pktmbuf_append` + **zero-fill the grown region**, shrink via `nfkit_pktmbuf_trim`; single-segment |
| ARP/ND maps | **None** (`process_guest_arp_nd<P>`) — in-place `arp_reply`/`nd_reply`, no maps, no `set_tail` |
| DHCP maps | **`&M` read-only** (`process_guest_dhcp4<P,M>`) — `dhcp::write` reads `dhcp_config`/`dhcp_meta` only; no `&mut` |
| DpdkMaps | **No changes** — DHCP support already present (`set_dhcp_config`/`add_dhcp_meta` + trait impls) |
| dpdk-sys | **No change** — `nfkit_pktmbuf_append`/`_trim` exist since M2 |

## 3. Components

```
flowplane/nfkit/src/mbuf_pkt.rs   + MbufPkt::set_tail (grow zero-fill / shrink)  ← the one new primitive
flowplane-core/src/datapath.rs    + process_guest_arp_nd<P>, + process_guest_dhcp4<P,M> (+ In-structs)
flowplane-sim/src/sim.rs           SimNode::guest_arp_nd / guest_dhcp4 → thin wrappers
flowplane/nfkit/tests/
  mbuf_pkt.rs        + set_tail byte-parity-vs-VecPkt unit case (grow zero-fill / shrink / equal)
  parity_arp_nd.rs   DPDK-vs-sim anchor: ARP reply, ND NA, non-ARP/ND Pass
  parity_dhcp4.rs    DPDK-vs-sim anchor: DISCOVER→OFFER (exercises set_tail + DHCP_CONFIG/DHCP_META)
```

### 3.1 `MbufPkt::set_tail` (the crux new primitive)

`Pkt::set_tail(&mut self, new_len) -> bool` sets an ABSOLUTE frame length — grow (zero-fill) or shrink at the tail; mirrors `bpf_xdp_adjust_tail` / `bpf_skb_change_tail`. `VecPkt` does `buf.resize(new_len, 0)` (zero-fills grown bytes). `MbufPkt` (currently the trait default `false`) implements it over the existing shim:
```
cur = data_len()
if new_len > cur:   p = nfkit_pktmbuf_append(delta); if p.is_null() { return false }; memset(p, 0, delta)  // ZERO-FILL
elif new_len < cur: if nfkit_pktmbuf_trim(delta) != 0 { return false }
// new_len == cur → no-op
true
```
**The zero-fill on grow is the load-bearing parity detail:** mbuf tailroom contains stale mempool bytes; `dhcp::write` fills the fixed reply but any byte it does not touch up to `REPLY_LEN` must be `0` to match `VecPkt`'s zeroed grow. Single-segment only (documented; REPLY_LEN ≈ 300 B ≪ 2 KB dataroom). Unit test asserts `MbufPkt::set_tail` produces byte-identical results to `VecPkt::set_tail` for grow (new tail zeroed), shrink (truncated), and equal (no-op).

### 3.2 `process_guest_arp_nd<P: Pkt>` (no maps)

```rust
pub struct GuestArpNdIn { pub gateway_ipv4: [u8; 4], pub gateway_ipv6: [u8; 16], pub ingress_ifindex: u32 }
pub fn process_guest_arp_nd<P: Pkt>(pkt: &mut P, in_: &GuestArpNdIn) -> Action;
```
Verbatim move of `guest_arp_nd` (`sim.rs:332-350`): `if arp_reply(pkt, in_.gateway_ipv4, GW_MAC) || nd_reply(pkt, in_.gateway_ipv6, GW_MAC) { Redirect(in_.ingress_ifindex) } else { Pass }`. `arp_reply`/`nd_reply` are in-place same-size rewrites (no maps, no `set_tail`). The wrapper passes `meta.gateway_ipv4`/`meta.gateway_ipv6`/`ingress_ifindex`.

### 3.3 `process_guest_dhcp4<P: Pkt, M: Maps>` (read-only maps)

```rust
pub struct GuestDhcp4In { pub guest_ipv4: [u8; 4], pub gateway_ipv4: [u8; 4], pub ingress_ifindex: u32 }
pub fn process_guest_dhcp4<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &GuestDhcp4In) -> Action;
```
Verbatim move of `guest_dhcp4` (`sim.rs:360-391`): `dhcp::parse(pkt)` (None→Pass) → `pkt.set_tail(dhcp::REPLY_LEN)` → `dhcp::write(pkt, &req, in_.guest_ipv4, in_.gateway_ipv4, GW_MAC, maps, in_.ingress_ifindex)` → `Redirect(in_.ingress_ifindex)` if ok else `Pass`. The wrapper passes `meta.guest_ipv4`/`meta.gateway_ipv4`/`ingress_ifindex` + `&self.maps`. `dhcp::write<P,M>` reads `dhcp_config()`/`dhcp_meta()` — both implemented on `DpdkMaps`.

## 4. Parity harness

Same shape as M3-M5 (EAL-once, `--test-threads=1`, `mp_bytes`/`run_dpdk`/`run_sim`; identical map population; positive Action asserted before byte-compare). Reuse fixtures from `flowplane-sim/src/arp_nd_test.rs` (`arp_request_frame()`, `ns_frame()`, `port_meta()`, `INGRESS_IFINDEX`) and `dhcp_test.rs` (the DISCOVER frame builder + how it seeds `DHCP_CONFIG`/`DHCP_META`, `port_meta()`, `INGRESS_IFINDEX`).
- **`parity_arp_nd.rs`** (no maps): (a) ARP request → reply (`Redirect(ingress)` + byte parity), (b) ND NS → NA (`Redirect(ingress)` + byte parity), (c) a non-ARP/ND frame → `Pass` (output == input both sides).
- **`parity_dhcp4.rs`** (`&M`): DISCOVER → OFFER — seed `MemMaps`+`DpdkMaps` identically (`set_dhcp_config`/`add_dhcp_meta` for `INGRESS_IFINDEX`), assert `Redirect(ingress)` + **full `REPLY_LEN`-frame byte parity** (this is what exercises `MbufPkt::set_tail` on the DPDK substrate — a request shorter than `REPLY_LEN` forces the zero-filling grow). Optionally add a non-DHCP → `Pass` case.

## 5. Definition of Done

- `cargo test -p nfkit -- --test-threads=1`: `mbuf_pkt` (with set_tail), `parity_arp_nd`, `parity_dhcp4`, + all M3-M5 anchors pass byte-identical DPDK-vs-sim.
- `cargo test -p flowplane-sim` passes **unchanged** — the two `SimNode` refactors are byte-preserving (`arp_nd_test.rs` + `dhcp_test.rs` are the witnesses).
- The `flowplane` `anchor_*` crate still compiles unchanged.
- `flowplane-core` gained two fns + two In-structs, still `no_std`, still no DPDK dep; **no new `Maps` trait method** → no `GlobalMaps`/eBPF change.
- `MbufPkt::set_tail` implemented + parity-tested; default host build untouched.
- **The datapath is now fully ported to DPDK** (uplink, guest-egress, NAT return, NAT64 egress/ingress, WAN-VIP, ARP/ND, DHCPv4).

## 6. Phasing (for the plan)

1. **`MbufPkt::set_tail`** (grow zero-fill / shrink) + `mbuf_pkt.rs` unit parity case. ← the new primitive; gate before the DHCP anchor.
2. **Extract `process_guest_arp_nd`** (no maps) + wrapper; sim green; `parity_arp_nd.rs`.
3. **Extract `process_guest_dhcp4`** (`&M`) + wrapper; sim green; `parity_dhcp4.rs` (exercises set_tail).

## 7. Risks / open questions

- **`set_tail` zero-fill** — the parity-critical detail (§3.1). If omitted, DHCP replies differ only in the tail padding the writer doesn't touch — a subtle, real bug the `parity_dhcp4` full-frame compare will catch. Test grow explicitly with a byte-parity assert vs `VecPkt`.
- **Single-segment `set_tail`** — grow must fit the mbuf tailroom; `REPLY_LEN` (~300 B) fits a standard 2 KB mbuf. Document the single-segment assumption (consistent with all M3 `MbufPkt` ops).
- **`arp_reply`/`nd_reply` size** — assumed in-place same-size (no `set_tail`); the sim-green gate confirms. If either resizes, Task 1's `set_tail` already covers it.
- **Verbatim moves** — Tasks 2/3 Step "sim suite green" is the acceptance test; if an `arp_nd_test`/`dhcp_test` case changes bytes, the move diverged — fix it.
- **DHCP fixture reuse** — read `dhcp_test.rs` for the exact DISCOVER frame + `DHCP_CONFIG`/`DHCP_META` contents so `DpdkMaps` seeds identically; the writer pulls MTU/DNS/hostname from those maps, so a mismatch changes bytes.
