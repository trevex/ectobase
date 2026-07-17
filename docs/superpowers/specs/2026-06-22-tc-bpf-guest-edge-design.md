# tc-BPF Guest Edge (Hybrid Datapath) — Design

**Date:** 2026-06-22
**Status:** Approved (brainstorm) — pending implementation plan
**Author:** Niklas Voss (with Claude)

## Problem

The flowplane datapath attaches **native XDP to the kernel tap** that each VM uses via **vhost-net**. Root-cause (see `memory/native-xdp-needs-kvm-vhost.md`): native XDP on a vhost-net tap only runs on the *datacopy fast path* (non-GSO, single-page). Stock virtio guests negotiate GSO/offload, so vhost builds an skb and `tun_xdp_one()` is never reached — **native XDP is silently bypassed** for guest egress. Generic/SKB XDP works (hooks post-skb) but isn't "native", and carries cloned-skb/TCP caveats.

Research (kernel source + Cilium/Calico practice) shows the production VM-edge pattern is **tc-BPF on the host-side virtual device**, with **XDP reserved for the physical NIC**. The real DPDK `dpservice` doesn't use a tap at all (SR-IOV VF + `rte_flow` HW offload); "tap + XDP" was never the production topology. Both future goals — HW offload (tc-flower/`rte_flow`/switchdev) and encryption (XFRM/WireGuard live on the skb path; Cilium disables XDP under encryption) — favor the tc/skb path. Native XDP *hardware* offload is Netronome-NFP-only (EOL); the broadly-supported "XDP" is native **driver** mode (host CPU), a software fast path.

## Goal

A **hybrid datapath**: native XDP on the uplink (a real NIC — the correct, well-supported, software-fast place), **tc-BPF (clsact) on the tap** for the guest edge (GSO-safe, sees all guest egress, can inject replies, encryption-ready). Maps are shared across both. Validation: the ioiab lab runs **without** SKB mode; conformance + netns-e2e stay green.

## Non-goals

- SR-IOV VF / switchdev / `rte_flow` HW offload topology (separate future track).
- Encryption (IPsec/WireGuard) — only the *seam* is kept clean; not built here.
- Replacing the uplink XDP program (it stays; it's the correct XDP usage).

## Architecture — composable: pure core + per-type glue

In eBPF every packet read needs a verifier-visible bounds check, and `data`/`data_end` are plain `usize`. A pure function over `(data, data_end, …)` re-establishes its own bounds checks regardless of caller — which is why the existing `usize`-based helpers (e.g. `parse::l4_ports`) already work in any program type. We exploit this instead of a generic `PktCtx` trait.

**Three layers:**

1. **Pure core (shared, the bulk, `cargo test`-able with no kernel):** parsing, classification, conntrack key/decision, NAT/VIP/LB math, csum, and *serializers* that fill a reply/encap into an already-sized `[data, data_end)` region. Signatures take `usize` bounds + plain values + `ifindex: u32` where needed:
   - `fn classify(data, data_end) -> Verdict` → `Arp(gw) | Nd(gw) | Dhcp | Overlay{route} | Local | Drop`
   - `fn fill_dhcp_offer(data, data_end, req: &DhcpReq, cfg: &DhcpCfg) -> Result<usize,()>` (returns new total len)
   - `fn fill_arp_reply(...)`, `fn fill_nd_reply(...)`
   - `fn write_encap_hdr(data, data_end, out: &RouteOut, local: &Local) -> Result<(),()>`
   - conntrack/nat/vip/lb decision functions (already `usize`/value-based)

2. **Thin glue — written separately for XDP and tc (concrete, ~tens of lines each):** fetch `data`/`data_end`/`ifindex`, perform the room change with the *correct* primitive, re-fetch bounds, call the pure core, map the result to a verdict:
   - `#[xdp] fn uplink_rx(ctx) -> u32` — uses `bpf_xdp_adjust_head`, returns `XDP_*`.
   - `#[classifier] fn tc_guest_tx(ctx) -> i32` — uses `skb_pull_data` + `skb_adjust_room` + `skb_change_tail`, returns `TC_ACT_*`.

3. **Shared `Verdict` / `CtVerdict` enums** are the composition seam between core and glue.

**Why composable (not a `PktCtx` trait):** the divergent ops (`xdp_adjust_head(-len)` vs `skb_adjust_room(+len, MAC)` + `skb_pull_data`) have genuinely different semantics — separate glue states this honestly instead of hiding it behind a leaky uniform method. The pure core becomes ordinary std unit tests (no kernel/root/verifier). Concrete glue means no generics/monomorphization surprises in the verifier. Only ~tens of lines of I/O glue are written twice; the kilolines of logic are shared. Moving the uplink to tc later (for encryption) is just adding a third glue function over the same core.

**Verdict → return-code/redirect mapping:**

| Verdict | XDP glue | tc glue |
|---|---|---|
| Pass | `XDP_PASS` | `TC_ACT_OK` |
| Drop | `XDP_DROP` | `TC_ACT_SHOT` |
| Redirect(i) | `bpf_redirect(i,0)` → `XDP_REDIRECT` | `bpf_redirect(i,0)` → `TC_ACT_REDIRECT` |
| Reflect (reply to guest) | `XDP_TX` | `bpf_redirect(self_ifindex,0)` |
| TailCallDhcp | `GUEST_PROGS_XDP.tail_call` | `GUEST_PROGS_TC.tail_call` |

## Data flow

**Guest egress — tc clsact *ingress* on the tap** (`tc_guest_tx`, may tail-call `tc_guest_dhcp`):
```
guest → vhost → tap → [tc ingress] tc_guest_tx(skb)
  glue: data/data_end/ifindex; skb_pull_data(hdr_len) to make writable
  classify(data,data_end):
    Arp(gw)      → fill_arp_reply()    → bpf_redirect(tap, 0)                       → (→ guest)
    Nd(gw)       → fill_nd_reply()     → bpf_redirect(tap, 0)                       → (→ guest)
    Dhcp         → tail_call tc_guest_dhcp → skb_change_tail(grow)+fill_dhcp_offer()→ bpf_redirect(tap,0)
    Overlay{rt}  → ct/nat/vip/fw/meter → skb_adjust_room(BPF_ADJ_ROOM_MAC)+write_encap_hdr() → bpf_redirect(uplink,0)
                  (room size mirrors the XDP encap's xdp_adjust_head(-IPV6_LEN); exact bytes pinned in the plan)
    Local/none   → TC_ACT_OK (host stack)   |   policy drop → TC_ACT_SHOT
```
At the ingress hook, `bpf_redirect(tap_ifindex, 0)` queues on that device's **egress = toward the guest** — this replaces `XDP_TX`/`reflect`.

**Overlay ingress — native XDP on the uplink (`uplink_rx`, unchanged):**
```
underlay → uplink NIC → [xdp] uplink_rx → decap (xdp_adjust_head +40) → ct/lb/nat64
  → bpf_redirect(tap, 0) → ndo_xdp_xmit → tun ptr_ring → vhost → guest RX
```
This is the kernel's *supported* native guest-injection path (redirect from a different device) and is the path SKB-mode VM↔VM already exercises — kept as-is.

## Loader / clsact wiring

- Tap-side attach switches from `aya::programs::Xdp` to **`aya::programs::SchedClassifier`** + `tc::qdisc_add_clsact(tap)` + attach `TcAttachType::Ingress`. The per-interface create/delete-interface gRPC path swaps its stored `XdpLink` for the tc attachment handle (same lifecycle shape).
- `uplink_rx` attach is unchanged (XDP).
- `GUEST_PROGS` becomes a tc (classifier) prog-array for the DHCP tail-call.
- **ioiab / libvirt-provider unchanged** — same tap device; we attach tc instead of XDP. `FLOWPLANE_SKB_MODE` becomes irrelevant for the guest path. `vnet_hdr` on the tap is harmless to leave.

## Risks & mitigations

- **tc writes on non-linear/GSO skb:** `skb_pull_data(hdr_len)` before header writes. Responders (ARP/ND/DHCP) are small non-GSO control frames. For bulk overlay encap, `skb_adjust_room` on a GSO skb is the supported pattern (kernel re-segments applying the new headroom per segment) — how Cilium does VXLAN encap in tc.
- **redirect-to-self direction** on the tap (ingress → egress toward guest): standard, validated in Phase 1.
- **maps shared across XDP+tc program types:** type-agnostic; one `CONNTRACK` etc.
- **test harness** currently attaches XDP — needs a tc attach path (Phase 4).
- **uplink XDP → tap redirect under vhost:** the supported `ndo_xdp_xmit`/ptr_ring path; already exercised by SKB-mode e2e. Re-validate in Phase 3.

## Incremental implementation/test plan (DHCP-on-tc is the proof)

0. Extract the DHCP serializer into a pure `fill_dhcp_offer(...)` + **std unit tests** (no kernel).
1. tc glue + `tc_guest_tx`/`tc_guest_dhcp` for **DHCP only**; focused netns test (tap + clsact, fake guest DISCOVER → expect OFFER). Proves `pull_data` + `change_tail` + redirect-to-guest + tail-call. **Gate.**
2. Port ARP/ND responders to tc.
3. Port overlay egress (encap + redirect-to-uplink) to tc; keep `uplink_rx` XDP; VM↔VM netns-e2e.
4. Update conformance + `netns-e2e` harness to attach tc on the guest side → all green.
5. ioiab: attach tc in the dpservice loader; validate the native lab end-to-end (DHCP + ping) with **no SKB mode**.

## Success criteria

- Pure-core unit tests pass (`cargo test`, no root).
- Phase-1 netns DHCP-on-tc test passes (OFFER received).
- Conformance + netns-e2e green after the tc harness update.
- ioiab lab: both VMs DHCP and VM↔VM ping with the guest edge on **tc-BPF**, no SKB mode, no native-XDP-on-tap.
