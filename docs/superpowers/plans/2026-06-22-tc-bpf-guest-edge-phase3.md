# tc-BPF Guest Edge — Phase 3 (overlay egress on tc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Forward guest→overlay IPv4 traffic from the tc (clsact-ingress) datapath: run the conntrack/firewall/VIP/NAT/meter/route pipeline, then either deliver locally (same-host) or encapsulate (IPv4-in-IPv6) and redirect out the uplink — matching what the XDP `guest_tx` does today.

**Architecture:** Split the egress forwarding into (a) a shared, map-driven `forward_decision_v4(data, data_end, ifindex, meta) -> EgressVerdict` in the eBPF crate that mutates the packet in place (NAT/VIP, no size change) and returns a context-neutral verdict, and (b) per-program glue that *executes* the verdict — `XDP_REDIRECT`/`bpf_xdp_adjust_head` for XDP, `TC_ACT_REDIRECT`/`bpf_skb_adjust_room` for tc. The packet mutators (`ct_apply`, `vip::*`, `nat_snat_egress`, …) are refactored from `&XdpContext` to `(data, data_end)` so both glues share them. This extends Phase 1/2's composable pattern to the forwarding path.

**Tech Stack:** Rust + aya/aya-ebpf (eBPF), `flowplane-common` host tests, bash + ip-netns + scapy gate, the dpservice conformance suite (XDP regression gate). Build via `nix develop`.

**Context for the implementer:** Phases 1–2 are done. Pure packet logic lives in `flowplane-common`; map-driven logic lives in the eBPF crate. The XDP egress forwarding is `flowplane-ebpf/src/egress.rs::try_guest_tx` (lines ~52–150, after the ARP/ND/DHCP classify): conntrack → egress firewall → VIP snat/dnat → route lookup → network NAT → conntrack track → meter → local-fast-path OR `encap_and_redirect` (`encap.rs`). The tc entry is `tc.rs::tc_guest_tx` (currently: ARP/ND/DHCP, else `TC_ACT_OK`). **Every change to the XDP path must keep `nix develop -c ./test/conformance/run.sh` at 93 passed / 2 skipped.** Also: out-of-line BPF subprograms sum stack frames (512-byte limit) — keep shared helpers `#[inline(always)]` where the stack-heavy `guest_tx` calls them (see Phase 2's `fix(arp_nd): inline pure builders`).

**Scope note:** IPv4 egress only (the `ETH_P_IP` path). The IPv6 inner path (`v6::v6_guest_tx`) and DHCPv6 are out of scope (later). Phase 4 = conformance/e2e harness cutover; Phase 5 = ioiab.

---

## File Structure

**Modified files:**
- `flowplane-ebpf/src/conntrack.rs`, `flowplane-ebpf/src/vip.rs`, `flowplane-ebpf/src/nat.rs` — change the packet mutators from `&XdpContext` to `(data: usize, data_end: usize)` params (they do in-place rewrites + incremental checksums; no size change). Behaviour-preserving.
- `flowplane-ebpf/src/egress.rs` — extract the forwarding pipeline into `pub fn forward_decision_v4(data, data_end, ifindex, &PortMeta) -> EgressVerdict`; rewrite XDP `try_guest_tx`'s IPv4 tail as glue that executes the verdict. Add the `EgressVerdict` enum.
- `flowplane-ebpf/src/encap.rs` — split `encap_and_redirect` into `write_outer_v6(data, data_end, &EncapParams)` (pure byte write, no size change) + keep the XDP room-making (`bpf_xdp_adjust_head`) in the XDP glue.
- `flowplane-ebpf/src/tc.rs` — `tc_guest_tx` IPv4 path: call `forward_decision_v4`, execute the verdict with tc primitives (`pull_data` + `bpf_skb_adjust_room` for encap + `bpf_redirect`).
- `test/tc-egress-netns.sh` (new) — a gate: guest tap + an "uplink" veth; send an inner IPv4 packet to a remote overlay IP from the tap; assert an **encapsulated IPv6 frame** (outer IPv6, next-header IPIP, correct underlay src/dst) arrives on the uplink. Also assert local-delivery to a second tap.

---

## Task 1: Refactor egress mutators to `(data, data_end)` (behaviour-preserving)

**Files:** `flowplane-ebpf/src/{conntrack.rs, vip.rs, nat.rs, egress.rs}`

- [ ] **Step 1: Change the mutator signatures**

Change these from `(ctx: &XdpContext, ip_off, …)` to `(data: usize, data_end: usize, ip_off, …)`, replacing every internal `ctx.data()`/`ctx.data_end()` with the params (they do NOT change packet size, so `data`/`data_end` stay valid throughout):
- `conntrack.rs`: `ct_apply`, `ct_touch`, `ct_ensure_default`
- `vip.rs`: `snat_egress`, `dnat_egress`
- `nat.rs`: `nat_snat_egress`

For each, the body change is mechanical: the first lines likely read `let data = ctx.data(); let data_end = ctx.data_end();` — delete those and use the params. If a function calls `ctx.ctx` for anything other than data/data_end, STOP and report (none should — they're pure in-place rewrites).

- [ ] **Step 2: Update the XDP callers in `egress.rs::try_guest_tx`**

At each call site (lines ~74, 76, 94, 98, 112, 116), pass `ctx.data(), ctx.data_end()` instead of `ctx`. Example:
```rust
crate::conntrack::ct_apply(ctx.data(), ctx.data_end(), ETH_LEN, &e);
...
crate::vip::snat_egress(ctx.data(), ctx.data_end(), ETH_LEN, meta.vni);
crate::vip::dnat_egress(ctx.data(), ctx.data_end(), ETH_LEN, meta.vni);
...
crate::nat::nat_snat_egress(ctx.data(), ctx.data_end(), ETH_LEN, meta.vni, is_ext);
...
crate::conntrack::ct_ensure_default(ctx.data(), ctx.data_end(), ETH_LEN, &key);
```
Also check `ingress.rs` (uplink_rx) for callers of these same functions (ct_apply/ct_touch are used on the ingress path too) and update them identically.

- [ ] **Step 3: Build + conformance (the gate for this refactor)**

Run: `nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.
Run: `nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped**. (This is the real proof the in-place mutators are unchanged. If a count drops, a mutator's data/data_end substitution is wrong — most likely a missing re-fetch after a NAT rewrite, but these don't resize so bounds are stable; recheck the edit.)

- [ ] **Step 4: Commit**
```bash
git add flowplane-ebpf/src/conntrack.rs flowplane-ebpf/src/vip.rs flowplane-ebpf/src/nat.rs flowplane-ebpf/src/egress.rs flowplane-ebpf/src/ingress.rs
git commit -m "refactor(egress): mutators take (data,data_end) not XdpContext (shareable by tc)"
```

---

## Task 2: Shared `forward_decision_v4` + `EgressVerdict`; XDP glue executes it

**Files:** `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/encap.rs`

- [ ] **Step 1: Add the `EgressVerdict` enum + `EncapParams` (in `egress.rs`)**
```rust
/// What the per-program glue should do after the (in-place) egress pipeline runs.
pub enum EgressVerdict {
    Pass,                 // not ours / no route → let it through (XDP_PASS / TC_ACT_OK)
    Drop,                 // firewall/meter dropped it
    /// Same-host delivery: rewrite inner eth (dst=guest_mac, src=GW_MAC) and redirect to the tap.
    Local { tap_ifindex: u32, guest_mac: [u8; 6] },
    /// Encapsulate (IPv4-in-IPv6) toward `nexthop` and redirect out the uplink.
    Encap(EncapParams),
}
pub struct EncapParams {
    pub gateway_mac: [u8; 6],
    pub uplink_mac: [u8; 6],
    pub uplink_ifindex: u32,
    pub src_underlay: [u8; 16],
    pub nexthop_ipv6: [u8; 16],
    pub inner_len: u16,   // frame_len - inner ETH_LEN, captured BEFORE making encap room
    pub inner_proto: u8,  // IPPROTO_IPIP for IPv4 inner
}
```

- [ ] **Step 2: Extract `forward_decision_v4`**

Move the IPv4 forwarding body (egress.rs lines ~52–149, from the `ethertype != ETH_P_IP` check through the local-fast-path and the `encap_and_redirect` call) into:
```rust
/// Run the in-place IPv4 egress pipeline (conntrack/firewall/vip/nat/meter/route) and decide what
/// to do. Map-driven (lives in the eBPF crate, shared by XDP `guest_tx` and tc `tc_guest_tx`).
/// Mutates the packet in place via the (data,data_end) mutators; does NOT resize (encap room is
/// made by the caller's glue). Assumes the frame is IPv4 (ethertype already checked by the caller).
#[inline(always)]
pub fn forward_decision_v4(
    data: usize, data_end: usize, ifindex: u32, meta: &PortMeta,
) -> EgressVerdict { /* moved body; returns EgressVerdict::{Pass,Drop,Local,Encap} instead of
    Ok(XDP_*)/encap_and_redirect. The local-fast-path branch → EgressVerdict::Local{..}; the final
    encap branch → EgressVerdict::Encap(EncapParams{ inner_len, src_underlay=meta.underlay_ipv6,
    nexthop=route.nexthop_ipv6, inner_proto=IPPROTO_IPIP, gateway_mac=local.gateway_mac,
    uplink_mac=local.uplink_mac, uplink_ifindex=local.uplink_ifindex }). DROP→Drop, route-miss/PASS→Pass. */ }
```
Notes: the route lookup, `is_ext`, conntrack, meter, etc. stay identical — only the *return* changes to a verdict (no packet resize here). `inner_len` and the `LOCAL.get(0)` read stay as today.

- [ ] **Step 3: Split the encap byte-write out of `encap_and_redirect` (in `encap.rs`)**

Add a pure (no resize) outer-header writer the glue calls AFTER it has made 40 bytes of room:
```rust
/// Write the outer Eth+IPv6 header into a frame that already has IPV6_LEN bytes of new room at the
/// front (the inner Ethernet has been consumed). Pure byte writes; no resize, no redirect.
#[inline(always)]
pub unsafe fn write_outer_v6(data: usize, data_end: usize, e: &crate::egress::EncapParams) -> bool {
    if data + ETH_LEN + IPV6_LEN > data_end { return false; }
    let p = data as *mut u8;
    write6(p, &e.gateway_mac);
    write6(p.add(6), &e.uplink_mac);
    core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
    let ip = p.add(ETH_LEN);
    *ip.add(0) = 0x60; *ip.add(1) = 0; *ip.add(2) = 0; *ip.add(3) = 0;
    core::ptr::write_unaligned(ip.add(4) as *mut u16, e.inner_len.to_be());
    *ip.add(6) = e.inner_proto; *ip.add(7) = 64;
    write16(ip.add(8), &e.src_underlay);
    write16(ip.add(24), &e.nexthop_ipv6);
    true
}
```
Keep `encap_and_redirect` for now (or reimplement it in terms of `write_outer_v6`): `bpf_xdp_adjust_head(-IPV6_LEN)` → `write_outer_v6(ctx.data(), ctx.data_end(), e)` → `bpf_redirect(uplink, 0)`. `reforward` is unchanged.

- [ ] **Step 4: Rewrite XDP `try_guest_tx`'s IPv4 tail as glue**
```rust
// after the ARP/ND/DHCP classify and the ethertype==ETH_P_IP check:
match egress::forward_decision_v4(ctx.data(), ctx.data_end(), ifindex, meta) {
    EgressVerdict::Pass => Ok(xdp_action::XDP_PASS),
    EgressVerdict::Drop => Ok(xdp_action::XDP_DROP),
    EgressVerdict::Local { tap_ifindex, guest_mac } => {
        let q = ctx.data() as *mut u8;
        if ctx.data() + ETH_LEN > ctx.data_end() { return Ok(xdp_action::XDP_PASS); }
        unsafe { crate::parse::write6(q, &guest_mac); crate::parse::write6(q.add(6), &crate::arp_nd::GW_MAC); }
        Ok(unsafe { aya_ebpf::helpers::bpf_redirect(tap_ifindex, 0) } as u32)
    }
    EgressVerdict::Encap(e) => {
        if unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, -(crate::parse::IPV6_LEN as i32)) } != 0 {
            return Err(());
        }
        if unsafe { crate::encap::write_outer_v6(ctx.data(), ctx.data_end(), &e) } {
            Ok(unsafe { aya_ebpf::helpers::bpf_redirect(e.uplink_ifindex, 0) } as u32)
        } else { Err(()) }
    }
}
```

- [ ] **Step 5: Build + conformance (XDP must be unchanged)**

Run: `nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.
Run: `nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped**.
If the verifier rejects `guest_tx` for stack size, ensure `forward_decision_v4` is `#[inline(always)]` (and if that overflows the single-frame limit, drop the `#[inline(always)]` and instead reduce locals — but try inline first; the original was one inlined body).

- [ ] **Step 6: Commit**
```bash
git add flowplane-ebpf/src/egress.rs flowplane-ebpf/src/encap.rs
git commit -m "refactor(egress): forward_decision_v4 + EgressVerdict; XDP glue executes it"
```

---

## Task 3: tc glue — execute the egress verdict on `tc_guest_tx`

**Files:** `flowplane-ebpf/src/tc.rs`

- [ ] **Step 1: Add the IPv4 forwarding tail to `tc_guest_tx`**

After the ARP/ND handling and the DHCP tail-call check (i.e. where it currently falls to `TC_ACT_OK`), add:
```rust
// IPv4 inner → overlay forwarding (conntrack/nat/vip/fw/meter/route → local or encap).
if ethertype == 0x0800 /* ETH_P_IP */ {
    // Make the inner IPv4 header range writable for the in-place pipeline (NAT/VIP rewrites).
    let _ = ctx.pull_data((flowplane_common::arp_nd::ETH_LEN + 40) as u32);
    match crate::egress::forward_decision_v4(ctx.data(), ctx.data_end(), ifindex, &meta) {
        crate::egress::EgressVerdict::Pass => return TC_ACT_OK,
        crate::egress::EgressVerdict::Drop => return TC_ACT_SHOT,
        crate::egress::EgressVerdict::Local { tap_ifindex, guest_mac } => {
            if ctx.data() + flowplane_common::arp_nd::ETH_LEN <= ctx.data_end() {
                let q = ctx.data() as *mut u8;
                unsafe {
                    write6_local(q, &guest_mac);
                    write6_local(q.add(6), &crate::arp_nd::GW_MAC);
                }
                return unsafe { bpf_redirect(tap_ifindex, 0) as i32 };
            }
            return TC_ACT_OK;
        }
        crate::egress::EgressVerdict::Encap(e) => {
            // Make IPV6_LEN bytes of room at the MAC layer for the outer Eth+IPv6 (inner eth is
            // consumed, matching the XDP adjust_head(-IPV6_LEN) semantics).
            if unsafe {
                aya_ebpf::helpers::bpf_skb_adjust_room(
                    ctx.skb.skb,
                    crate::parse::IPV6_LEN as i32,
                    BPF_ADJ_ROOM_MAC,
                    0,
                )
            } != 0 {
                return TC_ACT_OK;
            }
            if ctx
                .pull_data((flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN) as u32)
                .is_err()
            {
                return TC_ACT_OK;
            }
            if unsafe { crate::encap::write_outer_v6(ctx.data(), ctx.data_end(), &e) } {
                return unsafe { bpf_redirect(e.uplink_ifindex, 0) as i32 };
            }
            return TC_ACT_SHOT;
        }
    }
}
TC_ACT_OK
```
Provide a small local `write6_local` (or reuse one already imported) for the 6-byte eth rewrite, and import `BPF_ADJ_ROOM_MAC` from `aya_ebpf::bindings`. `IPV6_LEN`/`ETH_LEN` constants: use `crate::parse::IPV6_LEN`/`flowplane_common::arp_nd::ETH_LEN`.

### CRITICAL implementation notes (the hard part of this plan)
- **`bpf_skb_adjust_room` semantics differ from `bpf_xdp_adjust_head`.** The XDP path does `adjust_head(-40)` (grow headroom by 40; the inner eth's 14 bytes become part of the 54-byte outer header region → net +40, inner eth consumed). The tc equivalent that yields the SAME wire layout `[outer_eth(14)][outer_ipv6(40)][inner_ipv4...]` is NOT obvious — verify empirically:
  - First try `bpf_skb_adjust_room(skb, IPV6_LEN, BPF_ADJ_ROOM_MAC, 0)` (add 40 bytes after the MAC header), then re-pull and `write_outer_v6`. Inspect the frame captured on the uplink in the Task-4 gate; if the layout is shifted (e.g. the inner eth survived, or the outer headers landed at the wrong offset), adjust the `len_diff`/mode. You may need `len_diff = IPV6_LEN - ETH_LEN`/different mode, or to first strip the inner eth.
  - The Task-4 gate (decode the uplink frame) is how you confirm the bytes are right; iterate there. Document the working invocation in a comment.
- **GSO:** `bpf_skb_adjust_room` on a GSO super-frame is supported (the kernel re-segments applying the added headroom per segment) — this is how Cilium does VXLAN encap. No special handling needed beyond the adjust_room call; the Task-4 gate uses small packets anyway.
- Stack: keep `forward_decision_v4` `#[inline(always)]`; `tc_guest_tx` is lighter than XDP `guest_tx` so the 512-byte limit is unlikely to bite, but watch for it at load.

- [ ] **Step 2: Build**
Run: `nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5` → Finished. (Load/verify happens in the Task-4 gate.)

- [ ] **Step 3: Commit**
```bash
git add flowplane-ebpf/src/tc.rs
git commit -m "feat(ebpf): tc guest edge forwards IPv4 to overlay (encap) or local tap"
```

---

## Task 4: Egress gate — encap output on the uplink (+ local delivery)

**Files:** `test/tc-egress-netns.sh` (new), `test/tap-dhcp-probe.py` (extend), `flowplane/src/main.rs` (extend `tc-bringup`)

- [ ] **Step 1: Extend `tc-bringup` for an egress test topology**

The current `tc-bringup` programs one tap + DHCP. For egress it must also program: the **uplink** (`--uplink <dev>`: sets `LOCAL` via the existing `maps::LocalMap`/`Control` pattern — copy from the `Bringup` arm), a **remote route** (`--remote <overlay_ipv4>=<nexthop_underlay_ipv6>=<vni>` → `ROUTES` + the per-interface underlay), and attach `tc_guest_tx` to the tap (already) — the uplink does NOT need a tc/xdp program for this gate (we just capture what's redirected onto it). Reuse the exact map-wrapper calls from `Cmd::Bringup`. Keep the DHCP/ARP/ND bringup intact (additive args, all optional).

- [ ] **Step 2: Write the gate `test/tc-egress-netns.sh`**

Topology in a netns: a guest tap `tctap0` (gateway MAC) and an "uplink" veth pair `uplink`/`uplinkpeer` (so frames redirected to `uplink` are readable on `uplinkpeer`). Run `flowplane tc-bringup --tap tctap0 --uplink uplink --guest-ipv4 10.0.0.1 --gateway-ipv4 10.0.0.1 --guest-mac 52:54:00:00:00:01 --gateway-mac <uplink-nexthop-mac> --remote 10.0.0.2=fc00:2::2=100 ...` (program the guest's own underlay + the remote). Then, from the guest tap, send an inner IPv4 packet `Ether(src=guest_mac)/IP(src=10.0.0.1,dst=10.0.0.2)/ICMP` and **capture on `uplinkpeer`**. Assert the captured frame is `Ether/IPv6(nh=4 IPIP, dst=fc00:2::2, src=<guest underlay>)/IP(src=10.0.0.1,dst=10.0.0.2)` — i.e. correctly encapsulated. Print `ENCAP OK`. (Add a second local tap + a `--guest` local route to assert `EgressVerdict::Local` delivers the inner frame to that tap, printing `LOCAL OK` — optional if it complicates the harness; the encap assertion is the primary gate.)
Reuse the scapy/tap-fd scaffolding from `test/tap-dhcp-probe.py` (add an `--egress` probe mode); keep existing modes intact. Cleanup trap, unique netns, datapath log capture + verifier-rejection check (as in `tc-dhcp-netns.sh`).

- [ ] **Step 3: Run the gate (iterate on the adjust_room invocation here)**
Run: `nix develop -c ./test/tc-egress-netns.sh` → expect `ENCAP OK`. If the captured outer headers are wrong, fix the `bpf_skb_adjust_room` call in `tc.rs` (Task 3 critical note) and rerun. If `tc_guest_tx` fails to load, capture the verifier log and fix/report.

- [ ] **Step 4: Regression + commit**
Run: `nix develop -c ./test/tc-dhcp-netns.sh 2>&1 | tail -1` → still `PASS: tc DHCP + ARP + ND OK` (the IPv4 path addition must not break responders).
Run: `nix develop -c cargo test -p flowplane-common 2>&1 | grep "test result"` → ok.
Run: `nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → still **93 passed, 2 skipped**.
```bash
git add test/tc-egress-netns.sh test/tap-dhcp-probe.py flowplane/src/main.rs flowplane-ebpf/src/tc.rs
git commit -m "test(tc): egress gate — tc datapath encapsulates IPv4 to overlay on the uplink"
```

---

## Done criteria (Phase 3)

- XDP path refactored to `forward_decision_v4` + `EgressVerdict`, **conformance still 93/2** (no regression — run at Task 1, 2, and 4).
- `tc_guest_tx` forwards inner IPv4: local-delivers same-host and encapsulates+redirects remote traffic out the uplink; the egress gate prints `ENCAP OK` (and the working `bpf_skb_adjust_room` invocation is documented in `tc.rs`).
- Responder + DHCP gates still pass. The tap guest edge now does ARP + ND + DHCP + IPv4 overlay egress on tc. Phase 4 (harness cutover) and Phase 5 (ioiab) remain.
