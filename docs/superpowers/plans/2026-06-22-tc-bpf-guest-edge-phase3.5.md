# tc-BPF Guest Edge — Phase 3.5 (IPv6 egress + DHCPv6 on tc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two tractable tc gaps so the guest edge has IPv4+IPv6 parity for the common paths: (1) IPv6-inner overlay egress (route6 + encap, inner-proto 41) and (2) DHCPv6, both on the tc datapath — reusing Phase 1–3's composable pattern.

**Architecture:** Extend the `EgressVerdict` model to IPv6: a shared `forward_decision_v6(data, data_end, ifindex, &PortMeta) -> EgressVerdict` (route6 + Local/Encap, NO NAT64), executed by the XDP and tc glue (tc reuses the Phase-3 `skb_adjust_room` encap). For DHCPv6, extract a pure `write_dhcpv6_reply` into `flowplane-common` (mirroring `write_dhcpv4_reply`) and have `tc_guest_dhcp` answer SOLICIT/REQUEST/CONFIRM for v6 as well as v4. **NAT64 egress (`64:ff9b::/96`) stays XDP-only** (size-changing; Phase 3.6) — the XDP `v6_guest_tx` keeps calling `nat64_egress` before `forward_decision_v6`; the tc path route-misses 64:ff9b (documented gap).

**Tech Stack:** Rust + aya/aya-ebpf (eBPF), `flowplane-common` host tests, bash + ip-netns + scapy gates, the dpservice conformance suite as the XDP regression gate (must stay **93 passed / 2 skipped** — conformance still exercises the XDP path; the tc datapath is validated by the netns gates until the Phase-4 serve cutover).

**Context for the implementer:** Phases 1–3 are done. The XDP IPv6 egress is `flowplane-ebpf/src/v6.rs::v6_guest_tx` (lines 92–138): `nat64_egress` (keep) → route6 lookup (`ROUTES6`) → local-fast-path (`UNDERLAY`) → `encap_and_redirect(.., IPPROTO_IPV6)`. The IPv4 egress already uses `egress::forward_decision_v4 -> EgressVerdict {Pass,Drop,Local{tap_ifindex,guest_mac},Encap(EncapParams)}`, executed by XDP glue (`adjust_head`) and tc glue (`skb_adjust_room(IPV6_LEN, BPF_ADJ_ROOM_MAC, 0)` — see `tc.rs`). `encap::write_outer_v6(data,data_end,&EncapParams)` is the shared pure outer-header writer. The DHCPv4 pure builder is `flowplane_common::dhcp::write_dhcpv4_reply`; the XDP responder `dhcp.rs::try_dhcpv6_reply` (lines 659–~1050) is the code to mirror for v6; `tc.rs::tc_guest_dhcp` currently does v4 only.

---

## File Structure

**Modified files:**
- `flowplane-ebpf/src/egress.rs` — add `forward_decision_v6(data, data_end, ifindex, &PortMeta) -> EgressVerdict` (route6 + Local/Encap; inner_proto = IPPROTO_IPV6). Reuse the existing `EgressVerdict`/`EncapParams`.
- `flowplane-ebpf/src/v6.rs` — rewrite `v6_guest_tx` as: `nat64_egress` (keep) → `forward_decision_v6` → execute verdict with XDP primitives (behaviour-preserving).
- `flowplane-ebpf/src/tc.rs` — `tc_guest_tx` IPv6 branch (after ND): if not ND, call `forward_decision_v6` and execute (local redirect / `skb_adjust_room` encap — identical to the v4 Encap glue). `tc_guest_dhcp`: answer v6 too.
- `flowplane-common/src/lib.rs` — extend `pub mod dhcp` with the pure `write_dhcpv6_reply` + `parse_dhcpv6_request` + `Dhcpv6Reply`/`Dhcpv6Request` + DHCPv6 constants + host unit test (mirror the v4 work).
- `flowplane-ebpf/src/dhcp.rs` — `try_dhcpv6_reply` becomes XDP glue over the common builder + the map-touching `gather`/`learn` (mirror `try_dhcpv4_reply`).
- `test/tc-egress-netns.sh`, `test/tc-dhcp-netns.sh`, `test/tap-dhcp-probe.py`, `flowplane/src/main.rs` — extend the gates: IPv6 VM↔overlay encap on the uplink, and a DHCPv6 SOLICIT→ADVERTISE on the tap.

---

## Task 1: `forward_decision_v6` + rewire XDP `v6_guest_tx` (behaviour-preserving)

**Files:** `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/v6.rs`

- [ ] **Step 1: Add `forward_decision_v6` to `egress.rs`**
```rust
/// IPv6-inner egress decision (route6 + local/encap). Map-driven; shared by XDP `v6_guest_tx` and
/// tc. Mutates nothing that resizes. Does NOT handle NAT64 (caller runs that first on XDP).
/// Caller has verified ETH_LEN+IPV6_LEN present and ethertype==ETH_P_IPV6.
#[inline(always)]
pub fn forward_decision_v6(data: usize, data_end: usize, _ifindex: u32, meta: &PortMeta) -> EgressVerdict {
    // MOVE v6.rs::v6_guest_tx lines 100–137 here (the part AFTER the nat64 call): the ROUTES6 lookup
    // (route-miss/LOCAL-miss -> EgressVerdict::Pass), the local-fast-path (-> EgressVerdict::Local{
    // tap_ifindex: u.tap_ifindex, guest_mac: u.guest_mac }), and the encap branch (-> EgressVerdict::
    // Encap(EncapParams{ gateway_mac:local.gateway_mac, uplink_mac:local.uplink_mac,
    // uplink_ifindex:local.uplink_ifindex, src_underlay:meta.underlay_ipv6, nexthop_ipv6:route.nexthop_ipv6,
    // inner_len:(data_end-data-ETH_LEN) as u16, inner_proto: crate::parse::IPPROTO_IPV6 })).
}
```
Note: the Local branch in the v6 fast path also rewrites the inner ethertype to IPv6 — that lives in the GLUE (Step 2 / tc Task 2), not the verdict. The verdict only carries `tap_ifindex`+`guest_mac`.

- [ ] **Step 2: Rewrite XDP `v6_guest_tx` as glue**
```rust
#[inline(always)]
pub fn v6_guest_tx(ctx: &XdpContext, meta: &PortMeta) -> Result<u32, ()> {
    if let Some(act) = crate::nat64::nat64_egress(ctx, meta.vni, meta.guest_ipv4, &meta.underlay_ipv6)? {
        return Ok(act);
    }
    let data = ctx.data(); let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end { return Ok(xdp_action::XDP_PASS); }
    match crate::egress::forward_decision_v6(ctx.data(), ctx.data_end(), 0, meta) {
        crate::egress::EgressVerdict::Pass => Ok(xdp_action::XDP_PASS),
        crate::egress::EgressVerdict::Drop => Ok(xdp_action::XDP_DROP),
        crate::egress::EgressVerdict::Local { tap_ifindex, guest_mac } => {
            if ctx.data() + ETH_LEN > ctx.data_end() { return Ok(xdp_action::XDP_PASS); }
            let q = ctx.data() as *mut u8;
            unsafe {
                write6(q, &guest_mac); write6(q.add(6), &GW_MAC);
                core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
            }
            Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as u32)
        }
        crate::egress::EgressVerdict::Encap(e) => {
            if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 { return Err(()); }
            if unsafe { crate::encap::write_outer_v6(ctx.data(), ctx.data_end(), &e) } {
                Ok(unsafe { bpf_redirect(e.uplink_ifindex, 0) } as u32)
            } else { Err(()) }
        }
    }
}
```
Keep `try_icmpv6_echo_reply`, `v6_uplink_rx`, `reforward` untouched. Remove now-unused imports as the compiler dictates; keep `forward_decision_v6` `#[inline(always)]` (stack).

- [ ] **Step 3: Build + conformance**
`nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.
`nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped** (the v6 VM↔VM + encap tests prove the extraction is behaviour-preserving).

- [ ] **Step 4: Commit**
```bash
git add flowplane-ebpf/src/egress.rs flowplane-ebpf/src/v6.rs
git commit -m "refactor(v6): forward_decision_v6 + EgressVerdict; XDP v6_guest_tx executes it"
```

---

## Task 2: tc IPv6 overlay egress in `tc_guest_tx`

**Files:** `flowplane-ebpf/src/tc.rs`

- [ ] **Step 1: Add the IPv6 forwarding tail to the `ETH_P_IPV6` branch**

Today the `ethertype == ETH_P_IPV6` branch in `tc_guest_tx` tries ND then falls through. After the ND attempt (when `try_write_nd_reply` returns false), add IPv6 overlay forwarding (mirror the v4 Encap glue exactly, but call `forward_decision_v6`):
```rust
// (inside the ETH_P_IPV6 branch, after the ND try that fell through)
let _ = ctx.pull_data((flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN) as u32);
if ctx.data() + flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN > ctx.data_end() {
    return TC_ACT_OK;
}
match crate::egress::forward_decision_v6(ctx.data(), ctx.data_end(), ifindex, &meta) {
    crate::egress::EgressVerdict::Pass => return TC_ACT_OK,
    crate::egress::EgressVerdict::Drop => return TC_ACT_SHOT,
    crate::egress::EgressVerdict::Local { tap_ifindex, guest_mac } => {
        if ctx.data() + flowplane_common::arp_nd::ETH_LEN <= ctx.data_end() {
            let q = ctx.data() as *mut u8;
            unsafe {
                let g = guest_mac; let gw = crate::arp_nd::GW_MAC; let mut i = 0;
                while i < 6 { *q.add(i) = g[i]; *q.add(6+i) = gw[i]; i += 1; }
                core::ptr::write_unaligned(q.add(12) as *mut u16, 0x86DDu16.to_be());
            }
            return unsafe { bpf_redirect(tap_ifindex, 0) as i32 };
        }
        return TC_ACT_OK;
    }
    crate::egress::EgressVerdict::Encap(e) => {
        if unsafe { ctx.adjust_room(crate::parse::IPV6_LEN as i32, BPF_ADJ_ROOM_MAC, 0) }.is_err() {
            return TC_ACT_OK;
        }
        if ctx.pull_data((flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN) as u32).is_err() {
            return TC_ACT_OK;
        }
        if unsafe { crate::encap::write_outer_v6(ctx.data(), ctx.data_end(), &e) } {
            return unsafe { bpf_redirect(e.uplink_ifindex, 0) as i32 };
        }
        return TC_ACT_SHOT;
    }
}
```
This is identical to the v4 Encap glue (same `adjust_room` + `write_outer_v6`) — the only difference is `forward_decision_v6` and the IPv6 ethertype in the Local rewrite. Use the SAME working `ctx.adjust_room(.., BPF_ADJ_ROOM_MAC, 0)` invocation proven in Phase 3 Task 3.

- [ ] **Step 2: Build** → `nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail` → Finished.

- [ ] **Step 3: Commit**
```bash
git add flowplane-ebpf/src/tc.rs
git commit -m "feat(ebpf): tc guest edge forwards inner IPv6 to overlay (encap proto 41)"
```

---

## Task 3: DHCPv6 — pure builder in common + XDP rewire + tc wiring

**Files:** `flowplane-common/src/lib.rs`, `flowplane-ebpf/src/dhcp.rs`, `flowplane-ebpf/src/tc.rs`

- [ ] **Step 1: Extract the pure DHCPv6 reply into `flowplane_common::dhcp` (mirror the v4 work)**

Read `flowplane-ebpf/src/dhcp.rs::try_dhcpv6_reply` (lines 659–~1050). Split it exactly like `try_dhcpv4_reply` was split (Phase 1):
- Into `flowplane_common::dhcp`: `pub fn looks_like_dhcpv6(data,data_end)->bool`, `pub fn parse_dhcpv6_request(data,data_end)->Option<Dhcpv6Request>` (DUID/msg-type extraction; pure), `pub unsafe fn write_dhcpv6_reply(data,data_end,&Dhcpv6Reply)->Option<usize>` (the byte builder, verbatim move), the `Dhcpv6Request`/`Dhcpv6Reply` structs + the D6_* constants + `MIN_D6_LEN`/the reply-len const. ALL the byte-builder functions `#[inline(always)]` (stack — `v6_guest_dhcp`/`tc_guest_dhcp` are small but be safe).
- Keep in `flowplane-ebpf/src/dhcp.rs`: the map-touching glue (`gather_dhcpv6_reply` reading `DHCP_CONFIG`/`DHCP_META`, any v6 MAC/state learning) and `try_dhcpv6_reply` rewritten as XDP glue: parse → gather → resize (`bpf_xdp_adjust_tail`) → `write_dhcpv6_reply` → `Some(reflect(ctx))`.
- Add a host unit test in the `dhcp` module asserting the DHCPv6 ADVERTISE framing (msg-type, IA address option carrying the guest IPv6, the echoed client DUID). Run `nix develop -c cargo test -p flowplane-common 2>&1 | grep "test result"` → ok (count grows).

- [ ] **Step 2: Build + conformance (XDP DHCPv6 must be unchanged)**
`nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.
`nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped** (`test_dhcpv6` proves the v6 builder move is byte-correct on the XDP path).

- [ ] **Step 3: Wire DHCPv6 into `tc_guest_dhcp`**

`tc_guest_dhcp` currently answers v4 only. Make it answer either: after the v4 attempt (or by classifying the ethertype/dport first), if the frame is DHCPv6 (`looks_like_dhcpv6`), run the v6 path: `pull_data` the v6 reply length → `parse_dhcpv6_request` → `gather_dhcpv6_reply` → `bpf_skb_change_tail(reply_len)` → re-`pull_data` → `write_dhcpv6_reply` → `bpf_redirect(ifindex, 0)`. Also update `tc_guest_tx`'s DHCP classify so a DHCPv6 frame (IPv6/UDP dport 547) ALSO tail-calls `tc_guest_dhcp` (today `looks_like_dhcpv4` only catches v4; add a `looks_like_dhcpv6`-OR check before the tail call). Build.

- [ ] **Step 4: Commit**
```bash
git add flowplane-common/src/lib.rs flowplane-ebpf/src/dhcp.rs flowplane-ebpf/src/tc.rs
git commit -m "feat(dhcpv6): pure write_dhcpv6_reply in common; XDP + tc answer DHCPv6"
```

---

## Task 4: Extend the gates (tc IPv6 encap + tc DHCPv6) + regression

**Files:** `test/tc-egress-netns.sh`, `test/tc-dhcp-netns.sh`, `test/tap-dhcp-probe.py`, `flowplane/src/main.rs`

- [ ] **Step 1: tc IPv6 egress in the egress gate**

Extend `test/tc-egress-netns.sh` (+ `tap-dhcp-probe.py --egress`): after the IPv4 encap assertion, send an inner IPv6 packet `Ether(src=guest_mac)/IPv6(src=<guest v6>, dst=2001:db8::2)/ICMPv6EchoRequest` from the tap (the bringup must program an IPv6 remote route — add `--remote6 <overlay_ipv6>=<nexthop_underlay_ipv6>=<vni>` to `tc-bringup`, mirroring `Bringup`'s `--remote6`/`ROUTES6`; and a `--guest6` to set `meta.guest_ipv6`/the v6 overlay). Capture on `uplinkpeer`; require an encapped frame `Ether/IPv6(nh==41, dst=<nexthop>, src=<guest underlay>)/IPv6(...)`. Print `ENCAP6 OK`.

- [ ] **Step 2: tc DHCPv6 in the DHCP gate**

Extend `test/tc-dhcp-netns.sh` (+ `tap-dhcp-probe.py`): send a DHCPv6 SOLICIT (`IPv6/UDP(dport=547)/DHCP6_Solicit(.../IA_NA/ClientID)`) on the tap; require a `DHCP6_Advertise` (or Reply) carrying an IA address = the guest's overlay IPv6. The `tc-bringup` already programs DHCP config; ensure it programs the guest's IPv6 (`--guest6`) so the responder has an address to offer. Print `DHCPv6 OK`. Update the final success line to include it.

- [ ] **Step 3: Run the gates + full regression**
`nix develop -c ./test/tc-egress-netns.sh` → `ENCAP OK` and `ENCAP6 OK`.
`nix develop -c ./test/tc-dhcp-netns.sh` → DHCP + ARP + ND + DHCPv6 all OK.
`nix develop -c cargo test -p flowplane-common 2>&1 | grep "test result"` → ok.
`nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped** (XDP path still intact).
If the tc IPv6 encap layout is wrong, inspect the captured hex and adjust as in Phase 3 (the `adjust_room` invocation is the same as v4, so it should be correct).

- [ ] **Step 4: Commit**
```bash
git add test/tc-egress-netns.sh test/tc-dhcp-netns.sh test/tap-dhcp-probe.py flowplane/src/main.rs
git commit -m "test(tc): gates cover tc IPv6 overlay egress + DHCPv6"
```

---

## Done criteria (Phase 3.5)

- XDP path refactored (`forward_decision_v6`, pure `write_dhcpv6_reply`), **conformance still 93/2** at Tasks 1, 3, 4.
- tc datapath forwards inner IPv6 (local + encap, proto 41) and answers DHCPv6; the egress gate prints `ENCAP6 OK` and the DHCP gate prints DHCPv6 OK.
- The tc guest edge now covers ARP + ND + DHCPv4 + DHCPv6 + IPv4 egress + IPv6 egress. **Remaining: NAT64 egress on tc (Phase 3.6, `test_vf_to_pf`), then Phase 4 (serve cutover → full conformance on tc), then Phase 5 (ioiab).**
