# tc-BPF Guest Edge — Phase 2 (ARP + ND responders on tc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer guest ARP requests and IPv6 Neighbor Solicitations from the tc (clsact-ingress) datapath, reusing Phase 1's composable pure-core/per-type-glue pattern — so the tap guest edge now handles ARP + ND + DHCP on tc.

**Architecture:** Extract the in-place ARP/ND reply builders into pure, host-tested functions in `flowplane-common` (like Phase 1's `write_dhcpv4_reply`); the XDP glue (`arp_nd.rs`) and the tc glue (`tc.rs`) both call them. ARP/ND are **fixed-size in-place rewrites** (no `change_tail`), so the tc glue only needs `pull_data` (to make the header range writable) + the builder + `bpf_redirect(tap,0)`.

**Tech Stack:** Rust + aya/aya-ebpf 0.1 (eBPF), `flowplane-common` host unit tests (`cargo test -p flowplane-common`), bash + ip-netns + scapy gate. Build via `nix develop`.

**Context for the implementer:** Phase 1 established the pattern. Pure packet logic lives in `flowplane-common` (`#![cfg_attr(not(feature="user"), no_std)]`, host-testable — see the `dhcp` module added in Phase 1 and the `fw_match` precedent). The eBPF crate is `#![no_std] #![no_main]`; its modules are a bin target (NOT host-testable). The tc entry is `flowplane-ebpf/src/tc.rs::tc_guest_tx` (clsact ingress; reads ifindex via `(*ctx.skb.skb).ifindex`; replies via `bpf_redirect(ifindex, 0)` which returns `TC_ACT_REDIRECT`). `aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT}` are `i32`. The current XDP responders are `flowplane-ebpf/src/arp_nd.rs::{try_arp_reply, try_nd_reply}` — they rewrite in place and return `Some(reflect(ctx))`. `reflect`/`GW_MAC` stay in `arp_nd.rs`.

---

## File Structure

**Modified files:**
- `flowplane-common/src/lib.rs` — new `pub mod arp_nd` with the PURE, host-tested builders `try_write_arp_reply`, `try_write_nd_reply`, the `csum16` helper, and the small constants they need (`ETH_LEN`, `IPV6_LEN`, ethertypes, `ARP_LEN`, ND type codes). Mirrors the Phase 1 `dhcp` module.
- `flowplane-ebpf/src/arp_nd.rs` — `try_arp_reply`/`try_nd_reply` become thin XDP glue calling the common builders (behaviour-preserving). `reflect` + `GW_MAC` stay.
- `flowplane-ebpf/src/tc.rs` — `tc_guest_tx` gains ARP + ND handling before the DHCP tail-call.
- `test/tc-dhcp-netns.sh` + `test/tap-dhcp-probe.py` — extend the Phase-1 gate to also send an ARP request (expect a reply) and an ND NS (expect an NA).

---

## Task 1: Pure ARP reply builder in `flowplane-common` (+ unit test) + rewire XDP

**Files:**
- Modify: `flowplane-common/src/lib.rs` (new `pub mod arp_nd`), `flowplane-ebpf/src/arp_nd.rs`
- Test: `flowplane-common/src/lib.rs` (`#[cfg(test)]` in the new module)

- [ ] **Step 1: Write the failing unit test in the new `pub mod arp_nd`**

Add to `flowplane-common/src/lib.rs`:
```rust
/// Pure, host-tested ARP/ND responder byte-rewrites. The datapath glue (XDP and tc) supplies the
/// gateway address + reply MAC (from maps) and ensures the header range is writable; these
/// functions only read/rewrite bytes in [data, data_end). Mirrors the `dhcp` module.
pub mod arp_nd {
    pub const ETH_LEN: usize = 14;
    pub const ETH_P_ARP: u16 = 0x0806;
    pub const ARP_LEN: usize = 28; // opcode@6 sha@8 spa@14 tha@18 tpa@24

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rewrites_arp_request_to_reply() {
            // Build a 42-byte ARP request: who-has 10.0.0.1 tell 10.0.0.2 (sender 52:54:..:02).
            let mut f = [0u8; ETH_LEN + ARP_LEN];
            // eth: dst broadcast, src sender, type ARP
            f[0..6].copy_from_slice(&[0xff;6]);
            f[6..12].copy_from_slice(&[0x52,0x54,0,0,0,2]);
            f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
            let a = ETH_LEN;
            f[a+6..a+8].copy_from_slice(&1u16.to_be_bytes()); // opcode request
            f[a+8..a+14].copy_from_slice(&[0x52,0x54,0,0,0,2]); // sha
            f[a+14..a+18].copy_from_slice(&[10,0,0,2]);         // spa
            f[a+24..a+28].copy_from_slice(&[10,0,0,1]);         // tpa = gateway
            let data = f.as_mut_ptr() as usize;
            let ok = unsafe { try_write_arp_reply(data, data + f.len(), [10,0,0,1], [0x66,0,0,0,0,1]) };
            assert!(ok);
            assert_eq!(&f[0..6], &[0x52,0x54,0,0,0,2]);        // eth dst = requester
            assert_eq!(&f[6..12], &[0x66,0,0,0,0,1]);          // eth src = reply mac
            assert_eq!(&f[a+6..a+8], &2u16.to_be_bytes());     // opcode reply
            assert_eq!(&f[a+8..a+14], &[0x66,0,0,0,0,1]);      // sha = reply mac
            assert_eq!(&f[a+14..a+18], &[10,0,0,1]);           // spa = gateway
            assert_eq!(&f[a+18..a+24], &[0x52,0x54,0,0,0,2]);  // tha = requester
            assert_eq!(&f[a+24..a+28], &[10,0,0,2]);           // tpa = requester ip
        }
        #[test]
        fn ignores_non_arp() {
            let mut f = [0u8; ETH_LEN + ARP_LEN];
            f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            let data = f.as_mut_ptr() as usize;
            assert!(!unsafe { try_write_arp_reply(data, data + f.len(), [10,0,0,1], [0x66,0,0,0,0,1]) });
        }
    }
}
```

Run: `nix develop --command cargo test -p flowplane-common 2>&1 | grep -E "cannot find|test result" | tail`
Expected: compile error `cannot find function try_write_arp_reply`.

- [ ] **Step 2: Implement `try_write_arp_reply` (move the body from `arp_nd.rs:36-74`)**

Add inside `pub mod arp_nd` (before the test module). Move the in-place rewrite from `flowplane-ebpf/src/arp_nd.rs::try_arp_reply`, replacing `meta.gateway_ipv4`→`gateway_ipv4`, `meta.guest_mac`→`reply_mac`, `ctx.data()/data_end()`→params, dropping the `reflect`/`Some`:
```rust
    /// If [data,data_end) is an ARP request for `gateway_ipv4`, rewrite it in place into a reply
    /// from `reply_mac`/`gateway_ipv4` and return true. Else false (unchanged). Caller must have
    /// made the first ETH_LEN+ARP_LEN bytes writable. Unsafe: raw pointer writes.
    pub unsafe fn try_write_arp_reply(
        data: usize, data_end: usize, gateway_ipv4: [u8; 4], reply_mac: [u8; 6],
    ) -> bool {
        if data + ETH_LEN + ARP_LEN > data_end { return false; }
        let p = data as *mut u8;
        let ethertype = u16::from_be(core::ptr::read_unaligned(p.add(12) as *const u16));
        if ethertype != ETH_P_ARP { return false; }
        let arp = p.add(ETH_LEN);
        let opcode = u16::from_be(core::ptr::read_unaligned(arp.add(6) as *const u16));
        if opcode != 1 { return false; }
        let tpa = core::ptr::read_unaligned(arp.add(24) as *const [u8; 4]);
        if tpa != gateway_ipv4 { return false; }
        let sender_mac = core::ptr::read_unaligned(arp.add(8) as *const [u8; 6]);
        let spa = core::ptr::read_unaligned(arp.add(14) as *const [u8; 4]);
        // eth: dst = requester, src = reply_mac
        write6(p, &sender_mac);
        write6(p.add(6), &reply_mac);
        // arp reply
        core::ptr::write_unaligned(arp.add(6) as *mut u16, 2u16.to_be());
        write6(arp.add(8), &reply_mac);
        core::ptr::write_unaligned(arp.add(14) as *mut [u8; 4], gateway_ipv4);
        write6(arp.add(18), &sender_mac);
        core::ptr::write_unaligned(arp.add(24) as *mut [u8; 4], spa);
        true
    }
```
`write6`/`write16` are tiny pointer-copy helpers currently in `flowplane-ebpf/src/parse.rs`. Add equivalents to the common `arp_nd` module (small `#[inline(always)] unsafe fn write6/write16(dst: *mut u8, src: &[u8; N])`), or to a shared spot in common — define them locally in the module to keep it self-contained.

Run: `nix develop --command cargo test -p flowplane-common 2>&1 | grep "test result"` → ok (the new 2 tests + Phase-1's 18 → 20).

- [ ] **Step 3: Rewire the XDP `try_arp_reply` to call the common builder (behaviour-preserving)**

Replace the body of `flowplane-ebpf/src/arp_nd.rs::try_arp_reply` with:
```rust
#[inline(always)]
pub fn try_arp_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    if unsafe {
        flowplane_common::arp_nd::try_write_arp_reply(
            ctx.data(), ctx.data_end(), meta.gateway_ipv4, meta.guest_mac,
        )
    } {
        Some(reflect(ctx))
    } else {
        None
    }
}
```
Remove the now-dead local `ARP_LEN` const if unused. Keep `GW_MAC`, `reflect`, `csum16` (csum16 is still used by `try_nd_reply` until Task 2 moves it).

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.

- [ ] **Step 4: Commit**
```bash
git add flowplane-common/src/lib.rs flowplane-ebpf/src/arp_nd.rs
git commit -m "refactor(arp): pure host-tested try_write_arp_reply in flowplane-common"
```

---

## Task 2: Pure ND reply builder in `flowplane-common` (+ unit test) + rewire XDP

**Files:**
- Modify: `flowplane-common/src/lib.rs` (extend `pub mod arp_nd`), `flowplane-ebpf/src/arp_nd.rs`

- [ ] **Step 1: Add the failing ND unit test**

In the `arp_nd` module's `#[cfg(test)] mod tests`, add a test that builds an 86-byte ICMPv6 Neighbor Solicitation for a gateway IPv6 and asserts the rewrite to a Neighbor Advertisement:
```rust
#[test]
fn rewrites_ns_to_na() {
    use super::{ETH_LEN, IPV6_LEN};
    let gw6 = [0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    let mut f = [0u8; ETH_LEN + IPV6_LEN + 32];
    f[6..12].copy_from_slice(&[0x52,0x54,0,0,0,2]);          // eth src = requester
    f[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());     // ethertype IPv6
    let ip = ETH_LEN;
    f[ip+6] = 58;                                            // next header ICMPv6
    f[ip+8..ip+24].copy_from_slice(&[0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2]); // src
    let ic = ETH_LEN + IPV6_LEN;
    f[ic] = 135;                                             // NS
    f[ic+8..ic+24].copy_from_slice(&gw6);                    // target = gateway
    let data = f.as_mut_ptr() as usize;
    let ok = unsafe { try_write_nd_reply(data, data + f.len(), gw6, [0x66,0,0,0,0,1]) };
    assert!(ok);
    assert_eq!(&f[0..6], &[0x52,0x54,0,0,0,2]);              // eth dst = requester
    assert_eq!(&f[6..12], &[0x66,0,0,0,0,1]);                // eth src = reply mac
    assert_eq!(f[ic], 136);                                  // NA
    assert_eq!(f[ic+4], 0x60);                               // flags: solicited+override
    assert_eq!(f[ic+24], 2);                                 // opt type = target LL addr
    assert_eq!(&f[ic+26..ic+32], &[0x66,0,0,0,0,1]);         // opt = reply mac
}
```
Run the test → expect compile error `cannot find function try_write_nd_reply`.

- [ ] **Step 2: Move `csum16` + implement `try_write_nd_reply`**

Move `csum16` (`arp_nd.rs:84-98`) into the common `arp_nd` module as `pub(crate) unsafe fn csum16(...)`. Add the constants `IPV6_LEN: usize = 40`, `ETH_P_IPV6: u16 = 0x86DD`, `IPPROTO_ICMPV6: u8 = 58`, `ND_NS: u8 = 135`, `ND_NA: u8 = 136`. Then move the rewrite body from `arp_nd.rs::try_nd_reply` (`arp_nd.rs:104-162`) into:
```rust
    /// If [data,data_end) is an ICMPv6 Neighbor Solicitation for `gateway_ipv6`, rewrite in place
    /// into a solicited Neighbor Advertisement from `reply_mac` and return true. Else false. Caller
    /// must have made ETH_LEN+IPV6_LEN+32 bytes writable. Unsafe: raw pointer writes.
    pub unsafe fn try_write_nd_reply(
        data: usize, data_end: usize, gateway_ipv6: [u8; 16], reply_mac: [u8; 6],
    ) -> bool { /* move body; meta.gateway_ipv6 → gateway_ipv6, meta.guest_mac → reply_mac,
        ctx.data()/data_end() → params, return true at the end / false on each early-out */ }
```
Run: `nix develop --command cargo test -p flowplane-common 2>&1 | grep "test result"` → ok (now 21 tests).

- [ ] **Step 3: Rewire the XDP `try_nd_reply`**

Replace the body of `flowplane-ebpf/src/arp_nd.rs::try_nd_reply` with:
```rust
#[inline(always)]
pub fn try_nd_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    if unsafe {
        flowplane_common::arp_nd::try_write_nd_reply(
            ctx.data(), ctx.data_end(), meta.gateway_ipv6, meta.guest_mac,
        )
    } {
        Some(reflect(ctx))
    } else {
        None
    }
}
```
Remove the now-dead local `csum16`/`ND_NS`/`ND_NA`/`ARP_LEN` consts from `arp_nd.rs` if nothing else uses them (check: `csum16` is `pub(crate)` — grep for other users with `grep -rn csum16 flowplane-ebpf/src`; if used elsewhere, keep a re-export or leave it). Keep `GW_MAC` + `reflect`.

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.

- [ ] **Step 4: Commit**
```bash
git add flowplane-common/src/lib.rs flowplane-ebpf/src/arp_nd.rs
git commit -m "refactor(nd): pure host-tested try_write_nd_reply in flowplane-common"
```

---

## Task 3: tc glue — answer ARP + ND in `tc_guest_tx`

**Files:**
- Modify: `flowplane-ebpf/src/tc.rs`

- [ ] **Step 1: Extend `tc_guest_tx`**

Currently `tc_guest_tx` checks `PORT_META` presence then DHCP. Change it to capture `meta`, classify the ethertype, and answer ARP/ND in place before the DHCP tail-call. Replace the function body with:
```rust
#[classifier]
pub fn tc_guest_tx(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => *m,
        None => return TC_ACT_OK,
    };
    // Read the ethertype (bounds-checked direct read; classification only).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + 14 > data_end {
        return TC_ACT_OK;
    }
    let ethertype =
        u16::from_be(unsafe { core::ptr::read_unaligned((data as *const u8).add(12) as *const u16) });

    // ARP request for the gateway → reply in place, redirect back to the guest.
    if ethertype == flowplane_common::arp_nd::ETH_P_ARP {
        if ctx
            .pull_data((flowplane_common::arp_nd::ETH_LEN + flowplane_common::arp_nd::ARP_LEN) as u32)
            .is_ok()
            && unsafe {
                flowplane_common::arp_nd::try_write_arp_reply(
                    ctx.data(), ctx.data_end(), meta.gateway_ipv4, meta.guest_mac,
                )
            }
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        return TC_ACT_OK;
    }

    // IPv6 → may be an ND Neighbor Solicitation for the gateway.
    if ethertype == flowplane_common::arp_nd::ETH_P_IPV6 {
        const ND_FRAME: usize =
            flowplane_common::arp_nd::ETH_LEN + flowplane_common::arp_nd::IPV6_LEN + 32;
        if ctx.pull_data(ND_FRAME as u32).is_ok()
            && unsafe {
                flowplane_common::arp_nd::try_write_nd_reply(
                    ctx.data(), ctx.data_end(), meta.gateway_ipv6, meta.guest_mac,
                )
            }
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        // fall through (other IPv6, incl. DHCPv6 — handled in a later phase)
    }

    // DHCPv4 → tail-call the dedicated responder.
    if looks_like_dhcpv4(ctx.data(), ctx.data_end()) {
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_DHCP) };
        return TC_ACT_OK;
    }
    TC_ACT_OK
}
```
Notes:
- `ETH_P_IPV6`/`ETH_LEN`/`IPV6_LEN`/`ARP_LEN`/`ETH_P_ARP` must be `pub` in `flowplane_common::arp_nd` (Tasks 1–2 made the ethertypes/lengths `pub const`). Ensure they are.
- `pull_data(N)` makes N bytes writable; for ARP (`42`) and ND (`86`) these are ≤ the real frame length (guest ARP frames are padded to ≥60; an NS is ~86+), so the pull succeeds (unlike the Phase-1 DHCP pitfall where the pull exceeded a short DISCOVER). The builders also bounds-check internally and return false if the frame is shorter.
- The IPv6 branch falls through on non-NS so DHCPv6 (later phase) is unaffected.

- [ ] **Step 2: Build**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5` → Finished.

- [ ] **Step 3: Commit**
```bash
git add flowplane-ebpf/src/tc.rs
git commit -m "feat(ebpf): tc guest edge answers ARP + IPv6 ND (in place, redirect to guest)"
```

---

## Task 4: Extend the netns gate with ARP + ND assertions

**Files:**
- Modify: `test/tc-dhcp-netns.sh`, `test/tap-dhcp-probe.py`

- [ ] **Step 1: Add an ARP + ND probe mode to the client**

In `test/tap-dhcp-probe.py`, add an `--arp-nd` (or reuse `--client-only` with a `--probe arp|nd|dhcp` switch) path that, on the same tap queue used for DHCP:
- sends an ARP request (`who-has 10.0.0.1 tell 10.0.0.2`, sender mac `52:54:00:00:00:01`) and reads back a frame, requiring an ARP reply (`op==2`) with `psrc==10.0.0.1` and `hwsrc==52:54:00:00:00:01` (the datapath answers ARP with the guest's own MAC — see `arp_nd.rs` comment), printing `ARP reply OK`.
- sends an ICMPv6 NS for the gateway (build with scapy `IPv6/ICMPv6ND_NS(tgt=<gw6>)/ICMPv6NDOptSrcLLAddr`), reads back, requiring an `ICMPv6ND_NA`, printing `ND NA OK`.
Keep the existing DHCP/native behaviour intact. (Use a gateway IPv6 the bringup programs — extend `tc-bringup` if needed: add `--gateway6 fe80::1` and program `PortMeta.gateway_ipv6`; the bringup currently sets `gateway_ipv6: [0u8;16]`. Add the arg so ND has a target. If you add the arg, default it to `fe80::1`.)

- [ ] **Step 2: Drive ARP + ND from the gate after the DHCP check**

In `test/tc-dhcp-netns.sh`, after the existing DISCOVER→OFFER assertion (and with the same datapath still running), invoke the client's ARP and ND probes and require `ARP reply OK` and `ND NA OK`. Update the final success line to `PASS: tc DHCP + ARP + ND OK`. Keep the `cleanup` trap and the datapath-liveness/verifier-rejection check.

- [ ] **Step 3: Run the gate**

Run: `nix develop --command ./test/tc-dhcp-netns.sh`
Expected: ends with `PASS: tc DHCP + ARP + ND OK`, exit 0. If a responder doesn't reply, check whether `tc_guest_tx` loaded (the datapath log) and whether the probe frame matched the classifier (ethertype / opcode / target). If `pull_data` fails for a too-short ARP frame, pad the scapy ARP to 60 bytes.

- [ ] **Step 4: Regression + commit**

Run: `nix develop --command cargo test -p flowplane-common 2>&1 | grep "test result"` → ok (21).
```bash
git add test/tc-dhcp-netns.sh test/tap-dhcp-probe.py flowplane/src/main.rs
git commit -m "test(tc): extend Phase gate — tc datapath answers ARP + ND + DHCP"
```
(Include `flowplane/src/main.rs` only if you added the `--gateway6` arg to `tc-bringup`.)

---

## Done criteria (Phase 2)

- `try_write_arp_reply` + `try_write_nd_reply` are pure and host-unit-tested (`cargo test -p flowplane-common`, ~21 passing).
- The XDP datapath is behaviour-identical (responders now route through the common builders; `reflect` unchanged).
- `tc_guest_tx` answers ARP + ND in place and redirects to the guest; `test/tc-dhcp-netns.sh` prints `PASS: tc DHCP + ARP + ND OK`.
- Pattern extended cleanly: the tap guest edge handles ARP + ND + DHCP on tc. Phase 3 (overlay egress: encap + redirect-to-uplink) follows.
