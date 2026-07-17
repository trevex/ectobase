# tc-BPF Guest Edge — Phase 0–1 (DHCP-on-tc proof) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the composable tc-BPF guest-edge pattern by answering guest DHCP from a `#[classifier]` (tc) program attached to a tap's clsact ingress — replacing native XDP for that path — with the DHCP reply logic extracted into a pure, unit-tested serializer.

**Architecture:** Hybrid datapath (see `docs/superpowers/specs/2026-06-22-tc-bpf-guest-edge-design.md`). The DHCP reply byte-builder becomes a pure `write_dhcpv4_reply(data, data_end, …)` (std-unit-testable). Two thin glue layers call it: the existing XDP path (unchanged behaviour) and a new tc path (`tc_guest_tx` → tail-call `tc_guest_dhcp`). The tc glue resizes via `skb_change_tail`, makes the head writable via `skb_pull_data`, and replies to the guest via `bpf_redirect(tap_ifindex, 0)`. Maps are shared unchanged across both program types.

**Tech Stack:** Rust + aya / aya-ebpf 0.1 (eBPF), aya 0.13 (userspace loader), tokio, `cargo test` (std unit tests), bash + ip-netns + a small Python/scapy DHCP client for the integration gate. Build via `nix develop`.

**Scope note:** This plan delivers Phase 0 (pure extraction) and Phase 1 (DHCP-on-tc, the gate) only. Phases 2–5 (ARP/ND port, overlay-egress encap port, conformance/e2e harness update, ioiab cutover) are deferred to follow-on plans once this gate passes — per the spec's incremental design.

---

## File Structure

**New files:**
- `flowplane-ebpf/src/verdict.rs` — the context-neutral `Verdict` enum returned by the pure core; glue maps it to `XDP_*` / `TC_ACT_*`. One responsibility: the core↔glue seam type.
- `flowplane-ebpf/src/tc.rs` — the tc (classifier) glue programs `tc_guest_tx` and `tc_guest_dhcp`, plus tc-specific helpers (`pull_writable`, `set_total_len_tc`, `redirect_to_guest`). One responsibility: tc I/O glue.
- `test/tc-dhcp-netns.sh` — the Phase-1 integration gate: a tap in a netns with the tc datapath attached, a scapy DHCP DISCOVER, asserts an OFFER comes back.

**Modified files:**
- `flowplane-common/src/lib.rs` — **new `pub mod dhcp`** holding the PURE, host-testable pieces: `write_dhcpv4_reply`, `parse_dhcpv4_request`, `looks_like_dhcpv4`, the `Dhcpv4Request`/`Dhcpv4Reply` structs, and the DHCP framing constants the writer needs (`REPLY_LEN`, message-type/offset consts). This follows the existing precedent in this file (the `fw_match` pure firewall logic at lib.rs:360 — "no_std; used by the datapath and host-tested"). The eBPF crate is `#![no_std] #![no_main]` and its `dhcp.rs` is a *bin* module, so it cannot host-run `cargo test`; the pure logic must live in `flowplane-common`, which IS host-testable (`cargo test -p flowplane-common`).
- `flowplane-ebpf/src/dhcp.rs` — keeps the MAP-touching glue: `gather_dhcpv4_reply(req, meta)` (reads `DHCP_CONFIG`/`DHCP_META`), `learn_mac(ifindex, meta, eth_src)` (writes `PORT_META`/`UNDERLAY`/`INTERFACES`), and the rewritten XDP glue `try_dhcpv4_reply` that calls `flowplane_common::dhcp::{parse_dhcpv4_request, write_dhcpv4_reply}` around the XDP tail-resize. Remove the now-moved byte-builder and request-field constants (re-export or import from common).
- `flowplane-ebpf/src/maps.rs:69` — add a second `ProgramArray` `GUEST_PROGS_TC` for the tc tail-call (tc progs can only tail-call tc progs).
- `flowplane-ebpf/src/main.rs` — register `mod verdict; mod tc;`.
- `flowplane/src/loader.rs` — add `attach_tc_clsact_ingress(ebpf, prog, iface)` and `register_guest_dhcp_tc(ebpf)`.
- `flowplane/src/main.rs` — add a `tc-bringup` subcommand (minimal: one uplink + one guest tap, DHCP only) used by the netns gate; keeps the existing commands untouched.

---

## Task 1: `Verdict` seam type

**Files:**
- Create: `flowplane-ebpf/src/verdict.rs`
- Modify: `flowplane-ebpf/src/main.rs:4-20` (module list)

- [ ] **Step 1: Create the verdict module**

```rust
// flowplane-ebpf/src/verdict.rs
//! Context-neutral verdict returned by the pure datapath core. Each glue layer (XDP, tc) maps
//! it to that program type's concrete return code and performs the redirect/tail-call. Keeping
//! this enum free of `xdp_action`/`TC_ACT_*` constants is what lets one core serve both.

/// `ifindex` payloads are interface indices; `Reflect` means "send the (rewritten in place)
/// packet back out the interface it arrived on" (a responder reply to the guest).
pub enum Verdict {
    Pass,
    Drop,
    Redirect(u32),
    Reflect,
    TailCallDhcp,
}
```

- [ ] **Step 2: Register the module**

In `flowplane-ebpf/src/main.rs`, add `mod verdict;` to the module list (alphabetical, after `mod parse;` / before `mod vip;`):

```rust
mod parse;
mod v6;
mod verdict;
mod vip;
```

- [ ] **Step 3: Verify it compiles**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5`
Expected: `Finished` (a `dead_code` warning on unused variants is fine at this stage).

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf/src/verdict.rs flowplane-ebpf/src/main.rs
git commit -m "feat(ebpf): add context-neutral Verdict seam type"
```

---

## Task 2: Extract the pure DHCPv4 reply serializer (+ std unit test)

> **CORRECTION (location):** the pure functions + structs + DHCP constants + unit tests go in **`flowplane-common/src/lib.rs`** under a new `pub mod dhcp` — NOT in the eBPF crate. The eBPF crate is `#![no_std] #![no_main]` and `dhcp.rs` is a *bin* module, so `cargo test` cannot run there; `flowplane-common` is host-testable (`cargo test -p flowplane-common`, 16 tests already pass) and already hosts pure datapath logic (the `fw_match`/csum functions). The eBPF `dhcp.rs` keeps only the map-touching glue (`gather_dhcpv4_reply`, `learn_mac`) and the XDP entry `try_dhcpv4_reply`, importing the pure pieces from `flowplane_common::dhcp`. Tests run with `cargo test -p flowplane-common`, not `cargo test -p flowplane-ebpf`.

**Goal:** Split `try_dhcpv4_reply` (`flowplane-ebpf/src/dhcp.rs:53`) so the *byte-writing* is a pure function over `(data, data_end)` with no context, tail-resize, or map access — placed in `flowplane-common` and testable in plain `cargo test`. The context-coupled steps (read `ingress_ifindex`, MAC-learn map writes, `bpf_xdp_adjust_tail`) stay in the eBPF XDP glue.

**Files:**
- Modify: `flowplane-ebpf/src/dhcp.rs` (the v4 block, ~lines 53–400)
- Test: `flowplane-ebpf/src/dhcp.rs` (a `#[cfg(test)] mod tests` at file end — std, no eBPF)

- [ ] **Step 1: Define the pure builder's inputs**

Add this input struct near the top of `dhcp.rs` (after the `const` block, before `try_dhcpv4_reply`). It carries everything the byte-writer needs, gathered by the glue:

```rust
/// Everything `write_dhcpv4_reply` needs, gathered by the caller (glue) from the request +
/// maps. Pure: no context, no map access inside the writer.
pub struct Dhcpv4Reply {
    pub reply_type: u8,        // DHCP_MSG_OFFER or DHCP_MSG_ACK
    pub client_mac: [u8; 6],   // BOOTP chaddr / Ethernet dst of the reply
    pub yiaddr: [u8; 4],       // assigned IP (meta.guest_ipv4)
    pub gateway_ipv4: [u8; 4], // server identity (meta.gateway_ipv4)
    pub server_mac: [u8; 6],   // reply Ethernet src (the gateway MAC the datapath owns)
    pub xid_secs_flags: [u8; 8],// BOOTP xid(4)+secs(2)+flags(2) copied from the request
    pub mtu: u16,              // from DHCP_CONFIG (0 = omit option)
    pub dns: [[u8; 4]; flowplane_common::DHCP_MAX_DNS],
    pub dns_len: u8,
    pub lease_secs: u32,       // from DHCP_META or a default
}
```

- [ ] **Step 2: Write the failing unit test first**

At the end of `flowplane-ebpf/src/dhcp.rs`, add a std test that builds a reply into a stack buffer and asserts the BOOTP/IP/UDP framing. `write_dhcpv4_reply` operates on raw `data..data_end` so a `[u8; REPLY_LEN]` buffer works under `cargo test`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Dhcpv4Reply {
        Dhcpv4Reply {
            reply_type: DHCP_MSG_OFFER,
            client_mac: [0x52,0x54,0,1,2,3],
            yiaddr: [10,0,0,1],
            gateway_ipv4: [10,0,0,1],
            server_mac: [0x66,0x66,0x66,0x66,0x66,0],
            xid_secs_flags: [0xde,0xad,0xbe,0xef, 0,0, 0x80,0],
            mtu: 1500,
            dns: [[8,8,8,8],[0;4],[0;4],[0;4]],
            dns_len: 1,
            lease_secs: 3600,
        }
    }

    #[test]
    fn writes_bootp_reply_framing() {
        let mut buf = [0u8; REPLY_LEN];
        let data = buf.as_mut_ptr() as usize;
        let data_end = data + REPLY_LEN;
        // Pre-seed the Ethernet/IP src bytes the way the request would arrive (the writer
        // overwrites L2/L3/L4 headers; chaddr comes from the struct).
        let n = unsafe { write_dhcpv4_reply(data, data_end, &sample()) }.expect("fits");
        assert_eq!(n, REPLY_LEN);
        // Ethernet dst = client_mac, src = server_mac.
        assert_eq!(&buf[0..6], &[0x52,0x54,0,1,2,3]);
        assert_eq!(&buf[6..12], &[0x66,0x66,0x66,0x66,0x66,0]);
        // Ethertype IPv4.
        assert_eq!(&buf[12..14], &0x0800u16.to_be_bytes());
        // BOOTP op = BOOTREPLY(2) at ETH(14)+IP(20)+UDP(8) = 42.
        assert_eq!(buf[42], 2);
        // yiaddr at BOOTP +16 = 42+16 = 58.
        assert_eq!(&buf[58..62], &[10,0,0,1]);
    }
}
```

- [ ] **Step 2b: Run the test to confirm it fails to compile (function missing)**

Run: `nix develop --command cargo test -p flowplane-ebpf --lib 2>&1 | grep -E "cannot find function|error\[|test result" | head`
Expected: a compile error `cannot find function write_dhcpv4_reply`.

- [ ] **Step 3: Extract the pure writer**

In `dhcp.rs`, create `pub unsafe fn write_dhcpv4_reply(data: usize, data_end: usize, r: &Dhcpv4Reply) -> Option<usize>`. **Move** the byte-writing body of `try_dhcpv4_reply` (currently `dhcp.rs:181`–~`400`, i.e. everything from `let p = data as *mut u8;` through the option-block/UDP/IP/checksum writes and the final framing, but NOT the `XDP_TX` return) into it, applying these mechanical substitutions:
- The function receives `data`/`data_end` as params (do not call `ctx.data()`); bounds-check `if data + REPLY_LEN > data_end { return None; }` at the top.
- Replace reads of `meta.*`/`ifindex`/`DHCP_CONFIG`/`DHCP_META`-derived values with the corresponding `r.*` fields (`r.yiaddr`, `r.gateway_ipv4`, `r.server_mac`, `r.client_mac`, `r.xid_secs_flags`, `r.mtu`, `r.dns`/`r.dns_len`, `r.lease_secs`, `r.reply_type`).
- Remove the `bpf_xdp_adjust_tail` call and the `(*ctx.ctx).ingress_ifindex` read (these belong to the glue).
- Return `Some(REPLY_LEN)` on success.

- [ ] **Step 3b: Factor the shared parse/classify/gather helpers (used by BOTH glues)**

These are consumed by the tc glue in Task 3, so define them here, all `pub(crate)`. Also change `const REPLY_LEN` (`dhcp.rs:46`) to `pub(crate) const REPLY_LEN`.

```rust
/// Parsed DHCPv4 request fields the glue needs to build a reply.
pub(crate) struct Dhcpv4Request {
    pub reply_type: u8,         // OFFER (for DISCOVER) or ACK (for REQUEST)
    pub client_mac: [u8; 6],    // BOOTP chaddr
    pub eth_src: [u8; 6],       // Ethernet source (used for MAC learning)
    pub xid_secs_flags: [u8; 8],// BOOTP xid(4)+secs(2)+flags(2), copied verbatim into the reply
}

/// Cheap port-only check: IPv4 + UDP + dport 67. Used as the tail-call gate.
#[inline(always)]
pub(crate) fn looks_like_dhcpv4(data: usize, data_end: usize) -> bool {
    // Move the body of the existing `is_dhcp_request` IPv4/UDP/67 check here (egress.rs:155),
    // operating purely on data/data_end.
    // ... (bounds-checked reads of ethertype==0x0800, ip proto==17, udp dport==67)
    let _ = (data, data_end);
    unimplemented!("move from egress.rs::is_dhcp_request v4 branch")
}

/// Validate + parse a DISCOVER/REQUEST; returns None for other message types. Contains the
/// existing option-walk loop (dhcp.rs:~70–140). `ifindex`/`meta` are used only for the MAC-learn
/// side effect via `learn_mac`.
pub(crate) fn parse_dhcpv4_request(
    data: usize, data_end: usize, ifindex: u32, meta: &PortMeta,
) -> Option<Dhcpv4Request> { /* option-walk → msg_type → reply_type; read chaddr/eth_src/xid;
    call learn_mac(ifindex, meta, eth_src) */ unimplemented!() }

/// Gather the immutable reply inputs from maps + meta (DHCP_CONFIG, DHCP_META).
pub(crate) fn gather_dhcpv4_reply(req: &Dhcpv4Request, meta: &PortMeta) -> Dhcpv4Reply {
    /* read DHCP_CONFIG (mtu, dns) + DHCP_META (lease) and assemble Dhcpv4Reply */ unimplemented!()
}
```

> The `unimplemented!()`/comment bodies above are *signatures to fill by moving existing code* — the implementer relocates the corresponding blocks from `dhcp.rs`/`egress.rs` (cited line ranges) into these functions. They are not placeholders to invent logic; the logic already exists and is only being relocated and de-context-ified.

- [ ] **Step 4: Rewrite `try_dhcpv4_reply` as the XDP glue over the new pieces**

`try_dhcpv4_reply(ctx, meta)` now: (a) parses the request and computes `reply_type` (keep the existing parse loop, `dhcp.rs:~70`–`140`), returning `None` if not DISCOVER/REQUEST; (b) MAC-learns via a new shared `learn_mac(ifindex, meta, eth_src)` (move the `dhcp.rs:147`–`164` block into it verbatim — it's all map writes, context-agnostic); (c) gathers a `Dhcpv4Reply` from `meta` + `DHCP_CONFIG`/`DHCP_META`; (d) resizes the tail with `bpf_xdp_adjust_tail` (keep `dhcp.rs:169`–`177`); (e) `if write_dhcpv4_reply(ctx.data(), ctx.data_end(), &r).is_some() { Some(crate::arp_nd::reflect(ctx)) } else { None }`.

```rust
// sketch of the new tail of try_dhcpv4_reply (after parse + learn_mac + gather `r`):
let cur_len = ctx.data_end() - ctx.data();
if cur_len != REPLY_LEN {
    let delta = REPLY_LEN as i32 - cur_len as i32;
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) } != 0 { return None; }
}
match unsafe { write_dhcpv4_reply(ctx.data(), ctx.data_end(), &r) } {
    Some(_) => Some(crate::arp_nd::reflect(ctx)),
    None => None,
}
```

- [ ] **Step 5: Run the unit test to confirm it passes**

Run: `nix develop --command cargo test -p flowplane-ebpf --lib write 2>&1 | grep -E "test result|error" | tail -5`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 6: Confirm the eBPF object still builds and the XDP datapath is unchanged**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3`
Expected: `Finished` (the XDP path now routes through the pure writer; behaviour identical).

- [ ] **Step 7: Commit**

```bash
git add flowplane-ebpf/src/dhcp.rs
git commit -m "refactor(ebpf): extract pure write_dhcpv4_reply + learn_mac (unit-tested)"
```

---

## Task 3: tc glue programs (`tc_guest_tx`, `tc_guest_dhcp`)

**Files:**
- Create: `flowplane-ebpf/src/tc.rs`
- Modify: `flowplane-ebpf/src/maps.rs:69` (add `GUEST_PROGS_TC`), `flowplane-ebpf/src/main.rs` (`mod tc;`)

- [ ] **Step 1: Add the tc tail-call program array**

In `flowplane-ebpf/src/maps.rs`, after `GUEST_PROGS` (line 69):

```rust
/// Tail-call targets for the **tc** guest-edge split. Separate from `GUEST_PROGS` because a tc
/// (classifier) program may only tail-call other tc programs. Populated by the loader with
/// `tc_guest_dhcp` at `GUEST_PROG_DHCP`.
#[map]
pub static GUEST_PROGS_TC: ProgramArray = ProgramArray::with_max_entries(8, 0);
```

- [ ] **Step 2: Write the tc glue module**

```rust
// flowplane-ebpf/src/tc.rs
//! tc (clsact ingress) glue for the guest edge. Mirrors the XDP `guest_tx`/`guest_dhcp` split,
//! but uses skb primitives (pull_data/change_tail) and tc return codes, and replies to the guest
//! by redirecting back out the tap. The heavy logic lives in the shared pure core (dhcp.rs etc.).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::{bpf_redirect, bpf_skb_change_tail},
    macros::classifier,
    programs::TcContext,
};

use crate::dhcp::gather_dhcpv4_reply; // map-touching glue stays in the eBPF crate
use crate::maps::{GUEST_PROGS_TC, PORT_META};
use flowplane_common::dhcp::{looks_like_dhcpv4, parse_dhcpv4_request, write_dhcpv4_reply, REPLY_LEN};

/// clsact-ingress on a guest tap. Classifies guest egress; DHCP is tail-called to keep verifier
/// cost split, mirroring the XDP path.
#[classifier]
pub fn tc_guest_tx(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if unsafe { PORT_META.get(&ifindex) }.is_none() {
        return TC_ACT_OK;
    }
    if is_dhcpv4_request(&ctx) {
        // tail_call returns only on failure; on success control does not return here.
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_DHCP) };
        return TC_ACT_OK; // tail-call miss → let it pass (mirrors XDP_PASS)
    }
    TC_ACT_OK // Phase 1: only DHCP is handled on tc; forwarding/responders land in later phases.
}

/// tc DHCP responder. Builds the OFFER/ACK into the (resized) skb and redirects it back to the
/// guest. Reuses the pure `write_dhcpv4_reply`.
#[classifier]
pub fn tc_guest_dhcp(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => *m,
        None => return TC_ACT_OK,
    };
    // Parse the request from the (linear) head. Make the header range writable first.
    if ctx.pull_data(REPLY_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    let req = match parse_dhcpv4_request(ctx.data(), ctx.data_end(), ifindex, &meta) {
        Some(r) => r,
        None => return TC_ACT_OK,
    };
    // Resize the skb to exactly REPLY_LEN, then re-fetch bounds (change_tail invalidates them).
    let cur = (ctx.data_end() - ctx.data()) as u32;
    if cur != REPLY_LEN as u32
        && unsafe { bpf_skb_change_tail(ctx.skb.skb, REPLY_LEN as u32, 0) } != 0
    {
        return TC_ACT_OK;
    }
    if ctx.pull_data(REPLY_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    let r = gather_dhcpv4_reply(&req, &meta);
    if unsafe { write_dhcpv4_reply(ctx.data(), ctx.data_end(), &r) }.is_none() {
        return TC_ACT_SHOT;
    }
    // Reply to the guest: redirect back out the tap we arrived on (egress = toward guest).
    if unsafe { bpf_redirect(ifindex, 0) } as i32 == TC_ACT_REDIRECT {
        TC_ACT_REDIRECT
    } else {
        TC_ACT_SHOT
    }
}

/// Cheap port-only classifier: IPv4/UDP dport 67. Full validation happens in `tc_guest_dhcp`.
#[inline(always)]
fn is_dhcpv4_request(ctx: &TcContext) -> bool {
    looks_like_dhcpv4(ctx.data(), ctx.data_end())
}
```

> Implementation notes for the implementer:
> - `parse_dhcpv4_request(data, data_end, ifindex, meta) -> Option<Dhcpv4Request>`, `gather_dhcpv4_reply(req, meta) -> Dhcpv4Reply`, and `looks_like_dhcpv4(data, data_end) -> bool` are the shared helpers factored out of `dhcp.rs` in Task 2 / here. `Dhcpv4Request` carries `reply_type`, `client_mac`, `eth_src`, `xid_secs_flags`. Refactor `try_dhcpv4_reply` (XDP glue) to also call `parse_dhcpv4_request` + `gather_dhcpv4_reply` so both glues share one parser (DRY).
> - `gather_dhcpv4_reply` does the `DHCP_CONFIG`/`DHCP_META` map reads and `learn_mac` call (map access is fine in both program types).
> - `ctx.skb.skb` is the raw `*mut __sk_buff`; `ifindex` is a field on it.

- [ ] **Step 3: Register the module**

In `flowplane-ebpf/src/main.rs` add `mod tc;` (after `mod parse;`, before `mod v6;`).

- [ ] **Step 4: Build the eBPF object (verifier-relevant load happens in Task 4/5; here just compile)**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5`
Expected: `Finished`.

- [ ] **Step 5: Commit**

```bash
git add flowplane-ebpf/src/tc.rs flowplane-ebpf/src/maps.rs flowplane-ebpf/src/main.rs
git commit -m "feat(ebpf): tc clsact guest-edge glue (tc_guest_tx, tc_guest_dhcp) for DHCPv4"
```

---

## Task 4: Userspace loader — clsact attach + tc tail-call registration

**Files:**
- Modify: `flowplane/src/loader.rs`

- [ ] **Step 1: Add the tc attach + registration helpers**

```rust
// in flowplane/src/loader.rs
use aya::programs::{tc, SchedClassifier, TcAttachType};

/// Ensure a clsact qdisc exists on `iface`, then load+attach a tc (classifier) program to its
/// INGRESS hook (host receives = guest egress). Idempotent on the qdisc (EEXIST is fine).
pub fn attach_tc_clsact_ingress(
    ebpf: &mut Ebpf,
    prog_name: &str,
    iface: &str,
) -> anyhow::Result<()> {
    // qdisc_add_clsact returns EEXIST if already present — treat that as success.
    let _ = tc::qdisc_add_clsact(iface);
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    prog.attach(iface, TcAttachType::Ingress)
        .with_context(|| format!("attach {prog_name} to {iface} (clsact ingress)"))?;
    Ok(())
}

/// Load `tc_guest_dhcp` and register it in GUEST_PROGS_TC[GUEST_PROG_DHCP] so `tc_guest_tx`'s
/// DHCP tail-call resolves. Mirrors `register_guest_dhcp` but for the tc program array.
pub fn register_guest_dhcp_tc(ebpf: &mut Ebpf) -> anyhow::Result<ProgramArray<MapData>> {
    {
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_guest_dhcp")
            .context("tc_guest_dhcp program missing")?
            .try_into()?;
        prog.load().context("verify tc_guest_dhcp")?;
    }
    let prog_fd = {
        let prog: &SchedClassifier = ebpf
            .program("tc_guest_dhcp")
            .context("tc_guest_dhcp missing")?
            .try_into()?;
        prog.fd()?.try_clone()?
    };
    let mut arr: ProgramArray<MapData> = ebpf
        .take_map("GUEST_PROGS_TC")
        .context("GUEST_PROGS_TC map missing")?
        .try_into()?;
    arr.set(flowplane_common::GUEST_PROG_DHCP, &prog_fd, 0)
        .context("set GUEST_PROGS_TC[DHCP]")?;
    Ok(arr)
}
```

> Note: model `register_guest_dhcp_tc` on the existing `register_guest_dhcp` (`flowplane/src/loader.rs:63`) for the exact `ProgramFd`/`set` calls available in this aya version; the sketch above shows intent. The returned `ProgramArray` must be held in scope by the caller for the datapath's lifetime (same as the XDP one).

- [ ] **Step 2: Build the userspace crate**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5`
Expected: `Finished`.

- [ ] **Step 3: Commit**

```bash
git add flowplane/src/loader.rs
git commit -m "feat(loader): clsact-ingress tc attach + GUEST_PROGS_TC registration"
```

---

## Task 5: `tc-bringup` CLI subcommand (minimal, DHCP-only) for the gate

**Files:**
- Modify: `flowplane/src/main.rs` (add a `TcBringup` subcommand + arm)

- [ ] **Step 1: Add the subcommand enum variant**

In the `Cmd` enum in `flowplane/src/main.rs`, add:

```rust
/// Minimal tc guest-edge bringup for the Phase-1 DHCP gate: attach tc_guest_tx to one tap's
/// clsact ingress, program PORT_META + DHCP config for it, then idle.
TcBringup {
    #[arg(long)] tap: String,
    #[arg(long)] guest_ipv4: String,   // e.g. 10.0.0.1
    #[arg(long)] gateway_ipv4: String, // e.g. 10.0.0.1
    #[arg(long)] guest_mac: String,    // e.g. 52:54:00:00:00:01
    #[arg(long)] gateway_mac: String,  // e.g. 66:66:66:66:66:00
    #[arg(long, default_value_t = 1500)] dhcp_mtu: u32,
    #[arg(long = "dhcp-dns")] dhcp_dns: Vec<String>,
},
```

- [ ] **Step 2: Add the match arm**

```rust
Cmd::TcBringup { tap, guest_ipv4, gateway_ipv4, guest_mac, gateway_mac, dhcp_mtu, dhcp_dns } => {
    let mut ebpf = loader::load_ebpf()?;
    loader::maybe_install_logger(&mut ebpf); // FLOWPLANE_DEBUG honoured
    let tap_ifindex = ifindex(&tap)?;
    // Program the one interface's PortMeta so tc_guest_dhcp can answer for it.
    let mut ports = maps::PortMetaMap::open(&mut ebpf)?;
    ports.upsert(tap_ifindex, flowplane_common::PortMeta {
        vni: 100,
        guest_ipv4: parse_ipv4(&guest_ipv4)?,
        gateway_ipv4: parse_ipv4(&gateway_ipv4)?,
        guest_mac: parse_mac(&guest_mac)?,
        _pad: [0; 2],
        underlay_ipv6: [0u8; 16],
        gateway_ipv6: [0u8; 16],
        guest_ipv6: [0u8; 16],
    })?;
    // DHCP server-wide config (mtu + dns).
    {
        let mut dhcp_cfg = maps::DhcpConfigMap::open(&mut ebpf)?;
        let dns4: Vec<[u8;4]> = dhcp_dns.iter()
            .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())).collect();
        let dns4_len = dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8;
        let mut cfg = flowplane_common::DhcpConfig {
            mtu: dhcp_mtu as u16, dns4_len, dns6_len: 0,
            dns4: [[0;4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0;16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i,a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() { cfg.dns4[i] = *a; }
        dhcp_cfg.set(&cfg)?;
    }
    let _gpt = loader::register_guest_dhcp_tc(&mut ebpf)?; // hold in scope
    loader::attach_tc_clsact_ingress(&mut ebpf, "tc_guest_tx", &tap)?;
    println!("tc-bringup: tc_guest_tx on {tap} (ifindex {tap_ifindex}); ctrl-c to stop");
    let _ = gateway_mac; // reserved for the responder phase; accepted now to keep args stable
    tokio::signal::ctrl_c().await?;
}
```

> Note: `maps::PortMetaMap::upsert` and `maps::DhcpConfigMap` already exist (used by `Bringup`). Reuse them exactly; do not introduce new map wrappers.

- [ ] **Step 3: Build**

Run: `nix develop --command cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -5`
Expected: `Finished`.

- [ ] **Step 4: Commit**

```bash
git add flowplane/src/main.rs
git commit -m "feat(cli): tc-bringup subcommand (minimal DHCP-only tc guest edge)"
```

---

## Task 6: Phase-1 integration gate — tap + clsact, DISCOVER → OFFER

**Files:**
- Create: `test/tc-dhcp-netns.sh`
- Reference: `test/tap-dhcp-probe.sh`, `test/tap-dhcp-probe.py` (existing DHCP-probe scaffolding to mirror)

- [ ] **Step 1: Write the test harness**

The harness: builds the binary, creates a netns + a `vnet_hdr`-less tap, runs `flowplane tc-bringup` against it, injects a DHCP DISCOVER on the tap from a scapy client, and asserts an OFFER for `10.0.0.1` returns. Model the scapy client on `test/tap-dhcp-probe.py`.

```bash
#!/usr/bin/env bash
# Phase-1 gate: prove tc-BPF (clsact ingress) answers guest DHCPv4 on a tap.
set -euo pipefail
NS=tcdhcp$$
TAP=tctap0
GUEST_IP=10.0.0.1
GUEST_MAC=52:54:00:00:00:01
GW_MAC=66:66:66:66:66:00
BIN=target/release/flowplane

cleanup() {
  [ -n "${DP_PID:-}" ] && kill "$DP_PID" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

nix develop --command cargo build --release -p flowplane >/dev/null 2>&1

ip netns add "$NS"
ip netns exec "$NS" ip tuntap add dev "$TAP" mode tap
ip netns exec "$NS" ip link set "$TAP" address "$GW_MAC"
ip netns exec "$NS" ip link set "$TAP" up

# Start the tc datapath inside the netns (needs CAP_NET_ADMIN + CAP_BPF → run via sudo).
sudo ip netns exec "$NS" env FLOWPLANE_DEBUG=1 "$BIN" tc-bringup \
  --tap "$TAP" --guest-ipv4 "$GUEST_IP" --gateway-ipv4 "$GUEST_IP" \
  --guest-mac "$GUEST_MAC" --gateway-mac "$GW_MAC" --dhcp-dns 8.8.8.8 &
DP_PID=$!
sleep 2

# Inject DISCOVER and capture the OFFER (scapy client mirrors tap-dhcp-probe.py).
OUT=$(sudo ip netns exec "$NS" python3 test/tap-dhcp-probe.py --iface "$TAP" \
        --client-mac "$GUEST_MAC" --expect-yiaddr "$GUEST_IP" 2>&1)
echo "$OUT"
echo "$OUT" | grep -q "OFFER $GUEST_IP" && { echo "PASS: tc DHCP OFFER received"; exit 0; }
echo "FAIL: no OFFER"; exit 1
```

> If `test/tap-dhcp-probe.py` lacks `--expect-yiaddr`/`OFFER <ip>` output, extend it minimally to print `OFFER <yiaddr>` on receipt (a 3-line change), keeping its existing behaviour.

- [ ] **Step 2: Make it executable and run the gate**

Run:
```bash
chmod +x test/tc-dhcp-netns.sh
nix develop --command ./test/tc-dhcp-netns.sh
```
Expected: ends with `PASS: tc DHCP OFFER received`. If the eBPF verifier rejects `tc_guest_dhcp`, the `flowplane tc-bringup` process prints the verifier log — fix the glue (most likely a missing bounds re-check after `pull_data`/`change_tail`) and re-run.

- [ ] **Step 3: Confirm existing tests still pass (no XDP regression)**

Run: `nix develop --command cargo test -p flowplane-ebpf --lib 2>&1 | grep "test result"`
Expected: `ok` (the Task-2 unit test + any existing ones).

Run (root): `sudo nix develop --command ./test/conformance/run.sh 2>&1 | tail -5`
Expected: the conformance suite still passes (it exercises the **XDP** path, which Task 2 left behaviour-identical).

- [ ] **Step 4: Commit**

```bash
git add test/tc-dhcp-netns.sh test/tap-dhcp-probe.py
git commit -m "test(tc): Phase-1 gate — clsact tc datapath answers guest DHCPv4 (DISCOVER→OFFER)"
```

---

## Done criteria (Phase 0–1)

- `write_dhcpv4_reply` is pure and unit-tested (`cargo test`, no root).
- `tc_guest_tx`/`tc_guest_dhcp` load (pass the verifier) and `test/tc-dhcp-netns.sh` prints `PASS`.
- The XDP datapath is behaviour-identical (conformance still green).
- Pattern proven: `pull_data` → `change_tail` → pure writer → `bpf_redirect(tap,0)` reply, with shared pure core. Phases 2–5 (ARP/ND, overlay encap, harness cutover, ioiab) follow in their own plans.
