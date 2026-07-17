# guest_tx DHCP Tail-Call Split (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move both DHCP responders out of `guest_tx` into a tail-called `guest_dhcp` XDP program, so `guest_dhcp` verifies under its own 1M-instruction / 512-byte-stack budget (unblocking in-XDP DHCPv6) and `guest_tx` returns to its pre-DHCPv6 budget.

**Architecture:** `guest_tx` keeps ARP/ND + the IPv4/IPv6 forwarding paths inline (Phase 1). It classifies DHCP frames (IPv4+UDP/67 or IPv6+UDP/547) and `bpf_tail_call`s into `guest_dhcp` via a new `GUEST_PROGS` PROG_ARRAY map. `guest_dhcp` re-looks-up `PORT_META` and runs `try_dhcpv4_reply` / `try_dhcpv6_reply`, else `XDP_PASS`. Splitting `guest_ipv4_fwd` / `guest_ipv6` out is a deferred Phase 2.

**Tech Stack:** Rust, aya 0.13.1 / aya-ebpf 0.1.1, `ProgramArray` (BPF_MAP_TYPE_PROG_ARRAY), `bpf_tail_call`.

**Reference:** `docs/superpowers/specs/2026-06-19-guest-tx-tail-call-split-design.md`

**Pre-existing state:** `flowplane-ebpf/src/dhcp.rs` already contains the full DHCPv6 responder (`try_dhcpv6_reply` + `d6_parse`/`d6_emit`/`d6_checksum` bpf-to-bpf subprograms). It is correct and verified at ~749k instructions in isolation; it only fails today because it shares `guest_tx` with the IPv4 firewall. **Do not rewrite the DHCPv6 datapath** — this plan only changes program structure so it gets its own budget. These dhcp.rs changes are currently uncommitted on the working tree.

---

### Task 1: Add `GUEST_PROGS` PROG_ARRAY map + index constants

**Files:**
- Modify: `flowplane-common/src/lib.rs`
- Modify: `flowplane-ebpf/src/maps.rs`

- [ ] **Step 1: Add the tail-call index constants to common**

In `flowplane-common/src/lib.rs`, add (near the other shared constants, e.g. by `DHCP_MAX_DNS`):

```rust
/// Tail-call indices into the `GUEST_PROGS` program array (egress datapath split).
/// `GUEST_PROG_DHCP` is used in Phase 1; IPV4/IPV6 are reserved for the Phase 2 split.
pub const GUEST_PROG_DHCP: u32 = 0;
pub const GUEST_PROG_IPV4: u32 = 1;
pub const GUEST_PROG_IPV6: u32 = 2;
```

- [ ] **Step 2: Declare the PROG_ARRAY map in the eBPF crate**

In `flowplane-ebpf/src/maps.rs`, add `ProgramArray` to the aya-ebpf import and declare the map:

```rust
use aya_ebpf::{
    macros::map,
    maps::{lpm_trie::LpmTrie, Array, HashMap, LruHashMap, ProgramArray},
};
```

```rust
/// Tail-call targets for the egress datapath split. Index with `GUEST_PROG_*` from flowplane-common.
/// Populated by the loader at startup (guest_dhcp at GUEST_PROG_DHCP). 8 slots leaves room for the
/// Phase 2 IPv4/IPv6 split without resizing.
#[map]
pub static GUEST_PROGS: ProgramArray = ProgramArray::with_max_entries(8, 0);
```

- [ ] **Step 3: Build the eBPF crate to confirm it compiles**

Run: `cargo build -p flowplane`
Expected: `Finished` with no errors (the new map compiles into the object).

- [ ] **Step 4: Commit**

```bash
git add flowplane-common/src/lib.rs flowplane-ebpf/src/maps.rs
git commit -m "feat(egress): add GUEST_PROGS prog-array map + tail-call indices"
```

---

### Task 2: Add `guest_dhcp` program + `egress::dhcp_handle`

**Files:**
- Modify: `flowplane-ebpf/src/egress.rs`
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Add the DHCP handler to egress.rs**

Append to `flowplane-ebpf/src/egress.rs`:

```rust
/// Tail-call target: run the in-datapath DHCPv4 + DHCPv6 responders. Re-looks-up the port by its
/// ingress ifindex (tail calls invalidate the previous program's pointers/locals). Returns
/// `XDP_PASS` when the frame is not actually a DHCP request we answer.
pub fn dhcp_handle(ctx: &XdpContext) -> u32 {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => m,
        None => return xdp_action::XDP_PASS,
    };
    if let Some(act) = crate::dhcp::try_dhcpv4_reply(ctx, meta) {
        return act;
    }
    if let Some(act) = crate::dhcp::try_dhcpv6_reply(ctx, meta) {
        return act;
    }
    xdp_action::XDP_PASS
}
```

(`PORT_META` and `xdp_action` are already imported in egress.rs.)

- [ ] **Step 2: Add the `guest_dhcp` XDP entry point**

In `flowplane-ebpf/src/main.rs`, after the `guest_tx` definition:

```rust
#[xdp]
pub fn guest_dhcp(ctx: XdpContext) -> u32 {
    egress::dhcp_handle(&ctx)
}
```

- [ ] **Step 3: Build and run the verifier on guest_dhcp**

Run: `cargo build -p flowplane && cargo test -p flowplane --no-run`
Then load guest_dhcp through the verifier (root):
```bash
BIN=$(ls -t target/debug/deps/flowplane-* | grep -v '\.d$' | head -1)
sudo "$BIN" both_programs_pass_verifier --ignored --nocapture 2>&1 | tail -5
```
Expected at this step: the existing test only loads `uplink_rx` + `guest_tx`; `guest_tx` still contains DHCP inline here so it may still fail the 1M limit. That is fine — Task 2 only needs `cargo build` to succeed (guest_dhcp compiles into the object). The standalone guest_dhcp verification is asserted in Task 5 after Task 3 removes DHCP from guest_tx. If you want an early signal, temporarily add `"guest_dhcp"` to the test loop and confirm it loads in isolation, then revert.

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf/src/egress.rs flowplane-ebpf/src/main.rs
git commit -m "feat(egress): guest_dhcp tail-call target running the DHCP responders"
```

---

### Task 3: Make `try_guest_tx` classify + tail-call DHCP (remove inline DHCP)

**Files:**
- Modify: `flowplane-ebpf/src/egress.rs:8-44` (the early-return section of `try_guest_tx`)

- [ ] **Step 1: Replace the two inline DHCP blocks with a tail-call**

In `egress::try_guest_tx`, delete these blocks:

```rust
    // Answer DHCPv4 in-datapath.
    if let Some(act) = crate::dhcp::try_dhcpv4_reply(ctx, meta) {
        return Ok(act);
    }

    // Answer DHCPv6 in-datapath (before the IPv6 ethertype branch).
    if let Some(act) = crate::dhcp::try_dhcpv6_reply(ctx, meta) {
        return Ok(act);
    }
```

and in their place add a DHCP classifier that tail-calls `guest_dhcp`. Insert it AFTER the ARP/ND blocks and BEFORE the IPv6 ethertype branch:

```rust
    // DHCP (v4: IPv4/UDP dport 67, v6: IPv6/UDP dport 547) is handled by the separate `guest_dhcp`
    // program via tail call, so its verifier cost does not stack onto this program's IPv4 forwarding
    // path. A guest only sends to UDP 67/547 for DHCP, so port-based classification is sufficient;
    // on a tail-call miss we fall through and PASS (benign — DHCP is never forwarded anyway).
    if is_dhcp_request(ctx) {
        let _ = unsafe {
            crate::maps::GUEST_PROGS.tail_call(ctx, flowplane_common::GUEST_PROG_DHCP)
        };
        // tail_call only returns here on failure (empty slot / depth limit).
        return Ok(xdp_action::XDP_PASS);
    }
```

- [ ] **Step 2: Add the `is_dhcp_request` detection helper**

Add to `flowplane-ebpf/src/egress.rs` (uses `parse` offsets; add `ETH_P_IPV6`, `IPPROTO_UDP` to the `crate::parse` import as needed):

```rust
/// True if the frame is a DHCP request a guest would send: IPv4/UDP to dport 67, or IPv6/UDP to
/// dport 547. Pure reads, constant offsets, no packet mutation — cheap to run on every frame.
#[inline(always)]
fn is_dhcp_request(ctx: &XdpContext) -> bool {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Need through the UDP dst port for IPv6 (ETH(14)+IPv6(40)+2+2 = 58).
    if data + ETH_LEN + 44 > data_end {
        return false;
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype == ETH_P_IP {
        // IHL==5 assumed (DHCP requests carry no IP options); proto @ ETH+9, UDP dst @ ETH+22.
        if unsafe { *p.add(ETH_LEN + 9) } != crate::parse::IPPROTO_UDP {
            return false;
        }
        let dport =
            u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 22) as *const u16) });
        return dport == 67;
    }
    if ethertype == crate::parse::ETH_P_IPV6 {
        if unsafe { *p.add(ETH_LEN + 6) } != crate::parse::IPPROTO_UDP {
            return false;
        }
        let dport =
            u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16) });
        return dport == 547;
    }
    false
}
```

- [ ] **Step 3: Build, then verify `guest_tx` loads again (DHCP removed → back under budget)**

Run: `cargo build -p flowplane && cargo test -p flowplane --no-run`
```bash
BIN=$(ls -t target/debug/deps/flowplane-* | grep -v '\.d$' | head -1)
sudo "$BIN" both_programs_pass_verifier --ignored --nocapture 2>&1 | tail -5
```
Expected: `test result: ok. 1 passed` — `guest_tx` no longer carries DHCPv6, so it verifies within its budget (`uplink_rx` + `guest_tx` both load).

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf/src/egress.rs
git commit -m "feat(egress): guest_tx classifies DHCP and tail-calls guest_dhcp"
```

---

### Task 4: Loader — load `guest_dhcp` and populate `GUEST_PROGS`

**Files:**
- Modify: `flowplane/src/loader.rs`
- Modify: `flowplane/src/control.rs:145-150` (the `bring_up` startup path)

- [ ] **Step 1: Add a loader helper that loads guest_dhcp and registers it in the prog array**

In `flowplane/src/loader.rs`:

```rust
use aya::maps::ProgramArray;

/// Load (verify) `guest_dhcp` and register its fd in the `GUEST_PROGS` program array at
/// `GUEST_PROG_DHCP`, so `guest_tx`'s tail call resolves. Call once at startup, after `load_ebpf`.
pub fn register_guest_dhcp(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    {
        let prog: &mut Xdp = ebpf
            .program_mut("guest_dhcp")
            .context("guest_dhcp program missing")?
            .try_into()?;
        prog.load().context("verify guest_dhcp")?;
    }
    // Re-borrow to get an owned ProgramFd before taking the map (aya borrow rules).
    let prog_fd = {
        let prog: &Xdp = ebpf
            .program("guest_dhcp")
            .context("guest_dhcp program missing")?
            .try_into()?;
        prog.fd()?.try_clone()?
    };
    let mut progs: ProgramArray<_> = ebpf
        .take_map("GUEST_PROGS")
        .context("GUEST_PROGS map missing")?
        .try_into()?;
    progs
        .set(flowplane_common::GUEST_PROG_DHCP, &prog_fd, 0)
        .context("register guest_dhcp in GUEST_PROGS")?;
    Ok(())
}
```

Note: the exact `fd()` / `try_clone()` / borrow ordering may need adjustment for aya 0.13.1 — the
goal is "load guest_dhcp, then `ProgramArray::set(GUEST_PROG_DHCP, &fd, 0)`". If `ProgramFd` cannot
be cloned, keep the program-fd borrow alive and scope `take_map` accordingly, or set the array
entry before any conflicting borrow. Verify against `aya::maps::array::program_array`.

- [ ] **Step 2: Call it from bring_up**

In `flowplane/src/control.rs` `bring_up`, right after `loader::load_program(&mut ebpf, "guest_tx")?;` (around line 150):

```rust
        // Load guest_dhcp and wire it into GUEST_PROGS so guest_tx's DHCP tail call resolves.
        loader::register_guest_dhcp(&mut ebpf)?;
```

- [ ] **Step 3: Build the userspace binary**

Run: `cargo build -p flowplane`
Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add flowplane/src/loader.rs flowplane/src/control.rs
git commit -m "feat(loader): load guest_dhcp and register it in GUEST_PROGS at startup"
```

---

### Task 5: Extend the verifier test to assert guest_dhcp loads

**Files:**
- Modify: `flowplane/src/loader.rs` (the `both_programs_pass_verifier` test)

- [ ] **Step 1: Add guest_dhcp to the loaded-programs list**

In the test at `flowplane/src/loader.rs`, change:

```rust
        for name in ["uplink_rx", "guest_tx"] {
```
to:
```rust
        for name in ["uplink_rx", "guest_tx", "guest_dhcp"] {
```

- [ ] **Step 2: Run the verifier gate**

```bash
cargo test -p flowplane --no-run
BIN=$(ls -t target/debug/deps/flowplane-* | grep -v '\.d$' | head -1)
sudo "$BIN" both_programs_pass_verifier --ignored --nocapture 2>&1 | tail -5
```
Expected: `test result: ok. 1 passed` — all three programs (`uplink_rx`, `guest_tx`, `guest_dhcp`) load through the verifier. This is the core proof that the split works.

- [ ] **Step 3: Commit**

```bash
git add flowplane/src/loader.rs
git commit -m "test(verifier): assert guest_dhcp loads alongside uplink_rx and guest_tx"
```

---

### Task 6: Conformance — DHCPv6 green + full suite + regression

**Files:**
- Possibly modify: `test/conformance/conftest.py` / fixtures (restore the deferred `request_ip` in `prepare_ipv4` if still stubbed — 2b Task 5 carryover)

- [ ] **Step 1: Run the DHCPv6 conformance test alone**

```bash
CONF_TESTS="test_dhcpv6.py" ./test/conformance/run.sh 2>&1 | tail -20
```
Expected: `test_dhcpv6_vf0` and `test_dhcpv6_vf1` PASS (OFFER/REPLY with correct DUID echo, IAID, DNS servers, and the tftp:// / http:// boot file URL).

- [ ] **Step 2: If a fixture was stubbed for DHCP, restore it**

If `prepare_ipv4`/`prepare_ifaces` had its DHCP `request_ip` call removed during earlier DHCP bring-up, restore it so the IPv4 DHCP path is exercised too. Re-run `test_dhcpv4.py` to confirm.

- [ ] **Step 3: Run the full conformance suite**

```bash
make conformance 2>&1 | tail -15
```
Expected: all tests pass (target 93/93, 2 skipped) — DHCPv4, DHCPv6, ARP, ND, v4-forwarding, v6-overlay, NAT, NAT64, firewall, LB all green, proving the tail-call split preserved the datapath.

- [ ] **Step 4: Run the netns e2e regression**

```bash
make e2e 2>&1 | tail -15
```
Expected: the netns smoke/e2e probe passes (guest-to-guest + overlay still work end-to-end).

- [ ] **Step 5: Commit any fixture changes**

```bash
git add test/conformance
git commit -m "test(conformance): DHCPv6 green via tail-call split; restore IPv4 DHCP fixture"
```

---

## Notes for Phase 2 (deferred, not in this plan)

Split `guest_ipv4_fwd` (the conntrack/firewall/NAT/route/encap path) and `guest_ipv6`
(`v6_guest_tx`) into their own tail-called programs, with `guest_tx` tail-calling them too. This
requires the forwarding helpers (`vip`, `nat`, `encap`, `conntrack` apply/touch) to take
`data`/`data_end` rather than calling `ctx.data_end()` inside a subprogram (which trips the
verifier's "pointer arithmetic on pkt_end prohibited"). It buys further headroom but is not needed
to ship in-XDP DHCPv6 — Phase 1 already returns `guest_tx` to a verifying budget.
