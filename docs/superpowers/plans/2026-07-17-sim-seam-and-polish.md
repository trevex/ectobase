# Sim Seam Closure (option B) + Opportunistic Polish — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the overlay `inner_len` computation into the pure-core `write_outer_v6` (derived
from a new `Pkt::logical_len()`), delete the load-bearing tc override, make the linear-only sim
reproduce the non-linear case, add verifier load-anchors for the three tc classifiers, and land
seven mechanical Go/Rust polish items.

**Architecture:** `inner_len` is today computed independently by each encap glue path and passed
into `write_outer_v6` as an `EncapParams` field; the tc path overrides it with `skb->len`
because a non-linear skb's linear head under-counts. We give `Pkt` a `logical_len()` method,
compute `inner_len = logical_len - ETH_LEN - IPV6_LEN` **once** inside `write_outer_v6` (called
post-grow, layout `[outer_eth][outer_ipv6][inner_ip]`), remove the field, and let `VecPkt`
carry a settable logical length so a sim test guards the bug class. The substitution is
byte-identical on the wire.

**Tech Stack:** Rust (`no_std` eBPF core + aya), `xdp-dp-core`/`xdp-dp-ebpf`/`xdp-dp-sim`;
Go (`netplane`, controller-runtime).

**Reference spec:** `docs/superpowers/specs/2026-07-17-sim-seam-and-polish-design.md`

**Build/test commands** (from repo root, needs the nix flake PATH):
- Core + sim: `cargo test -p xdp-dp-core -p xdp-dp-sim`
- eBPF compile (verifier-target build): `cargo build -p xdp-dp-ebpf` (per the repo's ebpf build
  target; if the workspace uses a dedicated command, e.g. `cargo xtask build-ebpf`, use that).
- Verifier load-anchors: `cargo test -p xdp-dp --test <name>` (mirrors
  `xdp-dp/tests/verify_edge_wan_rx.rs`).
- Go: `cd netplane && go test ./...`

---

## Part A — Sim seam closure (option B)

### Task A1: Add `Pkt::logical_len()` + `RawPkt` logical length

**Files:**
- Modify: `xdp-dp-core/src/pkt.rs` (trait)
- Modify: `xdp-dp-ebpf/src/coreimpl.rs` (`CtxPkt`, `RawPkt`)

- [ ] **Step 1: Add the trait method** in `xdp-dp-core/src/pkt.rs`, inside `trait Pkt`, right
  after `fn len(&self) -> usize;`:

```rust
    /// Logical (wire) length of the packet in bytes.
    ///
    /// On skb-backed contexts this is `skb->len`, which may exceed the linear head
    /// (`data_end - data`). On XDP and linear buffers it equals the head length. The encap
    /// header writer uses this (not `len()`) so a non-linear skb gets a correct outer payload
    /// length.
    fn logical_len(&self) -> usize;
```

- [ ] **Step 2: Implement for `CtxPkt`** in `xdp-dp-ebpf/src/coreimpl.rs` (XDP is always linear),
  inside `impl Pkt for CtxPkt<'_>`, after `len`:

```rust
    #[inline(always)]
    fn logical_len(&self) -> usize {
        self.ctx.data_end() - self.ctx.data()
    }
```

- [ ] **Step 3: Give `RawPkt` a logical length field.** Change the struct and constructors:

```rust
pub struct RawPkt {
    data: usize,
    data_end: usize,
    logical_len: usize,
}

impl RawPkt {
    /// Build a window over `[data, data_end)`. Linear: `logical_len == data_end - data`.
    /// Caller guarantees the pointers come from the same packet and `data <= data_end`.
    #[inline(always)]
    pub fn new(data: usize, data_end: usize) -> Self {
        debug_assert!(data <= data_end, "RawPkt: data must not exceed data_end");
        Self { data, data_end, logical_len: data_end - data }
    }

    /// Build a window whose logical (wire) length differs from the linear head — e.g. a tc
    /// skb whose true length is `skb->len` (`ctx.len()`) but whose `[data, data_end)` covers
    /// only the pulled linear head.
    #[inline(always)]
    pub fn with_logical_len(data: usize, data_end: usize, logical_len: usize) -> Self {
        debug_assert!(data <= data_end, "RawPkt: data must not exceed data_end");
        Self { data, data_end, logical_len }
    }
}
```

- [ ] **Step 4: Implement `logical_len` for `RawPkt`**, inside `impl Pkt for RawPkt`, after `len`:

```rust
    #[inline(always)]
    fn logical_len(&self) -> usize {
        self.logical_len
    }
```

- [ ] **Step 5: Compile.** Run: `cargo build -p xdp-dp-ebpf` and `cargo test -p xdp-dp-core`
  Expected: builds clean. Existing `RawPkt::new` callers (e.g. firewall reads in `egress.rs`,
  `tc.rs`) are unaffected — `new` still sets `logical_len` to the linear length.

- [ ] **Step 6: Commit**

```bash
git add xdp-dp-core/src/pkt.rs xdp-dp-ebpf/src/coreimpl.rs
git commit -m "feat(pkt): add Pkt::logical_len() + RawPkt::with_logical_len"
```

---

### Task A2: `VecPkt` logical length + unit test

**Files:**
- Modify: `xdp-dp-sim/src/pkt.rs`

- [ ] **Step 1: Add the field + setter.** Update the struct, `from_bytes`, and impl `Pkt`:

```rust
pub struct VecPkt {
    buf: Vec<u8>,
    logical_len: usize,
}

impl VecPkt {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self { buf: b.to_vec(), logical_len: b.len() }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    /// Override the logical (wire) length to simulate a non-linear skb whose true length
    /// exceeds the linear buffer. Used to exercise the encap inner-length path.
    pub fn set_logical_len(&mut self, n: usize) {
        self.logical_len = n;
    }
}
```

- [ ] **Step 2: Keep `logical_len` in sync on resize + implement the trait method.** In
  `impl Pkt for VecPkt`, add `logical_len` and adjust `grow_head`/`shrink_head`:

```rust
    fn logical_len(&self) -> usize {
        self.logical_len
    }
```

  and in `grow_head`, after rebuilding `self.buf`, add `self.logical_len += delta;`
  (so a linear `VecPkt` keeps `logical_len == buf.len()`); in `shrink_head`, after the
  `self.buf.drain(0..delta)`, add `self.logical_len -= delta;`.

- [ ] **Step 3: Add a unit test** in the `tests` module of `xdp-dp-sim/src/pkt.rs`:

```rust
    #[test]
    fn logical_len_defaults_to_buf_and_tracks_resize() {
        let mut p = VecPkt::from_bytes(&[0u8; 20]);
        assert_eq!(p.logical_len(), 20);
        assert!(p.grow_head(14));
        assert_eq!(p.logical_len(), 34); // tracks grow
        assert!(p.shrink_head(14));
        assert_eq!(p.logical_len(), 20); // tracks shrink
        p.set_logical_len(1500); // simulate non-linear skb
        assert_eq!(p.logical_len(), 1500);
        assert_eq!(p.len(), 20); // linear buffer unchanged
    }
```

- [ ] **Step 4: Run tests.** Run: `cargo test -p xdp-dp-sim pkt::tests`
  Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add xdp-dp-sim/src/pkt.rs
git commit -m "feat(sim): VecPkt settable logical_len (models non-linear skb)"
```

---

### Task A3: Compute `inner_len` in `write_outer_v6`; delete tc override; regression test

**Files:**
- Modify: `xdp-dp-core/src/encap.rs` (`write_outer_v6`)
- Modify: `xdp-dp-ebpf/src/tc.rs` (both Encap branches)
- Modify: `xdp-dp-sim/src/encap_test.rs` (existing test + new regression test)

Note: `EncapParams.inner_len` is **kept** in this task (still set by literals, now ignored by
`write_outer_v6`). The field is removed in Task A4. This keeps the tree compiling and behavior
byte-identical at each step.

- [ ] **Step 1: Compute `inner_len` inside `write_outer_v6`** in `xdp-dp-core/src/encap.rs`.
  Replace the line `ok &= pkt.write_bytes(ip + 4, &e.inner_len.to_be_bytes());` with a locally
  computed value, and update the doc comment. The full function becomes:

```rust
/// Write outer Eth+IPv6 into a frame that already has IPV6_LEN bytes of front room. Pure byte
/// writes via `Pkt` — no resize, no redirect. Returns false on bounds failure.
///
/// The outer IPv6 `payload_length` (the encapsulated inner length) is derived from the packet's
/// LOGICAL length, not its linear head: the frame here is laid out `[outer_eth(ETH_LEN)]
/// [outer_ipv6(IPV6_LEN)][inner_ip…]`, so `inner_len = logical_len - ETH_LEN - IPV6_LEN`. Using
/// `logical_len()` (skb->len on tc) makes a non-linear skb encapsulate with the correct outer
/// length instead of a short, truncated one.
#[inline(always)]
pub fn write_outer_v6<P: Pkt>(pkt: &mut P, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let inner_len = pkt.logical_len().saturating_sub(ETH_LEN + IPV6_LEN) as u16;
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    ok &= pkt.write_bytes(ip, &[0x60, 0, 0, 0]);
    ok &= pkt.write_bytes(ip + 4, &inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]); // [next_header, hop_limit=64]
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}
```

- [ ] **Step 2: Delete the tc v6 override + use `with_logical_len`** in `xdp-dp-ebpf/src/tc.rs`.
  In the `EgressVerdict::Encap(mut e)` branch near line 132, remove the override block:

```rust
                // See the IPv4 Encap branch below: in the tc (skb) path forward_decision_v6's
                // inner_len counts only the linear head, so a non-linear inner-IPv6 skb would get a
                // short outer payload_length and be dropped as truncated. Recompute from skb->len
                // (full logical length) before adjust_room: outer IPv6 payload = skb->len - ETH_LEN.
                e.inner_len =
                    (ctx.len() as usize).saturating_sub(xdp_dp_common::arp_nd::ETH_LEN) as u16;
```

  Change `Encap(mut e)` to `Encap(e)` (no longer mutated). Then change the `RawPkt::new` at the
  write site (currently `let mut pkt = RawPkt::new(ctx.data(), ctx.data_end());`) to:

```rust
                // adjust_room grew skb->len by IPV6_LEN; ctx.len() is now the full logical
                // length. write_outer_v6 derives the outer payload from logical_len - ETH_LEN -
                // IPV6_LEN, correct even when the inner sits in a paged frag.
                let mut pkt =
                    RawPkt::with_logical_len(ctx.data(), ctx.data_end(), ctx.len() as usize);
```

- [ ] **Step 3: Delete the tc v4 override + use `with_logical_len`** in the second
  `EgressVerdict::Encap(mut e)` branch near line 202. Remove the override block:

```rust
                // forward_decision_v4 derived inner_len from data_end-data, which in the tc (skb)
                // path is only the LINEAR head of the skb. A non-linear skb — e.g. a TCP segment
                // whose L4 payload sits in a paged frag (busybox wget's GET reproduces this) —
                // undercounts by that payload, so the outer IPv6 payload_length would be written
                // short and the fabric/edge drops the frame as truncated (pure-ACK/SYN and raw ICMP
                // are linear, so they slipped through). Recompute from skb->len (the full logical
                // length) captured BEFORE adjust_room: the skb is [inner_eth(ETH_LEN)][inner_ip], so
                // the outer IPv6 payload = skb->len - ETH_LEN.
                e.inner_len =
                    (ctx.len() as usize).saturating_sub(xdp_dp_common::arp_nd::ETH_LEN) as u16;
```

  Change `Encap(mut e)` to `Encap(e)`, and change that branch's `RawPkt::new(ctx.data(),
  ctx.data_end())` to `RawPkt::with_logical_len(ctx.data(), ctx.data_end(), ctx.len() as usize)`
  with the same comment as Step 2. Keep the surrounding `adjust_room`/`pull_data` calls exactly
  as they are — the `RawPkt` is still built *after* them.

- [ ] **Step 4: Update the existing sim test** in `xdp-dp-sim/src/encap_test.rs`. The header is
  written from `p`'s logical length now. The test builds `[0u8; 34]` then `grow_head(IPV6_LEN)`,
  so `logical_len == 34 + IPV6_LEN` and `inner_len == 34`. The `inner_len: 34` literal in the
  `EncapParams` is now ignored but still compiles (removed in Task A4). Leave the assertion
  `assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(34));` — it still holds (34 == logical 74 − 54).
  No change required here beyond confirming it passes.

- [ ] **Step 5: Add the non-linear regression test** to `xdp-dp-sim/src/encap_test.rs`:

```rust
#[test]
fn encap_inner_len_uses_logical_not_linear() {
    // Simulate a non-linear skb: the linear head holds only the outer header room, but the
    // true (logical) frame is much larger with the inner payload in a "paged" region.
    // write_outer_v6 must derive the outer payload_length from logical_len, not buf.len().
    let mut p = VecPkt::from_bytes(&[0u8; ETH_LEN + IPV6_LEN]); // 54-byte linear head only
    p.set_logical_len(ETH_LEN + IPV6_LEN + 1400); // 1400-byte inner in the "frags"
    let e = EncapParams {
        gateway_mac: [1, 1, 1, 1, 1, 1],
        uplink_mac: [2, 2, 2, 2, 2, 2],
        uplink_ifindex: 7,
        src_underlay: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb],
        inner_len: 0, // ignored — write_outer_v6 derives it from logical_len
        inner_proto: 4,
    };
    assert!(write_outer_v6(&mut p, &e));
    // outer IPv6 payload_length == logical_len - ETH_LEN - IPV6_LEN == 1400, NOT
    // buf.len() - ETH_LEN - IPV6_LEN == 0.
    assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(1400));
}
```

- [ ] **Step 6: Run the tests.** Run: `cargo test -p xdp-dp-core -p xdp-dp-sim`
  Expected: PASS, including the new `encap_inner_len_uses_logical_not_linear`. To confirm it is a
  real guard, temporarily change `write_outer_v6` to use `pkt.len()` — the new test must FAIL —
  then revert.

- [ ] **Step 7: Verify the eBPF still builds + verifier-loads.** Run: `cargo build -p xdp-dp-ebpf`
  and the verifier load tests (`cargo test -p xdp-dp --test verify_edge_wan_rx` and any sibling
  verify tests). Expected: builds + loads clean.

- [ ] **Step 8: Commit**

```bash
git add xdp-dp-core/src/encap.rs xdp-dp-ebpf/src/tc.rs xdp-dp-sim/src/encap_test.rs
git commit -m "feat(encap): derive inner_len from logical_len in write_outer_v6; drop tc override

write_outer_v6 now computes the outer IPv6 payload_length from the packet's
logical length (skb->len on tc via RawPkt::with_logical_len), so the tc glue
no longer overrides EncapParams.inner_len. Byte-identical on the wire; a sim
regression test with a non-linear VecPkt guards the bug class."
```

---

### Task A4: Remove the dead `inner_len` field + plumbing

**Files:**
- Modify: `xdp-dp-core/src/encap.rs` (`EncapParams`)
- Modify: `xdp-dp-ebpf/src/encap.rs` (drop param from 3 fns)
- Modify: `xdp-dp-ebpf/src/egress.rs` (forward_decision v4/v6)
- Modify: `xdp-dp-ebpf/src/ingress.rs` (3 call sites)
- Modify: `xdp-dp-ebpf/src/nat64.rs` (1 call site — the `encap_and_redirect` one, NOT the inline synth path)
- Modify: `xdp-dp-sim/src/sim.rs`, `xdp-dp-sim/src/encap_test.rs`, `xdp-dp-sim/src/lb_scenario_test.rs`, `xdp-dp-sim/src/ns_scenario_test.rs` (EncapParams literals)

This is an atomic dead-code removal: `EncapParams.inner_len` is written nowhere-read after A3,
so remove the field and every site that sets or plumbs it. The tree must compile at the end.

- [ ] **Step 1: Remove the field** from `EncapParams` in `xdp-dp-core/src/encap.rs` (delete the
  `pub inner_len: u16,` line).

- [ ] **Step 2: Drop the `inner_len` param from the three ebpf encap fns** in
  `xdp-dp-ebpf/src/encap.rs`: `write_encap_outer`, `encap_and_redirect`,
  `encap_and_redirect_via_devmap`. Remove the `inner_len: u16,` parameter, remove `inner_len,`
  from the `EncapParams { … }` literal in `write_encap_outer`, and drop the argument where
  `write_encap_outer` is called inside the two `encap_and_redirect*` bodies. Update the doc
  comment on `write_encap_outer` (delete the `inner_len` sentence).

- [ ] **Step 3: Fix `forward_decision_v4` and `forward_decision_v6`** in
  `xdp-dp-ebpf/src/egress.rs`: delete `let inner_len = (data_end - data - ETH_LEN) as u16;`
  (lines ~129 and ~177) and the `inner_len,` field in each `EncapParams { … }` literal (lines
  ~140 and ~188). `data`/`data_end` may become unused in the tail — if the compiler warns,
  prefix with `_` at the binding or remove if genuinely unused (they are still used earlier for
  the metering/local-fast-path reads, so likely fine).

- [ ] **Step 4: Fix the `ingress.rs` call sites** (3): at each `encap_and_redirect_via_devmap`
  call (lines ~371, ~402, ~425) remove the `inner_len` argument, and delete the now-dead
  `let inner_len = (data_end - data - ETH_LEN) as u16;` locals (lines ~364, ~395, ~418).

- [ ] **Step 5: Fix the `nat64.rs` call site** (line ~566): remove the `inner_len` argument from
  the `encap_and_redirect(...)` call and delete the dead `let inner_len = (ctx.data_end() -
  ctx.data() - ETH_LEN) as u16;` local (line ~564). **Do NOT touch** the inline synth-encap path
  around lines 887–922 (`let inner_len = (20u16).wrapping_add(l4_len as u16);`) — it builds its
  outer header directly, not via `EncapParams`/`write_outer_v6`, and is out of scope.

- [ ] **Step 6: Remove `inner_len` from the sim `EncapParams` literals:**
  - `xdp-dp-sim/src/sim.rs:199` — delete `inner_len: 0, // edge_encap sets this`.
  - `xdp-dp-sim/src/sim.rs` `edge_encap` (line ~73) — delete `e.inner_len = (inner_frame.len()
    - ETH_LEN) as u16;` and change the `mut e` param to `e` if `e` is no longer mutated (it is
    still passed to `write_outer_v6` by `&e`); adjust the doc comment's `inner_len = …` clause.
  - `xdp-dp-sim/src/encap_test.rs:15` — delete `inner_len: 34,` (both the existing test literal
    and the regression-test literal's `inner_len: 0,` added in A3 Step 5).
  - `xdp-dp-sim/src/lb_scenario_test.rs:89` — delete `inner_len: 0,`.
  - `xdp-dp-sim/src/ns_scenario_test.rs:41` — delete `inner_len: 0,   // set by edge_encap`.

- [ ] **Step 7: Build everything + run tests.** Run:
  `cargo build -p xdp-dp-ebpf && cargo test -p xdp-dp-core -p xdp-dp-sim` and the verifier load
  tests. Expected: compiles clean (no unused-field/param warnings), all tests green, verifier
  loads. The on-wire bytes are unchanged from A3.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(encap): remove now-dead EncapParams.inner_len + plumbing

inner_len is computed in write_outer_v6 from logical_len; drop the field,
the fn params (write_encap_outer/encap_and_redirect*), the forward_decision
computations, and the sim literals. No behavior change."
```

---

### Task A5: Verifier load-anchors for the tc classifiers

**Files:**
- Create: `xdp-dp/tests/verify_tc_guest.rs`
- Reference: `xdp-dp/tests/verify_edge_wan_rx.rs` (existing pattern)

- [ ] **Step 1: Read the reference test** `xdp-dp/tests/verify_edge_wan_rx.rs` to copy its
  harness (how it locates the compiled ebpf object, loads it, and asserts a program loads). Note
  its program-load line (~32) casts to `Xdp`; the tc classifiers cast to `SchedClassifier`.

- [ ] **Step 2: Write the load-anchor test** `xdp-dp/tests/verify_tc_guest.rs`, loading the same
  ebpf object and asserting each tc classifier loads into the kernel (verifier-clean). Structure
  (adapt paths/loader to match the reference exactly):

```rust
// Load-only verifier anchor: the tc classifiers must load (pass the verifier). No datapath.
use aya::programs::SchedClassifier;

#[test]
fn tc_guest_classifiers_load() {
    // <copy the exact ebpf-object locate + Ebpf::load(...) preamble from verify_edge_wan_rx.rs>
    let mut bpf = /* load compiled ebpf object, same as verify_edge_wan_rx.rs */;
    for name in ["tc_guest_tx", "tc_guest_nat64", "tc_guest_dhcp"] {
        let prog: &mut SchedClassifier = bpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program {name} missing"))
            .try_into()
            .unwrap_or_else(|_| panic!("program {name} is not a SchedClassifier"));
        prog.load().unwrap_or_else(|e| panic!("verifier rejected {name}: {e}"));
    }
}
```

- [ ] **Step 3: Run it.** Run: `cargo test -p xdp-dp --test verify_tc_guest`
  Expected: PASS — all three classifiers load. (This test needs the same privileges/env as the
  existing verify tests; run under the repo's usual `sudo -E`/flake harness if required.)

- [ ] **Step 4: Commit**

```bash
git add xdp-dp/tests/verify_tc_guest.rs
git commit -m "test(verify): load-anchor tc_guest_tx/nat64/dhcp classifiers"
```

---

## Part B — Opportunistic polish

Each task is independent and mechanical; no behavior change. Run `cd netplane && go test ./...`
(Go tasks) or `cargo build -p xdp-dp-ebpf && cargo test -p xdp-dp-core` (Rust task) after each.

### Task B1: Rename `Reconciler` → `NATGatewayReconciler`

**Files:**
- Modify: `netplane/controllers/natgateway.go` (type + all methods/refs)
- Modify: any constructor/wiring referencing it (e.g. `main.go`/manager setup — grep first)

- [ ] **Step 1:** `cd netplane && grep -rn "Reconciler" controllers/natgateway.go` and
  `grep -rn "natgateway.Reconciler\|NATGateway.*Reconciler\|&Reconciler{" .` to find every
  reference before renaming.
- [ ] **Step 2:** Rename the type `Reconciler` → `NATGatewayReconciler` in
  `controllers/natgateway.go`, including the receiver on every method and any `SetupWithManager`.
- [ ] **Step 3:** Update all references found in Step 1 (constructor sites, manager wiring).
- [ ] **Step 4:** Run: `cd netplane && go build ./... && go test ./...` Expected: PASS.
- [ ] **Step 5:** Commit: `git commit -am "refactor(netplane): rename Reconciler to NATGatewayReconciler"`

### Task B2: Config struct over setter injection

**Files:**
- Modify: `netplane/agent/reconcile.go` (remove `SetUnderlay`/`SetDataplane`/`SetEdgeLoopback`)
- Modify: the construction site(s) that call those setters (grep)

- [ ] **Step 1:** `cd netplane && grep -rn "SetUnderlay\|SetDataplane\|SetEdgeLoopback" .` to map
  the setters + every caller.
- [ ] **Step 2:** Define a deps/config struct (e.g. `type Deps struct { Underlay …; Dataplane …;
  EdgeLoopback … }`) and accept it at construction of the reconciler, assigning the fields once.
  Follow the existing field types exactly (read the current setter bodies for the types).
- [ ] **Step 3:** Delete the three `Set*` methods; update all callers to pass `Deps` at
  construction instead of calling setters afterward.
- [ ] **Step 4:** Run: `cd netplane && go build ./... && go test ./...` Expected: PASS.
- [ ] **Step 5:** Commit: `git commit -am "refactor(agent): construct reconciler with a Deps struct, drop setter injection"`

### Task B3: Consolidate the two dataplane fakes

**Files:**
- Modify: `netplane/agent/bus_test.go` (`fakeDP`), `netplane/agent/reconcile_nat_test.go` (`natRecordingDP`)
- Create/Modify: a shared test helper (e.g. `netplane/agent/dp_fake_test.go`)

- [ ] **Step 1:** Read both fakes; list the union of methods/recording each provides.
- [ ] **Step 2:** Write one recording fake in `netplane/agent/dp_fake_test.go` implementing the
  full dataplane interface with the union of recorded calls.
- [ ] **Step 3:** Replace both `fakeDP` and `natRecordingDP` usages with the consolidated fake;
  delete the old definitions.
- [ ] **Step 4:** Run: `cd netplane && go test ./agent/...` Expected: PASS.
- [ ] **Step 5:** Commit: `git commit -am "test(agent): consolidate dataplane fakes into one recording fake"`

### Task B4: Thread `ctx` into `applyPublic`

**Files:**
- Modify: `netplane/agent/public.go` (`applyPublic` signature + body)
- Modify: `netplane/agent/bus.go` (call site in the loop)

- [ ] **Step 1:** `grep -rn "applyPublic" netplane/` to find the definition + all call sites.
- [ ] **Step 2:** Add `ctx context.Context` as the first param to `applyPublic`; thread it into
  any context-taking calls in the body (gRPC/client calls). Pass the loop's `ctx` at the call
  site in `bus.go`.
- [ ] **Step 3:** Run: `cd netplane && go build ./... && go test ./...` Expected: PASS.
- [ ] **Step 4:** Commit: `git commit -am "refactor(agent): thread ctx into applyPublic"`

### Task B5: Remove the `grpc.WaitForReady` hack

**Files:**
- Modify: `netplane/agent/bus.go` (line ~483, `var _ = grpc.WaitForReady`)

- [ ] **Step 1:** Read the surrounding context to confirm the `var _ = grpc.WaitForReady` line is
  a no-op keep-import/placeholder and nothing depends on it. Check whether `grpc` is still used
  elsewhere in the file (if the line only exists to keep the import, verify the import is
  otherwise used or remove it too).
- [ ] **Step 2:** Delete the line (and the now-unused `grpc` import if it was the only use).
- [ ] **Step 3:** Run: `cd netplane && go build ./... && go test ./...` Expected: PASS.
- [ ] **Step 4:** Commit: `git commit -am "chore(agent): remove grpc.WaitForReady placeholder"`

### Task B6: Unify NatBlock / PublicRecord representations

**Files:**
- Modify: `netplane/agent/natreconcile.go` (line ~31), `netplane/reflector/nattable.go` (line ~9), `netplane/reflector/publictable.go` (line ~9)

- [ ] **Step 1:** Read the three near-duplicate record types; determine the common fields and
  which package should own the shared type (prefer the lowest-level shared package both import;
  grep for an existing shared types package).
- [ ] **Step 2:** Define the unified type(s) in the shared location; replace the duplicates with
  it. Keep exported field names/JSON tags identical so serialization is unchanged.
- [ ] **Step 3:** Update all references; run: `cd netplane && go build ./... && go test ./...`
  Expected: PASS.
- [ ] **Step 4:** Commit: `git commit -am "refactor(netplane): unify NatBlock/PublicRecord types"`

### Task B7: `DpErr` enum replacing `Result<_, ()>`

**Files:**
- Create: the enum in `xdp-dp-core` (e.g. `xdp-dp-core/src/err.rs`, re-exported from `lib.rs`)
- Modify: `xdp-dp-core/src/uplink.rs:35`; `xdp-dp-ebpf/src/encap.rs:51,72`,
  `nat64.rs:267,661,953`, `ingress.rs:101,320,345`, `v6.rs:93,141`, `egress.rs:193`

- [ ] **Step 1:** Add the enum in `xdp-dp-core` (`no_std`-safe, no `std::error::Error`):

```rust
/// Coarse datapath failure reason for the eBPF hot path. Verifier-friendly: `Copy`, no alloc,
/// no panic. Carried in `Result<_, DpErr>` in place of the old `Result<_, ()>`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DpErr {
    /// A bounds/length check failed (packet too short, offset out of range).
    Bounds,
    /// Header parse/lookup produced an unexpected shape.
    Parse,
    /// The packet/protocol shape is not handled by this path.
    Unsupported,
    /// No route/entry resolved for the destination.
    NoRoute,
}
```

  Re-export from `xdp-dp-core/src/lib.rs` (`pub use err::DpErr;` or `pub mod err;`).

- [ ] **Step 2:** At each of the 12 sites, change the function's error type from `()` to
  `DpErr` and replace `.ok_or(())?` / `Err(())` / `.map_err(|_| ())` with the fitting variant
  (`Bounds` for length/offset failures, `Parse` for header/lookup shape, `Unsupported` for
  unhandled proto shapes, `NoRoute` for missing route/entry). Do them one file at a time,
  building after each so the error-type propagation is contained. Where a caller currently does
  `?` on a `Result<_, ()>`, its own signature must also move to `DpErr` (or map explicitly) —
  follow the chain up; if it reaches a top-level program fn that returns an xdp/tc action, map
  `DpErr` to the existing action (e.g. `XDP_ABORTED`/`TC_ACT_SHOT`) exactly as `Err(())` mapped
  before.
- [ ] **Step 3:** Build + verifier-load. Run: `cargo build -p xdp-dp-ebpf && cargo test -p
  xdp-dp-core` and the verifier load tests (`verify_edge_wan_rx`, `verify_tc_guest`). Expected:
  compiles, no new panics/allocation, verifier clean.
- [ ] **Step 4:** Commit: `git commit -am "refactor(xdp): replace Result<_,()> with coarse DpErr enum"`

---

## Final

- [ ] After all tasks: dispatch a final code review over the whole branch (spec compliance +
  quality), then use `superpowers:finishing-a-development-branch` to complete (tests → options).

## Self-review notes

- **Spec coverage:** A1–A2 (`logical_len` + `VecPkt`), A3 (compute-in-core + tc override delete +
  regression test), A4 (field/plumbing removal), A5 (verifier anchors), B1–B7 (the seven polish
  items) — every spec section maps to a task.
- **Type consistency:** `logical_len()` name used identically in trait + all impls;
  `RawPkt::with_logical_len` signature identical at definition (A1) and tc call sites (A3);
  `DpErr` variants fixed in B7 Step 1 and referenced in Step 2.
- **Atomicity:** A3 keeps `EncapParams.inner_len` (tree compiles, behavior byte-identical); A4
  removes it atomically across all literals/params. The two are ordered so each ends compiling.
