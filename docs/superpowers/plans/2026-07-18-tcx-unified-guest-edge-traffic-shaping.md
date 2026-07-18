# Unified tcx Guest Edge + EDT Traffic Shaping — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate the guest edge onto a single tcx datapath (delete the legacy XDP `guest_tx`) and add EDT egress traffic shaping (paced by an `fq` qdisc on the uplink) plus token-bucket policing for the external-egress sub-cap and ingress.

**Architecture:** The uplink stays XDP (`uplink_rx`). The guest edge is tcx-only (`tc_guest_tx` in `flowplane-ebpf/src/tc.rs`). Egress total is EDT-shaped: `tc_guest_tx` stamps `skb->tstamp` via a pure-core `edt_departure`, and an `fq` root qdisc on the uplink paces departure. Egress-public and ingress are token-bucket policed (reusing `meter::take`). The `MeterState` map gains an ingress lane; the `total` lane is reinterpreted as the EDT schedule. The metalnet-derived `InterfaceBandwidth` CRD is replaced by a shaping-native `InterfaceQoS`; `ConfigureMeter` gRPC becomes `ConfigureQoS`.

**Tech Stack:** Rust (aya 0.13 eBPF + userspace), `flowplane-core` pure-core seam, `flowplane-sim`, Go (controller-runtime CRDs + agent reconcilers), protobuf/gRPC (tonic + buf).

**Spec:** `docs/superpowers/specs/2026-07-18-tcx-unified-guest-edge-traffic-shaping-design.md`

**Key design decisions locked in this plan:**
- `MeterState` grows from 8 to 12 `u64` fields (64→96 bytes). `total_*` fields are reused for the
  EDT egress lane: `total_bps` = shaped rate, `total_last_ns` = EDT schedule cursor (`t_last`);
  `total_burst`/`total_tokens` are unused on the EDT path (kept 0). New `ingress_*` lane is a token
  bucket. `public_*` unchanged.
- Core functions: `edt_departure` (pure math), `edt_egress` (map-driven), `public_pass`,
  `ingress_pass` (both token-bucket police via existing `take`). Old `meter_pass` is removed after
  callers migrate.
- EDT `skb->tstamp` is set in `tc.rs` on the Encap→uplink path only (same-node `Local` and non-shaped
  paths are unaffected). Uplink gets `tc qdisc replace dev <uplink> root fq` (aya has no qdisc API).
- No `skb->tstamp` BPF_PROG_TEST_RUN anchor (infeasible — `xdp_md` has no tstamp, no tc test-run
  precedent). EDT is covered by pure-core unit tests + a sim departure-spacing test; wiring by
  `verify_tc_guest.rs` load check + live validation.

---

## Phase 1 — Pure-core foundation (additive, keeps tree green)

### Task 1: Grow MeterState with the ingress lane

**Files:**
- Modify: `flowplane/flowplane-common/src/lib.rs:184-198` (struct), `:782-786` (layout test)

- [ ] **Step 1: Replace the MeterState struct**

Replace lines 184-198 with:

```rust
/// Per-interface QoS state. Three lanes:
/// - Egress total (EDT SHAPING): `total_bps` = shaped rate (bytes/s, 0 = unlimited);
///   `total_last_ns` = the EDT schedule cursor (`t_last`, ns). `total_burst`/`total_tokens` are
///   UNUSED on the EDT path (no token bucket) and kept 0 for layout stability.
/// - Egress public (token-bucket POLICING of external/NATed egress): `public_*`.
/// - Ingress (token-bucket POLICING of traffic delivered to the guest): `ingress_*`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MeterState {
    pub total_bps: u64,
    pub total_burst: u64,
    pub total_tokens: u64,
    pub total_last_ns: u64,
    pub public_bps: u64,
    pub public_burst: u64,
    pub public_tokens: u64,
    pub public_last_ns: u64,
    pub ingress_bps: u64,
    pub ingress_burst: u64,
    pub ingress_tokens: u64,
    pub ingress_last_ns: u64,
}
```

- [ ] **Step 2: Update the layout test**

Replace lines 782-786 (`meter_state_layout`) with:

```rust
#[test]
fn meter_state_layout() {
    // 12 fields * 8 bytes each = 96 bytes.
    assert_eq!(core::mem::size_of::<MeterState>(), 96);
    assert_eq!(core::mem::align_of::<MeterState>(), 8);
}
```

- [ ] **Step 3: Build the common crate**

Run: `cargo build -p flowplane-common && cargo test -p flowplane-common meter_state_layout`
Expected: PASS. (The `aya::Pod for MeterState` impl at `:529` needs no change — it's `unsafe impl`.)

- [ ] **Step 4: Verify dependents still compile (fields are additive)**

Run: `cargo build -p flowplane-core -p flowplane-sim`
Expected: PASS — existing `take`/`meter_pass` only read `total_*`/`public_*`, which are unchanged.

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-common/src/lib.rs
git commit -m "feat(flowplane): add ingress lane to MeterState (96B)"
```

---

### Task 2: Pure-core EDT + police functions

**Files:**
- Modify: `flowplane/flowplane-core/src/meter.rs` (add functions + unit tests)

- [ ] **Step 1: Write the failing unit tests**

Append inside the existing `#[cfg(test)] mod tests { ... }` block in `flowplane/flowplane-core/src/meter.rs`:

```rust
    #[test]
    fn edt_unlimited_sends_now() {
        // rate 0 => send immediately, cursor tracks now.
        assert_eq!(super::edt_departure(0, 1500, 0, 12345), (12345, 12345));
    }

    #[test]
    fn edt_idle_departs_now_and_reserves_airtime() {
        // 1_000_000 B/s, 1500B => delay = 1500 * 1e9 / 1e6 = 1_500_000 ns.
        // Idle (t_last=0 < now): departs at now, cursor advances to now + delay.
        let (ts, t_last) = super::edt_departure(1_000_000, 1500, 0, 10_000_000);
        assert_eq!(ts, 10_000_000);
        assert_eq!(t_last, 11_500_000);
    }

    #[test]
    fn edt_backlogged_queues_after_cursor() {
        // Cursor ahead of now (backlog): packet departs at the cursor, not now.
        let (ts, t_last) = super::edt_departure(1_000_000, 1500, 20_000_000, 10_000_000);
        assert_eq!(ts, 20_000_000);
        assert_eq!(t_last, 21_500_000);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p flowplane-core meter::tests::edt_ 2>&1 | head -20`
Expected: FAIL to compile — `edt_departure` not found.

- [ ] **Step 3: Add the pure-core functions**

In `flowplane/flowplane-core/src/meter.rs`, after `take(...)` and before `meter_pass(...)`, add:

```rust
/// Earliest-departure-time step for one packet on a shaped lane. Returns
/// `(tstamp_ns, new_t_last)`. The packet may leave no earlier than `max(t_last, now)`; the schedule
/// cursor then advances by the packet's airtime (`wire_len * 1e9 / rate_bps`). `rate_bps == 0` =>
/// unlimited: send at `now`, cursor = `now`. Pure — no 128-bit ops (wire_len is bounded by the MTU,
/// so `wire_len * 1e9` stays within u64). This is the shaping analog of `take` (which polices).
#[inline(always)]
pub fn edt_departure(rate_bps: u64, wire_len: u64, t_last: u64, now: u64) -> (u64, u64) {
    if rate_bps == 0 {
        return (now, now);
    }
    let delay = wire_len.saturating_mul(1_000_000_000) / rate_bps;
    let t_sched = if t_last > now { t_last } else { now };
    (t_sched, t_sched.saturating_add(delay))
}

/// Map-driven EDT egress step for `ifindex` sending `wire_len` bytes. Reads `METER[ifindex]`,
/// advances the schedule cursor (`total_last_ns`) via [`edt_departure`] on the egress rate
/// (`total_bps`), writes it back, and returns the packet's departure timestamp (ns). `None` = no
/// egress shaping configured (no entry, or `total_bps == 0`) — caller sends immediately. The eBPF
/// wrapper passes `bpf_ktime_get_ns()`; the sim passes a controlled clock.
#[inline(always)]
pub fn edt_egress<M: Maps>(maps: &mut M, ifindex: u32, wire_len: u64, now: u64) -> Option<u64> {
    let mut m: MeterState = maps.meter_get(ifindex)?;
    if m.total_bps == 0 {
        return None;
    }
    let (tstamp, t_last) = edt_departure(m.total_bps, wire_len, m.total_last_ns, now);
    m.total_last_ns = t_last;
    maps.meter_update(ifindex, m);
    Some(tstamp)
}

/// Token-bucket POLICE of the external-egress (public) lane. Only gates when `is_external`. `true` =
/// pass, `false` = drop. No entry, or `public_bps == 0` => pass. Faithful reuse of [`take`].
#[inline(always)]
pub fn public_pass<M: Maps>(
    maps: &mut M,
    ifindex: u32,
    len: u64,
    is_external: bool,
    now: u64,
) -> bool {
    if !is_external {
        return true;
    }
    let mut m: MeterState = match maps.meter_get(ifindex) {
        Some(m) => m,
        None => return true,
    };
    if m.public_bps == 0 {
        return true;
    }
    let (pass, tok) = take(
        m.public_bps,
        m.public_burst,
        m.public_tokens,
        m.public_last_ns,
        now,
        len,
    );
    m.public_tokens = tok;
    m.public_last_ns = now;
    maps.meter_update(ifindex, m);
    pass
}

/// Token-bucket POLICE of the ingress lane (traffic delivered to the guest), keyed by the
/// destination tap `ifindex`. `true` = pass, `false` = drop. No entry, or `ingress_bps == 0` =>
/// pass. Faithful reuse of [`take`].
#[inline(always)]
pub fn ingress_pass<M: Maps>(maps: &mut M, ifindex: u32, len: u64, now: u64) -> bool {
    let mut m: MeterState = match maps.meter_get(ifindex) {
        Some(m) => m,
        None => return true,
    };
    if m.ingress_bps == 0 {
        return true;
    }
    let (pass, tok) = take(
        m.ingress_bps,
        m.ingress_burst,
        m.ingress_tokens,
        m.ingress_last_ns,
        now,
        len,
    );
    m.ingress_tokens = tok;
    m.ingress_last_ns = now;
    maps.meter_update(ifindex, m);
    pass
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p flowplane-core meter::tests 2>&1 | tail -20`
Expected: PASS (existing `take` tests + the 3 new `edt_` tests).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-core/src/meter.rs
git commit -m "feat(flowplane-core): edt_departure/edt_egress + public/ingress police seams"
```

---

## Phase 2 — eBPF datapath wiring

### Task 3: eBPF wrappers for the new lanes

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/meter.rs` (the whole file — replace `meter_pass` wrapper)

- [ ] **Step 1: Replace the eBPF meter wrappers**

Replace the `meter_pass` wrapper (`flowplane/flowplane-ebpf/src/meter.rs:12-21`) with three wrappers:

```rust
/// EDT egress: compute+advance the departure schedule for `ifindex` sending `wire_len` bytes.
/// Returns `Some(tstamp_ns)` when shaping is configured (caller sets `skb->tstamp`), else `None`.
#[inline(always)]
pub fn edt_stamp(ifindex: u32, wire_len: u64) -> Option<u64> {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::edt_egress(&mut crate::coreimpl::GlobalMaps, ifindex, wire_len, now)
}

/// Police the external-egress (public) lane. `true` = pass, `false` = drop.
#[inline(always)]
pub fn public_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::public_pass(&mut crate::coreimpl::GlobalMaps, ifindex, len, is_external, now)
}

/// Police the ingress lane (keyed by dest tap ifindex). `true` = pass, `false` = drop.
#[inline(always)]
pub fn ingress_pass(ifindex: u32, len: u64) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::ingress_pass(&mut crate::coreimpl::GlobalMaps, ifindex, len, now)
}
```

Keep the existing `use` of `bpf_ktime_get_ns` at the top of the file.

- [ ] **Step 2: Migrate the egress caller from meter_pass to public_pass**

In `flowplane/flowplane-ebpf/src/egress.rs`, replace the metering block (`:108-112`):

```rust
    // Rate metering.
    let frame_len = (data_end - data) as u64;
    if !crate::meter::meter_pass(ifindex, frame_len, is_ext) {
        return EgressVerdict::Drop;
    }
```

with (total is now EDT-shaped downstream in tc.rs; here we only POLICE the public lane):

```rust
    // Public-lane policing (external egress only). Total egress is EDT-shaped at the uplink FQ
    // via `edt_stamp` in tc_guest_tx's encap path, not policed here.
    let frame_len = (data_end - data) as u64;
    if !crate::meter::public_pass(ifindex, frame_len, is_ext) {
        return EgressVerdict::Drop;
    }
```

- [ ] **Step 3: Build the eBPF object**

Run: `cargo build -p flowplane-ebpf 2>&1 | tail -20`
Expected: PASS (or the workspace's eBPF build command, e.g. `cargo xtask build-ebpf` if present — check `Makefile`).

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane-ebpf/src/meter.rs flowplane/flowplane-ebpf/src/egress.rs
git commit -m "feat(flowplane-ebpf): split meter into edt_stamp + public/ingress police wrappers"
```

---

### Task 4: EDT tstamp on the tc encap→uplink path

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/tc.rs` (IPv4 Encap arm ~`:193-222`, IPv6 Encap arm ~`:125-147`, imports)

- [ ] **Step 1: Add the tstamp constant + helper import**

At the top of `flowplane/flowplane-ebpf/src/tc.rs`, add (near the other `use`/const items):

```rust
// skb->tstamp delivery-time kind: monotonic delivery time honored by the fq qdisc (EDT model).
const BPF_SKB_TSTAMP_DELIVERY_MONO: u32 = 1;
```

- [ ] **Step 2: Stamp EDT in the IPv4 Encap arm**

In the IPv4 `EgressVerdict::Encap(e)` arm, replace the success branch:

```rust
                if flowplane_core::encap::write_outer_v6(&mut pkt, &e) {
                    return unsafe { bpf_redirect(e.uplink_ifindex, 0) as i32 };
                }
                return TC_ACT_SHOT;
```

with:

```rust
                if flowplane_core::encap::write_outer_v6(&mut pkt, &e) {
                    // EDT egress shaping: stamp the wire-length-derived departure time so the
                    // uplink's fq qdisc paces this flow. `ctx.len()` is the full post-encap logical
                    // length. No shaping configured => no stamp (send immediately).
                    if let Some(ts) = crate::meter::edt_stamp(ifindex, ctx.len() as u64) {
                        unsafe {
                            aya_ebpf::helpers::gen::bpf_skb_set_tstamp(
                                ctx.skb.skb as *mut _,
                                ts,
                                BPF_SKB_TSTAMP_DELIVERY_MONO,
                            );
                        }
                    }
                    return unsafe { bpf_redirect(e.uplink_ifindex, 0) as i32 };
                }
                return TC_ACT_SHOT;
```

- [ ] **Step 3: Stamp EDT in the IPv6 Encap arm**

Apply the identical replacement to the IPv6 `EgressVerdict::Encap(e)` arm (the second occurrence of the same `write_outer_v6 { ... bpf_redirect(e.uplink_ifindex) }` block, ~`:143`).

- [ ] **Step 4: Build the eBPF object**

Run: `cargo build -p flowplane-ebpf 2>&1 | tail -30`
Expected: PASS. If `aya_ebpf::helpers::gen::bpf_skb_set_tstamp` is not present in aya 0.13, fall back to a direct context-field write (tc programs may write `skb->tstamp`): replace the `unsafe { ...gen::bpf_skb_set_tstamp... }` block with `unsafe { (*ctx.skb.skb).tstamp = ts; }`. Rebuild and confirm PASS.

- [ ] **Step 5: Load-verify the tc programs still verify**

Run: `cargo test -p flowplane --test verify_tc_guest 2>&1 | tail -20`
Expected: PASS — `tc_guest_tx` (and the DHCP/NAT64 tail targets) load and pass the verifier.

- [ ] **Step 6: Commit**

```bash
git add flowplane/flowplane-ebpf/src/tc.rs
git commit -m "feat(flowplane-ebpf): EDT skb->tstamp on tc_guest_tx encap->uplink path"
```

---

### Task 5: Ingress policing at uplink_rx delivery

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/ingress.rs` (the guest-tap delivery block ~`:291-314`)

- [ ] **Step 1: Insert the ingress police before guest delivery**

In `flowplane/flowplane-ebpf/src/ingress.rs`, in the `Ok(_)` branch after `decap_and_rewrite`, insert the ingress police immediately before the `Ok(crate::maps::GUEST_DEV.redirect(...))` return:

```rust
            // Ingress-lane policing (token bucket keyed by the destination tap). Over-rate frames
            // are dropped here, before delivery. No cap configured => pass. `ctx` post-decap length
            // is the inner frame delivered to the guest.
            let in_len = (ctx.data_end() - ctx.data()) as u64;
            if !crate::meter::ingress_pass(tap_ifindex, in_len) {
                return Ok(xdp_action::XDP_DROP);
            }
            // Deliver to the guest via the GUEST_DEV devmap ...
            Ok(crate::maps::GUEST_DEV
                .redirect(tap_ifindex, 0)
                .unwrap_or_else(|_| unsafe { bpf_redirect(tap_ifindex, 0) } as u32))
```

(Confirm `xdp_action` is in scope in `ingress.rs`; if not, add `use aya_ebpf::bindings::xdp_action;` at the top.)

- [ ] **Step 2: Build the eBPF object**

Run: `cargo build -p flowplane-ebpf 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 3: Load-verify uplink_rx still verifies**

Run: `cargo test -p flowplane --test anchor_uplink 2>&1 | tail -20`
Expected: PASS — `uplink_rx` loads and the byte-parity anchor holds (no METER entry => ingress_pass returns true, so byte-parity fixtures are unaffected).

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane-ebpf/src/ingress.rs
git commit -m "feat(flowplane-ebpf): ingress-lane policing at uplink_rx guest delivery"
```

---

## Phase 3 — Delete the legacy XDP guest_tx

### Task 6: Remove the XDP guest program + GuestLink::Xdp + FLOWPLANE_GUEST_TC fork

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/main.rs` (`:33-45`), `flowplane/flowplane-ebpf/src/egress.rs` (`try_guest_tx` XDP wrapper), `flowplane/flowplane/src/control.rs` (multiple sites), `flowplane/flowplane/src/loader.rs` (XDP-guest attach fns)

- [ ] **Step 1: Delete the `#[xdp] guest_tx` entry**

Remove the `#[xdp] pub fn guest_tx(ctx: XdpContext) -> u32 { ... }` block at `flowplane/flowplane-ebpf/src/main.rs:33-45`.

- [ ] **Step 2: Delete the XDP `try_guest_tx` wrapper**

In `flowplane/flowplane-ebpf/src/egress.rs`, delete the XDP-only `try_guest_tx(ctx: &XdpContext)` function (the wrapper that calls `forward_decision_v4`/`forward_decision_v6` and does the `bpf_xdp_adjust_head` + `write_outer_v6` + `bpf_redirect` glue at `:278-289` and its surrounding function). Keep `forward_decision_v4`/`forward_decision_v6`, `EgressVerdict`, and `deliver` — those are the shared core used by tc.rs.

- [ ] **Step 3: Collapse the FLOWPLANE_GUEST_TC fork in bring_up**

In `flowplane/flowplane/src/control.rs:293-313`, replace the `guest_tc` env read + `if guest_tc { ... } else { ... }` with the tc-only path:

```rust
        // Guest edge is tcx-only. Pre-load tc_guest_tx and register the tc DHCP/NAT64 tail-call
        // array (GUEST_PROGS_TC) once here; per-interface attach then only needs attach().
        let guest_progs = {
            let progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
            loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
            progs
        };
```

Delete the `guest_tc` field from `Inner` (`:248`) and every read of `g.guest_tc`.

- [ ] **Step 4: Simplify reattach_guest to tc-only**

Replace `flowplane/flowplane/src/control.rs:490-536` (`reattach_guest`) with the tc-only body:

```rust
    pub fn reattach_guest(&self, interface_id: &[u8], device: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "tc_guest_tx", &pin_dir, &gname)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt guest link {gname} failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &gname);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "tc_guest_tx", device, &pin_dir, &gname)?;
            }
            g.links.insert(interface_id.to_vec(), GuestLink::Pinned(gname));
            return Ok(());
        }
        let link = GuestLink::Tc(
            loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                .with_context(|| format!("re-attach tc_guest_tx to {device}"))?,
        );
        g.links.insert(interface_id.to_vec(), link);
        Ok(())
    }
```

- [ ] **Step 5: Simplify create_interface attach branch to tc-only**

Replace `flowplane/flowplane/src/control.rs:730-758` (the `let link = if g.pin_links { ... } else if g.guest_tc { ... } else { ... }`) with:

```rust
        let link = if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            loader::attach_tc_pinned_at(&mut g.ebpf, "tc_guest_tx", device, &pin_dir, &gname)
                .with_context(|| format!("attach+pin tc_guest_tx to {device}"))?;
            GuestLink::Pinned(gname)
        } else {
            GuestLink::Tc(
                loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                    .with_context(|| format!("attach tc_guest_tx to {device}"))?,
            )
        };
```

- [ ] **Step 6: Delete the GuestLink::Xdp variant**

In `flowplane/flowplane/src/control.rs:21-31`, remove the `Xdp(...)` arm from `GuestLink`, leaving `Tc` and `Pinned`. Update the doc comment (drop the "Xdp variant is the legacy fallback" sentence).

- [ ] **Step 7: Delete now-unused XDP-guest loader fns + XDP DHCP registration**

In `flowplane/flowplane/src/loader.rs`, delete `attach_xdp_pinned_at` **only if** it is used solely for the guest (grep first: `grep -rn attach_xdp_pinned_at flowplane/`). It is also used for uplink pinning — if so, KEEP it. Delete `readopt_xdp_link` and `register_guest_dhcp` (the XDP DHCP tail-call registration) **only if** grep shows no remaining callers after Steps 3-6. Delete `load_program`'s guest usage only if unused. Use:

Run: `grep -rn "guest_tx\|register_guest_dhcp\b\|readopt_xdp_link\|FLOWPLANE_GUEST_TC\|guest_tc" flowplane/flowplane/src`
Expected after edits: only `tc_guest_tx` / `register_guest_dhcp_tc` / `readopt_tc_link` remain. Delete every dead XDP-guest symbol the grep still flags.

- [ ] **Step 8: Build the whole workspace**

Run: `cargo build --workspace 2>&1 | tail -30`
Expected: PASS. Fix any remaining references to `guest_tx`, `GuestLink::Xdp`, or `guest_tc`.

- [ ] **Step 9: Run the guest anchor + verify tests**

Run: `cargo test -p flowplane --test anchor_guest_tx --test verify_tc_guest 2>&1 | tail -30`
Expected: PASS. NOTE: `anchor_guest_tx.rs` loads the XDP `guest_tx` program — since it is deleted, this anchor must be either (a) retargeted to load `tc_guest_tx` via a classifier test-run, or (b) removed and its coverage folded into the sim (`flowplane-sim` guest_tx tests). Per the spec's seam rule, prefer (b): delete `anchor_guest_tx.rs` and confirm `flowplane-sim` covers the guest_tx forward decision. Document the deletion in the commit.

- [ ] **Step 10: Commit**

```bash
git add -A flowplane/
git commit -m "refactor(flowplane): delete legacy XDP guest_tx; guest edge is tcx-only"
```

---

## Phase 4 — Control plane: QoS map write, gRPC, uplink FQ

### Task 7: Rework meter_state + set_qos for three lanes

**Files:**
- Modify: `flowplane/flowplane/src/control.rs` (`meter_state` `:664-681`, `set_meter` `:1796-1815`, and `program_iface_maps`/CLI callers of `meter_state`)

- [ ] **Step 1: Replace meter_state**

Replace `flowplane/flowplane/src/control.rs:664-681` with:

```rust
    /// Build a `MeterState` from per-lane caps in Mbit/s. Egress total is EDT-shaped: only
    /// `total_bps` + the schedule cursor (`total_last_ns`, seeded 0) matter — no token bucket.
    /// Public + ingress are token-bucket policers (burst = 1/8 s of rate, min 2000B). All 0 =>
    /// unlimited. Single source of truth shared by program_iface_maps, the CLI, and ConfigureQoS.
    pub fn meter_state(egress_mbps: u64, public_mbps: u64, ingress_mbps: u64) -> flowplane_common::MeterState {
        let e = egress_mbps.saturating_mul(1_000_000) / 8;
        let p = public_mbps.saturating_mul(1_000_000) / 8;
        let i = ingress_mbps.saturating_mul(1_000_000) / 8;
        flowplane_common::MeterState {
            total_bps: e,
            total_burst: 0,
            total_tokens: 0,
            total_last_ns: 0,
            public_bps: p,
            public_burst: (p / 8).max(2000),
            public_tokens: p / 8,
            public_last_ns: 0,
            ingress_bps: i,
            ingress_burst: (i / 8).max(2000),
            ingress_tokens: i / 8,
            ingress_last_ns: 0,
        }
    }
```

- [ ] **Step 2: Replace set_meter with set_qos**

Replace `flowplane/flowplane/src/control.rs:1796-1815` (`set_meter`) with:

```rust
    pub fn set_qos(
        &self,
        interface_id: &[u8],
        egress_mbps: u64,
        public_mbps: u64,
        ingress_mbps: u64,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let tap = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        if egress_mbps == 0 && public_mbps == 0 && ingress_mbps == 0 {
            let _ = g.meter.remove(&tap);
            Ok(())
        } else {
            let state = Self::meter_state(egress_mbps, public_mbps, ingress_mbps);
            g.meter.upsert(tap, state)
        }
    }
```

- [ ] **Step 3: Fix the other meter_state callers**

Run: `grep -rn "meter_state\|set_meter\b" flowplane/flowplane/src`
For each remaining caller of the old 2-arg `meter_state(total, public)` (e.g. `program_iface_maps`, the `--meter` CLI flag handler), update to `meter_state(total_mbps, public_mbps, 0)` — the create-time bandwidth maps to egress+public; ingress is set only via ConfigureQoS. Rename any `set_meter` call to `set_qos(iface, total, public, 0)`.

- [ ] **Step 4: Build**

Run: `cargo build -p flowplane 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane/src/control.rs
git commit -m "feat(flowplane): set_qos + three-lane meter_state derivation"
```

---

### Task 8: gRPC ConfigureMeter → ConfigureQoS

**Files:**
- Modify: `api/proto/dataplane/v1/dataplane.proto` (`:47-50`, `:177-182`), `flowplane/flowplane/src/node.rs` (`:514-540`), regenerate Go stubs

- [ ] **Step 1: Replace the proto RPC + messages**

In `api/proto/dataplane/v1/dataplane.proto`, replace the `ConfigureMeter` rpc (`:47-50`) with:

```proto
  // ConfigureQoS sets (or clears) the per-interface QoS lanes. egress_mbps is EDT-shaped; public and
  // ingress are token-bucket policed. All 0 = unlimited (clears the entry). Idempotent.
  rpc ConfigureQoS(ConfigureQoSRequest) returns (ConfigureQoSResponse);
```

and replace the `ConfigureMeterRequest`/`ConfigureMeterResponse` messages (`:177-182`) with:

```proto
message ConfigureQoSRequest {
  string interface_id = 1;      // target interface (as in AttachInterface)
  uint32 egress_mbps = 2;       // EDT-shaped total egress in Mbit/s; 0 = unlimited
  uint32 public_mbps = 3;       // external/NATed egress policer in Mbit/s; 0 = unlimited
  uint32 ingress_mbps = 4;      // ingress policer in Mbit/s; 0 = unlimited
  uint32 egress_burst_kb = 5;   // reserved (EDT ignores in v1); 0 = default
  uint32 ingress_burst_kb = 6;  // reserved (default burst in v1); 0 = default
}
message ConfigureQoSResponse {}
```

- [ ] **Step 2: Regenerate stubs**

Run the project's proto codegen (check `Makefile`/`buf.gen.yaml`): e.g. `make proto` or `buf generate`.
Expected: `cni/gen/dataplanev1/dataplane.pb.go` + `dataplane_grpc.pb.go` regenerate with `ConfigureQoS*`; the Rust tonic stubs regenerate (build.rs/prost) on next `cargo build`.

- [ ] **Step 3: Replace the Rust server handler**

Replace `flowplane/flowplane/src/node.rs:514-540` (`configure_meter`) with:

```rust
    async fn configure_qos(
        &self,
        req: Request<ConfigureQoSRequest>,
    ) -> Result<Response<ConfigureQoSResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let iface = r.interface_id.clone().into_bytes();
        let egress_mbps = r.egress_mbps as u64;
        let public_mbps = r.public_mbps as u64;
        let ingress_mbps = r.ingress_mbps as u64;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            attach.control.set_qos(&iface, egress_mbps, public_mbps, ingress_mbps)
        })
        .await
        .map_err(|e| Status::internal(format!("configure_qos task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "QOS configure iface={} egress_mbps={} public_mbps={} ingress_mbps={}",
            r.interface_id, r.egress_mbps, r.public_mbps, r.ingress_mbps
        );
        Ok(Response::new(ConfigureQoSResponse {}))
    }
```

Update the `use` import of `ConfigureMeterRequest`/`Response` to `ConfigureQoSRequest`/`ConfigureQoSResponse`, and rename the trait method in the `impl DataplaneNode for ...` block from `configure_meter` to `configure_qos`.

- [ ] **Step 4: Build the Rust node**

Run: `cargo build -p flowplane 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/proto/dataplane/v1/dataplane.proto flowplane/flowplane/src/node.rs cni/gen/dataplanev1/
git commit -m "feat(dataplane): ConfigureMeter -> ConfigureQoS (egress/public/ingress lanes)"
```

---

### Task 9: fq qdisc on the uplink

**Files:**
- Modify: `flowplane/flowplane/src/loader.rs` (add `ensure_fq_qdisc`, call it in `attach_uplink`), and the edge/extra-uplink attach sites in `control.rs`/`main.rs`

- [ ] **Step 1: Add the fq qdisc helper**

In `flowplane/flowplane/src/loader.rs`, add:

```rust
/// Ensure the uplink has an `fq` root qdisc so EDT `skb->tstamp` departure times are honored (the
/// shaping mechanism). aya 0.13 exposes no qdisc API beyond clsact, so shell out to `tc`. `replace`
/// is idempotent (creates or swaps the root qdisc). On a real multi-queue NIC, `mq` root + per-queue
/// `fq` is preferable; `root fq` is correct for single-queue/veth and a safe default. A failure is
/// logged but not fatal — shaping degrades to no pacing rather than dropping the datapath.
pub fn ensure_fq_qdisc(iface: &str) {
    match std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "fq"])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("warning: `tc qdisc replace dev {iface} root fq` exited {s}; egress shaping disabled"),
        Err(e) => eprintln!("warning: could not run tc to set fq on {iface} ({e}); egress shaping disabled"),
    }
}
```

- [ ] **Step 2: Call it from attach_uplink**

Replace `flowplane/flowplane/src/loader.rs:285-289` (`attach_uplink`) with:

```rust
pub fn attach_uplink(iface: &str, pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf(pin_dir)?;
    attach_xdp(&mut ebpf, "uplink_rx", iface)?;
    ensure_fq_qdisc(iface);
    Ok(ebpf)
}
```

- [ ] **Step 3: Call it on the map-driven + edge + extra-uplink attach paths**

Run: `grep -rn "attach_xdp_pinned_at\|attach_extra_uplink\|attach_edge\|uplink_rx" flowplane/flowplane/src/control.rs flowplane/flowplane/src/main.rs`
For each uplink that gets `uplink_rx` attached (the primary map-driven uplink, `attach_extra_uplink`, and the edge `wan_rx` uplink), add a `loader::ensure_fq_qdisc(<iface>)` call right after the XDP attach. (The WAN edge uplink also shapes external egress, so it needs fq too.)

- [ ] **Step 4: Build**

Run: `cargo build -p flowplane 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane/src/loader.rs flowplane/flowplane/src/control.rs flowplane/flowplane/src/main.rs
git commit -m "feat(flowplane): fq root qdisc on uplinks for EDT egress pacing"
```

---

## Phase 5 — Go CRD + reconciler

### Task 10: Replace InterfaceBandwidth with InterfaceQoS

**Files:**
- Modify: `api/v1alpha1/networkinterface_types.go` (`:11-35`), `api/v1alpha1/zz_generated.deepcopy.go`

- [ ] **Step 1: Replace the spec field + type**

In `api/v1alpha1/networkinterface_types.go`, replace the `Bandwidth *InterfaceBandwidth` field (`:21-23`) with:

```go
	// QoS caps/shapes throughput for this interface. Nil = unlimited.
	// +optional
	QoS *InterfaceQoS `json:"qos,omitempty" protobuf:"bytes,4,opt,name=qos"`
```

and replace the `InterfaceBandwidth` struct (`:26-35`) with:

```go
// InterfaceQoS is per-interface traffic control. Egress is EDT-shaped (smoothed) at the uplink fq
// qdisc; ingress is token-bucket policed. Programmed into the dataplane via DataplaneNode/ConfigureQoS.
type InterfaceQoS struct {
	// Egress shapes outbound (VM->out) throughput.
	// +optional
	Egress *EgressQoS `json:"egress,omitempty" protobuf:"bytes,1,opt,name=egress"`
	// Ingress polices inbound (out->VM) throughput.
	// +optional
	Ingress *RateLimit `json:"ingress,omitempty" protobuf:"bytes,2,opt,name=ingress"`
}

// EgressQoS shapes total egress (EDT) with an optional external sub-cap.
type EgressQoS struct {
	// RateMbps is the EDT-shaped total egress rate in Mbit/s. 0 = unlimited.
	// +optional
	RateMbps uint32 `json:"rateMbps,omitempty" protobuf:"varint,1,opt,name=rateMbps"`
	// BurstKB is an optional burst allowance in KB. Reserved (EDT ignores it in v1). 0 = default.
	// +optional
	BurstKB uint32 `json:"burstKB,omitempty" protobuf:"varint,2,opt,name=burstKB"`
	// PublicMbps caps external/NATed egress in Mbit/s (policed). 0 = unlimited.
	// +optional
	PublicMbps uint32 `json:"publicMbps,omitempty" protobuf:"varint,3,opt,name=publicMbps"`
}

// RateLimit is a token-bucket policing cap.
type RateLimit struct {
	// RateMbps caps throughput in Mbit/s. 0 = unlimited.
	// +optional
	RateMbps uint32 `json:"rateMbps,omitempty" protobuf:"varint,1,opt,name=rateMbps"`
	// BurstKB is an optional burst allowance in KB. Reserved (default burst in v1). 0 = default.
	// +optional
	BurstKB uint32 `json:"burstKB,omitempty" protobuf:"varint,2,opt,name=burstKB"`
}
```

- [ ] **Step 2: Regenerate deepcopy**

Run the project's codegen (check `Makefile`): `make generate` (controller-gen). Expected: `zz_generated.deepcopy.go` regenerates `InterfaceQoS`/`EgressQoS`/`RateLimit` DeepCopy funcs and updates `NetworkInterfaceSpec.DeepCopyInto` to reference `QoS`.

If `make generate` is unavailable, hand-edit `api/v1alpha1/zz_generated.deepcopy.go`: delete `InterfaceBandwidth`'s DeepCopy funcs (`:239-...`), replace the `Bandwidth` block in `NetworkInterfaceSpec.DeepCopyInto` (`:582-585`) with:

```go
	if in.QoS != nil {
		in, out := &in.QoS, &out.QoS
		*out = new(InterfaceQoS)
		(*in).DeepCopyInto(*out)
	}
```

and add DeepCopy funcs for the three new types:

```go
func (in *InterfaceQoS) DeepCopyInto(out *InterfaceQoS) {
	*out = *in
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = new(EgressQoS)
		**out = **in
	}
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = new(RateLimit)
		**out = **in
	}
}
func (in *InterfaceQoS) DeepCopy() *InterfaceQoS {
	if in == nil {
		return nil
	}
	out := new(InterfaceQoS)
	in.DeepCopyInto(out)
	return out
}
func (in *EgressQoS) DeepCopyInto(out *EgressQoS) { *out = *in }
func (in *EgressQoS) DeepCopy() *EgressQoS {
	if in == nil {
		return nil
	}
	out := new(EgressQoS)
	in.DeepCopyInto(out)
	return out
}
func (in *RateLimit) DeepCopyInto(out *RateLimit) { *out = *in }
func (in *RateLimit) DeepCopy() *RateLimit {
	if in == nil {
		return nil
	}
	out := new(RateLimit)
	in.DeepCopyInto(out)
	return out
}
```

- [ ] **Step 3: Build the API package**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./api/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add api/v1alpha1/
git commit -m "feat(api): replace InterfaceBandwidth with InterfaceQoS (egress shape + ingress police)"
```

---

### Task 11: Dataplane interface ConfigureMeter → ConfigureQoS

**Files:**
- Modify: `netplane/agent/bus.go` (`:20-46` interface, `:675-680` adapter), `netplane/agent/dp_fake_test.go` (`:172-184`)

- [ ] **Step 1: Replace the interface method**

In `netplane/agent/bus.go`, replace the `ConfigureMeter` declaration (`:44-46`) with:

```go
	// ConfigureQoS sets the per-interface QoS lanes: egressMbps is EDT-shaped, publicMbps and
	// ingressMbps are policed. All 0 = unlimited (clears). Idempotent.
	ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error
```

- [ ] **Step 2: Replace the adapter impl**

Replace `netplane/agent/bus.go:675-680` with:

```go
func (d dpAdapter) ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error {
	_, err := d.c.ConfigureQoS(ctx, &dpv1.ConfigureQoSRequest{
		InterfaceId: interfaceID, EgressMbps: egressMbps, PublicMbps: publicMbps, IngressMbps: ingressMbps,
	})
	return err
}
```

- [ ] **Step 3: Update the fake**

In `netplane/agent/dp_fake_test.go`, replace `ConfigureMeter` (`:172-178`) with a `ConfigureQoS` recording the three caps. Update the `meterCall` struct to `qosCall{iface string; egressMbps, publicMbps, ingressMbps uint32}` and rename `meters`/`meterN`/`getMeter` to `qos`/`qosN`/`getQoS` accordingly:

```go
func (f *recordingDP) ConfigureQoS(_ context.Context, iface string, egressMbps, publicMbps, ingressMbps uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qos[iface] = qosCall{iface: iface, egressMbps: egressMbps, publicMbps: publicMbps, ingressMbps: ingressMbps}
	f.qosN[iface]++
	return nil
}
func (f *recordingDP) getQoS(iface string) (qosCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.qos[iface]
	return v, ok
}
```

Also update the `recordingDP` struct fields + `newRecordingDP()` initializer (grep `meters`, `meterN`, `meterCall` in that file and rename).

- [ ] **Step 4: Build (compile only; reconciler updated next task)**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./netplane/... 2>&1 | head`
Expected: FAIL — `metereconcile.go` still calls `ConfigureMeter`/uses `InterfaceBandwidth`. That is fixed in Task 12; proceed.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/bus.go netplane/agent/dp_fake_test.go
git commit -m "feat(agent): Dataplane.ConfigureQoS replaces ConfigureMeter"
```

---

### Task 12: Rename meter reconciler → QoS reconciler (TDD)

**Files:**
- Rename+rewrite: `netplane/agent/metereconcile.go` → `netplane/agent/qosreconcile.go`
- Rename+rewrite: `netplane/agent/metereconcile_test.go` → `netplane/agent/qosreconcile_test.go`
- Modify: `netplane/agent/reconcile.go` (`:33` struct field), and the caller of `ReconcileMeter`

- [ ] **Step 1: Update the Reconciler field**

In `netplane/agent/reconcile.go`, replace the `appliedMeter` field with:

```go
	// appliedQoS tracks the last per-interface QoS pushed so ReconcileQoS only calls ConfigureQoS
	// when a NIC's QoS spec changes (level-triggered convergence).
	appliedQoS map[string]netv1.InterfaceQoS // interfaceID -> last-applied QoS
```

- [ ] **Step 2: Write the failing test file**

Create `netplane/agent/qosreconcile_test.go` (rename the old file). Mirror the three `metereconcile_test.go` cases against `InterfaceQoS` and `getQoS`. Full content:

```go
package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func qosScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func qosNodePtr(s string) *string { return &s }

func TestReconcileQoS_PushesCaps(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeA"),
			QoS: &netv1.InterfaceQoS{
				Egress:  &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40},
				Ingress: &netv1.RateLimit{RateMbps: 200},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getQoS("web-0-nic0")
	if !ok {
		t.Fatalf("ConfigureQoS not called for web-0-nic0; qos=%+v", dp.qos)
	}
	if got.egressMbps != 100 || got.publicMbps != 40 || got.ingressMbps != 200 {
		t.Fatalf("ConfigureQoS caps = (%d,%d,%d), want (100,40,200)", got.egressMbps, got.publicMbps, got.ingressMbps)
	}
}

func TestReconcileQoS_SkipsUnsetAndOffNode(t *testing.T) {
	noCap := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "vpc-a"}, NodeName: qosNodePtr("nodeA")},
	}
	offNode := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeB"),
			QoS:      &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 50}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(noCap, offNode).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.qos) != 0 {
		t.Fatalf("no qos expected, got %+v", dp.qos)
	}
}

func TestReconcileQoS_ConvergesAndClears(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeA"),
			QoS:      &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	for i := 0; i < 2; i++ {
		if err := r.ReconcileQoS(context.Background()); err != nil {
			t.Fatalf("reconcile #%d: %v", i+1, err)
		}
	}
	if n := dp.qosN["web-0-nic0"]; n != 1 {
		t.Fatalf("ConfigureQoS called %d times for unchanged caps, want 1", n)
	}

	nic.Spec.QoS = nil
	if err := cl.Update(context.Background(), nic); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getQoS("web-0-nic0")
	if !ok {
		t.Fatal("ConfigureQoS clear not called")
	}
	if got.egressMbps != 0 || got.publicMbps != 0 || got.ingressMbps != 0 {
		t.Fatalf("clear caps = (%d,%d,%d), want (0,0,0)", got.egressMbps, got.publicMbps, got.ingressMbps)
	}
	if n := dp.qosN["web-0-nic0"]; n != 2 {
		t.Fatalf("ConfigureQoS called %d times total, want 2", n)
	}
}
```

Then `git rm netplane/agent/metereconcile_test.go`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/nik/Development/ironcore-net-xdp && go test ./netplane/agent/ -run TestReconcileQoS 2>&1 | head`
Expected: FAIL to compile — `ReconcileQoS` not defined.

- [ ] **Step 4: Write the reconciler**

Create `netplane/agent/qosreconcile.go` (rename the old file):

```go
package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// lanes flattens an InterfaceQoS into the three scalar Mbit/s caps the dataplane takes.
func lanes(q netv1.InterfaceQoS) (egress, public, ingress uint32) {
	if q.Egress != nil {
		egress = q.Egress.RateMbps
		public = q.Egress.PublicMbps
	}
	if q.Ingress != nil {
		ingress = q.Ingress.RateMbps
	}
	return
}

// ReconcileQoS programs the QoS lanes (ConfigureQoS) for every NetworkInterface scheduled to this
// node whose spec.qos is set. Diffs against r.appliedQoS: unchanged NICs are skipped, cleared/removed
// NICs are set back to unlimited (0/0/0), new/changed caps are pushed. interface_id = NIC name.
func (r *Reconciler) ReconcileQoS(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return fmt.Errorf("list networkinterfaces: %w", err)
	}
	desired := map[string]netv1.InterfaceQoS{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != r.nodeID {
			continue
		}
		if nic.Spec.QoS == nil {
			continue
		}
		desired[nic.Name] = *nic.Spec.QoS
	}
	if r.appliedQoS == nil {
		r.appliedQoS = map[string]netv1.InterfaceQoS{}
	}
	var errs []error
	for iface := range r.appliedQoS {
		if _, ok := desired[iface]; ok {
			continue
		}
		if err := r.dp.ConfigureQoS(ctx, iface, 0, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureQoS clear %s: %w", iface, err))
			continue
		}
		delete(r.appliedQoS, iface)
	}
	for iface, q := range desired {
		if cur, ok := r.appliedQoS[iface]; ok && cur == q {
			continue
		}
		eg, pub, ing := lanes(q)
		if err := r.dp.ConfigureQoS(ctx, iface, eg, pub, ing); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureQoS %s: %w", iface, err))
			continue
		}
		r.appliedQoS[iface] = q
	}
	return errors.Join(errs...)
}
```

Then `git rm netplane/agent/metereconcile.go`.

NOTE on `cur == q`: `InterfaceQoS` contains pointer fields, so `==` compares pointers, not values — two equal specs from separate List calls would compare unequal and re-push every loop. To keep the idempotent-skip semantics, compare by value: replace `if cur, ok := r.appliedQoS[iface]; ok && cur == q` with a helper `qosEqual(cur, q)` that dereferences:

```go
func qosEqual(a, b netv1.InterfaceQoS) bool {
	ae, ap, ai := lanes(a)
	be, bp, bi := lanes(b)
	return ae == be && ap == bp && ai == bi
}
```

and use `ok && qosEqual(cur, q)`.

- [ ] **Step 5: Update the ReconcileMeter caller**

Run: `grep -rn "ReconcileMeter" netplane/`
Replace every `ReconcileMeter(` call (in the agent's reconcile loop) with `ReconcileQoS(`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /home/nik/Development/ironcore-net-xdp && go test ./netplane/agent/ -run TestReconcileQoS -v 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 7: Build the whole Go module**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./... && go test ./netplane/... 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add -A netplane/ && git commit -m "feat(agent): ReconcileQoS replaces ReconcileMeter (three lanes)"
```

---

## Phase 6 — Sim coverage for the new lanes

### Task 13: Sim public-police migration + EDT departure test + ingress police

**Files:**
- Modify: `flowplane/flowplane-sim/src/sim.rs` (`:318-332` meter call; add ingress police at the uplink deliver path), `flowplane/flowplane-sim/src/meter_test.rs` (add EDT test)

- [ ] **Step 1: Migrate the sim egress meter call to public_pass**

In `flowplane/flowplane-sim/src/sim.rs:318-332`, replace the `flowplane_core::meter::meter_pass(...)` call with the EDT-stamp + public-police pair that mirrors the eBPF path (`tc.rs` stamps EDT on encap; `egress.rs` polices public):

```rust
        // 6a. Public-lane policing (external egress only) — mirrors egress.rs.
        let frame_len = pkt.len() as u64;
        if !flowplane_core::meter::public_pass(&mut self.maps, self.src_ifindex, frame_len, is_ext, self.now) {
            return SimOut { action: Action::Drop, pkt: pkt.into_bytes() };
        }
        // 6b. EDT egress shaping — mirrors tc.rs encap path. The sim records the departure stamp on
        // the node so tests can assert pacing; the wire bytes are unchanged (FQ pacing is kernel-side).
        self.last_tstamp = flowplane_core::meter::edt_egress(&mut self.maps, self.src_ifindex, frame_len, self.now);
```

Add a `pub last_tstamp: Option<u64>` field to the sim node struct (near `pub now: u64` at `:38-40`) and initialize it to `None` in the node constructor.

- [ ] **Step 2: Add an EDT departure-spacing test**

Append to `flowplane/flowplane-sim/src/meter_test.rs`:

```rust
#[test]
fn edt_egress_paces_departures() {
    // 1 Mbit/s = 125_000 B/s egress shaping on the source interface. A ~1000B frame reserves
    // 1000 * 1e9 / 125_000 = 8_000_000 ns of airtime. Back-to-back frames at now=0 must be
    // scheduled 8ms apart (the second departs after the first's reserved airtime).
    let mut node = /* build a SimNode whose src_ifindex has an egress-shaped MeterState:
        MeterState { total_bps: 125_000, ..Default::default() } inserted at src_ifindex */ ;
    node.now = 0;
    let out1 = node.guest_tx(&frame_1000b());
    assert_eq!(out1.action, Action::Redirect(/* uplink */));
    let ts1 = node.last_tstamp.expect("shaped => Some");
    // Second frame, same instant: must be scheduled after ts1 + airtime.
    let out2 = node.guest_tx(&frame_1000b());
    assert_eq!(out2.action, Action::Redirect(/* uplink */));
    let ts2 = node.last_tstamp.expect("shaped => Some");
    assert!(ts2 >= ts1 + 8_000_000, "ts2={ts2} not paced 8ms after ts1={ts1}");
}
```

Fill the `/* build a SimNode ... */` and `frame_1000b()`/`Action::Redirect(uplink)` placeholders using the exact fixture-construction helpers already in `meter_test.rs` (the existing `meter_pass_exhaust_drop_then_refill` test at `:163-210` shows how a `SimNode` is built, how the `MeterState` is inserted via `meter_update`, and how a frame is constructed — reuse those helpers verbatim, changing only the `MeterState` to `{ total_bps: 125_000, ..Default::default() }` and asserting on `node.last_tstamp` instead of the drop action).

- [ ] **Step 3: Add ingress policing to the sim uplink-delivery path**

Find the sim's uplink→guest deliver path (grep `host_uplink` / `Action::Redirect(tap)` in `flowplane/flowplane-sim/src/sim.rs` / `fabric.rs`). Before returning the guest-delivery `Redirect(tap)`, insert:

```rust
        // Ingress-lane policing (keyed by dest tap) — mirrors ingress.rs uplink_rx.
        let in_len = pkt.len() as u64;
        if !flowplane_core::meter::ingress_pass(&mut self.maps, tap, in_len, self.now) {
            return SimOut { action: Action::Drop, pkt: pkt.into_bytes() };
        }
```

- [ ] **Step 4: Run sim tests**

Run: `cargo test -p flowplane-sim meter 2>&1 | tail -20`
Expected: PASS (existing metering tests + `edt_egress_paces_departures`).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-sim/
git commit -m "test(flowplane-sim): public/ingress police + EDT departure pacing"
```

---

## Phase 7 — Whole-system verification

### Task 14: Full build, test, and lint sweep

- [ ] **Step 1: Rust workspace build + test**

Run: `cargo build --workspace && cargo test --workspace 2>&1 | tail -40`
Expected: PASS. Address any anchor test that referenced the deleted XDP `guest_tx` (should already be handled in Task 6 Step 9).

- [ ] **Step 2: Rust lint + fmt**

Run: `cargo clippy --workspace -- -D warnings && cargo fmt --check`
Expected: clean.

- [ ] **Step 3: Go build + test + vet**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./... && go test ./... && go vet ./...`
Expected: PASS.

- [ ] **Step 4: Regenerate + diff-check CRDs**

Run: `make generate manifests 2>&1 | tail; git status --porcelain config/ api/`
Expected: any CRD YAML under `config/` reflecting `qos`/`InterfaceQoS` is regenerated and committed. If `make manifests` updates CRD YAML, commit it.

- [ ] **Step 5: Commit any regenerated artifacts**

```bash
git add -A && git commit -m "chore: regenerate CRDs/manifests for InterfaceQoS" || echo "nothing to regenerate"
```

---

## Phase 8 — Live validation (real fabric/VMs; NOT clab)

### Task 15: Validate policing in clab + shaping on real fabric

- [ ] **Step 1: clab bring-up + policing validation**

Bring up the clab fabric (per the repo's clab-up flow). Set a NIC's `spec.qos.egress.publicMbps` and `spec.qos.ingress.rateMbps`, generate over-rate traffic, and confirm drops (policing) via counters. Confirm `verify_tc_guest` + datapath still forwards. NOTE: clab (nested netns) CANNOT validate fq shaping — only policing + that `tc qdisc replace ... root fq` runs without error.

- [ ] **Step 2: Confirm fq is present on the uplink**

Run on a fabric node: `tc qdisc show dev <uplink>`
Expected: shows `fq` as the root qdisc (the loader installed it).

- [ ] **Step 3: Real-fabric/VM egress shaping validation**

On a real (non-nested-netns) fabric or VM host: set `spec.qos.egress.rateMbps` (e.g. 100), run a sustained egress transfer (iperf3) from the guest to a cross-node/external destination, and confirm the achieved rate is smoothly paced near the cap with LOW loss (shaping), contrasted against the public-lane policer which drops. Confirm same-node VM→VM is NOT shaped (expected limitation).

- [ ] **Step 4: Record results**

Append findings to the spec's validation notes or a new memory. Note kernel version (tcx ≥6.6, `bpf_skb_set_tstamp` support) of the validated host.

---

## Self-Review (completed during authoring)

- **Spec coverage:** unify tcx (Task 6) ✓; EDT egress shaping (Tasks 2-4, 9) ✓; public police (Tasks 2-3) ✓; ingress police (Tasks 2, 5) ✓; MeterState three lanes (Task 1) ✓; InterfaceQoS API (Task 10) ✓; ConfigureQoS gRPC (Task 8) ✓; qosreconcile (Task 12) ✓; fq qdisc (Task 9) ✓; pure-core seam + sim tests (Tasks 2, 13) ✓; delete XDP guest_tx (Task 6) ✓; clab-can't-validate-shaping + same-node limitation (Task 15) ✓.
- **Type consistency:** field names (`total_bps`/`total_last_ns`/`ingress_*`), fn names (`edt_departure`/`edt_egress`/`public_pass`/`ingress_pass`/`edt_stamp`/`set_qos`/`meter_state`/`ensure_fq_qdisc`/`ConfigureQoS`/`ReconcileQoS`/`appliedQoS`) are consistent across tasks.
- **Placeholders:** the two `/* ... */` in Task 13 Step 2 are explicitly directed to reuse named existing helpers in the same file — the executing worker reads those helpers and fills them; no invented symbols.
- **Out of scope (spec Future Work):** Pkt-trait-v2 / DHCPv6-to-core and BBR are NOT in this plan.
