# Sim Seam Closure + Opportunistic Polish — Design

**Status:** Approved
**Date:** 2026-07-17
**Author:** control-plane/datapath hardening backlog (item #5 + Go/Rust polish)

## Summary

Two independent bodies of work, shipped together because they are both low-risk cleanups
with no datapath behavior change:

- **Part A — Sim seam closure (option B).** The encapsulated inner-payload length (`inner_len`)
  is computed independently by each glue path and passed into the pure-core header writer
  `write_outer_v6` as an input field. The tc path must *override* the value with `skb->len`
  because a non-linear skb's linear head under-counts it — an override that is load-bearing
  (it is the only site with `skb->len`) and that the in-process sim (linear-only `VecPkt`)
  cannot exercise. We give the `Pkt` trait a `logical_len()` method, move the single `inner_len`
  computation *into* `write_outer_v6` (`logical_len - ETH_LEN - IPV6_LEN`), remove `inner_len`
  from `EncapParams`, delete the tc override for real, and give the sim a settable logical
  length so a regression test drives the same core function and guards the bug class. The value
  written on the wire is byte-identical before and after.

- **Part B — Opportunistic polish.** Seven independent, mechanical cleanups in `netplane` (Go)
  and `xdp-dp` (Rust) that reduce footguns and duplication. No behavior change.

## Part A — Sim seam closure (option B, the real fix)

### Background: the seam, and why the first design was infeasible

The overlay encap path writes an outer IPv6 header whose payload length is `inner_len` — the
length of the encapsulated inner packet (the inner IP header + payload, i.e. frame length minus
the inner Ethernet header). `inner_len` is currently computed **independently by each glue
path** and passed into the pure-core header writer `write_outer_v6` as an `EncapParams.inner_len`
field:

- XDP paths compute `(data_end - data - ETH_LEN)` *before* growing headroom
  (`egress.rs:129,177`; `nat64.rs:564`; `ingress.rs:364,395,418`; `encap.rs` takes it as a param).
  XDP frames are linear, so this is correct.
- The tc path's `forward_decision_*` computes the same linear value, but the tc glue then
  **overrides** it (`tc.rs:137-138` v6, `:211-212` v4) with `ctx.len() - ETH_LEN` (skb->len),
  because on an skb `data_end - data` is only the *linear head* — a non-linear skb (e.g.
  busybox `wget`'s GET, whose payload sits in a paged frag) would otherwise get a short outer
  `payload_length` and be dropped as truncated. **This override is load-bearing, not a wart:
  it is the only site with access to `skb->len`.**
- The sim's `edge_encap` (`sim.rs:73`) computes it a *third* time, `inner_frame.len() - ETH_LEN`.

An earlier design proposed "compute `inner_len` in the pure core from a `Pkt::logical_len()` and
delete the glue override." Reading the code showed that premise is false: `forward_decision_*`
lives in the **ebpf** crate and reads eBPF global maps directly (`UNDERLAY`, `ROUTES6`, `LOCAL`),
so the sim cannot call it; and at `write_outer_v6` time on tc the `Pkt` is a `RawPkt` built from
raw linear pointers with no access to `skb->len`. So `inner_len` is genuinely an *input* to the
core, and deleting the override would reintroduce the truncation bug.

### The fix (option B): compute `inner_len` inside `write_outer_v6` from `logical_len()`

Move the single computation into the one pure-core function every encap path already calls,
and give that function the packet's logical length via the `Pkt` trait. `write_outer_v6` is
always called **after** the frame has been grown by `IPV6_LEN`, and the final layout is
`[outer_eth(ETH_LEN)][outer_ipv6(IPV6_LEN)][inner_ip…]`. So:

```
inner_len = logical_len - ETH_LEN - IPV6_LEN
```

This is *byte-identical* to every current computation: each existing value is
`(pre-grow frame_len - ETH_LEN)`, and `post-grow logical_len = pre-grow frame_len + IPV6_LEN`.

1. **`Pkt` trait — new method** (`xdp-dp-core/src/pkt.rs`):

   ```rust
   /// Logical (wire) length of the packet in bytes.
   ///
   /// On skb-backed contexts this is `skb->len`, which may exceed the linear head
   /// (`data_end - data`). On XDP and linear buffers it equals the head length.
   fn logical_len(&self) -> usize;
   ```

2. **Implementations:**
   - `CtxPkt` (XDP, `coreimpl.rs`) → `data_end - data` (XDP is always linear).
   - `RawPkt` (`coreimpl.rs`) gains a `logical_len: usize` field. `RawPkt::new(data, data_end)`
     sets it to `data_end - data` (unchanged for existing linear callers, e.g. firewall reads);
     a new `RawPkt::with_logical_len(data, data_end, logical_len)` sets it explicitly.
     `logical_len()` returns the field.
   - `VecPkt` (`xdp-dp-sim/src/pkt.rs`) gains a `logical_len: usize` field, defaulting to
     `buf.len()` in `from_bytes`, kept in sync by `grow_head`/`shrink_head` (±delta), plus a
     `with_logical_len(n)` / `set_logical_len(n)` setter for tests. `logical_len()` returns it.

3. **`write_outer_v6` computes `inner_len`** (`xdp-dp-core/src/encap.rs`): remove `inner_len`
   from `EncapParams`; inside `write_outer_v6` compute
   `let inner_len = pkt.logical_len().saturating_sub(ETH_LEN + IPV6_LEN) as u16;` and write it
   into the outer IPv6 `payload_length`. The write bounds check still uses `pkt.len()` (the
   linear head, ≥ 54 after the caller's `pull_data`), and the header writes only touch the
   first `ETH_LEN + IPV6_LEN` bytes, which are always in the linear head.

4. **Delete the tc override** (`tc.rs` v4 + v6 branches): remove both `e.inner_len = …` blocks
   and their comments. Build the encap `Pkt` as
   `RawPkt::with_logical_len(ctx.data(), ctx.data_end(), ctx.len() as usize)` **after**
   `adjust_room`/`pull_data` (post-grow `ctx.len()` is the correct logical length). The override
   is no longer needed — the core derives the same value from `logical_len()`, correctly for
   non-linear skbs.

5. **Drop the now-dead `inner_len` plumbing on the XDP paths:** remove the `inner_len` param
   from `write_encap_outer` / `encap_and_redirect` / `encap_and_redirect_via_devmap`
   (`encap.rs`) and the dead pre-grow computations at their call sites (`nat64.rs:564`,
   `ingress.rs:364,395,418`), and the `inner_len` field/computation in `forward_decision_v4/v6`
   (`egress.rs:129,140,177,188`). The XDP `Encap` executors (`egress.rs:266`, `v6.rs:124`) are
   unchanged apart from `EncapParams` no longer carrying the field.

6. **Sim uses the core computation** (`sim.rs:66` `edge_encap`): drop the `e.inner_len = …`
   line; `VecPkt.logical_len()` after `grow_head(IPV6_LEN)` gives the right value. Remove the
   `inner_len` field from every `EncapParams` literal (`sim.rs:193`, `lb_scenario_test.rs:83`,
   `ns_scenario_test.rs:35`, `encap_test.rs:9`).

7. **Regression test** (`xdp-dp-sim`, `encap_test.rs`): construct a grown `VecPkt` whose
   `logical_len > buf.len()` (a simulated non-linear skb: linear head holds the outer header,
   logical length is larger), call `write_outer_v6`, and assert the outer IPv6 `payload_length`
   equals `logical_len - ETH_LEN - IPV6_LEN`, **not** `buf.len() - ETH_LEN - IPV6_LEN`. This
   test fails against a `write_outer_v6` that reads `len()` and passes once it reads
   `logical_len()` — a permanent guard for the exact bug the tc override was patching.

8. **Verifier load-anchors** for the three tc classifiers that have none today —
   `tc_guest_tx` (`tc.rs:27`), `tc_guest_nat64` (`tc.rs:248`), `tc_guest_dhcp` (`tc.rs:265`).
   Follow the pattern in `xdp-dp/tests/verify_edge_wan_rx.rs:32`, but cast the loaded program
   to `SchedClassifier` instead of `Xdp`.

### Non-goals (Part A)

- No paged/non-linear buffer model in the sim. `VecPkt` stays a linear buffer with a settable
  logical length; the core's header writes only touch the linear head, so they never read a
  paged region — they only need the length.
- The hand-rolled NAT64 synth-encap path (`nat64.rs:887-922`) builds its outer header inline
  without `EncapParams`/`write_outer_v6` (`inner_len = 20 + l4_len`); it is a separate faithful
  path and is **out of scope** — untouched.
- No datapath behavior change. The on-wire `inner_len` is byte-identical before and after; this
  relocates *where* the value is computed (once, in core) and closes the sim-testability gap.

## Part B — Opportunistic polish

Each item is independently committable. No behavior change.

### Go (netplane)

1. **Rename `Reconciler` → `NATGatewayReconciler`** (`controllers/natgateway.go:30`). Every
   sibling reconciler is `<Kind>Reconciler`; the bare name is inconsistent.

2. **Config struct over setter injection** (`agent/reconcile.go:52,55,59`). Replace
   `SetUnderlay()` / `SetDataplane()` / `SetEdgeLoopback()` post-construction mutation with a
   dependencies struct supplied at construction. Removes the "forgot to call the setter" bug
   class.

3. **Consolidate the two dataplane fakes** — `fakeDP` (`agent/bus_test.go:19`) and
   `natRecordingDP` (`agent/reconcile_nat_test.go:15`) into a single recording fake in a shared
   test helper.

4. **Thread `ctx` into `applyPublic`** (`agent/public.go:65`). It currently takes no context
   but is called inside the bus loop that already has one; propagate for cancellation.

5. **Remove the `var _ = grpc.WaitForReady` hack** (`agent/bus.go:483`).

6. **Unify NatBlock / PublicRecord representations** — the near-duplicate record types at
   `agent/natreconcile.go:31`, `reflector/nattable.go:9`, `reflector/publictable.go:9` into
   shared types.

### Rust (xdp-dp)

7. **`DpErr` enum replacing `Result<_, ()>`** across 12 sites (`uplink.rs:35`,
   `encap.rs:51,72`, `nat64.rs:267,661,953`, `ingress.rs:101,320,345`, `v6.rs:93,141`,
   `egress.rs:193`). A small error enum in `xdp-dp-core` with **coarse semantic variants**
   (e.g. `Bounds`, `Parse`, `Unsupported`, `NoRoute`) — each site maps to whichever fits.
   Constraints: `no_std`-compatible (no `std::error::Error` impl), verifier-friendly (no
   panics, no allocation), `#[derive(Copy, Clone, PartialEq, Eq, Debug)]`.

### Non-goals (Part B)

- No functional/behavioral change to any control-plane or datapath path.
- No unrelated refactoring beyond the seven enumerated items.

## Testing strategy

- **Part A:** the new sim regression test (non-linear `VecPkt`, `logical_len > buf.len()`) is
  the load-bearing proof — it fails if `write_outer_v6` reads `len()` and passes once it reads
  `logical_len()`. The existing `xdp-dp-sim` encap/scenario tests and any `BPF_PROG_TEST_RUN`
  byte-parity anchors must remain green (they assert the on-wire bytes are unchanged — the
  substitution is byte-identical). The three verifier load-anchors gate that the tc classifiers
  still load into the kernel. Because the change removes an `EncapParams` field and function
  params, "compiles + verifier-loads + existing byte-parity tests green" is a strong signal.
- **Part B:** `go test ./...` in `netplane` and `cargo test` / verifier tests in `xdp-dp`.
  The DpErr change is compile-and-verifier-gated; the Go items are covered by existing unit
  and envtest suites.

## Risk

Low–moderate. Part A touches every encap caller (removing an `EncapParams` field + function
params), so the blast radius is wider than a localized change — but each edit is mechanical and
the substitution is byte-identical, so the existing byte-parity tests + verifier load gate it
tightly. The one correctness subtlety to respect: on tc, build the `RawPkt` with the **post-grow**
`ctx.len()` (after `adjust_room`/`pull_data`), since `write_outer_v6` subtracts
`ETH_LEN + IPV6_LEN`. Part B is mechanical; the DpErr change must not introduce anything that
trips the eBPF verifier (allocation, panics, non-`Copy` payloads) — the verifier anchors catch
this.
