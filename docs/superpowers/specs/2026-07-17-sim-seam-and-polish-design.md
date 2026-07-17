# Sim Seam Closure + Opportunistic Polish — Design

**Status:** Approved
**Date:** 2026-07-17
**Author:** control-plane/datapath hardening backlog (item #5 + Go/Rust polish)

## Summary

Two independent bodies of work, shipped together because they are both low-risk cleanups
with no datapath behavior change:

- **Part A — Sim seam closure.** The encapsulated inner-payload length (`inner_len`) is
  computed inside the pure core but then *overridden* by the tc glue, because the core reads
  the packet's linear head length while the skb path needs `skb->len`. This makes the core's
  own computation wrong-by-construction on the tc path (correct only because glue patches it),
  and makes the whole `linear_len != logical_len` bug class untestable in the in-process sim
  (which only models linear packets). We close the seam by giving the `Pkt` trait a
  `logical_len()` method, letting the core compute `inner_len` correctly for both XDP and tc,
  deleting the glue override, and giving the sim a settable logical length so a regression
  test can reproduce the divergence.

- **Part B — Opportunistic polish.** Seven independent, mechanical cleanups in `netplane` (Go)
  and `xdp-dp` (Rust) that reduce footguns and duplication. No behavior change.

## Part A — Sim seam closure

### Background: the seam

The overlay encap path writes an outer IPv6 header whose payload length derives from
`inner_len` — the length of the encapsulated inner packet (minus the guest Ethernet header).

- Core computation (`xdp-dp-ebpf/src/egress.rs:129` v4, `:177` v6):
  `let inner_len = (data_end - data - ETH_LEN) as u16;`
- tc glue override (`xdp-dp-ebpf/src/tc.rs:137-138` v6, `:211-212` v4):
  `e.inner_len = (ctx.len() as usize).saturating_sub(ETH_LEN) as u16;`

On XDP the two agree (XDP packets are linear, so `data_end - data == skb->len`), and the XDP
guest path does **not** override. On tc, `data_end - data` is only the *linear head*, while
`ctx.len()` (`skb->len`) is the true logical length — so the glue must patch the core's value.

The seam has two costs:
1. The core's `inner_len` is a lie on the tc path — correct only because glue overwrites it.
2. The sim (`xdp-dp-sim`, `VecPkt` — always linear, `logical_len == buf.len()`) can never
   reproduce a bug where the linear head is shorter than the logical length. That entire class
   of encap-length bugs is invisible to in-process testing.

### The fix

Give the packet the responsibility of reporting its own logical length — a property of the
packet, not an out-of-band parameter threaded through call signatures.

1. **`Pkt` trait — new method** (`xdp-dp-core/src/pkt.rs`):

   ```rust
   /// Logical (wire) length of the packet in bytes.
   ///
   /// On skb-backed contexts this is `skb->len`, which may exceed the linear head
   /// (`data_end - data`). On XDP and raw/linear contexts it equals the head length.
   fn logical_len(&self) -> usize;
   ```

2. **Implementations** (`xdp-dp-ebpf/src/coreimpl.rs`):
   - `CtxPkt<XdpContext>` → `data_end - data` (XDP is always linear).
   - `CtxPkt<TcContext>` → `self.ctx.len()` (skb->len — the true logical length).
   - `RawPkt` → `data_end - data` (raw/linear path).

3. **Core uses it** (`xdp-dp-ebpf/src/egress.rs:129` and `:177`):
   `let inner_len = (pkt.logical_len().saturating_sub(ETH_LEN)) as u16;`

4. **Delete the glue override** (`xdp-dp-ebpf/src/tc.rs:137-138` and `:211-212`): remove the
   `e.inner_len = ...` assignments. The core now computes the correct value for both paths, so
   the override is dead code.

5. **Sim models it** (`xdp-dp-sim/src/pkt.rs`): `VecPkt` gains a `logical_len: usize` field,
   defaulting to `buf.len()` in every constructor, plus a `with_logical_len(n)` builder for
   tests. `logical_len()` returns the field.

6. **Regression test** (`xdp-dp-sim` tests): construct a `VecPkt` where
   `logical_len > buf.len()`, run the v4 and v6 encap decision, and assert the outer header's
   payload-length reflects `logical_len - ETH_LEN`, not `buf.len() - ETH_LEN`. This test fails
   against the pre-change core (which reads the linear length) and passes after — proving the
   seam is closed and stays closed.

7. **Verifier load-anchors** for the three tc classifiers that have none today —
   `tc_guest_tx` (`tc.rs:27`), `tc_guest_nat64` (`tc.rs:248`), `tc_guest_dhcp` (`tc.rs:265`).
   Follow the pattern in `xdp-dp/tests/verify_edge_wan_rx.rs:32`, but cast the loaded program
   to `SchedClassifier` instead of `Xdp`.

### Non-goals (Part A)

- No paged/non-linear buffer model in the sim. `VecPkt` stays a linear buffer with a settable
  logical length; our core reads never touch a paged region, they only need the length.
- No datapath behavior change. The on-wire `inner_len` is identical before and after — this is
  a refactor that relocates *where* the correct value is computed (core, not glue).

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

- **Part A:** the new sim regression test is the load-bearing proof (fails before, passes
  after). The three verifier anchors gate that the tc classifiers still load into the kernel.
  Existing `BPF_PROG_TEST_RUN` byte-parity anchors must remain green (they assert the on-wire
  bytes are unchanged).
- **Part B:** `go test ./...` in `netplane` and `cargo test` / verifier tests in `xdp-dp`.
  The DpErr change is compile-and-verifier-gated; the Go items are covered by existing unit
  and envtest suites.

## Risk

Low. Part A is a refactor with a regression test proving on-wire equivalence. Part B is
mechanical. The one thing to watch: the DpErr change must not introduce anything that trips
the eBPF verifier (allocation, panics, non-`Copy` payloads) — the verifier anchors catch this.
