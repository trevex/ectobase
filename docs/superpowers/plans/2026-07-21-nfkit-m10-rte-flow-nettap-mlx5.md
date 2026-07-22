# nfkit M10 — rte_flow net_tap testing + conditional mlx5 offload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The `flow` wrapper is FFI/unsafe-heavy — REQUIRED SUB-SKILL: unsafe-checker discipline (explicit `// SAFETY:` on every `unsafe`, spec/mask lifetimes, RAII destroy).

**Goal:** Bring `rte_flow` into nfkit — functionally test rule programming on the net_tap PMD (lowers to tc-flower), and conditionally enable mlx5 RAW_DECAP/ENCAP via a runtime probe with software fallback. nfkit + dpdk-sys only; no `flowplane-core`/eBPF change.

**Architecture:** (1) `#include <rte_flow.h>` in `dpdk-sys/wrapper.h` → `rte_flow_*` bindings. (2) `nfkit::flow` safe wrapper (RAII `FlowRule`, `validate`/`create`, rule builders, `probe_raw_flow_offload`). (3) net_tap privileged test programs a rule + observes the tc filter. (4) mlx5 probe returns false on non-mlx5 → software fallback (unprivileged test).

**Tech Stack:** Rust FFI over DPDK 25.11.2 `rte_flow`; `nfkit` (M2 `Backend::Tap`/`Eal`/`Port`), M7 privileged harness pattern. Tests inside `nix develop`.

**Context (grounded — I read these):**
- DPDK 25.11.2, static, built by `dpdk-sys/build.rs` with `DRIVERS="net/null,net/pcap,net/tap,net/af_xdp"` — **net/tap IS compiled in**. `rte_flow.h` is in the install `include/`; adding it to `wrapper.h` re-runs bindgen only (fast). bindgen allowlist already `rte_.*`/`RTE_.*`; `derive_default`/`derive_debug` are DISABLED globally → zero-init FFI structs via `std::mem::zeroed()` and set fields; bitfields (e.g. `rte_flow_attr.ingress`) get bindgen `set_ingress(1)` setters.
- `Backend::Tap { name }` (`nfkit/src/backend.rs`) emits `--vdev net_tap<...>,iface=<name>`; `Backend::Pcap`/`Null` too. `Eal::init([...])`, `Port::configure(id, nq, &pool)`. The M7 harness `hack/dpdk/afxdp-uplink.sh` is the template for the privileged self-restoring-hugepage + trap + tc pattern.
- `DpdkHash` (`nfkit/src/dpdk_hash.rs`) is the reference for the safe-wrapper-over-DPDK pattern (errno via `rte_errno`, RAII `Drop`, `!Send`, SAFETY comments).
- rte_flow API (verify exact layouts in the GENERATED bindings — `target/debug/build/dpdk-sys-*/out/bindings.rs`): `rte_flow_validate(port, *const rte_flow_attr, *const rte_flow_item, *const rte_flow_action, *mut rte_flow_error) -> i32` (0=ok); `rte_flow_create(...) -> *mut rte_flow`; `rte_flow_destroy(port, *mut rte_flow, *mut rte_flow_error) -> i32`. `rte_flow_item { type_, spec, last, mask }` END-terminated (`RTE_FLOW_ITEM_TYPE_END`); `rte_flow_action { type_, conf }` END-terminated (`RTE_FLOW_ACTION_TYPE_END`). Items: `RTE_FLOW_ITEM_TYPE_{ETH,IPV4,TCP,END}`; actions: `RTE_FLOW_ACTION_TYPE_{DROP,QUEUE,RAW_DECAP,RAW_ENCAP,END}`. `rte_flow_error { type_, cause, message }` (message is a human-readable `*const c_char` — log it when validate/create fails).

**Absolute rules:**
- Cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root. rustfmt hook active (fallback `rustfmt --edition 2021 <files>`).
- Every `unsafe` block gets a `// SAFETY:` comment. Spec/mask structs MUST outlive the `validate`/`create` call (keep on the caller stack; rte_flow copies them).
- No `flowplane-core`/eBPF edits. Run FULL `cargo test -p nfkit -- --test-threads=1` before final commits.

---

## File Structure
- `flowplane/dpdk-sys/wrapper.h` — `+ #include <rte_flow.h>`.
- `flowplane/nfkit/src/flow.rs` — new (`FlowRule`, `validate`, `create`, builders, `probe_raw_flow_offload`, `OffloadMode`).
- `flowplane/nfkit/src/lib.rs` — re-export.
- `flowplane/nfkit/tests/flow_binding.rs` — new (unpriv smoke).
- `flowplane/nfkit/tests/flow_mlx5_probe.rs` — new (unpriv fallback).
- `flowplane/nfkit/tests/flow_nettap.rs` + `hack/dpdk/nettap-flow.sh` — new (privileged).

---

## Task 1: rte_flow binding + safe `flow` wrapper

**Files:** `dpdk-sys/wrapper.h`, `nfkit/src/flow.rs`, `nfkit/src/lib.rs`, `nfkit/tests/flow_binding.rs`.

- [ ] **Step 1: Add the binding** — append `#include <rte_flow.h>` to `flowplane/dpdk-sys/wrapper.h` (after `rte_ethdev.h`). `cargo build -p dpdk-sys` → succeeds; confirm `rte_flow_validate`/`rte_flow_create` appear in the generated `bindings.rs` (`grep -c rte_flow_create target/debug/build/dpdk-sys-*/out/bindings.rs`).

- [ ] **Step 2: Inspect the generated layouts** — read the `rte_flow_attr`, `rte_flow_item`, `rte_flow_action`, `rte_flow_action_queue`, `rte_flow_action_raw_decap`, `rte_flow_action_raw_encap`, `rte_flow_error`, `rte_flow_item_type`, `rte_flow_action_type` definitions in the generated `bindings.rs`. Note the exact field names (`type_` vs `type`), bitfield setters, and the item/action union/struct shapes.

- [ ] **Step 3: Write `flowplane/nfkit/src/flow.rs`** — safe wrapper (model on `DpdkHash`):
```rust
//! Safe rte_flow wrapper: validate/create/destroy flow rules + a runtime probe for mlx5 RAW
//! decap/encap offload. Rules are END-terminated item/action arrays built on the caller stack
//! (rte_flow copies spec/mask during validate/create). See M10 design.
use dpdk_sys as ffi;
use std::os::raw::c_void;

#[derive(Debug)]
pub struct FlowError { pub etype: u32, pub errno: i32, pub message: String }
// Read rte_flow_error.message (may be null) into a String for diagnostics.

/// RAII flow rule — destroyed on drop. !Send (bound to the port's lcore).
pub struct FlowRule { port: u16, ptr: *mut ffi::rte_flow }
impl Drop for FlowRule {
    fn drop(&mut self) {
        let mut err: ffi::rte_flow_error = unsafe { std::mem::zeroed() };
        // SAFETY: self.ptr is a live rule from rte_flow_create on self.port; destroy is idempotent-safe.
        unsafe { ffi::rte_flow_destroy(self.port, self.ptr, &mut err); }
    }
}

/// Validate a rule (does not program it). Ok = the PMD accepts it.
pub fn validate(port: u16, attr: &ffi::rte_flow_attr,
                pattern: &[ffi::rte_flow_item], actions: &[ffi::rte_flow_action]) -> Result<(), FlowError> { /* rte_flow_validate; map rc!=0 → Err(read error) */ }

/// Create (program) a rule. Returns a RAII handle.
pub fn create(port: u16, attr: &ffi::rte_flow_attr,
              pattern: &[ffi::rte_flow_item], actions: &[ffi::rte_flow_action]) -> Result<FlowRule, FlowError> { /* rte_flow_create; null → Err */ }
```
Plus builders + probe:
```rust
/// Ingress attr (group 0, priority 0, ingress=1) — zeroed then set_ingress(1).
pub fn ingress_attr() -> ffi::rte_flow_attr;

/// Pattern [ETH, IPV4{dst}, TCP{dport}, END] + action [DROP, END]. Spec/mask structs are returned
/// in an owning holder so they outlive validate/create (caller keeps it on the stack).
pub struct Match5Drop { /* owns ipv4 spec/mask (rte_flow_item_ipv4), tcp spec/mask, items[], actions[] */ }
impl Match5Drop { pub fn new(dst_ip: [u8;4], dst_port: u16) -> Self; pub fn items(&self)->&[ffi::rte_flow_item]; pub fn actions(&self)->&[ffi::rte_flow_action]; }

/// RAW_DECAP (strip `len` outer bytes) / RAW_ENCAP (push `data`) actions — mlx5-only; used by the probe.
pub struct RawDecap { /* rte_flow_action_raw_decap{ data, size } + actions[] */ }
pub struct RawEncap { /* rte_flow_action_raw_encap{ data, preserve, size } + actions[] */ }

#[derive(Debug, PartialEq, Eq)] pub enum OffloadMode { HwRawFlow, Software }

/// True only if the port's driver is mlx5 AND rte_flow_validate accepts RAW_DECAP+RAW_ENCAP.
/// Decisive gate = validate succeeding (never the name alone). Logs the decision.
pub fn probe_raw_flow_offload(port: u16) -> bool {
    // rte_eth_dev_info_get(port) → driver_name contains "mlx5"; then validate(ingress_attr, eth+ipv6 pattern, raw_decap) and (…, raw_encap). Any failure → false.
}
/// The datapath's offload decision for a port: HwRawFlow iff probe true, else Software.
pub fn offload_mode(port: u16) -> OffloadMode { if probe_raw_flow_offload(port) { OffloadMode::HwRawFlow } else { OffloadMode::Software } }
```
Implement carefully from the generated layouts. Keep spec/mask owned by the `Match5Drop`/`RawDecap` holders (returned by value; caller binds to a `let` so it lives across the call). `lib.rs`: `mod flow; pub use flow::{FlowRule, FlowError, OffloadMode, offload_mode, probe_raw_flow_offload, validate as flow_validate, create as flow_create, Match5Drop};`.

- [ ] **Step 4: `flow_binding.rs` smoke (unpriv)** — init EAL with `Backend::Null` (or Pcap), `Port::configure(0,1,&pool)`, build a `Match5Drop`, call `flow::validate(0, ...)`. NULL/pcap PMDs have no flow support → expect `Err(FlowError)` (ENOTSUP) — assert it returns an Err WITHOUT panicking (proves the binding + error path + struct construction are sound). Also assert `offload_mode(0) == Software` (null isn't mlx5). Run `cargo test -p nfkit --test flow_binding -- --test-threads=1 --nocapture`.

- [ ] **Step 5: build + clippy + fmt + commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/dpdk-sys/wrapper.h flowplane/nfkit/src/flow.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/flow_binding.rs
git commit -m "feat(nfkit): rte_flow binding + safe flow wrapper (FlowRule RAII, validate/create, mlx5 probe)"
```

---

## Task 2: mlx5 probe + software fallback (unprivileged)

**Files:** `flowplane/nfkit/tests/flow_mlx5_probe.rs`.

- [ ] **Step 1: Write the fallback test** — init EAL with a non-mlx5 backend (`Backend::Pcap` or `Null`), `Port::configure`. Assert `probe_raw_flow_offload(0) == false` (driver isn't mlx5 and/or RAW validate unsupported) and `offload_mode(0) == OffloadMode::Software`. This proves the conditional gate + graceful fallback on hardware that can't offload — nothing is programmed. (Document: on a real mlx5 NIC the same call returns `HwRawFlow` and the offload path programs RAW_DECAP/ENCAP.)
- [ ] **Step 2: Run → PASS**, clippy + fmt clean. Commit:
```bash
git add flowplane/nfkit/tests/flow_mlx5_probe.rs
git commit -m "test(nfkit): mlx5 rte_flow offload probe → software fallback on non-mlx5 (no unconditional offload)"
```

---

## Task 3: net_tap functional rte_flow test (PRIVILEGED — main assistant drives the sudo run)

**Files:** `hack/dpdk/nettap-flow.sh`, `flowplane/nfkit/tests/flow_nettap.rs`. A small example bin may be needed to program the rule from inside the EAL process.

- [ ] **Step 1: A rule-programming entrypoint** — add an example `flowplane/nfkit/examples/nettap_flow.rs` (or extend an existing one): args `tap <iface>`; inits EAL `Backend::Tap{name}`, `Port::configure(0,1,&pool)`, brings port up, `flow::create(0, ingress_attr, Match5Drop::new(dst_ip, dport))`, prints `RULE OK` (or the rte_flow_error.message on failure), then sleeps briefly so the harness can inspect tc. On `create` ENOTSUP, print `FLOW UNSUPPORTED` and exit 77.
- [ ] **Step 2: `hack/dpdk/nettap-flow.sh`** — model on `hack/dpdk/afxdp-uplink.sh`: root-gate (exit 77), capture+restore `nr_hugepages` in a `trap` (reserve 1024; the M7 self-restoring pattern), run the example (output → logfile, **killed in the trap** — the M7 pipe-hang lesson), discover the real tap iface name (net_tap names it e.g. `dtap0`/the `iface=` value), then `tc filter show dev <iface> ingress` (or `parent ffff:`) and assert a `flower` filter matching the dst ip/port is present → exit 0; if the app printed `FLOW UNSUPPORTED` or no flower filter appears due to missing kernel cls_flower, exit 77 (skip) with a clear message. Kill app + restore hugepages + delete tap in the trap.
- [ ] **Step 3: `flow_nettap.rs`** — gated test (like `afxdp_datapath.rs`): build the example, run the script, match exit 0/77/other; auto-skips unprivileged.
- [ ] **Step 4 (MAIN ASSISTANT):** run the privileged pass under `sudo -E` (nix env preserved) like M7; confirm the tc-flower filter is observed + `nr_hugepages` restored to 0. If net_tap's flow→tc lowering isn't available on this kernel/build, accept the 77 skip and document it (the wrapper + validate path is still proven by Tasks 1–2). Commit:
```bash
git add hack/dpdk/nettap-flow.sh flowplane/nfkit/tests/flow_nettap.rs flowplane/nfkit/examples/nettap_flow.rs
git commit -m "test(nfkit): gated net_tap rte_flow e2e — program rule + observe tc-flower filter (self-restoring hugepages)"
```

---

## Definition of Done (M10)
- `dpdk-sys` rebuilds with `rte_flow_*` bindings; `cargo test -p nfkit -- --test-threads=1` green (all M3–M9 + `flow_binding` + `flow_mlx5_probe`); `flow_nettap` auto-skips unprivileged.
- Under `sudo`, `flow_nettap` programs a net_tap rule and the tc-flower filter is observed (or a documented 77-skip if the kernel/build lacks net_tap flow→tc); `nr_hugepages` restored to 0.
- `probe_raw_flow_offload` returns `false` on non-mlx5 → `Software` fallback (no offload programmed); RAW_DECAP/ENCAP builders exist + are validate-gated.
- Safe `flow` wrapper with RAII + `// SAFETY:` on every `unsafe`; nfkit + dpdk-sys only.
- Default host build untouched.

## Risks / notes
- **FFI layout drift** — build strictly from the generated `bindings.rs` (field names, bitfield setters, union access). Spec/mask MUST outlive validate/create (owned by the builder holder, bound to a `let`).
- **net_tap flow support** — subset via tc-flower over netlink; needs root + kernel `cls_flower`. If `create`/`validate` returns ENOTSUP, SKIP (77) — do not hard-fail; verify live under sudo (don't assume). Tasks 1–2 still prove the wrapper + gate.
- **tc output format** — grep `tc filter show dev <iface> ingress` (and `parent ffff:`) for `flower` + a matched key; get the iface from the `iface=` vdev arg.
- **Privileged-run hygiene (M7 lessons)** — app output to a logfile (never the captured pipe); kill the app IN the trap; restore `nr_hugepages`; pre-build unprivileged then `sudo -E env PATH=.. LD_LIBRARY_PATH=..` the test/example (no root-owned `target/`).
- **No unconditional offload** — RAW create is reached ONLY when `probe_raw_flow_offload` is true; `flow_mlx5_probe` asserts the default is `Software`.
