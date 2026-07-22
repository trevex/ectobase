# nfkit Milestone 10 — rte_flow: net_tap functional testing + conditional mlx5 offload

**Date:** 2026-07-21
**Status:** Design — approved in brainstorming (direction + Task-2 scope), pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M2 (`Backend::Tap` net_tap vdev, `Port`, `Eal`), M7 (privileged self-restoring hugepage/sudo harness). Branch `design/flowplane-dpdk`.
**User direction:** see memory `rte-flow-tap-testing-and-mlx5-probe`.

## 1. Goal & why

Bring `rte_flow` into the DPDK backend — the headline reason-to-exist (offload the IP-in-IPv6 hot path into the NIC eSwitch) — in a way that is **testable without a smartNIC** and **never programs offloads the hardware can't do**:
1. **Functionally test rte_flow rule programming** on the DPDK **net_tap** PMD, which lowers `rte_flow` rules to Linux **tc-flower/eBPF** filters — so match/action rule programming is exercised on a laptop.
2. **Conditionally enable `RAW_DECAP`/`RAW_ENCAP`** (the mlx5 outer-IPv6 decap/encap offload) only when a runtime probe confirms the NIC supports it (`rte_flow_validate` succeeds on an mlx5 driver); otherwise fall back to the software datapath. The probe→validate→create-or-fallback code path is built + tested here; the actual offload needs real ConnectX (deferred), but nothing is programmed unconditionally.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Binding | Add `#include <rte_flow.h>` to `dpdk-sys/wrapper.h` (bindgen allowlist `rte_.*` already covers `rte_flow_*`) |
| Safe wrapper | `nfkit::flow` — RAII `FlowRule` (destroys on drop) + `validate`/`create`; typed builders for a 5-tuple match→action rule and the RAW_DECAP/ENCAP rules |
| net_tap proof (Task 2) | **validate + create succeeds AND the lowered tc-flower filter is observed** via `tc filter show dev <tap>` (privileged, deterministic — no live packet I/O) |
| mlx5 gate | `probe_raw_flow_offload(port)` = driver name contains `mlx5` **AND** `rte_flow_validate` of the RAW rule succeeds → enable; else **software fallback** |
| Fallback test | On this host (net_tap/pcap/null — non-mlx5) the probe returns `false` → assert the software path is selected; no offload programmed |
| Safety | FFI/unsafe wrapper follows the existing `dpdk-sys` wrapper patterns (`DpdkHash`) with explicit `// SAFETY:` on every `unsafe` (see unsafe-checker discipline) |

## 3. Components

```
flowplane/dpdk-sys/wrapper.h        += #include <rte_flow.h>   (exposes rte_flow_* bindings)
flowplane/nfkit/src/flow.rs         new: FlowRule RAII + validate/create + rule builders + probe
flowplane/nfkit/src/lib.rs          re-export flow API
flowplane/nfkit/tests/flow_binding.rs      new (unpriv): symbols bind; validate returns a sane errno
flowplane/nfkit/tests/flow_mlx5_probe.rs   new (unpriv): probe=false on non-mlx5 → fallback selected
flowplane/nfkit/tests/flow_nettap.rs       new (PRIV): program a rule on net_tap, observe the tc filter
hack/dpdk/nettap-flow.sh            new: privileged net_tap harness (self-restoring hugepages + tc show)
```

### 3.1 `nfkit::flow` (safe wrapper)

- `struct FlowRule { port: u16, ptr: *mut rte_flow }` — RAII; `Drop` calls `rte_flow_destroy(port, ptr, &mut err)`. `!Send`.
- `fn validate(port, attr, pattern, actions) -> Result<(), FlowError>` → `rte_flow_validate`; `FlowError` carries `rte_flow_error.type` + errno (like `HashError`).
- `fn create(port, attr, pattern, actions) -> Result<FlowRule, FlowError>` → `rte_flow_create` (non-null or Err).
- **Rule builders** (construct the END-terminated `rte_flow_item[]` / `rte_flow_action[]` + `rte_flow_attr`):
  - `match5_action(...)` — pattern `[ETH, IPV4{spec,mask}, TCP{spec,mask}, END]`, action `[DROP | QUEUE{index}, END]` (net_tap-supported).
  - `raw_decap_rule(...)` / `raw_encap_rule(...)` — `rte_flow_action_raw_decap`/`raw_encap` with the outer-IPv6 header bytes (mlx5-only; used by the probe's `validate`).
- `fn probe_raw_flow_offload(port) -> bool` — `rte_eth_dev_info_get(port).driver_name` contains `mlx5` AND `validate(raw_decap_rule)`/`validate(raw_encap_rule)` both `Ok`. Logs the decision.
- The spec/masks live on the caller stack for the duration of the validate/create call (rte_flow copies them) — mirror the `WorkerArg` stack-lifetime discipline.

### 3.2 net_tap functional test (Task 2, privileged)

`hack/dpdk/nettap-flow.sh` (reuses the M7 self-restoring hugepage + trap pattern; root): runs a tiny nfkit example/bin that inits EAL with `Backend::Tap{name}`, brings the tap up, `create`s a `match5_action` DROP rule, then the harness runs `tc filter show dev <tap> ingress` (or `parent ffff:`) and asserts a `flower` filter with the matched keys is present. `flow_nettap.rs` drives it, **auto-skips (exit 77) unprivileged** (so `cargo test` stays green), and I run the privileged pass under `sudo`, confirming `nr_hugepages` restored. If net_tap's flow→tc lowering is unavailable on this kernel/DPDK build, the harness skips (77) with a clear message rather than failing.

### 3.3 mlx5 probe + fallback (Task 3, unprivileged)

`flow_mlx5_probe.rs`: init EAL with a non-mlx5 backend (pcap/null), assert `probe_raw_flow_offload(0) == false` (driver isn't mlx5 and/or RAW validate unsupported), and assert the datapath selects the **software path** (a small `enum OffloadMode { HwRawFlow, Software }` chosen by the probe → `Software` here). Proves the conditional gate + graceful fallback without hardware.

## 4. Definition of Done

- `dpdk-sys` rebuilds with `rte_flow_*` bindings; `cargo test -p nfkit -- --test-threads=1` green (all M3–M9 anchors + `flow_binding` + `flow_mlx5_probe`); `flow_nettap` auto-skips unprivileged.
- Under `sudo`, `flow_nettap` programs a net_tap rule and the lowered **tc-flower filter is observed**; `nr_hugepages` restored to 0.
- `probe_raw_flow_offload` returns `false` on non-mlx5 → software fallback selected (no offload programmed); the RAW_DECAP/ENCAP builders exist + validate-gated for real mlx5.
- Safe `flow` wrapper with RAII + explicit SAFETY comments; no `flowplane-core`/eBPF change (M10 is nfkit + dpdk-sys only).
- Default host build untouched.

## 5. Phasing (for the plan)

1. **Binding + `flow` wrapper** — `wrapper.h` include, `FlowRule`/`validate`/`create`, `match5_action` + `raw_decap/encap` builders, `flow_binding.rs` smoke.
2. **mlx5 probe + fallback** — `probe_raw_flow_offload` + `OffloadMode`, `flow_mlx5_probe.rs` (unpriv, non-mlx5 → Software).
3. **net_tap functional test** — `hack/dpdk/nettap-flow.sh` + `flow_nettap.rs` (privileged; program rule + observe tc filter); I run the privileged pass + confirm hugepage reset.

## 6. Risks / open questions

- **rte_flow FFI is fiddly** — END-terminated item/action arrays, `spec`/`mask`/`last` `*const c_void` per item, union access on `rte_flow_item`/`rte_flow_action`. Build from the GENERATED bindings' exact struct layouts; keep spec/mask on the stack across the call; RAII-destroy the rule. Highest-care task — follow unsafe-checker discipline.
- **net_tap flow→tc support** — the net_tap PMD implements a subset of rte_flow via tc-flower over netlink; requires kernel `cls_flower`/`act_gact` + root. If the DPDK build's net_tap lacks flow ops or the kernel lacks the modules, `create`/`validate` returns ENOTSUP → the harness SKIPS (77) with a clear message (do not hard-fail). Verify live under sudo (like M7 af_xdp), don't assume.
- **`net_tap` PMD compiled in?** — `Backend::Tap` exists in code (M2) but a live tap run may never have been exercised; confirm the `librte_net_tap` PMD is present at runtime (probe during Task 3/2). If absent, Task 2 skips and Task 3 uses `Backend::Pcap`/`Null` for the non-mlx5 probe.
- **tc filter assertion** — the exact `tc filter show dev <tap> ingress`/`parent ffff:` output format for a flower filter; grep for `flower` + a matched key (e.g. the dst_ip/dport). Tolerate driver-named tap (`dtap0` etc.) — get the real iface name from the vdev.
- **Probe correctness on mlx5** — the driver-name check must match mlx5's real `driver_name` (`mlx5_pci` / `net_mlx5`); use a substring `mlx5`. The decisive gate is `rte_flow_validate` succeeding, not the name alone — validate is the source of truth.
- **No unconditional offload** — `create` of RAW_DECAP/ENCAP is ONLY reached when `probe_raw_flow_offload` is true; the software path is the default. Assert this in the fallback test.
