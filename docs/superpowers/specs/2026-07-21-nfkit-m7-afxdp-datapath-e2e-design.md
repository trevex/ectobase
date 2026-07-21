# nfkit Milestone 7 — af_xdp datapath e2e + self-restoring hugepage harness

**Date:** 2026-07-21
**Status:** Design — approved in brainstorming, pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M2 (`Backend::AfXdp`, `afxdp-loopback.sh` l2fwd harness), M3 (`uplink_fwd` example + `datapath_pcap` net_pcap e2e). Branch `design/flowplane-dpdk`.

## 1. Goal & why

Prove the shared `process_uplink` datapath survives a **real af_xdp rx/tx path** — the closest thing to a hardware NIC available without a smartNIC — and establish a **reusable hugepage-managed test harness** that reserves hugepages and **restores the original `vm.nr_hugepages` on exit**. `datapath_pcap` (M3) already proves the datapath through the file-based `net_pcap` PMD; this proves it through the af_xdp PMD's real descriptor rings + mbuf lifecycle under a kernel-driven `AF_XDP` socket. First of three "hugepage-testable, no-smartNIC" milestones (M8 = multi-lcore per-lcore state; M9 = software EDT calendar + non-None EDT parity).

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Runner | **Reuse the existing `uplink_fwd` example** (already supports `Backend::AfXdp` + bakes the M3 Task-6 `DpdkMaps` decap config) — no example changes |
| Hugepage lifecycle | **Harness reserves + restores** `vm.nr_hugepages` via a bash `trap ... EXIT` (captures the original, sets 1024, restores on ANY exit — panic/skip/failure safe) |
| Gating | Gated test **auto-skips (exit 77)** when not root / hugepages not reservable → `cargo test` stays green unprivileged; the real assertion runs under `sudo` |
| Assertion | **Byte-parity vs sim** — scapy injects the encapped fixture + captures the output to a pcap; Rust compares it to `process_uplink` over the same frame+config (reuse the `datapath_pcap` comparison) — a true parity check, not a smoke test |
| Cleanup | veth pair removed on exit (trap); `nr_hugepages` restored to its captured value (0 on this host) |

## 3. Components

```
hack/dpdk/afxdp-uplink.sh          new: reserve+restore hugepages (trap) + veth + run uplink_fwd(afxdp)
                                    + scapy inject encapped fixture on the peer + capture output → pcap
flowplane/nfkit/tests/afxdp_datapath.rs   gated test: compute sim-expected, run the script (skip if
                                          unprivileged/no hugepages), compare captured frame == sim
Makefile / hack                    optional: `make dpdk-afxdp-datapath` convenience target
```

### 3.1 The harness `hack/dpdk/afxdp-uplink.sh` (the reusable pattern)

Modeled on `afxdp-loopback.sh`, but (a) runs `uplink_fwd` not l2fwd, (b) **manages hugepages itself**:
```sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "SKIP: not root"; exit 77; }
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"
restore() { sysctl -qw vm.nr_hugepages="$ORIG_HP" || true; ip link del "$VV0" 2>/dev/null || true; }
trap restore EXIT
sysctl -qw vm.nr_hugepages=1024
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || { echo "SKIP: hugepages not reservable"; exit 77; }
# veth up; run uplink_fwd afxdp vv0 (background); scapy: send $IN_FRAME on vv1, sniff 1 frame → wrpcap $OUT_PCAP; kill.
```
The captured output frame is written to `$OUT_PCAP`; the Rust test does the byte comparison (keeps the sim dependency in Rust). `$IN_FRAME`/`$OUT_PCAP`/`$UPLINK_BIN` passed via env.

### 3.2 The gated test `afxdp_datapath.rs`

Mirrors `afxdp_loopback.rs`: build/locate the `uplink_fwd` binary; build the encapped input frame + compute the expected decapped output via `process_uplink` over `VecPkt`+`MemMaps` with the **same config `uplink_fwd` bakes** (reuse `datapath_pcap.rs`'s fixture + comparison helpers). Write the input frame to a temp pcap/bin, run `afxdp-uplink.sh` (via `sudo` or already-root); on exit 77 → `eprintln!` skip + return (test green); on 0 → read `$OUT_PCAP`, assert the captured frame == the sim-expected bytes; on other → fail. `--test-threads=1`.

## 4. Execution (this milestone actually runs privileged)

1. Build + the gated test **auto-skips** unprivileged → `cargo test -p nfkit` stays green here.
2. **Privileged pass:** run the harness under `sudo` (it reserves hugepages → runs the af_xdp loopback → restores `nr_hugepages`). Confirm the datapath output == sim (af_xdp parity).
3. **Confirm reset:** assert `cat /proc/sys/vm/nr_hugepages` is back to `0` after the run (the trap guarantees it even on failure).
4. If `sudo` needs the user's hand in-session, hand them the exact `! sudo …` line.

## 5. Definition of Done

- `afxdp_datapath` passes under `sudo` — the af_xdp-transported decapped frame is **byte-identical** to `process_uplink`'s sim output; auto-skips cleanly unprivileged (`cargo test -p nfkit` green in this session/CI).
- **`vm.nr_hugepages` is restored to its original value (0)** after the run — verified; the harness trap makes this panic/skip/failure-safe.
- The reusable hugepage-reserve/restore harness pattern is in place for M8/M9.
- Default host build + existing tests untouched; no example changes (uplink_fwd reused as-is).

## 6. Phasing (for the plan)

1. Write `hack/dpdk/afxdp-uplink.sh` (hugepage reserve/restore trap + veth + uplink_fwd(afxdp) + scapy inject/capture→pcap).
2. Write `afxdp_datapath.rs` gated test (compute sim-expected, run script, skip-or-compare). Confirm it SKIPS cleanly unprivileged (`cargo test` green).
3. Privileged run (main session): `sudo` the harness, confirm parity pass, confirm `nr_hugepages` reset to 0. `make dpdk-afxdp-datapath` convenience target + `docs/dpdk-dev.md` note.

## 7. Risks / open questions

- **Hugepage restore robustness** — the `trap ... EXIT` must fire on every path (SIGINT, script error, scapy timeout). Test the restore by checking `nr_hugepages == ORIG_HP` after both a passing and a forced-failing run.
- **af_xdp on veth = copy mode, single queue** — fine for a functional datapath e2e (not a perf test); zero-copy/multi-queue is the smartNIC/perf phase.
- **sudo in the nix devShell** — the real setuid sudo is `/run/wrappers/bin/sudo` (the NixOS PATH gotcha); the harness + any in-session invocation must use it and preserve the nix `PATH`/`LD_LIBRARY_PATH` so the DPDK-linked binary + scapy resolve. Pass the built binary's absolute path via env.
- **Config drift** — the injected frame + expected output must use the exact `DpdkMaps` config `uplink_fwd` bakes (same source of truth `datapath_pcap` already relies on); reuse that fixture so pcap and af_xdp assert against the same sim output.
- **Frame delivery timing** — scapy sniffer must start before the inject (AsyncSniffer + a short settle), as in `afxdp-loopback.sh`; single frame, generous timeout.
