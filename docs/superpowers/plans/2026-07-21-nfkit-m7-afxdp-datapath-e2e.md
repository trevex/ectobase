# nfkit M7 — af_xdp datapath e2e + self-restoring hugepage harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove `process_uplink` runs byte-identically through a REAL af_xdp rx/tx path (veth loopback), via a harness that reserves hugepages and restores `vm.nr_hugepages` on exit.

**Architecture:** Reuse the `uplink_fwd` example (already supports `Backend::AfXdp` + bakes the decap `DpdkMaps` config). New `hack/dpdk/afxdp-uplink.sh` manages hugepages (trap-restore) + veth + scapy inject/capture. New gated `afxdp_datapath.rs` reuses `datapath_pcap.rs`'s fixture + sim-expected computation, swapping the pcap run for the af_xdp harness run; auto-skips unprivileged.

**Tech Stack:** bash, scapy (in the nix devShell), Rust test harness, DPDK af_xdp PMD (built since M2). Privileged run needs root + hugepages.

**Context (grounded — I read these):**
- `flowplane/nfkit/tests/afxdp_loopback.rs` — the gated-test pattern (build example → run script → match exit 0/77/other). `hack/dpdk/afxdp-loopback.sh` — the l2fwd harness (veth `nfkitvv0/1`, scapy AsyncSniffer-before-send, `exit 77` skip). Note: it only CHECKS hugepages; M7's script must RESERVE + RESTORE them.
- `flowplane/nfkit/tests/datapath_pcap.rs` — reuse verbatim: `inner_frame`/`encap_to`/`allow_meta`/`allow_rule`/`read_pcap_frames` + the sim-expected block (const `VNI=100`/`TAP=42`/`GUEST_MAC=[0x66;..0x00]`/`GUEST_IP=[10,0,0,10]`/`EXT_IP`/`EDGE_UL`/`HOST_UL`/`DST_PORT=443`; `process_uplink` over `MemMaps` with `fw_meta`/`fw_rules` → `Redirect(TAP)`). The committed fixture `tests/data/uplink_in.pcap` is exactly `encap_to(inner_frame(EXT_IP,GUEST_IP,443), HOST_UL)`.
- `uplink_fwd` example (`flowplane/nfkit/examples/uplink_fwd.rs`) — `Some("afxdp") => Backend::AfXdp{iface, queues:1}`; bakes the SAME config the test asserts against. Delivered (decapped) frame's eth dst = `GUEST_MAC` ([0x66,0x66,0x66,0x66,0x66,0x00]), src = `GW_MAC`.
- Host: `nr_hugepages=0` now; hugetlbfs mounted at `/dev/hugepages`; real sudo = `/run/wrappers/bin/sudo` (NixOS). af_xdp PMD built into `dpdk-sys` (M2).

**Absolute rules:**
- Cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook active; if the rustup `cargo fmt` shim prints usage, format touched files with `rustfmt --edition 2021 <files>`.
- Do NOT change the `uplink_fwd` example or `datapath_pcap.rs`. Reuse their fixture by DUPLICATING the small helper consts/fns into `afxdp_datapath.rs` (they're test-local; keep them byte-identical to `datapath_pcap.rs`).

---

## File Structure
- `hack/dpdk/afxdp-uplink.sh` — new harness (hugepage reserve/restore + veth + uplink_fwd(afxdp) + scapy inject/capture→pcap).
- `flowplane/nfkit/tests/afxdp_datapath.rs` — new gated test.
- `Makefile` — `+ dpdk-afxdp-datapath` target (optional convenience).
- `docs/dpdk-dev.md` — note the new privileged test + its hugepage self-management.

---

## Task 1: The hugepage-managing af_xdp uplink harness

**Files:** Create `hack/dpdk/afxdp-uplink.sh`.

- [ ] **Step 1: Write `hack/dpdk/afxdp-uplink.sh`**
```bash
#!/usr/bin/env bash
# af_xdp veth e2e for the nfkit uplink_fwd datapath. RESERVES hugepages and RESTORES the original
# vm.nr_hugepages on exit (trap). Injects the encapped fixture on the veth peer, captures the frame
# uplink_fwd tx's back (the decapped delivery), and writes it to $OUT_PCAP for the Rust test to
# byte-compare against the sim. Exits 77 (skip) if unprivileged / hugepages not reservable; 0 on OK.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + af_xdp + hugepage reserve need root)"

VV0=nfkitvv0; VV1=nfkitvv1
ORIG_HP="$(cat /proc/sys/vm/nr_hugepages)"
restore() {
  sysctl -qw vm.nr_hugepages="$ORIG_HP" 2>/dev/null || true
  ip link del "$VV0" 2>/dev/null || true
}
trap restore EXIT
# Reserve hugepages (idempotent); restored to $ORIG_HP by the trap on ANY exit.
sysctl -qw vm.nr_hugepages=1024 2>/dev/null || true
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || need_skip "hugepages not reservable"

: "${UPLINK_BIN:?set UPLINK_BIN to the built uplink_fwd example}"
: "${IN_PCAP:?set IN_PCAP to the encapped input fixture pcap}"
: "${OUT_PCAP:?set OUT_PCAP to the capture destination}"

ip link del "$VV0" 2>/dev/null || true
ip link add "$VV0" type veth peer name "$VV1"
ip link set "$VV0" up; ip link set "$VV1" up

"$UPLINK_BIN" afxdp "$VV0" &
APP=$!
sleep 2

# Inject the encapped fixture on the peer; capture the decapped delivery (eth dst = GUEST_MAC
# 66:66:66:66:66:00) uplink_fwd tx's back out vv0. Write it to $OUT_PCAP.
python3 - "$VV1" "$IN_PCAP" "$OUT_PCAP" <<'PY'
import sys, time
from scapy.all import rdpcap, sendp, wrpcap, Ether, AsyncSniffer
iface, in_pcap, out_pcap = sys.argv[1], sys.argv[2], sys.argv[3]
frame = bytes(rdpcap(in_pcap)[0])
snf = AsyncSniffer(iface=iface, count=1, timeout=6,
                   lfilter=lambda p: p.haslayer(Ether) and p[Ether].dst == "66:66:66:66:66:00")
snf.start(); time.sleep(0.3)
sendp(Ether(frame), iface=iface, verbose=0)
res = snf.stop()
assert res and len(res) == 1, "did not capture the decapped delivery frame"
wrpcap(out_pcap, res[0])
print("AFXDP UPLINK OK")
PY
RC=$?
kill "$APP" 2>/dev/null || true
exit $RC
```
`chmod +x hack/dpdk/afxdp-uplink.sh`.

- [ ] **Step 2: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add hack/dpdk/afxdp-uplink.sh
git commit -m "test(nfkit): af_xdp uplink datapath harness (self-restoring hugepages + veth + scapy capture)"
```

---

## Task 2: The gated `afxdp_datapath.rs` test

**Files:** Create `flowplane/nfkit/tests/afxdp_datapath.rs`; modify `Makefile` (+ target); modify `docs/dpdk-dev.md`.

- [ ] **Step 1: Write `flowplane/nfkit/tests/afxdp_datapath.rs`** — copy the fixture helpers + consts + the sim-expected block VERBATIM from `datapath_pcap.rs` (`inner_frame`, `encap_to`, `allow_meta`, `allow_rule`, `read_pcap_frames`, the `VNI/TAP/GUEST_MAC/...` consts, and the `process_uplink`-over-`MemMaps` expected computation). Replace only the "run on pcap" middle with the af_xdp harness run:
```rust
//! af_xdp datapath e2e: run `uplink_fwd` on the DPDK af_xdp PMD over a real veth loopback (the
//! hack/dpdk/afxdp-uplink.sh harness reserves+restores hugepages), then assert the frame it tx'd
//! back (captured via scapy) is byte-identical to `process_uplink` on the sim side. SKIPS (passes)
//! when unprivileged / hugepages not reservable (script exit 77). Run with `--test-threads=1`.
// ... (duplicate the datapath_pcap.rs helpers/consts here) ...

#[test]
fn afxdp_datapath_uplink_matches_sim() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let root = format!("{dir}/../..");
    let input = format!("{dir}/tests/data/uplink_in.pcap"); // reuse the committed fixture
    let out = format!("{}/afxdp_uplink_out.pcap", std::env::temp_dir().display());
    let _ = std::fs::remove_file(&out);

    let expected_frame = encap_to(&inner_frame(EXT_IP, GUEST_IP, DST_PORT), HOST_UL);

    // Build the example, then run the privileged harness (skips unprivileged).
    let b = std::process::Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "uplink_fwd"])
        .current_dir(&root).status().expect("build uplink_fwd");
    assert!(b.success());
    let bin = format!("{root}/target/debug/examples/uplink_fwd");

    let status = std::process::Command::new("bash")
        .arg(format!("{root}/hack/dpdk/afxdp-uplink.sh"))
        .env("UPLINK_BIN", &bin)
        .env("IN_PCAP", &input)
        .env("OUT_PCAP", &out)
        .current_dir(&root).status().expect("run afxdp-uplink.sh");
    match status.code() {
        Some(0) => {}
        Some(77) => { eprintln!("afxdp datapath skipped (unprivileged / no hugepages)"); return; }
        other => panic!("afxdp-uplink.sh failed: exit {other:?}"),
    }

    // Compare the af_xdp-transported delivery to the sim output (byte parity).
    let out_frames = read_pcap_frames(&std::fs::read(&out).expect("read capture pcap"));
    assert_eq!(out_frames.len(), 1);
    let u = UnderlayValue { vni: VNI, tap_ifindex: TAP, guest_mac: GUEST_MAC, _pad: [0; 2] };
    let zl = Local { uplink_ifindex: 0, uplink_mac: [0; 6], gateway_mac: [0; 6], underlay_ipv6: [0; 16] };
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(TAP, allow_meta());
    sim.fw_rules.insert((TAP, 0), allow_rule(DST_PORT));
    let mut vp = VecPkt::from_bytes(&expected_frame);
    let sim_action = process_uplink(&mut vp, &mut sim, &UplinkIn { vni: VNI, u, outer_dst: HOST_UL, local: &zl, now: 0 });
    assert_eq!(sim_action, Action::Redirect(TAP));
    assert_eq!(out_frames[0], vp.into_bytes(), "af_xdp datapath output != sim (byte parity broken)");
}
```
(Bring the same `use` lines as `datapath_pcap.rs`.)

- [ ] **Step 2: Confirm it SKIPS cleanly unprivileged (this session is not root)** — `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test afxdp_datapath -- --test-threads=1 --nocapture'`. Expected: builds, runs the script, script prints `SKIP: not root`, exit 77 → test prints "afxdp datapath skipped" and PASSES. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 3: Add convenience target + doc** — `Makefile`: `dpdk-afxdp-datapath:` running the test under `sudo` inside `nix develop` (mirror any existing `dpdk-afxdp-loopback` target). `docs/dpdk-dev.md`: a short note — the test self-manages hugepages (reserves 1024, restores original on exit) and needs `sudo`; unprivileged it auto-skips.

- [ ] **Step 4: Commit**
```bash
git add flowplane/nfkit/tests/afxdp_datapath.rs Makefile docs/dpdk-dev.md
git commit -m "test(nfkit): gated af_xdp uplink datapath e2e (byte-parity vs sim; auto-skips unprivileged)"
```

---

## Task 3: Privileged run + hugepage-reset verification (MAIN SESSION — not a subagent)

**This task is executed by the main assistant (needs interactive sudo), NOT dispatched.**

- [ ] **Step 1: Baseline** — confirm `cat /proc/sys/vm/nr_hugepages` is `0` before.
- [ ] **Step 2: Build the example** (unprivileged, inside nix): `cargo build -p nfkit --example uplink_fwd`.
- [ ] **Step 3: Privileged run** — run the harness under the real sudo, preserving the nix env so the DPDK-linked binary + scapy resolve:
  `sudo -E /run/wrappers/bin/... bash hack/dpdk/afxdp-uplink.sh` with `UPLINK_BIN`/`IN_PCAP`/`OUT_PCAP` set (or `sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" bash ...`). If sudo needs the user's hand, hand them the exact `! sudo …` line.
  Expected: `AFXDP UPLINK OK`, exit 0.
- [ ] **Step 4: Byte-parity** — either run the full gated test as root (`sudo -E <test-binary>`) so the Rust comparison asserts parity, OR compare the captured `$OUT_PCAP` frame to the sim output. Confirm byte-identical.
- [ ] **Step 5: Confirm the reset** — `cat /proc/sys/vm/nr_hugepages` is back to `0` (the trap restored it). Also force-fail once (e.g. bad `UPLINK_BIN`) and confirm the trap STILL restores `0`.

---

## Definition of Done (M7)
- `cargo test -p nfkit --test afxdp_datapath` **auto-skips** cleanly unprivileged (green in this session/CI).
- Under `sudo`, the af_xdp-transported decapped frame is **byte-identical** to `process_uplink`'s sim output.
- `vm.nr_hugepages` is **restored to 0** after the run (trap-safe on success AND failure) — verified.
- Reusable hugepage-reserve/restore harness pattern in place for M8/M9.
- Default host build + existing tests untouched; `uplink_fwd`/`datapath_pcap.rs` unchanged.

## Risks / notes
- **Trap restore** must fire on every exit path — verify `nr_hugepages==0` after both a passing and a forced-failing run (Task 3 Step 5).
- **sudo + nix env** — use `sudo -E` and pass the binary's absolute path + `LD_LIBRARY_PATH`/`PATH` so DPDK libs + scapy resolve; real sudo is `/run/wrappers/bin/sudo`.
- **af_xdp on veth = copy mode** — functional e2e only (perf is the smartNIC phase).
- **Sniffer filter** — keys on the decapped delivery's eth dst `66:66:66:66:66:00` (GUEST_MAC) to avoid capturing the injected frame; single frame, 6s timeout, AsyncSniffer started before send.
