# nfkit Environment & Toolchain Bootstrap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove DPDK builds and runs on this host/CI end-to-end — DPDK in the nix devShell, a `dpdk-sys` FFI crate (bindgen + C shim for the static-inline fast path), and a minimal safe `nfkit::Eal` that initializes EAL on a `net_null`/`net_pcap` vdev with `--no-huge` — plus a host-capability probe and setup docs.

**Architecture:** This is Milestone 1 (the environment gate) of the flowplane-dpdk spec (`docs/superpowers/specs/2026-07-20-flowplane-dpdk-nfkit-design.md`). It builds nothing of the datapath yet — it de-risks the toolchain: can we build/link DPDK from nix, generate bindings, wrap the inline fast path, and init EAL with no hugepages and no bound NIC (vdev-only)? The EAL-init smoke test is the proof the environment works. `dpdk-sys` is internal to `nfkit`; both are new Cargo workspace members excluded from `default-members` (like `flowplane-ebpf`) so the normal host build/CI is unaffected until opted in.

**Tech Stack:** Rust (rustup nightly-2026-01-15, matching the repo). **DPDK 25.11.2 built from source by `dpdk-sys/build.rs`** — the build script downloads the pinned release tarball on demand (checksum-verified), builds it with **meson/ninja** (static, only the PMDs we need), then runs `pkg-config`/`bindgen`/`cc`. Fetch/verify/extract via the `ureq` + `sha2` crates + system `tar`. Fully self-contained: no system/nix DPDK required.

**Host reality (probed 2026-07-20, this dev host):** kernel 7.0.11; hugetlbfs mounted at `/dev/hugepages` (2M pages) but **0 reserved**; IOMMU on; `/dev/vfio` present; **only physical NIC is `wlan0` (no spare to bind)**. Conclusion: functional/CI testing works with `--no-huge` + `net_pcap`/`net_null` (zero setup); `net_af_xdp` perf work needs `sudo sysctl vm.nr_hugepages=1024`.

---

## File Structure

- `flake.nix` — add DPDK + build/link/bindgen deps + `LIBCLANG_PATH` to the devShell.
- `hack/dpdk/check-host.sh` — host capability probe (kernel/hugepages/IOMMU/vfio/NICs → verdict + remediation).
- `Makefile` — add a `dpdk-check` target wrapping the probe.
- `docs/dpdk-dev.md` — DPDK dev setup: hugepages (runtime + NixOS), `--no-huge` CI mode, vdev usage, no-bindable-NIC note.
- `flowplane/dpdk-sys/` — new crate: `Cargo.toml`, `build.rs` (self-contained cached DPDK download+meson build), `wrapper.h`, `shim.h`, `shim.c`, `src/lib.rs`, `tests/link.rs`. DPDK source/build are cached under `~/.cache/dpdk-sys/` (outside the repo — nothing vendored in-tree).
- `flowplane/nfkit/` — new crate: `Cargo.toml`, `src/lib.rs` (`Eal` safe wrapper), `src/eal.rs`, `tests/eal_init.rs`.
- `flowplane/Cargo.toml` — add `dpdk-sys` + `nfkit` as workspace members, exclude from `default-members`.

---

## Task 1: Add the DPDK *build* toolchain to the nix devShell

`dpdk-sys` builds DPDK from source, so the devShell provides the DPDK build toolchain (meson/ninja/python-pyelftools), bindgen's clang, and the PMD/link deps — **not** a prebuilt `pkgs.dpdk`.

**Files:**
- Modify: `flake.nix` (the `devShells.default` `buildInputs` list + env vars)

- [ ] **Step 1: Add the DPDK build toolchain to `buildInputs`**

In `flake.nix`, inside `devShells.default = pkgs.mkShell { ... buildInputs = [ ... ]`, add these entries (place after `pkgs.util-linux`):

```nix
            # DPDK build toolchain — dpdk-sys/build.rs downloads the pinned DPDK release and
            # builds it with meson/ninja (static). These are the DPDK build + link deps and
            # bindgen's clang. No prebuilt pkgs.dpdk — we compile our own pinned version.
            pkgs.meson
            pkgs.ninja
            pkgs.pkg-config
            pkgs.clang                        # bindgen front-end
            pkgs.python3Packages.pyelftools   # required by the DPDK build
            pkgs.numactl                      # libnuma (DPDK dep)
            pkgs.libpcap                      # net_pcap PMD
            pkgs.libbpf                       # net_af_xdp PMD (Milestone 2)
            pkgs.libxdp                       # net_af_xdp PMD (Milestone 2)
```

(`curl`/`tar`/`xz` for the tarball fetch/extract are already in a standard devShell via coreutils/curl; if `tar` or `xz` is missing, add `pkgs.gnutar pkgs.xz`.)

- [ ] **Step 2: Add `LIBCLANG_PATH` env for bindgen**

In the same `mkShell` block, alongside `RUST_BACKTRACE = 1;`, add:

```nix
          # rust-bindgen (dpdk-sys/build.rs) needs libclang at runtime.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
```

- [ ] **Step 3: Verify the build toolchain is present**

Run: `nix develop --command bash -c 'meson --version && ninja --version && pkg-config --version && clang --version | head -1 && python3 -c "import elftools; print(\"pyelftools ok\")"'`
Expected: prints versions for meson, ninja, pkg-config, clang, and `pyelftools ok`. If any is missing, fix `buildInputs` before proceeding.

- [ ] **Step 4: Commit**

```bash
git add flake.nix
git commit -m "build(nix): add DPDK build toolchain (meson/ninja/pyelftools/clang) to devShell"
```

---

## Task 2: Host capability probe script

**Files:**
- Create: `hack/dpdk/check-host.sh`
- Modify: `Makefile` (add `dpdk-check` target)

- [ ] **Step 1: Write the probe script**

Create `hack/dpdk/check-host.sh`:

```bash
#!/usr/bin/env bash
# DPDK host-capability probe. Reports what this host can run and the exact remediation.
# Exit 0 if functional/CI testing (net_pcap/net_null + --no-huge) is possible — which is
# essentially always. Perf backends (af_xdp) additionally need reserved hugepages.
set -euo pipefail

say() { printf '%-22s %s\n' "$1" "$2"; }

echo "== DPDK host capability =="
say "kernel" "$(uname -r)"

hp_total=$(awk '/HugePages_Total/{print $2}' /proc/meminfo)
hp_size=$(awk '/Hugepagesize/{print $2" "$3}' /proc/meminfo)
say "hugepage size" "$hp_size"
say "hugepages reserved" "$hp_total"
mount | grep -q hugetlbfs && say "hugetlbfs" "mounted" || say "hugetlbfs" "NOT mounted"

[ -d /sys/kernel/iommu_groups ] && [ -n "$(ls -A /sys/kernel/iommu_groups 2>/dev/null)" ] \
  && say "IOMMU" "enabled" || say "IOMMU" "disabled/none"
[ -e /dev/vfio/vfio ] && say "vfio" "present" || say "vfio" "absent"

# Physical NICs (have a /device symlink) that are DOWN (candidate to bind); wlan/virtual excluded.
bindable=""
for n in /sys/class/net/*; do
  d=$(basename "$n")
  [ -e "$n/device" ] || continue
  case "$d" in lo|docker*|veth*|tailscale*|wlan*) continue;; esac
  bindable="$bindable $d"
done
say "bindable NICs" "${bindable:-<none — use vdev PMDs>}"

echo
echo "== verdict =="
echo "functional/CI (net_pcap + net_null, --no-huge): SUPPORTED (no setup needed)"
if [ "${hp_total:-0}" -gt 0 ]; then
  echo "af_xdp/perf backends (need hugepages): READY ($hp_total pages reserved)"
else
  echo "af_xdp/perf backends (need hugepages): reserve first ->"
  echo "    sudo sysctl -w vm.nr_hugepages=1024   # 2 GiB of 2M pages, runtime, no reboot"
  echo "    (persist on NixOS: boot.kernel.sysctl.\"vm.nr_hugepages\" = 1024;)"
fi
[ -z "$bindable" ] && echo "no spare NIC to bind -> vdev-only local dev (as designed)"
```

- [ ] **Step 2: Make it executable and run it**

Run: `chmod +x hack/dpdk/check-host.sh && ./hack/dpdk/check-host.sh`
Expected: prints the table + verdict; on this host, "functional/CI ... SUPPORTED", hugepages reserved = 0 with the sysctl remediation, "no spare NIC ... vdev-only".

- [ ] **Step 3: Add the Makefile target**

Add to `Makefile`:

```makefile
.PHONY: dpdk-check
dpdk-check: ## Probe host DPDK capability (hugepages/IOMMU/NICs)
	@hack/dpdk/check-host.sh
```

- [ ] **Step 4: Verify the target**

Run: `make dpdk-check`
Expected: same output as Step 2.

- [ ] **Step 5: Commit**

```bash
git add hack/dpdk/check-host.sh Makefile
git commit -m "feat(dpdk): host-capability probe (hack/dpdk/check-host.sh + make dpdk-check)"
```

---

## Task 3: DPDK dev setup docs

**Files:**
- Create: `docs/dpdk-dev.md`

- [ ] **Step 1: Write the doc**

Create `docs/dpdk-dev.md`:

```markdown
# DPDK development (nfkit / flowplane-dpdk)

All tooling is in the nix devShell (`nix develop`): DPDK, `pkg-config`, `clang`
(bindgen), `libpcap`/`libbpf`/`numactl`. Check the host with `make dpdk-check`.

## Testing without a smartNIC (the normal case)

There is usually no spare NIC to bind to DPDK on a dev laptop (and none is needed).
Use DPDK **vdev** PMDs, selected by EAL args — same binary, no code change:

- **CI / functional:** `net_pcap` or `net_null` with `--no-huge` (DPDK allocates from
  the malloc heap instead of hugepages). Requires **zero host setup**. This is the
  `BPF_PROG_TEST_RUN` analogue: feed a pcap, assert the emitted pcap.
- **Laptop full-stack:** `net_af_xdp` on a `veth`/`netns` (real kernel datapath).
  Needs hugepages (below).

## Hugepages (only for af_xdp / perf, not for --no-huge CI)

Reserve at runtime (no reboot; non-persistent):

    sudo sysctl -w vm.nr_hugepages=1024      # 2 GiB of 2M pages

Persist on NixOS (`configuration.nix`):

    boot.kernel.sysctl."vm.nr_hugepages" = 1024;

hugetlbfs is already mounted at `/dev/hugepages` on this host.

## Building DPDK (dpdk-sys is self-contained)

`dpdk-sys/build.rs` downloads the pinned DPDK release (`25.11.2`) and builds it with
meson/ninja — no system/nix DPDK needed. Source + build are cached under
`~/.cache/dpdk-sys/` (override with `DPDK_CACHE_DIR`), so the ~2–5 min build happens
**once**; later builds (even after `cargo clean`) are a cache hit. To use a prebuilt
DPDK instead, set `DPDK_PREFIX=/path/to/install` (build.rs then skips download+build —
the escape hatch for a future `nix build` / CI derivation).

## Binding a real NIC (production / perf on a box with a spare NIC)

Needs IOMMU + vfio (this host has both). Bind a spare NIC to `vfio-pci` with
`dpdk-devbind.py`. Never bind your only/uplink NIC. Not applicable to laptop dev.

## EAL arg cheat-sheet

- No hugepages, no PCI, null port:  `-l 0 --no-huge -m 512 --no-pci --vdev net_null0 --file-prefix nfkit`
- pcap replay/record:               `--vdev net_pcap0,rx_pcap=in.pcap,tx_pcap=out.pcap`
- af_xdp on veth end `vv0`:         `--vdev net_af_xdp0,iface=vv0`
```

- [ ] **Step 2: Commit**

```bash
git add docs/dpdk-dev.md
git commit -m "docs(dpdk): dev setup — vdev testing, hugepages, EAL cheat-sheet"
```

---

## Task 4: `dpdk-sys` crate (self-contained cached DPDK build + bindgen + C shim)

`dpdk-sys/build.rs` downloads the pinned DPDK release **once** into a stable cache dir (outside `OUT_DIR`), builds it with meson/ninja **once** (cache-keyed by version+config), then links statically, compiles the inline-fn C shim, and runs bindgen. A `DPDK_PREFIX` env var skips download+build (escape hatch for nix/CI).

**Files:**
- Create: `flowplane/dpdk-sys/Cargo.toml`, `flowplane/dpdk-sys/build.rs`, `flowplane/dpdk-sys/wrapper.h`, `flowplane/dpdk-sys/shim.h`, `flowplane/dpdk-sys/shim.c`, `flowplane/dpdk-sys/src/lib.rs`
- Modify: `flowplane/Cargo.toml` (workspace members + default-members)

- [ ] **Step 1: Register the crate in the workspace (excluded from default build)**

In `flowplane/Cargo.toml`, add `"dpdk-sys"` and `"nfkit"` to `[workspace] members`, and ensure `default-members` does NOT include them (mirroring how `flowplane-ebpf` is excluded so `cargo build`/clippy skip them):

```toml
# in flowplane/Cargo.toml [workspace] — only ADD dpdk-sys/nfkit; keep the rest as-is
members = [ ".", "flowplane-core", "flowplane-common", "flowplane-ebpf", "flowplane-sim", "dpdk-sys", "nfkit" ]
default-members = [ ".", "flowplane-core", "flowplane-common", "flowplane-sim" ]
```

- [ ] **Step 2: Record the DPDK tarball checksum (do this first — it's a pinned constant)**

Run: `nix develop --command bash -c 'curl -sSL https://fast.dpdk.org/rel/dpdk-25.11.2.tar.xz | sha256sum'`
Copy the 64-hex-char digest — you paste it into `build.rs` `DPDK_SHA256` in Step 4. (Pinning the checksum makes the on-demand download tamper-evident and reproducible.)

- [ ] **Step 3: Write `Cargo.toml`**

Create `flowplane/dpdk-sys/Cargo.toml`:

```toml
[package]
name = "dpdk-sys"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
doctest = false   # raw FFI only

[build-dependencies]
bindgen = "0.70"
cc = "1"
ureq = "2"      # tarball download (blocking, rustls)
sha2 = "0.10"   # checksum verification
```

- [ ] **Step 4: Write `build.rs` (cached self-contained DPDK build)**

Create `flowplane/dpdk-sys/build.rs`:

```rust
use std::{env, fs, path::{Path, PathBuf}, process::Command};
use sha2::{Digest, Sha256};

const DPDK_VERSION: &str = "25.11.2";
const DPDK_URL: &str = "https://fast.dpdk.org/rel/dpdk-25.11.2.tar.xz";
// SHA-256 of the tarball — paste the digest from Task 4 Step 2.
const DPDK_SHA256: &str = "PASTE_SHA256_FROM_STEP_2";
// Only the PMDs we need — keeps the DPDK build small/fast.
const DRIVERS: &str = "net/null,net/pcap,net/tap,net/af_xdp";

fn main() {
    // Escape hatch: a prebuilt DPDK prefix (nix/CI) skips the download+build entirely.
    let prefix = match env::var("DPDK_PREFIX") {
        Ok(p) => PathBuf::from(p),
        Err(_) => build_dpdk_cached(),
    };
    let pc_dir = prefix.join("lib/pkgconfig");

    // Static link line via `pkg-config --static` — forwarded verbatim so DPDK's
    // `-Wl,--whole-archive` PMD-constructor groups survive (the pkg-config *crate* would strip
    // them, breaking driver self-registration → "no such vdev"). We emit raw link-args.
    let libs = pkgconf(&pc_dir, &["--libs", "--static", "libdpdk"]);
    for tok in libs.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else {
            println!("cargo:rustc-link-arg={tok}");
        }
    }

    // Include paths for the shim (cc) and bindgen.
    let cflags = pkgconf(&pc_dir, &["--cflags", "libdpdk"]);
    let includes: Vec<String> = cflags
        .split_whitespace()
        .filter(|t| t.starts_with("-I"))
        .map(|t| t.to_string())
        .collect();

    // Compile the C shim (exposes DPDK's static-inline fast path as real symbols).
    let mut build = cc::Build::new();
    build.file("shim.c");
    for inc in &includes {
        build.flag(inc);
    }
    build.compile("nfkit_shim");

    // Bindgen the public API + shim.
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(&includes)
        .allowlist_function("rte_.*")
        .allowlist_function("nfkit_.*")
        .allowlist_type("rte_.*")
        .allowlist_var("RTE_.*")
        .derive_default(true)
        .generate()
        .expect("bindgen failed");
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("write bindings");

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim.h");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-env-changed=DPDK_PREFIX");
}

/// Download (once) + build (once) DPDK into a STABLE cache dir outside OUT_DIR, so `cargo clean`
/// does not force a re-download or rebuild. Returns the install prefix. Cache-keyed by version+config.
fn build_dpdk_cached() -> PathBuf {
    let root = cache_root();
    fs::create_dir_all(&root).unwrap();
    let tarball = root.join(format!("dpdk-{DPDK_VERSION}.tar.xz"));
    let srcdir = root.join(format!("dpdk-{DPDK_VERSION}"));
    let key = short_hash(&format!("{DPDK_VERSION}|{DRIVERS}|static|generic"));
    let prefix = root.join(format!("install-{key}"));
    let stamp = prefix.join("lib/pkgconfig/libdpdk.pc");
    if stamp.exists() {
        return prefix; // CACHE HIT: no download, no build.
    }

    if !tarball.exists() {
        download(DPDK_URL, &tarball);
    }
    verify_sha256(&tarball, DPDK_SHA256);
    if !srcdir.exists() {
        run("tar", &["-xf", tarball.to_str().unwrap(), "-C", root.to_str().unwrap()]);
    }

    // Build+install into a temp dir, then atomically rename (safe under parallel cargo builds).
    let tmp = root.join(format!("install-{key}.tmp.{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let build = srcdir.join(format!("build-{key}"));
    let _ = fs::remove_dir_all(&build);
    run("meson", &[
        "setup", build.to_str().unwrap(), srcdir.to_str().unwrap(),
        &format!("--prefix={}", tmp.display()),
        "--default-library=static",
        "-Dplatform=generic",   // portable, no -march=native
        "-Dtests=false",
        "-Denable_kmods=false",
        "-Dexamples=",
        &format!("-Denable_drivers={DRIVERS}"),
    ]);
    run("ninja", &["-C", build.to_str().unwrap(), "install"]);
    if prefix.exists() {
        let _ = fs::remove_dir_all(&tmp); // another build won the race
    } else {
        fs::rename(&tmp, &prefix).expect("atomic install rename");
    }
    prefix
}

fn cache_root() -> PathBuf {
    if let Ok(d) = env::var("DPDK_CACHE_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = env::var("XDG_CACHE_HOME") {
        return PathBuf::from(d).join("dpdk-sys");
    }
    PathBuf::from(env::var("HOME").expect("HOME unset")).join(".cache/dpdk-sys")
}

fn download(url: &str, dest: &Path) {
    let tmp = dest.with_extension("part");
    let resp = ureq::get(url).call().expect("dpdk tarball download failed");
    let mut r = resp.into_reader();
    let mut f = fs::File::create(&tmp).unwrap();
    std::io::copy(&mut r, &mut f).unwrap();
    fs::rename(&tmp, dest).unwrap();
}

fn verify_sha256(path: &Path, expected: &str) {
    let bytes = fs::read(path).unwrap();
    let got = hex(&Sha256::digest(&bytes));
    assert_eq!(
        got, expected,
        "DPDK tarball checksum mismatch — expected {expected}, got {got}. Delete {} and retry.",
        path.display()
    );
}

fn pkgconf(pc_dir: &Path, args: &[&str]) -> String {
    let existing = env::var("PKG_CONFIG_PATH").unwrap_or_default();
    let out = Command::new("pkg-config")
        .args(args)
        .env("PKG_CONFIG_PATH", format!("{}:{existing}", pc_dir.display()))
        .output()
        .expect("pkg-config not found");
    assert!(out.status.success(), "pkg-config {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd).args(args).status().unwrap_or_else(|e| panic!("{cmd} failed to start: {e}"));
    assert!(status.success(), "{cmd} {:?} failed", args);
}

fn short_hash(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))[..16].to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

- [ ] **Step 5: Write the bindgen header + shim**

Create `flowplane/dpdk-sys/wrapper.h`:

```c
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include "shim.h"
```

Create `flowplane/dpdk-sys/shim.h`:

```c
#pragma once
#include <stdint.h>
struct rte_mbuf;
/* Non-inline wrappers for DPDK's static-inline fast path (bindgen can't emit inline fns). */
uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
struct rte_mbuf *nfkit_pktmbuf_alloc(struct rte_mempool *mp);
void nfkit_pktmbuf_free(struct rte_mbuf *m);
```

Create `flowplane/dpdk-sys/shim.c`:

```c
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "shim.h"

uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb) {
    return rte_eth_rx_burst(port, qid, pkts, nb);
}
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb) {
    return rte_eth_tx_burst(port, qid, pkts, nb);
}
struct rte_mbuf *nfkit_pktmbuf_alloc(struct rte_mempool *mp) { return rte_pktmbuf_alloc(mp); }
void nfkit_pktmbuf_free(struct rte_mbuf *m) { rte_pktmbuf_free(m); }
```

- [ ] **Step 6: Write `src/lib.rs`**

Create `flowplane/dpdk-sys/src/lib.rs`:

```rust
//! Raw DPDK FFI: bindgen over the public API + a C shim for the static-inline fast path.
//! All `unsafe`. Safe wrappers live in `nfkit`.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

- [ ] **Step 7: Build it (first build downloads + compiles DPDK — slow once, then cached)**

Run: `nix develop --command bash -c 'cd flowplane && cargo build -p dpdk-sys'`
Expected: the FIRST build downloads `dpdk-25.11.2.tar.xz` into `~/.cache/dpdk-sys/` and does a meson/ninja build (~2–5 min); subsequent builds (even after `cargo clean`) are fast — the cache stamp `~/.cache/dpdk-sys/install-*/lib/pkgconfig/libdpdk.pc` short-circuits the rebuild. Then the crate compiles clean. Debugging: if the DPDK build fails, re-run the printed `meson`/`ninja` commands in `~/.cache/dpdk-sys/` to see the error; if bindgen errors, adjust `allowlist_*` / `wrapper.h`.

- [ ] **Step 8: Verify the cache works (clean rebuild does NOT re-download or rebuild DPDK)**

Run: `nix develop --command bash -c 'cd flowplane && cargo clean -p dpdk-sys && time cargo build -p dpdk-sys'`
Expected: completes in seconds (cache hit — no tarball fetch, no meson build). If it re-downloads/rebuilds, the cache-key/stamp logic in `build_dpdk_cached` is wrong — fix before continuing.

- [ ] **Step 9: Add a link smoke test**

Create `flowplane/dpdk-sys/tests/link.rs`:

```rust
// Compiling + linking this test proves the DPDK static libs + the shim resolve. We only take
// addresses to force symbol resolution — rte_eal_init itself is exercised by nfkit (Task 5).
#[test]
fn symbols_resolve() {
    let rx: unsafe extern "C" fn(u16, u16, *mut *mut dpdk_sys::rte_mbuf, u16) -> u16 =
        dpdk_sys::nfkit_eth_rx_burst;
    let init: unsafe extern "C" fn(std::os::raw::c_int, *mut *mut std::os::raw::c_char) -> std::os::raw::c_int =
        dpdk_sys::rte_eal_init;
    assert!(!(rx as *const ()).is_null());
    assert!(!(init as *const ()).is_null());
}
```

- [ ] **Step 10: Run the link test**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p dpdk-sys --test link'`
Expected: PASS (proves the DPDK static libs + shim symbols link — including the `--whole-archive` PMD groups).

- [ ] **Step 11: Commit**

```bash
git add flowplane/dpdk-sys flowplane/Cargo.toml
git commit -m "feat(dpdk-sys): self-contained cached DPDK build + bindgen + C shim FFI crate"
```

---

## Task 5: `nfkit::Eal` — safe EAL init, proven on a vdev with `--no-huge`

**Files:**
- Create: `flowplane/nfkit/Cargo.toml`, `flowplane/nfkit/src/lib.rs`, `flowplane/nfkit/src/eal.rs`, `flowplane/nfkit/tests/eal_init.rs`

- [ ] **Step 1: Write the failing test first**

Create `flowplane/nfkit/tests/eal_init.rs`:

```rust
// Proof-of-toolchain: initialize DPDK EAL on THIS host with no hugepages, no PCI, a null
// vdev — then clean up. If this passes in CI, the environment is good end to end.
use nfkit::Eal;

#[test]
fn eal_inits_on_null_vdev_no_huge() {
    let eal = Eal::init([
        "nfkit-test",
        "-l", "0",
        "--no-huge",
        "-m", "512",
        "--no-pci",
        "--vdev", "net_null0",
        "--file-prefix", "nfkit_test",
    ])
    .expect("EAL init failed — check hugepages/permissions/vdev support");
    // EAL is up; a null port should exist.
    assert!(eal.port_count() >= 1, "expected the net_null0 vdev port");
}
```

- [ ] **Step 2: Write `Cargo.toml`**

Create `flowplane/nfkit/Cargo.toml`:

```toml
[package]
name = "nfkit"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
dpdk-sys = { path = "../dpdk-sys" }
```

- [ ] **Step 3: Write the `Eal` wrapper**

Create `flowplane/nfkit/src/eal.rs`:

```rust
//! Safe EAL lifecycle. `Eal::init` is the one entry point; the returned guard gates DPDK use
//! and calls `rte_eal_cleanup` on drop. Not `Send`/`Sync` (EAL is process-global, main-lcore).
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_char;

/// RAII guard proving EAL is initialized. `!Send + !Sync` via the `PhantomData` marker.
pub struct Eal {
    _not_send: PhantomData<*const ()>,
}

#[derive(Debug)]
pub enum EalError {
    /// rte_eal_init returned < 0 (see rte_errno).
    Init(i32),
    /// An arg contained an interior NUL.
    BadArg,
}

impl Eal {
    /// Initialize EAL with the given argv (including argv[0] program name). Safe wrapper:
    /// converts args, calls `rte_eal_init`, and on success returns a guard.
    pub fn init<I, S>(args: I) -> Result<Eal, EalError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cstrings: Vec<CString> = args
            .into_iter()
            .map(|s| CString::new(s.as_ref()).map_err(|_| EalError::BadArg))
            .collect::<Result<_, _>>()?;
        let mut ptrs: Vec<*mut c_char> = cstrings.iter().map(|c| c.as_ptr() as *mut c_char).collect();

        // SAFETY: `ptrs` points to `ptrs.len()` valid, NUL-terminated C strings that outlive the
        // call (owned by `cstrings`). rte_eal_init only reads them during the call.
        let rc = unsafe { dpdk_sys::rte_eal_init(ptrs.len() as i32, ptrs.as_mut_ptr()) };
        if rc < 0 {
            return Err(EalError::Init(rc));
        }
        Ok(Eal { _not_send: PhantomData })
    }

    /// Number of probed ethdev ports.
    pub fn port_count(&self) -> u16 {
        // SAFETY: EAL is initialized (we hold the guard); the fn takes no args and reads global state.
        unsafe { dpdk_sys::rte_eth_dev_count_avail() }
    }
}

impl Drop for Eal {
    fn drop(&mut self) {
        // SAFETY: EAL was initialized; cleanup is the documented teardown and is idempotent-safe here
        // because only one Eal exists at a time (single init in practice).
        unsafe {
            dpdk_sys::rte_eal_cleanup();
        }
    }
}
```

- [ ] **Step 4: Write `src/lib.rs`**

Create `flowplane/nfkit/src/lib.rs`:

```rust
//! nfkit — a safe, zero-cost DPDK network-function substrate. Milestone 1: EAL lifecycle only.
mod eal;
pub use eal::{Eal, EalError};
```

- [ ] **Step 5: Run the test — verify it passes on this host**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test eal_init -- --test-threads=1'`
Expected: PASS. `--test-threads=1` because EAL is process-global (one init per process). If it fails with a hugepage error despite `--no-huge`, check `/dev/hugepages` permissions or add `--huge-unlink`; if it fails to find `net_null0`, the nixpkgs dpdk lacks the null PMD — use `--vdev net_pcap0,rx_pcap=/dev/null` or report.

- [ ] **Step 6: Verify the default host build is unaffected**

Run: `nix develop --command bash -c 'cd flowplane && cargo build && cargo test -p flowplane-sim --lib'`
Expected: builds and the 69 sim tests pass — confirming `dpdk-sys`/`nfkit` are excluded from `default-members` and didn't disturb the existing workspace.

- [ ] **Step 7: Commit**

```bash
git add flowplane/nfkit
git commit -m "feat(nfkit): safe Eal init proven on a null vdev with --no-huge (toolchain gate)"
```

---

## Task 6: CI note + milestone wrap-up

**Files:**
- Modify: `docs/dpdk-dev.md` (append a CI section)

- [ ] **Step 1: Document the CI invocation**

Append to `docs/dpdk-dev.md`:

```markdown
## CI

The DPDK crates are excluded from `default-members`, so normal CI is unaffected. A DPDK CI
job runs inside `nix develop` with no special hardware:

    cargo test -p dpdk-sys -p nfkit -- --test-threads=1

This needs no hugepages (EAL runs with `--no-huge`) and no bound NIC (null/pcap vdevs).
```

- [ ] **Step 2: Commit**

```bash
git add docs/dpdk-dev.md
git commit -m "docs(dpdk): CI invocation for the nfkit toolchain crates"
```

---

## Definition of done (Milestone 1)

- `make dpdk-check` reports the host's capability + remediation.
- `cargo test -p dpdk-sys -p nfkit -- --test-threads=1` passes inside `nix develop` — DPDK builds, bindings generate, the inline-fn shim links, and **EAL initializes on this host with no hugepages and no NIC**. That is the proof the environment is viable for the rest of the flowplane-dpdk build.
- The existing host build + `flowplane-sim` tests are untouched (opt-in workspace members).

**Next milestone (separate plan):** `nfkit` Port/Mempool/Mbuf/Rx-Tx + an l2fwd-equivalent on `net_pcap`/`net_af_xdp` (spec Phase 1 remainder), then the Phase-2 datapath gate.
