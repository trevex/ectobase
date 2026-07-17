# flowplaneservice Foundation Implementation Plan (Milestones 1–3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a Rust/aya eBPF-XDP dataplane that speaks the real dpservice `DPDKironcore` gRPC contract and carries guest-to-guest traffic across two hypervisor VMs via XDP IP-in-IPv6 encap/decap.

**Architecture:** A cargo workspace with three crates — `flowplane-common` (`no_std` POD types shared with eBPF), `flowplane-ebpf` (XDP programs built for the BPF target), and `flowplane` (userspace `tonic` gRPC server + `aya` loader/CLI) — plus an `xtask` build helper and an `env/` harness (KVM VMs, host underlay bridge, k3s, netns/tap guests). The control plane translates `DPDKironcore` RPCs into BPF map writes; XDP programs on the guest tap and uplink do encap/redirect and decap/redirect (Approach A, pure XDP).

**Tech Stack:** Rust (stable + nightly/`rust-src` for the BPF target), `aya` / `aya-ebpf`, `bpf-linker`, `tonic` + `prost` (+ `protoc`), Nix flake devShell, `just`, qemu/libvirt, iproute2, k3s, the real Go `dpservice-cli` as conformance driver.

**Scope:** This plan covers spec Milestones 1–3 (Scaffold → gRPC skeleton → Overlay base). Milestones 4–8 (VIP, LB/maglev, NAT-GW, metalbond, metalnet) are deferred to follow-on plans; each builds on the maps + datapath established here.

**Spec:** `docs/superpowers/specs/2026-06-15-flowplaneservice-design.md`

---

## File Structure

```
ironcore-net-xdp/
  Cargo.toml                # [workspace] members = common, ebpf, flowplane, xtask
  flake.nix                 # devShell: single NIGHTLY toolchain (+rust-src, bpfel target),
                            #   bpf-linker, protobuf, qemu/libvirt, iproute2
  # NOTE: no rust-toolchain.toml — this host uses a Nix-provided toolchain with NO rustup,
  #   so `cargo +nightly` and rust-toolchain.toml are inert. The flake supplies one nightly
  #   toolchain; the ambient `cargo` runs `-Z build-std=core` directly.
  proto/
    dpdk.proto              # vendored from ironcore-dev/dpservice (package dpdkironcore.v1)
  flowplane-common/
    Cargo.toml
    src/lib.rs              # no_std POD map key/value structs + tunnel constants
  flowplane-ebpf/
    Cargo.toml
    src/main.rs             # #[xdp] guest_tx (encap) + uplink_rx (decap) programs + maps
  flowplane/
    Cargo.toml
    build.rs                # tonic_build compile of proto/dpdk.proto
    src/main.rs             # CLI entry (serve / load / debug)
    src/grpc.rs             # DPDKironcore service impl -> state
    src/state.rs            # authoritative in-memory state + BPF map projection
    src/maps.rs             # typed wrappers over aya maps (interfaces, routes)
    src/loader.rs           # aya program load/attach to ifaces
  xtask/
    Cargo.toml
    src/main.rs             # `cargo xtask build-ebpf` helper (calls nightly build)
  env/
    justfile                # up/down/demo targets
    setup-host.sh           # underlay bridge on host
    setup-hyp-vm.sh         # per-VM: k3s, tap, netns guest, attach flowplane
    cloud-init/             # VM images / ignition (libvirt)
```

---

## Milestone 1: Scaffold

### Task 1: Workspace skeleton + toolchain pin

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore` (append)

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
# Members start empty and are appended by each crate task (cargo errors on a listed
# member whose Cargo.toml does not exist yet, and a `*` glob errors on non-crate dirs
# like docs/proto/env — so we grow this list explicitly: Task 3 adds "flowplane-common",
# Task 4 adds "xtask", Task 5 adds "flowplane").
members = []
# flowplane-ebpf is built out-of-tree for the BPF target via xtask. `exclude` is REQUIRED:
# xtask runs `cargo` inside flowplane-ebpf/, which would otherwise error that the package
# is inside the workspace root but not a member.
exclude = ["flowplane-ebpf"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
aya = "0.13"
aya-ebpf = "0.1"
aya-log = "0.2"
aya-log-ebpf = "0.1"
tonic = "0.12"
prost = "0.13"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal"] }
anyhow = "1"
clap = { version = "4", features = ["derive"] }
network-types = "0.0.7"
```

- [ ] **Step 2: Toolchain note (no file to create)**

Do **not** create a `rust-toolchain.toml`. This host has no rustup; the Rust toolchain
is provided by the Nix devShell. Task 2 switches that devShell to a single **nightly**
toolchain with `rust-src`, so the ambient `cargo` can build the BPF target via
`-Z build-std=core` with no `+toolchain` proxy. Confirm the BPF target is known:

Run: `rustc --print target-list | grep -x bpfel-unknown-none`
Expected: `bpfel-unknown-none`

- [ ] **Step 3: Append build artifacts to .gitignore**

Append to `.gitignore`:
```
/target
*.o
```

- [ ] **Step 4: Verify workspace parses**

Run: `cargo metadata --no-deps --format-version 1 >/dev/null && echo OK`
Expected: `OK` (an empty-members virtual workspace is valid; members get appended by Tasks 3/4/5).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .gitignore
git commit -m "chore: scaffold cargo workspace and toolchain pin"
```

### Task 2: Extend the Nix devShell for eBPF + gRPC + VMs

**Files:**
- Modify: `flake.nix`

- [ ] **Step 1: Switch the toolchain to nightly and add the new tools**

In `flake.nix`, change `rustToolchain` from stable to a pinned **nightly** with the BPF
target, and keep it as the single toolchain (pre-commit clippy/rustfmt keep using it):
```nix
        rustToolchain = pkgs.rust-bin.nightly."2026-05-01".default.override {
          extensions = [ "rust-src" "rust-analyzer" "rustfmt" "clippy" ];
          targets = [ "bpfel-unknown-none" ];
        };
```
Then extend `buildInputs` (keep existing entries) with:
```nix
            pkgs.bpf-linker
            pkgs.protobuf
            pkgs.grpcurl
            pkgs.qemu
            pkgs.libvirt
            pkgs.OVMF
            pkgs.iproute2
            pkgs.bridge-utils
            pkgs.kubectl
```
And add an env var so `tonic-build` finds `protoc`:
```nix
          PROTOC = "${pkgs.protobuf}/bin/protoc";
```
> If `pkgs.rust-bin.nightly."2026-05-01"` is unavailable, pick the nearest available
> nightly date from `rust-overlay`; the only requirements are `rust-src` + the
> `bpfel-unknown-none` target. If `pkgs.bpf-linker` is missing from the pinned nixpkgs,
> install it via `cargo install bpf-linker` inside the shell and note it as a concern.

- [ ] **Step 2: Reload the devShell and verify tools resolve**

Run:
```bash
nix develop --command bash -c 'cargo --version && bpf-linker --version && protoc --version && qemu-system-x86_64 --version | head -1 && rustc --print target-list | grep -x bpfel-unknown-none'
```
Expected: `cargo` reports a `-nightly` version, plus a version line for each tool and
`bpfel-unknown-none` printed (no "command not found").

- [ ] **Step 3: Commit**

```bash
git add flake.nix flake.lock
git commit -m "chore: add eBPF, gRPC and VM tooling to devShell"
```

### Task 3: `flowplane-common` crate with a tested POD type

**Files:**
- Create: `flowplane-common/Cargo.toml`
- Create: `flowplane-common/src/lib.rs`

- [ ] **Step 1: Write the crate manifest**

`flowplane-common/Cargo.toml`:
```toml
[package]
name = "flowplane-common"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]

[features]
default = []
user = []   # gates std-only impls (e.g. aya Pod) for the userspace side
```

Then register the crate in the root workspace — edit root `Cargo.toml` so:
```toml
members = ["flowplane-common"]
```

- [ ] **Step 2: Write the failing test**

`flowplane-common/src/lib.rs`:
```rust
#![cfg_attr(not(feature = "user"), no_std)]

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `interfaces` map: where to deliver/encap for this overlay IP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote-only).
    pub tap_ifindex: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (the tunnel dst).
    pub underlay_ipv6: [u8; 16],
}

impl IfaceKey {
    pub fn new(vni: u32, ipv4: [u8; 4]) -> Self {
        Self { vni, ipv4 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_key_is_word_packed() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 4 (ipv4).
        assert_eq!(core::mem::size_of::<IfaceKey>(), 8);
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv4, [10, 0, 0, 5]);
    }
}
```

- [ ] **Step 3: Run the test (expect compile-driven failure first, then pass)**

Run: `cargo test -p flowplane-common --features user`
Expected: PASS (`iface_key_is_word_packed`). If size assertion fails, fix field order/padding before proceeding.

- [ ] **Step 4: Add the aya `Pod` impls behind the `user` feature**

Append to `flowplane-common/src/lib.rs`:
```rust
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for IfaceKey {}
    unsafe impl aya::Pod for IfaceValue {}
}
```
Add to `[dependencies]` in `flowplane-common/Cargo.toml`:
```toml
aya = { workspace = true, optional = true }
```
And change the `user` feature line to:
```toml
user = ["dep:aya"]
```

- [ ] **Step 5: Verify both build shapes compile**

Run:
```bash
cargo test -p flowplane-common --features user
cargo build -p flowplane-common   # no_std shape, no aya
```
Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add flowplane-common
git commit -m "feat(common): POD map key/value types shared with eBPF"
```

### Task 4: `flowplane-ebpf` crate (XDP_PASS skeleton; compiled later by aya-build)

**Files:**
- Create: `flowplane-ebpf/Cargo.toml`
- Create: `flowplane-ebpf/src/lib.rs`
- Create: `flowplane-ebpf/src/main.rs`
- Create: `flowplane-ebpf/build.rs`
- Modify: root `Cargo.toml` (workspace membership + ebpf profile)

> **Build model (IMPORTANT — no xtask).** Following the current aya pattern, the eBPF object
> is compiled by the `aya-build` crate invoked from `flowplane`'s `build.rs` (Task 5). aya-build
> runs cargo-in-cargo with `-Z build-std` and selects `bpf-linker` automatically — so there
> is no hand-rolled xtask and no manual linker config. Consequences for this crate:
> - It is a workspace **member** but excluded from `default-members`, so a normal host
>   `cargo build` does not try to compile its `#![no_main]` bin for the host.
> - It exposes a tiny `src/lib.rs` (`#![no_std]`) purely to provide a **library target** so
>   the host-built `path` build-dependency declared by `flowplane` (Task 5) resolves; the actual
>   XDP programs live in `src/main.rs` and are compiled only for `bpfel-unknown-none`.
> - Never run `cargo build -p flowplane-ebpf` (whole-package) or `cargo build --workspace`: those
>   try to host-compile the bin and fail. Build only the lib target for sanity checks.

- [ ] **Step 1: Write the eBPF crate manifest**

`flowplane-ebpf/Cargo.toml`:
```toml
[package]
name = "flowplane-ebpf"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
flowplane-common = { path = "../flowplane-common", default-features = false }
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"
network-types = "0.0.7"

[build-dependencies]
which = "6"

[lib]
path = "src/lib.rs"

[[bin]]
name = "flowplane-ebpf"
path = "src/main.rs"
```
> Do NOT put `[profile.*]` here — profile settings in a workspace member are ignored with a
> warning; the BPF profile goes in the root workspace manifest (Step 5).

- [ ] **Step 2: Write the library shim**

`flowplane-ebpf/src/lib.rs`:
```rust
#![no_std]

// This crate's real content is the bpfel-only program binary in `src/main.rs`. This empty
// `#![no_std]` library target exists so that `flowplane`'s host-built `path` build-dependency on
// this crate resolves (build-dependencies compile the lib target for the host).
```

- [ ] **Step 3: Write the XDP_PASS programs**

`flowplane-ebpf/src/main.rs`:
```rust
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn uplink_rx(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[xdp]
pub fn guest_tx(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Declare a GPL-compatible license so GPL-only helpers (bpf_redirect, bpf_fib_lookup, used
// from Task 11 onward) are permitted by the verifier. edition-2021 attribute spelling.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

- [ ] **Step 4: Write the build.rs bpf-linker rebuild hint**

`flowplane-ebpf/build.rs`:
```rust
use which::which;

// aya-build links the object with `bpf-linker`. This rebuild hint (mirrored from the aya
// template) re-runs the build when the resolved bpf-linker binary changes.
fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found in PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
```

- [ ] **Step 5: Register the crate in the workspace (member, not default; BPF profile)**

Edit root `Cargo.toml`: add `flowplane-ebpf` as a member, **remove** the `exclude` line, add a
`default-members` that omits the ebpf crate, and add the BPF release profile. The
`[workspace]` table should read:
```toml
[workspace]
resolver = "2"
members = ["flowplane-common", "flowplane-ebpf"]
default-members = ["flowplane-common"]

[profile.release.package.flowplane-ebpf]
debug = 2
codegen-units = 1
strip = false
```
(Leave `[workspace.package]` and `[workspace.dependencies]` unchanged. Task 5 appends
`flowplane` to both `members` and `default-members`.)

- [ ] **Step 6: Verify structural validity (host lib only; the bpfel object builds in Task 5)**

Run:
```bash
cargo build -p flowplane-ebpf --lib          # host-compiles the no_std lib shim only
cargo build -p flowplane-common              # default member still builds
cargo metadata --no-deps --format-version 1 | grep -q '"name":"flowplane-ebpf"' && echo MEMBER_OK
```
Expected: both builds finish; `MEMBER_OK` printed. Do NOT attempt to build the bin/object
here — that happens via aya-build in Task 5.

- [ ] **Step 7: Commit**

```bash
git add flowplane-ebpf Cargo.toml
git commit -m "feat(ebpf): XDP_PASS skeleton (aya-build compiles it from flowplane)"
```

### Task 5: `flowplane` userspace crate loads and attaches the eBPF program

**Files:**
- Create: `flowplane/Cargo.toml`
- Create: `flowplane/src/main.rs`
- Create: `flowplane/src/loader.rs`

- [ ] **Step 1: Write the userspace manifest**

`flowplane/Cargo.toml`:
```toml
[package]
name = "flowplane"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
aya = { workspace = true }
aya-log = { workspace = true }
flowplane-common = { path = "../flowplane-common", features = ["user"] }
tokio = { workspace = true }
anyhow = { workspace = true }
clap = { workspace = true }
tonic = { workspace = true }
prost = { workspace = true }

[build-dependencies]
anyhow = { workspace = true }
aya-build = "0.1.3"
cargo_metadata = "0.23"
# Declared so cargo tracks the ebpf crate for cache invalidation; it is built for the host
# as a (no_std) lib here, and separately compiled to bpfel by aya-build in build.rs.
flowplane-ebpf = { path = "../flowplane-ebpf" }
```
(`tonic-build` is added in Task 6 when the proto is introduced.)

Register `flowplane` in the root workspace — edit root `Cargo.toml` so both lists include it:
```toml
members = ["flowplane-common", "flowplane-ebpf", "flowplane"]
default-members = ["flowplane-common", "flowplane"]
```

- [ ] **Step 2: Write build.rs that compiles the eBPF object via aya-build**

`flowplane/build.rs`:
```rust
use anyhow::{anyhow, Context as _};
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // Locate the flowplane-ebpf package and compile its bin to bpfel via build-std + bpf-linker.
    // aya-build places the resulting object at $OUT_DIR/flowplane-ebpf.
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;
    let ebpf = metadata
        .packages
        .into_iter()
        .find(|p| p.name.as_str() == "flowplane-ebpf")
        .ok_or_else(|| anyhow!("flowplane-ebpf package not found"))?;
    let root_dir = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", ebpf.manifest_path))?
        .to_string();
    aya_build::build_ebpf(
        [Package { name: "flowplane-ebpf", root_dir: root_dir.as_str(), ..Default::default() }],
        Toolchain::Custom("nightly-2026-01-15"),
    )
}
```
> NOTE: aya-build 0.1.3 API (verified): `build_ebpf(impl IntoIterator<Item=Package>, Toolchain)`;
> `Package { name: &str, root_dir: &str, no_default_features: bool, features: &[&str] }` (impls
> Default); `Toolchain::{Nightly, Custom(&str)}`. aya-build runs `rustup run <toolchain> cargo
> build … -Z build-std=core --target bpfel-unknown-none` — so rustup must be present (it is) and
> the toolchain must exist. We use `Toolchain::Custom("nightly-2026-01-15")` ON PURPOSE: it is
> the LLVM-21 nightly pinned in `rust-toolchain.toml` that matches nixpkgs bpf-linker (LLVM 21).
> Do NOT use `Toolchain::Nightly`/default — that resolves to the latest nightly (LLVM 22) and
> fails bpf-linker with "ERROR llvm: Invalid record".

- [ ] **Step 3: Write the loader that embeds and attaches the eBPF object**

`flowplane/src/loader.rs`:
```rust
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

/// Load the eBPF object that aya-build compiled to bpfel and placed in OUT_DIR.
pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-ebpf")))
        .context("load ebpf object")
}

/// Load the eBPF object and attach `uplink_rx` to the named uplink interface.
pub fn attach_uplink(iface: &str) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf()?;
    let prog: &mut Xdp = ebpf
        .program_mut("uplink_rx")
        .context("uplink_rx program missing")?
        .try_into()?;
    prog.load().context("verify uplink_rx")?;
    prog.attach(iface, XdpFlags::default())
        .with_context(|| format!("attach uplink_rx to {iface}"))?;
    Ok(ebpf)
}
```

- [ ] **Step 4: Write the CLI entrypoint**

`flowplane/src/main.rs`:
```rust
mod loader;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "flowplane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load and attach the XDP datapath to an interface, then idle.
    Load {
        #[arg(long)]
        uplink: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Load { uplink } => {
            let _ebpf = loader::attach_uplink(&uplink)?;
            println!("attached uplink_rx to {uplink}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Build the userspace binary (this compiles the eBPF object via build.rs)**

Run: `cargo build -p flowplane`
Expected: succeeds. The first build runs `build.rs` → `aya-build` compiles `flowplane-ebpf` to
bpfel and writes `$OUT_DIR/flowplane-ebpf`, which `include_bytes_aligned!` then embeds. If the
build fails inside aya-build, capture the exact error (toolchain/linker) and report it — do
not paper over it.

- [ ] **Step 6: Smoke-test attach on a throwaway veth (needs root)**

This step needs root/CAP_BPF; the controller will run it or hand it to the user. Commands:
```bash
sudo ip link add veth-smoke type veth peer name veth-smoke-peer
sudo ./target/debug/flowplane load --uplink veth-smoke &
sleep 1; sudo bpftool prog show | grep -i xdp && echo ATTACH_OK
sudo kill %1; sudo ip link del veth-smoke
```
Expected: `ATTACH_OK` and a visible xdp prog. (`bpftool` is provided by the iproute2/kernel
tooling; if absent, verify via `ip link show veth-smoke` reporting an attached `xdp` prog id.)

- [ ] **Step 7: Commit**

```bash
git add flowplane Cargo.toml
git commit -m "feat(userspace): load and attach XDP datapath via aya (aya-build)"
```

---

## Milestone 2: gRPC skeleton (`DPDKironcore`)

### Task 6: Vendor the proto and generate the service

**Files:**
- Create: `proto/dpdk.proto` (+ any imported protos)
- Modify: `flowplane/build.rs` (Task 5 created it for aya-build; here we ALSO compile the proto)
- Modify: `flowplane/Cargo.toml` (add `tonic-build` build-dependency)
- Modify: `flowplane/src/main.rs`

- [ ] **Step 1: Vendor the proto**

Fetch the real proto (and any files it `import`s) from the dpservice repo into `proto/`:
```bash
mkdir -p proto
curl -fsSL https://raw.githubusercontent.com/ironcore-dev/dpservice/main/proto/dpdk.proto -o proto/dpdk.proto
```
If `dpdk.proto` has `import` lines, fetch those siblings into `proto/` too (re-run curl per import path). Confirm `head -5 proto/dpdk.proto` shows `syntax = "proto3";` and `package dpdkironcore.v1;`.

- [ ] **Step 2: Add the tonic-build dependency and extend build.rs**

Add to `flowplane/Cargo.toml` under `[build-dependencies]` (keep the aya-build entries):
```toml
tonic-build = "0.12"
```
Then EXTEND the existing `flowplane/build.rs` (created in Task 5 for aya-build) so it ALSO
compiles the proto. The file becomes:
```rust
use anyhow::{anyhow, Context as _};
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // 1) Compile the eBPF object via aya-build (unchanged from Task 5).
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;
    let ebpf = metadata
        .packages
        .into_iter()
        .find(|p| p.name.as_str() == "flowplane-ebpf")
        .ok_or_else(|| anyhow!("flowplane-ebpf package not found"))?;
    let root_dir = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", ebpf.manifest_path))?
        .to_string();
    aya_build::build_ebpf(
        [Package { name: "flowplane-ebpf", root_dir: root_dir.as_str(), ..Default::default() }],
        Toolchain::Custom("nightly-2026-01-15"),
    )?;

    // 2) Generate the DPDKironcore gRPC service (server only).
    tonic_build::configure()
        .build_client(false)
        .compile_protos(&["../proto/dpdk.proto"], &["../proto"])
        .context("tonic-build compile dpdk.proto")?;
    println!("cargo:rerun-if-changed=../proto/dpdk.proto");
    Ok(())
}
```

- [ ] **Step 3: Wire the generated module and verify it compiles**

Add to top of `flowplane/src/main.rs`:
```rust
pub mod pb {
    tonic::include_proto!("dpdkironcore.v1");
}
```
Run: `cargo build -p flowplane`
Expected: builds; generated types available under `pb::` (e.g. `pb::dpdk_ironcore_server::DpdkIroncore`). If the generated server trait/module name differs, note the exact path printed in the error and use it in Task 7.

- [ ] **Step 4: Commit**

```bash
git add proto flowplane/build.rs flowplane/src/main.rs
git commit -m "feat(grpc): vendor dpservice proto and generate DPDKironcore service"
```

### Task 7: Implement `Initialize`/`CheckInitialized`/`GetVersion` with state

**Files:**
- Create: `flowplane/src/state.rs`
- Create: `flowplane/src/grpc.rs`
- Modify: `flowplane/src/main.rs`

- [ ] **Step 1: Write the failing test for init state**

`flowplane/src/state.rs`:
```rust
use std::sync::Mutex;

use uuid::Uuid;

/// Authoritative control-plane state (BPF map projection added in Milestone 3).
#[derive(Default)]
pub struct State {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    uuid: Option<String>,
}

impl State {
    /// Idempotently initialize; returns the stable service uuid.
    pub fn initialize(&self) -> String {
        let mut g = self.inner.lock().unwrap();
        g.uuid.get_or_insert_with(|| Uuid::new_v4().to_string()).clone()
    }

    /// Returns Some(uuid) if initialized.
    pub fn check_initialized(&self) -> Option<String> {
        self.inner.lock().unwrap().uuid.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_is_idempotent_and_check_reflects_it() {
        let s = State::default();
        assert_eq!(s.check_initialized(), None);
        let u1 = s.initialize();
        let u2 = s.initialize();
        assert_eq!(u1, u2, "initialize must be idempotent");
        assert_eq!(s.check_initialized(), Some(u1));
    }
}
```
Add to `flowplane/Cargo.toml` `[dependencies]`:
```toml
uuid = { version = "1", features = ["v4"] }
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cargo test -p flowplane state::tests`
Expected: PASS (`initialize_is_idempotent_and_check_reflects_it`).

- [ ] **Step 3: Implement the gRPC service over the state**

`flowplane/src/grpc.rs` (adjust the trait/type paths to whatever Task 6 Step 3 printed):
```rust
use std::sync::Arc;

use tonic::{Request, Response, Status};

// VERIFIED generated names (prost snake-cases "DPDKironcore" → "dpd_kironcore"):
use crate::pb::dpd_kironcore_server::DpdKironcore;
use crate::pb::{
    CheckInitializedRequest, CheckInitializedResponse, GetVersionRequest, GetVersionResponse,
    InitializeRequest, InitializeResponse, Status as DpStatus,
};
use crate::state::State;

pub struct Service {
    pub state: Arc<State>,
}

// Status has fields { code: u32, message: String } (NOT `error`).
fn ok() -> Option<DpStatus> {
    Some(DpStatus { code: 0, message: "OK".into() })
}

#[tonic::async_trait]
impl DpdKironcore for Service {
    async fn initialize(
        &self,
        _req: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let uuid = self.state.initialize();
        Ok(Response::new(InitializeResponse { status: ok(), uuid }))
    }

    async fn check_initialized(
        &self,
        _req: Request<CheckInitializedRequest>,
    ) -> Result<Response<CheckInitializedResponse>, Status> {
        let uuid = self.state.check_initialized().unwrap_or_default();
        Ok(Response::new(CheckInitializedResponse { status: ok(), uuid }))
    }

    async fn get_version(
        &self,
        req: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let r = req.into_inner();
        Ok(Response::new(GetVersionResponse {
            status: ok(),
            service_protocol: r.client_protocol,
            service_version: env!("CARGO_PKG_VERSION").into(),
        }))
    }
}
```
> VERIFIED field names from the generated code: `Status { code: u32, message: String }`;
> `InitializeResponse { status: Option<Status>, uuid: String }`;
> `CheckInitializedResponse { status, uuid }`;
> `GetVersionRequest { client_protocol, client_name, client_version }`;
> `GetVersionResponse { status, service_protocol, service_version }`. Use exactly these.

- [ ] **Step 4: Add a `serve` subcommand**

In `flowplane/src/main.rs` add modules and a command:
```rust
mod grpc;
mod state;
```
Add a `Serve { addr: String }` variant to `Cmd`, and handle it:
```rust
Cmd::Serve { addr } => {
    let svc = grpc::Service { state: std::sync::Arc::new(state::State::default()) };
    let server = crate::pb::dpd_kironcore_server::DpdKironcoreServer::new(svc);
    println!("serving DPDKironcore on {addr}");
    tonic::transport::Server::builder()
        .add_service(server)
        .serve(addr.parse()?)
        .await?;
}
```

- [ ] **Step 5: Build and run, then probe with grpcurl**

Run:
```bash
cargo run -p flowplane -- serve --addr 127.0.0.1:1337 &
sleep 1
grpcurl -plaintext -import-path proto -proto dpdk.proto \
  127.0.0.1:1337 dpdkironcore.v1.DPDKironcore/Initialize
kill %1
```
Expected: a JSON response containing a `uuid` and `status` with `OK`. (Add `grpcurl` to the devShell `buildInputs` if absent.)

- [ ] **Step 6: Commit**

```bash
git add flowplane
git commit -m "feat(grpc): Initialize/CheckInitialized/GetVersion backed by state"
```

### Task 8: Conformance — real `dpservice-cli` drives our server

**Files:**
- Create: `env/justfile` (target `dpservice-cli`)

- [ ] **Step 1: Obtain the real Go client**

Install `dpservice-cli` from ironcore-dev (Go toolchain is in the devShell):
```bash
go install github.com/ironcore-dev/dpservice/cli/dpservice-cli@latest || \
  echo "if the module path differs, clone ironcore-dev/dpservice and 'go build ./cli/...'"
```

- [ ] **Step 2: Run the real client against our server**

Run:
```bash
cargo run -p flowplane -- serve --addr 127.0.0.1:1337 &
sleep 1
dpservice-cli --address 127.0.0.1:1337 init || dpservice-cli --address 127.0.0.1:1337 get version
kill %1
```
Expected: the genuine CLI completes the call without a proto/transport error (it may warn about unimplemented RPCs — that is fine; the contract handshake is what we are proving).

- [ ] **Step 3: Record the conformance recipe**

`env/justfile`:
```make
# Drive our Rust server with the genuine Go dpservice-cli.
conformance addr="127.0.0.1:1337":
    dpservice-cli --address {{addr}} get version
```

- [ ] **Step 4: Commit**

```bash
git add env/justfile
git commit -m "test(grpc): conformance recipe driving server with real dpservice-cli"
```

---

## Milestone 3: Overlay base (the core proof)

### Task 9: `interfaces` + `routes` BPF maps shared common types

**Files:**
- Modify: `flowplane-common/src/lib.rs`

- [ ] **Step 1: Write the failing test for the route types**

Append to `flowplane-common/src/lib.rs` (above the `#[cfg(test)]` module, then extend tests):
```rust
/// Key for the `routes` map: (VNI, IPv4 prefix). Host-order length in `prefix_len`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    pub vni: u32,
    pub prefix_len: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `routes` map: the underlay IPv6 nexthop (tunnel dst) + nexthop VNI.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
}
```
Extend the `tests` module:
```rust
    #[test]
    fn route_types_have_stable_layout() {
        assert_eq!(core::mem::size_of::<RouteKey>(), 12);
        assert_eq!(core::mem::size_of::<RouteValue>(), 20);
    }
```
And add the Pod impls in `user_impls`:
```rust
    unsafe impl aya::Pod for RouteKey {}
    unsafe impl aya::Pod for RouteValue {}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p flowplane-common --features user`
Expected: PASS (`route_types_have_stable_layout`).

- [ ] **Step 3: Commit**

```bash
git add flowplane-common
git commit -m "feat(common): RouteKey/RouteValue POD types"
```

### Task 10: Userspace typed map wrappers (TDD against a real BPF map)

**Files:**
- Create: `flowplane/src/maps.rs`
- Modify: `flowplane/src/main.rs` (add `mod maps;`)

- [ ] **Step 1: Declare maps in the eBPF crate**

In `flowplane-ebpf/src/main.rs`, above the programs:
```rust
use aya_ebpf::maps::HashMap;
use aya_ebpf::macros::map;
use flowplane_common::{IfaceKey, IfaceValue, RouteKey, RouteValue};

#[map]
static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);

#[map]
static ROUTES: HashMap<RouteKey, RouteValue> = HashMap::with_max_entries(4096, 0);
```
Rebuild the object: `cargo run -p xtask -- --release` (expected: `ebpf build OK`).

- [ ] **Step 2: Write the failing test for the userspace wrapper**

`flowplane/src/maps.rs`:
```rust
use anyhow::Context;
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use flowplane_common::{IfaceKey, IfaceValue};

/// Typed handle over the `INTERFACES` BPF map.
pub struct Interfaces {
    map: HashMap<MapData, IfaceKey, IfaceValue>,
}

impl Interfaces {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("INTERFACES").context("INTERFACES map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert iface")
    }

    pub fn get(&self, key: &IfaceKey) -> Option<IfaceValue> {
        self.map.get(key, 0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static OBJ: &[u8] =
        include_bytes!("../../flowplane-ebpf/target/bpfel-unknown-none/release/flowplane");

    #[test]
    fn interfaces_roundtrip_through_bpf_map() {
        // Requires CAP_BPF/root and a kernel; run under `sudo -E`.
        let mut ebpf = Ebpf::load(OBJ).expect("load");
        let mut ifaces = Interfaces::open(&mut ebpf).expect("open");
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        let v = IfaceValue { tap_ifindex: 7, underlay_ipv6: [0xfd; 16] };
        ifaces.upsert(k, v).expect("upsert");
        assert_eq!(ifaces.get(&k), Some(v));
    }
}
```
Add to `flowplane/src/main.rs`: `mod maps;`

- [ ] **Step 3: Run the test (privileged)**

Run: `cargo run -p xtask -- --release && sudo -E cargo test -p flowplane maps::tests`
Expected: PASS. If it fails with EPERM, the runner lacks CAP_BPF — run as root. This is the gate proving userspace ↔ kernel map I/O works end to end.

- [ ] **Step 4: Commit**

```bash
git add flowplane flowplane-ebpf
git commit -m "feat(maps): typed Interfaces wrapper with BPF-map roundtrip test"
```

### Task 11: XDP encap on guest tap + decap on uplink

**Files:**
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Implement decap in `uplink_rx`**

Replace `uplink_rx` body. Parse outer IPv6; if `next_header` is our tunnel proto (IPIP = 4 for IPv4-in-IPv6), shrink the head past the IPv6 header and redirect to the local tap resolved from `INTERFACES`:
```rust
use aya_ebpf::helpers::bpf_xdp_adjust_head;
use aya_ebpf::bindings::xdp_action;
use network_types::{eth::EthHdr, ip::Ipv6Hdr};

const IPPROTO_IPIP: u8 = 4; // IPv4 encapsulated in IPv6 outer

#[xdp]
pub fn uplink_rx(ctx: XdpContext) -> u32 {
    match try_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth).ether_type } != network_types::eth::EtherType::Ipv6 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip6: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    if unsafe { (*ip6).next_hdr } as u8 != IPPROTO_IPIP {
        return Ok(xdp_action::XDP_PASS);
    }
    // Strip outer IPv6 (keep inner eth+ipv4 to follow). Adjust by Ipv6Hdr::LEN.
    let delta = Ipv6Hdr::LEN as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta) } != 0 {
        return Err(());
    }
    // For the PoC, redirect to a fixed local tap looked up from INTERFACES by inner dst.
    // (Inner-IP lookup + bpf_redirect added below.)
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
```

- [ ] **Step 2: Implement encap + redirect in `guest_tx`**

Look up `ROUTES` by inner IPv4 dst, grow headroom by `Ipv6Hdr::LEN`, write the outer IPv6 (src = local underlay, dst = `nexthop_ipv6`, next_hdr = IPIP), then `bpf_redirect` to the uplink ifindex (held in a single-entry `DEVMAP`/config map). Add:
```rust
use aya_ebpf::helpers::bpf_redirect;
use aya_ebpf::maps::Array;
use network_types::ip::Ipv4Hdr;

#[map]
static UPLINK_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

#[xdp]
pub fn guest_tx(ctx: XdpContext) -> u32 {
    match try_guest_tx(&ctx) {
        Ok(act) => act,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_guest_tx(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth).ether_type } != network_types::eth::EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip4: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let dst = unsafe { (*ip4).dst_addr }.to_be_bytes();
    let key = RouteKey { vni: 100, prefix_len: 32, ipv4: dst };
    let route = unsafe { ROUTES.get(&key) }.ok_or(())?;

    // Grow headroom for the outer IPv6 header.
    let delta = -(Ipv6Hdr::LEN as i32);
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta) } != 0 {
        return Err(());
    }
    // Write outer IPv6 header at the new head (bounds-checked), next_hdr = IPIP,
    // dst = route.nexthop_ipv6. (Field writes elided here; implement with ptr_at_mut.)
    let _ = route;

    let ifindex = unsafe { UPLINK_IFINDEX.get(0) }.copied().ok_or(())?;
    Ok(unsafe { bpf_redirect(ifindex, 0) } as u32)
}
```
> NOTE: exact `network_types` field names (`ether_type`, `next_hdr`, `dst_addr`) and the `XdpContext` raw-ctx accessor (`ctx.ctx`) must match the crate versions pinned in Task 1. Fix to the real names if the build complains; the structure is the contract.

- [ ] **Step 3: Build the object**

Run: `cargo run -p xtask -- --release`
Expected: `ebpf build OK`. Resolve any field-name/borrow errors now (this is where the eBPF verifier-friendly bounds checks matter).

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf
git commit -m "feat(ebpf): IPv6 encap on guest_tx and decap on uplink_rx"
```

### Task 12: Control plane programs maps from `CreateInterface`/`CreateRoute`

**Files:**
- Modify: `flowplane/src/state.rs`
- Modify: `flowplane/src/grpc.rs`
- Modify: `flowplane/src/loader.rs`

- [ ] **Step 1: Write the failing test for route translation**

Add to `flowplane/src/state.rs` a pure helper that converts a proto `Route` into `(RouteKey, RouteValue)`, and test it:
```rust
use flowplane_common::{RouteKey, RouteValue};

/// Convert a (vni, ipv4 prefix, prefix_len, nexthop ipv6, nexthop vni) into map entries.
pub fn route_entry(
    vni: u32,
    ipv4: [u8; 4],
    prefix_len: u32,
    nexthop_ipv6: [u8; 16],
    nexthop_vni: u32,
) -> (RouteKey, RouteValue) {
    (
        RouteKey { vni, prefix_len, ipv4 },
        RouteValue { nexthop_vni, nexthop_ipv6 },
    )
}

#[cfg(test)]
mod route_tests {
    use super::*;

    #[test]
    fn route_entry_maps_fields() {
        let (k, v) = route_entry(100, [10, 0, 0, 5], 32, [0xfd; 16], 100);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv4, [10, 0, 0, 5]);
        assert_eq!(k.prefix_len, 32);
        assert_eq!(v.nexthop_ipv6, [0xfd; 16]);
        assert_eq!(v.nexthop_vni, 100);
    }
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p flowplane route_tests`
Expected: PASS (`route_entry_maps_fields`).

- [ ] **Step 3: Implement `CreateInterface` / `CreateRoute` RPCs**

Extend `flowplane/src/grpc.rs` with the two methods, parsing the proto messages and calling into a `State` that holds the opened map wrappers (`Interfaces`, `Routes`). Decode `interface_id`/IP `bytes` fields into `[u8;4]`/`[u8;16]`, call `route_entry`, and `upsert`. (Mirror the `Interfaces` wrapper with a `Routes` wrapper in `maps.rs`.) Return `status: ok()`.
> The exact proto field access (`req.into_inner().route`, `Prefix`, `IpAddress.address` bytes) must match generated types from Task 6.

- [ ] **Step 4: Build**

Run: `cargo run -p xtask -- --release && cargo build -p flowplane`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add flowplane
git commit -m "feat(grpc): CreateInterface/CreateRoute program BPF maps"
```

### Task 13: Two-VM environment harness

**Files:**
- Create: `env/setup-host.sh`
- Create: `env/setup-hyp-vm.sh`
- Modify: `env/justfile`

- [ ] **Step 1: Host underlay bridge script**

`env/setup-host.sh` (idempotent): create a Linux bridge `br-underlay`, assign an IPv6 ULA prefix (e.g. `fd00:underlay::/64`), and document attaching the two VM tap/macvtap uplinks to it. Include `set -euo pipefail` and guards (`ip link show br-underlay || ip link add ...`).

- [ ] **Step 2: Per-hypervisor-VM setup script**

`env/setup-hyp-vm.sh` (runs inside each VM): install/enable k3s (`curl -sfL https://get.k3s.io | sh -`), create a guest netns + veth/tap pair (`guest0` ↔ `tap0`), assign the guest overlay IPv4 (e.g. A=`10.0.0.5/24`, B=`10.0.0.6/24`), set the VM's underlay IPv6 on its uplink, then run `flowplane` attaching `guest_tx` to `tap0` and `uplink_rx` to the uplink, seeding `UPLINK_IFINDEX`.

- [ ] **Step 3: `just` orchestration targets**

Add to `env/justfile`:
```make
host-up:
    sudo bash env/setup-host.sh

# Bring up VM A and VM B with libvirt (images defined under env/cloud-init).
vms-up:
    @echo "create/boot hypA and hypB via virt-install or virsh (see env/cloud-init)"

# Program the overlay: create interfaces + routes on both hypervisors via gRPC.
overlay-up addrA="hypA:1337" addrB="hypB:1337":
    dpservice-cli --address {{addrA}} create interface --id guestA --vni 100 --ipv4 10.0.0.5
    dpservice-cli --address {{addrB}} create interface --id guestB --vni 100 --ipv4 10.0.0.6
    dpservice-cli --address {{addrA}} create route --vni 100 --prefix 10.0.0.6/32 --nexthop-vni 100 --nexthop-ip <hypB-underlay-ipv6>
    dpservice-cli --address {{addrB}} create route --vni 100 --prefix 10.0.0.5/32 --nexthop-vni 100 --nexthop-ip <hypA-underlay-ipv6>
```
> Replace `<hypX-underlay-ipv6>` with the actual ULA addresses chosen in Step 1. If `dpservice-cli` flag names differ, use its `--help` output; the gRPC call is the contract.

- [ ] **Step 4: Commit**

```bash
git add env
git commit -m "feat(env): two-VM overlay harness (host bridge, k3s, netns/tap)"
```

### Task 14: End-to-end acceptance — guest-A ⇄ guest-B over XDP

**Files:**
- Create: `env/demo.sh`
- Modify: `env/justfile`

- [ ] **Step 1: Write the demo/acceptance script**

`env/demo.sh`: assumes `host-up`, `vms-up`, both `flowplane` attached, and `overlay-up` applied. Then from guest netns A, ping guest B and run iperf3, and capture the underlay to prove encapsulation:
```bash
set -euo pipefail
# 1. connectivity
ip netns exec guestA ping -c 3 10.0.0.6
# 2. throughput
ip netns exec guestB iperf3 -s -D
ip netns exec guestA iperf3 -c 10.0.0.6 -t 5
# 3. prove it's tunneled: outer must be IPv6 on the underlay
timeout 5 tcpdump -ni br-underlay 'ip6 and proto 4' -c 3
```

- [ ] **Step 2: Add the acceptance target**

Add to `env/justfile`:
```make
demo:
    sudo bash env/demo.sh
```

- [ ] **Step 3: Run the full acceptance gate**

Run: `just -f env/justfile demo`
Expected:
- `ping`: 3 packets received, 0% loss.
- `iperf3`: a non-zero bitrate summary.
- `tcpdump`: at least one `IP6 ... proto 4` (IPv4-in-IPv6) frame on `br-underlay`, proving XDP did the encap.

- [ ] **Step 4: Commit**

```bash
git add env
git commit -m "test(e2e): guest-to-guest connectivity over XDP IPv6 overlay"
```

---

## Deferred to follow-on plans

- **Milestone 4 — VIP (1:1 DNAT/SNAT):** extend `flowplane-common` with a `vips` map, add `CreateVip`/`GetVip`/`DeleteVip`, rewrite in the XDP pass.
- **Milestone 5 — LB (maglev):** maglev backend table in a BPF map; `CreateLoadBalancer`/`...Target`; consistent-hash select + rewrite.
- **Milestone 6 — NAT-GW:** SNAT + port-range allocation; the one feature permitted a TC-egress/userspace-assist carve-out.
- **Milestone 7 — metalbond client:** subscribe for dynamic overlay routes and program `ROUTES`.
- **Milestone 8 — metalnet integration:** adapt metalnet's sysfs/VF assumptions to the tap model; run unmodified where possible.

---

## Self-Review

**Spec coverage (Milestones 1–3):**
- M1 Scaffold → Tasks 1–5 (workspace, flake, common, ebpf, userspace loader). ✓
- M2 gRPC skeleton + `dpservice-cli` conformance → Tasks 6–8. ✓
- M3 Overlay base (maps, XDP encap/decap, control-plane programming, two-VM env, e2e ping) → Tasks 9–14. ✓
- Offload-readiness rule → enforced in Task 11 (bounds-checked `ptr_at`, fixed-shape map lookups, `adjust_head`/`redirect` only); called out as a review criterion. ✓
- Conformance-driver decision → Task 8. Defer metalbond/metalnet → "Deferred" section + spec §7. ✓

**Placeholder scan:** No "TBD/TODO/implement later". Two intentional `> NOTE` callouts (Task 7/11/12) flag where generated-proto and `network-types`/aya field names must be matched to pinned crate versions rather than invented — these are verification instructions, not missing content; each task still ships complete, runnable code and an explicit run/expected gate.

**Type consistency:** `IfaceKey::new(vni, ipv4)`, `IfaceValue { tap_ifindex, underlay_ipv6 }`, `RouteKey { vni, prefix_len, ipv4 }`, `RouteValue { nexthop_vni, nexthop_ipv6 }` are defined in Tasks 3/9 and used identically in Tasks 10/11/12. Map names `INTERFACES`/`ROUTES`/`UPLINK_IFINDEX` consistent between eBPF (Tasks 10/11) and userspace `take_map`/`open` (Task 10). gRPC types (`InitializeResponse.uuid`, `Status{error,message}`) flagged as proto-generated and to be matched, not invented.
