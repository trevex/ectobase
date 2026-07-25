# DPDK B2a: Host-Device Attach Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the DPDK `AttachInterface`/`DetachInterface` handlers stand up a container (veth) guest device — create the veth, IPAM the underlay /128, program the shared maps, register the device, and return the real response — reusing the eBPF device lifecycle behind a new shared `flowplane-device` crate.

**Architecture:** New pure `flowplane-device` crate (host device + IPAM via `ip`/`ip netns` subprocess) holding `UnderlayIpam` (moved verbatim from eBPF) + a bounded `create_veth_pair`. BOTH backends' container path routes through it (no drift). DPDK attach = shared device lifecycle → `ControlCore::program_interface` (existing seam) → new DPDK `PortRegistry` → real `AttachInterfaceResponse`. af_xdp bind/poll + guest traffic = B2b (deferred). eBPF-only `Tap`/`PodTap` stay in `attach.rs`.

**Tech Stack:** Rust, `ip`/`ip netns exec` subprocess, `flowplane-control` (`ControlCore::program_interface`, `IfaceParams`), tonic (`flowplane_node::pb`).

**Reference spec:** `docs/superpowers/specs/2026-07-25-dpdk-b2a-host-device-attach-design.md`

---

## File Structure

- `flowplane/flowplane-device/` — NEW crate: `Cargo.toml`, `src/lib.rs`, `src/underlay.rs` (moved verbatim), `src/veth.rs` (extracted device core)
- `Cargo.toml` (root) — add member
- `flowplane/flowplane/src/underlay.rs` — DELETED; importers repointed to `flowplane_device`
- `flowplane/flowplane/src/attach.rs` — Veth path routed through `flowplane_device::create_veth_pair`
- `flowplane/flowplane/Cargo.toml` — dep on `flowplane-device`
- `flowplane/flowplane-dpdk/src/node.rs` — `attach_interface`/`detach_interface` implemented (veth); `DpdkNodeService` gains attach state
- `flowplane/flowplane-dpdk/src/attach_state.rs` — NEW: `PortRegistry` + `DpdkAttachState` (IPAM + registry)
- `flowplane/flowplane-dpdk/Cargo.toml` — dep on `flowplane-device`
- `flowplane/flowplane-dpdk/src/serve.rs` — seed IPAM + build attach state, pass into `DpdkNodeService::new`

---

## Task 1: `flowplane-device` crate + move `underlay.rs`

**Files:**
- Create: `flowplane/flowplane-device/Cargo.toml`, `flowplane/flowplane-device/src/lib.rs`, `flowplane/flowplane-device/src/underlay.rs`
- Modify: root `Cargo.toml` (members); `flowplane/flowplane/Cargo.toml`; delete `flowplane/flowplane/src/underlay.rs`; repoint its importers in `flowplane/flowplane/src/*`

- [ ] **Step 1: Scaffold the crate**

Add `"flowplane/flowplane-device"` to `members` in root `Cargo.toml` (NOT default-members). Write `flowplane/flowplane-device/Cargo.toml` (read `flowplane/flowplane/Cargo.toml` for exact versions of `anyhow` + any deps `underlay.rs` uses — it uses `ipnet`/`Ipv6Net`; copy that dep's exact spec):

```toml
[package]
name = "flowplane-device"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "<copy from flowplane>"
# whatever underlay.rs needs (e.g. ipnet); copy exact specs from flowplane/Cargo.toml
```

`flowplane/flowplane-device/src/lib.rs`:
```rust
//! Host-device + underlay-IPAM plumbing shared by the eBPF `flowplane` and DPDK `flowplane-dpdk`
//! agents. Pure Linux plumbing (`ip`/`ip netns exec` subprocess) — no tonic, no eBPF, no DPDK.
pub mod underlay;
pub mod veth;

pub use underlay::{
    infer_underlay_address, infer_underlay_prefix, read_host_ifaddrs, IfAddr, UnderlayIpam,
};
pub use veth::{create_veth_pair, delete_link, DeviceInfo, VethSpec};
```

- [ ] **Step 2: Move `underlay.rs` verbatim + a stub `veth.rs`**

`git mv flowplane/flowplane/src/underlay.rs flowplane/flowplane-device/src/underlay.rs` (or copy then delete). Do NOT change its contents (it's pure). Its `#[cfg(test)] mod tests` moves with it. Create `flowplane/flowplane-device/src/veth.rs` as a stub (`//! veth lifecycle` + empty — filled in Task 2) so lib.rs compiles; temporarily comment the `pub use veth::…` line and the `pub mod veth;` if needed until Task 2, OR add minimal stub types. Simplest: in Task 1 make `veth.rs` just `//! doc` and remove the `veth` mod + re-export from lib.rs (add them in Task 2).

- [ ] **Step 3: Repoint eBPF importers, delete the old file**

`grep -rn 'crate::underlay\|mod underlay\|use crate::underlay' flowplane/flowplane/src/` — for each hit: change `crate::underlay::X` → `flowplane_device::X` (or `flowplane_device::underlay::X`), remove the `mod underlay;` line from `flowplane/flowplane/src/lib.rs` (or main.rs), and add `flowplane-device = { path = "../flowplane-device" }` to `flowplane/flowplane/Cargo.toml`. The old `flowplane/flowplane/src/underlay.rs` is now deleted (moved).

- [ ] **Step 4: Verify**

Run: `cargo test -p flowplane-device && cargo build -p flowplane`
Expected: flowplane-device builds + its moved underlay tests pass; flowplane still builds (importers repointed).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml flowplane/flowplane-device/ flowplane/flowplane/
git commit -m "feat(device): flowplane-device crate; move UnderlayIpam out of the eBPF crate"
```

---

## Task 2: `create_veth_pair` in `flowplane-device`

**Files:**
- Modify: `flowplane/flowplane-device/src/veth.rs`, `flowplane/flowplane-device/src/lib.rs` (add the `veth` mod + re-exports if deferred from Task 1)

The implementation is a verbatim extraction of the veth sequence in `flowplane/flowplane/src/attach.rs` (the `setup_veth` fn, ~lines 315–380, plus the `run`/`run_netns` helpers ~lines 553–585 and `fmt_mac`). Read those and transcribe.

- [ ] **Step 1: Write `veth.rs`**

```rust
//! Container guest-edge device lifecycle: create a veth pair, move the guest end into the pod
//! netns, configure both ends, and resolve the host ifindex. Extracted verbatim from the eBPF
//! `attach.rs` veth path so both backends share ONE implementation (no drift).

use anyhow::{Context, Result};
use std::process::Command;

/// What the caller wants stood up.
pub struct VethSpec {
    /// Host-side (root-netns) datapath device name, e.g. `veth-<id>`.
    pub host_name: String,
    /// Guest-side interface name inside the netns (the pod's eth0), e.g. `eth0`.
    pub guest_name: String,
    /// Target netns path, e.g. `/var/run/netns/<ns>`.
    pub netns_path: String,
    /// MAC applied to BOTH ends (see attach.rs rationale: local delivery addresses guest_mac).
    pub mac: [u8; 6],
    /// Guest + host link MTU (underlay MTU - encap overhead).
    pub mtu: u32,
    /// Disable guest tx-checksum offload (software-veth fabric only; see attach.rs).
    pub disable_csum_offload: bool,
}

/// Resolved device facts the caller programs into the maps + returns to the CNI.
pub struct DeviceInfo {
    pub host_ifindex: u32,
    pub host_name: String,
    pub mac: [u8; 6],
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

pub(crate) fn run(args: &[&str]) -> Result<()> {
    // Transcribe verbatim from attach.rs `fn run` (spawn `args[0]` with the rest, check status,
    // include stderr in the error). Do not change behavior.
    let out = Command::new(args[0]).args(&args[1..]).output().with_context(|| format!("spawn {args:?}"))?;
    anyhow::ensure!(out.status.success(), "{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

pub(crate) fn run_netns(netns_path: &str, args: &[&str]) -> Result<()> {
    // Transcribe verbatim from attach.rs `fn run_netns` (prefix with `nsenter --net=<path>` or
    // `ip netns exec` exactly as the original does). Match the original mechanism EXACTLY.
    let mut full: Vec<&str> = vec!["nsenter", "--net"]; // ADJUST to match attach.rs's exact form
    let netns_arg = format!("--net={netns_path}");
    full[1] = &netns_arg;
    full.extend_from_slice(args);
    run(&full)
}

/// Idempotent `ip link del <name>` (ignores "not found").
pub fn delete_link(name: &str) {
    let _ = run(&["ip", "link", "del", name]);
}

/// Read `/sys/class/net/<name>/ifindex`.
fn ifindex_of(name: &str) -> Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .with_context(|| format!("read ifindex of {name}"))?;
    s.trim().parse().with_context(|| format!("parse ifindex of {name}: {s:?}"))
}

/// Create + configure the veth pair, returning the resolved host device facts. Rolls back
/// (`delete_link(host)`) if any step fails. Transcribe the ip-command sequence VERBATIM from
/// attach.rs `setup_veth` (create pair → move peer to netns → rename → guest mac/up/mtu →
/// tcp_mtu_probing → optional ethtool csum-off → host mac/mtu/up), then resolve the host ifindex.
pub fn create_veth_pair(spec: &VethSpec) -> Result<DeviceInfo> {
    delete_link(&spec.host_name); // fresh start
    let host = &spec.host_name;
    let tmp_guest = format!("{host}p");
    let macs = fmt_mac(spec.mac);
    let mtu = spec.mtu.to_string();
    let result = (|| -> Result<u32> {
        run(&["ip", "link", "add", host, "type", "veth", "peer", "name", &tmp_guest]).context("create veth pair")?;
        run(&["ip", "link", "set", &tmp_guest, "netns", &spec.netns_path]).context("move guest veth into netns")?;
        run_netns(&spec.netns_path, &["ip", "link", "set", &tmp_guest, "name", &spec.guest_name]).context("rename guest veth")?;
        run_netns(&spec.netns_path, &["ip", "link", "set", &spec.guest_name, "address", &macs]).context("set guest veth mac")?;
        run_netns(&spec.netns_path, &["ip", "link", "set", &spec.guest_name, "up"]).context("guest veth up")?;
        run_netns(&spec.netns_path, &["ip", "link", "set", &spec.guest_name, "mtu", &mtu]).context("set guest veth mtu")?;
        let _ = run_netns(&spec.netns_path, &["sysctl", "-wq", "net.ipv4.tcp_mtu_probing=1"]);
        if spec.disable_csum_offload {
            let _ = run_netns(&spec.netns_path, &["ethtool", "-K", &spec.guest_name, "tx-checksum-ip-generic", "off"]);
        }
        run(&["ip", "link", "set", host, "address", &macs]).context("set host veth mac")?;
        run(&["ip", "link", "set", host, "mtu", &mtu]).context("set host veth mtu")?;
        run(&["ip", "link", "set", host, "up"]).context("host veth up")?;
        ifindex_of(host)
    })();
    match result {
        Ok(host_ifindex) => Ok(DeviceInfo { host_ifindex, host_name: spec.host_name.clone(), mac: spec.mac }),
        Err(e) => { delete_link(host); Err(e) }
    }
}
```
CRITICAL: `run` and `run_netns` MUST be transcribed to match `attach.rs`'s exact implementations (especially `run_netns`'s netns-entry mechanism — `nsenter --net=<path>` vs `ip netns exec <name>`; the original uses a PATH, so match that). Read attach.rs lines 553–585 and copy the mechanism exactly. If attach.rs's `fmt_mac` differs, copy that too.

- [ ] **Step 2: Write the tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_mac_lowercases_colon_separated() {
        assert_eq!(fmt_mac([0x02, 0, 0, 0, 0, 0x01]), "02:00:00:00:00:01");
    }

    #[test]
    fn ifindex_of_loopback_is_one() {
        // lo is ifindex 1 in every netns incl. the root — no privileges needed to read /sys.
        assert_eq!(ifindex_of("lo").unwrap(), 1);
    }

    #[test]
    #[ignore = "privileged: creates a veth pair + netns (needs CAP_NET_ADMIN); run under sudo"]
    fn create_veth_pair_stands_up_a_container_device() {
        // Make a throwaway netns.
        let ns = "fpdev-test-ns";
        let _ = run(&["ip", "netns", "del", ns]);
        run(&["ip", "netns", "add", ns]).unwrap();
        let netns_path = format!("/var/run/netns/{ns}");
        let spec = VethSpec {
            host_name: "fpdev-h0".into(),
            guest_name: "eth0".into(),
            netns_path: netns_path.clone(),
            mac: [0x02, 0, 0, 0, 0, 0x77],
            mtu: 1400,
            disable_csum_offload: false,
        };
        let info = create_veth_pair(&spec).expect("create veth");
        assert!(info.host_ifindex >= 2, "resolved a real host ifindex");
        assert_eq!(info.mac, spec.mac);
        // host end exists in root netns
        assert!(ifindex_of("fpdev-h0").is_ok(), "host end present");
        // guest end present in the netns with the requested name
        run_netns(&netns_path, &["ip", "link", "show", "eth0"]).expect("guest end in netns");
        // cleanup
        delete_link("fpdev-h0");
        let _ = run(&["ip", "netns", "del", ns]);
    }
}
```
(If Task 1 deferred the `veth` mod/re-exports in lib.rs, add `pub mod veth;` + the `pub use veth::…` line now.)

- [ ] **Step 3: Verify**

Run (unprivileged): `cargo test -p flowplane-device` — the 2 non-ignored tests pass.
Run (privileged): `sudo -E $(command -v cargo) test -p flowplane-device -- --ignored --test-threads=1` — `create_veth_pair_stands_up_a_container_device` passes.

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane-device/
git commit -m "feat(device): create_veth_pair — shared container device lifecycle"
```

---

## Task 3: Route the eBPF Veth path through `flowplane_device::create_veth_pair`

**Files:**
- Modify: `flowplane/flowplane/src/attach.rs`

- [ ] **Step 1: Replace the inlined veth creation with the shared call**

In `attach.rs`, the `Veth` arm of `attach()` currently calls the local `setup_veth(...)`. Replace that call with `flowplane_device::create_veth_pair(&VethSpec{ host_name, guest_name, netns_path, mac, mtu: self.guest_mtu, disable_csum_offload: self.disable_guest_csum_offload })` and use the returned `DeviceInfo` where the code needs the host name/ifindex/mac. DELETE the now-unused local `setup_veth` fn. KEEP `setup_tap` (Tap) and the PodTap path untouched. If `run`/`run_netns`/`fmt_mac` are now only used by the remaining Tap/PodTap paths, keep them; if they become unused, delete them (build must be warning-clean). Do NOT change any observable behavior of the container attach (same device names, MACs, MTU, sysctls).

- [ ] **Step 2: Verify eBPF build + existing attach tests unchanged**

Run: `cargo build -p flowplane 2>&1 | grep -E 'warning|error'` (expect none) and `cargo test -p flowplane` (baseline suite green — the node/attach unit tests). If `attach.rs` has privileged `#[ignore]` device tests, run them under sudo if present: `sudo -E $(command -v cargo) test -p flowplane attach -- --ignored` (only if such tests exist; skip if not).

- [ ] **Step 3: Commit**

```bash
git add flowplane/flowplane/src/attach.rs
git commit -m "refactor(ebpf): route the container veth path through flowplane-device (de-drift)"
```

---

## Task 4: DPDK `AttachInterface`/`DetachInterface` (veth)

**Files:**
- Create: `flowplane/flowplane-dpdk/src/attach_state.rs`
- Modify: `flowplane/flowplane-dpdk/Cargo.toml` (dep on flowplane-device), `flowplane/flowplane-dpdk/src/lib.rs` (add `mod attach_state;`), `flowplane/flowplane-dpdk/src/node.rs` (struct + handlers), `flowplane/flowplane-dpdk/src/serve.rs` (build + wire the state)

- [ ] **Step 1: `attach_state.rs` — PortRegistry + DpdkAttachState**

```rust
//! DPDK host-device attach state: the underlay /128 IPAM + the registry of attached guest devices
//! (what B2b will af_xdp-bind + poll). Guarded by a Mutex; the attach/detach handlers are the only
//! writers.
use std::collections::HashMap;
use std::sync::Mutex;

use flowplane_device::UnderlayIpam;

/// One attached container device (veth host end).
#[derive(Clone, Debug)]
pub struct AttachedDevice {
    pub host_ifindex: u32,
    pub host_name: String,
    pub netns_path: String,
}

/// Process-wide attach state: underlay IPAM (seeded from the node /64) + the interface_id → device
/// registry. B2b iterates `registry` to bind/poll each guest af_xdp port.
pub struct DpdkAttachState {
    pub ipam: Mutex<UnderlayIpam>,
    pub registry: Mutex<HashMap<Vec<u8>, AttachedDevice>>,
    /// Guest link MTU (underlay MTU - encap overhead) applied to created veths.
    pub guest_mtu: u32,
    /// Gateway addresses programmed into IfaceParams (overlay gateway the datapath answers for).
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
}

impl DpdkAttachState {
    pub fn register(&self, id: Vec<u8>, dev: AttachedDevice) {
        self.registry.lock().unwrap().insert(id, dev);
    }
    pub fn forget(&self, id: &[u8]) -> Option<AttachedDevice> {
        self.registry.lock().unwrap().remove(id)
    }
}
```

- [ ] **Step 2: Wire the state into `DpdkNodeService`**

In `node.rs`, add a field to `DpdkNodeService`: `attach: std::sync::Arc<crate::attach_state::DpdkAttachState>`, and add it as a `new(...)` parameter. In `serve.rs`, build a `DpdkAttachState`: seed `UnderlayIpam::new(prefix)` from `--local-underlay` (parse the `/64`; if unset, infer via `flowplane_device::infer_underlay_prefix(&flowplane_device::read_host_ifaddrs()?)`), set `guest_mtu` (from `--guest-mtu` or a default — mirror the eBPF default), gateway from `--gateway`/`--gateway-mac`-adjacent args, wrap in `Arc`, and pass to `DpdkNodeService::new(ctrl, shared, attach)`. Add `flowplane-device = { path = "../flowplane-device" }` to `flowplane-dpdk/Cargo.toml` and `mod attach_state;` to `lib.rs`.

- [ ] **Step 3: Implement `attach_interface` (veth only)**

Replace the current stub body (which programs stub IfaceParams then returns `Unimplemented`). New body: reject non-veth device_type; run the device lifecycle off the tokio thread (`tokio::task::spawn_blocking`, since `create_veth_pair` shells out) then program maps under the `ctrl` lock:

```rust
    async fn attach_interface(
        &self,
        req: Request<AttachInterfaceRequest>,
    ) -> Result<Response<AttachInterfaceResponse>, Status> {
        let r = req.into_inner();
        // B2a supports the container/veth device_type only.
        if !(r.device_type.is_empty() || r.device_type == "veth") {
            return Err(Status::invalid_argument(format!(
                "device_type {:?} not supported on DPDK yet (B2a = veth/container only)",
                r.device_type
            )));
        }
        let ipv4 = first_ipv4(&r.requested_ips);
        let ipv6 = first_ipv6(&r.requested_ips);
        let mac = if r.mac.is_empty() {
            // deterministic MAC from the interface id (mirror the eBPF `mac_for`)
            flowplane_dpdk::attach_state::mac_for(&r.interface_id)
        } else {
            parse_mac(&r.mac).map_err(|e| Status::invalid_argument(e.to_string()))?
        };
        let host_name = format!("veth-{}", short_id(&r.interface_id)); // mirror eBPF host_veth_name
        let guest_name = "eth0".to_string();
        let attach = self.attach.clone();
        // Underlay /128 from the pool.
        let underlay = {
            let mut ipam = attach.ipam.lock().unwrap();
            ipam.allocate().ok_or_else(|| Status::resource_exhausted("underlay /64 exhausted"))?.octets()
        };
        // Create the device off-thread (subprocess).
        let spec = flowplane_device::VethSpec {
            host_name: host_name.clone(),
            guest_name: guest_name.clone(),
            netns_path: r.netns_path.clone(),
            mac,
            mtu: attach.guest_mtu,
            disable_csum_offload: false, // real NIC finalizes csum; clab detection is a follow-up
        };
        let info = tokio::task::spawn_blocking(move || flowplane_device::create_veth_pair(&spec))
            .await
            .map_err(|e| Status::internal(format!("attach task panicked: {e}")))?
            .map_err(|e| Status::internal(format!("create veth: {e}")))?;
        // Program the shared maps with REAL device-resolved values.
        {
            let mut core = self.ctrl.lock();
            core.program_interface(IfaceParams {
                interface_id: r.interface_id.clone().into_bytes(),
                device: info.host_name.clone(),
                tap: info.host_ifindex,
                effective_mac: info.mac,
                vni: r.vni,
                ipv4,
                ipv6,
                gateway_ipv4: attach.gateway_ipv4,
                gateway_ipv6: attach.gateway_ipv6,
                underlay_ipv6: underlay,
                total_mbps: 0,
                public_mbps: 0,
            })
            .map_err(|e| Status::internal(e.to_string()))?;
            core.register_iface_meta(
                r.interface_id.clone().into_bytes(),
                IfaceMeta { vni: r.vni, ipv4, ipv6, underlay, ifindex: info.host_ifindex },
            );
        }
        attach.register(
            r.interface_id.clone().into_bytes(),
            crate::attach_state::AttachedDevice {
                host_ifindex: info.host_ifindex,
                host_name: info.host_name.clone(),
                netns_path: r.netns_path.clone(),
            },
        );
        Ok(Response::new(AttachInterfaceResponse {
            ifname: guest_name,
            ips: r.requested_ips,
            mac: fmt_mac_string(mac), // "aa:bb:.." — mirror how eBPF formats it
            gateway: String::new(),   // mirror eBPF: gateway string (fill from attach.gateway if eBPF does)
            underlay_route: std::net::Ipv6Addr::from(underlay).to_string(),
        }))
    }
```
Add the small helpers referenced (`mac_for`, `short_id`/`host_veth_name`, `fmt_mac_string`) — transcribe `mac_for`/`host_veth_name`/`fmt_mac` from `flowplane/src/attach.rs` (they are deterministic string/byte helpers). Put `mac_for`/`host_veth_name` in `attach_state.rs` (pub) and `fmt_mac_string` locally. IMPORTANT: read the eBPF `attach_interface`/`AttachOutcome` response build in `flowplane/src/attach.rs` and MATCH its `ifname`/`mac`/`gateway`/`underlay_route` formatting so the CNI sees the same shape from both backends.

- [ ] **Step 4: Implement the `detach_interface` device step**

Keep the existing map-purge + `forget_iface_meta`. Add: look up the registry entry; if present, `tokio::task::spawn_blocking(move || flowplane_device::delete_link(&host_name)).await`; then `attach.forget(&id)`. Return `Ok(Response::new(DetachInterfaceResponse{}))` (was `Unimplemented`). Missing device/entry is not an error.

- [ ] **Step 5: Integration test (dev; privileged for the device step)**

Add `flowplane/flowplane-dpdk/tests/attach_veth.rs`:
```rust
//! DPDK AttachInterface (veth) stands up a real container device + programs the shared maps + returns
//! the real response. Needs CAP_NET_ADMIN (creates a veth + netns); no EAL, no traffic. Run --ignored.
#![cfg(test)]
// Build a DpdkNodeService with an in-memory ControlCore (DpdkMapWriter over a SharedConfigMaps needs
// EAL, so this test uses the flowplane-control MemMapWriter path IF DpdkNodeService can be generic —
// otherwise gate behind EAL like generation_invalidation.rs). See NOTE below.
```
NOTE (test strategy — the implementer picks based on what compiles): `DpdkNodeService` is concrete over `DpdkMapWriter` (needs `SharedConfigMaps` → EAL). So the integration test must either (a) init a `--no-huge` EAL like `nfkit/tests/generation_invalidation.rs` and build the real `DpdkNodeService`, then call `attach_interface` and assert the response + a `registry` entry + that `program_interface` populated the maps (readable via `shared`/`ComposedMaps`); or (b) if that's too heavy, test the pure pieces directly: call `create_veth_pair` (Task 2 already covers it) and unit-test `DpdkAttachState`/`PortRegistry` register/forget + `mac_for`/`host_veth_name` determinism without the gRPC handler. Prefer (a) for a true end-to-end attach; fall back to (b) + a focused handler test if EAL-in-test is impractical. Whichever: assert the real `AttachInterfaceResponse` (non-empty ifname, underlay_route parses as the allocated /128) and that detach removes the registry entry + device.

- [ ] **Step 6: Verify**

Run: `cargo build -p flowplane-dpdk 2>&1 | grep -E 'warning|error'` (none); `cargo test -p flowplane-dpdk` (existing tests green); the new attach test per the chosen strategy (privileged under sudo if it creates a device).

- [ ] **Step 7: Commit**

```bash
git add flowplane/flowplane-dpdk/
git commit -m "feat(dpdk): AttachInterface stands up a container veth device (B2a)"
```

---

## Task 5: Final verification

- [ ] **Step 1: fmt + clippy**

Run: `cargo fmt --check -p flowplane-device -p flowplane-dpdk -p flowplane && cargo clippy -p flowplane-device -p flowplane-dpdk -p flowplane 2>&1 | grep -E '^(warning|error)(\[|:)' | grep -v 'flowplane@0.1.0' | grep -v too_many_arguments`
Expected: no fmt diff; no NEW clippy warnings (pre-existing `attach.rs` too_many_arguments allowed).

- [ ] **Step 2: Non-root suites unaffected (control/host-plane only)**

Run: `make test && make sim`
Expected: host tests + `flowplane-sim` 70 green — datapath/sim untouched.

- [ ] **Step 3: eBPF anchors unchanged**

Run: `make sim-anchor`
Expected: all anchors green (no datapath/eBPF-program change).

- [ ] **Step 4: Privileged device tests**

Run: `sudo -E $(command -v cargo) test -p flowplane-device -- --ignored --test-threads=1` and (if the DPDK attach test creates a device) the flowplane-dpdk attach test under sudo.
Expected: veth creation + DPDK attach (if strategy (a)) pass.

- [ ] **Step 5: Commit any fmt fixup**

```bash
git add -A && git commit -m "chore(device): fmt after B2a host-device attach"
```

---

## Self-Review Notes (author)

- **Spec coverage:** flowplane-device crate + underlay move (T1); create_veth_pair (T2); eBPF Veth de-drift (T3); DPDK attach/detach + PortRegistry + real response (T4); verification (T5). Tap/PodTap left eBPF-only (spec scope). af_xdp bind/poll deferred to B2b (not in any task). All spec sections mapped.
- **Scope:** container/veth only; ControlCore/datapath/eBPF programs/sim untouched; flowplane-device is pure (no tonic/eBPF/DPDK deps).
- **Type consistency:** `VethSpec`/`DeviceInfo`/`create_veth_pair`/`delete_link` (device crate); `DpdkAttachState`/`AttachedDevice`/`PortRegistry`(the HashMap)/`register`/`forget` (dpdk); `IfaceParams` fields match flowplane-control. Transcription risks (the `run_netns` netns mechanism, `mac_for`/`host_veth_name`/response formatting) are explicitly flagged in T2/T4 with instructions to copy from `attach.rs`.
- **Known risk:** the DPDK attach integration test may need an EAL (`--no-huge`) to build a real `DpdkNodeService`; T4 Step 5 gives a fallback (test the pure pieces) if that's impractical.
