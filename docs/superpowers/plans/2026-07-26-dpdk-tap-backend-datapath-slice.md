# DPDK TapBackend (VM guest port) — Datapath Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (fresh subagent per task + two-stage spec/quality review). Steps use `- [ ]` checkboxes.

**Goal:** Add a `TapBackend` implementation of the `GuestPortBackend` seam so a VM (qemu, via a tap fd) can be a guest of the DPDK af_xdp pool — the datapath slice, proven on this host with a raw `/dev/net/tun` fd (no KubeVirt).

**Architecture:** af_xdp binds the tap's kernel netdev (the pool port, in the serve netns); qemu/the test holds the tap char-device fd (the guest-facing side). Structurally parallel to `VethBackend` but MORE VF-like (a persistent tap survives the VM → `recover()` is a near-no-op). The datapath (`process_guest_tx`/rings/GC) is unchanged — it keys on the pool host ifindex regardless of backend kind. A `--guest-backend veth|tap` arg selects the pool backend kind per serve process.

**Tech Stack:** Rust, DPDK (nfkit af_xdp `Port`/`MbufPkt`), tap via iproute2 `ip tuntap` + `/dev/net/tun` `TUNSETIFF` ioctl (libc), `flowplane-device`, `flowplane-dpdk` `GuestPortBackend` seam, in-process EAL `--no-huge` tests (sudo).

**Spec:** `docs/superpowers/specs/2026-07-26-dpdk-tap-backend-datapath-slice-design.md`.

**Source-of-truth anchors (verify against current code; cite drift):**
- `flowplane-dpdk/src/port_backend.rs`: `GuestPortBackend` trait (`preallocate(index,mtu)->HostDevice`, `assign(host_ifname,&AssignTarget,mac,mtu)->Result`, `release(host_ifname,&AssignTarget)`, `is_alive(&GuestPortSlot)->bool`, `recover(&mut GuestPortSlot,pool_port_id)->Result<u32>`, `teardown(host_ifname)`); `AssignTarget { netns_path, guest_ifname }` (a STRUCT today — Task 3 converts it to an enum); `HostDevice { host_ifname, host_ifindex }`; `VethBackend` (impl to mirror — `preallocate` = `create_preallocated_veth("fpg{i}", 02:00:00:00:0e:<i>, mtu)`).
- `flowplane-dpdk/src/serve.rs`: `run()` constructs `let port_backend: Arc<dyn GuestPortBackend> = Arc::new(VethBackend { mtu: guest_mtu });` (~line 510-516); `guest_mtu` at ~510; `ServeArgs` clap struct (add `--guest-backend`); the af_xdp vdev list is built via `Backend::eal_args_lcores_with_guest_ifaces(prog, lcores, &guest_ifnames)` (nfkit/src/backend.rs) — a TAP netdev name works there identically to a veth name.
- `flowplane-dpdk/src/node.rs`: attach builds `AssignTarget { netns_path, guest_ifname }` + calls `backend.assign(...)`/`release(...)` via `spawn_blocking` (capturing an `Arc<dyn GuestPortBackend>` clone).
- `flowplane-device/src/veth.rs`: `pub fn run(args:&[&str])->Result<()>` (runs `ip ...`), `pub fn ifindex_of(name)->Result<u32>`, `pub fn mac_of(name)->Result<[u8;6]>`, `pub fn link_exists(name)->bool`, `pub fn delete_link(name)`, `fn fmt_mac`, `struct DeviceInfo{host_ifindex,host_name,mac}`. `flowplane-device/src/lib.rs` re-exports.
- Test templates: `nfkit/tests/afxdp_datapath.rs` + `multi_afxdp_port.rs` + `hotplug.rs` (af_xdp-on-netdev + EAL `--no-huge` + skip-77 idioms), `flowplane-dpdk/tests/attach_veth.rs` (backend/pool test), `nfkit/tests/guest_tx_datapath.rs`/`serve_e2e.rs` (datapath component patterns).

**Environment note (ALL tasks):** prior sudo runs may leave `target/` root-owned → `sudo chown -R "$(id -un):$(id -gn)" /home/nik/Development/ironcore-net-xdp/target` after any sudo run. Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Do NOT run git-mutating subagents in parallel. Do NOT merge/push per-task; finish the branch at the end.

---

## Task 1: DE-RISK GATE — af_xdp binds a tap netdev + fd round-trip (do FIRST)

**Goal:** Prove af_xdp binds a tap *netdev* and forwards a frame written to its *fd*, on this host. If this fails, the whole model is invalid — STOP and report BLOCKED (do not build the backend).

**Files:** Create `nfkit/tests/afxdp_tap.rs`. Possibly add `libc` to `nfkit`'s dev-dependencies (check `nfkit/Cargo.toml`; the test needs the `TUNSETIFF` ioctl).

- [ ] **Step 1: Write the de-risk test** (self-contained — creates the tap inline, does NOT depend on the not-yet-existing `flowplane-device::tap`). Skip (return) if `unsafe { libc::geteuid() } != 0`. Sequence:
  1. `std::process::Command`: `ip tuntap add dev fptaphp0 mode tap` (creates a PERSISTENT tap netdev), `ip link set fptaphp0 up` (delete any stale one first: `ip tuntap del dev fptaphp0 mode tap` ignoring errors). Use a guard to delete it at the end even on panic.
  2. Open the guest-facing fd: `open("/dev/net/tun", O_RDWR)`, then `ioctl(fd, TUNSETIFF, &ifreq)` with `ifr_name="fptaphp0"`, `ifr_flags = IFF_TAP | IFF_NO_PI` (attach to the existing persistent tap). `TUNSETIFF = 0x400454ca`, `IFF_TAP = 0x0002`, `IFF_NO_PI = 0x1000`. Build the 40-byte `ifreq` (16-byte name + flags) manually or via `libc::ifreq`. Keep the returned fd.
  3. `Eal::init(["fp-afxdp-tap","-l","0-1","--no-huge","-m","512","--vdev","net_af_xdp0,iface=fptaphp0,start_queue=0,queue_count=1","--file-prefix","fp_afxdp_tap"])`; `Mempool::new(...)`; `Port::configure(0, 1, &pool)` → assert up (n_queues>=1).
  4. **Guest→pool (fd write → af_xdp rx):** write a test Ethernet frame (`[dst 6][src 6][ethertype 0x0800][payload]`, ~64B) to the tap fd via `libc::write(fd, ...)` a few times (af_xdp copy-mode warmup drops — mirror afxdp_datapath.rs's inject-several-times). `RxQueue::rx` on port 0 in a poll loop (bounded, ~2s); assert a received mbuf's bytes match the written frame (byte-exact, allowing padding).
  5. **Pool→guest (af_xdp tx → fd read):** alloc an mbuf, write a distinct frame, `TxQueue::tx` on port 0; `libc::read(fd, ...)` in a bounded loop; assert the read bytes match. (Set the fd non-blocking or use a short timeout so the read loop is bounded.)
  6. Cleanup: drop Port, close fd, `ip tuntap del dev fptaphp0 mode tap`.
- [ ] **Step 2: Run — MUST pass under sudo.** `sudo -E $(command -v cargo) test -p nfkit --test afxdp_tap -- --test-threads=1 --nocapture 2>&1 | tail -30`. Expected: both directions round-trip. If af_xdp bind / Port::configure on the tap FAILS, or no frame round-trips, STOP and report BLOCKED with the exact error — the model is invalid (do NOT proceed to Task 2). Chown target/ back.
- [ ] **Step 3: Commit** — `test(nfkit): de-risk — af_xdp binds a tap netdev + fd round-trips (TapBackend gate)`.

---

## Task 2: `flowplane-device` tap helpers (`tap.rs`)

**Goal:** Factor the proven tap mechanics into reusable helpers, mirroring `veth.rs`.

**Files:** Create `flowplane-device/src/tap.rs`; export from `flowplane-device/src/lib.rs`. Add `libc` to `flowplane-device/Cargo.toml` if absent.

- [ ] **Step 1: Write failing helper tests** in `tap.rs` `#[cfg(test)]` (privileged, `#[ignore]`): `tap_create_persist_open_delete_roundtrips` — `create_persistent_tap("fpdevtap0", [0x02,0,0,0,0x0f,0x00], 1400)` → `link_exists("fpdevtap0")` true, `ifindex_of` Ok, `mac_of` matches; `open_tap_fd("fpdevtap0")` returns a usable `OwnedFd` (write a byte, no error); drop the fd → `link_exists` STILL true (persistent survives fd close); `delete_tap("fpdevtap0")` → `link_exists` false. Plus a non-privileged `open_tap_fd` on a bogus name returns `Err`.
- [ ] **Step 2: Run — expect FAIL** (fns don't exist): `cargo test -p flowplane-device 2>&1 | tail`.
- [ ] **Step 3: Implement `tap.rs`:**
```rust
//! Persistent tap-device lifecycle for the DPDK af_xdp guest-port pool (VM backend). The tap's
//! KERNEL NETDEV is af_xdp-bound as a pool port; its char-device FD (`open_tap_fd`) is the
//! guest-facing side handed to qemu. Mirrors `veth.rs`'s ip-command style; reuses run/ifindex_of/
//! mac_of/link_exists. A persistent tap SURVIVES an fd close (unlike a veth pair, which dies with
//! its peer) — the VF-like property TapBackend relies on.
use anyhow::{Context, Result};
use std::os::fd::OwnedFd;
use crate::veth::{run, ifindex_of, mac_of, link_exists, delete_link};   // reuse (make them pub(crate)/pub as needed)

/// Create a PERSISTENT tap netdev (survives fd close + process exit): `ip tuntap add ... mode tap`
/// → set mac/mtu/up. Idempotent (deletes a stale same-named tap first). Returns resolved facts.
pub fn create_persistent_tap(name: &str, mac: [u8;6], mtu: u32) -> Result<crate::veth::DeviceInfo> {
    delete_tap(name); // idempotent stale cleanup
    run(&["ip","tuntap","add","dev",name,"mode","tap"]).context("ip tuntap add")?;
    let macs = crate::veth::fmt_mac(mac);           // make fmt_mac pub(crate)
    run(&["ip","link","set",name,"address",&macs]).context("set tap mac")?;
    run(&["ip","link","set",name,"mtu",&mtu.to_string()]).context("set tap mtu")?;
    run(&["ip","link","set",name,"up"]).context("tap up")?;
    let host_ifindex = ifindex_of(name)?;
    Ok(crate::veth::DeviceInfo { host_ifindex, host_name: name.to_string(), mac })
}

/// Open the guest-facing char-device fd for an EXISTING persistent tap (`/dev/net/tun` +
/// `TUNSETIFF(name, IFF_TAP|IFF_NO_PI)`). This is the fd handed to qemu (the VM's NIC backend);
/// in the datapath slice the test holds it to simulate the VM.
pub fn open_tap_fd(name: &str) -> Result<OwnedFd> {
    // open /dev/net/tun O_RDWR; build ifreq{ ifr_name=name, ifr_flags=IFF_TAP|IFF_NO_PI };
    // ioctl(fd, TUNSETIFF, &ifreq); on success wrap the raw fd in OwnedFd. (TUNSETIFF=0x400454ca,
    // IFF_TAP=0x0002, IFF_NO_PI=0x1000.) Return Err with context on any failure.
}

/// Idempotent delete: `ip tuntap del dev <name> mode tap` (ignores "not found").
pub fn delete_tap(name: &str) { let _ = run(&["ip","tuntap","del","dev",name,"mode","tap"]); }
```
(Make `veth.rs`'s `fmt_mac` + `DeviceInfo` reachable — `pub(crate)`/`pub` as needed. `run`/`ifindex_of`/`mac_of`/`link_exists`/`delete_link` are already pub.) Export `create_persistent_tap`, `open_tap_fd`, `delete_tap` from `lib.rs`.
- [ ] **Step 4: Run — expect PASS** (privileged): `sudo -E $(command -v cargo) test -p flowplane-device -- --ignored --test-threads=1 2>&1 | tail`. Chown target/ back. Non-priv: `cargo test -p flowplane-device 2>&1 | tail` (the bogus-name test passes).
- [ ] **Step 5: Commit** — `feat(device): persistent tap helpers (create/open-fd/delete) for the DPDK VM backend`.

---

## Task 3: `TapBackend` on the `GuestPortBackend` seam + `AssignTarget` enum

**Goal:** Add `TapBackend` parallel to `VethBackend`; convert `AssignTarget` to an enum so tap (no netns) and veth are type-distinct; keep node.rs backend-agnostic.

**Files:** Modify `flowplane-dpdk/src/port_backend.rs` (`AssignTarget` enum, `assign_target` trait method, `TapBackend`), `flowplane-dpdk/src/node.rs` (build the target via the backend), `flowplane-dpdk/tests/attach_veth.rs` (update the `AssignTarget` construction if it builds one directly).

- [ ] **Step 1: Convert `AssignTarget` to an enum + add a builder trait method.**
```rust
pub enum AssignTarget {
    Veth { netns_path: String, guest_ifname: String },
    Tap  { guest_ifname: String },   // no netns — the tap netdev stays in the serve netns; qemu holds the fd
}
// add to the trait:
    /// Build the backend-appropriate AssignTarget from the attach inputs (keeps callers agnostic).
    fn assign_target(&self, netns_path: String, guest_ifname: String) -> AssignTarget;
```
`VethBackend::assign_target` → `AssignTarget::Veth { netns_path, guest_ifname }`. Update `VethBackend::assign`/`release` to `match target { AssignTarget::Veth{netns_path,guest_ifname} => <existing bind/unbind>, AssignTarget::Tap{..} => unreachable!("VethBackend got a Tap target") }`.
- [ ] **Step 2: Implement `TapBackend`:**
```rust
/// VM guest-port backend: a persistent tap netdev af_xdp-bound as a pool port; qemu holds the fd.
/// More VF-like than veth — the persistent tap survives the VM, so `recover` is a near-no-op.
pub struct TapBackend { pub mtu: u32 }
impl GuestPortBackend for TapBackend {
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice> {
        let host = format!("fpgtap{index}");
        let mac = [0x02,0x00,0x00,0x00,0x0f,index as u8];  // 0x0f family byte distinguishes tap pool from veth's 0x0e
        let d = flowplane_device::create_persistent_tap(&host, mac, mtu)?;
        Ok(HostDevice { host_ifname: d.host_name, host_ifindex: d.host_ifindex })
    }
    fn assign_target(&self, _netns_path: String, guest_ifname: String) -> AssignTarget {
        AssignTarget::Tap { guest_ifname }
    }
    fn assign(&self, _host_ifname: &str, target: &AssignTarget, _mac: [u8;6], _mtu: u32) -> Result<()> {
        // The tap netdev already exists + is up (preallocate). The guest-facing fd is opened by the
        // VM (qemu) / the test via flowplane_device::open_tap_fd(host_ifname) — NOT here. So assign is
        // a no-op for the slice beyond confirming the target kind. (The real qemu fd-handoff is the
        // deferred KubeVirt path.)
        match target { AssignTarget::Tap { .. } => Ok(()), AssignTarget::Veth { .. } => unreachable!("TapBackend got a Veth target") }
    }
    fn release(&self, _host_ifname: &str, _target: &AssignTarget) { /* tap persists; qemu owns the fd close */ }
    fn is_alive(&self, slot: &GuestPortSlot) -> bool { flowplane_device::link_exists(&slot.host_ifname) }
    fn recover(&self, slot: &mut GuestPortSlot, _pool_port_id: u16) -> Result<u32> {
        // Persistent tap SURVIVES the VM → near-no-op (the VF-like win). Only recreate if somehow gone.
        if !flowplane_device::link_exists(&slot.host_ifname) {
            let d = flowplane_device::create_persistent_tap(&slot.host_ifname,
                     [0x02,0,0,0,0x0f,(_pool_port_id.saturating_sub(1)) as u8], self.mtu)?;
            slot.host_ifindex = d.host_ifindex;
        }
        slot.dead = false;
        Ok(slot.host_ifindex)
    }
    fn teardown(&self, host_ifname: &str) { flowplane_device::delete_tap(host_ifname); }
}
```
- [ ] **Step 3: node.rs — build the target via the backend.** Where attach currently constructs `AssignTarget { netns_path, guest_ifname }`, call `let target = attach.backend.assign_target(r.netns_path.clone(), guest_name.clone());` and pass `&target` to `assign`/`release`. This keeps node.rs agnostic. Update `attach_veth.rs` similarly if it builds an `AssignTarget` directly (it likely goes through the backend already).
- [ ] **Step 4: Build + verify no veth regression.** `cargo build -p flowplane-dpdk 2>&1 | tail`; `cargo clippy -p flowplane-dpdk --all-targets 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1 2>&1 | tail -8` (veth path 6/6 — the enum conversion didn't break veth). Chown target/ back.
- [ ] **Step 5: Commit** — `feat(dpdk): TapBackend on the GuestPortBackend seam + AssignTarget enum (veth|tap)`.

---

## Task 4: Serve `--guest-backend veth|tap` selector

**Goal:** Select the pool backend kind at serve startup (one kind per process).

**Files:** Modify `flowplane-dpdk/src/serve.rs`.

- [ ] **Step 1: Add the clap arg** to `ServeArgs`: `#[arg(long = "guest-backend", value_enum, default_value_t = GuestBackendKind::Veth)] pub guest_backend: GuestBackendKind` with `#[derive(Copy,Clone,Debug,PartialEq,Eq,ValueEnum)] pub enum GuestBackendKind { Veth, Tap }`.
- [ ] **Step 2: Construct the backend by kind** where `run()` builds `port_backend`:
```rust
let port_backend: Arc<dyn GuestPortBackend> = match args.guest_backend {
    GuestBackendKind::Veth => Arc::new(VethBackend { mtu: guest_mtu }),
    GuestBackendKind::Tap  => Arc::new(TapBackend  { mtu: guest_mtu }),
};
```
Import `TapBackend`. Everything downstream (preallocate loop, `eal_args_lcores_with_guest_ifaces` with the returned `fpgtap{i}` names, attach/detach, worker) is unchanged — the af_xdp vdev binds a tap netdev name identically to a veth name.
- [ ] **Step 3: Unit test** the arg parses (`--guest-backend tap` → `GuestBackendKind::Tap`; default `Veth`) in `serve.rs` `#[cfg(test)] mod tests` (no EAL).
- [ ] **Step 4: Build + verify.** `cargo build -p flowplane-dpdk 2>&1 | tail`; `cargo clippy -p flowplane-dpdk 2>&1 | tail`; `cargo test -p flowplane-dpdk --lib 2>&1 | tail`; `make -C /home/nik/Development/ironcore-net-xdp sim 2>&1 | grep "test result" | tail -2`.
- [ ] **Step 5: Commit** — `feat(dpdk): --guest-backend veth|tap selects the pool backend at serve startup`.

---

## Task 5: Tap-backed datapath component test (guest→fabric + return over af_xdp-on-tap)

**Goal:** Prove the full guest-egress datapath runs over an af_xdp-on-tap pool port driven by a raw tap fd (simulating qemu).

**Files:** Create `nfkit/tests/tap_guest_datapath.rs` (or `flowplane-dpdk/tests/`), mirroring `nfkit/tests/guest_tx_datapath.rs` + the Task 1 tap harness.

- [ ] **Step 1: Write the test** (sudo, `--no-huge`, skip-77 unprivileged): `flowplane_device::create_persistent_tap("fpgtapd0", mac, 1450)`; EAL with `--vdev=net_af_xdp0,iface=fpgtapd0`; `Port::configure(0,1,&pool)`; build a `SharedConfigMaps` + `PerLcoreFlowMaps` → `ComposedMaps`; program the guest-tx fixture (PortMeta keyed by `ifindex_of("fpgtapd0")`, external route, NAT source, LOCAL, egress-allow fw — reuse the `guest_tx_datapath.rs` / `guest_tx_nat_return_handoff.rs` fixture constants). `open_tap_fd("fpgtapd0")` for the "VM side". Then:
  1. **guest→fabric:** write a guest IPv4 TCP frame to the tap fd (several times, warmup); `RxQueue::rx` port 0 in a bounded loop → wrap `MbufPkt` → `process_guest_tx(&mut pkt, &mut composed, &GuestTxIn{meta:&pm, src_ifindex: ifindex, now})` → assert `Redirect(uplink_ifindex)` + encap (frame grew 40, outer IPv6). (This proves the VM's frame reached the datapath over af_xdp-on-tap.)
  2. **fabric→guest (return):** build the matching decapped delivery frame (inner-eth dst = guest_mac), `TxQueue::tx` port 0, `read(fd)` in a bounded loop → assert the guest frame is delivered to the tap fd. (Proves the return path reaches the VM.)
  Clean up: drop Port, close fd, `delete_tap`.
- [ ] **Step 2: Run — MUST pass under sudo.** `sudo -E $(command -v cargo) test -p nfkit --test tap_guest_datapath -- --test-threads=1 --nocapture 2>&1 | tail -25`. Chown target/ back. If flaky on warmup, inject/poll more (mirror afxdp_datapath.rs). This is the slice's functional proof.
- [ ] **Step 3: Commit** — `test(dpdk): tap-backed guest datapath — process_guest_tx over af_xdp-on-tap via a raw fd`.

---

## Task 6: Final verification + docs + finish

- [ ] `make check` (0), `make sim`/`make test` green, `cargo build -p flowplane-dpdk -p nfkit -p flowplane-device` clean; ALL privileged tests pass under sudo (afxdp_tap, tap_guest_datapath, the flowplane-device tap tests, + no regression on attach_veth/serve_e2e/the existing suite). Chown target/ back.
- [ ] Update `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` "Remaining follow-ups": TapBackend datapath slice DONE (af_xdp-on-tap guest port for VMs, `--guest-backend tap`); the KubeVirt binding-plugin/CNI wiring + real-qemu e2e + fd-handoff-to-pod-netns remain the follow-up.
- [ ] Commit docs. Then finish the branch (superpowers:finishing-a-development-branch) — merge to main + push per the usual pattern.

## Notes / risks
- **Task 1 (de-risk) is the gate** — if af_xdp-on-tap doesn't round-trip on this host, STOP (the model is invalid); do not build Tasks 2-5.
- The `TUNSETIFF` ioctl (`open_tap_fd`) is the only raw-syscall part; everything else is `ip tuntap`/`ip link` (reuses veth.rs's `run`). Constants: `TUNSETIFF=0x400454ca`, `IFF_TAP=0x0002`, `IFF_NO_PI=0x1000`.
- `recover` is a near-no-op for tap (persistent tap survives) — the deliberate contrast with `VethBackend::recover` (hotplug rebind). Document it.
- Slice = one backend kind per serve process; mixed veth+tap pools + the KubeVirt control-plane + real-qemu e2e are deferred (documented).
- Sequence: Task 1 (gate) → 2 (device helpers) → 3 (backend+enum) → 4 (serve selector) → 5 (datapath test) → 6 (finish).
