# Graceful Datapath Restart Implementation Plan

> **Context:** This is item #1 (graceful restart) of the 2026-07-16 hardening backlog — see the `review-hardening-backlog` memory. Branch: `hardening/resilience-security`. Foundation `UnderlayIpam::mark_used` already merged (6f2f089).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `flowplane` dataplane survive a process restart (DaemonSet roll / crash / OOM) without dropping the node's overlay datapath or reissuing a live guest underlay `/128`.

**Architecture:** Pin the *state* eBPF maps by name (load-time `LIBBPF_PIN_BY_NAME` via aya) so their contents survive a restart; on boot, `Serve` in `--pin-dir` mode ADOPTS the pinned maps, re-attaches the programs fresh (their links died with the old process), and rebuilds `Control`'s in-memory bookkeeping + `UnderlayIpam` by scanning the surviving maps. Program-array maps (`GUEST_PROGS*`) are deliberately NOT reused (they hold per-load program fds).

**Tech Stack:** Rust, aya 0.13.1 / aya-ebpf 0.1.1 (eBPF), tonic gRPC, containerlab kind fabric for live validation.

---

## Background & Key Facts (read before starting)

Current state (verified 2026-07-16):
- `Cmd::Serve` (production) accepts `--pin-dir` but **ignores it** (`pin_dir: _pin_dir` in `flowplane/src/main.rs`). It does NO pinning. A restart therefore drops every XDP/tc link and every map.
- `Cmd::Bringup` (lab) has partial pinning: `attach_xdp_pinned` (links) + `pin_map` for CONNTRACK only + `--adopt` re-opening `Conntrack::from_pin`. This is the pattern to generalize, but note the map-classification and program-array caveats below.
- eBPF maps are declared in `flowplane-ebpf/src/maps.rs` with `X::with_max_entries(n, flags)`. aya-ebpf also provides `X::pinned(n, flags)` (verified: `HashMap::pinned`, `LpmTrie::pinned` exist as `const fn`).
- aya userspace `EbpfLoader::map_pin_path(dir)` (verified `aya-0.13.1/src/bpf.rs:243`) makes a `pinned` map bind to `<dir>/<name>` if it already exists (reuse), else create+pin. **This is the ONLY mechanism that makes a freshly-loaded program use surviving maps.** Runtime `pin_map`/`Map::from_pin` does NOT — the reloaded program keeps its own fresh maps.
- aya userspace `HashMap` has `.iter()` and `.keys()` (verified `aya-0.13.1/src/maps/hash_map/hash_map.rs:66,72`). `Conntrack::entries()` already uses this pattern.
- `UnderlayIpam::mark_used(ip)` already exists (committed 6f2f089) for the rebuild.

### CRITICAL constraint: a `pinned` map ALWAYS needs a `map_pin_path`
If a map is declared `pinned` but the loader has no `map_pin_path`, aya errors at load. Every load path — production `Serve`, lab `Bringup`, the verifier anchor tests, the sim — must therefore set a `map_pin_path`. Solution: `load_ebpf()` gains a `pin_dir: &Path` parameter and always calls `loader.map_pin_path(pin_dir)`. Fresh/test runs pass a per-run temp dir (maps created+pinned there, behaves like today); production passes the persistent bpffs dir.

### Map classification (WHICH maps to pin)
PIN (state that must survive a restart — the veths/taps they reference persist across the flowplane restart, so their ifindex/tap values stay valid):
`INTERFACES, ROUTES, ROUTES6, PORT_META, LB, MAGLEV, CONNTRACK, NAT, NAT_IPS, VIPS, FW_RULES, FW_META, UNDERLAY, NEIGHBOR_NAT, NEIGHBOR_NAT_COUNT, METER, GUEST_DEV, DHCP_CONFIG, DHCP_META, CONFIG, LOCAL`

DO NOT PIN (must be rebuilt each load):
- `GUEST_PROGS`, `GUEST_PROGS_TC` — hold program fds that are invalid across a reload; re-populated by `register_guest_dhcp`/`register_guest_dhcp_tc`.
- `UPLINK_DEV` — a devmap holding the uplink ifindex; re-populated at uplink re-attach. (Safe either way, but rebuild is simplest.)
- `INSPECT` — debug-only.

> The classification is the crux. If unsure whether a map holds a per-load fd, DO NOT pin it — rebuild it. Getting this wrong (pinning a program array) silently breaks tail calls.

### Live validation is mandatory
Unit tests cannot catch a lifecycle regression. Every integration task ends with the kill-test protocol (Task 7). The clab fabric must be up (`hack/clab-up.sh`) with the netplane stack on k01.

---

## File Structure

- `flowplane-ebpf/src/maps.rs` — change the PINNED maps from `with_max_entries` to `pinned`. One responsibility: eBPF map declarations.
- `flowplane/src/loader.rs` — `load_ebpf(pin_dir)` sets `map_pin_path`; new `adopt_program(ebpf, name)` (attach-only, program already verified) is not needed — reuse existing attach helpers. One responsibility: load/verify/attach + pin plumbing.
- `flowplane/src/maps.rs` — add `iter_entries()` to the `Interfaces` and `Underlay` userspace wrappers (for the rebuild scan). One responsibility: userspace map wrappers.
- `flowplane/src/control.rs` — new `Control::adopt(...)` constructor + `rebuild_from_maps()` that repopulates `by_id`/`iface_underlay`/`next_table_id` and returns the set of `(interface_id, device)` to re-attach; `bring_up` gains a `pin_dir`. One responsibility: control-plane state.
- `flowplane/src/main.rs` — `Serve` honours `--pin-dir`: adopt-or-fresh, re-attach uplink + guests, rebuild IPAM. One responsibility: process wiring.
- `flowplane/src/attach.rs` — `AttachState` gains a way to seed `UnderlayIpam` from recovered addresses (uses `mark_used`). One responsibility: veth/netns/IPAM lifecycle.
- `test/scenario-restart.sh` (new) — the live kill-test harness. One responsibility: restart validation.

---

## Task 1: `load_ebpf` takes a pin dir and always sets `map_pin_path`

**Files:**
- Modify: `flowplane/src/loader.rs:24-45` (`load_ebpf`)
- Modify all callers: `flowplane/src/loader.rs:263-266` (`attach_uplink`), `flowplane/src/control.rs` (`bring_up` ~line 218), `flowplane/src/main.rs` (Serve/Bringup/TcBringup), `flowplane/src/loader.rs:333` (verifier test), any sim/anchor load.

- [ ] **Step 1: Change the signature to require a pin dir**

```rust
// loader.rs
use std::path::Path;

/// Load the eBPF object. `pin_dir` is where ByName-pinned maps live; it MUST be set because the
/// state maps are declared `pinned` (a pinned map with no map_pin_path fails to load). Fresh runs
/// pass a per-run dir (maps are created+pinned there); a restart passes the persistent dir so the
/// reloaded programs re-bind to the surviving maps.
pub fn load_ebpf(pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let mut loader = aya::EbpfLoader::new();
    loader.map_pin_path(pin_dir);
    for (map, var) in [
        ("CONNTRACK", "FLOWPLANE_CONNTRACK_MAX"),
        ("ROUTES", "FLOWPLANE_ROUTES_MAX"),
        ("INTERFACES", "FLOWPLANE_INTERFACES_MAX"),
        ("MAGLEV", "FLOWPLANE_MAGLEV_MAX"),
        ("NAT", "FLOWPLANE_NAT_MAX"),
        ("LB", "FLOWPLANE_LB_MAX"),
        ("PORT_META", "FLOWPLANE_PORT_META_MAX"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let n: u32 = v.parse().with_context(|| format!("{var} must be a u32, got {v:?}"))?;
            loader.set_max_entries(map, n);
        }
    }
    loader.load(bytes).context("load ebpf object")
}
```

- [ ] **Step 2: Update every caller to pass a pin dir**

For `attach_uplink`, thread a `pin_dir: &Path` param. For the verifier test (`loader.rs:333`) and any sim/anchor load, create a temp dir:
```rust
// In the verifier test both_programs_pass_verifier and any test load:
let pin_dir = tempfile::tempdir().expect("tempdir");
// use EbpfLoader::new().map_pin_path(pin_dir.path())...  (mirror load_ebpf)
```
Add `tempfile` to `flowplane` dev-dependencies if not present (`tempfile = "3"` in `[workspace.dependencies]` + `tempfile = { workspace = true }` under `[dev-dependencies]`).

- [ ] **Step 3: Build**

Run: `cargo build -p flowplane`
Expected: compiles (maps are still `with_max_entries`, so `map_pin_path` is a harmless no-op until Task 2).

- [ ] **Step 4: Run the verifier anchor to confirm loading still works with a pin path**

Run: `sudo -E cargo test -p flowplane --test anchor_uplink -- --ignored` (and `both_programs_pass_verifier`)
Expected: PASS (loading with a temp `map_pin_path` and unpinned maps is unaffected).

- [ ] **Step 5: Commit**

```bash
git add flowplane/src/loader.rs flowplane/src/control.rs flowplane/src/main.rs Cargo.toml flowplane/Cargo.toml Cargo.lock
git commit -m "refactor(loader): load_ebpf takes a pin dir + always sets map_pin_path"
```

---

## Task 2: Declare the state maps `pinned`

**Files:**
- Modify: `flowplane-ebpf/src/maps.rs` (the PIN list from the classification above)

- [ ] **Step 1: Change each PINNED map from `with_max_entries` to `pinned`**

Example diffs (apply to ALL maps in the PIN list, NOT to `GUEST_PROGS`, `GUEST_PROGS_TC`, `UPLINK_DEV`, `INSPECT`):
```rust
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::pinned(1024, 0);
pub static ROUTES: LpmTrie<RouteLpmData, RouteValue> = LpmTrie::pinned(65536, 1);
pub static UNDERLAY: HashMap<[u8; 16], UnderlayValue> = HashMap::pinned(4096, 0);
pub static GUEST_DEV: DevMapHash = DevMapHash::pinned(1024, 0);
pub static CONNTRACK: LruHashMap<CtKey, CtEntry> = LruHashMap::pinned(1_048_576, 0);
// ...and the rest of the PIN list. Keep GUEST_PROGS/GUEST_PROGS_TC/UPLINK_DEV/INSPECT as with_max_entries.
```
> Verify each map type exposes `pinned` (HashMap, LpmTrie, LruHashMap, DevMapHash, Array all do in aya-ebpf 0.1.1). If a type lacks `pinned`, leave that map `with_max_entries` and note it — do not invent an API.

- [ ] **Step 2: Rebuild the eBPF object**

Run: `cargo build -p flowplane`
Expected: the eBPF object compiles (aya-build reinvokes bpf-linker).

- [ ] **Step 3: Verify a fresh load pins the maps**

Run: `sudo -E cargo test -p flowplane --test anchor_uplink -- --ignored`
Expected: PASS. The anchor sets a temp `map_pin_path`; after load, `ls <tempdir>` shows the pinned map files (add a temporary `eprintln!` of the dir listing if unsure, then remove it).

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf/src/maps.rs
git commit -m "feat(ebpf): pin state maps by name (survive a dataplane restart)"
```

---

## Task 3: Iteration wrappers on `Interfaces` and `Underlay`

**Files:**
- Modify: `flowplane/src/maps.rs` (`Interfaces` wrapper ~line 15, `Underlay` wrapper ~line 395)
- Test: `flowplane/src/maps.rs` `#[cfg(test)]` (unit test with a MockableMap is impractical; instead validate in the Task 7 live test — mark this task's test as an integration assertion).

- [ ] **Step 1: Add `entries()` to `Interfaces`**

```rust
impl Interfaces {
    /// Snapshot every (key, value) — used at restart to rebuild by_id from the surviving map.
    pub fn entries(&self) -> Vec<(IfaceKey, IfaceValue)> {
        self.map
            .iter()
            .filter_map(|r| r.ok())
            .collect()
    }
}
```
(Mirror `Conntrack::entries()` at `flowplane/src/maps.rs:329` for the exact `self.map` field name and error handling.)

- [ ] **Step 2: Add `keys()` to `Underlay`**

```rust
impl Underlay {
    /// Every underlay /128 currently programmed — used at restart to rebuild UnderlayIpam.used.
    pub fn keys(&self) -> Vec<[u8; 16]> {
        self.map.keys().filter_map(|r| r.ok()).collect()
    }
}
```

- [ ] **Step 3: Build**

Run: `cargo build -p flowplane`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add flowplane/src/maps.rs
git commit -m "feat(maps): iteration wrappers on Interfaces/Underlay for restart rebuild"
```

---

## Task 4: `Control` adopt + rebuild-from-maps

**Files:**
- Modify: `flowplane/src/control.rs` (`bring_up` ~218, add `rebuild_from_maps`)

- [ ] **Step 1: Thread `pin_dir` into `bring_up` and split adopt-vs-fresh**

`bring_up` currently calls `load_ebpf()` then attaches uplink(s) then opens maps. Change it to:
1. Take `pin_dir: &Path` and `adopt: bool`.
2. Call `load_ebpf(pin_dir)`.
3. Always re-verify + re-attach the programs (uplink_rx to the uplink(s); guest programs are attached per-interface later). Programs are freshly loaded regardless — only maps are reused.
4. If `adopt`, call `rebuild_from_maps` to repopulate `by_id`/`iface_underlay`/`next_table_id`.

- [ ] **Step 2: Implement `rebuild_from_maps`**

```rust
impl Control {
    /// After adopting pinned maps on restart, repopulate the in-memory bookkeeping from the surviving
    /// INTERFACES map so DetachInterface/AddLb/etc. see the pre-restart state. Returns the list of
    /// (interface_id, device) whose guest program must be RE-ATTACHED (their links died with the old
    /// process). Also returns the recovered underlay /128s so the caller can seed UnderlayIpam.
    fn rebuild_from_maps(g: &mut Inner) -> anyhow::Result<(Vec<(Vec<u8>, String)>, Vec<[u8; 16]>)> {
        // NOTE: INTERFACES is keyed by (vni, ipv4) and does not store interface_id or device name.
        // The rebuild therefore needs interface_id -> device. Two options; pick during implementation:
        //   (a) Persist a small interface_id->(vni,ipv4,device,underlay) table in a NEW pinned map
        //       (e.g. IFACE_META keyed by a hash of interface_id) written in program_iface_maps.
        //   (b) Derive interface_id from the host veth naming convention (attach.rs host_veth_name)
        //       by scanning `ip link` for the h-<id> veths, then cross-referencing PORT_META[ifindex].
        // (a) is the robust choice — INTERFACES/PORT_META alone do NOT carry interface_id or device.
        todo!("implement per the chosen option; see Task 4 Step 3")
    }
}
```

- [ ] **Step 3: Add a pinned `IFACE_META` map to carry the rebuild keys (option a)**

The existing maps do NOT store `interface_id` or the device name, so a faithful rebuild needs them. Add a pinned map:
```rust
// flowplane-ebpf/src/maps.rs  (userspace-written, never read by the datapath — a control-plane journal)
#[map]
pub static IFACE_META: HashMap<IfaceMetaKey, IfaceMetaVal> = HashMap::pinned(1024, 0);
```
Define `IfaceMetaKey { id_hash: u64 }` and `IfaceMetaVal { vni, ipv4, ipv6, device_bytes: [u8; 16], device_len, underlay: [u8;16] }` in `flowplane-common`. Write it in `program_iface_maps` (Task 4 Step 4) and read it in `rebuild_from_maps`. `interface_id` itself can exceed the map value; store the full id in a second parallel structure keyed by id_hash if needed, or cap device/id length (document the cap).

> This is the one genuinely new persistent structure. If it feels heavy, the fallback is to have the AGENT re-drive AttachInterface for all NICs on this node after an flowplane restart (control-plane rebuild instead of dataplane journal) — see "Alternative" at the end. Decide before implementing Step 2/3.

- [ ] **Step 4: Write `IFACE_META` in `program_iface_maps`**

Add the `IFACE_META.upsert(...)` write alongside the existing PORT_META/INTERFACES/UNDERLAY writes in `program_iface_maps`, and the matching `remove` in `detach_interface`.

- [ ] **Step 5: Build + unit-test the rebuild parsing**

Add a unit test that constructs synthetic `IFACE_META` entries and asserts `rebuild_from_maps` produces the expected `(interface_id, device)` list and underlay set. (Pure parsing of the recovered structs — no BPF needed if you factor the pure part out.)

Run: `cargo test -p flowplane rebuild`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add flowplane/src/control.rs flowplane-ebpf/src/maps.rs flowplane-common/src/lib.rs
git commit -m "feat(control): adopt pinned maps + rebuild bookkeeping on restart"
```

---

## Task 5: `Serve` honours `--pin-dir` (adopt-or-fresh + re-attach)

**Files:**
- Modify: `flowplane/src/main.rs` (`Cmd::Serve` ~352-460)
- Modify: `flowplane/src/attach.rs` (`AttachState` gains `seed_ipam(addrs: &[[u8;16]])` calling `UnderlayIpam::mark_used`)

- [ ] **Step 1: Serve computes the pin dir (default + `--pin-dir`) and detects adopt**

```rust
// Default persistent bpffs dir; overridable by --pin-dir. adopt = the dir already has our pins.
let pin_dir = pin_dir.unwrap_or_else(|| "/sys/fs/bpf/flowplane".to_string());
std::fs::create_dir_all(&pin_dir).ok();
let adopt = std::path::Path::new(&pin_dir).join("INTERFACES").exists();
```

- [ ] **Step 2: bring_up in adopt-or-fresh mode, then re-attach uplink + guests**

```rust
let ctrl = Control::bring_up(&uplinks, std::path::Path::new(&pin_dir), adopt, /* other args */)?;
if adopt {
    // Programs were re-attached inside bring_up (uplink). Re-attach each guest program to its veth
    // and re-seed IPAM from the recovered underlay /128s.
    for (id, device) in ctrl.recovered_interfaces() {
        ctrl.reattach_guest(&id, &device)?; // wraps attach_tc_clsact_ingress_link / xdp guest_tx
    }
    attach.seed_ipam(&ctrl.recovered_underlays());
    log::info!("adopted pinned datapath at {pin_dir}: re-attached {} guests", ...);
}
```
`reattach_guest` mirrors the attach half of `create_interface` WITHOUT re-programming maps (they survived) and WITHOUT re-inserting bookkeeping (rebuild_from_maps already did) — it only re-creates the `GuestLink` and stores it in `g.links`.

- [ ] **Step 3: Build**

Run: `cargo build -p flowplane`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add flowplane/src/main.rs flowplane/src/attach.rs
git commit -m "feat(serve): adopt pinned datapath on restart (re-attach programs, reseed IPAM)"
```

---

## Task 6: SIGTERM = clean exit that PRESERVES pins

**Files:**
- Modify: `flowplane/src/main.rs` (Serve await)

- [ ] **Step 1: On SIGTERM, drop the tonic server but DO NOT unpin maps/links**

The whole point is that pins survive. Ensure the shutdown path (existing `ctrl_c().await`) does NOT call any unpin/cleanup on the pinned maps or the uplink link. Add a `tokio::signal::unix::SignalKind::terminate()` handler alongside ctrl_c so a `docker stop`/kubelet SIGTERM also exits cleanly (kubelet sends SIGTERM, not SIGINT).

```rust
let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
tokio::select! {
    _ = tokio::signal::ctrl_c() => {}
    _ = term.recv() => {}
}
log::info!("shutting down; pinned datapath preserved for adopt on restart");
```

- [ ] **Step 2: Build + commit**

Run: `cargo build -p flowplane`
```bash
git add flowplane/src/main.rs
git commit -m "feat(serve): handle SIGTERM (kubelet) with pin-preserving shutdown"
```

---

## Task 7: Live kill-test on the clab fabric (MANDATORY — the real acceptance test)

**Files:**
- Create: `test/scenario-restart.sh`

**Prereq:** `hack/clab-up.sh` up, netplane stack on k01, image rebuilt+loaded with Tasks 1-6 (`make image TAG=dev && kind load docker-image ghcr.io/trevex/ectobase/flowplane:dev --name k01 && kubectl -n ectobase-system rollout restart ds/flowplane`). The DS pod command must pass `--pin-dir /sys/fs/bpf/flowplane` AND mount a bpffs at that path (add a `hostPath`/`emptyDir` won't persist across pod restarts on the same node — use a bpffs mount; verify the DS spec pins to a path under a `bpffs` volume that survives container restart on the node).

- [ ] **Step 1: Attach a NAT pod (reuse scenario-nat-egress.sh setup) and confirm egress works**

Run the NAT egress scenario; confirm `wget http://1.1.1.1/` returns 301 and note the pod's underlay `/128` (e.g. `fd00:db8:0:2:8000::`).

- [ ] **Step 2: Kill the flowplane container (simulate a crash/roll) WITHOUT tearing down the pod netns**

```bash
CID=$(sudo docker exec k01-worker sh -c 'crictl ps | grep " flowplane " | awk "{print \$1}" | head -1')
sudo docker exec k01-worker crictl stop "$CID"   # kubelet restarts it -> Serve adopts
# wait for the new flowplane container to be Running and logs "adopted pinned datapath"
```

- [ ] **Step 3: Assert the datapath SURVIVED**

```bash
# The SAME pod's egress must work again with NO re-attach from the CNI:
sudo docker exec k01-worker ip netns exec natpod /busybox wget -T 8 -O /dev/null http://1.1.1.1/
```
Expected: 301 again. Verify via `bpftool map dump pinned /sys/fs/bpf/flowplane/UNDERLAY` that the pod's `/128` is still present, and `bpftool link` / `query_tcx` that a guest program is re-attached to the veth.

- [ ] **Step 4: Assert IPAM did NOT reissue the live `/128`**

Attach a SECOND pod after the restart and confirm its underlay is a DIFFERENT `/128` (e.g. `...8000::1`), never the first pod's — proving `mark_used` rebuilt the used-set from the surviving UNDERLAY map.

- [ ] **Step 5: Assert conntrack survived (bonus)**

An established TCP flow's conntrack entry should survive the restart (CONNTRACK is pinned) — a long-lived `nc` or `curl` kept open across the restart should not reset. (Best-effort; note if the SKB/clab harness interferes.)

- [ ] **Step 6: Commit the scenario + a note**

```bash
git add test/scenario-restart.sh
git commit -m "test(restart): live kill-test proving datapath survives an flowplane restart"
```

---

## Rollback / Risk

- Every task is behind `--pin-dir`/adopt; a fresh start (`adopt=false`) behaves exactly as today, so the change is dark until the DS opts in. Land the DS `--pin-dir` flip LAST (after Task 7 passes).
- If pinning a specific map breaks tail calls or verification, move it from PIN to DO-NOT-PIN and rebuild from the control plane instead. The program-array maps are the known hazard.
- If `rebuild_from_maps` proves too fragile (Task 4), fall back to the **Alternative** below — it is strictly simpler and reuses the reconcile work already merged.

## Alternative (simpler, if the map-journal rebuild is too heavy)

Instead of a dataplane `IFACE_META` journal, do a **control-plane rebuild**: on flowplane restart with adopted maps, the *agent* re-drives `AttachInterface` for every NetworkInterface scheduled to this node (it already lists them for reconcile). `create_interface` becomes idempotent against surviving maps (skip map writes that already match; only re-attach the program + re-commit bookkeeping). This trades a new pinned map for making attach idempotent, and leans on the steady-state reconcile loop already merged (commit 7c4d985). Evaluate both at Task 4; pick one, delete the other from the plan.

---

## Self-Review notes (author)

- Spec coverage: pinning (Task 2), adopt+rebuild (Task 4-5), IPAM rebuild (Task 5 + already-merged `mark_used`), SIGTERM (Task 6), live validation (Task 7) — all covered.
- Known open decision deliberately surfaced (not a placeholder): Task 4 IFACE_META journal vs Task-4-alt control-plane rebuild. Both are fully specified; the executor picks one at Task 4 and deletes the other. This is a real fork that needs a live spike to decide, hence left explicit.
- Type consistency: `load_ebpf(pin_dir)`, `bring_up(pin_dir, adopt)`, `rebuild_from_maps -> (Vec<(Vec<u8>,String)>, Vec<[u8;16]>)`, `recovered_interfaces()/recovered_underlays()/reattach_guest()`, `seed_ipam()/mark_used()` used consistently across Tasks 4-5.
