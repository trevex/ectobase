# M13 — HA Flow-State via Pinned Maps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the datapath **survive a control-plane restart/upgrade with zero flow loss** — the eBPF programs (and all their maps, including the live `CONNTRACK` state) stay kernel-resident via **pinned XDP links**, and a restarted control plane **adopts** the pinned `CONNTRACK` map to resume aging/management without re-attaching. This is the spec's pinned-maps HA model (§4.8), the cloud-cornerstone property that lets you upgrade the userspace agent without dropping connections.

**Architecture:** When started with `--pin-dir <bpffs-path>`, the first `bringup` attaches the XDP programs and **pins each link** (`XdpLink::pin`) to `<dir>/links/<name>`, and pins the `CONNTRACK` map (`Map::pin`) to `<dir>/CONNTRACK`. Because a pinned `bpf_link` holds a reference to its program, and a loaded program keeps all of its maps alive, the entire datapath + every map (conntrack, NAT, routes, …) survives the control-plane process exiting. On restart with `--adopt`, the control plane does **not** load or attach anything; it opens the pinned `CONNTRACK` via `Map::from_pin` and resumes the GC sweep. The datapath never stopped.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§4.8; milestone M13). Decision locked there: **pinned-maps model only** (no `0x88B5` sync protocol).

**Starting point (M1–M10 complete):** `loader::load_ebpf()` (`EbpfLoader` + env map-size overrides), `loader::attach_xdp(&mut ebpf, prog, iface)` / `attach_xdp_extra(...)` (attach, discard the `XdpLinkId` — link drops on `Ebpf` drop). `bringup` loads the object, attaches `uplink_rx` + `guest_tx`, programs maps, spawns `conntrack_gc::run(Conntrack, 10s)`, then idles on ctrl-c. `Conntrack::open(&mut Ebpf)` wraps `take_map("CONNTRACK")` into `aya::maps::HashMap<MapData, CtKey, CtEntry>` and offers `entries()`/`remove()`. 12 e2e tests; HA is opt-in (`--pin-dir`), so default behavior is unchanged.

## aya pinning APIs (verified)
- `aya::programs::Xdp::attach(iface, flags) -> XdpLinkId`; `Xdp::take_link(id) -> XdpLink`; `XdpLink::pin(path) -> PinnedLink`. Dropping a `PinnedLink` leaves the pin on bpffs (the attachment persists).
- `ebpf.map_mut(name) -> Option<&mut Map>`; `Map::pin(path) -> Result<(), PinError>`; `aya::maps::Map::from_pin(path) -> Result<Map, MapError>`.
- bpffs must be mounted at the pin dir's filesystem (`/sys/fs/bpf`). The pin dir must be unique per datapath instance (per hypervisor) to avoid name collisions.

## Design decisions locked for M13

- **Opt-in via `--pin-dir`.** No `--pin-dir` ⇒ today's behavior (links drop on exit; no pinning). With `--pin-dir`, the datapath is HA.
- **Pin the links, not every map.** Pinned links keep programs + all maps alive ⇒ full flow state survives. We additionally pin **only** `CONNTRACK` (the one map the restarted CP must re-acquire for GC). Config maps don't need re-acquiring (they persist via the links; a restart that wants to re-program them can re-attach instead of adopt).
- **`--adopt` skips load/attach** and opens the pinned `CONNTRACK` via `Map::from_pin`, then resumes GC and idles. Auto-detect is avoided to keep the lifecycle explicit (the operator/orchestrator knows whether it is a fresh start or an upgrade).
- **Dedicated `env/ha-smoke.sh`** (minimal 2-node setup) for the HA acceptance, keeping the 12-test `netns-e2e.sh` untouched and the HA lifecycle isolated. Teardown cleans the bpffs pins.

## File Structure

```
flowplane/src/
  loader.rs   # attach_xdp_pinned (pin link); pin_map helper; load with map adoption left default
  maps.rs     # Conntrack::from_pin(path)
  main.rs     # bringup: --pin-dir / --adopt lifecycle
env/ha-smoke.sh   # NEW: kill+restart-CP HA acceptance
```

---

## Task 1: Loader — pin XDP links + pin/open the conntrack map

**Files:** Modify `flowplane/src/loader.rs`, `flowplane/src/maps.rs`

- [ ] **Step 1: `attach_xdp_pinned` in `loader.rs`**
Read `loader.rs`. `attach_xdp` currently does `let prog: &mut Xdp = ebpf.program_mut(name).try_into()?; prog.load()?; prog.attach(iface, XdpFlags::default())?;` (discarding the link id). Add a pinned variant that pins the link so it survives `Ebpf` drop:
```rust
use std::path::Path;

/// Attach `prog` to `iface` and PIN the resulting XDP link to `<pin_dir>/links/<prog>-<iface>`,
/// so the attachment (and thus the program + all its maps) survives this process exiting.
pub fn attach_xdp_pinned(
    ebpf: &mut aya::Ebpf,
    prog: &str,
    iface: &str,
    pin_dir: &str,
    already_loaded: bool,
) -> anyhow::Result<()> {
    use aya::programs::{Xdp, XdpFlags};
    let p: &mut Xdp = ebpf
        .program_mut(prog)
        .with_context(|| format!("program {prog} missing"))?
        .try_into()?;
    if !already_loaded {
        p.load().with_context(|| format!("load {prog}"))?;
    }
    let id = p
        .attach(iface, XdpFlags::default())
        .or_else(|_| p.attach(iface, XdpFlags::SKB_MODE))
        .with_context(|| format!("attach {prog} to {iface}"))?;
    let link = p.take_link(id).context("take xdp link")?;
    let links_dir = format!("{pin_dir}/links");
    std::fs::create_dir_all(&links_dir).ok();
    let link_path = format!("{links_dir}/{prog}-{iface}");
    let _ = std::fs::remove_file(&link_path); // replace a stale pin from a prior run
    link.pin(Path::new(&link_path))
        .with_context(|| format!("pin link {link_path}"))?;
    Ok(())
}

/// Pin a loaded map to `<pin_dir>/<name>` (so a restarted control plane can re-acquire it).
pub fn pin_map(ebpf: &mut aya::Ebpf, name: &str, pin_dir: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(pin_dir).ok();
    let path = format!("{pin_dir}/{name}");
    let _ = std::fs::remove_file(&path);
    ebpf.map_mut(name)
        .with_context(|| format!("map {name} missing"))?
        .pin(Path::new(&path))
        .with_context(|| format!("pin map {path}"))?;
    Ok(())
}
```
(Ensure `anyhow::Context` is imported in `loader.rs`.)

- [ ] **Step 2: `Conntrack::from_pin` in `maps.rs`**
`Conntrack` wraps `HashMap<MapData, CtKey, CtEntry>`. Add:
```rust
    /// Adopt a previously-pinned CONNTRACK map (HA restart) instead of taking it from a loaded object.
    pub fn from_pin(path: &str) -> anyhow::Result<Self> {
        let map = aya::maps::Map::from_pin(path).context("open pinned CONNTRACK")?;
        let map = HashMap::try_from(map)?;
        Ok(Self { map })
    }
```
(`aya::maps::Map` + `from_pin` import as needed.)

- [ ] **Step 3: build + commit**
```bash
cargo build -p flowplane
cargo fmt --all
git add flowplane
git commit -m "feat(ha): loader pin-xdp-link + pin-map + Conntrack::from_pin"
```

## Task 2: Bringup `--pin-dir` / `--adopt` lifecycle

**Files:** Modify `flowplane/src/main.rs`

- [ ] **Step 1: CLI flags**
Add to the `Bringup` subcommand:
```rust
        /// Pin the XDP links + CONNTRACK under this bpffs dir so the datapath survives a control-
        /// plane restart (HA). Requires bpffs mounted (e.g. /sys/fs/bpf). Unset = non-HA (today).
        #[arg(long)]
        pin_dir: Option<String>,
        /// Adopt an already-running pinned datapath (after a restart): do NOT load/attach; just
        /// re-open the pinned CONNTRACK and resume aging. Requires --pin-dir.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        adopt: bool,
```
Destructure `pin_dir, adopt` in the `Cmd::Bringup { .. }` arm.

- [ ] **Step 2: Adopt path (early return)**
At the very top of the `Bringup` arm body (before `load_ebpf`), handle adopt:
```rust
            if adopt {
                let dir = pin_dir
                    .as_deref()
                    .context("--adopt requires --pin-dir")?;
                // The datapath (pinned links + maps) is already running in the kernel. Re-acquire
                // the pinned CONNTRACK and resume aging; do not load or attach anything.
                let ct = maps::Conntrack::from_pin(&format!("{dir}/CONNTRACK"))?;
                tokio::spawn(conntrack_gc::run(ct, std::time::Duration::from_secs(10)));
                println!("adopted pinned datapath at {dir}; resuming conntrack GC; ctrl-c to stop");
                tokio::signal::ctrl_c().await?;
                return Ok(());
            }
```

- [ ] **Step 3: First-start pinning**
In the normal `Bringup` body, when `pin_dir` is `Some`, use the pinned attach for the programs and pin CONNTRACK. The current attach loop calls `loader::attach_xdp(&mut ebpf, "uplink_rx", &uplink)` and `loader::attach_xdp`/`attach_xdp_extra` for `guest_tx`. Branch on `pin_dir`:
```rust
            // uplink_rx
            match pin_dir.as_deref() {
                Some(dir) => loader::attach_xdp_pinned(&mut ebpf, "uplink_rx", &uplink, dir, false)?,
                None => loader::attach_xdp(&mut ebpf, "uplink_rx", &uplink)?,
            }
            // guest_tx: load once (first guest), attach-only after
            for (idx, g) in guests.iter().enumerate() {
                let ifname = g.split('=').next().context("--guest ifname")?;
                match pin_dir.as_deref() {
                    Some(dir) => loader::attach_xdp_pinned(&mut ebpf, "guest_tx", ifname, dir, idx != 0)?,
                    None => {
                        if idx == 0 {
                            loader::attach_xdp(&mut ebpf, "guest_tx", ifname)?;
                        } else {
                            loader::attach_xdp_extra(&mut ebpf, "guest_tx", ifname)?;
                        }
                    }
                }
            }
```
(Adapt to the actual existing attach loop; `attach_xdp_pinned`'s `already_loaded` mirrors the `idx==0` load-once logic.) After all maps are programmed and just before/after spawning the GC, pin CONNTRACK when `pin_dir` is set:
```rust
            if let Some(dir) = pin_dir.as_deref() {
                loader::pin_map(&mut ebpf, "CONNTRACK", dir)?;
            }
```
IMPORTANT: when pinned, the `ebpf` object is still dropped at the end of `main` when the process exits — but the pinned links keep the programs+maps alive. So the process can exit (or be killed) and the datapath persists. The GC task + ctrl-c idle remain as today for the live process.

- [ ] **Step 4: build + a quick non-HA regression**
```bash
cargo build -p flowplane
./env/netns-e2e.sh run 2>&1 | tail -6   # 12 tests still pass (no --pin-dir => unchanged path)
```

- [ ] **Step 5: Commit**
```bash
cargo fmt --all
git add flowplane
git commit -m "feat(ha): bringup --pin-dir (pin links + CONNTRACK) and --adopt restart"
```

## Task 3: HA acceptance — `env/ha-smoke.sh`

**Files:** Create `env/ha-smoke.sh`

- [ ] **Step 1: Minimal 2-node setup + kill/restart scenario**
A focused script (model the netns-e2e structure: EXIT-trap teardown, `$BIN`, tcpdump optional) with two hypervisors (hypa/guesta 10.0.0.5, hypb/guestb 10.0.0.6) on a bridge, brought up **with `--pin-dir /sys/fs/bpf/flowplane-uA` (hypa) / `/sys/fs/bpf/flowplane-uB` (hypb)** and broadcast gateway-mac. Scenario:
```bash
# 1. up + verify guesta->guestb works.
# 2. start a sustained background ping guesta->guestb (e.g. ping -i 0.3, capture loss).
# 3. record hypa's bringup PID; kill it (SIGKILL). The pinned links keep hypa's datapath running.
# 4. while hypa's CP is DEAD, confirm guesta->guestb STILL works (the datapath survived).
# 5. restart hypa: `bringup ... --pin-dir /sys/fs/bpf/flowplane-uA --adopt` (re-acquires CONNTRACK).
# 6. confirm guesta->guestb still works after adopt; the sustained ping shows ~0 loss across the
#    kill+restart window.
# 7. teardown: kill procs, `sudo rm -rf /sys/fs/bpf/flowplane-uA /sys/fs/bpf/flowplane-uB`, del ns/bridge.
```
Concretely, the acceptance prints:
```
  HA: control-plane killed; datapath still forwarding (guesta -> guestb) -> SURVIVED
  HA: control-plane re-adopted pinned datapath; flows intact -> OK
```
Bound the check: a `ping -c N` issued WHILE hypa's CP is dead must succeed (proves kernel-resident datapath). Mount bpffs if needed: `sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true` at the top.

- [ ] **Step 2: Run + commit**
```bash
chmod +x env/ha-smoke.sh
./env/ha-smoke.sh run 2>&1 | tail -30   # SURVIVED + OK, clean teardown
git add env/ha-smoke.sh
git commit -m "test(ha): kill+restart control-plane; pinned datapath survives, CP re-adopts"
```

---

## Self-Review

**Spec coverage (§4.8 pinned-maps HA):**
- pin dynamic-state maps + adopt-on-restart → Tasks 1,2 (pin links keep ALL maps alive; pin+adopt CONNTRACK for GC). ✓
- loader adopts pinned maps idempotently → Task 2 (`--adopt`). ✓
- prove failover (kill+restart CP mid-flow; flows survive) → Task 3. ✓
- no `0x88B5` sync protocol → not implemented (per the spec decision). ✓

**Placeholder scan:** the `ha-smoke.sh` steps are concrete (kill PID, ping-while-dead, adopt, rm pins); bpffs mount handled. No TBD. Default (no `--pin-dir`) path is untouched → the 12-test lab is the regression gate (Task 2 Step 4).

**Type consistency:** `attach_xdp_pinned(ebpf, prog, iface, pin_dir, already_loaded)` + `pin_map(ebpf, name, pin_dir)` (Task 1) called from bringup (Task 2). `Conntrack::from_pin(path)` (Task 1) used by the `--adopt` arm (Task 2). Pin layout: links at `<dir>/links/<prog>-<iface>`, CONNTRACK at `<dir>/CONNTRACK` — consistent between pin (Task 2 first-start) and adopt (`from_pin(<dir>/CONNTRACK)`).

**Risk note:** the subtle kernel behavior — a pinned `bpf_link` keeps its program loaded, and a loaded program keeps its maps alive — is what makes "kill the CP, datapath survives" work; Task 3 Step 1's "ping while the CP is dead" is the direct proof. If the kernel uses netlink (not `bpf_link`) XDP, the attach persists anyway (netlink XDP isn't fd-bound), so the pinned-link approach is a superset. bpffs cleanup in teardown prevents a stale adopt on the next run.
