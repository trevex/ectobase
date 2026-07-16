# Link-Pinning for Zero-Downtime Datapath Restart — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an xdp-dp process restart (crash/OOM/liveness-kill/`crictl stop`/rolling upgrade) cause **zero** forwarding gap by pinning the eBPF program links to bpffs and atomically re-pointing them at the freshly-loaded program on adopt.

**Architecture:** Extends the merged graceful-restart work (pinned maps + `IFACE_META` adopt, commits `127e021`→`169dd7f`). Programs are attached via fd-owned links (XDP `bpf_link`; tc via **tcx** on kernel ≥ 6.6). We pin those links under `<pin_dir>/links/` so they outlive the process; on restart we re-open each with `PinnedLink::from_pin` and call `Xdp/SchedClassifier::attach_to_link` — an atomic `bpf_link_update` that swaps in the new process's program with no packet gap (Cilium's mechanism). Gated by `--pin-links` (default on); `--pin-links=false` is the exact revert to today's fresh re-attach.

**Tech Stack:** Rust, aya 0.13.1 (`FdLink::pin`, `PinnedLink::from_pin/unpin`, `Xdp::attach_to_link`, `SchedClassifier::attach_to_link`), containerlab kind fabric for live validation.

**Spec:** `docs/superpowers/specs/2026-07-16-link-pinning-zero-downtime-restart-design.md`

---

## Background & Key Facts (read before starting)

- Today `Serve` attaches: `uplink_rx` via `loader::attach_xdp` (control.rs:238, link dropped into the ebpf object → detaches on exit); extra uplinks via `attach_xdp_extra` (control.rs:479); `wan_rx` via `attach_xdp` (control.rs:457); guests via `attach_tc_clsact_ingress_link`/`attach_xdp_link`, held in `Inner.links: HashMap<Vec<u8>, GuestLink>` and dropped on `detach_interface` (control.rs:438-448, 622).
- `GuestLink` (control.rs:25-30) = `Xdp(XdpLink)` | `Tc(SchedClassifierLink)`.
- An existing `attach_xdp_pinned` (loader.rs) already pins an XDP link (`XdpLink` → `FdLink` → `FdLink::pin`) — the pattern to generalize. It's used only by the lab `Bringup` path today.
- aya kernel-version behavior: `SchedClassifier::attach(iface, Ingress)` uses **tcx** (`BPF_TCX_INGRESS`, an `FdLink`) on kernel ≥ 6.6, else netlink `cls_bpf`. Our nodes are 7.0.11.
- `Xdp::attach_to_link(link: XdpLink)` and `SchedClassifier::attach_to_link(link: SchedClassifierLink)` are public and do `bpf_link_update` (atomic replace). `PinnedLink::from_pin(path) -> PinnedLink`; `FdLink: From<PinnedLink>` (so `pinned.into()`); `FdLink::pin(path) -> PinnedLink`; `XdpLink: TryFrom<FdLink>` and `SchedClassifierLink: TryFrom<FdLink>` (so `fd.try_into()` — the tc TryFrom requires `BPF_LINK_TYPE_TCX`). `XdpLink: TryInto<FdLink>` for the pin path (as existing `attach_xdp_pinned` uses).
- **Task 0 spike result (validated on kernel 7.0.11):** guest tc attach yields a **tcx `FdLink`** (pinnable); XDP attach yields a pinnable `FdLink`; `from_pin → try_into → attach_to_link` succeeds and **the bpffs pin survives `attach_to_link`** (zero-gap re-point confirmed). So the netlink-fallback branch is not exercised on our kernels.
- **tcx attachments appear in `bpftool net show` (`tc:` section), NOT in `tc filter show … ingress`.**
- The `--pin-dir` flag already exists on `Serve` (main.rs:131-132, destructured at 363). `serve_pin_dir` is computed at main.rs:382. Guest re-attach on adopt is `main.rs` adopt block (`control.reattach_guest`) + `control.rs::reattach_guest`.

### Pinned-link lifecycle (the model this plan implements)
- **Attach (pin-links on):** attach program → get link → `FdLink::pin(<pin_dir>/links/<name>)`. The bpffs pin keeps the program attached after the process exits. We do **not** need to hold the link handle for the uplink/wan (the pin owns lifetime); for a **guest** we track the pin **path** so detach can unpin it.
- **Adopt:** `PinnedLink::from_pin(path)` → into `XdpLink`/`SchedClassifierLink` → `new_prog.attach_to_link(link)` (atomic swap to new bytecode) → the bpffs pin remains valid, now referencing the new program.
- **Detach (guest):** remove the bpffs pin file (unpin) → program detaches from the veth.
- **Clean shutdown:** do nothing to the pins (they must survive for the next process to adopt).

---

## File Structure

- `xdp-dp/src/loader.rs` — new link helpers: `attach_xdp_pinned_at`, `attach_tc_pinned_at`, `readopt_xdp_link`, `readopt_tc_link`, `unpin_link`. One responsibility: attach/pin/re-adopt/unpin eBPF links.
- `xdp-dp/src/control.rs` — `bring_up`/`attach_edge`/`attach_extra_uplink`/`create_interface`/`reattach_guest`/`detach_interface` honour a `pin_links: bool`; `Inner` gains `pin_links`, `pin_dir: PathBuf`, and guest link-pin tracking. One responsibility: control-plane attach/detach + adopt wiring.
- `xdp-dp/src/main.rs` — `Serve` gains `--pin-links` (default true) and threads it in. One responsibility: process wiring.
- `test/scenario-restart.sh` — extend with the uplink zero-gap assertion + fix the guest check to `bpftool net show`. One responsibility: live restart validation.
- `xdp-dp/tests/spike_link_pin.rs` (throwaway, deleted after Task 0) — validates the aya pin/re-adopt/attach_to_link API on a scratch veth.

---

## Task 0: Spike — validate pin → from_pin → attach_to_link on this kernel (throwaway)

De-risks the exact aya API + confirms guest tc is a pinnable tcx `FdLink` here, before wiring into the datapath. This task writes a throwaway root test, records findings inline in the plan, and is reverted at the end.

**Files:**
- Create (throwaway): `xdp-dp/tests/spike_link_pin.rs`

- [ ] **Step 1: Write the spike**

```rust
// xdp-dp/tests/spike_link_pin.rs — THROWAWAY (deleted at end of Task 0).
// Run: sudo -E cargo test -p xdp-dp --test spike_link_pin -- --ignored --nocapture
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{tc, Link, SchedClassifier, TcAttachType, Xdp, XdpFlags};

#[test]
#[ignore = "root/CAP_BPF + creates a scratch veth"]
fn xdp_pin_readopt_attach_to_link() {
    // scratch veth pair
    let _ = std::process::Command::new("ip").args(["link","add","spk0","type","veth","peer","name","spk1"]).status();
    let pin = tempfile::Builder::new().prefix("spike-").tempdir_in("/sys/fs/bpf").unwrap();
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut ebpf = aya::EbpfLoader::new().map_pin_path(pin.path()).load(bytes).unwrap();

    // attach uplink_rx to spk0, pin the link
    let link_path = pin.path().join("uplink-spk0");
    {
        let p: &mut Xdp = ebpf.program_mut("uplink_rx").unwrap().try_into().unwrap();
        p.load().unwrap();
        let id = p.attach("spk0", XdpFlags::SKB_MODE).unwrap();
        let link = p.take_link(id).unwrap();
        let fd: FdLink = link.try_into().unwrap();
        fd.pin(&link_path).unwrap();          // bpffs now owns the attachment
    }
    // re-open the pin and atomically re-point it at a freshly (re)loaded program
    {
        let pinned = PinnedLink::from_pin(&link_path).unwrap();
        let fd: FdLink = pinned.into();         // PinnedLink -> FdLink
        let xlink: aya::programs::xdp::XdpLink = fd.into();
        let p: &mut Xdp = ebpf.program_mut("uplink_rx").unwrap().try_into().unwrap();
        let new_id = p.attach_to_link(xlink).unwrap();   // <-- atomic bpf_link_update
        let _held = p.take_link(new_id).unwrap();
        // NOTE: record whether the bpffs pin file still exists here and whether `bpftool net show`
        // shows exactly ONE xdp prog on spk0 (no duplicate) — that is the zero-gap invariant.
    }
    let _ = std::process::Command::new("ip").args(["link","del","spk0"]).status();
}

#[test]
#[ignore = "root/CAP_BPF + creates a scratch veth; confirms guest tc is a pinnable tcx FdLink"]
fn tc_is_tcx_fdlink_and_pins() {
    let _ = std::process::Command::new("ip").args(["link","add","spk2","type","veth","peer","name","spk3"]).status();
    let pin = tempfile::Builder::new().prefix("spike-").tempdir_in("/sys/fs/bpf").unwrap();
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut ebpf = aya::EbpfLoader::new().map_pin_path(pin.path()).load(bytes).unwrap();
    let _ = tc::qdisc_add_clsact("spk2");
    let link_path = pin.path().join("guest-spk2");
    {
        let p: &mut SchedClassifier = ebpf.program_mut("tc_guest_tx").unwrap().try_into().unwrap();
        p.load().unwrap();
        let id = p.attach("spk2", TcAttachType::Ingress).unwrap();
        let link = p.take_link(id).unwrap();
        // KEY ASSERTION: on kernel >=6.6 this is a tcx FdLink and converts; if it fails, we're on
        // netlink cls_bpf and guest link-pinning is unavailable (fall back to re-attach for guests).
        let fd: FdLink = link.try_into().expect("guest tc link is a tcx FdLink (kernel >=6.6)");
        fd.pin(&link_path).unwrap();
    }
    {
        let pinned = PinnedLink::from_pin(&link_path).unwrap();
        let fd: FdLink = pinned.into();
        let tlink: aya::programs::tc::SchedClassifierLink = fd.into();
        let p: &mut SchedClassifier = ebpf.program_mut("tc_guest_tx").unwrap().try_into().unwrap();
        let new_id = p.attach_to_link(tlink).unwrap();
        let _held = p.take_link(new_id).unwrap();
    }
    let _ = std::process::Command::new("ip").args(["link","del","spk2"]).status();
}
```

- [ ] **Step 2: Run the spike as root**

Run: `sudo -E cargo test -p xdp-dp --test spike_link_pin -- --ignored --nocapture`
Then chown back: `sudo chown -R "$(id -un):$(id -gn)" target`
Expected: both tests PASS. If `try_into::<FdLink>()` on the tc link fails, RECORD IT — guests use the fallback (Task 5 note) and only uplink/wan get zero-gap.

- [ ] **Step 3: Confirm the exact type conversions compile**

The precise conversions used above (`FdLink: From<PinnedLink>` vs `PinnedLink::unpin()`, `XdpLink: From<FdLink>`, `SchedClassifierLink: From<FdLink>`) are what Tasks 1–5 depend on. If any differ (e.g. `PinnedLink::unpin()` instead of `Into<FdLink>`), NOTE the working form here; Tasks 1–5 use whatever compiled in the spike.

- [ ] **Step 4: Record findings + delete the spike**

Append findings (tc is/ isn't tcx FdLink; the exact conversion calls) as a comment block at the top of `xdp-dp/src/loader.rs` in Task 1. Then:
```bash
git rm -f xdp-dp/tests/spike_link_pin.rs 2>/dev/null || rm -f xdp-dp/tests/spike_link_pin.rs
```
(No commit for the spike itself.)

---

## Task 1: loader.rs link helpers (attach+pin, re-adopt, unpin)

**Files:**
- Modify: `xdp-dp/src/loader.rs`

- [ ] **Step 1: Add the helpers (use the exact conversions validated in Task 0)**

```rust
// loader.rs — add near attach_xdp_pinned. `<pin_dir>/links/<name>` is the link pin path.
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{SchedClassifier, Xdp};

fn link_pin_path(pin_dir: &Path, name: &str) -> std::path::PathBuf {
    pin_dir.join("links").join(name)
}

/// Attach an already-loaded XDP `prog` to `iface` and pin the link to `<pin_dir>/links/<name>` so it
/// survives this process exiting. The bpffs pin owns the attachment; the caller need not hold a handle.
pub fn attach_xdp_pinned_at(
    ebpf: &mut Ebpf, prog: &str, iface: &str, pin_dir: &Path, name: &str,
) -> anyhow::Result<()> {
    let p: &mut Xdp = ebpf.program_mut(prog).with_context(|| format!("{prog} missing"))?.try_into()?;
    let id = if std::env::var_os("XDP_DP_SKB_MODE").is_some() {
        p.attach(iface, aya::programs::XdpFlags::SKB_MODE)
            .with_context(|| format!("attach {prog} to {iface} (SKB_MODE)"))?
    } else {
        p.attach(iface, aya::programs::XdpFlags::default())
            .or_else(|_| p.attach(iface, aya::programs::XdpFlags::SKB_MODE))
            .with_context(|| format!("attach {prog} to {iface}"))?
    };
    let fd: FdLink = p.take_link(id)?.try_into()
        .map_err(|_| anyhow::anyhow!("XDP link is not an FdLink (kernel < 5.9?)"))?;
    let path = link_pin_path(pin_dir, name);
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let _ = std::fs::remove_file(&path);
    fd.pin(&path).with_context(|| format!("pin xdp link {}", path.display()))?;
    Ok(())
}

/// Re-open a pinned XDP link and atomically re-point it at (a freshly-loaded) `prog` — no gap.
/// Returns true if the pin existed (adopted); false if absent (caller attaches fresh).
pub fn readopt_xdp_link(ebpf: &mut Ebpf, prog: &str, pin_dir: &Path, name: &str) -> anyhow::Result<bool> {
    let path = link_pin_path(pin_dir, name);
    if !path.exists() { return Ok(false); }
    let pinned = PinnedLink::from_pin(&path).with_context(|| format!("from_pin {}", path.display()))?;
    let fd: FdLink = pinned.into();
    let xlink: aya::programs::xdp::XdpLink = fd.try_into()
        .map_err(|_| anyhow::anyhow!("pinned link at {} is not an XDP link", path.display()))?;
    let p: &mut Xdp = ebpf.program_mut(prog).with_context(|| format!("{prog} missing"))?.try_into()?;
    let id = p.attach_to_link(xlink).with_context(|| format!("attach_to_link {prog}"))?;
    let _ = p.take_link(id); // held by the process; the bpffs pin persists the attachment
    Ok(true)
}

/// tc analogues (tcx FdLink). If Task 0 found tc is NOT an FdLink on this kernel, these return an
/// error the caller treats as "fall back to fresh re-attach".
pub fn attach_tc_pinned_at(
    ebpf: &mut Ebpf, prog: &str, iface: &str, pin_dir: &Path, name: &str,
) -> anyhow::Result<()> {
    let _ = aya::programs::tc::qdisc_add_clsact(iface);
    let p: &mut SchedClassifier = ebpf.program_mut(prog).with_context(|| format!("tc {prog} missing"))?.try_into()?;
    let id = p.attach(iface, aya::programs::TcAttachType::Ingress)
        .with_context(|| format!("attach {prog} to {iface}"))?;
    let fd: FdLink = p.take_link(id)?.try_into()
        .map_err(|_| anyhow::anyhow!("tc link is not a tcx FdLink (kernel < 6.6); pinning unavailable"))?;
    let path = link_pin_path(pin_dir, name);
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let _ = std::fs::remove_file(&path);
    fd.pin(&path).with_context(|| format!("pin tc link {}", path.display()))?;
    Ok(())
}

pub fn readopt_tc_link(ebpf: &mut Ebpf, prog: &str, pin_dir: &Path, name: &str) -> anyhow::Result<bool> {
    let path = link_pin_path(pin_dir, name);
    if !path.exists() { return Ok(false); }
    let pinned = PinnedLink::from_pin(&path).with_context(|| format!("from_pin {}", path.display()))?;
    let fd: FdLink = pinned.into();
    let tlink: aya::programs::tc::SchedClassifierLink = fd.try_into()
        .map_err(|_| anyhow::anyhow!("pinned link at {} is not a tcx link", path.display()))?;
    let p: &mut SchedClassifier = ebpf.program_mut(prog).with_context(|| format!("tc {prog} missing"))?.try_into()?;
    let id = p.attach_to_link(tlink).with_context(|| format!("attach_to_link {prog}"))?;
    let _ = p.take_link(id);
    Ok(true)
}

/// Remove a link pin (detaches the program). Used on guest detach.
pub fn unpin_link(pin_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(link_pin_path(pin_dir, name));
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p xdp-dp`
Expected: compiles. (Adjust the `From`/`try_into` conversions to whatever Task 0 validated.)

- [ ] **Step 3: Commit**

```bash
git add xdp-dp/src/loader.rs
git commit -m "feat(loader): pinned-link helpers (attach+pin, readopt via attach_to_link, unpin)"
```

---

## Task 2: `Serve` gains `--pin-links` (default true), threaded to Control

**Files:**
- Modify: `xdp-dp/src/main.rs` (Serve arg + bring_up call)
- Modify: `xdp-dp/src/control.rs` (`bring_up` signature + `Inner` fields)

- [ ] **Step 1: Add the flag to `Cmd::Serve`**

In `xdp-dp/src/main.rs`, in the `Serve { … }` variant (near `pin_dir` at line 131-132), add:
```rust
        /// Pin program links to bpffs so a restart keeps the datapath attached (zero forwarding gap).
        /// Disable for a guaranteed fresh re-attach on every start.
        #[arg(long = "pin-links", default_value_t = true, action = clap::ArgAction::Set, env = "XDP_DP_PIN_LINKS")]
        pin_links: bool,
```
Destructure `pin_links,` in the `Cmd::Serve { … }` match arm (next to `pin_dir,`).

- [ ] **Step 2: Thread `pin_links` + the pin dir into `Control` via `bring_up`**

In `control.rs`, add to `Inner` (near the `iface_meta`/`recovered` fields):
```rust
    /// Link-pinning enabled: pin program links + adopt them atomically on restart.
    pin_links: bool,
    /// Persistent pin dir (for link pins); mirrors the map pin dir passed to load_ebpf.
    pin_dir: std::path::PathBuf,
```
Change `bring_up` signature to take `pin_links: bool` and set both fields in the `Inner { … }` literal (`pin_links,` and `pin_dir: pin_dir.to_path_buf(),`). Also set them in the `#[cfg(test)] from_ebpf_for_test` Inner literal (`pin_links: false, pin_dir: std::path::PathBuf::from("/tmp"),`).

- [ ] **Step 3: bring_up attaches the uplink pinned-or-not**

Replace `loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;` (control.rs:238) with:
```rust
        if pin_links {
            loader::attach_xdp_pinned_at(&mut ebpf, "uplink_rx", uplink, pin_dir, &format!("uplink-{uplink}"))?;
        } else {
            loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;
        }
```

- [ ] **Step 4: Update the Serve call site**

In `main.rs`, pass `pin_links` to `bring_up(&uplink, …, &serve_pin_dir, adopt, pin_links)`.

- [ ] **Step 5: Build**

Run: `cargo build -p xdp-dp`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add xdp-dp/src/main.rs xdp-dp/src/control.rs
git commit -m "feat(serve): --pin-links flag (default on); bring_up pins the uplink link"
```

---

## Task 3: Adopt re-points the uplink link atomically (zero gap)

**Files:**
- Modify: `xdp-dp/src/control.rs` (`bring_up` adopt branch), `xdp-dp/src/main.rs`

- [ ] **Step 1: On adopt, re-adopt the uplink pin instead of attaching fresh**

In `bring_up`, before the plain attach, branch on adopt + pin_links. Replace the Step-3 block from Task 2 with:
```rust
        let uplink_pin = format!("uplink-{uplink}");
        if pin_links && adopt && loader::readopt_xdp_link(&mut ebpf, "uplink_rx", pin_dir, &uplink_pin)? {
            // pinned uplink kept the program attached across the restart; atomically re-pointed at the
            // fresh program — no gap. (readopt returns false if the pin was absent -> fall through.)
        } else if pin_links {
            loader::attach_xdp_pinned_at(&mut ebpf, "uplink_rx", uplink, pin_dir, &uplink_pin)?;
        } else {
            loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;
        }
```

- [ ] **Step 2: Same for extra uplinks + wan_rx**

In `attach_extra_uplink` (control.rs:477) and `attach_edge` (control.rs:455), read `g.pin_links`/`g.pin_dir` (clone the PathBuf before the `&mut g.ebpf` borrow) and use `readopt_xdp_link`-or-`attach_xdp_pinned_at` for `uplink_rx`/`wan_rx` with names `uplink-<iface>` / `wan-<iface>`. On a fresh (non-adopt) start these just attach+pin. (These methods run after `bring_up`, so on adopt they should try `readopt_xdp_link` first.)

- [ ] **Step 3: Build**

Run: `cargo build -p xdp-dp`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add xdp-dp/src/control.rs xdp-dp/src/main.rs
git commit -m "feat(control): adopt re-points uplink/wan links atomically (attach_to_link)"
```

---

## Task 4: Guests — pin on attach, re-adopt on restart, unpin on detach

**Files:**
- Modify: `xdp-dp/src/control.rs` (`GuestLink`, `create_interface`, `reattach_guest`, `detach_interface`)

- [ ] **Step 1: Add a pinned guest-link variant**

```rust
enum GuestLink {
    Xdp(#[allow(dead_code)] aya::programs::xdp::XdpLink),
    Tc(#[allow(dead_code)] aya::programs::tc::SchedClassifierLink),
    /// pin-links mode: the link lives in bpffs at links/<name>; we track the name to unpin on detach.
    Pinned(String),
}
```

- [ ] **Step 2: `create_interface` pins the guest link when pin_links**

Replace the `let link = if g.guest_tc { … attach_tc_clsact_ingress_link … } else { … attach_xdp_link … }` block (control.rs:436-448) with a pin-aware version. Compute the pin name once with the module-private `hex_encode` defined in Step 3 (filesystem-safe, unique, identical on attach and re-adopt): `let gname = format!("guest-{}", hex_encode(interface_id));`. Then:
```rust
        let link = if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            if g.guest_tc {
                loader::attach_tc_pinned_at(&mut g.ebpf, "tc_guest_tx", device, &pin_dir, &gname)
                    .with_context(|| format!("attach+pin tc_guest_tx to {device}"))?;
            } else {
                loader::attach_xdp_pinned_at(&mut g.ebpf, "guest_tx", device, &pin_dir, &gname)
                    .with_context(|| format!("attach+pin guest_tx to {device}"))?;
            }
            GuestLink::Pinned(gname)
        } else if g.guest_tc {
            GuestLink::Tc(loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)?)
        } else {
            GuestLink::Xdp(loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device)?)
        };
```
(Keep the existing "commit bookkeeping after fallible writes" ordering; `link`/`GuestLink::Pinned` is stored in `g.links` exactly as before.)

- [ ] **Step 3: `reattach_guest` re-adopts the pinned link on restart**

```rust
    pub fn reattach_guest(&self, interface_id: &[u8], device: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            let prog = if g.guest_tc { "tc_guest_tx" } else { "guest_tx" };
            let readopted = if g.guest_tc {
                loader::readopt_tc_link(&mut g.ebpf, prog, &pin_dir, &gname)?
            } else {
                loader::readopt_xdp_link(&mut g.ebpf, prog, &pin_dir, &gname)?
            };
            if !readopted {
                // pin was absent (e.g. pin-links was off before) — attach fresh + pin.
                if g.guest_tc { loader::attach_tc_pinned_at(&mut g.ebpf, prog, device, &pin_dir, &gname)?; }
                else { loader::attach_xdp_pinned_at(&mut g.ebpf, prog, device, &pin_dir, &gname)?; }
            }
            g.links.insert(interface_id.to_vec(), GuestLink::Pinned(gname));
            return Ok(());
        }
        // non-pin-links: today's fresh re-attach (unchanged) ...
        let link = if g.guest_tc {
            GuestLink::Tc(loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)?)
        } else {
            GuestLink::Xdp(loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device)?)
        };
        g.links.insert(interface_id.to_vec(), link);
        Ok(())
    }
```
Add a small module-private `fn hex_encode(b: &[u8]) -> String` (lowercase hex) used by both Step 2 and Step 3 so the guest pin name is identical on attach and re-adopt.

- [ ] **Step 4: `detach_interface` unpins the guest link**

Where `g.links.remove(interface_id)` runs (control.rs:622), first read the removed value: if it was `GuestLink::Pinned(name)`, `loader::unpin_link(&g.pin_dir, &name)` (clone `pin_dir` first). Dropping `Xdp`/`Tc` variants still detaches as today.

- [ ] **Step 5: Unit test the pin-name stability**

```rust
#[test]
fn guest_pin_name_is_stable_and_hex() {
    assert_eq!(hex_encode(b"natpod"), "6e6174706f64");
    // same id -> same name on attach and re-adopt
    assert_eq!(hex_encode(b"rpod"), hex_encode(b"rpod"));
}
```
Run: `cargo test -p xdp-dp guest_pin_name` — Expected: PASS.

- [ ] **Step 6: Build + commit**

Run: `cargo build -p xdp-dp`
```bash
git add xdp-dp/src/control.rs
git commit -m "feat(control): pin guest links; re-adopt atomically on restart; unpin on detach"
```

---

## Task 5: Verifier anchors + fresh-start regression (root)

**Files:**
- Modify: `xdp-dp/tests` usage — run existing anchors to confirm no load/verify regression.

- [ ] **Step 1: Anchors still pass (pinned maps + new helpers don't perturb load)**

Run: `sudo -E cargo test -p xdp-dp --test anchor_uplink --test anchor_lb --test verify_edge_wan_rx -- --ignored`
Then: `sudo chown -R "$(id -un):$(id -gn)" target`
Expected: all PASS.

- [ ] **Step 2: Commit (if any test-only tweaks were needed)**

```bash
git add -A && git commit -m "test: confirm anchors pass with pinned-link helpers" || true
```

---

## Task 6: Live zero-gap kill-test on the clab fabric (MANDATORY)

**Files:**
- Modify: `test/scenario-restart.sh`

**Prereq:** clab fabric up + netplane stack on k01; image rebuilt with Tasks 1-4 and rolled (`sudo docker build -t ghcr.io/trevex/dpservice-xdp:dev . && sudo ~/go/bin/kind load docker-image ghcr.io/trevex/dpservice-xdp:dev --name k01 && kubectl -n ectobase-system rollout restart ds/xdp-dp`). The DS needs no manifest change (default `--pin-links=true`, bpffs already hostPath-mounted).

- [ ] **Step 1: Fix the guest check to `bpftool net show`**

In `test/scenario-restart.sh` Step [4], replace `tc filter show dev "veth-$NIC" ingress … grep -qi bpf` with:
```bash
sudo docker exec "$SRC_NODE" bpftool net show dev "veth-$NIC" 2>/dev/null | grep -qiE "tcx|tc_guest_tx|guest_tx"
```

- [ ] **Step 2: Add the uplink zero-gap assertion**

Add a new step after the restart (before cleanup):
```bash
echo "== [4b] uplink program stayed attached across the restart (zero-gap) =="
# The uplink XDP prog id on eth1 must be present both before and after; the pinned link file must
# persist through the crictl stop (proving the program was never detached).
PRE_ID=$(sudo docker exec "$SRC_NODE" bpftool net show dev eth1 2>/dev/null | grep -oE 'id [0-9]+' | head -1)
# (captured before the kill in [1]; here assert after:)
POST_ID=$(sudo docker exec "$SRC_NODE" bpftool net show dev eth1 2>/dev/null | grep -oE 'id [0-9]+' | head -1)
sudo docker exec "$SRC_NODE" ls "$PIN/links/uplink-eth1" >/dev/null 2>&1 \
  && pass "uplink link pin survived the restart ($POST_ID)" \
  || fail "uplink link pin missing after restart — link was not pinned/re-adopted"
```
(Capture `PRE_ID` in step [1] before `crictl stop`; assert the pin file `"$PIN/links/uplink-eth1"` exists both before and after, and that an uplink XDP prog id is present after.)

- [ ] **Step 3: Run the kill-test for real**

Run: `sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-restart.sh`
Expected: `ALL DETERMINISTIC CHECKS PASSED`, plus the new `[4b]` uplink-pin-survived PASS. The adopt log should show the uplink re-adopted (no "attached uplink_rx" fresh line when the pin was present — or add a log line in `readopt_xdp_link` to make it greppable).

- [ ] **Step 4: Commit**

```bash
git add test/scenario-restart.sh
git commit -m "test(restart): assert uplink link stays attached across restart (zero-gap)"
```

---

## Rollback / Risk

- Everything is behind `--pin-links`; `--pin-links=false` reverts to the merged Task-5 fresh re-attach behavior. No map/journal format change.
- If Task 0 finds guest tc is **not** a tcx `FdLink` on the target kernel: `attach_tc_pinned_at` errors; `create_interface`/`reattach_guest` catch it and fall back to the non-pinned `attach_tc_clsact_ingress_link` for guests (uplink/wan still get zero-gap). Add that `.or_else(fallback)` in Task 4 Step 2/3 if the spike shows it.
- A stale link pin whose program died (crash mid-op): `readopt_*` returns the pin, `attach_to_link` re-points it at the fresh program; if `from_pin` errors, treat as pin-missing and attach fresh (wrap `readopt_*` callers to fall through on error).

## Self-Review notes (author)

- Spec coverage: flag (Task 2), pin uplink/wan/extra (Task 2-3), atomic adopt via attach_to_link (Task 3-4), guest pin/re-adopt/unpin (Task 4), `bpftool net show` test fix + uplink zero-gap live assert (Task 6), spike de-risk (Task 0), rollback via flag — all covered. No version marker (removed per revised spec).
- Type consistency: `attach_xdp_pinned_at`/`attach_tc_pinned_at`/`readopt_xdp_link`/`readopt_tc_link`/`unpin_link`, `GuestLink::Pinned(String)`, `hex_encode`, `pin_links`/`pin_dir` on `Inner`, `bring_up(…, pin_links)` used consistently across Tasks 1-4.
- Known de-risk: the exact aya conversion calls (`PinnedLink`→`FdLink`, `FdLink`→`XdpLink`/`SchedClassifierLink`) are validated in Task 0 before Tasks 1-4 rely on them.
