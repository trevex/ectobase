use std::path::{Path, PathBuf};

use anyhow::Context;
use aya::maps::{MapData, ProgramArray};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{tc, ProgramFd, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;

/// Load the eBPF object that aya-build compiled to bpfel and placed in OUT_DIR.
///
/// BPF map sizes can be overridden at load time via environment variables, allowing operators to
/// tune hot maps per node role without recompiling:
///
/// | Map        | Env var                  | Compile-time default |
/// |------------|--------------------------|----------------------|
/// | CONNTRACK  | XDP_DP_CONNTRACK_MAX     | 1_048_576            |
/// | ROUTES     | XDP_DP_ROUTES_MAX        | 4_096                |
/// | INTERFACES | XDP_DP_INTERFACES_MAX    | 1_024                |
/// | MAGLEV     | XDP_DP_MAGLEV_MAX        | 65_536               |
/// | NAT        | XDP_DP_NAT_MAX           | 1_024                |
/// | LB         | XDP_DP_LB_MAX            | 1_024                |
/// | PORT_META  | XDP_DP_PORT_META_MAX     | 1_024                |
///
/// Unset variables leave the compile-time `with_max_entries` default in place.
///
/// `pin_dir` is where ByName-pinned maps live and MUST be set: the state maps are declared
/// `pinned` (a `pinned` map with no `map_pin_path` fails to load). A fresh run passes a per-run
/// dir (see [`ephemeral_pin_dir`]) so the maps are created+pinned there and behaviour matches a
/// non-pinned load; a restart passes the persistent bpffs dir so the reloaded programs re-bind to
/// the surviving maps instead of creating fresh ones.
pub fn load_ebpf(pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut loader = aya::EbpfLoader::new();
    loader.map_pin_path(pin_dir);
    // Map name -> env var. Unset => keep the compile-time `with_max_entries` default.
    for (map, var) in [
        ("CONNTRACK", "XDP_DP_CONNTRACK_MAX"),
        ("ROUTES", "XDP_DP_ROUTES_MAX"),
        ("INTERFACES", "XDP_DP_INTERFACES_MAX"),
        ("MAGLEV", "XDP_DP_MAGLEV_MAX"),
        ("NAT", "XDP_DP_NAT_MAX"),
        ("LB", "XDP_DP_LB_MAX"),
        ("PORT_META", "XDP_DP_PORT_META_MAX"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let n: u32 = v
                .parse()
                .with_context(|| format!("{var} must be a u32, got {v:?}"))?;
            loader.set_max_entries(map, n);
        }
    }
    loader.load(bytes).context("load ebpf object")
}

/// A per-process bpffs pin dir for load paths that do NOT persist datapath state across a restart:
/// the debug/lab subcommands (`Load`/`Pass`/`Inspect`/`TcBringup`, and `Bringup` without `--pin-dir`).
/// The state maps are declared `pinned`, so every load needs *some* bpffs `map_pin_path`; these
/// callers get a private `/sys/fs/bpf/xdp-dp-eph-<pid>` dir. Nothing here is meant to survive — the
/// maps stay alive via the returned handles even after this dir is removed — so the persistent
/// adopt path (production `Serve`) never uses it.
pub fn ephemeral_pin_dir() -> anyhow::Result<PathBuf> {
    let dir = PathBuf::from(format!("/sys/fs/bpf/xdp-dp-eph-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create ephemeral pin dir {}", dir.display()))?;
    Ok(dir)
}

/// Install the aya-log `EbpfLogger` that drains the datapath's `dlog!` messages to the `log`
/// facade (env_logger backend → dpservice stdout), but ONLY when `XDP_DP_DEBUG` is set. On a
/// non-debug image the `AYA_LOGS` map is absent, so this is a graceful no-op with a one-line
/// note. Call once right after `load_ebpf()`; the logger self-drives via per-CPU tokio tasks,
/// so it must be called from within the tokio runtime.
pub fn maybe_install_logger(ebpf: &mut Ebpf) {
    if std::env::var_os("XDP_DP_DEBUG").is_none() {
        return;
    }
    match aya_log::EbpfLogger::init(ebpf) {
        Ok(_) => eprintln!("XDP_DP_DEBUG: eBPF datapath logger installed"),
        Err(e) => eprintln!(
            "XDP_DP_DEBUG set but eBPF logger not installed ({e}); \
             is this a `--features debug` image?"
        ),
    }
}

/// Load (verify) a named XDP program without attaching it. Call this once at startup so that
/// subsequent `attach_xdp_link` calls only need to attach (not load).
pub fn load_program(ebpf: &mut Ebpf, prog_name: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    Ok(())
}

/// Load (verify) a named tc (classifier) program without attaching it. The tc analogue of
/// `load_program`: `load_program` casts to `Xdp`, which fails for SchedClassifier programs, so
/// the guest tc edge needs its own pre-load. Call once at startup before `attach_tc_clsact_ingress_link`.
pub fn load_program_tc(ebpf: &mut Ebpf, prog_name: &str) -> anyhow::Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    Ok(())
}

/// Load (verify) `guest_dhcp` and register its fd in the `GUEST_PROGS` program array at
/// `GUEST_PROG_DHCP`, so `guest_tx`'s DHCP tail call resolves at runtime. Returns the owned
/// `ProgramArray` handle; the caller MUST keep it alive (dropping it closes the userspace map fd —
/// the kernel map itself survives because guest_tx references it, but holding the handle is the
/// clean, explicit lifetime). Call once at startup after `load_ebpf`, before attaching guest_tx.
pub fn register_guest_dhcp(ebpf: &mut Ebpf) -> anyhow::Result<ProgramArray<MapData>> {
    {
        let prog: &mut Xdp = ebpf
            .program_mut("guest_dhcp")
            .context("guest_dhcp program missing")?
            .try_into()?;
        prog.load().context("verify guest_dhcp")?;
    }
    let mut progs: ProgramArray<_> = ebpf
        .take_map("GUEST_PROGS")
        .context("GUEST_PROGS map missing")?
        .try_into()?;
    let prog: &Xdp = ebpf
        .program("guest_dhcp")
        .context("guest_dhcp program missing")?
        .try_into()?;
    let fd: &ProgramFd = prog.fd()?;
    progs
        .set(xdp_dp_common::GUEST_PROG_DHCP, fd, 0)
        .context("register guest_dhcp in GUEST_PROGS")?;
    Ok(progs)
}

/// Ensure a clsact qdisc exists on `iface`, then load+attach a tc (classifier) program to its
/// INGRESS hook (host receives = guest egress). The qdisc add is idempotent — an "already exists"
/// error is fine.
pub fn attach_tc_clsact_ingress(
    ebpf: &mut Ebpf,
    prog_name: &str,
    iface: &str,
) -> anyhow::Result<()> {
    // Adding clsact when it already exists returns an error; ignore that case only.
    let _ = tc::qdisc_add_clsact(iface);
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    prog.attach(iface, TcAttachType::Ingress)
        .with_context(|| format!("attach {prog_name} to {iface} (clsact ingress)"))?;
    Ok(())
}

/// Load `tc_guest_dhcp` and register it in `GUEST_PROGS_TC[GUEST_PROG_DHCP]` so `tc_guest_tx`'s
/// DHCP tail-call resolves. Mirrors `register_guest_dhcp` but for the tc program array. The
/// returned `ProgramArray` MUST be held in scope by the caller for the datapath's lifetime.
pub fn register_guest_dhcp_tc(ebpf: &mut Ebpf) -> anyhow::Result<ProgramArray<MapData>> {
    {
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_guest_dhcp")
            .context("tc_guest_dhcp program missing")?
            .try_into()?;
        prog.load().context("verify tc_guest_dhcp")?;
    }
    let mut progs: ProgramArray<_> = ebpf
        .take_map("GUEST_PROGS_TC")
        .context("GUEST_PROGS_TC map missing")?
        .try_into()?;
    let prog: &SchedClassifier = ebpf
        .program("tc_guest_dhcp")
        .context("tc_guest_dhcp program missing")?
        .try_into()?;
    let fd: &ProgramFd = prog.fd()?;
    progs
        .set(xdp_dp_common::GUEST_PROG_DHCP, fd, 0)
        .context("register tc_guest_dhcp in GUEST_PROGS_TC")?;

    // NAT64 egress tail-call target (slot GUEST_PROG_IPV6): tc_guest_tx tail-calls this when the
    // inner IPv6 dst is in 64:ff9b::/96, giving the translate+SNAT+encap path its own stack budget.
    {
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_guest_nat64")
            .context("tc_guest_nat64 program missing")?
            .try_into()?;
        prog.load().context("verify tc_guest_nat64")?;
    }
    let prog: &SchedClassifier = ebpf
        .program("tc_guest_nat64")
        .context("tc_guest_nat64 program missing")?
        .try_into()?;
    let fd: &ProgramFd = prog.fd()?;
    progs
        .set(xdp_dp_common::GUEST_PROG_IPV6, fd, 0)
        .context("register tc_guest_nat64 in GUEST_PROGS_TC")?;
    Ok(progs)
}

/// Attach an XDP program honouring the same mode policy as `attach_xdp_link`: force SKB/generic
/// when `XDP_DP_SKB_MODE` is set (veth uplinks — e.g. containerlab/kind fabric links — do not
/// support native XDP), else prefer native and fall back to SKB. Shared by the uplink attach paths.
fn attach_xdp_mode(prog: &mut Xdp, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    if std::env::var_os("XDP_DP_SKB_MODE").is_some() {
        prog.attach(iface, XdpFlags::SKB_MODE)
            .with_context(|| format!("attach {prog_name} to {iface} (SKB_MODE)"))?;
    } else {
        prog.attach(iface, XdpFlags::default())
            .or_else(|_| prog.attach(iface, XdpFlags::SKB_MODE))
            .with_context(|| format!("attach {prog_name} to {iface}"))?;
    }
    Ok(())
}

/// Load (verify) and attach a named XDP program to one interface. Call this for the first
/// interface; use `attach_xdp_loaded` for subsequent interfaces with the same program name.
pub fn attach_xdp(ebpf: &mut Ebpf, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    attach_xdp_mode(prog, prog_name, iface)
}

/// Attach an already-loaded XDP program to an additional interface (skips the `load()` call).
pub fn attach_xdp_extra(ebpf: &mut Ebpf, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    attach_xdp_mode(prog, prog_name, iface)
}

/// Attach an already-loaded XDP program to an interface and RETURN the owned link, so the caller
/// can later drop it to detach (used for dynamic interface teardown). Falls back to SKB mode.
pub fn attach_xdp_link(
    ebpf: &mut Ebpf,
    prog_name: &str,
    iface: &str,
) -> anyhow::Result<aya::programs::xdp::XdpLink> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    // Attach mode: default to native (driver) mode and fall back to SKB (generic) so production
    // guest taps get the fast path. The DHCP responder grows the frame via bpf_xdp_adjust_tail,
    // which veth's native XDP cannot do — so the conformance harness sets XDP_DP_SKB_MODE=1 to
    // force generic mode (where adjust_tail growth works). Real tap/NIC drivers support native
    // adjust_tail, so production stays on the fast path.
    let id = if std::env::var_os("XDP_DP_SKB_MODE").is_some() {
        prog.attach(iface, XdpFlags::SKB_MODE)
            .with_context(|| format!("attach {prog_name} to {iface} (SKB_MODE)"))?
    } else {
        prog.attach(iface, XdpFlags::default())
            .or_else(|_| prog.attach(iface, XdpFlags::SKB_MODE))
            .with_context(|| format!("attach {prog_name} to {iface}"))?
    };
    prog.take_link(id).context("take xdp link")
}

/// Ensure a clsact qdisc exists on `iface`, then attach an already-loaded tc (classifier) program
/// to its INGRESS hook and RETURN the owned link, so the caller can later drop it to detach (the
/// tc analogue of `attach_xdp_link`, used for dynamic guest interface teardown). The program must
/// be pre-loaded once via `load_program_tc`; this only attaches. The qdisc add is idempotent.
pub fn attach_tc_clsact_ingress_link(
    ebpf: &mut Ebpf,
    prog_name: &str,
    iface: &str,
) -> anyhow::Result<aya::programs::tc::SchedClassifierLink> {
    let _ = tc::qdisc_add_clsact(iface);
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    let link_id = prog
        .attach(iface, TcAttachType::Ingress)
        .with_context(|| format!("attach {prog_name} to {iface} (clsact ingress)"))?;
    prog.take_link(link_id).context("take tc link")
}

/// Load the eBPF object and attach `uplink_rx` to the named uplink interface. `pin_dir` is the
/// bpffs `map_pin_path` for the load (debug `Load` command passes [`ephemeral_pin_dir`]).
pub fn attach_uplink(iface: &str, pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf(pin_dir)?;
    attach_xdp(&mut ebpf, "uplink_rx", iface)?;
    Ok(ebpf)
}

/// Attach `prog` to `iface` and pin the resulting XDP link to
/// `<pin_dir>/links/<prog>-<iface>`, so the attachment (and thus the program + all its maps)
/// survives this process exiting.
///
/// `already_loaded` mirrors the "load the program once, attach-only afterward" pattern used
/// when the same program is attached to multiple interfaces.
pub fn attach_xdp_pinned(
    ebpf: &mut Ebpf,
    prog: &str,
    iface: &str,
    pin_dir: &str,
    already_loaded: bool,
) -> anyhow::Result<()> {
    use aya::programs::links::FdLink;

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
    // XdpLink wraps an FdLink on kernels >= 5.9 (bpf_link_create path); convert to pin.
    let fd_link: FdLink = link.try_into().map_err(|_| {
        anyhow::anyhow!(
            "XDP link is not an FdLink (kernel < 5.9?); pinning requires bpf_link_create support"
        )
    })?;
    let links_dir = format!("{pin_dir}/links");
    std::fs::create_dir_all(&links_dir).ok();
    let link_path = format!("{links_dir}/{prog}-{iface}");
    let _ = std::fs::remove_file(&link_path);
    fd_link
        .pin(Path::new(&link_path))
        .with_context(|| format!("pin link {link_path}"))?;
    Ok(())
}

fn link_pin_path(pin_dir: &Path, name: &str) -> std::path::PathBuf {
    pin_dir.join("links").join(name)
}

/// Attach an already-loaded XDP `prog` to `iface` and pin the link to `<pin_dir>/links/<name>` so it
/// survives this process exiting. The bpffs pin owns the attachment; the caller need not hold a handle.
pub fn attach_xdp_pinned_at(
    ebpf: &mut Ebpf,
    prog: &str,
    iface: &str,
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<()> {
    let p: &mut Xdp = ebpf
        .program_mut(prog)
        .with_context(|| format!("{prog} missing"))?
        .try_into()?;
    let id = if std::env::var_os("XDP_DP_SKB_MODE").is_some() {
        p.attach(iface, aya::programs::XdpFlags::SKB_MODE)
            .with_context(|| format!("attach {prog} to {iface} (SKB_MODE)"))?
    } else {
        p.attach(iface, aya::programs::XdpFlags::default())
            .or_else(|_| p.attach(iface, aya::programs::XdpFlags::SKB_MODE))
            .with_context(|| format!("attach {prog} to {iface}"))?
    };
    let fd: FdLink = p
        .take_link(id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("XDP link is not an FdLink (kernel < 5.9?)"))?;
    let path = link_pin_path(pin_dir, name);
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let _ = std::fs::remove_file(&path);
    fd.pin(&path)
        .with_context(|| format!("pin xdp link {}", path.display()))?;
    Ok(())
}

/// Re-open a pinned XDP link and atomically re-point it at (a freshly-loaded) `prog` — no gap.
/// Returns true if the pin existed (adopted); false if absent (caller attaches fresh).
pub fn readopt_xdp_link(
    ebpf: &mut Ebpf,
    prog: &str,
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<bool> {
    let path = link_pin_path(pin_dir, name);
    if !path.exists() {
        return Ok(false);
    }
    {
        let p: &mut Xdp = ebpf
            .program_mut(prog)
            .with_context(|| format!("{prog} missing"))?
            .try_into()?;
        if p.fd().is_err() {
            p.load().with_context(|| format!("load {prog}"))?;
        }
    }
    let pinned =
        PinnedLink::from_pin(&path).with_context(|| format!("from_pin {}", path.display()))?;
    let fd: FdLink = pinned.into();
    let xlink: aya::programs::xdp::XdpLink = fd
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned link at {} is not an XDP link", path.display()))?;
    let p: &mut Xdp = ebpf
        .program_mut(prog)
        .with_context(|| format!("{prog} missing"))?
        .try_into()?;
    let id = p
        .attach_to_link(xlink)
        .with_context(|| format!("attach_to_link {prog}"))?;
    let _ = p.take_link(id);
    Ok(true)
}

/// tc analogues (tcx FdLink).
pub fn attach_tc_pinned_at(
    ebpf: &mut Ebpf,
    prog: &str,
    iface: &str,
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<()> {
    let _ = aya::programs::tc::qdisc_add_clsact(iface);
    let p: &mut SchedClassifier = ebpf
        .program_mut(prog)
        .with_context(|| format!("tc {prog} missing"))?
        .try_into()?;
    let id = p
        .attach(iface, aya::programs::TcAttachType::Ingress)
        .with_context(|| format!("attach {prog} to {iface}"))?;
    let fd: FdLink = p.take_link(id)?.try_into().map_err(|_| {
        anyhow::anyhow!("tc link is not a tcx FdLink (kernel < 6.6); pinning unavailable")
    })?;
    let path = link_pin_path(pin_dir, name);
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let _ = std::fs::remove_file(&path);
    fd.pin(&path)
        .with_context(|| format!("pin tc link {}", path.display()))?;
    Ok(())
}

pub fn readopt_tc_link(
    ebpf: &mut Ebpf,
    prog: &str,
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<bool> {
    let path = link_pin_path(pin_dir, name);
    if !path.exists() {
        return Ok(false);
    }
    {
        let p: &mut SchedClassifier = ebpf
            .program_mut(prog)
            .with_context(|| format!("tc {prog} missing"))?
            .try_into()?;
        if p.fd().is_err() {
            p.load().with_context(|| format!("load {prog}"))?;
        }
    }
    let pinned =
        PinnedLink::from_pin(&path).with_context(|| format!("from_pin {}", path.display()))?;
    let fd: FdLink = pinned.into();
    let tlink: aya::programs::tc::SchedClassifierLink = fd
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned link at {} is not a tcx link", path.display()))?;
    let p: &mut SchedClassifier = ebpf
        .program_mut(prog)
        .with_context(|| format!("tc {prog} missing"))?
        .try_into()?;
    let id = p
        .attach_to_link(tlink)
        .with_context(|| format!("attach_to_link {prog}"))?;
    let _ = p.take_link(id);
    Ok(true)
}

/// Remove a link pin (detaches the program). Used on guest detach.
pub fn unpin_link(pin_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(link_pin_path(pin_dir, name));
}

/// Pin a loaded map to `<pin_dir>/<name>` so a restarted control plane can re-acquire it.
/// Must be called BEFORE `take_map` / `Conntrack::open` on the same map name, because
/// `take_map` removes the map from the `Ebpf` object's collection.
pub fn pin_map(ebpf: &mut Ebpf, name: &str, pin_dir: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(pin_dir).ok();
    let path = format!("{pin_dir}/{name}");
    let _ = std::fs::remove_file(&path);
    ebpf.map_mut(name)
        .with_context(|| format!("map {name} missing"))?
        .pin(Path::new(&path))
        .with_context(|| format!("pin map {path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aya::programs::Xdp;
    use aya::{EbpfLoader, VerifierLogLevel};

    #[test]
    #[ignore = "requires root/CAP_BPF; loads programs through the verifier"]
    fn both_programs_pass_verifier() {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
        // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
        let pin = tempfile::Builder::new()
            .prefix("xdp-dp-verify-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir");
        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
            .map_pin_path(pin.path())
            .load(bytes)
            .expect("load ebpf object");
        for name in ["uplink_rx", "guest_tx", "guest_dhcp"] {
            let prog: &mut Xdp = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing"))
                .try_into()
                .expect("is xdp");
            prog.load()
                .unwrap_or_else(|e| panic!("verifier rejected {name}: {e}"));
        }
    }
}
