use std::path::{Path, PathBuf};

use anyhow::Context;
use aya::maps::{MapData, ProgramArray};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{tc, ProgramFd, SchedClassifier, TcAttachType};
use aya::Ebpf;

/// Load the eBPF object that aya-build compiled to bpfel and placed in OUT_DIR.
///
/// BPF map sizes can be overridden at load time via environment variables, allowing operators to
/// tune hot maps per node role without recompiling:
///
/// | Map        | Env var                  | Compile-time default |
/// |------------|--------------------------|----------------------|
/// | CONNTRACK  | FLOWPLANE_CONNTRACK_MAX     | 1_048_576            |
/// | ROUTES     | FLOWPLANE_ROUTES_MAX        | 4_096                |
/// | INTERFACES | FLOWPLANE_INTERFACES_MAX    | 1_024                |
/// | MAGLEV     | FLOWPLANE_MAGLEV_MAX        | 65_536               |
/// | NAT        | FLOWPLANE_NAT_MAX           | 1_024                |
/// | LB         | FLOWPLANE_LB_MAX            | 1_024                |
/// | PORT_META  | FLOWPLANE_PORT_META_MAX     | 1_024                |
///
/// Unset variables leave the compile-time `with_max_entries` default in place.
///
/// `pin_dir` is where ByName-pinned maps live and MUST be set: the state maps are declared
/// `pinned` (a `pinned` map with no `map_pin_path` fails to load). A fresh run passes a per-run
/// dir (see [`ephemeral_pin_dir`]) so the maps are created+pinned there and behaviour matches a
/// non-pinned load; a restart passes the persistent bpffs dir so the reloaded programs re-bind to
/// the surviving maps instead of creating fresh ones.
pub fn load_ebpf(pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let mut loader = aya::EbpfLoader::new();
    loader.map_pin_path(pin_dir);
    // Map name -> env var. Unset => keep the compile-time `with_max_entries` default.
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
/// callers get a private `/sys/fs/bpf/flowplane-eph-<pid>` dir. Nothing here is meant to survive — the
/// maps stay alive via the returned handles even after this dir is removed — so the persistent
/// adopt path (production `Serve`) never uses it.
pub fn ephemeral_pin_dir() -> anyhow::Result<PathBuf> {
    let dir = PathBuf::from(format!("/sys/fs/bpf/flowplane-eph-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create ephemeral pin dir {}", dir.display()))?;
    Ok(dir)
}

/// Install the aya-log `EbpfLogger` that drains the datapath's `dlog!` messages to the `log`
/// facade (env_logger backend → dpservice stdout), but ONLY when `FLOWPLANE_DEBUG` is set. On a
/// non-debug image the `AYA_LOGS` map is absent, so this is a graceful no-op with a one-line
/// note. Call once right after `load_ebpf()`; the logger self-drives via per-CPU tokio tasks,
/// so it must be called from within the tokio runtime.
pub fn maybe_install_logger(ebpf: &mut Ebpf) {
    if std::env::var_os("FLOWPLANE_DEBUG").is_none() {
        return;
    }
    match aya_log::EbpfLogger::init(ebpf) {
        Ok(_) => eprintln!("FLOWPLANE_DEBUG: eBPF datapath logger installed"),
        Err(e) => eprintln!(
            "FLOWPLANE_DEBUG set but eBPF logger not installed ({e}); \
             is this a `--features debug` image?"
        ),
    }
}

/// Load (verify) a named tc (classifier) program without attaching it. Call once at startup before
/// `attach_tc_clsact_ingress_link`.
pub fn load_program_tc(ebpf: &mut Ebpf, prog_name: &str) -> anyhow::Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    prog.load().with_context(|| format!("verify {prog_name}"))?;
    Ok(())
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
/// DHCP tail-call resolves. The returned `ProgramArray` MUST be held in scope by the caller for
/// the datapath's lifetime.
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
        .set(flowplane_common::GUEST_PROG_DHCP, fd, 0)
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
        .set(flowplane_common::GUEST_PROG_IPV6, fd, 0)
        .context("register tc_guest_nat64 in GUEST_PROGS_TC")?;

    // IPv6 overlay egress tail-call target (slot GUEST_PROG_V6_FWD): tc_guest_tx tail-calls this for
    // a non-ND/non-NAT64/non-DHCPv6 inner-IPv6 guest packet, giving the firewall + conntrack + route6
    // + encap path its own stack budget (the v6 fw/ct structures overflow tc_guest_tx's 512B frame).
    {
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_guest_egress_v6")
            .context("tc_guest_egress_v6 program missing")?
            .try_into()?;
        prog.load().context("verify tc_guest_egress_v6")?;
    }
    let prog: &SchedClassifier = ebpf
        .program("tc_guest_egress_v6")
        .context("tc_guest_egress_v6 program missing")?
        .try_into()?;
    let fd: &ProgramFd = prog.fd()?;
    progs
        .set(flowplane_common::GUEST_PROG_V6_FWD, fd, 0)
        .context("register tc_guest_egress_v6 in GUEST_PROGS_TC")?;
    Ok(progs)
}

/// Load `xdp_uplink_v6` (a tc program despite the name — see its doc comment in `main.rs`) and
/// register it in `UPLINK_PROGS[UPLINK_PROG_V6]` so `uplink_rx`'s inner-v6 tail-call resolves.
/// `xdp_uplink_v6` is a tail-call TARGET — it is loaded (verified) but NOT attached to an interface;
/// it only ever runs via `uplink_rx`'s tail-call. The returned `ProgramArray` MUST be held in scope
/// by the caller for the datapath's lifetime. Mirrors `register_guest_dhcp_tc`'s pattern.
pub fn register_uplink_v6_tc(ebpf: &mut Ebpf) -> anyhow::Result<ProgramArray<MapData>> {
    {
        let prog: &mut SchedClassifier = ebpf
            .program_mut("xdp_uplink_v6")
            .context("xdp_uplink_v6 program missing")?
            .try_into()?;
        prog.load().context("verify xdp_uplink_v6")?;
    }
    let mut progs: ProgramArray<_> = ebpf
        .take_map("UPLINK_PROGS")
        .context("UPLINK_PROGS map missing")?
        .try_into()?;
    let prog: &SchedClassifier = ebpf
        .program("xdp_uplink_v6")
        .context("xdp_uplink_v6 program missing")?
        .try_into()?;
    let fd: &ProgramFd = prog.fd()?;
    progs
        .set(flowplane_common::UPLINK_PROG_V6, fd, 0)
        .context("register xdp_uplink_v6 in UPLINK_PROGS")?;
    Ok(progs)
}

/// Ensure a clsact qdisc exists on `iface`, then attach an already-loaded tc (classifier) program
/// to its INGRESS hook and RETURN the owned link, so the caller can later drop it to detach (used
/// for dynamic guest interface teardown). The program must
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

/// Ensure the uplink has an `fq` root qdisc so EDT `skb->tstamp` departure times are honored (the
/// shaping mechanism). aya 0.13 exposes no qdisc API beyond clsact, so shell out to `tc`. `replace`
/// is idempotent (creates or swaps the root qdisc). On a real multi-queue NIC, `mq` root + per-queue
/// `fq` is preferable; `root fq` is correct for single-queue/veth and a safe default. A failure is
/// logged but not fatal — shaping degrades to no pacing rather than dropping the datapath.
pub fn ensure_fq_qdisc(iface: &str) {
    match std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "fq"])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "warning: `tc qdisc replace dev {iface} root fq` exited {s}; egress shaping disabled"
        ),
        Err(e) => eprintln!(
            "warning: could not run tc to set fq on {iface} ({e}); egress shaping disabled"
        ),
    }
}

/// Load the eBPF object and attach `uplink_rx` (tcx, on the named uplink interface — NOTE: this
/// debug helper attaches directly to `iface`, NOT the geneve `collect_md` device; `Control::bring_up`
/// is what attaches it to the geneve device for the real datapath). `pin_dir` is the bpffs
/// `map_pin_path` for the load (debug `Load` command passes [`ephemeral_pin_dir`]).
pub fn attach_uplink(iface: &str, pin_dir: &Path) -> anyhow::Result<Ebpf> {
    let mut ebpf = load_ebpf(pin_dir)?;
    attach_tc_clsact_ingress(&mut ebpf, "uplink_rx", iface)?;
    ensure_fq_qdisc(iface);
    Ok(ebpf)
}

fn link_pin_path(pin_dir: &Path, name: &str) -> std::path::PathBuf {
    pin_dir.join("links").join(name)
}

/// tc (tcx FdLink) link pinning. Was "tc analogues" of an XDP pinning pair removed in P2 Task 4b
/// (the whole overlay ingress/egress pipeline is tcx now — no XDP program is pinned any more).
pub fn attach_tc_pinned_at(
    ebpf: &mut Ebpf,
    prog: &str,
    iface: &str,
    pin_dir: &Path,
    name: &str,
) -> anyhow::Result<()> {
    // Detach any stale pinned link of this name first (avoids a doubled tcx attach).
    let _ = std::fs::remove_file(link_pin_path(pin_dir, name));
    let _ = aya::programs::tc::qdisc_add_clsact(iface);
    let p: &mut SchedClassifier = ebpf
        .program_mut(prog)
        .with_context(|| format!("tc {prog} missing"))?
        .try_into()?;
    if p.fd().is_err() {
        p.load().with_context(|| format!("load {prog}"))?;
    }
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
    println!("adopt: re-pointed pinned link {name} -> {prog} (atomic, zero-gap)");
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
    use aya::programs::SchedClassifier;
    use aya::{EbpfLoader, VerifierLogLevel};

    #[test]
    #[ignore = "requires root/CAP_BPF; loads programs through the verifier"]
    fn programs_pass_verifier() {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
        // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
        let pin = tempfile::Builder::new()
            .prefix("flowplane-verify-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir");
        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
            .map_pin_path(pin.path())
            .load(bytes)
            .expect("load ebpf object");
        for name in [
            "uplink_rx",
            "xdp_uplink_v6",
            "wan_rx",
            "tc_guest_tx",
            "tc_guest_dhcp",
            "tc_guest_nat64",
        ] {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("tc program {name} missing"))
                .try_into()
                .expect("is tc");
            prog.load()
                .unwrap_or_else(|e| panic!("verifier rejected {name}: {e}"));
        }
    }
}
