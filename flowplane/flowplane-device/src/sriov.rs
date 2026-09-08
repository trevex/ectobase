//! SR-IOV VF guest-edge backend: CLAIM a pre-provisioned VF (flowplane never writes sriov_numvfs /
//! eswitch mode — that is one-time node/operator setup), resolve its switchdev REPRESENTOR netdev
//! (the root-netns datapath device tc_guest_tx attaches to), set the VF mac/mtu, move the VF into the
//! guest netns, and return the representor DeviceInfo. Mirrors tap.rs/netkit.rs (ip/devlink shell-out
//! via veth.rs helpers; no netlink crate). SF (subfunction) is a future sibling entry point.

use crate::veth::{fmt_mac, ifindex_of, run, run_netns, DeviceInfo};
use anyhow::{bail, Context, Result};

/// Parse one `devlink port show` line: return the port's `netdev <name>` iff the port handle begins
/// with `<devlink_dev>/`, the port `flavour` is `pcivf`, and its `vfnum` equals `vfnum`. Portable
/// across netdevsim (`netdevsim/netdevsim<id>/...`) and real NICs (`pci/<bdf>/...`). None otherwise.
pub(crate) fn parse_devlink_port_line(line: &str, devlink_dev: &str, vfnum: u32) -> Option<String> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    // first token is the port handle with a trailing ':' — e.g. "netdevsim/netdevsim99/128:".
    let handle = toks.first()?.strip_suffix(':')?;
    if !handle.starts_with(&format!("{devlink_dev}/")) {
        return None;
    }
    let mut is_pcivf = false;
    let mut vf_ok = false;
    let mut netdev: Option<&str> = None;
    for (i, t) in toks.iter().enumerate() {
        match *t {
            "flavour" if toks.get(i + 1) == Some(&"pcivf") => is_pcivf = true,
            "vfnum" => {
                if toks.get(i + 1).and_then(|n| n.parse::<u32>().ok()) == Some(vfnum) {
                    vf_ok = true;
                }
            }
            "netdev" => netdev = toks.get(i + 1).copied(),
            _ => {}
        }
    }
    if is_pcivf && vf_ok {
        netdev.map(|n| n.to_string())
    } else {
        None
    }
}

/// Pure parse of one `devlink port show` line: if the port's `flavour` is `pcivf` AND it carries a
/// `netdev <name>`, return that netdev name; None otherwise (physical/other flavour, or a pcivf port
/// with no netdev). Attach-state-independent and PF-independent — matches EVERY switchdev VF
/// representor on the box, which is what the offload startup flush needs.
fn parse_pcivf_netdev(line: &str) -> Option<&str> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mut is_pcivf = false;
    let mut netdev: Option<&str> = None;
    for (i, t) in toks.iter().enumerate() {
        match *t {
            "flavour" if toks.get(i + 1) == Some(&"pcivf") => is_pcivf = true,
            "netdev" => netdev = toks.get(i + 1).copied(),
            _ => {}
        }
    }
    if is_pcivf {
        netdev
    } else {
        None
    }
}

/// Enumerate the ifindexes of ALL switchdev `pcivf` representor netdevs on the system (every PF's VF
/// representors), independent of overlay attach state. Used by the offload manager's startup flush to
/// clear owned flower filters even on representors whose guest has since detached. Empty on a system
/// with no switchdev VFs. Parses `devlink port show`: each line with `flavour pcivf` carries a
/// `netdev <name>`; resolve `/sys/class/net/<name>/ifindex`.
pub fn pcivf_reps() -> Result<Vec<u32>> {
    // A host with no `devlink` (non-switchdev / no SR-IOV) has nothing to flush — not an error.
    let out = match std::process::Command::new("devlink")
        .args(["port", "show"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Ok(vec![]),
    };
    if !out.status.success() {
        return Ok(vec![]);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut seen = std::collections::BTreeSet::new();
    let mut reps = Vec::new();
    for line in text.lines() {
        if let Some(name) = parse_pcivf_netdev(line) {
            if let Ok(ifindex) = ifindex_of(name) {
                if seen.insert(ifindex) {
                    reps.push(ifindex);
                }
            }
        }
    }
    Ok(reps)
}

/// What the caller wants stood up over a VF.
pub struct VfSpec {
    /// The VF's PCI BDF, e.g. "0000:65:00.3".
    pub pci_address: String,
    /// Guest netns path to move the VF into (None = leave in root netns, e.g. a local test).
    pub netns_path: Option<String>,
    /// Guest name for the VF inside the netns (e.g. "eth0").
    pub guest_name: String,
    /// MAC to set on the VF (local delivery rewrites frame dst to this; must match the guest).
    pub mac: [u8; 6],
    /// Guest link MTU (underlay MTU - encap overhead).
    pub mtu: u32,
}

/// Resolve the VF netdev name for a PCI BDF: the single entry under `/sys/bus/pci/devices/<bdf>/net/`.
fn vf_netdev_of(pci: &str) -> Result<String> {
    let dir = format!("/sys/bus/pci/devices/{pci}/net");
    let mut it = std::fs::read_dir(&dir).with_context(|| format!("read {dir}"))?;
    let first = it.next().with_context(|| {
        format!("no netdev under {dir} (is the VF bound to a netdev driver?)")
    })??;
    Ok(first.file_name().to_string_lossy().into_owned())
}

/// Map a VF PCI BDF to (its PF's devlink device handle `pci/<pf_bdf>`, its vfnum). mlx5/real-NIC only
/// (netdevsim has no PCI sysfs — the netdevsim test drives `representor_for` directly). vfnum = the `N`
/// for which `<pf>/virtfnN` -> this bdf.
fn pf_devlink_and_vfnum(pci: &str) -> Result<(String, u32)> {
    let physfn = std::fs::read_link(format!("/sys/bus/pci/devices/{pci}/physfn"))
        .with_context(|| format!("read physfn of {pci} (not a VF?)"))?;
    let pf = physfn
        .file_name()
        .context("physfn basename")?
        .to_string_lossy()
        .into_owned();
    for n in 0..256u32 {
        if let Ok(t) = std::fs::read_link(format!("/sys/bus/pci/devices/{pf}/virtfn{n}")) {
            if t.file_name()
                .map(|b| b.to_string_lossy() == *pci)
                .unwrap_or(false)
            {
                return Ok((format!("pci/{pf}"), n));
            }
        }
    }
    bail!("could not find virtfn index for {pci} under PF {pf}")
}

/// Resolve the switchdev representor netdev for `vfnum` under devlink device `devlink_dev`
/// (e.g. "pci/0000:65:00.0" on mlx5, "netdevsim/netdevsim3" under test) by parsing `devlink port show`.
/// Portable across netdevsim and real NICs — the standard switchdev representor lookup.
fn representor_for(devlink_dev: &str, vfnum: u32) -> Result<String> {
    let out = std::process::Command::new("devlink")
        .args(["port", "show"])
        .output()
        .context("run `devlink port show`")?;
    if !out.status.success() {
        bail!(
            "devlink port show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(netdev) = parse_devlink_port_line(line, devlink_dev, vfnum) {
            return Ok(netdev);
        }
    }
    bail!("no switchdev pcivf representor for vfnum {vfnum} under {devlink_dev} (PF in switchdev mode?)")
}

/// CLAIM a pre-provisioned VF: resolve its representor, set the VF mac/mtu, move the VF into the guest
/// netns, and return the REPRESENTOR DeviceInfo (host_ifindex = representor ifindex). Does NOT create
/// VFs or set eswitch mode.
pub fn claim_vf(spec: &VfSpec) -> Result<DeviceInfo> {
    let pci = &spec.pci_address;
    let (pf_devlink, vfnum) = pf_devlink_and_vfnum(pci)?;
    let representor = representor_for(&pf_devlink, vfnum)?;
    let vf_netdev = vf_netdev_of(pci)?;

    let macs = fmt_mac(spec.mac);
    let mtu = spec.mtu.to_string();
    // The representor is the root-netns datapath device: its MTU must be >= the guest's so a full-size
    // return-path frame redirected onto it toward the VF is never dropped (same invariant veth.rs's
    // host end / netkit.rs's primary set — matters on a jumbo underlay where guest MTU can be >1500).
    run(&["ip", "link", "set", &representor, "mtu", &mtu]).context("set representor mtu")?;
    run(&["ip", "link", "set", &representor, "up"]).context("representor up")?;
    run(&["ip", "link", "set", &vf_netdev, "address", &macs]).context("set vf mac")?;
    run(&["ip", "link", "set", &vf_netdev, "mtu", &mtu]).context("set vf mtu")?;
    if let Some(ns) = &spec.netns_path {
        run(&["ip", "link", "set", &vf_netdev, "netns", ns]).context("move vf to netns")?;
        run_netns(
            ns,
            &["ip", "link", "set", &vf_netdev, "name", &spec.guest_name],
        )
        .context("rename vf in netns")?;
        run_netns(ns, &["ip", "link", "set", &spec.guest_name, "up"]).context("vf up in netns")?;
    } else {
        run(&["ip", "link", "set", &vf_netdev, "up"]).context("vf up")?;
    }

    let host_ifindex = ifindex_of(&representor)?;
    Ok(DeviceInfo {
        host_ifindex,
        host_name: representor,
        mac: spec.mac,
    })
}

/// Release a claimed VF: move it back to the root netns (best-effort) and down it. The representor is
/// left in place (owned by the PF). Errors surfaced but callers may treat as best-effort.
pub fn release_vf(pci_address: &str, netns_path: Option<&str>, guest_name: &str) -> Result<()> {
    if let Some(ns) = netns_path {
        let _ = run_netns(ns, &["ip", "link", "set", guest_name, "netns", "1"]);
    }
    if let Ok(vf_netdev) = vf_netdev_of(pci_address) {
        let _ = run(&["ip", "link", "set", &vf_netdev, "down"]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_devlink_port_line_matches_vf() {
        let l0 = "netdevsim/netdevsim99/128: type eth netdev eni99npf0vf0 flavour pcivf controller 0 pfnum 0 vfnum 0 external false splittable false";
        let l1 = "netdevsim/netdevsim99/129: type eth netdev eni99npf0vf1 flavour pcivf controller 0 pfnum 0 vfnum 1 external false splittable false";
        let pf = "netdevsim/netdevsim99/0: type eth netdev eni99np1 flavour physical port 1 splittable false";
        assert_eq!(
            parse_devlink_port_line(l0, "netdevsim/netdevsim99", 0).as_deref(),
            Some("eni99npf0vf0")
        );
        assert_eq!(
            parse_devlink_port_line(l1, "netdevsim/netdevsim99", 1).as_deref(),
            Some("eni99npf0vf1")
        );
        assert_eq!(
            parse_devlink_port_line(l0, "netdevsim/netdevsim99", 1),
            None,
            "vfnum mismatch"
        );
        assert_eq!(
            parse_devlink_port_line(pf, "netdevsim/netdevsim99", 0),
            None,
            "physical flavour, not pcivf"
        );
        assert_eq!(
            parse_devlink_port_line(l0, "netdevsim/netdevsim9", 0),
            None,
            "different devlink dev must not prefix-match"
        );
        // An mlx5-style line resolves too (portability):
        let m = "pci/0000:03:00.0/131074: type eth netdev ens1f0npf0vf3 flavour pcivf controller 0 pfnum 0 vfnum 3 external false splittable false";
        assert_eq!(
            parse_devlink_port_line(m, "pci/0000:03:00.0", 3).as_deref(),
            Some("ens1f0npf0vf3")
        );
    }

    #[test]
    fn parse_pcivf_netdev_matches_flavour() {
        let l0 = "netdevsim/netdevsim99/128: type eth netdev eni99npf0vf0 flavour pcivf controller 0 pfnum 0 vfnum 0 external false splittable false";
        let l1 = "netdevsim/netdevsim99/129: type eth netdev eni99npf0vf1 flavour pcivf controller 0 pfnum 0 vfnum 1 external false splittable false";
        let pf = "netdevsim/netdevsim99/0: type eth netdev eni99np1 flavour physical port 1 splittable false";
        assert_eq!(parse_pcivf_netdev(l0), Some("eni99npf0vf0"));
        assert_eq!(parse_pcivf_netdev(l1), Some("eni99npf0vf1"));
        assert_eq!(parse_pcivf_netdev(pf), None, "physical flavour, not pcivf");
        // A pcivf port with no `netdev` token yields None (nothing to resolve/flush).
        let no_netdev = "pci/0000:03:00.0/131074: type eth flavour pcivf controller 0 pfnum 0 vfnum 3 external false splittable false";
        assert_eq!(parse_pcivf_netdev(no_netdev), None, "pcivf but no netdev");
    }

    /// Privileged: stand up a netdevsim device in switchdev mode with 2 VFs and assert the devlink
    /// resolver finds the real representor netdevs. netdevsim moves no packets — this validates the
    /// portable representor resolution (`representor_for`) against a real kernel switchdev eswitch,
    /// which is the mechanism the production mlx5 path also uses. The PCI→vfnum mapping
    /// (`pf_devlink_and_vfnum`) is mlx5-only and is exercised in the live lab, not here.
    #[test]
    #[ignore = "privileged: modprobe netdevsim + devlink switchdev (needs root); run under sudo"]
    fn representor_for_resolves_netdevsim_vf() {
        use std::process::Command;
        // Provision (the TEST owns provisioning; flowplane's claim path never provisions).
        let _ = Command::new("modprobe").arg("netdevsim").status();
        std::fs::write("/sys/bus/netdevsim/new_device", "99 1").expect("new_device");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::write("/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs", "0");
                let _ = std::fs::write("/sys/bus/netdevsim/del_device", "99");
            }
        }
        let _c = Cleanup;
        assert!(
            Command::new("devlink")
                .args([
                    "dev",
                    "eswitch",
                    "set",
                    "netdevsim/netdevsim99",
                    "mode",
                    "switchdev"
                ])
                .status()
                .expect("devlink eswitch set")
                .success(),
            "switchdev set"
        );
        std::fs::write("/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs", "2").expect("numvfs");
        // The VF representor netdevs are created with kernel-default names (eth0, eth1, ...) and
        // renamed to their `eni<id>npf<M>vf<N>` switchdev names ASYNCHRONOUSLY by udev; wait for that
        // to settle so `devlink port show` reports the stable representor name (else we race the rename).
        let _ = Command::new("udevadm").arg("settle").status();

        assert_eq!(
            representor_for("netdevsim/netdevsim99", 0).expect("resolve vf0 representor"),
            "eni99npf0vf0"
        );
        assert_eq!(
            representor_for("netdevsim/netdevsim99", 1).expect("resolve vf1 representor"),
            "eni99npf0vf1"
        );
    }

    /// Privileged: stand up a netdevsim device in switchdev mode with 2 VFs and assert `pcivf_reps()`
    /// enumerates BOTH VF representor ifindexes (device-level, attach-state-independent) — the seam
    /// the offload startup flush closes. Unique netdevsim id (61) so it can run alongside the sibling
    /// test. netdevsim moves no packets; this validates the enumeration against a real kernel eswitch.
    #[test]
    #[ignore = "privileged: modprobe netdevsim + devlink switchdev (needs root); run under sudo"]
    fn pcivf_reps_enumerates_netdevsim_vfs() {
        use std::process::Command;
        let _ = Command::new("modprobe").arg("netdevsim").status();
        std::fs::write("/sys/bus/netdevsim/new_device", "61 1").expect("new_device");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::write("/sys/bus/netdevsim/devices/netdevsim61/sriov_numvfs", "0");
                let _ = std::fs::write("/sys/bus/netdevsim/del_device", "61");
            }
        }
        let _c = Cleanup;
        assert!(
            Command::new("devlink")
                .args([
                    "dev",
                    "eswitch",
                    "set",
                    "netdevsim/netdevsim61",
                    "mode",
                    "switchdev"
                ])
                .status()
                .expect("devlink eswitch set")
                .success(),
            "switchdev set"
        );
        std::fs::write("/sys/bus/netdevsim/devices/netdevsim61/sriov_numvfs", "2").expect("numvfs");
        let _ = Command::new("udevadm").arg("settle").status();

        let vf0 = ifindex_of("eni61npf0vf0").expect("resolve vf0 representor ifindex");
        let vf1 = ifindex_of("eni61npf0vf1").expect("resolve vf1 representor ifindex");
        let reps = pcivf_reps().expect("enumerate pcivf reps");
        assert!(
            reps.contains(&vf0),
            "pcivf_reps {reps:?} must contain vf0 ifindex {vf0}"
        );
        assert!(
            reps.contains(&vf1),
            "pcivf_reps {reps:?} must contain vf1 ifindex {vf1}"
        );
    }
}
