//! SR-IOV VF guest-edge backend: CLAIM a pre-provisioned VF (flowplane never writes sriov_numvfs /
//! eswitch mode — that is one-time node/operator setup), resolve its switchdev REPRESENTOR netdev
//! (the root-netns datapath device tc_guest_tx attaches to), set the VF mac/mtu, move the VF into the
//! guest netns, and return the representor DeviceInfo. Mirrors tap.rs/netkit.rs (ip/devlink shell-out
//! via veth.rs helpers; no netlink crate). SF (subfunction) is a future sibling entry point.

use crate::veth::{fmt_mac, ifindex_of, run, run_netns, DeviceInfo};
use anyhow::{bail, Context, Result};

/// A representor's VF index parsed from a `phys_port_name`. mlx5 form `pf<M>vf<N>` and the bare
/// `vf<N>` form both resolve to `N`. Anything else (PF/SF/uplink port names) → None.
pub(crate) fn parse_phys_port_name(s: &str) -> Option<u32> {
    let s = s.trim();
    let (_pf, vf) = s.split_once("vf")?; // "pf0vf3" -> ("pf0","3"); "vf3" -> ("","3")
    vf.parse::<u32>().ok()
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

/// The VF's index on its parent PF: the `N` for which `<pf>/virtfnN` -> this `bdf`.
pub(crate) fn vf_index_of(pci: &str) -> Result<u32> {
    let physfn = std::fs::read_link(format!("/sys/bus/pci/devices/{pci}/physfn"))
        .with_context(|| format!("read physfn of {pci} (not a VF?)"))?;
    let pf = physfn
        .file_name()
        .context("physfn has no basename")?
        .to_string_lossy()
        .into_owned();
    for n in 0..256u32 {
        let link = format!("/sys/bus/pci/devices/{pf}/virtfn{n}");
        if let Ok(t) = std::fs::read_link(&link) {
            if t.file_name()
                .map(|b| b.to_string_lossy() == *pci)
                .unwrap_or(false)
            {
                return Ok(n);
            }
        }
    }
    bail!("could not find virtfn index for {pci} under PF {pf}")
}

/// Find the switchdev representor netdev for `vf_index` whose parent PCI dev is `pf` — the root-netns
/// netdev whose `phys_port_name` parses to `vf_index`. Requires the PF to be in switchdev mode (else
/// no representor exists → error; flowplane does not enable switchdev — that is operator setup).
fn find_representor(pf: &str, vf_index: u32) -> Result<String> {
    for entry in std::fs::read_dir("/sys/class/net").context("read /sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let ppn_path = format!("/sys/class/net/{name}/phys_port_name");
        let Ok(ppn) = std::fs::read_to_string(&ppn_path) else {
            continue;
        };
        if parse_phys_port_name(&ppn) != Some(vf_index) {
            continue;
        }
        let dev = std::fs::read_link(format!("/sys/class/net/{name}/device"))
            .ok()
            .and_then(|p| p.file_name().map(|b| b.to_string_lossy().into_owned()));
        if dev.as_deref() == Some(pf) {
            return Ok(name);
        }
    }
    bail!("no switchdev representor for vf{vf_index} on PF {pf} (is the PF in switchdev mode?)")
}

/// CLAIM a pre-provisioned VF: resolve its representor, set the VF mac/mtu, move the VF into the guest
/// netns, and return the REPRESENTOR DeviceInfo (host_ifindex = representor ifindex). Does NOT create
/// VFs or set eswitch mode.
pub fn claim_vf(spec: &VfSpec) -> Result<DeviceInfo> {
    let pci = &spec.pci_address;
    let pf = std::fs::read_link(format!("/sys/bus/pci/devices/{pci}/physfn"))
        .with_context(|| format!("read physfn of {pci}"))?
        .file_name()
        .context("physfn basename")?
        .to_string_lossy()
        .into_owned();
    let vf_index = vf_index_of(pci)?;
    let representor = find_representor(&pf, vf_index)?;
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
    fn phys_port_name_parses_vf_index() {
        assert_eq!(parse_phys_port_name("pf0vf3"), Some(3));
        assert_eq!(parse_phys_port_name("pf1vf0"), Some(0));
        assert_eq!(parse_phys_port_name("vf7"), Some(7));
        assert_eq!(parse_phys_port_name("p0"), None); // PF/uplink port
        assert_eq!(parse_phys_port_name("pf0sf88"), None); // subfunction rep, not a VF
        assert_eq!(parse_phys_port_name(""), None);
    }
}
