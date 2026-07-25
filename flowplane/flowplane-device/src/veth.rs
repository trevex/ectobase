//! Container guest-edge device lifecycle: create a veth pair, move the guest end into the pod
//! netns, configure both ends, and resolve the host ifindex. Extracted verbatim from the eBPF
//! `attach.rs` veth path so both backends share ONE implementation (no drift).

use anyhow::{bail, Context, Result};
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

/// Verbatim from attach.rs `fn fmt_mac`.
fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Run `ip`/other command in the root netns. Verbatim from attach.rs `fn run`.
pub(crate) fn run(args: &[&str]) -> Result<()> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {args:?}"))?;
    if !out.status.success() {
        bail!(
            "command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Run a command inside the netns identified by `netns_path` via `ip netns exec <name>`.
/// `netns_path` is a path like `/var/run/netns/<name>`; we extract `<name>` for `ip netns exec`.
/// Verbatim from attach.rs `fn run_netns`.
pub(crate) fn run_netns(netns_path: &str, args: &[&str]) -> Result<()> {
    let ns = netns_path.rsplit('/').next().unwrap_or(netns_path);
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    run(&full)
}

/// Read `/sys/class/net/<name>/ifindex` to resolve the host interface index.
fn ifindex_of(name: &str) -> Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .with_context(|| format!("read ifindex of {name}"))?;
    s.trim()
        .parse()
        .with_context(|| format!("parse ifindex of {name}: {s:?}"))
}

/// Idempotent `ip link del <name>` (ignores errors / "not found").
pub fn delete_link(name: &str) {
    let _ = run(&["ip", "link", "del", name]);
}

/// Create + configure the veth pair, returning the resolved host device facts. Rolls back
/// (`delete_link(host)`) on any step failure. The `ip` command sequence is transcribed verbatim
/// from `attach.rs` `setup_veth`: create pair → move peer to netns → rename → guest mac/up/mtu
/// → tcp_mtu_probing best-effort → optional ethtool csum-off → host mac/mtu/up.
pub fn create_veth_pair(spec: &VethSpec) -> Result<DeviceInfo> {
    // Fresh start: remove any stale host-side veth from a previous run.
    let _ = run(&["ip", "link", "del", &spec.host_name]);
    let host = &spec.host_name;
    // Temporary guest-end name in the root netns before we move it (must differ from host and
    // be unique); derive it from the host name to avoid collisions.
    let tmp_guest = format!("{host}p");
    let macs = fmt_mac(spec.mac);
    let mtu = spec.mtu.to_string();

    let result = (|| -> Result<u32> {
        run(&[
            "ip", "link", "add", host, "type", "veth", "peer", "name", &tmp_guest,
        ])
        .context("create veth pair")?;
        // Move the guest end into the target netns (by path, e.g. /var/run/netns/<ns>).
        run(&["ip", "link", "set", &tmp_guest, "netns", &spec.netns_path])
            .context("move guest veth into netns")?;
        // Inside the netns: rename to the requested guest name, set MAC, bring up.
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &tmp_guest, "name", &spec.guest_name],
        )
        .context("rename guest veth")?;
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &spec.guest_name, "address", &macs],
        )
        .context("set guest veth mac")?;
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &spec.guest_name, "up"],
        )
        .context("guest veth up")?;
        // Set the guest link MTU (node-wide value = underlay MTU - encap overhead).
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &spec.guest_name, "mtu", &mtu],
        )
        .context("set guest veth mtu")?;
        // Enable TCP Packetization-Layer PMTUD (RFC 4821) in the guest netns — best-effort.
        let _ = run_netns(
            &spec.netns_path,
            &["sysctl", "-wq", "net.ipv4.tcp_mtu_probing=1"],
        );
        // Disable tx-checksum offload on the guest end — only when the uplink can't finalize
        // CHECKSUM_PARTIAL in hardware (software veth fabric). Best-effort.
        if spec.disable_csum_offload {
            let _ = run_netns(
                &spec.netns_path,
                &[
                    "ethtool",
                    "-K",
                    &spec.guest_name,
                    "tx-checksum-ip-generic",
                    "off",
                ],
            );
        }
        // Give the HOST end the SAME (guest) MAC, then bring it up.
        run(&["ip", "link", "set", host, "address", &macs]).context("set host veth mac")?;
        // Host end MTU must be >= the guest's so a full-size guest frame is never dropped.
        run(&["ip", "link", "set", host, "mtu", &mtu]).context("set host veth mtu")?;
        run(&["ip", "link", "set", host, "up"]).context("host veth up")?;
        ifindex_of(host)
    })();

    match result {
        Ok(host_ifindex) => Ok(DeviceInfo {
            host_ifindex,
            host_name: spec.host_name.clone(),
            mac: spec.mac,
        }),
        Err(e) => {
            delete_link(host);
            Err(e)
        }
    }
}

/// Create a veth pair with BOTH ends in the root netns (host-end up, mac/mtu set) for the
/// preallocated per-guest af_xdp port pool. The guest-end (`<host_name>p`, the [`create_veth_pair`]
/// tmp-guest convention) stays a root-netns placeholder until AttachInterface moves it into the pod
/// netns. Returns the resolved host [`DeviceInfo`]. Rolls back (delete host) on failure.
///
/// This is the preallocation sibling of [`create_veth_pair`]: the `ip` sequence is modeled on it but
/// WITHOUT the netns move/rename (`ip link add <host> type veth peer name <host>p` → set host
/// mac/mtu/up → leave the peer down in the root netns → resolve host ifindex). The peer name
/// convention `<host>p` is preserved so AttachInterface knows where to find the placeholder guest end.
pub fn create_preallocated_veth(host_name: &str, mac: [u8; 6], mtu: u32) -> Result<DeviceInfo> {
    // Fresh start: remove any stale host-side veth from a previous run (deletes the peer too).
    delete_link(host_name);
    // Temporary/placeholder guest-end name in the root netns — same `<host>p` convention as
    // `create_veth_pair`'s `tmp_guest` so AttachInterface can locate + move it later.
    let tmp_guest = format!("{host_name}p");
    let macs = fmt_mac(mac);
    let mtu = mtu.to_string();

    let result = (|| -> Result<u32> {
        run(&[
            "ip", "link", "add", host_name, "type", "veth", "peer", "name", &tmp_guest,
        ])
        .context("create preallocated veth pair")?;
        // Give the HOST end the placeholder MAC (the real guest MAC is programmed at attach), then
        // bring it up. The peer stays down in the root netns as a placeholder.
        run(&["ip", "link", "set", host_name, "address", &macs]).context("set host veth mac")?;
        run(&["ip", "link", "set", host_name, "mtu", &mtu]).context("set host veth mtu")?;
        run(&["ip", "link", "set", host_name, "up"]).context("host veth up")?;
        ifindex_of(host_name)
    })();

    match result {
        Ok(host_ifindex) => Ok(DeviceInfo {
            host_ifindex,
            host_name: host_name.to_string(),
            mac,
        }),
        Err(e) => {
            delete_link(host_name);
            Err(e)
        }
    }
}

/// Bind a PREALLOCATED pool slot's placeholder guest-end into a pod netns (Task 4 attach).
///
/// The guest-end currently lives in the ROOT netns as `placeholder_peer` (the `<host>p` convention
/// from [`create_preallocated_veth`]). This moves it into `netns_path`, renames it to `guest_name`,
/// sets its MAC, brings it up, sets the MTU, best-effort PLPMTUD + optional csum-off — i.e. exactly
/// [`create_veth_pair`]'s netns portion, but starting from an EXISTING peer instead of creating a new
/// pair. The host-end (`fpg{i}`, bound to the af_xdp ethdev port) is UNTOUCHED — it stays up in the
/// root netns and keeps its static poll-set membership; only the guest-end moves.
///
/// On any step failure this attempts to move the guest-end back to the root netns and rename it to
/// `placeholder_peer` (best-effort) so a failed bind doesn't strand the placeholder inside a netns.
pub fn bind_preallocated_guest_end(
    placeholder_peer: &str,
    netns_path: &str,
    guest_name: &str,
    mac: [u8; 6],
    mtu: u32,
    disable_csum_offload: bool,
) -> Result<()> {
    let macs = fmt_mac(mac);
    let mtu_s = mtu.to_string();

    let result = (|| -> Result<()> {
        // Move the placeholder guest-end into the target netns (by path).
        run(&["ip", "link", "set", placeholder_peer, "netns", netns_path])
            .context("move pool guest-end into netns")?;
        // Inside the netns: rename to the requested guest name, set MAC, bring up, set MTU.
        run_netns(
            netns_path,
            &["ip", "link", "set", placeholder_peer, "name", guest_name],
        )
        .context("rename pool guest-end")?;
        run_netns(
            netns_path,
            &["ip", "link", "set", guest_name, "address", &macs],
        )
        .context("set pool guest-end mac")?;
        run_netns(netns_path, &["ip", "link", "set", guest_name, "up"])
            .context("pool guest-end up")?;
        run_netns(
            netns_path,
            &["ip", "link", "set", guest_name, "mtu", &mtu_s],
        )
        .context("set pool guest-end mtu")?;
        // Enable TCP PLPMTUD (RFC 4821) in the guest netns — best-effort.
        let _ = run_netns(netns_path, &["sysctl", "-wq", "net.ipv4.tcp_mtu_probing=1"]);
        // Disable tx-checksum offload only when the uplink can't finalize CHECKSUM_PARTIAL in
        // hardware (software veth fabric). Best-effort.
        if disable_csum_offload {
            let _ = run_netns(
                netns_path,
                &["ethtool", "-K", guest_name, "tx-checksum-ip-generic", "off"],
            );
        }
        Ok(())
    })();

    if let Err(e) = result {
        // Best-effort rollback: whichever step failed, try to get the guest-end back to the root
        // netns under its placeholder name so the slot isn't stranded. The rename may or may not
        // have happened, so try both names for the move-back.
        let _ = run_netns(netns_path, &["ip", "link", "set", guest_name, "netns", "1"]);
        let _ = run_netns(
            netns_path,
            &["ip", "link", "set", placeholder_peer, "netns", "1"],
        );
        // If the rename succeeded, the link is now `guest_name` in the root netns — rename it back.
        let _ = run(&["ip", "link", "set", guest_name, "name", placeholder_peer]);
        let _ = run(&["ip", "link", "set", placeholder_peer, "down"]);
        return Err(e);
    }
    Ok(())
}

/// Unbind a pool slot's guest-end from a pod netns back to the root netns (Task 4 detach).
///
/// Moves the guest-end (`guest_name` inside `netns_path`) back to the init/root netns (by pid 1),
/// renames it to `placeholder_peer` (the `<host>p` convention), and brings it DOWN — restoring the
/// preallocated placeholder for slot reuse. The host-end is untouched.
///
/// BEST-EFFORT by design: if the netns or the link is already gone (a pod whose netns was destroyed
/// took the guest-end — and, because veth pairs die together, potentially the host-end — with it),
/// each step is ignored so the detach RPC's map/IPAM/slot reclaim always completes. Always returns
/// `Ok`; robust dead-slot reclaim (recreating the veth + rebinding the ethdev) is a documented
/// follow-up ("detach/reuse hardening" in the plan), NOT implemented here.
pub fn unbind_preallocated_guest_end(
    netns_path: &str,
    guest_name: &str,
    placeholder_peer: &str,
) -> Result<()> {
    // Move the guest-end to the init/root netns by pid 1 (works from inside `ip netns exec`).
    let _ = run_netns(netns_path, &["ip", "link", "set", guest_name, "netns", "1"]);
    // Back in the root netns: rename to the placeholder + set down. Ignore errors (link may be gone
    // if the pod netns was destroyed before detach — a documented first-slice limitation).
    let _ = run(&["ip", "link", "set", guest_name, "name", placeholder_peer]);
    let _ = run(&["ip", "link", "set", placeholder_peer, "down"]);
    Ok(())
}

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

    #[test]
    #[ignore = "privileged: creates a root-netns veth pair (needs CAP_NET_ADMIN); run under sudo"]
    fn create_preallocated_veth_leaves_peer_in_root_netns() {
        let host = "fpdev-pg0";
        delete_link(host);
        let info =
            create_preallocated_veth(host, [0x02, 0, 0, 0, 0x0e, 0x00], 1450).expect("create");
        assert!(info.host_ifindex >= 2, "resolved a real host ifindex");
        assert_eq!(info.host_name, host);
        // Host end present in the root netns.
        assert!(ifindex_of(host).is_ok(), "host end present");
        // The placeholder guest end (`<host>p`) is ALSO present in the root netns (not moved away).
        assert!(
            ifindex_of(&format!("{host}p")).is_ok(),
            "peer stays in root netns"
        );
        // cleanup (deletes the peer too)
        delete_link(host);
    }

    #[test]
    #[ignore = "privileged: creates a pool veth + netns (needs CAP_NET_ADMIN); run under sudo"]
    fn bind_then_unbind_preallocated_guest_end_roundtrips() {
        let host = "fpdev-bind0";
        let peer = "fpdev-bind0p";
        let ns = "fpdev-bind-ns";
        delete_link(host);
        let _ = run(&["ip", "netns", "del", ns]);
        run(&["ip", "netns", "add", ns]).unwrap();
        let netns_path = format!("/var/run/netns/{ns}");

        // Preallocate the pool pair (host up, peer down in root netns).
        create_preallocated_veth(host, [0x02, 0, 0, 0, 0x0e, 0x01], 1450).expect("create");
        assert!(ifindex_of(peer).is_ok(), "placeholder peer in root netns");

        // Bind: move the peer into the netns as `guest0`.
        bind_preallocated_guest_end(
            peer,
            &netns_path,
            "guest0",
            [0x02, 0, 0, 0, 0x0e, 0x02],
            1400,
            false,
        )
        .expect("bind");
        // Peer gone from root netns; guest0 present inside the netns; host untouched.
        assert!(ifindex_of(peer).is_err(), "peer moved out of root netns");
        run_netns(&netns_path, &["ip", "link", "show", "guest0"]).expect("guest0 in netns");
        assert!(ifindex_of(host).is_ok(), "host end survives bind");

        // Unbind: move it back to the root netns as the placeholder.
        unbind_preallocated_guest_end(&netns_path, "guest0", peer).expect("unbind");
        assert!(ifindex_of(peer).is_ok(), "peer back in root netns");
        assert!(ifindex_of(host).is_ok(), "host end survives unbind");

        // cleanup
        delete_link(host);
        let _ = run(&["ip", "netns", "del", ns]);
    }
}
