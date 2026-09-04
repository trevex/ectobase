//! Host-side L3 `netkit` pod-device lifecycle. netkit is the in-kernel BPF-programmable pod device
//! (netkit primary in the root netns is the datapath device the eBPF program attaches to; the peer
//! lives inside the pod netns as its `eth0`). In `mode l3` the device carries no L2/eth header and
//! the peer's default policy is drop until a program attaches to the primary (that attach is B.4).
//! Mirrors `geneve.rs`'s `ip`-subprocess style and `veth.rs`'s `create_veth_pair` create → move-peer
//! → rename → set up/mtu → resolve-ifindex → rollback sequence (no MAC-set — L3 netkit has no L2
//! header; see `create_netkit_pair`), reusing `crate::veth::{run, run_netns, ifindex_of}` so there is
//! ONE way this daemon shells `ip` (no drift).
use crate::veth::{ifindex_of, run, run_netns, DeviceInfo, VethSpec};
use anyhow::{Context, Result};

/// Build the `ip link add <primary> type netkit mode l3 peer name <peer>` argument vector. This one
/// command creates BOTH ends at once (primary in the root netns, peer named `<peer>` also in the
/// root netns until moved). `mode l3` selects the L3 (no-eth) datapath. Args only — `run()` supplies
/// the leading `"ip"` (same convention as `geneve_add_args`).
pub fn netkit_add_args(primary: &str, peer: &str) -> Vec<String> {
    vec![
        "link".into(),
        "add".into(),
        primary.into(),
        "type".into(),
        "netkit".into(),
        "mode".into(),
        "l3".into(),
        "peer".into(),
        "name".into(),
        peer.into(),
    ]
}

/// Create + configure the L3 netkit pair, returning the resolved primary (datapath) device facts.
/// Idempotent (deletes any stale primary first) and rolls back (`delete_netkit(primary)`) on any step
/// failure after create. Models `veth.rs::create_veth_pair`'s sequence: create pair → move peer into
/// the pod netns → rename to `spec.guest_name` → set peer up/mtu → set primary mtu/up → resolve
/// primary ifindex. Reuses `netkit_add_args` for the add command so the tested arg vector is exactly
/// what gets shelled. Uses the same `run_netns` (`ip netns exec`) netns-entry mechanism as veth.rs.
pub fn create_netkit_pair(spec: &VethSpec) -> Result<DeviceInfo> {
    // Fresh start: remove any stale primary from a previous run (deletes the peer too).
    delete_netkit(&spec.host_name)?;
    let primary = &spec.host_name;
    // Temporary peer name in the root netns before we move it (must differ from primary and be
    // unique); derive it from the primary name to avoid collisions — same `<primary>p` convention
    // as `create_veth_pair`'s `tmp_guest`.
    let tmp_peer = format!("{primary}p");
    let mtu = spec.mtu.to_string();

    let result = (|| -> Result<u32> {
        let mut argv: Vec<String> = vec!["ip".into()];
        argv.extend(netkit_add_args(primary, &tmp_peer));
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run(&argv).context("create netkit pair")?;
        // Move the peer end into the target netns (by path, e.g. /var/run/netns/<ns>).
        run(&["ip", "link", "set", &tmp_peer, "netns", &spec.netns_path])
            .context("move netkit peer into netns")?;
        // Inside the netns: rename to the requested guest name, bring up, set MTU.
        //
        // NOTE — unlike veth (L2), an L3 netkit device carries NO L2/eth header: it comes up with a
        // fixed all-zero MAC and the `NOARP` flag, and the kernel REJECTS an address-set on it
        // (`RTNETLINK: Operation not supported`, verified live on this host). So `spec.mac` is NOT
        // applied to the device — it is retained in the returned `DeviceInfo` only for the caller's
        // map programming (local L3 delivery doesn't consult a device MAC). This is the one place the
        // sequence intentionally differs from `create_veth_pair`.
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &tmp_peer, "name", &spec.guest_name],
        )
        .context("rename netkit peer")?;
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &spec.guest_name, "up"],
        )
        .context("netkit peer up")?;
        run_netns(
            &spec.netns_path,
            &["ip", "link", "set", &spec.guest_name, "mtu", &mtu],
        )
        .context("set netkit peer mtu")?;
        // Configure the PRIMARY (datapath) end in the root netns: MTU >= the peer's, then up. No MAC
        // is set on the primary either — `mode l3` carries no L2/eth header.
        run(&["ip", "link", "set", primary, "mtu", &mtu]).context("set netkit primary mtu")?;
        run(&["ip", "link", "set", primary, "up"]).context("netkit primary up")?;
        ifindex_of(primary)
    })();

    match result {
        Ok(host_ifindex) => Ok(DeviceInfo {
            host_ifindex,
            host_name: spec.host_name.clone(),
            mac: spec.mac,
        }),
        Err(e) => {
            let _ = delete_netkit(primary);
            Err(e)
        }
    }
}

/// Idempotent `ip link del <primary>` — deletes the netkit pair (the peer dies with the primary).
/// Ignores "does not exist" / any other error (best-effort, mirroring `delete_geneve_dev`).
pub fn delete_netkit(primary: &str) -> Result<()> {
    let _ = run(&["ip", "link", "del", primary]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veth::link_exists;

    #[test]
    fn netkit_add_args_are_l3_primary_peer() {
        assert_eq!(
            netkit_add_args("fp-nk0", "fp-nk0p"),
            vec![
                "link", "add", "fp-nk0", "type", "netkit", "mode", "l3", "peer", "name", "fp-nk0p"
            ]
        );
    }

    #[test]
    fn delete_netkit_of_bogus_name_is_ok() {
        // Deleting a device that never existed must not error (best-effort, matches
        // `delete_geneve_dev`'s "ignore not found" contract).
        assert!(delete_netkit("fp-no-such-netkit-xyz").is_ok());
    }

    #[test]
    #[ignore = "privileged: creates a netkit pair (needs CAP_NET_ADMIN); run under sudo"]
    fn create_netkit_pair_stands_up_an_l3_pod_device() {
        // Make a throwaway netns for the peer.
        let ns = "fpdev-netkit-ns";
        let _ = run(&["ip", "netns", "del", ns]);
        run(&["ip", "netns", "add", ns]).unwrap();
        let netns_path = format!("/var/run/netns/{ns}");
        let spec = VethSpec {
            host_name: "fpdev-nk0".into(),
            guest_name: "eth0".into(),
            netns_path: netns_path.clone(),
            mac: [0x02, 0, 0, 0, 0, 0x88],
            mtu: 1400,
            disable_csum_offload: false,
        };
        let info = create_netkit_pair(&spec).expect("create netkit pair");
        // The primary (datapath) end resolves to a real ifindex in the root netns.
        assert!(info.host_ifindex >= 2, "resolved a real primary ifindex");
        // `spec.mac` is carried through for the caller's map programming (an L3 netkit device has no
        // settable MAC — see create_netkit_pair), so DeviceInfo echoes what was requested.
        assert_eq!(info.mac, spec.mac);
        assert!(
            link_exists("fpdev-nk0"),
            "primary end present in root netns"
        );
        // The peer end exists inside the pod netns under the requested guest name.
        run_netns(&netns_path, &["ip", "link", "show", "eth0"]).expect("peer end in netns");
        // Validate the L3 pair came up clean: the peer is UP with the requested MTU, and is an L3
        // (`NOARP`) device — netkit L2 had a kernel MAC-set bug history; the L3 pair sidesteps L2
        // entirely (no MAC to set). Parse the in-netns `ip -o link show` (peer sysfs isn't reachable
        // from the root mount ns).
        assert_peer_up_l3_with_mtu(&netns_path, "eth0", spec.mtu);
        // cleanup
        delete_netkit("fpdev-nk0").expect("delete netkit");
        assert!(!link_exists("fpdev-nk0"), "primary gone after delete");
        let _ = run(&["ip", "netns", "del", ns]);
    }

    /// Assert (inside `netns_path`) that link `name` is UP, an L3/`NOARP` device, and has the
    /// expected MTU, by parsing `ip -o link show <name>`. Panics with a clear message on mismatch.
    fn assert_peer_up_l3_with_mtu(netns_path: &str, name: &str, mtu: u32) {
        use std::process::Command;
        let ns = netns_path.rsplit('/').next().unwrap_or(netns_path);
        let out = Command::new("ip")
            .args(["netns", "exec", ns, "ip", "-o", "link", "show", name])
            .output()
            .expect("spawn ip link show");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("mtu {mtu}")),
            "peer {name} mtu {mtu} not found in {text:?}"
        );
        assert!(text.contains("UP"), "peer {name} not UP in {text:?}");
        assert!(
            text.contains("NOARP"),
            "peer {name} not an L3/NOARP netkit device in {text:?}"
        );
    }
}
