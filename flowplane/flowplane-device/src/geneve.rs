//! Host-side `collect_md` Geneve device lifecycle. P2 replaces the hand-rolled IP-in-IPv6 overlay
//! encap with a single kernel Geneve device in "external" (`collect_md`) metadata mode: the
//! datapath programs `bpf_skb_set_tunnel_key`/`bpf_skb_get_tunnel_key` per-packet instead of a
//! fixed per-device VNI/remote. Mirrors `veth.rs`'s `ip`-subprocess style; reuses `run`/`ifindex_of`
//! so there is ONE way this daemon shells `ip` (no drift).
use crate::veth::{ifindex_of, link_exists, mac_of, run};
use anyhow::{Context, Result};

/// Well-known name for the single node-wide `collect_md` Geneve device the daemon creates at
/// bring-up. One device serves every VNI/remote — `external` mode means the kernel does not fix a
/// destination or VNI on the device itself; the tc program supplies both per-packet.
pub const GENEVE_DEV: &str = "fp-geneve0";

/// Outcome of [`ensure_geneve_dev`]: the resolved ifindex, plus whether the netdev was CREATED fresh
/// this call (`recreated == true`) versus CONFIRMED in place (`false`). Callers use `recreated` to
/// decide how to (re)attach the device's pinned tc links: a fresh device has a new ifindex, so any
/// surviving pinned link from a prior process points at the OLD (now-gone) device and MUST be
/// fresh-attached — re-pointing it via `bpf_link_update` can silently land on a dangling link
/// (program updated, but attached to nothing). A confirmed device keeps its links valid, so the
/// zero-gap adopt re-point is correct.
pub struct GeneveDev {
    pub ifindex: u32,
    pub recreated: bool,
}

/// Build the `ip link add <name> type geneve external` argument vector (no destination, no VNI —
/// `external` is exactly the `collect_md` metadata mode: the datapath program supplies the tunnel
/// key per-packet via `bpf_skb_set_tunnel_key`/`get_tunnel_key`). Args only — `run()` supplies the
/// leading `"ip"` (see `veth.rs`'s `run`/`ifindex_of` convention).
pub fn geneve_add_args(name: &str) -> Vec<String> {
    vec![
        "link".into(),
        "add".into(),
        name.into(),
        "type".into(),
        "geneve".into(),
        "external".into(),
    ]
}

/// Idempotently ensure the `collect_md` Geneve device exists, is UP, and carries the gateway MAC,
/// returning its ifindex + whether it was (re)created this call. A device that is absent OR mis-MAC'd
/// is recreated (`ip link add ... type geneve external`); a correctly-MAC'd survivor is CONFIRMED
/// without recreating (the delete+add would sever the pinned tc/tcx links — `uplink_rx`,
/// `uplink_dsr_note` — and the adopt re-point can then silently land on a dead link, leaving
/// `uplink_rx` attached to nothing; see `Control::bring_up`'s fresh-attach-on-recreate handling).
/// Either way the MAC is stamped AFTER `up` and unconditionally (see below). Reuses `geneve_add_args`
/// so the tested arg vector is exactly what gets shelled.
pub fn ensure_geneve_dev(name: &str, gateway_mac: [u8; 6]) -> Result<GeneveDev> {
    let macs = crate::veth::fmt_mac(gateway_mac);
    // CONFIRM (already the gateway MAC) vs RECREATE (absent / mis-MAC'd / random). The confirm path
    // preserves the surviving device's pinned datapath links for a zero-gap adopt.
    let recreated = if link_exists(name) && mac_of(name).map(|m| m == gateway_mac).unwrap_or(false)
    {
        false
    } else {
        delete_geneve_dev(name)?;
        let mut argv: Vec<String> = vec!["ip".into()];
        argv.extend(geneve_add_args(name));
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        run(&argv).with_context(|| format!("create geneve dev {name}"))?;
        true
    };
    // Bring up FIRST, then stamp the MAC — and stamp it UNCONDITIONALLY (idempotent on the confirm
    // path). The kernel `collect_md` geneve device carries INNER ETHERNET (TEB) and runs
    // `eth_type_trans` on decap: an overlay->WAN reply (e.g. a DSR reverse-SNAT src->VIP) arrives with
    // inner dst MAC = the gateway MAC, so the device MAC MUST equal it or `ip6_rcv_core` drops it
    // `PACKET_OTHERHOST` before it can be forwarded/local-delivered (backends never hit this —
    // `uplink_rx` bpf_redirects at the tc-ingress hook, BEFORE that check; only the edge's kernel
    // local-deliver does). CRUCIAL ordering: a geneve device can regenerate its link address on `up`,
    // silently overriding a pre-`up` stamp (observed live — one anycast edge kept a random MAC and
    // black-holed the DSR return); stamping AFTER `up` sticks. `setmac`-while-up on a geneve device is
    // link-safe (does NOT sever tc links, verified live), so this is safe on the confirm path too.
    run(&["ip", "link", "set", name, "up"]).with_context(|| format!("geneve dev {name} up"))?;
    run(&["ip", "link", "set", name, "address", &macs])
        .with_context(|| format!("set geneve dev {name} mac"))?;
    Ok(GeneveDev {
        ifindex: ifindex_of(name)?,
        recreated,
    })
}

/// Idempotent `ip link del <name>` (ignores "does not exist" / any other error — best-effort,
/// matching `veth.rs::delete_link`'s contract, just `Result`-returning per this module's callers).
pub fn delete_geneve_dev(name: &str) -> Result<()> {
    let _ = run(&["ip", "link", "del", name]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veth::{link_exists, mac_of};

    #[test]
    fn geneve_add_args_are_collect_md() {
        assert_eq!(
            geneve_add_args("fp-geneve0"),
            vec!["link", "add", "fp-geneve0", "type", "geneve", "external"]
        );
    }

    #[test]
    #[ignore = "privileged: creates a geneve netdev (needs CAP_NET_ADMIN); run under sudo"]
    fn ensure_geneve_dev_is_idempotent_and_up() {
        let name = "fpdev-geneve-test0";
        let _ = delete_geneve_dev(name);
        let gw_mac = [0x02, 0, 0, 0, 0, 0x01];
        let dev1 = ensure_geneve_dev(name, gw_mac).expect("create geneve dev");
        assert!(dev1.ifindex >= 2, "resolved a real ifindex");
        assert!(dev1.recreated, "first ensure creates the device fresh");
        assert!(link_exists(name), "geneve dev present after create");
        assert_eq!(
            mac_of(name).expect("read geneve mac"),
            gw_mac,
            "gateway MAC stamped"
        );
        // Re-running must be idempotent AND must PRESERVE the surviving device (CONFIRM path, not
        // delete+recreate) so any pinned tc links on it stay valid — same ifindex + recreated==false
        // proves it was not torn down and re-added.
        let dev2 = ensure_geneve_dev(name, gw_mac).expect("confirm geneve dev");
        assert_eq!(
            dev2.ifindex, dev1.ifindex,
            "confirm path preserves the surviving device"
        );
        assert!(!dev2.recreated, "confirm path does not recreate");
        delete_geneve_dev(name).expect("delete geneve dev");
        assert!(
            !link_exists(name),
            "geneve dev gone after delete_geneve_dev"
        );
    }

    #[test]
    fn delete_geneve_dev_of_bogus_name_is_ok() {
        // Deleting a device that never existed must not error (best-effort, matches
        // `veth::delete_link`'s "ignore not found" contract).
        assert!(delete_geneve_dev("fp-no-such-geneve-xyz").is_ok());
    }
}
