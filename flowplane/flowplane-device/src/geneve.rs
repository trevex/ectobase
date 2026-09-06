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

/// Idempotently ensure the `collect_md` Geneve device exists and is correctly configured, returning
/// its ifindex. On a FRESH start (device absent, or present but mis-MAC'd) it (re)creates the device
/// `ip link add ... type geneve external`, stamps the gateway MAC, brings it up. On a RESTART where a
/// correctly-configured device SURVIVES (the netdev is deliberately not torn down on graceful
/// shutdown — see `Control::bring_up`), it CONFIRMS-without-recreating: the delete+add would sever
/// every pinned tc/tcx link on the device (`uplink_rx`, `uplink_dsr_note`), and the adopt re-point can
/// then silently re-point a program onto the now-dead link instead of re-attaching, leaving
/// `uplink_rx` attached to nothing. Leaving the survivor in place keeps those links valid so the
/// zero-gap adopt works as designed. Reuses `geneve_add_args` so the tested arg vector is exactly what
/// gets shelled.
pub fn ensure_geneve_dev(name: &str, gateway_mac: [u8; 6]) -> Result<u32> {
    // CONFIRM path: a correctly-MAC'd device already survives from a prior bring-up. Do NOT recreate
    // it (that severs the pinned datapath links); just make sure it is up (idempotent, link-safe) and
    // return its ifindex. The gateway-MAC match is the "this is our device, configured by the current
    // code" signal — a survivor from before the MAC fix falls through to the recreate path below.
    if link_exists(name) && mac_of(name).map(|m| m == gateway_mac).unwrap_or(false) {
        run(&["ip", "link", "set", name, "up"]).with_context(|| format!("geneve dev {name} up"))?;
        return ifindex_of(name);
    }
    // Fresh start: remove any stale/mis-MAC'd device from a previous run (ignores "does not exist").
    delete_geneve_dev(name)?;
    let mut argv: Vec<String> = vec!["ip".into()];
    argv.extend(geneve_add_args(name));
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(&argv).with_context(|| format!("create geneve dev {name}"))?;
    // Stamp the device MAC = the anycast overlay gateway MAC (while still DOWN). The kernel
    // `collect_md` geneve device carries INNER ETHERNET (TEB) and runs `eth_type_trans` on decap: an
    // overlay->WAN reply (e.g. a DSR reverse-SNAT src->VIP) arrives with inner dst MAC = the gateway
    // MAC (the guest sent it to its default gateway), so the device MAC MUST match or `ip6_rcv_core`
    // drops it `PACKET_OTHERHOST` before it can be forwarded/local-delivered. Backends never hit this
    // (their `uplink_rx`/`uplink_dsr_note` bpf_redirect at the tc-ingress hook, BEFORE that check);
    // it only bites where the kernel decap path reaches the IP stack — the edge's local-deliver.
    let macs = crate::veth::fmt_mac(gateway_mac);
    run(&["ip", "link", "set", name, "address", &macs])
        .with_context(|| format!("set geneve dev {name} mac"))?;
    run(&["ip", "link", "set", name, "up"]).with_context(|| format!("geneve dev {name} up"))?;
    ifindex_of(name)
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
        let ifindex1 = ensure_geneve_dev(name, gw_mac).expect("create geneve dev");
        assert!(ifindex1 >= 2, "resolved a real ifindex");
        assert!(link_exists(name), "geneve dev present after create");
        assert_eq!(
            mac_of(name).expect("read geneve mac"),
            gw_mac,
            "gateway MAC stamped"
        );
        // Re-running must be idempotent AND must PRESERVE the surviving device (CONFIRM path, not
        // delete+recreate) so any pinned tc links on it stay valid — same ifindex proves it was not
        // torn down and re-added.
        let ifindex2 = ensure_geneve_dev(name, gw_mac).expect("confirm geneve dev");
        assert_eq!(
            ifindex2, ifindex1,
            "confirm path preserves the surviving device"
        );
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
