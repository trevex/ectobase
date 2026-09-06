//! Host-side `collect_md` Geneve device lifecycle. P2 replaces the hand-rolled IP-in-IPv6 overlay
//! encap with a single kernel Geneve device in "external" (`collect_md`) metadata mode: the
//! datapath programs `bpf_skb_set_tunnel_key`/`bpf_skb_get_tunnel_key` per-packet instead of a
//! fixed per-device VNI/remote. Mirrors `veth.rs`'s `ip`-subprocess style; reuses `run`/`ifindex_of`
//! so there is ONE way this daemon shells `ip` (no drift).
use crate::veth::{ifindex_of, run};
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

/// Idempotently create the `collect_md` Geneve device: delete-if-exists, `ip link add ... type
/// geneve external`, bring it up, resolve + return its ifindex. Mirrors `veth.rs`'s
/// create-fresh-then-configure idiom (`create_veth_pair`/`create_preallocated_veth`). Reuses
/// `geneve_add_args` for the add command so the tested arg vector is exactly what gets shelled.
pub fn ensure_geneve_dev(name: &str, gateway_mac: [u8; 6]) -> Result<u32> {
    // Fresh start: remove any stale device from a previous run (ignores "does not exist").
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
    use crate::veth::link_exists;

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
        // Re-running must be idempotent (delete-then-recreate), not error.
        let ifindex2 = ensure_geneve_dev(name, gw_mac).expect("re-create geneve dev");
        assert!(ifindex2 >= 2);
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
