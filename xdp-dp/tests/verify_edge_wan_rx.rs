//! Verifier load check for the WAN-edge `wan_rx` program.
//!
//! `wan_rx` contains the `encap_and_redirect` fabric redirect, which was changed from a plain
//! `bpf_redirect(uplink_ifindex)` to a `UPLINK_DEV` devmap redirect (so containerlab veth uplinks
//! deliver the XDP_REDIRECT without a peer XDP program). The existing anchors only load `uplink_rx`,
//! which does NOT contain `encap_and_redirect`, so this test loads `wan_rx` specifically to prove the
//! devmap-redirect path passes the kernel verifier.
//!
//! Privileged: needs CAP_BPF + a kernel with XDP. Run via `sudo -E cargo test -p xdp-dp --test
//! verify_edge_wan_rx -- --ignored`.

use aya::programs::Xdp;

#[test]
#[ignore = "requires root/CAP_BPF and a kernel with XDP"]
fn wan_rx_devmap_redirect_verifies() {
    // Load the real compiled eBPF object the same way the daemon (and the anchors) do.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut ebpf = aya::EbpfLoader::new()
        .load(bytes)
        .expect("load compiled eBPF object (creates all maps, incl UPLINK_DEV)");

    // Load (= verify) wan_rx into the kernel. This exercises the verifier over the devmap redirect in
    // encap_and_redirect. No map population is needed — loading verifies the instructions regardless
    // of map contents.
    let prog: &mut Xdp = ebpf
        .program_mut("wan_rx")
        .expect("wan_rx program present")
        .try_into()
        .expect("wan_rx is an XDP program");
    prog.load()
        .expect("verify/load wan_rx (devmap redirect must pass the verifier)");
}
