//! Verifier load check for the guest-facing tc classifiers.
//!
//! The XDP anchors (`anchor_uplink`, `anchor_lb`, `verify_edge_wan_rx`) load the uplink/edge XDP
//! programs, but the guest-egress path runs as `tc` (`SchedClassifier`) programs on the tap: the
//! main guest-TX classifier plus the NAT64 and DHCPv6 helpers. This test loads each of them from
//! the SAME compiled eBPF object and asserts the kernel verifier accepts them, so a verifier
//! regression in the tc datapath is caught by CI's `--ignored` anchor run just like the XDP ones.
//!
//! Privileged: needs CAP_BPF + a kernel with tc BPF. Run via `sudo -E cargo test -p xdp-dp --test
//! verify_tc_guest -- --ignored`.

use aya::programs::SchedClassifier;

#[test]
#[ignore = "requires root/CAP_BPF and a kernel with tc BPF"]
fn tc_guest_classifiers_load() {
    // Load the real compiled eBPF object the same way the daemon (and the XDP anchors) do.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
    let pin = tempfile::Builder::new()
        .prefix("xdp-dp-verify-tc-guest-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object (creates all maps)");

    // Load (= verify) each guest-facing tc classifier into the kernel. Loading verifies the
    // instructions regardless of map contents, so no map population is needed.
    for name in ["tc_guest_tx", "tc_guest_nat64", "tc_guest_dhcp"] {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program {name} present"))
            .try_into()
            .unwrap_or_else(|_| panic!("{name} is a SchedClassifier program"));
        prog.load()
            .unwrap_or_else(|e| panic!("verify/load {name} (must pass the verifier): {e}"));
    }
}
