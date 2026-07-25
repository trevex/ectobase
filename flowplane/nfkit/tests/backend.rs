use nfkit::Backend;

#[test]
fn backend_builds_eal_and_vdev_args() {
    let b = Backend::Pcap {
        rx: "in.pcap".into(),
        tx: "out.pcap".into(),
    };
    let eal = b.eal_args("nfkit");
    assert!(eal.iter().any(|a| a == "--no-huge"));
    assert!(
        eal.iter().any(|a| a.starts_with("net_pcap")),
        "vdev arg present: {eal:?}"
    );
    let n = Backend::Null.eal_args("nfkit");
    assert!(n.iter().any(|a| a == "net_null0"));
    let a = Backend::AfXdp {
        iface: "vv0".into(),
        queues: 1,
    };
    let ae = a.eal_args("nfkit");
    assert!(!ae.iter().any(|x| x == "--no-huge"));
    assert!(ae.iter().any(|x| x.contains("iface=vv0")));
}

/// `eal_args_lcores` builds an explicit `-l <list>` for constrained hosts (clab/CI), while the
/// convenience `eal_args` keeps the default `0-3`.
#[test]
fn eal_args_lcores_sets_explicit_l_range() {
    let b = Backend::Null;
    let default = b.eal_args("nfkit");
    let l_idx = default.iter().position(|a| a == "-l").expect("-l present");
    assert_eq!(default[l_idx + 1], "0-3", "default lcore range");

    let single = b.eal_args_lcores("nfkit", "0-1");
    let l_idx = single.iter().position(|a| a == "-l").expect("-l present");
    assert_eq!(
        single[l_idx + 1],
        "0-1",
        "explicit lcore range threaded through"
    );
    // Still a valid Null-backend argv otherwise.
    assert!(single.iter().any(|a| a == "net_null0"));
    assert!(single.iter().any(|a| a == "--no-huge"));
}

/// `eal_args_lcores_with_guest_ifaces` appends one `net_af_xdp{1+i}` vdev per guest iface for the
/// AfXdp backend, indexed after the uplink (net_af_xdp0). This is the per-guest af_xdp port model.
#[test]
fn guest_ifaces_append_indexed_afxdp_vdevs() {
    let b = Backend::AfXdp {
        iface: "uplink0".into(),
        queues: 2,
    };
    let guests = vec!["vethg0".to_string(), "vethg1".to_string()];
    let args = b.eal_args_lcores_with_guest_ifaces("nfkit", "0-3", &guests);
    // Uplink is net_af_xdp0.
    assert!(
        args.iter()
            .any(|a| a.starts_with("net_af_xdp0,iface=uplink0")),
        "uplink vdev present: {args:?}"
    );
    // Guest 0 -> net_af_xdp1, guest 1 -> net_af_xdp2 (offset by the uplink).
    assert!(
        args.iter()
            .any(|a| a.starts_with("net_af_xdp1,iface=vethg0")),
        "guest 0 vdev present: {args:?}"
    );
    assert!(
        args.iter()
            .any(|a| a.starts_with("net_af_xdp2,iface=vethg1")),
        "guest 1 vdev present: {args:?}"
    );
    // Each guest port is single-queue.
    assert!(args
        .iter()
        .any(|a| a == "net_af_xdp1,iface=vethg0,start_queue=0,queue_count=1"));
}

/// For non-AfXdp backends, guest ifaces are ignored (guest af_xdp ports are AfXdp-only).
#[test]
fn guest_ifaces_ignored_for_non_afxdp() {
    let b = Backend::Null;
    let guests = vec!["vethg0".to_string()];
    let with = b.eal_args_lcores_with_guest_ifaces("nfkit", "0-1", &guests);
    let without = b.eal_args_lcores("nfkit", "0-1");
    assert_eq!(
        with, without,
        "guest ifaces must not alter a non-AfXdp argv"
    );
}
