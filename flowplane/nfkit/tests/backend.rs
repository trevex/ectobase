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
