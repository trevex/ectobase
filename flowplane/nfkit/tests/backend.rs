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
