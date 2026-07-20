// DpdkMaps: Maps trait backed by rte_hash — route add/get + conntrack insert/get.
// Run with --test-threads=1 (EAL is process-global).
use flowplane_common::{CtEntry, CtKey, RouteValue};
use flowplane_core::maps::Maps;
use nfkit::{DpdkMaps, Eal};

#[test]
fn dpdk_maps_route_and_conntrack() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_maps",
    ])
    .expect("EAL init");

    let mut m = DpdkMaps::new(0).expect("DpdkMaps::new");

    // ---- route4: add via test setter, look up via trait getter ----
    let rv = RouteValue {
        nexthop_vni: 99,
        nexthop_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        is_external: 0,
        _pad: [0; 3],
    };
    m.add_route4(7, [10, 0, 0, 5], rv);
    // hit
    assert!(m.route4_get(7, &[10, 0, 0, 5]).is_some(), "route4 hit");
    // wrong host
    assert!(
        m.route4_get(7, &[10, 0, 0, 6]).is_none(),
        "route4 miss (wrong host)"
    );
    // wrong VNI
    assert!(
        m.route4_get(8, &[10, 0, 0, 5]).is_none(),
        "route4 miss (wrong vni)"
    );

    // ---- conntrack: insert via trait mut method, look up via trait getter ----
    let k = CtKey {
        vni: 7,
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        src_port: 1234,
        dst_port: 80,
        proto: 6,
        _pad: [0; 3],
    };
    let e = CtEntry {
        last_seen: 42,
        xlate_ip: [10, 0, 1, 1],
        xlate_port: 8080,
        flags: 0x01,
        tcp_state: 3,
        fwall_action: 1,
        _pad: [0; 7],
    };
    assert!(
        m.conntrack_get(&k).is_none(),
        "conntrack miss before insert"
    );
    m.conntrack_insert(k, e);
    assert!(m.conntrack_get(&k).is_some(), "conntrack hit after insert");

    // different key must miss
    let k2 = CtKey {
        src_port: 9999,
        ..k
    };
    assert!(
        m.conntrack_get(&k2).is_none(),
        "conntrack miss (different key)"
    );
}
