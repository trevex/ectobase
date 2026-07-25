// DpdkMaps: Maps trait backed by rte_hash — route add/get + conntrack insert/get.
// Run with --test-threads=1 (EAL is process-global).
use flowplane_common::{CtEntry, CtKey, CtKey6, FwMeta, FwRule6, FwRuleKey, RouteValue};
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
        gen_bytes: [0; 4],
        _pad: [0; 3],
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

    // is_nat_ip: add → hit; wrong vni/ip → miss.
    assert!(!m.is_nat_ip(7, &[100, 64, 0, 1]));
    m.add_nat_ip(7, [100, 64, 0, 1]);
    assert!(m.is_nat_ip(7, &[100, 64, 0, 1]));
    assert!(!m.is_nat_ip(8, &[100, 64, 0, 1]), "wrong vni misses");
    assert!(!m.is_nat_ip(7, &[100, 64, 0, 2]), "wrong ip misses");

    // Two DpdkMaps must coexist (per-lcore instantiation) — previously the fixed hash names collided.
    let mut a = DpdkMaps::new(0).expect("maps A");
    let mut b = DpdkMaps::new(0).expect("maps B"); // must NOT fail on a name clash
    let ka = CtKey {
        vni: 1,
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        src_port: 1,
        dst_port: 2,
        proto: 6,
        _pad: [0; 3],
    };
    let kb = CtKey {
        vni: 9,
        src_ip: [10, 0, 0, 9],
        dst_ip: [10, 0, 0, 8],
        src_port: 9,
        dst_port: 8,
        proto: 6,
        _pad: [0; 3],
    };
    a.conntrack_insert(ka, CtEntry::default());
    assert!(a.conntrack_get(&ka).is_some());
    assert!(
        b.conntrack_get(&ka).is_none(),
        "A's flow must not appear in B (shared-nothing)"
    );
    b.conntrack_insert(kb, CtEntry::default());
    assert!(b.conntrack_get(&kb).is_some());
    assert!(a.conntrack_get(&kb).is_none());

    // ---- IPv6 firewall + conntrack parity (FW_RULES6 / FW_META6 / CONNTRACK6) ----
    // These are the Task-9 overrides that replace the no-op `Maps` trait defaults; without them the
    // DPDK v6 firewall silently no-ops.
    let mut v6 = DpdkMaps::new(0).expect("maps v6");

    // Defaults (pre-populate) must miss, proving the override reads a real (empty) table, not the
    // trait default which would ALWAYS return None regardless.
    let fwk = FwRuleKey { ifindex: 3, idx: 0 };
    assert!(v6.fw_rule6(&fwk).is_none(), "fw_rule6 miss before add");
    assert!(v6.fw_meta6(5).is_none(), "fw_meta6 miss before add");

    // fw_meta6 round-trip.
    let meta = FwMeta {
        ingress_count: 2,
        egress_count: 1,
    };
    v6.add_fw_meta6(5, meta);
    assert_eq!(v6.fw_meta6(5), Some(meta), "fw_meta6 hit after add");
    assert!(v6.fw_meta6(6).is_none(), "fw_meta6 miss (wrong ifindex)");

    // fw_rule6 round-trip.
    let rule = FwRule6 {
        src_ip: [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        src_mask: [0xff; 16],
        dst_ip: [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        dst_mask: [0xff; 16],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 80,
        dst_port_max: 80,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: 1,
        direction: 0,
        enabled: 1,
    };
    v6.add_fw_rule6(3, 0, rule);
    assert_eq!(v6.fw_rule6(&fwk), Some(rule), "fw_rule6 hit after add");
    assert!(
        v6.fw_rule6(&FwRuleKey { ifindex: 3, idx: 1 }).is_none(),
        "fw_rule6 miss (wrong slot)"
    );

    // CONNTRACK6 round-trip via the trait mut/get methods.
    let ck6 = CtKey6 {
        vni: 7,
        src_ip: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        dst_ip: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        src_port: 1234,
        dst_port: 80,
        proto: 6,
        _pad: [0; 3],
    };
    assert!(v6.conntrack6_get(&ck6).is_none(), "ct6 miss before insert");
    let ce = CtEntry {
        last_seen: 7,
        fwall_action: 1,
        flags: 0x20,
        ..CtEntry::default()
    };
    v6.conntrack6_insert(ck6, ce);
    assert_eq!(v6.conntrack6_get(&ck6), Some(ce), "ct6 hit after insert");
    let ck6b = CtKey6 {
        src_port: 9999,
        ..ck6
    };
    assert!(
        v6.conntrack6_get(&ck6b).is_none(),
        "ct6 miss (different key)"
    );
}
