//! nfkit M11 — conntrack/NAT snapshot round-trip + established-flow continuity.
//!
//! Proves the blue-green state-handoff primitive: an OLD `DpdkMaps` (instance A) serializes its
//! flow tables, a FRESH `DpdkMaps` (instance B — the "new binary") restores them, and an
//! ESTABLISHED NAT flow keeps working on B — its RETURN packet is reverse-DNAT'd correctly using
//! the RESTORED binding, byte-identical to the sim reference.
//!
//! EAL is process-global and inits once, so every assertion lives in ONE `#[test]`. Run with
//! `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtEntry, CtKey, NatKey, NatValue, UnderlayValue, CT_F_SRC_NAT, CT_REWRITE_DST,
};
use flowplane_core::datapath::{process_uplink_nat_return, UplinkNatReturnIn};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{restore_maps, serialize_maps, DpdkMaps, Eal, MbufPkt, Mempool, RestoreStats};

// ── NAT-return continuity fixture (mirrors parity_nat_return.rs) ──────────────
const DNAT_VNI: u32 = 100;
const DNAT_TAP: u32 = 42;
const DNAT_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const DNAT_GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const DNAT_NAT_IP: [u8; 4] = [198, 51, 100, 7];
const DNAT_EXT_IP: [u8; 4] = [203, 0, 113, 9];
const DNAT_ORIG_SPORT: u16 = 40000;
const DNAT_NAT_PORT: u16 = 20018;
const DNAT_EXT_PORT: u16 = 443;

const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

fn dnat_reverse_ct_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: DNAT_GUEST_IP,
        xlate_port: DNAT_ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        _pad: [0; 7],
    }
}

fn dnat_reverse_ct_key(proto: u8) -> CtKey {
    CtKey {
        vni: DNAT_VNI,
        src_ip: [0; 4],
        dst_ip: DNAT_NAT_IP,
        src_port: 0,
        dst_port: DNAT_NAT_PORT,
        proto,
        _pad: [0; 3],
    }
}

fn encap_return(inner: &[u8]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: EDGE_UNDERLAY,
            nexthop_ipv6: HOST_UNDERLAY,
            inner_proto: 4,
            flow_label: 0,
        },
    )
}

fn dnat_tcp_encapped() -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(DNAT_EXT_IP, DNAT_NAT_IP, 64)
        .tcp(DNAT_EXT_PORT, DNAT_NAT_PORT, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    encap_return(&frame)
}

fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

fn run_dpdk(
    pool: &Mempool,
    maps: &mut DpdkMaps,
    frame: &[u8],
    in_: &UplinkNatReturnIn,
) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_uplink_nat_return(&mut mp, maps, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

// ── generic round-trip helpers ───────────────────────────────────────────────

/// Collect a table via a `*_for_each` accessor into a Vec of `(key_bytes, value_bytes)`, sorted so
/// two instances can be compared regardless of rte_hash iteration order.
fn sorted_entries<F>(collect: F) -> Vec<(Vec<u8>, Vec<u8>)>
where
    F: FnOnce(&mut dyn FnMut(&[u8], &[u8])),
{
    let mut v: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut push = |k: &[u8], val: &[u8]| v.push((k.to_vec(), val.to_vec()));
    collect(&mut push);
    v.sort();
    v
}

/// Raw bytes of a `#[repr(C)] Copy` POD value (test-side mirror of the serializer's byte view).
fn pod_bytes<T: Copy>(v: &T) -> Vec<u8> {
    // SAFETY: `T` is `#[repr(C)] Copy` POD (CtKey/CtEntry/NatKey/NatValue/NatIpKey). Reading its
    // `size_of::<T>()` bytes as `&[u8]` is a plain byte view of a live aligned value.
    let bytes = unsafe {
        std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>())
    };
    bytes.to_vec()
}

/// Sorted `(key_bytes, value_bytes)` entries of one table.
type Table = Vec<(Vec<u8>, Vec<u8>)>;

fn dump_all(maps: &DpdkMaps) -> (Table, Table, Table) {
    let ct =
        sorted_entries(|push| maps.conntrack_for_each(|k, v| push(&pod_bytes(k), &pod_bytes(v))));
    let nat = sorted_entries(|push| maps.nat_for_each(|k, v| push(&pod_bytes(k), &pod_bytes(v))));
    let nips =
        sorted_entries(|push| maps.nat_ips_for_each(|k, v| push(&pod_bytes(k), &pod_bytes(v))));
    (ct, nat, nips)
}

#[test]
fn snapshot_roundtrip_and_flow_continuity() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_snap",
    ])
    .expect("EAL init");
    let pool = Mempool::new("snap_pool", 1023, 250, 0).expect("pool");

    // ── Part 1: round-trip byte parity ───────────────────────────────────────
    // Populate instance A deterministically (no datapath needed).
    let mut a = DpdkMaps::new(0).expect("DpdkMaps::new A");
    // several conntrack entries
    a.conntrack_insert(
        CtKey {
            vni: 7,
            src_ip: [10, 0, 0, 1],
            dst_ip: [10, 0, 0, 2],
            src_port: 1111,
            dst_port: 2222,
            proto: 6,
            _pad: [0; 3],
        },
        CtEntry {
            last_seen: 42,
            xlate_ip: [192, 0, 2, 1],
            xlate_port: 5555,
            flags: CT_REWRITE_DST,
            tcp_state: 1,
            fwall_action: 0,
            _pad: [0; 7],
        },
    );
    a.conntrack_insert(dnat_reverse_ct_key(6), dnat_reverse_ct_entry());
    a.conntrack_insert(
        CtKey {
            vni: 9,
            src_ip: [172, 16, 0, 5],
            dst_ip: [8, 8, 8, 8],
            src_port: 33000,
            dst_port: 53,
            proto: 17,
            _pad: [0; 3],
        },
        CtEntry {
            last_seen: 99,
            xlate_ip: [198, 51, 100, 200],
            xlate_port: 40001,
            flags: CT_F_SRC_NAT,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
    );
    // nat config
    a.add_nat(
        NatKey {
            vni: DNAT_VNI,
            ipv4: DNAT_GUEST_IP,
        },
        NatValue {
            nat_ipv4: DNAT_NAT_IP,
            port_min: 20000,
            port_max: 30000,
        },
    );
    a.add_nat(
        NatKey {
            vni: 9,
            ipv4: [172, 16, 0, 5],
        },
        NatValue {
            nat_ipv4: [198, 51, 100, 200],
            port_min: 40000,
            port_max: 41000,
        },
    );
    // nat_ips
    a.add_nat_ip(DNAT_VNI, DNAT_NAT_IP);
    a.add_nat_ip(9, [198, 51, 100, 200]);

    let blob = serialize_maps(&a);

    // Restore into a FRESH instance B.
    let mut b = DpdkMaps::new(0).expect("DpdkMaps::new B");
    let stats = restore_maps(&mut b, &blob).expect("restore ok");
    assert_eq!(
        stats,
        RestoreStats {
            conntrack: 3,
            nat: 2,
            nat_ips: 2,
        },
        "restore stats == inserted counts"
    );

    // Every A entry present + equal in B, and B has NO extras (sorted-vec equality).
    let (a_ct, a_nat, a_nips) = dump_all(&a);
    let (b_ct, b_nat, b_nips) = dump_all(&b);
    assert_eq!(a_ct, b_ct, "conntrack table identical after round-trip");
    assert_eq!(a_nat, b_nat, "nat table identical after round-trip");
    assert_eq!(a_nips, b_nips, "nat_ips table identical after round-trip");

    // ── Part 2: header validation (no panic on bad magic / bad version) ──────
    let mut bad_magic = blob.clone();
    bad_magic[0] = b'X';
    let mut junk = DpdkMaps::new(0).expect("DpdkMaps::new junk");
    assert_eq!(
        restore_maps(&mut junk, &bad_magic),
        Err(nfkit::SnapshotError("bad magic")),
        "bad magic refused"
    );
    let mut bad_ver = blob.clone();
    bad_ver[4] = 0xFF;
    bad_ver[5] = 0xFF;
    assert_eq!(
        restore_maps(&mut junk, &bad_ver),
        Err(nfkit::SnapshotError("unsupported version")),
        "bad version refused"
    );
    // Truncated blobs never panic — each returns Err.
    for cut in [0usize, 3, 5, 6, 10, blob.len() - 1] {
        assert!(
            restore_maps(&mut DpdkMaps::new(0).expect("dm"), &blob[..cut]).is_err(),
            "truncated blob (len {cut}) refused without panic"
        );
    }
    // Empty and single-byte garbage.
    assert!(restore_maps(&mut junk, &[]).is_err());
    assert!(restore_maps(&mut junk, &[0xAB]).is_err());

    // ── Part 3: behavioral continuity — established NAT flow survives the swap ─
    // Instance A installs the exact NAT-return binding + reverse conntrack the datapath creates for
    // an established flow (same fixture parity_nat_return proves byte-identical to eBPF/sim). We
    // already inserted the reverse CT + registered the nat_ip into A above; serialize→restore into a
    // FRESH instance C (the "new binary"), then run the flow's RETURN packet through C's datapath
    // and assert C reverse-DNATs it correctly using the RESTORED binding — byte-identical to the sim
    // reference. This proves the flow actually WORKS post-swap, not merely that maps are present.
    let proto: u8 = 6;
    let frame = dnat_tcp_encapped();
    let u = UnderlayValue {
        vni: DNAT_VNI,
        tap_ifindex: DNAT_TAP,
        guest_mac: DNAT_GUEST_MAC,
        _pad: [0; 2],
    };
    let in_ = UplinkNatReturnIn {
        vni: DNAT_VNI,
        tap_ifindex: u.tap_ifindex,
        guest_mac: DNAT_GUEST_MAC,
    };

    // sim reference (independent of DPDK).
    let mut sim = MemMaps::default();
    sim.conntrack_insert(dnat_reverse_ct_key(proto), dnat_reverse_ct_entry());
    sim.nat_ips.insert((DNAT_VNI, DNAT_NAT_IP));
    let mut vp = VecPkt::from_bytes(&frame);
    let a_sim = process_uplink_nat_return(&mut vp, &mut sim, &in_);
    let out_sim = vp.into_bytes();

    // Restore A's snapshot into a fresh instance C and run the return on C.
    let mut c = DpdkMaps::new(0).expect("DpdkMaps::new C");
    let stats_c = restore_maps(&mut c, &blob).expect("restore into C");
    assert_eq!(stats_c, stats, "C restored the same entry counts as B");
    // The restored reverse CT + nat_ip must be present in C for the flow.
    assert_eq!(
        c.conntrack_get(&dnat_reverse_ct_key(proto)),
        Some(dnat_reverse_ct_entry()),
        "restored reverse CT present in C"
    );
    assert!(
        c.is_nat_ip(DNAT_VNI, &DNAT_NAT_IP),
        "restored nat_ip present in C"
    );

    let (out_c, a_c) = run_dpdk(&pool, &mut c, &frame, &in_);

    // Datapath assertions on the RESTORED instance.
    assert_eq!(
        a_sim,
        Action::Redirect(DNAT_TAP),
        "sim: reverse-DNAT'd return delivered to the guest tap"
    );
    assert_eq!(a_c, a_sim, "restored instance C: same Action as sim");
    assert_eq!(
        out_c, out_sim,
        "restored instance C: NAT-return output frame byte-identical to sim"
    );
    // The inner dst IP was reverse-DNAT'd to the guest IP using the RESTORED binding.
    let inner_ip_off = flowplane_core::encap::ETH_LEN;
    assert_eq!(
        &out_c[inner_ip_off + 16..inner_ip_off + 20],
        &DNAT_GUEST_IP,
        "restored flow: inner dst reverse-DNAT'd to guest IP"
    );
}
