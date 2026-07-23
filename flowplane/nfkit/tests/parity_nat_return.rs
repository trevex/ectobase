//! DPDK NAT-return (reverse-DNAT) byte-parity anchor. For a crafted encapped returning frame +
//! identical map contents (reverse CT entry + registered nat_ip) in `DpdkMaps` and `MemMaps`,
//! assert `process_uplink_nat_return` over `MbufPkt`+`DpdkMaps` produces a byte-identical output
//! frame + identical `Action` to `VecPkt`+`MemMaps`. This proves the shared
//! `flowplane_core::datapath::process_uplink_nat_return` orchestrator runs identically on the DPDK
//! substrate.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]`. Run with
//! `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{CtEntry, CtKey, UnderlayValue, CT_F_SRC_NAT, CT_REWRITE_DST};
use flowplane_core::datapath::{process_uplink_nat_return, UplinkNatReturnIn};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── DNAT fixture (mirrors flowplane-sim/src/nat_test.rs) ─────────────────────
const DNAT_VNI: u32 = 100;
const DNAT_TAP: u32 = 42;
const DNAT_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const DNAT_GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const DNAT_NAT_IP: [u8; 4] = [198, 51, 100, 7];
const DNAT_EXT_IP: [u8; 4] = [203, 0, 113, 9];
const DNAT_ORIG_SPORT: u16 = 40000; // restored inner dst port after reverse-DNAT
const DNAT_NAT_PORT: u16 = 20018; // allocated NAT port (inner dst port in the returning packet)
const DNAT_EXT_PORT: u16 = 443; // external peer's port (inner src port, unchanged)

const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

/// The reverse CT entry: `(vni, 0, nat_ip, 0, nat_port)` → `CT_REWRITE_DST | CT_F_SRC_NAT`,
/// `xlate_ip = guest_ip`, `xlate_port = orig_sport`.
fn dnat_reverse_ct_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: DNAT_GUEST_IP,
        xlate_port: DNAT_ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
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

/// Encapsulate an inner Eth+IPv4 returning frame IP-in-IPv6 toward the host underlay (fabric wire
/// format), reusing the REAL `SimNode::edge_encap`.
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
            inner_proto: 4, // IPPROTO_IPIP
            flow_label: 0,
        },
    )
}

/// Build the encapped returning TCP frame: inner is `EXT_IP:EXT_PORT → NAT_IP:NAT_PORT` (as it
/// arrives from the peer), payload = 4 bytes so the L4 checksum is non-trivial.
fn dnat_tcp_encapped() -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(DNAT_EXT_IP, DNAT_NAT_IP, 64)
        .tcp(DNAT_EXT_PORT, DNAT_NAT_PORT, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    encap_return(&frame)
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to the data-pointer
/// moves that grow/shrink_head cause — reads are always relative to the current front).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Load `frame` into a fresh mbuf and run `process_uplink_nat_return` over `MbufPkt` + `DpdkMaps`.
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

/// Run `process_uplink_nat_return` over `VecPkt` + `MemMaps`.
fn run_sim(maps: &mut MemMaps, frame: &[u8], in_: &UplinkNatReturnIn) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_uplink_nat_return(&mut vp, maps, in_);
    (vp.into_bytes(), action)
}

#[test]
fn dpdk_nat_return_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pnr",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pnr_pool", 1023, 250, 0).expect("pool");

    // TCP reverse-DNAT return: EXT_IP:443 → NAT_IP:NAT_PORT reverse-DNAT'd to
    // EXT_IP:443 → GUEST_IP:ORIG_SPORT, then decapped + delivered to the guest tap.
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

    // sim reference — reverse CT under the peer-independent key + registered nat_ip.
    let mut sim = MemMaps::default();
    sim.conntrack_insert(dnat_reverse_ct_key(proto), dnat_reverse_ct_entry());
    sim.nat_ips.insert((DNAT_VNI, DNAT_NAT_IP));
    let (out_sim, a_sim) = run_sim(&mut sim, &frame, &in_);

    // dpdk under test — identical map contents.
    let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new");
    dm.conntrack_insert(dnat_reverse_ct_key(proto), dnat_reverse_ct_entry());
    dm.add_nat_ip(DNAT_VNI, DNAT_NAT_IP);
    let (out_dpdk, a_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

    // Positive delivery FIRST (guards against a trivial both-drop), then byte parity.
    assert_eq!(
        a_sim,
        Action::Redirect(DNAT_TAP),
        "sim: reverse-DNAT'd return delivered to the guest tap"
    );
    assert_eq!(a_dpdk, a_sim, "action parity");
    assert_eq!(out_dpdk, out_sim, "NAT-return output frame byte parity");

    // Sanity: after decap the inner IPv4 dst was reverse-DNAT'd to the guest IP.
    let inner_ip_off = flowplane_core::encap::ETH_LEN; // 14
    assert_eq!(
        &out_dpdk[inner_ip_off + 16..inner_ip_off + 20],
        &DNAT_GUEST_IP,
        "inner dst IP reverse-DNAT'd to the guest IP"
    );
}
