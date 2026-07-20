//! DPDK uplink byte-parity anchor. For a crafted encapped input frame + identical map contents in
//! `DpdkMaps` and `MemMaps`, assert `process_uplink` over `MbufPkt`+`DpdkMaps` produces a
//! byte-identical output frame + identical `Action` to `VecPkt`+`MemMaps`. This proves the shared
//! `flowplane_core::datapath::process_uplink` orchestrator runs identically on the DPDK substrate.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running two scenarios
//! sequentially. Run with `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, LbKey, LbValue, Local, MaglevKey, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_INGRESS,
};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── addressing (shared by both scenarios) ───────────────────────────────────
const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const BACKEND_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1];

fn local_reforward() -> Local {
    Local {
        uplink_ifindex: 9,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: HOST_UL,
    }
}

fn zero_local() -> Local {
    Local {
        uplink_ifindex: 0,
        uplink_mac: [0; 6],
        gateway_mac: [0; 6],
        underlay_ipv6: [0; 16],
    }
}

/// A full inner Ethernet frame `[Eth][IPv4][TCP]` src→dst on `dport`.
fn inner_frame(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Encapsulate an inner Eth+IPv4 frame IP-in-IPv6 toward `dst_ul` (fabric wire format), reusing the
/// REAL `SimNode::edge_encap`.
fn encap_to(inner: &[u8], dst_ul: [u8; 16]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: EDGE_UL,
            nexthop_ipv6: dst_ul,
            inner_proto: 4, // IPPROTO_IPIP
            flow_label: 0,
        },
    )
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

/// Load `frame` into a fresh mbuf and run `process_uplink` over `MbufPkt` + `DpdkMaps`, returning
/// the resulting frame bytes + `Action`.
fn run_dpdk(
    pool: &Mempool,
    maps: &mut DpdkMaps,
    frame: &[u8],
    in_: &UplinkIn,
) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_uplink(&mut mp, maps, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_uplink` over `VecPkt` + `MemMaps`, returning the resulting frame bytes + `Action`.
fn run_sim(maps: &mut MemMaps, frame: &[u8], in_: &UplinkIn) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_uplink(&mut vp, maps, in_);
    (vp.into_bytes(), action)
}

// ── firewall allow rule (installed identically on both map impls) ────────────
fn allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 1,
        egress_count: 0,
    }
}
fn allow_rule(port: u16) -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: GUEST_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: port,
        dst_port_max: port,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

#[test]
fn dpdk_uplink_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pu",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pu_pool", 1023, 250, 0).expect("pool");

    // ───────────────── Scenario (a): base decap → local delivery (non-LB) ─────────────────
    // No LB maps → lb_select_forward returns None → base path: ingress FW allow + CT create + decap.
    {
        let inner = inner_frame(EXT_IP, GUEST_IP, 443);
        let frame = encap_to(&inner, HOST_UL);
        let u = UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        };
        let zl = zero_local();
        let in_ = UplinkIn {
            vni: VNI,
            u,
            outer_dst: HOST_UL,
            local: &zl,
            now: 0,
        };

        // sim reference
        let mut sim = MemMaps::default();
        sim.fw_meta.insert(TAP, allow_meta());
        sim.fw_rules.insert((TAP, 0), allow_rule(443));
        let (out_sim, a_sim) = run_sim(&mut sim, &frame, &in_);

        // dpdk under test — identical map contents
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (a)");
        dm.add_fw_meta(TAP, allow_meta());
        dm.add_fw_rule(TAP, 0, allow_rule(443));
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(a_sim, Action::Redirect(TAP), "(a) sim: delivered to tap");
        assert_eq!(a_dpdk, a_sim, "(a) action parity");
        assert_eq!(out_dpdk, out_sim, "(a) output frame byte parity");
    }

    // ───────────────── Scenario (b): LB remote backend → reforward (no decap) ─────────────────
    // LB maps select BACKEND_UL; the node's underlay map has NO BACKEND_UL entry → underlay_get
    // returns None → reforward the encapped frame toward the backend (no decap).
    {
        let inner = inner_frame([10, 0, 0, 20], OVERLAY_VIP, 443);
        let frame = encap_to(&inner, HOST_UL);
        // Base underlay (unused on the reforward path — kept identical on both sides for hygiene).
        let u = UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        };
        let local = local_reforward();
        let in_ = UplinkIn {
            vni: VNI,
            u,
            outer_dst: HOST_UL,
            local: &local,
            now: 0,
        };

        let lb_key = LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        };
        let lb_val = LbValue {
            table_id: 7,
            size: 1,
        };
        let mag_key = MaglevKey {
            table_id: 7,
            slot: 0,
        };

        // sim reference
        let mut sim = MemMaps::default();
        sim.lb.insert(lb_key, lb_val);
        sim.maglev.insert(mag_key, BACKEND_UL);
        let (out_sim, a_sim) = run_sim(&mut sim, &frame, &in_);

        // dpdk under test — identical map contents
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (b)");
        dm.add_lb(lb_key, lb_val);
        dm.add_maglev(mag_key, BACKEND_UL);
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Redirect(local_reforward().uplink_ifindex),
            "(b) sim: reforwarded out the uplink ifindex"
        );
        assert_eq!(a_dpdk, a_sim, "(b) action parity");
        assert_eq!(out_dpdk, out_sim, "(b) reforwarded frame byte parity");
        // Sanity: the reforward rewrote the outer IPv6 dst to the selected backend underlay.
        assert_eq!(
            &out_dpdk[flowplane_core::encap::ETH_LEN + 24..flowplane_core::encap::ETH_LEN + 40],
            &BACKEND_UL,
            "(b) outer IPv6 dst rewritten to backend"
        );
    }
}
