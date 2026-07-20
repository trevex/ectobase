//! DPDK edge WAN-VIP ingress (`wan_rx`) byte-parity anchor. For a plain WAN frame + identical map
//! contents in `DpdkMaps` and `MemMaps`, assert `process_wan_rx` over `MbufPkt`+`DpdkMaps` produces
//! a byte-identical output frame + identical `Action` to `VecPkt`+`MemMaps`. This proves the shared
//! `flowplane_core::datapath::process_wan_rx` orchestrator runs identically on the DPDK substrate —
//! v4 VIP → IPIP encap, v6 VIP → IPPROTO_IPV6 encap (the first inner-v6 anchor), and no-VIP → Pass.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running three scenarios
//! sequentially. Run with `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{LbKey, LbValue, Local, MaglevKey};
use flowplane_core::datapath::{process_wan_rx, WanRxIn};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── addressing (shared by all scenarios) ─────────────────────────────────────
const UPLINK_IFINDEX: u32 = 9;
const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const BACKEND_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];

// v4 VIP
const WAN_SRC_V4: [u8; 4] = [198, 51, 100, 7];
const VIP_V4: [u8; 4] = [203, 0, 113, 50];
// v6 VIP (its last-4 bytes are the LB key ipv4)
const WAN_SRC_V6: [u8; 16] = [0x26, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const VIP_V6: [u8; 16] = [0x2a, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 60];
const NON_VIP_V4: [u8; 4] = [203, 0, 113, 99];

fn edge_local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: EDGE_UL,
    }
}

/// A plain `[Eth(0x0800)][IPv4][TCP]` WAN frame src→dst on `dport`.
fn v4_frame(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// A plain `[Eth(0x86DD)][IPv6][TCP]` WAN frame src→dst on `dport`.
fn v6_frame(src: [u8; 16], dst: [u8; 16], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to grow/shrink_head).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Load `frame` into a fresh mbuf and run `process_wan_rx` over `MbufPkt` + `DpdkMaps`.
fn run_dpdk(pool: &Mempool, maps: &DpdkMaps, frame: &[u8], in_: &WanRxIn) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_wan_rx(&mut mp, maps, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_wan_rx` over `VecPkt` + `MemMaps`.
fn run_sim(maps: &MemMaps, frame: &[u8], in_: &WanRxIn) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_wan_rx(&mut vp, maps, in_);
    (vp.into_bytes(), action)
}

#[test]
fn dpdk_wan_rx_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pwr",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pwr_pool", 1023, 250, 0).expect("pool");

    let local = edge_local();
    let in_ = WanRxIn { local: &local };

    // ───────────────── Scenario (a): v4 VIP → IPIP encap ─────────────────
    // lb_select_forward keys on (vni=0, dst=VIP_V4, port=dport, proto=6) → Maglev → BACKEND_UL.
    {
        let dport = 443u16;
        let frame = v4_frame(WAN_SRC_V4, VIP_V4, dport);
        let lb_key = LbKey {
            vni: 0,
            ipv4: VIP_V4,
            port: dport,
            proto: 6,
            _pad: 0,
        };
        let lb_val = LbValue {
            table_id: 11,
            size: 1,
        };
        let mag_key = MaglevKey {
            table_id: 11,
            slot: 0,
        };

        let mut sim = MemMaps::default();
        sim.lb.insert(lb_key, lb_val);
        sim.maglev.insert(mag_key, BACKEND_UL);
        let (out_sim, a_sim) = run_sim(&sim, &frame, &in_);

        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (a)");
        dm.add_lb(lb_key, lb_val);
        dm.add_maglev(mag_key, BACKEND_UL);
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Redirect(UPLINK_IFINDEX),
            "(a) sim: v4 VIP hit → redirect out uplink"
        );
        assert_eq!(a_dpdk, a_sim, "(a) action parity");
        assert_eq!(out_dpdk, out_sim, "(a) v4 encapped frame byte parity");
        // Sanity: outer is IPv6 (version nibble 6) toward the selected backend underlay.
        assert_eq!(out_dpdk[ETH_LEN] >> 4, 6, "(a) outer IP version == 6");
        assert_eq!(
            &out_dpdk[ETH_LEN + 24..ETH_LEN + 40],
            &BACKEND_UL,
            "(a) outer IPv6 dst == backend underlay"
        );
    }

    // ───────────────── Scenario (b): v6 VIP → IPPROTO_IPV6 encap ─────────────────
    // lb_select_forward_v6 keys on (vni=0, dst4=last4(VIP_V6), port=dport, proto=6) → BACKEND_UL.
    {
        let dport = 8443u16;
        let frame = v6_frame(WAN_SRC_V6, VIP_V6, dport);
        let dst4: [u8; 4] = [VIP_V6[12], VIP_V6[13], VIP_V6[14], VIP_V6[15]];
        let lb_key = LbKey {
            vni: 0,
            ipv4: dst4,
            port: dport,
            proto: 6,
            _pad: 0,
        };
        let lb_val = LbValue {
            table_id: 22,
            size: 1,
        };
        let mag_key = MaglevKey {
            table_id: 22,
            slot: 0,
        };

        let mut sim = MemMaps::default();
        sim.lb.insert(lb_key, lb_val);
        sim.maglev.insert(mag_key, BACKEND_UL);
        let (out_sim, a_sim) = run_sim(&sim, &frame, &in_);

        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (b)");
        dm.add_lb(lb_key, lb_val);
        dm.add_maglev(mag_key, BACKEND_UL);
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Redirect(UPLINK_IFINDEX),
            "(b) sim: v6 VIP hit → redirect out uplink"
        );
        assert_eq!(a_dpdk, a_sim, "(b) action parity");
        assert_eq!(out_dpdk, out_sim, "(b) v6 encapped frame byte parity");
        assert_eq!(out_dpdk[ETH_LEN] >> 4, 6, "(b) outer IP version == 6");
        assert_eq!(
            &out_dpdk[ETH_LEN + 24..ETH_LEN + 40],
            &BACKEND_UL,
            "(b) outer IPv6 dst == backend underlay"
        );
        // Sanity: inner-proto (outer IPv6 next-header at ETH_LEN+6) is IPPROTO_IPV6 (41).
        assert_eq!(out_dpdk[ETH_LEN + 6], 41, "(b) outer next-header == 41");
    }

    // ───────────────── Scenario (c): no-VIP → Pass ─────────────────
    // Empty LB maps → lb_select_forward returns None → Pass, frame untouched.
    {
        let frame = v4_frame(WAN_SRC_V4, NON_VIP_V4, 80);

        let sim = MemMaps::default();
        let (out_sim, a_sim) = run_sim(&sim, &frame, &in_);

        let dm = DpdkMaps::new(0).expect("DpdkMaps::new (c)");
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &dm, &frame, &in_);

        assert_eq!(a_sim, Action::Pass, "(c) sim: no VIP → Pass");
        assert_eq!(a_dpdk, a_sim, "(c) action parity");
        assert_eq!(out_sim, frame, "(c) sim: frame untouched");
        assert_eq!(out_dpdk, out_sim, "(c) pass-through byte parity");
    }
}
