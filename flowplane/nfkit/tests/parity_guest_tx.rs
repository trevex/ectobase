//! DPDK guest-egress byte-parity anchor. For a crafted guest Ethernet frame + identical map
//! contents in `DpdkMaps` and `MemMaps`, assert `process_guest_tx` over `MbufPkt`+`DpdkMaps`
//! produces a byte-identical output frame + identical `Action` + identical `edt_tstamp` to
//! `VecPkt`+`MemMaps`. This proves the shared `flowplane_core::datapath::process_guest_tx`
//! orchestrator runs identically on the DPDK substrate — including the `grow_head`/`write_outer_v6`
//! PREPEND path (encap), which the uplink anchor does not exercise.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running three scenarios
//! sequentially. Run with `--test-threads=1`.

// The sim-side map population is deliberately kept line-for-line parallel with the DpdkMaps side
// (set_local / add_route4 / add_fw_*), so we reassign `MemMaps::default()` fields rather than use a
// struct literal — clarity of the parity mirror over the initializer lint.
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, MeterState, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── addressing (shared by the scenarios) ─────────────────────────────────────
const VNI: u32 = 100;
const SRC_IFINDEX: u32 = 10;
const UPLINK_IFINDEX: u32 = 7;
const PEER_TAP: u32 = 77;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const EXT_DST: [u8; 4] = [203, 0, 113, 9];
const PEER_DST: [u8; 4] = [10, 1, 1, 1];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const PEER_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
const PEER_MAC: [u8; 6] = [0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn node_local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SRC_UL,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// A full guest Ethernet frame `[Eth][IPv4][UDP]` GUEST_IP→`dst` on `dport`.
fn guest_frame(dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, dst, 64)
        .udp(12345, dport);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
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

/// Load `frame` into a fresh mbuf and run `process_guest_tx` over `MbufPkt` + `DpdkMaps`, returning
/// the resulting frame bytes + `Action` + `edt_tstamp`.
fn run_dpdk(
    pool: &Mempool,
    maps: &mut DpdkMaps,
    frame: &[u8],
    in_: &GuestTxIn,
) -> (Vec<u8>, Action, Option<u64>) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let out = process_guest_tx(&mut mp, maps, in_);
    (mp_bytes(&mp), out.action, out.edt_tstamp)
}

/// Run `process_guest_tx` over `VecPkt` + `MemMaps`, returning frame bytes + `Action` + `edt_tstamp`.
fn run_sim(maps: &mut MemMaps, frame: &[u8], in_: &GuestTxIn) -> (Vec<u8>, Action, Option<u64>) {
    let mut vp = VecPkt::from_bytes(frame);
    let out = process_guest_tx(&mut vp, maps, in_);
    (vp.into_bytes(), out.action, out.edt_tstamp)
}

// ── firewall rules (installed identically on both map impls) ─────────────────
fn egress_allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 0,
        egress_count: 1,
    }
}
fn egress_allow_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: [0; 4],
        dst_mask: [0; 4],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}
fn ingress_allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 1,
        egress_count: 0,
    }
}
fn ingress_allow_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: [0; 4],
        dst_mask: [0; 4],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

#[test]
fn dpdk_guest_tx_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pg",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pg_pool", 1023, 250, 0).expect("pool");

    let meta = port_meta();
    let in_ = GuestTxIn {
        meta: &meta,
        src_ifindex: SRC_IFINDEX,
        now: 0,
    };

    // ───────────── Scenario (a): guest → external ENCAP (grow_head + write_outer_v6) ─────────────
    // is_external=1 route, nexthop underlay NOT in the underlay map, LOCAL set → deliver = Encap.
    // No NAT entry → snat_egress is a no-op; no METER entry → public_pass passes + edt_tstamp = None.
    // Exercises the PREPEND path (outer IPv6 header + flow label) not covered by parity_uplink.
    {
        let frame = guest_frame(EXT_DST, 443);
        let route = RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        };

        // sim reference
        let mut sim = MemMaps::default();
        sim.local = Some(node_local());
        sim.add_route4(VNI, EXT_DST, route);
        sim.fw_meta.insert(SRC_IFINDEX, egress_allow_meta());
        sim.fw_rules.insert((SRC_IFINDEX, 0), egress_allow_rule());
        let (out_sim, a_sim, edt_sim) = run_sim(&mut sim, &frame, &in_);

        // dpdk under test — identical map contents
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (a)");
        dm.set_local(node_local());
        dm.add_route4(VNI, EXT_DST, route);
        dm.add_fw_meta(SRC_IFINDEX, egress_allow_meta());
        dm.add_fw_rule(SRC_IFINDEX, 0, egress_allow_rule());
        let (out_dpdk, a_dpdk, edt_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Redirect(UPLINK_IFINDEX),
            "(a) sim: encapped + redirected out the uplink"
        );
        assert_eq!(a_dpdk, a_sim, "(a) action parity");
        assert_eq!(edt_dpdk, edt_sim, "(a) edt_tstamp parity");
        assert_eq!(edt_sim, None, "(a) no METER entry → edt_tstamp None");
        assert_eq!(out_dpdk, out_sim, "(a) encapped frame byte parity");
        // Sanity: the output carries an outer IPv6 header (version nibble 6) prepended at ETH_LEN,
        // and its dst is the route nexthop — proves the grow_head + write_outer_v6 prepend ran.
        assert_eq!(out_dpdk[ETH_LEN] >> 4, 6, "(a) outer IPv6 version");
        assert_eq!(
            &out_dpdk[ETH_LEN + 24..ETH_LEN + 40],
            &NEXTHOP_UL,
            "(a) outer IPv6 dst == route nexthop"
        );
    }

    // ───────────── Scenario (b): guest → internal LOCAL delivery (inner-Eth rewrite) ─────────────
    // is_external=0 route whose nexthop underlay IS a LOCAL tap (tap_ifindex != 0) → deliver = Local.
    // Egress FW allow on the source + ingress FW allow on the peer tap (same-node delivery gate).
    {
        let frame = guest_frame(PEER_DST, 8080);
        let route = RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_UL,
            is_external: 0,
            _pad: [0; 3],
        };
        let peer_ul = UnderlayValue {
            vni: VNI,
            tap_ifindex: PEER_TAP,
            guest_mac: PEER_MAC,
            _pad: [0; 2],
        };

        // sim reference
        let mut sim = MemMaps::default();
        sim.local = Some(node_local());
        sim.underlay.insert(PEER_UL, peer_ul);
        sim.add_route4(VNI, PEER_DST, route);
        sim.fw_meta.insert(SRC_IFINDEX, egress_allow_meta());
        sim.fw_rules.insert((SRC_IFINDEX, 0), egress_allow_rule());
        sim.fw_meta.insert(PEER_TAP, ingress_allow_meta());
        sim.fw_rules.insert((PEER_TAP, 0), ingress_allow_rule());
        let (out_sim, a_sim, edt_sim) = run_sim(&mut sim, &frame, &in_);

        // dpdk under test — identical map contents
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (b)");
        dm.set_local(node_local());
        dm.add_underlay(PEER_UL, peer_ul);
        dm.add_route4(VNI, PEER_DST, route);
        dm.add_fw_meta(SRC_IFINDEX, egress_allow_meta());
        dm.add_fw_rule(SRC_IFINDEX, 0, egress_allow_rule());
        dm.add_fw_meta(PEER_TAP, ingress_allow_meta());
        dm.add_fw_rule(PEER_TAP, 0, ingress_allow_rule());
        let (out_dpdk, a_dpdk, edt_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Redirect(PEER_TAP),
            "(b) sim: delivered locally to the peer tap"
        );
        assert_eq!(a_dpdk, a_sim, "(b) action parity");
        assert_eq!(edt_dpdk, edt_sim, "(b) edt_tstamp parity");
        assert_eq!(
            edt_sim, None,
            "(b) Local delivery is unshaped → edt_tstamp None"
        );
        assert_eq!(
            out_dpdk, out_sim,
            "(b) inner-Eth-rewritten frame byte parity"
        );
        // Sanity: the inner Ethernet dst was rewritten to the peer guest MAC (no encap, same len).
        assert_eq!(
            &out_dpdk[0..6],
            &PEER_MAC,
            "(b) inner Eth dst == peer guest MAC"
        );
        assert_eq!(
            out_dpdk.len(),
            frame.len(),
            "(b) Local delivery does not grow the frame"
        );
    }

    // ───────────── Scenario (c): egress firewall DROP (no allow rule) ─────────────
    // No egress FW allow rule installed → the fresh-flow egress firewall denies → Action::Drop.
    // The frame is untouched before the drop, so bytes must match the input on BOTH sides.
    {
        let frame = guest_frame(EXT_DST, 443);
        let route = RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        };

        // sim reference — route present but NO egress allow rule (deny-by-default).
        let mut sim = MemMaps::default();
        sim.local = Some(node_local());
        sim.add_route4(VNI, EXT_DST, route);
        let (out_sim, a_sim, edt_sim) = run_sim(&mut sim, &frame, &in_);

        // dpdk under test — identical map contents
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (c)");
        dm.set_local(node_local());
        dm.add_route4(VNI, EXT_DST, route);
        let (out_dpdk, a_dpdk, edt_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(
            a_sim,
            Action::Drop,
            "(c) sim: egress FW deny-by-default drop"
        );
        assert_eq!(a_dpdk, a_sim, "(c) action parity");
        assert_eq!(edt_dpdk, edt_sim, "(c) edt_tstamp parity");
        assert_eq!(out_dpdk, out_sim, "(c) dropped frame byte parity");
        assert_eq!(out_dpdk, frame, "(c) frame untouched before drop");
    }

    // ───────────── Scenario (d): metered ENCAP → non-None edt_tstamp parity ─────────────
    // Same encap path as (a), but a METER entry with total_bps>0 and a FUTURE schedule cursor
    // (total_last_ns=5000 > now=0) makes edt_egress return Some(t_sched=5000). public_bps=0 so the
    // public lane doesn't police. Exercises DpdkMaps::meter_get/meter_update + edt_egress over rte_hash
    // — the first non-None edt_tstamp DPDK-vs-sim parity (all of a/b/c were None).
    {
        let frame = guest_frame(EXT_DST, 443);
        let route = RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        };
        let meter = MeterState {
            total_bps: 1_000_000_000,
            total_last_ns: 5000,
            ..MeterState::default()
        };

        let mut sim = MemMaps::default();
        sim.local = Some(node_local());
        sim.add_route4(VNI, EXT_DST, route);
        sim.fw_meta.insert(SRC_IFINDEX, egress_allow_meta());
        sim.fw_rules.insert((SRC_IFINDEX, 0), egress_allow_rule());
        sim.meter.insert(SRC_IFINDEX, meter);
        let (out_sim, a_sim, edt_sim) = run_sim(&mut sim, &frame, &in_);

        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (d)");
        dm.set_local(node_local());
        dm.add_route4(VNI, EXT_DST, route);
        dm.add_fw_meta(SRC_IFINDEX, egress_allow_meta());
        dm.add_fw_rule(SRC_IFINDEX, 0, egress_allow_rule());
        flowplane_core::maps::Maps::meter_update(&mut dm, SRC_IFINDEX, meter);
        let (out_dpdk, a_dpdk, edt_dpdk) = run_dpdk(&pool, &mut dm, &frame, &in_);

        assert_eq!(a_dpdk, a_sim, "(d) action parity");
        assert_eq!(
            a_sim,
            Action::Redirect(UPLINK_IFINDEX),
            "(d) encapped + redirected"
        );
        assert_eq!(edt_dpdk, edt_sim, "(d) edt_tstamp parity");
        assert_eq!(
            edt_sim,
            Some(5000),
            "(d) metered encap → deterministic edt = max(total_last_ns, now)"
        );
        assert_eq!(
            out_dpdk, out_sim,
            "(d) encapped frame byte parity (metering doesn't touch bytes)"
        );
    }
}
