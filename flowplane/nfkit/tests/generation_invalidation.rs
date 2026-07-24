//! §5a: after a NAT binding is withdrawn (config_generation bumped), the next datapath packet on a
//! previously-established flow must NOT emit under the withdrawn binding (zero stale emission),
//! WITHOUT the control thread reaching into per-lcore conntrack state.
//!
//! This drives the SHARED `flowplane_core::datapath::process_guest_tx` SNAT-egress orchestrator over
//! the DPDK `ComposedMaps` (process-wide `SharedConfigMaps` CONFIG half + a per-lcore
//! `PerLcoreFlowMaps` FLOW half). The CONFIG half is programmed / withdrawn directly via
//! `SharedConfigMaps` setters (the same tables `DpdkMapWriter` writes); a withdrawal bumps the
//! generation exactly as `DpdkMapWriter::conntrack_flush` does.
//!
//! EAL is process-global and inits once, so this is ONE `#[test]`. Run with `--test-threads=1`.

#![cfg(test)]

use etherparse::PacketBuilder;
use flowplane_common::{Local, NatKey, NatValue, PortMeta, RouteValue};
use flowplane_core::datapath::{
    process_guest_tx, process_guest_tx_nat64, GuestTxIn, GuestTxNat64In,
};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── addressing ───────────────────────────────────────────────────────────────
const VNI: u32 = 100;
const SRC_IFINDEX: u32 = 10;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const EXT_DST: [u8; 4] = [203, 0, 113, 9];
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

// Encapped output layout: [OuterEth 14][OuterIPv6 40][InnerIPv4 ...] — the outer write CONSUMES the
// original 14-byte inner Ethernet (datapath.rs `write_outer_v6`). Inner IPv4 src is at 14+40+12 = 66.
const INNER_IPV4_SRC_OFF: usize = 14 + 40 + 12;
// Inner IPv4 header starts at 14+40 = 54; IHL 20 → inner UDP at 74; UDP src port = first 2 bytes.
const UDP_SPORT_OFF: usize = 14 + 40 + 20;

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

/// A full guest Ethernet frame `[Eth][IPv4][UDP]` GUEST_IP → EXT_DST.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, EXT_DST, 64)
        .udp(12345, 443);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` (robust to grow/shrink_head data-pointer moves).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Load `frame` into a fresh mbuf and run `process_guest_tx` over `MbufPkt` + `ComposedMaps`.
fn run(
    pool: &Mempool,
    maps: &mut ComposedMaps<'_>,
    frame: &[u8],
    in_: &GuestTxIn,
) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let out = process_guest_tx(&mut mp, maps, in_);
    (mp_bytes(&mp), out.action)
}

// ── NAT64 egress fixture (a DISTINCT guest so its conntrack keys never collide with the SNAT flow) ──
const NAT64_GUEST_V4: [u8; 4] = [10, 0, 2, 30]; // the NAT-key guest IPv4 (nat64 keys on guest_ipv4)
const NAT64_GUEST_V6: [u8; 16] = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30];

/// The NAT64 well-known-prefix dst embedding `EXT_DST`: `64:ff9b::EXT_DST`.
fn nat64_dst() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_DST[0], EXT_DST[1], EXT_DST[2],
        EXT_DST[3],
    ]
}

fn nat64_port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: NAT64_GUEST_V4,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: NAT64_GUEST_V6,
    }
}

/// A guest IPv6 frame `[Eth][IPv6][UDP]` `NAT64_GUEST_V6:sport → 64:ff9b::EXT_DST:443`.
fn guest_frame_v6(sport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv6(NAT64_GUEST_V6, nat64_dst(), 64)
        .udp(sport, 443);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Load a v6 `frame` into a fresh mbuf and run the NAT64 egress orchestrator.
fn run_nat64(
    pool: &Mempool,
    maps: &mut ComposedMaps<'_>,
    frame: &[u8],
    in_: &GuestTxNat64In,
) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_guest_tx_nat64(&mut mp, maps, in_);
    (mp_bytes(&mp), action)
}

#[test]
#[ignore = "requires EAL --no-huge"]
fn withdrawn_nat_binding_not_emitted_after_generation_bump() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_gen",
    ])
    .expect("EAL init");
    let pool = Mempool::new("gen_pool", 1023, 250, 0).expect("pool");

    // ── Program the CONFIG half (the tables DpdkMapWriter writes) ──────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
    shared.set_local(node_local());
    // External /32 route → snat_egress runs.
    assert!(shared.route4_insert(
        VNI,
        EXT_DST,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        },
    ));
    // Egress firewall: allow-all on the source interface (deny-by-default otherwise).
    assert!(shared.fw_meta_insert(
        SRC_IFINDEX,
        flowplane_common::FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    ));
    assert!(shared.fw_rules_insert(
        flowplane_common::FwRuleKey {
            ifindex: SRC_IFINDEX,
            idx: 0,
        },
        flowplane_common::FwRule {
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
            action: flowplane_common::FW_ACTION_ACCEPT,
            direction: flowplane_common::FW_DIR_EGRESS,
            enabled: 1,
        },
    ));
    // NAT binding: guest IP → NAT_IP over a source-port range → snat_egress rewrites the src IP.
    assert!(shared.nat_insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: 20000,
            port_max: 30000,
        },
    ));

    let meta = port_meta();
    let in_ = GuestTxIn {
        meta: &meta,
        src_ifindex: SRC_IFINDEX,
        now: 0,
    };
    let frame = guest_frame();

    // Compose the shared CONFIG half with a per-lcore FLOW (conntrack) half.
    let flow = PerLcoreFlowMaps::new(0).expect("per-lcore flow");
    let mut maps = ComposedMaps { cfg: &shared, flow };

    // ── (1) Establish the flow under generation G0: SNAT rewrites src → NAT_IP ─
    assert_eq!(maps.config_generation(), 0, "starts at generation 0");
    let (out0, a0) = run(&pool, &mut maps, &frame, &in_);
    assert_eq!(
        a0,
        Action::Redirect(UPLINK_IFINDEX),
        "(1) encapped + redirected out the uplink"
    );
    assert_eq!(
        &out0[INNER_IPV4_SRC_OFF..INNER_IPV4_SRC_OFF + 4],
        &NAT_IP,
        "(1) inner src IP SNAT-rewritten to NAT_IP under generation G0"
    );

    // Sanity: the forward conntrack entry was stamped under generation 0.
    let fwd_key = flowplane_common::CtKey {
        vni: VNI,
        src_ip: GUEST_IP,
        dst_ip: EXT_DST,
        src_port: 12345,
        dst_port: 443,
        proto: 17, // UDP
        _pad: [0; 3],
    };
    let e0 = maps
        .conntrack_get(&fwd_key)
        .expect("(1) forward CT entry created");
    assert_eq!(e0.gen(), 0, "(1) CT entry stamped with generation 0");

    // ── (2) Withdraw the NAT binding: delete config + bump generation (= conntrack_flush) ──
    assert!(shared.nat_remove(&NatKey {
        vni: VNI,
        ipv4: GUEST_IP,
    }));
    shared.bump_generation(); // DpdkMapWriter::conntrack_flush semantics
    assert_eq!(maps.config_generation(), 1, "(2) generation bumped to G1");

    // ── (3) Next packet on the SAME established flow must NOT emit under the withdrawn binding ──
    let (out1, a1) = run(&pool, &mut maps, &frame, &in_);
    // The cached CT entry is stamped gen=0 != current gen=1, so the SNAT reuse fast-path is bypassed;
    // snat_egress re-derives from nat_get → None (withdrawn) → NO src rewrite. The inner src IP must
    // therefore be the ORIGINAL GUEST_IP, never the stale NAT_IP.
    assert_ne!(
        &out1[INNER_IPV4_SRC_OFF..INNER_IPV4_SRC_OFF + 4],
        &NAT_IP,
        "(3) STALE-EMISSION BUG: packet emitted under the withdrawn NAT binding"
    );
    assert_eq!(
        &out1[INNER_IPV4_SRC_OFF..INNER_IPV4_SRC_OFF + 4],
        &GUEST_IP,
        "(3) withdrawn binding gone → src IP is the un-NATed guest IP"
    );
    assert_eq!(
        a1,
        Action::Redirect(UPLINK_IFINDEX),
        "(3) still forwarded (route intact), just without the withdrawn SNAT"
    );

    // ── (4) REBIND to a DIFFERENT port range: the recheck branch itself (not just the None re-fetch) ──
    // The pure-withdrawal case (3) is also caught by snat_egress's unconditional `nat_get` (returns
    // None). This scenario exercises the GENERATION RECHECK specifically: re-add a NAT binding for the
    // same guest IP but with a DISJOINT source-port range, then bump the generation again. A first
    // packet establishes a fresh CT entry (port in the NEW range, stamped gen=2). Then rebind AGAIN to
    // a THIRD, disjoint range + bump to gen=3, and send another packet on the same flow. Without the
    // gen recheck the cached entry's stale `xlate_port` (from the gen=2 range) would be reused and
    // emitted; WITH it, gen mismatch forces re-derivation into the current range. We assert the emitted
    // L4 source port lies within the CURRENT range — proving no stale port is emitted.
    const RANGE_A: (u16, u16) = (20000, 21000);
    const RANGE_B: (u16, u16) = (40000, 41000);

    // Establish under RANGE_A (generation 2).
    assert!(shared.nat_insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: RANGE_A.0,
            port_max: RANGE_A.1
        },
    ));
    shared.bump_generation();
    assert_eq!(maps.config_generation(), 2);
    let (out2, _) = run(&pool, &mut maps, &frame, &in_);
    let sport2 = u16::from_be_bytes([out2[UDP_SPORT_OFF], out2[UDP_SPORT_OFF + 1]]);
    assert!(
        (RANGE_A.0..RANGE_A.1).contains(&sport2),
        "(4a) established SNAT port {sport2} within RANGE_A {RANGE_A:?}"
    );

    // Rebind the same guest IP to the DISJOINT RANGE_B + bump (generation 3) = the config change.
    assert!(shared.nat_insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: RANGE_B.0,
            port_max: RANGE_B.1
        },
    ));
    shared.bump_generation();
    assert_eq!(maps.config_generation(), 3);

    // Same flow again: the cached CT entry is stamped gen=2 != current gen=3 → recheck fires → the
    // stale RANGE_A port must NOT be reused; the emitted port must fall in the CURRENT RANGE_B.
    let (out3, a3) = run(&pool, &mut maps, &frame, &in_);
    let sport3 = u16::from_be_bytes([out3[UDP_SPORT_OFF], out3[UDP_SPORT_OFF + 1]]);
    assert_eq!(a3, Action::Redirect(UPLINK_IFINDEX), "(4b) still forwarded");
    assert!(
        !(RANGE_A.0..RANGE_A.1).contains(&sport3),
        "(4b) STALE-EMISSION BUG: reused the pre-rebind RANGE_A port {sport3} after generation bump"
    );
    assert!(
        (RANGE_B.0..RANGE_B.1).contains(&sport3),
        "(4b) recheck re-derived the SNAT port {sport3} into the CURRENT RANGE_B {RANGE_B:?}"
    );

    // ── (5) NAT64 egress: the SAME generation recheck guards nat64_egress_parse's port allocation ──
    // NAT64 stamps its fwd/rev CT_F_NAT64 entries with the config generation too (fixed to mirror the
    // SNAT path). A rebind to a DISJOINT source-port range + generation bump must force re-derivation
    // into the new range, never reuse the stale cached nat_port. A DISTINCT guest (NAT64_GUEST_V4/V6)
    // keeps its conntrack keys from colliding with the SNAT flow above.
    const N64_RANGE_A: (u16, u16) = (22000, 23000);
    const N64_RANGE_B: (u16, u16) = (42000, 43000);
    let n64_meta = nat64_port_meta();
    let n64_local = node_local();
    let n64_in = GuestTxNat64In {
        meta: &n64_meta,
        local: &n64_local,
    };
    let v6_frame = guest_frame_v6(12345);

    // Establish under N64_RANGE_A (generation 4).
    assert!(shared.nat_insert(
        NatKey {
            vni: VNI,
            ipv4: NAT64_GUEST_V4,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: N64_RANGE_A.0,
            port_max: N64_RANGE_A.1,
        },
    ));
    shared.bump_generation();
    assert_eq!(maps.config_generation(), 4);
    let (n0, na0) = run_nat64(&pool, &mut maps, &v6_frame, &n64_in);
    assert_eq!(
        na0,
        Action::Redirect(UPLINK_IFINDEX),
        "(5a) nat64 translated + encapped + forwarded"
    );
    assert_eq!(
        &n0[INNER_IPV4_SRC_OFF..INNER_IPV4_SRC_OFF + 4],
        &NAT_IP,
        "(5a) inner src SNAT-rewritten to NAT_IP"
    );
    let n64_sport_a = u16::from_be_bytes([n0[UDP_SPORT_OFF], n0[UDP_SPORT_OFF + 1]]);
    assert!(
        (N64_RANGE_A.0..N64_RANGE_A.1).contains(&n64_sport_a),
        "(5a) established nat64 port {n64_sport_a} within N64_RANGE_A {N64_RANGE_A:?}"
    );
    // Sanity: the fwd nat64 CT entry is stamped under the CURRENT generation (4) — not 0.
    let n64_fwd = flowplane_common::CtKey {
        vni: VNI,
        src_ip: NAT64_GUEST_V4,
        dst_ip: EXT_DST,
        src_port: 12345,
        dst_port: 443,
        proto: 17,
        _pad: [0; 3],
    };
    assert_eq!(
        maps.conntrack_get(&n64_fwd)
            .expect("(5a) nat64 fwd CT entry created")
            .gen(),
        4,
        "(5a) nat64 CT entry stamped with the current generation (was hardcoded 0 before the fix)"
    );

    // Rebind the same guest to the DISJOINT N64_RANGE_B + bump (generation 5) = the config change.
    assert!(shared.nat_insert(
        NatKey {
            vni: VNI,
            ipv4: NAT64_GUEST_V4,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: N64_RANGE_B.0,
            port_max: N64_RANGE_B.1,
        },
    ));
    shared.bump_generation();
    assert_eq!(maps.config_generation(), 5);

    // Same nat64 flow: cached CT stamped gen=4 != current gen=5 → recheck fires → the stale
    // N64_RANGE_A port must NOT be reused; the emitted port must fall in the CURRENT N64_RANGE_B.
    let (n1, na1) = run_nat64(&pool, &mut maps, &v6_frame, &n64_in);
    assert_eq!(
        na1,
        Action::Redirect(UPLINK_IFINDEX),
        "(5b) still forwarded"
    );
    let n64_sport_b = u16::from_be_bytes([n1[UDP_SPORT_OFF], n1[UDP_SPORT_OFF + 1]]);
    assert!(
        !(N64_RANGE_A.0..N64_RANGE_A.1).contains(&n64_sport_b),
        "(5b) STALE-EMISSION BUG: nat64 reused the pre-rebind N64_RANGE_A port {n64_sport_b} after a generation bump"
    );
    assert!(
        (N64_RANGE_B.0..N64_RANGE_B.1).contains(&n64_sport_b),
        "(5b) nat64 recheck re-derived the port {n64_sport_b} into the CURRENT N64_RANGE_B {N64_RANGE_B:?}"
    );
}
