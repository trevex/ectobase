//! The NAT64 `shared_ct` HANDOFF across the two REAL datapath
//! entrypoints — the v6→v4 egress WRITE and the v4→v6 ingress READ — over ONE [`ComposedMaps`].
//!
//! ── WHAT THIS PROVES ──────────────────────────────────────────────────────────────────────────
//! The DPDK serve worker now branches the guest block on inner ethertype: an IPv6 guest frame whose
//! dst is in the NAT64 well-known prefix `64:ff9b::/96` runs `process_guest_tx_nat64` (v6→v4 SNAT +
//! translate + IP-in-IPv6 encap). That egress installs a PEER-INDEPENDENT reverse conntrack entry
//! `(vni, 0, nat_ip, 0, nat_port)` carrying `CT_F_NAT64 | CT_REWRITE_DST` into the SHARED conntrack
//! table (`shared_ct`, the cross-lcore mechanism). The external IPv4 reply then arrives encapped on
//! the uplink and MUST resolve THAT reverse entry — and, because the flag is `CT_F_NAT64`, be
//! v4→v6-EXPANDED via `process_uplink_nat64_ingress` (NOT plain reverse-DNAT), delivering an IPv6
//! frame back to the originating guest.
//!
//! This drives the WHOLE NAT64 round-trip over ONE `ComposedMaps` using BOTH real entrypoints:
//!   1. `process_guest_tx_nat64` on a guest IPv6 TCP frame → SNAT + v4 translate + outer-IPv6 encap →
//!      `Redirect(uplink)`, and (the WRITE side) the `CT_F_NAT64` reverse entry lands in `shared_ct`.
//!   2. The NAT identity (nat_ip / nat_port) is DISCOVERED from the real SNAT allocation — read back
//!      out of the post-translation encapped frame (inner IPv4 src @ +12 + inner TCP src port @ +20),
//!      NOT hardcoded — so the test proves the handoff regardless of the allocator's port choice.
//!   3. `process_uplink_rx` (the READ side) on the matching encapped v4 WAN return, resolved EXACTLY
//!      as the serve worker resolves it (`read_array::<16>(ETH_LEN+24)` outer dst → `underlay_get` →
//!      `UplinkIn`) → `Redirect(guest_tap)` AND the delivered frame is v6-EXPANDED (inner ethertype
//!      0x86DD, inner IPv6 dst == the guest's overlay IPv6) — proving the `CT_F_NAT64` dispatch into
//!      `process_uplink_nat64_ingress`.
//!
//! This is the NAT64 analogue of `guest_tx_nat_return_handoff.rs` (the IPv4 SNAT handoff): it closes
//! backlog #3 by proving the NAT64 egress WRITE → NAT64 ingress READ handoff is END-TO-END reachable
//! over the exact `ComposedMaps` the serve worker holds — the reason to wire the ethertype branch.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, FwMeta, FwRule, Local, NatKey, NatValue, PortMeta, RouteValue, UnderlayValue,
    CT_F_NAT64, CT_REWRITE_DST, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::datapath::{
    process_guest_tx_nat64, process_uplink_rx, GuestTxNat64In, UplinkIn,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps; // brings `underlay_get` into scope on ComposedMaps (as serve.rs does)
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::SimNode;
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── addressing (NAT64 egress half — mirrors flowplane-sim/src/nat64_test.rs) ───────────────────
const VNI: u32 = 300;
const GUEST_TAP: u32 = 9; // this node's guest port ifindex (src on egress, redirect on return)
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 0, 42]; // the guest's overlay IPv4 (NAT key)
/// The guest's IPv6 (any host address; the NAT key is the guest IPv4). Restored as the ingress dst.
const GUEST_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const GUEST_MAC: [u8; 6] = [0x22; 6];
/// The external IPv4 the guest reaches (embedded in the `64:ff9b::` dst).
const EXT_V4: [u8; 4] = [203, 0, 113, 9];
const NAT_IP: [u8; 4] = [198, 51, 100, 7]; // the guest's public NAT IPv4
const NAT_PORT_MIN: u16 = 20000;
const NAT_PORT_MAX: u16 = 20512;
const SPORT: u16 = 40000; // original guest source port (restored inner dst port on ingress)
const DPORT: u16 = 443; // external peer's port
                        // SRC_UL = THIS node's underlay: outer src on egress AND the outer dst of the returning frame.
const SRC_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];

/// The NAT64-embedded IPv6 dst = `64:ff9b::EXT_V4`.
fn nat64_dst() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_V4[0], EXT_V4[1], EXT_V4[2], EXT_V4[3],
    ]
}

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
        guest_ipv6: GUEST_IP6,
    }
}

/// External route for the embedded IPv4 dst (is_external=1) → the NAT64 egress encap arm.
fn ext_route() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UL,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: NAT_PORT_MIN,
        port_max: NAT_PORT_MAX,
    }
}

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

/// A guest Ethernet frame `[Eth][IPv6][TCP]` GUEST_IP6:SPORT → `64:ff9b::EXT_V4`:DPORT.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to head-grow data-pointer
/// moves — reads are relative to the current front).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Encapsulate an inner `[Eth][IPv4]` returning frame IP-in-IPv6 toward THIS node's underlay
/// (`SRC_UL`), via the REAL `SimNode::edge_encap` (as the SNAT sibling / multilcore tests do). Outer
/// dst = `nexthop_ipv6` = `SRC_UL`, so the serve-worker `underlay_get(outer_dst)` resolves it locally.
fn encap_return_toward_this_node(inner: &[u8]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: NEXTHOP_UL, // some remote edge underlay (outer src, unused by our rx)
            nexthop_ipv6: SRC_UL,     // outer dst = THIS node's underlay
            inner_proto: 4,           // IPPROTO_IPIP
            flow_label: 0,
        },
    )
}

/// The encapped v4 WAN return: inner `[Eth][IPv4 EXT_V4:DPORT → NAT_IP:nat_port][TCP + 4B payload]`,
/// as it arrives from the peer (dst is the SNAT public identity discovered from the real allocation).
fn return_frame(nat_port: u16) -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_V4, NAT_IP, 64)
        .tcp(DPORT, nat_port, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    encap_return_toward_this_node(&frame)
}

#[test]
fn shared_ct_handoff_nat64_egress_write_to_uplink_rx_v6_expansion() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_n64ho",
    ])
    .expect("EAL init");
    let pool = Mempool::new("n64ho_pool", 1023, 250, 0).expect("pool");

    // ── ONE SharedConfigMaps (the cross-lcore, read-only config half). Program BOTH directions:
    //    egress side (LOCAL, external route on the embedded v4, NAT source, nat public ip, egress-allow
    //    firewall) AND the return side (an UNDERLAY entry mapping THIS node's underlay `SRC_UL` → the
    //    local guest port). ────────────────────────────────────────────────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    // Program the guest port so the return-side `guest_ipv6` plumbing (ports_get) resolves — this is
    // what the serve worker reads to build UplinkIn.guest_ipv6 for the v6 expansion.
    assert!(shared.ports_insert(GUEST_TAP, port_meta()), "ports meta");
    assert!(shared.route4_insert(VNI, EXT_V4, ext_route()), "route4");
    assert!(
        shared.nat_insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP
            },
            nat_value()
        ),
        "nat binding"
    );
    assert!(shared.nat_ips_insert(VNI, NAT_IP), "nat public ip");
    assert!(
        shared.fw_meta_insert(GUEST_TAP, egress_allow_meta()),
        "fw_meta"
    );
    assert!(
        shared.fw_rules_insert(
            flowplane_common::FwRuleKey {
                ifindex: GUEST_TAP,
                idx: 0,
            },
            egress_allow_rule(),
        ),
        "fw_rule"
    );
    // Return-side delivery: outer dst `SRC_UL` → vni + guest tap + guest mac (what the serve worker
    // reads via `underlay_get(outer_dst)` to build `UplinkIn`).
    assert!(
        shared.underlay_insert(
            SRC_UL,
            UnderlayValue {
                vni: VNI,
                tap_ifindex: GUEST_TAP,
                guest_mac: GUEST_MAC,
                _pad: [0; 2],
            }
        ),
        "underlay delivery entry"
    );

    // ── ONE ComposedMaps (shared config half + a fresh per-lcore flow half) — the exact structure a
    //    serve worker holds. The NAT64 reverse entry (src_ip==0 && src_port==0) routes into shared_ct.
    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // STEP 1 — NAT64 GUEST EGRESS (the real WRITE): process_guest_tx_nat64 installs the shared_ct
    //          CT_F_NAT64 reverse entry.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let frame = guest_frame();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let meta = port_meta();
    let local = node_local();
    // Scope the MbufPkt borrow so it ends before we reuse `composed` freely below.
    let (action, egress_bytes) = {
        let mut pkt = MbufPkt::new(&mut mb);
        // process_guest_tx_nat64 returns Action directly (NOT GuestTxOut).
        let action = process_guest_tx_nat64(
            &mut pkt,
            &mut composed,
            &GuestTxNat64In {
                meta: &meta,
                local: &local,
            },
        );
        (action, mp_bytes(&pkt))
    };

    assert_eq!(
        action,
        Action::Redirect(UPLINK_IFINDEX),
        "NAT64 egress: translate + SNAT + encap arm redirects out the uplink"
    );
    // v6→v4 shrinks inner 20B, then a 40B outer IPv6 is prepended → net +20 vs the guest v6 frame.
    assert_eq!(
        egress_bytes.len(),
        frame.len() + 20,
        "NAT64 egress: inner v6(40)→v4(20) then outer IPv6(40) → net +20 bytes"
    );

    // ── DISCOVER the NAT identity from the REAL SNAT allocation (not hardcoded): read it back out of
    //    the post-translation encapped frame. Inner IPv4 header starts after outer Eth(14)+IPv6(40);
    //    inner IPv4 src @ +12, and (20B IPv4 header, no options) inner TCP src port @ +20. ───────────
    let inner_ip = ETH_LEN + 40;
    let nat_ip_alloc: [u8; 4] = egress_bytes[inner_ip + 12..inner_ip + 16]
        .try_into()
        .unwrap();
    assert_eq!(
        nat_ip_alloc, NAT_IP,
        "NAT64 egress: inner IPv4 src SNAT'd to the NAT public IP"
    );
    let nat_port_alloc =
        u16::from_be_bytes([egress_bytes[inner_ip + 20], egress_bytes[inner_ip + 20 + 1]]);
    assert!(
        (NAT_PORT_MIN..NAT_PORT_MAX).contains(&nat_port_alloc),
        "NAT64 egress: allocated NAT port {nat_port_alloc} within the source range"
    );

    // ── The peer-independent CT_F_NAT64 reverse entry the handoff depends on IS present in shared_ct,
    //    keyed at the DISCOVERED identity `(vni, 0, nat_ip, 0, nat_port)`, flagged CT_F_NAT64 |
    //    CT_REWRITE_DST, restoring the guest IPv4 + original guest sport.
    let reverse_key = CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP,
        src_port: 0,
        dst_port: nat_port_alloc,
        proto: 6,
        _pad: [0; 3],
    };
    let rev = shared.shared_ct_get(&reverse_key);
    assert!(
        rev.is_some(),
        "handoff WRITE: NAT64 reverse entry present in shared_ct at the discovered nat identity"
    );
    let rev = rev.unwrap();
    assert_ne!(
        rev.flags & CT_F_NAT64,
        0,
        "handoff WRITE: reverse entry carries CT_F_NAT64 (drives the v6-expansion ingress dispatch)"
    );
    assert_ne!(
        rev.flags & CT_REWRITE_DST,
        0,
        "handoff WRITE: reverse entry carries CT_REWRITE_DST (reverse-DNAT the inner dst)"
    );
    assert_eq!(
        rev.xlate_ip, GUEST_IP,
        "handoff WRITE: reverse entry restores the guest IPv4"
    );
    assert_eq!(
        rev.xlate_port, SPORT,
        "handoff WRITE: reverse entry restores the original guest source port"
    );

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // STEP 2 — NAT64 RETURN (the real READ): process_uplink_rx resolves THAT CT_F_NAT64 reverse entry
    //          and v4→v6-EXPANDS the reply to the guest.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let ret = return_frame(nat_port_alloc);
    let mut rmb = pool.alloc().expect("alloc mbuf");
    rmb.append(ret.len() as u16).expect("append");
    rmb.data_mut().copy_from_slice(&ret);
    // Scope the MbufPkt borrow (as the serve worker does per rx'd mbuf).
    let (action, delivered) = {
        let mut rpkt = MbufPkt::new(&mut rmb);
        // Resolve the uplink input EXACTLY as the serve worker does: outer IPv6 dst @ ETH_LEN+24 (=38)
        // → underlay_get(outer_dst) → guest_ipv6 via ports_get(tap) → UplinkIn.
        let outer_dst = rpkt.read_array::<16>(ETH_LEN + 24).expect("outer v6 dst");
        assert_eq!(outer_dst, SRC_UL, "return outer dst = THIS node's underlay");
        let u = composed
            .underlay_get(&outer_dst)
            .expect("underlay delivery entry resolves the return's outer dst");
        let guest_ipv6 = composed
            .cfg
            .ports_get(u.tap_ifindex)
            .map(|m| m.guest_ipv6)
            .unwrap_or([0u8; 16]);
        assert_eq!(
            guest_ipv6, GUEST_IP6,
            "return-side ports_get resolves the guest's overlay IPv6 (the v6-expansion dst)"
        );
        let action = process_uplink_rx(
            &mut rpkt,
            &mut composed,
            &UplinkIn {
                vni: u.vni,
                u,
                outer_dst,
                local: &local,
                now: 0,
                guest_ipv6,
            },
        );
        (action, mp_bytes(&rpkt))
    };

    // ── The loop closes: the CT_F_NAT64 reverse entry process_guest_tx_nat64 WROTE is what
    //    process_uplink_rx READ — and it dispatched to the v6-expansion ingress, NOT plain decap. ────
    assert_eq!(
        action,
        Action::Redirect(GUEST_TAP),
        "handoff READ: NAT64 return resolves the shared_ct CT_F_NAT64 reverse entry and delivers to \
         the guest tap (a miss / wrong dispatch would be a firewall DROP or raw-IPv4 mis-delivery)"
    );
    // The delivered frame is v6-EXPANDED: inner ethertype 0x86DD, inner IPv6 dst == the guest IPv6.
    let inner_ethertype = u16::from_be_bytes([delivered[12], delivered[13]]);
    assert_eq!(
        inner_ethertype, 0x86DD,
        "handoff READ: delivered frame is IPv6 (dispatched to the NAT64 v6-expansion path, not raw \
         IPv4 decap)"
    );
    let inner_v6_dst: [u8; 16] = delivered[ETH_LEN + 24..ETH_LEN + 40].try_into().unwrap();
    assert_eq!(
        inner_v6_dst, GUEST_IP6,
        "handoff READ: inner IPv6 dst reconstructed to the guest's overlay IPv6"
    );
    let inner_eth_dst: [u8; 6] = delivered[0..6].try_into().unwrap();
    assert_eq!(
        inner_eth_dst, GUEST_MAC,
        "handoff READ: inner eth dst set to the guest MAC"
    );

    shared.report_quiescent(&tok);
}
