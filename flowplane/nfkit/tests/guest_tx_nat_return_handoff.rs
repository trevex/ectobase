//! Task 5 (fallback a): the `shared_ct` HANDOFF across the two REAL datapath entrypoints.
//!
//! ── WHAT THIS PROVES ──────────────────────────────────────────────────────────────────────────
//! The DPDK serve worker runs guest egress (`process_guest_tx`) and NAT return (`process_uplink_rx`)
//! over ONE [`ComposedMaps`] (the shared read-only [`SharedConfigMaps`] config half + a per-lcore
//! [`PerLcoreFlowMaps`] flow half). A guest's SNAT egress installs a PEER-INDEPENDENT reverse
//! conntrack entry `(vni, 0, nat_ip, 0, nat_port)` into the SHARED conntrack table (`shared_ct`, the
//! cross-lcore fix). The external reply then arrives on the uplink and MUST resolve THAT reverse
//! entry to reverse-DNAT back to the originating guest.
//!
//! This test drives the WHOLE round-trip over ONE `ComposedMaps` using BOTH real entrypoints:
//!   1. `process_guest_tx` on a guest IPv4 TCP frame → SNAT + outer-IPv6 encap → `Redirect(uplink)`,
//!      and (the WRITE side of the handoff) the reverse entry lands in `shared_ct`.
//!   2. The NAT identity (nat_ip / nat_port) is DISCOVERED from the real SNAT allocation — read back
//!      out of the post-SNAT encapped frame (inner IPv4 src + inner TCP src port) — NOT hardcoded,
//!      so the test proves the handoff regardless of the allocator's internal port choice.
//!   3. `process_uplink_rx` (the READ side) on the matching encapped WAN return, resolved EXACTLY as
//!      the serve worker resolves it (`read_array::<16>(ETH_LEN+24)` outer dst → `underlay_get` →
//!      `UplinkIn`) → `Redirect(guest_tap)` with the inner dst reverse-DNAT'd back to the guest IP +
//!      original guest sport, and inner eth dst = guest_mac.
//!
//! This closes the loop: the reverse entry `process_guest_tx` WROTE into `shared_ct` is exactly what
//! `process_uplink_rx` READS to deliver the return — via the two real datapath entrypoints (NOT a
//! manually-inserted CT entry like `multilcore_nat_return.rs` uses to isolate the table-selection
//! property).
//!
//! ── WHY THIS IS THE COMPONENT TEST (Task 5 fallback a) ────────────────────────────────────────
//! Every datapath seam is already independently proven, so the remaining unproven property is the
//! shared_ct HANDOFF itself, proven here over the exact `ComposedMaps` the serve worker uses:
//!   * `guest_tx_datapath.rs` — real `process_guest_tx` over MbufPkt: SNAT+encap byte-parity + the
//!     reverse entry lands in shared_ct.
//!   * `afxdp_datapath.rs` — real `process_uplink` over REAL af_xdp transport, byte-parity.
//!   * `attach_veth.rs` — real gRPC attach binds a preallocated guest af_xdp pool slot.
//!   * THIS test — the guest_tx → shared_ct → uplink_rx handoff, end to end.
//!
//! ── FOLLOW-UP (documented, NOT done here) ─────────────────────────────────────────────────────
//! The full-serve af_xdp e2e — bring up `flowplane-dpdk serve` with a preallocated guest port, gRPC
//! attach, then inject a guest frame on the guest veth + the matching NAT return on the uplink over
//! REAL af_xdp transport, asserting the encapped egress + reverse-DNAT delivery with real polling +
//! timing — is a documented FOLLOW-UP (Task 6 backlog). It is heavy and flaky, and each of its seams
//! (datapath entrypoints, af_xdp transport, attach/pool binding, and — here — the shared_ct handoff)
//! is independently proven above.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, FwMeta, FwRule, Local, NatKey, NatValue, PortMeta, RouteValue, UnderlayValue,
    FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::datapath::{process_guest_tx, process_uplink_rx, GuestTxIn, UplinkIn};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps; // brings `underlay_get` into scope on ComposedMaps (as serve.rs does)
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::SimNode;
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── addressing (guest-egress half — mirrors guest_tx_datapath.rs) ──────────────────────────────
const VNI: u32 = 100;
const GUEST_TAP: u32 = 10; // this node's guest port ifindex (src_ifindex on egress, redirect on return)
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const EXT_DST: [u8; 4] = [203, 0, 113, 9];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
// SRC_UL = THIS node's underlay: outer src on egress AND the outer dst of the returning frame.
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
// NAT source: guest GUEST_IP masquerades behind NAT_IP with an allocatable port range.
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const NAT_PORT_MIN: u16 = 20000;
const NAT_PORT_MAX: u16 = 20200;
const SPORT: u16 = 12345; // original guest source port (restored inner dst port after reverse-DNAT)
const DPORT: u16 = 443; // external peer's port

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

/// External default route (`0.0.0.0/0`, is_external=1) → guest_tx takes the SNAT + encap arm.
fn ext_route() -> RouteValue {
    RouteValue {
        nexthop_vni: 0,
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

/// A guest Ethernet frame `[Eth][IPv4][TCP]` GUEST_IP:SPORT → EXT_DST:DPORT.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, EXT_DST, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to grow_head data-pointer
/// moves — reads are relative to the current front).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Encapsulate an inner Eth+IPv4 returning frame IP-in-IPv6 toward THIS node's underlay (`SRC_UL`),
/// via the REAL `SimNode::edge_encap` (as `multilcore_nat_return.rs` does). Outer dst = `nexthop_ipv6`
/// = `SRC_UL`, so the serve-worker `underlay_get(outer_dst)` resolves it to the local guest port.
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

/// The encapped WAN return: inner `[Eth][IPv4 EXT_DST:DPORT → NAT_IP:nat_port][TCP + 4B payload]`,
/// as it arrives from the peer (dst is the SNAT public identity discovered from the real allocation).
fn return_frame(nat_port: u16) -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_DST, NAT_IP, 64)
        .tcp(DPORT, nat_port, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    encap_return_toward_this_node(&frame)
}

#[test]
fn shared_ct_handoff_guest_tx_write_to_uplink_rx_read() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_ctho",
    ])
    .expect("EAL init");
    let pool = Mempool::new("ctho_pool", 1023, 250, 0).expect("pool");

    // ── ONE SharedConfigMaps (the cross-lcore, read-only config half). Program BOTH directions:
    //    egress side (LOCAL, external route, NAT source, egress-allow firewall) AND the return side
    //    (an UNDERLAY entry mapping THIS node's underlay `SRC_UL` → the local guest port). ──────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(shared.route4_insert(VNI, EXT_DST, ext_route()), "route4");
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
    //    serve worker holds. The SNAT reverse entry (src_ip==0 && src_port==0) routes into shared_ct.
    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // STEP 1 — GUEST EGRESS (the real WRITE): process_guest_tx installs the shared_ct reverse entry.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let frame = guest_frame();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let meta = port_meta();
    // Scope the MbufPkt borrow so it ends before we reuse `composed` freely below.
    let (out, egress_bytes) = {
        let mut pkt = MbufPkt::new(&mut mb);
        let out = process_guest_tx(
            &mut pkt,
            &mut composed,
            &GuestTxIn {
                meta: &meta,
                src_ifindex: GUEST_TAP,
                now: 0,
            },
        );
        (out, mp_bytes(&pkt))
    };

    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "guest egress: SNAT+encap arm redirects out the uplink"
    );
    assert_eq!(
        egress_bytes.len(),
        frame.len() + 40,
        "guest egress: outer IPv6 header (40B) prepended"
    );

    // ── DISCOVER the NAT identity from the REAL SNAT allocation (not hardcoded): read it back out of
    //    the post-SNAT encapped frame. Inner IPv4 header starts after outer Eth(14)+IPv6(40); inner
    //    IPv4 src @ +12, and (20B IPv4 header, no options) inner TCP src port @ +20. ────────────────
    let inner_ip = ETH_LEN + 40;
    let nat_ip_alloc: [u8; 4] = egress_bytes[inner_ip + 12..inner_ip + 16]
        .try_into()
        .unwrap();
    assert_eq!(
        nat_ip_alloc, NAT_IP,
        "guest egress: inner IPv4 src SNAT'd to the NAT public IP"
    );
    let nat_port_alloc =
        u16::from_be_bytes([egress_bytes[inner_ip + 20], egress_bytes[inner_ip + 20 + 1]]);
    assert!(
        (NAT_PORT_MIN..=NAT_PORT_MAX).contains(&nat_port_alloc),
        "guest egress: allocated NAT port {nat_port_alloc} within the source range"
    );

    // ── The peer-independent reverse entry the handoff depends on IS present in shared_ct, keyed at
    //    the DISCOVERED identity `(vni, 0, nat_ip, 0, nat_port)`, and restores the original guest sport.
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
        "handoff WRITE: SNAT reverse entry present in shared_ct at the discovered nat identity"
    );
    assert_eq!(
        rev.unwrap().xlate_port,
        SPORT,
        "handoff WRITE: reverse entry restores the original guest source port"
    );

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // STEP 2 — NAT RETURN (the real READ): process_uplink_rx resolves THAT shared_ct reverse entry.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let ret = return_frame(nat_port_alloc);
    let mut rmb = pool.alloc().expect("alloc mbuf");
    rmb.append(ret.len() as u16).expect("append");
    rmb.data_mut().copy_from_slice(&ret);
    let local = node_local();
    // Scope the MbufPkt borrow (as the serve worker does per rx'd mbuf).
    let (action, delivered) = {
        let mut rpkt = MbufPkt::new(&mut rmb);
        // Resolve the uplink input EXACTLY as the serve worker does: outer IPv6 dst @ ETH_LEN+24
        // (=38) → underlay_get(outer_dst) → UplinkIn.
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

    // ── The loop closes: the reverse entry process_guest_tx WROTE is what process_uplink_rx READ. ──
    assert_eq!(
        action,
        Action::Redirect(GUEST_TAP),
        "handoff READ: NAT return resolves the shared_ct reverse entry and reverse-DNATs to the guest \
         tap (a miss would be a base-path ingress-firewall DROP / new-inbound-flow)"
    );
    // After decap the delivered frame is `[InnerEth][IPv4][TCP]`; inner IPv4 dst @ ETH_LEN+16, inner
    // TCP dst port @ ETH_LEN+20(hdr)+2, inner eth dst @ 0.
    let d_ip = ETH_LEN;
    let dst_ip: [u8; 4] = delivered[d_ip + 16..d_ip + 20].try_into().unwrap();
    assert_eq!(
        dst_ip, GUEST_IP,
        "handoff READ: inner dst reverse-DNAT'd back to the guest IP"
    );
    let dst_port = u16::from_be_bytes([delivered[d_ip + 20 + 2], delivered[d_ip + 20 + 3]]);
    assert_eq!(
        dst_port, SPORT,
        "handoff READ: inner dst TCP port restored to the original guest sport"
    );
    let inner_eth_dst: [u8; 6] = delivered[0..6].try_into().unwrap();
    assert_eq!(
        inner_eth_dst, GUEST_MAC,
        "handoff READ: inner eth dst set to the guest MAC"
    );

    shared.report_quiescent(&tok);
}
