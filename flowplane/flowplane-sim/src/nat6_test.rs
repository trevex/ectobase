//! Conformance tests for the NAT66 guest-egress SNAT path (`snat_egress6`), the v6 sibling of
//! `nat_test.rs`. These drive the REAL `flowplane_core::nat::snat_egress6` via the full
//! `SimNode::guest_tx_v6` compose (`process_guest_tx_v6`) that the eBPF `forward_decision_v6`
//! delegates to — the native SimNode is the reference oracle; nothing is reimplemented.
//!
//! A v6 guest frame `[Eth 0x86DD][IPv6 guest_v6 → ext_v6][TCP]` with an egress-allow firewall, an
//! EXTERNAL v6 `route6`, and a NAT66 config for the guest is SNAT'd: src IPv6 -> nat_ipv6, TCP src
//! port -> a deterministic slot in `[port_min, port_max)`, with a VALID TCP checksum (the address
//! delta is folded into the L4 checksum via the v6 pseudo-header — the exact thing whose omission
//! black-holed the DSR return, so this test verifies the checksum actually folds to zero).

use etherparse::PacketBuilder;
use flowplane_common::{
    CtEntry6, CtKey6, FwMeta, FwRule6, IfaceValue, Local, NatKey6, NatValue6, NeighborNat6Entry,
    PortMeta, RouteValue, CT_F_SRC_NAT, CT_REWRITE_DST, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::encap::{TunnelEncap, ETH_LEN};
use flowplane_core::pkt::Action;

use crate::{MemMaps, SimNode};

// ─── fixed test topology ──────────────────────────────────────────────────────
const VNI: u32 = 400;
const SRC_IFINDEX: u32 = 11;
const UPLINK_IFINDEX: u32 = 7;
/// Guest overlay v6 (private ULA-ish).
const GUEST_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
/// Second guest sharing the same public nat_ipv6 in a distinct port block.
const GUEST_B_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x43,
];
/// External v6 dst — NOT in 64:ff9b::/96, so native v6→v6 (no NAT64).
const EXT_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
];
/// Public NAT66 source both guests are SNAT'd onto (edge public prefix).
const NAT_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
];
const SELF_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const GUEST_MAC: [u8; 6] = [0x22; 6];

const PORT_MIN_A: u16 = 3000;
const PORT_MAX_A: u16 = PORT_MIN_A + 256; // range 256
const PORT_MIN_B: u16 = 4000;
const PORT_MAX_B: u16 = PORT_MIN_B + 256;

// ─── helpers ─────────────────────────────────────────────────────────────────
fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn port_meta(guest_v6: [u8; 16]) -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: [10, 0, 0, 42],
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        l3: 0,
        offloaded: 0,
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: guest_v6,
    }
}

fn external_route6() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn egress_allow_rule() -> FwRule6 {
    FwRule6 {
        src_ip: [0; 16],
        src_mask: [0; 16],
        dst_ip: [0; 16],
        dst_mask: [0; 16],
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

fn add_nat6(maps: &mut MemMaps, guest_v6: [u8; 16], port_min: u16, port_max: u16) {
    maps.nat6.insert(
        NatKey6 {
            vni: VNI,
            ipv6: guest_v6,
        },
        NatValue6 {
            nat_ipv6: NAT_V6,
            port_min,
            port_max,
        },
    );
    maps.nat_ips6.insert((VNI, NAT_V6));
}

/// A SimNode with LOCAL, an external v6 route, and an egress-allow v6 firewall on SRC_IFINDEX.
fn node() -> SimNode {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.add_route6(VNI, EXT_V6, external_route6());
    node.maps.fw_meta6.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps
        .fw_rules6
        .insert((SRC_IFINDEX, 0), egress_allow_rule());
    node
}

fn tcp6_frame(src_v6: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0x11; 6])
        .ipv6(src_v6, EXT_V6, 64)
        .tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// True iff the TCP checksum over the emitted v6 packet is VALID: the ones-complement sum of the
/// IPv6 pseudo-header + the whole TCP segment (checksum field included) folds to 0xFFFF.
fn tcp6_checksum_valid(pkt: &[u8], ip_off: usize) -> bool {
    let src = &pkt[ip_off + 8..ip_off + 24];
    let dst = &pkt[ip_off + 24..ip_off + 40];
    let tcp = &pkt[ip_off + 40..];
    let mut sum: u32 = 0;
    for a in src.chunks(2).chain(dst.chunks(2)) {
        sum += u16::from_be_bytes([a[0], a[1]]) as u32;
    }
    let tcp_len = tcp.len() as u32; // IPv6 upper-layer packet length (32-bit)
    sum += (tcp_len >> 16) & 0xffff;
    sum += tcp_len & 0xffff;
    sum += 6; // next-header = TCP
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16) == 0xffff
}

// ─── (a) NAT66 rewrite: src IPv6 + port rewritten, checksum valid ─────────────
#[test]
fn snat6_rewrites_src_and_port_with_valid_checksum() {
    let sport: u16 = 50000;
    let dport: u16 = 443;
    let mut node = node();
    add_nat6(&mut node.maps, GUEST_V6, PORT_MIN_A, PORT_MAX_A);

    let out = node.guest_tx_v6(&tcp6_frame(GUEST_V6, sport, dport), &port_meta(GUEST_V6));

    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "external route → encap out the uplink"
    );
    let pkt = &out.pkt;
    let ip_off = ETH_LEN;

    // src IPv6 rewritten to NAT_V6 (at ip_off+8..+24).
    assert_eq!(
        &pkt[ip_off + 8..ip_off + 24],
        &NAT_V6,
        "src IPv6 -> nat_ipv6"
    );
    // TCP src port (at ip_off+40) rewritten into the assigned block.
    let new_sport = u16::from_be_bytes([pkt[ip_off + 40], pkt[ip_off + 41]]);
    assert!(
        (PORT_MIN_A..PORT_MAX_A).contains(&new_sport),
        "rewritten sport {new_sport} must be within [{PORT_MIN_A},{PORT_MAX_A})"
    );
    assert_ne!(new_sport, sport, "sport must actually be rewritten");
    // The TCP checksum must be VALID (address delta folded via the v6 pseudo-header).
    assert!(
        tcp6_checksum_valid(pkt, ip_off),
        "NAT66 must leave a valid TCP checksum (folds the src-addr delta into the v6 pseudo-header)"
    );
}

// ─── (b) distinct sources map to distinct blocks ─────────────────────────────
#[test]
fn snat6_distinct_sources_map_to_distinct_blocks() {
    let mut node = node();
    add_nat6(&mut node.maps, GUEST_V6, PORT_MIN_A, PORT_MAX_A);
    add_nat6(&mut node.maps, GUEST_B_V6, PORT_MIN_B, PORT_MAX_B);

    let out_a = node.guest_tx_v6(&tcp6_frame(GUEST_V6, 11111, 80), &port_meta(GUEST_V6));
    let out_b = node.guest_tx_v6(&tcp6_frame(GUEST_B_V6, 22222, 80), &port_meta(GUEST_B_V6));
    let ip_off = ETH_LEN;

    let sport_a = u16::from_be_bytes([out_a.pkt[ip_off + 40], out_a.pkt[ip_off + 41]]);
    let sport_b = u16::from_be_bytes([out_b.pkt[ip_off + 40], out_b.pkt[ip_off + 41]]);
    assert!((PORT_MIN_A..PORT_MAX_A).contains(&sport_a), "A in block A");
    assert!((PORT_MIN_B..PORT_MAX_B).contains(&sport_b), "B in block B");
    // Both SNAT'd onto the same public IP.
    assert_eq!(&out_a.pkt[ip_off + 8..ip_off + 24], &NAT_V6);
    assert_eq!(&out_b.pkt[ip_off + 8..ip_off + 24], &NAT_V6);
}

// ─── (c) no NAT66 config → no SNAT (packet forwarded unchanged) ───────────────
#[test]
fn snat6_no_op_without_config() {
    let mut node = node(); // external route + firewall, but NO nat6 config
    let frame = tcp6_frame(GUEST_V6, 50000, 443);
    let out = node.guest_tx_v6(&frame, &port_meta(GUEST_V6));
    assert_eq!(
        out.pkt, frame,
        "with no NAT66 config the frame is byte-for-byte unchanged (snat_egress6 no-ops)"
    );
}

// ─── (d) port exhaustion drops instead of colliding ──────────────────────────
#[test]
fn snat6_port_exhaustion_drops() {
    let mut node = node();
    // Range of exactly ONE port: the first flow consumes it, the second must be dropped rather than
    // reuse a live reverse key (which would mis-demux the first flow's return).
    add_nat6(&mut node.maps, GUEST_V6, 5000, 5001);

    let first = node.guest_tx_v6(&tcp6_frame(GUEST_V6, 40000, 80), &port_meta(GUEST_V6));
    assert_eq!(
        first.action,
        Action::Redirect(UPLINK_IFINDEX),
        "first flow allocates the single port + is forwarded"
    );
    // A second, distinct flow (different dst-port so a distinct fwd key) finds the only reverse slot
    // live → Exhausted → Drop.
    let second = node.guest_tx_v6(&tcp6_frame(GUEST_V6, 40001, 81), &port_meta(GUEST_V6));
    assert_eq!(
        second.action,
        Action::Drop,
        "second flow with the port block exhausted must be dropped"
    );
}

// ─── (e) NAT66 reverse-DNAT return: owner-node delivers to the guest ──────────
const RET_TAP: u32 = 55;
const RET_GUEST_MAC: [u8; 6] = [0x66; 6];
const RET_ORIG_SPORT: u16 = 40000; // restored inner dst port after reverse-DNAT
const RET_NAT_PORT: u16 = 3111; // the allocated NAT port (inner dst port in the return)
const RET_EXT_PORT: u16 = 443; // external peer port (inner src, unchanged)

fn ret_reverse_ct_key(proto: u8) -> CtKey6 {
    CtKey6 {
        vni: VNI,
        src_ip: [0; 16],
        dst_ip: NAT_V6,
        src_port: 0,
        dst_port: RET_NAT_PORT,
        proto,
        _pad: [0; 3],
    }
}

fn ret_reverse_ct_entry() -> CtEntry6 {
    CtEntry6 {
        last_seen: 0,
        xlate_ip6: GUEST_V6,
        xlate_port: RET_ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        _pad: [0; 4],
    }
}

/// Owner node seeded with the peer-independent reverse NAT_CT6 entry, the nat_ip6 registration, and
/// an INTERFACES6 entry for the RESTORED guest overlay IP (mechanism #2 delivery target).
fn ret_owner_node(proto: u8) -> SimNode {
    let mut node = SimNode::new();
    node.maps
        .nat_ct6
        .insert(ret_reverse_ct_key(proto), ret_reverse_ct_entry());
    node.maps.nat_ips6.insert((VNI, NAT_V6));
    node.maps.add_iface6(
        VNI,
        GUEST_V6,
        IfaceValue {
            tap_ifindex: RET_TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: RET_GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    node
}

/// Post-decap return frame `[Eth 0x86DD][IPv6 EXT_V6 → NAT_V6][TCP EXT_PORT → NAT_PORT]`.
fn ret_tcp_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(EXT_V6, NAT_V6, 64)
        .tcp(RET_EXT_PORT, RET_NAT_PORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

#[test]
fn dnat6_return_rewrites_dst_ip_and_port_valid_checksum() {
    let out = ret_owner_node(6).uplink_v6_dsr(&ret_tcp_frame(), VNI, &Local::default(), None);
    assert_eq!(
        out.action,
        Action::Redirect(RET_TAP),
        "reverse-DNAT'd return delivered to the guest tap"
    );
    let pkt = &out.pkt;
    let ip_off = ETH_LEN;
    // inner dst IPv6 restored to the guest overlay IP.
    assert_eq!(
        &pkt[ip_off + 24..ip_off + 40],
        &GUEST_V6,
        "inner dst IPv6 reverse-DNAT'd to the guest overlay IP"
    );
    // inner TCP dst port restored to the guest's original src port.
    let dport = u16::from_be_bytes([pkt[ip_off + 40 + 2], pkt[ip_off + 40 + 3]]);
    assert_eq!(
        dport, RET_ORIG_SPORT,
        "inner dst port restored to the guest's orig sport"
    );
    // checksum valid after the reverse rewrite (addr + port folded into the L4 csum).
    assert!(
        tcp6_checksum_valid(pkt, ip_off),
        "reverse-DNAT must leave a valid TCP checksum"
    );
}

// ─── (f) WAN-edge relay: nat_ip6 return to a remote owner is re-forwarded ─────
const OWNER_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77];
const OWNER_VNI: u32 = 909;

#[test]
fn wan6_rx_relays_nat_ip6_return_to_owner_with_owner_vni() {
    let mut node = SimNode::with_local(local());
    node.maps.neighbor_nat6.push(NeighborNat6Entry {
        underlay: OWNER_UNDERLAY,
        nat_ip6: NAT_V6,
        vni: OWNER_VNI,
        port_min: RET_NAT_PORT,
        port_max: RET_NAT_PORT + 1,
        enabled: 1,
        _pad: [0; 3],
    });
    // A plain WAN v6 frame EXT_V6 → NAT_V6:NAT_PORT (no LB VIP, no local ownership).
    let out = node.wan_rx(&ret_tcp_frame());
    assert_eq!(
        out.action,
        Action::Redirect(local().uplink_ifindex),
        "WAN-edge relays the nat_ip6 return out the uplink toward the owner"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: OWNER_VNI,
            remote: OWNER_UNDERLAY,
        }),
        "relay carries the OWNER's real vni + underlay (so its reverse CT key matches)"
    );
}

// ─── (g) intra-fabric relay: a non-owner node re-forwards a nat_ip6 return ────
#[test]
fn uplink6_relays_nat_ip6_return_to_owner() {
    let mut node = SimNode::with_local(local());
    node.maps.neighbor_nat6.push(NeighborNat6Entry {
        underlay: OWNER_UNDERLAY,
        nat_ip6: NAT_V6,
        vni: VNI,
        port_min: RET_NAT_PORT,
        port_max: RET_NAT_PORT + 1,
        enabled: 1,
        _pad: [0; 3],
    });
    // Not a locally-owned nat_ip (no nat_ips6/nat_ct6), no local INTERFACES6 → neighbor relay.
    let out = node.uplink_v6_dsr(&ret_tcp_frame(), VNI, &local(), None);
    assert_eq!(
        out.action,
        Action::Redirect(local().uplink_ifindex),
        "non-owner node relays the nat_ip6 return toward the owner"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: OWNER_UNDERLAY,
        }),
        "relay reforwards with the same vni toward the owner underlay"
    );
}
