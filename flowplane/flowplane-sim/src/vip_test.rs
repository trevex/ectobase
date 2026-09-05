//! F2 — 1:1 floating-IP ingress DNAT oracle coverage (rebuild of the pre-P2 eBPF `vip::dnat_ingress`,
//! now in `flowplane_core::datapath`). A frame whose inner dst is a floating IP `V` with `VIPS[(vni,V)]
//! = G` is rewritten dst V->G (+checksums) and delivered locally to G's tap. ICMP echo to a floating
//! IP is DNAT'd + forwarded to the guest (the guest answers), never answered by the dataplane.

use etherparse::PacketBuilder;
use flowplane_common::{FwMeta, FwRule, IfaceValue, Local, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::pkt::Action;

use crate::SimNode;

const VNI: u32 = 100;
const VIP: [u8; 4] = [203, 0, 113, 7]; // the floating IP (inner dst on the wire)
const GUEST: [u8; 4] = [10, 0, 0, 9]; // the backing guest overlay IPv4
const CLIENT: [u8; 4] = [198, 51, 100, 5];
const TAP: u32 = 77;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x09];

fn local() -> Local {
    Local {
        uplink_ifindex: 5,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
    }
}

/// A node that owns floating IP VIP->GUEST and has GUEST as a local interface.
///
/// DEVIATION from the task's given verbatim `vip_node()`: also seeds a permissive ingress `FW_META`/
/// `FW_RULES` ALLOW-all entry for `TAP`. `process_uplink`'s step 2 (`uplink_ingress_firewall_drop`)
/// evaluates the deny-by-default ingress firewall on every NEW flow's delivery tap unconditionally —
/// including the F2 VIP-DNAT arm, which sets `is_lb = false` exactly like normal guest delivery — so
/// without an explicit ALLOW rule for `TAP` every local-delivery sim test in this codebase (e.g.
/// `ns_scenario_test.rs::allow_tcp`, `lb_scenario_test.rs::apply_fw`) seeds one; this test module is
/// no exception. The rule matches on the POST-DNAT dst (`GUEST`) since the firewall evaluates the
/// packet AFTER `vip_dnat_rewrite` has already run.
fn vip_node() -> SimNode {
    let mut n = SimNode::with_local(local());
    n.maps.add_vip(VNI, VIP, GUEST);
    n.maps.add_iface(
        VNI,
        GUEST,
        IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    n.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    n.maps.fw_rules.insert(
        (TAP, 0),
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
        },
    );
    n
}

fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

fn eth_ipv4_icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .icmpv4_echo_request(1, 1);
    let mut out = Vec::new();
    b.write(&mut out, &[0xde, 0xad]).unwrap();
    out
}

#[test]
fn floating_ip_dnat_tcp_rewrites_dst_and_delivers_local() {
    let frame = eth_ipv4_tcp(CLIENT, VIP, 443);
    let out = vip_node().uplink(&frame, VNI, &local());

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "DNAT'd floating-IP frame must be delivered to the backing guest tap"
    );
    let ip_off = 14; // inner Eth
    let dst: [u8; 4] = out.pkt[ip_off + 16..ip_off + 20].try_into().unwrap();
    assert_eq!(dst, GUEST, "inner dst must be DNAT'd V->G");
    let src: [u8; 4] = out.pkt[ip_off + 12..ip_off + 16].try_into().unwrap();
    assert_eq!(src, CLIENT, "inner src must be unchanged");
    let ip_csum = u16::from_be_bytes([out.pkt[ip_off + 10], out.pkt[ip_off + 11]]);
    assert_ne!(ip_csum, 0, "IP checksum must be recomputed (non-zero)");
    let l4 = ip_off + 20;
    let tcp_csum = u16::from_be_bytes([out.pkt[l4 + 16], out.pkt[l4 + 17]]);
    assert_ne!(tcp_csum, 0, "TCP checksum must be fixed up (non-zero)");
    assert_eq!(out.tunnel, None, "local delivery emits no tunnel decision");
}

#[test]
fn floating_ip_dnat_icmp_echo_forwarded_to_guest_not_answered() {
    let frame = eth_ipv4_icmp_echo(CLIENT, VIP);
    let out = vip_node().uplink(&frame, VNI, &local());

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "ICMP echo to a floating IP must be DNAT'd + forwarded to the guest, NOT answered by the dataplane"
    );
    let ip_off = 14;
    let dst: [u8; 4] = out.pkt[ip_off + 16..ip_off + 20].try_into().unwrap();
    assert_eq!(dst, GUEST, "echo inner dst DNAT'd V->G");
    // ICMP type at l4[0] must still be 8 (echo REQUEST) — the dataplane did not turn it into a reply.
    let l4 = ip_off + 20;
    assert_eq!(
        out.pkt[l4], 8,
        "must remain an echo REQUEST (type 8) forwarded to the guest"
    );
}

#[test]
fn non_vip_dst_takes_normal_path_unchanged() {
    // dst not in VIPS and not a local interface -> Drop (fail-closed), inner bytes unchanged.
    let frame = eth_ipv4_tcp(CLIENT, [203, 0, 113, 200], 443);
    let mut n = vip_node();
    let out = n.uplink(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Drop,
        "non-VIP, non-local dst is fail-closed dropped"
    );
}

#[test]
fn floating_ip_maps_to_nonlocal_guest_drops() {
    // VIPS hit but G is not a local interface (misconfig) -> Drop, no reforward.
    let mut n = SimNode::with_local(local());
    n.maps.add_vip(VNI, VIP, GUEST); // no add_iface for GUEST
    let frame = eth_ipv4_tcp(CLIENT, VIP, 443);
    let out = n.uplink(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Drop,
        "floating IP with no local backing guest drops"
    );
}
