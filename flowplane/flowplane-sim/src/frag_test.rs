//! IPv4 fragment handling.
//!
//! All fragments of an IPv4 datagram carry the original protocol number in the header, but only the
//! FIRST one carries the L4 header. `l4_ports` reads at `ip_off + ihl` off the protocol byte alone,
//! so for a non-first fragment it was reading payload bytes and calling them ports. Everything
//! keyed off that read inherited the garbage: the firewall matched on payload-derived ports,
//! conntrack gave every fragment of one flow a different key, Maglev hashed fragments of a flow
//! onto different backends, and `snat_egress` rewrote "the source port" straight into the payload.
//!
//! The fix keys a non-first fragment the way the v6 path already keys an extension-header packet —
//! `(proto, 0, 0)`, via `l4_ports` returning None — so fragments of one datagram share a key and no
//! payload is ever read or written as a port. Paths that REQUIRE an L4 translation cannot be made
//! correct that way and drop instead (see `snat_drops`).
//!
//! KNOWN LIMITATION: a fragmented flow therefore does not traverse NAT or a load balancer, and
//! needs a port-agnostic firewall rule to pass at all. Full support would need a fragment-tracking
//! map (keyed `(src, dst, proto, ip_id)`, carrying the first fragment's ports) — deliberately not
//! built here.

use crate::{MemMaps, SimNode, VecPkt};
use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, NatKey, NatValue, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::nat::{snat_egress, SnatOutcome};
use flowplane_core::parse::l4_ports;
use flowplane_core::pkt::Action;

const VNI: u32 = 100;
const SRC_IFINDEX: u32 = 10;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 0, 42];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const NAT_IP: [u8; 4] = [192, 0, 2, 7];
const SELF_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];

fn local() -> flowplane_common::Local {
    flowplane_common::Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [2; 6],
        gateway_mac: [3; 6],
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        l3: 0,
        offloaded: 0,
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// A bare `[IPv4][TCP][payload]` datagram at `ip_off = 0`.
fn ipv4_tcp(payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(GUEST_IP, EXT_IP, 64).tcp(50000, 443, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, payload).unwrap();
    out
}

/// Turn a datagram into a NON-FIRST fragment: strip the 20-byte L4 header (a non-first fragment
/// carries only payload continuation) and set the 13-bit fragment offset, in 8-byte units. Frag
/// flags/offset live at IPv4 +6/+7. What now sits at `ip_off + ihl` is payload.
fn make_non_first_fragment(mut pkt: Vec<u8>, offset_units: u16) -> Vec<u8> {
    assert!(
        offset_units > 0,
        "a non-first fragment has a nonzero offset"
    );
    pkt.splice(20..40, []); // drop the TCP header; payload moves up to ip_off + ihl
    let flags_frag = offset_units & 0x1fff;
    pkt[6] = (flags_frag >> 8) as u8;
    pkt[7] = (flags_frag & 0xff) as u8;
    pkt
}

/// The payload bytes a non-first fragment carries where the L4 header would be. Chosen so that
/// misreading them as ports yields a recognisable, policy-relevant value (443 in the dport slot).
const PORTLIKE_PAYLOAD: [u8; 8] = [0xc3, 0x50, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef];

#[test]
fn l4_ports_refuses_to_read_ports_from_a_non_first_fragment() {
    let first = ipv4_tcp(&PORTLIKE_PAYLOAD);
    // Sanity: as a FIRST fragment the real TCP header is present and parses normally.
    assert_eq!(
        l4_ports(&VecPkt::from_bytes(&first), 0),
        Some((6, 50000, 443)),
        "an unfragmented/first fragment parses its real L4 ports"
    );

    let non_first = make_non_first_fragment(first, 185);
    assert_eq!(
        l4_ports(&VecPkt::from_bytes(&non_first), 0),
        None,
        "a non-first fragment has no L4 header; its payload must never be read as ports"
    );
}

/// The concrete consequence of the garbage read: two fragments of ONE datagram must not key as two
/// different flows just because their payloads differ where the ports would be.
#[test]
fn fragments_of_one_datagram_share_a_conntrack_key() {
    let a = make_non_first_fragment(ipv4_tcp(&PORTLIKE_PAYLOAD), 185);
    let b = make_non_first_fragment(ipv4_tcp(&[0x11; 8]), 370);

    let ka = flowplane_core::conntrack::ct_key(&VecPkt::from_bytes(&a), 0, VNI).unwrap();
    let kb = flowplane_core::conntrack::ct_key(&VecPkt::from_bytes(&b), 0, VNI).unwrap();
    assert_eq!(
        (ka.src_port, ka.dst_port),
        (0, 0),
        "a non-first fragment keys with zero ports, not payload bytes"
    );
    assert_eq!(ka, kb, "fragments of one flow must share one conntrack key");
    assert_eq!(ka.proto, 6, "the real protocol number is still keyed");
}

/// SNAT cannot be applied to a non-first fragment — there is no port field to rewrite, and the
/// reverse demux is port-keyed. Passing it would emit the guest's overlay source to the internet,
/// which is exactly the leak `SnatOutcome::Exhausted` already exists to prevent.
#[test]
fn snat_drops_a_non_first_fragment_rather_than_leaking_the_guest_source() {
    let mut m = MemMaps::default();
    m.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: 1024,
            port_max: 2048,
        },
    );

    let raw = make_non_first_fragment(ipv4_tcp(&PORTLIKE_PAYLOAD), 185);
    let mut pkt = VecPkt::from_bytes(&raw);
    let out = snat_egress(&mut pkt, &mut m, 0, VNI, true, 0, 0);

    assert_ne!(
        out,
        SnatOutcome::Continue,
        "a NAT-required fragment must not be forwarded un-SNATed"
    );
    assert_eq!(
        pkt.bytes(),
        raw.as_slice(),
        "a refused SNAT must not have written a port into the payload"
    );
}

/// End-to-end: the same fragment through the full guest-egress compose is dropped, not emitted.
#[test]
fn guest_tx_drops_a_nat_required_non_first_fragment() {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.add_route4(
        VNI,
        EXT_IP,
        RouteValue {
            nexthop_vni: VNI,
            nexthop_ipv6: NEXTHOP_UNDERLAY,
            is_external: 1,
            _pad: [0; 3],
        },
    );
    node.maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: 1024,
            port_max: 2048,
        },
    );
    // A port-agnostic egress allow, so the firewall is NOT what drops this.
    node.maps.fw_meta.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert(
        (SRC_IFINDEX, 0),
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
        },
    );

    // `[Eth][IPv4 frag][payload]` — build the bare datagram then prepend an Ethernet header.
    let bare = make_non_first_fragment(ipv4_tcp(&PORTLIKE_PAYLOAD), 185);
    let mut frame = vec![0u8; 14];
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame.extend_from_slice(&bare);

    let out = node.guest_tx(&frame, &port_meta());
    assert_eq!(
        out.action,
        Action::Drop,
        "a fragment that needs SNAT it cannot receive must be dropped, not sent out un-SNATed"
    );
}
