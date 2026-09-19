//! Policy changes reach ESTABLISHED flows (the conntrack epoch). Every conntrack entry records the
//! node's policy epoch it was last evaluated under; the dataplane bumps the epoch whenever an
//! interface's firewall binding changes. A conntrack hit on a FORWARD entry from an older epoch —
//! or a bare TCP SYN reusing a tracked tuple — re-runs the checks a new flow gets, once; a refusal
//! drops the packet and forgets the flow. Replies ride their reverse entry and are never
//! re-evaluated, exactly as for a new flow.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, FwRule, FwRule6, IfaceValue, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
    FW_DIR_INGRESS,
};
use flowplane_core::conntrack::{ct_key, ct_key6};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;

use crate::{SimNode, VecPkt};

const VNI: u32 = 300;
const A_IP: [u8; 4] = [10, 0, 0, 10];
const B_IP: [u8; 4] = [10, 0, 0, 20];
const A_IF: u32 = 10;
const B_TAP: u32 = 77;

fn allow_all(n: &mut SimNode, ifindex: u32, dir: u8) {
    let m = n.maps.fw_meta.entry(ifindex).or_default();
    if dir == FW_DIR_EGRESS {
        m.egress_count += 1;
    } else {
        m.ingress_count += 1;
    }
    let slot = (0..)
        .find(|i| !n.maps.fw_rules.contains_key(&(ifindex, *i)))
        .unwrap();
    n.maps.fw_rules.insert(
        (ifindex, slot),
        FwRule {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            direction: dir,
            enabled: 1,
            ..Default::default()
        },
    );
}

/// Revoke every rule of `ifindex` in `dir` (the dataplane would rebind to an empty scope).
fn revoke(n: &mut SimNode, ifindex: u32, dir: u8) {
    if let Some(m) = n.maps.fw_meta.get_mut(&ifindex) {
        if dir == FW_DIR_EGRESS {
            m.egress_count = 0;
        } else {
            m.ingress_count = 0;
        }
    }
}

/// The INTERFACES row delivering to `tap`.
fn local(tap: u32, mac: u8) -> IfaceValue {
    IfaceValue {
        tap_ifindex: tap,
        is_local: 1,
        underlay_ipv6: [0; 16],
        guest_mac: [mac; 6],
        peer_capable: 0,
        _pad: [0; 1],
    }
}

fn route() -> RouteValue {
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99],
        is_external: 0,
        _pad: [0; 3],
    }
}

/// A and B on the same node, both allowed to talk: A egress + B ingress allow, and B egress + A
/// ingress allow for replies-as-new-flows.
fn same_node() -> SimNode {
    let mut n = SimNode::new();
    for (ip, tap, mac) in [(A_IP, A_IF, 0xaa), (B_IP, B_TAP, 0xcc)] {
        n.maps.add_route4(VNI, ip, route());
        n.maps.add_iface(VNI, ip, local(tap, mac));
    }
    allow_all(&mut n, A_IF, FW_DIR_EGRESS);
    allow_all(&mut n, B_TAP, FW_DIR_INGRESS);
    n
}

fn meta(ip: [u8; 4], mac: u8) -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: ip,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [mac; 6],
        l3: 0,
        offloaded: 0,
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, syn: bool, ack: bool) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, 0, 1024);
    if syn {
        step = step.syn();
    }
    if ack {
        step = step.ack(1);
    }
    let mut out = Vec::new();
    step.write(&mut out, &[]).unwrap();
    out
}

/// A → B, from A's interface.
fn a_to_b(n: &mut SimNode, syn: bool) -> Action {
    n.src_ifindex = A_IF;
    n.guest_tx(&tcp(A_IP, B_IP, 40000, 22, syn, !syn), &meta(A_IP, 0xaa))
        .action
}

/// B → A reply, from B's interface.
fn b_to_a(n: &mut SimNode) -> Action {
    n.src_ifindex = B_TAP;
    n.guest_tx(&tcp(B_IP, A_IP, 22, 40000, true, true), &meta(B_IP, 0xcc))
        .action
}

fn fwd_key() -> CtKey {
    ct_key(
        &VecPkt::from_bytes(&tcp(A_IP, B_IP, 40000, 22, true, false)),
        ETH_LEN,
        VNI,
    )
    .unwrap()
}

#[test]
fn revoking_the_source_egress_cuts_an_established_flow() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    assert_eq!(a_to_b(&mut n, false), Action::Redirect(B_TAP));
    revoke(&mut n, A_IF, FW_DIR_EGRESS);
    n.maps.fw_epoch = n.maps.fw_epoch.wrapping_add(1);
    assert_eq!(
        a_to_b(&mut n, false),
        Action::Drop,
        "established flow must meet the new policy"
    );
    assert!(
        n.maps.conntrack_get(&fwd_key()).is_none(),
        "the refused flow is forgotten"
    );
}

#[test]
fn revoking_the_destination_ingress_cuts_an_established_same_node_flow() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    revoke(&mut n, B_TAP, FW_DIR_INGRESS);
    n.maps.fw_epoch = n.maps.fw_epoch.wrapping_add(1);
    assert_eq!(a_to_b(&mut n, false), Action::Drop);
    assert!(n.maps.conntrack_get(&fwd_key()).is_none());
}

// Without an epoch bump nothing is re-evaluated: the rules changed but no binding did, so the
// established flow keeps its verdict — the epoch is what carries a policy change to it.
#[test]
fn an_unchanged_epoch_keeps_established_flows_on_the_fast_path() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    revoke(&mut n, A_IF, FW_DIR_EGRESS);
    assert_eq!(a_to_b(&mut n, false), Action::Redirect(B_TAP));
}

// A re-evaluation that still allows keeps the flow and stamps the current epoch, so the next
// packet is back on the fast path.
#[test]
fn a_passing_recheck_stamps_the_current_epoch() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    n.maps.fw_epoch = n.maps.fw_epoch.wrapping_add(1);
    assert_eq!(a_to_b(&mut n, false), Action::Redirect(B_TAP));
    let e = n.maps.conntrack_get(&fwd_key()).unwrap();
    assert_eq!(e.policy_epoch, n.maps.fw_epoch);
}

// A bare SYN on a tracked tuple is a new connection: it meets the current policy even when no
// epoch changed (Calico's port-reuse rule). Mid-connection segments stay on the fast path.
#[test]
fn a_syn_reusing_a_tracked_tuple_is_rechecked() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    revoke(&mut n, A_IF, FW_DIR_EGRESS);
    assert_eq!(
        a_to_b(&mut n, false),
        Action::Redirect(B_TAP),
        "ACK: fast path"
    );
    assert_eq!(
        a_to_b(&mut n, true),
        Action::Drop,
        "SYN: new connection, current policy"
    );
}

// Replies are never re-evaluated: B may not send to A on its own (no B egress, no A ingress
// rules), yet replies of A's flow keep flowing after a policy change, on their reverse entry.
#[test]
fn replies_are_not_reevaluated() {
    let mut n = same_node();
    assert_eq!(a_to_b(&mut n, true), Action::Redirect(B_TAP));
    n.maps.fw_epoch = n.maps.fw_epoch.wrapping_add(1);
    assert_eq!(b_to_a(&mut n), Action::Redirect(A_IF));
}

// ---- cross-node: the ingress hook ----------------------------------------------------------------

const GUEST_MAC: [u8; 6] = [0xcc; 6];

fn inbound(syn: bool) -> Vec<u8> {
    tcp([10, 9, 9, 9], B_IP, 40000, 443, syn, !syn)
}

#[test]
fn revoking_the_ingress_cuts_an_established_inbound_flow() {
    let mut host = SimNode::new();
    allow_all(&mut host, B_TAP, FW_DIR_INGRESS);
    let deliver = |h: &mut SimNode, syn| {
        h.host_uplink(&inbound(syn), VNI, B_IP, B_TAP, GUEST_MAC)
            .action
    };
    assert_eq!(deliver(&mut host, true), Action::Redirect(B_TAP));
    assert_eq!(deliver(&mut host, false), Action::Redirect(B_TAP));
    revoke(&mut host, B_TAP, FW_DIR_INGRESS);
    host.maps.fw_epoch = host.maps.fw_epoch.wrapping_add(1);
    assert_eq!(deliver(&mut host, false), Action::Drop);
    let key = ct_key(&VecPkt::from_bytes(&inbound(false)), ETH_LEN, VNI).unwrap();
    assert!(
        host.maps.conntrack_get(&key).is_none(),
        "the refused flow is forgotten"
    );
}

// ---- IPv6 ----------------------------------------------------------------------------------------

const A6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
const B6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];

fn allow_all6(n: &mut SimNode, ifindex: u32, dir: u8) {
    let m = n.maps.fw_meta6.entry(ifindex).or_default();
    if dir == FW_DIR_EGRESS {
        m.egress_count += 1;
    } else {
        m.ingress_count += 1;
    }
    let slot = (0..)
        .find(|i| !n.maps.fw_rules6.contains_key(&(ifindex, *i)))
        .unwrap();
    n.maps.fw_rules6.insert(
        (ifindex, slot),
        FwRule6 {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            direction: dir,
            enabled: 1,
            ..Default::default()
        },
    );
}

fn tcp6(syn: bool) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv6(A6, B6, 64)
        .tcp(40000, 22, 0, 1024);
    step = if syn { step.syn() } else { step.ack(1) };
    let mut out = Vec::new();
    step.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn v6_revoking_the_destination_ingress_cuts_an_established_same_node_flow() {
    let mut n = SimNode::new();
    n.maps.add_route6(VNI, B6, route());
    n.maps.add_iface6(VNI, B6, local(B_TAP, 0xcc));
    allow_all6(&mut n, A_IF, FW_DIR_EGRESS);
    allow_all6(&mut n, B_TAP, FW_DIR_INGRESS);
    n.src_ifindex = A_IF;
    let meta6 = PortMeta {
        guest_ipv6: A6,
        ..meta(A_IP, 0xaa)
    };
    assert_eq!(
        n.guest_tx_v6(&tcp6(true), &meta6).action,
        Action::Redirect(B_TAP)
    );
    assert_eq!(
        n.guest_tx_v6(&tcp6(false), &meta6).action,
        Action::Redirect(B_TAP)
    );
    if let Some(m) = n.maps.fw_meta6.get_mut(&B_TAP) {
        m.ingress_count = 0;
    }
    n.maps.fw_epoch = n.maps.fw_epoch.wrapping_add(1);
    assert_eq!(n.guest_tx_v6(&tcp6(false), &meta6).action, Action::Drop);
    let key = ct_key6(&VecPkt::from_bytes(&tcp6(false)), ETH_LEN, VNI).unwrap();
    assert!(
        n.maps.conntrack6_get(&key).is_none(),
        "the refused flow is forgotten"
    );
}
