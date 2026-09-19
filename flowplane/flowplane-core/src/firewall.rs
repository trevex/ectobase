//! The datapath firewall: a two-stage classifier, generic over `Pkt` + `Maps`. **Deny-by-default:**
//! the verdict is ACCEPT only when the matched rule allows; no binding, no rules in the direction,
//! an unreadable header or no matching entry is DROP. The control plane materializes any
//! "default-allow" as explicit allow rules.
//!
//! The rule lists are compiled by the dataplane (`flowplane_control::fwclass`) into content-addressed
//! scopes; `FW_BIND` points an interface at one scope per direction. Every first-match decision is
//! settled at compile time (rank precedence and insert-time shadowing), so evaluation is a constant
//! number of lookups whatever the number of rules. See `flowplane_common::FwBind` / `FwPolKey`.

use crate::arp_nd::IPPROTO_ICMPV6;
use crate::maps::Maps;
use crate::parse::{icmp_type_code, l4_ports, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::Pkt;
use flowplane_common::{
    fw_precedence_allows, FwPolKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_CLASS_ANY, FW_DIR_EGRESS,
    FW_SCOPE_NONE,
};

/// The classifier's decision from its two policy probes: the higher precedence wins (they never
/// tie — precedences are unique ranks), and it accepts only if its verdict byte is ALLOW. No hit in
/// either probe denies.
#[inline(always)]
fn fw_probe_verdict(specific: Option<u32>, any: Option<u32>) -> u8 {
    let best = match (specific, any) {
        (Some(a), Some(b)) => Some(if a > b { a } else { b }),
        (a, None) => a,
        (None, b) => b,
    };
    match best {
        Some(p) if fw_precedence_allows(p) => FW_ACTION_ACCEPT,
        _ => FW_ACTION_DROP,
    }
}

/// The policy key's proto + port suffix for the packet: the destination port for TCP/UDP, `[type,
/// code]` for ICMP (`icmp_proto` = 1 on v4, 58 on v6), zero otherwise (and for a non-first fragment,
/// which carries no L4 header).
#[inline(always)]
fn fw_pol_suffix(proto: u8, dport: u16, icmp: (u16, u16), icmp_proto: u8) -> [u8; 2] {
    if proto == icmp_proto {
        [icmp.0 as u8, icmp.1 as u8]
    } else if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        dport.to_be_bytes()
    } else {
        [0, 0]
    }
}

/// Two-stage classifier for the IPv4 packet at `ip_off` on interface `ifindex` in `dir` (FW_DIR_*).
/// Deny-by-default: FW_ACTION_ACCEPT only when the matched rule allows. The interface's scope for `dir` comes from `FW_BIND`; the PEER address (source on
/// ingress, destination on egress) is classified by longest prefix in the scope's class trie; the
/// scope's policy trie is then probed with that class and with class 0 ("any peer"), and the higher
/// precedence decides. Cost is two map lookups plus two probes, whatever the number of rules.
#[inline(always)]
pub fn fw_classify<P: Pkt, M: Maps>(pkt: &P, maps: &M, ip_off: usize, ifindex: u32, dir: u8) -> u8 {
    let scope = match maps.fw_bind(ifindex) {
        Some(b) => b.scope(dir),
        None => return FW_ACTION_DROP,
    };
    if scope == FW_SCOPE_NONE {
        return FW_ACTION_DROP;
    }
    let peer_off = if dir == FW_DIR_EGRESS { 16 } else { 12 };
    let peer = match pkt.read_array::<4>(ip_off + peer_off) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let (proto, _, dport) = match l4_ports(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 9).unwrap_or(0), 0u16, 0u16),
    };
    let port = fw_pol_suffix(proto, dport, icmp_type_code(pkt, ip_off), IPPROTO_ICMP);
    let specific = match maps.fw_class4(scope, &peer) {
        Some(c) if c != FW_CLASS_ANY => maps.fw_policy4(scope, &FwPolKey::new(c, proto, port)),
        _ => None,
    };
    let any = maps.fw_policy4(scope, &FwPolKey::new(FW_CLASS_ANY, proto, port));
    fw_probe_verdict(specific, any)
}

/// IPv6 sibling of [`fw_classify`]: same stages over the scope's v6 tries, reading the fixed IPv6
/// header (src@+8, dst@+24, L4@+40); ICMP here is ICMPv6 (58).
#[inline(always)]
pub fn fw_classify6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    ifindex: u32,
    dir: u8,
) -> u8 {
    let scope = match maps.fw_bind(ifindex) {
        Some(b) => b.scope(dir),
        None => return FW_ACTION_DROP,
    };
    if scope == FW_SCOPE_NONE {
        return FW_ACTION_DROP;
    }
    let peer_off = if dir == FW_DIR_EGRESS { 24 } else { 8 };
    let peer = match pkt.read_array::<16>(ip_off + peer_off) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let (proto, _, dport) = match crate::parse::l4_ports_v6(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 6).unwrap_or(0), 0u16, 0u16),
    };
    let port = fw_pol_suffix(
        proto,
        dport,
        crate::parse::icmp_type_code_v6(pkt, ip_off),
        IPPROTO_ICMPV6,
    );
    let specific = match maps.fw_class6(scope, &peer) {
        Some(c) if c != FW_CLASS_ANY => maps.fw_policy6(scope, &FwPolKey::new(c, proto, port)),
        _ => None,
    };
    let any = maps.fw_policy6(scope, &FwPolKey::new(FW_CLASS_ANY, proto, port));
    fw_probe_verdict(specific, any)
}
