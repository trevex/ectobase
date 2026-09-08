//! Directional firewall evaluator, generic over `Pkt` + `Maps`. **Deny-by-default:** the verdict is
//! ACCEPT only when a rule in this direction explicitly matches with an accept action; every other
//! outcome — no per-interface meta, zero rules in this direction, an unreadable header, or no
//! matching rule — is DROP. The drop is unconditional. The control plane is responsible for
//! materializing k8s "default-allow" as an explicit allow-all rule per unpolicied direction.

use crate::maps::Maps;
use crate::parse::{icmp_type_code, l4_ports};
use crate::pkt::Pkt;
use flowplane_common::{FwRule, FwRule6, FwRuleKey, FW_ACTION_DROP, FW_DIR_EGRESS, FW_MAX_RULES};

/// The packet fields a firewall rule is matched against. `icmp_type`/`icmp_code` are only
/// consulted when `proto == 1` (ICMP).
pub struct PacketSelectors {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
}

/// Pure firewall match (no_std; used by the datapath and host-tested). Returns true if `r` matches
/// the packet selectors `s`.
///
/// Lives here in `flowplane-core` (not the `flowplane-common` types crate) because it is datapath
/// *logic*, not a shared POD type; the only callers are this crate's firewall evaluators
/// ([`fw_eval_dir`] / [`fw_eval_dir6`]).
#[inline]
pub fn fw_rule_matches(r: &FwRule, s: &PacketSelectors) -> bool {
    let PacketSelectors {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type,
        icmp_code,
    } = *s;
    if r.enabled == 0 {
        return false;
    }
    if r.proto != 0 && r.proto != proto {
        return false;
    }
    for i in 0..4 {
        if src[i] & r.src_mask[i] != r.src_ip[i] & r.src_mask[i] {
            return false;
        }
        if dst[i] & r.dst_mask[i] != r.dst_ip[i] & r.dst_mask[i] {
            return false;
        }
    }
    match proto {
        6 | 17 => {
            sport >= r.src_port_min
                && sport <= r.src_port_max
                && dport >= r.dst_port_min
                && dport <= r.dst_port_max
        }
        1 => {
            (r.icmp_type == 0xffff || icmp_type == r.icmp_type)
                && (r.icmp_code == 0xffff || icmp_code == r.icmp_code)
        }
        _ => true,
    }
}

/// IPv6 packet selectors (16-byte addresses). Mirror of `PacketSelectors`.
pub struct PacketSelectors6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
}

/// Pure IPv6 firewall match. Mirror of `fw_rule_matches`; ICMPv6 uses proto 58.
#[inline]
pub fn fw_rule6_matches(r: &FwRule6, s: &PacketSelectors6) -> bool {
    let PacketSelectors6 {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type,
        icmp_code,
    } = *s;
    if r.enabled == 0 {
        return false;
    }
    if r.proto != 0 && r.proto != proto {
        return false;
    }
    for i in 0..16 {
        if src[i] & r.src_mask[i] != r.src_ip[i] & r.src_mask[i] {
            return false;
        }
        if dst[i] & r.dst_mask[i] != r.dst_ip[i] & r.dst_mask[i] {
            return false;
        }
    }
    match proto {
        6 | 17 => {
            sport >= r.src_port_min
                && sport <= r.src_port_max
                && dport >= r.dst_port_min
                && dport <= r.dst_port_max
        }
        58 => {
            (r.icmp_type == 0xffff || icmp_type == r.icmp_type)
                && (r.icmp_code == 0xffff || icmp_code == r.icmp_code)
        }
        _ => true,
    }
}

/// Evaluate the firewall for the IPv4 packet at `ip_off` against interface `ifindex` in `dir`
/// (FW_DIR_*). Deny-by-default: returns FW_ACTION_ACCEPT only on an explicit matching accept rule,
/// FW_ACTION_DROP otherwise.
///
/// NOTE: this fn is shared by BOTH the ingress (`process_uplink`, via `datapath::
/// uplink_ingress_firewall_drop`) and egress (`egress::forward_decision_v4`) real-eBPF call sites,
/// each with its own tight BPF combined-stack budget (see `tc.rs`'s comments on `tc_guest_tx`'s).
/// Stays `#[inline(always)]` (tried leaving it unattributed and `#[inline(never)]` — LLVM still
/// fully inlines it either way at these call sites, and `#[inline(never)]` additionally cost a real
/// subprogram-call frame, making things worse); the P2 Task 4b ingress fix lives in how
/// `flowplane_core::datapath` shapes its OWN call depth around this fn instead (see
/// `datapath::uplink_ingress_firewall_drop`'s doc comment).
#[inline(always)]
pub fn fw_eval_dir<P: Pkt, M: Maps>(pkt: &P, maps: &M, ip_off: usize, ifindex: u32, dir: u8) -> u8 {
    // No per-interface firewall meta at all => no explicit allow => deny.
    let meta = match maps.fw_meta(ifindex) {
        Some(m) => m,
        None => return FW_ACTION_DROP,
    };
    let count = if dir == FW_DIR_EGRESS {
        meta.egress_count
    } else {
        meta.ingress_count
    };
    // No rules in this direction => no explicit allow => deny.
    if count == 0 {
        return FW_ACTION_DROP;
    }
    // Unreadable inner IPv4 header => cannot match any rule => deny.
    let src = match pkt.read_array::<4>(ip_off + 12) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let dst = match pkt.read_array::<4>(ip_off + 16) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let (proto, sport, dport) = match l4_ports(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 9).unwrap_or(0), 0u16, 0u16),
    };
    let (itype, icode) = icmp_type_code(pkt, ip_off);
    let sel = PacketSelectors {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type: itype,
        icmp_code: icode,
    };
    let mut idx: u32 = 0;
    while idx < FW_MAX_RULES {
        if let Some(r) = maps.fw_rule(&FwRuleKey { ifindex, idx }) {
            if r.direction == dir && fw_rule_matches(&r, &sel) {
                return r.action;
            }
        }
        idx += 1;
    }
    FW_ACTION_DROP
}

/// IPv6 firewall evaluator. Deny-by-default, identical semantics to [`fw_eval_dir`] but reads the
/// inner IPv6 header (src@+8, dst@+24, L4@+40) and scans `FW_RULES6`/`FW_META6`.
#[inline(always)]
pub fn fw_eval_dir6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    ifindex: u32,
    dir: u8,
) -> u8 {
    let meta = match maps.fw_meta6(ifindex) {
        Some(m) => m,
        None => return FW_ACTION_DROP,
    };
    let count = if dir == FW_DIR_EGRESS {
        meta.egress_count
    } else {
        meta.ingress_count
    };
    if count == 0 {
        return FW_ACTION_DROP;
    }
    let src = match pkt.read_array::<16>(ip_off + 8) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let dst = match pkt.read_array::<16>(ip_off + 24) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let (proto, sport, dport) = match crate::parse::l4_ports_v6(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 6).unwrap_or(0), 0u16, 0u16),
    };
    let (itype, icode) = crate::parse::icmp_type_code_v6(pkt, ip_off);
    let sel = PacketSelectors6 {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type: itype,
        icmp_code: icode,
    };
    let mut idx: u32 = 0;
    while idx < FW_MAX_RULES {
        if let Some(r) = maps.fw_rule6(&FwRuleKey { ifindex, idx }) {
            if r.direction == dir && fw_rule6_matches(&r, &sel) {
                return r.action;
            }
        }
        idx += 1;
    }
    FW_ACTION_DROP
}

#[cfg(test)]
mod tests {
    use super::{fw_rule_matches, PacketSelectors};
    use flowplane_common::{FwRule, FW_ACTION_ACCEPT, FW_DIR_INGRESS};

    #[test]
    fn fw_match_proto_and_ports() {
        let r = FwRule {
            src_ip: [0, 0, 0, 0],
            src_mask: [0, 0, 0, 0],
            dst_ip: [10, 0, 0, 5],
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 80,
            dst_port_max: 80,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        let sel = |dst: [u8; 4], proto: u8, dport: u16| PacketSelectors {
            src: [1, 2, 3, 4],
            dst,
            proto,
            sport: 12345,
            dport,
            icmp_type: 0,
            icmp_code: 0,
        };
        assert!(fw_rule_matches(&r, &sel([10, 0, 0, 5], 6, 80)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 5], 6, 81)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 5], 17, 80)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 6], 6, 80)));
    }

    #[test]
    fn fw_match_icmp_and_any() {
        let r = FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 8,
            icmp_code: 0xffff,
            proto: 1,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        let icmp = |icmp_type: u16| PacketSelectors {
            src: [1, 1, 1, 1],
            dst: [2, 2, 2, 2],
            proto: 1,
            sport: 0,
            dport: 0,
            icmp_type,
            icmp_code: 0,
        };
        assert!(fw_rule_matches(&r, &icmp(8)));
        assert!(!fw_rule_matches(&r, &icmp(0)));
        let mut d = r;
        d.enabled = 0;
        assert!(!fw_rule_matches(&d, &icmp(8)));
    }
}
