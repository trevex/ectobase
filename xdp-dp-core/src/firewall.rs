//! Directional firewall evaluator, generic over `Pkt` + `Maps`. Faithful port of the eBPF
//! `firewall::fw_eval_dir`. Whitelist semantics: zero rules in this direction => ACCEPT; else the
//! first matching rule's action; no match => DROP.

use crate::maps::Maps;
use crate::parse::{fw_rule_matches, icmp_type_code, l4_ports, PacketSelectors};
use crate::pkt::Pkt;
use xdp_dp_common::{FwRuleKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_MAX_RULES};

/// Evaluate the firewall for the IPv4 packet at `ip_off` against interface `ifindex` in `dir`
/// (FW_DIR_*). Returns FW_ACTION_ACCEPT / FW_ACTION_DROP.
#[inline(always)]
pub fn fw_eval_dir<P: Pkt, M: Maps>(pkt: &P, maps: &M, ip_off: usize, ifindex: u32, dir: u8) -> u8 {
    let meta = match maps.fw_meta(ifindex) {
        Some(m) => m,
        None => return FW_ACTION_ACCEPT,
    };
    let count = if dir == FW_DIR_EGRESS {
        meta.egress_count
    } else {
        meta.ingress_count
    };
    if count == 0 {
        return FW_ACTION_ACCEPT;
    }
    let src = match pkt.read_array::<4>(ip_off + 12) {
        Some(v) => v,
        None => return FW_ACTION_ACCEPT,
    };
    let dst = match pkt.read_array::<4>(ip_off + 16) {
        Some(v) => v,
        None => return FW_ACTION_ACCEPT,
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
