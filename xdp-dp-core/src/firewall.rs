//! Directional firewall evaluator, generic over `Pkt` + `Maps`. **Deny-by-default:** the verdict is
//! ACCEPT only when a rule in this direction explicitly matches with an accept action; every other
//! outcome — no per-interface meta, zero rules in this direction, an unreadable header, or no
//! matching rule — is DROP. The actual drop is gated by `fw_enforcing()` at the call site, so a
//! node with the firewall disabled (evaluate-only) still forwards. The control plane is responsible
//! for materializing k8s "default-allow" as an explicit allow-all rule per unpolicied direction.

use crate::maps::Maps;
use crate::parse::{fw_rule_matches, icmp_type_code, l4_ports, PacketSelectors};
use crate::pkt::Pkt;
use xdp_dp_common::{FwRuleKey, FW_ACTION_DROP, FW_DIR_EGRESS, FW_MAX_RULES};

/// Evaluate the firewall for the IPv4 packet at `ip_off` against interface `ifindex` in `dir`
/// (FW_DIR_*). Deny-by-default: returns FW_ACTION_ACCEPT only on an explicit matching accept rule,
/// FW_ACTION_DROP otherwise.
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
