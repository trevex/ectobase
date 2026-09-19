//! The first-match reference evaluator the classifier is held to: the datapath's evaluator before the
//! classifier replaced it, now over a rule LIST instead of the old `FW_RULES` slots. A packet takes
//! the action of the first rule in its direction that matches it; no match is DROP. Test-only — it
//! exists to judge `fw_classify{,6}` (see `fw_classify_diff_test`).

use flowplane_common::{FwRule, FwRule6, FW_ACTION_DROP};
use flowplane_core::parse::{icmp_type_code, icmp_type_code_v6, l4_ports, l4_ports_v6};
use flowplane_core::pkt::Pkt;

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

/// Whether rule `r` matches the packet selectors `s`. Ports are matched for TCP/UDP only, type/code
/// for ICMP only; a disabled rule matches nothing.
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

/// IPv6 mirror of [`fw_rule_matches`]; ICMPv6 uses proto 58.
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

/// The first-match verdict for the IPv4 packet at `ip_off` in `dir` (FW_DIR_*) under `rules`.
pub fn first_match<P: Pkt>(pkt: &P, ip_off: usize, rules: &[FwRule], dir: u8) -> u8 {
    let (Some(src), Some(dst)) = (
        pkt.read_array::<4>(ip_off + 12),
        pkt.read_array::<4>(ip_off + 16),
    ) else {
        return FW_ACTION_DROP;
    };
    let (proto, sport, dport) =
        l4_ports(pkt, ip_off).unwrap_or((pkt.read_u8(ip_off + 9).unwrap_or(0), 0, 0));
    let (icmp_type, icmp_code) = icmp_type_code(pkt, ip_off);
    let sel = PacketSelectors {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type,
        icmp_code,
    };
    rules
        .iter()
        .find(|r| r.direction == dir && fw_rule_matches(r, &sel))
        .map_or(FW_ACTION_DROP, |r| r.action)
}

/// IPv6 sibling of [`first_match`] (src@+8, dst@+24, L4@+40).
pub fn first_match6<P: Pkt>(pkt: &P, ip_off: usize, rules: &[FwRule6], dir: u8) -> u8 {
    let (Some(src), Some(dst)) = (
        pkt.read_array::<16>(ip_off + 8),
        pkt.read_array::<16>(ip_off + 24),
    ) else {
        return FW_ACTION_DROP;
    };
    let (proto, sport, dport) =
        l4_ports_v6(pkt, ip_off).unwrap_or((pkt.read_u8(ip_off + 6).unwrap_or(0), 0, 0));
    let (icmp_type, icmp_code) = icmp_type_code_v6(pkt, ip_off);
    let sel = PacketSelectors6 {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type,
        icmp_code,
    };
    rules
        .iter()
        .find(|r| r.direction == dir && fw_rule6_matches(r, &sel))
        .map_or(FW_ACTION_DROP, |r| r.action)
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
