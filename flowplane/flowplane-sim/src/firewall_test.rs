use crate::{MemMaps, VecPkt};
use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, FwRule6, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::firewall::{fw_eval_dir, fw_eval_dir6};
use flowplane_core::pkt::Pkt;

pub(crate) fn tcp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn ingress_allow_rule_matches() {
    let ifindex = 42u32;
    let mut m = MemMaps::default();
    m.fw_meta.insert(
        ifindex,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    m.fw_rules.insert(
        (ifindex, 0),
        FwRule {
            src_ip: [10, 0, 0, 0],
            src_mask: [255, 255, 255, 0],
            dst_ip: [0, 0, 0, 0],
            dst_mask: [0, 0, 0, 0],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 443,
            dst_port_max: 443,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
    // ip_off = 0: PacketBuilder::ipv4 emits starting at the IPv4 header (no Ethernet).
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));
    assert_eq!(pkt.read_u8(9), Some(6)); // sanity: proto at ip_off+9
    assert_eq!(
        fw_eval_dir(&pkt, &m, 0, ifindex, FW_DIR_INGRESS),
        FW_ACTION_ACCEPT
    );
    let pkt2 = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 80));
    assert_eq!(
        fw_eval_dir(&pkt2, &m, 0, ifindex, FW_DIR_INGRESS),
        FW_ACTION_DROP
    );
}

/// Deny-by-default: with no per-interface firewall meta at all, or meta with zero rules in the
/// direction, the verdict is DROP (unconditional — the drop is no longer gated).
#[test]
fn deny_by_default_when_no_rules() {
    let ifindex = 7u32;
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));

    // No fw_meta for the interface at all → DROP.
    let empty = MemMaps::default();
    assert_eq!(
        fw_eval_dir(&pkt, &empty, 0, ifindex, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "no firewall meta => deny-by-default"
    );

    // Meta present but zero ingress rules → DROP.
    let mut m = MemMaps::default();
    m.fw_meta.insert(
        ifindex,
        FwMeta {
            ingress_count: 0,
            egress_count: 0,
        },
    );
    assert_eq!(
        fw_eval_dir(&pkt, &m, 0, ifindex, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "zero rules in direction => deny-by-default"
    );
}

/// Build a bare IPv6 + TCP packet at ip_off=0 (no Ethernet): next-header (6) at byte 6, src at
/// 8..24, dst at 24..40, TCP src/dst ports at 40..44. Mirrors the byte layout the v6 datapath reads.
fn tcp_v6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 44];
    p[0] = 0x60; // version 6
    p[4] = 0; // payload length hi
    p[5] = 4; // payload length lo (4 bytes of "TCP" ports written below)
    p[6] = 6; // next header = TCP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p[40..42].copy_from_slice(&sport.to_be_bytes());
    p[42..44].copy_from_slice(&dport.to_be_bytes());
    p
}

const V6_SRC: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
];
const V6_DST: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
];

/// An ingress accept rule matching V6_DST on dport 443 (any src).
fn v6_accept_rule(direction: u8) -> FwRule6 {
    FwRule6 {
        src_ip: [0; 16],
        src_mask: [0; 16],
        dst_ip: V6_DST,
        dst_mask: [0xff; 16],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 443,
        dst_port_max: 443,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction,
        enabled: 1,
    }
}

#[test]
fn v6_deny_by_default_no_meta() {
    let m = MemMaps::default();
    let pkt = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 443));
    assert_eq!(pkt.read_u8(6), Some(6)); // sanity: next-header at ip_off+6
    assert_eq!(
        fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "no v6 firewall meta => deny-by-default"
    );
}

#[test]
fn v6_zero_rules_in_direction_denies() {
    let mut m = MemMaps::default();
    m.fw_meta6.insert(
        7,
        FwMeta {
            ingress_count: 0,
            egress_count: 0,
        },
    );
    let pkt = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 443));
    assert_eq!(
        fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "zero rules in direction => deny-by-default"
    );
}

#[test]
fn v6_explicit_allow_matches() {
    let mut m = MemMaps::default();
    m.fw_meta6.insert(
        7,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    m.fw_rules6.insert((7, 0), v6_accept_rule(FW_DIR_INGRESS));
    let pkt = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 443));
    assert_eq!(
        fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_ACCEPT
    );
    // A non-matching dport is denied.
    let pkt2 = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 80));
    assert_eq!(
        fw_eval_dir6(&pkt2, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_DROP
    );
}

#[test]
fn v6_direction_isolation() {
    let mut m = MemMaps::default();
    m.fw_meta6.insert(
        7,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    // An EGRESS accept rule must NOT accept an INGRESS eval.
    m.fw_rules6.insert((7, 0), v6_accept_rule(FW_DIR_EGRESS));
    let pkt = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 443));
    assert_eq!(
        fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "egress rule does not match an ingress eval"
    );
}

#[test]
fn v6_prefix_mask_miss_denies() {
    let mut m = MemMaps::default();
    m.fw_meta6.insert(
        7,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    // Full /128 dst_mask but dst_ip != packet dst => no match => DROP.
    let mut rule = v6_accept_rule(FW_DIR_INGRESS);
    rule.dst_ip = V6_SRC; // wrong dst
    m.fw_rules6.insert((7, 0), rule);
    let pkt = VecPkt::from_bytes(&tcp_v6(V6_SRC, V6_DST, 5000, 443));
    assert_eq!(
        fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS),
        FW_ACTION_DROP,
        "masked dst mismatch => deny"
    );
}
