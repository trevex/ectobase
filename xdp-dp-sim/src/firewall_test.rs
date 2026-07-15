use crate::{MemMaps, VecPkt};
use etherparse::PacketBuilder;
use xdp_dp_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
use xdp_dp_core::firewall::fw_eval_dir;
use xdp_dp_core::pkt::Pkt;

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
/// direction, the verdict is DROP (the caller gates the actual drop on `fw_enforcing()`).
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
