// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

//! Serde mirror of the CompiledNIC JSON produced by the Go compiler, plus `apply()` which lowers
//! a CompiledNIC's firewall into the sim's native MemMaps. This is the pillar1→pillar2 bridge.

use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
use serde::Deserialize;

use crate::MemMaps;

/// Serde mirror of the Go CompiledNIC JSON (top-level).
#[derive(Deserialize)]
pub struct CompiledNic {
    pub spec: Spec,
}

/// Serde mirror of CompiledNICSpec.
#[derive(Deserialize)]
pub struct Spec {
    pub vni: i32,
    #[serde(default, rename = "underlayRoute")]
    pub underlay_route: String,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub lb: Vec<Lb>,
}

/// Serde mirror of CompiledFirewall.
#[derive(Deserialize, Default)]
pub struct Firewall {
    #[serde(default)]
    pub ingress: Vec<Rule>,
    #[serde(default)]
    pub egress: Vec<Rule>,
}

/// Serde mirror of CompiledFwRule.
#[derive(Deserialize)]
pub struct Rule {
    pub cidr: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub port: i32,
    pub action: String,
}

/// Serde mirror of CompiledLB.
#[derive(Deserialize, Default)]
pub struct Lb {
    pub vip: String,
    #[serde(default)]
    pub ports: Vec<LbPort>,
}

/// Serde mirror of CompiledLBPort.
#[derive(Deserialize, Default)]
pub struct LbPort {
    pub port: i32,
    #[serde(default)]
    pub proto: String,
}

/// Parse a CIDR string ("a.b.c.d/len") into (ip bytes, mask bytes).
/// "0.0.0.0/0" → ([0;4], [0;4]) meaning "match anything".
fn parse_cidr(cidr: &str) -> ([u8; 4], [u8; 4]) {
    let (addr_str, len_str) = match cidr.split_once('/') {
        Some(pair) => pair,
        None => return ([0; 4], [255, 255, 255, 255]),
    };
    let prefix_len: u32 = len_str.trim().parse().unwrap_or(0);
    let mask_u32: u32 = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let mask = mask_u32.to_be_bytes();

    let octets: Vec<u8> = addr_str
        .trim()
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    let ip: [u8; 4] = if octets.len() == 4 {
        [octets[0], octets[1], octets[2], octets[3]]
    } else {
        [0; 4]
    };

    (ip, mask)
}

/// Convert a protocol name string to its IP protocol number.
/// "" or unrecognized → 0 (any).
fn proto_to_u8(proto: &str) -> u8 {
    match proto.to_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        _ => 0,
    }
}

/// Convert a single compiled firewall rule to the native FwRule. Mirrors the agent's `compiledToFw`:
/// k8s semantics — an INGRESS rule's peer CIDR is the SOURCE (dst any), an EGRESS rule's is the
/// DESTINATION (src any); the port is always the destination port.
pub fn rule_to_fw(r: &Rule, direction: u8) -> FwRule {
    let (peer_ip, peer_mask) = parse_cidr(&r.cidr);
    let proto = proto_to_u8(&r.proto);
    let action = if r.action == "Allow" {
        FW_ACTION_ACCEPT
    } else {
        FW_ACTION_DROP
    };

    let (dst_port_min, dst_port_max) = if r.port == 0 {
        (0u16, 65535u16)
    } else {
        (r.port as u16, r.port as u16)
    };

    let (src_ip, src_mask, dst_ip, dst_mask) = if direction == FW_DIR_INGRESS {
        (peer_ip, peer_mask, [0; 4], [0; 4])
    } else {
        ([0; 4], [0; 4], peer_ip, peer_mask)
    };

    FwRule {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min,
        dst_port_max,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto,
        action,
        direction,
        enabled: 1,
    }
}

/// Lower a CompiledNIC's firewall into `tap`'s native maps — the sim analog of the agent's gRPC
/// lowering. Sets fw_meta ingress_count + one FwRule per ingress rule (dst CIDR/proto/port/action).
pub fn apply(m: &mut MemMaps, c: &CompiledNic, tap: u32) {
    let ingress = &c.spec.firewall.ingress;
    let egress = &c.spec.firewall.egress;

    m.fw_meta.insert(
        tap,
        FwMeta {
            ingress_count: ingress.len() as u32,
            egress_count: egress.len() as u32,
        },
    );

    for (idx, r) in ingress.iter().enumerate() {
        m.fw_rules
            .insert((tap, idx as u32), rule_to_fw(r, FW_DIR_INGRESS));
    }

    // Egress rules follow after ingress in the index space (matching the agent convention).
    for (idx, r) in egress.iter().enumerate() {
        m.fw_rules.insert(
            (tap, (ingress.len() + idx) as u32),
            rule_to_fw(r, flowplane_common::FW_DIR_EGRESS),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall_test::tcp_v4;
    use crate::VecPkt;
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
    use flowplane_core::firewall::fw_eval_dir;
    use flowplane_core::pkt::Pkt;

    const FIXTURE: &str = include_str!("../testdata/compilednic.json");

    #[test]
    fn apply_and_eval_from_fixture() {
        let c: CompiledNic = serde_json::from_str(FIXTURE).expect("parse fixture");

        let tap = 42u32;
        let mut maps = MemMaps::default();
        apply(&mut maps, &c, tap);

        // Sanity: 1 ingress rule was installed.
        let meta = maps.fw_meta.get(&tap).expect("fw_meta for tap");
        assert_eq!(meta.ingress_count, 1, "should have 1 ingress rule");

        // Ingress rule = allow from SOURCE 10.0.0.0/24 on port 443. A packet FROM 10.0.0.5:*->:443
        // matches. (PacketBuilder::ipv4 emits starting at the IPv4 header, so ip_off = 0.)
        let pkt_accept = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));
        assert_eq!(pkt_accept.read_u8(9), Some(6), "proto should be TCP=6");
        assert_eq!(
            fw_eval_dir(&pkt_accept, &maps, 0, tap, FW_DIR_INGRESS),
            FW_ACTION_ACCEPT,
            "in-range source on port 443 should be accepted"
        );

        // Wrong source (not in 10.0.0.0/24) → no match → deny-by-default DROP.
        let pkt_bad_src = VecPkt::from_bytes(&tcp_v4([192, 168, 1, 1], [10, 0, 0, 10], 5000, 443));
        assert_eq!(
            fw_eval_dir(&pkt_bad_src, &maps, 0, tap, FW_DIR_INGRESS),
            FW_ACTION_DROP,
            "out-of-range source should be dropped"
        );

        // In-range source but wrong port (80) → no match → DROP.
        let pkt_drop = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 80));
        assert_eq!(
            fw_eval_dir(&pkt_drop, &maps, 0, tap, FW_DIR_INGRESS),
            FW_ACTION_DROP,
            "port 80 should be dropped"
        );
    }
}
