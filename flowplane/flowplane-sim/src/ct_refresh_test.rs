//! Conformance tests for the conntrack HIT refresh in the SHARED datapath core (`ct_refresh`,
//! mirroring the eBPF `ct_touch`). These drive the REAL `flowplane_core::datapath::process_guest_tx`
//! compose (which now refreshes `last_seen` + TCP state on a CT hit) over in-memory `MemMaps` /
//! `VecPkt` — nothing is reimplemented.
//!
//! Regression: before this fix the shared orchestrator only CREATED conntrack entries on a miss
//! (with `now = 0`) and did NOTHING on a hit, so an established TCP flow kept
//! `tcp_state = 0` forever → `timeout_ns` always returned the 30 s idle timeout (never the 24 h
//! ESTABLISHED timeout) and `last_seen` was never bumped, so a GC keyed on `ct_is_expired` evicted
//! active NAT'd TCP flows after 30 s.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
    FW_DIR_INGRESS, TCP_ESTABLISHED,
};
use flowplane_core::conntrack::{
    ct_is_expired, ct_key, ct_refresh, timeout_ns, DEFAULT_TIMEOUT_NS, TCP_ESTABLISHED_TIMEOUT_NS,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps;

use crate::{MemMaps, SimNode, VecPkt};

const VNI: u32 = 300;
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const PEER_IP: [u8; 4] = [10, 0, 0, 20];
const SRC_IFINDEX: u32 = 10;
const PEER_TAP: u32 = 77;
const PEER_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

/// Build a guest Ethernet frame `[Eth(14)][IPv4][TCP]` from `GUEST_IP:sport` to `PEER_IP:dport`
/// with the given TCP control flags.
fn guest_tcp_frame(sport: u16, dport: u16, syn: bool, ack: bool) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(GUEST_IP, PEER_IP, 64)
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

fn allow_all(node: &mut SimNode, ifindex: u32, dir: u8) {
    let (ingress_count, egress_count) = if dir == FW_DIR_INGRESS {
        (1, 0)
    } else {
        (0, 1)
    };
    node.maps.fw_meta.insert(
        ifindex,
        FwMeta {
            ingress_count,
            egress_count,
        },
    );
    node.maps.fw_rules.insert(
        (ifindex, 0),
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
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: dir,
            enabled: 1,
        },
    );
}

/// Wire an internal (same-node) route so `process_guest_tx` reaches the CT create/refresh step and
/// delivers locally (Redirect to a peer tap — no SNAT, no encap, so the CT key is a stable guest
/// 5-tuple across both packets).
fn node_with_internal_route() -> SimNode {
    let mut node = SimNode::new();
    node.maps.underlay.insert(
        PEER_UNDERLAY,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: PEER_TAP,
            guest_mac: [0xcc; 6],
            _pad: [0; 2],
        },
    );
    node.maps.add_route4(
        VNI,
        PEER_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_UNDERLAY,
            is_external: 0, // internal → local deliver, no SNAT
            _pad: [0; 3],
        },
    );
    allow_all(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);
    allow_all(&mut node, PEER_TAP, FW_DIR_INGRESS);
    node.src_ifindex = SRC_IFINDEX;
    node
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        _pad: [0; 2],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// End-to-end via the SHARED `process_guest_tx`: a first SYN packet creates the CT entry; a second
/// ACK packet of the same flow, 40 s later, must (a) bump `last_seen` to the new `now` and (b)
/// advance `tcp_state` past the initial state to ESTABLISHED — so `timeout_ns` returns the 24 h
/// timeout and the entry is NOT expired at now+40 s. Regression guard for the eviction bug.
#[test]
fn guest_tx_refreshes_last_seen_and_tcp_state_on_hit() {
    let sport = 40000u16;
    let dport = 80u16;
    let mut node = node_with_internal_route();
    let meta = port_meta();

    // Packet 1 @ t=0: SYN. Creates the CT entry (tcp_state = NEW_SYN, last_seen = 0).
    node.now = 0;
    let f1 = guest_tcp_frame(sport, dport, /*syn*/ true, /*ack*/ false);
    let _ = node.guest_tx(&f1, &meta);

    // Derive the (stable, no-SNAT) forward key from the same flow to inspect the map.
    let key = ct_key(&VecPkt::from_bytes(&f1), ETH_LEN, VNI).expect("ct key");
    let created = node
        .maps
        .conntrack_get(&key)
        .expect("entry created on miss");
    assert_eq!(created.last_seen, 0, "created entry stamped with now=0");
    assert_ne!(
        created.tcp_state, TCP_ESTABLISHED,
        "SYN-only flow starts below ESTABLISHED"
    );
    assert_eq!(
        timeout_ns(&created),
        DEFAULT_TIMEOUT_NS,
        "pre-established flow uses the 30 s idle timeout"
    );

    // Packet 2 @ t=40 s: ACK. HIT → refresh: last_seen := now, tcp_state NEW_SYN → ESTABLISHED.
    let now2: u64 = 40 * 1_000_000_000;
    node.now = now2;
    let f2 = guest_tcp_frame(sport, dport, /*syn*/ false, /*ack*/ true);
    let _ = node.guest_tx(&f2, &meta);

    let refreshed = node.maps.conntrack_get(&key).expect("entry still present");
    // (a) last_seen bumped to the new now.
    assert_eq!(
        refreshed.last_seen, now2,
        "last_seen must be refreshed to the new now on a hit"
    );
    // (b) TCP state advanced to ESTABLISHED → 24 h timeout, NOT expired at now+40 s.
    assert_eq!(
        refreshed.tcp_state, TCP_ESTABLISHED,
        "TCP state must advance past the initial state on a hit"
    );
    assert_eq!(
        timeout_ns(&refreshed),
        TCP_ESTABLISHED_TIMEOUT_NS,
        "established flow must use the 24 h timeout"
    );
    assert!(
        !ct_is_expired(&refreshed, now2),
        "established flow must NOT be expired at now+40 s"
    );

    // Before the fix, last_seen stayed 0 and tcp_state below ESTABLISHED → 30 s timeout → the entry
    // would be expired at t=40 s (40 s > 30 s). Prove that would-be eviction is now avoided.
    assert!(
        now2 > DEFAULT_TIMEOUT_NS,
        "sanity: 40 s exceeds the 30 s default timeout"
    );
}

/// Pure `ct_refresh` unit test: on a matched entry, ACK flags advance NEW_SYN → ESTABLISHED and
/// last_seen is bumped, writing the entry back to the map. Map-only; the packet is not consulted for
/// bytes beyond the TCP flags.
#[test]
fn ct_refresh_bumps_last_seen_and_advances_tcp_state() {
    use flowplane_common::{CtEntry, CT_F_DEFAULT, TCP_NEW_SYN};

    let mut m = MemMaps::default();
    // ACK-only packet at ip_off = 0 (no Ethernet — PacketBuilder::ipv4 starts at the IP header).
    let ack = {
        let mut step = PacketBuilder::ipv4(GUEST_IP, PEER_IP, 64).tcp(40000, 80, 0, 1024);
        step = step.ack(1);
        let mut out = Vec::new();
        step.write(&mut out, &[]).unwrap();
        out
    };
    let pkt = VecPkt::from_bytes(&ack);
    let key = ct_key(&pkt, 0, VNI).expect("ct key");
    // Seed a NEW_SYN entry with last_seen = 0.
    m.conntrack_insert(
        key,
        CtEntry {
            last_seen: 0,
            tcp_state: TCP_NEW_SYN,
            flags: CT_F_DEFAULT,
            ..Default::default()
        },
    );

    let now: u64 = 40 * 1_000_000_000;
    let mut e = m.conntrack_get(&key).unwrap();
    ct_refresh(&pkt, &mut m, 0, &key, &mut e, now);

    let out = m.conntrack_get(&key).expect("entry present after refresh");
    assert_eq!(out.last_seen, now, "last_seen bumped");
    assert_eq!(
        out.tcp_state, TCP_ESTABLISHED,
        "NEW_SYN + ACK → ESTABLISHED"
    );
    assert_eq!(timeout_ns(&out), TCP_ESTABLISHED_TIMEOUT_NS);
    assert!(!ct_is_expired(&out, now));
}
