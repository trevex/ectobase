//! Conformance tests for the guest-egress rate meter (per-interface token bucket).
//!
//! These drive the REAL `flowplane_core::meter::meter_pass` through the full `SimNode::guest_tx`
//! compose (the SAME code the eBPF `egress::forward_decision_v4` calls) over in-memory
//! `MemMaps`/`VecPkt`. Metering does not mutate packet bytes — it reads/refills/writes the
//! `METER[src_ifindex]` bucket and returns a pass/drop verdict — so these assert on the delivery
//! `Action` (Redirect on pass, Drop on exhaustion) and prove refill after the clock advances.
//!
//! No METER entry => unlimited (pass), which is why the byte-parity fixtures (which install no
//! METER) are unaffected. Here we install a low-burst entry and drive several packets at a fixed
//! `now` so the bucket exhausts, then advance `SimNode::now` to prove refill.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, MeterState, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::pkt::Action;

use crate::SimNode;

const VNI: u32 = 300;
/// Sending guest port ifindex — the eBPF meter keys `METER[ingress_ifindex]`; the sim keys it on
/// `SimNode::src_ifindex`.
const SRC_IFINDEX: u32 = 21;
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
/// Internal peer (delivered locally to its tap → Redirect, no encap, no NAT).
const PEER_IP: [u8; 4] = [10, 0, 0, 20];
const PEER_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
const PEER_TAP: u32 = 88;

const SEC: u64 = 1_000_000_000;

/// A full guest Ethernet frame `[Eth(14)][IPv4][TCP]` from `GUEST_IP` → `PEER_IP`.
fn guest_frame(sport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(GUEST_IP, PEER_IP, 64)
        .tcp(sport, 80, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
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

/// Install a wildcard ALLOW rule for `dir` on `ifindex`.
fn allow(node: &mut SimNode, ifindex: u32, dir: u8) {
    let meta = node.maps.fw_meta.entry(ifindex).or_insert(FwMeta {
        ingress_count: 0,
        egress_count: 0,
    });
    let idx = if dir == FW_DIR_EGRESS {
        meta.egress_count += 1;
        meta.egress_count - 1
    } else {
        meta.ingress_count += 1;
        meta.ingress_count - 1
    };
    node.maps.fw_rules.insert(
        (ifindex, idx),
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

/// A node wired so `guest_tx` delivers GUEST_IP→PEER_IP locally to PEER_TAP (internal route,
/// nexthop resolves to a local tap → Redirect, no encap/NAT). Egress+ingress firewalls open.
fn deliver_node() -> SimNode {
    let mut node = SimNode::new();
    node.src_ifindex = SRC_IFINDEX;
    // Internal route: nexthop underlay resolves to a LOCAL tap → deliver locally (Redirect).
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
            is_external: 0,
            _pad: [0; 3],
        },
    );
    allow(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);
    allow(&mut node, PEER_TAP, FW_DIR_INGRESS);
    node
}

/// Program a `total`-bucket METER entry (public bucket disabled) for SRC_IFINDEX.
fn set_meter(node: &mut SimNode, total_bps: u64, total_burst: u64) {
    node.maps.meter.insert(
        SRC_IFINDEX,
        MeterState {
            total_bps,
            total_burst,
            total_tokens: total_burst, // start full
            total_last_ns: 0,
            public_bps: 0,
            public_burst: 0,
            public_tokens: 0,
            public_last_ns: 0,
            ingress_bps: 0,
            ingress_burst: 0,
            ingress_tokens: 0,
            ingress_last_ns: 0,
        },
    );
}

/// With NO meter entry the egress path is unlimited: every packet passes (Redirect to the peer tap),
/// confirming the meter seam is behavior-neutral when unconfigured (byte-parity fixtures unaffected).
#[test]
fn no_meter_entry_always_passes() {
    let mut node = deliver_node();
    for i in 0..10 {
        let out = node.guest_tx(&guest_frame(40000 + i), &port_meta());
        assert_eq!(
            out.action,
            Action::Redirect(PEER_TAP),
            "packet {i} must pass (no METER entry = unlimited)"
        );
    }
}

/// Token-bucket pass → exhaust → drop → refill, all at controlled timestamps through the real
/// `meter_pass` inside `guest_tx`.
///
/// Fixture: frame length is a fixed ~54 bytes; burst = 120 tokens (≈2 frames), bps = 60 B/s so a
/// refill of one frame takes ~1 s. Start full (tokens = burst = 120) at now = 0:
///   - packet 1 spends ~54 → ~66 left → PASS
///   - packet 2 spends ~54 → ~12 left → PASS
///   - packet 3 needs ~54 but only ~12 remain, no time elapsed (now still 0) → DROP
///   - advance now by 2 s → refill 2·60 = 120 (clamped to burst 120) → packet 4 PASSES again.
#[test]
fn meter_pass_exhaust_drop_then_refill() {
    let mut node = deliver_node();

    // Measure the exact egress frame length so the bucket math is deterministic.
    let frame_len = guest_frame(1).len() as u64;
    // burst holds 2 frames + a sliver; bps refills ~1 frame/sec.
    let burst = frame_len * 2 + 10;
    let bps = frame_len; // ≈1 frame worth of tokens per second
    set_meter(&mut node, bps, burst);

    node.now = 0;
    let out1 = node.guest_tx(&guest_frame(1), &port_meta());
    assert_eq!(
        out1.action,
        Action::Redirect(PEER_TAP),
        "packet 1 must PASS (bucket full)"
    );
    let out2 = node.guest_tx(&guest_frame(2), &port_meta());
    assert_eq!(
        out2.action,
        Action::Redirect(PEER_TAP),
        "packet 2 must PASS (bucket still has ~1 frame)"
    );
    // Bucket now holds < 1 frame and no time has elapsed → the third frame is dropped.
    let out3 = node.guest_tx(&guest_frame(3), &port_meta());
    assert_eq!(
        out3.action,
        Action::Drop,
        "packet 3 must DROP (bucket exhausted, no refill)"
    );

    // Advance the clock so the bucket refills (≥1 frame worth), then a later frame passes again.
    node.now = 2 * SEC;
    let out4 = node.guest_tx(&guest_frame(4), &port_meta());
    assert_eq!(
        out4.action,
        Action::Redirect(PEER_TAP),
        "packet 4 must PASS after the bucket refilled (now advanced 2 s)"
    );

    // The METER entry was written back with the updated last_ns (proves meter_update ran).
    let m = node.maps.meter.get(&SRC_IFINDEX).copied().unwrap();
    assert_eq!(
        m.total_last_ns,
        2 * SEC,
        "meter state must be persisted with the last-seen timestamp"
    );
}
