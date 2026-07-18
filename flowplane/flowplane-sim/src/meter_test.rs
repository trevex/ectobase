//! Conformance tests for the guest-egress rate meter.
//!
//! These drive the REAL `flowplane_core::meter::{public_pass, edt_egress}` through the full
//! `SimNode::guest_tx` compose (the SAME code path the eBPF `egress::forward_decision_v4` +
//! `tc_guest_tx` call) over in-memory `MemMaps`/`VecPkt`. Metering does not mutate packet bytes —
//! it reads/writes the `METER[src_ifindex]` state and returns a pass/drop verdict (public lane) or
//! records a departure timestamp (EDT total lane) — so these assert on the delivery `Action`
//! (Redirect on pass, Drop on public-lane exhaustion) and on `SimNode::last_tstamp` for EDT pacing.
//!
//! No METER entry => unlimited (pass / no tstamp), which is why the byte-parity fixtures (which
//! install no METER) are unaffected. The eBPF path migrated the total lane from token-bucket
//! policing to EDT shaping: packets are NEVER dropped by the total lane; instead, `edt_egress`
//! records when the packet should depart (kernel FQ enforces pacing). Public-lane policing still
//! drops external packets when the public bucket is exhausted.

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
/// Under the new eBPF egress path, `total_bps` drives EDT shaping (no drop), not policing.
fn set_meter(node: &mut SimNode, total_bps: u64, total_burst: u64) {
    node.maps.meter.insert(
        SRC_IFINDEX,
        MeterState {
            total_bps,
            total_burst,
            total_tokens: total_burst, // start full (legacy field; edt_egress uses total_last_ns)
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

/// Program a `public`-bucket METER entry (total EDT rate also set; public bucket polices external
/// egress) for SRC_IFINDEX. `public_bps/burst` drive token-bucket DROP on external packets.
fn set_public_meter(node: &mut SimNode, total_bps: u64, public_bps: u64, public_burst: u64) {
    node.maps.meter.insert(
        SRC_IFINDEX,
        MeterState {
            total_bps,
            total_burst: 0,
            total_tokens: 0,
            total_last_ns: 0,
            public_bps,
            public_burst,
            public_tokens: public_burst, // start full
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

/// EDT total-lane shaping: packets are NEVER dropped by the total lane; instead `edt_egress`
/// advances the departure cursor and records a `last_tstamp`. Mirrors the eBPF `tc_guest_tx` path.
///
/// Fixture: total_bps = 1 frame/s. Three packets fired at now=0:
///   - packet 1: idle cursor (total_last_ns=0 ≤ now=0) → departs AT now (0); cursor = 0 + airtime.
///   - packet 2: cursor > now → departs AT cursor (back-to-back queueing); cursor advances again.
///   - packet 3: same; all three PASS — EDT never drops.
/// Advance now past the cursor → packet 4 departs at now (queue drained).
#[test]
fn edt_total_lane_shapes_not_drops() {
    let mut node = deliver_node();

    let frame_len = guest_frame(1).len() as u64;
    // Rate = 1 frame/s → airtime = frame_len * 1e9 / frame_len = 1 s per packet.
    set_meter(&mut node, frame_len, 0); // total_bps = frame_len B/s; burst field unused by EDT

    node.now = 0;

    // Packet 1: idle cursor → departs at now=0.
    let out1 = node.guest_tx(&guest_frame(1), &port_meta());
    assert_eq!(
        out1.action,
        Action::Redirect(PEER_TAP),
        "packet 1 must PASS — EDT never drops"
    );
    assert_eq!(
        node.last_tstamp,
        Some(0),
        "packet 1 departs at now=0 (idle cursor)"
    );

    // Packet 2: cursor is now at airtime; departs at the cursor (backlog).
    let out2 = node.guest_tx(&guest_frame(2), &port_meta());
    assert_eq!(
        out2.action,
        Action::Redirect(PEER_TAP),
        "packet 2 must PASS — EDT never drops"
    );
    let ts2 = node.last_tstamp.expect("EDT stamp must be set");
    assert!(ts2 >= SEC, "packet 2 must be scheduled ≥1 s after packet 1");

    // Packet 3: still at now=0, cursor further advanced — passes immediately.
    let out3 = node.guest_tx(&guest_frame(3), &port_meta());
    assert_eq!(
        out3.action,
        Action::Redirect(PEER_TAP),
        "packet 3 must PASS — EDT never drops (confirms no total-lane policing)"
    );
    let ts3 = node.last_tstamp.expect("EDT stamp must be set");
    assert!(
        ts3 > ts2,
        "packet 3 must depart after packet 2 (cursor advanced)"
    );

    // Advance now past the cursor → next packet departs at now (queue drained).
    node.now = ts3 + 2 * SEC;
    let out4 = node.guest_tx(&guest_frame(4), &port_meta());
    assert_eq!(
        out4.action,
        Action::Redirect(PEER_TAP),
        "packet 4 must PASS after clock advanced past the cursor"
    );
    assert_eq!(
        node.last_tstamp,
        Some(node.now),
        "packet 4 departs at now (idle cursor after advance)"
    );

    // The METER entry was written back with the updated cursor (proves meter_update ran).
    let m = node.maps.meter.get(&SRC_IFINDEX).copied().unwrap();
    assert!(
        m.total_last_ns > 0,
        "meter state must be persisted with the last-seen cursor"
    );
}

/// Public-lane policing: external packets are DROP'd when the public bucket is exhausted.
/// Internal packets bypass the public lane and always pass. Mirrors `egress.rs:public_pass`.
///
/// Fixture: public_bps/burst sized for ~2 frames. After 2 external passes the bucket is exhausted
/// and the next external packet drops. An internal packet with the same depleted state still passes.
#[test]
fn public_lane_exhaust_drop_then_pass_internal() {
    // We need an external route to trigger is_ext=true. Use a separate node with an ext route.
    let ext_ip: [u8; 4] = [8, 8, 8, 8];
    let ext_nexthop: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee, 0x01];

    let mut node = SimNode::new();
    node.src_ifindex = SRC_IFINDEX;

    // `deliver()` reads `maps.local()` for the Encap path (uplink_ifindex + MACs).
    // Set a non-zero uplink_ifindex so we get Redirect(UPLINK_IFINDEX), not Pass.
    const UPLINK_IFINDEX: u32 = 5;
    node.maps.local = Some(flowplane_common::Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0xde; 6],
        gateway_mac: [0xbe; 6],
        underlay_ipv6: [0xfd; 16],
    });

    // External route (is_external=1) → triggers public-lane policing.
    node.maps.add_route4(
        VNI,
        ext_ip,
        flowplane_common::RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: ext_nexthop,
            is_external: 1,
            _pad: [0; 3],
        },
    );
    // Internal peer route (is_external=0) → public lane is NOT checked.
    node.maps.underlay.insert(
        PEER_UNDERLAY,
        flowplane_common::UnderlayValue {
            vni: VNI,
            tap_ifindex: PEER_TAP,
            guest_mac: [0xcc; 6],
            _pad: [0; 2],
        },
    );
    node.maps.add_route4(
        VNI,
        PEER_IP,
        flowplane_common::RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_UNDERLAY,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    allow(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);
    allow(&mut node, PEER_TAP, FW_DIR_INGRESS);

    let frame_len = guest_frame(1).len() as u64;
    // Public bucket holds ~2 frames; no total shaping configured (total_bps=0 → edt_egress no-op).
    let public_burst = frame_len * 2 + 10;
    set_public_meter(&mut node, 0, frame_len, public_burst);

    node.now = 0;

    // Build an external frame (GUEST_IP → ext_ip).
    let ext_frame = |sport: u16| -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
            .ipv4(GUEST_IP, ext_ip, 64)
            .tcp(sport, 80, 0, 1024);
        let mut out = Vec::new();
        builder.write(&mut out, &[]).unwrap();
        out
    };

    let out1 = node.guest_tx(&ext_frame(1001), &port_meta());
    assert_eq!(
        out1.action,
        Action::Redirect(UPLINK_IFINDEX),
        "ext packet 1 must PASS (bucket full)"
    );
    let out2 = node.guest_tx(&ext_frame(1002), &port_meta());
    assert_eq!(
        out2.action,
        Action::Redirect(UPLINK_IFINDEX),
        "ext packet 2 must PASS (bucket ~1 frame remaining)"
    );
    // Bucket now < 1 frame, no time elapsed → external packet drops.
    let out3 = node.guest_tx(&ext_frame(1003), &port_meta());
    assert_eq!(
        out3.action,
        Action::Drop,
        "ext packet 3 must DROP (public bucket exhausted)"
    );

    // Internal packet (to PEER_IP) with the same depleted public state → PASS (public not checked).
    let out4 = node.guest_tx(&guest_frame(2001), &port_meta());
    assert_eq!(
        out4.action,
        Action::Redirect(PEER_TAP),
        "internal packet must PASS even when the public bucket is exhausted"
    );
}
