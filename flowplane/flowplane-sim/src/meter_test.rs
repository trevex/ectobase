//! Conformance tests for the guest-egress rate meter and the ingress-lane policer.
//!
//! The egress tests drive the REAL `flowplane_core::meter::{public_pass, edt_egress}` through the
//! full `SimNode::guest_tx` compose (the SAME code path the eBPF `egress::forward_decision_v4` +
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
//!
//! The ingress test drives `flowplane_core::meter::ingress_pass` through the full
//! `SimNode::host_uplink` compose (the SAME code path the eBPF `try_uplink_rx` calls after
//! `decap_and_rewrite`). Over-rate frames directed at the guest tap are dropped; under-rate
//! frames (and frames with no METER entry) pass.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, MeterState, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
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
/// The fixture routes packets via an EXTERNAL/ENCAP path (no local tap resolved → `deliver` returns
/// `Encap`) so the sim stamps EDT after `grow_head(IPV6_LEN)` + `write_outer_v6`, using the
/// POST-encap length — exactly when `tc_guest_tx` calls `edt_stamp` (after `adjust_room`). A local
/// route (Local delivery) does NOT stamp, matching the eBPF behaviour (same-node is unshaped).
///
/// Rate = 1 wire-frame/s. Three packets fired at now=0:
///   - packet 1: idle cursor (total_last_ns=0 ≤ now=0) → departs AT now (0); cursor = 0 + airtime.
///   - packet 2: cursor > now → departs AT cursor (back-to-back queueing); cursor advances again.
///   - packet 3: same; all three PASS — EDT never drops.
/// Advance now past the cursor → packet 4 departs at now (queue drained).
/// Optional: after a local delivery last_tstamp is None (local is unshaped).
#[test]
fn edt_total_lane_shapes_not_drops() {
    // Wire up an ENCAP route: ext_ip has no local UnderlayValue → deliver() returns Encap.
    let ext_ip: [u8; 4] = [8, 8, 8, 8];
    let ext_nexthop: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xed, 0x01];
    const UPLINK_IFINDEX: u32 = 5;

    let mut node = SimNode::new();
    node.src_ifindex = SRC_IFINDEX;
    node.maps.local = Some(flowplane_common::Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0xde; 6],
        gateway_mac: [0xbe; 6],
        underlay_ipv6: [0xfd; 16],
    });
    // External route (is_external=1, no local tap) → `deliver` returns Encap.
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
    allow(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);

    // Build an external frame from GUEST_IP → ext_ip.
    let ext_frame = |sport: u16| -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
            .ipv4(GUEST_IP, ext_ip, 64)
            .tcp(sport, 80, 0, 1024);
        let mut out = Vec::new();
        builder.write(&mut out, &[]).unwrap();
        out
    };

    // The wire length the meter sees is the POST-encap length: inner frame + 40-byte outer IPv6.
    let inner_len = ext_frame(1).len() as u64;
    let wire_len = inner_len + IPV6_LEN as u64;
    // Rate = 1 wire-frame/s → airtime = wire_len * 1e9 / wire_len = 1 s per packet.
    set_meter(&mut node, wire_len, 0); // total_bps = wire_len B/s; burst field unused by EDT

    node.now = 0;

    // Packet 1: idle cursor → departs at now=0, action Redirect(uplink).
    let out1 = node.guest_tx(&ext_frame(1), &port_meta());
    assert_eq!(
        out1.action,
        Action::Redirect(UPLINK_IFINDEX),
        "packet 1 must PASS — EDT never drops"
    );
    assert_eq!(
        node.last_tstamp,
        Some(0),
        "packet 1 departs at now=0 (idle cursor)"
    );

    // Packet 2: cursor is now at airtime; departs at the cursor (backlog).
    let out2 = node.guest_tx(&ext_frame(2), &port_meta());
    assert_eq!(
        out2.action,
        Action::Redirect(UPLINK_IFINDEX),
        "packet 2 must PASS — EDT never drops"
    );
    let ts2 = node.last_tstamp.expect("EDT stamp must be set");
    assert!(ts2 >= SEC, "packet 2 must be scheduled ≥1 s after packet 1");

    // Packet 3: still at now=0, cursor further advanced — passes and stamps again.
    let out3 = node.guest_tx(&ext_frame(3), &port_meta());
    assert_eq!(
        out3.action,
        Action::Redirect(UPLINK_IFINDEX),
        "packet 3 must PASS — EDT never drops (confirms no total-lane policing)"
    );
    let ts3 = node.last_tstamp.expect("EDT stamp must be set");
    assert!(
        ts3 > ts2,
        "packet 3 must depart after packet 2 (cursor advanced)"
    );

    // Advance now past the cursor → next packet departs at now (queue drained).
    node.now = ts3 + 2 * SEC;
    let out4 = node.guest_tx(&ext_frame(4), &port_meta());
    assert_eq!(
        out4.action,
        Action::Redirect(UPLINK_IFINDEX),
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

    // Confirm that LOCAL delivery does NOT stamp: route GUEST_IP→PEER_IP internally, then
    // verify last_tstamp is None after the local Redirect (same-node is unshaped).
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
    allow(&mut node, PEER_TAP, FW_DIR_INGRESS);
    node.last_tstamp = Some(99999); // poison — must be cleared by None on local delivery
    let local_out = node.guest_tx(&guest_frame(9999), &port_meta());
    assert_eq!(
        local_out.action,
        Action::Redirect(PEER_TAP),
        "local delivery must pass (internal route)"
    );
    assert_eq!(
        node.last_tstamp, None,
        "local delivery must NOT stamp EDT (same-node delivery is never shaped)"
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

// ---------------------------------------------------------------------------
// Ingress-lane policing tests (mirrors ingress.rs `try_uplink_rx` after decap)
// ---------------------------------------------------------------------------

/// Constants for the uplink ingress fixture.
const INGRESS_VNI: u32 = 400;
const INGRESS_TAP: u32 = 55;
const INGRESS_GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x01, 0x02, 0x03];
const INGRESS_GUEST_IP: [u8; 4] = [10, 1, 0, 10];
const INGRESS_EXT_IP: [u8; 4] = [203, 0, 113, 42];
const EDGE_UNDERLAY_INGRESS: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];

/// Build a TCP/IPv4 inner Ethernet frame from INGRESS_EXT_IP -> INGRESS_GUEST_IP.
fn ingress_inner_frame(sport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(INGRESS_EXT_IP, INGRESS_GUEST_IP, 64)
        .tcp(sport, 443, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Build an encapped fabric frame ready for `host_uplink` by running the real `edge_encap`.
fn ingress_encapped(sport: u16) -> Vec<u8> {
    let inner = ingress_inner_frame(sport);
    let edge = SimNode::new();
    let e = EncapParams {
        gateway_mac: [0x01; 6],
        uplink_mac: [0x02; 6],
        uplink_ifindex: 7,
        src_underlay: EDGE_UNDERLAY_INGRESS,
        nexthop_ipv6: [0u8; 16], // outer IPv6 dst; resolved by host_uplink via UnderlayValue
        inner_proto: 4,          // IPPROTO_IPIP
    };
    edge.edge_encap(&inner, e)
}

/// Open an ingress ALLOW rule on INGRESS_TAP (needed so the firewall pass gate doesn't drop).
fn allow_ingress_tap(node: &mut SimNode) {
    node.maps.fw_meta.insert(
        INGRESS_TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (INGRESS_TAP, 0),
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
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

/// Program a tight ingress-lane METER entry on INGRESS_TAP. `ingress_burst` tokens are pre-loaded so
/// the first packets within the burst pass, and subsequent packets (at `now=0`, no refill) drop.
fn set_ingress_meter(node: &mut SimNode, ingress_bps: u64, ingress_burst: u64) {
    node.maps.meter.insert(
        INGRESS_TAP,
        MeterState {
            total_bps: 0,
            total_burst: 0,
            total_tokens: 0,
            total_last_ns: 0,
            public_bps: 0,
            public_burst: 0,
            public_tokens: 0,
            public_last_ns: 0,
            ingress_bps,
            ingress_burst,
            ingress_tokens: ingress_burst, // start full
            ingress_last_ns: 0,
        },
    );
}

/// Ingress-lane policing: frames to the guest tap are dropped once the ingress bucket is exhausted.
///
/// Fixture: ingress_burst sized for ~2 inner frames. Three encapped packets arrive at now=0:
///   - packets 1 and 2: within burst → Redirect(INGRESS_TAP);
///   - packet 3: bucket exhausted, no time elapsed → Drop.
/// No METER entry configured on the SENDING side (egress), confirming the ingress lane is independent.
#[test]
fn ingress_lane_exhaust_drop() {
    // Compute burst from one inner frame length (outer Eth+IPv6 stripped by decap_and_rewrite).
    let inner_len = ingress_inner_frame(1).len() as u64;
    // Burst fits ~2 frames: first two pass, third drops.
    let ingress_burst = inner_len * 2 + 10;

    let mut node = SimNode::new();
    node.now = 0;
    allow_ingress_tap(&mut node);
    set_ingress_meter(&mut node, inner_len, ingress_burst); // bps=1 frame/s; burst=~2 frames

    // Build three different flows (distinct sports) so each hits the firewall as a new flow.
    let pkt1 = ingress_encapped(40001);
    let pkt2 = ingress_encapped(40002);
    let pkt3 = ingress_encapped(40003);

    // Verify: outer Eth+IPv6 header is present (sanity check on the fixture).
    assert!(
        pkt1.len() > ETH_LEN + IPV6_LEN,
        "encapped frame must contain outer Eth+IPv6"
    );

    let out1 = node.host_uplink(&pkt1, INGRESS_VNI, INGRESS_TAP, INGRESS_GUEST_MAC);
    assert_eq!(
        out1.action,
        Action::Redirect(INGRESS_TAP),
        "ingress packet 1 must PASS (bucket full)"
    );

    let out2 = node.host_uplink(&pkt2, INGRESS_VNI, INGRESS_TAP, INGRESS_GUEST_MAC);
    assert_eq!(
        out2.action,
        Action::Redirect(INGRESS_TAP),
        "ingress packet 2 must PASS (bucket ~1 frame remaining)"
    );

    // Bucket now < 1 frame, no time elapsed → ingress policing drops.
    let out3 = node.host_uplink(&pkt3, INGRESS_VNI, INGRESS_TAP, INGRESS_GUEST_MAC);
    assert_eq!(
        out3.action,
        Action::Drop,
        "ingress packet 3 must DROP (ingress bucket exhausted)"
    );

    // Meter state must have been persisted with updated tokens (proves ingress_pass ran its update).
    let m = node.maps.meter.get(&INGRESS_TAP).copied().unwrap();
    assert!(
        m.ingress_last_ns == 0,
        "ingress_last_ns stays 0 (all packets at now=0)"
    );
    // After 2 passes (each spending ~inner_len tokens), remaining tokens < inner_len.
    assert!(
        m.ingress_tokens < inner_len,
        "ingress tokens must be depleted below one frame after two passes"
    );
}
