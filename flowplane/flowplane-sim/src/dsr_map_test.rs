//! B7/B7b/B7c: at the backend node, the DSR Geneve option (read off the tunnel metadata the same
//! `get_tunnel_key` call recovers `vni` from) notes the REVERSE DSR VIP so the guest's reply is later
//! reverse-SNAT'd src -> VIP (`ct_apply`/its v6 sibling, applied on egress in B8). The only
//! per-connection DSR state lives here on the backend.
//!
//! B7b moved this state OUT of `CONNTRACK`/`CtEntry` (which briefly grew an `xlate_ip6` field, B5)
//! into dedicated compact `DSR`/`DSR6` LRU maps (see `flowplane_common::DsrVip`) — the `CtEntry` copy
//! on the stack in the pre-existing hot conntrack frames (`ct_apply`/`ct_create_default`) had pushed
//! `uplink_rx`'s combined BPF stack over the verifier's 512-byte limit. This file was `dsr_ct_test.rs`
//! before B7b; renamed to reflect the new map-based storage.
//!
//! B7c moved the note itself OFF `uplink_rx`'s call graph entirely, into a SEPARATE tcx pre-program
//! (`uplink_dsr_note`, attached to run before `uplink_rx` on the same geneve ingress hook — see
//! `flowplane-ebpf/src/ingress.rs::try_uplink_dsr_note`'s doc comment): even out-of-lined, the note's
//! `ct_key` build still pushed `uplink_rx`'s combined stack over budget once inlined, and out-of-lining
//! it as a pkt-taking subprogram hit "R2 pointer arithmetic on pkt_end prohibited". `UplinkIn` no
//! longer carries a `dsr` field at all; `SimNode::uplink_dsr`/`uplink_v6_dsr` model the two-program
//! sequence by calling `dsr_note`/`dsr_note6` directly (modeling `uplink_dsr_note`) BEFORE
//! `process_uplink`/`process_uplink_v6` (modeling `uplink_rx`) — see their doc comments.
//!
//! # Coverage
//!
//! 1. `flowplane_core::conntrack::dsr_note`/`dsr_note6` directly (unit level): the reverse VIP is
//!    stored in the `DSR`/`DSR6` map at `invert_key(ct_key(forwarded))` /
//!    `invert_key6(ct_key6(forwarded))`, with `DsrVip::vip == vip` (left-justified for v4);
//!    idempotent (a second call with a different VIP never overwrites the first).
//! 2. End-to-end through `SimNode::uplink_v6_dsr`/`uplink_dsr`: a DSR-forwarded frame hitting a LOCAL
//!    LB-backend delivery notes the reverse DSR VIP in the map — the SAME core path
//!    `process_uplink`/`process_uplink_v6` runs in production, driven (post-B7c) by the SEPARATE
//!    `uplink_dsr_note` tcx program's `get_tunnel_opt` + `dsr::decode` (see `ingress.rs`/`v6.rs`).
//! 3. Regression: a non-DSR (`dsr: None`) LB delivery notes NOTHING (no `DSR`/`DSR6` entry, and no
//!    `CONNTRACK`/`CONNTRACK6` entry either) — matches the pre-existing "LB is DSR, no ct" contract
//!    (`ns_scenario_v6_test.rs`, `v6_lb_local_backend_delivered_no_conntrack6_created`); `dsr`
//!    defaulting to `None` must not change behavior for every pre-existing (non-DSR) uplink caller.

use etherparse::PacketBuilder;
use flowplane_common::{
    DsrOpt, DsrVip, FwMeta, FwRule, FwRule6, IfaceValue, LbBackend, LbKey, LbValue, MaglevKey,
    PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::conntrack::{ct_key, ct_key6, dsr_note, dsr_note6, invert_key, invert_key6};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};

use crate::maps::{Route4, Route6};
use crate::{MemMaps, SimNode, VecPkt};

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const HOSTB_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

fn local_for(underlay: [u8; 16], ifindex: u32) -> flowplane_common::Local {
    flowplane_common::Local {
        uplink_ifindex: ifindex,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: underlay,
    }
}

/// Left-justify a v4 address into the 16-byte `DsrVip::vip` layout (mirrors `DsrOpt::vip`/
/// `LbBackend::overlay_ip`).
fn vip16(v4: [u8; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&v4);
    b
}

// ─── direct dsr_note6 / dsr_note unit coverage ─────────────────────────────────────────────────────

const CLIENT_IP6: [u8; 16] = [0xfd, 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const BACKEND_OVERLAY_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81];
const VIP_IP6: [u8; 16] = [
    0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x01,
];
const OTHER_VIP_IP6: [u8; 16] = [
    0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x02,
];

const CLIENT_IP: [u8; 4] = [203, 0, 113, 9];
const BACKEND_OVERLAY_IP: [u8; 4] = [10, 0, 0, 181];
const VIP_IP: [u8; 4] = [10, 0, 100, 1];
const OTHER_VIP_IP: [u8; 4] = [10, 0, 100, 2];

/// Build a bare `[IPv6(40)][TCP(20)][payload]` frame at `ip_off = 0`, matching `ct_apply_test.rs`'s
/// `bare_ipv6_tcp` pattern — a DSR-forwarded frame at the backend: `src = client, dst = backend
/// overlay`.
fn bare_ipv6_tcp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv6(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Build a bare `[IPv4(20)][TCP(20)][payload]` frame at `ip_off = 0`.
fn bare_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

#[test]
fn dsr_note6_inserts_reverse_entry_keyed_on_guest_reply_tuple() {
    // The forwarded frame at the backend: src=client, dst=backend overlay.
    let raw = bare_ipv6_tcp(CLIENT_IP6, BACKEND_OVERLAY_IP6, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_note6(&pkt, &mut maps, 0, VNI, &VIP_IP6, 12345);

    let fwd = ct_key6(&pkt, 0, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = maps
        .dsr6_get(&rev)
        .expect("reverse DSR6 map entry must exist, keyed on invert_key6(forwarded)");
    assert_eq!(e.vip, VIP_IP6, "reverse entry notes reply src -> VIP");
    assert_eq!(e.last_seen, 12345);

    // No FORWARD entry is created by this fn — only the reverse.
    assert!(
        maps.dsr6_get(&fwd).is_none(),
        "dsr_note6 must not create a forward entry"
    );
    // DSR state lives in DSR6, never CONNTRACK6.
    assert_eq!(
        maps.conntrack6.len(),
        0,
        "dsr_note6 must not touch CONNTRACK6"
    );
}

#[test]
fn dsr_note6_is_idempotent_never_overwrites() {
    let raw = bare_ipv6_tcp(CLIENT_IP6, BACKEND_OVERLAY_IP6, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_note6(&pkt, &mut maps, 0, VNI, &VIP_IP6, 1);
    dsr_note6(&pkt, &mut maps, 0, VNI, &OTHER_VIP_IP6, 2);

    let fwd = ct_key6(&pkt, 0, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = maps.dsr6_get(&rev).unwrap();
    assert_eq!(e.vip, VIP_IP6, "first writer wins; never overwritten");
    assert_eq!(
        e.last_seen, 1,
        "last_seen from the first call, not the second"
    );
}

#[test]
fn dsr_note_inserts_reverse_entry_v4() {
    let raw = bare_ipv4_tcp(CLIENT_IP, BACKEND_OVERLAY_IP, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_note(&pkt, &mut maps, 0, VNI, &VIP_IP, 6789);

    let fwd = ct_key(&pkt, 0, VNI).unwrap();
    let rev = invert_key(&fwd);
    let e = maps
        .dsr_get(&rev)
        .expect("reverse DSR map entry must exist, keyed on invert_key(forwarded)");
    assert_eq!(
        e.vip,
        vip16(VIP_IP),
        "reverse entry notes reply src -> VIP (v4 left-justified in 16 bytes)"
    );
    assert_eq!(e.last_seen, 6789);
    assert!(
        maps.dsr_get(&fwd).is_none(),
        "dsr_note must not create a forward entry"
    );
    assert_eq!(maps.conntrack.len(), 0, "dsr_note must not touch CONNTRACK");
}

#[test]
fn dsr_note_is_idempotent_never_overwrites_v4() {
    let raw = bare_ipv4_tcp(CLIENT_IP, BACKEND_OVERLAY_IP, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_note(&pkt, &mut maps, 0, VNI, &VIP_IP, 1);
    dsr_note(&pkt, &mut maps, 0, VNI, &OTHER_VIP_IP, 2);

    let fwd = ct_key(&pkt, 0, VNI).unwrap();
    let rev = invert_key(&fwd);
    let e = maps.dsr_get(&rev).unwrap();
    assert_eq!(e.vip, vip16(VIP_IP), "first writer wins; never overwritten");
    assert_eq!(
        e.last_seen, 1,
        "last_seen from the first call, not the second"
    );
}

// ─── end-to-end: SimNode::uplink_v6_dsr / uplink_dsr through the LB local-delivery arm ─────────────

const OVERLAY_VIP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x01,
];
const GUEST_A6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];

const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1];
const GUEST_A: [u8; 4] = [10, 0, 0, 20];

/// A full guest Ethernet frame `[Eth(0x86DD)][IPv6][TCP]` src -> dst on `dport`.
fn eth_ipv6_tcp(src: [u8; 16], dst: [u8; 16], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` src -> dst on `dport`.
fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Install a v6 LB service `(VNI, OVERLAY_VIP6, 443, TCP)` -> Maglev table pointing at a LOCAL
/// backend (`node_vtep == backend_underlay`).
fn install_lb6(node: &mut SimNode, backend_underlay: [u8; 16]) {
    let last4 = [
        OVERLAY_VIP6[12],
        OVERLAY_VIP6[13],
        OVERLAY_VIP6[14],
        OVERLAY_VIP6[15],
    ];
    node.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: last4,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 21,
            size: 1,
        },
    );
    node.maps.maglev.insert(
        MaglevKey {
            table_id: 21,
            slot: 0,
        },
        LbBackend {
            node_vtep: backend_underlay,
            overlay_ip: BACKEND_OVERLAY_IP6,
            vni: VNI,
            is_v6: 1,
            _pad: [0; 3],
        },
    );
}

/// v4 mirror of `install_lb6`.
fn install_lb(node: &mut SimNode, backend_underlay: [u8; 16]) {
    node.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 22,
            size: 1,
        },
    );
    let mut overlay16 = [0u8; 16];
    overlay16[..4].copy_from_slice(&BACKEND_OVERLAY_IP);
    node.maps.maglev.insert(
        MaglevKey {
            table_id: 22,
            slot: 0,
        },
        LbBackend {
            node_vtep: backend_underlay,
            overlay_ip: overlay16,
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
}

/// Install a wildcard-dst ingress ALLOW rule on `tap` for TCP:`port` (v6) — the LB/DSR delivery
/// keeps the inner dst as the VIP, never either backend's own overlay IP, so the rule must not pin
/// `dst_ip` (mirrors `lb_scenario_test.rs`'s `apply_fw6`).
fn allow_tcp6_any_dst(maps: &mut MemMaps, tap: u32, port: u16) {
    maps.fw_meta6.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    maps.fw_rules6.insert(
        (tap, 0),
        FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: [0; 16],
            dst_mask: [0; 16],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: port,
            dst_port_max: port,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

/// v4 mirror of `allow_tcp6_any_dst`.
fn allow_tcp_any_dst(maps: &mut MemMaps, tap: u32, port: u16) {
    maps.fw_meta.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    maps.fw_rules.insert(
        (tap, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: port,
            dst_port_max: port,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

#[test]
fn v6_lb_local_delivery_with_dsr_notes_reverse_vip() {
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.add_iface6(
        VNI,
        BACKEND_OVERLAY_IP6,
        IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    install_lb6(&mut node, HOSTB_UL);
    allow_tcp6_any_dst(&mut node.maps, TAP, 443);

    let inner = eth_ipv6_tcp(GUEST_A6, OVERLAY_VIP6, 443);
    let dsr = Some(DsrOpt {
        family: 1,
        _pad: 0,
        port: 443,
        vip: OVERLAY_VIP6,
    });
    let out = node.uplink_v6_dsr(&inner, VNI, &local_for(HOSTB_UL, 9), dsr);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "LB-selected local backend delivered to its own tap"
    );

    // DSR never rewrites the inner dst (stays the VIP) and the DSR note is made BEFORE the inner
    // Ethernet rewrite (which only touches MACs, not L3), so `ct_key6` over the ORIGINAL `inner`
    // bytes reproduces the exact forwarded-frame tuple `dsr_note6` keyed off internally.
    let fwd = ct_key6(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = node
        .maps
        .dsr6_get(&rev)
        .expect("reverse DSR6 map entry must exist after a DSR local-LB delivery");
    assert_eq!(e.vip, OVERLAY_VIP6, "reverse entry notes reply src -> VIP");

    assert!(
        node.maps.dsr6_get(&fwd).is_none(),
        "LB (DSR) delivery must still create NO forward DSR6 entry — only the reverse"
    );
    assert_eq!(
        node.maps.conntrack6.len(),
        0,
        "DSR state lives in DSR6, never CONNTRACK6"
    );
}

#[test]
fn v6_lb_local_delivery_without_dsr_notes_nothing() {
    // Regression: `dsr: None` (the default for every pre-existing non-DSR uplink caller) must not
    // note a reverse DSR VIP — matches the pre-existing "LB is DSR, no ct" contract.
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.add_iface6(
        VNI,
        BACKEND_OVERLAY_IP6,
        IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    install_lb6(&mut node, HOSTB_UL);
    allow_tcp6_any_dst(&mut node.maps, TAP, 443);

    let inner = eth_ipv6_tcp(GUEST_A6, OVERLAY_VIP6, 443);
    let out = node.uplink_v6(&inner, VNI, &local_for(HOSTB_UL, 9));

    assert_eq!(out.action, Action::Redirect(TAP));
    assert_eq!(
        node.maps.dsr6.len(),
        0,
        "no DSR option -> no DSR6 entry of any kind is created"
    );
    assert_eq!(
        node.maps.conntrack6.len(),
        0,
        "no DSR option -> no conntrack6 entry of any kind is created"
    );
}

#[test]
fn v4_lb_local_delivery_with_dsr_notes_reverse_vip() {
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.add_iface(
        VNI,
        BACKEND_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    install_lb(&mut node, HOSTB_UL);
    allow_tcp_any_dst(&mut node.maps, TAP, 443);

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let dsr = Some(DsrOpt {
        family: 0,
        _pad: 0,
        port: 443,
        vip: vip16(OVERLAY_VIP),
    });
    let out = node.uplink_dsr(&inner, VNI, &local_for(HOSTB_UL, 9), dsr);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "LB-selected local backend delivered to its own tap"
    );

    let fwd = ct_key(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    let rev = invert_key(&fwd);
    let e = node
        .maps
        .dsr_get(&rev)
        .expect("reverse DSR map entry must exist after a DSR local-LB delivery");
    assert_eq!(
        e.vip,
        vip16(OVERLAY_VIP),
        "reverse entry notes reply src -> VIP"
    );

    assert!(
        node.maps.dsr_get(&fwd).is_none(),
        "LB (DSR) delivery must still create NO forward DSR entry — only the reverse"
    );
    assert_eq!(
        node.maps.conntrack.len(),
        0,
        "DSR state lives in DSR, never CONNTRACK"
    );
}

#[test]
fn v4_lb_local_delivery_without_dsr_notes_nothing() {
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.add_iface(
        VNI,
        BACKEND_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    install_lb(&mut node, HOSTB_UL);
    allow_tcp_any_dst(&mut node.maps, TAP, 443);

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let out = node.uplink(&inner, VNI, &local_for(HOSTB_UL, 9));

    assert_eq!(out.action, Action::Redirect(TAP));
    assert_eq!(
        node.maps.dsr.len(),
        0,
        "no DSR option -> no DSR entry of any kind is created"
    );
    assert_eq!(
        node.maps.conntrack.len(),
        0,
        "no DSR option -> no conntrack entry of any kind is created"
    );
}

// ─── B8: guest-egress DSR reverse-SNAT (`SimNode::guest_tx_v6` / `guest_tx`) ───────────────────────
//
// At the backend, the guest's REPLY to a DSR-load-balanced flow (src = the guest's own overlay IP,
// dst = the real client) must have its src rewritten to the VIP the edge dispatched — the reverse
// state the ingress `uplink_dsr_note`/`uplink_dsr_note6` tcx pre-program recorded (B7/B7c) in `DSR`/
// `DSR6`, keyed on the reply's OWN 5-tuple. `process_guest_tx`/`process_guest_tx_v6` apply it on
// egress, between the firewall/conntrack stage and the route/deliver tail — the route decision keys
// off DST (the real client), so it is unaffected; the rewritten src is what leaves via the ordinary
// route (typically external, encapping toward any anycast edge, since the real client is never a
// local `INTERFACES`/`INTERFACES6` entry).

const EDGE_UNDERLAY6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee, 0xee,
];
const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd];
const SERVICE_PORT: u16 = 443;
const CLIENT_PORT: u16 = 51000;

fn port_meta6_for(vni: u32, underlay: [u8; 16]) -> PortMeta {
    PortMeta {
        vni,
        guest_ipv4: [0; 4],
        gateway_ipv4: [0; 4],
        guest_mac: GUEST_MAC,
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: underlay,
        gateway_ipv6: [0; 16],
        guest_ipv6: BACKEND_OVERLAY_IP6,
    }
}

fn port_meta4_for(vni: u32, underlay: [u8; 16]) -> PortMeta {
    PortMeta {
        vni,
        guest_ipv4: BACKEND_OVERLAY_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: underlay,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// Wildcard EGRESS-allow v6 firewall rule (any src/dst/port/proto) — the reply's egress firewall
/// check must not deny-by-default block it, matching `guest_tx_v6_test.rs`'s `egress_allow_rule`.
fn wildcard_egress_rule6() -> FwRule6 {
    FwRule6 {
        src_ip: [0; 16],
        src_mask: [0; 16],
        dst_ip: [0; 16],
        dst_mask: [0; 16],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// v4 mirror of `wildcard_egress_rule6`.
fn wildcard_egress_rule4() -> FwRule {
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
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// A full guest Ethernet frame `[Eth][IPv6][TCP]` with EXPLICIT sport/dport (unlike `eth_ipv6_tcp`'s
/// fixed sport=40000) — the reply direction needs sport=service port, dport=client port.
fn eth_ipv6_tcp_reply(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(src, dst, 64)
        .tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// v4 mirror of `eth_ipv6_tcp_reply`.
fn eth_ipv4_tcp_reply(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// A `SimNode` ready to run a v6 guest-egress reply off `TAP`: LOCAL identity + `maps.local` set
/// (required for the `deliver()` Encap arm), a wildcard egress-allow v6 rule on `TAP`, and a
/// public-VNI DEFAULT route (`::/0`) toward `EDGE_UNDERLAY6` so an unrecognised dst (the real client)
/// still routes/encaps instead of Pass-ing.
fn node_for_guest_tx6() -> SimNode {
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.local = Some(local_for(HOSTB_UL, 9));
    node.src_ifindex = TAP;
    node.maps.fw_meta6.insert(
        TAP,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps
        .fw_rules6
        .insert((TAP, 0), wildcard_egress_rule6());
    node.maps.routes6.push(Route6 {
        vni: VNI,
        ipv6: [0u8; 16],
        prefix: 0,
        value: RouteValue {
            nexthop_vni: VNI,
            nexthop_ipv6: EDGE_UNDERLAY6,
            is_external: 1,
            _pad: [0; 3],
        },
    });
    node
}

/// v4 mirror of `node_for_guest_tx6`.
fn node_for_guest_tx4() -> SimNode {
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.local = Some(local_for(HOSTB_UL, 9));
    node.src_ifindex = TAP;
    node.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert((TAP, 0), wildcard_egress_rule4());
    node.maps.routes4.push(Route4 {
        vni: VNI,
        ipv4: [0u8; 4],
        prefix: 0,
        value: RouteValue {
            nexthop_vni: VNI,
            nexthop_ipv6: EDGE_UNDERLAY,
            is_external: 1,
            _pad: [0; 3],
        },
    });
    node
}

#[test]
fn v6_guest_reply_with_dsr_entry_reverse_snats_src_to_vip_and_encaps() {
    let mut node = node_for_guest_tx6();
    let reply = eth_ipv6_tcp_reply(BACKEND_OVERLAY_IP6, CLIENT_IP6, SERVICE_PORT, CLIENT_PORT);

    // Seed the DSR6 note the way B7/B7c's `uplink_dsr_note` would have on ingress: keyed on the
    // reply's OWN 5-tuple (== `invert_key6` of the originally-forwarded flow's key).
    let key = ct_key6(&VecPkt::from_bytes(&reply), ETH_LEN, VNI).unwrap();
    node.maps.dsr6_insert(
        key,
        DsrVip {
            vip: VIP_IP6,
            last_seen: 0,
        },
    );

    let out = node.guest_tx_v6(&reply, &port_meta6_for(VNI, HOSTB_UL));

    assert_eq!(
        out.action,
        Action::Redirect(9),
        "reply routes out the uplink toward the edge"
    );
    assert!(
        out.tunnel.is_some(),
        "reply is encapped (public-VNI default route) toward the edge underlay"
    );

    let out_pkt = VecPkt::from_bytes(&out.pkt);
    let src = out_pkt.read_array::<16>(ETH_LEN + 8).unwrap();
    let dst = out_pkt.read_array::<16>(ETH_LEN + 24).unwrap();
    assert_eq!(
        src, VIP_IP6,
        "reply src rewritten: guest overlay IP -> the VIP the edge dispatched"
    );
    assert_eq!(dst, CLIENT_IP6, "reply dst (the real client) is untouched");
}

/// Regression: a reply with NO recorded DSR entry is byte-unchanged (no reverse-SNAT) — DSR
/// reverse-SNAT must not fire for an ordinary (non-DSR) flow.
#[test]
fn v6_guest_reply_without_dsr_entry_is_unchanged_regression() {
    let mut node = node_for_guest_tx6();
    let reply = eth_ipv6_tcp_reply(BACKEND_OVERLAY_IP6, CLIENT_IP6, SERVICE_PORT, CLIENT_PORT);
    // No DSR6 entry seeded.

    let out = node.guest_tx_v6(&reply, &port_meta6_for(VNI, HOSTB_UL));

    assert!(
        out.tunnel.is_some(),
        "still routes/encaps toward the edge (route lookup is unaffected)"
    );
    let out_pkt = VecPkt::from_bytes(&out.pkt);
    let src = out_pkt.read_array::<16>(ETH_LEN + 8).unwrap();
    assert_eq!(
        src, BACKEND_OVERLAY_IP6,
        "no DSR entry -> src is NOT rewritten"
    );
}

#[test]
fn v4_guest_reply_with_dsr_entry_reverse_snats_src_to_vip_and_encaps() {
    let mut node = node_for_guest_tx4();
    let reply = eth_ipv4_tcp_reply(BACKEND_OVERLAY_IP, CLIENT_IP, SERVICE_PORT, CLIENT_PORT);

    let key = ct_key(&VecPkt::from_bytes(&reply), ETH_LEN, VNI).unwrap();
    node.maps.dsr_insert(
        key,
        DsrVip {
            vip: vip16(VIP_IP),
            last_seen: 0,
        },
    );

    let out = node.guest_tx(&reply, &port_meta4_for(VNI, HOSTB_UL));

    assert_eq!(
        out.action,
        Action::Redirect(9),
        "reply routes out the uplink toward the edge"
    );
    assert!(
        out.tunnel.is_some(),
        "reply is encapped (public-VNI default route) toward the edge underlay"
    );

    let out_pkt = VecPkt::from_bytes(&out.pkt);
    let src = out_pkt.read_array::<4>(ETH_LEN + 12).unwrap();
    let dst = out_pkt.read_array::<4>(ETH_LEN + 16).unwrap();
    assert_eq!(
        src, VIP_IP,
        "reply src rewritten: guest overlay IP -> the VIP the edge dispatched"
    );
    assert_eq!(dst, CLIENT_IP, "reply dst (the real client) is untouched");
}

/// v4 regression mirror of `v6_guest_reply_without_dsr_entry_is_unchanged_regression`.
#[test]
fn v4_guest_reply_without_dsr_entry_is_unchanged_regression() {
    let mut node = node_for_guest_tx4();
    let reply = eth_ipv4_tcp_reply(BACKEND_OVERLAY_IP, CLIENT_IP, SERVICE_PORT, CLIENT_PORT);
    // No DSR entry seeded.

    let out = node.guest_tx(&reply, &port_meta4_for(VNI, HOSTB_UL));

    assert!(
        out.tunnel.is_some(),
        "still routes/encaps toward the edge (route lookup is unaffected)"
    );
    let out_pkt = VecPkt::from_bytes(&out.pkt);
    let src = out_pkt.read_array::<4>(ETH_LEN + 12).unwrap();
    assert_eq!(
        src, BACKEND_OVERLAY_IP,
        "no DSR entry -> src is NOT rewritten"
    );
}
