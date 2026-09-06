//! B7: at the backend node, `uplink_rx` (post-decap) reads the DSR Geneve option (threaded in like
//! `vni` via `UplinkIn::dsr`) and, on a load-balanced LOCAL delivery, creates the REVERSE conntrack
//! entry so the guest's reply is later reverse-SNAT'd src -> VIP (`ct_apply`/`ct_apply6`, applied on
//! egress in B8). The only per-connection DSR state lives here on the backend.
//!
//! # Coverage
//!
//! 1. `flowplane_core::conntrack::dsr_ct_create`/`dsr_ct_create6` directly (unit level, mirroring
//!    `ct_apply_test.rs`'s pattern): the reverse entry is keyed on `invert_key(ct_key(forwarded))` /
//!    `invert_key6(ct_key6(forwarded))`, carries `CT_REWRITE_SRC | CT_F_DSR`, and
//!    `xlate_ip`/`xlate_ip6 == vip`; idempotent (a second call with a different VIP never overwrites
//!    the first).
//! 2. End-to-end through `SimNode::uplink_v6_dsr`/`uplink_dsr`: a DSR-forwarded frame hitting a LOCAL
//!    LB-backend delivery creates the reverse DSR conntrack entry — the SAME core path
//!    `process_uplink`/`process_uplink_v6` runs in production, driven by the eBPF `uplink_rx`'s
//!    `get_tunnel_opt` + `dsr::decode` (see `ingress.rs`/`v6.rs`).
//! 3. Regression: a non-DSR (`dsr: None`) LB delivery creates NO conntrack entry at all — matches the
//!    pre-existing "LB is DSR, no ct" contract (`ns_scenario_v6_test.rs`,
//!    `v6_lb_local_backend_delivered_no_conntrack6_created`); `dsr` defaulting to `None` must not
//!    change behavior for every pre-existing (non-DSR) uplink caller.

use etherparse::PacketBuilder;
use flowplane_common::{
    DsrOpt, FwMeta, FwRule, FwRule6, IfaceValue, LbBackend, LbKey, LbValue, MaglevKey, CT_F_DSR,
    CT_REWRITE_SRC, FW_ACTION_ACCEPT, FW_DIR_INGRESS,
};
use flowplane_core::conntrack::{
    ct_key, ct_key6, dsr_ct_create, dsr_ct_create6, invert_key, invert_key6,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;

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

// ─── direct dsr_ct_create6 / dsr_ct_create unit coverage ──────────────────────────────────────────

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
fn dsr_ct_create6_inserts_reverse_entry_keyed_on_guest_reply_tuple() {
    // The forwarded frame at the backend: src=client, dst=backend overlay.
    let raw = bare_ipv6_tcp(CLIENT_IP6, BACKEND_OVERLAY_IP6, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_ct_create6(&pkt, &mut maps, 0, VNI, &VIP_IP6, 12345);

    let fwd = ct_key6(&pkt, 0, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = maps
        .conntrack6_get(&rev)
        .expect("reverse DSR conntrack6 entry must exist, keyed on invert_key6(forwarded)");
    assert_eq!(
        e.flags & (CT_REWRITE_SRC | CT_F_DSR),
        CT_REWRITE_SRC | CT_F_DSR,
        "reverse entry must carry CT_REWRITE_SRC | CT_F_DSR"
    );
    assert_eq!(
        e.xlate_ip6, VIP_IP6,
        "reverse entry rewrites reply src -> VIP"
    );
    assert_eq!(e.last_seen, 12345);

    // No FORWARD entry is created by this fn — only the reverse.
    assert!(
        maps.conntrack6_get(&fwd).is_none(),
        "dsr_ct_create6 must not create a forward entry"
    );
}

#[test]
fn dsr_ct_create6_is_idempotent_never_overwrites() {
    let raw = bare_ipv6_tcp(CLIENT_IP6, BACKEND_OVERLAY_IP6, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_ct_create6(&pkt, &mut maps, 0, VNI, &VIP_IP6, 1);
    dsr_ct_create6(&pkt, &mut maps, 0, VNI, &OTHER_VIP_IP6, 2);

    let fwd = ct_key6(&pkt, 0, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = maps.conntrack6_get(&rev).unwrap();
    assert_eq!(e.xlate_ip6, VIP_IP6, "first writer wins; never overwritten");
    assert_eq!(
        e.last_seen, 1,
        "last_seen from the first call, not the second"
    );
}

#[test]
fn dsr_ct_create_inserts_reverse_entry_v4() {
    let raw = bare_ipv4_tcp(CLIENT_IP, BACKEND_OVERLAY_IP, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_ct_create(&pkt, &mut maps, 0, VNI, &VIP_IP, 6789);

    let fwd = ct_key(&pkt, 0, VNI).unwrap();
    let rev = invert_key(&fwd);
    let e = maps
        .conntrack_get(&rev)
        .expect("reverse DSR conntrack entry must exist, keyed on invert_key(forwarded)");
    assert_eq!(
        e.flags & (CT_REWRITE_SRC | CT_F_DSR),
        CT_REWRITE_SRC | CT_F_DSR,
        "reverse entry must carry CT_REWRITE_SRC | CT_F_DSR"
    );
    assert_eq!(
        e.xlate_ip, VIP_IP,
        "reverse entry rewrites reply src -> VIP"
    );
    assert_eq!(e.last_seen, 6789);
    assert!(
        maps.conntrack_get(&fwd).is_none(),
        "dsr_ct_create must not create a forward entry"
    );
}

#[test]
fn dsr_ct_create_is_idempotent_never_overwrites_v4() {
    let raw = bare_ipv4_tcp(CLIENT_IP, BACKEND_OVERLAY_IP, 40000, 443);
    let pkt = VecPkt::from_bytes(&raw);
    let mut maps = MemMaps::default();

    dsr_ct_create(&pkt, &mut maps, 0, VNI, &VIP_IP, 1);
    dsr_ct_create(&pkt, &mut maps, 0, VNI, &OTHER_VIP_IP, 2);

    let fwd = ct_key(&pkt, 0, VNI).unwrap();
    let rev = invert_key(&fwd);
    let e = maps.conntrack_get(&rev).unwrap();
    assert_eq!(e.xlate_ip, VIP_IP, "first writer wins; never overwritten");
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
fn v6_lb_local_delivery_with_dsr_creates_reverse_ct() {
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

    // DSR never rewrites the inner dst (stays the VIP) and the DSR-CT is created BEFORE the inner
    // Ethernet rewrite (which only touches MACs, not L3), so `ct_key6` over the ORIGINAL `inner`
    // bytes reproduces the exact forwarded-frame tuple `dsr_ct_create6` keyed off internally.
    let fwd = ct_key6(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    let rev = invert_key6(&fwd);
    let e = node
        .maps
        .conntrack6_get(&rev)
        .expect("reverse DSR conntrack6 entry must exist after a DSR local-LB delivery");
    assert_eq!(
        e.flags & (CT_REWRITE_SRC | CT_F_DSR),
        CT_REWRITE_SRC | CT_F_DSR,
        "reverse entry must carry CT_REWRITE_SRC | CT_F_DSR"
    );
    assert_eq!(
        e.xlate_ip6, OVERLAY_VIP6,
        "reverse entry rewrites reply src -> VIP"
    );

    assert!(
        node.maps.conntrack6_get(&fwd).is_none(),
        "LB (DSR) delivery must still create NO forward conntrack6 entry — only the reverse"
    );
}

#[test]
fn v6_lb_local_delivery_without_dsr_creates_no_conntrack6_entry() {
    // Regression: `dsr: None` (the default for every pre-existing non-DSR uplink caller) must not
    // create the reverse DSR entry — matches the pre-existing "LB is DSR, no ct" contract.
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
        node.maps.conntrack6.len(),
        0,
        "no DSR option -> no conntrack6 entry of any kind is created"
    );
}

#[test]
fn v4_lb_local_delivery_with_dsr_creates_reverse_ct() {
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
    let mut vip16 = [0u8; 16];
    vip16[..4].copy_from_slice(&OVERLAY_VIP);
    let dsr = Some(DsrOpt {
        family: 0,
        _pad: 0,
        port: 443,
        vip: vip16,
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
        .conntrack_get(&rev)
        .expect("reverse DSR conntrack entry must exist after a DSR local-LB delivery");
    assert_eq!(
        e.flags & (CT_REWRITE_SRC | CT_F_DSR),
        CT_REWRITE_SRC | CT_F_DSR,
        "reverse entry must carry CT_REWRITE_SRC | CT_F_DSR"
    );
    assert_eq!(
        e.xlate_ip, OVERLAY_VIP,
        "reverse entry rewrites reply src -> VIP"
    );

    assert!(
        node.maps.conntrack_get(&fwd).is_none(),
        "LB (DSR) delivery must still create NO forward conntrack entry — only the reverse"
    );
}

#[test]
fn v4_lb_local_delivery_without_dsr_creates_no_conntrack_entry() {
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
        node.maps.conntrack.len(),
        0,
        "no DSR option -> no conntrack entry of any kind is created"
    );
}
