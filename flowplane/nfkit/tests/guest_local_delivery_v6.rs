//! VERIFY that NATIVE v6→v6 guest↔guest SAME-NODE local
//! delivery already works over the DPDK substrate — the compose of the real
//! `flowplane_core::datapath::process_guest_tx_v6` `Deliver::Local` arm and the `nfkit::LcoreRing`
//! cross-lcore handoff the serve worker uses to route a local-delivery redirect to the dest guest
//! port. This mirrors `guest_local_delivery.rs` (the v4 test) on the native v6 datapath.
//!
//! ── WHAT THIS PROVES ──────────────────────────────────────────────────────────────────────────
//! When guest A egresses a NATIVE v6 frame toward a peer whose route6 is INTERNAL (is_external=0) and
//! whose nexthop underlay resolves to a LOCAL guest tap, `process_guest_tx_v6` takes the
//! `Deliver::Local` arm: NO SNAT, NO encap — it REWRITES the inner Ethernet in place (dst = dest
//! guest_mac, src = GW_MAC, ethertype STAYS 0x86DD/IPv6) and returns `Action::Redirect(dest_tap)`.
//! The serve worker then hands the mbuf to the dest port's `LcoreRing` (the dest port may be owned by
//! another lcore); the owning worker dequeues and tx's it as-is. The worker's guest↔guest routing —
//! `Redirect(ix != uplink) → rings[ifindex_to_index[ix]]` — is ETHERTYPE-AGNOSTIC, so the v6 Local
//! redirect composes with it exactly as the v4 one does.
//!
//! This is a VERIFICATION (no datapath change): the v6 Local arm + the ethertype-agnostic ring
//! delivery should ALREADY deliver v6→v6 same-node. Drives BOTH halves over ONE `ComposedMaps`:
//!   1. The REAL `process_guest_tx_v6` on a guest-A→guest-B native v6 TCP frame → asserts
//!      `Action::Redirect(DEST_TAP)` AND the inner Eth was rewritten (dst == DEST_GUEST_MAC,
//!      src == GW_MAC), ethertype STILL 0x86DD, the IPv6/TCP payload (from byte 14) INTACT, and the
//!      frame length UNCHANGED (no encap — same-node delivery).
//!   2. The SAME mbuf is then handed through a real `LcoreRing` (enqueue → dequeue_burst) — the exact
//!      serve-worker handoff — and the DEQUEUED frame is asserted BYTE-IDENTICAL to the
//!      `process_guest_tx_v6` output.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule6, Local, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
    FW_DIR_INGRESS,
};
use flowplane_core::datapath::{process_guest_tx_v6, GuestTxIn};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_core::uplink::GW_MAC;
use nfkit::{
    ComposedMaps, Eal, LcoreRing, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps,
};

// ── addressing ───────────────────────────────────────────────────────────────
const VNI: u32 = 400;
const SRC_TAP: u32 = 10; // guest A's port ifindex (src_ifindex on egress)
const DEST_TAP: u32 = 11; // guest B's port ifindex (the Deliver::Local redirect target)
const UPLINK_IFINDEX: u32 = 7;
const SRC_GUEST_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];
const SRC_GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
/// Same-node peer (same VNI), a native v6 dst NOT in `64:ff9b::/96` → native v6→v6 (no NAT64).
const DEST_GUEST_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21,
];
const DEST_GUEST_MAC: [u8; 6] = [0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x11];
// PEER_UNDERLAY: the internal route's nexthop; underlay_get resolves it → DEST_TAP (a LOCAL tap).
const PEER_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SPORT: u16 = 50000;
const DPORT: u16 = 443;

fn node_local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SRC_UL,
    }
}

fn src_port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: [10, 0, 0, 20],
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: SRC_GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: SRC_GUEST_V6,
    }
}

/// INTERNAL v6 route (is_external=0) whose nexthop underlay maps to a LOCAL tap → `Deliver::Local`
/// (no SNAT, no encap; the inner Eth is rewritten and the frame is redirected to the peer tap).
fn internal_route() -> RouteValue {
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: PEER_UNDERLAY,
        is_external: 0,
        _pad: [0; 3],
    }
}

fn allow_meta(egress: u32, ingress: u32) -> FwMeta {
    FwMeta {
        ingress_count: ingress,
        egress_count: egress,
    }
}
fn allow_rule6(direction: u8) -> FwRule6 {
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
        direction,
        enabled: 1,
    }
}

/// A native v6 guest-A→guest-B frame `[Eth 0x86DD][IPv6 SRC_GUEST_V6→DEST_GUEST_V6][TCP]`.
/// Inner eth dst is arbitrary (guest sends toward its gateway); the datapath rewrites it to the peer.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(SRC_GUEST_MAC, [0xbb; 6])
        .ipv6(SRC_GUEST_V6, DEST_GUEST_V6, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader.
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

#[test]
fn guest_local_delivery_v6_process_guest_tx_v6_local_then_ring_handoff() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "fp_glocalv6",
    ])
    .expect("EAL init");
    let pool = Mempool::new("glocalv6_pool", 1023, 250, 0).expect("pool");

    // ── ONE SharedConfigMaps: program the native-v6 same-node delivery fixture. LOCAL, an INTERNAL
    //    v6 route to the peer, the UNDERLAY entry mapping the route's nexthop → the DEST guest tap +
    //    MAC (this is what turns the route into a `Deliver::Local`), the DEST guest's PortMeta (keyed
    //    by DEST_TAP), and v6 firewall allow rules for egress on the source tap + ingress on the dest
    //    tap (the Local arm runs the dest ingress firewall on new flows). ───────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(
        shared.route6_insert(VNI, DEST_GUEST_V6, internal_route()),
        "internal v6 route to the same-node peer"
    );
    // underlay_get(nexthop) → LOCAL tap (tap_ifindex != 0) ⇒ deliver() returns Deliver::Local.
    assert!(
        shared.underlay_insert(
            PEER_UNDERLAY,
            UnderlayValue {
                vni: VNI,
                tap_ifindex: DEST_TAP,
                guest_mac: DEST_GUEST_MAC,
                _pad: [0; 2],
            }
        ),
        "underlay delivery entry → local dest tap"
    );
    // The dest guest's PortMeta (a LOCAL guest), keyed by its tap ifindex.
    assert!(
        shared.ports_insert(
            DEST_TAP,
            PortMeta {
                vni: VNI,
                guest_ipv4: [10, 0, 0, 21],
                gateway_ipv4: [10, 0, 0, 1],
                guest_mac: DEST_GUEST_MAC,
                _pad: [0; 2],
                underlay_ipv6: SRC_UL,
                gateway_ipv6: [0; 16],
                guest_ipv6: DEST_GUEST_V6,
            }
        ),
        "dest guest PortMeta"
    );
    // v6 firewall: allow egress on the source tap AND ingress on the dest tap (Deliver::Local runs
    // the destination ingress firewall on NEW flows — a deny-by-default dest would DROP delivery).
    assert!(
        shared.fw_meta6_insert(SRC_TAP, allow_meta(1, 0)),
        "src fw_meta6"
    );
    assert!(
        shared.fw_rules6_insert(
            flowplane_common::FwRuleKey {
                ifindex: SRC_TAP,
                idx: 0,
            },
            allow_rule6(FW_DIR_EGRESS),
        ),
        "src egress fw_rule6"
    );
    assert!(
        shared.fw_meta6_insert(DEST_TAP, allow_meta(0, 1)),
        "dest fw_meta6"
    );
    assert!(
        shared.fw_rules6_insert(
            flowplane_common::FwRuleKey {
                ifindex: DEST_TAP,
                idx: 0,
            },
            allow_rule6(FW_DIR_INGRESS),
        ),
        "dest ingress fw_rule6"
    );

    // ── ONE ComposedMaps (shared config + a fresh per-lcore flow half) — the serve-worker structure.
    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();

    // ── STEP 1 — the REAL process_guest_tx_v6 local-deliver arm ──────────────────────────────────
    let frame = guest_frame();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let meta = src_port_meta();
    let (action, local_bytes) = {
        let mut pkt = MbufPkt::new(&mut mb);
        let out = process_guest_tx_v6(
            &mut pkt,
            &mut composed,
            &GuestTxIn {
                meta: &meta,
                src_ifindex: SRC_TAP,
                now: 0,
            },
        );
        (out.action, mp_bytes(&pkt))
    };

    // Local-deliver arm: redirect to the DEST guest tap (NOT the uplink), frame length UNCHANGED
    // (no encap — this is same-node delivery).
    assert_eq!(
        action,
        Action::Redirect(DEST_TAP),
        "Deliver::Local → redirect to the same-node dest guest tap (no encap)"
    );
    assert_eq!(
        local_bytes.len(),
        frame.len(),
        "native v6 same-node local delivery does NOT change the frame length (no encap)"
    );

    // Inner Ethernet rewritten for the dest guest: dst = DEST_GUEST_MAC, src = GW_MAC; ethertype
    // STAYS IPv6 (0x86DD — the frame was already v6); the IPv6/TCP payload (byte 14 on) untouched.
    let inner_eth_dst: [u8; 6] = local_bytes[0..6].try_into().unwrap();
    let inner_eth_src: [u8; 6] = local_bytes[6..12].try_into().unwrap();
    assert_eq!(
        inner_eth_dst, DEST_GUEST_MAC,
        "local delivery: inner eth dst rewritten to the dest guest MAC"
    );
    assert_eq!(
        inner_eth_src, GW_MAC,
        "local delivery: inner eth src rewritten to the gateway MAC"
    );
    assert_eq!(
        u16::from_be_bytes([local_bytes[12], local_bytes[13]]),
        0x86DD,
        "ethertype still IPv6 (native v6 Local delivery leaves it untouched)"
    );
    assert_eq!(
        &local_bytes[14..],
        &frame[14..],
        "IPv6/TCP payload untouched (only the inner Eth header changed; SRC_V6→DEST_V6 preserved)"
    );

    // ── STEP 2 — the LcoreRing handoff (the exact ETHERTYPE-AGNOSTIC serve-worker cross-lcore route)
    // Enqueue the just-processed mbuf into the dest port's ring (any worker may enqueue), then dequeue
    // it (only the owning worker dequeues) and assert byte-identical — proving the v6 Local datapath
    // output + the ring handoff compose into a correct guest↔guest delivery.
    let ring = LcoreRing::new("glocalv6_ring", 1024, 0).expect("ring");
    assert!(
        ring.enqueue(mb).is_ok(),
        "enqueue the v6 local-deliver mbuf into the dest port ring"
    );

    let mut burst = MbufBurst::new();
    let n = ring.dequeue_burst(&mut burst);
    assert_eq!(n, 1, "dequeue exactly the one handed-off mbuf");
    let dequeued_bytes = {
        let m = burst.drain(..).next().unwrap();
        let d = m.data();
        d.to_vec() // m frees on drop
    };
    assert_eq!(
        dequeued_bytes, local_bytes,
        "the dequeued frame is byte-identical to process_guest_tx_v6's local-deliver output — the \
         dest worker tx's exactly the rewritten v6 frame (ring routing is ethertype-agnostic)"
    );

    // Drain done (ring empty); nothing leaks at ring free.
    let mut empty = MbufBurst::new();
    assert_eq!(ring.dequeue_burst(&mut empty), 0, "ring drained");

    shared.report_quiescent(&tok);
}
