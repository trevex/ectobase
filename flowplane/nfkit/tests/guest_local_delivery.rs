//! Task 5: guest↔guest SAME-NODE delivery over the DPDK substrate — the compose of the real
//! `flowplane_core::datapath::process_guest_tx` `Deliver::Local` arm and the `nfkit::LcoreRing`
//! cross-lcore handoff the serve worker uses to route a local-delivery redirect to the dest guest
//! port.
//!
//! ── WHAT THIS PROVES ──────────────────────────────────────────────────────────────────────────
//! When guest A egresses toward a peer whose route is INTERNAL (is_external=0) and whose nexthop
//! underlay resolves to a LOCAL guest tap, `process_guest_tx` takes the `Deliver::Local` arm: NO
//! SNAT, NO encap — it REWRITES the inner Ethernet in place (dst = dest guest_mac, src = GW_MAC) and
//! returns `Action::Redirect(dest_tap_ifindex)`. The serve worker cannot tx that mbuf directly (the
//! dest port may be owned by another lcore; a `TxQueue` is `!Send`), so it hands the mbuf to the dest
//! port's `LcoreRing`; the owning worker dequeues and tx's it as-is.
//!
//! This test drives BOTH halves over ONE `ComposedMaps` (the exact structure a serve worker holds):
//!   1. The REAL `process_guest_tx` on a guest-A→guest-B IPv4 TCP frame → asserts
//!      `Action::Redirect(DEST_TAP)` AND the inner Eth was rewritten (dst == DEST_GUEST_MAC,
//!      src == GW_MAC) with the ethertype (IPv4) and the rest of the frame intact.
//!   2. The SAME mbuf is then handed through a real `LcoreRing` (enqueue → dequeue_burst) — the exact
//!      serve-worker handoff — and the DEQUEUED frame is asserted BYTE-IDENTICAL to the
//!      `process_guest_tx` output. Together this proves the local-deliver datapath output + the ring
//!      handoff COMPOSE into a correct guest↔guest delivery (the dest worker tx's exactly those bytes).
//!
//! ── FOLLOW-UP (documented, NOT done here) ─────────────────────────────────────────────────────
//! The full TWO-LCORE af_xdp serve e2e — bring up `flowplane-dpdk serve` with two preallocated guest
//! ports on two workers, attach two guests, inject a frame on guest A's veth and observe it delivered
//! out guest B's veth over REAL af_xdp transport with real polling — is a documented Task 6 backlog
//! item. It is heavy/flaky, and each seam here (the `Deliver::Local` datapath arm + the `LcoreRing`
//! handoff) is proven independently.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
    FW_DIR_INGRESS,
};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_core::uplink::GW_MAC;
use nfkit::{
    ComposedMaps, Eal, LcoreRing, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps,
};

// ── addressing ───────────────────────────────────────────────────────────────
const VNI: u32 = 100;
const SRC_TAP: u32 = 10; // guest A's port ifindex (src_ifindex on egress)
const DEST_TAP: u32 = 11; // guest B's port ifindex (the Deliver::Local redirect target)
const UPLINK_IFINDEX: u32 = 7;
const SRC_GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const SRC_GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const DEST_GUEST_IP: [u8; 4] = [10, 0, 2, 21]; // same-node peer (same VNI)
const DEST_GUEST_MAC: [u8; 6] = [0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x11];
// PEER_UNDERLAY: the internal route's nexthop; underlay_get resolves it → DEST_TAP (a LOCAL tap).
const PEER_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SPORT: u16 = 12345;
const DPORT: u16 = 80;

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
        guest_ipv4: SRC_GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: SRC_GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// INTERNAL route (is_external=0) whose nexthop underlay maps to a LOCAL tap → `Deliver::Local`
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
fn allow_rule(direction: u8) -> FwRule {
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
        direction,
        enabled: 1,
    }
}

/// A guest-A→guest-B Ethernet frame `[Eth][IPv4][TCP]` SRC_GUEST_IP:SPORT → DEST_GUEST_IP:DPORT.
/// Inner eth dst is the GW MAC (guest sends to its gateway; the datapath rewrites it to the peer's).
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(SRC_GUEST_MAC, [0xbb; 6])
        .ipv4(SRC_GUEST_IP, DEST_GUEST_IP, 64)
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
fn guest_local_delivery_process_guest_tx_local_then_ring_handoff() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_gld",
    ])
    .expect("EAL init");
    let pool = Mempool::new("gld_pool", 1023, 250, 0).expect("pool");

    // ── ONE SharedConfigMaps: program the same-node delivery fixture. LOCAL (needed even on the
    //    local path so `deliver` can fall through consistently), an INTERNAL route to the peer, the
    //    UNDERLAY entry mapping the route's nexthop → the DEST guest tap + MAC (this is what turns the
    //    route into a `Deliver::Local`), the DEST guest's PortMeta (keyed by DEST_TAP), and firewall
    //    allow rules for egress on the source tap + ingress on the dest tap (the local arm runs the
    //    dest ingress firewall on new flows). ───────────────────────────────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(
        shared.route4_insert(VNI, DEST_GUEST_IP, internal_route()),
        "internal route to the same-node peer"
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
    // The dest guest's PortMeta (a LOCAL guest). Present so a real deployment resolves the dest, and
    // consistent with the serve model where every attached guest has a PortMeta by its tap ifindex.
    assert!(
        shared.ports_insert(
            DEST_TAP,
            PortMeta {
                vni: VNI,
                guest_ipv4: DEST_GUEST_IP,
                gateway_ipv4: [10, 0, 0, 1],
                guest_mac: DEST_GUEST_MAC,
                _pad: [0; 2],
                underlay_ipv6: SRC_UL,
                gateway_ipv6: [0; 16],
                guest_ipv6: [0; 16],
            }
        ),
        "dest guest PortMeta"
    );
    // Firewall: allow egress on the source tap AND ingress on the dest tap (Deliver::Local runs the
    // destination ingress firewall on NEW flows — a deny-by-default dest would DROP the delivery).
    assert!(
        shared.fw_meta_insert(SRC_TAP, allow_meta(1, 0)),
        "src fw_meta"
    );
    assert!(
        shared.fw_rules_insert(
            flowplane_common::FwRuleKey {
                ifindex: SRC_TAP,
                idx: 0,
            },
            allow_rule(FW_DIR_EGRESS),
        ),
        "src egress fw_rule"
    );
    assert!(
        shared.fw_meta_insert(DEST_TAP, allow_meta(0, 1)),
        "dest fw_meta"
    );
    assert!(
        shared.fw_rules_insert(
            flowplane_common::FwRuleKey {
                ifindex: DEST_TAP,
                idx: 0,
            },
            allow_rule(FW_DIR_INGRESS),
        ),
        "dest ingress fw_rule"
    );

    // ── ONE ComposedMaps (shared config + a fresh per-lcore flow half) — the serve-worker structure.
    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();

    // ── STEP 1 — the REAL process_guest_tx local-deliver arm ─────────────────────────────────────
    let frame = guest_frame();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let meta = src_port_meta();
    let (action, local_bytes) = {
        let mut pkt = MbufPkt::new(&mut mb);
        let out = process_guest_tx(
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
        "same-node local delivery does NOT change the frame length (no encap/SNAT header change)"
    );

    // Inner Ethernet rewritten for the dest guest: dst = DEST_GUEST_MAC, src = GW_MAC; ethertype
    // (IPv4, 0x0800) intact; the IPv4/TCP payload (from byte 14 on) untouched.
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
        0x0800,
        "ethertype still IPv4"
    );
    assert_eq!(
        &local_bytes[14..],
        &frame[14..],
        "IPv4/TCP payload untouched (only the inner Eth header changed)"
    );

    // ── STEP 2 — the LcoreRing handoff (the exact serve-worker cross-lcore route) ─────────────────
    // Enqueue the just-processed mbuf into the dest port's ring (any worker may enqueue), then dequeue
    // it (only the owning worker dequeues) and assert byte-identical — proving the datapath output +
    // the ring handoff compose into a correct delivery.
    let ring = LcoreRing::new("gld_ring", 1024, 0).expect("ring");
    assert!(
        ring.enqueue(mb).is_ok(),
        "enqueue the local-deliver mbuf into the dest port ring"
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
        "the dequeued frame is byte-identical to process_guest_tx's local-deliver output — the dest \
         worker tx's exactly the rewritten frame"
    );

    // Drain done (ring empty); nothing leaks at ring free.
    let mut empty = MbufBurst::new();
    assert_eq!(ring.dequeue_burst(&mut empty), 0, "ring drained");

    shared.report_quiescent(&tok);
}
