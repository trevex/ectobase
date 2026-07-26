//! Prove the shared-core NATIVE IPv6→IPv6 guest-egress datapath `process_guest_tx_v6` over the DPDK
//! `Pkt`/`Maps` backend — `MbufPkt` + `ComposedMaps` (SharedConfigMaps read-only config half +
//! PerLcoreFlowMaps flow half). A native v6 guest TCP frame (dst NOT in the NAT64 prefix) with an
//! egress-allow v6 firewall rule + an external v6 route gets v6-firewall + conntrack6 track + outer-
//! IPv6 encap (inner-proto 41, IPv6-in-IPv6) → `Action::Redirect(uplink_ifindex)`, BYTE-IDENTICALLY
//! to the sim (`process_guest_tx_v6` over `VecPkt` + `MemMaps` with the same map state), AND the
//! conntrack6 firewall-track (forward + reverse) lands.
//!
//! This is the DPDK datapath half of the native-v6 egress slice, mirroring `guest_tx_datapath.rs`.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey6, FwMeta, FwRule6, Local, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::conntrack::invert_key6;
use flowplane_core::datapath::{process_guest_tx_v6, GuestTxIn};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── addressing ───────────────────────────────────────────────────────────────
const VNI: u32 = 400;
const SRC_IFINDEX: u32 = 11;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
/// External v6 dst — NOT in `64:ff9b::/96` → native v6→v6 (no NAT64).
const EXT_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0x22; 6];
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

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: [10, 0, 0, 42],
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: GUEST_V6,
    }
}

/// External v6 route (is_external=1) → the encap arm (no UNDERLAY[nexthop] entry).
fn ext_route() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UL,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn egress_allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 0,
        egress_count: 1,
    }
}
fn egress_allow_rule() -> FwRule6 {
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

/// A native v6 guest frame `[Eth 0x86DD][IPv6 GUEST_V6→EXT_V6][TCP]`.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv6(GUEST_V6, EXT_V6, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

fn fwd_key() -> CtKey6 {
    CtKey6 {
        vni: VNI,
        src_ip: GUEST_V6,
        dst_ip: EXT_V6,
        src_port: SPORT,
        dst_port: DPORT,
        proto: 6,
        _pad: [0; 3],
    }
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to grow_head moves).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Sim reference: run `process_guest_tx_v6` over `VecPkt` + `MemMaps` with the SAME fixture state.
fn sim_output() -> (Vec<u8>, Action) {
    let mut sim = MemMaps::default();
    sim.local = Some(node_local());
    sim.add_route6(VNI, EXT_V6, ext_route());
    sim.fw_meta6.insert(SRC_IFINDEX, egress_allow_meta());
    sim.fw_rules6.insert((SRC_IFINDEX, 0), egress_allow_rule());

    let meta = port_meta();
    let mut vp = VecPkt::from_bytes(&guest_frame());
    let out = process_guest_tx_v6(
        &mut vp,
        &mut sim,
        &GuestTxIn {
            meta: &meta,
            src_ifindex: SRC_IFINDEX,
            now: 0,
        },
    );
    (vp.into_bytes(), out.action)
}

#[test]
fn dpdk_guest_tx_v6_native_encap_and_conntrack6() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_gtv6",
    ])
    .expect("EAL init");
    let pool = Mempool::new("gtv6_pool", 1023, 250, 0).expect("pool");

    // ── Program the CONFIG half (SharedConfigMaps): LOCAL, an external v6 route, an egress-allow v6
    //    firewall rule on the source ifindex — the SAME fixture the sim gets. ─────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(shared.route6_insert(VNI, EXT_V6, ext_route()), "route6");
    assert!(
        shared.fw_meta6_insert(SRC_IFINDEX, egress_allow_meta()),
        "fw_meta6"
    );
    assert!(
        shared.fw_rules6_insert(
            flowplane_common::FwRuleKey {
                ifindex: SRC_IFINDEX,
                idx: 0,
            },
            egress_allow_rule(),
        ),
        "fw_rule6"
    );

    // ── Compose the shared config half with a fresh per-lcore FLOW half (conntrack6). ────────────
    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();

    // ── Build the guest frame into an mbuf, wrap MbufPkt, run the shared-core datapath. ──────────
    let frame = guest_frame();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let mut pkt = MbufPkt::new(&mut mb);
    let meta = port_meta();
    let out = process_guest_tx_v6(
        &mut pkt,
        &mut composed,
        &GuestTxIn {
            meta: &meta,
            src_ifindex: SRC_IFINDEX,
            now: 0,
        },
    );
    let dpdk_bytes = mp_bytes(&pkt);

    // 1. Encap arm → redirect out the uplink; frame grew by exactly 40 (outer IPv6 prepended).
    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "native v6 encap arm redirects out the uplink"
    );
    assert_eq!(
        dpdk_bytes.len(),
        frame.len() + 40,
        "outer IPv6 header (40B) prepended by grow_head/write_outer_v6"
    );

    // 2. Byte-parity vs the sim (`process_guest_tx_v6` over VecPkt+MemMaps, same map state).
    let (sim_bytes, sim_action) = sim_output();
    assert_eq!(sim_action, out.action, "action parity DPDK vs sim");
    assert_eq!(
        dpdk_bytes, sim_bytes,
        "DPDK == sim encapped-frame byte parity"
    );

    // 3. Concrete header-field sanity: outer IPv6 version=6, next-header IPPROTO_IPV6 (41 — the
    //    IPv6-in-IPv6 difference from the v4 IPIP/4 path), src = node underlay, dst = route nexthop.
    assert_eq!(dpdk_bytes[ETH_LEN] >> 4, 6, "outer IPv6 version 6");
    assert_eq!(
        dpdk_bytes[ETH_LEN + 6],
        41,
        "outer next-header = IPPROTO_IPV6 (IPv6-in-IPv6)"
    );
    assert_eq!(
        &dpdk_bytes[ETH_LEN + 8..ETH_LEN + 24],
        &SRC_UL,
        "outer IPv6 src = node underlay"
    );
    assert_eq!(
        &dpdk_bytes[ETH_LEN + 24..ETH_LEN + 40],
        &NEXTHOP_UL,
        "outer IPv6 dst = route nexthop"
    );
    // Inner IPv6 unchanged (no SNAT on the native v6 path).
    let inner = ETH_LEN + IPV6_LEN;
    assert_eq!(
        &dpdk_bytes[inner + 8..inner + 24],
        &GUEST_V6,
        "inner IPv6 src unchanged"
    );
    assert_eq!(
        &dpdk_bytes[inner + 24..inner + 40],
        &EXT_V6,
        "inner IPv6 dst unchanged"
    );

    // 4. conntrack6 firewall-track landed: forward + pre-seeded reverse entries.
    let fwd = fwd_key();
    assert!(
        composed.conntrack6_get(&fwd).is_some(),
        "forward conntrack6 entry landed"
    );
    assert!(
        composed.conntrack6_get(&invert_key6(&fwd)).is_some(),
        "reverse conntrack6 entry pre-seeded"
    );

    shared.report_quiescent(&tok);
}
