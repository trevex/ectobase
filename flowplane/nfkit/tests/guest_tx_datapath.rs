//! Prove the shared-core guest-egress datapath `flowplane_core::datapath::process_guest_tx`
//! over the DPDK `Pkt`/`Maps` backend — `MbufPkt` + `ComposedMaps` (SharedConfigMaps read-only
//! config half + PerLcoreFlowMaps flow half). A guest IPv4 TCP frame with a NAT source + an external
//! `0.0.0.0/0` route gets SNAT + outer-IPv6 encap → `Action::Redirect(uplink_ifindex)`, BYTE-
//! IDENTICALLY to the sim (`process_guest_tx` over `VecPkt` + `MemMaps` with the same map state),
//! AND the peer-independent SNAT reverse conntrack entry lands in the SHARED conntrack table
//! (`shared_ct` — the cross-lcore fix), routed there by `ComposedMaps::conntrack_insert`'s
//! `is_reverse_shape` demux.
//!
//! This is the DPDK datapath half of the guest-egress slice: it validates `process_guest_tx` over
//! the DPDK substrate (incl. the `grow_head`/`write_outer_v6` encap prepend) AND exercises the
//! `shared_ct` write path before the serve-loop integration lands.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Run with `--test-threads=1`.
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, FwMeta, FwRule, Local, NatKey, NatValue, PortMeta, RouteValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS,
};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── addressing ───────────────────────────────────────────────────────────────
const VNI: u32 = 100;
const SRC_IFINDEX: u32 = 10;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const EXT_DST: [u8; 4] = [203, 0, 113, 9];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
// NAT source: guest GUEST_IP masquerades behind NAT_IP with an allocatable port range.
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const NAT_PORT_MIN: u16 = 20000;
const NAT_PORT_MAX: u16 = 20200;
const SPORT: u16 = 12345;
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
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// External default route (`0.0.0.0/0`, is_external=1) → guest_tx takes the SNAT + encap arm.
fn ext_route() -> RouteValue {
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: NEXTHOP_UL,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: NAT_PORT_MIN,
        port_max: NAT_PORT_MAX,
    }
}

fn egress_allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 0,
        egress_count: 1,
    }
}
fn egress_allow_rule() -> FwRule {
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

/// A guest Ethernet frame `[Eth][IPv4][TCP]` GUEST_IP:SPORT → EXT_DST:DPORT.
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, EXT_DST, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to grow_head data-pointer
/// moves — reads are relative to the current front).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Sim reference: run `process_guest_tx` over `VecPkt` + `MemMaps` with the SAME fixture map state.
/// Returns the output frame bytes + Action + the SNAT-allocated nat_port (from the forward CT entry
/// the sim created) — the nat_port is the `dst_port` of the peer-independent reverse key.
fn sim_output() -> (Vec<u8>, Action, u16) {
    let mut sim = MemMaps::default();
    sim.local = Some(node_local());
    sim.add_route4(VNI, EXT_DST, ext_route());
    sim.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        nat_value(),
    );
    sim.nat_ips.insert((VNI, NAT_IP));
    sim.fw_meta.insert(SRC_IFINDEX, egress_allow_meta());
    sim.fw_rules.insert((SRC_IFINDEX, 0), egress_allow_rule());

    let meta = port_meta();
    let mut vp = VecPkt::from_bytes(&guest_frame());
    let out = process_guest_tx(
        &mut vp,
        &mut sim,
        &GuestTxIn {
            meta: &meta,
            src_ifindex: SRC_IFINDEX,
            now: 0,
        },
    );
    // The forward SNAT entry the sim created carries the allocated nat_port in `xlate_port`.
    let fwd = CtKey {
        vni: VNI,
        src_ip: GUEST_IP,
        dst_ip: EXT_DST,
        src_port: SPORT,
        dst_port: DPORT,
        proto: 6,
        _pad: [0; 3],
    };
    let nat_port = flowplane_core::maps::Maps::conntrack_get(&sim, &fwd)
        .expect("sim forward SNAT entry")
        .xlate_port;
    (vp.into_bytes(), out.action, nat_port)
}

#[test]
fn dpdk_guest_tx_snat_encap_lands_shared_ct_reverse() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_gtd",
    ])
    .expect("EAL init");
    let pool = Mempool::new("gtd_pool", 1023, 250, 0).expect("pool");

    // ── Program the CONFIG half (SharedConfigMaps) — the read-only, cross-lcore config. Same fixture
    //    the sim gets: LOCAL, an external default route, a NAT source (binding + public IP), and an
    //    egress-allow firewall rule on the source ifindex. ────────────────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(shared.route4_insert(VNI, EXT_DST, ext_route()), "route4");
    assert!(
        shared.nat_insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP
            },
            nat_value()
        ),
        "nat binding"
    );
    assert!(shared.nat_ips_insert(VNI, NAT_IP), "nat public ip");
    assert!(
        shared.fw_meta_insert(SRC_IFINDEX, egress_allow_meta()),
        "fw_meta"
    );
    assert!(
        shared.fw_rules_insert(
            flowplane_common::FwRuleKey {
                ifindex: SRC_IFINDEX,
                idx: 0,
            },
            egress_allow_rule(),
        ),
        "fw_rule"
    );

    // ── Compose the shared config half with a fresh per-lcore FLOW half (conntrack + meter). The
    //    SNAT reverse entry (src_ip==0 && src_port==0) is routed by ComposedMaps into `shared_ct`. ─
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
    let out = process_guest_tx(
        &mut pkt,
        &mut composed,
        &GuestTxIn {
            meta: &meta,
            src_ifindex: SRC_IFINDEX,
            now: 0,
        },
    );
    let dpdk_bytes = mp_bytes(&pkt);

    // ── Assertions ───────────────────────────────────────────────────────────────────────────────
    // 1. Encap arm → redirect out the uplink; frame grew by exactly 40 (outer IPv6 prepended).
    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "SNAT+encap arm redirects out the uplink"
    );
    assert_eq!(
        dpdk_bytes.len(),
        frame.len() + 40,
        "outer IPv6 header (40B) prepended by grow_head/write_outer_v6"
    );

    // 2. Byte-parity vs the sim (`process_guest_tx` over VecPkt+MemMaps, same map state). This is the
    //    DPDK==sim guard: the shared orchestrator emits identical bytes on both substrates.
    let (sim_bytes, sim_action, nat_port) = sim_output();
    assert_eq!(sim_action, out.action, "action parity DPDK vs sim");
    assert_eq!(
        dpdk_bytes, sim_bytes,
        "DPDK == sim encapped-frame byte parity"
    );

    // Concrete header-field sanity (independent of the sim oracle): outer IPv6 version=6,
    // next-header = IPPROTO_IPIP (4), src = node underlay, dst = route nexthop.
    assert_eq!(dpdk_bytes[ETH_LEN] >> 4, 6, "outer IPv6 version 6");
    assert_eq!(
        dpdk_bytes[ETH_LEN + 6],
        4,
        "outer next-header = IPPROTO_IPIP"
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
    // Inner IPv4 src was SNAT'd guest → nat_ip (inner IPv4 header starts after outer Eth+IPv6).
    let inner_ip = ETH_LEN + 40;
    assert_eq!(
        &dpdk_bytes[inner_ip + 12..inner_ip + 16],
        &NAT_IP,
        "inner IPv4 src rewritten to nat_ip"
    );

    // 3. The SNAT reverse conntrack entry landed in the SHARED table (the cross-lcore fix). The
    //    peer-independent reverse key is `(vni, [0;4], nat_ip, 0, nat_port, proto)`; nat_port is the
    //    allocation the sim reproduced deterministically (same hash5 seed → same chosen port).
    let reverse_key = CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP,
        src_port: 0,
        dst_port: nat_port,
        proto: 6,
        _pad: [0; 3],
    };
    let rev = shared.shared_ct_get(&reverse_key);
    assert!(
        rev.is_some(),
        "SNAT reverse entry present in shared_ct at the derived peer-independent key"
    );
    assert_eq!(
        rev.unwrap().xlate_port,
        SPORT,
        "reverse entry restores the original guest source port"
    );

    // Exactly ONE reverse-shape entry exists in shared_ct (the single SNAT allocation), and it is the
    // one we asserted above — proving the forward flow's per-lcore entry did NOT leak into shared_ct.
    let mut reverse_shape = 0usize;
    shared.shared_ct_for_each(|k, _| {
        if k.src_ip == [0; 4] && k.src_port == 0 {
            reverse_shape += 1;
        }
    });
    assert_eq!(
        reverse_shape, 1,
        "exactly one reverse-shape entry in shared_ct (the SNAT reverse)"
    );

    // The forward (real-src) SNAT entry stays in the PER-LCORE flow half, NOT shared_ct.
    let fwd_key = CtKey {
        vni: VNI,
        src_ip: GUEST_IP,
        dst_ip: EXT_DST,
        src_port: SPORT,
        dst_port: DPORT,
        proto: 6,
        _pad: [0; 3],
    };
    assert!(
        shared.shared_ct_get(&fwd_key).is_none(),
        "forward flow entry must NOT be in shared_ct (per-lcore only)"
    );

    shared.report_quiescent(&tok);
}
