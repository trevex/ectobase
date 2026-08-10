//! DPDK NAT64 byte-parity anchor. For a crafted frame + inputs, assert the shared
//! `flowplane_core::datapath::process_uplink_nat64_ingress` orchestrator produces a byte-identical
//! output frame + identical `Action` over `MbufPkt` vs `VecPkt`. This proves the NAT64 datapath runs
//! identically on the DPDK substrate.
//!
//! `process_uplink_nat64_ingress` is map-less (`<P: Pkt>`, no `Maps`), so its runners take only the
//! pkt + In-struct; no `DpdkMaps`/`MemMaps` is needed for this scenario.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running scenarios
//! sequentially (ingress and egress scenarios). Run with `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtEntry, Local, NatKey, NatValue, PortMeta, RouteValue, CT_F_NAT64, CT_F_SRC_NAT,
    CT_REWRITE_DST,
};
use flowplane_core::datapath::{
    process_guest_tx_nat64, process_uplink_nat64_ingress, GuestTxNat64In, UplinkNat64IngressIn,
};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::parse::IPPROTO_TCP;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── NAT64 ingress fixture (mirrors flowplane-sim/src/nat64_test.rs) ──────────
const GUEST_IP: [u8; 4] = [10, 0, 0, 42];
const GUEST_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const EXT_V4: [u8; 4] = [203, 0, 113, 9];
const SPORT: u16 = 40000;
const DPORT: u16 = 443;
const TAP_IFINDEX: u32 = 9;
const GUEST_MAC: [u8; 6] = [0x22; 6];
const UPLINK_MAC: [u8; 6] = [2; 6];
const GATEWAY_MAC: [u8; 6] = [1; 6];
const SELF_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const SERVER_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd];

/// The reverse (peer-independent) conntrack entry the egress allocator stored: restores the guest
/// IPv4 + orig port, and flags the flow as NAT64 for the ingress expansion.
fn rev_ct(orig_sport: u16) -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: GUEST_IP,
        xlate_port: orig_sport,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64,
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    }
}

/// Inner IPv4 reply `EXT_V4:DPORT → NAT_IP:nat_port` (pre-`ct_apply`, valid v4 checksums), stripped
/// to `[IPv4][L4]`.
fn inner_reply(nat_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0; 6], [0; 6]).ipv4(EXT_V4, NAT_IP, 63);
    let mut full = Vec::new();
    builder
        .tcp(DPORT, nat_port, 0, 1024)
        .write(&mut full, &[0x01, 0x02, 0x03, 0x04])
        .unwrap();
    full[ETH_LEN..].to_vec()
}

/// Wrap an inner `[IPv4][L4]` reply in the outer `[Eth][IPv6]` IP-in-IPv6 encap the uplink receives.
fn encap_reply(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_LEN + IPV6_LEN + inner.len());
    out.extend_from_slice(&UPLINK_MAC);
    out.extend_from_slice(&GATEWAY_MAC);
    out.extend_from_slice(&0x86DDu16.to_be_bytes());
    out.push(0x60);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.push(4); // IPPROTO_IPIP
    out.push(64);
    out.extend_from_slice(&SERVER_UNDERLAY);
    out.extend_from_slice(&SELF_UNDERLAY);
    out.extend_from_slice(inner);
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

/// Load `frame` into a fresh mbuf and run `process_uplink_nat64_ingress` over `MbufPkt`.
fn run_dpdk(pool: &Mempool, frame: &[u8], in_: &UplinkNat64IngressIn) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_uplink_nat64_ingress(&mut mp, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_uplink_nat64_ingress` over `VecPkt`.
fn run_sim(frame: &[u8], in_: &UplinkNat64IngressIn) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_uplink_nat64_ingress(&mut vp, in_);
    (vp.into_bytes(), action)
}

// ── NAT64 egress fixture (mirrors flowplane-sim/src/nat64_test.rs) ───────────
const VNI: u32 = 300;
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 20512; // exclusive → range = 512
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_IFINDEX: u32 = 7;

fn egress_local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: UPLINK_MAC,
        gateway_mac: GATEWAY_MAC,
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn egress_port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0x22; 6],
        _pad: [0; 2],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: GUEST_IP6,
    }
}

fn egress_route_value() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

/// The NAT64-embedded IPv6 dst = `64:ff9b::EXT_V4`.
fn nat64_dst() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_V4[0], EXT_V4[1], EXT_V4[2], EXT_V4[3],
    ]
}

/// `[Eth][IPv6][UDP]` guest frame `GUEST_IP6:SPORT` → `64:ff9b::EXT_V4:DPORT` (non-empty payload).
fn udp_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .udp(SPORT, DPORT);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// Load `frame` into a fresh mbuf and run `process_guest_tx_nat64` over `MbufPkt` + `DpdkMaps`.
fn run_dpdk_egress(
    pool: &Mempool,
    maps: &mut DpdkMaps,
    frame: &[u8],
    in_: &GuestTxNat64In,
) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_guest_tx_nat64(&mut mp, maps, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_guest_tx_nat64` over `VecPkt` + `MemMaps`.
fn run_sim_egress(maps: &mut MemMaps, frame: &[u8], in_: &GuestTxNat64In) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_guest_tx_nat64(&mut vp, maps, in_);
    (vp.into_bytes(), action)
}

/// The nat_port the egress allocator picks for the TCP 5-tuple — mirrors nat64_test.rs.
fn expected_nat_port() -> u16 {
    use flowplane_core::parse::hash5;
    const PORT_MIN: u16 = 20000;
    const PORT_MAX: u16 = 20512;
    let range = (PORT_MAX - PORT_MIN) as u32;
    let start = (hash5(&GUEST_IP, &EXT_V4, SPORT, DPORT, IPPROTO_TCP) % range) as u16;
    PORT_MIN.wrapping_add(start)
}

#[test]
fn dpdk_nat64_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pn64",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pn64_pool", 1023, 250, 0).expect("pool");

    // ───────────────── Scenario (ingress): external TCP reply → guest IPv6 ─────────────────
    {
        let nat_port = expected_nat_port();
        let inner = inner_reply(nat_port);
        let frame = encap_reply(&inner);
        let rev = rev_ct(SPORT);
        let in_ = UplinkNat64IngressIn {
            tap_ifindex: TAP_IFINDEX,
            guest_mac: GUEST_MAC,
            guest_ipv6: GUEST_IP6,
            rev: &rev,
        };

        let (out_sim, a_sim) = run_sim(&frame, &in_);
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &frame, &in_);

        // POSITIVE delivery (guards against a trivial both-drop/both-pass), asserted before byte-cmp.
        assert_eq!(
            a_sim,
            Action::Redirect(TAP_IFINDEX),
            "(ingress) sim: TCP NAT64 reply delivered to the guest tap"
        );
        assert_eq!(a_dpdk, a_sim, "(ingress) action parity");
        assert_eq!(out_dpdk, out_sim, "(ingress) output frame byte parity");
        // Sanity: net -20 bytes; guest-facing dst MAC = guest MAC; ethertype IPv6.
        assert_eq!(out_dpdk.len(), frame.len() - 20, "(ingress) net -20 bytes");
        assert_eq!(&out_dpdk[0..6], &GUEST_MAC, "(ingress) dst MAC = guest MAC");
        assert_eq!(
            &out_dpdk[12..14],
            &0x86DDu16.to_be_bytes(),
            "(ingress) ethertype IPv6"
        );
    }

    // ───────────────── Scenario (egress): guest IPv6 → external IPv4, SNAT + encap ─────────────
    // Exercises the port-allocation parity: both map impls start EMPTY and are populated
    // IDENTICALLY, so the hash-probe source-port allocator lands on the same port on both sides.
    // The FULL encapped output embeds the allocated port and exercises shrink_head + grow_head.
    {
        let frame = udp_frame();
        let meta = egress_port_meta();
        let local = egress_local();

        // Populate MemMaps and DpdkMaps identically (both start empty).
        let mut mem = MemMaps {
            local: Some(local),
            ..Default::default()
        };
        mem.nat.insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP,
            },
            NatValue {
                nat_ipv4: NAT_IP,
                port_min: PORT_MIN,
                port_max: PORT_MAX,
            },
        );
        mem.add_route4(VNI, EXT_V4, egress_route_value());

        let mut dpdk = DpdkMaps::new(0).expect("dpdk maps");
        dpdk.set_local(local);
        dpdk.add_nat(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP,
            },
            NatValue {
                nat_ipv4: NAT_IP,
                port_min: PORT_MIN,
                port_max: PORT_MAX,
            },
        );
        dpdk.add_route4(VNI, EXT_V4, egress_route_value());

        let in_ = GuestTxNat64In {
            meta: &meta,
            local: &local,
        };

        let (out_sim, a_sim) = run_sim_egress(&mut mem, &frame, &in_);
        let (out_dpdk, a_dpdk) = run_dpdk_egress(&pool, &mut dpdk, &frame, &in_);

        // POSITIVE redirect out the uplink (guards against a trivial both-drop/both-pass).
        assert_eq!(
            a_sim,
            Action::Redirect(UPLINK_IFINDEX),
            "(egress) sim: NAT64 egress encaps out the uplink"
        );
        assert_eq!(a_dpdk, a_sim, "(egress) action parity");
        // Full encapped frame byte parity → proves identical allocated source port.
        assert_eq!(out_dpdk, out_sim, "(egress) output frame byte parity");

        // Sanity: outer IPv6 version nibble == 6; outer dst == route nexthop underlay.
        assert_eq!(
            out_dpdk[ETH_LEN] & 0xf0,
            0x60,
            "(egress) outer IPv6 version 6"
        );
        assert_eq!(
            &out_dpdk[ETH_LEN + 24..ETH_LEN + 40],
            &NEXTHOP_UNDERLAY,
            "(egress) outer IPv6 dst = route nexthop underlay"
        );
    }
}
