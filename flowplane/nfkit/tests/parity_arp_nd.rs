//! DPDK ARP/ND byte-parity anchor. For a guest ARP request / ICMPv6 Neighbor Solicitation for the
//! virtual gateway (and a plain non-ARP/ND frame), assert `process_guest_arp_nd` over
//! `MbufPkt` produces a byte-identical output frame + identical `Action` to `VecPkt`. This proves the
//! shared `flowplane_core::datapath::process_guest_arp_nd` responder runs identically on the DPDK
//! substrate. `process_guest_arp_nd` takes NO maps, so the runners are map-less.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running three scenarios
//! sequentially. Run with `--test-threads=1`.

use flowplane_core::datapath::{process_guest_arp_nd, GuestArpNdIn};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::VecPkt;
use nfkit::{Eal, MbufPkt, Mempool};

// ── addressing / fixtures (mirroring flowplane-sim/src/arp_nd_test.rs) ────────
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1];
const GATEWAY_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const REQUESTER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const REQUESTER_IPV4: [u8; 4] = [10, 0, 0, 42];
const REQUESTER_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
const INGRESS_IFINDEX: u32 = 7;

const ETH_LEN: usize = 14;
const IPV6_LEN: usize = 40;
const ARP_LEN: usize = 28;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_ICMPV6: u8 = 58;

fn arp_nd_in() -> GuestArpNdIn {
    GuestArpNdIn {
        gateway_ipv4: GATEWAY_IPV4,
        gateway_ipv6: GATEWAY_IPV6,
        ingress_ifindex: INGRESS_IFINDEX,
    }
}

/// A guest ARP REQUEST `who-has GATEWAY_IPV4 tell REQUESTER_IPV4` (broadcast). Ethernet + 28-byte ARP.
fn arp_request_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + ARP_LEN];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    let a = ETH_LEN;
    f[a..a + 2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
    f[a + 2..a + 4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
    f[a + 4] = 6; // hlen
    f[a + 5] = 4; // plen
    f[a + 6..a + 8].copy_from_slice(&1u16.to_be_bytes()); // opcode = request
    f[a + 8..a + 14].copy_from_slice(&REQUESTER_MAC); // sha
    f[a + 14..a + 18].copy_from_slice(&REQUESTER_IPV4); // spa
    f[a + 24..a + 28].copy_from_slice(&GATEWAY_IPV4); // tpa = gateway
    f
}

/// A guest ICMPv6 Neighbor Solicitation for GATEWAY_IPV6. Ethernet + 40-byte IPv6 + 32-byte ICMPv6.
fn ns_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + IPV6_LEN + 32];
    f[0..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 0x42]); // solicited-node multicast dst MAC
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    f[ip] = 0x60;
    f[ip + 4..ip + 6].copy_from_slice(&32u16.to_be_bytes()); // payload length
    f[ip + 6] = IPPROTO_ICMPV6;
    f[ip + 7] = 255;
    f[ip + 8..ip + 24].copy_from_slice(&REQUESTER_IPV6); // src
    f[ip + 24..ip + 40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0x01]);
    let ic = ETH_LEN + IPV6_LEN;
    f[ic] = 135; // NS
    f[ic + 8..ic + 24].copy_from_slice(&GATEWAY_IPV6); // target
    f[ic + 24] = 1; // source LL addr option
    f[ic + 25] = 1;
    f[ic + 26..ic + 32].copy_from_slice(&REQUESTER_MAC);
    f
}

/// A plain IPv4/UDP frame (not ARP, not ND) — the responder must leave it untouched and `Pass`.
fn plain_udp_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + 20 + 8];
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // dst = gateway MAC
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
    let ip = ETH_LEN;
    f[ip] = 0x45; // version 4, ihl 5
    f[ip + 2..ip + 4].copy_from_slice(&28u16.to_be_bytes()); // total length
    f[ip + 8] = 64; // ttl
    f[ip + 9] = 17; // UDP
    f[ip + 12..ip + 16].copy_from_slice(&REQUESTER_IPV4); // src
    f[ip + 16..ip + 20].copy_from_slice(&GATEWAY_IPV4); // dst
    let u = ETH_LEN + 20;
    f[u..u + 2].copy_from_slice(&5000u16.to_be_bytes()); // sport
    f[u + 2..u + 4].copy_from_slice(&53u16.to_be_bytes()); // dport
    f[u + 4..u + 6].copy_from_slice(&8u16.to_be_bytes()); // length
    f
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to data-pointer moves).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

/// Load `frame` into a fresh mbuf and run `process_guest_arp_nd` over `MbufPkt`, returning the
/// resulting frame bytes + `Action`.
fn run_dpdk(pool: &Mempool, frame: &[u8], in_: &GuestArpNdIn) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_guest_arp_nd(&mut mp, in_);
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_guest_arp_nd` over `VecPkt`, returning the resulting frame bytes + `Action`.
fn run_sim(frame: &[u8], in_: &GuestArpNdIn) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_guest_arp_nd(&mut vp, in_);
    (vp.into_bytes(), action)
}

#[test]
fn dpdk_arp_nd_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pan",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pan_pool", 1023, 250, 0).expect("pool");

    // ───────────────── Scenario (a): ARP request → ARP reply ─────────────────
    {
        let frame = arp_request_frame();
        let (out_sim, a_sim) = run_sim(&frame, &arp_nd_in());
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &frame, &arp_nd_in());

        assert_eq!(
            a_sim,
            Action::Redirect(INGRESS_IFINDEX),
            "(a) sim: ARP reply reflected via ingress ifindex"
        );
        assert_eq!(a_dpdk, a_sim, "(a) action parity");
        assert_eq!(out_dpdk, out_sim, "(a) ARP reply byte parity");
    }

    // ───────────────── Scenario (b): ND NS → Neighbor Advertisement ─────────────────
    {
        let frame = ns_frame();
        let (out_sim, a_sim) = run_sim(&frame, &arp_nd_in());
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &frame, &arp_nd_in());

        assert_eq!(
            a_sim,
            Action::Redirect(INGRESS_IFINDEX),
            "(b) sim: NA reflected via ingress ifindex"
        );
        assert_eq!(a_dpdk, a_sim, "(b) action parity");
        assert_eq!(out_dpdk, out_sim, "(b) NA byte parity");
    }

    // ───────────────── Scenario (c): plain IPv4 UDP → Pass, unchanged ─────────────────
    {
        let frame = plain_udp_frame();
        let (out_sim, a_sim) = run_sim(&frame, &arp_nd_in());
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &frame, &arp_nd_in());

        assert_eq!(a_sim, Action::Pass, "(c) sim: non-ARP/ND frame passes");
        assert_eq!(a_dpdk, a_sim, "(c) action parity");
        assert_eq!(out_sim, frame, "(c) sim frame unchanged");
        assert_eq!(out_dpdk, out_sim, "(c) frame byte parity (both == input)");
    }
}
