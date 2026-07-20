//! DPDK NAT64 byte-parity anchor. For a crafted frame + inputs, assert the shared
//! `flowplane_core::datapath::process_uplink_nat64_ingress` orchestrator produces a byte-identical
//! output frame + identical `Action` over `MbufPkt` vs `VecPkt`. This proves the NAT64 datapath runs
//! identically on the DPDK substrate.
//!
//! `process_uplink_nat64_ingress` is map-less (`<P: Pkt>`, no `Maps`), so its runners take only the
//! pkt + In-struct; no `DpdkMaps`/`MemMaps` is needed for this scenario.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running scenarios
//! sequentially (Task 4 appends the egress scenario here). Run with `--test-threads=1`.

use etherparse::PacketBuilder;
use flowplane_common::{CtEntry, CT_F_NAT64, CT_F_SRC_NAT, CT_REWRITE_DST};
use flowplane_core::datapath::{process_uplink_nat64_ingress, UplinkNat64IngressIn};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::parse::IPPROTO_TCP;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::VecPkt;
use nfkit::{Eal, MbufPkt, Mempool};

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
        _pad: [0; 7],
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
}
