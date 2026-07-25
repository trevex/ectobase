//! Multi-lcore NAT-return demux across the shared reverse-conntrack table.
//!
//! ── THE BUG THIS PROVES ───────────────────────────────────────────────────────────────────────
//! DPDK conntrack is PER-LCORE shared-nothing ([`PerLcoreFlowMaps`], composed per-worker into a
//! [`ComposedMaps`]). A SNAT/NAT64 egress installs the PEER-INDEPENDENT reverse entry
//! `(vni, 0, nat_ip, 0, nat_port)` (via `snat_egress` → `conntrack_insert`) into the conntrack table
//! of the lcore that processed the guest's OUTBOUND packet. The external reply arrives on the uplink
//! and is steered to a queue/lcore by the NIC's RSS over the OUTER/underlay headers — which has no
//! relationship to the inner flow tuple the reverse entry was keyed under. If the reply lands on a
//! DIFFERENT lcore, a per-lcore-only `conntrack_get(rev)` MISSES → the return is treated as a new
//! inbound flow (ingress-firewall drop / no reverse-DNAT).
//!
//! ── HOW IT'S PROVEN (no hardware; one EAL init; single-threaded) ──────────────────────────────
//! The bug is about WHICH TABLE the reverse entry lives in, not about thread scheduling, so it is
//! proven with two `PerLcoreFlowMaps` instances (lcore A + lcore B) sharing ONE `SharedConfigMaps`,
//! driven on the main thread. Registering the reverse CT via `ComposedMaps::conntrack_insert` on A
//! is EXACTLY the call `snat_egress` makes on the guest's outbound packet (same key + entry as the
//! `parity_nat_return` anchor). Then `process_uplink_rx` runs on B's composed maps with the matching
//! encapped WAN return:
//!   * `cross_lcore_nat_return_resolves` (the FIX assertion): B resolves the reverse entry via the
//!     SHARED table → reverse-DNAT fires → `Redirect(TAP)` with the inner dst restored to GUEST_IP.
//!   * `same_lcore_nat_return_still_resolves`: the return landing on A (the egress lcore) still
//!     resolves — the shared table does not regress the same-lcore path.
//!   * `normal_forward_ct_stays_per_lcore`: a plain (non-NAT, real-src) forward CT created on A is
//!     NOT visible on B — the per-lcore fast path stays shared-nothing (the M8 isolation property).
//!
//! Before the fix, `cross_lcore_nat_return_resolves` FAILS (B misses → base-path ingress-firewall
//! drop, inner dst never restored). Run with `--test-threads=1` (EAL is process-global).

use etherparse::PacketBuilder;
use flowplane_common::{CtEntry, CtKey, Local, UnderlayValue, CT_F_SRC_NAT, CT_REWRITE_DST};
use flowplane_core::datapath::{process_uplink_rx, UplinkIn};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::SimNode;
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

// ── DNAT fixture (mirrors parity_nat_return.rs / flowplane-sim nat_test.rs) ───
const DNAT_VNI: u32 = 100;
const DNAT_TAP: u32 = 42;
const DNAT_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const DNAT_GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const DNAT_NAT_IP: [u8; 4] = [198, 51, 100, 7];
const DNAT_EXT_IP: [u8; 4] = [203, 0, 113, 9];
const DNAT_ORIG_SPORT: u16 = 40000; // restored inner dst port after reverse-DNAT
const DNAT_NAT_PORT: u16 = 20018; // allocated NAT port (inner dst port in the returning packet)
const DNAT_EXT_PORT: u16 = 443; // external peer's port (inner src port, unchanged)

const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

/// The reverse CT entry `snat_egress` pins: `(vni,0,nat_ip,0,nat_port)` → `CT_REWRITE_DST |
/// CT_F_SRC_NAT`, `xlate_ip = guest_ip`, `xlate_port = orig_sport`.
fn dnat_reverse_ct_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: DNAT_GUEST_IP,
        xlate_port: DNAT_ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    }
}

fn dnat_reverse_ct_key(proto: u8) -> CtKey {
    CtKey {
        vni: DNAT_VNI,
        src_ip: [0; 4],
        dst_ip: DNAT_NAT_IP,
        src_port: 0,
        dst_port: DNAT_NAT_PORT,
        proto,
        _pad: [0; 3],
    }
}

/// Encapsulate an inner Eth+IPv4 returning frame IP-in-IPv6 toward the host underlay, via the REAL
/// `SimNode::edge_encap`.
fn encap_return(inner: &[u8]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: EDGE_UNDERLAY,
            nexthop_ipv6: HOST_UNDERLAY,
            inner_proto: 4, // IPPROTO_IPIP
            flow_label: 0,
        },
    )
}

/// The encapped returning TCP frame: inner `EXT_IP:EXT_PORT → NAT_IP:NAT_PORT` (as it arrives from
/// the peer), payload = 4 bytes so the L4 checksum is non-trivial.
fn dnat_tcp_encapped() -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(DNAT_EXT_IP, DNAT_NAT_IP, 64)
        .tcp(DNAT_EXT_PORT, DNAT_NAT_PORT, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    encap_return(&frame)
}

fn zero_local() -> Local {
    Local {
        uplink_ifindex: 0,
        uplink_mac: [0; 6],
        gateway_mac: [0; 6],
        underlay_ipv6: [0; 16],
    }
}

/// Run `process_uplink_rx` over `MbufPkt` + the given composed maps; return the delivered bytes +
/// action.
fn run_uplink_rx(pool: &Mempool, maps: &mut ComposedMaps, frame: &[u8]) -> (Vec<u8>, Action) {
    let u = UnderlayValue {
        vni: DNAT_VNI,
        tap_ifindex: DNAT_TAP,
        guest_mac: DNAT_GUEST_MAC,
        _pad: [0; 2],
    };
    let local = zero_local();
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_uplink_rx(
        &mut mp,
        maps,
        &UplinkIn {
            vni: DNAT_VNI,
            u,
            outer_dst: HOST_UNDERLAY,
            local: &local,
            now: 0,
            // Plain (non-NAT64) NAT return: guest_ipv6 is only read on the CT_F_NAT64 branch.
            guest_ipv6: [0; 16],
        },
    );
    let mut out = Vec::with_capacity(mp.len());
    for i in 0..mp.len() {
        out.push(mp.read_array::<1>(i).unwrap()[0]);
    }
    (out, action)
}

/// ONE `#[test]` (EAL is process-global — single init per process). Drives all three sub-checks.
#[test]
fn multilcore_nat_return_shared_reverse_ct() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_mlcnr",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mlcnr_pool", 1023, 250, 0).expect("pool");

    // One shared CONFIG half; the registered nat_ip lives here (all lcores see it).
    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
    assert!(shared.nat_ips_insert(DNAT_VNI, DNAT_NAT_IP));

    let proto: u8 = 6;
    let rev_key = dnat_reverse_ct_key(proto);
    let rev_entry = dnat_reverse_ct_entry();

    // Two lcores' FLOW halves, composed with the ONE shared config half.
    let mut lcore_a = ComposedMaps {
        cfg: &shared,
        flow: PerLcoreFlowMaps::new(0).expect("plf a"),
    };
    let mut lcore_b = ComposedMaps {
        cfg: &shared,
        flow: PerLcoreFlowMaps::new(0).expect("plf b"),
    };

    // ── egress on lcore A: pin the SNAT reverse entry (exactly `snat_egress`'s call) ──
    lcore_a.conntrack_insert(rev_key, rev_entry);

    // ── (1) cross-lcore: the WAN return lands on lcore B (RSS over outer headers) ──────
    // With the FIX, B resolves the reverse entry via the SHARED table → reverse-DNAT + deliver.
    let frame = dnat_tcp_encapped();
    let (out_b, act_b) = run_uplink_rx(&pool, &mut lcore_b, &frame);
    assert_eq!(
        act_b,
        Action::Redirect(DNAT_TAP),
        "cross-lcore NAT return must resolve the shared reverse entry and reverse-DNAT to the tap \
         (pre-fix: per-lcore miss → base-path ingress-firewall DROP)"
    );
    let inner_ip_off = flowplane_core::encap::ETH_LEN; // 14
    assert_eq!(
        &out_b[inner_ip_off + 16..inner_ip_off + 20],
        &DNAT_GUEST_IP,
        "cross-lcore: inner dst reverse-DNAT'd to the guest IP"
    );

    // ── (2) same-lcore: the return landing on A (the egress lcore) still resolves ────
    let (out_a, act_a) = run_uplink_rx(&pool, &mut lcore_a, &frame);
    assert_eq!(
        act_a,
        Action::Redirect(DNAT_TAP),
        "same-lcore NAT return still resolves (shared table must not regress the local path)"
    );
    assert_eq!(
        &out_a[inner_ip_off + 16..inner_ip_off + 20],
        &DNAT_GUEST_IP,
        "same-lcore: inner dst reverse-DNAT'd to the guest IP"
    );

    // ── (3) per-lcore fast path stays shared-nothing for NORMAL (real-src) forward CT ──
    // A plain forward CT (non-NAT: real src_ip + src_port) created on A must NOT be visible on B.
    let fwd_key = CtKey {
        vni: DNAT_VNI,
        src_ip: [10, 9, 0, 1],
        dst_ip: DNAT_GUEST_IP,
        src_port: 40000,
        dst_port: 443,
        proto: 6,
        _pad: [0; 3],
    };
    let fwd_entry = CtEntry {
        last_seen: 0,
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: 0, // no CT_REWRITE_* → a plain tracked flow, not a NAT reverse entry
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    };
    lcore_a.conntrack_insert(fwd_key, fwd_entry);
    assert_eq!(
        lcore_a.conntrack_get(&fwd_key),
        Some(fwd_entry),
        "normal forward CT is present on its own lcore"
    );
    assert_eq!(
        lcore_b.conntrack_get(&fwd_key),
        None,
        "normal forward CT stays PER-LCORE (not visible on another lcore — M8 isolation preserved)"
    );
}
