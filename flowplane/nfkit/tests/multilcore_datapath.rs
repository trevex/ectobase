//! Shared-nothing per-lcore state: N worker lcores each run `process_uplink` over their OWN DpdkMaps
//! on an in-process batch of distinct flows. Asserts (a) each worker's decapped output is byte-
//! identical to the sim, and (b) conntrack isolation — a worker's map holds ITS flows, none of the
//! others'. Runs --no-huge, -l 0-4 (4 workers). Run with --test-threads=1.
//!
//! The base decap → local-deliver path of `process_uplink` (non-LB) DOES create conntrack
//! (datapath.rs step 3: `ct_create_default` on miss), keyed via `ct_key` on the inner IPv4 5-tuple
//! (src_ip, dst_ip, host-order TCP sport=40000, dport=DST_PORT, proto=6). The isolation assertion
//! rebuilds that exact key per (worker, flow) and checks presence in each worker's own map.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, FwMeta, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS,
};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{worker_lcore_count, DpdkMaps, Eal, LcoreRuntime, MbufPkt, Mempool};
use std::sync::Mutex;

// ── addressing (copied verbatim from parity_uplink.rs) ───────────────────────
const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const DST_PORT: u16 = 443;
const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

const N_WORKERS: u16 = 4;
const FLOWS_PER_WORKER: u16 = 4;

/// A full inner Ethernet frame `[Eth][IPv4][TCP]` src→dst on `dport`, TCP sport = 40000.
fn inner_frame(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Encapsulate an inner Eth+IPv4 frame IP-in-IPv6 toward `dst_ul` (fabric wire format), reusing the
/// REAL `SimNode::edge_encap`.
fn encap_to(inner: &[u8], dst_ul: [u8; 16]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: EDGE_UL,
            nexthop_ipv6: dst_ul,
            inner_proto: 4, // IPPROTO_IPIP
            flow_label: 0,
        },
    )
}

// ── firewall allow rule (installed identically on both map impls) ────────────
fn allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 1,
        egress_count: 0,
    }
}
fn allow_rule(port: u16) -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: GUEST_IP,
        dst_mask: [255, 255, 255, 255],
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
    }
}

fn zero_local() -> Local {
    Local {
        uplink_ifindex: 0,
        uplink_mac: [0; 6],
        gateway_mac: [0; 6],
        underlay_ipv6: [0; 16],
    }
}

/// Distinct inner-src IP per (worker, flow) → distinct CT keys; same dst GUEST_IP so the one fw
/// allow rule matches all of them.
fn flow_src(worker: u16, flow: u16) -> [u8; 4] {
    [10, 9, worker as u8, (flow + 1) as u8]
}

/// Is the (worker,flow) inner 5-tuple present in `maps`' conntrack? Builds the EXACT key that
/// `flowplane_core::conntrack::ct_key` derives for this uplink base-decap flow: VNI + inner IPv4
/// src/dst + host-order TCP ports (sport 40000 from `inner_frame`, dport DST_PORT) + proto 6.
fn ct_present(maps: &DpdkMaps, worker: u16, flow: u16) -> bool {
    let k = CtKey {
        vni: VNI,
        src_ip: flow_src(worker, flow),
        dst_ip: GUEST_IP,
        src_port: 40000,
        dst_port: DST_PORT,
        proto: 6,
        _pad: [0; 3],
    };
    Maps::conntrack_get(maps, &k).is_some()
}

/// Sim reference output for a flow (VecPkt + MemMaps) — the byte-parity oracle.
fn sim_uplink(src: [u8; 4]) -> Vec<u8> {
    let frame = encap_to(&inner_frame(src, GUEST_IP, DST_PORT), HOST_UL);
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(TAP, allow_meta());
    sim.fw_rules.insert((TAP, 0), allow_rule(DST_PORT));
    let u = UnderlayValue {
        vni: VNI,
        tap_ifindex: TAP,
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
    };
    let zl = zero_local();
    let mut vp = VecPkt::from_bytes(&frame);
    let a = process_uplink(
        &mut vp,
        &mut sim,
        &UplinkIn {
            vni: VNI,
            u,
            outer_dst: HOST_UL,
            local: &zl,
            now: 0,
        },
    );
    assert_eq!(a, Action::Redirect(TAP));
    vp.into_bytes()
}

#[derive(Default)]
struct WorkerOut {
    outputs: Vec<Vec<u8>>,
    own_ct_hits: usize,
    foreign_ct_hits: usize,
}

#[test]
fn multilcore_per_lcore_state() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-4",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_mlc",
    ])
    .expect("EAL init");
    // N_WORKERS=4 needs ≥4 worker lcores (main + 4 = -l 0-4). Skip cleanly if the host is too small.
    if worker_lcore_count() < N_WORKERS {
        eprintln!(
            "SKIP multilcore_per_lcore_state: need {N_WORKERS} worker lcores, have {}",
            worker_lcore_count()
        );
        return;
    }
    // rte_pktmbuf_alloc is MT-safe → one shared pool, workers alloc concurrently.
    let pool = Mempool::new("mlc_pool", 8191, 250, 0).expect("pool");
    let results: Vec<Mutex<WorkerOut>> = (0..N_WORKERS)
        .map(|_| Mutex::new(WorkerOut::default()))
        .collect();

    LcoreRuntime::for_each_worker(N_WORKERS, |q| {
        // Each worker builds its OWN DpdkMaps (unique rte_hash names, auto) + a fw allow on TAP.
        let mut maps = DpdkMaps::new(0).expect("per-lcore DpdkMaps");
        maps.add_fw_meta(TAP, allow_meta());
        maps.add_fw_rule(TAP, 0, allow_rule(DST_PORT));
        let u = UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        };
        let zl = zero_local();

        let mut out = WorkerOut::default();
        for f in 0..FLOWS_PER_WORKER {
            let frame = encap_to(&inner_frame(flow_src(q, f), GUEST_IP, DST_PORT), HOST_UL);
            let mut mb = pool.alloc().expect("alloc mbuf");
            mb.append(frame.len() as u16).expect("append");
            mb.data_mut().copy_from_slice(&frame);
            let mut mp = MbufPkt::new(&mut mb);
            let action = process_uplink(
                &mut mp,
                &mut maps,
                &UplinkIn {
                    vni: VNI,
                    u,
                    outer_dst: HOST_UL,
                    local: &zl,
                    now: 0,
                },
            );
            // Record output bytes — do NOT assert here (a worker panic ABORTS the process).
            if action == Action::Redirect(TAP) {
                let mut bytes = Vec::with_capacity(mp.len());
                for i in 0..mp.len() {
                    bytes.push(mp.read_array::<1>(i).unwrap()[0]);
                }
                out.outputs.push(bytes);
            }
        }
        // Isolation snapshot: our flows present, EVERY other worker's flows absent (loop over ALL
        // `other != q`, not just the neighbour — the shared-nothing proof must hold pairwise).
        for f in 0..FLOWS_PER_WORKER {
            if ct_present(&maps, q, f) {
                out.own_ct_hits += 1;
            }
            for other in 0..N_WORKERS {
                if other != q && ct_present(&maps, other, f) {
                    out.foreign_ct_hits += 1;
                }
            }
        }
        *results[q as usize].lock().unwrap() = out;
    });

    // Assert on the MAIN thread (post-join).
    for q in 0..N_WORKERS {
        let out = results[q as usize].lock().unwrap();
        assert_eq!(
            out.outputs.len(),
            FLOWS_PER_WORKER as usize,
            "worker {q}: all flows delivered to tap"
        );
        assert_eq!(
            out.own_ct_hits, FLOWS_PER_WORKER as usize,
            "worker {q}: own flows tracked in its conntrack"
        );
        assert_eq!(
            out.foreign_ct_hits, 0,
            "worker {q}: NO foreign flows (shared-nothing per-lcore isolation)"
        );
        // Byte-parity vs sim for each flow.
        for (f, got) in out.outputs.iter().enumerate() {
            let expected = sim_uplink(flow_src(q, f as u16));
            assert_eq!(
                *got, expected,
                "worker {q} flow {f}: DPDK != sim byte parity"
            );
        }
    }
}
