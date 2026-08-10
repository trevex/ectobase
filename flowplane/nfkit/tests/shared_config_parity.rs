//! Deployable-DPDK-dataplane vertical slice: config programmed via DpdkMapWriter+ControlCore (the gRPC-handler path),
//! datapath run on N lcores over SharedConfigMaps + per-lcore flow state, asserted byte-identical
//! to the sim AND conntrack-isolated across lcores. Extends DPDK==sim==eBPF through the control path.
//!
//! This mirrors `multilcore_datapath.rs` EXACTLY (same addressing, same flows, same sim oracle, same
//! isolation assertion) with ONE structural change: the datapath config is NOT populated directly
//! into per-lcore `DpdkMaps`. Instead it is programmed ONCE, process-wide, through
//! `ControlCore<DpdkMapWriter>` — the SAME control API the T9 gRPC handlers drive — into a shared
//! `SharedConfigMaps`. Every worker lcore then composes that read-only shared config with its OWN
//! `PerLcoreFlowMaps` (conntrack/meter) and runs the SAME `flowplane_core::process_uplink`. Proving
//! the worker output frames are byte-identical to the sim proves the CONTROL path (not just the
//! datapath) yields byte-correct datapath behavior.
//!
//! The base decap → local-deliver path of `process_uplink` (non-LB) creates conntrack (datapath.rs
//! step 3: `ct_create_default` on miss), keyed via `ct_key` on the inner IPv4 5-tuple. The isolation
//! assertion rebuilds that exact key per (worker, flow) against each worker's OWN per-lcore flow map.
#![cfg(test)]

use etherparse::PacketBuilder;
use flowplane_common::{CtKey, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_control::{shadow::IfaceMeta, ControlCore};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_dpdk::writer::DpdkMapWriter;
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{
    worker_lcore_count, ComposedMaps, Eal, LcoreRuntime, MbufPkt, Mempool, PerLcoreFlowMaps,
    SharedConfigMaps,
};
use std::sync::{Arc, Mutex};

// ── addressing (copied verbatim from multilcore_datapath.rs) ─────────────────
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

// ── firewall allow rule (the fixture — installed via ControlCore on the DPDK side, direct on sim) ─
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

/// Program the fixture config into `shared` THROUGH `ControlCore<DpdkMapWriter>` — the SAME control
/// API the T9 gRPC handlers drive. The datapath's base decap → local-deliver path reads exactly the
/// firewall (FW_META + FW_RULES) on TAP, so the fixture is:
///   1. `register_iface_meta` — mirror the interface metadata so `add_fw_rule` can resolve the
///      interface_id → ifindex (TAP) it keys FW_RULES/FW_META by (the eBPF `create_interface` does
///      the same mirror). `ipv4 = GUEST_IP` so a NAT/VIP-by-overlay lookup would resolve too.
///   2. `add_fw_rule` — one ingress ACCEPT rule on TAP for dst GUEST_IP:DST_PORT. `add_fw_rule`
///      writes FW_RULES[TAP,0] = the rule AND reprograms FW_META{ingress_count:1, egress_count:0},
///      byte-identical to the direct `add_fw_meta`/`add_fw_rule` fixture in multilcore_datapath.
fn program_fixture_via_control(shared: &Arc<SharedConfigMaps>) {
    let mut core = ControlCore::new(DpdkMapWriter::new(shared.clone()));
    core.register_iface_meta(
        b"if-tap".to_vec(),
        IfaceMeta {
            vni: VNI,
            ipv4: GUEST_IP,
            ipv6: [0u8; 16],
            underlay: HOST_UL,
            ifindex: TAP,
        },
    );
    core.add_fw_rule(b"if-tap", b"allow-443".to_vec(), allow_rule(DST_PORT))
        .expect("add_fw_rule via ControlCore");
    // `core` (and the DpdkMapWriter it owns) is dropped here — the shared maps now hold the config,
    // exactly the state the datapath lcores will read through their own Arc.
}

/// Distinct inner-src IP per (worker, flow) → distinct CT keys; same dst GUEST_IP so the one fw
/// allow rule matches all of them.
fn flow_src(worker: u16, flow: u16) -> [u8; 4] {
    [10, 9, worker as u8, (flow + 1) as u8]
}

/// Sim reference output for a flow (VecPkt + MemMaps) — the byte-parity oracle. Identical to
/// multilcore_datapath's `sim_uplink`: the sim's MemMaps is populated DIRECTLY (the sim is the
/// oracle; the DPDK side is what goes through the control path). Both must land the SAME map state.
fn sim_uplink(src: [u8; 4]) -> Vec<u8> {
    let frame = encap_to(&inner_frame(src, GUEST_IP, DST_PORT), HOST_UL);
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(
        TAP,
        flowplane_common::FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
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
            guest_ipv6: [0; 16],
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
#[ignore = "requires EAL --no-huge"]
fn multilcore_config_via_writer_parity_and_isolation() {
    let _eal = Eal::init([
        "nfkit-scp",
        "-l",
        "0-4",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_scp",
    ])
    .expect("EAL init");
    // N_WORKERS=4 needs ≥4 worker lcores (main + 4 = -l 0-4). Skip cleanly if the host is too small.
    if worker_lcore_count() < N_WORKERS {
        eprintln!(
            "SKIP multilcore_config_via_writer_parity_and_isolation: need {N_WORKERS} worker lcores, have {}",
            worker_lcore_count()
        );
        return;
    }

    // ── ONE process-wide SharedConfigMaps, programmed ONCE through the CONTROL path ──────────────
    // This is the structural difference vs multilcore_datapath: the fixture is written via
    // ControlCore<DpdkMapWriter> (the gRPC-handler path), NOT populated into per-lcore DpdkMaps.
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    program_fixture_via_control(&shared);

    // rte_pktmbuf_alloc is MT-safe → one shared pool, workers alloc concurrently.
    let pool = Mempool::new("scp_pool", 8191, 250, 0).expect("pool");
    let results: Vec<Mutex<WorkerOut>> = (0..N_WORKERS)
        .map(|_| Mutex::new(WorkerOut::default()))
        .collect();

    LcoreRuntime::for_each_worker(N_WORKERS, |q| {
        // Each worker composes the SHARED (read-only) config half with its OWN per-lcore FLOW half.
        let flow = PerLcoreFlowMaps::new(0).expect("per-lcore flow");
        let mut maps = ComposedMaps { cfg: &shared, flow };
        // Register as a QSBR reader on the shared config (lock-free reads + RCU grace-period progress).
        let tok = shared.register_reader();

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
                    guest_ipv6: [0; 16],
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
        // Isolation snapshot: our flows present in OUR conntrack, EVERY other worker's flows absent.
        // Conntrack lives entirely in the per-lcore `flow` half, so a lookup through `maps`
        // (ComposedMaps) reads only this worker's flow state.
        for f in 0..FLOWS_PER_WORKER {
            let mine = CtKey {
                vni: VNI,
                src_ip: flow_src(q, f),
                dst_ip: GUEST_IP,
                src_port: 40000,
                dst_port: DST_PORT,
                proto: 6,
                _pad: [0; 3],
            };
            if maps.conntrack_get(&mine).is_some() {
                out.own_ct_hits += 1;
            }
            for other in 0..N_WORKERS {
                if other == q {
                    continue;
                }
                let foreign = CtKey {
                    vni: VNI,
                    src_ip: flow_src(other, f),
                    dst_ip: GUEST_IP,
                    src_port: 40000,
                    dst_port: DST_PORT,
                    proto: 6,
                    _pad: [0; 3],
                };
                if maps.conntrack_get(&foreign).is_some() {
                    out.foreign_ct_hits += 1;
                }
            }
        }
        // Report quiescence so the writer's deferred RCU frees can make progress (none pending here,
        // but this is the required reader-loop contract).
        shared.report_quiescent(&tok);
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
        // Byte-parity vs sim for each flow — the headline proof: DPDK-via-control-path == sim.
        for (f, got) in out.outputs.iter().enumerate() {
            let expected = sim_uplink(flow_src(q, f as u16));
            assert_eq!(
                *got, expected,
                "worker {q} flow {f}: DPDK(control-path) != sim byte parity"
            );
        }
    }
}
