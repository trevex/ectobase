//! net_pcap uplink datapath forwarder: rx a burst, run the SHARED
//! `flowplane_core::datapath::process_uplink` over each frame with a fixed `DpdkMaps` + `UplinkIn`
//! populated at startup, and tx the decapped result — one worker per queue via LcoreRuntime.
//!   cargo run -p nfkit --example uplink_fwd -- pcap in.pcap out.pcap
//!   cargo run -p nfkit --example uplink_fwd -- null
//!
//! The map/input config here MUST stay byte-for-byte identical to `tests/parity_uplink.rs`
//! scenario (a) (base decap → local delivery, NON-LB) so `tests/datapath_pcap.rs` can re-derive the
//! expected output independently via the sim. The constants are duplicated (not shared) on purpose.
use flowplane_common::{FwMeta, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::Action;
use nfkit::{Backend, DpdkMaps, Eal, LcoreRuntime, MbufBurst, MbufPkt, Mempool, Port};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

// ── addressing (IDENTICAL to parity_uplink.rs scenario (a)) ──────────────────
const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const HOST_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
/// The inner-frame dst TCP port the ingress-FW allow rule matches.
const DST_PORT: u16 = 443;

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

/// Build the fixed `DpdkMaps` for scenario (a): ingress-FW allow on TAP, no LB maps.
fn build_maps() -> DpdkMaps {
    let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new");
    dm.add_fw_meta(TAP, allow_meta());
    dm.add_fw_rule(TAP, 0, allow_rule(DST_PORT));
    dm
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let backend = match a.first().map(String::as_str) {
        Some("pcap") => Backend::Pcap {
            rx: a[1].clone(),
            tx: a[2].clone(),
        },
        Some("afxdp") => Backend::AfXdp {
            iface: a[1].clone(),
            queues: 1,
        },
        Some("tap") => Backend::Tap { name: a[1].clone() },
        _ => Backend::Null,
    };
    let is_pcap = matches!(backend, Backend::Pcap { .. });

    let _eal = Eal::init(backend.eal_args("nfkit-uplinkfwd")).expect("EAL init");
    let pool = Mempool::new("uplinkfwd", 8191, 250, 0).expect("pool");
    let requested = nfkit::worker_lcore_count().max(1);
    let port = Port::configure(0, requested, &pool).expect("configure port 0");
    let nq = port.n_queues();

    // The fixed maps + delivery `UplinkIn` are (re)built INSIDE the per-worker closure so the `Fn`
    // captures no borrowed non-Send state across lcores (one pcap worker here → trivially fine).
    LcoreRuntime::for_each_worker(nq, |queue_id| {
        let (mut rx, mut tx) = port.queue(queue_id);
        // Fixed maps + delivery input, "populated at startup" (per worker here — one pcap queue).
        let mut maps = build_maps();
        let u = UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        };
        let zero_local = Local {
            uplink_ifindex: 0,
            uplink_mac: [0; 6],
            gateway_mac: [0; 6],
            underlay_ipv6: [0; 16],
        };
        let in_ = UplinkIn {
            vni: VNI,
            u,
            outer_dst: HOST_UL,
            local: &zero_local,
            now: 0,
            guest_ipv6: [0; 16],
        };

        let mut rx_burst = MbufBurst::new();
        let mut tx_burst = MbufBurst::new();
        let mut idle = 0u32;
        while !STOP.load(Ordering::Relaxed) {
            rx_burst.clear();
            let n = rx.rx(&mut rx_burst);
            if n == 0 {
                idle += 1;
                if is_pcap && idle > 1000 {
                    break; // pcap drained
                }
                continue;
            }
            idle = 0;
            // Process each rx'd frame through the shared uplink datapath; keep only deliveries.
            for mut m in rx_burst.drain(..) {
                let action = {
                    let mut mp = MbufPkt::new(&mut m);
                    process_uplink(&mut mp, &mut maps, &in_)
                };
                match action {
                    Action::Drop => { /* free by dropping `m` */ }
                    Action::Pass | Action::Redirect(_) => tx_burst.push(m),
                }
            }
            while !tx_burst.is_empty() {
                let sent = tx.tx(&mut tx_burst);
                if sent == 0 {
                    break; // ring full; drop remainder
                }
            }
        }
    });
    println!("uplink_fwd done");
}
