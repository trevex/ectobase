//! RSS l2fwd: rx a burst, swap src/dst MAC, tx it back — one worker per queue via LcoreRuntime.
//!   cargo run -p nfkit --example l2fwd -- pcap in.pcap out.pcap
//!   cargo run -p nfkit --example l2fwd -- afxdp vv0
//!   cargo run -p nfkit --example l2fwd -- null
use nfkit::{Backend, Eal, LcoreRuntime, MbufBurst, Mempool, Port};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

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

    let _eal = Eal::init(backend.eal_args("nfkit-l2fwd")).expect("EAL init");
    let pool = Mempool::new("l2fwd", 8191, 250, 0).expect("pool");
    let requested = nfkit::worker_lcore_count().max(1);
    let port = Port::configure(0, requested, &pool).expect("configure port 0");
    let nq = port.n_queues();

    LcoreRuntime::for_each_worker(nq, |queue_id| {
        let (mut rx, mut tx) = port.queue(queue_id);
        let mut burst = MbufBurst::new();
        let mut idle = 0u32;
        while !STOP.load(Ordering::Relaxed) {
            burst.clear();
            let n = rx.rx(&mut burst);
            if n == 0 {
                idle += 1;
                if is_pcap && idle > 1000 {
                    break; // pcap drained
                }
                continue;
            }
            idle = 0;
            for m in burst.iter_mut() {
                if m.len() >= 12 {
                    let d = m.data_mut();
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&d[0..6]);
                    d.copy_within(6..12, 0); // dst = old src
                    d[6..12].copy_from_slice(&mac); // src = old dst
                }
            }
            while !burst.is_empty() {
                let sent = tx.tx(&mut burst);
                if sent == 0 {
                    break; // ring full; drop remainder (kept simple for this example)
                }
            }
        }
    });
    println!("l2fwd done");
}
