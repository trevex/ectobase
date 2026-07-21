//! Program a single 5-tuple→DROP `rte_flow` rule on the DPDK net_tap PMD, which lowers it to a
//! kernel tc-flower filter on the backing Linux tap device — then hold the rule briefly so the
//! privileged harness (`hack/dpdk/nettap-flow.sh`) can observe the filter via `tc filter show`.
//!
//!   cargo run -p nfkit --example nettap_flow -- tap <iface>
//!
//! Exit codes: 0 = `RULE OK` (rule created + flushed), 77 = `FLOW UNSUPPORTED` (the PMD returned an
//! unsupported errno, e.g. -ENOSYS/-ENOTSUP — the kernel lacks cls_flower or net_tap flow lowering),
//! 1 = any other error. The chosen dst_ip / dst_port are printed so the harness knows which tc keys
//! to grep for.
use nfkit::{flow_create, ingress_attr, Backend, Eal, Match5Drop, Mempool, Port};

/// The rule's match keys — printed so the harness can grep the resulting tc-flower filter.
const DST_IP: [u8; 4] = [10, 0, 0, 9];
const DST_PORT: u16 = 443;

/// errno magnitudes that mean "this PMD/kernel does not support the rule" → skip (77), not fail.
/// ENOSYS=38, ENOTSUP/EOPNOTSUPP=95 on Linux; rte_flow reports the negative of these.
fn is_unsupported(errno: i32) -> bool {
    matches!(errno.unsigned_abs(), 38 | 95)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let iface = match (a.first().map(String::as_str), a.get(1)) {
        (Some("tap"), Some(name)) => name.clone(),
        _ => {
            eprintln!("usage: nettap_flow tap <iface>");
            std::process::exit(2);
        }
    };

    let backend = Backend::Tap {
        name: iface.clone(),
    };
    let _eal = Eal::init(backend.eal_args("nfkit-nettap-flow")).expect("EAL init");
    let pool = Mempool::new("nettapflow", 1023, 250, 0).expect("pool");
    // net_tap flow lowering is per-queue tc-flower; a single queue is sufficient. `configure` also
    // starts the port (rte_eth_dev_start), which brings the backing tap up.
    let _port = Port::configure(0, 1, &pool).expect("configure port 0");

    // Announce the match keys BEFORE programming so the harness can grep for them regardless of
    // whether the rule lands (e.g. to distinguish a real filter from stale state).
    println!(
        "RULE KEYS dst_ip={}.{}.{}.{} dst_port={} iface={}",
        DST_IP[0], DST_IP[1], DST_IP[2], DST_IP[3], DST_PORT, iface
    );

    let attr = ingress_attr();
    // Bind the holder to a `let` so its spec/mask outlive the create call (rte_flow copies them, but
    // the pointers must be valid for the duration of the call).
    let rule = Match5Drop::new(DST_IP, DST_PORT);

    match flow_create(0, &attr, rule.items(), rule.actions()) {
        Ok(_handle) => {
            // Keep `_handle` alive across the sleep so the rule stays programmed while the harness
            // inspects tc (dropping it would `rte_flow_destroy` immediately).
            println!("RULE OK");
            // Flush stdout so the harness's grep sees `RULE OK` promptly, then hold the rule so tc
            // can be inspected while it is live.
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::thread::sleep(std::time::Duration::from_secs(3));
            std::process::exit(0);
        }
        Err(e) if is_unsupported(e.errno) => {
            println!("FLOW UNSUPPORTED: {e}");
            std::process::exit(77);
        }
        Err(e) => {
            println!("RULE ERROR: {e}");
            std::process::exit(1);
        }
    }
}
