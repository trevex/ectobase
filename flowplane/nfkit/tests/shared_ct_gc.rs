//! Shared reverse-conntrack (`SharedConfigMaps::shared_ct`) IDLE-TIMEOUT GC sweep.
//!
//! ── WHAT THIS EXERCISES ───────────────────────────────────────────────────────────────────────
//! `shared_ct` holds the peer-independent NAT/NAT64 reverse entries `(vni, 0, nat_ip, 0, nat_port)`
//! that a guest's SNAT/NAT64 EGRESS pins so a WAN reply RSS-steered to ANY lcore can resolve the
//! reverse-DNAT. Those entries carry `last_seen` (ns) + `tcp_state`, maintained by `ct_refresh`
//! (the eBPF `ct_touch` port). Without a reclaimer, a long-running node LEAKS reverse-CT entries as
//! flows end: nothing ever removes them.
//!
//! `SharedConfigMaps::shared_ct_sweep_expired(now)` evicts entries idle past their STATE-DEPENDENT
//! timeout, reusing the SAME `flowplane_core::conntrack` model the eBPF/sim datapaths use:
//!   * ESTABLISHED TCP (`tcp_state == TCP_ESTABLISHED`, value 3) → 24 h idle timeout
//!     (`TCP_ESTABLISHED_TIMEOUT_NS`)
//!   * everything else (NEW/SYN, etc.)                            → 30 s idle timeout
//!     (`DEFAULT_TIMEOUT_NS`)
//! Timeouts are in NANOSECONDS; `last_seen` is in nanoseconds; expiry is
//! `now.saturating_sub(last_seen) > timeout` (exactly `flowplane_core::conntrack::ct_is_expired`).
//!
//! DETERMINISM: `now` is a FIXED test value (`100 s` in ns), so the arithmetic is exact — the test
//! NEVER calls the real clock. EAL is process-global → run with `--test-threads=1`.

use flowplane_common::{
    CtEntry, CtKey, CT_F_SRC_NAT, CT_REWRITE_DST, TCP_ESTABLISHED, TCP_NEW_SYN,
};
use nfkit::{Eal, SharedConfigMaps};

const DNAT_VNI: u32 = 100;
/// Guest IP the reverse entry restores the inner dst to (payload; constant across entries).
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];

/// A fixed, deterministic `now`: 100 s in ns. Chosen well past the 60 s `last_seen` offsets below so
/// `now - last_seen` never underflows and the arithmetic is unambiguous.
const NOW: u64 = 100 * 1_000_000_000;
/// One second in ns.
const SEC_NS: u64 = 1_000_000_000;

/// A peer-independent reverse key `(vni, 0, nat_ip, 0, nat_port)` — the exact shape SNAT egress pins.
/// `nat_ip` varies per case so the three keys are distinct.
fn rev_key(nat_ip: [u8; 4], nat_port: u16) -> CtKey {
    CtKey {
        vni: DNAT_VNI,
        src_ip: [0; 4],
        dst_ip: nat_ip, // reverse shape: src==0, dst==nat_ip
        src_port: 0,
        dst_port: nat_port,
        proto: 6, // TCP
        _pad: [0; 3],
    }
}

/// A reverse CT entry with a given `tcp_state` + `last_seen`, otherwise the realistic payload
/// `snat_egress` pins (`CT_REWRITE_DST | CT_F_SRC_NAT`, `xlate_ip = GUEST_IP`).
fn rev_entry(tcp_state: u8, last_seen: u64) -> CtEntry {
    CtEntry {
        last_seen,
        xlate_ip: GUEST_IP,
        xlate_port: 4321,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    }
}

#[test]
fn shared_ct_sweep_expired_evicts_only_stale_by_state() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_ctgc",
    ])
    .expect("EAL init");

    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");

    // ── The three cases (distinct keys, peer-independent reverse shape) ─────────────
    // (a) ESTABLISHED, idle 60 s → SURVIVES (60 s < 24 h ESTABLISHED timeout).
    let key_a = rev_key([203, 0, 113, 1], 20001);
    let ent_a = rev_entry(TCP_ESTABLISHED, NOW - 60 * SEC_NS);
    // (b) NEW/SYN, idle 60 s → EVICTED (60 s > 30 s NEW/default timeout).
    let key_b = rev_key([203, 0, 113, 2], 20002);
    let ent_b = rev_entry(TCP_NEW_SYN, NOW - 60 * SEC_NS);
    // (c) fresh (last_seen == now), NEW/SYN → SURVIVES (idle 0 s < 30 s).
    let key_c = rev_key([203, 0, 113, 3], 20003);
    let ent_c = rev_entry(TCP_NEW_SYN, NOW);

    assert!(shared.shared_ct_insert(key_a, ent_a), "insert (a)");
    assert!(shared.shared_ct_insert(key_b, ent_b), "insert (b)");
    assert!(shared.shared_ct_insert(key_c, ent_c), "insert (c)");

    // ── Sweep at the fixed `now` ───────────────────────────────────────────────────
    let evicted = shared.shared_ct_sweep_expired(NOW);

    assert_eq!(
        evicted, 1,
        "exactly ONE entry (the idle NEW/SYN one) must be evicted"
    );

    // (a) ESTABLISHED + idle 60 s → still present, byte-exact.
    assert_eq!(
        shared.shared_ct_get(&key_a),
        Some(ent_a),
        "(a) ESTABLISHED idle 60 s must SURVIVE (24 h timeout) byte-exact"
    );
    // (b) NEW/SYN + idle 60 s → gone.
    assert_eq!(
        shared.shared_ct_get(&key_b),
        None,
        "(b) NEW/SYN idle 60 s must be EVICTED (30 s timeout)"
    );
    // (c) fresh → still present, byte-exact.
    assert_eq!(
        shared.shared_ct_get(&key_c),
        Some(ent_c),
        "(c) fresh entry must SURVIVE byte-exact"
    );
}
