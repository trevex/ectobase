use crate::firewall_test::tcp_v4; // pub(crate) helper
use crate::{MemMaps, VecPkt};
use flowplane_common::TCP_ESTABLISHED;
use flowplane_core::conntrack::{ct_create_default, ct_is_expired, ct_key};
use flowplane_core::maps::Maps;

#[test]
fn conntrack_entry_created_for_new_flow() {
    let vni = 100u32;
    let mut m = MemMaps::default();
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));
    let key = ct_key(&pkt, 0, vni).expect("ct key");
    assert!(m.conntrack_get(&key).is_none());
    // `now: u64` is 0 in the native path (no bpf_ktime_get_ns).
    ct_create_default(&pkt, &mut m, 0, vni, 0);
    assert!(m.conntrack_get(&key).is_some(), "forward CT entry inserted");
}

/// Simulate one GC sweep over `MemMaps`: evict every entry whose idle age at `now_ns` exceeds its
/// protocol timeout. Uses the shared `ct_is_expired` from `flowplane_core` — identical predicate
/// to the production `conntrack_gc::run`.
fn gc_sweep(m: &mut MemMaps, now_ns: u64) {
    let stale: Vec<_> = m
        .conntrack
        .iter()
        .filter(|(_, e)| ct_is_expired(e, now_ns))
        .map(|(k, _)| *k)
        .collect();
    for k in stale {
        m.conntrack.remove(&k);
    }
}

/// A flow created with `last_seen = 0` is expired after a GC sweep at t = 60 s (> 30 s default
/// timeout). A subsequent packet on the same 5-tuple is treated as a brand-new flow, not a CT hit.
#[test]
fn flow_timeout_expires_idle_entry() {
    let vni = 100u32;
    let mut m = MemMaps::default();

    // Step 1: create the flow at t = 0 ns (last_seen = 0).
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));
    let fwd_key = ct_key(&pkt, 0, vni).expect("ct key");
    ct_create_default(&pkt, &mut m, 0, vni, 0);
    assert!(
        m.conntrack_get(&fwd_key).is_some(),
        "forward CT entry must exist before timeout"
    );

    // Step 2: advance simulated time to 60 s and run a GC sweep.
    // The entry's idle age is 60 s, which exceeds the 30 s default timeout → evicted.
    let now_ns: u64 = 60 * 1_000_000_000;
    gc_sweep(&mut m, now_ns);

    // Step 3: assert the entry is gone.
    assert!(
        m.conntrack_get(&fwd_key).is_none(),
        "forward CT entry must be evicted after timeout"
    );

    // Step 4: a subsequent packet on the same 5-tuple is a miss (asserted above) — a new entry is
    // created, proving the expired flow is re-learned rather than treated as an existing hit.
    ct_create_default(&pkt, &mut m, 0, vni, now_ns);
    let re_entry = m
        .conntrack_get(&fwd_key)
        .expect("new CT entry after re-injection");
    assert_eq!(
        re_entry.last_seen, now_ns,
        "re-created entry must carry the new timestamp"
    );
}

/// An ESTABLISHED TCP flow survives the 30 s sweep (24-hour timeout) but is evicted after 25 h.
#[test]
fn established_tcp_flow_survives_short_timeout_and_expires_at_long_timeout() {
    use flowplane_common::{CtEntry, CT_F_DEFAULT};

    let vni = 200u32;
    let mut m = MemMaps::default();

    // Insert a synthetic ESTABLISHED CT entry with last_seen = 0.
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 1, 1], [10, 0, 1, 2], 6000, 80));
    let fwd_key = ct_key(&pkt, 0, vni).expect("ct key");
    m.conntrack_insert(
        fwd_key,
        CtEntry {
            last_seen: 0,
            tcp_state: TCP_ESTABLISHED,
            flags: CT_F_DEFAULT,
            ..Default::default()
        },
    );

    // At 60 s: still alive (24 h timeout).
    gc_sweep(&mut m, 60 * 1_000_000_000);
    assert!(
        m.conntrack_get(&fwd_key).is_some(),
        "established TCP must survive the short (30 s) sweep"
    );

    // At 25 h: evicted (> 24 h timeout).
    gc_sweep(&mut m, 25 * 60 * 60 * 1_000_000_000);
    assert!(
        m.conntrack_get(&fwd_key).is_none(),
        "established TCP must be evicted after 25 h (> 24 h timeout)"
    );
}
