//! Userspace conntrack aging: periodically evict entries idle longer than their timeout. Mirrors
//! dpservice (30 s default, 1-day established-TCP). Times are kernel-monotonic ns (bpf_ktime).
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

use flowplane_core::conntrack::ct_is_expired;

use crate::maps::Conntrack;

/// Kernel-monotonic time (ns) — the same clock `bpf_ktime_get_ns` stamps `last_seen` with.
fn ktime_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// Sweep loop: every `interval`, remove entries whose idle age exceeds their timeout.
/// The conntrack map is shared via Arc<Mutex<>> with the control plane for flush operations.
pub async fn run(ct: Arc<Mutex<Conntrack>>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let now = ktime_now_ns();
        let stale: Vec<_> = {
            let ct_guard = ct.lock();
            ct_guard
                .entries()
                .into_iter()
                .filter(|(_, e)| ct_is_expired(e, now))
                .map(|(k, _)| k)
                .collect()
        };
        let mut ct_guard = ct.lock();
        for k in stale {
            let _ = ct_guard.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use flowplane_common::{CtEntry, TCP_ESTABLISHED, TCP_NONE};
    use flowplane_core::conntrack::{
        ct_is_expired, timeout_ns, DEFAULT_TIMEOUT_NS, TCP_ESTABLISHED_TIMEOUT_NS,
    };

    fn entry(tcp_state: u8, last_seen: u64) -> CtEntry {
        CtEntry {
            last_seen,
            tcp_state,
            ..Default::default()
        }
    }

    #[test]
    fn established_tcp_gets_long_timeout() {
        assert_eq!(
            timeout_ns(&entry(TCP_ESTABLISHED, 0)),
            TCP_ESTABLISHED_TIMEOUT_NS
        );
        assert_eq!(timeout_ns(&entry(TCP_NONE, 0)), DEFAULT_TIMEOUT_NS);
    }

    #[test]
    fn idle_beyond_timeout_is_stale() {
        let now = 60 * 1_000_000_000u64; // 60s
        let fresh = entry(TCP_NONE, now - 5 * 1_000_000_000); // 5s idle -> keep
        let old = entry(TCP_NONE, now - 40 * 1_000_000_000); // 40s idle -> evict (>30s)
        assert!(!ct_is_expired(&fresh, now));
        assert!(ct_is_expired(&old, now));
    }
}
