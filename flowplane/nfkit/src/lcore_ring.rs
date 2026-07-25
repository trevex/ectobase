//! Inter-lcore Mbuf handoff over a DPDK rte_ring (MP enqueue / SC dequeue). Carries Mbuf OWNERSHIP:
//! `enqueue` moves an Mbuf INTO the ring (as a raw ptr); `dequeue_burst` moves them back OUT as owned
//! Mbufs. Any lcore may enqueue (multi-producer, internally synchronized); exactly ONE lcore may
//! dequeue (single-consumer, enforced by construction — only the owning worker calls dequeue).
use crate::mbuf::{Mbuf, MbufBurst, BURST};
use std::ffi::CString;
use std::os::raw::c_void;
use std::ptr::NonNull;

/// Ring creation failed. Wraps `rte_errno` (like [`crate::PortError`]).
#[derive(Debug)]
pub struct RingError(pub i32);

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rte_ring create failed (rc={}; check rte_errno)", self.0)
    }
}

impl std::error::Error for RingError {}

/// A DPDK `rte_ring` carrying `Mbuf` ownership between lcores: multi-producer enqueue,
/// single-consumer dequeue (`RING_F_SC_DEQ`).
///
/// Ownership discipline: at every instant each mbuf is owned by EXACTLY ONE of an [`Mbuf`] wrapper
/// or the ring (as a raw `*mut rte_mbuf`). [`enqueue`](LcoreRing::enqueue) transfers a wrapper's
/// ownership into the ring on success (and returns it back on failure); [`dequeue_burst`](
/// LcoreRing::dequeue_burst) transfers ring ownership back out into fresh wrappers.
pub struct LcoreRing {
    raw: *mut dpdk_sys::rte_ring,
}

// SAFETY: MP enqueue is internally synchronized, so &LcoreRing may be shared across lcores for
// enqueue. Send+Sync so it can live in an Arc captured by the for_each_worker closure. The SC
// contract (one dequeuer) is upheld by the caller (Task 5: only the owning worker dequeues its ring).
unsafe impl Send for LcoreRing {}
unsafe impl Sync for LcoreRing {}

impl LcoreRing {
    /// Create a ring holding up to `count-1` mbuf pointers (rte_ring reserves one slot).
    ///
    /// `count` MUST be a power of two (an rte_ring requirement). `name` MUST be unique within the
    /// EAL instance (like ports/hashes/mempools) — a duplicate name fails creation. `socket` is the
    /// NUMA socket id (or a negative value for `SOCKET_ID_ANY`).
    ///
    /// # Errors
    ///
    /// Returns [`RingError`] (carrying `rte_errno`) if `rte_ring_create` returns NULL.
    pub fn new(name: &str, count: u32, socket: i32) -> Result<LcoreRing, RingError> {
        debug_assert!(
            count.is_power_of_two(),
            "rte_ring count must be a power of two (got {count})"
        );
        let cname = CString::new(name).map_err(|_| RingError(0))?;
        // SAFETY: cname is a valid C string for the call; count/socket are plain scalars.
        let raw = unsafe { dpdk_sys::nfkit_ring_create_scdeq(cname.as_ptr(), count, socket) };
        if raw.is_null() {
            // SAFETY: read-only after a failed DPDK call; rte_errno holds the reason.
            return Err(RingError(unsafe { dpdk_sys::nfkit_rte_errno() }));
        }
        Ok(LcoreRing { raw })
    }

    /// Move `m` INTO the ring (multi-producer; safe to call from any lcore via `&self`).
    ///
    /// On success ownership now lives in the ring. On failure (ring full) the mbuf is handed BACK to
    /// the caller as `Err(m)` so it can be dropped/retried — the mbuf is never leaked.
    ///
    /// # Errors
    ///
    /// Returns `Err(m)` — the same, still-owned mbuf — if the ring is full.
    #[inline]
    pub fn enqueue(&self, m: Mbuf) -> Result<(), Mbuf> {
        // Ownership leaves the wrapper here. `p` is now the sole handle to a live mbuf and MUST end
        // up either in the ring (success) or back in a wrapper (failure) — never both, never dropped.
        let p = m.into_raw();
        let mut obj = p as *mut c_void;
        // SAFETY: obj points to one valid mbuf ptr; mp_enqueue_bulk is internally synchronized and
        // reads exactly one slot. It returns 1 iff it took the object.
        let n = unsafe { dpdk_sys::nfkit_ring_mp_enqueue_bulk(self.raw, &mut obj, 1) };
        if n == 1 {
            // Ownership transferred into the ring; do NOT wrap or free `p`.
            Ok(())
        } else {
            // Ring was full: it did NOT take the object, so `p` is still the unique owner. Re-wrap it
            // so the caller regains ownership (and Drop frees it if unused). SAFETY: `p` came from a
            // just-released Mbuf (valid, singly-owned) and the ring left it untouched.
            Err(unsafe { Mbuf::from_raw(NonNull::new_unchecked(p)) })
        }
    }

    /// Move up to `out`'s remaining capacity mbufs OUT of the ring into `out` (single-consumer;
    /// call ONLY from the one owning lcore). Appends owned [`Mbuf`]s. Returns the count dequeued.
    #[inline]
    pub fn dequeue_burst(&self, out: &mut MbufBurst) -> usize {
        let cap = out.remaining_capacity();
        if cap == 0 {
            return 0;
        }
        let mut raw: [*mut c_void; BURST] = [std::ptr::null_mut(); BURST];
        // SAFETY: raw has room for cap <= BURST ptrs; sc_dequeue_burst fills exactly raw[0..n] with
        // mbuf pointers whose ownership the ring hands to us (single-consumer: no other lcore reads).
        let n = unsafe {
            dpdk_sys::nfkit_ring_sc_dequeue_burst(self.raw, raw.as_mut_ptr(), cap as u32)
        } as usize;
        for &p in raw.iter().take(n) {
            // SAFETY: sc_dequeue_burst fills raw[0..n] with the exact non-null owned mbuf pointers we
            // enqueued; ownership now transfers into fresh wrappers (each frees on drop). Mirrors
            // RxQueue::rx.
            out.push(unsafe {
                Mbuf::from_raw(NonNull::new_unchecked(p as *mut dpdk_sys::rte_mbuf))
            });
        }
        n
    }
}

impl Drop for LcoreRing {
    fn drop(&mut self) {
        // SAFETY: sole owner; frees the ring. NOTE: any mbufs STILL enqueued at drop are leaked —
        // callers must drain the ring before dropping it. In practice the ring lives for the whole
        // process (like Port). We do NOT drain here: Drop has no single-consumer context.
        unsafe { dpdk_sys::rte_ring_free(self.raw) }
    }
}
