//! Safe RAII wrapper over a DPDK pktmbuf mempool.
use crate::mbuf::Mbuf;
use std::ffi::CString;
use std::ptr::NonNull;

/// A pool of packet mbufs. Freed on drop. Shareable across lcores via DPDK's per-lcore cache
/// (the underlying `rte_mempool` is internally synchronized), so this is `Sync`.
pub struct Mempool {
    raw: NonNull<dpdk_sys::rte_mempool>,
}

// SAFETY: rte_mempool is internally synchronized (per-lcore caches + a shared ring); concurrent
// alloc/free from multiple lcores is the documented usage.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

#[derive(Debug)]
pub struct MempoolError;

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mempool creation failed (check rte_errno)")
    }
}

impl std::error::Error for MempoolError {}

impl Mempool {
    /// Create a pktmbuf pool: `n` mbufs, `cache` per-lcore cache size, on NUMA `socket`.
    pub fn new(name: &str, n: u32, cache: u32, socket: i32) -> Result<Mempool, MempoolError> {
        let cname = CString::new(name).map_err(|_| MempoolError)?;
        // SAFETY: name is a valid C string for the call; other args are plain scalars.
        let raw = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                n,
                cache,
                0,
                dpdk_sys::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket,
            )
        };
        NonNull::new(raw)
            .map(|raw| Mempool { raw })
            .ok_or(MempoolError)
    }

    /// Allocate one mbuf, or `None` if the pool is exhausted.
    pub fn alloc(&self) -> Option<Mbuf> {
        // SAFETY: self.raw is a live pool for the lifetime of &self.
        let m = unsafe { dpdk_sys::nfkit_pktmbuf_alloc(self.raw.as_ptr()) };
        NonNull::new(m).map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Number of free buffers currently available (for tests/observability).
    pub fn avail_count(&self) -> u32 {
        // SAFETY: live pool.
        unsafe { dpdk_sys::rte_mempool_avail_count(self.raw.as_ptr()) }
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        // SAFETY: sole owner; frees the pool.
        unsafe { dpdk_sys::rte_mempool_free(self.raw.as_ptr()) }
    }
}
