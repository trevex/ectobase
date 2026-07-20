//! Safe owned handle over a DPDK `rte_mbuf`. Drop frees it. Move-only.
use arrayvec::ArrayVec;
use std::ptr::NonNull;
use std::slice;

/// Rx/Tx burst size — one cache-friendly batch.
pub const BURST: usize = 32;
/// A fixed-capacity, zero-heap-alloc batch of owned mbufs.
pub type MbufBurst = ArrayVec<Mbuf, BURST>;

#[derive(Debug)]
pub struct MbufError;

impl std::fmt::Display for MbufError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "mbuf operation failed (no headroom/tailroom or length exceeded)"
        )
    }
}

impl std::error::Error for MbufError {}

/// An owned packet buffer. Dropping frees it back to its pool. `TxQueue::tx` transfers ownership
/// of transmitted mbufs to DPDK via [`Mbuf::into_raw`]. Not `Clone`.
pub struct Mbuf {
    raw: NonNull<dpdk_sys::rte_mbuf>,
}

impl Mbuf {
    /// SAFETY: `raw` must be a live, singly-owned mbuf.
    pub(crate) unsafe fn from_raw(raw: NonNull<dpdk_sys::rte_mbuf>) -> Mbuf {
        Mbuf { raw }
    }

    /// Return the raw mbuf pointer without transferring ownership. Used by `TxQueue` to read
    /// the pointer while building the burst array.
    #[inline]
    pub(crate) fn as_raw(&self) -> *mut dpdk_sys::rte_mbuf {
        self.raw.as_ptr()
    }

    /// Give up ownership, returning the raw pointer without freeing — used by `TxQueue` to hand
    /// sent mbufs to DPDK (DPDK frees them after transmit).
    #[inline]
    pub(crate) fn into_raw(self) -> *mut dpdk_sys::rte_mbuf {
        let p = self.raw.as_ptr();
        std::mem::forget(self);
        p
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        // SAFETY: live mbuf.
        unsafe { dpdk_sys::nfkit_pktmbuf_data_len(self.raw.as_ptr()) as usize }
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the packet data as a byte slice.
    ///
    /// # Safety
    ///
    /// The returned slice is invalidated by any subsequent `prepend`/`append`/`adjust`/`trim`
    /// (they may move the data pointer); do not hold it across such calls.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        // SAFETY: mtod points into the mbuf dataroom for `data_len` bytes; borrow tied to &self.
        unsafe {
            let p = dpdk_sys::nfkit_pktmbuf_mtod(self.raw.as_ptr());
            slice::from_raw_parts(p, self.len())
        }
    }

    /// Return the packet data as a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The returned slice is invalidated by any subsequent `prepend`/`append`/`adjust`/`trim`
    /// (they may move the data pointer); do not hold it across such calls.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive &mut self; mtod + data_len bound the slice.
        unsafe {
            let p = dpdk_sys::nfkit_pktmbuf_mtod(self.raw.as_ptr());
            slice::from_raw_parts_mut(p, self.len())
        }
    }

    /// Grow head by `n` (into headroom); returns the new front `n` bytes. Err if no room.
    ///
    /// # Errors
    ///
    /// Returns `MbufError` if `n` exceeds the available headroom.
    #[inline]
    pub fn prepend(&mut self, n: u16) -> Result<&mut [u8], MbufError> {
        // SAFETY: DPDK bounds-checks headroom, returns NULL on overflow.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_prepend(self.raw.as_ptr(), n) };
        if p.is_null() {
            return Err(MbufError);
        }
        Ok(unsafe { slice::from_raw_parts_mut(p, n as usize) })
    }

    /// Grow tail by `n`; returns the new trailing `n` bytes. Err if no room.
    ///
    /// # Errors
    ///
    /// Returns `MbufError` if `n` exceeds the available tailroom.
    #[inline]
    pub fn append(&mut self, n: u16) -> Result<&mut [u8], MbufError> {
        // SAFETY: DPDK bounds-checks tailroom, returns NULL on overflow.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_append(self.raw.as_ptr(), n) };
        if p.is_null() {
            return Err(MbufError);
        }
        Ok(unsafe { slice::from_raw_parts_mut(p, n as usize) })
    }

    /// Strip `n` bytes from the head. Err if `n > len`.
    ///
    /// # Errors
    ///
    /// Returns `MbufError` if `n` exceeds the current data length.
    #[inline]
    pub fn adjust(&mut self, n: u16) -> Result<(), MbufError> {
        // SAFETY: DPDK returns NULL if n > data_len.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_adj(self.raw.as_ptr(), n) };
        if p.is_null() {
            Err(MbufError)
        } else {
            Ok(())
        }
    }

    /// Strip `n` bytes from the tail. Err if `n > len`.
    ///
    /// # Errors
    ///
    /// Returns `MbufError` if `n` exceeds the current data length.
    #[inline]
    pub fn trim(&mut self, n: u16) -> Result<(), MbufError> {
        // SAFETY: DPDK returns <0 if n > data_len.
        let rc = unsafe { dpdk_sys::nfkit_pktmbuf_trim(self.raw.as_ptr(), n) };
        if rc < 0 {
            Err(MbufError)
        } else {
            Ok(())
        }
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // SAFETY: sole owner; free returns the buffer to its pool.
        unsafe { dpdk_sys::nfkit_pktmbuf_free(self.raw.as_ptr()) }
    }
}
