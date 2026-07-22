//! `flowplane_core::pkt::Pkt` over an `Mbuf` (single-segment). Thin wrappers over the mbuf shim.
use crate::mbuf::Mbuf;
use flowplane_core::pkt::Pkt;
use std::marker::PhantomData;
use std::slice;

/// A `Pkt` view over a borrowed mutable `Mbuf`. The mbuf stays owned by the caller.
///
/// Single-segment assumption: `pkt_len == data_len` (no chained segments). All
/// bounds checks are against `data_len` so reads/writes never reach outside the
/// linear data region.
pub struct MbufPkt<'a> {
    raw: *mut dpdk_sys::rte_mbuf,
    _m: PhantomData<&'a mut Mbuf>,
}

impl<'a> MbufPkt<'a> {
    #[inline]
    #[must_use]
    pub fn new(m: &'a mut Mbuf) -> Self {
        Self {
            raw: m.as_raw(),
            _m: PhantomData,
        }
    }

    #[inline]
    fn data_len(&self) -> usize {
        // SAFETY: `raw` is a live mbuf borrowed for lifetime 'a.
        unsafe { dpdk_sys::nfkit_pktmbuf_data_len(self.raw) as usize }
    }

    #[inline]
    fn base(&self) -> *mut u8 {
        // SAFETY: live mbuf; mtod returns the pointer to the first byte of packet data
        // within the dataroom. Valid for data_len() bytes.
        unsafe { dpdk_sys::nfkit_pktmbuf_mtod(self.raw) }
    }
}

impl Pkt for MbufPkt<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.data_len()
    }

    #[inline]
    fn logical_len(&self) -> usize {
        // Single-segment: pkt_len == data_len. Using pkt_len for correctness if
        // a multi-segment mbuf is ever passed (it won't crash, it'll just report
        // the total chain length — which is the logical wire length).
        unsafe { dpdk_sys::nfkit_pktmbuf_pkt_len(self.raw) as usize }
    }

    #[inline]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        if off.checked_add(N)? > self.data_len() {
            return None;
        }
        let mut out = [0u8; N];
        // SAFETY: off + N <= data_len, so base+off..+N is within the packet data region.
        out.copy_from_slice(unsafe { slice::from_raw_parts(self.base().add(off), N) });
        Some(out)
    }

    #[inline]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        match off.checked_add(src.len()) {
            Some(end) if end <= self.data_len() => {
                // SAFETY: off + src.len() <= data_len; &mut self guarantees exclusive access.
                unsafe { slice::from_raw_parts_mut(self.base().add(off), src.len()) }
                    .copy_from_slice(src);
                true
            }
            _ => false,
        }
    }

    #[inline]
    fn grow_head(&mut self, delta: usize) -> bool {
        // SAFETY: DPDK bounds-checks available headroom and returns NULL on overflow.
        // We propagate NULL → false without dereferencing it.
        !unsafe { dpdk_sys::nfkit_pktmbuf_prepend(self.raw, delta as u16) }.is_null()
    }

    #[inline]
    fn shrink_head(&mut self, delta: usize) -> bool {
        // SAFETY: DPDK returns NULL if delta > data_len. We propagate NULL → false.
        !unsafe { dpdk_sys::nfkit_pktmbuf_adj(self.raw, delta as u16) }.is_null()
    }

    #[inline]
    fn set_tail(&mut self, new_len: usize) -> bool {
        let cur = self.data_len();
        match new_len.cmp(&cur) {
            core::cmp::Ordering::Greater => {
                let delta = new_len - cur;
                // SAFETY: append returns a pointer to `delta` new bytes within the (single-segment)
                // dataroom, or NULL if there's no tailroom. Zero-fill them to match VecPkt::set_tail
                // (buf.resize(_, 0)) — mbuf tailroom holds stale mempool bytes.
                let p = unsafe { dpdk_sys::nfkit_pktmbuf_append(self.raw, delta as u16) };
                if p.is_null() {
                    return false;
                }
                unsafe { core::ptr::write_bytes(p, 0u8, delta) };
                true
            }
            core::cmp::Ordering::Less => {
                let delta = cur - new_len;
                // SAFETY: trim removes `delta` bytes off the tail; returns 0 on success.
                unsafe { dpdk_sys::nfkit_pktmbuf_trim(self.raw, delta as u16) == 0 }
            }
            core::cmp::Ordering::Equal => true,
        }
    }
}
