use aya_ebpf::{helpers::bpf_xdp_adjust_head, programs::XdpContext};
use xdp_dp_common::{CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue};
use xdp_dp_core::maps::Maps;
use xdp_dp_core::pkt::Pkt;

/// `Maps` over the real eBPF `#[map]` statics (zero-cost wrapper). Used by the core datapath
/// modules (e.g. `xdp_dp_core::firewall::fw_eval_dir`) so the same logic runs in eBPF and natively.
pub struct GlobalMaps;

impl Maps for GlobalMaps {
    #[inline(always)]
    fn local(&self) -> Option<Local> {
        crate::maps::LOCAL.get(0).copied()
    }
    #[inline(always)]
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        unsafe { crate::maps::UNDERLAY.get(addr).copied() }
    }
    #[inline(always)]
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        unsafe { crate::maps::FW_META.get(&ifindex).copied() }
    }
    #[inline(always)]
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        unsafe { crate::maps::FW_RULES.get(key).copied() }
    }
    #[inline(always)]
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        unsafe { crate::maps::CONNTRACK.get(key).copied() }
    }
    #[inline(always)]
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        let _ = crate::maps::CONNTRACK.insert(&key, &entry, 0);
    }
    #[inline(always)]
    fn fw_enforcing(&self) -> bool {
        crate::firewall::fw_enforcing()
    }
}

/// `Pkt` over an XDP context. read/write are bounds-checked against data_end (verifier-safe).
pub struct CtxPkt<'a> {
    pub ctx: &'a XdpContext,
}

impl Pkt for CtxPkt<'_> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.ctx.data_end() - self.ctx.data()
    }
    #[inline(always)]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let start = self.ctx.data() + off;
        if start + N > self.ctx.data_end() {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(start as *const [u8; N]) })
    }
    #[inline(always)]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        let start = self.ctx.data() + off;
        if start + src.len() > self.ctx.data_end() {
            return false;
        }
        for (i, b) in src.iter().enumerate() {
            unsafe { *((start + i) as *mut u8) = *b };
        }
        true
    }
    #[inline(always)]
    fn grow_head(&mut self, delta: usize) -> bool {
        unsafe { bpf_xdp_adjust_head(self.ctx.ctx, -(delta as i32)) == 0 }
    }
    #[inline(always)]
    fn shrink_head(&mut self, delta: usize) -> bool {
        unsafe { bpf_xdp_adjust_head(self.ctx.ctx, delta as i32) == 0 }
    }
}

/// `Pkt` over a raw (data, data_end) window with no owning context. Used by callers that resize
/// with a non-XDP primitive (e.g. tc `adjust_room`/`pull_data`) and then need the pure byte-write
/// core encap. `grow_head`/`shrink_head` are unsupported (the caller resizes itself); the encap
/// core only uses `len()`/`write_bytes()`.
pub struct RawPkt {
    pub data: usize,
    pub data_end: usize,
}

impl Pkt for RawPkt {
    #[inline(always)]
    fn len(&self) -> usize {
        self.data_end - self.data
    }
    #[inline(always)]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let start = self.data + off;
        if start + N > self.data_end {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(start as *const [u8; N]) })
    }
    #[inline(always)]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        let start = self.data + off;
        if start + src.len() > self.data_end {
            return false;
        }
        for (i, b) in src.iter().enumerate() {
            unsafe { *((start + i) as *mut u8) = *b };
        }
        true
    }
    #[inline(always)]
    fn grow_head(&mut self, _delta: usize) -> bool {
        false
    }
    #[inline(always)]
    fn shrink_head(&mut self, _delta: usize) -> bool {
        false
    }
}
