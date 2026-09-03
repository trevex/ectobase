use aya_ebpf::{helpers::bpf_xdp_adjust_head, programs::XdpContext};
use flowplane_common::{
    CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local,
    MaglevKey, MeterState, NatKey, NatValue, RouteLpmData, RouteLpmData6, RouteValue,
    UnderlayValue, VipKey,
};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Pkt;

/// `Maps` over the real eBPF `#[map]` statics (zero-cost wrapper). Used by the core datapath
/// modules (e.g. `flowplane_core::firewall::fw_eval_dir`) so the same logic runs in eBPF and natively.
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
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        unsafe { crate::maps::FW_META6.get(&ifindex).copied() }
    }
    #[inline(always)]
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        unsafe { crate::maps::FW_RULES6.get(key).copied() }
    }
    #[inline(always)]
    fn conntrack6_get(&self, key: &flowplane_common::CtKey6) -> Option<CtEntry> {
        unsafe { crate::maps::CONNTRACK6.get(key).copied() }
    }
    #[inline(always)]
    fn conntrack6_insert(&mut self, key: flowplane_common::CtKey6, entry: CtEntry) {
        let _ = crate::maps::CONNTRACK6.insert(&key, &entry, 0);
    }
    #[inline(always)]
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        unsafe { crate::maps::LB.get(key).copied() }
    }
    #[inline(always)]
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        unsafe { crate::maps::MAGLEV.get(key).copied() }
    }
    #[inline(always)]
    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        unsafe { crate::maps::NAT.get(key).copied() }
    }
    #[inline(always)]
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        unsafe {
            crate::maps::NAT_IPS
                .get(&VipKey { vni, ipv4: *ip })
                .is_some()
        }
    }
    #[inline(always)]
    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
        crate::maps::ROUTES
            .get(&aya_ebpf::maps::lpm_trie::Key::new(
                64,
                RouteLpmData {
                    vni: vni.to_be_bytes(),
                    ipv4: *dst,
                },
            ))
            .copied()
    }
    #[inline(always)]
    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
        crate::maps::ROUTES6
            .get(&aya_ebpf::maps::lpm_trie::Key::new(
                160,
                RouteLpmData6 {
                    vni: vni.to_be_bytes(),
                    ipv6: *dst,
                },
            ))
            .copied()
    }
    #[inline(always)]
    fn dhcp_config(&self) -> Option<DhcpConfig> {
        crate::maps::DHCP_CONFIG.get(0).copied()
    }
    #[inline(always)]
    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta> {
        unsafe { crate::maps::DHCP_META.get(&ifindex).copied() }
    }
    #[inline(always)]
    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        unsafe { crate::maps::METER.get(&ifindex).copied() }
    }
    #[inline(always)]
    fn meter_update(&mut self, ifindex: u32, state: MeterState) {
        let _ = crate::maps::METER.insert(&ifindex, &state, 0);
    }
}

/// Shared raw read over a `[base, end)` packet window. `CtxPkt` and `RawPkt` both delegate here so
/// their bounds/read behavior can never diverge.
///
/// # Safety
/// `base..end` must be the packet's real `data..data_end`. `off`/`N` are small caller-bounded
/// constants, so `base + off + N` does not overflow in practice; the `> end` compare is the exact
/// bounds idiom the XDP verifier accepts.
#[inline(always)]
unsafe fn read_raw<const N: usize>(base: usize, end: usize, off: usize) -> Option<[u8; N]> {
    let start = base + off;
    if start + N > end {
        return None;
    }
    Some(core::ptr::read_unaligned(start as *const [u8; N]))
}

/// Shared raw write over a `[base, end)` packet window (see [`read_raw`] for the safety contract).
#[inline(always)]
unsafe fn write_raw(base: usize, end: usize, off: usize, src: &[u8]) -> bool {
    let start = base + off;
    if start + src.len() > end {
        return false;
    }
    for (i, b) in src.iter().enumerate() {
        *((start + i) as *mut u8) = *b;
    }
    true
}

/// Fixed-size raw write: bounds-check then a SINGLE `write_unaligned` of `[u8; N]` (see [`read_raw`]
/// for the safety contract). Const `N` lets LLVM emit one store instead of a byte loop — the smaller
/// bytecode that keeps the SNAT rewriter inside the XDP verifier's single-function budget.
#[inline(always)]
unsafe fn write_raw_array<const N: usize>(
    base: usize,
    end: usize,
    off: usize,
    src: &[u8; N],
) -> bool {
    let start = base + off;
    if start + N > end {
        return false;
    }
    core::ptr::write_unaligned(start as *mut [u8; N], *src);
    true
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
    fn logical_len(&self) -> usize {
        self.ctx.data_end() - self.ctx.data()
    }
    #[inline(always)]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        unsafe { read_raw::<N>(self.ctx.data(), self.ctx.data_end(), off) }
    }
    #[inline(always)]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        unsafe { write_raw(self.ctx.data(), self.ctx.data_end(), off, src) }
    }
    #[inline(always)]
    fn write_array<const N: usize>(&mut self, off: usize, src: &[u8; N]) -> bool {
        unsafe { write_raw_array::<N>(self.ctx.data(), self.ctx.data_end(), off, src) }
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
/// with a non-XDP primitive (e.g. tc `adjust_room`/`pull_data`) and then need a pure byte-write
/// core seam (nat64 translation, ARP/ND replies, DHCP). `grow_head`/`shrink_head` are unsupported
/// (the caller resizes itself). Construct via [`RawPkt::new`].
pub struct RawPkt {
    data: usize,
    data_end: usize,
    logical_len: usize,
}

impl RawPkt {
    /// Build a window over `[data, data_end)`. Linear: `logical_len == data_end - data`.
    /// Caller guarantees the pointers come from the same packet and `data <= data_end`.
    #[inline(always)]
    pub fn new(data: usize, data_end: usize) -> Self {
        debug_assert!(data <= data_end, "RawPkt: data must not exceed data_end");
        Self {
            data,
            data_end,
            logical_len: data_end - data,
        }
    }
}

impl Pkt for RawPkt {
    #[inline(always)]
    fn len(&self) -> usize {
        self.data_end - self.data
    }
    #[inline(always)]
    fn logical_len(&self) -> usize {
        self.logical_len
    }
    #[inline(always)]
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        unsafe { read_raw::<N>(self.data, self.data_end, off) }
    }
    #[inline(always)]
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        unsafe { write_raw(self.data, self.data_end, off, src) }
    }
    #[inline(always)]
    fn write_array<const N: usize>(&mut self, off: usize, src: &[u8; N]) -> bool {
        unsafe { write_raw_array::<N>(self.data, self.data_end, off, src) }
    }
    #[inline(always)]
    fn grow_head(&mut self, _delta: usize) -> bool {
        debug_assert!(
            false,
            "RawPkt does not support resize; the caller resizes itself"
        );
        false
    }
    #[inline(always)]
    fn shrink_head(&mut self, _delta: usize) -> bool {
        debug_assert!(
            false,
            "RawPkt does not support resize; the caller resizes itself"
        );
        false
    }
}
