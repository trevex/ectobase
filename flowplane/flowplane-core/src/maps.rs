use flowplane_common::{
    CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local, MaglevKey, UnderlayValue,
};

/// Typed access to the datapath maps the core needs. eBPF impl wraps the `#[map]` statics
/// (zero-cost); native impl is HashMap-backed. Monomorphized — no `dyn`.
pub trait Maps {
    fn local(&self) -> Option<Local>;
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue>;
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta>;
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule>;
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry>;
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry);
    fn lb_get(&self, key: &LbKey) -> Option<LbValue>;
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]>;
}
