use std::collections::HashMap;
use xdp_dp_common::{CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue};
use xdp_dp_core::maps::Maps;

#[derive(Default)]
pub struct MemMaps {
    pub local: Option<Local>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub fw_rules: HashMap<(u32, u32), FwRule>, // (ifindex, idx)
    pub conntrack: HashMap<CtKey, CtEntry>,
}

impl Maps for MemMaps {
    fn local(&self) -> Option<Local> {
        self.local
    }
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        self.underlay.get(addr).copied()
    }
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta.get(&ifindex).copied()
    }
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.fw_rules.get(&(key.ifindex, key.idx)).copied()
    }
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        self.conntrack.get(key).copied()
    }
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        self.conntrack.insert(key, entry);
    }
}
