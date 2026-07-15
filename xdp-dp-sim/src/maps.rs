use std::collections::HashMap;
use xdp_dp_common::{
    CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local, MaglevKey, UnderlayValue,
};
use xdp_dp_core::maps::Maps;

#[derive(Default)]
pub struct MemMaps {
    pub local: Option<Local>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub fw_rules: HashMap<(u32, u32), FwRule>, // (ifindex, idx)
    pub conntrack: HashMap<CtKey, CtEntry>,
    pub fw_enforcing: bool,
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
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
    fn fw_enforcing(&self) -> bool {
        self.fw_enforcing
    }
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb.get(key).copied()
    }
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.maglev.get(key).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdp_dp_common::{LbKey, LbValue, MaglevKey};

    #[test]
    fn lb_and_maglev_roundtrip() {
        let mut m = MemMaps::default();
        let lk = LbKey {
            vni: 100,
            ipv4: [10, 0, 100, 1],
            port: 443,
            proto: 6,
            _pad: 0,
        };
        m.lb.insert(
            lk,
            LbValue {
                table_id: 7,
                size: 3,
            },
        );
        m.maglev.insert(
            MaglevKey {
                table_id: 7,
                slot: 2,
            },
            [0x20; 16],
        );
        assert_eq!(m.lb_get(&lk).map(|v| v.size), Some(3));
        assert_eq!(
            m.maglev_get(&MaglevKey {
                table_id: 7,
                slot: 2
            }),
            Some([0x20; 16])
        );
        assert_eq!(
            m.maglev_get(&MaglevKey {
                table_id: 7,
                slot: 9
            }),
            None
        );
    }
}
