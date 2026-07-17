use flowplane_common::{
    CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local, MaglevKey, NatKey, NatValue,
    RouteValue, UnderlayValue,
};
use flowplane_core::maps::Maps;
use std::collections::{HashMap, HashSet};

/// An IPv4 route as stored in the sim `ROUTES` LPM trie: a `(vni, ipv4/prefix)` key plus its
/// [`RouteValue`]. `prefix` is the number of IPv4 host bits (0..=32); the sim does longest-prefix
/// match over these to mirror the eBPF `ROUTES` trie (queried at prefix_len 64 = 32 VNI + 32 host).
#[derive(Copy, Clone)]
pub struct Route4 {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub prefix: u8,
    pub value: RouteValue,
}

/// An IPv6 route as stored in the sim `ROUTES6` LPM trie (prefix = 0..=128 host bits).
#[derive(Copy, Clone)]
pub struct Route6 {
    pub vni: u32,
    pub ipv6: [u8; 16],
    pub prefix: u8,
    pub value: RouteValue,
}

#[derive(Default)]
pub struct MemMaps {
    pub local: Option<Local>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub fw_rules: HashMap<(u32, u32), FwRule>, // (ifindex, idx)
    pub conntrack: HashMap<CtKey, CtEntry>,
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
    pub nat: HashMap<NatKey, NatValue>,
    /// Registered NAT IPs (`NAT_IPS` map), keyed `(vni, ipv4)`. The ingress return path uses this to
    /// demux NAT returns peer-independently: if the inner dst is a registered nat_ip, the external
    /// src ip+port are zeroed so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)`
    /// reverse entry the egress allocator stored.
    pub nat_ips: HashSet<(u32, [u8; 4])>,
    pub routes4: Vec<Route4>,
    pub routes6: Vec<Route6>,
}

/// True if the first `prefix` bits of `a` and `b` (big-endian byte order) are equal.
fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

impl MemMaps {
    /// Add an exact-host (`/32`) IPv4 route — the common case for the datapath tests/anchor.
    pub fn add_route4(&mut self, vni: u32, ipv4: [u8; 4], value: RouteValue) {
        self.routes4.push(Route4 {
            vni,
            ipv4,
            prefix: 32,
            value,
        });
    }
    /// Add an exact-host (`/128`) IPv6 route.
    pub fn add_route6(&mut self, vni: u32, ipv6: [u8; 16], value: RouteValue) {
        self.routes6.push(Route6 {
            vni,
            ipv6,
            prefix: 128,
            value,
        });
    }
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
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb.get(key).copied()
    }
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.maglev.get(key).copied()
    }
    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.nat.get(key).copied()
    }
    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
        // Longest-prefix match over the stored routes for this VNI (mirrors the eBPF LPM trie).
        self.routes4
            .iter()
            .filter(|r| r.vni == vni && prefix_match(&r.ipv4, dst, r.prefix))
            .max_by_key(|r| r.prefix)
            .map(|r| r.value)
    }
    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
        self.routes6
            .iter()
            .filter(|r| r.vni == vni && prefix_match(&r.ipv6, dst, r.prefix))
            .max_by_key(|r| r.prefix)
            .map(|r| r.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_common::{LbKey, LbValue, MaglevKey};

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
