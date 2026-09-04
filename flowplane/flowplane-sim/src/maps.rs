use flowplane_common::{
    CtEntry, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, IfaceValue, LbKey,
    LbValue, Local, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry, PortMeta,
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
    /// IPv6 firewall meta (`FW_META6`).
    pub fw_meta6: HashMap<u32, FwMeta>,
    /// IPv6 firewall rule slots (`FW_RULES6`), keyed `(ifindex, idx)`.
    pub fw_rules6: HashMap<(u32, u32), flowplane_common::FwRule6>,
    pub conntrack: HashMap<CtKey, CtEntry>,
    /// Firewall-only IPv6 conntrack (`CONNTRACK6` map).
    pub conntrack6: HashMap<CtKey6, CtEntry>,
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
    pub nat: HashMap<NatKey, NatValue>,
    /// Registered NAT IPs (`NAT_IPS` map), keyed `(vni, ipv4)`. The ingress return path uses this to
    /// demux NAT returns peer-independently: if the inner dst is a registered nat_ip, the external
    /// src ip+port are zeroed so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)`
    /// reverse entry the egress allocator stored.
    pub nat_ips: HashSet<(u32, [u8; 4])>,
    /// Neighbor-NAT return-route table (`NEIGHBOR_NAT`), linear-scanned like the eBPF array — see
    /// `Maps::neighbor_nat_lookup`. Tests populate directly (`m.neighbor_nat.push(..)`), mirroring
    /// how `m.lb`/`m.maglev` are seeded.
    pub neighbor_nat: Vec<NeighborNatEntry>,
    pub routes4: Vec<Route4>,
    pub routes6: Vec<Route6>,
    /// Server-wide DHCP config (`DHCP_CONFIG[0]`): MTU + DNS lists.
    pub dhcp_config: Option<DhcpConfig>,
    /// Per-interface DHCP config (`DHCP_META[ifindex]`): hostname + PXE.
    pub dhcp_meta: HashMap<u32, DhcpMeta>,
    /// Per-interface egress token-bucket state (`METER[ifindex]`).
    pub meter: HashMap<u32, MeterState>,
    /// Per-port metadata (`PORT_META[tap_ifindex]`): vni + guest/gateway identity + the guest's
    /// overlay IPv6. Read by [`Maps::port_meta_get`] — used on the CT_F_NAT64 ingress-return
    /// dispatch to source the guest's overlay IPv6 once the delivery tap is resolved.
    pub port_meta: HashMap<u32, PortMeta>,
    /// Local-delivery demux by overlay (VNI, IPv4) (`INTERFACES` map). Seed with [`Self::add_iface`].
    pub ifaces: HashMap<(u32, [u8; 4]), IfaceValue>,
    /// Local-delivery demux by overlay (VNI, IPv6) (`INTERFACES6` map). Seed with [`Self::add_iface6`].
    pub ifaces6: HashMap<(u32, [u8; 16]), IfaceValue>,
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
    /// Seed an `INTERFACES` local-delivery entry for overlay `(vni, ipv4)`.
    pub fn add_iface(&mut self, vni: u32, ipv4: [u8; 4], value: IfaceValue) {
        self.ifaces.insert((vni, ipv4), value);
    }
    /// Seed an `INTERFACES6` local-delivery entry for overlay `(vni, ipv6)`.
    pub fn add_iface6(&mut self, vni: u32, ipv6: [u8; 16], value: IfaceValue) {
        self.ifaces6.insert((vni, ipv6), value);
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
    fn conntrack6_get(&self, key: &CtKey6) -> Option<CtEntry> {
        self.conntrack6.get(key).copied()
    }
    fn conntrack6_insert(&mut self, key: CtKey6, entry: CtEntry) {
        self.conntrack6.insert(key, entry);
    }
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta6.get(&ifindex).copied()
    }
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        self.fw_rules6.get(&(key.ifindex, key.idx)).copied()
    }
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb.get(key).copied()
    }
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.maglev.get(key).copied()
    }
    fn neighbor_nat_lookup(&self, vni: u32, dst: [u8; 4], dport: u16) -> Option<[u8; 16]> {
        self.neighbor_nat
            .iter()
            .find(|e| {
                e.enabled != 0
                    && e.vni == vni
                    && e.nat_ip == dst
                    && dport >= e.port_min
                    && dport < e.port_max
            })
            .map(|e| e.underlay)
    }
    fn neighbor_nat_lookup_any(&self, dst: [u8; 4], dport: u16) -> Option<([u8; 16], u32)> {
        self.neighbor_nat
            .iter()
            .find(|e| {
                e.enabled != 0 && e.nat_ip == dst && dport >= e.port_min && dport < e.port_max
            })
            .map(|e| (e.underlay, e.vni))
    }
    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.nat.get(key).copied()
    }
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.nat_ips.contains(&(vni, *ip))
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
    fn dhcp_config(&self) -> Option<DhcpConfig> {
        self.dhcp_config
    }
    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta> {
        self.dhcp_meta.get(&ifindex).copied()
    }
    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        self.meter.get(&ifindex).copied()
    }
    fn meter_update(&mut self, ifindex: u32, state: MeterState) {
        self.meter.insert(ifindex, state);
    }
    fn port_meta_get(&self, ifindex: u32) -> Option<PortMeta> {
        self.port_meta.get(&ifindex).copied()
    }
    fn ifaces_get(&self, vni: u32, ipv4: &[u8; 4]) -> Option<IfaceValue> {
        self.ifaces.get(&(vni, *ipv4)).copied()
    }
    fn ifaces6_get(&self, vni: u32, ipv6: &[u8; 16]) -> Option<IfaceValue> {
        self.ifaces6.get(&(vni, *ipv6)).copied()
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
