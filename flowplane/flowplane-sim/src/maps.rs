use flowplane_common::{
    CtEntry, CtEntry6, CtKey, CtKey6, DhcpConfig, DhcpMeta, DsrLbIP, FwBind, FwMeta, FwPolKey,
    FwRule, FwRuleKey, IfaceValue, LbBackend, LbKey, LbValue, Local, MaglevKey, MeterState, NatKey,
    NatKey6, NatValue, NatValue6, NeighborNat6Entry, NeighborNatEntry, PortMeta, RouteValue,
    UnderlayValue, FW_DIR_EGRESS, FW_DIR_INGRESS, FW_MAX_RULES,
};
use flowplane_control::fwclass::{compile_scope, Scope};
use flowplane_core::maps::Maps;
use std::cell::RefCell;
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
    /// DSR reverse-LB address state (`DSR` map, B7b), keyed on the guest-reply 5-tuple.
    pub dsr: HashMap<CtKey, DsrLbIP>,
    /// IPv6 sibling of `dsr` (`DSR6` map).
    pub dsr6: HashMap<CtKey6, DsrLbIP>,
    pub lb: HashMap<LbKey, LbValue>,
    pub lb6: HashMap<flowplane_common::LbKey6, LbValue>,
    pub maglev: HashMap<MaglevKey, LbBackend>,
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
    /// NAT66 (v6 network SNAT) config (`NAT6` map), keyed `(vni, guest-ipv6)`.
    pub nat6: HashMap<NatKey6, NatValue6>,
    /// Registered NAT66 public source IPs (`NAT_IPS6`), keyed `(vni, ipv6)` — v6 sibling of `nat_ips`.
    pub nat_ips6: HashSet<(u32, [u8; 16])>,
    /// Dedicated NAT66 conntrack (`NAT_CT6`), fwd + reverse xlate — the v4 `conntrack`'s xlate is
    /// v4-only, so v6 NAT gets its own CtKey6->CtEntry6 map.
    pub nat_ct6: HashMap<CtKey6, CtEntry6>,
    /// NAT66 neighbor-NAT return table (`NEIGHBOR_NAT6`), v6 sibling of `neighbor_nat`.
    pub neighbor_nat6: Vec<NeighborNat6Entry>,
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
    /// 1:1 floating-IP map (`FLOATING_IPS`), keyed `(vni, V)` → guest `G`. Seed with [`Self::add_floating_ip`].
    pub floating_ips: HashMap<(u32, [u8; 4]), [u8; 4]>,
    /// Firewall classifier binding (`FW_BIND[ifindex]`).
    pub fw_bind: HashMap<u32, FwBind>,
    /// Per-scope v4 peer-class tries (`FW_CLASS[scope]`): `(addr, prefix_len, class)`, matched by
    /// longest prefix like the eBPF inner LPM trie.
    pub fw_class4: HashMap<u64, Vec<([u8; 4], u8, u32)>>,
    /// Per-scope v6 peer-class tries (`FW_CLASS6[scope]`).
    pub fw_class6: HashMap<u64, Vec<([u8; 16], u8, u32)>>,
    /// Per-scope v4 policy tries (`FW_POLICY[scope]`): `(prefix_len, key, precedence)`, the prefix
    /// counted over the key's bytes in memory order (class, proto, big-endian port).
    pub fw_policy4: HashMap<u64, Vec<(u32, FwPolKey, u32)>>,
    /// Per-scope v6 policy tries (`FW_POLICY6[scope]`).
    pub fw_policy6: HashMap<u64, Vec<(u32, FwPolKey, u32)>>,
    /// The node's firewall epoch (`FW_EPOCH[0]`). Bump it after changing a binding (or the legacy
    /// seeds a binding is derived from) to have established flows meet the new policy.
    pub fw_epoch: u32,
    /// Scopes DERIVED from the legacy rule-slot seeds (`fw_meta`/`fw_rules`,
    /// `fw_meta6`/`fw_rules6`) for an interface with no explicit `fw_bind` entry — see
    /// [`MemMaps::derived_bind`].
    derived_scopes: RefCell<HashMap<u64, Scope>>,
}

/// The bytes an LPM trie compares for a policy key: class (native byte order, always matched in
/// full), proto, port (big-endian). The pad byte is never covered by a prefix.
fn pol_key_bytes(k: &FwPolKey) -> [u8; 7] {
    let c = k.class.to_ne_bytes();
    [c[0], c[1], c[2], c[3], k.proto, k.port[0], k.port[1]]
}

/// Longest-prefix match over a sim policy trie for a full-length key → the entry's precedence.
fn policy_lpm(entries: Option<&Vec<(u32, FwPolKey, u32)>>, key: &FwPolKey) -> Option<u32> {
    let want = pol_key_bytes(key);
    entries?
        .iter()
        .filter(|(plen, k, _)| prefix_match(&pol_key_bytes(k), &want, *plen as u8))
        .max_by_key(|(plen, _, _)| *plen)
        .map(|(_, _, prec)| *prec)
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
    /// The classifier binding the dataplane would program for an interface seeded through the legacy
    /// rule slots: its slot lists (in slot order, a direction included only if its count is non-zero
    /// — exactly what the old evaluator scanned) compiled with the dataplane's own
    /// `fwclass::compile_scope`, the scopes cached for the stage lookups. Scenario tests keep seeding
    /// rule lists; the classifier is what evaluates them.
    fn derived_bind(&self, ifindex: u32) -> Option<FwBind> {
        let (m4, m6) = (self.fw_meta.get(&ifindex), self.fw_meta6.get(&ifindex));
        if m4.is_none() && m6.is_none() {
            return None;
        }
        let counted = |m: Option<&FwMeta>, dir: u8| {
            m.is_some_and(|m| {
                if dir == FW_DIR_EGRESS {
                    m.egress_count > 0
                } else {
                    m.ingress_count > 0
                }
            })
        };
        let mut bind = FwBind::default();
        for dir in [FW_DIR_INGRESS, FW_DIR_EGRESS] {
            let v4: Vec<FwRule> = (0..FW_MAX_RULES)
                .filter_map(|i| self.fw_rules.get(&(ifindex, i)).copied())
                .filter(|_| counted(m4, dir))
                .collect();
            let v6: Vec<flowplane_common::FwRule6> = (0..FW_MAX_RULES)
                .filter_map(|i| self.fw_rules6.get(&(ifindex, i)).copied())
                .filter(|_| counted(m6, dir))
                .collect();
            let scope = compile_scope(dir, v4.iter(), v6.iter()).unwrap_or_else(|e| {
                panic!("sim seed for ifindex {ifindex} cannot be compiled for the classifier: {e}")
            });
            if let Some(s) = scope {
                if dir == FW_DIR_EGRESS {
                    bind.egress_scope = s.id;
                } else {
                    bind.ingress_scope = s.id;
                }
                self.derived_scopes.borrow_mut().insert(s.id, s);
            }
        }
        Some(bind)
    }

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
    /// Seed a `FLOATING_IPS` 1:1 floating-IP entry: inner dst `v` (the LB_IP_CONST) → backing guest `g`.
    pub fn add_floating_ip(&mut self, vni: u32, v: [u8; 4], g: [u8; 4]) {
        self.floating_ips.insert((vni, v), g);
    }
    /// Seed a `MAGLEV` slot with a full `LbBackend` value.
    pub fn add_maglev(&mut self, table_id: u32, slot: u32, backend: LbBackend) {
        self.maglev.insert(MaglevKey { table_id, slot }, backend);
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
    fn conntrack_remove(&mut self, key: &CtKey) {
        self.conntrack.remove(key);
    }
    fn conntrack6_remove(&mut self, key: &CtKey6) {
        self.conntrack6.remove(key);
    }
    fn conntrack6_get(&self, key: &CtKey6) -> Option<CtEntry> {
        self.conntrack6.get(key).copied()
    }
    fn conntrack6_insert(&mut self, key: CtKey6, entry: CtEntry) {
        self.conntrack6.insert(key, entry);
    }
    fn dsr_get(&self, key: &CtKey) -> Option<DsrLbIP> {
        self.dsr.get(key).copied()
    }
    fn dsr_insert(&mut self, key: CtKey, v: DsrLbIP) {
        self.dsr.insert(key, v);
    }
    fn dsr6_get(&self, key: &CtKey6) -> Option<DsrLbIP> {
        self.dsr6.get(key).copied()
    }
    fn dsr6_insert(&mut self, key: CtKey6, v: DsrLbIP) {
        self.dsr6.insert(key, v);
    }
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta6.get(&ifindex).copied()
    }
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        self.fw_rules6.get(&(key.ifindex, key.idx)).copied()
    }
    fn fw_epoch(&self) -> u32 {
        self.fw_epoch
    }
    fn fw_bind(&self, ifindex: u32) -> Option<FwBind> {
        match self.fw_bind.get(&ifindex) {
            Some(b) => Some(*b),
            None => self.derived_bind(ifindex),
        }
    }
    fn fw_class4(&self, scope: u64, addr: &[u8; 4]) -> Option<u32> {
        let derived = self.derived_scopes.borrow();
        let classes = match self.fw_class4.get(&scope) {
            Some(c) => c,
            None => &derived.get(&scope)?.v4.classes,
        };
        classes
            .iter()
            .filter(|(a, len, _)| prefix_match(a, addr, *len))
            .max_by_key(|(_, len, _)| *len)
            .map(|(_, _, class)| *class)
    }
    fn fw_class6(&self, scope: u64, addr: &[u8; 16]) -> Option<u32> {
        let derived = self.derived_scopes.borrow();
        let classes = match self.fw_class6.get(&scope) {
            Some(c) => c,
            None => &derived.get(&scope)?.v6.classes,
        };
        classes
            .iter()
            .filter(|(a, len, _)| prefix_match(a, addr, *len))
            .max_by_key(|(_, len, _)| *len)
            .map(|(_, _, class)| *class)
    }
    fn fw_policy4(&self, scope: u64, key: &FwPolKey) -> Option<u32> {
        match self.fw_policy4.get(&scope) {
            Some(p) => policy_lpm(Some(p), key),
            None => policy_lpm(
                self.derived_scopes
                    .borrow()
                    .get(&scope)
                    .map(|s| &s.v4.policy),
                key,
            ),
        }
    }
    fn fw_policy6(&self, scope: u64, key: &FwPolKey) -> Option<u32> {
        match self.fw_policy6.get(&scope) {
            Some(p) => policy_lpm(Some(p), key),
            None => policy_lpm(
                self.derived_scopes
                    .borrow()
                    .get(&scope)
                    .map(|s| &s.v6.policy),
                key,
            ),
        }
    }
    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb.get(key).copied()
    }
    fn lb6_get(&self, key: &flowplane_common::LbKey6) -> Option<LbValue> {
        self.lb6.get(key).copied()
    }
    fn maglev_get(&self, key: &MaglevKey) -> Option<LbBackend> {
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
    // NAT66 (v6) — mirror the v4 filters exactly.
    fn nat_get6(&self, key: &NatKey6) -> Option<NatValue6> {
        self.nat6.get(key).copied()
    }
    fn is_nat_ip6(&self, vni: u32, ip: &[u8; 16]) -> bool {
        self.nat_ips6.contains(&(vni, *ip))
    }
    fn neighbor_nat_lookup6(&self, vni: u32, dst: [u8; 16], dport: u16) -> Option<[u8; 16]> {
        self.neighbor_nat6
            .iter()
            .find(|e| {
                e.enabled != 0
                    && e.vni == vni
                    && e.nat_ip6 == dst
                    && dport >= e.port_min
                    && dport < e.port_max
            })
            .map(|e| e.underlay)
    }
    fn neighbor_nat_lookup_any6(&self, dst: [u8; 16], dport: u16) -> Option<([u8; 16], u32)> {
        self.neighbor_nat6
            .iter()
            .find(|e| {
                e.enabled != 0 && e.nat_ip6 == dst && dport >= e.port_min && dport < e.port_max
            })
            .map(|e| (e.underlay, e.vni))
    }
    fn nat_ct6_get(&self, key: &CtKey6) -> Option<CtEntry6> {
        self.nat_ct6.get(key).copied()
    }
    fn nat_ct6_insert(&mut self, key: CtKey6, entry: CtEntry6) {
        self.nat_ct6.insert(key, entry);
    }
    fn floating_ip_get(&self, vni: u32, v: &[u8; 4]) -> Option<[u8; 4]> {
        self.floating_ips.get(&(vni, *v)).copied()
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
        let backend = LbBackend {
            node_vtep: [0x20; 16],
            ..Default::default()
        };
        m.maglev.insert(
            MaglevKey {
                table_id: 7,
                slot: 2,
            },
            backend,
        );
        assert_eq!(m.lb_get(&lk).map(|v| v.size), Some(3));
        assert_eq!(
            m.maglev_get(&MaglevKey {
                table_id: 7,
                slot: 2
            }),
            Some(backend)
        );
        assert_eq!(
            m.maglev_get(&MaglevKey {
                table_id: 7,
                slot: 9
            }),
            None
        );
    }

    #[test]
    fn floating_ips_roundtrip() {
        let mut m = MemMaps::default();
        m.add_floating_ip(100, [203, 0, 113, 7], [10, 0, 0, 9]);
        assert_eq!(
            m.floating_ip_get(100, &[203, 0, 113, 7]),
            Some([10, 0, 0, 9])
        );
        // wrong vni misses; unmapped V misses.
        assert_eq!(m.floating_ip_get(101, &[203, 0, 113, 7]), None);
        assert_eq!(m.floating_ip_get(100, &[203, 0, 113, 8]), None);
    }
}
