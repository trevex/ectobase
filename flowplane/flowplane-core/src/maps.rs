use flowplane_common::{
    CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local,
    MaglevKey, NatKey, NatValue, RouteValue, UnderlayValue,
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
    /// Network-NAT config for a `(vni, guest-ipv4)` pair (`NAT` map).
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    /// Exact-match (`/32`) route lookup for an inner IPv4 dst in a VNI (`ROUTES` LPM trie, queried at
    /// prefix_len 64 = 32 VNI bits + 32 host bits — the same lookup the eBPF egress does).
    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue>;
    /// Exact-match (`/128`) route lookup for an inner IPv6 dst in a VNI (`ROUTES6` LPM trie, queried
    /// at prefix_len 160 = 32 VNI bits + 128 host bits).
    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue>;
    /// Server-wide DHCP config (`DHCP_CONFIG[0]`): MTU + DNS server lists. `None` if unset.
    fn dhcp_config(&self) -> Option<DhcpConfig>;
    /// Per-interface DHCP config (`DHCP_META[ifindex]`): hostname + PXE. `None` if unset.
    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta>;
}
