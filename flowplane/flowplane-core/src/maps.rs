use flowplane_common::{
    CtEntry, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local,
    MaglevKey, MeterState, NatKey, NatValue, RouteValue, UnderlayValue,
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
    /// Firewall-only IPv6 conntrack lookup (`CONNTRACK6` map). DEFAULT `None`: backends that have not
    /// wired the v6 firewall datapath (the eBPF `GlobalMaps` and DPDK `DpdkMaps` until their v6
    /// tasks land) return `None`, so v6 conntrack is simply absent there. The sim `MemMaps` overrides
    /// this with a real `HashMap`-backed store.
    fn conntrack6_get(&self, _key: &CtKey6) -> Option<CtEntry> {
        None
    }
    /// Firewall-only IPv6 conntrack insert (`CONNTRACK6` map). DEFAULT no-op — see [`Self::conntrack6_get`].
    fn conntrack6_insert(&mut self, _key: CtKey6, _entry: CtEntry) {}
    /// IPv6 firewall meta (`FW_META6`). DEFAULT `None` — a backend without v6 fw wiring denies v6 by
    /// default (see [`crate::firewall::fw_eval_dir6`]). Overridden by the sim `MemMaps`; the eBPF
    /// `GlobalMaps` and DPDK `DpdkMaps` gain overrides in their later v6-firewall tasks.
    fn fw_meta6(&self, _ifindex: u32) -> Option<FwMeta> {
        None
    }
    /// IPv6 firewall rule slot (`FW_RULES6`). DEFAULT `None` — see [`Self::fw_meta6`].
    fn fw_rule6(&self, _key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        None
    }
    fn lb_get(&self, key: &LbKey) -> Option<LbValue>;
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]>;
    /// Network-NAT config for a `(vni, guest-ipv4)` pair (`NAT` map).
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    /// Is `(vni, ip)` a registered public NAT IP (the `NAT_IPS` set)? NAT returns are demuxed
    /// peer-independently: when the inner dst is a registered nat_ip, the external src ip+port are
    /// zeroed so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)` reverse entry.
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool;
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
    /// Per-interface egress token-bucket state (`METER[ifindex]`). `None` = no rate limit configured.
    fn meter_get(&self, ifindex: u32) -> Option<MeterState>;
    /// Store the refilled per-interface token-bucket state back (`METER[ifindex]`).
    fn meter_update(&mut self, ifindex: u32, state: MeterState);
}
