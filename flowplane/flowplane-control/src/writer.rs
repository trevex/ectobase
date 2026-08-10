//! The control-plane map write surface. eBPF (`AyaWriter`) and DPDK (`SharedConfigMaps`)
//! each implement this; `ControlCore` programs maps only through it.
use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRule6, FwRuleKey, IfaceKey, IfaceMetaKey, IfaceMetaVal,
    IfaceValue, LbKey, LbValue, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry,
    PortMeta, RouteValue, UnderlayValue, VipKey,
};

/// The set of conntrack entries a NAT teardown must invalidate. eBPF flushes matching CT map
/// entries; DPDK bumps the config-generation (spec §5a). Fields mirror `ct_flush_for_guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtFlushScope {
    pub vni: u32,
    pub guest_ip: [u8; 4],
    pub nat_ip: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// Uniform config-map write surface. All methods return `anyhow::Result<()>` except the reads
/// used by conflict checks. Method names are `<map>_<op>`.
pub trait MapWriter {
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()>;
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()>;
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()>;
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<()>;
    fn nat_upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()>;
    fn nat_remove(&mut self, key: &NatKey) -> anyhow::Result<()>;
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    fn nat_ips_set(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    fn nat_ips_remove(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    fn neigh_nat_upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()>;
    fn neigh_nat_count_set(&mut self, count: u32) -> anyhow::Result<()>;
    fn lb_upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()>;
    fn lb_remove(&mut self, key: &LbKey) -> anyhow::Result<()>;
    fn maglev_upsert(&mut self, key: MaglevKey, val: [u8; 16]) -> anyhow::Result<()>;
    fn maglev_remove(&mut self, key: &MaglevKey) -> anyhow::Result<()>;
    fn underlay_upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()>;
    fn underlay_remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()>;
    fn underlay_get(&self, key: &[u8; 16]) -> Option<UnderlayValue>;
    fn fw_rules_upsert(&mut self, key: FwRuleKey, val: FwRule) -> anyhow::Result<()>;
    fn fw_rules_remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()>;
    fn fw_meta_upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()>;
    /// IPv6 firewall rule upsert (`FW_RULES6`). DEFAULT no-op — real backends override in tasks 7/9.
    fn fw_rules6_upsert(&mut self, _key: FwRuleKey, _val: FwRule6) -> anyhow::Result<()> {
        Ok(())
    }
    /// IPv6 firewall rule remove (`FW_RULES6`). DEFAULT no-op — real backends override in tasks 7/9.
    fn fw_rules6_remove(&mut self, _key: &FwRuleKey) -> anyhow::Result<()> {
        Ok(())
    }
    /// IPv6 firewall meta upsert (`FW_META6`). DEFAULT no-op — real backends override in tasks 7/9.
    fn fw_meta6_upsert(&mut self, _ifindex: u32, _val: FwMeta) -> anyhow::Result<()> {
        Ok(())
    }
    fn meter_upsert(&mut self, ifindex: u32, val: MeterState) -> anyhow::Result<()>;
    fn meter_remove(&mut self, ifindex: &u32) -> anyhow::Result<()>;
    fn dhcp_config_set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()>;
    // INTERFACE domain: the per-interface programming maps `program_interface` writes and
    // the VNI-purge / detach reconciliation reads.
    fn ports_upsert(&mut self, ifindex: u32, meta: PortMeta) -> anyhow::Result<()>;
    fn ports_remove(&mut self, ifindex: u32) -> anyhow::Result<()>;
    fn ifaces_upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()>;
    fn ifaces_remove(&mut self, key: IfaceKey) -> anyhow::Result<()>;
    fn ifaces_get(&self, key: &IfaceKey) -> Option<IfaceValue>;
    fn iface_meta_upsert(&mut self, key: IfaceMetaKey, val: IfaceMetaVal) -> anyhow::Result<()>;
    fn iface_meta_remove(&mut self, key: &IfaceMetaKey) -> anyhow::Result<()>;
    fn dhcp_meta_remove(&mut self, ifindex: u32) -> anyhow::Result<()>;
    fn vips_upsert(&mut self, key: VipKey, val: [u8; 4]) -> anyhow::Result<()>;
    fn vips_remove(&mut self, key: &VipKey) -> anyhow::Result<()>;
    fn vips_get(&self, key: &VipKey) -> Option<[u8; 4]>;
    fn conntrack_flush(&mut self, scope: CtFlushScope) -> anyhow::Result<()>;
}
