//! In-memory `MapWriter` for testing `ControlCore` without CAP_BPF or a live map.
use crate::writer::{CtFlushScope, MapWriter};
use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRule6, FwRuleKey, IfaceKey, IfaceKey6, IfaceMetaKey,
    IfaceMetaVal, IfaceValue, LbKey, LbValue, MaglevKey, MeterState, NatKey, NatValue,
    NeighborNatEntry, PortMeta, RouteValue, UnderlayValue, VipKey,
};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct MemMapWriter {
    pub routes: HashMap<(u32, [u8; 4], u32), RouteValue>,
    pub routes6: HashMap<(u32, [u8; 16], u32), RouteValue>,
    pub nat: HashMap<NatKey, NatValue>,
    pub nat_ips: HashSet<(u32, [u8; 4])>,
    pub neigh_nat: HashMap<u32, NeighborNatEntry>,
    pub neigh_nat_count: u32,
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_rules: HashMap<FwRuleKey, FwRule>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub fw_rules6: HashMap<FwRuleKey, FwRule6>,
    pub fw_meta6: HashMap<u32, FwMeta>,
    pub meter: HashMap<u32, MeterState>,
    pub dhcp_config: Option<DhcpConfig>,
    // INTERFACE domain.
    pub ports: HashMap<u32, PortMeta>,
    pub ifaces: HashMap<IfaceKey, IfaceValue>,
    pub ifaces6: HashMap<IfaceKey6, IfaceValue>,
    // IfaceMetaKey is only Copy/Clone (not Hash), so key the fake by the padded id array.
    pub iface_meta: HashMap<[u8; flowplane_common::IFACE_ID_MAX], IfaceMetaVal>,
    pub dhcp_meta_removed: Vec<u32>,
    pub vips: HashMap<VipKey, [u8; 4]>,
    pub ct_flushes: Vec<CtFlushScope>,
    pub ct_iface_flushes: Vec<(u32, [u8; 4], [u8; 16])>,
}

impl MapWriter for MemMapWriter {
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        p: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        self.routes.insert((vni, ipv4, p), val);
        Ok(())
    }
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], p: u32) -> anyhow::Result<()> {
        self.routes.remove(&(vni, ipv4, p));
        Ok(())
    }
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        p: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        self.routes6.insert((vni, ipv6, p), val);
        Ok(())
    }
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], p: u32) -> anyhow::Result<()> {
        self.routes6.remove(&(vni, ipv6, p));
        Ok(())
    }
    fn nat_upsert(&mut self, k: NatKey, v: NatValue) -> anyhow::Result<()> {
        self.nat.insert(k, v);
        Ok(())
    }
    fn nat_remove(&mut self, k: &NatKey) -> anyhow::Result<()> {
        self.nat.remove(k);
        Ok(())
    }
    fn nat_get(&self, k: &NatKey) -> Option<NatValue> {
        self.nat.get(k).copied()
    }
    fn nat_ips_set(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> {
        self.nat_ips.insert((vni, ip));
        Ok(())
    }
    fn nat_ips_remove(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> {
        self.nat_ips.remove(&(vni, ip));
        Ok(())
    }
    fn neigh_nat_upsert(&mut self, i: u32, v: NeighborNatEntry) -> anyhow::Result<()> {
        self.neigh_nat.insert(i, v);
        Ok(())
    }
    fn neigh_nat_count_set(&mut self, c: u32) -> anyhow::Result<()> {
        self.neigh_nat_count = c;
        Ok(())
    }
    fn lb_upsert(&mut self, k: LbKey, v: LbValue) -> anyhow::Result<()> {
        self.lb.insert(k, v);
        Ok(())
    }
    fn lb_remove(&mut self, k: &LbKey) -> anyhow::Result<()> {
        self.lb.remove(k);
        Ok(())
    }
    fn maglev_upsert(&mut self, k: MaglevKey, v: [u8; 16]) -> anyhow::Result<()> {
        self.maglev.insert(k, v);
        Ok(())
    }
    fn maglev_remove(&mut self, k: &MaglevKey) -> anyhow::Result<()> {
        self.maglev.remove(k);
        Ok(())
    }
    fn underlay_upsert(&mut self, k: [u8; 16], v: UnderlayValue) -> anyhow::Result<()> {
        self.underlay.insert(k, v);
        Ok(())
    }
    fn underlay_remove(&mut self, k: &[u8; 16]) -> anyhow::Result<()> {
        self.underlay.remove(k);
        Ok(())
    }
    fn underlay_get(&self, k: &[u8; 16]) -> Option<UnderlayValue> {
        self.underlay.get(k).copied()
    }
    fn fw_rules_upsert(&mut self, k: FwRuleKey, v: FwRule) -> anyhow::Result<()> {
        self.fw_rules.insert(k, v);
        Ok(())
    }
    fn fw_rules_remove(&mut self, k: &FwRuleKey) -> anyhow::Result<()> {
        self.fw_rules.remove(k);
        Ok(())
    }
    fn fw_meta_upsert(&mut self, i: u32, v: FwMeta) -> anyhow::Result<()> {
        self.fw_meta.insert(i, v);
        Ok(())
    }
    fn fw_rules6_upsert(&mut self, k: FwRuleKey, v: FwRule6) -> anyhow::Result<()> {
        self.fw_rules6.insert(k, v);
        Ok(())
    }
    fn fw_rules6_remove(&mut self, k: &FwRuleKey) -> anyhow::Result<()> {
        self.fw_rules6.remove(k);
        Ok(())
    }
    fn fw_meta6_upsert(&mut self, i: u32, v: FwMeta) -> anyhow::Result<()> {
        self.fw_meta6.insert(i, v);
        Ok(())
    }
    fn meter_upsert(&mut self, i: u32, v: MeterState) -> anyhow::Result<()> {
        self.meter.insert(i, v);
        Ok(())
    }
    fn meter_remove(&mut self, i: &u32) -> anyhow::Result<()> {
        self.meter.remove(i);
        Ok(())
    }
    fn dhcp_config_set(&mut self, c: &DhcpConfig) -> anyhow::Result<()> {
        self.dhcp_config = Some(*c);
        Ok(())
    }
    fn ports_upsert(&mut self, i: u32, m: PortMeta) -> anyhow::Result<()> {
        self.ports.insert(i, m);
        Ok(())
    }
    fn ports_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.ports.remove(&i);
        Ok(())
    }
    fn ifaces_upsert(&mut self, k: IfaceKey, v: IfaceValue) -> anyhow::Result<()> {
        self.ifaces.insert(k, v);
        Ok(())
    }
    fn ifaces_remove(&mut self, k: IfaceKey) -> anyhow::Result<()> {
        self.ifaces.remove(&k);
        Ok(())
    }
    fn ifaces_get(&self, k: &IfaceKey) -> Option<IfaceValue> {
        self.ifaces.get(k).copied()
    }
    fn ifaces6_upsert(&mut self, k: IfaceKey6, v: IfaceValue) -> anyhow::Result<()> {
        self.ifaces6.insert(k, v);
        Ok(())
    }
    fn ifaces6_remove(&mut self, k: IfaceKey6) -> anyhow::Result<()> {
        self.ifaces6.remove(&k);
        Ok(())
    }
    fn ifaces6_get(&self, k: &IfaceKey6) -> Option<IfaceValue> {
        self.ifaces6.get(k).copied()
    }
    fn iface_meta_upsert(&mut self, k: IfaceMetaKey, v: IfaceMetaVal) -> anyhow::Result<()> {
        self.iface_meta.insert(k.id, v);
        Ok(())
    }
    fn iface_meta_remove(&mut self, k: &IfaceMetaKey) -> anyhow::Result<()> {
        self.iface_meta.remove(&k.id);
        Ok(())
    }
    fn dhcp_meta_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.dhcp_meta_removed.push(i);
        Ok(())
    }
    fn vips_upsert(&mut self, k: VipKey, v: [u8; 4]) -> anyhow::Result<()> {
        self.vips.insert(k, v);
        Ok(())
    }
    fn vips_remove(&mut self, k: &VipKey) -> anyhow::Result<()> {
        self.vips.remove(k);
        Ok(())
    }
    fn vips_get(&self, k: &VipKey) -> Option<[u8; 4]> {
        self.vips.get(k).copied()
    }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> {
        self.ct_flushes.push(s);
        Ok(())
    }
    fn conntrack_flush_interface(
        &mut self,
        vni: u32,
        guest_ip: [u8; 4],
        guest_ip6: [u8; 16],
    ) -> anyhow::Result<()> {
        self.ct_iface_flushes.push((vni, guest_ip, guest_ip6));
        Ok(())
    }
}
