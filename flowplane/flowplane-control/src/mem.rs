//! In-memory `MapWriter` for testing `ControlCore` without CAP_BPF or a live map.
use crate::writer::{CtFlushScope, CtFlushScope6, MapWriter, Walk};
use flowplane_common::{
    DhcpConfig, FloatingIPKey, FwBind, IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue,
    LbBackend, LbKey, LbKey6, LbValue, MaglevKey, MeterState, NatKey, NatKey6, NatOwner,
    NatOwnerKey, NatOwnerKey6, NatValue, NatValue6, PortMeta, RouteValue, UnderlayValue,
};
use std::collections::{HashMap, HashSet};

/// Test knob: fail the upsert or the remove of exactly one `NAT_OWNERS{,6}` prefix, as a kernel
/// map write can. The default fails nothing.
#[derive(Default, Clone, Copy)]
pub struct NatOwnerFault<K> {
    pub upsert: Option<(u32, K)>,
    pub remove: Option<(u32, K)>,
}

#[derive(Default)]
pub struct MemMapWriter {
    pub routes: HashMap<(u32, [u8; 4], u32), RouteValue>,
    pub routes6: HashMap<(u32, [u8; 16], u32), RouteValue>,
    /// Test knobs: fail the remove of exactly one route, as a kernel map delete can.
    pub route_remove_fault: Option<(u32, [u8; 4], u32)>,
    pub route6_remove_fault: Option<(u32, [u8; 16], u32)>,
    pub nat: HashMap<NatKey, NatValue>,
    pub nat_ips: HashSet<(u32, [u8; 4])>,
    pub nat_owners: HashMap<(u32, NatOwnerKey), NatOwner>,
    // NAT66 (v6) siblings of the three v4 nat fields above.
    pub nat6: HashMap<NatKey6, NatValue6>,
    pub nat_ips6: HashSet<(u32, [u8; 16])>,
    pub nat_owners6: HashMap<(u32, NatOwnerKey6), NatOwner>,
    pub nat_owner_fault: NatOwnerFault<NatOwnerKey>,
    pub nat_owner6_fault: NatOwnerFault<NatOwnerKey6>,
    pub lb: HashMap<LbKey, LbValue>,
    pub lb6: HashMap<LbKey6, LbValue>,
    pub maglev: HashMap<MaglevKey, LbBackend>,
    /// Test knob: fail every `MAGLEV` write to this table.
    pub maglev_upsert_fault: Option<u32>,
    /// Test knob: cut the adopt walk of each named map (`"LB"`, `"FW_BIND"`, `"IFACE_META"`, ...)
    /// short after that many entries, as a kernel map walk can fail part-way.
    pub walk_cut: HashMap<&'static str, usize>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_bind: HashMap<u32, FwBind>,
    pub fw_scopes: HashMap<u64, crate::fwclass::Scope>,
    /// Call counters, so tests can assert an unchanged replace writes nothing.
    pub fw_scope_creates: usize,
    pub fw_bind_writes: usize,
    /// Test knob: fail every `FW_BIND` write.
    pub fw_bind_fault: bool,
    pub fw_epoch: u32,
    pub meter: HashMap<u32, MeterState>,
    pub dhcp_config: Option<DhcpConfig>,
    // INTERFACE domain.
    pub ports: HashMap<u32, PortMeta>,
    pub ifaces: HashMap<IfaceKey, IfaceValue>,
    pub ifaces6: HashMap<IfaceKey6, IfaceValue>,
    // IfaceMetaKey is only Copy/Clone (not Hash), so key the fake by the padded id array.
    pub iface_meta: HashMap<[u8; flowplane_common::IFACE_ID_MAX], IfaceMetaVal>,
    pub dhcp_meta_removed: Vec<u32>,
    pub floating_ips: HashMap<FloatingIPKey, [u8; 4]>,
    pub ct_flushes: Vec<CtFlushScope>,
    pub ct6_flushes: Vec<CtFlushScope6>,
    pub ct_iface_flushes: Vec<(u32, [u8; 4], [u8; 16])>,
}

impl MemMapWriter {
    fn walk<T>(&self, name: &str, all: impl Iterator<Item = T>) -> Walk<T> {
        match self.walk_cut.get(name) {
            Some(&n) => Walk {
                entries: all.take(n).collect(),
                error: Some(anyhow::anyhow!("injected {name} walk failure")),
            },
            None => Walk {
                entries: all.collect(),
                error: None,
            },
        }
    }
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
        if self.route_remove_fault == Some((vni, ipv4, p)) {
            anyhow::bail!("injected ROUTES remove failure");
        }
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
        if self.route6_remove_fault == Some((vni, ipv6, p)) {
            anyhow::bail!("injected ROUTES6 remove failure");
        }
        self.routes6.remove(&(vni, ipv6, p));
        Ok(())
    }
    fn route_entries(&self) -> Walk<(u32, [u8; 4], u32, RouteValue)> {
        let all = self.routes.iter().map(|(&(v, p, l), r)| (v, p, l, *r));
        self.walk("ROUTES", all)
    }
    fn route6_entries(&self) -> Walk<(u32, [u8; 16], u32, RouteValue)> {
        let all = self.routes6.iter().map(|(&(v, p, l), r)| (v, p, l, *r));
        self.walk("ROUTES6", all)
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
    fn nat_owner_upsert(&mut self, p: u32, k: NatOwnerKey, v: NatOwner) -> anyhow::Result<()> {
        if self.nat_owner_fault.upsert == Some((p, k)) {
            anyhow::bail!("injected NAT_OWNERS upsert failure");
        }
        self.nat_owners.insert((p, k), v);
        Ok(())
    }
    fn nat_owner_remove(&mut self, p: u32, k: &NatOwnerKey) -> anyhow::Result<()> {
        if self.nat_owner_fault.remove == Some((p, *k)) {
            anyhow::bail!("injected NAT_OWNERS remove failure");
        }
        self.nat_owners.remove(&(p, *k));
        Ok(())
    }
    fn nat_owner_entries(&self) -> Walk<(u32, NatOwnerKey, NatOwner)> {
        let all = self.nat_owners.iter().map(|((p, k), v)| (*p, *k, *v));
        self.walk("NAT_OWNERS", all)
    }
    fn nat6_upsert(&mut self, k: NatKey6, v: NatValue6) -> anyhow::Result<()> {
        self.nat6.insert(k, v);
        Ok(())
    }
    fn nat6_remove(&mut self, k: &NatKey6) -> anyhow::Result<()> {
        self.nat6.remove(k);
        Ok(())
    }
    fn nat6_get(&self, k: &NatKey6) -> Option<NatValue6> {
        self.nat6.get(k).copied()
    }
    fn nat_ips6_set(&mut self, vni: u32, ip: [u8; 16]) -> anyhow::Result<()> {
        self.nat_ips6.insert((vni, ip));
        Ok(())
    }
    fn nat_ips6_remove(&mut self, vni: u32, ip: [u8; 16]) -> anyhow::Result<()> {
        self.nat_ips6.remove(&(vni, ip));
        Ok(())
    }
    fn nat_owner6_upsert(&mut self, p: u32, k: NatOwnerKey6, v: NatOwner) -> anyhow::Result<()> {
        if self.nat_owner6_fault.upsert == Some((p, k)) {
            anyhow::bail!("injected NAT_OWNERS6 upsert failure");
        }
        self.nat_owners6.insert((p, k), v);
        Ok(())
    }
    fn nat_owner6_remove(&mut self, p: u32, k: &NatOwnerKey6) -> anyhow::Result<()> {
        if self.nat_owner6_fault.remove == Some((p, *k)) {
            anyhow::bail!("injected NAT_OWNERS6 remove failure");
        }
        self.nat_owners6.remove(&(p, *k));
        Ok(())
    }
    fn nat_owner6_entries(&self) -> Walk<(u32, NatOwnerKey6, NatOwner)> {
        let all = self.nat_owners6.iter().map(|((p, k), v)| (*p, *k, *v));
        self.walk("NAT_OWNERS6", all)
    }
    fn lb_upsert(&mut self, k: LbKey, v: LbValue) -> anyhow::Result<()> {
        self.lb.insert(k, v);
        Ok(())
    }
    fn lb_remove(&mut self, k: &LbKey) -> anyhow::Result<()> {
        self.lb.remove(k);
        Ok(())
    }
    fn lb6_upsert(&mut self, k: LbKey6, v: LbValue) -> anyhow::Result<()> {
        self.lb6.insert(k, v);
        Ok(())
    }
    fn lb6_remove(&mut self, k: &LbKey6) -> anyhow::Result<()> {
        self.lb6.remove(k);
        Ok(())
    }
    fn maglev_upsert(&mut self, k: MaglevKey, v: LbBackend) -> anyhow::Result<()> {
        if self.maglev_upsert_fault == Some(k.table_id) {
            anyhow::bail!("injected MAGLEV write failure");
        }
        self.maglev.insert(k, v);
        Ok(())
    }
    fn maglev_remove(&mut self, k: &MaglevKey) -> anyhow::Result<()> {
        self.maglev.remove(k);
        Ok(())
    }
    fn maglev_get(&self, k: &MaglevKey) -> anyhow::Result<Option<LbBackend>> {
        Ok(self.maglev.get(k).copied())
    }
    fn lb_entries(&self) -> Walk<(LbKey, LbValue)> {
        self.walk("LB", self.lb.iter().map(|(k, v)| (*k, *v)))
    }
    fn lb6_entries(&self) -> Walk<(LbKey6, LbValue)> {
        self.walk("LB6", self.lb6.iter().map(|(k, v)| (*k, *v)))
    }
    fn maglev_entries(&self) -> Walk<(MaglevKey, LbBackend)> {
        self.walk("MAGLEV", self.maglev.iter().map(|(k, v)| (*k, *v)))
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
    fn fw_scope_create(&mut self, scope: &crate::fwclass::Scope) -> anyhow::Result<()> {
        self.fw_scope_creates += 1;
        self.fw_scopes.insert(scope.id, scope.clone());
        Ok(())
    }
    fn fw_scope_delete(&mut self, id: u64) -> anyhow::Result<()> {
        self.fw_scopes.remove(&id);
        Ok(())
    }
    fn fw_bind_upsert(&mut self, ifindex: u32, val: FwBind) -> anyhow::Result<()> {
        if self.fw_bind_fault {
            anyhow::bail!("injected FW_BIND write failure");
        }
        self.fw_bind_writes += 1;
        self.fw_bind.insert(ifindex, val);
        Ok(())
    }
    fn fw_bind_remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.fw_bind.remove(&ifindex);
        Ok(())
    }
    fn fw_epoch_bump(&mut self) -> anyhow::Result<()> {
        self.fw_epoch = self.fw_epoch.wrapping_add(1);
        Ok(())
    }
    fn fw_bind_entries(&self) -> Walk<(u32, FwBind)> {
        self.walk("FW_BIND", self.fw_bind.iter().map(|(k, v)| (*k, *v)))
    }
    fn fw_scope_ids(&self) -> Walk<u64> {
        self.walk("FW_SCOPES", self.fw_scopes.keys().copied())
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
    fn iface_meta_entries(&self) -> Walk<(IfaceMetaKey, IfaceMetaVal)> {
        let all = self
            .iface_meta
            .iter()
            .map(|(id, v)| (IfaceMetaKey { id: *id }, *v));
        self.walk("IFACE_META", all)
    }
    fn iface_meta_remove(&mut self, k: &IfaceMetaKey) -> anyhow::Result<()> {
        self.iface_meta.remove(&k.id);
        Ok(())
    }
    fn dhcp_meta_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.dhcp_meta_removed.push(i);
        Ok(())
    }
    fn floating_ips_upsert(&mut self, k: FloatingIPKey, v: [u8; 4]) -> anyhow::Result<()> {
        self.floating_ips.insert(k, v);
        Ok(())
    }
    fn floating_ips_remove(&mut self, k: &FloatingIPKey) -> anyhow::Result<()> {
        self.floating_ips.remove(k);
        Ok(())
    }
    fn floating_ips_get(&self, k: &FloatingIPKey) -> Option<[u8; 4]> {
        self.floating_ips.get(k).copied()
    }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> {
        self.ct_flushes.push(s);
        Ok(())
    }
    fn conntrack6_flush(&mut self, s: CtFlushScope6) -> anyhow::Result<()> {
        self.ct6_flushes.push(s);
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
