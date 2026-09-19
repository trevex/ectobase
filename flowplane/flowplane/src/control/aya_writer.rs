//! `MapWriter` over the eBPF aya map wrappers. Owns the config maps moved out of `Control::Inner`.
use std::sync::Arc;

use parking_lot::Mutex;

use crate::maps::{
    Conntrack, Conntrack6, DhcpConfigMap, DhcpMetaMap, FloatingIPs, FwBindMap, FwEpochMap,
    FwScopes, IfaceMetaMap, Interfaces, Interfaces6, Lb, Maglev, Meter, Nat, Nat6, NatCt6, NatIps,
    NatIps6, NatOwners, NatOwners6, PortMetaMap, Routes, Routes6, Underlay,
};
use flowplane_common::{
    CtKey, CtKey6, FloatingIPKey, IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue,
    NatKey, NatKey6, NatOwner, NatOwnerKey, NatOwnerKey6, NatValue, NatValue6, PortMeta,
    RouteValue,
};
use flowplane_control::{CtFlushScope, CtFlushScope6, MapWriter};

pub struct AyaWriter {
    pub routes: Routes,
    pub routes6: Routes6,
    // NAT domain.
    pub nat: Nat,
    pub nat_ips: NatIps,
    pub nat_owners: NatOwners,
    // NAT66 (v6) domain — siblings of the three v4 nat handles above, plus the dedicated NAT66
    // conntrack handle the teardown flush scans.
    pub nat6: Nat6,
    pub nat_ips6: NatIps6,
    pub nat_owners6: NatOwners6,
    pub nat_ct6: NatCt6,
    // LB domain: LB service map, Maglev table, and the UNDERLAY map. UNDERLAY is also
    // read/written by the interface + edge paths via `core.writer_mut()`.
    pub lb: Lb,
    pub lb6: crate::maps::Lb6,
    pub maglev: Maglev,
    pub underlay: Underlay,
    // FIREWALL classifier: interface -> scopes binding, the scopes' tries, and the epoch that
    // carries a binding change to established flows.
    pub fw_bind: FwBindMap,
    pub fw_scopes: FwScopes,
    pub fw_epoch: FwEpochMap,
    // INTERFACE + QoS + DHCP domain: the last config maps, moved out of `Inner`. After
    // this, `AyaWriter` owns ALL config maps and `Inner` holds only device/loader fields + `core`.
    pub ports: PortMetaMap,
    pub ifaces: Interfaces,
    pub ifaces6: Interfaces6,
    pub floating_ips: FloatingIPs,
    pub meter: Meter,
    pub dhcp_config: DhcpConfigMap,
    pub dhcp_meta: DhcpMetaMap,
    /// Restart journal: interface_id -> rebuild detail. Written on attach/detach; scanned on adopt.
    pub iface_meta: IfaceMetaMap,
    /// Shared conntrack handle (same Arc `Control` holds for the GC task); the NAT teardown flush
    /// scans+removes matching CONNTRACK entries here.
    pub conntrack: Arc<Mutex<Conntrack>>,
    /// v6 firewall-only conntrack handle; the interface-detach flush scans+removes matching
    /// CONNTRACK6 entries here (v6 has no userspace GC — the LRU map auto-evicts otherwise).
    pub conntrack6: Arc<Mutex<Conntrack6>>,
}

impl AyaWriter {
    /// All `IFACE_META` restart-journal entries (adopt scan). Reaches the raw map, which lives here
    /// now; not part of the `MapWriter` trait.
    pub fn iface_meta_entries(&self) -> Vec<(IfaceMetaKey, IfaceMetaVal)> {
        self.iface_meta.entries()
    }

    /// Count of live `INTERFACES` entries (adopt journal-drift cross-check).
    pub fn ifaces_count(&self) -> usize {
        self.ifaces.entries().len()
    }
}

/// Flush CONNTRACK entries whose egress 5-tuple originated from `(vni, guest_ip)`.
/// For NAT flows this removes both the forward entry (CT_REWRITE_SRC, key.src_ip == gip)
/// and the reverse entry (CT_REWRITE_DST, key.dst_ip == nat_ip with xlate_port in range).
///
/// The CONNTRACK map lives in the eBPF backend, so the scan/remove belongs to
/// `AyaWriter::conntrack_flush`.
fn ct_flush_for_guest(
    ct: &mut Conntrack,
    vni: u32,
    gip: [u8; 4],
    nat_ip: [u8; 4],
    port_min: u16,
    port_max: u16,
) {
    // Collect all keys to remove first to avoid borrow issues during iteration.
    let to_remove: Vec<CtKey> = ct
        .entries()
        .into_iter()
        .filter_map(|(k, e)| {
            if k.vni != vni {
                return None;
            }
            // Forward NAT entry: src_ip == guest IP, CT_REWRITE_SRC set.
            let is_fwd = k.src_ip == gip
                && (e.flags & flowplane_common::CT_REWRITE_SRC != 0
                    || e.flags & flowplane_common::CT_F_SRC_NAT != 0);
            // Reverse NAT entry: dst_ip == nat_ip, dst_port in the NAT port range.
            let is_rev = k.dst_ip == nat_ip
                && k.dst_port >= port_min
                && k.dst_port < port_max
                && e.flags & flowplane_common::CT_REWRITE_DST != 0;
            if is_fwd || is_rev {
                Some(k)
            } else {
                None
            }
        })
        .collect();
    for k in to_remove {
        let _ = ct.remove(&k);
    }
}

/// v6 sibling of [`ct_flush_for_guest`] — flush the `NAT_CT6` entries for a NAT66 flow: the forward
/// entry (`CtKey6.src_ip == gip`, CT_REWRITE_SRC/CT_F_SRC_NAT) and the peer-independent reverse
/// entry (`CtKey6.dst_ip == nat_ip`, dst_port in range, CT_REWRITE_DST).
fn ct_flush_for_guest6(
    ct: &mut NatCt6,
    vni: u32,
    gip: [u8; 16],
    nat_ip: [u8; 16],
    port_min: u16,
    port_max: u16,
) {
    let to_remove: Vec<CtKey6> = ct
        .entries()
        .into_iter()
        .filter_map(|(k, e)| {
            if k.vni != vni {
                return None;
            }
            let is_fwd = k.src_ip == gip
                && (e.flags & flowplane_common::CT_REWRITE_SRC != 0
                    || e.flags & flowplane_common::CT_F_SRC_NAT != 0);
            let is_rev = k.dst_ip == nat_ip
                && k.dst_port >= port_min
                && k.dst_port < port_max
                && e.flags & flowplane_common::CT_REWRITE_DST != 0;
            if is_fwd || is_rev {
                Some(k)
            } else {
                None
            }
        })
        .collect();
    for k in to_remove {
        let _ = ct.remove(&k);
    }
}

impl MapWriter for AyaWriter {
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        p: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        self.routes.upsert(vni, ipv4, p, val)
    }
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], p: u32) -> anyhow::Result<()> {
        self.routes.remove(vni, ipv4, p)
    }
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        p: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        self.routes6.upsert(vni, ipv6, p, val)
    }
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], p: u32) -> anyhow::Result<()> {
        self.routes6.remove(vni, ipv6, p)
    }
    fn nat_upsert(&mut self, k: NatKey, v: NatValue) -> anyhow::Result<()> {
        self.nat.upsert(k, v)
    }
    fn nat_remove(&mut self, k: &NatKey) -> anyhow::Result<()> {
        self.nat.remove(k)
    }
    fn nat_get(&self, k: &NatKey) -> Option<NatValue> {
        self.nat.get(k)
    }
    fn nat_ips_set(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> {
        self.nat_ips.set(vni, ip)
    }
    fn nat_ips_remove(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> {
        self.nat_ips.remove(vni, ip)
    }
    fn nat_owner_upsert(&mut self, p: u32, k: NatOwnerKey, v: NatOwner) -> anyhow::Result<()> {
        self.nat_owners.upsert(p, k, v)
    }
    fn nat_owner_remove(&mut self, p: u32, k: &NatOwnerKey) -> anyhow::Result<()> {
        self.nat_owners.remove(p, *k)
    }
    fn nat_owner_entries(&self) -> Vec<(u32, NatOwnerKey, NatOwner)> {
        self.nat_owners.entries()
    }
    fn nat6_upsert(&mut self, k: NatKey6, v: NatValue6) -> anyhow::Result<()> {
        self.nat6.upsert(k, v)
    }
    fn nat6_remove(&mut self, k: &NatKey6) -> anyhow::Result<()> {
        self.nat6.remove(k)
    }
    fn nat6_get(&self, k: &NatKey6) -> Option<NatValue6> {
        self.nat6.get(k)
    }
    fn nat_ips6_set(&mut self, vni: u32, ip: [u8; 16]) -> anyhow::Result<()> {
        self.nat_ips6.set(vni, ip)
    }
    fn nat_ips6_remove(&mut self, vni: u32, ip: [u8; 16]) -> anyhow::Result<()> {
        self.nat_ips6.remove(vni, ip)
    }
    fn nat_owner6_upsert(&mut self, p: u32, k: NatOwnerKey6, v: NatOwner) -> anyhow::Result<()> {
        self.nat_owners6.upsert(p, k, v)
    }
    fn nat_owner6_remove(&mut self, p: u32, k: &NatOwnerKey6) -> anyhow::Result<()> {
        self.nat_owners6.remove(p, *k)
    }
    fn nat_owner6_entries(&self) -> Vec<(u32, NatOwnerKey6, NatOwner)> {
        self.nat_owners6.entries()
    }
    fn lb_upsert(
        &mut self,
        k: flowplane_common::LbKey,
        v: flowplane_common::LbValue,
    ) -> anyhow::Result<()> {
        self.lb.upsert(k, v)
    }
    fn lb_remove(&mut self, k: &flowplane_common::LbKey) -> anyhow::Result<()> {
        self.lb.remove(k)
    }
    fn lb6_upsert(
        &mut self,
        k: flowplane_common::LbKey6,
        v: flowplane_common::LbValue,
    ) -> anyhow::Result<()> {
        self.lb6.upsert(k, v)
    }
    fn lb6_remove(&mut self, k: &flowplane_common::LbKey6) -> anyhow::Result<()> {
        self.lb6.remove(k)
    }
    fn maglev_upsert(
        &mut self,
        k: flowplane_common::MaglevKey,
        v: flowplane_common::LbBackend,
    ) -> anyhow::Result<()> {
        self.maglev.upsert(k, v)
    }
    fn maglev_remove(&mut self, k: &flowplane_common::MaglevKey) -> anyhow::Result<()> {
        self.maglev.remove(k)
    }
    fn underlay_upsert(
        &mut self,
        k: [u8; 16],
        v: flowplane_common::UnderlayValue,
    ) -> anyhow::Result<()> {
        self.underlay.upsert(k, v)
    }
    fn underlay_remove(&mut self, k: &[u8; 16]) -> anyhow::Result<()> {
        self.underlay.remove(k)
    }
    fn underlay_get(&self, k: &[u8; 16]) -> Option<flowplane_common::UnderlayValue> {
        self.underlay.get(k)
    }
    fn fw_scope_create(&mut self, scope: &flowplane_control::fwclass::Scope) -> anyhow::Result<()> {
        self.fw_scopes.create(scope)
    }
    fn fw_scope_delete(&mut self, id: u64) -> anyhow::Result<()> {
        self.fw_scopes.delete(id)
    }
    fn fw_bind_upsert(
        &mut self,
        ifindex: u32,
        val: flowplane_common::FwBind,
    ) -> anyhow::Result<()> {
        self.fw_bind.upsert(ifindex, val)
    }
    fn fw_bind_remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.fw_bind.remove(ifindex)
    }
    fn fw_epoch_bump(&mut self) -> anyhow::Result<()> {
        self.fw_epoch.bump()
    }
    fn fw_bind_entries(&self) -> Vec<(u32, flowplane_common::FwBind)> {
        self.fw_bind.entries()
    }
    fn fw_scope_ids(&self) -> Vec<u64> {
        self.fw_scopes.ids()
    }
    fn meter_upsert(&mut self, i: u32, v: flowplane_common::MeterState) -> anyhow::Result<()> {
        self.meter.upsert(i, v)
    }
    fn meter_remove(&mut self, i: &u32) -> anyhow::Result<()> {
        self.meter.remove(i)
    }
    fn dhcp_config_set(&mut self, c: &flowplane_common::DhcpConfig) -> anyhow::Result<()> {
        self.dhcp_config.set(c)
    }
    fn ports_upsert(&mut self, i: u32, m: PortMeta) -> anyhow::Result<()> {
        self.ports.upsert(i, m)
    }
    fn ports_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.ports.remove(i)
    }
    fn ifaces_upsert(&mut self, k: IfaceKey, v: IfaceValue) -> anyhow::Result<()> {
        self.ifaces.upsert(k, v)
    }
    fn ifaces_remove(&mut self, k: IfaceKey) -> anyhow::Result<()> {
        self.ifaces.remove(k)
    }
    fn ifaces_get(&self, k: &IfaceKey) -> Option<IfaceValue> {
        self.ifaces.get(k)
    }
    fn ifaces6_upsert(&mut self, k: IfaceKey6, v: IfaceValue) -> anyhow::Result<()> {
        self.ifaces6.upsert(k, v)
    }
    fn ifaces6_remove(&mut self, k: IfaceKey6) -> anyhow::Result<()> {
        self.ifaces6.remove(k)
    }
    fn ifaces6_get(&self, k: &IfaceKey6) -> Option<IfaceValue> {
        self.ifaces6.get(k)
    }
    fn iface_meta_upsert(&mut self, k: IfaceMetaKey, v: IfaceMetaVal) -> anyhow::Result<()> {
        self.iface_meta.upsert(k, v)
    }
    fn iface_meta_remove(&mut self, k: &IfaceMetaKey) -> anyhow::Result<()> {
        self.iface_meta.remove(k)
    }
    fn dhcp_meta_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.dhcp_meta.remove(i)
    }
    fn floating_ips_upsert(&mut self, k: FloatingIPKey, v: [u8; 4]) -> anyhow::Result<()> {
        self.floating_ips.upsert(k, v)
    }
    fn floating_ips_remove(&mut self, k: &FloatingIPKey) -> anyhow::Result<()> {
        self.floating_ips.remove(k)
    }
    fn floating_ips_get(&self, k: &FloatingIPKey) -> Option<[u8; 4]> {
        self.floating_ips.get(k)
    }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> {
        // Flush CT entries for this guest under the conntrack lock (a separate lock from the
        // control inner). Mirrors the former `delete_nat` teardown.
        let mut ct = self.conntrack.lock();
        ct_flush_for_guest(&mut ct, s.vni, s.guest_ip, s.nat_ip, s.port_min, s.port_max);
        Ok(())
    }
    fn conntrack6_flush(&mut self, s: CtFlushScope6) -> anyhow::Result<()> {
        // NAT66 teardown: flush the guest's NAT_CT6 entries. AyaWriter owns the sole handle (no GC
        // task holds it — the LRU map self-evicts), so no separate lock is needed.
        ct_flush_for_guest6(
            &mut self.nat_ct6,
            s.vni,
            s.guest_ip6,
            s.nat_ip6,
            s.port_min,
            s.port_max,
        );
        Ok(())
    }

    fn conntrack_flush_interface(
        &mut self,
        vni: u32,
        guest_ip: [u8; 4],
        guest_ip6: [u8; 16],
    ) -> anyhow::Result<()> {
        // Remove every v4 CT entry for this (vni, guest_ip) — src OR dst — so a reschedule of the
        // same overlay IP starts with a clean firewall state (no inherited established bypass).
        {
            let mut ct = self.conntrack.lock();
            let to_remove: Vec<CtKey> = ct
                .entries()
                .into_iter()
                .filter_map(|(k, _)| {
                    if k.vni == vni && (k.src_ip == guest_ip || k.dst_ip == guest_ip) {
                        Some(k)
                    } else {
                        None
                    }
                })
                .collect();
            for k in to_remove {
                let _ = ct.remove(&k);
            }
        }
        // Same for the v6 firewall conntrack (skip when the interface has no v6 overlay IP).
        if guest_ip6 != [0u8; 16] {
            let mut ct6 = self.conntrack6.lock();
            let to_remove: Vec<CtKey6> = ct6
                .entries()
                .into_iter()
                .filter_map(|(k, _)| {
                    if k.vni == vni && (k.src_ip == guest_ip6 || k.dst_ip == guest_ip6) {
                        Some(k)
                    } else {
                        None
                    }
                })
                .collect();
            for k in to_remove {
                let _ = ct6.remove(&k);
            }
        }
        Ok(())
    }
}
