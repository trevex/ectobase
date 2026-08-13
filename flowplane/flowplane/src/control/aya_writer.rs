//! `MapWriter` over the eBPF aya map wrappers. Owns the config maps moved out of `Control::Inner`.
use std::sync::Arc;

use parking_lot::Mutex;

use crate::maps::{
    Conntrack, Conntrack6, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwMetaMap6, FwRules, FwRules6,
    IfaceMetaMap, Interfaces, Lb, Maglev, Meter, Nat, NatIps, NeighborNat, NeighborNatCount,
    PortMetaMap, Routes, Routes6, Underlay, Vips,
};
use flowplane_common::{
    CtKey, CtKey6, IfaceKey, IfaceMetaKey, IfaceMetaVal, IfaceValue, NatKey, NatValue,
    NeighborNatEntry, PortMeta, RouteValue, VipKey,
};
use flowplane_control::{CtFlushScope, MapWriter};

pub struct AyaWriter {
    pub routes: Routes,
    pub routes6: Routes6,
    // NAT domain.
    pub nat: Nat,
    pub nat_ips: NatIps,
    pub neigh_nat: NeighborNat,
    pub neigh_nat_count: NeighborNatCount,
    // LB domain: LB service map, Maglev table, and the UNDERLAY map. UNDERLAY is also
    // read/written by the interface + edge paths via `core.writer_mut()`.
    pub lb: Lb,
    pub maglev: Maglev,
    pub underlay: Underlay,
    // FIREWALL domain: per-interface rule slots + per-direction rule counts.
    pub fw_rules: FwRules,
    pub fw_meta: FwMetaMap,
    // IPv6 FIREWALL domain: v6 rule slots + per-direction rule counts (FW_RULES6 / FW_META6).
    pub fw_rules6: FwRules6,
    pub fw_meta6: FwMetaMap6,
    // INTERFACE + QoS + DHCP domain: the last config maps, moved out of `Inner`. After
    // this, `AyaWriter` owns ALL config maps and `Inner` holds only device/loader fields + `core`.
    pub ports: PortMetaMap,
    pub ifaces: Interfaces,
    pub vips: Vips,
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
    /// Every underlay /128 currently programmed (restart adopt reseeds `UnderlayIpam` from these).
    /// Reaches the raw UNDERLAY map, which lives here now; not part of the `MapWriter` trait.
    pub fn underlay_keys(&self) -> Vec<[u8; 16]> {
        self.underlay.keys()
    }

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
/// Moved verbatim from `control/nat.rs` (was `Control::ct_flush_for_guest`); the CONNTRACK map
/// lives in the eBPF backend, so the scan/remove belongs to `AyaWriter::conntrack_flush`.
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
    fn neigh_nat_upsert(&mut self, i: u32, v: NeighborNatEntry) -> anyhow::Result<()> {
        self.neigh_nat.upsert(i, v)
    }
    fn neigh_nat_count_set(&mut self, c: u32) -> anyhow::Result<()> {
        self.neigh_nat_count.set(c)
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
    fn maglev_upsert(&mut self, k: flowplane_common::MaglevKey, v: [u8; 16]) -> anyhow::Result<()> {
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
    fn fw_rules_upsert(
        &mut self,
        k: flowplane_common::FwRuleKey,
        v: flowplane_common::FwRule,
    ) -> anyhow::Result<()> {
        self.fw_rules.upsert(k, v)
    }
    fn fw_rules_remove(&mut self, k: &flowplane_common::FwRuleKey) -> anyhow::Result<()> {
        self.fw_rules.remove(k)
    }
    fn fw_meta_upsert(&mut self, i: u32, v: flowplane_common::FwMeta) -> anyhow::Result<()> {
        self.fw_meta.upsert(i, v)
    }
    fn fw_rules6_upsert(
        &mut self,
        k: flowplane_common::FwRuleKey,
        v: flowplane_common::FwRule6,
    ) -> anyhow::Result<()> {
        self.fw_rules6.upsert(k, v)
    }
    fn fw_rules6_remove(&mut self, k: &flowplane_common::FwRuleKey) -> anyhow::Result<()> {
        self.fw_rules6.remove(k)
    }
    fn fw_meta6_upsert(&mut self, i: u32, v: flowplane_common::FwMeta) -> anyhow::Result<()> {
        self.fw_meta6.upsert(i, v)
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
    fn iface_meta_upsert(&mut self, k: IfaceMetaKey, v: IfaceMetaVal) -> anyhow::Result<()> {
        self.iface_meta.upsert(k, v)
    }
    fn iface_meta_remove(&mut self, k: &IfaceMetaKey) -> anyhow::Result<()> {
        self.iface_meta.remove(k)
    }
    fn dhcp_meta_remove(&mut self, i: u32) -> anyhow::Result<()> {
        self.dhcp_meta.remove(i)
    }
    fn vips_upsert(&mut self, k: VipKey, v: [u8; 4]) -> anyhow::Result<()> {
        self.vips.upsert(k, v)
    }
    fn vips_remove(&mut self, k: &VipKey) -> anyhow::Result<()> {
        self.vips.remove(k)
    }
    fn vips_get(&self, k: &VipKey) -> Option<[u8; 4]> {
        self.vips.get(k)
    }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> {
        // Flush CT entries for this guest under the conntrack lock (a separate lock from the
        // control inner). Mirrors the former `delete_nat` teardown.
        let mut ct = self.conntrack.lock();
        ct_flush_for_guest(&mut ct, s.vni, s.guest_ip, s.nat_ip, s.port_min, s.port_max);
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
