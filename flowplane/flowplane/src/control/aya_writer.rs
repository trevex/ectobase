//! `MapWriter` over the eBPF aya map wrappers. Owns the config maps moved out of `Control::Inner`.
use std::sync::Arc;

use parking_lot::Mutex;

use crate::maps::{Conntrack, Nat, NatIps, NeighborNat, NeighborNatCount, Routes, Routes6};
use flowplane_common::{CtKey, NatKey, NatValue, NeighborNatEntry, RouteValue};
use flowplane_control::{CtFlushScope, MapWriter};

pub struct AyaWriter {
    pub routes: Routes,
    pub routes6: Routes6,
    // NAT domain (Task 4).
    pub nat: Nat,
    pub nat_ips: NatIps,
    pub neigh_nat: NeighborNat,
    pub neigh_nat_count: NeighborNatCount,
    /// Shared conntrack handle (same Arc `Control` holds for the GC task); the NAT teardown flush
    /// scans+removes matching CONNTRACK entries here.
    pub conntrack: Arc<Mutex<Conntrack>>,
    // Remaining config maps are migrated here in Tasks 5-7.
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
        _k: flowplane_common::LbKey,
        _v: flowplane_common::LbValue,
    ) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn lb_remove(&mut self, _k: &flowplane_common::LbKey) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn maglev_upsert(
        &mut self,
        _k: flowplane_common::MaglevKey,
        _v: [u8; 16],
    ) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn maglev_remove(&mut self, _k: &flowplane_common::MaglevKey) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn underlay_upsert(
        &mut self,
        _k: [u8; 16],
        _v: flowplane_common::UnderlayValue,
    ) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn underlay_remove(&mut self, _k: &[u8; 16]) -> anyhow::Result<()> {
        unimplemented!("Task 5")
    }
    fn underlay_get(&self, _k: &[u8; 16]) -> Option<flowplane_common::UnderlayValue> {
        unimplemented!("Task 5")
    }
    fn fw_rules_upsert(
        &mut self,
        _k: flowplane_common::FwRuleKey,
        _v: flowplane_common::FwRule,
    ) -> anyhow::Result<()> {
        unimplemented!("Task 6")
    }
    fn fw_rules_remove(&mut self, _k: &flowplane_common::FwRuleKey) -> anyhow::Result<()> {
        unimplemented!("Task 6")
    }
    fn fw_meta_upsert(&mut self, _i: u32, _v: flowplane_common::FwMeta) -> anyhow::Result<()> {
        unimplemented!("Task 6")
    }
    fn meter_upsert(&mut self, _i: u32, _v: flowplane_common::MeterState) -> anyhow::Result<()> {
        unimplemented!("Task 7")
    }
    fn meter_remove(&mut self, _i: &u32) -> anyhow::Result<()> {
        unimplemented!("Task 7")
    }
    fn dhcp_config_set(&mut self, _c: &flowplane_common::DhcpConfig) -> anyhow::Result<()> {
        unimplemented!("Task 7")
    }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> {
        // Flush CT entries for this guest under the conntrack lock (a separate lock from the
        // control inner). Mirrors the former `delete_nat` teardown.
        let mut ct = self.conntrack.lock();
        ct_flush_for_guest(&mut ct, s.vni, s.guest_ip, s.nat_ip, s.port_min, s.port_max);
        Ok(())
    }
}
