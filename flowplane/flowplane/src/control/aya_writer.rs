//! `MapWriter` over the eBPF aya map wrappers. Owns the config maps moved out of `Control::Inner`.
use crate::maps::{Routes, Routes6};
use flowplane_common::RouteValue;
use flowplane_control::{CtFlushScope, MapWriter};

pub struct AyaWriter {
    pub routes: Routes,
    pub routes6: Routes6,
    // Remaining config maps are migrated here in Tasks 4-7.
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
    fn nat_upsert(
        &mut self,
        _k: flowplane_common::NatKey,
        _v: flowplane_common::NatValue,
    ) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
    fn nat_remove(&mut self, _k: &flowplane_common::NatKey) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
    fn nat_get(&self, _k: &flowplane_common::NatKey) -> Option<flowplane_common::NatValue> {
        unimplemented!("Task 4")
    }
    fn nat_ips_set(&mut self, _vni: u32, _ip: [u8; 4]) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
    fn nat_ips_remove(&mut self, _vni: u32, _ip: [u8; 4]) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
    fn neigh_nat_upsert(
        &mut self,
        _i: u32,
        _v: flowplane_common::NeighborNatEntry,
    ) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
    fn neigh_nat_count_set(&mut self, _c: u32) -> anyhow::Result<()> {
        unimplemented!("Task 4")
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
    fn conntrack_flush(&mut self, _s: CtFlushScope) -> anyhow::Result<()> {
        unimplemented!("Task 4")
    }
}
