//! [`DpdkMapWriter`] — the DPDK `flowplane_control::MapWriter`, sibling of the eBPF `AyaWriter`.
//!
//! It programs `nfkit::shared_config::SharedConfigMaps` (LF+RCU DPDK config tables) so the SAME
//! `flowplane_control::ControlCore` orchestration drives both backends. Each of the 35 `MapWriter`
//! methods maps to the SAME logical table with the SAME key/value construction the eBPF `AyaWriter`
//! uses, so the two backends are semantically identical (the parity goal for the node service).
//!
//! ── OWNERSHIP ──────────────────────────────────────────────────────────────────────────────────
//! `DpdkMapWriter` OWNS an `Arc<SharedConfigMaps>` (not a borrow), so `ControlCore<DpdkMapWriter>`
//! is `'static` and can be stored long-lived in the gRPC service (it holds shadow state across
//! RPCs). The same `Arc<SharedConfigMaps>` is shared with the datapath lcores, which hold it for
//! lock-free reads. Soundness rests on the single-writer convention (see `SharedConfigMaps`): the
//! `ControlCore<DpdkMapWriter>` lives behind a `Mutex` on the tokio control thread (the SOLE
//! writer), while lcores only call the `&self` getters. That is why every `SharedConfigMaps` writer
//! method takes `&self` and `DpdkMapWriter` can call them through a shared `Arc`.
//!
//! ── insert-bool → Result ───────────────────────────────────────────────────────────────────────
//! `SharedConfigMaps` `*_insert` returns `false` when the table is FULL; `DpdkMapWriter` surfaces
//! that as an `anyhow` error (a real `-ENOSPC`-class failure the control plane must see). `*_remove`
//! returns `false` when the key is ABSENT; matching `AyaWriter` (whose aya `remove` treats a missing
//! key as success and returns `Ok(())`), a remove-of-absent is NOT an error → `Ok(())`.
//!
//! ── meter gap (Task 9) ─────────────────────────────────────────────────────────────────────────
//! `SharedConfigMaps` has NO meter table: in the DPDK datapath the meter (`MeterState`) is per-lcore
//! FLOW state (token buckets / EDT cursors mutated per-packet), not a shared config table (Task 4
//! deliberately excluded it). eBPF instead shares one meter map whose config fields the control
//! plane seeds. So `meter_upsert`/`meter_remove` have no config-map target here; they bump the
//! config generation (the same generation-based signal the datapath already observes) so lcores can
//! re-derive their per-lcore meter config, and flag the real distribution mechanism as a Task-9
//! concern. See the method docs.
use std::sync::Arc;

use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceMetaKey, IfaceMetaVal, IfaceValue, LbKey,
    LbValue, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry, PortMeta, RouteValue,
    UnderlayValue, VipKey,
};
use flowplane_control::{CtFlushScope, MapWriter};
use nfkit::SharedConfigMaps;

/// DPDK `MapWriter` over an owned `Arc<SharedConfigMaps>` (see module doc for the ownership model).
pub struct DpdkMapWriter {
    sc: Arc<SharedConfigMaps>,
}

impl DpdkMapWriter {
    /// Wrap a shared config-map handle. The `Arc` is cloned from the same handle the datapath lcores
    /// read; this writer is the single serialized writer (guarded downstream by a `Mutex`).
    #[must_use]
    pub fn new(sc: Arc<SharedConfigMaps>) -> Self {
        Self { sc }
    }

    /// Borrow the shared config maps (e.g. to hand the same `Arc` to the datapath lcores).
    #[must_use]
    pub fn shared(&self) -> &Arc<SharedConfigMaps> {
        &self.sc
    }
}

/// Turn an `*_insert` bool into a Result: `false` = table full → error.
#[inline]
fn insert_ok(ok: bool, table: &str) -> anyhow::Result<()> {
    if ok {
        Ok(())
    } else {
        anyhow::bail!("{table} table full")
    }
}

impl MapWriter for DpdkMapWriter {
    // ── ROUTES ───────────────────────────────────────────────────────────────
    // `prefix_len` is DROPPED: `SharedConfigMaps` stores exact `/32`(v4) / `/128`(v6) host keys,
    // the same exact-match model as the DPDK/eBPF route maps (AyaWriter forwards prefix to the aya
    // Routes wrapper, but the underlying map key is the host address only — the datapath does an
    // exact lookup). So dropping it here is byte-compatible with the eBPF key.
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        _prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        insert_ok(self.sc.route4_insert(vni, ipv4, val), "route4")
    }
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], _prefix_len: u32) -> anyhow::Result<()> {
        self.sc.route4_remove(vni, ipv4);
        Ok(())
    }
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        _prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        insert_ok(self.sc.route6_insert(vni, ipv6, val), "route6")
    }
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], _prefix_len: u32) -> anyhow::Result<()> {
        self.sc.route6_remove(vni, ipv6);
        Ok(())
    }

    // ── NAT ──────────────────────────────────────────────────────────────────
    fn nat_upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()> {
        insert_ok(self.sc.nat_insert(key, val), "nat")
    }
    fn nat_remove(&mut self, key: &NatKey) -> anyhow::Result<()> {
        self.sc.nat_remove(key);
        Ok(())
    }
    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.sc.nat_get(key)
    }
    fn nat_ips_set(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()> {
        insert_ok(self.sc.nat_ips_insert(vni, nat_ip), "nat_ips")
    }
    fn nat_ips_remove(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()> {
        self.sc.nat_ips_remove(vni, nat_ip);
        Ok(())
    }
    fn neigh_nat_upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()> {
        insert_ok(self.sc.neigh_nat_insert(idx, val), "neigh_nat")
    }
    fn neigh_nat_count_set(&mut self, count: u32) -> anyhow::Result<()> {
        self.sc.set_neigh_nat_count(count);
        Ok(())
    }

    // ── LB ───────────────────────────────────────────────────────────────────
    fn lb_upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()> {
        insert_ok(self.sc.lb_insert(key, val), "lb")
    }
    fn lb_remove(&mut self, key: &LbKey) -> anyhow::Result<()> {
        self.sc.lb_remove(key);
        Ok(())
    }
    fn maglev_upsert(&mut self, key: MaglevKey, val: [u8; 16]) -> anyhow::Result<()> {
        insert_ok(self.sc.maglev_insert(key, val), "maglev")
    }
    fn maglev_remove(&mut self, key: &MaglevKey) -> anyhow::Result<()> {
        self.sc.maglev_remove(key);
        Ok(())
    }

    // ── UNDERLAY ─────────────────────────────────────────────────────────────
    fn underlay_upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()> {
        insert_ok(self.sc.underlay_insert(key, val), "underlay")
    }
    fn underlay_remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()> {
        self.sc.underlay_remove(key);
        Ok(())
    }
    fn underlay_get(&self, key: &[u8; 16]) -> Option<UnderlayValue> {
        self.sc.underlay_get(key)
    }

    // ── FIREWALL ─────────────────────────────────────────────────────────────
    fn fw_rules_upsert(&mut self, key: FwRuleKey, val: FwRule) -> anyhow::Result<()> {
        insert_ok(self.sc.fw_rules_insert(key, val), "fw_rules")
    }
    fn fw_rules_remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()> {
        self.sc.fw_rules_remove(key);
        Ok(())
    }
    fn fw_meta_upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()> {
        insert_ok(self.sc.fw_meta_insert(ifindex, val), "fw_meta")
    }

    // ── METER (Task-9 gap: no config-map target — see module doc) ────────────
    /// No `SharedConfigMaps` meter table exists (meter is per-lcore FLOW state in the DPDK model).
    /// Bump the config generation so datapath lcores can re-derive their per-lcore meter config; the
    /// concrete QoS-rate distribution to lcores is a Task-9 concern.
    fn meter_upsert(&mut self, _ifindex: u32, _val: MeterState) -> anyhow::Result<()> {
        self.sc.bump_generation();
        Ok(())
    }
    /// See [`Self::meter_upsert`]: no config-map target; bump generation, no error.
    fn meter_remove(&mut self, _ifindex: &u32) -> anyhow::Result<()> {
        self.sc.bump_generation();
        Ok(())
    }

    // ── DHCP config singleton ────────────────────────────────────────────────
    fn dhcp_config_set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()> {
        self.sc.set_dhcp_config(*cfg);
        Ok(())
    }

    // ── INTERFACE domain ─────────────────────────────────────────────────────
    fn ports_upsert(&mut self, ifindex: u32, meta: PortMeta) -> anyhow::Result<()> {
        insert_ok(self.sc.ports_insert(ifindex, meta), "ports")
    }
    fn ports_remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.sc.ports_remove(ifindex);
        Ok(())
    }
    fn ifaces_upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()> {
        insert_ok(self.sc.ifaces_insert(key, val), "ifaces")
    }
    fn ifaces_remove(&mut self, key: IfaceKey) -> anyhow::Result<()> {
        self.sc.ifaces_remove(key);
        Ok(())
    }
    fn ifaces_get(&self, key: &IfaceKey) -> Option<IfaceValue> {
        self.sc.ifaces_get(key)
    }
    fn iface_meta_upsert(&mut self, key: IfaceMetaKey, val: IfaceMetaVal) -> anyhow::Result<()> {
        insert_ok(self.sc.iface_meta_insert(key, val), "iface_meta")
    }
    fn iface_meta_remove(&mut self, key: &IfaceMetaKey) -> anyhow::Result<()> {
        self.sc.iface_meta_remove(key);
        Ok(())
    }
    fn dhcp_meta_remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.sc.dhcp_meta_remove(ifindex);
        Ok(())
    }
    fn vips_upsert(&mut self, key: VipKey, val: [u8; 4]) -> anyhow::Result<()> {
        insert_ok(self.sc.vips_insert(key, val), "vips")
    }
    fn vips_remove(&mut self, key: &VipKey) -> anyhow::Result<()> {
        self.sc.vips_remove(key);
        Ok(())
    }
    fn vips_get(&self, key: &VipKey) -> Option<[u8; 4]> {
        self.sc.vips_get(key)
    }

    // ── CONNTRACK invalidation ───────────────────────────────────────────────
    /// DPDK conntrack invalidation = config-generation bump (spec §5a). Unlike eBPF (which scans and
    /// removes matching CONNTRACK map entries), the DPDK datapath compares each per-lcore CT entry's
    /// stored generation against the current config generation and treats an out-of-date entry as
    /// stale. So the scope fields are not needed here — bumping the generation invalidates all CT
    /// entries created before this config change.
    fn conntrack_flush(&mut self, _scope: CtFlushScope) -> anyhow::Result<()> {
        self.sc.bump_generation();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_control::MapWriter;
    use std::sync::Arc;

    #[test]
    #[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
    fn dpdk_writer_route_and_flush_via_shared() {
        let _eal = nfkit::Eal::init(
            [
                "fp_dpdk_w",
                "-l",
                "0-1",
                "--no-huge",
                "-m",
                "512",
                "--no-pci",
                "--file-prefix",
                "fp_dpdk_w",
            ]
            .iter()
            .copied(),
        )
        .unwrap();

        let sc = Arc::new(nfkit::SharedConfigMaps::new(0, 1024).unwrap());
        let mut w = DpdkMapWriter::new(sc.clone());

        let rv = RouteValue {
            nexthop_vni: 7,
            nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
            is_external: 0,
            _pad: [0; 3],
        };
        w.route_upsert(7, [10, 0, 0, 1], 32, rv).unwrap();
        w.conntrack_flush(CtFlushScope {
            vni: 7,
            guest_ip: [10, 0, 0, 1],
            nat_ip: [0; 4],
            port_min: 0,
            port_max: 0,
        })
        .unwrap();

        // The route landed in the shared config maps (read through the same Arc a datapath lcore
        // would hold).
        assert!(sc.route4_get(7, &[10, 0, 0, 1]).is_some());
        // conntrack_flush bumped the config generation exactly once.
        assert_eq!(sc.generation(), 1);

        // OWNERSHIP GOAL: ControlCore<DpdkMapWriter> is constructible + `'static` (owns its Arc, so
        // it can be stored long-lived in the gRPC service).
        let _core = flowplane_control::ControlCore::new(DpdkMapWriter::new(sc.clone()));
        fn assert_static<T: 'static>(_: &T) {}
        assert_static(&_core);
    }
}
