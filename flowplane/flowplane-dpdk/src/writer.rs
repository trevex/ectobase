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
//! ── meter config table ─────────────────────────────────────────────────────────────────────────
//! `SharedConfigMaps` carries a `meter_config` table (keyed by ifindex) that stores the rate-config
//! half of `MeterState` (the six `*_bps`/`*_burst` fields). `meter_upsert` extracts those fields
//! via `MeterConfig::from_state` and writes them into the shared table so every datapath lcore reads
//! the same per-interface rate on the next packet. The token/timestamp state (`*_tokens`/`*_last_ns`)
//! stays per-lcore and is not part of this shared config. The generation bump is kept for consistency
//! but is no longer load-bearing for the meter (config is read fresh per packet).
use std::sync::Arc;

use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRule6, FwRuleKey, IfaceKey, IfaceMetaKey, IfaceMetaVal,
    IfaceValue, LbKey, LbValue, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry,
    PortMeta, RouteValue, UnderlayValue, VipKey,
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
    // `prefix_len` is VALIDATED to be a host route (`/32` v4, `/128` v6): `SharedConfigMaps` stores
    // exact host keys, the same exact-match model as the DPDK/eBPF route maps (AyaWriter forwards
    // prefix to the aya Routes wrapper, but the underlying map key is the host address only — the
    // datapath does an exact lookup). A NON-host prefix (e.g. a `/0` default route) would silently
    // collapse into a host key that never matches → silent Pass, so we REJECT it up-front here
    // rather than drop the prefix. (Removal is by host key, so `route_remove`/`route6_remove` still
    // ignore `prefix_len`.)
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        if prefix_len != 32 {
            anyhow::bail!(
                "DPDK route table is exact-match (/32 host routes only); got /{prefix_len} for \
                 {}.{}.{}.{} — non-host prefixes (e.g. a /0 default route) never match. Use \
                 per-dest /32 routes or add LPM.",
                ipv4[0],
                ipv4[1],
                ipv4[2],
                ipv4[3]
            );
        }
        insert_ok(self.sc.route4_insert(vni, ipv4, val), "route4")
    }
    // Removal is by host key — `prefix_len` is not part of the key, so it is ignored here.
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], _prefix_len: u32) -> anyhow::Result<()> {
        self.sc.route4_remove(vni, ipv4);
        Ok(())
    }
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        if prefix_len != 128 {
            anyhow::bail!(
                "DPDK route table is exact-match (/128 host routes only); got /{prefix_len} — \
                 non-host prefixes (e.g. a /0 default route) never match. Use per-dest /128 routes \
                 or add LPM."
            );
        }
        insert_ok(self.sc.route6_insert(vni, ipv6, val), "route6")
    }
    // Removal is by host key — `prefix_len` is not part of the key, so it is ignored here.
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
    fn fw_rules6_upsert(&mut self, key: FwRuleKey, val: FwRule6) -> anyhow::Result<()> {
        insert_ok(self.sc.fw_rules6_insert(key, val), "fw_rules6")
    }
    fn fw_rules6_remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()> {
        self.sc.fw_rules6_remove(key);
        Ok(())
    }
    fn fw_meta6_upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()> {
        insert_ok(self.sc.fw_meta6_insert(ifindex, val), "fw_meta6")
    }

    // ── METER ────────────────────────────────────────────────────────────────
    /// Write the rate-config half of `val` into the shared meter-config table so every datapath
    /// lcore reads the SAME per-interface rate (full-rate-per-lcore: each lcore enforces the full
    /// cap independently — aggregate across N RSS lcores can reach N× the cap, a documented
    /// limitation). The token/timestamp state stays per-lcore. The generation bump is kept for
    /// consistency but is no longer load-bearing for the meter (config is read fresh per packet).
    fn meter_upsert(&mut self, ifindex: u32, val: MeterState) -> anyhow::Result<()> {
        let ok = self
            .sc
            .meter_config_insert(ifindex, flowplane_common::MeterConfig::from_state(&val));
        anyhow::ensure!(ok, "meter-config table full for ifindex {ifindex}");
        self.sc.bump_generation();
        Ok(())
    }
    /// Remove the interface's shared meter config (rate no longer enforced). Bump generation.
    fn meter_remove(&mut self, ifindex: &u32) -> anyhow::Result<()> {
        self.sc.meter_config_remove(*ifindex);
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

    fn conntrack_flush_interface(&mut self, _vni: u32, _guest_ip: [u8; 4]) -> anyhow::Result<()> {
        // Same DPDK invalidation primitive as conntrack_flush: bump the config generation so CT
        // entries created before this detach are treated as stale by the generation check.
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
        // Host route (/32) is accepted.
        w.route_upsert(7, [10, 0, 0, 1], 32, rv).unwrap();
        // Exact-match table: a NON-host prefix is REJECTED loudly (would otherwise collapse into a
        // host key that never matches → silent Pass).
        assert!(w.route_upsert(7, [10, 0, 0, 1], 24, rv).is_err());
        // v6 host route (/128) is accepted; a non-host v6 prefix is rejected.
        let ip6 = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        w.route6_upsert(7, ip6, 128, rv).unwrap();
        assert!(w.route6_upsert(7, ip6, 64, rv).is_err());
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
