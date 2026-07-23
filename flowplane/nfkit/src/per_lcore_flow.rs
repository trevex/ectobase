//! [`PerLcoreFlowMaps`] — the per-lcore, shared-nothing FLOW half of the datapath maps (conntrack +
//! meter), and [`ComposedMaps`] — a [`flowplane_core::maps::Maps`] view that composes the
//! process-wide [`SharedConfigMaps`] (CONFIG half, `&`-shared across every lcore) with a per-lcore
//! [`PerLcoreFlowMaps`] (FLOW half, owned by exactly one lcore).
//!
//! ── WHY THE SPLIT ─────────────────────────────────────────────────────────────────────────────
//! In the DPDK serve binary the CONFIG maps (routes/fw/lb/maglev/underlay/nat/dhcp) are written by
//! the single tokio control thread and read lock-free by every datapath lcore — so they live once,
//! process-wide, in [`SharedConfigMaps`] (LF+RCU). The FLOW maps (conntrack, meter) are mutated on
//! the datapath every packet; making them per-lcore shared-nothing avoids any cross-lcore
//! synchronization on the hot path. This mirrors the M8 per-lcore `DpdkMaps` model, but factors the
//! flow half out so a worker composes it with the shared config half.
//!
//! ── FLOW HALF = PLAIN `DpdkHash` ──────────────────────────────────────────────────────────────
//! A per-lcore table is single-threaded (only its owning lcore touches it), so it uses the plain
//! [`DpdkHash`] (slab-backed, cheap) — NOT the concurrent LF+RCU [`crate::RcuHash`]. Capacities and
//! per-instance-unique naming mirror [`crate::DpdkMaps`]'s conntrack/meter tables: conntrack
//! [`CAP_CT`] = 65536, meter [`CAP_STD`] = 4096.
//!
//! ── SATURATION ────────────────────────────────────────────────────────────────────────────────
//! [`Maps::conntrack_insert`] / [`Maps::meter_update`] return `()`; a full conntrack table drops
//! silently. As in `DpdkMaps`, the drop is COUNTED ([`PerLcoreFlowMaps::dropped_conntrack_inserts`])
//! so saturation is observable. `Cell` (not atomic): per-lcore, mutated behind `&mut self`.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};

use flowplane_common::{
    CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local,
    MaglevKey, MeterState, NatKey, NatValue, RouteValue, UnderlayValue,
};
use flowplane_core::maps::Maps;

use crate::shared_config::SharedConfigMaps;
use crate::{DpdkHash, HashError};

/// Monotonic counter yielding a unique id per [`PerLcoreFlowMaps`] instance so each instance's
/// `rte_hash` tables get unique names (fixed names collide when two coexist — one per lcore).
/// Mirrors `DpdkMaps::NEXT_INSTANCE`.
static NEXT_INSTANCE: AtomicU32 = AtomicU32::new(0);

/// Conntrack capacity: one entry per live flow (matches `DpdkMaps::CAP_CT`).
const CAP_CT: u32 = 65_536;
/// Meter capacity: one entry per interface (matches `DpdkMaps::CAP_STD`).
const CAP_STD: u32 = 4_096;

/// Key for the meter map (a single `u32` ifindex). Mirrors `DpdkMaps::U32Key`.
#[repr(C)]
#[derive(Copy, Clone)]
struct U32Key {
    v: u32,
}
const _: () = assert!(std::mem::size_of::<U32Key>() == 4);

/// The per-lcore, shared-nothing FLOW half of the datapath maps: conntrack + meter. Owned by exactly
/// one worker lcore; single-threaded (no concurrency), so plain [`DpdkHash`] not [`crate::RcuHash`].
pub struct PerLcoreFlowMaps {
    conntrack: DpdkHash<CtKey, CtEntry>,
    meter: DpdkHash<U32Key, MeterState>,

    /// Conntrack inserts dropped on saturation. `conntrack_insert` returns `()`, so this counter is
    /// the only way to observe conntrack saturation. Monotonic per instance. `Cell` (per-lcore,
    /// `&mut self` mutation — no cross-thread access).
    dropped_ct_inserts: Cell<u64>,
}

impl PerLcoreFlowMaps {
    /// Build the per-lcore conntrack ([`CAP_CT`]) + meter ([`CAP_STD`]) tables on `socket_id` with
    /// per-instance-unique `rte_hash` names.
    ///
    /// # Errors
    /// Returns [`HashError`] if any `rte_hash_create` fails (name collision / OOM).
    pub fn new(socket_id: i32) -> Result<Self, HashError> {
        let n = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            conntrack: DpdkHash::new(&format!("plf_ct_{n}"), CAP_CT, socket_id)?,
            meter: DpdkHash::new(&format!("plf_mt_{n}"), CAP_STD, socket_id)?,
            dropped_ct_inserts: Cell::new(0),
        })
    }

    /// Number of conntrack inserts dropped because the conntrack table was full. `conntrack_insert`
    /// (a `Maps` method) returns `()`, so this counter is the only way to observe saturation.
    #[must_use]
    pub fn dropped_conntrack_inserts(&self) -> u64 {
        self.dropped_ct_inserts.get()
    }

    // ── flow getters/mutators (the FLOW half of the Maps trait) ──────────────────

    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        self.conntrack.get(key)
    }

    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        // Trait method returns `()`; a full conntrack table drops here. Count it so saturation is
        // observable via `dropped_conntrack_inserts()`.
        if !self.conntrack.insert(&key, entry) {
            self.dropped_ct_inserts
                .set(self.dropped_ct_inserts.get() + 1);
        }
    }

    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        self.meter.get(&U32Key { v: ifindex })
    }

    fn meter_update(&mut self, ifindex: u32, state: MeterState) {
        // Meter state is keyed by a bounded ifindex set (one entry per interface); it should never
        // fill. A dropped update just fails to advance the meter this call (not a correctness
        // hazard). Ignore the bool (debug_assert surfaces the impossible full case).
        let ok = self.meter.insert(&U32Key { v: ifindex }, state);
        debug_assert!(ok, "meter table full (bounded by interface count)");
    }
}

/// A [`Maps`] view composing the process-wide CONFIG half (`cfg`, `&`-shared across lcores) with a
/// per-lcore FLOW half (`flow`, owned). CONFIG getters delegate to [`SharedConfigMaps`]; FLOW
/// getters/mutators delegate to [`PerLcoreFlowMaps`]. Each worker lcore constructs one of these,
/// borrowing the single shared config for its lifetime and owning its own flow state.
pub struct ComposedMaps<'a> {
    /// Process-wide CONFIG half, shared read-only across every datapath lcore.
    pub cfg: &'a SharedConfigMaps,
    /// Per-lcore FLOW half (conntrack + meter), owned by this lcore.
    pub flow: PerLcoreFlowMaps,
}

impl Maps for ComposedMaps<'_> {
    // ── CONFIG half → self.cfg (SharedConfigMaps getters match the trait 1:1) ────

    fn local(&self) -> Option<Local> {
        self.cfg.local()
    }

    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        self.cfg.underlay_get(addr)
    }

    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        self.cfg.fw_meta(ifindex)
    }

    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.cfg.fw_rule(key)
    }

    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.cfg.lb_get(key)
    }

    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.cfg.maglev_get(key)
    }

    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.cfg.nat_get(key)
    }

    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.cfg.is_nat_ip(vni, ip)
    }

    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
        self.cfg.route4_get(vni, dst)
    }

    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
        self.cfg.route6_get(vni, dst)
    }

    fn dhcp_config(&self) -> Option<DhcpConfig> {
        self.cfg.dhcp_config()
    }

    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta> {
        self.cfg.dhcp_meta(ifindex)
    }

    // ── FLOW half → self.flow (per-lcore conntrack + meter) ──────────────────────

    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry> {
        self.flow.conntrack_get(key)
    }

    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry) {
        self.flow.conntrack_insert(key, entry);
    }

    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        self.flow.meter_get(ifindex)
    }

    fn meter_update(&mut self, ifindex: u32, state: MeterState) {
        self.flow.meter_update(ifindex, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_core::maps::Maps;

    #[test]
    #[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
    fn composed_maps_routes_getters_to_halves() {
        let _eal = crate::eal::Eal::init(
            [
                "nfkit_plf",
                "-l",
                "0-1",
                "--no-huge",
                "-m",
                "512",
                "--no-pci",
                "--file-prefix",
                "nfkit_plf",
            ]
            .iter()
            .copied(),
        )
        .unwrap();

        // Seed the SHARED config half BEFORE composing (ComposedMaps borrows it immutably): a /32
        // route the datapath getter should read back through the composed view.
        let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
        let rv = RouteValue {
            nexthop_vni: 7,
            nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
            is_external: 0,
            _pad: [0; 3],
        };
        assert!(shared.route4_insert(100, [10, 0, 0, 1], rv));

        let flow = PerLcoreFlowMaps::new(0).expect("per-lcore flow");
        let mut composed = ComposedMaps { cfg: &shared, flow };

        // (a) A conntrack insert lands in the PER-LCORE half and reads back through the composed
        // view. Key mirrors the inner-5-tuple CtKey construction in multilcore_datapath.rs.
        let key = CtKey {
            vni: 100,
            src_ip: [10, 9, 0, 1],
            dst_ip: [10, 0, 0, 10],
            src_port: 40000,
            dst_port: 443,
            proto: 6,
            _pad: [0; 3],
        };
        let entry = CtEntry {
            last_seen: 0,
            xlate_ip: [0; 4],
            xlate_port: 0,
            flags: 0,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        };
        assert!(composed.conntrack_get(&key).is_none());
        composed.conntrack_insert(key, entry);
        assert_eq!(composed.conntrack_get(&key), Some(entry));

        // (b) A CONFIG getter routes THROUGH the composed view to the shared half.
        assert_eq!(composed.route4_get(100, &[10, 0, 0, 1]), Some(rv));
        assert_eq!(composed.route4_get(100, &[10, 0, 0, 99]), None);

        // (c) The meter mutator/getter round-trips through the per-lcore half.
        let ms = MeterState {
            total_bps: 1_000_000,
            ..Default::default()
        };
        assert_eq!(composed.meter_get(42), None);
        composed.meter_update(42, ms);
        assert_eq!(composed.meter_get(42), Some(ms));
    }
}
