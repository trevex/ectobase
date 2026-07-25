//! [`DpdkMaps`] — a [`flowplane_core::maps::Maps`] implementation backed by [`DpdkHash`]
//! (DPDK `rte_hash`).  Mirrors [`flowplane_sim::maps::MemMaps`] in key derivation so the two
//! implementations produce identical key→value behaviour and M3 parity anchors remain valid.

use crate::{DpdkHash, HashError};
use flowplane_common::{
    CtEntry, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRule6, FwRuleKey, LbKey,
    LbValue, Local, MaglevKey, MeterState, NatKey, NatValue, RouteValue, UnderlayValue,
};
use flowplane_core::maps::Maps;
use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};

/// Monotonic counter yielding a unique id per `DpdkMaps` instance so each instance's `rte_hash`
/// tables get unique names (fixed names collide when two instances coexist — e.g. per-lcore state).
static NEXT_INSTANCE: AtomicU32 = AtomicU32::new(0);

// ── local key types ─────────────────────────────────────────────────────────

/// Composite key for the IPv4 route hash: (vni, ipv4 host bits). Matches the fields
/// `MemMaps::route4_get` filters on (`r.vni == vni && prefix_match(&r.ipv4, dst, 32)`).
/// `DpdkMaps` only stores exact-host (/32) routes so LPM reduces to an exact hash lookup.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Route4Key {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Composite key for the IPv6 route hash: (vni, ipv6 host bits).  Same reasoning as
/// [`Route4Key`] but for /128 routes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Route6Key {
    pub vni: u32,
    pub ipv6: [u8; 16],
}

/// Composite key for the NAT-IP set hash: (vni, ipv4). Mirrors `MemMaps.nat_ips` (a
/// `HashSet<(u32, [u8; 4])>`); the value is a dummy `u8` since `rte_hash` needs a value type.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct NatIpKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}
const _: () = assert!(core::mem::size_of::<NatIpKey>() == 8); // no padding

/// Key for maps keyed by a single `u32` ifindex / slot (underlay is [u8;16], handled separately).
#[repr(C)]
#[derive(Copy, Clone)]
struct U32Key {
    v: u32,
}

/// Key for the underlay map (node IPv6 → delivery info).
#[repr(C)]
#[derive(Copy, Clone)]
struct Ipv6Key {
    addr: [u8; 16],
}

// Compile-time padding-free guarantees for all hash keys.
const _: () = assert!(std::mem::size_of::<Route4Key>() == 4 + 4);
const _: () = assert!(std::mem::size_of::<Route6Key>() == 4 + 16);
const _: () = assert!(std::mem::size_of::<U32Key>() == 4);
const _: () = assert!(std::mem::size_of::<Ipv6Key>() == 16);
// flowplane-common key structs already verified in their own tests; spot-check here too.
const _: () = assert!(std::mem::size_of::<CtKey>() == 20);
const _: () = assert!(std::mem::size_of::<CtKey6>() == 44);
const _: () = assert!(std::mem::size_of::<FwRuleKey>() == 8);
const _: () = assert!(std::mem::size_of::<FwRule6>() == 80);
const _: () = assert!(std::mem::size_of::<LbKey>() == 12);
const _: () = assert!(std::mem::size_of::<MaglevKey>() == 8);
const _: () = assert!(std::mem::size_of::<NatKey>() == 8);

// ── capacity constants ───────────────────────────────────────────────────────

/// Default conntrack capacity: high cardinality (one entry per live flow).
const CAP_CT: u32 = 65_536;
/// Default capacity for all non-conntrack maps.
const CAP_STD: u32 = 4_096;

// ── DpdkMaps ─────────────────────────────────────────────────────────────────

/// `Maps` implementation over DPDK `rte_hash` tables.  Drop-in replacement for `MemMaps` in
/// DPDK NF contexts: identical key derivation, same public test-only setters, safe Rust surface.
pub struct DpdkMaps {
    // Singletons — stored inline, not in a hash.
    local: Option<Local>,
    dhcp_config: Option<DhcpConfig>,

    // Per-key hashes.
    conntrack: DpdkHash<CtKey, CtEntry>,
    conntrack6: DpdkHash<CtKey6, CtEntry>,
    underlay: DpdkHash<Ipv6Key, UnderlayValue>,
    fw_meta: DpdkHash<U32Key, FwMeta>,
    fw_rules: DpdkHash<FwRuleKey, FwRule>,
    fw_meta6: DpdkHash<U32Key, FwMeta>,
    fw_rules6: DpdkHash<FwRuleKey, FwRule6>,
    lb: DpdkHash<LbKey, LbValue>,
    maglev: DpdkHash<MaglevKey, [u8; 16]>,
    nat: DpdkHash<NatKey, NatValue>,
    nat_ips: DpdkHash<NatIpKey, u8>,
    route4: DpdkHash<Route4Key, RouteValue>,
    route6: DpdkHash<Route6Key, RouteValue>,
    dhcp_meta: DpdkHash<U32Key, DhcpMeta>,
    meter: DpdkHash<U32Key, MeterState>,

    // ── observability: flow-table insert drops on saturation ──────────────────
    // `Maps::conntrack_insert`/`meter_update` return `()` (shared trait — cannot change), so a
    // full flow table would otherwise drop silently. Count the drops here (nfkit-local) so callers
    // can observe saturation. `Cell` (not atomic): `DpdkMaps` is per-lcore, shared-nothing, and
    // mutated behind `&mut self` on the datapath — no cross-thread access.
    dropped_ct_inserts: Cell<u64>,
    dropped_nat_inserts: Cell<u64>,
}

impl DpdkMaps {
    /// Create all backing hashes on `socket_id` with the default capacities
    /// ([`CAP_CT`] for conntrack, [`CAP_STD`] for every other map).
    ///
    /// # Errors
    /// Returns `HashError` if any `rte_hash_create` call fails (name collision, OOM).
    pub fn new(socket_id: i32) -> Result<Self, HashError> {
        Self::with_capacities(socket_id, CAP_CT, CAP_STD)
    }

    /// Create all backing hashes on `socket_id` with explicit capacities: `ct_cap` sizes the
    /// conntrack (flow) table, `std_cap` sizes every other map (underlay/fw/lb/maglev/nat/
    /// nat_ips/routes/dhcp/meter). [`new`] is `with_capacities(socket_id, CAP_CT, CAP_STD)`.
    ///
    /// Useful for tuning flow-table capacity per deployment, and for tests that need a small table
    /// to exercise the saturation / restore-overflow paths deterministically.
    ///
    /// # Errors
    /// Returns `HashError` if any `rte_hash_create` call fails (name collision, OOM).
    pub fn with_capacities(socket_id: i32, ct_cap: u32, std_cap: u32) -> Result<Self, HashError> {
        let n = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            local: None,
            dhcp_config: None,
            conntrack: DpdkHash::new(&format!("dm_ct_{n}"), ct_cap, socket_id)?,
            conntrack6: DpdkHash::new(&format!("dm_ct6_{n}"), ct_cap, socket_id)?,
            underlay: DpdkHash::new(&format!("dm_ul_{n}"), std_cap, socket_id)?,
            fw_meta: DpdkHash::new(&format!("dm_fm_{n}"), std_cap, socket_id)?,
            fw_rules: DpdkHash::new(&format!("dm_fr_{n}"), std_cap, socket_id)?,
            fw_meta6: DpdkHash::new(&format!("dm_fm6_{n}"), std_cap, socket_id)?,
            fw_rules6: DpdkHash::new(&format!("dm_fr6_{n}"), std_cap, socket_id)?,
            lb: DpdkHash::new(&format!("dm_lb_{n}"), std_cap, socket_id)?,
            maglev: DpdkHash::new(&format!("dm_mg_{n}"), std_cap, socket_id)?,
            nat: DpdkHash::new(&format!("dm_nat_{n}"), std_cap, socket_id)?,
            nat_ips: DpdkHash::new(&format!("dm_ni_{n}"), std_cap, socket_id)?,
            route4: DpdkHash::new(&format!("dm_r4_{n}"), std_cap, socket_id)?,
            route6: DpdkHash::new(&format!("dm_r6_{n}"), std_cap, socket_id)?,
            dhcp_meta: DpdkHash::new(&format!("dm_dm_{n}"), std_cap, socket_id)?,
            meter: DpdkHash::new(&format!("dm_mt_{n}"), std_cap, socket_id)?,
            dropped_ct_inserts: Cell::new(0),
            dropped_nat_inserts: Cell::new(0),
        })
    }

    /// Number of conntrack inserts dropped because the conntrack table was full. `conntrack_insert`
    /// (a `Maps` trait method) returns `()`, so this counter is the only way to observe conntrack
    /// saturation. Monotonic per `DpdkMaps` instance.
    #[must_use]
    pub fn dropped_conntrack_inserts(&self) -> u64 {
        self.dropped_ct_inserts.get()
    }

    /// Number of NAT-config inserts (`add_nat`/`add_nat_ip`) dropped because a NAT table was full.
    /// A full NAT table is a real misconfiguration; counting it makes the drop observable.
    #[must_use]
    pub fn dropped_nat_inserts(&self) -> u64 {
        self.dropped_nat_inserts.get()
    }

    // ── test-only population setters (mirror MemMaps public setters) ──────────

    /// Add an exact-host (/32) IPv4 route — mirrors `MemMaps::add_route4`.
    pub fn add_route4(&mut self, vni: u32, ipv4: [u8; 4], value: RouteValue) {
        let ok = self.route4.insert(&Route4Key { vni, ipv4 }, value);
        debug_assert!(ok, "route4 table full at populate time");
    }

    /// Add an exact-host (/128) IPv6 route — mirrors `MemMaps::add_route6`.
    pub fn add_route6(&mut self, vni: u32, ipv6: [u8; 16], value: RouteValue) {
        let ok = self.route6.insert(&Route6Key { vni, ipv6 }, value);
        debug_assert!(ok, "route6 table full at populate time");
    }

    /// Set the singleton `Local` — mirrors `MemMaps.local = Some(v)`.
    pub fn set_local(&mut self, v: Local) {
        self.local = Some(v);
    }

    /// Insert an underlay entry — mirrors `MemMaps.underlay.insert`.
    pub fn add_underlay(&mut self, addr: [u8; 16], value: UnderlayValue) {
        let ok = self.underlay.insert(&Ipv6Key { addr }, value);
        debug_assert!(ok, "underlay table full at populate time");
    }

    /// Insert a firewall meta entry — mirrors `MemMaps.fw_meta.insert`.
    pub fn add_fw_meta(&mut self, ifindex: u32, value: FwMeta) {
        let ok = self.fw_meta.insert(&U32Key { v: ifindex }, value);
        debug_assert!(ok, "fw_meta table full at populate time");
    }

    /// Insert a firewall rule — mirrors `MemMaps.fw_rules.insert((ifindex, idx), rule)`.
    pub fn add_fw_rule(&mut self, ifindex: u32, idx: u32, rule: FwRule) {
        let ok = self.fw_rules.insert(&FwRuleKey { ifindex, idx }, rule);
        debug_assert!(ok, "fw_rules table full at populate time");
    }

    /// Insert an IPv6 firewall meta entry — mirrors `add_fw_meta` for the `FW_META6` table.
    pub fn add_fw_meta6(&mut self, ifindex: u32, value: FwMeta) {
        let ok = self.fw_meta6.insert(&U32Key { v: ifindex }, value);
        debug_assert!(ok, "fw_meta6 table full at populate time");
    }

    /// Insert an IPv6 firewall rule — mirrors `add_fw_rule` for the `FW_RULES6` table.
    pub fn add_fw_rule6(&mut self, ifindex: u32, idx: u32, rule: FwRule6) {
        let ok = self.fw_rules6.insert(&FwRuleKey { ifindex, idx }, rule);
        debug_assert!(ok, "fw_rules6 table full at populate time");
    }

    /// Insert an LB entry.
    pub fn add_lb(&mut self, key: LbKey, value: LbValue) {
        let ok = self.lb.insert(&key, value);
        debug_assert!(ok, "lb table full at populate time");
    }

    /// Insert a Maglev slot.
    pub fn add_maglev(&mut self, key: MaglevKey, backend: [u8; 16]) {
        let ok = self.maglev.insert(&key, backend);
        debug_assert!(ok, "maglev table full at populate time");
    }

    /// Insert a NAT config entry. A full NAT table is a real problem (not a populate-time
    /// impossibility like the config maps), so a dropped insert is counted, not asserted.
    pub fn add_nat(&mut self, key: NatKey, value: NatValue) {
        if !self.nat.insert(&key, value) {
            self.dropped_nat_inserts
                .set(self.dropped_nat_inserts.get() + 1);
        }
    }

    /// Register `(vni, ip)` as a public NAT IP (mirrors `MemMaps.nat_ips.insert`).
    pub fn add_nat_ip(&mut self, vni: u32, ip: [u8; 4]) {
        if !self.nat_ips.insert(&NatIpKey { vni, ipv4: ip }, 1) {
            self.dropped_nat_inserts
                .set(self.dropped_nat_inserts.get() + 1);
        }
    }

    /// Set the server-wide DHCP config singleton.
    pub fn set_dhcp_config(&mut self, v: DhcpConfig) {
        self.dhcp_config = Some(v);
    }

    /// Insert a per-interface DHCP meta entry.
    pub fn add_dhcp_meta(&mut self, ifindex: u32, value: DhcpMeta) {
        let ok = self.dhcp_meta.insert(&U32Key { v: ifindex }, value);
        debug_assert!(ok, "dhcp_meta table full at populate time");
    }

    // ── flow-table iteration (snapshot export) ────────────────────────────────
    // Only the FLOW tables (conntrack, nat, nat_ips) are iterable — they are the
    // per-flow state a blue-green upgrade must carry across the binary swap. The
    // config maps (routes/fw/lb/maglev/underlay/dhcp/meter) are re-derived from
    // the control plane on the new instance and are deliberately not exposed here.

    /// Visit every live conntrack `(CtKey, CtEntry)` entry (order unspecified).
    pub fn conntrack_for_each(&self, f: impl FnMut(&CtKey, &CtEntry)) {
        self.conntrack.for_each(f);
    }

    /// Visit every live NAT-config `(NatKey, NatValue)` entry (order unspecified).
    pub fn nat_for_each(&self, f: impl FnMut(&NatKey, &NatValue)) {
        self.nat.for_each(f);
    }

    /// Visit every registered NAT-IP `(NatIpKey, u8)` entry (order unspecified).
    /// The value is the dummy `1` `rte_hash` needs; only the key carries meaning.
    pub fn nat_ips_for_each(&self, f: impl FnMut(&NatIpKey, &u8)) {
        self.nat_ips.for_each(f);
    }
}

// ── Maps trait impl ──────────────────────────────────────────────────────────

impl Maps for DpdkMaps {
    fn local(&self) -> Option<Local> {
        self.local
    }

    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        self.underlay.get(&Ipv6Key { addr: *addr })
    }

    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta.get(&U32Key { v: ifindex })
    }

    /// Mirror `MemMaps`: key on `(key.ifindex, key.idx)`.
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.fw_rules.get(key)
    }

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

    // ── IPv6 firewall / conntrack (parity with the v4 fw/ct methods above) ────
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta6.get(&U32Key { v: ifindex })
    }

    /// Mirror `fw_rule`: key on `(key.ifindex, key.idx)` in the `FW_RULES6` table.
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<FwRule6> {
        self.fw_rules6.get(key)
    }

    fn conntrack6_get(&self, key: &CtKey6) -> Option<CtEntry> {
        self.conntrack6.get(key)
    }

    fn conntrack6_insert(&mut self, key: CtKey6, entry: CtEntry) {
        // Same as v4 `conntrack_insert`: a full v6 conntrack table drops here; count it so
        // saturation is observable via `dropped_conntrack_inserts()`.
        if !self.conntrack6.insert(&key, entry) {
            self.dropped_ct_inserts
                .set(self.dropped_ct_inserts.get() + 1);
        }
    }

    fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb.get(key)
    }

    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.maglev.get(key)
    }

    fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.nat.get(key)
    }

    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.nat_ips.get(&NatIpKey { vni, ipv4: *ip }).is_some()
    }

    /// Exact-match (/32) IPv4 route lookup.  `DpdkMaps` stores only host routes so the LPM
    /// in `MemMaps` reduces to a direct hash lookup on `(vni, dst)`.
    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
        self.route4.get(&Route4Key { vni, ipv4: *dst })
    }

    /// Exact-match (/128) IPv6 route lookup.
    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
        self.route6.get(&Route6Key { vni, ipv6: *dst })
    }

    fn dhcp_config(&self) -> Option<DhcpConfig> {
        self.dhcp_config
    }

    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta> {
        self.dhcp_meta.get(&U32Key { v: ifindex })
    }

    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        self.meter.get(&U32Key { v: ifindex })
    }

    fn meter_update(&mut self, ifindex: u32, state: MeterState) {
        // Meter state is keyed by a bounded ifindex set (one entry per interface); it should never
        // fill. A dropped update just means the meter's rate state isn't advanced this call — not a
        // correctness hazard — so ignore the bool (debug_assert to surface the impossible case).
        let ok = self.meter.insert(&U32Key { v: ifindex }, state);
        debug_assert!(ok, "meter table full (bounded by interface count)");
    }
}
