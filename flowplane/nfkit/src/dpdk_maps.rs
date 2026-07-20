//! [`DpdkMaps`] — a [`flowplane_core::maps::Maps`] implementation backed by [`DpdkHash`]
//! (DPDK `rte_hash`).  Mirrors [`flowplane_sim::maps::MemMaps`] in key derivation so the two
//! implementations produce identical key→value behaviour and M3 parity anchors remain valid.

use crate::{DpdkHash, HashError};
use flowplane_common::{
    CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local,
    MaglevKey, MeterState, NatKey, NatValue, RouteValue, UnderlayValue,
};
use flowplane_core::maps::Maps;

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
const _: () = assert!(std::mem::size_of::<FwRuleKey>() == 8);
const _: () = assert!(std::mem::size_of::<LbKey>() == 12);
const _: () = assert!(std::mem::size_of::<MaglevKey>() == 8);
const _: () = assert!(std::mem::size_of::<NatKey>() == 8);

// ── capacity constants ───────────────────────────────────────────────────────

const CAP_CT: u32 = 65_536; // conntrack: high cardinality
const CAP_STD: u32 = 4_096; // all other maps

// ── DpdkMaps ─────────────────────────────────────────────────────────────────

/// `Maps` implementation over DPDK `rte_hash` tables.  Drop-in replacement for `MemMaps` in
/// DPDK NF contexts: identical key derivation, same public test-only setters, safe Rust surface.
pub struct DpdkMaps {
    // Singletons — stored inline, not in a hash.
    local: Option<Local>,
    dhcp_config: Option<DhcpConfig>,

    // Per-key hashes.
    conntrack: DpdkHash<CtKey, CtEntry>,
    underlay: DpdkHash<Ipv6Key, UnderlayValue>,
    fw_meta: DpdkHash<U32Key, FwMeta>,
    fw_rules: DpdkHash<FwRuleKey, FwRule>,
    lb: DpdkHash<LbKey, LbValue>,
    maglev: DpdkHash<MaglevKey, [u8; 16]>,
    nat: DpdkHash<NatKey, NatValue>,
    route4: DpdkHash<Route4Key, RouteValue>,
    route6: DpdkHash<Route6Key, RouteValue>,
    dhcp_meta: DpdkHash<U32Key, DhcpMeta>,
    meter: DpdkHash<U32Key, MeterState>,
}

impl DpdkMaps {
    /// Create all backing hashes on `socket_id`.
    ///
    /// # Errors
    /// Returns `HashError` if any `rte_hash_create` call fails (name collision, OOM).
    pub fn new(socket_id: i32) -> Result<Self, HashError> {
        Ok(Self {
            local: None,
            dhcp_config: None,
            conntrack: DpdkHash::new("dm_ct", CAP_CT, socket_id)?,
            underlay: DpdkHash::new("dm_underlay", CAP_STD, socket_id)?,
            fw_meta: DpdkHash::new("dm_fw_meta", CAP_STD, socket_id)?,
            fw_rules: DpdkHash::new("dm_fw_rules", CAP_STD, socket_id)?,
            lb: DpdkHash::new("dm_lb", CAP_STD, socket_id)?,
            maglev: DpdkHash::new("dm_maglev", CAP_STD, socket_id)?,
            nat: DpdkHash::new("dm_nat", CAP_STD, socket_id)?,
            route4: DpdkHash::new("dm_route4", CAP_STD, socket_id)?,
            route6: DpdkHash::new("dm_route6", CAP_STD, socket_id)?,
            dhcp_meta: DpdkHash::new("dm_dhcp_meta", CAP_STD, socket_id)?,
            meter: DpdkHash::new("dm_meter", CAP_STD, socket_id)?,
        })
    }

    // ── test-only population setters (mirror MemMaps public setters) ──────────

    /// Add an exact-host (/32) IPv4 route — mirrors `MemMaps::add_route4`.
    pub fn add_route4(&mut self, vni: u32, ipv4: [u8; 4], value: RouteValue) {
        self.route4.insert(&Route4Key { vni, ipv4 }, value);
    }

    /// Add an exact-host (/128) IPv6 route — mirrors `MemMaps::add_route6`.
    pub fn add_route6(&mut self, vni: u32, ipv6: [u8; 16], value: RouteValue) {
        self.route6.insert(&Route6Key { vni, ipv6 }, value);
    }

    /// Set the singleton `Local` — mirrors `MemMaps.local = Some(v)`.
    pub fn set_local(&mut self, v: Local) {
        self.local = Some(v);
    }

    /// Insert an underlay entry — mirrors `MemMaps.underlay.insert`.
    pub fn add_underlay(&mut self, addr: [u8; 16], value: UnderlayValue) {
        self.underlay.insert(&Ipv6Key { addr }, value);
    }

    /// Insert a firewall meta entry — mirrors `MemMaps.fw_meta.insert`.
    pub fn add_fw_meta(&mut self, ifindex: u32, value: FwMeta) {
        self.fw_meta.insert(&U32Key { v: ifindex }, value);
    }

    /// Insert a firewall rule — mirrors `MemMaps.fw_rules.insert((ifindex, idx), rule)`.
    pub fn add_fw_rule(&mut self, ifindex: u32, idx: u32, rule: FwRule) {
        self.fw_rules.insert(&FwRuleKey { ifindex, idx }, rule);
    }

    /// Insert an LB entry.
    pub fn add_lb(&mut self, key: LbKey, value: LbValue) {
        self.lb.insert(&key, value);
    }

    /// Insert a Maglev slot.
    pub fn add_maglev(&mut self, key: MaglevKey, backend: [u8; 16]) {
        self.maglev.insert(&key, backend);
    }

    /// Insert a NAT config entry.
    pub fn add_nat(&mut self, key: NatKey, value: NatValue) {
        self.nat.insert(&key, value);
    }

    /// Set the server-wide DHCP config singleton.
    pub fn set_dhcp_config(&mut self, v: DhcpConfig) {
        self.dhcp_config = Some(v);
    }

    /// Insert a per-interface DHCP meta entry.
    pub fn add_dhcp_meta(&mut self, ifindex: u32, value: DhcpMeta) {
        self.dhcp_meta.insert(&U32Key { v: ifindex }, value);
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
        self.conntrack.insert(&key, entry);
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
        self.meter.insert(&U32Key { v: ifindex }, state);
    }
}
