//! [`SharedConfigMaps`] — the process-wide, single-writer CONFIG-map tables for the DPDK serve
//! binary. One instance for the whole process: the tokio control thread is the SOLE writer
//! (writer methods take `&self` but are single-writer only — see the SINGLE-WRITER MODEL note on
//! the struct), and every datapath lcore holds a `&SharedConfigMaps` and reads it lock-free every
//! packet. Each table is an [`RcuHash`] (lock-free reader + QSBR-RCU value reclamation, per the
//! Task-3 gate); this instance owns the single QSBR variable all its tables share, plus an
//! `AtomicU64` config generation the writer bumps on config changes (conntrack invalidation, spec
//! §5a).
//!
//! ── WHAT THIS IS / ISN'T ──────────────────────────────────────────────────────────────────────
//! This is the WRITER side + table STORAGE. It exposes:
//!  * writer methods (`*_insert`/`*_remove`/`*_set`) the `DpdkMapWriter` (Task 6) calls, and
//!  * reader getters (`*_get`/`is_nat_ip`/…) the composed datapath `Maps` impl (Task 5) calls.
//!
//! It deliberately does NOT `impl flowplane_core::maps::Maps` — that composition (shared CONFIG plus
//! per-lcore FLOW state: conntrack/meter) is Task 5.
//!
//! ── TABLE SET (derived from writer.rs ∩ maps.rs ∩ dpdk_maps.rs) ───────────────────────────────
//! The CONFIG half only. The FLOW half of `DpdkMaps` (conntrack, plus the meter's per-packet token
//! STATE — mutated on the datapath) stays per-lcore and is NOT here; only the meter RATE CONFIG
//! (`meter_config`) lives here, composed with per-lcore tokens on read. Union of "what `MapWriter`
//! writes" and "what the datapath `Maps` reads":
//!   route4, route6, nat, nat_ips, lb, maglev, underlay, fw_rules, fw_meta,   (writer ∩ reader)
//!   ifaces, iface_meta, ports, neigh_nat, vips,                              (writer-only, iface domain)
//!   dhcp_meta (writer removes / reader reads),                              (reader ∩ writer)
//!   meter_config (writer sets/clears QoS rate / reader reads per-iface rate), (reader ∩ writer)
//!   + singletons: dhcp_config, local, neigh_nat_count.
//!
//! ── ALL-ZERO-KEY SAFETY (Task-3 constraint 2) ─────────────────────────────────────────────────
//! `RcuHash::insert` double-frees on an all-zero key (it aliases DPDK's reserved dummy slot 0).
//! Several CONFIG keys CAN legitimately be all-zero — e.g. `Route4Key{vni:0, ipv4:0.0.0.0}` (a
//! default route in VNI 0), `NatKey{vni:0, ipv4:0.0.0.0}`, `U32Key{v:0}` (ifindex 0),
//! `MaglevKey{table_id:0, slot:0}`, an all-zero `IfaceKey`/`VipKey`/`LbKey`. So we CANNOT rely on
//! "keys are never all-zero in practice". Instead EVERY table key is wrapped in a per-table struct
//! carrying a UNIQUE NON-ZERO `tag: u8` as its first byte. Because the tag is always non-zero, the
//! wrapped key can NEVER be the all-zero byte pattern regardless of its payload. The tag is also
//! distinct per table, which is belt-and-suspenders (tables are already separate rte_hash
//! instances). All wrapper structs are `#[repr(C)]` and padding-free (checked by `const _` asserts)
//! so the hashed key bytes are fully initialized.

use std::alloc::Layout;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use flowplane_common::{
    DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRule6, FwRuleKey, IfaceKey, IfaceMetaKey, IfaceMetaVal,
    IfaceValue, LbKey, LbValue, Local, MaglevKey, NatKey, NatValue, NeighborNatEntry, PortMeta,
    RouteValue, UnderlayValue, VipKey,
};

use crate::rcu_hash::RcuHash;
use crate::HashError;

/// Max reader threads (datapath lcores) that may register on this instance's QSBR. 64 is generous
/// vs. realistic per-node lcore counts and matches the `MAX_READERS` the task specifies.
pub const MAX_READERS: u32 = 64;

/// Monotonic per-process instance id, so each `SharedConfigMaps`' rte_hash tables get unique names.
/// (EAL is process-global; two coexisting instances — or the same test re-run in one process —
/// would collide on fixed names. Mirrors `DpdkMaps::NEXT_INSTANCE`.)
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// ~2× headroom on every table (Task-3 constraint 3): RCU defers reclaim of overwritten/deleted
/// slots until a grace period, so the live rte_hash count can transiently exceed the working set.
/// Sizing at 2× keeps churn from spuriously hitting `-ENOSPC` before stale slots are reclaimed.
const HEADROOM: u32 = 2;

// ── per-table tagged key wrappers (unique non-zero tag ⇒ never all-zero) ──────────────────────────
// Each has the tag FIRST followed by the payload and explicit padding so there are NO implicit
// padding bytes (uninitialized padding would feed garbage into the key hash). const asserts below
// verify size == sum(fields) for every wrapper.

macro_rules! tagged_key {
    ($(#[$m:meta])* $name:ident, $tag:expr, { $($field:ident : $ty:ty),* $(,)? }, $pad:expr) => {
        $(#[$m])*
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct $name {
            tag: u8,
            _pad: [u8; $pad],
            $($field : $ty),*
        }
        impl $name {
            const TAG: u8 = $tag;
            #[inline]
            fn new($($field : $ty),*) -> Self {
                Self { tag: Self::TAG, _pad: [0u8; $pad], $($field),* }
            }
        }
    };
}

// tag 1: route4 (vni,ipv4). payload 4+4=8, tag+pad3 = 4 → total 12, padding-free.
tagged_key!(Route4Key, 1, { vni: u32, ipv4: [u8; 4] }, 3);
// tag 2: route6 (vni,ipv6). payload 4+16=20, tag+pad3=4 → total 24.
tagged_key!(Route6Key, 2, { vni: u32, ipv6: [u8; 16] }, 3);
// tag 3: nat config (vni,ipv4).
tagged_key!(NatK, 3, { vni: u32, ipv4: [u8; 4] }, 3);
// tag 4: nat-ip set (vni,ipv4).
tagged_key!(NatIpK, 4, { vni: u32, ipv4: [u8; 4] }, 3);
// tag 5: lb (vni,ipv4,port,proto). Manually laid out padding-free: tag+pad3=4, then vni(4),
// ipv4(4), port(2), proto(1), trailing _pad1(1) → total 16, no implicit padding.
#[repr(C)]
#[derive(Copy, Clone)]
struct LbK {
    tag: u8,
    _pad: [u8; 3],
    vni: u32,
    ipv4: [u8; 4],
    port: u16,
    proto: u8,
    _pad1: [u8; 1],
}
impl LbK {
    const TAG: u8 = 5;
    #[inline]
    fn new(vni: u32, ipv4: [u8; 4], port: u16, proto: u8) -> Self {
        Self {
            tag: Self::TAG,
            _pad: [0; 3],
            vni,
            ipv4,
            port,
            proto,
            _pad1: [0; 1],
        }
    }
}
// tag 6: maglev (table_id,slot).
tagged_key!(MaglevK, 6, { table_id: u32, slot: u32 }, 3);
// tag 7: underlay (ipv6). payload 16, tag+pad3=4 → total 20.
tagged_key!(UnderlayK, 7, { addr: [u8; 16] }, 3);
// tag 8: fw rule (ifindex,idx).
tagged_key!(FwRuleK, 8, { ifindex: u32, idx: u32 }, 3);
// tag 9: fw meta (ifindex).
tagged_key!(FwMetaK, 9, { ifindex: u32 }, 3);
// tag 10: interfaces (vni,ipv4).
tagged_key!(IfaceK, 10, { vni: u32, ipv4: [u8; 4] }, 3);
// tag 11: iface-meta journal (id[64]). payload 64, tag+pad3=4 → total 68.
tagged_key!(IfaceMetaK, 11, { id: [u8; flowplane_common::IFACE_ID_MAX] }, 3);
// tag 12: ports (ifindex).
tagged_key!(PortK, 12, { ifindex: u32 }, 3);
// tag 13: neigh-nat (slot idx).
tagged_key!(NeighNatK, 13, { idx: u32 }, 3);
// tag 14: vips (vni,ipv4).
tagged_key!(VipK, 14, { vni: u32, ipv4: [u8; 4] }, 3);
// tag 15: dhcp-meta (ifindex).
tagged_key!(DhcpMetaK, 15, { ifindex: u32 }, 3);
// tag 16: meter config (ifindex).
tagged_key!(MeterCfgK, 16, { ifindex: u32 }, 3);
// tag 17: fw rule6 (ifindex,idx). Parallel v6 firewall rule table.
tagged_key!(FwRule6K, 17, { ifindex: u32, idx: u32 }, 3);
// tag 18: fw meta6 (ifindex). Parallel v6 firewall meta table.
tagged_key!(FwMeta6K, 18, { ifindex: u32 }, 3);

// Padding-free guarantees (uninitialized padding bytes would corrupt the hashed key).
const _: () = assert!(std::mem::size_of::<Route4Key>() == 12);
const _: () = assert!(std::mem::size_of::<Route6Key>() == 24);
const _: () = assert!(std::mem::size_of::<NatK>() == 12);
const _: () = assert!(std::mem::size_of::<NatIpK>() == 12);
const _: () = assert!(std::mem::size_of::<LbK>() == 16);
const _: () = assert!(std::mem::size_of::<MaglevK>() == 12);
const _: () = assert!(std::mem::size_of::<UnderlayK>() == 20);
const _: () = assert!(std::mem::size_of::<FwRuleK>() == 12);
const _: () = assert!(std::mem::size_of::<FwMetaK>() == 8);
const _: () = assert!(std::mem::size_of::<IfaceK>() == 12);
const _: () = assert!(std::mem::size_of::<IfaceMetaK>() == 68);
const _: () = assert!(std::mem::size_of::<PortK>() == 8);
const _: () = assert!(std::mem::size_of::<NeighNatK>() == 8);
const _: () = assert!(std::mem::size_of::<VipK>() == 12);
const _: () = assert!(std::mem::size_of::<DhcpMetaK>() == 8);
const _: () = assert!(std::mem::size_of::<MeterCfgK>() == 8);
const _: () = assert!(std::mem::size_of::<FwRule6K>() == 12);
const _: () = assert!(std::mem::size_of::<FwMeta6K>() == 8);

// ── reader token ─────────────────────────────────────────────────────────────────────────────────

/// Proof-of-registration handle for a datapath reader thread. `register_reader` registers the
/// calling thread on this instance's QSBR and marks it online; the caller passes the token back to
/// `report_quiescent` each poll loop so the writer's deferred RCU frees can make progress. The token
/// carries the QSBR reader id (0..MAX_READERS).
#[derive(Copy, Clone, Debug)]
pub struct ReaderToken {
    id: u32,
}

impl ReaderToken {
    /// The QSBR thread id this reader registered as.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
}

// ── SharedConfigMaps ──────────────────────────────────────────────────────────────────────────────

/// Process-wide single-writer LF+RCU CONFIG tables + generation counter (see module doc).
///
/// SINGLE-WRITER MODEL: all mutators take `&self` (interior mutation via the C-side rte_hash /
/// atomics), but are SOUND ONLY UNDER THE SINGLE-WRITER CONVENTION: the caller guarantees no
/// concurrent writers. The sole writer is the tokio control thread — its `DpdkMapWriter` /
/// `ControlCore` lives behind a `Mutex`, so writes are serialized — while N datapath lcores hold an
/// `Arc<SharedConfigMaps>` and call ONLY the `&self` getters lock-free (RCU/QSBR). `&self` (rather
/// than `&mut self`) is what lets an `Arc<SharedConfigMaps>` be shared across the writer thread and
/// the reader lcores at once; `RcuHash`'s `RW_CONCURRENCY_LF` makes ONE writer + N lock-free readers
/// safe but NOT concurrent writers, so the Mutex on the writer side is load-bearing.
pub struct SharedConfigMaps {
    // ── QSBR (single, shared by every table; 64-byte aligned hand alloc) ──────
    qsbr: *mut dpdk_sys::rte_rcu_qsbr,
    qsbr_layout: Layout,
    /// Next QSBR reader id to hand out (0..MAX_READERS). `AtomicU32` so `register_reader` can take
    /// `&self` (each datapath lcore registers itself through the shared `Arc`); the fetch_add is the
    /// single source of unique ids.
    next_reader: AtomicU32,

    // ── config generation (writer bumps; readers/CT-invalidation observe) ─────
    config_generation: AtomicU64,

    // ── singletons (inline, not hashed) ──────────────────────────────────────
    // These are NOT in an RcuHash, so they carry their own interior mutability so the writer methods
    // can take `&self` (single-writer convention, same as the tables). The two `Copy` Option
    // singletons use an `RwLock` (single writer ⇒ read-locks never contend with each other and only
    // rarely with the lone serialized writer); the count is a plain `AtomicU32`.
    local: std::sync::RwLock<Option<Local>>,
    dhcp_config: std::sync::RwLock<Option<DhcpConfig>>,
    neigh_nat_count: AtomicU32,

    // ── CONFIG tables (ManuallyDrop<RcuHash>; drop BEFORE the qsbr they reference) ──────────
    // ManuallyDrop prevents the compiler from auto-dropping these fields after Drop::drop returns.
    // Drop::drop calls ManuallyDrop::drop on each table (= exactly once), then frees the QSBR.
    route4: std::mem::ManuallyDrop<RcuHash<Route4Key, RouteValue>>,
    route6: std::mem::ManuallyDrop<RcuHash<Route6Key, RouteValue>>,
    nat: std::mem::ManuallyDrop<RcuHash<NatK, NatValue>>,
    nat_ips: std::mem::ManuallyDrop<RcuHash<NatIpK, u8>>,
    lb: std::mem::ManuallyDrop<RcuHash<LbK, LbValue>>,
    maglev: std::mem::ManuallyDrop<RcuHash<MaglevK, [u8; 16]>>,
    underlay: std::mem::ManuallyDrop<RcuHash<UnderlayK, UnderlayValue>>,
    fw_rules: std::mem::ManuallyDrop<RcuHash<FwRuleK, FwRule>>,
    fw_meta: std::mem::ManuallyDrop<RcuHash<FwMetaK, FwMeta>>,
    fw_rules6: std::mem::ManuallyDrop<RcuHash<FwRule6K, FwRule6>>,
    fw_meta6: std::mem::ManuallyDrop<RcuHash<FwMeta6K, FwMeta>>,
    ifaces: std::mem::ManuallyDrop<RcuHash<IfaceK, IfaceValue>>,
    iface_meta: std::mem::ManuallyDrop<RcuHash<IfaceMetaK, IfaceMetaVal>>,
    ports: std::mem::ManuallyDrop<RcuHash<PortK, PortMeta>>,
    neigh_nat: std::mem::ManuallyDrop<RcuHash<NeighNatK, NeighborNatEntry>>,
    vips: std::mem::ManuallyDrop<RcuHash<VipK, [u8; 4]>>,
    dhcp_meta: std::mem::ManuallyDrop<RcuHash<DhcpMetaK, DhcpMeta>>,
    meter_config: std::mem::ManuallyDrop<RcuHash<MeterCfgK, flowplane_common::MeterConfig>>,
}

// SAFETY: `SharedConfigMaps` holds a raw `*mut rte_rcu_qsbr` and (inside each `RcuHash`) raw
// rte_hash pointers, which are not auto-`Send`/`Sync`. Implementing both by hand is sound because
// the RCU concurrency contract is upheld by the caller, NOT by Rust aliasing rules:
//   * WRITES are serialized — the sole writer (`ControlCore<DpdkMapWriter>`, owning an
//     `Arc<SharedConfigMaps>`) lives behind a `Mutex` on the tokio control thread, so only one
//     writer ever touches the tables at a time (`&self` writer methods, single-writer convention).
//   * READS are lock-free and safe under `RW_CONCURRENCY_LF` + QSBR: each datapath lcore registers
//     via `register_reader` and reports quiescence, so value boxes are RCU-reclaimed only past a
//     grace period. Readers call ONLY the `&self` getters.
// This is exactly the 1-writer/N-lock-free-reader model the §5b RCU anchor validated. It lets an
// `Arc<SharedConfigMaps>` be shared across the tokio writer thread and the datapath lcore threads.
// `Send`/`Sync` are NOT a license for concurrent WRITERS — that remains the caller's Mutex to guard.
unsafe impl Send for SharedConfigMaps {}
unsafe impl Sync for SharedConfigMaps {}

impl SharedConfigMaps {
    /// Build all CONFIG tables on `socket_id`, each sized `entries * HEADROOM`, sharing one freshly
    /// allocated + initialized QSBR variable. `generation` starts at 0.
    ///
    /// # Errors
    /// Returns `HashError` if the QSBR allocation fails or any `RcuHash::new_lf_rcu` fails (name
    /// collision / OOM / QSBR attach). On table-build failure, already-built tables and the QSBR are
    /// dropped/freed by the early return (each table is a local until moved into `Self`).
    pub fn new(socket_id: i32, entries: u32) -> Result<Self, HashError> {
        // ── QSBR: 64-byte aligned, zeroed, initialized. Must outlive every table. ──
        let sz = unsafe { dpdk_sys::nfkit_rcu_qsbr_get_memsize(MAX_READERS) } as usize;
        let qsbr_layout = Layout::from_size_align(sz, 64).map_err(|_| HashError)?;
        // SAFETY: non-zero size (get_memsize > 0 for MAX_READERS >= 1); freed in Drop.
        let qsbr =
            unsafe { std::alloc::alloc_zeroed(qsbr_layout) }.cast::<dpdk_sys::rte_rcu_qsbr>();
        if qsbr.is_null() {
            return Err(HashError);
        }
        // SAFETY: qsbr points to `sz` zeroed, 64B-aligned bytes >= get_memsize(MAX_READERS).
        let rc = unsafe { dpdk_sys::nfkit_rcu_qsbr_init(qsbr, MAX_READERS) };
        if rc != 0 {
            // SAFETY: qsbr came from alloc_zeroed(qsbr_layout); not yet handed to any table.
            unsafe { std::alloc::dealloc(qsbr.cast::<u8>(), qsbr_layout) };
            return Err(HashError);
        }

        let cap = entries.saturating_mul(HEADROOM).max(1);
        let n = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);

        // Helper: build one RcuHash with a per-instance-unique name. On any error we must free the
        // QSBR (tables built so far are locals and drop naturally on `?`, reclaiming their own
        // boxes; but the QSBR is raw and would leak). We use a closure-free explicit match so we can
        // free the QSBR before returning Err.
        macro_rules! build {
            ($short:literal) => {{
                // SAFETY: qsbr is initialized above and outlives all tables (freed in Drop after
                // tables). Unique name per (instance, table).
                match unsafe {
                    RcuHash::new_lf_rcu(&format!("sc_{}_{}", $short, n), cap, socket_id, qsbr)
                } {
                    Ok(h) => h,
                    Err(e) => {
                        // SAFETY: qsbr not referenced by the failed table; earlier tables (locals)
                        // will be dropped as this scope unwinds via the returned Err.
                        unsafe { std::alloc::dealloc(qsbr.cast::<u8>(), qsbr_layout) };
                        return Err(e);
                    }
                }
            }};
        }

        let route4 = build!("r4");
        let route6 = build!("r6");
        let nat = build!("nat");
        let nat_ips = build!("ni");
        let lb = build!("lb");
        let maglev = build!("mg");
        let underlay = build!("ul");
        let fw_rules = build!("fr");
        let fw_meta = build!("fm");
        let fw_rules6 = build!("fr6");
        let fw_meta6 = build!("fm6");
        let ifaces = build!("if");
        let iface_meta = build!("im");
        let ports = build!("pt");
        let neigh_nat = build!("nn");
        let vips = build!("vip");
        let dhcp_meta = build!("dm");
        let meter_config = build!("mc");

        Ok(Self {
            qsbr,
            qsbr_layout,
            next_reader: AtomicU32::new(0),
            config_generation: AtomicU64::new(0),
            local: std::sync::RwLock::new(None),
            dhcp_config: std::sync::RwLock::new(None),
            neigh_nat_count: AtomicU32::new(0),
            route4: std::mem::ManuallyDrop::new(route4),
            route6: std::mem::ManuallyDrop::new(route6),
            nat: std::mem::ManuallyDrop::new(nat),
            nat_ips: std::mem::ManuallyDrop::new(nat_ips),
            lb: std::mem::ManuallyDrop::new(lb),
            maglev: std::mem::ManuallyDrop::new(maglev),
            underlay: std::mem::ManuallyDrop::new(underlay),
            fw_rules: std::mem::ManuallyDrop::new(fw_rules),
            fw_meta: std::mem::ManuallyDrop::new(fw_meta),
            fw_rules6: std::mem::ManuallyDrop::new(fw_rules6),
            fw_meta6: std::mem::ManuallyDrop::new(fw_meta6),
            ifaces: std::mem::ManuallyDrop::new(ifaces),
            iface_meta: std::mem::ManuallyDrop::new(iface_meta),
            ports: std::mem::ManuallyDrop::new(ports),
            neigh_nat: std::mem::ManuallyDrop::new(neigh_nat),
            vips: std::mem::ManuallyDrop::new(vips),
            dhcp_meta: std::mem::ManuallyDrop::new(dhcp_meta),
            meter_config: std::mem::ManuallyDrop::new(meter_config),
        })
    }

    // ── generation ────────────────────────────────────────────────────────────

    /// Current config generation (Acquire). Datapath / CT-invalidation reads this to detect that the
    /// writer changed config (spec §5a: a NAT teardown bumps it to invalidate stale conntrack).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.config_generation.load(Ordering::Acquire)
    }

    /// Bump the config generation by one (Release), publishing that a config change happened after
    /// the map writes that precede this call.
    pub fn bump_generation(&self) {
        self.config_generation.fetch_add(1, Ordering::Release);
    }

    // ── reader registration ─────────────────────────────────────────────────────

    /// Register the CALLING thread as a QSBR reader (datapath lcore) and mark it online, returning a
    /// [`ReaderToken`] it must pass to [`report_quiescent`] each poll loop. Ids are handed out
    /// 0..[`MAX_READERS`]; registering more than `MAX_READERS` readers panics (a real bug — the
    /// process has more datapath lcores than the QSBR was sized for).
    ///
    /// [`report_quiescent`]: Self::report_quiescent
    pub fn register_reader(&self) -> ReaderToken {
        let id = self.next_reader.fetch_add(1, Ordering::Relaxed);
        assert!(
            id < MAX_READERS,
            "SharedConfigMaps: more than MAX_READERS ({MAX_READERS}) reader threads registered"
        );
        // SAFETY: id < MAX_READERS; qsbr initialized for MAX_READERS threads.
        let rc = unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_register(self.qsbr, id) };
        assert_eq!(rc, 0, "qsbr thread_register failed for reader {id}");
        // SAFETY: this thread was just registered on qsbr with `id`.
        unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_online(self.qsbr, id) };
        ReaderToken { id }
    }

    /// Report that the reader `tok` has reached a quiescent state (dropped all borrows of any value
    /// it read). Lets the writer's deferred RCU frees (overwrite/delete) reclaim past this thread.
    /// Call once per datapath poll iteration on `&self` (readers hold only `&SharedConfigMaps`).
    pub fn report_quiescent(&self, tok: &ReaderToken) {
        // SAFETY: `tok` was produced by `register_reader` on THIS instance's qsbr, so `tok.id` is
        // registered+online on `self.qsbr`.
        unsafe { dpdk_sys::nfkit_rcu_qsbr_quiescent(self.qsbr, tok.id) };
    }

    // ── singleton setters/getters ───────────────────────────────────────────────

    /// Set the `LOCAL[0]` singleton (uplink + underlay gateway).
    pub fn set_local(&self, v: Local) {
        *self.local.write().expect("local RwLock poisoned") = Some(v);
    }

    /// Read the `LOCAL[0]` singleton.
    #[must_use]
    pub fn local(&self) -> Option<Local> {
        *self.local.read().expect("local RwLock poisoned")
    }

    /// Set the server-wide DHCP config singleton (`DHCP_CONFIG[0]`).
    pub fn set_dhcp_config(&self, cfg: DhcpConfig) {
        *self
            .dhcp_config
            .write()
            .expect("dhcp_config RwLock poisoned") = Some(cfg);
    }

    /// Read the server-wide DHCP config singleton.
    #[must_use]
    pub fn dhcp_config(&self) -> Option<DhcpConfig> {
        *self
            .dhcp_config
            .read()
            .expect("dhcp_config RwLock poisoned")
    }

    /// Set the neighbor-NAT active-slot count (bounds the datapath's neigh-nat scan).
    pub fn set_neigh_nat_count(&self, count: u32) {
        self.neigh_nat_count.store(count, Ordering::Release);
    }

    /// Read the neighbor-NAT active-slot count.
    #[must_use]
    pub fn neigh_nat_count(&self) -> u32 {
        self.neigh_nat_count.load(Ordering::Acquire)
    }

    // ── WRITER side (names the DpdkMapWriter, Task 6, calls) ─────────────────────
    // Each is a thin wrapper building the tagged key then insert/remove. `insert`/`remove` return
    // bool (false = table full / absent); writer methods propagate that so Task 6 can surface a
    // `-ENOSPC`. Names are `<table>_insert` / `<table>_remove` mirroring the DpdkMaps setters.

    /// Insert/overwrite a `/32` IPv4 route `(vni,ipv4)`. Returns false if the table is full.
    pub fn route4_insert(&self, vni: u32, ipv4: [u8; 4], val: RouteValue) -> bool {
        self.route4.insert(&Route4Key::new(vni, ipv4), val)
    }
    /// Remove a `/32` IPv4 route. Returns true if present.
    pub fn route4_remove(&self, vni: u32, ipv4: [u8; 4]) -> bool {
        self.route4.remove(&Route4Key::new(vni, ipv4))
    }

    /// Insert/overwrite a `/128` IPv6 route `(vni,ipv6)`. Returns false if the table is full.
    pub fn route6_insert(&self, vni: u32, ipv6: [u8; 16], val: RouteValue) -> bool {
        self.route6.insert(&Route6Key::new(vni, ipv6), val)
    }
    /// Remove a `/128` IPv6 route. Returns true if present.
    pub fn route6_remove(&self, vni: u32, ipv6: [u8; 16]) -> bool {
        self.route6.remove(&Route6Key::new(vni, ipv6))
    }

    /// Insert/overwrite a NAT-GW config entry. Returns false if the table is full.
    pub fn nat_insert(&self, key: NatKey, val: NatValue) -> bool {
        self.nat.insert(&NatK::new(key.vni, key.ipv4), val)
    }
    /// Remove a NAT-GW config entry. Returns true if present.
    pub fn nat_remove(&self, key: &NatKey) -> bool {
        self.nat.remove(&NatK::new(key.vni, key.ipv4))
    }

    /// Register `(vni,ip)` as a public NAT IP (value is a dummy `1`). Returns false if full.
    pub fn nat_ips_insert(&self, vni: u32, ip: [u8; 4]) -> bool {
        self.nat_ips.insert(&NatIpK::new(vni, ip), 1)
    }
    /// Deregister a public NAT IP. Returns true if present.
    pub fn nat_ips_remove(&self, vni: u32, ip: [u8; 4]) -> bool {
        self.nat_ips.remove(&NatIpK::new(vni, ip))
    }

    /// Insert/overwrite an LB service entry. Returns false if the table is full.
    pub fn lb_insert(&self, key: LbKey, val: LbValue) -> bool {
        self.lb
            .insert(&LbK::new(key.vni, key.ipv4, key.port, key.proto), val)
    }
    /// Remove an LB service entry. Returns true if present.
    pub fn lb_remove(&self, key: &LbKey) -> bool {
        self.lb
            .remove(&LbK::new(key.vni, key.ipv4, key.port, key.proto))
    }

    /// Insert/overwrite a Maglev slot → backend IPv6. Returns false if the table is full.
    pub fn maglev_insert(&self, key: MaglevKey, backend: [u8; 16]) -> bool {
        self.maglev
            .insert(&MaglevK::new(key.table_id, key.slot), backend)
    }
    /// Remove a Maglev slot. Returns true if present.
    pub fn maglev_remove(&self, key: &MaglevKey) -> bool {
        self.maglev.remove(&MaglevK::new(key.table_id, key.slot))
    }

    /// Insert/overwrite an underlay delivery entry (node IPv6 → vni/tap/mac). Returns false if full.
    pub fn underlay_insert(&self, addr: [u8; 16], val: UnderlayValue) -> bool {
        self.underlay.insert(&UnderlayK::new(addr), val)
    }
    /// Remove an underlay entry. Returns true if present.
    pub fn underlay_remove(&self, addr: &[u8; 16]) -> bool {
        self.underlay.remove(&UnderlayK::new(*addr))
    }

    /// Insert/overwrite a firewall rule slot `(ifindex,idx)`. Returns false if the table is full.
    pub fn fw_rules_insert(&self, key: FwRuleKey, rule: FwRule) -> bool {
        self.fw_rules
            .insert(&FwRuleK::new(key.ifindex, key.idx), rule)
    }
    /// Remove a firewall rule slot. Returns true if present.
    pub fn fw_rules_remove(&self, key: &FwRuleKey) -> bool {
        self.fw_rules.remove(&FwRuleK::new(key.ifindex, key.idx))
    }

    /// Insert/overwrite per-interface firewall rule counts. Returns false if the table is full.
    pub fn fw_meta_insert(&self, ifindex: u32, val: FwMeta) -> bool {
        self.fw_meta.insert(&FwMetaK::new(ifindex), val)
    }
    /// Remove per-interface firewall meta. Returns true if present.
    pub fn fw_meta_remove(&self, ifindex: u32) -> bool {
        self.fw_meta.remove(&FwMetaK::new(ifindex))
    }

    /// Insert/overwrite an IPv6 firewall rule slot `(ifindex,idx)`. Returns false if the table is full.
    pub fn fw_rules6_insert(&self, key: FwRuleKey, rule: FwRule6) -> bool {
        self.fw_rules6
            .insert(&FwRule6K::new(key.ifindex, key.idx), rule)
    }
    /// Remove an IPv6 firewall rule slot. Returns true if present.
    pub fn fw_rules6_remove(&self, key: &FwRuleKey) -> bool {
        self.fw_rules6.remove(&FwRule6K::new(key.ifindex, key.idx))
    }

    /// Insert/overwrite per-interface IPv6 firewall rule counts. Returns false if the table is full.
    pub fn fw_meta6_insert(&self, ifindex: u32, val: FwMeta) -> bool {
        self.fw_meta6.insert(&FwMeta6K::new(ifindex), val)
    }
    /// Remove per-interface IPv6 firewall meta. Returns true if present.
    pub fn fw_meta6_remove(&self, ifindex: u32) -> bool {
        self.fw_meta6.remove(&FwMeta6K::new(ifindex))
    }

    /// Insert/overwrite a per-interface meter rate config. Returns false if the table is full.
    pub fn meter_config_insert(&self, ifindex: u32, cfg: flowplane_common::MeterConfig) -> bool {
        self.meter_config.insert(&MeterCfgK::new(ifindex), cfg)
    }
    /// Remove a per-interface meter rate config. Returns true if present.
    pub fn meter_config_remove(&self, ifindex: u32) -> bool {
        self.meter_config.remove(&MeterCfgK::new(ifindex))
    }

    /// Insert/overwrite an interfaces entry `(vni,ipv4)` → delivery info. Returns false if full.
    pub fn ifaces_insert(&self, key: IfaceKey, val: IfaceValue) -> bool {
        self.ifaces.insert(&IfaceK::new(key.vni, key.ipv4), val)
    }
    /// Remove an interfaces entry. Returns true if present.
    pub fn ifaces_remove(&self, key: IfaceKey) -> bool {
        self.ifaces.remove(&IfaceK::new(key.vni, key.ipv4))
    }

    /// Insert/overwrite an `IFACE_META` restart-journal entry. Returns false if the table is full.
    pub fn iface_meta_insert(&self, key: IfaceMetaKey, val: IfaceMetaVal) -> bool {
        self.iface_meta.insert(&IfaceMetaK::new(key.id), val)
    }
    /// Remove an `IFACE_META` journal entry. Returns true if present.
    pub fn iface_meta_remove(&self, key: &IfaceMetaKey) -> bool {
        self.iface_meta.remove(&IfaceMetaK::new(key.id))
    }

    /// Insert/overwrite per-port metadata keyed by tap ifindex. Returns false if the table is full.
    pub fn ports_insert(&self, ifindex: u32, meta: PortMeta) -> bool {
        self.ports.insert(&PortK::new(ifindex), meta)
    }
    /// Remove per-port metadata. Returns true if present.
    pub fn ports_remove(&self, ifindex: u32) -> bool {
        self.ports.remove(&PortK::new(ifindex))
    }

    /// Insert/overwrite a neighbor-NAT slot. Returns false if the table is full.
    pub fn neigh_nat_insert(&self, idx: u32, val: NeighborNatEntry) -> bool {
        self.neigh_nat.insert(&NeighNatK::new(idx), val)
    }
    /// Remove a neighbor-NAT slot. Returns true if present.
    pub fn neigh_nat_remove(&self, idx: u32) -> bool {
        self.neigh_nat.remove(&NeighNatK::new(idx))
    }

    /// Insert/overwrite a VIP 1:1 mapping `(vni,ipv4)` → mapped IPv4. Returns false if full.
    pub fn vips_insert(&self, key: VipKey, mapped: [u8; 4]) -> bool {
        self.vips.insert(&VipK::new(key.vni, key.ipv4), mapped)
    }
    /// Remove a VIP mapping. Returns true if present.
    pub fn vips_remove(&self, key: &VipKey) -> bool {
        self.vips.remove(&VipK::new(key.vni, key.ipv4))
    }

    /// Insert/overwrite per-interface DHCP meta. Returns false if the table is full.
    pub fn dhcp_meta_insert(&self, ifindex: u32, val: DhcpMeta) -> bool {
        self.dhcp_meta.insert(&DhcpMetaK::new(ifindex), val)
    }
    /// Remove per-interface DHCP meta. Returns true if present.
    pub fn dhcp_meta_remove(&self, ifindex: u32) -> bool {
        self.dhcp_meta.remove(&DhcpMetaK::new(ifindex))
    }

    // ── READER side (getters the composed Maps impl, Task 5, calls) ──────────────
    // Signatures MATCH `flowplane_core::maps::Maps` exactly so Task 5 can forward 1:1. Lock-free
    // (`&self`) — safe concurrent with the single writer.

    /// Exact-match (`/32`) IPv4 route lookup (matches `Maps::route4_get`).
    #[must_use]
    pub fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
        self.route4.get(&Route4Key::new(vni, *dst))
    }
    /// Exact-match (`/128`) IPv6 route lookup (matches `Maps::route6_get`).
    #[must_use]
    pub fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
        self.route6.get(&Route6Key::new(vni, *dst))
    }
    /// NAT-GW config lookup (matches `Maps::nat_get`). Also used by the writer's conflict check.
    #[must_use]
    pub fn nat_get(&self, key: &NatKey) -> Option<NatValue> {
        self.nat.get(&NatK::new(key.vni, key.ipv4))
    }
    /// Is `(vni,ip)` a registered public NAT IP (matches `Maps::is_nat_ip`)?
    #[must_use]
    pub fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool {
        self.nat_ips.get(&NatIpK::new(vni, *ip)).is_some()
    }
    /// LB service lookup (matches `Maps::lb_get`).
    #[must_use]
    pub fn lb_get(&self, key: &LbKey) -> Option<LbValue> {
        self.lb
            .get(&LbK::new(key.vni, key.ipv4, key.port, key.proto))
    }
    /// Maglev slot → backend lookup (matches `Maps::maglev_get`).
    #[must_use]
    pub fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]> {
        self.maglev.get(&MaglevK::new(key.table_id, key.slot))
    }
    /// Underlay delivery lookup (matches `Maps::underlay_get`). Also used by the writer conflict
    /// check.
    #[must_use]
    pub fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue> {
        self.underlay.get(&UnderlayK::new(*addr))
    }
    /// Firewall rule slot lookup (matches `Maps::fw_rule`).
    #[must_use]
    pub fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule> {
        self.fw_rules.get(&FwRuleK::new(key.ifindex, key.idx))
    }
    /// Per-interface firewall meta lookup (matches `Maps::fw_meta`).
    #[must_use]
    pub fn fw_meta(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta.get(&FwMetaK::new(ifindex))
    }
    /// IPv6 firewall rule slot lookup (matches `Maps::fw_rule6`).
    #[must_use]
    pub fn fw_rule6(&self, key: &FwRuleKey) -> Option<FwRule6> {
        self.fw_rules6.get(&FwRule6K::new(key.ifindex, key.idx))
    }
    /// Per-interface IPv6 firewall meta lookup (matches `Maps::fw_meta6`).
    #[must_use]
    pub fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        self.fw_meta6.get(&FwMeta6K::new(ifindex))
    }
    /// Interfaces entry lookup. Also used by the writer's VNI-purge / detach reconciliation.
    #[must_use]
    pub fn ifaces_get(&self, key: &IfaceKey) -> Option<IfaceValue> {
        self.ifaces.get(&IfaceK::new(key.vni, key.ipv4))
    }
    /// Per-port metadata lookup keyed by tap ifindex.
    #[must_use]
    pub fn ports_get(&self, ifindex: u32) -> Option<PortMeta> {
        self.ports.get(&PortK::new(ifindex))
    }
    /// Neighbor-NAT slot lookup.
    #[must_use]
    pub fn neigh_nat_get(&self, idx: u32) -> Option<NeighborNatEntry> {
        self.neigh_nat.get(&NeighNatK::new(idx))
    }
    /// VIP 1:1 mapping lookup (matches the writer's `vips_get`).
    #[must_use]
    pub fn vips_get(&self, key: &VipKey) -> Option<[u8; 4]> {
        self.vips.get(&VipK::new(key.vni, key.ipv4))
    }
    /// Per-interface DHCP meta lookup (matches `Maps::dhcp_meta`).
    #[must_use]
    pub fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta> {
        self.dhcp_meta.get(&DhcpMetaK::new(ifindex))
    }
    /// Lock-free read of a per-interface meter rate config (None = no QoS configured).
    #[must_use]
    pub fn meter_config_get(&self, ifindex: u32) -> Option<flowplane_common::MeterConfig> {
        self.meter_config.get(&MeterCfgK::new(ifindex))
    }
}

impl Drop for SharedConfigMaps {
    fn drop(&mut self) {
        // Order matters: every RcuHash references `self.qsbr` (its RCU DQ drains through it on
        // `rte_hash_free`). Drop all tables FIRST, THEN free the QSBR.
        //
        // The fields are `ManuallyDrop<RcuHash<…>>`, so the Rust compiler does NOT auto-drop them
        // after this `drop` body returns — this impl is the SOLE teardown. We call
        // `ManuallyDrop::drop` on each field here (= `RcuHash::drop` exactly once per table,
        // freeing its rte_hash and flushing its defer queue), then dealloc the QSBR. Without
        // ManuallyDrop, plain fields would also be auto-dropped by the compiler after `drop`
        // returns → double `rte_hash_free` + `rte_hash_free`'s defer-queue flush against an
        // already-deallocated QSBR (use-after-free).
        //
        // SAFETY: each `ManuallyDrop::drop` is called exactly once (this is the sole Drop impl);
        // no field is read or dropped again after this block. After all tables are dropped, no
        // table references `self.qsbr`, so the dealloc below is sound.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut self.route4);
            std::mem::ManuallyDrop::drop(&mut self.route6);
            std::mem::ManuallyDrop::drop(&mut self.nat);
            std::mem::ManuallyDrop::drop(&mut self.nat_ips);
            std::mem::ManuallyDrop::drop(&mut self.lb);
            std::mem::ManuallyDrop::drop(&mut self.maglev);
            std::mem::ManuallyDrop::drop(&mut self.underlay);
            std::mem::ManuallyDrop::drop(&mut self.fw_rules);
            std::mem::ManuallyDrop::drop(&mut self.fw_meta);
            std::mem::ManuallyDrop::drop(&mut self.fw_rules6);
            std::mem::ManuallyDrop::drop(&mut self.fw_meta6);
            std::mem::ManuallyDrop::drop(&mut self.ifaces);
            std::mem::ManuallyDrop::drop(&mut self.iface_meta);
            std::mem::ManuallyDrop::drop(&mut self.ports);
            std::mem::ManuallyDrop::drop(&mut self.neigh_nat);
            std::mem::ManuallyDrop::drop(&mut self.vips);
            std::mem::ManuallyDrop::drop(&mut self.dhcp_meta);
            std::mem::ManuallyDrop::drop(&mut self.meter_config);
        }
        // SAFETY: all tables dropped above → qsbr unreferenced; same layout as the alloc in `new`.
        unsafe { std::alloc::dealloc(self.qsbr.cast::<u8>(), self.qsbr_layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
    fn shared_config_new_generation_and_route_roundtrip() {
        let _eal = crate::eal::Eal::init(
            [
                "nfkit_sc",
                "-l",
                "0-1",
                "--no-huge",
                "-m",
                "512",
                "--no-pci",
                "--file-prefix",
                "nfkit_sc",
            ]
            .iter()
            .copied(),
        )
        .unwrap();

        let sc = SharedConfigMaps::new(0, 1024).expect("shared config");
        assert_eq!(sc.generation(), 0);
        sc.bump_generation();
        assert_eq!(sc.generation(), 1);

        let tok = sc.register_reader();

        // A route write is visible via the datapath getter.
        let rv = RouteValue {
            nexthop_vni: 7,
            nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
            is_external: 0,
            _pad: [0; 3],
        };
        assert!(sc.route4_insert(7, [10, 0, 0, 1], rv));
        assert_eq!(sc.route4_get(7, &[10, 0, 0, 1]), Some(rv));
        sc.report_quiescent(&tok);

        // ALL-ZERO-CAPABLE key: a default route in VNI 0 (vni=0, 0.0.0.0). The tag byte makes the
        // wrapped key non-zero, so this must NOT double-free.
        assert!(sc.route4_insert(0, [0, 0, 0, 0], rv));
        assert_eq!(sc.route4_get(0, &[0, 0, 0, 0]), Some(rv));
        assert!(sc.route4_remove(0, [0, 0, 0, 0]));
        sc.report_quiescent(&tok);
    }
}
