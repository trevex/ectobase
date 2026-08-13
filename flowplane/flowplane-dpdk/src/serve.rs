//! `flowplane-dpdk serve` — the DPDK serve-process scaffold.
//!
//! The DPDK sibling of the eBPF `flowplane serve` command. It mirrors that process structure but
//! swaps the datapath (eBPF/aya → nfkit/DPDK) and drops all eBPF/device specifics:
//!
//!   1. Parse [`ServeArgs`] (clap).
//!   2. Map `--backend`/`--uplink`/`--queues` → [`nfkit::Backend`]; build the EAL argv via
//!      `Backend::eal_args_lcores("flowplane-dpdk", &lcore_list)` where the `-l` range is sized from
//!      `--lcores` (or derived as `queues + 1`) so constrained hosts (clab/CI) can run few lcores;
//!      `--queues` is clamped to the worker lcores available (+ `--no-huge` on request); `Eal::init`.
//!   3. Mempool + [`nfkit::Port::configure`] (RSS symmetric-Toeplitz lives in port.rs already).
//!   4. `Arc<SharedConfigMaps>` — the process-wide single-writer CONFIG tables.
//!   5. `Arc<parking_lot::Mutex<ControlCore<DpdkMapWriter>>>` — the SINGLE serialized writer (the
//!      Mutex enforces single-writer over the `&self` `SharedConfigMaps` writes). The gRPC service
//!      drives `ControlCore` through this handle.
//!   6. Datapath workers on a DEDICATED std::thread: `LcoreRuntime::for_each_worker` BLOCKS until
//!      every worker lcore joins, so it cannot share the main thread with the tokio server. Each
//!      worker registers as a `SharedConfigMaps` reader, owns a per-lcore `PerLcoreFlowMaps`,
//!      composes them into a `ComposedMaps`, and runs the rx → `process_uplink` → tx poll loop
//!      until the `stop` flag is set.
//!   7. Main thread: the tokio runtime hosts the tonic gRPC server. `tonic_health` is set Serving
//!      only AFTER the worker thread is up (readiness contract: listener open == datapath live).
//!      On SIGTERM/SIGINT the server drains, `stop` is set, and the worker thread is joined.
//!
//! ── SHARING MODEL ──────────────────────────────────────────────────────────────────────────────
//! One `Arc<SharedConfigMaps>` is cloned three ways: (a) into `DpdkMapWriter` inside the
//! `Mutex<ControlCore>` (the SOLE writer), (b) into the worker thread where every lcore derefs it to
//! `&*shared` for lock-free reads (sound because `SharedConfigMaps: Sync`), and later (c) into the
//! gRPC service via the same `Arc<Mutex<ControlCore>>`. Workers NEVER get a writer.
#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use ipnet::Ipv6Net;
use nfkit::{
    Backend, ComposedMaps, Eal, LcoreRing, LcoreRuntime, MbufBurst, MbufPkt, Mempool,
    PerLcoreFlowMaps, Port, SharedConfigMaps,
};

use flowplane_control::ControlCore;
use flowplane_core::datapath::{
    process_guest_tx, process_guest_tx_nat64, process_guest_tx_v6, process_uplink_rx, GuestTxIn,
    GuestTxNat64In, UplinkIn,
};
use flowplane_core::maps::Maps; // brings `underlay_get`/`local` method syntax into scope on ComposedMaps
use flowplane_core::pkt::{Action, Pkt}; // `Pkt` brings `read_array` into scope on MbufPkt
use nfkit::monotonic_ns;

use crate::attach_state::{DpdkAttachState, GuestPortSlot};
use crate::port_backend::{GuestPortBackend, TapBackend, VethBackend};

use crate::node::{pb, DpdkNodeService};
use crate::writer::DpdkMapWriter;

/// Byte offset of the outer IPv6 destination address within an encapped fabric frame:
/// `[OuterEth(14)][OuterIPv6 …dst@byte24…]`. The IPv6 dst occupies bytes 24..40 of the IPv6 header,
/// i.e. `ETH_LEN(14) + 24`. Matches the parity tests (`out[ETH_LEN + 24..ETH_LEN + 40]`).
const OUTER_V6_DST_OFF: usize = 14 + 24;

/// Config-table capacity (entries) for the process-wide `SharedConfigMaps`. Matches the sizing the
/// nfkit datapath tests use; the tables carry ~2× headroom internally (RCU reclaim slack).
const CONFIG_ENTRIES: u32 = 4096;

/// NUMA socket the maps + mempool are allocated on. Single-socket assumption for the scaffold; a
/// real multi-socket deployment would derive this per-port.
const SOCKET_ID: i32 = 0;

/// A preallocated guest af_xdp port during STARTUP BUILD only: the configured ethdev `Port` plus the
/// host veth ifindex its `PortMeta` is keyed by (`ports_get(host_ifindex)`). Built in `run` (pairing
/// each configured guest `Port` with its `GuestPortSlot.host_ifindex`), then decomposed into the
/// shared `GuestDatapath` (the `Port` moves into a `Mutex<Option<Port>>` cell; the ifindex seeds the
/// redirect resolver). Not held past that — the datapath owns the Ports thereafter (so recovery can
/// swap them). Kept as a small named pairing to make the ring/resolver build readable.
struct GuestPort {
    port: Port,
    host_ifindex: u32,
}

/// Round-robin ownership predicate: worker `q` owns the guest port at `port_index` iff
/// `port_index % n_workers == q`. This partitions the preallocated guest af_xdp pool across ALL
/// worker lcores (each guest port is polled by exactly one worker), so guest egress scales with the
/// lcore count instead of pinning every guest to worker 0. It is the sole source of truth for the
/// partition: used both by `worker_loop` to build its strided `guest_qs` and by the unit test below.
/// Generalizes the first-slice default (1 guest port + 1 worker → `owns(0, 0, 1) == true`, every
/// other worker owns none) rather than regressing it.
///
/// Cross-lcore model: per-lcore flow state stays shared-nothing (each worker has its own
/// `PerLcoreFlowMaps` conntrack). When a guest egresses, its SNAT reverse entry lands in its OWNING
/// lcore's per-lcore CT AND in the writer-owned `shared_ct`. The matching NAT return arrives on the
/// uplink and is RSS-steered to a possibly DIFFERENT worker; that worker misses in its per-lcore CT
/// and resolves the reverse-DNAT via `shared_ct` — the exact cross-lcore demux mechanism proven by
/// `nfkit/tests/multilcore_nat_return.rs`. So partitioning guests across lcores is safe precisely
/// because return demux never depends on which lcore owns the originating guest port.
fn owns(port_index: usize, q: u16, n_workers: u16) -> bool {
    port_index % n_workers as usize == q as usize
}

/// The cross-thread guest-port datapath state shared between the control plane (recovery) and the
/// datapath workers. It is the machinery of the GENERATION HANDSHAKE that makes dead-slot live
/// recovery sound without ever moving a `!Send` queue handle across threads:
///
///   • `ports[pi]` — the ethdev `Port` for guest port index `pi`, behind a `Mutex` so the CONTROL
///     thread can SWAP in a freshly `Port::configure`d one during recovery while a WORKER holds it
///     only briefly to (re)derive its `!Send` `(RxQueue, TxQueue)` handles ON ITS OWN LCORE. `Port`
///     is `{id,n_queues}` (auto `Send + Sync`); the `Mutex` is uncontended except during a rare
///     recover swap. NOTE: the queue HANDLES are built on-lcore from the `Port` and NEVER cross a
///     thread — only the `Port` (plain scalars) is shared.
///   • `generations[pi]` — bumped (Release) by the control thread AFTER it swaps `ports[pi]`. Each
///     owning worker caches the last-seen value and, on a mismatch (Acquire), rebuilds its cached
///     queue handles for `pi` against the swapped-in `Port` + the pool slot's new `host_ifindex`.
///   • `ifindex_to_index` — the redirect resolver (`Redirect(ifindex)` → guest port index → ring).
///     A slot's `host_ifindex` CHANGES on recovery (new veth), so this map is behind an `RwLock`:
///     the control path updates the entry (old→remove, new→insert) atomically with the generation
///     bump; workers take a cheap read lock per redirect (writes are rare recovery events).
///
/// `Send + Sync` (all fields are), so it crosses into the `Fn + Sync` `for_each_worker` closure and
/// is also cloned into `RecoverHandle` for the control-plane recovery path.
struct GuestDatapath {
    /// One `Mutex<Option<Port>>` per guest port index (uplink = port 0 is separate). `Some` while the
    /// port is live; SWAPPED (`*cell = Some(new)`) on recovery; `take()`n at shutdown to DROP the
    /// ethdev (stop+close) BEFORE the pool veths are deleted (preserving the ethdev-close-before-
    /// link-delete ordering even though the `Port` no longer lives in the worker-thread scope). A
    /// `None` cell means "no live port" — the worker skips it (only transiently possible at shutdown).
    ports: Vec<parking_lot::Mutex<Option<Port>>>,
    /// Per-port-index generation, bumped by the control recovery path; read by the owning worker.
    generations: Vec<AtomicU32>,
    /// Redirect-target ifindex → guest port index. Mutated on recovery (ifindex changes with the
    /// recreated veth); read per redirect by the workers. `RwLock` keeps recovery writes rare + the
    /// read path cheap/uncontended.
    ifindex_to_index: parking_lot::RwLock<std::collections::HashMap<u32, usize>>,
}

/// Control-plane handle for dead-slot LIVE RECOVERY, reachable from the attach path (node.rs). Holds
/// only what the recovery orchestration needs and NOTHING `!Send`: the shared `Mempool` (to
/// `Port::configure` the re-added ethdev) and the `GuestDatapath` (to swap the new `Port` + bump the
/// generation + update the redirect map). The pool slots + backend are passed IN by the caller
/// (`&DpdkAttachState`) rather than held here — that avoids an `Arc` cycle (`DpdkAttachState` stores
/// this handle) and keeps ownership one-directional.
///
/// ── WHO DOES `Port::configure` (the Step-5 crux) ────────────────────────────────────────────────
/// The CONTROL thread does it — NOT the worker-on-bump. This is sound (and the cleanest split)
/// precisely because both `Port` (`{id:u16,n_queues:u16}`, auto `Send + Sync`) and `Mempool`
/// (explicitly `Send + Sync` — an internally-synchronized `rte_mempool`) can safely cross to the
/// control thread. So the control path does the WHOLE `Send` sequence off-lcore — veth recreate +
/// hotplug (`VethBackend::recover`) → `port_by_name` → `Port::configure` → swap into `ports[pi]` →
/// update `ifindex_to_index` → bump `generations[pi]` — and the worker's ONLY job on the bump is to
/// rebuild its `!Send` `(RxQueue, TxQueue)` handles on its own lcore. No `!Send` value ever crosses
/// a thread; the worker never runs fallible FFI mid-poll.
#[derive(Clone)]
pub struct RecoverHandle {
    pool: Arc<Mempool>,
    datapath: Arc<GuestDatapath>,
}

impl RecoverHandle {
    /// Recover ONE dead guest-port slot (identified by its guest port INDEX `port_index` in the
    /// static poll set + its ethdev `pool_port_id`) end-to-end. Runs entirely on the CONTROL thread
    /// (the caller wraps it in `spawn_blocking` — it shells out to `ip` + calls blocking DPDK FFI);
    /// it must NEVER run on a datapath lcore.
    ///
    /// Steps: (1) `backend.recover` recreates the veth + hot-rebinds the af_xdp vdev + updates the
    /// pool slot's `host_ifindex`/clears `dead` (device mechanics); (2) re-resolve the re-added
    /// ethdev's ACTUAL port id via `port_by_name` (DPDK assigns the lowest free id — do NOT assume it
    /// equals `pool_port_id`); (3) `Port::configure` it; (4) update `ifindex_to_index` (old ifindex →
    /// new) + bump the slot's durable `generation`; (5) swap the new `Port` into `datapath.ports[..]`
    /// and bump `generations[..]` (Release) so the owning worker rebuilds its queue handles on-lcore.
    ///
    /// `attach` supplies the pool slots + the device backend (passed in to avoid an `Arc` cycle).
    /// Returns the NEW host ifindex on success.
    pub fn recover_slot(
        &self,
        attach: &DpdkAttachState,
        port_index: usize,
        pool_port_id: u16,
    ) -> anyhow::Result<u32> {
        // (0) CLOSE the dead slot's stale ethdev FIRST. Its backing veth is gone, but the `Port`
        // object still lives in the shared cell — and a LIVE ethdev cannot be hot-removed (the af_xdp
        // PMD refuses `rte_eal_hotplug_remove` on a started device, exactly as the nfkit hotplug
        // de-risk test drops the Port before removing). `take()` the cell → the `Port` drops → ethdev
        // stop+close, so `backend.recover`'s `hotplug_remove` below can succeed. Do this BEFORE the
        // device mechanics. (The bump published later re-derives the worker's handles from the new
        // Port; between here and the swap the worker sees a `None` cell and simply skips the port —
        // acceptable for a dead port that wasn't forwarding anyway.)
        let _ = self.datapath.ports[port_index].lock().take();

        // (1) Device mechanics + slot update under the pool lock (mutating the pooled slot in place so
        // the attach path sees the recovered slot). We hold the std pool Mutex only across the (Send)
        // device work; no await, no datapath-lcore work here.
        let (old_ifindex, new_ifindex) = {
            let mut pool = attach.guest_pool.lock().unwrap();
            let slot = pool
                .iter_mut()
                .find(|s| s.port_id == pool_port_id)
                .ok_or_else(|| {
                    anyhow::anyhow!("recover: no pool slot for port_id {pool_port_id}")
                })?;
            let old = slot.host_ifindex;
            let new = attach.backend.recover(slot, pool_port_id)?;
            // Bump the DURABLE per-slot generation (survives attach/detach; the cross-thread signal
            // is the parallel atomic bumped in step (5)).
            slot.generation = slot.generation.wrapping_add(1);
            (old, new)
        };

        // (2) Re-resolve the re-added ethdev's actual port id by device name (NOT assumed == pool_port_id).
        let vdev = format!("net_af_xdp{pool_port_id}");
        let ethdev_id = nfkit::port_by_name(&vdev)
            .map_err(|e| anyhow::anyhow!("recover: resolve re-added ethdev {vdev}: {e}"))?;
        // (3) Configure the re-added ethdev (single queue — the af_xdp vdev is queue_count=1).
        let new_port = Port::configure(ethdev_id, 1, &self.pool)
            .map_err(|e| anyhow::anyhow!("recover: Port::configure({ethdev_id}) failed: {e}"))?;

        // (4) Update the redirect resolver: the recovered slot's ifindex CHANGED, so remove the stale
        // mapping + insert the new one → the same port index. (5) Swap the Port into the shared cell
        // and bump the generation so the OWNING worker rebuilds its !Send queue handles on-lcore.
        {
            let mut map = self.datapath.ifindex_to_index.write();
            map.remove(&old_ifindex);
            map.insert(new_ifindex, port_index);
        }
        // Swap in the new Port (the cell was emptied in step 0, so this just installs the fresh one).
        *self.datapath.ports[port_index].lock() = Some(new_port);
        // Release ordering: pairs with the worker's Acquire load — the swapped Port + updated map are
        // published BEFORE the generation bump the worker observes.
        self.datapath.generations[port_index].fetch_add(1, Ordering::Release);
        Ok(new_ifindex)
    }

    /// TEST-ONLY constructor: build a `RecoverHandle` over a single guest-port `GuestDatapath` seeded
    /// with an already-configured `Port` at index 0 (host ifindex `host_ifindex`). Lets the privileged
    /// `attach_veth` recover test drive the full control-level recovery (`recover_slot`) — which needs
    /// the private `GuestDatapath` — without spinning up the whole serve loop. `#[doc(hidden)]`: not a
    /// public API, only a test seam.
    #[doc(hidden)]
    #[must_use]
    pub fn for_test_single_port(pool: Arc<Mempool>, port: Port, host_ifindex: u32) -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert(host_ifindex, 0usize);
        RecoverHandle {
            pool,
            datapath: Arc::new(GuestDatapath {
                ports: vec![parking_lot::Mutex::new(Some(port))],
                generations: vec![AtomicU32::new(0)],
                ifindex_to_index: parking_lot::RwLock::new(map),
            }),
        }
    }

    /// TEST-ONLY: the current generation for guest port index `pi` (proves recovery bumped it).
    #[doc(hidden)]
    #[must_use]
    pub fn generation_for_test(&self, pi: usize) -> u32 {
        self.datapath.generations[pi].load(Ordering::Acquire)
    }
}

/// Rebuild ONE worker `guest_qs` entry from the shared `GuestDatapath` after a generation bump —
/// the WORKER side of the recovery handshake, factored out so it is unit-testable without a live
/// datapath. Runs ON the worker's lcore: it locks `datapath.ports[pi]` only briefly to derive fresh
/// `!Send` `(RxQueue, TxQueue)` handles (which stay on THIS lcore, never cross a thread), re-reads
/// the slot's current `host_ifindex` from the pool, and updates the entry + the cached generation.
///
/// `entry` is `(port_index, host_ifindex, RxQueue, TxQueue)` — the same tuple `worker_loop` builds.
/// Returns the observed generation so the caller can update its `cached[..]`. If the shared cell is
/// `None` (a transient shutdown state — the Port was `take()`n), the entry is left untouched and the
/// current generation is still returned (so the worker doesn't re-attempt every iteration; it is
/// about to exit on `stop` anyway).
fn rebuild_guest_qs_entry(
    datapath: &GuestDatapath,
    attach: &DpdkAttachState,
    entry: &mut (usize, u32, nfkit::RxQueue, nfkit::TxQueue),
) -> u32 {
    let pi = entry.0;
    // Observe the generation with Acquire so the swapped Port + updated map (published Release in
    // `recover_slot`) are visible before we read them.
    let gen = datapath.generations[pi].load(Ordering::Acquire);
    // Re-read the slot's CURRENT host_ifindex (recovery gave it a new veth → new ifindex). Match by
    // port_id: guest port index `pi` maps to ethdev port_id `pi + 1` (uplink = 0, guests = 1..=N).
    let new_ifindex = {
        let pool = attach.guest_pool.lock().unwrap();
        pool.iter()
            .find(|s| s.port_id == (pi as u16 + 1))
            .map(|s| s.host_ifindex)
            .unwrap_or(entry.1)
    };
    // Lock the shared Port ONLY to derive the fresh queue handles on THIS lcore (the handles stay on
    // this lcore, never cross a thread). A `None` cell = shutdown teardown → leave the entry as-is.
    if let Some(port) = datapath.ports[pi].lock().as_ref() {
        let (r, t) = port.queue(0);
        entry.1 = new_ifindex;
        entry.2 = r;
        entry.3 = t;
    }
    gen
}

/// Default guest MTU = 1500 (underlay) − 40 (outer IPv6 header) − 8 (encap overhead for the
/// Geneve-style encap) = 1452, but we use 1450 to round down safely. Used both for the preallocated
/// guest veths (before EAL init) and the attach-state default.
const DEFAULT_GUEST_MTU: u32 = 1450;

/// Which nfkit port backend the datapath runs on. Mirrors [`nfkit::Backend`] minus its
/// backend-specific fields (those are derived from `--uplink`/`--queues`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BackendKind {
    /// AF_XDP on a kernel netdev (`--uplink` = iface, `--queues` = queue count).
    AfXdp,
    /// A real NIC by PCI address (`--uplink` = PCI address).
    Nic,
    /// pcap replay/record (`--uplink` = the pcap file, used for both rx and tx).
    Pcap,
    /// Kernel TAP (`--uplink` = tap name).
    Tap,
    /// Null sink/source (`--uplink` ignored).
    Null,
}

/// Which guest-port pool backend the serve process uses (one kind per process). Selects the
/// concrete [`GuestPortBackend`] built at startup; everything downstream (prealloc → af_xdp bind →
/// attach/detach/worker) is backend-agnostic, so a tap netdev name binds identically to a veth name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum GuestBackendKind {
    /// veth pairs (containers) — the guest-end moves into the pod netns.
    Veth,
    /// persistent taps (VMs) — af_xdp binds the tap netdev, qemu holds the fd.
    Tap,
}

/// `flowplane-dpdk serve` arguments. The datapath-relevant surface of the eBPF `flowplane serve`
/// command, minus eBPF/pinning/edge-role specifics (the DPDK datapath has no bpffs pins or XDP
/// attach; a DPDK port replaces the uplink netdev).
#[derive(Parser, Debug)]
#[command(name = "flowplane-dpdk")]
pub struct ServeArgs {
    /// Address the gRPC control server listens on.
    #[arg(long, default_value = "127.0.0.1:1337")]
    pub addr: String,
    /// Uplink identifier — interpreted per `--backend` (netdev for af-xdp/tap, PCI addr for nic,
    /// pcap file for pcap, ignored for null).
    #[arg(long)]
    pub uplink: String,
    /// Overlay IPv4 gateway the datapath answers ARP for (e.g. 169.254.0.1).
    #[arg(long)]
    pub gateway: String,
    /// Overlay IPv6 gateway the datapath answers ND for (e.g. fe80::1). Optional.
    #[arg(long = "gateway6")]
    pub gateway6: Option<String>,
    /// Underlay next-hop MAC — outer eth dst for ALL encapped traffic.
    #[arg(long = "gateway-mac")]
    pub gateway_mac: String,
    /// This node's underlay IPv6 (outer src on encap; the /64 the AttachInterface pool allocates
    /// from). Optional — resolved from the node IP when unset.
    #[arg(long = "local-underlay")]
    pub local_underlay: Option<String>,
    /// DPDK port backend.
    #[arg(long, value_enum, default_value_t = BackendKind::AfXdp)]
    pub backend: BackendKind,
    /// Guest-port pool backend: `veth` (containers) or `tap` (VMs). One kind per serve process.
    #[arg(long = "guest-backend", value_enum, default_value_t = GuestBackendKind::Veth)]
    pub guest_backend: GuestBackendKind,
    /// Total EAL lcores (main + workers), used to build the EAL `-l 0-{lcores-1}` range. Unset =
    /// derive `queues + 1` (one main lcore + one worker per queue), which fits constrained hosts
    /// (clab/CI). Set explicitly to pin a specific count (must be `>= queues + 1`, else `queues` is
    /// clamped to the available workers `lcores - 1`).
    #[arg(long)]
    pub lcores: Option<u16>,
    /// Number of rx/tx queues (= datapath worker lcores). Also the af-xdp `queue_count`.
    #[arg(long, default_value_t = 1)]
    pub queues: u16,
    /// Run EAL under `--no-huge` (software backends / no-hugepage hosts). Software backends already
    /// force it via `Backend::eal_args`; this makes it explicit for af-xdp/nic on such hosts.
    #[arg(long = "no-huge", default_value_t = false)]
    pub no_huge: bool,
    /// DHCPv4 DNS server, repeatable (server-wide).
    #[arg(long = "dhcp-dns")]
    pub dhcp_dns: Vec<String>,
    /// DHCPv6 DNS server, repeatable (server-wide).
    #[arg(long = "dhcpv6-dns")]
    pub dhcpv6_dns: Vec<String>,
    /// Guest MTU override. Unset = derive from the uplink MTU minus encap overhead.
    #[arg(long = "guest-mtu")]
    pub guest_mtu: Option<u32>,
    /// Number of PREALLOCATED per-guest af_xdp ports (VF-style). The serve process creates this many
    /// guest veth pairs BEFORE EAL init and passes each as an extra `--vdev=net_af_xdp<i>`, giving a
    /// STATIC poll set that AttachInterface later binds to guests. Only
    /// meaningful for the af-xdp backend (ignored/skipped otherwise).
    #[arg(long = "guest-ports", default_value_t = 1)]
    pub guest_ports: u16,
}

impl ServeArgs {
    /// Total EAL lcore count: the explicit `--lcores`, else `queues + 1` (one main + one worker per
    /// queue). Floored at 2 so there is always at least a main lcore plus one datapath worker.
    fn lcore_count(&self) -> u16 {
        self.lcores.unwrap_or(self.queues + 1).max(2)
    }

    /// The DPDK `-l` lcore list: a contiguous `0-{lcore_count-1}` range (lcore 0 = main lcore).
    fn eal_lcore_list(&self) -> String {
        format!("0-{}", self.lcore_count() - 1)
    }

    /// Datapath worker lcores available = every lcore except the main one.
    fn worker_lcores(&self) -> u16 {
        self.lcore_count() - 1
    }

    /// First-slice preallocated-pool cap: `--guest-ports` must be `<= 256`. Beyond that the
    /// placeholder MAC's last octet (`i as u8`) and the `1 + i` port_id would alias/overflow (see
    /// the guard in `run`). Pure predicate so the cap can be unit-tested without EAL.
    fn guest_pool_cap_ok(&self) -> bool {
        self.guest_ports <= 256
    }

    /// Map the parsed backend kind + uplink into an [`nfkit::Backend`]. `queues` is the effective
    /// (possibly clamped-to-worker-lcores) queue count — it drives the af-xdp `queue_count`.
    fn to_backend(&self, queues: u16) -> Backend {
        match self.backend {
            BackendKind::AfXdp => Backend::AfXdp {
                iface: self.uplink.clone(),
                queues,
            },
            BackendKind::Nic => Backend::Nic {
                pci: self.uplink.clone(),
            },
            // pcap uses the one path for both rx and tx (record/replay against a single file).
            BackendKind::Pcap => Backend::Pcap {
                rx: self.uplink.clone(),
                tx: self.uplink.clone(),
            },
            BackendKind::Tap => Backend::Tap {
                name: self.uplink.clone(),
            },
            BackendKind::Null => Backend::Null,
        }
    }
}

/// RAII rollback guard for the PREALLOCATED pool host devices during serve STARTUP. It exists to
/// close a startup-only leak window: `run` creates the guest veths (`fpg{i}`) via
/// `port_backend.preallocate` BEFORE any of the later fallible startup calls (EAL/mempool/`Port::
/// configure`/`LcoreRing::new`/`SharedConfigMaps::new`/`ControlCore`/`DpdkAttachState`/the worker
/// `.spawn`). Any `?`-return from one of those would otherwise leave the already-created veths on the
/// host — nothing has taken ownership of teardown yet (the worker thread owns shutdown teardown, and
/// it isn't running).
///
/// The guard is ARMED as devices are created (`track` after each `preallocate`) and covers EVERY `?`
/// through the worker spawn: on Drop-while-armed it tears down every tracked host device via the
/// backend. Once `.spawn(...)` succeeds — the closure has moved the guest `Port`s/rings in and will
/// tear the pool down on shutdown — the guard is `disarm()`ed so the HAPPY path does NOT touch the
/// devices (no double-teardown; behavior identical to before this guard).
///
/// It holds an `Arc<dyn GuestPortBackend>` (a clone of the serve loop's `port_backend`), NOT a `&`,
/// so tracking is independent of where the `slots`/`Arc` later move (into `guest_pool`/the thread) —
/// moving those does not disturb the guard. It tracks host_ifnames (cheap `String` clones) only.
struct StartupGuard {
    backend: Arc<dyn GuestPortBackend>,
    host_ifnames: Vec<String>,
    armed: bool,
}

impl StartupGuard {
    fn new(backend: Arc<dyn GuestPortBackend>) -> Self {
        Self {
            backend,
            host_ifnames: Vec::new(),
            armed: true,
        }
    }
    /// Record a just-created pool host device so a mid-startup failure tears it down.
    fn track(&mut self, host_ifname: String) {
        self.host_ifnames.push(host_ifname);
    }
    /// Ownership of pool teardown has passed to the worker thread — stop tearing down on Drop.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        if self.armed {
            // Tear down in creation order (idempotent/best-effort per the backend contract).
            for h in &self.host_ifnames {
                self.backend.teardown(h);
            }
        }
    }
}

/// Format a 6-byte MAC as `aa:bb:cc:dd:ee:ff` for startup log lines.
fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Run the DPDK serve process (see the module doc for the full structure). This is `async` and
/// hosts the tonic server on the calling (tokio) thread; the datapath runs on a dedicated OS thread.
pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    // Parse the listen address UP-FRONT, before any pool device is created or any worker is spawned,
    // so a bad `--addr` fails here and CANNOT leak a spawned worker thread or a preallocated pool
    // device (the teardown for those runs only AFTER the workers join, past the disarmed
    // StartupGuard). `addr` stays in scope for `serve_with_shutdown(addr, ...)` below.
    let addr: std::net::SocketAddr = args.addr.parse().context("parse --addr")?;

    // ── 2. EAL ────────────────────────────────────────────────────────────────
    // Clamp the queue request to the datapath worker lcores available (lcores - 1): each worker
    // runs on its own non-main lcore, so more queues than workers would leave queues unpolled (and
    // trip `for_each_worker`'s assert). Under-provisioning lcores is a config choice, not an error.
    let queues = args.queues.min(args.worker_lcores());
    if queues < args.queues {
        eprintln!(
            "warning: --queues {} exceeds worker lcores {} (from --lcores {}); clamping to {queues}",
            args.queues,
            args.worker_lcores(),
            args.lcore_count(),
        );
    }
    let backend = args.to_backend(queues);

    // The guest link MTU (underlay MTU - encap overhead). Computed up front (no EAL dependency): the
    // §2a preallocation veths need it, the attach state below reuses it, AND the backend captures it
    // so `recover` can recreate a dead slot's veth at the identical MTU. Kept BEFORE the backend
    // construction so it can be threaded into `VethBackend { mtu }`.
    let guest_mtu = args.guest_mtu.unwrap_or(DEFAULT_GUEST_MTU);

    // The backend-agnostic guest-port pool lifecycle. Constructed ONCE and shared: it drives the
    // §2a preallocation here and is stored (cloned) in `DpdkAttachState` so attach/detach route
    // their assign/release/is_alive/recover device ops through the SAME instance. `--guest-backend`
    // selects the kind at startup (one per process): veth (containers) or tap (VMs). Carries
    // `guest_mtu` so dead-slot recovery recreates the port at the same link MTU as preallocation.
    //
    // Everything downstream is unchanged by the choice: `port_backend.preallocate(i, guest_mtu)`
    // returns `fpgtap{i}` names fed to `eal_args_lcores_with_guest_ifaces` → attach/detach/worker,
    // and a tap netdev name binds an af_xdp vdev identically to a veth name.
    let port_backend: Arc<dyn GuestPortBackend> = match args.guest_backend {
        GuestBackendKind::Veth => Arc::new(VethBackend { mtu: guest_mtu }),
        GuestBackendKind::Tap => Arc::new(TapBackend { mtu: guest_mtu }),
    };

    // ── 2a. PREALLOCATE the per-guest af_xdp port pool BEFORE EAL init ───────────
    // VF-style static poll set: create `--guest-ports` guest veth pairs NOW (in the root netns) so
    // each host end can be handed to EAL as an extra `--vdev=net_af_xdp<i>,iface=<host_ifname>`. The
    // multi_afxdp_port de-risk test (nfkit @cd1b7ed) proved two af_xdp vdevs coexist as ethdev ports
    // 0 and 1 in one EAL; here the uplink is port 0 and the guests are ports 1..=N.
    //
    // Only the af-xdp backend gets per-guest ports in this slice — the other backends have no netdev
    // to bind a per-guest af_xdp vdev to, so we build an EMPTY pool and note it. `guest_mtu` is the
    // guest link MTU (underlay MTU - encap overhead); we need it HERE for the veths, and it has no
    // EAL dependency, so compute it once up front and reuse it for the attach state below.
    //
    // The guest-end of each pair (`<host_ifname>p`, the create_veth_pair peer convention) stays a
    // root-netns PLACEHOLDER until AttachInterface moves it into the pod netns; the MAC set
    // here is a deterministic placeholder (the real guest MAC is programmed at attach). `bound` is
    // `None` for every slot (attach binds them). `guest_mtu` was computed above (before the backend).
    // RAII startup-rollback guard, ARMED here and kept in scope across EVERY `?` from prealloc through
    // the worker `.spawn` below. As each pool device is created we `track` it; any early return drops
    // the guard and tears down what was created so far. We `disarm()` only AFTER the worker thread
    // takes ownership (it tears the pool down on shutdown). Holds an `Arc` clone of the backend so it
    // is independent of the `slots`/backend-`Arc` moves that happen later in startup.
    let mut guard = StartupGuard::new(port_backend.clone());
    let slots: Vec<GuestPortSlot> = match args.backend {
        BackendKind::AfXdp => {
            // First-slice pool cap. The placeholder MAC's last octet is `i as u8` and the ethdev
            // `port_id` is `1 + i`, so a pool larger than 256 would (a) ALIAS the placeholder MAC
            // (slots 0 and 256 both get `…:00`, a silent duplicate) and (b) risk `1 + i` overflowing
            // near `u16::MAX`. The real multi-guest scaling (unique MAC scheme + wider port range)
            // is a later task; enforce the cap at runtime here so the aliasing can never happen
            // silently. Only reached for the af-xdp backend, i.e. when a pool is actually built.
            if !args.guest_pool_cap_ok() {
                anyhow::bail!(
                    "--guest-ports {} exceeds the first-slice pool cap of 256 (placeholder MAC \
                     octet + port_id would alias/overflow); larger pools are a later multi-guest task",
                    args.guest_ports
                );
            }
            let mut slots = Vec::with_capacity(args.guest_ports as usize);
            for i in 0..args.guest_ports {
                // Route preallocation through the backend (device mechanics: create `fpg{i}` with the
                // deterministic placeholder MAC — the backend owns the naming/MAC scheme). Not
                // datapath-significant yet; the real guest MAC is programmed at attach.
                //
                // On failure the `?`-return drops `guard`, tearing down every device tracked so far —
                // the RAII guard now covers prealloc failures too (no hand-rolled per-slot rollback).
                let dev = port_backend.preallocate(i, guest_mtu).with_context(|| {
                    format!("create preallocated guest device fpg{i} (slot {i})")
                })?;
                // Track BEFORE building the slot: the device is on the host now, so it must be torn
                // down on any later early return.
                guard.track(dev.host_ifname.clone());
                slots.push(GuestPortSlot {
                    host_ifname: dev.host_ifname,
                    host_ifindex: dev.host_ifindex,
                    // ethdev port id: uplink = 0, guests = 1..=N (matches the vdev append order).
                    port_id: 1 + i,
                    bound: None,
                    // Freshly-created pool devices are live; dead-slot detection happens lazily at attach.
                    dead: false,
                    // No recovery has run yet — generation starts at 0 (matches the parallel
                    // `generations` atomic seeded to 0 below; a bump means "worker, rebuild me").
                    generation: 0,
                });
            }
            println!(
                "preallocated {} guest af_xdp port(s): {:?}",
                slots.len(),
                slots.iter().map(|s| &s.host_ifname).collect::<Vec<_>>()
            );
            slots
        }
        other => {
            println!(
                "backend {other:?}: per-guest af_xdp ports are af-xdp-only in this slice; \
                 skipping the preallocated pool (--guest-ports ignored)"
            );
            Vec::new()
        }
    };

    // Build the EAL argv WITH the per-guest af_xdp vdevs (identical to `eal_args_lcores` for an empty
    // guest-iface list, so non-af-xdp backends are unaffected).
    let guest_ifaces: Vec<String> = slots.iter().map(|s| s.host_ifname.clone()).collect();
    let mut eal_argv = backend.eal_args_lcores_with_guest_ifaces(
        "flowplane-dpdk",
        &args.eal_lcore_list(),
        &guest_ifaces,
    );
    // `--no-huge` is idempotent — software backends already appended it; adding it again for
    // af-xdp/nic when requested is harmless (DPDK dedups repeated EAL flags).
    if args.no_huge && !eal_argv.iter().any(|a| a == "--no-huge") {
        eal_argv.push("--no-huge".into());
        eal_argv.push("-m".into());
        eal_argv.push("512".into());
    }
    let _eal = Eal::init(&eal_argv).map_err(|e| anyhow::anyhow!("EAL init failed: {e}"))?;
    println!("EAL initialized ({eal_argv:?})");

    // ── 3. Mempool + Port ──────────────────────────────────────────────────────
    // One shared MT-safe pktmbuf pool (rte_pktmbuf_alloc is MT-safe; workers alloc concurrently).
    // `Arc` because dead-slot recovery on the CONTROL thread needs it to `Port::configure` the
    // re-added ethdev (see `RecoverHandle`): `Mempool` is `Send + Sync` (internally-synchronized
    // rte_mempool), so sharing it across the control + worker threads is sound.
    let pool = Arc::new(
        Mempool::new("fp_dpdk_pool", 8191, 250, SOCKET_ID)
            .map_err(|e| anyhow::anyhow!("mempool create failed: {e}"))?,
    );
    let port = Port::configure(0, queues, &pool)
        .map_err(|e| anyhow::anyhow!("port configure failed: {e}"))?;
    let n_workers = port.n_queues();
    println!("port 0 up with {n_workers} queue(s)");

    // Configure each PREALLOCATED guest port (ethdev ids 1..=N). Single queue per guest port (the
    // af_xdp vdev was probed with queue_count=1). Each configured `Port` is paired with its host
    // veth ifindex (the key `ports_get` uses to resolve the guest's `PortMeta` in `worker_loop`).
    // These `GuestPort`s MUST outlive the datapath — a `Port` Drop stops+closes the ethdev — so they
    // are moved into the worker thread below, where the worker polls their rx queue → `process_guest_tx`.
    let mut guest_ports: Vec<GuestPort> = Vec::with_capacity(slots.len());
    for slot in &slots {
        // A guest ethdev-configure failure leaves the already-created host veths on the host; the
        // `?`-return drops `guest_ports` FIRST (declared after `guard` → drops before it in reverse
        // order — its inner `Port` Drop = ethdev close, which must precede deleting the links) and
        // THEN drops `guard`, which tears the tracked veths down. Ordering (ethdev close → link
        // delete) is thus preserved by the drop order, matching the old hand-rolled rollback.
        let gp = Port::configure(slot.port_id, 1, &pool).map_err(|e| {
            anyhow::anyhow!(
                "guest port {} ({}) configure failed: {e}",
                slot.port_id,
                slot.host_ifname
            )
        })?;
        println!(
            "guest port {} ({}) up with {} queue(s)",
            slot.port_id,
            slot.host_ifname,
            gp.n_queues()
        );
        guest_ports.push(GuestPort {
            port: gp,
            host_ifindex: slot.host_ifindex,
        });
    }

    // ── 3b. Guest↔guest local-delivery handoff: one LcoreRing per guest port ─────
    // A same-node guest→guest flow's `process_guest_tx` returns `Redirect(dest_tap_ifindex)` (inner
    // Eth already rewritten). The dest guest port may be OWNED BY A DIFFERENT WORKER (guest ports are
    // partitioned round-robin across lcores, see `owns`), and a `TxQueue` is `!Send` — it is built on
    // and serviced by exactly one lcore, so the source worker CANNOT tx out a port it doesn't own.
    //
    // Bridge that with a UNIFORM per-port MP/SC ring (nfkit `LcoreRing`): `rings[i]` is the inbox for
    // `guest_ports[i]`. Any worker that decides a redirect to port `i` ENQUEUES the mbuf into
    // `rings[i]` (multi-producer, `&self`); the ONE worker that owns port `i` DEQUEUES + tx's it out
    // that port. This is uniform — even a same-worker dest goes through the ring (the round-trip is
    // negligible and it avoids a `guest_qs` mutable-borrow-while-iterating problem). `LcoreRing` is
    // `Send + Sync`, so `Arc<Vec<LcoreRing>>` crosses into the `Fn + Sync` `for_each_worker` closure.
    //
    // `ifindex_to_index` maps a redirect target ifindex → the parallel `rings`/`guest_ports` index, so
    // any worker can resolve `Redirect(dest_tap_ifindex)` → the dest port's ring. A target that isn't
    // a local guest port (not in the map) is dropped. Built once at startup; read-only thereafter.
    let mut rings: Vec<LcoreRing> = Vec::with_capacity(guest_ports.len());
    let mut ifindex_to_index: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::with_capacity(guest_ports.len());
    for (i, gp) in guest_ports.iter().enumerate() {
        // Unique EAL name per ring (like ports/hashes/mempools); power-of-two size (rte_ring req).
        let ring = LcoreRing::new(&format!("fpgring{}", slots[i].port_id), 1024, SOCKET_ID)
            .map_err(|e| anyhow::anyhow!("guest ring {} create failed: {e}", slots[i].port_id))?;
        rings.push(ring);
        ifindex_to_index.insert(gp.host_ifindex, i);
    }
    let rings = Arc::new(rings);

    // ── 3c. GuestDatapath: the shared Port cells + generation handshake (dead-slot recovery) ──────────────
    // Move each configured guest `Port` into a per-index `Mutex<Option<Port>>` cell so the CONTROL
    // thread can SWAP a recovered Port in (dead-slot recovery) while a worker holds the cell only
    // briefly to (re)derive its `!Send` queue handles on-lcore. `generations[pi]` starts at 0 (matches
    // each slot's durable `generation`); the redirect resolver goes behind an `RwLock` because a
    // recovered slot's ifindex CHANGES (new veth) and recovery updates the map in lock-step with the
    // generation bump. This is the ONE sanctioned mutation to the otherwise-static poll set.
    let datapath = Arc::new(GuestDatapath {
        ports: guest_ports
            .into_iter()
            .map(|gp| parking_lot::Mutex::new(Some(gp.port)))
            .collect(),
        generations: (0..rings.len()).map(|_| AtomicU32::new(0)).collect(),
        ifindex_to_index: parking_lot::RwLock::new(ifindex_to_index),
    });

    // ── 4. Shared config maps (process-wide, single-writer) ─────────────────────
    let shared = Arc::new(
        SharedConfigMaps::new(SOCKET_ID, CONFIG_ENTRIES)
            .map_err(|e| anyhow::anyhow!("SharedConfigMaps::new failed: {e}"))?,
    );

    // Resolve BOTH the node's underlay HOST address (the /128 — this node's fabric-src, written into
    // LOCAL as `underlay_ipv6`, the outer IPv6 SRC on encapped frames) and the /64 network prefix
    // (seeds `UnderlayIpam` in §5b). `--local-underlay` is a host address; the prefix is its /64. When
    // unset, both are inferred from the host interfaces (address, then its /64) so they stay consistent.
    let underlay_addr: std::net::Ipv6Addr = match &args.local_underlay {
        Some(s) => s
            .parse()
            .with_context(|| format!("parse --local-underlay {s:?} as IPv6"))?,
        None => flowplane_device::infer_underlay_address(&flowplane_device::read_host_ifaddrs()?)
            .ok_or_else(|| {
            anyhow::anyhow!(
                "could not infer underlay address from host interfaces; set --local-underlay"
            )
        })?,
    };
    let underlay_prefix: Ipv6Net = Ipv6Net::new(underlay_addr, 64)
        .map_err(|e| anyhow::anyhow!("build /64 from underlay address {underlay_addr}: {e}"))?
        .trunc();

    // ── 4a. Program LOCAL (uplink identity) ─────────────────────────────────────
    // The eBPF sibling writes this at bring-up (`flowplane/src/control/mod.rs`): without it the
    // `worker_loop` has no uplink identity (outer MACs + uplink ifindex) and DROPS EVERY uplink and
    // guest-egress burst by design. Program it ONCE, here, after `shared` exists and the uplink `Port`
    // is configured — the fix for the "datapath is inert" bug.
    //
    // Fields:
    //   • gateway_mac  — `--gateway-mac`, the underlay next-hop (outer eth DST for all encap).
    //   • underlay_ipv6 — this node's underlay HOST address (the /128), outer IPv6 SRC on encap.
    //   • uplink_ifindex/uplink_mac — the `--uplink` netdev's real ifindex + MAC. For af-xdp/tap the
    //     uplink IS a kernel netdev (`args.uplink`), so resolve from sysfs; the encap arm returns
    //     `Redirect(uplink_ifindex)` and `worker_loop` routes it to the uplink tx only when it matches
    //     LOCAL.uplink_ifindex, so a consistent non-zero value is what matters (real ifindex keeps the
    //     outer frame fabric-correct + matches eBPF). For nic/pcap/null there is no host netdev →
    //     best-effort sentinel (ifindex = uplink ethdev port 0's id + 1 = 1, non-zero; mac = zeros).
    let gateway_mac = flowplane_node::parse_mac(&args.gateway_mac)
        .with_context(|| format!("parse --gateway-mac {:?}", args.gateway_mac))?;
    let (uplink_ifindex, uplink_mac) = match args.backend {
        BackendKind::AfXdp | BackendKind::Tap => {
            let ifindex = flowplane_device::ifindex_of(&args.uplink)
                .with_context(|| format!("resolve --uplink {:?} ifindex for LOCAL", args.uplink))?;
            let mac = flowplane_device::mac_of(&args.uplink)
                .with_context(|| format!("resolve --uplink {:?} MAC for LOCAL", args.uplink))?;
            (ifindex, mac)
        }
        other => {
            // No host netdev to read (nic = PCI addr, pcap = file, null = nothing). LOCAL is
            // best-effort: a non-zero sentinel ifindex keeps the encap-redirect path self-consistent,
            // and the outer eth SRC is zeros. Guest egress is af-xdp-focused, so do NOT fail startup.
            eprintln!(
                "warning: backend {other:?} has no host uplink netdev; LOCAL uplink identity is \
                 best-effort (ifindex=1 sentinel, uplink_mac=00:00:..)"
            );
            (1u32, [0u8; 6])
        }
    };
    shared.set_local(flowplane_common::Local {
        uplink_ifindex,
        uplink_mac,
        gateway_mac,
        underlay_ipv6: underlay_addr.octets(),
    });
    println!(
        "LOCAL programmed: uplink_ifindex={uplink_ifindex}, uplink_mac={}, gateway_mac={}, \
         underlay_ipv6={underlay_addr}",
        fmt_mac(&uplink_mac),
        fmt_mac(&gateway_mac),
    );

    // ── 5. The SINGLE writer: ControlCore<DpdkMapWriter> behind a Mutex ─────────
    // The Mutex enforces single-writer over the `&self` SharedConfigMaps writes (soundness of the
    // LF+RCU tables rests on exactly one writer). The DataplaneNode service takes handlers that
    // lock this and drive ControlCore. Cloned here so the handle survives into the gRPC service.
    let ctrl = Arc::new(parking_lot::Mutex::new(ControlCore::new(
        DpdkMapWriter::new(shared.clone()),
    )));

    // ── 5b. Host-device attach state: underlay IPAM + device registry ─────────────────
    // `underlay_prefix` (the /64 that seeds `UnderlayIpam`) was resolved with `underlay_addr` up front
    // (§4a needs the host address for LOCAL). The guest_mtu defaults to a sane 1450 (underlay MTU 1500
    // - 40-byte outer IPv6 - 8-byte encap header) when not set.
    let gateway_ipv4: [u8; 4] = args
        .gateway
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("parse --gateway {:?}", args.gateway))?
        .octets();
    let gateway_ipv6: [u8; 16] = args
        .gateway6
        .as_deref()
        .map(|s| {
            s.parse::<std::net::Ipv6Addr>()
                .with_context(|| format!("parse --gateway6 {s:?}"))
                .map(|a| a.octets())
        })
        .transpose()?
        .unwrap_or([0u8; 16]);
    // `guest_mtu` was computed up front (before EAL init) for the preallocated guest veths; reuse it.
    // The preallocated `slots` move into `guest_pool` (behind a Mutex) so AttachInterface can
    // bind/release them; the guest `Port`s themselves are held live by the worker thread (below).
    let guest_pool_len = slots.len();
    let attach_state = Arc::new(DpdkAttachState {
        ipam: std::sync::Mutex::new(flowplane_device::UnderlayIpam::new(underlay_prefix)),
        registry: std::sync::Mutex::new(std::collections::HashMap::new()),
        guest_mtu,
        gateway_ipv4,
        gateway_ipv6,
        guest_pool: std::sync::Mutex::new(slots),
        // Share the SAME backend instance §2a preallocated with — attach/detach route their
        // assign/release/is_alive/recover device ops through it (call sites in node.rs).
        backend: port_backend.clone(),
        // Set just below, once the datapath + Mempool Arcs exist (they build the RecoverHandle).
        recover: std::sync::OnceLock::new(),
    });

    // Wire the dead-slot LIVE RECOVERY handle into the attach state. The handle carries
    // the shared `Mempool` + the `GuestDatapath` generation-handshake state; the attach path
    // (`node.rs`) reads it to recover a dead slot when no free live slot remains. Set ONCE, before the
    // gRPC server (hence any attach) can run. Ignore the (impossible) re-set error.
    let _ = attach_state.recover.set(RecoverHandle {
        pool: pool.clone(),
        datapath: datapath.clone(),
    });
    println!(
        "B2a attach state: underlay prefix={underlay_prefix}, gateway={}, guest_mtu={guest_mtu}, \
         guest_pool={guest_pool_len} slot(s)",
        args.gateway
    );

    // ── 6. Datapath workers on a dedicated OS thread ────────────────────────────
    // `for_each_worker` BLOCKS until every worker lcore joins, so it must run OFF the tokio thread.
    // The workers read `shared` lock-free (deref the captured Arc to `&*shared`, sound because
    // `SharedConfigMaps: Sync`) and own their per-lcore flow state. `stop` breaks every poll loop
    // on shutdown; the main thread joins this handle after the server drains.
    let stop = Arc::new(AtomicBool::new(false));
    let shared_for_workers = shared.clone();
    let stop_w = stop.clone();
    // The guest↔guest handoff rings, cloned into the worker thread (`Send + Sync`).
    let rings_w = rings.clone();
    // The GuestDatapath (shared Port cells + generation handshake + redirect resolver) and the attach
    // state (the pool slots — the worker re-reads a recovered slot's ifindex from here on a generation
    // bump). Both `Arc`-wrapped `Send + Sync`, so they cross into the `Fn + Sync` closure below.
    let datapath_w = datapath.clone();
    let attach_w = attach_state.clone();
    // Move the uplink Port + Mempool into the worker thread: the rx/tx queue handles are `!Send` and
    // must be built ON each lcore, and the Port/pool must outlive every worker. `_eal` stays on the
    // main thread (the EAL guard is `!Send` and cleans up on process exit).
    let pool_w = pool.clone();
    let workers = std::thread::Builder::new()
        .name("fp-dpdk-datapath".into())
        .spawn(move || {
            // The guest `Port`s now live in `datapath.ports` (shared `Mutex<Option<Port>>` cells so
            // recovery can swap them). The worker borrows the `Arc<GuestDatapath>`; a worker derives
            // its `!Send` queue handles on-lcore from the cells it owns and rebuilds them on a
            // generation bump. Ethdev close now happens at shutdown via `datapath.ports[..].take()`
            // (see the shutdown block) or on the recovery swap, NOT when this closure returns.
            let rings_w = rings_w;
            let datapath_w = datapath_w;
            let attach_w = attach_w;
            let pool_w = pool_w; // keep the pool alive for the worker thread's lifetime
            let _ = &pool_w;
            LcoreRuntime::for_each_worker(n_workers, |q| {
                // Partition the preallocated guest ports round-robin across ALL worker lcores: worker
                // `q` polls guest port index `i` where `owns(i, q, n_workers)`. `worker_loop` rebuilds
                // its strided `guest_qs` via the `owns` filter over `datapath.ports`. A worker that
                // owns zero guest ports just runs an empty guest block.
                worker_loop(
                    q,
                    n_workers,
                    &shared_for_workers,
                    &port,
                    &datapath_w,
                    &attach_w,
                    &rings_w,
                    &stop_w,
                );
            });
        })
        .context("spawn datapath worker thread")?;

    // The worker thread is up and OWNS the guest `Port`s/rings (it tears the pool down on shutdown,
    // see the `attach_state.guest_pool` delete after `workers.join()`). Disarm the startup guard so
    // the HAPPY path does NOT tear the devices down (no double-teardown; behavior identical to before
    // the guard). Every fallible startup call from prealloc to here was covered by the armed guard.
    guard.disarm();

    // ── 7. tokio + tonic health (Serving AFTER the datapath thread is up) ───────
    // Readiness contract (mirrors eBPF): the health service reports Serving only once the datapath
    // worker thread has been launched, so a passing gRPC liveness probe == a live datapath.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    // `addr` was parsed up-front (see the top of `run`) so a bad `--addr` fails before any worker or
    // pool device exists; here we just use it.
    println!("serving flowplane-dpdk DataplaneNode on {addr}");

    // Graceful shutdown: stop the server on SIGINT (ctrl-c) or SIGTERM (kubelet/`docker stop`).
    let shutdown = async {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("cannot install SIGTERM handler ({e}); ctrl-c only");
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        println!("shutting down flowplane-dpdk");
    };

    let serve_result = tonic::transport::Server::builder()
        .add_service(health_service)
        // The DataplaneNode service. Its handlers lock `ctrl` (the sole writer) to drive the SAME
        // `ControlCore` orchestration the eBPF binary runs; `shared` backs getter-based reads. The
        // agnostic RPCs (routes/NAT/LB/fw/QoS) program the config maps; Attach/Detach bind/release a
        // preallocated per-guest af_xdp pool slot (guest-end → pod netns); the worker above polls each
        // guest port → `process_guest_tx` → uplink (guest egress is wired). See `node.rs`.
        .add_service(pb::dataplane_node_server::DataplaneNodeServer::new(
            DpdkNodeService::new(ctrl.clone(), shared.clone(), attach_state.clone()),
        ))
        .serve_with_shutdown(addr, shutdown)
        .await;

    // ── shutdown: stop the workers, join the datapath thread ────────────────────
    // Signal every poll loop to exit, then join. `for_each_worker` returns once all lcores observe
    // `stop` and return, so the join completes shortly after.
    stop.store(true, Ordering::Release);
    if let Err(e) = workers.join() {
        eprintln!("datapath worker thread panicked on shutdown: {e:?}");
    }

    // Close every guest ethdev BEFORE deleting its backing veth (the ethdev-close-before-link-delete
    // ordering the pre-recovery code got from the guest `Port`s dropping when the worker closure returned).
    // With dead-slot recovery the guest `Port`s live in `datapath.ports` (shared cells so recovery can swap them), so
    // they do NOT drop at `workers.join()`. Explicitly `take()` each cell here — the `Option<Port>`
    // → `None` transition runs `rte_eth_dev_stop`/`close`. The workers are already joined, so no
    // worker will observe the `None` (and even if the timing raced, `rebuild_guest_qs_entry` skips a
    // `None` cell). This restores the ordering guarantee: every ethdev is closed before we delete the
    // underlying netdev below.
    for cell in &datapath.ports {
        let _ = cell.lock().take(); // drop the Port → ethdev stop+close
    }

    // Delete the PREALLOCATED guest host devices created at startup. They would otherwise leak across
    // restarts (a restart only masks this by first deleting stale same-named devices). Ethdev close
    // (above) precedes this device delete. Route through `backend.teardown` (NOT a hardcoded
    // `delete_link`) so each backend runs its own teardown mechanic — veth: `ip link del`; tap:
    // `ip tuntap del`. Reading the ifnames from `attach_state` (not a captured Vec) keeps this correct
    // even after attach/recovery mutates the pool at runtime.
    {
        let pool = attach_state.guest_pool.lock().unwrap();
        for slot in pool.iter() {
            attach_state.backend.teardown(&slot.host_ifname);
        }
    }

    serve_result.context("gRPC server error")?;
    Ok(())
}

/// The per-lcore datapath poll loop for worker queue `q`. Modeled on
/// `nfkit/tests/multilcore_datapath.rs`: build per-lcore flow state, compose with the shared config,
/// then poll BOTH the uplink (fabric→guest, `process_uplink_rx`) and any owned guest af_xdp ports
/// (guest→fabric, `process_guest_tx`) each iteration until `stop` is set, reporting quiescence each
/// iteration so the writer's RCU reclamation can make progress.
///
/// UPLINK block: for each rx'd mbuf, wrap it as [`MbufPkt`], read the outer IPv6 dst from the frame,
/// resolve `UNDERLAY[outer_dst]` → the [`UplinkIn`] `u`/`vni`, then drive the SAME unified
/// `flowplane_core::datapath::process_uplink_rx` seam the sim/eBPF/DPDK parity tests drive (base path
/// plus established NAT-return reverse-DNAT). Forward verdicts (`Redirect`/`Pass`) queue the (mutated)
/// mbuf onto the uplink tx burst; `Drop` (or a frame with no resolvable underlay) frees the mbuf by
/// letting it fall out of scope (`Mbuf`'s Drop returns it to the pool).
///
/// GUEST block: worker `q` owns the STRIDED subset of `guest_ports` for which
/// `owns(i, q, n_workers)` (round-robin by port index). For each owned guest port, rx its single
/// queue and run the shared-core
/// `process_guest_tx` (the exact seam `guest_tx_datapath.rs` proves DPDK==sim on). Resolve
/// the sending guest's `PortMeta` by the port's host veth ifindex (`ports_get`); an unbound pool port
/// (no guest attached yet, attach binds them) has no `PortMeta` → drop. The encap arm returns
/// `Redirect(uplink_ifindex)`, so a redirect whose target is `LOCAL.uplink_ifindex` is queued onto
/// the SAME uplink tx burst (encap→fabric out the uplink).
///
/// GUEST↔GUEST: the `Deliver::Local` arm returns `Redirect(dest_tap_ifindex)` (inner Eth
/// already rewritten for the dest guest). The dest port may be owned by a DIFFERENT worker, and a
/// `TxQueue` is `!Send`, so the source worker cannot tx it directly. It instead resolves the target
/// ifindex → its port index (`ifindex_to_index`) and ENQUEUEs the mbuf into that port's `LcoreRing`
/// (multi-producer, uniform — even a same-worker dest). Each worker then DRAINS the rings for the
/// ports IT owns and tx's the handed-off mbufs out that port's `TxQueue` (single-consumer). A redirect
/// to a non-local-guest ifindex, or a full ring, drops. `Pass`/`Drop` free.
///
/// Both blocks share one `now` + `LOCAL` read per iteration. Without `LOCAL` programmed there is no
/// uplink identity (no outer MACs / uplink ifindex) → both blocks drop their bursts. Guest ports are
/// polled EVERY iteration regardless of uplink rx count (no early `continue` on an idle uplink).
///
/// NOTE: each owned guest port's `TxQueue` (`gtx`) is used by the ring-drain block to tx the
/// guest↔guest frames handed off into that port's `LcoreRing` by any worker's guest rx block.
#[allow(clippy::too_many_arguments)]
fn worker_loop(
    q: u16,
    n_workers: u16,
    shared: &SharedConfigMaps,
    port: &Port,
    datapath: &GuestDatapath,
    attach: &DpdkAttachState,
    rings: &[LcoreRing],
    stop: &AtomicBool,
) {
    // Register as a QSBR reader so the writer's deferred RCU frees can reclaim past this lcore.
    let tok = shared.register_reader();
    let flow = match PerLcoreFlowMaps::new(SOCKET_ID) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("worker {q}: PerLcoreFlowMaps::new failed: {e}; worker exiting");
            // Go offline before exiting: a registered-but-dead reader would stall the writer's
            // RCU reclamation on every sibling worker forever.
            shared.reader_offline(tok);
            return;
        }
    };
    // Deref the shared Arc to `&SharedConfigMaps` for the composed reader view (sound: `Sync`).
    // `mut` because `process_uplink_rx` takes `&mut composed` to mutate the per-lcore conntrack on the
    // base decap path (`ct_create_default` on miss) / NAT-return reverse-DNAT apply.
    let mut composed = ComposedMaps { cfg: shared, flow };

    let (mut rx, mut tx) = port.queue(q);
    // Build the guest rx/tx handles ONCE, here on this lcore (the queue handles are `!Send`, so they
    // must be constructed on the worker lcore, never moved in). Guest ports are single-queue (queue 0).
    //
    // PARTITION: this worker owns the round-robin subset `{ port_index i : owns(i, q, n_workers) }`
    // (see `owns`). We iterate the shared `datapath.ports` cells, filter to the owned ones, and derive
    // each owned port's queue handles from its `Mutex<Option<Port>>` cell. A worker owning zero guest
    // ports ends up with an empty `guest_qs` → the guest block below loops over nothing.
    // Carry the port INDEX (`i`) alongside the ifindex + queues: the index is this port's slot in the
    // parallel `rings`/`datapath.ports`/`generations` vecs, so the ring-drain block below can drain
    // exactly `rings[pi]` for each owned port and the recovery rebuild can re-derive handles for it.
    // The initial `host_ifindex` is read from the pool slot for port index `i` (port_id = i + 1).
    // Snapshot every port's generation BEFORE deriving any queue handles below. If a
    // recover_slot lands between this snapshot and the handle derive, the cached gen (from
    // the snapshot) will be < the current gen, so the top-of-loop check rebuilds against the
    // swapped-in Port. Reading the gen AFTER deriving handles (the previous order) could cache
    // the post-recovery gen over pre-recovery handles and miss the rebuild forever.
    let gen_snapshot: Vec<u32> = (0..datapath.generations.len())
        .map(|i| datapath.generations[i].load(Ordering::Acquire))
        .collect();
    let mut guest_qs: Vec<(usize, u32, nfkit::RxQueue, nfkit::TxQueue)> = (0..datapath.ports.len())
        .filter(|i| owns(*i, q, n_workers))
        .filter_map(|i| {
            let host_ifindex = {
                let pool = attach.guest_pool.lock().unwrap();
                pool.iter()
                    .find(|s| s.port_id == (i as u16 + 1))
                    .map(|s| s.host_ifindex)
                    .unwrap_or(0)
            };
            // Derive the `!Send` handles on THIS lcore from the shared Port cell. A `None` cell can
            // only occur during shutdown teardown — skip it (the worker is exiting anyway).
            datapath.ports[i]
                .lock()
                .as_ref()
                .map(|p| p.queue(0))
                .map(|(r, t)| (i, host_ifindex, r, t))
        })
        .collect();
    // The GENERATION HANDSHAKE reader side: cache the last-seen generation for each owned port index
    // (parallel to `guest_qs`), seeded from the current atomic. On a mismatch at the top of the poll
    // loop the worker rebuilds that port's `guest_qs` entry on-lcore (`rebuild_guest_qs_entry`) — the
    // ONE sanctioned mutation to the static poll set. Control never touches the worker's `!Send`
    // handles; it only swaps the shared `Port` + bumps the generation.
    let mut cached_gen: Vec<u32> = guest_qs.iter().map(|(pi, ..)| gen_snapshot[*pi]).collect();

    let mut rx_burst = MbufBurst::new();
    let mut tx_burst = MbufBurst::new();
    let mut guest_burst = MbufBurst::new();
    // Reused each iteration to drain the guest↔guest handoff rings for the ports this worker owns.
    let mut ring_burst = MbufBurst::new();

    // Last time (monotonic ns) this worker ran the shared_ct idle-timeout GC sweep. Only worker 0
    // sweeps (see the throttle below), so this stays 0 on every other worker.
    let mut last_gc_ns: u64 = 0;

    while !stop.load(Ordering::Acquire) {
        // Single monotonic-clock + `LOCAL` read per iteration, shared by BOTH blocks (the meter
        // stamps `last_ns` from `now`, same CLOCK_MONOTONIC domain as the eBPF `bpf_ktime_get_ns`;
        // per-iteration granularity is fine for policing). `LOCAL` supplies the outer MACs + uplink
        // ifindex the encap/reforward paths need; it must be programmed by the control plane before
        // any packet can be forwarded. With no `LOCAL` yet, both blocks drop their bursts.
        let now = monotonic_ns();
        let local = composed.cfg.local();

        // ── GENERATION HANDSHAKE (dead-slot live recovery): rebuild owned ports whose gen bumped. ────
        // The control thread (RecoverHandle::recover_slot) recreates a dead slot's veth + af_xdp
        // ethdev, `Port::configure`s it, swaps it into `datapath.ports[pi]`, updates the redirect map,
        // and bumps `generations[pi]` (Release). Here, ON THIS LCORE, each owned entry whose atomic no
        // longer matches its cached value rebuilds its `!Send` `(RxQueue, TxQueue)` handles against the
        // freshly-swapped `Port` + re-reads the recovered slot's new `host_ifindex`. This is the ONE
        // sanctioned mutation to the otherwise-static poll set; the worker never touches control state.
        for (entry, cg) in guest_qs.iter_mut().zip(cached_gen.iter_mut()) {
            let pi = entry.0;
            if datapath.generations[pi].load(Ordering::Acquire) != *cg {
                *cg = rebuild_guest_qs_entry(datapath, attach, entry);
            }
        }

        // ── shared_ct idle-timeout GC (worker 0 only, throttled to ~1 Hz) ───────────────────────────
        // The peer-independent reverse conntrack entries a guest's SNAT/NAT64 egress pins into
        // `shared_ct` are never otherwise reclaimed → a long-running node LEAKS them as flows end.
        // Sweep them on their state-dependent idle timeout (eBPF CT model: 30 s NEW/SYN, 24 h
        // ESTABLISHED — the exact `flowplane_core::conntrack` thresholds; see
        // `SharedConfigMaps::shared_ct_sweep_expired`). Only worker 0 sweeps: a SINGLE sweeper is
        // enough (removes are Mutex-serialized regardless, so extra sweepers would just contend the
        // write lock). Reuses the per-burst `now` — no new timer/clock. Off the per-packet path:
        // capped at one walk per second.
        if q == 0 && now.saturating_sub(last_gc_ns) > 1_000_000_000 {
            composed.cfg.shared_ct_sweep_expired(now);
            last_gc_ns = now;
        }

        // ── UPLINK block (fabric → guest): rx the uplink, run process_uplink_rx. ──────────────────
        rx_burst.clear();
        let n = rx.rx(&mut rx_burst);
        if n > 0 {
            match &local {
                // No LOCAL programmed → no uplink identity; drop the whole burst.
                None => {
                    for _mbuf in rx_burst.drain(..) { /* freed on drop */ }
                }
                Some(local) => {
                    for mut mbuf in rx_burst.drain(..) {
                        // Run the datapath in a block scoped to the `MbufPkt` borrow so that borrow
                        // ends (and the mbuf becomes movable onto the tx burst) before dispatch.
                        let action = {
                            // Resolve the uplink input exactly as multilcore_datapath.rs /
                            // afxdp_datapath.rs do: read the outer IPv6 dst, look up
                            // `UNDERLAY[outer_dst]` → the delivery `UnderlayValue` (carrying vni +
                            // base tap). A frame whose outer dst isn't a locally-programmed underlay
                            // isn't destined here → `Drop`.
                            let mut pkt = MbufPkt::new(&mut mbuf);
                            match pkt.read_array::<16>(OUTER_V6_DST_OFF) {
                                // runt / non-encapped frame → drop
                                None => Action::Drop,
                                Some(outer_dst) => match composed.underlay_get(&outer_dst) {
                                    // no local underlay for this dst → drop
                                    None => Action::Drop,
                                    Some(u) => {
                                        // guest_ipv6 is read only on the CT_F_NAT64 reverse-return
                                        // branch (to reconstruct the reply's inner IPv6 dst). Source
                                        // it from the delivery port's PortMeta by tap ifindex; absent
                                        // (e.g. NAT-gateway node with no local guest) → all-zero, and
                                        // the NAT64 parse rejects it (Pass).
                                        let guest_ipv6 = composed
                                            .cfg
                                            .ports_get(u.tap_ifindex)
                                            .map(|m| m.guest_ipv6)
                                            .unwrap_or([0u8; 16]);
                                        let in_ = UplinkIn {
                                            vni: u.vni,
                                            u,
                                            outer_dst,
                                            local,
                                            now,
                                            guest_ipv6,
                                        };
                                        // The SAME unified `flowplane_core` uplink entry the eBPF
                                        // `try_uplink_rx` mirrors: it dispatches established NAT
                                        // returns to the reverse-DNAT path and everything else to the
                                        // LB+base path, so this backend runs byte-identical to
                                        // sim/eBPF for BOTH.
                                        process_uplink_rx(&mut pkt, &mut composed, &in_)
                                    }
                                },
                            }
                        };
                        // Resolve a `Redirect` target ifindex → its guest port index ONCE via the
                        // shared redirect resolver (behind an `RwLock` because recovery re-keys it when
                        // a slot's ifindex changes). Cheap read lock; writes are rare recovery events.
                        let redirect_pi = if let Action::Redirect(ix) = action {
                            datapath.ifindex_to_index.read().get(&ix).copied()
                        } else {
                            None
                        };
                        match action {
                            // Fabric → guest delivery (decap + reverse-DNAT / LB / base): the uplink
                            // entry returns `Redirect(guest_tap_ifindex)`. That target is a LOCAL guest
                            // af_xdp port that may be owned by ANOTHER worker (and `TxQueue` is `!Send`),
                            // so it MUST go through the per-port handoff ring — the SAME mechanism the
                            // guest↔guest local-delivery path uses. The owning worker drains the ring and
                            // tx's it out the guest port (see the RING DRAIN block below). Without this,
                            // the decapped return was pushed onto the UPLINK tx burst and sent back out
                            // the fabric instead of down to the guest (the "NAT-return not delivered" bug).
                            Action::Redirect(_) if redirect_pi.is_some() => {
                                let pi = redirect_pi.unwrap();
                                if let Err(m) = rings[pi].enqueue(mbuf) {
                                    drop(m); // ring full: return frame dropped (dest port backpressured)
                                }
                            }
                            // Any other forward verdict (a redirect NOT to a local guest port — e.g.
                            // reforward-to-fabric — or `Pass`) egresses the uplink tx burst as before.
                            Action::Redirect(_) | Action::Pass => tx_burst.push(mbuf),
                            // Drop: let the mbuf fall out of scope → `Mbuf`'s Drop frees it.
                            Action::Drop => {}
                        }
                    }
                }
            }
        }

        // ── Mid-loop flush: drain the uplink-forwarded burst BEFORE the guest block runs. ─────────
        // Both the uplink block above and the guest block below forward onto the SAME `tx_burst`. The
        // uplink block can fill it to the full BURST capacity in a single iteration (every rx'd frame
        // a Redirect/Pass), which would leave NO room for the guest block's encap-arm pushes and make
        // the next `tx_burst.push` overflow the fixed-capacity ArrayVec (a PANIC). Draining here keeps
        // room for the guest pushes and prevents a within-iteration overflow. This is NOT a full
        // guarantee on its own — a saturated tx ring can leave backpressure leftovers in `tx_burst`
        // (the `tx` below frees only the SENT prefix), so the guest push is ALSO made overflow-safe.
        if !tx_burst.is_empty() {
            tx.tx(&mut tx_burst);
            tx_burst.clear();
        }

        // ── GUEST block (guest → fabric): rx each owned guest port, run process_guest_tx. ──
        // Only meaningful with `LOCAL` programmed — the encapped frame egresses the uplink identified
        // by LOCAL. Without LOCAL there is no uplink identity, so poll+drain the guest ports (so their
        // rx rings don't back up) but drop everything.
        for (_pi, host_ifindex, grx, _gtx) in guest_qs.iter_mut() {
            guest_burst.clear();
            grx.rx(&mut guest_burst);
            for mut mbuf in guest_burst.drain(..) {
                let action = {
                    let mut pkt = MbufPkt::new(&mut mbuf);
                    // Branch on the inner frame's ethertype (offset 12): an IPv6 guest frame first
                    // tries NAT64 v6→v4 (dst in 64:ff9b::/96); a NON-NAT64 v6 dst falls through to the
                    // NATIVE v6→v6 egress (process_guest_tx_v6 — v6 firewall + conntrack6 + route6 +
                    // IPv6-in-IPv6 encap). Everything else is the IPv4 SNAT+encap path.
                    let ethertype = pkt.read_array::<2>(12).map(u16::from_be_bytes);
                    // `ports_get` returns an OWNED `PortMeta` copy — bind it to `pm` so the subsequent
                    // `&mut composed` borrow in the datapath fn doesn't conflict (mirrors the handoff
                    // test + the uplink block's `ports_get(..).map(..)`).
                    match (&local, composed.cfg.ports_get(*host_ifindex)) {
                        // process_guest_tx{,_nat64}'s SNAT arm writes the reverse NAT/CT entry into THIS
                        // lcore's per-lcore CT *and* the cross-lcore `shared_ct`. Guest ports are
                        // partitioned round-robin across workers (see `owns`), so a guest egresses on
                        // its OWNING worker, but the NAT-return can arrive on ANY uplink worker;
                        // `shared_ct` is the mechanism by which that other worker's reverse-DNAT (and
                        // NAT64 v6-expansion) lookup finds this flow. This is exactly why partitioning
                        // guests across lcores is safe — return demux never depends on the owning lcore.
                        (Some(l), Some(pm)) => match ethertype {
                            // IPv6 guest egress: NAT64 v6→v4 FIRST (dst in 64:ff9b::/96), else the
                            // NATIVE v6→v6 path. `process_guest_tx_nat64` returns `Action::Pass` for a
                            // NON-NAT64 dst — and it does so at `nat64_egress_parse`'s `is_nat64_addr`
                            // gate BEFORE any `shrink_head`/write, so the frame is UNMUTATED when it
                            // Passes (verified against nat64.rs). We can therefore fall through and run
                            // `process_guest_tx_v6` on the SAME frame: v6 firewall + conntrack6 +
                            // route6 + IPv6-in-IPv6 encap (inner-proto 41). This lights up v6
                            // deny-by-default firewall + conntrack6 on the DPDK serve loop.
                            Some(0x86DD) => {
                                let nat64 = process_guest_tx_nat64(
                                    &mut pkt,
                                    &mut composed,
                                    &GuestTxNat64In {
                                        meta: &pm,
                                        local: l,
                                    },
                                );
                                match nat64 {
                                    Action::Pass => {
                                        process_guest_tx_v6(
                                            &mut pkt,
                                            &mut composed,
                                            &GuestTxIn {
                                                meta: &pm,
                                                src_ifindex: *host_ifindex,
                                                now,
                                            },
                                        )
                                        .action
                                    }
                                    other => other,
                                }
                            }
                            // IPv4 SNAT + encap egress.
                            _ => {
                                process_guest_tx(
                                    &mut pkt,
                                    &mut composed,
                                    &GuestTxIn {
                                        meta: &pm,
                                        src_ifindex: *host_ifindex,
                                        now,
                                    },
                                )
                                .action
                            }
                        },
                        // No LOCAL (no uplink identity for the encap arm) or unbound pool port (no guest
                        // attached yet; attach binds them) → drop.
                        _ => Action::Drop,
                    }
                };
                // Route the verdict. The encap arm returns `Redirect(uplink_ifindex)`; the Local
                // guest↔guest arm returns `Redirect(tap_ifindex)`.
                match action {
                    Action::Redirect(ix)
                        if Some(ix) == local.as_ref().map(|l| l.uplink_ifindex) =>
                    {
                        // Encap → fabric: queue onto the SAME uplink tx burst (out the uplink). Use
                        // `try_push`, not `push`: even after the mid-loop flush above, tx-ring
                        // backpressure can leave `tx_burst` near-full (the flush frees only the SENT
                        // prefix) while guest frames keep arriving (guest_burst holds up to BURST, and
                        // multiple guest ports iterate onto the one burst). A full `tx_burst` therefore
                        // DROPS the guest frame (returned `Err` mbuf freed on scope exit) rather than
                        // panicking — guest egress is lossy under sustained tx backpressure, which is
                        // correct PMD behavior (the fabric is the bottleneck, not a bug).
                        if tx_burst.try_push(mbuf).is_err() { /* full: dropped, freed on scope exit */
                        }
                    }
                    // Guest↔guest same-node delivery: `process_guest_tx`'s `Deliver::Local` arm
                    // returns `Redirect(dest_tap_ifindex)` with the inner Ethernet ALREADY rewritten
                    // (dst = dest guest_mac, src = GW_MAC). The dest port may be owned by ANOTHER
                    // worker and a `TxQueue` is `!Send`, so we cannot tx it here directly. Resolve the
                    // target ifindex → its ring index and ENQUEUE (multi-producer) into that port's
                    // ring; the worker that OWNS the dest port drains + tx's it (see the drain block
                    // below). Uniform: enqueue even for a same-worker dest (no special case).
                    Action::Redirect(ix) => {
                        // Resolve the target ifindex → its ring index via the shared redirect resolver
                        // (RwLock; recovery re-keys it on ifindex change). A target that isn't a local
                        // guest port (not in the resolver) falls through and drops.
                        let pi = datapath.ifindex_to_index.read().get(&ix).copied();
                        if let Some(pi) = pi {
                            // Full ring → DROP (free the returned mbuf on scope exit); never spin in
                            // the poll loop. A full ring means the dest port's owner is backpressured.
                            if let Err(m) = rings[pi].enqueue(mbuf) {
                                drop(m); // ring full: guest↔guest frame dropped
                            }
                        }
                    }
                    // TODO: guest_tx Pass (no route / non-forwardable); no kernel behind the af_xdp
                    // guest port, so drop.
                    Action::Pass => {}
                    // Drop: let the mbuf fall out of scope → `Mbuf`'s Drop frees it.
                    Action::Drop => {}
                }
            }
        }

        // ── Flush the forwarded mbufs (uplink + guest-encap) out the uplink tx queue. ─────────────
        // `tx` removes+frees only the SENT prefix, leaving any un-sent mbufs (tx-ring backpressure)
        // in the burst. Drop those leftovers so the burst is empty for the next iteration — this both
        // frees them (via `Mbuf`'s Drop) and keeps `tx_burst` bounded (its `push` above would
        // otherwise overflow the fixed BURST capacity across iterations).
        if !tx_burst.is_empty() {
            tx.tx(&mut tx_burst);
            tx_burst.clear();
        }

        // ── RING DRAIN (guest↔guest delivery, owning worker only): tx handed-off mbufs. ───────────
        // For each guest port THIS worker owns, drain its handoff ring (`rings[pi]`, single-consumer:
        // only the owner dequeues) and tx each mbuf out that port's `TxQueue`. The mbuf was already
        // fully processed by the SOURCE worker's `process_guest_tx` (inner Eth rewritten for the dest
        // guest), so we tx it AS-IS — no reprocessing. Drain until a `dequeue_burst` returns 0
        // (`dequeue_burst` caps at the burst's remaining capacity ≤ BURST, so a backed-up ring takes
        // several passes). This runs EVERY iteration (even when this worker's own guest rx is idle) so
        // cross-worker delivery is never starved by an idle owner.
        for (pi, _ifx, _grx, gtx) in guest_qs.iter_mut() {
            loop {
                ring_burst.clear();
                let n = rings[*pi].dequeue_burst(&mut ring_burst);
                if n == 0 {
                    break;
                }
                // tx frees only the SENT prefix; drop any leftover (tx-ring backpressure) via clear.
                gtx.tx(&mut ring_burst);
                ring_burst.clear();
            }
        }

        // Report quiescence EVERY iteration (incl. idle) so the writer's RCU reclaim can progress.
        shared.report_quiescent(&tok);
    }
    // Normal exit (stop signalled): go offline+unregister so the writer's RCU reclaim never waits
    // on this stopped reader.
    shared.reader_offline(tok);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_backend::{AssignTarget, HostDevice};
    use std::sync::Mutex;

    /// A no-EAL fake `GuestPortBackend` that RECORDS `teardown` calls (name + order) so the
    /// `StartupGuard` Drop behavior can be asserted without creating real veths. Every device-mechanics
    /// method except `teardown` is `unimplemented!()` — the guard only ever calls `teardown` on Drop.
    /// The record is `Arc<Mutex<Vec<String>>>` so the fake stays `Send + Sync` (trait bound) and the
    /// test can inspect it after the guard drops.
    struct RecordingBackend {
        torn_down: Arc<Mutex<Vec<String>>>,
    }

    impl GuestPortBackend for RecordingBackend {
        fn preallocate(&self, _index: u16, _mtu: u32) -> anyhow::Result<HostDevice> {
            unimplemented!("not exercised by the StartupGuard tests")
        }
        fn assign_target(&self, netns_path: String, guest_ifname: String) -> AssignTarget {
            AssignTarget::Veth {
                netns_path,
                guest_ifname,
            }
        }
        fn assign(
            &self,
            _host_ifname: &str,
            _target: &AssignTarget,
            _mac: [u8; 6],
            _mtu: u32,
        ) -> anyhow::Result<()> {
            unimplemented!("not exercised by the StartupGuard tests")
        }
        fn release(&self, _host_ifname: &str, _target: &AssignTarget) {
            unimplemented!("not exercised by the StartupGuard tests")
        }
        fn is_alive(&self, _slot: &GuestPortSlot) -> bool {
            unimplemented!("not exercised by the StartupGuard tests")
        }
        fn recover(&self, _slot: &mut GuestPortSlot, _pool_port_id: u16) -> anyhow::Result<u32> {
            unimplemented!("not exercised by the StartupGuard tests")
        }
        fn teardown(&self, host_ifname: &str) {
            self.torn_down.lock().unwrap().push(host_ifname.to_string());
        }
    }

    /// An ARMED guard tears down every tracked host device on Drop, in creation order — the
    /// mid-startup leak fix. Simulates a `?`-return before the worker spawn (guard never disarmed).
    #[test]
    fn startup_guard_armed_tears_down_tracked_in_order() {
        let torn_down = Arc::new(Mutex::new(Vec::new()));
        let backend: Arc<dyn GuestPortBackend> = Arc::new(RecordingBackend {
            torn_down: torn_down.clone(),
        });
        {
            let mut guard = StartupGuard::new(backend);
            guard.track("a".into());
            guard.track("b".into());
            guard.track("c".into());
            // drop here (armed) → teardown a, b, c
        }
        assert_eq!(*torn_down.lock().unwrap(), vec!["a", "b", "c"]);
    }

    /// A DISARMED guard tears NOTHING down on Drop — the happy path where the worker thread has taken
    /// ownership of the pool. This is what keeps the successful-startup path byte-identical.
    #[test]
    fn startup_guard_disarmed_tears_down_nothing() {
        let torn_down = Arc::new(Mutex::new(Vec::new()));
        let backend: Arc<dyn GuestPortBackend> = Arc::new(RecordingBackend {
            torn_down: torn_down.clone(),
        });
        {
            let mut guard = StartupGuard::new(backend);
            guard.track("a".into());
            guard.track("b".into());
            guard.disarm();
            // drop here (disarmed) → no teardown
        }
        assert!(torn_down.lock().unwrap().is_empty());
    }

    #[test]
    fn serve_args_parse_minimal() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
            "--backend",
            "af-xdp",
            "--no-huge",
        ]);
        assert_eq!(a.uplink, "eth0");
        assert!(a.no_huge);
    }

    #[test]
    fn serve_args_defaults() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
        ]);
        assert_eq!(a.addr, "127.0.0.1:1337");
        assert_eq!(a.backend, BackendKind::AfXdp);
        // First slice: one preallocated per-guest af_xdp port by default.
        assert_eq!(a.guest_ports, 1);
        // Clab/CI-friendly defaults: 1 worker queue, lcores derived as queues + 1 (main + worker).
        assert_eq!(a.queues, 1);
        assert_eq!(a.lcores, None);
        assert_eq!(a.lcore_count(), 2);
        assert_eq!(a.eal_lcore_list(), "0-1");
        assert_eq!(a.worker_lcores(), 1);
        assert!(!a.no_huge);
        // Default guest-port pool backend is veth — no behavior change for existing veth deploys.
        assert_eq!(a.guest_backend, GuestBackendKind::Veth);
    }

    /// `--guest-backend` selects the pool backend kind at startup: `tap` → `Tap`, `veth` → `Veth`,
    /// and omitting the arg defaults to `Veth` (so existing container deploys are unaffected).
    #[test]
    fn serve_args_guest_backend() {
        let base = [
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
        ];

        let tap = ServeArgs::parse_from(base.iter().copied().chain(["--guest-backend", "tap"]));
        assert_eq!(tap.guest_backend, GuestBackendKind::Tap);

        let veth = ServeArgs::parse_from(base.iter().copied().chain(["--guest-backend", "veth"]));
        assert_eq!(veth.guest_backend, GuestBackendKind::Veth);

        // Arg omitted → default.
        let def = ServeArgs::parse_from(base);
        assert_eq!(def.guest_backend, GuestBackendKind::Veth);
    }

    /// The round-robin guest-port partition predicate (`owns`): each guest port is owned by exactly
    /// one worker (`i % n_workers`), the partition generalizes the first-slice 1-port/1-worker default
    /// (`owns(0, 0, 1)`), and no port is owned by two workers.
    #[test]
    fn owns_partitions_guest_ports_round_robin() {
        // n_workers = 2: even ports → w0, odd ports → w1.
        assert!(owns(0, 0, 2));
        assert!(!owns(0, 1, 2));
        assert!(!owns(1, 0, 2));
        assert!(owns(1, 1, 2));
        assert!(owns(2, 0, 2));
        assert!(!owns(2, 1, 2));
        assert!(!owns(3, 0, 2));
        assert!(owns(3, 1, 2));

        // n_workers = 1 (first-slice default): every port → w0.
        assert!(owns(0, 0, 1));
        assert!(owns(1, 0, 1));
        assert!(owns(42, 0, 1));

        // n_workers = 3: 0→w0, 1→w1, 2→w2, 3→w0.
        assert!(owns(0, 0, 3));
        assert!(owns(1, 1, 3));
        assert!(owns(2, 2, 3));
        assert!(owns(3, 0, 3));

        // Every port is owned by exactly one worker (no gaps, no overlaps).
        for n_workers in 1u16..=4 {
            for i in 0usize..16 {
                let owners = (0..n_workers).filter(|q| owns(i, *q, n_workers)).count();
                assert_eq!(owners, 1, "port {i} with {n_workers} workers");
            }
        }
    }

    /// `--guest-ports` parses to the requested count (VF-style preallocated per-guest af_xdp pool).
    #[test]
    fn guest_ports_parses_explicit_value() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
            "--guest-ports",
            "4",
        ]);
        assert_eq!(a.guest_ports, 4);
    }

    /// The first-slice pool cap predicate: `<=256` OK, `>256` rejected (guards the placeholder-MAC
    /// aliasing / port_id overflow). Mirrors the `anyhow::bail!` guard in `run`.
    #[test]
    fn guest_pool_cap_predicate() {
        let mk = |n: &str| {
            ServeArgs::parse_from([
                "flowplane-dpdk",
                "--uplink",
                "eth0",
                "--gateway",
                "169.254.0.1",
                "--gateway-mac",
                "02:00:00:00:00:01",
                "--guest-ports",
                n,
            ])
        };
        assert!(mk("1").guest_pool_cap_ok());
        assert!(mk("256").guest_pool_cap_ok()); // boundary OK
        assert!(!mk("257").guest_pool_cap_ok()); // first aliasing value rejected
        assert!(!mk("65535").guest_pool_cap_ok());
    }

    /// Explicit `--lcores` builds the `-l 0-{n-1}` range and sizes the worker pool.
    #[test]
    fn lcores_override_builds_eal_range() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
            "--lcores",
            "4",
            "--queues",
            "3",
        ]);
        assert_eq!(a.lcore_count(), 4);
        assert_eq!(a.eal_lcore_list(), "0-3");
        assert_eq!(a.worker_lcores(), 3); // 3 workers for 3 queues — consistent
        assert_eq!(a.queues.min(a.worker_lcores()), 3); // no clamp
    }

    /// A queue request beyond the worker lcores is clamped to `lcores - 1` (each worker needs its
    /// own non-main lcore); the default single-lcore-derivation never over-subscribes.
    #[test]
    fn queues_clamped_to_worker_lcores() {
        let a = ServeArgs::parse_from([
            "flowplane-dpdk",
            "--uplink",
            "eth0",
            "--gateway",
            "169.254.0.1",
            "--gateway-mac",
            "02:00:00:00:00:01",
            "--lcores",
            "2",
            "--queues",
            "8",
        ]);
        assert_eq!(a.worker_lcores(), 1);
        assert_eq!(a.queues.min(a.worker_lcores()), 1); // 8 clamped to 1
        assert_eq!(a.eal_lcore_list(), "0-1");
    }
}
