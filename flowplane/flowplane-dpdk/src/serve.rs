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
//!      (Task 9) will drive `ControlCore` through this handle.
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
//! gRPC service (Task 9) via the same `Arc<Mutex<ControlCore>>`. Workers NEVER get a writer.
#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use ipnet::Ipv6Net;
use nfkit::{
    Backend, ComposedMaps, Eal, LcoreRuntime, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, Port,
    SharedConfigMaps,
};

use flowplane_control::ControlCore;
use flowplane_core::datapath::{process_uplink_rx, UplinkIn};
use flowplane_core::maps::Maps; // brings `underlay_get`/`local` method syntax into scope on ComposedMaps
use flowplane_core::pkt::{Action, Pkt}; // `Pkt` brings `read_array` into scope on MbufPkt
use nfkit::monotonic_ns;

use crate::attach_state::{DpdkAttachState, GuestPortSlot};

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
/// real multi-socket deployment would derive this per-port (Task 9+).
const SOCKET_ID: i32 = 0;

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
    /// from). Optional — resolved later (Task 9) from the node IP when unset.
    #[arg(long = "local-underlay")]
    pub local_underlay: Option<String>,
    /// DPDK port backend.
    #[arg(long, value_enum, default_value_t = BackendKind::AfXdp)]
    pub backend: BackendKind,
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
    /// Guest MTU override. Unset = derive from the uplink MTU minus encap overhead (Task 9).
    #[arg(long = "guest-mtu")]
    pub guest_mtu: Option<u32>,
    /// Number of PREALLOCATED per-guest af_xdp ports (VF-style). The serve process creates this many
    /// guest veth pairs BEFORE EAL init and passes each as an extra `--vdev=net_af_xdp<i>`, giving a
    /// STATIC poll set that AttachInterface (Task 4) later binds to guests. First slice: 1. Only
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

/// Run the DPDK serve process (see the module doc for the full structure). This is `async` and
/// hosts the tonic server on the calling (tokio) thread; the datapath runs on a dedicated OS thread.
pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
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
    // root-netns PLACEHOLDER until Task 4's AttachInterface moves it into the pod netns; the MAC set
    // here is a deterministic placeholder (the real guest MAC is programmed at attach). `bound` is
    // `None` for every slot (Task 4 binds them).
    let guest_mtu = args.guest_mtu.unwrap_or(DEFAULT_GUEST_MTU);
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
            // Track host ifnames we've already created so ANY failure below (this loop OR the guest
            // ethdev-configure loop) can tear them down before returning — otherwise a mid-pool
            // failure would leak the veths already on the host (e.g. `fpg0`/`fpg1` if slot 2 fails).
            let mut created: Vec<String> = Vec::with_capacity(args.guest_ports as usize);
            for i in 0..args.guest_ports {
                let host_ifname = format!("fpg{i}");
                // Deterministic placeholder MAC: 02:00:00:00:0e:<i>. Not datapath-significant yet —
                // the real guest MAC is programmed at attach (Task 4).
                let mac = [0x02, 0x00, 0x00, 0x00, 0x0e, i as u8];
                let dev = match flowplane_device::create_preallocated_veth(
                    &host_ifname,
                    mac,
                    guest_mtu,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        // Roll back every veth created so far, mirroring create_preallocated_veth's
                        // own rollback style, then propagate the error.
                        for h in &created {
                            flowplane_device::delete_link(h);
                        }
                        return Err(e).with_context(|| {
                            format!("create preallocated guest veth {host_ifname} (slot {i})")
                        });
                    }
                };
                created.push(dev.host_name.clone());
                slots.push(GuestPortSlot {
                    host_ifname: dev.host_name,
                    host_ifindex: dev.host_ifindex,
                    // ethdev port id: uplink = 0, guests = 1..=N (matches the vdev append order).
                    port_id: 1 + i,
                    bound: None,
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
    let pool = Mempool::new("fp_dpdk_pool", 8191, 250, SOCKET_ID)
        .map_err(|e| anyhow::anyhow!("mempool create failed: {e}"))?;
    let port = Port::configure(0, queues, &pool)
        .map_err(|e| anyhow::anyhow!("port configure failed: {e}"))?;
    let n_workers = port.n_queues();
    println!("port 0 up with {n_workers} queue(s)");

    // Configure each PREALLOCATED guest port (ethdev ids 1..=N). Single queue per guest port (the
    // af_xdp vdev was probed with queue_count=1). These `Port`s MUST outlive the datapath — a `Port`
    // Drop stops+closes the ethdev — so they are moved into the worker thread below. Task 3 wires the
    // per-guest rx/tx polling; for now they are just held live.
    let mut guest_ports: Vec<Port> = Vec::with_capacity(slots.len());
    for slot in &slots {
        let gp = match Port::configure(slot.port_id, 1, &pool) {
            Ok(gp) => gp,
            Err(e) => {
                // A guest ethdev-configure failure leaves the already-created host veths (all of
                // `slots`) on the host — tear them ALL down before returning so a partial startup
                // doesn't leak. Drop the guest `Port`s configured so far first (their ethdev close
                // must precede deleting the underlying links).
                drop(guest_ports);
                for s in &slots {
                    flowplane_device::delete_link(&s.host_ifname);
                }
                return Err(anyhow::anyhow!(
                    "guest port {} ({}) configure failed: {e}",
                    slot.port_id,
                    slot.host_ifname
                ));
            }
        };
        println!(
            "guest port {} ({}) up with {} queue(s)",
            slot.port_id,
            slot.host_ifname,
            gp.n_queues()
        );
        guest_ports.push(gp);
    }

    // ── 4. Shared config maps (process-wide, single-writer) ─────────────────────
    let shared = Arc::new(
        SharedConfigMaps::new(SOCKET_ID, CONFIG_ENTRIES)
            .map_err(|e| anyhow::anyhow!("SharedConfigMaps::new failed: {e}"))?,
    );

    // ── 5. The SINGLE writer: ControlCore<DpdkMapWriter> behind a Mutex ─────────
    // The Mutex enforces single-writer over the `&self` SharedConfigMaps writes (soundness of the
    // LF+RCU tables rests on exactly one writer). Task 9's DataplaneNode service takes handlers that
    // lock this and drive ControlCore. Cloned here so the handle survives into the gRPC service.
    let ctrl = Arc::new(parking_lot::Mutex::new(ControlCore::new(
        DpdkMapWriter::new(shared.clone()),
    )));

    // ── 5b. B2a attach state: underlay IPAM + device registry ─────────────────
    // Seed `UnderlayIpam` from `--local-underlay` if set (parsed as a /64 to truncate to the
    // network address), else infer from the host's interface addresses. The guest_mtu defaults to
    // a sane 1450 (underlay MTU 1500 - 40-byte outer IPv6 - 8-byte encap header) when not set.
    let underlay_prefix: Ipv6Net = match &args.local_underlay {
        Some(s) => {
            // Parse as a /128 host address + build the /64 network around it.
            let ip: std::net::Ipv6Addr = s
                .parse()
                .with_context(|| format!("parse --local-underlay {s:?} as IPv6"))?;
            Ipv6Net::new(ip, 64)
                .map_err(|e| anyhow::anyhow!("build /64 from --local-underlay {s}: {e}"))?
                .trunc()
        }
        None => flowplane_device::infer_underlay_prefix(&flowplane_device::read_host_ifaddrs()?)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not infer underlay /64 from host interfaces; set --local-underlay"
                )
            })?,
    };
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
    // The preallocated `slots` move into `guest_pool` (behind a Mutex) so Task 4's AttachInterface can
    // bind/release them; the guest `Port`s themselves are held live by the worker thread (below).
    let guest_pool_len = slots.len();
    let attach_state = Arc::new(DpdkAttachState {
        ipam: std::sync::Mutex::new(flowplane_device::UnderlayIpam::new(underlay_prefix)),
        registry: std::sync::Mutex::new(std::collections::HashMap::new()),
        guest_mtu,
        gateway_ipv4,
        gateway_ipv6,
        guest_pool: std::sync::Mutex::new(slots),
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
    // Move the Port + Mempool into the worker thread: the rx/tx queue handles are `!Send` and must
    // be built ON each lcore, and the Port/pool must outlive every worker. `_eal` stays on the main
    // thread (the EAL guard is `!Send` and cleans up on process exit).
    let workers = std::thread::Builder::new()
        .name("fp-dpdk-datapath".into())
        .spawn(move || {
            // Hold the preallocated guest `Port`s alive for the lifetime of the datapath thread: a
            // `Port` Drop stops+closes its ethdev, so they must outlive the workers. Task 3 wires the
            // per-guest rx/tx polling into `worker_loop`; for now they are just kept live (bound to a
            // live variable so they aren't dropped early).
            //
            // NOTE: the binding MUST be a NAMED `_guest_ports`, not a bare `let _ = guest_ports;`.
            // A bare underscore is NOT a binding — it drops the value IMMEDIATELY at that statement,
            // which here would close every guest ethdev before the workers even start (Vec<Port> Drop
            // → per-Port ethdev stop+close). The named `_guest_ports` keeps them live until the
            // closure returns. This binding is load-bearing; do not "simplify" it to `let _`.
            let _guest_ports = guest_ports;
            LcoreRuntime::for_each_worker(n_workers, |q| {
                worker_loop(q, &shared_for_workers, &port, &stop_w);
            });
        })
        .context("spawn datapath worker thread")?;

    // ── 7. tokio + tonic health (Serving AFTER the datapath thread is up) ───────
    // Readiness contract (mirrors eBPF): the health service reports Serving only once the datapath
    // worker thread has been launched, so a passing gRPC liveness probe == a live datapath.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    let addr = args.addr.parse().context("parse --addr")?;
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
        // agnostic RPCs (routes/NAT/LB/fw/QoS) program the config maps; Attach/Detach stand up the
        // container veth device (B2a) — af_xdp bind + guest-traffic polling is B2b. See `node.rs`.
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

    // Delete the PREALLOCATED guest veths created at startup. They are host-side links that would
    // otherwise leak across restarts (a restart only masks this by first deleting stale same-named
    // links). We do this AFTER `workers.join()` for a deliberate ORDERING reason: the guest `Port`s
    // (whose Drop runs `rte_eth_dev_close`) live inside the worker-thread closure and are dropped
    // when that closure returns — i.e. BEFORE `workers.join()` completes. So by the time we reach
    // here every guest ethdev is already closed, and deleting the underlying netdev is safe (ethdev
    // close precedes link delete, never the reverse). Reading the ifnames from `attach_state` (not a
    // captured Vec) keeps this correct even after Task 4 mutates the pool at runtime.
    {
        let pool = attach_state.guest_pool.lock().unwrap();
        for slot in pool.iter() {
            flowplane_device::delete_link(&slot.host_ifname);
        }
    }

    serve_result.context("gRPC server error")?;
    Ok(())
}

/// The per-lcore datapath poll loop for worker queue `q`. Modeled on
/// `nfkit/tests/multilcore_datapath.rs`: build per-lcore flow state, compose with the shared config,
/// then rx → `process_uplink_rx` → tx until `stop` is set, reporting quiescence each iteration so the
/// writer's RCU reclamation can make progress.
///
/// For each rx'd mbuf the loop mirrors the multilcore/afxdp datapath tests exactly: wrap the mbuf as
/// [`MbufPkt`], read the outer IPv6 dst from the frame, resolve `UNDERLAY[outer_dst]` → the
/// [`UplinkIn`] `u`/`vni`, then drive the SAME unified `flowplane_core::datapath::process_uplink_rx`
/// seam the sim/eBPF/DPDK parity tests drive (base path + established NAT-return reverse-DNAT). Forward verdicts (`Redirect`/`Pass`) queue the (mutated) mbuf
/// for tx; `Drop` (or a frame with no resolvable underlay / no `LOCAL` programmed) frees the mbuf by
/// letting it fall out of scope (`Mbuf`'s Drop returns it to the pool).
fn worker_loop(q: u16, shared: &SharedConfigMaps, port: &Port, stop: &AtomicBool) {
    // Register as a QSBR reader so the writer's deferred RCU frees can reclaim past this lcore.
    let tok = shared.register_reader();
    let flow = match PerLcoreFlowMaps::new(SOCKET_ID) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("worker {q}: PerLcoreFlowMaps::new failed: {e}; worker exiting");
            return;
        }
    };
    // Deref the shared Arc to `&SharedConfigMaps` for the composed reader view (sound: `Sync`).
    // `mut` because `process_uplink_rx` takes `&mut composed` to mutate the per-lcore conntrack on the
    // base decap path (`ct_create_default` on miss) / NAT-return reverse-DNAT apply.
    let mut composed = ComposedMaps { cfg: shared, flow };

    let (mut rx, mut tx) = port.queue(q);
    let mut rx_burst = MbufBurst::new();
    let mut tx_burst = MbufBurst::new();

    while !stop.load(Ordering::Acquire) {
        rx_burst.clear();
        let n = rx.rx(&mut rx_burst);
        if n == 0 {
            // Empty poll: still report quiescence so the writer isn't blocked, then spin.
            shared.report_quiescent(&tok);
            continue;
        }
        // `LOCAL` supplies the outer MACs/ifindex an LB remote `reforward` needs; it must be
        // programmed by the control plane before any packet can be forwarded. Fetch it once per burst
        // (owned copy; stable within a burst). With no `LOCAL` yet, drop the whole burst.
        let local = match composed.cfg.local() {
            Some(l) => l,
            None => {
                for _mbuf in rx_burst.drain(..) { /* freed on drop */ }
                shared.report_quiescent(&tok);
                continue;
            }
        };
        // Single monotonic-clock read per burst (the ingress-lane meter stamps `last_ns` from it —
        // same CLOCK_MONOTONIC domain as the eBPF `bpf_ktime_get_ns`). Per-burst granularity is fine
        // for policing.
        let now = monotonic_ns();

        for mut mbuf in rx_burst.drain(..) {
            // Run the datapath in a block scoped to the `MbufPkt` borrow so that borrow ends (and the
            // mbuf becomes movable onto the tx burst) before the verdict dispatch below.
            let action = {
                // Resolve the uplink input exactly as multilcore_datapath.rs / afxdp_datapath.rs do:
                // read the outer IPv6 dst, look up `UNDERLAY[outer_dst]` → the delivery
                // `UnderlayValue` (carrying vni + base tap). A frame whose outer dst isn't a
                // locally-programmed underlay isn't destined here → `Drop`.
                let mut pkt = MbufPkt::new(&mut mbuf);
                match pkt.read_array::<16>(OUTER_V6_DST_OFF) {
                    // runt / non-encapped frame → drop
                    None => Action::Drop,
                    Some(outer_dst) => match composed.underlay_get(&outer_dst) {
                        // no local underlay for this dst → drop
                        None => Action::Drop,
                        Some(u) => {
                            // guest_ipv6 is read only on the CT_F_NAT64 reverse-return branch (to
                            // reconstruct the reply's inner IPv6 dst). Source it from the delivery
                            // port's PortMeta by tap ifindex; absent (e.g. NAT-gateway node with no
                            // local guest) → all-zero, and the NAT64 parse rejects it (Pass).
                            let guest_ipv6 = composed
                                .cfg
                                .ports_get(u.tap_ifindex)
                                .map(|m| m.guest_ipv6)
                                .unwrap_or([0u8; 16]);
                            let in_ = UplinkIn {
                                vni: u.vni,
                                u,
                                outer_dst,
                                local: &local,
                                now,
                                guest_ipv6,
                            };
                            // The SAME unified `flowplane_core` uplink entry the eBPF `try_uplink_rx`
                            // mirrors: it dispatches established NAT returns to the reverse-DNAT path
                            // and everything else to the LB+base path, so this backend runs
                            // byte-identical to sim/eBPF for BOTH.
                            process_uplink_rx(&mut pkt, &mut composed, &in_)
                        }
                    },
                }
            };
            match action {
                // Forward verdicts: queue the (mutated) mbuf for tx.
                Action::Redirect(_) | Action::Pass => tx_burst.push(mbuf),
                // Drop: let the mbuf fall out of scope → `Mbuf`'s Drop frees it back to the pool.
                Action::Drop => {}
            }
        }
        // Flush the forwarded mbufs. `tx` removes+frees only the SENT prefix, leaving any un-sent
        // mbufs (tx-ring backpressure) in the burst. Drop those leftovers so the burst is empty for
        // the next iteration — this both frees them (via `Mbuf`'s Drop) and keeps `tx_burst` bounded
        // (its `push` above would otherwise overflow the fixed BURST capacity across iterations).
        if !tx_burst.is_empty() {
            tx.tx(&mut tx_burst);
            tx_burst.clear();
        }
        shared.report_quiescent(&tok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
