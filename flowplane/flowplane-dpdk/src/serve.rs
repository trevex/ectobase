//! `flowplane-dpdk serve` — the DPDK serve-process scaffold.
//!
//! The DPDK sibling of the eBPF `flowplane serve` command. It mirrors that process structure but
//! swaps the datapath (eBPF/aya → nfkit/DPDK) and drops all eBPF/device specifics:
//!
//!   1. Parse [`ServeArgs`] (clap).
//!   2. Map `--backend`/`--uplink`/`--queues` → [`nfkit::Backend`]; build the EAL argv via
//!      `Backend::eal_args("flowplane-dpdk")` (+ `--no-huge` on request); `Eal::init(argv)`.
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
use nfkit::{
    Backend, ComposedMaps, Eal, LcoreRuntime, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, Port,
    SharedConfigMaps,
};

use flowplane_control::ControlCore;
// `flowplane_core::datapath::{process_uplink, UplinkIn}` are the Task-9 seam the worker loop drives
// once outer-dst resolution lands — referenced in `worker_loop`'s doc comment, not yet called here.
use crate::writer::DpdkMapWriter;

/// Config-table capacity (entries) for the process-wide `SharedConfigMaps`. Matches the sizing the
/// nfkit datapath tests use; the tables carry ~2× headroom internally (RCU reclaim slack).
const CONFIG_ENTRIES: u32 = 4096;

/// NUMA socket the maps + mempool are allocated on. Single-socket assumption for the scaffold; a
/// real multi-socket deployment would derive this per-port (Task 9+).
const SOCKET_ID: i32 = 0;

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
    /// Number of EAL lcores (main + workers). Currently informational; the EAL argv `-l` range is
    /// built by `Backend::eal_args`. Kept for parity with the eBPF surface and future tuning.
    #[arg(long, default_value_t = 4)]
    pub lcores: u16,
    /// Number of rx/tx queues (= datapath worker lcores). Also the af-xdp `queue_count`.
    #[arg(long, default_value_t = 4)]
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
}

impl ServeArgs {
    /// Map the parsed backend kind + uplink/queues into an [`nfkit::Backend`].
    fn to_backend(&self) -> Backend {
        match self.backend {
            BackendKind::AfXdp => Backend::AfXdp {
                iface: self.uplink.clone(),
                queues: self.queues,
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
    let backend = args.to_backend();
    let mut eal_argv = backend.eal_args("flowplane-dpdk");
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
    let port = Port::configure(0, args.queues, &pool)
        .map_err(|e| anyhow::anyhow!("port configure failed: {e}"))?;
    let n_workers = port.n_queues();
    println!("port 0 up with {n_workers} queue(s)");

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
    // Silence the "unused until Task 9" warning while keeping the handle wired + documented.
    let _ = &ctrl;

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
        // Task 9: add the DataplaneNode service here —
        //   `.add_service(DataplaneNodeServer::new(NodeService::new(ctrl.clone(), ...)))`
        // The handlers lock `ctrl: Arc<Mutex<ControlCore<DpdkMapWriter>>>` (the sole writer) to
        // program the shared config maps. Requires a build.rs proto compile (routebus/dataplane
        // node .proto) to generate the server trait, mirroring flowplane's node::pb module.
        .serve_with_shutdown(addr, shutdown)
        .await;

    // ── shutdown: stop the workers, join the datapath thread ────────────────────
    // Signal every poll loop to exit, then join. `for_each_worker` returns once all lcores observe
    // `stop` and return, so the join completes shortly after.
    stop.store(true, Ordering::Release);
    if let Err(e) = workers.join() {
        eprintln!("datapath worker thread panicked on shutdown: {e:?}");
    }
    serve_result.context("gRPC server error")?;
    Ok(())
}

/// The per-lcore datapath poll loop for worker queue `q`. Modeled on
/// `nfkit/tests/multilcore_datapath.rs`: build per-lcore flow state, compose with the shared config,
/// then rx → `process_uplink` → tx until `stop` is set, reporting quiescence each iteration so the
/// writer's RCU reclamation can make progress.
///
/// NOTE (scaffold): this wires the rx → datapath → tx structure. The `UplinkIn` fields it feeds
/// `process_uplink` (vni / underlay-value / outer_dst resolution from the packet's outer IPv6 dst,
/// and the monotonic clock) are the Task-9 concern — the serve process can't be booted without a
/// live NIC here, so the resolution logic is validated live later. Until then a worker that receives
/// a packet resolves the outer dst from `LOCAL`/`UNDERLAY` (present once the control plane programs
/// them); with no config + no NIC the loop simply idles on empty rx bursts.
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
    // Task 9 makes this `mut` (the `process_uplink` call takes `&mut composed` to mutate per-lcore
    // conntrack); the scaffold only reads config through it, so it is immutable here.
    let composed = ComposedMaps { cfg: shared, flow };

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
        for mut mbuf in rx_burst.drain(..) {
            // ── Task-9 seam: outer-dst resolution → UplinkIn → process_uplink → tx ──────────────
            // The control plane must have programmed LOCAL before any packet can be forwarded; with
            // no config (or no NIC) we simply drop. Once LOCAL is present, the remaining Task-9 work
            // is: read the outer IPv6 dst from the packet, `composed.cfg.underlay_get(&outer_dst)`
            // to derive `vni`/`u`, stamp `now` from a monotonic clock, then:
            //
            //     let mut pkt = MbufPkt::new(&mut mbuf);
            //     let in_ = UplinkIn { vni, u, outer_dst, local: &local, now };
            //     match process_uplink(&mut pkt, &mut composed, &in_) {
            //         Action::Redirect(_) | Action::Pass => tx_burst.push(mbuf),
            //         _ => { /* mbuf drops (freed) at end of iteration */ }
            //     }
            //
            // `process_uplink` is the SAME entry point the nfkit multilcore datapath test drives, so
            // this backend runs byte-identical to the sim/eBPF once the resolution lands. Until then
            // the mbuf is freed when it drops at the end of this iteration.
            if composed.cfg.local().is_none() {
                // No LOCAL programmed yet — nothing to forward against; mbuf drops (freed) below.
                continue;
            }
            // Wrap the packet through the seam so the `Pkt` view is exercised even in the scaffold.
            // The `MbufPkt` borrows `mbuf`; both are released at the end of this iteration (the mbuf
            // is freed back to the pool by `Mbuf`'s Drop — nothing is queued for tx in the scaffold).
            let _pkt = MbufPkt::new(&mut mbuf);
        }
        // Flush anything queued for tx (empty in the scaffold until the datapath call above lands).
        if !tx_burst.is_empty() {
            tx.tx(&mut tx_burst);
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
        assert_eq!(a.queues, 4);
        assert_eq!(a.lcores, 4);
        assert!(!a.no_huge);
    }
}
