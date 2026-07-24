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
use nfkit::{
    Backend, ComposedMaps, Eal, LcoreRuntime, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, Port,
    SharedConfigMaps,
};

use flowplane_control::ControlCore;
use flowplane_core::datapath::{process_uplink_rx, UplinkIn};
use flowplane_core::maps::Maps; // brings `underlay_get`/`local` method syntax into scope on ComposedMaps
use flowplane_core::pkt::{Action, Pkt}; // `Pkt` brings `read_array` into scope on MbufPkt
use nfkit::monotonic_ns;

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
    let mut eal_argv = backend.eal_args_lcores("flowplane-dpdk", &args.eal_lcore_list());
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
        // The DataplaneNode service. Its handlers lock `ctrl` (the sole writer) to drive the SAME
        // `ControlCore` orchestration the eBPF binary runs; `shared` backs getter-based reads. The
        // agnostic RPCs (routes/NAT/LB/fw/QoS) program the config maps; Attach/Detach program the
        // agnostic half and return Unimplemented (the host-device step is B2). See `node.rs`.
        .add_service(pb::dataplane_node_server::DataplaneNodeServer::new(
            DpdkNodeService::new(ctrl.clone(), shared.clone()),
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
                            let in_ = UplinkIn {
                                vni: u.vni,
                                u,
                                outer_dst,
                                local: &local,
                                now,
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
        // Clab/CI-friendly defaults: 1 worker queue, lcores derived as queues + 1 (main + worker).
        assert_eq!(a.queues, 1);
        assert_eq!(a.lcores, None);
        assert_eq!(a.lcore_count(), 2);
        assert_eq!(a.eal_lcore_list(), "0-1");
        assert_eq!(a.worker_lcores(), 1);
        assert!(!a.no_huge);
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
