// `tonic::Status` is a large type, and it is the error type the generated gRPC service traits
// mandate for every handler (and the decode helpers that feed them). Boxing it everywhere to
// satisfy `result_large_err` would add indirection and noise for no real benefit on a gRPC server.
#![allow(clippy::result_large_err)]

mod attach;
mod cli;
mod conntrack_gc;
mod control;
mod error;
mod handlers;
mod loader;
mod maps;
mod node;
mod offload;
mod parse;
pub mod pb {
    tonic::include_proto!("dataplane.v1");

    #[cfg(test)]
    mod tests {
        #[test]
        fn proto_types_present() {
            let _ = super::AddRouteRequest::default();
            let _ = super::AddRouteResponse::default();
            let _ = super::ConfigureQoSRequest::default();
        }
    }
}
use anyhow::Context;
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// Sysfs / encap constants shared across subcommands
// ---------------------------------------------------------------------------

/// Read `/sys/class/net/<iface>/ifindex` and parse it as a u32.
pub(crate) fn ifindex(iface: &str) -> anyhow::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("read ifindex for {iface}"))?;
    Ok(s.trim().parse()?)
}

/// Read `/sys/class/net/<iface>/address` and return 6 MAC bytes.
pub(crate) fn mac_of(iface: &str) -> anyhow::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read mac for {iface}"))?;
    crate::parse::parse_mac(s.trim())
}

/// Base encap overhead subtracted from the underlay L3 MTU to get the guest L3 MTU: outer IPv6 (40)
/// + outer UDP (8) + Geneve header (8) = 56 (`flowplane_common::GENEVE_OVERHEAD`). The outer Ethernet
/// (14) is link framing, off the L3 MTU. (Pre-Geneve this was IP-in-IPv6 — a bare inner IP packet,
/// no inner Ethernet/UDP/Geneve on the wire — so the overhead was 40; the Geneve retarget added the
/// UDP + Geneve headers on top.)
const GENEVE_BASE_OVERHEAD_V6: u32 = flowplane_common::GENEVE_OVERHEAD as u32;

/// Encap overhead subtracted from the underlay L3 MTU to get the guest L3 MTU: the base Geneve
/// overhead ([`GENEVE_BASE_OVERHEAD_V6`], 56) plus the DSR Geneve option
/// (`flowplane_core::dsr::DSR_OPT_BUF_LEN`, 24) that the edge stamps onto edge->backend
/// DSR-redirected packets (B9). Subtracted globally — not only on nodes that can host LB
/// backends — so the guest MTU is uniform across the fleet and a full-MTU inner frame plus the DSR
/// option always fits the underlay path MTU, however the traffic ends up routed.
pub(crate) const ENCAP_OVERHEAD_V6: u32 =
    GENEVE_BASE_OVERHEAD_V6 + flowplane_core::dsr::DSR_OPT_BUF_LEN as u32;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "flowplane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

// One `Cmd` is parsed once at startup and lives for the process; the size gap between the tiny
// subcommands and the flag-heavy `Bringup`/`TcBringup` is irrelevant, and boxing variants fights
// clap's derive (it expects `#[arg]` fields directly on the variant).
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Cmd {
    /// Load and attach the XDP datapath to an interface, then idle.
    Load {
        #[arg(long)]
        uplink: String,
    },
    /// Start the gRPC control-plane server with a live datapath.
    Serve(cli::serve::ServeArgs),
    /// Infer this host's underlay /64 from its interface addresses (prefers a lo/dummy* fabric
    /// loopback) and print it, then exit. No datapath, no root — reads `ip -6 -o addr`. Used by the
    /// containerlab IPv6-fabric e2e to assert the inferred /64 matches the fabric-announced dummy0.
    InferUnderlay,
    /// Attach xdp_inspect to an interface and print the first packet bytes every 500 ms.
    Inspect(cli::inspect::InspectArgs),
    /// Bring up the map-driven datapath: attach programs and program all maps, then idle.
    Bringup(cli::bringup::BringupArgs),
    /// Minimal tc guest-edge bringup for the Phase-1 DHCP gate: attach tc_guest_tx to one tap's
    /// clsact ingress, program PORT_META + DHCP config for it, then idle.
    TcBringup(cli::tc_bringup::TcBringupArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logger backend for the eBPF `dlog!` tracing (active only with FLOWPLANE_DEBUG + a debug image).
    // Honors RUST_LOG; defaults to `info` so datapath traces show without extra config.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Load { uplink } => {
            let _ebpf = loader::attach_uplink(&uplink, &loader::ephemeral_pin_dir()?)?;
            println!("attached uplink_rx to {uplink}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::InferUnderlay => {
            // Pure, root-free observability hook for the containerlab IPv6-fabric e2e: read the
            // host ifaddrs and print the inferred underlay /64 in a stable, greppable form.
            let addrs = flowplane_device::read_host_ifaddrs()?;
            let prefix = flowplane_device::infer_underlay_prefix(&addrs)
                .context("no global-unicast IPv6 address found to infer underlay /64")?;
            println!("inferred underlay prefix: {prefix}");
        }
        Cmd::Serve(args) => cli::serve::run(args).await?,
        Cmd::Inspect(args) => cli::inspect::run(args).await?,
        Cmd::Bringup(args) => cli::bringup::run(args).await?,
        Cmd::TcBringup(args) => cli::tc_bringup::run(args).await?,
    }
    Ok(())
}
