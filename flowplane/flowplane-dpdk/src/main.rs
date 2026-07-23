//! `flowplane-dpdk serve` binary entrypoint — the DPDK sibling of the eBPF `flowplane serve`.
//! Parses [`flowplane_dpdk::serve::ServeArgs`] and runs the serve process (EAL → maps → datapath
//! workers → tokio/tonic gRPC server). See `serve.rs` for the full process structure.
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = flowplane_dpdk::serve::ServeArgs::parse();
    flowplane_dpdk::serve::run(args).await
}
