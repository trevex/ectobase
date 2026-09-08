//! `flowplane inspect`: attach xdp_inspect to an interface and print the first packet bytes
//! every 500 ms.
use anyhow::Context;

use crate::{loader, maps};

#[derive(clap::Args)]
pub struct InspectArgs {
    #[arg(long)]
    iface: String,
}

pub async fn run(args: InspectArgs) -> anyhow::Result<()> {
    let InspectArgs { iface } = args;
    let mut ebpf = loader::load_ebpf(&loader::ephemeral_pin_dir()?)?;

    // Try native (driver) mode first; fall back to SKB (generic) mode if rejected.
    let prog: &mut aya::programs::Xdp = ebpf
        .program_mut("xdp_inspect")
        .context("xdp_inspect program missing")?
        .try_into()?;
    prog.load().context("verify xdp_inspect")?;
    let mode = match prog.attach(&iface, aya::programs::XdpFlags::default()) {
        Ok(_) => "native/driver",
        Err(native_err) => {
            eprintln!("native attach failed ({native_err}), retrying with SKB_MODE");
            prog.attach(&iface, aya::programs::XdpFlags::SKB_MODE)
                .with_context(|| format!("attach xdp_inspect to {iface} (SKB_MODE)"))?;
            "SKB/generic"
        }
    };
    println!("xdp_inspect attached to {iface} in {mode} mode");

    let inspect = maps::InspectMap::open(&mut ebpf)?;

    let mut prev_seen = 0u32;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                match inspect.get() {
                    Ok(e) => {
                        if e.seen != prev_seen {
                            prev_seen = e.seen;
                            let hex: String = e.bytes.iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            // Probe multiple offsets for the ethertype-like u16.
                            let et12 = u16::from_be_bytes([e.bytes[12], e.bytes[13]]);
                            let et10 = u16::from_be_bytes([e.bytes[10], e.bytes[11]]);
                            let et14 = u16::from_be_bytes([e.bytes[14], e.bytes[15]]);
                            let et22 = u16::from_be_bytes([e.bytes[22], e.bytes[23]]);
                            println!(
                                "seen={} len={} bytes=[{hex}] \
                                 et@10={et10:#06x} et@12={et12:#06x} et@14={et14:#06x} et@22={et22:#06x}",
                                e.seen, e.len,
                            );
                        }
                    }
                    Err(e) => eprintln!("inspect read error: {e}"),
                }
            }
        }
    }
    println!("detaching");
    Ok(())
}
