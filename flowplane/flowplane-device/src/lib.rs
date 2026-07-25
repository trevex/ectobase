//! Host-device + underlay-IPAM plumbing shared by the eBPF `flowplane` and DPDK `flowplane-dpdk`
//! agents. Pure Linux plumbing (`ip`/`ip netns exec` subprocess) — no tonic, no eBPF, no DPDK.
pub mod underlay;

pub use underlay::{
    infer_underlay_address, infer_underlay_prefix, read_host_ifaddrs, IfAddr, UnderlayIpam,
};
