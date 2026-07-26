//! Host-device + underlay-IPAM plumbing shared by the eBPF `flowplane` and DPDK `flowplane-dpdk`
//! agents. Pure Linux plumbing (`ip`/`ip netns exec` subprocess) — no tonic, no eBPF, no DPDK.
pub mod netns;
pub mod underlay;
pub mod veth;

pub use netns::{configure_guest_netns, GuestNetConfig};
pub use underlay::{
    infer_underlay_address, infer_underlay_prefix, read_host_ifaddrs, IfAddr, UnderlayIpam,
};
pub use veth::{
    bind_preallocated_guest_end, create_preallocated_veth, create_veth_pair, delete_link,
    ifindex_of, link_exists, mac_of, unbind_preallocated_guest_end, DeviceInfo, VethSpec,
};
