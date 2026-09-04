//! Host-device + underlay-inference plumbing for the eBPF `flowplane` agent. Pure Linux plumbing
//! (`ip`/`ip netns exec` subprocess) — no tonic, no eBPF.
pub mod geneve;
pub mod grpc;
pub mod netns;
pub mod tap;
pub mod underlay;
pub mod veth;

pub use geneve::{delete_geneve_dev, ensure_geneve_dev, geneve_add_args, GENEVE_DEV};
pub use netns::{configure_guest_netns, GuestNetConfig};
pub use tap::{create_persistent_tap, delete_tap, open_tap_fd};
pub use underlay::{
    infer_underlay_address, infer_underlay_address_within, infer_underlay_prefix,
    infer_underlay_prefix_within, read_host_ifaddrs, IfAddr,
};
pub use veth::{
    bind_preallocated_guest_end, create_preallocated_veth, create_veth_pair, delete_link,
    ifindex_of, link_exists, mac_of, unbind_preallocated_guest_end, DeviceInfo, VethSpec,
};
