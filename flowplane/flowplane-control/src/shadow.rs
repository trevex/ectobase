//! Agnostic shadow/meta types moved out of the eBPF `Control::Inner`.
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV4.
pub type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV6.
pub type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);
