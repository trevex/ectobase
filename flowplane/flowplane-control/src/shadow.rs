//! Agnostic shadow/meta types moved out of the eBPF `Control::Inner`.
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV4.
pub type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV6.
pub type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);

/// Agnostic per-interface metadata the nat/lb/fw/qos logic reads (subset of the eBPF IfaceRecord).
#[derive(Clone, Copy, Debug)]
pub struct IfaceMeta {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub underlay: [u8; 16],
}

/// Registered load balancer (agnostic subset). For Task 4 the NAT preferred-underlay collision
/// check only needs `lb_underlay`; the full backend/service state is moved here in Task 5.
#[derive(Clone, Copy, Debug)]
pub struct LbEntry {
    pub lb_underlay: [u8; 16],
    // backends etc. added in Task 5
}
