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
    /// Tap ifindex (was `Control::Inner.by_ifindex`); the firewall resolves interface_id -> ifindex
    /// through this so it can key `FW_RULES`/`FW_META`.
    pub ifindex: u32,
}

/// LB IP address (IPv4 or IPv6) at the gRPC/create boundary. Moved out of `control/mod.rs`
/// (was `crate::control::LbIpBytes`); re-exported from there for call-site compatibility.
pub enum LbIpBytes {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

/// LB IP address stored in the shadow state (IPv4 or IPv6). Moved out of `control/mod.rs`.
#[derive(Clone)]
pub enum LbIp {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl LbIp {
    /// Return the last 4 bytes of the address for underlay derivation.
    pub fn last4(&self) -> [u8; 4] {
        match self {
            LbIp::Ipv4(ip) => *ip,
            LbIp::Ipv6(ip) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&ip[12..16]);
                b
            }
        }
    }
}

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `ControlCore.lbs` by the LB's id.
/// Moved verbatim out of `control/mod.rs`; the NAT preferred-underlay collision check
/// reads `lb_underlay`.
pub struct LbEntry {
    pub vni: u32,
    pub ip: LbIp,
    pub lb_underlay: [u8; 16],
    pub ports: Vec<(u16, u8)>,
    pub table_id: u32,
    pub backends: Vec<flowplane_common::LbBackend>,
}
