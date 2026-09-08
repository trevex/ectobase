//! Route map key & value types (the `ROUTES` / `ROUTES6` LPM-trie maps).

/// Key for the `routes` map: (VNI, IPv4 prefix). Host-order length in `prefix_len`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    pub vni: u32,
    pub prefix_len: u32,
    pub ipv4: [u8; 4],
}

/// LPM-trie key data for `ROUTES`: VNI (big-endian, matched MSB-first as a fixed 32-bit VRF
/// discriminator) followed by the IPv4 octets (network order, variable prefix).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData {
    pub vni: [u8; 4],
    pub ipv4: [u8; 4],
}

/// LPM-trie key data for `ROUTES6`: VNI (big-endian) + IPv6 (network order, variable prefix).
/// prefix_len = 32 + v6_prefix_len; lookups use prefix_len = 160.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData6 {
    pub vni: [u8; 4],
    pub ipv6: [u8; 16],
}

/// Value for the `routes` map: the underlay IPv6 nexthop (tunnel dst). MAC-free — the outer
/// L2 next-hop is the single underlay gateway in `Local`, not per-route.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
    /// 1 = the nexthop is the external/public network (NAT-eligible egress); 0 = overlay peer.
    pub is_external: u8,
    pub _pad: [u8; 3],
}

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for RouteKey {}
    unsafe impl aya::Pod for RouteLpmData {}
    unsafe impl aya::Pod for RouteLpmData6 {}
    unsafe impl aya::Pod for RouteValue {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn route_lpm_keys_are_word_packed() {
        // total size == sum of field sizes (no hidden hole).
        assert_eq!(size_of::<RouteLpmData>(), 4 + 4);
        assert_eq!(size_of::<RouteLpmData6>(), 4 + 16);
    }

    #[test]
    fn route_types_have_stable_layout() {
        // 4 (vni) + 4 (prefix_len) + 4 (ipv4) = 12.
        // 4 (nexthop_vni) + 16 (ipv6) + 1 (is_external) + 3 (_pad) = 24.
        assert_eq!(size_of::<RouteKey>(), 12);
        assert_eq!(size_of::<RouteValue>(), 24);
        // LPM key data: 4 (vni be) + 4 (ipv4) = 8.
        assert_eq!(size_of::<RouteLpmData>(), 8);
        // LPM key data v6: 4 (vni be) + 16 (ipv6) = 20.
        assert_eq!(size_of::<RouteLpmData6>(), 20);
    }
}
