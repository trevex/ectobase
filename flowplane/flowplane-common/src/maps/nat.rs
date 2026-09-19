//! NAT / NAT66 config map key & value types plus the neighbor-NAT entries (the `NAT_CONFIG`,
//! `NAT_CONFIG6`, `NAT_OWNERS`, `NAT_OWNERS6` maps).

/// NAT-GW config key: (vni, local guest IPv4).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// NAT-GW config value: the public NAT IPv4 + the source-port range [port_min, port_max).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NatValue {
    pub nat_ipv4: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// NAT66 config key: (vni, local guest IPv6). v6 sibling of [`NatKey`].
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatKey6 {
    pub vni: u32,
    pub ipv6: [u8; 16],
}

/// NAT66 config value: the public NAT IPv6 + the source-port range [port_min, port_max). v6 sibling
/// of [`NatValue`].
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NatValue6 {
    pub nat_ipv6: [u8; 16],
    pub port_min: u16,
    pub port_max: u16,
}

/// `NAT_OWNERS` trie key data (after the LPM trie's 4-byte prefix length): a nat_ip and a
/// destination port, big-endian so a prefix masks the port's high bits. A neighbor-NAT block
/// `[port_min, port_max)` is stored as the fewest aligned port prefixes covering it; the prefix
/// length is [`NAT_OWNER_ADDR_BITS4`] + the port prefix bits.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatOwnerKey {
    pub nat_ip: [u8; 4],
    pub port: [u8; 2],
}

/// IPv6 sibling of [`NatOwnerKey`] (`NAT_OWNERS6`); prefix length [`NAT_OWNER_ADDR_BITS6`] + port bits.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatOwnerKey6 {
    pub nat_ip6: [u8; 16],
    pub port: [u8; 2],
}

/// The node owning the NAT port block a `NAT_OWNERS{,6}` prefix belongs to — its underlay /128 and
/// the block's VNI — and the block itself (`[port_min, port_max)`), so the dataplane can rebuild
/// its block list from the pinned trie after a restart.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NatOwner {
    pub underlay: [u8; 16],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
}

/// Prefixes each `NAT_OWNERS{,6}` trie holds. A default 1024-port block starting on a multiple of
/// 1024 is one prefix; an arbitrary range is at most 30.
pub const NAT_OWNERS_MAX: u32 = 65536;
/// Prefix bits of the address part of a [`NatOwnerKey`] / [`NatOwnerKey6`].
pub const NAT_OWNER_ADDR_BITS4: u32 = 32;
pub const NAT_OWNER_ADDR_BITS6: u32 = 128;

/// A neighbor-NAT block: a remote node owns `(vni, nat_ip, [port_min, port_max))`; return traffic
/// to that nat_ip:port is re-forwarded to `underlay`. Stored in the datapath as `NAT_OWNERS`
/// prefixes (see [`NatOwnerKey`]).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NeighborNatEntry {
    pub underlay: [u8; 16],
    pub nat_ip: [u8; 4],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

/// A neighbor-NAT block: v6 sibling of [`NeighborNatEntry`]. A remote node owns
/// `(vni, nat_ip6, [port_min, port_max))`; return traffic to that nat_ip6:port is re-forwarded to
/// `underlay`. Stored in the datapath as `NAT_OWNERS6` prefixes (see [`NatOwnerKey6`]).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NeighborNat6Entry {
    pub underlay: [u8; 16],
    pub nat_ip6: [u8; 16],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for NatKey {}
    unsafe impl aya::Pod for NatValue {}
    unsafe impl aya::Pod for NatKey6 {}
    unsafe impl aya::Pod for NatValue6 {}
    unsafe impl aya::Pod for NatOwnerKey {}
    unsafe impl aya::Pod for NatOwnerKey6 {}
    unsafe impl aya::Pod for NatOwner {}
    unsafe impl aya::Pod for NeighborNatEntry {}
    unsafe impl aya::Pod for NeighborNat6Entry {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn nat_key_word_packed() {
        assert_eq!(size_of::<NatKey>(), 4 + 4);
    }

    #[test]
    fn nat_layouts() {
        assert_eq!(size_of::<NatKey>(), 8);
        assert_eq!(size_of::<NatValue>(), 8);
    }

    #[test]
    fn nat6_layouts() {
        assert_eq!(size_of::<NatKey6>(), 20); // 4 + 16
        assert_eq!(size_of::<NatValue6>(), 20); // 16 + 2 + 2
        assert_eq!(size_of::<NeighborNat6Entry>(), 44); // 16 + 16 + 4 + 2 + 2 + 1 + 3
    }

    #[test]
    fn neighbor_nat_entry_layout() {
        // 16 (underlay) + 4 (nat_ip) + 4 (vni) + 2 (port_min) + 2 (port_max)
        // + 1 (enabled) + 3 (_pad) = 32.
        assert_eq!(size_of::<NeighborNatEntry>(), 32);
        assert_eq!(align_of::<NeighborNatEntry>(), 4);
    }

    #[test]
    fn nat_owner_layouts() {
        // NatOwnerKey: 4 (nat_ip) + 2 (port); the trie key is 4 (prefix length) + 6.
        assert_eq!(size_of::<NatOwnerKey>(), 6);
        assert_eq!(align_of::<NatOwnerKey>(), 1);
        assert_eq!(offset_of!(NatOwnerKey, nat_ip), 0);
        assert_eq!(offset_of!(NatOwnerKey, port), 4);

        // NatOwnerKey6: 16 (nat_ip6) + 2 (port).
        assert_eq!(size_of::<NatOwnerKey6>(), 18);
        assert_eq!(align_of::<NatOwnerKey6>(), 1);
        assert_eq!(offset_of!(NatOwnerKey6, nat_ip6), 0);
        assert_eq!(offset_of!(NatOwnerKey6, port), 16);

        // NatOwner: 16 (underlay) + 4 (vni) + 2 (port_min) + 2 (port_max) = 24.
        assert_eq!(size_of::<NatOwner>(), 24);
        assert_eq!(align_of::<NatOwner>(), 4);
        assert_eq!(offset_of!(NatOwner, underlay), 0);
        assert_eq!(offset_of!(NatOwner, vni), 16);
        assert_eq!(offset_of!(NatOwner, port_min), 20);
        assert_eq!(offset_of!(NatOwner, port_max), 22);
    }
}
