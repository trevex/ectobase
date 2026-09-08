//! NAT / NAT66 config map key & value types plus the neighbor-NAT entries (the `NAT_CONFIG`,
//! `NAT_CONFIG6`, `NEIGHBOR_NAT`, `NEIGHBOR_NAT6` maps).

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

/// Maximum number of neighbor-NAT entries the datapath will scan.
pub const NB_MAX_ENTRIES: u32 = 64;

/// A neighbor-NAT entry: a remote node owns `(vni, nat_ip, [port_min, port_max))`; return traffic
/// to that nat_ip:port is re-forwarded to `underlay`. `enabled` 1 = slot in use.
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

/// A NAT66 neighbor-NAT entry: v6 sibling of [`NeighborNatEntry`]. A remote node owns
/// `(vni, nat_ip6, [port_min, port_max))`; return traffic to that nat_ip6:port is re-forwarded to
/// `underlay`. `enabled` 1 = slot in use.
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
    unsafe impl aya::Pod for NeighborNatEntry {}
    unsafe impl aya::Pod for NeighborNat6Entry {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

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
}
