//! A neighbor-NAT block as the `NAT_OWNERS{,6}` trie entries that store it, and the errors
//! programming one can refuse with.

use core::fmt;

use crate::ports::port_prefixes;
use flowplane_common::{
    NatOwner, NatOwnerKey, NatOwnerKey6, NeighborNat6Entry, NeighborNatEntry, NAT_OWNER_ADDR_BITS4,
    NAT_OWNER_ADDR_BITS6,
};

/// The trie entries `(prefix_len, key, owner)` that store block `b`: one per aligned port prefix of
/// `[port_min, port_max)`. Empty for an empty range.
pub fn owner_prefixes4(b: &NeighborNatEntry) -> Vec<(u32, NatOwnerKey, NatOwner)> {
    if b.port_min >= b.port_max {
        return Vec::new();
    }
    let owner = NatOwner {
        underlay: b.underlay,
        vni: b.vni,
        port_min: b.port_min,
        port_max: b.port_max,
    };
    port_prefixes(b.port_min, b.port_max - 1)
        .into_iter()
        .map(|(port, bits)| {
            let key = NatOwnerKey {
                nat_ip: b.nat_ip,
                port: port.to_be_bytes(),
            };
            (NAT_OWNER_ADDR_BITS4 + u32::from(bits), key, owner)
        })
        .collect()
}

/// IPv6 sibling of [`owner_prefixes4`].
pub fn owner_prefixes6(b: &NeighborNat6Entry) -> Vec<(u32, NatOwnerKey6, NatOwner)> {
    if b.port_min >= b.port_max {
        return Vec::new();
    }
    let owner = NatOwner {
        underlay: b.underlay,
        vni: b.vni,
        port_min: b.port_min,
        port_max: b.port_max,
    };
    port_prefixes(b.port_min, b.port_max - 1)
        .into_iter()
        .map(|(port, bits)| {
            let key = NatOwnerKey6 {
                nat_ip6: b.nat_ip6,
                port: port.to_be_bytes(),
            };
            (NAT_OWNER_ADDR_BITS6 + u32::from(bits), key, owner)
        })
        .collect()
}

/// A neighbor-NAT programming failure, classified for the gRPC layer.
#[derive(Debug)]
pub enum NeighborNatError {
    /// `port_min >= port_max`: the block holds no port.
    EmptyRange,
    /// The block overlaps another block on the same nat_ip (in any VNI).
    Overlap,
    /// The family's trie cannot take the block's prefixes.
    Full { needed: usize, max: u32 },
    /// Programming the maps failed.
    Map(anyhow::Error),
}

impl fmt::Display for NeighborNatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NeighborNatError::EmptyRange => f.write_str("neighbor NAT block has an empty port range"),
            // The "ALREADY_EXISTS:" prefix predates this type; callers grep for it.
            NeighborNatError::Overlap => f.write_str(
                "ALREADY_EXISTS: neighbor NAT block overlaps an existing block on this nat_ip",
            ),
            NeighborNatError::Full { needed, max } => write!(
                f,
                "neighbor NAT table full: the block needs {needed} more prefixes (max {max} per family)"
            ),
            NeighborNatError::Map(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for NeighborNatError {}

impl From<anyhow::Error> for NeighborNatError {
    fn from(e: anyhow::Error) -> Self {
        NeighborNatError::Map(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_common::{NeighborNatEntry, NAT_OWNER_ADDR_BITS4};

    fn block(port_min: u16, port_max: u16) -> NeighborNatEntry {
        NeighborNatEntry {
            underlay: [7; 16],
            nat_ip: [203, 0, 113, 9],
            vni: 42,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    /// True if trie entry `(plen, key)` covers `port` of the block's nat_ip.
    fn covers(plen: u32, key: &NatOwnerKey, port: u16) -> bool {
        let bits = plen - NAT_OWNER_ADDR_BITS4;
        let mask = if bits == 0 {
            0
        } else {
            u16::MAX << (16 - bits)
        };
        port & mask == u16::from_be_bytes(key.port) & mask
    }

    #[test]
    fn an_aligned_block_is_one_prefix() {
        let e = owner_prefixes4(&block(1024, 2048));
        assert_eq!(e.len(), 1);
        let (plen, key, owner) = e[0];
        assert_eq!(plen, NAT_OWNER_ADDR_BITS4 + 6);
        assert_eq!(
            key,
            NatOwnerKey {
                nat_ip: [203, 0, 113, 9],
                port: 1024u16.to_be_bytes()
            }
        );
        assert_eq!(
            (owner.vni, owner.port_min, owner.port_max),
            (42, 1024, 2048)
        );
    }

    // The entries cover exactly [port_min, port_max): every port of the range once, nothing else.
    #[test]
    fn an_arbitrary_block_covers_exactly_its_range() {
        for (lo, hi) in [
            (20000, 30000),
            (1, 65535),
            (5, 6),
            (1024, 1524),
            (65534, 65535),
        ] {
            let e = owner_prefixes4(&block(lo, hi));
            assert!(e.len() <= 30, "{lo}..{hi}: {} prefixes", e.len());
            for port in 0..=u16::MAX {
                let n = e.iter().filter(|(p, k, _)| covers(*p, k, port)).count();
                let want = usize::from(port >= lo && port < hi);
                assert_eq!(n, want, "{lo}..{hi}: port {port} covered {n} times");
            }
        }
    }

    #[test]
    fn an_empty_block_has_no_entries() {
        assert!(owner_prefixes4(&block(3000, 3000)).is_empty());
        assert!(owner_prefixes4(&block(3000, 2000)).is_empty());
    }

    #[test]
    fn a_v6_block_covers_exactly_its_range() {
        use flowplane_common::{NeighborNat6Entry, NAT_OWNER_ADDR_BITS6};
        let ip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        for (lo, hi) in [(20000, 30000), (1, 65535), (1024, 2048)] {
            let e = owner_prefixes6(&NeighborNat6Entry {
                underlay: [7; 16],
                nat_ip6: ip,
                vni: 42,
                port_min: lo,
                port_max: hi,
                enabled: 1,
                _pad: [0; 3],
            });
            for port in 0..=u16::MAX {
                let n = e
                    .iter()
                    .filter(|(p, k, _)| {
                        assert_eq!(k.nat_ip6, ip);
                        let bits = *p - NAT_OWNER_ADDR_BITS6;
                        let mask = if bits == 0 {
                            0
                        } else {
                            u16::MAX << (16 - bits)
                        };
                        port & mask == u16::from_be_bytes(k.port) & mask
                    })
                    .count();
                assert_eq!(
                    n,
                    usize::from(port >= lo && port < hi),
                    "{lo}..{hi}: port {port}"
                );
            }
        }
    }
}
