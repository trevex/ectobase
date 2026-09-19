//! A neighbor-NAT block as the `NAT_OWNERS{,6}` trie entries that store it, and the errors
//! programming one can refuse with.

use core::fmt;

use crate::ports::port_prefixes;
use flowplane_common::{
    NatOwner, NatOwnerKey, NatOwnerKey6, NeighborNat6Entry, NeighborNatEntry, NAT_OWNER_ADDR_BITS4,
    NAT_OWNER_ADDR_BITS6,
};

/// The trie entries `(prefix_len, key, owner)` that store block `b`: one per aligned port prefix of
/// `[port_min, port_max)`. Empty for an empty range. `enabled` is not consulted: a written block is
/// live.
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
            NeighborNatError::EmptyRange => {
                f.write_str("neighbor NAT block has an empty port range")
            }
            // The "ALREADY_EXISTS:" prefix predates the typed error and stays in the status
            // message clients see.
            NeighborNatError::Overlap => f.write_str(
                "ALREADY_EXISTS: neighbor NAT block overlaps an existing block on this nat_ip",
            ),
            NeighborNatError::Full { needed, max } => write!(
                f,
                "neighbor NAT table full: {needed} prefixes needed and the table holds at most \
                 {max} per family"
            ),
            NeighborNatError::Map(e) => write!(f, "{e:#}"),
        }
    }
}

// No source(): Display already renders the anyhow chain, so a chain-walking reporter would print
// it twice.
impl std::error::Error for NeighborNatError {}

impl From<anyhow::Error> for NeighborNatError {
    fn from(e: anyhow::Error) -> Self {
        NeighborNatError::Map(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAT_IP: [u8; 4] = [203, 0, 113, 9];
    const NAT_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    const UNDERLAY: [u8; 16] = [7; 16];

    // Aligned, mid-range, odd-width and single-port blocks; the 30-prefix worst case [1, 65535);
    // and both ends of the space: a block from port 0, and one ending at 65534, the highest port
    // a half-open u16 block can hold.
    const RANGES: [(u16, u16); 7] = [
        (20000, 30000),
        (1, 65535),
        (5, 6),
        (1024, 1524),
        (65534, 65535),
        (0, 65535),
        (1024, 2048),
    ];

    fn block(port_min: u16, port_max: u16) -> NeighborNatEntry {
        NeighborNatEntry {
            underlay: UNDERLAY,
            nat_ip: NAT_IP,
            vni: 42,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    fn block6(port_min: u16, port_max: u16) -> NeighborNat6Entry {
        NeighborNat6Entry {
            underlay: UNDERLAY,
            nat_ip6: NAT_IP6,
            vni: 42,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    fn want_owner(port_min: u16, port_max: u16) -> NatOwner {
        NatOwner {
            underlay: UNDERLAY,
            vni: 42,
            port_min,
            port_max,
        }
    }

    /// True if a `port_bits`-bit port prefix `key_port` covers `port`.
    fn covers(port_bits: u32, key_port: [u8; 2], port: u16) -> bool {
        let mask = u16::MAX.checked_shl(16 - port_bits).unwrap_or(0);
        port & mask == u16::from_be_bytes(key_port) & mask
    }

    /// Assert that `(prefix_len, port_bytes)` pairs — stripped of the address part `entries` came
    /// with, at `addr_bits` — cover exactly `[lo, hi)`: every port in range covered once, every
    /// port outside it not at all. Shared by both families.
    fn assert_exact_coverage(entries: &[(u32, [u8; 2])], addr_bits: u32, lo: u16, hi: u16) {
        assert!(
            entries.len() <= 30,
            "{lo}..{hi}: {} prefixes",
            entries.len()
        );
        for port in 0..=u16::MAX {
            let n = entries
                .iter()
                .filter(|&&(plen, key_port)| covers(plen - addr_bits, key_port, port))
                .count();
            assert_eq!(
                n,
                usize::from(port >= lo && port < hi),
                "{lo}..{hi}: port {port} covered {n} times"
            );
        }
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
                nat_ip: NAT_IP,
                port: 1024u16.to_be_bytes()
            }
        );
        assert_eq!(owner, want_owner(1024, 2048));
    }

    // The entries cover exactly [port_min, port_max): every port of the range once, nothing else,
    // every entry keyed on the block's nat_ip and carrying its full owner.
    #[test]
    fn an_arbitrary_block_covers_exactly_its_range() {
        for (lo, hi) in RANGES {
            let want = want_owner(lo, hi);
            let e = owner_prefixes4(&block(lo, hi));
            assert!(
                e.iter().all(|&(_, k, o)| k.nat_ip == NAT_IP && o == want),
                "{lo}..{hi}: wrong nat_ip or owner"
            );
            let ports: Vec<(u32, [u8; 2])> = e.iter().map(|&(p, k, _)| (p, k.port)).collect();
            assert_exact_coverage(&ports, NAT_OWNER_ADDR_BITS4, lo, hi);
        }
    }

    #[test]
    fn a_v6_block_covers_exactly_its_range() {
        for (lo, hi) in RANGES {
            let want = want_owner(lo, hi);
            let e = owner_prefixes6(&block6(lo, hi));
            assert!(
                e.iter().all(|&(_, k, o)| k.nat_ip6 == NAT_IP6 && o == want),
                "{lo}..{hi}: wrong nat_ip6 or owner"
            );
            let ports: Vec<(u32, [u8; 2])> = e.iter().map(|&(p, k, _)| (p, k.port)).collect();
            assert_exact_coverage(&ports, NAT_OWNER_ADDR_BITS6, lo, hi);
        }
    }

    #[test]
    fn an_empty_block_has_no_entries() {
        assert!(owner_prefixes4(&block(3000, 3000)).is_empty());
        assert!(owner_prefixes4(&block(3000, 2000)).is_empty());
        // The guard's real boundary: port_max == 0 underflows `port_max - 1` unless caught first.
        assert!(owner_prefixes4(&block(0, 0)).is_empty());
        assert!(owner_prefixes6(&block6(0, 0)).is_empty());
    }
}
