//! Port-range decomposition shared by the firewall classifier and the NAT owner tries: an LPM trie
//! keyed on a big-endian port matches a range as a set of aligned prefixes.

/// Split the inclusive 16-bit range `lo..=hi` into the fewest `(value, prefix_bits)` pairs whose
/// union is exactly the range: each covers the `2^(16 - bits)` values sharing `value`'s top `bits`.
/// `0..=65535` is the single pair `(0, 0)`. At most 30 pairs (2 × 16 − 2).
pub fn port_prefixes(lo: u16, hi: u16) -> Vec<(u16, u8)> {
    let mut out = Vec::new();
    let (mut lo, hi) = (lo as u32, hi as u32);
    while lo <= hi {
        // The largest block starting at `lo` that is aligned and stays within `hi`.
        let mut size = if lo == 0 {
            1u32 << 16
        } else {
            lo & lo.wrapping_neg()
        };
        while lo + size - 1 > hi {
            size >>= 1;
        }
        out.push((lo as u16, 16 - size.trailing_zeros() as u8));
        lo += size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expand prefix pairs back into the set of ports they cover.
    fn covered(pairs: &[(u16, u8)]) -> Vec<u16> {
        let mut v: Vec<u16> = pairs
            .iter()
            .flat_map(|&(value, bits)| {
                let span = 1u32 << (16 - bits);
                (0..span).map(move |i| (value as u32 + i) as u16)
            })
            .collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn port_prefixes_cover_exactly_the_range() {
        for (lo, hi) in [
            (0u16, 65535u16),
            (443, 443),
            (0, 1023),
            (1024, 2047),
            (1, 65534),
            (1000, 2000),
            (65535, 65535),
            (8000, 8100),
        ] {
            let pairs = port_prefixes(lo, hi);
            assert_eq!(
                covered(&pairs),
                (lo..=hi).collect::<Vec<_>>(),
                "{lo}..={hi}"
            );
            assert!(pairs.len() <= 30, "{lo}..={hi}: {} pairs", pairs.len());
            for &(value, bits) in &pairs {
                let low_bits = 16 - bits as u32;
                assert_eq!(
                    value as u32 & ((1u32 << low_bits) - 1),
                    0,
                    "unaligned {value}/{bits}"
                );
            }
        }
    }

    #[test]
    fn port_prefixes_are_minimal_for_aligned_blocks() {
        assert_eq!(port_prefixes(0, 65535), vec![(0, 0)]);
        assert_eq!(port_prefixes(0, 1023), vec![(0, 6)]);
        assert_eq!(port_prefixes(1024, 2047), vec![(1024, 6)]);
        assert_eq!(port_prefixes(443, 443), vec![(443, 16)]);
        assert_eq!(port_prefixes(1, 65534).len(), 30, "the worst case");
    }
}
