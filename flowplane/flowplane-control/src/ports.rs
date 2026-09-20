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

/// How many pairs [`port_prefixes`] would return for `lo..=hi`, without building them: the
/// capacity check of a whole block set needs the count and nothing else.
pub fn port_prefix_count(lo: u16, hi: u16) -> usize {
    let (mut lo, hi) = (lo as u32, hi as u32);
    let mut n = 0;
    while lo <= hi {
        let mut size = if lo == 0 {
            1u32 << 16
        } else {
            lo & lo.wrapping_neg()
        };
        while lo + size - 1 > hi {
            size >>= 1;
        }
        n += 1;
        lo += size;
    }
    n
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

    // The count has to agree with the decomposition everywhere, including the shapes that make
    // port_prefixes split most: it is what the capacity check trusts instead of allocating.
    #[test]
    fn the_count_matches_the_decomposition() {
        for (lo, hi) in [
            (0u16, 65535u16),
            (1, 65535),
            (1024, 2047),
            (20000, 29999),
            (5, 5),
            (65534, 65535),
        ] {
            assert_eq!(
                port_prefix_count(lo, hi),
                port_prefixes(lo, hi).len(),
                "{lo}..={hi}"
            );
        }
        // A deterministic sweep: every range starting below 300, and every range ending above
        // 65300, plus a stride across the middle — enough shapes that an off-by-one shows up.
        for lo in 0..300u16 {
            for hi in [lo, lo + 1, lo + 7, 40000, 65535] {
                if hi >= lo {
                    assert_eq!(
                        port_prefix_count(lo, hi),
                        port_prefixes(lo, hi).len(),
                        "{lo}..={hi}"
                    );
                }
            }
        }
        for lo in 65300..=65535u16 {
            assert_eq!(
                port_prefix_count(lo, 65535),
                port_prefixes(lo, 65535).len(),
                "{lo}..=65535"
            );
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
