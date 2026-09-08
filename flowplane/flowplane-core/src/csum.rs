//! RFC 1071 one's-complement checksum primitives, shared by the native datapath ports
//! (`arp_nd`, `dhcp`, `nat64`).
//!
//! These are the two building blocks the responders/translators reimplemented independently: fold a
//! 32-bit accumulator into a 16-bit checksum, and accumulate one big-endian 16-bit word. They are
//! byte-identical to the previous per-module copies (`csum16`'s fold, `nat64::csum_fold`,
//! `dhcp::csum_add`, `nat64::csum_add16`). The related incremental `csum_replace2/4/16` helpers live
//! in `flowplane_common::csum` / `conntrack`.

/// Fold a 32-bit accumulated one's-complement sum into a 16-bit checksum. Two fold rounds suffice
/// for any 32-bit accumulator (the BPF verifier requires bounded loops).
#[inline(always)]
pub(crate) fn fold(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Accumulate one big-endian 16-bit word (`hi`, `lo`) into a one's-complement sum.
#[inline(always)]
pub(crate) fn add_be16(sum: u32, hi: u8, lo: u8) -> u32 {
    sum.wrapping_add(((hi as u32) << 8) | lo as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_be16_accumulates_big_endian() {
        // 0x1234 then 0xabcd -> 0x1234 + 0xabcd = 0xbe01.
        let s = add_be16(0, 0x12, 0x34);
        assert_eq!(s, 0x1234);
        let s = add_be16(s, 0xab, 0xcd);
        assert_eq!(s, 0x1234 + 0xabcd);
    }

    #[test]
    fn fold_wraps_carries_and_complements() {
        // Two 16-bit words summed then folded; RFC1071 checksum of [0x0001, 0xf203, 0xf4f5].
        let mut s = 0u32;
        s = add_be16(s, 0x00, 0x01);
        s = add_be16(s, 0xf2, 0x03);
        s = add_be16(s, 0xf4, 0xf5);
        // sum = 0x0001 + 0xf203 + 0xf4f5 = 0x1e6f9; fold -> 0xe6fa; !0xe6fa = 0x1905.
        assert_eq!(fold(s), 0x1905);
    }

    #[test]
    fn fold_handles_carry_out_of_16_bits() {
        // sum with a carry: 0xffff + 0x0003 = 0x10002 -> fold -> 0x0003 -> !0x0003 = 0xfffc.
        let s = 0xffffu32 + 0x0003;
        assert_eq!(fold(s), 0xfffc);
    }

    #[test]
    fn fold_all_ones_is_zero() {
        // A fully-set 16-bit sum folds/complements to 0 (RFC1071 -0 == +0 boundary).
        assert_eq!(fold(0xffff), 0x0000);
    }
}
