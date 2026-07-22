//! Symmetric-Toeplitz RSS: a symmetric key (0x6d5a repeated) for which Toeplitz(A‖B) == Toeplitz(B‖A),
//! so both directions of a flow hash to the same queue → the same lcore. This is what makes the
//! per-lcore conntrack/nat state correct (a flow's reply lands on the lcore that created its CT).
//! `Port::configure` programs this key; the HW spreading needs a real NIC (deferred), but the KEY's
//! symmetry property is verified in software here.

/// The canonical symmetric RSS key (Woo & Park): 40 bytes of the 2-byte period `0x6d 0x5a`.
pub const SYMMETRIC_RSS_KEY: [u8; 40] = {
    let mut k = [0u8; 40];
    let mut i = 0;
    while i < 40 {
        k[i] = if i % 2 == 0 { 0x6d } else { 0x5a };
        i += 1;
    }
    k
};

/// Software Toeplitz RSS hash (matches the NIC's `rte_softrss`): for each set bit of `input` (MSB
/// first), XOR in the 32-bit window of `key` starting at that bit position.
#[must_use]
pub fn toeplitz_softrss(input: &[u8], key: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for (i, &byte) in input.iter().enumerate() {
        for b in 0..8u32 {
            if byte & (0x80 >> b) != 0 {
                let bitpos = i as u32 * 8 + b;
                let mut window: u32 = 0;
                for j in 0..32u32 {
                    let kb = bitpos + j;
                    let bit = (key[(kb / 8) as usize] >> (7 - (kb % 8))) & 1;
                    window = (window << 1) | u32::from(bit);
                }
                result ^= window;
            }
        }
    }
    result
}

/// Map an RSS hash to a queue index (NIC uses the low bits of the redirection table; for our test we
/// use the modulo, which preserves the symmetry property).
#[must_use]
pub fn rss_queue(hash: u32, n_queues: u16) -> u16 {
    (hash % u32::from(n_queues.max(1))) as u16
}
