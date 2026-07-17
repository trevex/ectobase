//! Re-export the host-tested incremental checksum helper for use in XDP programs.
pub use flowplane_common::csum::csum_replace4;

/// Incrementally fold a 16-bit field change (network-order `old`/`new`) into an L4/ICMP
/// checksum by reusing `csum_replace4` with the upper 2 bytes zeroed in both arguments.
#[inline(always)]
pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let o = old.to_be_bytes();
    let n = new.to_be_bytes();
    csum_replace4(check, &[o[0], o[1], 0, 0], &[n[0], n[1], 0, 0])
}
