//! Shared xorshift64* PRNG for the sim's differential/property tests (e.g. `fw_classify_diff_test`,
//! `neighbor_nat_test`): one algorithm, so a fixed seed reproduces the same case everywhere.

/// xorshift64*: deterministic, dependency-free.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}
