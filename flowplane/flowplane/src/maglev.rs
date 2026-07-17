//! Maglev consistent-hashing lookup-table builder (userspace).
pub const TABLE_SIZE: u32 = 1021; // prime

/// A tiny FNV-1a over bytes (stable, no external deps), used for offset/skip seeds.
fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build a Maglev lookup table of size `TABLE_SIZE` over `backends` (each identified by its
/// 16-byte underlay IPv6). Returns `table[slot] = backend_index`. Empty backends -> empty vec.
pub fn build(backends: &[[u8; 16]]) -> Vec<u32> {
    let n = backends.len();
    let m = TABLE_SIZE as usize;
    if n == 0 {
        return Vec::new();
    }
    // permutation parameters per backend
    let mut offset = vec![0usize; n];
    let mut skip = vec![0usize; n];
    for (i, b) in backends.iter().enumerate() {
        offset[i] = (fnv1a(b, 1) % m as u64) as usize;
        skip[i] = (fnv1a(b, 2) % (m as u64 - 1) + 1) as usize;
    }
    let mut next = vec![0usize; n];
    let mut table = vec![u32::MAX; m];
    let mut filled = 0usize;
    while filled < m {
        for i in 0..n {
            let mut c = (offset[i] + next[i] * skip[i]) % m;
            while table[c] != u32::MAX {
                next[i] += 1;
                c = (offset[i] + next[i] * skip[i]) % m;
            }
            table[c] = i as u32;
            next[i] += 1;
            filled += 1;
            if filled == m {
                break;
            }
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributes_evenly_across_two_backends() {
        let b0: [u8; 16] = [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b1: [u8; 16] = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let table = build(&[b0, b1]);
        assert_eq!(table.len(), TABLE_SIZE as usize);
        let c0 = table.iter().filter(|&&x| x == 0).count();
        let c1 = table.iter().filter(|&&x| x == 1).count();
        // each backend should get within ~5% of half the slots
        let half = TABLE_SIZE as usize / 2;
        assert!(
            (c0 as i64 - half as i64).abs() < (TABLE_SIZE as i64 / 20),
            "c0={c0}"
        );
        assert!(
            (c1 as i64 - half as i64).abs() < (TABLE_SIZE as i64 / 20),
            "c1={c1}"
        );
        assert_eq!(c0 + c1, TABLE_SIZE as usize); // no MAX left
    }

    #[test]
    fn deterministic() {
        let b0: [u8; 16] = [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b1: [u8; 16] = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let a = build(&[b0, b1]);
        let b = build(&[b0, b1]);
        assert_eq!(a, b);
    }
}
