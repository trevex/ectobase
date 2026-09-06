//! Maglev consistent-hashing lookup-table builder (backend-agnostic).
//!
//! Moved verbatim out of the eBPF `flowplane/src/maglev.rs`; it is pure (std-only, no
//! aya deps) so it lives here and is called by `ControlCore`'s LB programming.
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

/// Build a Maglev lookup table of size `TABLE_SIZE` over `backends`, each hashed by its UNIQUE
/// overlay IP (`LbBackend.overlay_ip`) so two backends sharing a node get distinct distributions.
/// Returns `table[slot] = backend_index`. Empty backends -> empty vec.
pub fn build(backends: &[flowplane_common::LbBackend]) -> Vec<u32> {
    let n = backends.len();
    let m = TABLE_SIZE as usize;
    if n == 0 {
        return Vec::new();
    }
    // permutation parameters per backend
    let mut offset = vec![0usize; n];
    let mut skip = vec![0usize; n];
    for (i, b) in backends.iter().enumerate() {
        offset[i] = (fnv1a(&b.overlay_ip, 1) % m as u64) as usize;
        skip[i] = (fnv1a(&b.overlay_ip, 2) % (m as u64 - 1) + 1) as usize;
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

    /// Wrap a raw 16-byte value (what `build` used to hash directly) into an `LbBackend` whose
    /// `overlay_ip` carries those SAME bytes, so hashing on `overlay_ip` reproduces the exact
    /// pre-`LbBackend` distribution these tests assert on.
    fn backend_from_bytes(bytes: [u8; 16]) -> flowplane_common::LbBackend {
        flowplane_common::LbBackend {
            node_vtep: bytes,
            overlay_ip: bytes,
            vni: 0,
            is_v6: 0,
            _pad: [0; 3],
        }
    }

    #[test]
    fn distributes_evenly_across_two_backends() {
        let b0: [u8; 16] = [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b1: [u8; 16] = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let table = build(&[backend_from_bytes(b0), backend_from_bytes(b1)]);
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
        let a = build(&[backend_from_bytes(b0), backend_from_bytes(b1)]);
        let b = build(&[backend_from_bytes(b0), backend_from_bytes(b1)]);
        assert_eq!(a, b);
    }

    #[test]
    fn build_distinguishes_same_node_backends_by_overlay() {
        use flowplane_common::LbBackend;
        let node: [u8; 16] = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
        let be = |last: u8| LbBackend {
            node_vtep: node, // SAME node for both
            overlay_ip: [10, 0, 0, last, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        let backends = vec![be(61), be(62)];
        let table = build(&backends);
        assert_eq!(table.len(), TABLE_SIZE as usize);
        let n0 = table.iter().filter(|&&i| i == 0).count();
        let n1 = table.iter().filter(|&&i| i == 1).count();
        assert!(
            n0 > 0 && n1 > 0,
            "both same-node backends must get slots (n0={n0}, n1={n1})"
        );
    }
}
