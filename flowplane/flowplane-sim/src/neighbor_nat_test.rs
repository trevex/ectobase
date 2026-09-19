//! Neighbor-NAT owners as the dataplane stores them: `NAT_OWNERS{,6}` tries keyed
//! `[nat_ip ++ port]`, seeded from blocks through the dataplane's own decomposition
//! (`MemMaps::add_neighbor_nat{,6}`). The lookups are the shared core ones the eBPF runs.

use crate::MemMaps;
use flowplane_common::{NeighborNat6Entry, NeighborNatEntry};
use flowplane_core::maps::Maps;
use flowplane_core::nat::{neighbor_nat_owner, neighbor_nat_owner6};

fn block(nat_ip: [u8; 4], vni: u32, lo: u16, hi: u16, owner: u8) -> NeighborNatEntry {
    NeighborNatEntry {
        underlay: [owner; 16],
        nat_ip,
        vni,
        port_min: lo,
        port_max: hi,
        enabled: 1,
        _pad: [0; 3],
    }
}

// The old table held 64 blocks fleet-wide. A thousand now resolve, each to its own block (a
// distinct VNI per block makes a neighbour's answer visible), at every edge of every block.
#[test]
fn a_thousand_blocks_all_resolve() {
    let mut m = MemMaps::default();
    let mut blocks = Vec::new();
    for ip in 0..10u8 {
        for i in 0..100u16 {
            let lo = 1024 + i * 500; // 500-port blocks: not aligned, several prefixes each
            let b = block(
                [203, 0, 113, ip],
                u32::from(ip) * 1000 + u32::from(i),
                lo,
                lo + 500,
                ip + 1,
            );
            m.add_neighbor_nat(b);
            blocks.push(b);
        }
    }
    for b in &blocks {
        for port in [b.port_min, b.port_min + 250, b.port_max - 1] {
            let o = m.nat_owner(&b.nat_ip, port).expect("owned port");
            assert_eq!(
                (o.underlay, o.vni),
                (b.underlay, b.vni),
                "{:?}:{port}",
                b.nat_ip
            );
        }
    }
}

#[test]
fn a_block_is_half_open() {
    let mut m = MemMaps::default();
    m.add_neighbor_nat(block([203, 0, 113, 9], 7, 20000, 30000, 1));
    let ip = [203, 0, 113, 9];
    assert!(m.nat_owner(&ip, 19999).is_none());
    assert!(m.nat_owner(&ip, 20000).is_some());
    assert!(m.nat_owner(&ip, 29999).is_some());
    assert!(m.nat_owner(&ip, 30000).is_none());
    assert!(
        m.nat_owner(&[203, 0, 113, 8], 25000).is_none(),
        "another nat_ip"
    );
}

// The node-side relay only follows a block of the packet's own VNI; the edge takes any.
#[test]
fn the_node_relay_filters_on_vni() {
    let mut m = MemMaps::default();
    m.add_neighbor_nat(block([203, 0, 113, 9], 7, 20000, 30000, 3));
    assert_eq!(
        neighbor_nat_owner(&m, 7, &[203, 0, 113, 9], 25000),
        Some([3; 16])
    );
    assert_eq!(neighbor_nat_owner(&m, 8, &[203, 0, 113, 9], 25000), None);
}

#[test]
fn v6_blocks_resolve_at_their_edges() {
    let ip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let mut m = MemMaps::default();
    for i in 0..200u16 {
        let lo = 1024 + i * 300;
        m.add_neighbor_nat6(NeighborNat6Entry {
            underlay: [(i % 250) as u8 + 1; 16],
            nat_ip6: ip,
            vni: 9,
            port_min: lo,
            port_max: lo + 300,
            enabled: 1,
            _pad: [0; 3],
        });
    }
    let o = m
        .nat_owner6(&ip, 1024 + 57 * 300 + 299)
        .expect("last port of block 57");
    assert_eq!(o.underlay, [58; 16]);
    assert!(m.nat_owner6(&ip, 1023).is_none());
    assert_eq!(neighbor_nat_owner6(&m, 9, &ip, 1024), Some([1; 16]));
    assert_eq!(neighbor_nat_owner6(&m, 10, &ip, 1024), None);
}

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

// Oracle: the retired datapath's semantics — the first block whose nat_ip matches and whose
// half-open range contains the port. Random disjoint blocks of random sizes, random probes: the
// trie must agree on every one.
#[test]
fn the_trie_agrees_with_the_block_scan() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..50 {
        let mut m = MemMaps::default();
        let mut blocks = Vec::new();
        for ip in 0..4u8 {
            let mut port: u32 = 1 + (r.next() % 500) as u32;
            while port < 65000 {
                let size = 1 + (r.next() % 3000) as u32;
                let hi = (port + size).min(65535);
                if !r.next().is_multiple_of(4) {
                    let b = block(
                        [10, 0, 0, ip],
                        (r.next() % 3) as u32,
                        port as u16,
                        hi as u16,
                        (r.next() % 250) as u8 + 1,
                    );
                    m.add_neighbor_nat(b);
                    blocks.push(b);
                }
                port = hi + (r.next() % 200) as u32;
            }
        }
        for _ in 0..2000 {
            let ip = [10, 0, 0, (r.next() % 5) as u8];
            let port = (r.next() % 65536) as u16;
            let want = blocks
                .iter()
                .find(|b| b.nat_ip == ip && port >= b.port_min && port < b.port_max)
                .map(|b| (b.underlay, b.vni));
            let got = m.nat_owner(&ip, port).map(|o| (o.underlay, o.vni));
            assert_eq!(got, want, "round {round}: {ip:?}:{port}");
        }
    }
}
