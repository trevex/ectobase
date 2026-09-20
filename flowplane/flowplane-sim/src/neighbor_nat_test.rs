//! Neighbor-NAT owners as the dataplane stores them: `NAT_OWNERS{,6}` tries keyed
//! `[nat_ip ++ port]`, seeded from blocks through the dataplane's own decomposition
//! (`MemMaps::add_neighbor_nat{,6}`). The lookups are the shared core ones the eBPF runs.

use crate::rng::Rng;
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
    }
}

// The old table held 64 blocks fleet-wide. A thousand now resolve, each to its own block (a
// distinct VNI per block makes a neighbor's answer visible), at every edge of every block.
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
                (o.underlay, o.vni, o.port_min, o.port_max),
                (b.underlay, b.vni, b.port_min, b.port_max),
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

// Every block, checked at both ends of its half-open range (full owner, including the range
// itself — two blocks never share an owner by accident), plus the gaps below the first block and
// above the last, and the VNI-filtered relay at the first block's own edge.
#[test]
fn v6_blocks_resolve_at_their_edges() {
    let ip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let mut m = MemMaps::default();
    let mut blocks = Vec::new();
    for i in 0..200u16 {
        let lo = 1024 + i * 300;
        let b = NeighborNat6Entry {
            underlay: [(i % 250) as u8 + 1; 16],
            nat_ip6: ip,
            vni: 9,
            port_min: lo,
            port_max: lo + 300,
        };
        m.add_neighbor_nat6(b);
        blocks.push(b);
    }

    for b in &blocks {
        for port in [b.port_min, b.port_max - 1] {
            let o = m.nat_owner6(&ip, port).expect("owned port");
            assert_eq!(
                (o.underlay, o.vni, o.port_min, o.port_max),
                (b.underlay, b.vni, b.port_min, b.port_max),
                "port {port}"
            );
        }
    }
    assert!(m.nat_owner6(&ip, blocks[0].port_min - 1).is_none());
    assert!(m.nat_owner6(&ip, blocks.last().unwrap().port_max).is_none());

    assert_eq!(neighbor_nat_owner6(&m, 9, &ip, 1024), Some([1; 16]));
    assert_eq!(neighbor_nat_owner6(&m, 10, &ip, 1024), None);
}

// Oracle: the retired datapath's semantics — the first block whose nat_ip matches and whose
// half-open range contains the port; and, for the node relay, the first such block that ALSO
// matches the probed VNI (the old table was VNI-keyed). Random disjoint blocks of random sizes
// (including port_min == 0), random probes PLUS every block's own edges and the absolute
// port-space edges on every ip (random probes alone almost never land exactly on a boundary): the
// trie must agree with the naive scan on every one, in both the VNI-agnostic and the VNI-filtered
// form — the latter is the design's whole basis for dropping the VNI from the trie key.
/// The VNIs the oracle's blocks are drawn from; the per-VNI relay oracle has one slot each.
const VNIS: u64 = 3;

#[test]
fn the_trie_agrees_with_the_block_scan() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    // 15 rounds: each fills the whole port space per ip (~125 blocks, ~1250 trie prefixes), and the
    // per-probe checks below run BOTH the plain and the 3-way VNI-filtered lookup, each an O(entries)
    // scan — more rounds pushed this well past 2s in debug without adding a new kind of case.
    for round in 0..15 {
        let mut m = MemMaps::default();
        let mut blocks = Vec::new();
        for ip in 0..4u8 {
            // ip 0's first block starts at port 0; the others at a random offset.
            let mut port: u32 = if ip == 0 { 0 } else { (r.next() % 500) as u32 };
            while port < 65000 {
                let size = 1 + (r.next() % 3000) as u32;
                let hi = (port + size).min(65535);
                if !r.next().is_multiple_of(4) {
                    let b = block(
                        [10, 0, 0, ip],
                        (r.next() % VNIS) as u32,
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
        // Random probes, plus every block's own edges (both endpoints of the half-open range,
        // and one step outside each) and the absolute port-space edges on every ip.
        let mut probes: Vec<(u8, u16)> = (0..200)
            .map(|_| ((r.next() % 5) as u8, (r.next() % 65536) as u16))
            .collect();
        for b in &blocks {
            let ip = b.nat_ip[3];
            probes.push((ip, b.port_min.saturating_sub(1)));
            probes.push((ip, b.port_min));
            probes.push((ip, b.port_max - 1));
            probes.push((ip, b.port_max));
        }
        for ip in 0..=4u8 {
            probes.push((ip, 0));
            probes.push((ip, 65535));
        }

        for &(ip8, port) in &probes {
            let ip = [10, 0, 0, ip8];
            // One naive pass over the block list stands in for both oracles: the first match of
            // any VNI, and the first match per VNI in 0..VNIS (the only VNIs generated above).
            let mut want: Option<([u8; 16], u32, u16, u16)> = None;
            let mut want_by_vni = [None::<[u8; 16]>; VNIS as usize];
            for b in &blocks {
                if b.nat_ip == ip && port >= b.port_min && port < b.port_max {
                    want.get_or_insert((b.underlay, b.vni, b.port_min, b.port_max));
                    want_by_vni[b.vni as usize].get_or_insert(b.underlay);
                }
            }

            let got = m
                .nat_owner(&ip, port)
                .map(|o| (o.underlay, o.vni, o.port_min, o.port_max));
            assert_eq!(got, want, "round {round}: {ip:?}:{port}");

            for (vni, &want_relay) in want_by_vni.iter().enumerate() {
                let got_relay = neighbor_nat_owner(&m, vni as u32, &ip, port);
                assert_eq!(
                    got_relay, want_relay,
                    "round {round}: vni {vni} {ip:?}:{port}"
                );
            }
        }
    }
}
