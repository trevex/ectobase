//! Byte-level tests for the IPv6 L4 parse helpers `l4_ports_v6` / `icmp_type_code_v6`.
//! IPv6 has a fixed 40-byte header: next-header at `ip_off + 6`, L4 header at `ip_off + 40`.

use crate::VecPkt;
use flowplane_core::parse::{icmp_type_code_v6, l4_ports_v6};

fn v6_l4(nexthdr: u8) -> Vec<u8> {
    let mut b = vec![0u8; 40 + 20];
    b[6] = nexthdr; // next header at ip_off + 6
    b
}

fn v6_tcp(sport: u16, dport: u16) -> Vec<u8> {
    let mut b = v6_l4(6);
    b[40..42].copy_from_slice(&sport.to_be_bytes()); // L4 at ip_off + 40
    b[42..44].copy_from_slice(&dport.to_be_bytes());
    b
}

fn v6_udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut b = v6_l4(17);
    b[40..42].copy_from_slice(&sport.to_be_bytes());
    b[42..44].copy_from_slice(&dport.to_be_bytes());
    b
}

fn v6_icmp6(typ: u8, code: u8, id: u16) -> Vec<u8> {
    let mut b = v6_l4(58);
    b[40] = typ;
    b[41] = code;
    b[44..46].copy_from_slice(&id.to_be_bytes()); // id at l4 + 4
    b
}

#[test]
fn l4_ports_v6_reads_tcp_ports() {
    let pkt = VecPkt::from_bytes(&v6_tcp(1234, 80));
    assert_eq!(l4_ports_v6(&pkt, 0), Some((6, 1234, 80)));
}

#[test]
fn l4_ports_v6_reads_udp_ports() {
    let pkt = VecPkt::from_bytes(&v6_udp(53, 4000));
    assert_eq!(l4_ports_v6(&pkt, 0), Some((17, 53, 4000)));
}

#[test]
fn l4_ports_v6_mirrors_icmp6_id() {
    let pkt = VecPkt::from_bytes(&v6_icmp6(128, 0, 0xABCD));
    assert_eq!(l4_ports_v6(&pkt, 0), Some((58, 0xABCD, 0xABCD)));
}

#[test]
fn icmp_type_code_v6_reads_type_and_code() {
    let pkt = VecPkt::from_bytes(&v6_icmp6(128, 3, 0xABCD));
    assert_eq!(icmp_type_code_v6(&pkt, 0), (128, 3));
}

#[test]
fn icmp_type_code_v6_non_icmp_is_sentinel() {
    let pkt = VecPkt::from_bytes(&v6_tcp(1234, 80));
    assert_eq!(icmp_type_code_v6(&pkt, 0), (0xffff, 0xffff));
}

/// `hash_v6_at` exists only to keep two 16-byte addresses off the BPF stack; it must fold to
/// EXACTLY the same value as `hash_v6`, because the v6 LB forward path and the ICMPv6-error relay
/// path pick a Maglev slot with it and must agree on the backend for one flow. Any divergence
/// would send an error to a different backend than the flow it belongs to.
#[test]
fn hash_v6_at_matches_hash_v6() {
    use flowplane_core::parse::{hash_v6, hash_v6_at};

    let src = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 9, 9, 9, 9, 10, 0, 100, 1];
    let dst = [
        0x20u8, 1, 0xd, 0xb8, 0xff, 0xff, 0, 0, 1, 2, 3, 4, 10, 0, 100, 1,
    ];

    // Lay the two addresses out at arbitrary but distinct offsets and read them back streamed.
    let mut buf = vec![0u8; 8 + 16 + 16];
    buf[8..24].copy_from_slice(&src);
    buf[24..40].copy_from_slice(&dst);
    let pkt = crate::VecPkt::from_bytes(&buf);

    for &(sport, dport, proto) in &[(50000u16, 443u16, 6u8), (0, 0, 17), (1, 65535, 6)] {
        assert_eq!(
            hash_v6_at(&pkt, 8, 24, sport, dport, proto),
            Some(hash_v6(&src, &dst, sport, dport, proto)),
            "streamed and array folds must be byte-identical ({sport},{dport},{proto})"
        );
    }
    // Swapping the offsets must equal swapping the arrays — this is how the ICMP-error relay
    // reconstructs the forward-flow hash from the quoted (reversed) tuple.
    assert_eq!(
        hash_v6_at(&pkt, 24, 8, 443, 50000, 6),
        Some(hash_v6(&dst, &src, 443, 50000, 6)),
        "swapping the two offsets must swap the tuple"
    );
}
