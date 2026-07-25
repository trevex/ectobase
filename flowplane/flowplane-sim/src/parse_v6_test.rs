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
