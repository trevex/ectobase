//! Tests for the flow-label entropy helpers (RFC 6437/6438 fabric ECMP hash fold).
//!
//! NOTE: these helpers (`flow_label20`/`inner_flow_label`/`hash5`/`hash_v6`) are no longer wired
//! into the production datapath — they used to feed the outer IPv6 flow-label field
//! `write_outer_v6` wrote, which no longer exists (see `flowplane_core::encap::TunnelEncap`). Under
//! Geneve, fabric ECMP entropy becomes the kernel's own Geneve UDP-source-port hash, not something
//! this crate computes. The helpers themselves stay (still-correct, reusable hash-fold math); only
//! the end-to-end "guest_tx writes the label into the outer header" test is gone — there is no outer
//! header to write it into anymore.
use crate::VecPkt;
use flowplane_core::encap::ETH_LEN;
use flowplane_core::parse::{flow_label20, hash5, hash_v6, inner_flow_label};

#[test]
fn flow_label20_stays_within_20_bits() {
    // Any 32-bit hash folds into the low 20 bits; the top 12 bits must be clear
    // (they overlap the IPv6 version/traffic-class nibble and must not be set).
    assert_eq!(flow_label20(0xFFFF_FFFF) & 0xFFF0_0000, 0);
    assert_eq!(flow_label20(0x1234_5678) & 0xFFF0_0000, 0);
    assert_eq!(flow_label20(0) & 0xFFF0_0000, 0);
}

#[test]
fn flow_label20_folds_high_bits_in() {
    // Fold is (h ^ (h >> 20)) & 0xFFFFF, so bits above 20 influence the label
    // (otherwise high-entropy hashes would collide on their low 20 bits).
    let a = flow_label20(0x0000_0001);
    let b = flow_label20(0x0010_0001); // differs only in bit 20 -> XORs into bit 0
    assert_ne!(a, b);
}

#[test]
fn hash_v6_is_deterministic_and_flow_sensitive() {
    let s = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let d = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let h = hash_v6(&s, &d, 1000, 80, 6);
    assert_eq!(h, hash_v6(&s, &d, 1000, 80, 6)); // deterministic
    assert_ne!(h, hash_v6(&s, &d, 1001, 80, 6)); // different sport -> different hash
    assert_ne!(h, hash_v6(&d, &s, 1000, 80, 6)); // swapped addrs -> different hash
}

#[test]
fn inner_flow_label_v4_matches_hash5_fold() {
    // [eth(14)][inner IPv4(20)][TCP ports] — the helper must hash the inner 5-tuple.
    let mut b = vec![0u8; ETH_LEN + 24];
    b[ETH_LEN] = 0x45; // version 4, IHL 5
    b[ETH_LEN + 9] = 6; // proto = TCP
    b[ETH_LEN + 12..ETH_LEN + 16].copy_from_slice(&[10, 0, 0, 1]); // src
    b[ETH_LEN + 16..ETH_LEN + 20].copy_from_slice(&[10, 0, 0, 2]); // dst
    b[ETH_LEN + 20..ETH_LEN + 22].copy_from_slice(&1234u16.to_be_bytes()); // sport
    b[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&80u16.to_be_bytes()); // dport
    let p = VecPkt::from_bytes(&b);
    let expect = flow_label20(hash5(&[10, 0, 0, 1], &[10, 0, 0, 2], 1234, 80, 6));
    assert_eq!(inner_flow_label(&p, ETH_LEN, false), expect);
    assert_eq!(inner_flow_label(&p, ETH_LEN, false) & 0xFFF0_0000, 0); // 20-bit
}

#[test]
fn inner_flow_label_v6_matches_hashv6_fold() {
    // [eth(14)][inner IPv6(40)][TCP ports].
    let src = [0x20u8, 1, 0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20u8, 1, 0, 0xb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut b = vec![0u8; ETH_LEN + 44];
    b[ETH_LEN] = 0x60; // version 6
    b[ETH_LEN + 6] = 6; // next-header = TCP
    b[ETH_LEN + 8..ETH_LEN + 24].copy_from_slice(&src);
    b[ETH_LEN + 24..ETH_LEN + 40].copy_from_slice(&dst);
    b[ETH_LEN + 40..ETH_LEN + 42].copy_from_slice(&5000u16.to_be_bytes()); // sport
    b[ETH_LEN + 42..ETH_LEN + 44].copy_from_slice(&443u16.to_be_bytes()); // dport
    let p = VecPkt::from_bytes(&b);
    let expect = flow_label20(hash_v6(&src, &dst, 5000, 443, 6));
    assert_eq!(inner_flow_label(&p, ETH_LEN, true), expect);
}
