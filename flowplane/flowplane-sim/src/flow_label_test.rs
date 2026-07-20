//! Tests for the outer IPv6 flow-label entropy helpers (RFC 6437/6438 fabric ECMP).
use flowplane_core::parse::{flow_label20, hash_v6};

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
