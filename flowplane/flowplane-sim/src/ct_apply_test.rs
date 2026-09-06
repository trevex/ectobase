//! Direct unit tests for `flowplane_core::conntrack::ct_apply`/`ct_apply6` — the CT-rewrite seam
//! shared by the production eBPF path and `SimNode`.
//!
//! # Why these live in `flowplane-sim` rather than `flowplane-core`
//!
//! `ct_apply<P: Pkt>` is generic over the `Pkt` trait.  `flowplane-core` itself provides no
//! concrete `Pkt` implementation — `VecPkt` lives in `flowplane-sim`.  Adding a test `Pkt`
//! implementation to `flowplane-core` would either pollute the production crate or require a
//! `dev-dependency` on `flowplane-sim`, creating a circular dependency.  The right place for
//! tests that need a concrete `Pkt` is therefore `flowplane-sim`, which already depends on
//! `flowplane-core` and re-exports `VecPkt`.  This is consistent with `conntrack_test.rs` and
//! `firewall_test.rs` which follow the same pattern (they call `flowplane_core` functions from
//! `flowplane-sim` using `VecPkt`/`MemMaps`).  `flowplane-sim` also carries the `etherparse`
//! dev-dependency `flowplane-core` deliberately does not have, so v6 DSR (`ct_apply6`) frames
//! below are built with `etherparse::PacketBuilder` for correct initial checksums, same as the
//! v4 frames.
//!
//! # Coverage
//!
//! 1. `CT_REWRITE_SRC` TCP — rewrites inner src IP + src port, folds both changes into the
//!    IP and TCP checksums.
//! 2. `CT_REWRITE_SRC` UDP — same for UDP; also verifies zero-csum invariant: a UDP frame
//!    with checksum == 0 is left with checksum == 0 after the address rewrite (zero stays zero).
//! 3. DEFAULT / flag-less entry — `ct_apply` is a no-op; every byte is unchanged.
//! 4. `ct_apply6` (B5, v6 DSR reverse-SNAT): `CT_REWRITE_SRC` rewrites the inner v6 src to
//!    `xlate_ip6`, folding the 16-byte address delta into the TCP/UDP checksum (IPv6 has no IP
//!    checksum).

use crate::VecPkt;
use flowplane_common::{CtEntry, CT_F_DEFAULT, CT_F_DSR, CT_REWRITE_SRC};
use flowplane_core::conntrack::{ct_apply, ct_apply6};

// ─── fixed topology ───────────────────────────────────────────────────────────

/// Original (pre-SNAT) guest source IP.
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
/// Public NAT IP the src will be rewritten to.
const NAT_IP: [u8; 4] = [100, 64, 0, 1];
/// External destination.
const EXT_IP: [u8; 4] = [203, 0, 113, 1];

/// Original guest L4 source port.
const ORIG_SPORT: u16 = 12345;
/// NAT-allocated port (the xlate target).
const NAT_SPORT: u16 = 1385;
/// Destination port (unchanged by SNAT).
const DPORT: u16 = 80;

// ─── frame builders ──────────────────────────────────────────────────────────

/// Build a bare `[IPv4(20)][TCP(20)][payload(4)]` frame at `ip_off = 0` (no Ethernet prefix).
/// Uses `etherparse` to get correct initial IP+TCP checksums, then strips the Ethernet header
/// so the IP header is at offset 0 — matching `ct_apply(pkt, ip_off=0, ...)`.
fn bare_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Build a bare `[IPv4(20)][UDP(8)][payload(4)]` frame at `ip_off = 0`.
fn bare_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// A `CT_REWRITE_SRC` entry: `xlate_ip = NAT_IP`, `xlate_port = NAT_SPORT`.
fn snat_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: NAT_IP,
        xlate_port: NAT_SPORT,
        flags: CT_REWRITE_SRC,
        tcp_state: 0,
        fwall_action: 0,
        xlate_ip6: [0; 16],
        _pad: [0; 7],
    }
}

// ─── Part B tests ────────────────────────────────────────────────────────────

/// `CT_REWRITE_SRC` on a TCP packet rewrites:
///   - inner src IP at ip_off+12 → `NAT_IP` ([100, 64, 0, 1])
///   - TCP src port at l4+0 → `NAT_SPORT` (1385, [0x05, 0x69])
///   - IP checksum at ip_off+10 updated (non-zero)
///   - TCP checksum at l4+16 updated (non-zero)
///   - dst IP and dst port are NOT changed
#[test]
fn ct_apply_rewrite_src_tcp() {
    let raw = bare_ipv4_tcp(GUEST_IP, EXT_IP, ORIG_SPORT, DPORT);
    let mut pkt = VecPkt::from_bytes(&raw);
    let e = snat_entry();

    ct_apply(&mut pkt, 0, &e);

    let out = pkt.bytes();

    // Pinned: src IP at offset 12 must be NAT_IP = [100, 64, 0, 1].
    let src_ip: [u8; 4] = out[12..16].try_into().unwrap();
    assert_eq!(
        src_ip, NAT_IP,
        "CT_REWRITE_SRC: src IP must be rewritten to NAT_IP [100,64,0,1]"
    );

    // Pinned: TCP src port at l4+0 = offset 20 must be NAT_SPORT = 1385 = 0x0569.
    let src_port = u16::from_be_bytes([out[20], out[21]]);
    assert_eq!(
        src_port, NAT_SPORT,
        "CT_REWRITE_SRC: TCP src port must be rewritten to NAT_SPORT ({NAT_SPORT})"
    );

    // dst IP at offset 16 unchanged.
    let dst_ip: [u8; 4] = out[16..20].try_into().unwrap();
    assert_eq!(dst_ip, EXT_IP, "dst IP must be unchanged by CT_REWRITE_SRC");

    // TCP dst port at l4+2 = offset 22 unchanged.
    let dst_port = u16::from_be_bytes([out[22], out[23]]);
    assert_eq!(
        dst_port, DPORT,
        "TCP dst port must be unchanged by CT_REWRITE_SRC"
    );

    // IP checksum at offset 10 — non-zero (src IP changed from a non-trivial address).
    let ip_csum = u16::from_be_bytes([out[10], out[11]]);
    assert_ne!(
        ip_csum, 0,
        "IP checksum must be non-zero after CT_REWRITE_SRC"
    );

    // TCP checksum at l4+16 = offset 36 — non-zero.
    let tcp_csum = u16::from_be_bytes([out[36], out[37]]);
    assert_ne!(
        tcp_csum, 0,
        "TCP checksum must be non-zero after CT_REWRITE_SRC"
    );

    // Payload bytes unchanged.
    assert_eq!(
        &out[out.len() - 4..],
        &[0x01, 0x02, 0x03, 0x04],
        "payload must be unchanged"
    );
}

/// `CT_REWRITE_SRC` on a UDP packet with non-zero checksum:
///   - inner src IP at ip_off+12 → `NAT_IP` ([100, 64, 0, 1])
///   - UDP src port at l4+0 → `NAT_SPORT` (1385, [0x05, 0x69])
///   - IP checksum updated (non-zero)
///   - UDP checksum non-zero (payload is non-zero → original csum non-zero; fold preserves non-zero)
#[test]
fn ct_apply_rewrite_src_udp_nonzero_csum() {
    let raw = bare_ipv4_udp(GUEST_IP, EXT_IP, ORIG_SPORT, DPORT);
    let mut pkt = VecPkt::from_bytes(&raw);
    let e = snat_entry();

    ct_apply(&mut pkt, 0, &e);

    let out = pkt.bytes();

    // Pinned: src IP at offset 12 → NAT_IP = [100, 64, 0, 1].
    let src_ip: [u8; 4] = out[12..16].try_into().unwrap();
    assert_eq!(
        src_ip, NAT_IP,
        "CT_REWRITE_SRC UDP: src IP must be rewritten to NAT_IP"
    );

    // Pinned: UDP src port at l4+0 = offset 20 → NAT_SPORT = 1385.
    let src_port = u16::from_be_bytes([out[20], out[21]]);
    assert_eq!(
        src_port, NAT_SPORT,
        "CT_REWRITE_SRC UDP: src port must be rewritten to NAT_SPORT ({NAT_SPORT})"
    );

    // dst IP at offset 16 unchanged.
    let dst_ip: [u8; 4] = out[16..20].try_into().unwrap();
    assert_eq!(dst_ip, EXT_IP, "UDP: dst IP must be unchanged");

    // UDP dst port at l4+2 = offset 22 unchanged.
    let dst_port = u16::from_be_bytes([out[22], out[23]]);
    assert_eq!(dst_port, DPORT, "UDP: dst port must be unchanged");

    // IP checksum non-zero.
    let ip_csum = u16::from_be_bytes([out[10], out[11]]);
    assert_ne!(ip_csum, 0, "IP checksum must be non-zero (UDP)");

    // UDP checksum at l4+6 = offset 26 — non-zero (was non-zero before, fold keeps it non-zero).
    let udp_csum = u16::from_be_bytes([out[26], out[27]]);
    assert_ne!(
        udp_csum, 0,
        "UDP checksum must remain non-zero after CT_REWRITE_SRC fold"
    );
}

/// `CT_REWRITE_SRC` on a UDP frame whose checksum field is 0 (disabled): the zero-checksum must
/// stay zero after the address + port rewrite (mirror of the inline eBPF `c0 != 0` guard in
/// `ct_apply`'s UDP branch).
#[test]
fn ct_apply_rewrite_src_udp_zero_csum_stays_zero() {
    // Build a UDP frame and manually zero the UDP checksum field at l4+6 = offset 26.
    let mut raw = bare_ipv4_udp(GUEST_IP, EXT_IP, ORIG_SPORT, DPORT);
    raw[26] = 0;
    raw[27] = 0;

    let mut pkt = VecPkt::from_bytes(&raw);
    ct_apply(&mut pkt, 0, &snat_entry());

    let out = pkt.bytes();
    // src IP rewritten.
    let src_ip: [u8; 4] = out[12..16].try_into().unwrap();
    assert_eq!(src_ip, NAT_IP, "zero-csum UDP: src IP still rewritten");

    // UDP checksum at offset 26 must remain zero (zero-stays-zero guard).
    let udp_csum = u16::from_be_bytes([out[26], out[27]]);
    assert_eq!(
        udp_csum, 0,
        "CT_REWRITE_SRC UDP: a zero checksum must stay zero (the guard `c0 != 0` must fire)"
    );
}

/// FLAG-LESS / DEFAULT entry is a complete no-op: `ct_apply` returns immediately without touching
/// any byte.  Covers both the `flags == 0` case and the `CT_F_DEFAULT` (0x10) case (neither has
/// `CT_REWRITE_SRC | CT_REWRITE_DST` set).
#[test]
fn ct_apply_default_entry_is_noop() {
    let raw = bare_ipv4_tcp(GUEST_IP, EXT_IP, ORIG_SPORT, DPORT);

    for &flags in &[0u8, CT_F_DEFAULT] {
        let e = CtEntry {
            last_seen: 0,
            xlate_ip: NAT_IP, // would rewrite if applied
            xlate_port: NAT_SPORT,
            flags,
            tcp_state: 0,
            fwall_action: 0,
            xlate_ip6: [0; 16],
            _pad: [0; 7],
        };

        let mut pkt = VecPkt::from_bytes(&raw);
        ct_apply(&mut pkt, 0, &e);

        assert_eq!(
            pkt.bytes(),
            raw.as_slice(),
            "flags=0x{flags:02x}: ct_apply with a DEFAULT (flag-less) entry must be a no-op; \
             every byte must be identical to the original"
        );
    }
}

// ─── ct_apply6 (B5, v6 DSR reverse-SNAT) tests ────────────────────────────────

/// Guest overlay IPv6 source (the address DSR reverse-SNAT rewrites away).
const OVERLAY_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61];
/// External client IPv6 destination.
const CLIENT_IP6: [u8; 16] = [0xfd, 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
/// The VIP the overlay src is rewritten to (DSR reverse-SNAT translate address).
const VIP_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Build a bare `[IPv6(40)][TCP(20)][payload]` frame at `ip_off = 0` via `etherparse`, matching
/// `bare_ipv4_tcp`'s pattern so `ct_apply6` gets a real initial TCP checksum to fold.
fn bare_ipv6_tcp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ipv6(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Build a bare `[IPv6(40)][UDP(8)][payload]` frame at `ip_off = 0`.
fn bare_ipv6_udp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ipv6(src, dst, 64).udp(sport, dport);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// A `CT_REWRITE_SRC | CT_F_DSR` entry: `xlate_ip6 = VIP_IP6` (reverse-SNAT src -> VIP).
fn dsr_reverse_snat_entry() -> CtEntry {
    CtEntry {
        xlate_ip6: VIP_IP6,
        flags: CT_REWRITE_SRC | CT_F_DSR,
        ..Default::default()
    }
}

/// `ct_apply6` on a TCP packet with `CT_REWRITE_SRC` rewrites:
///   - inner src IP at ip_off+8 -> `VIP_IP6`
///   - TCP checksum at l4+16 = offset 56 updated (non-zero; folds the 16-byte address delta)
///   - dst IP at ip_off+24 is NOT changed
///   - dst/src ports are NOT changed (DSR reverse-SNAT is address-only, no port NAT)
#[test]
fn ct_apply6_rewrites_src_to_xlate_ip6() {
    let raw = bare_ipv6_tcp(OVERLAY_IP6, CLIENT_IP6, 80, 40000);
    let mut pkt = VecPkt::from_bytes(&raw);
    let e = dsr_reverse_snat_entry();

    ct_apply6(&mut pkt, 0, &e);

    let out = pkt.bytes();

    // Pinned: src IP at offset 8..24 must be VIP_IP6.
    assert_eq!(&out[8..24], &VIP_IP6, "src -> vip");

    // dst IP at offset 24..40 unchanged.
    assert_eq!(&out[24..40], &CLIENT_IP6, "dst IP must be unchanged");

    // TCP ports (l4+0 = offset 40, l4+2 = offset 42) unchanged — address-only rewrite.
    assert_eq!(
        u16::from_be_bytes([out[40], out[41]]),
        80,
        "TCP src port must be unchanged by ct_apply6"
    );
    assert_eq!(
        u16::from_be_bytes([out[42], out[43]]),
        40000,
        "TCP dst port must be unchanged by ct_apply6"
    );

    // TCP checksum at l4+16 = offset 56 — non-zero after folding the address delta.
    let tcp_csum = u16::from_be_bytes([out[56], out[57]]);
    assert_ne!(
        tcp_csum, 0,
        "TCP checksum must be non-zero after ct_apply6's address rewrite"
    );

    // Payload bytes unchanged.
    assert_eq!(
        &out[out.len() - 4..],
        &[0x01, 0x02, 0x03, 0x04],
        "payload must be unchanged"
    );
}

/// `ct_apply6` on a UDP packet with non-zero checksum folds the address delta the same way TCP
/// does, leaving the checksum non-zero.
#[test]
fn ct_apply6_rewrite_src_udp_nonzero_csum() {
    let raw = bare_ipv6_udp(OVERLAY_IP6, CLIENT_IP6, 80, 40000);
    let mut pkt = VecPkt::from_bytes(&raw);
    let e = dsr_reverse_snat_entry();

    ct_apply6(&mut pkt, 0, &e);

    let out = pkt.bytes();
    assert_eq!(&out[8..24], &VIP_IP6, "UDP: src -> vip");
    assert_eq!(&out[24..40], &CLIENT_IP6, "UDP: dst IP must be unchanged");

    // UDP checksum at l4+6 = offset 46 — non-zero (was non-zero before, fold keeps it non-zero).
    let udp_csum = u16::from_be_bytes([out[46], out[47]]);
    assert_ne!(
        udp_csum, 0,
        "UDP checksum must remain non-zero after ct_apply6's address fold"
    );
}

/// `ct_apply6` on a UDP frame whose checksum field is 0 (disabled) leaves it at zero — the
/// zero-stays-zero guard mirrors `ct_apply`'s UDP branch.
#[test]
fn ct_apply6_rewrite_src_udp_zero_csum_stays_zero() {
    let mut raw = bare_ipv6_udp(OVERLAY_IP6, CLIENT_IP6, 80, 40000);
    // UDP checksum is at l4+6 = offset 46 for a bare (no-ethernet) v6 frame.
    raw[46] = 0;
    raw[47] = 0;

    let mut pkt = VecPkt::from_bytes(&raw);
    ct_apply6(&mut pkt, 0, &dsr_reverse_snat_entry());

    let out = pkt.bytes();
    assert_eq!(
        &out[8..24],
        &VIP_IP6,
        "zero-csum UDP: src IP still rewritten"
    );
    assert_eq!(
        u16::from_be_bytes([out[46], out[47]]),
        0,
        "ct_apply6 UDP: a zero checksum must stay zero"
    );
}

/// `CT_REWRITE_DST` rewrites the inner dst IP instead of src, leaving src untouched.
#[test]
fn ct_apply6_rewrite_dst_to_xlate_ip6() {
    let raw = bare_ipv6_tcp(CLIENT_IP6, OVERLAY_IP6, 40000, 80);
    let mut pkt = VecPkt::from_bytes(&raw);
    let e = CtEntry {
        xlate_ip6: VIP_IP6,
        flags: flowplane_common::CT_REWRITE_DST,
        ..Default::default()
    };

    ct_apply6(&mut pkt, 0, &e);

    let out = pkt.bytes();
    assert_eq!(
        &out[8..24],
        &CLIENT_IP6,
        "CT_REWRITE_DST: src must be unchanged"
    );
    assert_eq!(&out[24..40], &VIP_IP6, "CT_REWRITE_DST: dst -> vip");
}

/// FLAG-LESS / DEFAULT entry is a complete no-op for `ct_apply6`, same contract as `ct_apply`.
#[test]
fn ct_apply6_default_entry_is_noop() {
    let raw = bare_ipv6_tcp(OVERLAY_IP6, CLIENT_IP6, 80, 40000);

    for &flags in &[0u8, CT_F_DEFAULT] {
        let e = CtEntry {
            xlate_ip6: VIP_IP6, // would rewrite if applied
            flags,
            ..Default::default()
        };

        let mut pkt = VecPkt::from_bytes(&raw);
        ct_apply6(&mut pkt, 0, &e);

        assert_eq!(
            pkt.bytes(),
            raw.as_slice(),
            "flags=0x{flags:02x}: ct_apply6 with a DEFAULT (flag-less) entry must be a no-op"
        );
    }
}
