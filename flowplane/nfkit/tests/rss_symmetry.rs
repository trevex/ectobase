//! The symmetric RSS key makes Toeplitz(fwd 5-tuple) == Toeplitz(rev 5-tuple), so a flow and its
//! reply hash to the SAME queue/lcore. Verifies the property the per-lcore state model depends on.
use nfkit::{rss_queue, toeplitz_softrss, SYMMETRIC_RSS_KEY};

// RSS input for IPv4+L4 = src_ip ‖ dst_ip ‖ src_port ‖ dst_port (network order).
fn tuple(sip: [u8; 4], dip: [u8; 4], sp: u16, dp: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&sip);
    v.extend_from_slice(&dip);
    v.extend_from_slice(&sp.to_be_bytes());
    v.extend_from_slice(&dp.to_be_bytes());
    v
}

// RSS input for IPv6+L4 = 16B src_ip ‖ 16B dst_ip ‖ src_port ‖ dst_port (network order).
fn tuple6(sip: [u8; 16], dip: [u8; 16], sp: u16, dp: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    v.extend_from_slice(&sip);
    v.extend_from_slice(&dip);
    v.extend_from_slice(&sp.to_be_bytes());
    v.extend_from_slice(&dp.to_be_bytes());
    v
}

#[test]
fn symmetric_key_pins_both_directions() {
    let cases = [
        ([10, 0, 0, 1], [203, 0, 113, 9], 40000u16, 443u16),
        ([192, 168, 1, 5], [8, 8, 8, 8], 1234, 53),
        ([10, 9, 0, 1], [10, 9, 1, 2], 22, 51000),
    ];
    for (sip, dip, sp, dp) in cases {
        let fwd = toeplitz_softrss(&tuple(sip, dip, sp, dp), &SYMMETRIC_RSS_KEY);
        let rev = toeplitz_softrss(&tuple(dip, sip, dp, sp), &SYMMETRIC_RSS_KEY);
        assert_eq!(
            fwd, rev,
            "symmetric key must hash fwd == rev for {sip:?}:{sp} <-> {dip:?}:{dp}"
        );
        for n in [2u16, 4, 8, 16] {
            assert_eq!(rss_queue(fwd, n), rss_queue(rev, n), "same queue for n={n}");
        }
    }
    // ── IPv6 5-tuples (WAN-edge / NAT64 v6 flows the per-lcore model also relies on) ──
    // 16B src ++ 16B dst ++ 2B sport ++ 2B dport; symmetric key must pin fwd == rev here too.
    let v6_cases = [
        (
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a],
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb9],
            40000u16,
            443u16,
        ),
        (
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            53,
        ),
        (
            [
                0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e,
            ],
            [
                0x20, 0x01, 0x4a, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
            ],
            22,
            51000,
        ),
    ];
    for (sip, dip, sp, dp) in v6_cases {
        let fwd = toeplitz_softrss(&tuple6(sip, dip, sp, dp), &SYMMETRIC_RSS_KEY);
        let rev = toeplitz_softrss(&tuple6(dip, sip, dp, sp), &SYMMETRIC_RSS_KEY);
        assert_eq!(
            fwd, rev,
            "v6 symmetric key must hash fwd == rev for {sip:?}:{sp} <-> {dip:?}:{dp}"
        );
        for n in [2u16, 4, 8, 16] {
            assert_eq!(
                rss_queue(fwd, n),
                rss_queue(rev, n),
                "v6 same queue for n={n}"
            );
        }
    }

    // Sanity: distinct flows generally land on different hashes (not all-equal → the hash is live).
    let a = toeplitz_softrss(&tuple([1, 1, 1, 1], [2, 2, 2, 2], 1, 2), &SYMMETRIC_RSS_KEY);
    let b = toeplitz_softrss(&tuple([9, 9, 9, 9], [8, 8, 8, 8], 7, 8), &SYMMETRIC_RSS_KEY);
    assert_ne!(a, b, "hash should differ across distinct flows");
}
