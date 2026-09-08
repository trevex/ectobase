#![cfg_attr(not(feature = "user"), no_std)]

//! Shared datapath types + wire helpers for flowplane. The bulk of this crate is the set of eBPF
//! map key/value POD structs, which now live in the [`maps`] submodule tree (grouped by domain) and
//! are re-exported at the crate root so external importers keep their `flowplane_common::<Name>`
//! paths (e.g. `flowplane_common::CtEntry`, `IfaceKey`, `RouteValue`, `LbKey`, `NatKey`, `FwRule`,
//! `CT_F_DEFAULT`, `TCP_ESTABLISHED`, …). The wire helpers (`csum`, `proto`, `arp_nd`, `dhcp`) stay
//! here as their own modules.

/// Manual incremental checksum updates (XDP has no bpf_l3/l4_csum_replace helpers).
pub mod csum {
    #[inline(always)]
    fn fold(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// RFC 1624 incremental update of a 16-bit ones-complement checksum `check` (host order, i.e.
    /// already `u16::from_be`) when a 32-bit field changes from `old` to `new` (big-endian bytes).
    /// Returns the new checksum (host order) to store back as big-endian.
    ///
    /// HC' = ~( ~HC + ~m + m' ), summed over the two 16-bit words of the changed field.
    #[inline(always)]
    pub fn csum_replace4(check: u16, old: &[u8; 4], new: &[u8; 4]) -> u16 {
        let mut sum: u32 = (!check) as u32;
        sum += (!u16::from_be_bytes([old[0], old[1]])) as u32;
        sum += (!u16::from_be_bytes([old[2], old[3]])) as u32;
        sum += u16::from_be_bytes([new[0], new[1]]) as u32;
        sum += u16::from_be_bytes([new[2], new[3]]) as u32;
        !fold(sum)
    }

    /// Incrementally fold a 16-bit field change (network-order `old`/`new`) into an L4/ICMP
    /// checksum by reusing [`csum_replace4`] with the upper 2 bytes zeroed in both arguments.
    #[inline(always)]
    pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
        let o = old.to_be_bytes();
        let n = new.to_be_bytes();
        csum_replace4(check, &[o[0], o[1], 0, 0], &[n[0], n[1], 0, 0])
    }
}

/// Datapath map key/value POD types, grouped by domain, re-exported at the crate root so external
/// importers keep their existing `flowplane_common::<Name>` paths.
mod maps;
pub use maps::*;

/// Shared L2/L3 protocol constants — the single source of truth for the datapath across the eBPF
/// crate, `flowplane-core`, and `flowplane-sim`. Other modules (`arp_nd`, eBPF `parse`, core `encap`/
/// `uplink`) re-export from here so every call site resolves to ONE definition.
pub mod proto {
    pub const ETH_LEN: usize = 14;
    pub const IPV6_LEN: usize = 40;
    pub const ETH_P_IP: u16 = 0x0800;
    pub const ETH_P_IPV6: u16 = 0x86DD;
    /// Virtual gateway MAC: answered to ARP/ND and used as the inner-eth src on host delivery.
    pub const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
}

/// ARP/ND wire-format constants. The byte-rewrite responders live in `flowplane_core::arp_nd` (the
/// `Pkt`-trait seam the eBPF datapath, native sim, and BPF_PROG_TEST_RUN anchor all share); this
/// module re-exports the L2/L3 protocol constants so `arp_nd::{ETH_LEN, IPV6_LEN, ETH_P_IPV6}`
/// import paths resolve.
pub mod arp_nd {
    pub use super::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};
}

/// Cheap fixed-offset DHCP request detection (used by the guest-edge glue to decide whether to
/// tail-call the DHCP responder). The DHCPv4 request parse + reply construction live in
/// `flowplane_core::dhcp` over the `Pkt`/`Maps` seam (the SAME code the eBPF datapath, the sim, and
/// the byte-parity anchor run); this module keeps only the port-sniffing detectors, which are pure
/// fixed-offset reads over `(data, data_end)` and have no packet/map trait dependency. The DHCPv6
/// responder lives in the eBPF crate (its option block is runtime-variable-length; see
/// `flowplane_core::dhcp` for why it cannot cross the fixed-size `Pkt` seam).
pub mod dhcp {
    const ETH_LEN: usize = 14;
    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;
    const IPPROTO_UDP: u8 = 17;

    // ETH(14) + IPv4(20) + UDP(8) + BOOTP-through-magic-cookie(240) = 282.
    const F_BOOTP: usize = ETH_LEN + 20 + 8;
    const BOOTP_OPTIONS_OFF: usize = 240;
    /// Smallest DHCPv4 frame the detector/parse needs present (through the option area start).
    pub const MIN_DHCP_LEN: usize = F_BOOTP + BOOTP_OPTIONS_OFF;

    // ETH(14) + IPv6(40) + UDP(8) + DHCPv6 header(4) = 66.
    const MIN_DHCPV6_LEN: usize = ETH_LEN + 40 + 8 + 4;

    /// Cheap port-only check: IPv4 + IHL==5 + UDP + dport 67. Bounds-checked on `data..data_end`.
    #[inline(always)]
    pub fn looks_like_dhcpv4(data: usize, data_end: usize) -> bool {
        if data + MIN_DHCP_LEN > data_end {
            return false;
        }
        let p = data as *const u8;
        let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
        if ethertype != ETH_P_IP {
            return false;
        }
        if unsafe { *p.add(ETH_LEN) } & 0x0f != 5 {
            return false;
        }
        if unsafe { *p.add(ETH_LEN + 9) } != IPPROTO_UDP {
            return false;
        }
        let udp_dst =
            u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 22) as *const u16) });
        udp_dst == 67
    }

    /// Cheap fixed-offset check: IPv6 + next-header UDP + UDP dport 547. Bounds-checked on
    /// `data..data_end`. All offsets are constant, so this is safe in `flowplane-common`.
    #[inline(always)]
    pub fn looks_like_dhcpv6(data: usize, data_end: usize) -> bool {
        if data + MIN_DHCPV6_LEN > data_end {
            return false;
        }
        let p = data as *const u8;
        let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
        if ethertype != ETH_P_IPV6 {
            return false;
        }
        // IPv6 next-header (no extension-header support needed for DHCPv6).
        if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_UDP {
            return false;
        }
        let udp_dst = u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16)
        });
        udp_dst == 547
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn detects_dhcpv6_solicit() {
            let mut buf = [0u8; MIN_DHCPV6_LEN];
            buf[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
            buf[ETH_LEN + 6] = IPPROTO_UDP; // IPv6 next-header
            buf[ETH_LEN + 40 + 2..ETH_LEN + 40 + 4].copy_from_slice(&547u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(looks_like_dhcpv6(data, data + buf.len()));
            // Wrong port -> rejected.
            buf[ETH_LEN + 40 + 2..ETH_LEN + 40 + 4].copy_from_slice(&546u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(!looks_like_dhcpv6(data, data + buf.len()));
            // Undersized -> rejected.
            assert!(!looks_like_dhcpv6(data, data + MIN_DHCPV6_LEN - 1));
        }

        #[test]
        fn detects_dhcpv4_discover() {
            let mut buf = [0u8; MIN_DHCP_LEN];
            buf[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
            buf[ETH_LEN] = 0x45; // version 4, IHL 5
            buf[ETH_LEN + 9] = IPPROTO_UDP;
            buf[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&67u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(looks_like_dhcpv4(data, data + buf.len()));
            buf[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&68u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(!looks_like_dhcpv4(data, data + buf.len()));
            assert!(!looks_like_dhcpv4(data, data + MIN_DHCP_LEN - 1));
        }
    }
}

#[cfg(test)]
mod csum_tests {
    use super::csum::csum_replace4;

    /// Full ones-complement checksum over a byte slice (16-bit words, big-endian), folded.
    fn full_csum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a minimal 20-byte IPv4 header with a correct checksum, then verify that changing the
    /// destination address via csum_replace4 yields the same checksum as a full recompute.
    #[test]
    fn ipv4_dst_change_matches_full_recompute() {
        // ver/ihl=0x45, tos=0, total_len=0x0054, id=0, flags/frag=0x4000, ttl=64, proto=1(ICMP),
        // checksum=0 (placeholder), src=10.0.0.5, dst=10.0.0.6
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 5,
            10, 0, 0, 6,
        ];
        // initial correct checksum
        let init = full_csum(&hdr);
        hdr[10] = (init >> 8) as u8;
        hdr[11] = (init & 0xff) as u8;

        let old_dst = [hdr[16], hdr[17], hdr[18], hdr[19]];
        let new_dst = [10u8, 0, 0, 7];

        // incremental
        let inc = csum_replace4(u16::from_be_bytes([hdr[10], hdr[11]]), &old_dst, &new_dst);

        // apply change + full recompute (zero the checksum field first)
        hdr[16..20].copy_from_slice(&new_dst);
        hdr[10] = 0;
        hdr[11] = 0;
        let full = full_csum(&hdr);

        assert_eq!(inc, full, "incremental checksum must equal full recompute");
    }

    /// Also verify the round-trip: changing A->B then B->A restores the original checksum.
    #[test]
    fn round_trip_restores_checksum() {
        let a = [10u8, 0, 0, 5];
        let b = [192u8, 168, 1, 1];
        let start = 0x1234u16;
        let once = csum_replace4(start, &a, &b);
        let back = csum_replace4(once, &b, &a);
        assert_eq!(back, start);
    }
}
