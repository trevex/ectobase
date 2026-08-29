//! Pure parse/validate helpers: proto string fields → flowplane-control domain types.
//!
//! The eBPF `flowplane` node service uses these; keeping a single copy here enforces
//! byte-identical behaviour wherever the node service is invoked.

/// Parse a CIDR string into (is_v6, 16-byte address buffer, prefix_len). For IPv4 the four octets
/// are left-aligned in the buffer (bytes[0..4]). Verbatim from the eBPF node service.
pub fn parse_prefix(cidr: &str) -> anyhow::Result<(bool, [u8; 16], u32)> {
    use std::net::IpAddr;
    let (addr, len) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("prefix {cidr:?} missing /len"))?;
    let len: u32 = len
        .parse()
        .map_err(|_| anyhow::anyhow!("bad prefix len in {cidr:?}"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("bad address in {cidr:?}"))?;
    let mut buf = [0u8; 16];
    match ip {
        IpAddr::V4(a) => {
            if len > 32 {
                anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}");
            }
            buf[..4].copy_from_slice(&a.octets());
            Ok((false, buf, len))
        }
        IpAddr::V6(a) => {
            if len > 128 {
                anyhow::bail!("v6 prefix len {len} > 128 in {cidr:?}");
            }
            buf.copy_from_slice(&a.octets());
            Ok((true, buf, len))
        }
    }
}

/// A parsed firewall CIDR, family-tagged. IPv4 stores `(ip, mask)` as four octets each; IPv6 as
/// sixteen octets each. The handler branches on the variant to build a `FwRule` or `FwRule6`.
pub enum FwCidr {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

/// Parse a firewall CIDR into a family-tagged `(ip, mask)`. Empty = "any" (v4 wildcard `0.0.0.0/0`);
/// bare address = full-length prefix. Accepts both IPv4 and IPv6. Verbatim-derived from the eBPF
/// node service, extended for v6.
pub fn parse_fw_cidr(cidr: &str) -> anyhow::Result<FwCidr> {
    if cidr.is_empty() {
        // empty = v4 wildcard; caller re-encodes if the rule is v6
        return Ok(FwCidr::V4([0u8; 4], [0u8; 4]));
    }
    let (addr, len_str) = match cidr.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (cidr, None),
    };
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        let len: u32 = len_str.map(|l| l.parse()).transpose()?.unwrap_or(32);
        if len > 32 {
            anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}");
        }
        let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        return Ok(FwCidr::V4(v4.octets(), mask.to_be_bytes()));
    }
    let v6: std::net::Ipv6Addr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("bad ip address in {cidr:?}"))?;
    let len: u32 = len_str.map(|l| l.parse()).transpose()?.unwrap_or(128);
    if len > 128 {
        anyhow::bail!("v6 prefix len {len} > 128 in {cidr:?}");
    }
    let mask: u128 = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    Ok(FwCidr::V6(v6.octets(), mask.to_be_bytes()))
}

/// Parse an IPv6 nexthop underlay address into 16 bytes.
pub fn parse_nexthop6(s: &str) -> anyhow::Result<[u8; 16]> {
    let a: std::net::Ipv6Addr = s
        .parse()
        .map_err(|_| anyhow::anyhow!("bad nexthop underlay ipv6 {s:?}"))?;
    Ok(a.octets())
}

/// Parse an IPv4 address string into its four octets.
pub fn parse_ipv4(s: &str) -> anyhow::Result<[u8; 4]> {
    let a: std::net::Ipv4Addr = s.parse().map_err(|_| anyhow::anyhow!("bad ipv4 {s:?}"))?;
    Ok(a.octets())
}

/// Narrow a proto `uint32` port into a `u16`, rejecting out-of-range values.
pub fn port_u16(p: u32) -> anyhow::Result<u16> {
    u16::try_from(p).map_err(|_| anyhow::anyhow!("port {p} out of range (0..=65535)"))
}

/// Parse a `xx:xx:xx:xx:xx:xx` MAC into 6 bytes.
pub fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            anyhow::bail!("bad mac {s:?}: too many octets");
        }
        out[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow::anyhow!("bad mac octet {part:?} in {s:?}"))?;
        n += 1;
    }
    if n != 6 {
        anyhow::bail!("bad mac {s:?}: expected 6 octets, got {n}");
    }
    Ok(out)
}

/// First IPv4 in a `requested_ips` list, or `0.0.0.0` if none. The CNI passes overlay IPs as
/// strings; the eBPF node's attach programs the v4/v6 it finds (IPAM of unset IPs is B2).
pub fn first_ipv4(ips: &[String]) -> [u8; 4] {
    ips.iter()
        .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| a.octets())
        .next()
        .unwrap_or([0u8; 4])
}

/// First IPv6 in a `requested_ips` list, or the all-zero address if none.
pub fn first_ipv6(ips: &[String]) -> [u8; 16] {
    ips.iter()
        .filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok())
        .map(|a| a.octets())
        .next()
        .unwrap_or([0u8; 16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_v4_and_v6() {
        // (is_v6, 16-byte buffer with the address left-aligned for v4, prefix_len)
        let (v6, bytes, len) = parse_prefix("10.0.0.5/32").unwrap();
        assert!(!v6);
        assert_eq!(&bytes[..4], &[10, 0, 0, 5]);
        assert_eq!(len, 32);

        let (v6, bytes, len) = parse_prefix("2001:db8::5/128").unwrap();
        assert!(v6);
        assert_eq!(
            bytes,
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets()
        );
        assert_eq!(len, 128);
    }

    #[test]
    fn parse_prefix_rejects_bad() {
        assert!(parse_prefix("10.0.0.5").is_err()); // no /len
        assert!(parse_prefix("10.0.0.5/33").is_err()); // v4 len > 32
        assert!(parse_prefix("nonsense/32").is_err());
    }

    #[test]
    fn port_u16_bounds() {
        assert_eq!(port_u16(0).unwrap(), 0);
        assert_eq!(port_u16(65535).unwrap(), 65535);
        assert!(port_u16(65536).is_err());
    }

    #[test]
    fn parse_mac_ok_and_bad() {
        assert_eq!(parse_mac("02:00:00:00:00:01").unwrap(), [2, 0, 0, 0, 0, 1]);
        assert!(parse_mac("not-a-mac").is_err());
    }

    #[test]
    fn parse_fw_cidr_v6() {
        match parse_fw_cidr("2001:db8::/32").unwrap() {
            FwCidr::V6(ip, mask) => {
                assert_eq!(&ip[0..2], &[0x20, 0x01]);
                assert_eq!(&mask[0..4], &[0xff, 0xff, 0xff, 0xff]);
                assert_eq!(mask[4], 0x00);
            }
            _ => panic!("expected V6"),
        }
        assert!(matches!(
            parse_fw_cidr("10.0.0.0/8").unwrap(),
            FwCidr::V4(..)
        ));
        assert!(matches!(parse_fw_cidr("::/0").unwrap(), FwCidr::V6(_, m) if m == [0u8;16]));
        assert!(parse_fw_cidr("2001:db8::/129").is_err());
    }
}
