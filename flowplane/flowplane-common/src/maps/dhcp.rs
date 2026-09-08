//! DHCP config map value types (the `DHCP_CONFIG` / `DHCP_META` maps).
//!
//! NOTE: the cheap fixed-offset DHCP *wire* detectors (`looks_like_dhcpv4` / `looks_like_dhcpv6`)
//! live in the top-level `crate::dhcp` module — this file holds only the map POD config types.

/// Max DNS servers per family carried in DHCP replies (caps the in-map array — 8 covers the
/// conformance set + headroom).
pub const DHCP_MAX_DNS: usize = 8;

/// Server-wide DHCP config (DHCP_CONFIG[0]): the MTU + v4/v6 DNS server lists advertised in DHCP replies.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DhcpConfig {
    pub mtu: u16,
    pub dns4_len: u8, // number of valid entries in dns4
    pub dns6_len: u8, // number of valid entries in dns6
    pub dns4: [[u8; 4]; DHCP_MAX_DNS],
    pub dns6: [[u8; 16]; DHCP_MAX_DNS],
}

/// Per-interface DHCP config (DHCP_META[ifindex]). hostname + PXE; the guest IP/MAC come from PORT_META.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DhcpMeta {
    pub hostname: [u8; 64],
    pub hostname_len: u8,
    pub boot_filename: [u8; 64],
    pub boot_filename_len: u8,
    /// Printable PXE server string for DHCPv6 BootFileUrl option, e.g. "2001:dede::1"
    /// (without brackets; the eBPF responder wraps it with "[" and "]" in the URL).
    /// All-zero / pxe_host_len==0 means no PXE. Max 46 bytes (IPv6 INET6_ADDRSTRLEN).
    pub pxe_host: [u8; 46],
    pub pxe_host_len: u8,
    pub _pad: [u8; 1],
}

// SAFETY: `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so their
// raw bytes are a valid map value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for DhcpConfig {}
    unsafe impl aya::Pod for DhcpMeta {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn dhcp_layouts() {
        assert_eq!(
            size_of::<DhcpConfig>(),
            2 + 1 + 1 + 4 * DHCP_MAX_DNS + 16 * DHCP_MAX_DNS
        );
        // hostname(64) + hostname_len(1) + boot_filename(64) + boot_filename_len(1)
        // + pxe_host(46) + pxe_host_len(1) + _pad(1) = 178
        assert_eq!(size_of::<DhcpMeta>(), 64 + 1 + 64 + 1 + 46 + 1 + 1);
    }
}
