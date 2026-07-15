//! Pure IPv4 parse helpers rewritten over the `Pkt` trait (no raw pointers). Faithful ports of the
//! eBPF `parse::l4_ports` / `firewall::icmp_type_code`. `PacketSelectors` and `fw_rule_matches` are
//! single-sourced in `xdp-dp-common` and re-exported here for the core firewall evaluator.

use crate::pkt::Pkt;

pub use xdp_dp_common::{fw_rule_matches, PacketSelectors};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Read the L4 "ports" for a parsed IPv4 packet at `ip_off`. For TCP/UDP returns (proto,sport,dport)
/// with ports in host order; for ICMP returns (proto,id,id). Returns None if out of bounds /
/// unsupported. Faithful port of the eBPF `parse::l4_ports`.
#[inline(always)]
pub fn l4_ports<P: Pkt>(pkt: &P, ip_off: usize) -> Option<(u8, u16, u16)> {
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`: the full 20-byte IPv4 header
    // must be present before we read IHL/proto.
    let hdr = pkt.read_array::<20>(ip_off)?;
    let ihl = (hdr[0] & 0x0f) as usize * 4;
    let proto = hdr[9];
    let l4 = ip_off + ihl;
    match proto {
        IPPROTO_TCP | IPPROTO_UDP => {
            let sp = pkt.read_u16_be(l4)?;
            let dp = pkt.read_u16_be(l4 + 2)?;
            Some((proto, sp, dp))
        }
        IPPROTO_ICMP => {
            let id = pkt.read_u16_be(l4 + 4)?;
            Some((proto, id, id))
        }
        _ => None,
    }
}

/// Extract ICMP (type, code) for an IPv4 packet at `ip_off` (0,0 if not ICMP / OOB / has options).
/// Faithful port of the eBPF `firewall::icmp_type_code`.
#[inline(always)]
pub fn icmp_type_code<P: Pkt>(pkt: &P, ip_off: usize) -> (u16, u16) {
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`.
    let hdr = match pkt.read_array::<20>(ip_off) {
        Some(h) => h,
        None => return (0, 0),
    };
    if hdr[0] & 0x0f != 5 || hdr[9] != IPPROTO_ICMP {
        return (0, 0);
    }
    let l4 = ip_off + 20;
    match pkt.read_array::<2>(l4) {
        Some(b) => (b[0] as u16, b[1] as u16),
        None => (0, 0),
    }
}
