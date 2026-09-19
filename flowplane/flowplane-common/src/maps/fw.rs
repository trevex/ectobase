//! Firewall rule types plus the firewall direction/action constants.
//!
//! `FwRule`/`FwRule6` are the dataplane's form of one rule in an interface's first-match list: the
//! `ReplaceInterfaceFirewall` handler parses the wire rules into them, and the classifier compiler
//! (`flowplane_control::fwclass`) turns the lists into the scopes the datapath evaluates
//! (`FwBind`/`FwPolKey`, `fwclass.rs`). They are no longer stored in any map.

/// A single firewall rule. Ports are inclusive ranges (0..=65535 = any); icmp_type/icmp_code
/// 0xffff = any; proto 0 = any; action 1=accept/0=drop; direction 1=egress/0=ingress; enabled 1 =
/// the rule is live.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwRule {
    pub src_ip: [u8; 4],
    pub src_mask: [u8; 4],
    pub dst_ip: [u8; 4],
    pub dst_mask: [u8; 4],
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub enabled: u8,
}

/// IPv6 firewall rule. Identical to `FwRule` but 16-byte addresses/masks.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwRule6 {
    pub src_ip: [u8; 16],
    pub src_mask: [u8; 16],
    pub dst_ip: [u8; 16],
    pub dst_mask: [u8; 16],
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub enabled: u8,
}

pub const FW_DIR_INGRESS: u8 = 0;
pub const FW_DIR_EGRESS: u8 = 1;
pub const FW_ACTION_DROP: u8 = 0;
pub const FW_ACTION_ACCEPT: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn fw_types_layout() {
        // 4*4 (ip/mask pairs) + 4*2 (port ranges) + 2+2 (icmp) + 4 (proto/action/dir/enabled) = 32.
        assert_eq!(size_of::<FwRule>(), 32);
        assert_eq!(size_of::<FwRule6>(), 80);
    }
}
