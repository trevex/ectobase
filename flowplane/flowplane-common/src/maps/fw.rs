//! Firewall map key & value types plus the firewall direction/action constants (the `FW_RULES`,
//! `FW_RULES6`, `FW_META`, `FW_META6` maps).
//!
//! The pure match logic (`fw_rule_matches` / `fw_rule6_matches` + the `PacketSelectors` /
//! `PacketSelectors6` inputs) deliberately lives in `flowplane-core` (`flowplane_core::firewall`),
//! not here: this is a shared *types* crate, and the datapath firewall evaluator that consumes these
//! rules already lives in `flowplane-core`. Keeping only the POD rule types here avoids hiding
//! datapath logic in the types crate (review P1.2).

/// Max firewall rules scanned per interface per direction in the datapath (bounded loop).
pub const FW_MAX_RULES: u32 = 16;

/// Firewall rule slot key: (interface ifindex, slot index 0..FW_MAX_RULES).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct FwRuleKey {
    pub ifindex: u32,
    pub idx: u32,
}

/// A single firewall rule (fixed-size POD). Ports are inclusive ranges (0..=65535 = any);
/// icmp_type/icmp_code 0xffff = any; proto 0 = any; action 1=accept/0=drop; direction
/// 1=egress/0=ingress; enabled 1 = slot in use.
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

/// IPv6 firewall rule (fixed-size POD). Identical to `FwRule` but 16-byte addresses/masks.
/// Programmed into the parallel `FW_RULES6` map; the v4 `FwRule`/`FW_RULES` are untouched.
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

/// Per-interface rule counts (so empty-direction => ACCEPT can be decided cheaply).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwMeta {
    pub ingress_count: u32,
    pub egress_count: u32,
}

pub const FW_DIR_INGRESS: u8 = 0;
pub const FW_DIR_EGRESS: u8 = 1;
pub const FW_ACTION_DROP: u8 = 0;
pub const FW_ACTION_ACCEPT: u8 = 1;

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for FwRuleKey {}
    unsafe impl aya::Pod for FwRule {}
    unsafe impl aya::Pod for FwRule6 {}
    unsafe impl aya::Pod for FwMeta {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn fw_rule_key_word_packed() {
        assert_eq!(size_of::<FwRuleKey>(), 4 + 4);
    }

    #[test]
    fn fw_types_layout() {
        // 4 (ifindex) + 4 (idx) = 8.
        assert_eq!(size_of::<FwRuleKey>(), 8);
        // 4*4 (ip/mask pairs) + 4*2 (port ranges) + 2+2 (icmp) + 4 (proto/action/dir/enabled) = 32.
        assert_eq!(size_of::<FwRule>(), 32);
        // 4 (ingress_count) + 4 (egress_count) = 8.
        assert_eq!(size_of::<FwMeta>(), 8);
    }

    #[test]
    fn fw6_types_layout() {
        assert_eq!(size_of::<FwRule6>(), 80);
        // regression guard: v4 layouts unchanged
        assert_eq!(size_of::<FwRule>(), 32);
        assert_eq!(size_of::<FwMeta>(), 8);
    }
}
