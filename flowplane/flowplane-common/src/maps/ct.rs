//! Conntrack map key & value types plus the connection-tracking flag / TCP-state constants
//! (the `CONNTRACK`, `CONNTRACK6`, `NAT_CT6` maps).

/// Conntrack key: the VNI + 5-tuple (host-order ports; for ICMP the ports hold the id).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct CtKey {
    pub vni: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// IPv6 conntrack key (firewall-only). Mirror of `CtKey` with 16-byte addresses.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct CtKey6 {
    pub vni: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Unified conntrack entry value. Keyed by the 5-tuple (`CtKey`) of the packet that will be SEEN;
/// the datapath's `ct_apply` rewrites that packet's src or dst address (+L4 port) to
/// `xlate_ip`/`xlate_port`.
///
/// DSR reverse-SNAT state does NOT live here: storing it inline would grow `CtEntry`, and the copy
/// landing in the hot `ct_apply`/`ct_create_default` stack frames would push `uplink_rx`'s combined
/// BPF stack over the 512-byte verifier limit. DSR reverse state lives in its own compact `DSR`/`DSR6`
/// LRU maps (see `DsrLbIP`), keyed by the reply 5-tuple; `CtEntry` stays at 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry {
    pub last_seen: u64,
    pub xlate_ip: [u8; 4],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub fwall_action: u8,
    /// Padding up to `policy_epoch`'s alignment; the whole value stays 24 bytes / align 8 (the eBPF
    /// `CONNTRACK`/`CONNTRACK6` map value ABI).
    pub _pad: [u8; 3],
    /// The node's firewall epoch (`FW_EPOCH`) this flow was last evaluated under. A FORWARD entry
    /// (see [`CT_F_REPLY`]) hit under a newer epoch meets the firewall again before it is used, so a
    /// policy change reaches established flows on their next packet. 32 bits: never wraps in
    /// practice, so a stale entry cannot alias the current epoch.
    pub policy_epoch: u32,
}

// CtEntry.flags bits
pub const CT_REWRITE_SRC: u8 = 0x01;
pub const CT_REWRITE_DST: u8 = 0x02;
pub const CT_F_SRC_NAT: u8 = 0x04;
pub const CT_F_DST_LB: u8 = 0x08;
pub const CT_F_DEFAULT: u8 = 0x10;
pub const CT_F_FIREWALL: u8 = 0x20;
/// Set on NAT64 flows (IPv6 guest → IPv4 external via the 64:ff9b::/96 prefix). Both the forward
/// and reverse conntrack entries carry this flag so the ingress reply path knows to expand
/// IPv4 back to IPv6 when delivering the translated reply to the guest.
pub const CT_F_NAT64: u8 = 0x40;
/// A pre-seeded REVERSE default entry: it carries the replies of the flow that created it and is
/// never re-evaluated by the firewall (a reply is allowed because its flow was). NAT reverse entries
/// are replies too; they are recognised by `CT_REWRITE_DST`. DSR reverse-SNAT state lives in the
/// dedicated `DSR`/`DSR6` maps (see `DsrLbIP`), not in CtEntry flags.
pub const CT_F_REPLY: u8 = 0x80;

/// Dedicated v6 NAT (NAT66) conntrack value, keyed by `CtKey6` in the `NAT_CT6` map. The v4 NAT
/// stores its xlate state in `CtEntry.xlate_ip` (`[u8;4]`, v4-only), which is not grown to hold a v6
/// address (that would break the 24-byte layout / 512B-BPF-stack constraint), so NAT66 gets its own
/// value type + map, like the dedicated `DSR6` v6 map. Same `CT_*` flags as [`CtEntry`]
/// (`CT_REWRITE_SRC`/`CT_REWRITE_DST`/`CT_F_SRC_NAT`).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry6 {
    pub last_seen: u64,
    pub xlate_ip6: [u8; 16],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub _pad: [u8; 4],
}

// CtEntry.tcp_state values (TCP connection-tracking state machine)
pub const TCP_NONE: u8 = 0;
pub const TCP_NEW_SYN: u8 = 1;
pub const TCP_NEW_SYNACK: u8 = 2;
pub const TCP_ESTABLISHED: u8 = 3;
pub const TCP_FINWAIT: u8 = 4;
pub const TCP_RST_FIN: u8 = 5;

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for CtKey {}
    unsafe impl aya::Pod for CtKey6 {}
    unsafe impl aya::Pod for CtEntry {}
    unsafe impl aya::Pod for CtEntry6 {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn ct_key_has_no_implicit_padding() {
        // BPF map lookups hash the *raw bytes* of the key, so any implicit padding hole silently
        // breaks lookups. Pin the field offsets and assert no padding beyond the explicit `_pad`.
        // CtKey: vni(4) src_ip(4) dst_ip(4) src_port(2) dst_port(2) proto(1) _pad(3) = 20.
        assert_eq!(offset_of!(CtKey, vni), 0);
        assert_eq!(offset_of!(CtKey, src_ip), 4);
        assert_eq!(offset_of!(CtKey, dst_ip), 8);
        assert_eq!(offset_of!(CtKey, src_port), 12);
        assert_eq!(offset_of!(CtKey, dst_port), 14);
        assert_eq!(offset_of!(CtKey, proto), 16);
        assert_eq!(offset_of!(CtKey, _pad), 17);
        assert_eq!(size_of::<CtKey>(), 4 + 4 + 4 + 2 + 2 + 1 + 3);
        assert_eq!(align_of::<CtKey>(), 4, "CtKey must stay 4-byte aligned");
    }

    #[test]
    fn ct_key_layouts() {
        assert_eq!(size_of::<CtKey>(), 20);
        assert_eq!(size_of::<CtKey6>(), 44);
    }

    #[test]
    fn ct_entry_layout() {
        // 8 (last_seen) + 4 (xlate_ip) + 2 (xlate_port) + 1 (flags) + 1 (tcp_state)
        // + 1 (fwall_action) + 3 (_pad) + 4 (policy_epoch) = 24, u64-aligned. CONNTRACK/CONNTRACK6 are RUNTIME LRU maps
        // re-created on load — growing/shrinking the value is NOT a wire/journal ABI concern; the
        // coupling is the core+ebpf ct_apply twins + the aya_writer GC + this test, changed together.
        assert_eq!(size_of::<CtEntry>(), 24);
        // Alignment must also be unchanged (u64 = 8) — a bigger alignment would change the map layout.
        assert_eq!(align_of::<CtEntry>(), 8);
        // The epoch took over the old trailing pad: no hole before it.
        assert_eq!(offset_of!(CtEntry, policy_epoch), 20);
    }

    #[test]
    fn ct_entry6_layout() {
        assert_eq!(size_of::<CtEntry6>(), 32); // 8 + 16 + 2 + 1 + 1 + 4
        assert_eq!(align_of::<CtEntry6>(), 8);
    }
}
