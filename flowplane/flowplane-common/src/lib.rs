#![cfg_attr(not(feature = "user"), no_std)]

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
}

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Value for the `interfaces` map: how to reach/deliver to an overlay IP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote).
    pub tap_ifindex: u32,
    /// 1 = interface is local to this hypervisor, 0 = remote.
    pub is_local: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (tunnel dst for remote).
    pub underlay_ipv6: [u8; 16],
    /// Guest MAC (inner eth dst for local delivery).
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// Ingress delivery entry: an interface's underlay IPv6 -> its VNI + local tap + guest MAC.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct UnderlayValue {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// Sentinel `UnderlayValue::tap_ifindex` marking a WAN-edge local-deliver underlay: `uplink_rx`
/// decaps the inner IPv4 and XDP_PASSes it to the local kernel (VyOS routes/masquerades to the real
/// WAN) instead of redirecting to a guest tap. A real ifindex is never `u32::MAX`; `tap_ifindex==0`
/// already means an LB-anycast VNF, so this needs a distinct value.
pub const UNDERLAY_LOCAL_DELIVER: u32 = u32::MAX;

/// Per-port metadata, keyed by the guest tap's host-side ifindex.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PortMeta {
    pub vni: u32,
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
    pub underlay_ipv6: [u8; 16],
    pub gateway_ipv6: [u8; 16],
    /// Guest overlay IPv6 address (all-zero when the guest is IPv4-only). Used by NAT64 to
    /// reconstruct the IPv6 destination of the reply packet.
    pub guest_ipv6: [u8; 16],
}

impl IfaceKey {
    pub fn new(vni: u32, ipv4: [u8; 4]) -> Self {
        Self { vni, ipv4 }
    }
}

/// Max bytes of an `interface_id` persisted in the `IFACE_META` restart journal. An interface_id is
/// a k8s UID plus a short interface name (~60 bytes in practice); attach rejects longer ids.
pub const IFACE_ID_MAX: usize = 64;
/// Max bytes of a device (kernel netdev) name in the journal — Linux IFNAMSIZ (16) covers it.
pub const IFACE_DEV_MAX: usize = 16;

/// Key of the `IFACE_META` restart journal: the full `interface_id`, zero-padded to a fixed width so
/// the whole id survives a restart (a hash would lose it — we need the id back verbatim to rebuild
/// `by_id`/`links`). Written by userspace only; the datapath never reads this map.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfaceMetaKey {
    pub id: [u8; IFACE_ID_MAX],
}

/// Value of the `IFACE_META` restart journal: everything the control plane needs to rebuild its
/// in-memory bookkeeping and re-attach the guest program after an flowplane restart. `id_len`/`device_len`
/// give the used prefix of the padded `IfaceMetaKey.id` / `device`. `tap_ifindex` is the ifindex at
/// attach time; the rebuild re-derives the live ifindex from `device` (the veth persists) and treats
/// this as a cross-check. Field order is chosen so the struct has no implicit padding.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfaceMetaVal {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub ipv4: [u8; 4],
    pub id_len: u16,
    pub device_len: u16,
    pub ipv6: [u8; 16],
    pub underlay: [u8; 16],
    pub device: [u8; IFACE_DEV_MAX],
}

impl IfaceMetaKey {
    /// Pad `id` into the fixed-width key. Returns `None` if `id` exceeds [`IFACE_ID_MAX`] (attach
    /// rejects such ids rather than silently truncating — a truncated key could alias another id).
    pub fn from_id(id: &[u8]) -> Option<Self> {
        if id.len() > IFACE_ID_MAX {
            return None;
        }
        let mut k = [0u8; IFACE_ID_MAX];
        k[..id.len()].copy_from_slice(id);
        Some(Self { id: k })
    }
}

/// Key for the `routes` map: (VNI, IPv4 prefix). Host-order length in `prefix_len`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    pub vni: u32,
    pub prefix_len: u32,
    pub ipv4: [u8; 4],
}

/// LPM-trie key data for `ROUTES`: VNI (big-endian, matched MSB-first as a fixed 32-bit VRF
/// discriminator) followed by the IPv4 octets (network order, variable prefix).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData {
    pub vni: [u8; 4],
    pub ipv4: [u8; 4],
}

/// LPM-trie key data for `ROUTES6`: VNI (big-endian) + IPv6 (network order, variable prefix).
/// prefix_len = 32 + v6_prefix_len; lookups use prefix_len = 160.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData6 {
    pub vni: [u8; 4],
    pub ipv6: [u8; 16],
}

/// Value for the `routes` map: the underlay IPv6 nexthop (tunnel dst). MAC-free — the outer
/// L2 next-hop is the single underlay gateway in `Local`, not per-route.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct RouteValue {
    pub nexthop_vni: u32,
    pub nexthop_ipv6: [u8; 16],
    /// 1 = the nexthop is the external/public network (NAT-eligible egress); 0 = overlay peer.
    pub is_external: u8,
    pub _pad: [u8; 3],
}

/// Per-interface egress token buckets. `*_bps` are bytes/sec (0 = unlimited); `*_tokens`/`*_last_ns`
/// are mutable runtime state refilled from bpf_ktime. `total` gates all egress; `public` gates
/// south-north (external) egress.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MeterState {
    pub total_bps: u64,
    pub total_burst: u64,
    pub total_tokens: u64,
    pub total_last_ns: u64,
    pub public_bps: u64,
    pub public_burst: u64,
    pub public_tokens: u64,
    pub public_last_ns: u64,
}

/// This hypervisor's uplink + underlay gateway, written once into LOCAL[0] by the control plane.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Local {
    pub uplink_ifindex: u32,
    pub uplink_mac: [u8; 6],
    /// Underlay next-hop (gateway/ToR router) MAC — outer eth dst for ALL encapped traffic.
    pub gateway_mac: [u8; 6],
    pub underlay_ipv6: [u8; 16],
}

/// Debug-only type for the `INSPECT` map: records the first 32 bytes of the first packet an
/// XDP program sees, plus the total length and a per-packet counter.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct InspectEntry {
    pub len: u32,
    pub seen: u32,
    pub bytes: [u8; 32],
}

/// Key for the `vips` map: (VNI, IPv4). Value is the mapped IPv4 (the 1:1 counterpart).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct VipKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// LB service key: (vni, balanced IPv4, L4 port, proto). proto: 6=TCP, 17=UDP, 1=ICMP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct LbKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// LB value: the Maglev table id + its size (number of slots).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct LbValue {
    pub table_id: u32,
    pub size: u32,
}

/// Maglev slot key: (table_id, slot). Value in the map is the backend IPv4 (`[u8;4]`).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct MaglevKey {
    pub table_id: u32,
    pub slot: u32,
}

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

/// NAT-GW config key: (vni, local guest IPv4).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NatKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// NAT-GW config value: the public NAT IPv4 + the source-port range [port_min, port_max).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NatValue {
    pub nat_ipv4: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// Unified conntrack entry value. Keyed by the 5-tuple (`CtKey`) of the packet that will be SEEN;
/// the datapath's `ct_apply` rewrites that packet's src or dst address (+L4 port) to
/// `xlate_ip`/`xlate_port`. Replaces the feature-private `CtVal`/`NatCtVal` (removed in M5 Task 3).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry {
    pub last_seen: u64,
    pub xlate_ip: [u8; 4],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub fwall_action: u8,
    pub _pad: [u8; 7],
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

// CtEntry.tcp_state values (mirror dpservice dp_flow_tcp_state)
pub const TCP_NONE: u8 = 0;
pub const TCP_NEW_SYN: u8 = 1;
pub const TCP_NEW_SYNACK: u8 = 2;
pub const TCP_ESTABLISHED: u8 = 3;
pub const TCP_FINWAIT: u8 = 4;
pub const TCP_RST_FIN: u8 = 5;

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

/// Per-interface rule counts (so empty-direction => ACCEPT can be decided cheaply).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwMeta {
    pub ingress_count: u32,
    pub egress_count: u32,
}

/// Max DNS servers per family carried in DHCP replies (dpservice's flags are repeatable; this caps
/// the in-map array — 8 covers the conformance set + headroom).
pub const DHCP_MAX_DNS: usize = 8;

/// Tail-call indices into the `GUEST_PROGS` program array (egress datapath split).
/// `GUEST_PROG_DHCP` is used in Phase 1; IPV4/IPV6 are reserved for the Phase 2 split.
pub const GUEST_PROG_DHCP: u32 = 0;
pub const GUEST_PROG_IPV4: u32 = 1;
pub const GUEST_PROG_IPV6: u32 = 2;

/// Server-wide DHCP config (DHCP_CONFIG[0]). Mirrors dpservice's --dhcp-mtu/--dhcp-dns/--dhcpv6-dns.
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

pub const FW_DIR_INGRESS: u8 = 0;
pub const FW_DIR_EGRESS: u8 = 1;
pub const FW_ACTION_DROP: u8 = 0;
pub const FW_ACTION_ACCEPT: u8 = 1;

/// Maximum number of neighbor-NAT entries the datapath will scan.
pub const NB_MAX_ENTRIES: u32 = 64;

/// A neighbor-NAT entry: a remote node owns `(vni, nat_ip, [port_min, port_max))`; return traffic
/// to that nat_ip:port is re-forwarded to `underlay`. `enabled` 1 = slot in use.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NeighborNatEntry {
    pub underlay: [u8; 16],
    pub nat_ip: [u8; 4],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

/// The packet fields a firewall rule is matched against. `icmp_type`/`icmp_code` are only
/// consulted when `proto == 1` (ICMP).
pub struct PacketSelectors {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
}

/// Pure firewall match (no_std; used by the datapath and host-tested). Returns true if `r` matches
/// the packet selectors `s`.
#[inline]
pub fn fw_rule_matches(r: &FwRule, s: &PacketSelectors) -> bool {
    let PacketSelectors {
        src,
        dst,
        proto,
        sport,
        dport,
        icmp_type,
        icmp_code,
    } = *s;
    if r.enabled == 0 {
        return false;
    }
    if r.proto != 0 && r.proto != proto {
        return false;
    }
    for i in 0..4 {
        if src[i] & r.src_mask[i] != r.src_ip[i] & r.src_mask[i] {
            return false;
        }
        if dst[i] & r.dst_mask[i] != r.dst_ip[i] & r.dst_mask[i] {
            return false;
        }
    }
    match proto {
        6 | 17 => {
            sport >= r.src_port_min
                && sport <= r.src_port_max
                && dport >= r.dst_port_min
                && dport <= r.dst_port_max
        }
        1 => {
            (r.icmp_type == 0xffff || icmp_type == r.icmp_type)
                && (r.icmp_code == 0xffff || icmp_code == r.icmp_code)
        }
        _ => true,
    }
}

/// Single-entry `CONFIG` map: per-hypervisor datapath parameters for the PoC's
/// CONFIG-driven single-peer overlay (one guest + one peer hypervisor). The XDP programs
/// read entry 0; the control plane populates it. MACs/ifindexes are filled at e2e time.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Config {
    /// Overlay VNI this hypervisor's guest belongs to.
    pub vni: u32,
    /// ifindex of the underlay-facing uplink (encap redirect target).
    pub uplink_ifindex: u32,
    /// ifindex of the guest-facing tap/veth (decap redirect target).
    pub guest_ifindex: u32,
    pub _pad: u32,
    /// This hypervisor's underlay IPv6 (outer src on encap).
    pub local_underlay_ipv6: [u8; 16],
    /// The peer hypervisor's underlay IPv6 (outer dst on encap).
    pub peer_underlay_ipv6: [u8; 16],
    /// Uplink source MAC (outer eth src on encap).
    pub local_mac: [u8; 6],
    /// Peer uplink MAC (outer eth dst on encap).
    pub peer_mac: [u8; 6],
    /// Guest MAC (inner eth dst on decap delivery).
    pub guest_mac: [u8; 6],
    pub _pad2: [u8; 2],
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for IfaceKey {}
    unsafe impl aya::Pod for IfaceValue {}
    unsafe impl aya::Pod for IfaceMetaKey {}
    unsafe impl aya::Pod for IfaceMetaVal {}
    unsafe impl aya::Pod for UnderlayValue {}
    unsafe impl aya::Pod for PortMeta {}
    unsafe impl aya::Pod for RouteKey {}
    unsafe impl aya::Pod for RouteLpmData {}
    unsafe impl aya::Pod for RouteLpmData6 {}
    unsafe impl aya::Pod for RouteValue {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Local {}
    unsafe impl aya::Pod for InspectEntry {}
    unsafe impl aya::Pod for VipKey {}
    unsafe impl aya::Pod for LbKey {}
    unsafe impl aya::Pod for LbValue {}
    unsafe impl aya::Pod for MaglevKey {}
    unsafe impl aya::Pod for CtKey {}
    unsafe impl aya::Pod for NatKey {}
    unsafe impl aya::Pod for NatValue {}
    unsafe impl aya::Pod for CtEntry {}
    unsafe impl aya::Pod for FwRuleKey {}
    unsafe impl aya::Pod for FwRule {}
    unsafe impl aya::Pod for FwMeta {}
    unsafe impl aya::Pod for NeighborNatEntry {}
    unsafe impl aya::Pod for MeterState {}
    unsafe impl aya::Pod for DhcpConfig {}
    unsafe impl aya::Pod for DhcpMeta {}
}

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

/// Pure, host-tested ARP/ND responder byte-rewrites. The datapath glue (XDP and tc) supplies the
/// gateway address + reply MAC (from maps) and ensures the header range is writable; these
/// functions only read/rewrite bytes in [data, data_end). Mirrors the `dhcp` module.
pub mod arp_nd {
    // L2/L3 protocol constants are single-sourced in `super::proto`; re-exported here so existing
    // `arp_nd::{ETH_LEN, IPV6_LEN, ETH_P_IPV6}` import paths keep resolving.
    pub use super::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};
    pub const ETH_P_ARP: u16 = 0x0806;
    pub const ARP_LEN: usize = 28; // opcode@6 sha@8 spa@14 tha@18 tpa@24

    pub const IPPROTO_ICMPV6: u8 = 58;
    const ND_NS: u8 = 135;
    const ND_NA: u8 = 136;

    #[inline(always)]
    unsafe fn write6(dst: *mut u8, src: &[u8; 6]) {
        let mut i = 0;
        while i < 6 {
            *dst.add(i) = src[i];
            i += 1;
        }
    }

    #[inline(always)]
    unsafe fn write16(dst: *mut u8, src: &[u8; 16]) {
        let mut i = 0;
        while i < 16 {
            *dst.add(i) = src[i];
            i += 1;
        }
    }

    /// One's-complement checksum over `len` bytes at `ptr`, plus an initial `sum` (pseudo-header).
    ///
    /// The carry-propagation is done with exactly 2 fixed iterations (not a while loop) because
    /// the BPF verifier requires bounded loops and one's complement fold needs at most 2 steps.
    #[inline(always)]
    pub(crate) unsafe fn csum16(mut sum: u32, ptr: *const u8, len: usize) -> u16 {
        let mut i = 0;
        while i + 1 < len {
            sum += u16::from_be(core::ptr::read_unaligned(ptr.add(i) as *const u16)) as u32;
            i += 2;
        }
        if i < len {
            sum += (*ptr.add(i) as u32) << 8;
        }
        // Fold carries: two rounds suffices for any 32-bit accumulator (BPF verifier requires
        // bounded loops, so we unroll rather than use `while sum >> 16 != 0`).
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        !(sum as u16)
    }

    /// If [data,data_end) is an ICMPv6 Neighbor Solicitation for `gateway_ipv6`, rewrite it in place
    /// into a solicited Neighbor Advertisement from `reply_mac` and return true. Else false.
    ///
    /// # Safety
    /// `data`/`data_end` must be the bounds of a single packet buffer (`data <= data_end`), and the
    /// caller must have made the first `ETH_LEN + IPV6_LEN + 32` bytes from `data` writable (e.g. via
    /// the XDP/tc direct-packet-access guarantees). The function re-checks the length internally and
    /// only writes when it fits, but the pointer itself must be valid.
    ///
    /// `#[inline(always)]`: the XDP `guest_tx` caller is stack-heavy (conntrack/nat/v6); keeping
    /// this out-of-line makes it a separate BPF subprogram whose frame is summed with the caller's,
    /// blowing the 512-byte BPF stack limit ("combined stack size of N calls too large").
    #[inline(always)]
    pub unsafe fn try_write_nd_reply(
        data: usize,
        data_end: usize,
        gateway_ipv6: [u8; 16],
        reply_mac: [u8; 6],
    ) -> bool {
        if data + ETH_LEN + IPV6_LEN + 32 > data_end {
            return false;
        }
        let p = data as *mut u8;
        let ethertype = u16::from_be(core::ptr::read_unaligned(p.add(12) as *const u16));
        if ethertype != ETH_P_IPV6 {
            return false;
        }
        let ip = p.add(ETH_LEN);
        if *ip.add(6) != IPPROTO_ICMPV6 {
            return false;
        }
        let icmp = p.add(ETH_LEN + IPV6_LEN);
        if *icmp != ND_NS {
            return false;
        }
        let target = core::ptr::read_unaligned(icmp.add(8) as *const [u8; 16]);
        if target != gateway_ipv6 {
            return false;
        }
        let req_mac = core::ptr::read_unaligned(p.add(6) as *const [u8; 6]);
        let req_src = core::ptr::read_unaligned(ip.add(8) as *const [u8; 16]);
        // Like ARP, present the virtual v6 gateway to the VF using the guest's own MAC.
        let gw_mac = reply_mac;
        write6(p, &req_mac);
        write6(p.add(6), &gw_mac);
        write16(ip.add(8), &gateway_ipv6);
        write16(ip.add(24), &req_src);
        *ip.add(7) = 255;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, 32u16.to_be());
        *icmp = ND_NA;
        *icmp.add(1) = 0;
        core::ptr::write_unaligned(icmp.add(2) as *mut u16, 0);
        *icmp.add(4) = 0x60;
        *icmp.add(5) = 0;
        *icmp.add(6) = 0;
        *icmp.add(7) = 0;
        // target @ +8 stays = gateway. Option @ +24: type=2 (target LL addr), len=1, gw_mac.
        *icmp.add(24) = 2;
        *icmp.add(25) = 1;
        write6(icmp.add(26), &gw_mac);
        let mut sum: u32 = 0;
        let mut k = 0;
        while k < 16 {
            sum += u16::from_be(core::ptr::read_unaligned(ip.add(8 + k) as *const u16)) as u32;
            sum += u16::from_be(core::ptr::read_unaligned(ip.add(24 + k) as *const u16)) as u32;
            k += 2;
        }
        sum += 32u32;
        sum += IPPROTO_ICMPV6 as u32;
        let cks = csum16(sum, icmp as *const u8, 32);
        core::ptr::write_unaligned(icmp.add(2) as *mut u16, cks.to_be());
        true
    }

    /// If [data,data_end) is an ARP request for `gateway_ipv4`, rewrite it in place into a reply
    /// from `reply_mac`/`gateway_ipv4` and return true. Else false (unchanged).
    ///
    /// # Safety
    /// `data`/`data_end` must bound a single packet buffer (`data <= data_end`), and the caller must
    /// have made the first `ETH_LEN + ARP_LEN` bytes from `data` writable. The length is re-checked
    /// internally before any write, but the `data` pointer itself must be valid.
    ///
    /// `#[inline(always)]` for the same BPF-stack reason as `try_write_nd_reply` (the XDP
    /// `guest_tx` caller is stack-heavy).
    #[inline(always)]
    pub unsafe fn try_write_arp_reply(
        data: usize,
        data_end: usize,
        gateway_ipv4: [u8; 4],
        reply_mac: [u8; 6],
    ) -> bool {
        if data + ETH_LEN + ARP_LEN > data_end {
            return false;
        }
        let p = data as *mut u8;
        let ethertype = u16::from_be(core::ptr::read_unaligned(p.add(12) as *const u16));
        if ethertype != ETH_P_ARP {
            return false;
        }
        let arp = p.add(ETH_LEN);
        let opcode = u16::from_be(core::ptr::read_unaligned(arp.add(6) as *const u16));
        if opcode != 1 {
            return false;
        }
        let tpa = core::ptr::read_unaligned(arp.add(24) as *const [u8; 4]);
        if tpa != gateway_ipv4 {
            return false;
        }
        let sender_mac = core::ptr::read_unaligned(arp.add(8) as *const [u8; 6]);
        let spa = core::ptr::read_unaligned(arp.add(14) as *const [u8; 4]);
        write6(p, &sender_mac);
        write6(p.add(6), &reply_mac);
        core::ptr::write_unaligned(arp.add(6) as *mut u16, 2u16.to_be());
        write6(arp.add(8), &reply_mac);
        core::ptr::write_unaligned(arp.add(14) as *mut [u8; 4], gateway_ipv4);
        write6(arp.add(18), &sender_mac);
        core::ptr::write_unaligned(arp.add(24) as *mut [u8; 4], spa);
        true
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rewrites_ns_to_na() {
            let gw6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut f = [0u8; ETH_LEN + IPV6_LEN + 32];
            f[6..12].copy_from_slice(&[0x52, 0x54, 0, 0, 0, 2]);
            f[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
            let ip = ETH_LEN;
            f[ip + 6] = 58;
            f[ip + 8..ip + 24]
                .copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            let ic = ETH_LEN + IPV6_LEN;
            f[ic] = 135;
            f[ic + 8..ic + 24].copy_from_slice(&gw6);
            let data = f.as_mut_ptr() as usize;
            let ok =
                unsafe { try_write_nd_reply(data, data + f.len(), gw6, [0x66, 0, 0, 0, 0, 1]) };
            assert!(ok);
            assert_eq!(&f[0..6], &[0x52, 0x54, 0, 0, 0, 2]); // eth dst = requester
            assert_eq!(&f[6..12], &[0x66, 0, 0, 0, 0, 1]); // eth src = reply mac
            assert_eq!(f[ic], 136); // NA
            assert_eq!(f[ic + 4], 0x60); // solicited+override flags
            assert_eq!(f[ic + 24], 2); // opt type = target LL addr
            assert_eq!(&f[ic + 26..ic + 32], &[0x66, 0, 0, 0, 0, 1]); // opt = reply mac
        }
        #[test]
        fn rewrites_arp_request_to_reply() {
            let mut f = [0u8; ETH_LEN + ARP_LEN];
            f[0..6].copy_from_slice(&[0xff; 6]);
            f[6..12].copy_from_slice(&[0x52, 0x54, 0, 0, 0, 2]);
            f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
            let a = ETH_LEN;
            f[a + 6..a + 8].copy_from_slice(&1u16.to_be_bytes());
            f[a + 8..a + 14].copy_from_slice(&[0x52, 0x54, 0, 0, 0, 2]);
            f[a + 14..a + 18].copy_from_slice(&[10, 0, 0, 2]);
            f[a + 24..a + 28].copy_from_slice(&[10, 0, 0, 1]);
            let data = f.as_mut_ptr() as usize;
            let ok = unsafe {
                try_write_arp_reply(data, data + f.len(), [10, 0, 0, 1], [0x66, 0, 0, 0, 0, 1])
            };
            assert!(ok);
            assert_eq!(&f[0..6], &[0x52, 0x54, 0, 0, 0, 2]);
            assert_eq!(&f[6..12], &[0x66, 0, 0, 0, 0, 1]);
            assert_eq!(&f[a + 6..a + 8], &2u16.to_be_bytes());
            assert_eq!(&f[a + 8..a + 14], &[0x66, 0, 0, 0, 0, 1]);
            assert_eq!(&f[a + 14..a + 18], &[10, 0, 0, 1]);
            assert_eq!(&f[a + 18..a + 24], &[0x52, 0x54, 0, 0, 0, 2]);
            assert_eq!(&f[a + 24..a + 28], &[10, 0, 0, 2]);
        }
        #[test]
        fn ignores_non_arp() {
            let mut f = [0u8; ETH_LEN + ARP_LEN];
            f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            let data = f.as_mut_ptr() as usize;
            assert!(!unsafe {
                try_write_arp_reply(data, data + f.len(), [10, 0, 0, 1], [0x66, 0, 0, 0, 0, 1])
            });
        }
    }
}

/// Pure, host-testable DHCPv4 reply construction. The map-touching glue and the XDP entry stay in
/// the eBPF crate; this module owns the wire-format constants, the request parse, and the byte
/// writer so the produced bytes can be unit-tested off-target. Byte-for-byte identical to the
/// previous inline builder in `flowplane-ebpf/src/dhcp.rs`.
pub mod dhcp {
    // Frame geometry constants (mirrors the eBPF `parse` module; redefined here so the pure module
    // has no dependency on the eBPF crate).
    const ETH_LEN: usize = 14;
    const ETH_P_IP: u16 = 0x0800;
    const IPPROTO_UDP: u8 = 17;

    pub const DHCP_MAGIC: u32 = 0x6382_5363;
    pub const OPT_PAD: u8 = 0;
    pub const OPT_END: u8 = 255;
    pub const OPT_MESSAGE_TYPE: u8 = 53;
    pub const OPT_LEASE_TIME: u8 = 51;
    pub const OPT_SERVER_ID: u8 = 54;
    pub const OPT_CLASSLESS_ROUTE: u8 = 121;
    pub const OPT_SUBNET_MASK: u8 = 1;
    pub const OPT_DNS: u8 = 6;
    pub const OPT_HOSTNAME: u8 = 12;
    pub const OPT_MTU: u8 = 26;
    pub const DHCP_MSG_DISCOVER: u8 = 1;
    pub const DHCP_MSG_REQUEST: u8 = 3;
    pub const DHCP_MSG_OFFER: u8 = 2;
    pub const DHCP_MSG_ACK: u8 = 5;

    const F_BOOTP: usize = ETH_LEN + 20 + 8;
    const BOOTP_MAGIC_OFF: usize = 236;
    const BOOTP_OPTIONS_OFF: usize = 240;
    const F_OPTS: usize = F_BOOTP + BOOTP_OPTIONS_OFF;
    pub const MIN_DHCP_LEN: usize = F_OPTS;

    // Byte-by-byte scan: scan at most this many bytes (fixed stride of 1, verifier-safe)
    const OPTS_SCAN_BYTES: usize = 128;

    const O_MSGTYPE: usize = 0;
    const O_LEASE: usize = 3;
    const O_SERVERID: usize = 9;
    const O_CLASSLESS: usize = 15;
    const O_SUBNET: usize = 29;
    const O_MTU: usize = 35;
    const O_ROUTER: usize = 39;
    const O_DNS: usize = 45;
    const O_HOSTNAME: usize = 79;
    const OPT_BLOCK_MAX: usize = 146;
    pub const REPLY_LEN: usize = F_OPTS + OPT_BLOCK_MAX;

    /// Maximum hostname bytes echoed in the host-name option (option-block budget).
    pub const MAX_HOSTNAME: usize = 64;

    #[inline(always)]
    unsafe fn write6(dst: *mut u8, src: &[u8; 6]) {
        let mut i = 0;
        while i < 6 {
            *dst.add(i) = src[i];
            i += 1;
        }
    }

    /// A parsed DISCOVER/REQUEST: the fields the glue needs to build a reply, with no packet/map
    /// dependency.
    pub struct Dhcpv4Request {
        /// DHCP_MSG_OFFER (for DISCOVER) or DHCP_MSG_ACK (for REQUEST).
        pub reply_type: u8,
        /// The request's Ethernet source (= reply eth dst + BOOTP chaddr).
        pub client_mac: [u8; 6],
        /// BOOTP xid(4)+secs(2)+flags(2), copied verbatim into the reply.
        pub xid_secs_flags: [u8; 8],
    }

    /// The fully resolved reply, assembled by the glue (map reads done there) and written verbatim
    /// by `write_dhcpv4_reply`.
    pub struct Dhcpv4Reply {
        pub reply_type: u8,
        pub client_mac: [u8; 6],
        pub yiaddr: [u8; 4],
        /// Server identity (siaddr / giaddr / server-id / classless-route gw / IP src).
        pub gateway_ipv4: [u8; 4],
        /// Reply Ethernet source.
        pub server_mac: [u8; 6],
        pub xid_secs_flags: [u8; 8],
        /// 0 => omit the MTU option.
        pub mtu: u16,
        pub dns: [[u8; 4]; crate::DHCP_MAX_DNS],
        pub dns_len: u8,
        pub lease_secs: u32,
        /// Host-name option payload; `hostname_len == 0` omits the option.
        pub hostname: [u8; MAX_HOSTNAME],
        pub hostname_len: u8,
    }

    impl Default for Dhcpv4Reply {
        fn default() -> Self {
            Dhcpv4Reply {
                reply_type: 0,
                client_mac: [0; 6],
                yiaddr: [0; 4],
                gateway_ipv4: [0; 4],
                server_mac: [0; 6],
                xid_secs_flags: [0; 8],
                mtu: 0,
                dns: [[0; 4]; crate::DHCP_MAX_DNS],
                dns_len: 0,
                lease_secs: 0,
                hostname: [0; MAX_HOSTNAME],
                hostname_len: 0,
            }
        }
    }

    /// Cheap port-only check: IPv4 + UDP + dport 67. Bounds-checked on `data..data_end`.
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

    const ETH_P_IPV6: u16 = 0x86DD;
    // ETH(14) + IPv6(40) + UDP(8) + DHCPv6 header(4) = 66.
    const MIN_DHCPV6_LEN: usize = ETH_LEN + 40 + 8 + 4;

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

    /// Validate + parse a DISCOVER/REQUEST; `None` for other message types. Pure (no maps): reads
    /// `msg_type` via the option walk, the Ethernet source, and xid/secs/flags. Computes
    /// `reply_type`.
    #[inline(always)]
    pub fn parse_dhcpv4_request(data: usize, data_end: usize) -> Option<Dhcpv4Request> {
        if data + MIN_DHCP_LEN > data_end {
            return None;
        }
        let p = data as *const u8;

        let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
        if ethertype != ETH_P_IP {
            return None;
        }
        if unsafe { *p.add(ETH_LEN) } & 0x0f != 5 {
            return None;
        }
        if unsafe { *p.add(ETH_LEN + 9) } != IPPROTO_UDP {
            return None;
        }
        let udp_dst =
            u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 22) as *const u16) });
        if udp_dst != 67 {
            return None;
        }
        let magic = u32::from_be(unsafe {
            core::ptr::read_unaligned(p.add(F_BOOTP + BOOTP_MAGIC_OFF) as *const u32)
        });
        if magic != DHCP_MAGIC {
            return None;
        }

        // Byte-by-byte option state machine.
        // sm_state: 0 = expect code, 1 = expect length, 2 = reading value bytes (counting down
        // sm_remain). i always increments by 1 (fixed stride = verifier-friendly loop).
        let mut msg_type: u8 = 0;
        let mut sm_state: u8 = 0;
        let mut _sm_code: u8 = 0;
        let mut sm_remain: usize = 0;
        let mut sm_is_msgtype: bool = false;

        let mut i: usize = 0;
        while i < OPTS_SCAN_BYTES {
            let boff = data + F_OPTS + i;
            if boff >= data_end {
                break;
            }
            let b = unsafe { *(boff as *const u8) };
            i += 1;

            if sm_state == 0 {
                // Expecting option code
                if b == OPT_PAD {
                    // no-op
                } else if b == OPT_END {
                    break;
                } else {
                    _sm_code = b;
                    sm_is_msgtype = b == OPT_MESSAGE_TYPE;
                    sm_state = 1;
                }
            } else if sm_state == 1 {
                // Expecting option length
                sm_remain = b as usize;
                if sm_remain == 0 {
                    sm_state = 0;
                } else {
                    sm_state = 2;
                }
            } else {
                // sm_state == 2: reading value bytes. MESSAGE_TYPE always has len=1, so the single
                // value byte (sm_remain==1, before the decrement below) is the message type.
                if sm_is_msgtype && sm_remain == 1 {
                    msg_type = b;
                }
                sm_remain -= 1;
                if sm_remain == 0 {
                    sm_state = 0;
                }
            }
        }

        if msg_type != DHCP_MSG_DISCOVER && msg_type != DHCP_MSG_REQUEST {
            return None;
        }
        let reply_type = if msg_type == DHCP_MSG_DISCOVER {
            DHCP_MSG_OFFER
        } else {
            DHCP_MSG_ACK
        };

        // MAC learning uses the Ethernet source (bytes 6-11), not BOOTP chaddr.
        let client_mac = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };
        // BOOTP xid(4)+secs(2)+flags(2) at F_BOOTP+4 .. F_BOOTP+12, copied verbatim into the reply.
        let xid_secs_flags =
            unsafe { core::ptr::read_unaligned(p.add(F_BOOTP + 4) as *const [u8; 8]) };

        Some(Dhcpv4Request {
            reply_type,
            client_mac,
            xid_secs_flags,
        })
    }

    /// Write the OFFER/ACK reply bytes into `[data, data_end)` (which the caller has already sized
    /// to `REPLY_LEN`). Returns `Some(REPLY_LEN)` on success, `None` if the region is too small.
    ///
    /// # Safety
    /// Performs raw pointer writes over `[data, data_end)`; the caller must guarantee the region is
    /// valid for writes of at least `REPLY_LEN` bytes. Byte-for-byte identical to the previous
    /// inline builder.
    pub unsafe fn write_dhcpv4_reply(
        data: usize,
        data_end: usize,
        r: &Dhcpv4Reply,
    ) -> Option<usize> {
        if data + REPLY_LEN > data_end {
            return None;
        }
        let p = data as *mut u8;

        // BOOTP header. Mirror dpservice's dhcp_node.c byte-for-byte: op=BOOTREPLY(2),
        // yiaddr=assigned IP, siaddr+giaddr=the virtual gateway (server identity), chaddr=the
        // client's L2 address, xid/secs/flags echoed verbatim from the request. sname/file (from
        // +44) are zeroed.
        let gw = r.gateway_ipv4;
        unsafe {
            *p.add(F_BOOTP) = 2;
            core::ptr::write_unaligned(p.add(F_BOOTP + 4) as *mut [u8; 8], r.xid_secs_flags); // xid/secs/flags
            core::ptr::write_unaligned(p.add(F_BOOTP + 16) as *mut [u8; 4], r.yiaddr); // yiaddr
            core::ptr::write_unaligned(p.add(F_BOOTP + 20) as *mut [u8; 4], gw); // siaddr
            core::ptr::write_unaligned(p.add(F_BOOTP + 24) as *mut [u8; 4], gw); // giaddr
            write6(p.add(F_BOOTP + 28), &r.client_mac); // chaddr
            core::ptr::write_bytes(p.add(F_BOOTP + 44), 0, 192);
        }

        unsafe {
            *p.add(F_OPTS + O_MSGTYPE) = OPT_MESSAGE_TYPE;
            *p.add(F_OPTS + O_MSGTYPE + 1) = 1;
            *p.add(F_OPTS + O_MSGTYPE + 2) = r.reply_type;
            *p.add(F_OPTS + O_LEASE) = OPT_LEASE_TIME;
            *p.add(F_OPTS + O_LEASE + 1) = 4;
            let lease = r.lease_secs.to_be_bytes();
            *p.add(F_OPTS + O_LEASE + 2) = lease[0];
            *p.add(F_OPTS + O_LEASE + 3) = lease[1];
            *p.add(F_OPTS + O_LEASE + 4) = lease[2];
            *p.add(F_OPTS + O_LEASE + 5) = lease[3];
            *p.add(F_OPTS + O_SERVERID) = OPT_SERVER_ID;
            *p.add(F_OPTS + O_SERVERID + 1) = 4;
            *p.add(F_OPTS + O_SERVERID + 2) = gw[0];
            *p.add(F_OPTS + O_SERVERID + 3) = gw[1];
            *p.add(F_OPTS + O_SERVERID + 4) = gw[2];
            *p.add(F_OPTS + O_SERVERID + 5) = gw[3];
            *p.add(F_OPTS + O_CLASSLESS) = OPT_CLASSLESS_ROUTE;
            *p.add(F_OPTS + O_CLASSLESS + 1) = 12;
            *p.add(F_OPTS + O_CLASSLESS + 2) = 16;
            *p.add(F_OPTS + O_CLASSLESS + 3) = 169;
            *p.add(F_OPTS + O_CLASSLESS + 4) = 254;
            *p.add(F_OPTS + O_CLASSLESS + 5) = 0;
            *p.add(F_OPTS + O_CLASSLESS + 6) = 0;
            *p.add(F_OPTS + O_CLASSLESS + 7) = 0;
            *p.add(F_OPTS + O_CLASSLESS + 8) = 0;
            *p.add(F_OPTS + O_CLASSLESS + 9) = 0;
            *p.add(F_OPTS + O_CLASSLESS + 10) = gw[0];
            *p.add(F_OPTS + O_CLASSLESS + 11) = gw[1];
            *p.add(F_OPTS + O_CLASSLESS + 12) = gw[2];
            *p.add(F_OPTS + O_CLASSLESS + 13) = gw[3];
            *p.add(F_OPTS + O_SUBNET) = OPT_SUBNET_MASK;
            *p.add(F_OPTS + O_SUBNET + 1) = 4;
            *p.add(F_OPTS + O_SUBNET + 2) = 0xff;
            *p.add(F_OPTS + O_SUBNET + 3) = 0xff;
            *p.add(F_OPTS + O_SUBNET + 4) = 0xff;
            *p.add(F_OPTS + O_SUBNET + 5) = 0xff;
        }

        unsafe {
            if r.mtu != 0 {
                *p.add(F_OPTS + O_MTU) = OPT_MTU;
                *p.add(F_OPTS + O_MTU + 1) = 2;
                core::ptr::write_unaligned(p.add(F_OPTS + O_MTU + 2) as *mut u16, r.mtu.to_be());
            } else {
                core::ptr::write_bytes(p.add(F_OPTS + O_MTU), OPT_PAD, 4);
            }
            // dpservice emits the ROUTER(3) option only in PXE setups; the v4 path here has no PXE
            // support (unlike the v6 path), so this slot is intentionally left as PAD. Reserved for
            // a future v4-PXE branch.
            core::ptr::write_bytes(p.add(F_OPTS + O_ROUTER), OPT_PAD, 6);
        }

        unsafe {
            core::ptr::write_bytes(p.add(F_OPTS + O_DNS), OPT_PAD, 34);
        }
        let dns_len = (r.dns_len as usize).min(crate::DHCP_MAX_DNS);
        if dns_len > 0 {
            unsafe {
                *p.add(F_OPTS + O_DNS) = OPT_DNS;
                *p.add(F_OPTS + O_DNS + 1) = (dns_len * 4) as u8;
            }
            let mut j = 0usize;
            while j < dns_len {
                let off = F_OPTS + O_DNS + 2 + j * 4;
                unsafe {
                    *p.add(off) = r.dns[j][0];
                    *p.add(off + 1) = r.dns[j][1];
                    *p.add(off + 2) = r.dns[j][2];
                    *p.add(off + 3) = r.dns[j][3];
                }
                j += 1;
            }
        }

        unsafe {
            core::ptr::write_bytes(p.add(F_OPTS + O_HOSTNAME), OPT_PAD, 66);
        }
        let hn_len = (r.hostname_len as usize).min(MAX_HOSTNAME);
        if hn_len > 0 {
            unsafe {
                *p.add(F_OPTS + O_HOSTNAME) = OPT_HOSTNAME;
                *p.add(F_OPTS + O_HOSTNAME + 1) = hn_len as u8;
            }
            let mut k = 0usize;
            while k < hn_len {
                unsafe {
                    *p.add(F_OPTS + O_HOSTNAME + 2 + k) = r.hostname[k];
                }
                k += 1;
            }
        }
        unsafe {
            *p.add(F_OPTS + OPT_BLOCK_MAX - 1) = OPT_END;
        }

        // Ethernet: dst = requester, src = the reply server MAC (the synthetic GW_MAC the ARP/ND
        // responders also advertise, passed in as r.server_mac).
        unsafe {
            write6(p, &r.client_mac);
            write6(p.add(6), &r.server_mac);
            core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IP.to_be());
        }

        let ip_total = (REPLY_LEN - ETH_LEN) as u16;
        let vihl = unsafe { *p.add(ETH_LEN) };
        let tos = unsafe { *p.add(ETH_LEN + 1) };
        let ip_hdr: [u8; 20] = [
            vihl,
            tos,
            (ip_total >> 8) as u8,
            (ip_total & 0xff) as u8,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_UDP,
            0,
            0,
            r.gateway_ipv4[0],
            r.gateway_ipv4[1],
            r.gateway_ipv4[2],
            r.gateway_ipv4[3],
            255,
            255,
            255,
            255,
        ];
        let mut s: u32 = 0;
        s = s.wrapping_add(((ip_hdr[0] as u32) << 8) | ip_hdr[1] as u32);
        s = s.wrapping_add(((ip_hdr[2] as u32) << 8) | ip_hdr[3] as u32);
        s = s.wrapping_add(((ip_hdr[4] as u32) << 8) | ip_hdr[5] as u32);
        s = s.wrapping_add(((ip_hdr[6] as u32) << 8) | ip_hdr[7] as u32);
        s = s.wrapping_add(((ip_hdr[8] as u32) << 8) | ip_hdr[9] as u32);
        s = s.wrapping_add(((ip_hdr[12] as u32) << 8) | ip_hdr[13] as u32);
        s = s.wrapping_add(((ip_hdr[14] as u32) << 8) | ip_hdr[15] as u32);
        s = s.wrapping_add(((ip_hdr[16] as u32) << 8) | ip_hdr[17] as u32);
        s = s.wrapping_add(((ip_hdr[18] as u32) << 8) | ip_hdr[19] as u32);
        s = (s & 0xffff) + (s >> 16);
        s = (s & 0xffff) + (s >> 16);
        let ip_csum = !(s as u16);
        unsafe {
            core::ptr::copy_nonoverlapping(ip_hdr.as_ptr(), p.add(ETH_LEN), 20);
            core::ptr::write_unaligned(p.add(ETH_LEN + 10) as *mut u16, ip_csum.to_be());
        }

        let udp_len = (REPLY_LEN - ETH_LEN - 20) as u16;
        unsafe {
            core::ptr::write_unaligned(p.add(ETH_LEN + 20) as *mut u16, 67u16.to_be());
            core::ptr::write_unaligned(p.add(ETH_LEN + 22) as *mut u16, 68u16.to_be());
            core::ptr::write_unaligned(p.add(ETH_LEN + 24) as *mut u16, udp_len.to_be());
            core::ptr::write_unaligned(p.add(ETH_LEN + 26) as *mut u16, 0u16);
        }

        Some(REPLY_LEN)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_undersized_buffer() {
            let mut buf = [0u8; REPLY_LEN - 1];
            let data = buf.as_mut_ptr() as usize;
            assert!(unsafe {
                write_dhcpv4_reply(data, data + REPLY_LEN - 1, &Dhcpv4Reply::default())
            }
            .is_none());
        }

        #[test]
        fn writes_bootp_reply_framing() {
            let mut buf = [0u8; REPLY_LEN];
            let data = buf.as_mut_ptr() as usize;
            let data_end = data + REPLY_LEN;
            let r = Dhcpv4Reply {
                reply_type: DHCP_MSG_OFFER,
                client_mac: [0x52, 0x54, 0, 1, 2, 3],
                yiaddr: [10, 0, 0, 1],
                gateway_ipv4: [10, 0, 0, 1],
                server_mac: [0x66, 0x66, 0x66, 0x66, 0x66, 0],
                xid_secs_flags: [0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0],
                mtu: 1500,
                dns: {
                    let mut d = [[0u8; 4]; crate::DHCP_MAX_DNS];
                    d[0] = [8, 8, 8, 8];
                    d
                },
                dns_len: 1,
                lease_secs: 3600,
                ..Default::default()
            };
            let n = unsafe { write_dhcpv4_reply(data, data_end, &r) }.expect("fits");
            assert_eq!(n, REPLY_LEN);
            assert_eq!(&buf[0..6], &[0x52, 0x54, 0, 1, 2, 3]); // eth dst = client
            assert_eq!(&buf[6..12], &[0x66, 0x66, 0x66, 0x66, 0x66, 0]); // eth src = server
            assert_eq!(&buf[12..14], &0x0800u16.to_be_bytes()); // ethertype IPv4
            assert_eq!(buf[42], 2); // BOOTP op = BOOTREPLY at ETH(14)+IP(20)+UDP(8)
            assert_eq!(&buf[58..62], &[10, 0, 0, 1]); // yiaddr at BOOTP+16
                                                      // xid/secs/flags echoed at BOOTP+4
            assert_eq!(&buf[46..54], &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0]);
        }

        #[test]
        fn detects_dhcpv6_solicit() {
            let mut buf = [0u8; MIN_DHCPV6_LEN];
            buf[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
            buf[ETH_LEN + 6] = IPPROTO_UDP; // IPv6 next-header
            buf[ETH_LEN + 40 + 2..ETH_LEN + 40 + 4].copy_from_slice(&547u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(looks_like_dhcpv6(data, data + buf.len()));
            // Wrong port → rejected.
            buf[ETH_LEN + 40 + 2..ETH_LEN + 40 + 4].copy_from_slice(&546u16.to_be_bytes());
            let data = buf.as_ptr() as usize;
            assert!(!looks_like_dhcpv6(data, data + buf.len()));
            // Undersized → rejected.
            assert!(!looks_like_dhcpv6(data, data + MIN_DHCPV6_LEN - 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    /// BPF map lookups hash the *raw bytes* of the key, so any implicit padding hole (whose bytes
    /// the writer may leave as garbage) silently breaks lookups — the dpservice-class trap. This
    /// pins the field offsets of the hot hashed keys and asserts each one has no padding beyond the
    /// explicit `_pad` fields, so a field reorder/insert that introduces a hole fails loudly here
    /// rather than as a heisen-miss in production.
    #[test]
    fn hashed_keys_have_no_implicit_padding() {
        // CtKey: vni(4) src_ip(4) dst_ip(4) src_port(2) dst_port(2) proto(1) _pad(3) = 20.
        assert_eq!(offset_of!(CtKey, vni), 0);
        assert_eq!(offset_of!(CtKey, src_ip), 4);
        assert_eq!(offset_of!(CtKey, dst_ip), 8);
        assert_eq!(offset_of!(CtKey, src_port), 12);
        assert_eq!(offset_of!(CtKey, dst_port), 14);
        assert_eq!(offset_of!(CtKey, proto), 16);
        assert_eq!(offset_of!(CtKey, _pad), 17);
        assert_eq!(size_of::<CtKey>(), 4 + 4 + 4 + 2 + 2 + 1 + 3);

        // LbKey: vni(4) ipv4(4) port(2) proto(1) _pad(1) = 12.
        assert_eq!(offset_of!(LbKey, vni), 0);
        assert_eq!(offset_of!(LbKey, ipv4), 4);
        assert_eq!(offset_of!(LbKey, port), 8);
        assert_eq!(offset_of!(LbKey, proto), 10);
        assert_eq!(offset_of!(LbKey, _pad), 11);
        assert_eq!(size_of::<LbKey>(), 4 + 4 + 2 + 1 + 1);

        // The padding-free word-packed keys: total size == sum of field sizes (no hidden hole),
        // and natural 4-byte alignment (so an Array/Hash of them is densely packed).
        assert_eq!(size_of::<IfaceKey>(), 4 + 4);
        assert_eq!(size_of::<NatKey>(), 4 + 4);
        assert_eq!(size_of::<VipKey>(), 4 + 4);
        assert_eq!(size_of::<FwRuleKey>(), 4 + 4);
        assert_eq!(size_of::<MaglevKey>(), 4 + 4);
        assert_eq!(size_of::<RouteLpmData>(), 4 + 4);
        assert_eq!(size_of::<RouteLpmData6>(), 4 + 16);
        for (a, n) in [
            (align_of::<CtKey>(), "CtKey"),
            (align_of::<LbKey>(), "LbKey"),
            (align_of::<IfaceKey>(), "IfaceKey"),
        ] {
            assert_eq!(a, 4, "{n} must stay 4-byte aligned");
        }
    }

    #[test]
    fn iface_key_is_word_packed() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 4 (ipv4).
        assert_eq!(core::mem::size_of::<IfaceKey>(), 8);
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv4, [10, 0, 0, 5]);
    }

    #[test]
    fn route_types_have_stable_layout() {
        // 4 (vni) + 4 (prefix_len) + 4 (ipv4) = 12.
        // 4 (nexthop_vni) + 16 (ipv6) + 1 (is_external) + 3 (_pad) = 24.
        assert_eq!(core::mem::size_of::<RouteKey>(), 12);
        assert_eq!(core::mem::size_of::<RouteValue>(), 24);
        // 4 (uplink_ifindex) + 6 (uplink_mac) + 6 (gateway_mac) + 16 (underlay_ipv6) = 32.
        assert_eq!(core::mem::size_of::<Local>(), 32);
        // LPM key data: 4 (vni be) + 4 (ipv4) = 8.
        assert_eq!(core::mem::size_of::<RouteLpmData>(), 8);
        // LPM key data v6: 4 (vni be) + 16 (ipv6) = 20.
        assert_eq!(core::mem::size_of::<RouteLpmData6>(), 20);
    }

    #[test]
    fn port_meta_and_iface_layout() {
        // 4 (vni) + 4 (guest_ipv4) + 4 (gateway_ipv4) + 6 (guest_mac) + 2 (_pad)
        // + 16 (underlay_ipv6) + 16 (gateway_ipv6) + 16 (guest_ipv6) = 68.
        assert_eq!(core::mem::size_of::<PortMeta>(), 68);
        assert_eq!(core::mem::size_of::<IfaceValue>(), 32);
        assert_eq!(core::mem::align_of::<PortMeta>(), 4);
    }

    #[test]
    fn config_has_stable_layout() {
        // 4*4 (u32s) + 16 + 16 (underlays) + 6+6+6+2 (macs+pad) = 16 + 32 + 20 = 68.
        assert_eq!(core::mem::size_of::<Config>(), 68);
        assert_eq!(core::mem::align_of::<Config>(), 4);
    }

    #[test]
    fn vip_key_layout() {
        assert_eq!(core::mem::size_of::<VipKey>(), 8);
    }

    #[test]
    fn lb_ct_layouts() {
        assert_eq!(core::mem::size_of::<LbKey>(), 12);
        assert_eq!(core::mem::size_of::<LbValue>(), 8);
        assert_eq!(core::mem::size_of::<MaglevKey>(), 8);
        assert_eq!(core::mem::size_of::<CtKey>(), 20);
        assert_eq!(core::mem::size_of::<UnderlayValue>(), 16);
    }

    #[test]
    fn nat_layouts() {
        assert_eq!(core::mem::size_of::<NatKey>(), 8);
        assert_eq!(core::mem::size_of::<NatValue>(), 8);
    }

    #[test]
    fn ct_entry_layout() {
        // 8 (last_seen) + 4 (xlate_ip) + 2 (xlate_port) + 1 (flags) + 1 (tcp_state)
        // + 1 (fwall_action) + 7 (_pad) = 24, u64-aligned.
        assert_eq!(core::mem::size_of::<CtEntry>(), 24);
    }

    #[test]
    fn fw_types_layout() {
        // 4 (ifindex) + 4 (idx) = 8.
        assert_eq!(core::mem::size_of::<FwRuleKey>(), 8);
        // 4*4 (ip/mask pairs) + 4*2 (port ranges) + 2+2 (icmp) + 4 (proto/action/dir/enabled) = 32.
        assert_eq!(core::mem::size_of::<FwRule>(), 32);
        // 4 (ingress_count) + 4 (egress_count) = 8.
        assert_eq!(core::mem::size_of::<FwMeta>(), 8);
    }

    #[test]
    fn meter_state_layout() {
        // 8 fields * 8 bytes each = 64 bytes.
        assert_eq!(core::mem::size_of::<MeterState>(), 64);
        assert_eq!(core::mem::align_of::<MeterState>(), 8);
    }

    #[test]
    fn neighbor_nat_entry_layout() {
        // 16 (underlay) + 4 (nat_ip) + 4 (vni) + 2 (port_min) + 2 (port_max)
        // + 1 (enabled) + 3 (_pad) = 32.
        assert_eq!(core::mem::size_of::<NeighborNatEntry>(), 32);
        assert_eq!(core::mem::align_of::<NeighborNatEntry>(), 4);
    }

    #[test]
    fn dhcp_layouts() {
        assert_eq!(
            core::mem::size_of::<DhcpConfig>(),
            2 + 1 + 1 + 4 * DHCP_MAX_DNS + 16 * DHCP_MAX_DNS
        );
        // hostname(64) + hostname_len(1) + boot_filename(64) + boot_filename_len(1)
        // + pxe_host(46) + pxe_host_len(1) + _pad(1) = 178
        assert_eq!(
            core::mem::size_of::<DhcpMeta>(),
            64 + 1 + 64 + 1 + 46 + 1 + 1
        );
    }

    #[test]
    fn fw_match_proto_and_ports() {
        let r = FwRule {
            src_ip: [0, 0, 0, 0],
            src_mask: [0, 0, 0, 0],
            dst_ip: [10, 0, 0, 5],
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 80,
            dst_port_max: 80,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        let sel = |dst: [u8; 4], proto: u8, dport: u16| PacketSelectors {
            src: [1, 2, 3, 4],
            dst,
            proto,
            sport: 12345,
            dport,
            icmp_type: 0,
            icmp_code: 0,
        };
        assert!(fw_rule_matches(&r, &sel([10, 0, 0, 5], 6, 80)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 5], 6, 81)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 5], 17, 80)));
        assert!(!fw_rule_matches(&r, &sel([10, 0, 0, 6], 6, 80)));
    }

    #[test]
    fn fw_match_icmp_and_any() {
        let r = FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 8,
            icmp_code: 0xffff,
            proto: 1,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        let icmp = |icmp_type: u16| PacketSelectors {
            src: [1, 1, 1, 1],
            dst: [2, 2, 2, 2],
            proto: 1,
            sport: 0,
            dport: 0,
            icmp_type,
            icmp_code: 0,
        };
        assert!(fw_rule_matches(&r, &icmp(8)));
        assert!(!fw_rule_matches(&r, &icmp(0)));
        let mut d = r;
        d.enabled = 0;
        assert!(!fw_rule_matches(&d, &icmp(8)));
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
