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

    /// Incrementally fold a 16-bit field change (network-order `old`/`new`) into an L4/ICMP
    /// checksum by reusing [`csum_replace4`] with the upper 2 bytes zeroed in both arguments.
    #[inline(always)]
    pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
        let o = old.to_be_bytes();
        let n = new.to_be_bytes();
        csum_replace4(check, &[o[0], o[1], 0, 0], &[n[0], n[1], 0, 0])
    }
}

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Key for the `interfaces6` map: an overlay (VNI, IPv6) tuple. The v6 sibling of [`IfaceKey`];
/// shares the same [`IfaceValue`]. Used by the node-VTEP local-delivery demux.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey6 {
    pub vni: u32,
    pub ipv6: [u8; 16],
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
    /// 1 = the local delivery device has a netns peer (veth/netkit) → local delivery may use
    /// `bpf_redirect_peer` (inject at the peer's ingress in the pod netns, same softirq). 0 = a
    /// peerless device (root-netns tap) → must use plain `bpf_redirect`. Set at attach from the
    /// DeviceType. Additive ABI: reuses a former `_pad` byte, so `size_of::<IfaceValue>()` is unchanged.
    pub peer_capable: u8,
    pub _pad: [u8; 1],
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

/// Geneve overlay wire overhead the kernel's `collect_md` device adds on top of the inner frame the
/// eBPF programs see: outer IPv6 (40) + outer UDP (8) + Geneve header (8) = 56. The outer Ethernet
/// (14) is link framing on the fabric NIC, not part of the L3/L4 overhead a guest's own MTU needs to
/// account for. Since P2 stopped writing outer bytes in the datapath (the kernel builds them from a
/// `TunnelEncap` decision — see `flowplane_core::encap`), `pkt.len()` on the egress Encap arm and the
/// ingress uplink path is the INNER length only; anywhere that needs to reflect real wire bytes
/// (rate metering, the advertised guest MTU) adds this constant back in.
pub const GENEVE_OVERHEAD: usize = 56;

/// Per-port metadata, keyed by the guest tap's host-side ifindex.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PortMeta {
    pub vni: u32,
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub guest_mac: [u8; 6],
    /// 1 = L3 pod edge (netkit): IP from byte 0, no L2 responders, synthetic-eth push/pop at the
    /// edge; 0 = L2 (veth/tap).
    pub l3: u8,
    pub _pad: [u8; 1],
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

impl IfaceKey6 {
    pub fn new(vni: u32, ipv6: [u8; 16]) -> Self {
        Self { vni, ipv6 }
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
/// this as a cross-check. `l3` records how the guest program was attached, so adopt re-points the pinned
/// link with the matching mechanism (netkit → `bpf(BPF_LINK_UPDATE)`, veth/tcx → `readopt_tc_link`).
/// Field order is chosen so the struct has no implicit padding (`_pad` makes the tail explicit).
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
    /// 1 = the guest program is attached to a netkit L3 primary via `BPF_NETKIT_PEER` (adopt must
    /// re-point it with `bpf(BPF_LINK_UPDATE)`); 0 = tcx/clsact on a veth (adopt uses `readopt_tc_link`).
    pub l3: u8,
    pub _pad: [u8; 3],
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

/// Per-interface QoS state. Three lanes:
/// - Egress total (EDT SHAPING): `total_bps` = shaped rate (bytes/s, 0 = unlimited);
///   `total_last_ns` = the EDT schedule cursor (`t_last`, ns). `total_burst`/`total_tokens` are
///   UNUSED on the EDT path (no token bucket) and kept 0 for layout stability.
/// - Egress public (token-bucket POLICING of external/NATed egress): `public_*`.
/// - Ingress (token-bucket POLICING of traffic delivered to the guest): `ingress_*`.
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
    pub ingress_bps: u64,
    pub ingress_burst: u64,
    pub ingress_tokens: u64,
    pub ingress_last_ns: u64,
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
/// `xlate_ip`/`xlate_port`. Replaces the former feature-private `CtVal`/`NatCtVal`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry {
    pub last_seen: u64,
    pub xlate_ip: [u8; 4],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub fwall_action: u8,
    /// Trailing padding to keep the eBPF `CONNTRACK` map value ABI at 24 bytes / align 8.
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

/// Max DNS servers per family carried in DHCP replies (dpservice's flags are repeatable; this caps
/// the in-map array — 8 covers the conformance set + headroom).
pub const DHCP_MAX_DNS: usize = 8;

/// Tail-call indices into the `GUEST_PROGS_TC` program array (egress datapath split).
/// `GUEST_PROG_DHCP` dispatches the DHCP responder; `GUEST_PROG_IPV6` the NAT64 egress path;
/// `GUEST_PROG_V6_FWD` the IPv6 overlay egress (firewall + conntrack + route6 + encap), split out
/// because the v6 firewall/conntrack structures overflow tc_guest_tx's 512B combined BPF stack.
/// `GUEST_PROG_IPV4` stays reserved for a future v4 split.
pub const GUEST_PROG_DHCP: u32 = 0;
pub const GUEST_PROG_IPV4: u32 = 1;
pub const GUEST_PROG_IPV6: u32 = 2;
pub const GUEST_PROG_V6_FWD: u32 = 3;

/// Tail-call index into the `UPLINK_PROGS` **tc** program array (ingress datapath split; the
/// programs it tail-calls between were XDP pre-P2-Task-4b, now tc/tcx on the geneve device).
/// `UPLINK_PROG_V6` dispatches the inner-IPv6 ingress path (`xdp_uplink_v6`), split out of
/// `uplink_rx` because the v6 firewall/conntrack structures overflow the combined BPF stack. tc
/// programs can only tail-call other tc programs of the SAME attach type, so this lives in its own
/// array (not the guest-egress-side `GUEST_PROGS_TC`).
pub const UPLINK_PROG_V6: u32 = 0;

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

/// IPv6 packet selectors (16-byte addresses). Mirror of `PacketSelectors`.
pub struct PacketSelectors6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
}

/// Pure IPv6 firewall match. Mirror of `fw_rule_matches`; ICMPv6 uses proto 58.
#[inline]
pub fn fw_rule6_matches(r: &FwRule6, s: &PacketSelectors6) -> bool {
    let PacketSelectors6 {
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
    for i in 0..16 {
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
        58 => {
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
    unsafe impl aya::Pod for IfaceKey6 {}
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
    unsafe impl aya::Pod for FwRule6 {}
    unsafe impl aya::Pod for FwMeta {}
    unsafe impl aya::Pod for CtKey6 {}
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

/// ARP/ND wire-format constants. The byte-rewrite RESPONDERS moved to `flowplane_core::arp_nd` (the
/// `Pkt`-trait seam the eBPF datapath, native sim, and BPF_PROG_TEST_RUN anchor all share); this
/// module now only re-exports the L2/L3 protocol constants so existing
/// `arp_nd::{ETH_LEN, IPV6_LEN, ETH_P_IPV6}` import paths keep resolving.
pub mod arp_nd {
    pub use super::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};
}

/// Cheap fixed-offset DHCP request detection (used by the guest-edge glue to decide whether to
/// tail-call the DHCP responder). The DHCPv4 request parse + reply construction now live in
/// `flowplane_core::dhcp` over the `Pkt`/`Maps` seam (the SAME code the eBPF datapath, the sim, and
/// the byte-parity anchor run); this module keeps only the port-sniffing detectors, which are pure
/// fixed-offset reads over `(data, data_end)` and have no packet/map trait dependency. The DHCPv6
/// responder still lives in the eBPF crate (its option block is runtime-variable-length; see
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
    fn iface_key6_layout() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 16 (ipv6) = 20, align 4.
        assert_eq!(offset_of!(IfaceKey6, vni), 0);
        assert_eq!(offset_of!(IfaceKey6, ipv6), 4);
        assert_eq!(size_of::<IfaceKey6>(), 4 + 16);
        assert_eq!(align_of::<IfaceKey6>(), 4);
        let k = IfaceKey6::new(100, [0x20; 16]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv6, [0x20; 16]);
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
        // 4 (vni) + 4 (guest_ipv4) + 4 (gateway_ipv4) + 6 (guest_mac) + 1 (l3) + 1 (_pad)
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
        // + 1 (fwall_action) + 7 (_pad) = 24, u64-aligned. The eBPF CONNTRACK map value ABI is
        // UNCHANGED from before the §5a generation stamp's removal (those 4 bytes were always 0).
        assert_eq!(core::mem::size_of::<CtEntry>(), 24);
        // Alignment must also be unchanged (u64 = 8) — a bigger alignment would change the map layout.
        assert_eq!(core::mem::align_of::<CtEntry>(), 8);
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
    fn fw6_types_layout() {
        assert_eq!(core::mem::size_of::<FwRule6>(), 80);
        assert_eq!(core::mem::size_of::<CtKey6>(), 44);
        // regression guard: v4 layouts unchanged
        assert_eq!(core::mem::size_of::<FwRule>(), 32);
        assert_eq!(core::mem::size_of::<FwMeta>(), 8);
        assert_eq!(core::mem::size_of::<CtKey>(), 20);
    }

    #[test]
    fn meter_state_layout() {
        // 12 fields * 8 bytes each = 96 bytes.
        assert_eq!(core::mem::size_of::<MeterState>(), 96);
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
