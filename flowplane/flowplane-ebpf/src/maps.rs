use aya_ebpf::{
    macros::map,
    maps::{lpm_trie::LpmTrie, Array, HashMap, LruHashMap, ProgramArray},
};
use flowplane_common::{
    Config, CtEntry, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRule6, FwRuleKey,
    IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue, InspectEntry, LbBackend, LbKey,
    LbValue, Local, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry, PortMeta,
    RouteLpmData, RouteLpmData6, RouteValue, UnderlayValue, VipKey,
};

#[map]
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::pinned(1024, 0);
/// IPv6 sibling of `INTERFACES`: overlay (VNI, IPv6) -> delivery info. Populated by the control
/// plane alongside `INTERFACES`; the node-VTEP local-delivery demux reads it in a later step.
#[map]
pub static INTERFACES6: HashMap<IfaceKey6, IfaceValue> = HashMap::pinned(1024, 0);
// Control-plane restart journal: interface_id -> (vni, ipv4/ipv6, device, underlay, tap). Written by
// userspace on attach, removed on detach, and scanned on restart to rebuild in-memory bookkeeping +
// re-attach guest programs. NEVER read by the datapath. Pinned so it survives an flowplane restart.
#[map]
pub static IFACE_META: HashMap<IfaceMetaKey, IfaceMetaVal> = HashMap::pinned(1024, 0);
// LPM trie: key data = [vni_be(4) ++ ipv4(4)], prefix_len = 32 + ipv4_prefix. flags=1 is
// BPF_F_NO_PREALLOC, REQUIRED for LPM tries (the load fails without it).
#[map]
pub static ROUTES: LpmTrie<RouteLpmData, RouteValue> = LpmTrie::pinned(65536, 1);
#[map]
pub static ROUTES6: LpmTrie<RouteLpmData6, RouteValue> = LpmTrie::pinned(65536, 1);
#[map]
pub static CONFIG: Array<Config> = Array::pinned(1, 0);
#[map]
pub static PORT_META: HashMap<u32, PortMeta> = HashMap::pinned(1024, 0);
#[map]
pub static LOCAL: Array<Local> = Array::pinned(1, 0);
#[map]
pub static INSPECT: Array<InspectEntry> = Array::with_max_entries(1, 0);
// Single-slot config map holding the kernel `collect_md` Geneve device's ifindex (Task 1's device,
// see `control::Inner`). Populated by the loader (Task 4); the tc guest-egress encap path reads it
// via `geneve_ifindex()` to `bpf_redirect` an overlay-bound skb after `bpf_skb_set_tunnel_key` has
// stamped the tunnel-key metadata dst — the geneve device builds the real outer Eth/IPv6/UDP/Geneve
// header from that metadata on transmit.
#[map]
pub static GENEVE_IFINDEX: Array<u32> = Array::pinned(1, 0);
/// The configured Geneve `collect_md` device ifindex, or 0 if unset (loader hasn't populated it yet).
#[inline(always)]
pub fn geneve_ifindex() -> u32 {
    GENEVE_IFINDEX.get(0).copied().unwrap_or(0)
}
/// 1:1 VIP map. Value is the mapped IPv4 counterpart: (vni,G)->V for egress SNAT, (vni,V)->G for
/// ingress DNAT.
#[map]
pub static VIPS: HashMap<VipKey, [u8; 4]> = HashMap::pinned(1024, 0);
#[map]
pub static LB: HashMap<LbKey, LbValue> = HashMap::pinned(1024, 0);
#[map]
pub static MAGLEV: HashMap<MaglevKey, LbBackend> = HashMap::pinned(65536, 0);
#[map]
/// Unified conntrack. Sized to dpservice's DP_FLOW_TABLE_MAX order (LRU_HASH preallocates, ~80-100MB;
/// memcg-accounted on kernels >= 5.11). The size is fixed at load time by the loader.
pub static CONNTRACK: LruHashMap<CtKey, CtEntry> = LruHashMap::pinned(1_048_576, 0);
#[map]
pub static NAT: HashMap<NatKey, NatValue> = HashMap::pinned(1024, 0);
/// Marks a (vni, nat_ip) as a network-NAT IP (value = 1). Used by ingress ONLY for peer-independent
/// NAT-return demux (`Maps::is_nat_ip`): a registered nat_ip inner dst keys the reverse conntrack
/// entry `(vni,0,nat_ip,0,nat_port)`. The dataplane does NOT answer ICMP echo to a NAT IP — pings
/// are forwarded (an unsolicited ping to a SNAT address has no backend and drops).
#[map]
pub static NAT_IPS: HashMap<VipKey, u8> = HashMap::pinned(1024, 0);
#[map]
pub static FW_RULES: HashMap<FwRuleKey, FwRule> = HashMap::pinned(16384, 0);
#[map]
pub static FW_META: HashMap<u32, FwMeta> = HashMap::pinned(1024, 0);
/// IPv6 firewall rule slots ((ifindex, slot) -> FwRule6). Mirror of `FW_RULES` with 16-byte prefixes.
#[map]
pub static FW_RULES6: HashMap<FwRuleKey, FwRule6> = HashMap::pinned(16384, 0);
/// IPv6 firewall per-interface meta (ifindex -> per-direction rule counts). Mirror of `FW_META`.
#[map]
pub static FW_META6: HashMap<u32, FwMeta> = HashMap::pinned(1024, 0);
/// IPv6 firewall-only conntrack (`CtKey6` -> `CtEntry`). Mirror of `CONNTRACK` (LRU, same cap/flags).
#[map]
pub static CONNTRACK6: LruHashMap<CtKey6, CtEntry> = LruHashMap::pinned(1_048_576, 0);
#[map]
pub static UNDERLAY: HashMap<[u8; 16], UnderlayValue> = HashMap::pinned(4096, 0);
#[map]
pub static NEIGHBOR_NAT: HashMap<u32, NeighborNatEntry> = HashMap::pinned(64, 0);
/// Entry 0: number of populated NEIGHBOR_NAT slots (datapath scans 0..count).
#[map]
pub static NEIGHBOR_NAT_COUNT: Array<u32> = Array::pinned(1, 0);
#[map]
pub static METER: HashMap<u32, MeterState> = HashMap::pinned(1024, 0);
#[map]
pub static DHCP_CONFIG: Array<DhcpConfig> = Array::pinned(1, 0);
#[map]
pub static DHCP_META: HashMap<u32, DhcpMeta> = HashMap::pinned(1024, 0);
/// Tail-call targets for the **tc** guest-edge split. tc classifiers can only tail-call other tc
/// programs, so these live in a separate array from any XDP tail-call table. Populated by the
/// loader with `tc_guest_dhcp` at `GUEST_PROG_DHCP`.
#[map]
pub static GUEST_PROGS_TC: ProgramArray = ProgramArray::with_max_entries(8, 0);

/// Tail-call targets for the uplink (ingress) split, now tc (was XDP pre-4b — tc programs can only
/// tail-call other tc programs, hence a separate array from `GUEST_PROGS_TC`, which lives on the
/// guest-egress side of the process and is populated independently). Populated by the loader with
/// `xdp_uplink_v6` at `UPLINK_PROG_V6`; `uplink_rx` tail-calls it for decapped frames whose inner
/// ethertype is IPv6 (the v6 firewall + conntrack overflow uplink_rx's combined BPF stack).
#[map]
pub static UPLINK_PROGS: ProgramArray = ProgramArray::with_max_entries(4, 0);
