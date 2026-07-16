use aya_ebpf::{
    macros::map,
    maps::{lpm_trie::LpmTrie, Array, DevMap, DevMapHash, HashMap, LruHashMap, ProgramArray},
};
use xdp_dp_common::{
    Config, CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceValue,
    InspectEntry, LbKey, LbValue, Local, MaglevKey, MeterState, NatKey, NatValue, NeighborNatEntry,
    PortMeta, RouteLpmData, RouteLpmData6, RouteValue, UnderlayValue, VipKey,
};

#[map]
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);
// LPM trie: key data = [vni_be(4) ++ ipv4(4)], prefix_len = 32 + ipv4_prefix. flags=1 is
// BPF_F_NO_PREALLOC, REQUIRED for LPM tries (the load fails without it).
#[map]
pub static ROUTES: LpmTrie<RouteLpmData, RouteValue> = LpmTrie::with_max_entries(65536, 1);
#[map]
pub static ROUTES6: LpmTrie<RouteLpmData6, RouteValue> = LpmTrie::with_max_entries(65536, 1);
#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
pub static PORT_META: HashMap<u32, PortMeta> = HashMap::with_max_entries(1024, 0);
#[map]
pub static LOCAL: Array<Local> = Array::with_max_entries(1, 0);
// Single-slot devmap holding the fabric uplink ifindex (key 0), populated by userspace when LOCAL
// is set. The edge `wan_rx` RX->fabric redirect (encap_and_redirect) goes through this instead of a
// plain bpf_redirect: on veth (containerlab) a plain XDP_REDIRECT only delivers if the peer port has
// an XDP program (veth ndo_xdp_xmit requirement); the devmap path does not carry that constraint.
// Production real NICs work either way, so this is a harness-robustness change, not a logic change.
#[map]
pub static UPLINK_DEV: DevMap = DevMap::with_max_entries(1, 0);
// Per-guest-tap devmap (key = tap ifindex -> same ifindex), populated by userspace on interface
// attach. `uplink_rx`'s guest DELIVERY redirect goes through this instead of a plain bpf_redirect:
// on containerlab veths a plain XDP_REDIRECT into the guest veth is silently dropped (veth
// ndo_xdp_xmit peer requirement), while the devmap path delivers. Production real NICs are
// unaffected. Mirrors UPLINK_DEV, but keyed by ifindex (many guests) via DEVMAP_HASH.
#[map]
pub static GUEST_DEV: DevMapHash = DevMapHash::with_max_entries(1024, 0);
#[map]
pub static INSPECT: Array<InspectEntry> = Array::with_max_entries(1, 0);
/// 1:1 VIP map. Value is the mapped IPv4 counterpart: (vni,G)->V for egress SNAT, (vni,V)->G for
/// ingress DNAT.
#[map]
pub static VIPS: HashMap<VipKey, [u8; 4]> = HashMap::with_max_entries(1024, 0);
#[map]
pub static LB: HashMap<LbKey, LbValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static MAGLEV: HashMap<MaglevKey, [u8; 16]> = HashMap::with_max_entries(65536, 0);
#[map]
/// Unified conntrack. Sized to dpservice's DP_FLOW_TABLE_MAX order (LRU_HASH preallocates, ~80-100MB;
/// memcg-accounted on kernels >= 5.11). Operators tune via the loader (a later task adds an env knob).
pub static CONNTRACK: LruHashMap<CtKey, CtEntry> = LruHashMap::with_max_entries(1_048_576, 0);
#[map]
pub static NAT: HashMap<NatKey, NatValue> = HashMap::with_max_entries(1024, 0);
/// Marks a (vni, nat_ip) as a network-NAT IP (value = 1). Used by ingress to detect incoming
/// ICMP echo requests targeting the NAT IP and reply in the dataplane (without involving the VM).
#[map]
pub static NAT_IPS: HashMap<VipKey, u8> = HashMap::with_max_entries(1024, 0);
#[map]
pub static FW_RULES: HashMap<FwRuleKey, FwRule> = HashMap::with_max_entries(16384, 0);
#[map]
pub static FW_META: HashMap<u32, FwMeta> = HashMap::with_max_entries(1024, 0);
#[map]
pub static UNDERLAY: HashMap<[u8; 16], UnderlayValue> = HashMap::with_max_entries(4096, 0);
#[map]
pub static NEIGHBOR_NAT: HashMap<u32, NeighborNatEntry> = HashMap::with_max_entries(64, 0);
/// Entry 0: number of populated NEIGHBOR_NAT slots (datapath scans 0..count).
#[map]
pub static NEIGHBOR_NAT_COUNT: Array<u32> = Array::with_max_entries(1, 0);
#[map]
pub static METER: HashMap<u32, MeterState> = HashMap::with_max_entries(1024, 0);
#[map]
pub static DHCP_CONFIG: Array<DhcpConfig> = Array::with_max_entries(1, 0);
#[map]
pub static DHCP_META: HashMap<u32, DhcpMeta> = HashMap::with_max_entries(1024, 0);
/// Tail-call targets for the egress datapath split. Index with `GUEST_PROG_*` from xdp-dp-common.
/// Populated by the loader at startup (guest_dhcp at GUEST_PROG_DHCP). 8 slots leaves room for the
/// Phase 2 IPv4/IPv6 split without resizing.
#[map]
pub static GUEST_PROGS: ProgramArray = ProgramArray::with_max_entries(8, 0);

/// Tail-call targets for the **tc** guest-edge split. Separate from `GUEST_PROGS` because a tc
/// (classifier) program may only tail-call other tc programs. Populated by the loader with
/// `tc_guest_dhcp` at `GUEST_PROG_DHCP`.
#[map]
pub static GUEST_PROGS_TC: ProgramArray = ProgramArray::with_max_entries(8, 0);
