use flowplane_common::{
    CtEntry, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, IfaceValue, LbKey,
    LbValue, Local, MaglevKey, MeterState, NatKey, NatValue, PortMeta, RouteValue, UnderlayValue,
};

/// Typed access to the datapath maps the core needs. eBPF impl wraps the `#[map]` statics
/// (zero-cost); native impl is HashMap-backed. Monomorphized — no `dyn`.
pub trait Maps {
    fn local(&self) -> Option<Local>;
    fn underlay_get(&self, addr: &[u8; 16]) -> Option<UnderlayValue>;
    fn fw_meta(&self, ifindex: u32) -> Option<FwMeta>;
    fn fw_rule(&self, key: &FwRuleKey) -> Option<FwRule>;
    fn conntrack_get(&self, key: &CtKey) -> Option<CtEntry>;
    fn conntrack_insert(&mut self, key: CtKey, entry: CtEntry);
    /// Firewall-only IPv6 conntrack lookup (`CONNTRACK6` map). DEFAULT `None`: the eBPF `GlobalMaps`
    /// has not wired the v6 firewall datapath yet, so v6 conntrack is simply absent there. The sim
    /// `MemMaps` overrides this with a real `HashMap`-backed store.
    fn conntrack6_get(&self, _key: &CtKey6) -> Option<CtEntry> {
        None
    }
    /// Firewall-only IPv6 conntrack insert (`CONNTRACK6` map). DEFAULT no-op — see [`Self::conntrack6_get`].
    fn conntrack6_insert(&mut self, _key: CtKey6, _entry: CtEntry) {}
    /// IPv6 firewall meta (`FW_META6`). DEFAULT `None` — a backend without v6 fw wiring denies v6 by
    /// default (see [`crate::firewall::fw_eval_dir6`]). Overridden by the sim `MemMaps`; the eBPF
    /// `GlobalMaps` gains an override in a later v6-firewall task.
    fn fw_meta6(&self, _ifindex: u32) -> Option<FwMeta> {
        None
    }
    /// IPv6 firewall rule slot (`FW_RULES6`). DEFAULT `None` — see [`Self::fw_meta6`].
    fn fw_rule6(&self, _key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        None
    }
    fn lb_get(&self, key: &LbKey) -> Option<LbValue>;
    fn maglev_get(&self, key: &MaglevKey) -> Option<[u8; 16]>;
    /// Neighbor-NAT return-route lookup (`NEIGHBOR_NAT` table, linear-scanned): if `(vni, dst,
    /// dport)` matches a registered block, return the OWNING node's underlay /128. NEIGHBOR_NAT
    /// entries are installed ONLY for nat_ip blocks owned by ANOTHER node (mesh gossip; see
    /// `mesh/agent/bus_test.go::TestApplyNatInstallsNeighborNatOnlyForRemoteOwners`) — a locally
    /// owned nat_ip never appears here. Used for the cross-node relay case: an inbound packet whose
    /// inner dst is a nat_ip this node does NOT own gets re-forwarded, byte-unchanged, toward the
    /// real owner. Faithful port of the eBPF `nat::neighbor_nat_lookup`.
    fn neighbor_nat_lookup(&self, vni: u32, dst: [u8; 4], dport: u16) -> Option<[u8; 16]>;
    /// VNI-agnostic variant for the WAN-edge return path (`wan_rx`): a plain WAN-arriving IPv4
    /// packet carries no VNI, so match on `(nat_ip, dport)` alone and return BOTH the owner's
    /// underlay /128 AND its VNI — the edge must encap toward the owner WITH that VNI so the
    /// owner's peer-independent reverse-conntrack key `(vni,0,nat_ip,0,nat_port)` matches. Faithful
    /// port of the eBPF `nat::neighbor_nat_lookup_any`.
    fn neighbor_nat_lookup_any(&self, dst: [u8; 4], dport: u16) -> Option<([u8; 16], u32)>;
    /// Network-NAT config for a `(vni, guest-ipv4)` pair (`NAT` map).
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    /// Is `(vni, ip)` a registered public NAT IP (the `NAT_IPS` set)? NAT returns are demuxed
    /// peer-independently: when the inner dst is a registered nat_ip, the external src ip+port are
    /// zeroed so the CT lookup hits the globally-unique `(vni,0,nat_ip,0,nat_port)` reverse entry.
    fn is_nat_ip(&self, vni: u32, ip: &[u8; 4]) -> bool;
    /// Exact-match (`/32`) route lookup for an inner IPv4 dst in a VNI (`ROUTES` LPM trie, queried at
    /// prefix_len 64 = 32 VNI bits + 32 host bits — the same lookup the eBPF egress does).
    fn route4_get(&self, vni: u32, dst: &[u8; 4]) -> Option<RouteValue>;
    /// Exact-match (`/128`) route lookup for an inner IPv6 dst in a VNI (`ROUTES6` LPM trie, queried
    /// at prefix_len 160 = 32 VNI bits + 128 host bits).
    fn route6_get(&self, vni: u32, dst: &[u8; 16]) -> Option<RouteValue>;
    /// Server-wide DHCP config (`DHCP_CONFIG[0]`): MTU + DNS server lists. `None` if unset.
    fn dhcp_config(&self) -> Option<DhcpConfig>;
    /// Per-interface DHCP config (`DHCP_META[ifindex]`): hostname + PXE. `None` if unset.
    fn dhcp_meta(&self, ifindex: u32) -> Option<DhcpMeta>;
    /// Per-interface egress token-bucket state (`METER[ifindex]`). `None` = no rate limit configured.
    fn meter_get(&self, ifindex: u32) -> Option<MeterState>;
    /// Store the refilled per-interface token-bucket state back (`METER[ifindex]`).
    fn meter_update(&mut self, ifindex: u32, state: MeterState);
    /// Per-port metadata (`PORT_META[tap_ifindex]`): vni + guest/gateway identity + the guest's
    /// overlay IPv6. Used by the NAT64-ingress dispatch ([`crate::datapath::process_uplink_rx`]) to
    /// source the guest's overlay IPv6 for the v4→v6 expansion AFTER the delivery tap has been
    /// resolved (mechanism #2) — the caller cannot know the tap up front, so this can't be threaded
    /// in as a plain input; it is read here, keyed by the just-resolved `tap_ifindex`. `None` if unset.
    fn port_meta_get(&self, ifindex: u32) -> Option<PortMeta>;
    /// Local-delivery demux by overlay (VNI, IPv4) (`INTERFACES` map). The v4 sibling of
    /// [`Self::ifaces6_get`]; both back the node-VTEP local-delivery path added in a later step.
    fn ifaces_get(&self, vni: u32, ipv4: &[u8; 4]) -> Option<IfaceValue>;
    /// Local-delivery demux by overlay (VNI, IPv6) (`INTERFACES6` map). DEFAULT `None` so a backend
    /// that has not populated the v6 map still compiles; the eBPF + sim backends override it.
    fn ifaces6_get(&self, _vni: u32, _ipv6: &[u8; 16]) -> Option<IfaceValue> {
        None
    }
    /// 1:1 floating-IP ingress lookup: the `VIPS` map's `(vni, V) → G` direction — the counterpart
    /// of the egress `snat_egress` `(vni, G) → V` read. `Some(G)` means an inbound frame's inner
    /// dst `V` must be DNAT'd to the backing guest IPv4 `G` and delivered locally (see
    /// [`crate::datapath::process_uplink`]'s floating-IP arm). Required (no default): both the eBPF
    /// `GlobalMaps` and the sim `MemMaps` wire it — a floating IP the core cannot see is a silent
    /// black hole, not a graceful degradation.
    fn vip_get(&self, vni: u32, v: &[u8; 4]) -> Option<[u8; 4]>;
}
