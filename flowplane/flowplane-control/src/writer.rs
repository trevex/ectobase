//! The control-plane map write surface. The eBPF `AyaWriter` (and the in-memory `MemMapWriter`
//! used in tests) implement this; `ControlCore` programs maps only through it.
use flowplane_common::{
    DhcpConfig, FloatingIPKey, FwBind, IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue,
    LbBackend, LbKey, LbKey6, LbValue, MaglevKey, MeterState, NatKey, NatKey6, NatValue, NatValue6,
    NeighborNat6Entry, NeighborNatEntry, PortMeta, RouteValue, UnderlayValue,
};

/// The set of conntrack entries a NAT teardown must invalidate; the eBPF writer flushes the
/// matching CT map entries. Fields mirror `ct_flush_for_guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtFlushScope {
    pub vni: u32,
    pub guest_ip: [u8; 4],
    pub nat_ip: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// The v6 sibling of [`CtFlushScope`] — invalidates the matching `NAT_CT6` entries on a NAT66
/// teardown. `[u8; 16]` guest/nat addresses; ports unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtFlushScope6 {
    pub vni: u32,
    pub guest_ip6: [u8; 16],
    pub nat_ip6: [u8; 16],
    pub port_min: u16,
    pub port_max: u16,
}

/// Uniform config-map write surface. All methods return `anyhow::Result<()>` except the reads
/// used by conflict checks. Method names are `<map>_<op>`.
pub trait MapWriter {
    fn route_upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()>;
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()>;
    fn route6_upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()>;
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<()>;
    fn nat_upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()>;
    fn nat_remove(&mut self, key: &NatKey) -> anyhow::Result<()>;
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    fn nat_ips_set(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    fn nat_ips_remove(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    fn neigh_nat_upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()>;
    fn neigh_nat_count_set(&mut self, count: u32) -> anyhow::Result<()>;
    // NAT66 (v6) write surface — sibling of the v4 nat methods above. No defaults: a silently
    // no-op'd v6 NAT would fail OPEN (leak the guest source v6), so every backend implements these.
    fn nat6_upsert(&mut self, key: NatKey6, val: NatValue6) -> anyhow::Result<()>;
    fn nat6_remove(&mut self, key: &NatKey6) -> anyhow::Result<()>;
    fn nat6_get(&self, key: &NatKey6) -> Option<NatValue6>;
    fn nat_ips6_set(&mut self, vni: u32, nat_ip: [u8; 16]) -> anyhow::Result<()>;
    fn nat_ips6_remove(&mut self, vni: u32, nat_ip: [u8; 16]) -> anyhow::Result<()>;
    fn neigh_nat6_upsert(&mut self, idx: u32, val: NeighborNat6Entry) -> anyhow::Result<()>;
    fn neigh_nat6_count_set(&mut self, count: u32) -> anyhow::Result<()>;
    fn lb_upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()>;
    fn lb_remove(&mut self, key: &LbKey) -> anyhow::Result<()>;
    /// IPv6 LB service row (`LB6`), keyed on the full v6 address — see [`LbKey6`].
    fn lb6_upsert(&mut self, key: LbKey6, val: LbValue) -> anyhow::Result<()>;
    fn lb6_remove(&mut self, key: &LbKey6) -> anyhow::Result<()>;
    fn maglev_upsert(&mut self, key: MaglevKey, val: LbBackend) -> anyhow::Result<()>;
    fn maglev_remove(&mut self, key: &MaglevKey) -> anyhow::Result<()>;
    fn underlay_upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()>;
    fn underlay_remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()>;
    fn underlay_get(&self, key: &[u8; 16]) -> Option<UnderlayValue>;
    /// FIREWALL classifier: make a compiled scope reachable under its id — both families' class and
    /// policy tries, FULLY populated before the id is inserted into the outer maps, so no lookup
    /// ever sees a half-built scope. Required (no default): a no-op'd scope would deny everything
    /// bound to it, or worse, leave a stale scope reachable.
    fn fw_scope_create(&mut self, scope: &crate::fwclass::Scope) -> anyhow::Result<()>;
    /// Remove a scope from the outer maps; in-flight lookups finish on the old tries (RCU).
    fn fw_scope_delete(&mut self, id: u64) -> anyhow::Result<()>;
    /// Point an interface at its scopes (`FW_BIND`): one write cuts both directions and families.
    fn fw_bind_upsert(&mut self, ifindex: u32, val: FwBind) -> anyhow::Result<()>;
    fn fw_bind_remove(&mut self, ifindex: u32) -> anyhow::Result<()>;
    /// Advance the node's firewall epoch (`FW_EPOCH`) after a binding change, so established flows
    /// meet their interfaces' new policy on their next packet.
    fn fw_epoch_bump(&mut self) -> anyhow::Result<()>;
    /// Adopt: the bindings and scope ids that survived a restart in the pinned maps.
    fn fw_bind_entries(&self) -> Vec<(u32, FwBind)>;
    fn fw_scope_ids(&self) -> Vec<u64>;
    fn meter_upsert(&mut self, ifindex: u32, val: MeterState) -> anyhow::Result<()>;
    fn meter_remove(&mut self, ifindex: &u32) -> anyhow::Result<()>;
    fn dhcp_config_set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()>;
    // INTERFACE domain: the per-interface programming maps `program_interface` writes and
    // the VNI-purge / detach reconciliation reads.
    fn ports_upsert(&mut self, ifindex: u32, meta: PortMeta) -> anyhow::Result<()>;
    fn ports_remove(&mut self, ifindex: u32) -> anyhow::Result<()>;
    fn ifaces_upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()>;
    fn ifaces_remove(&mut self, key: IfaceKey) -> anyhow::Result<()>;
    fn ifaces_get(&self, key: &IfaceKey) -> Option<IfaceValue>;
    /// IPv6 sibling of `ifaces_upsert` (`INTERFACES6`). Dual-written by `program_interface`.
    fn ifaces6_upsert(&mut self, key: IfaceKey6, val: IfaceValue) -> anyhow::Result<()>;
    fn ifaces6_remove(&mut self, key: IfaceKey6) -> anyhow::Result<()>;
    fn ifaces6_get(&self, key: &IfaceKey6) -> Option<IfaceValue>;
    fn iface_meta_upsert(&mut self, key: IfaceMetaKey, val: IfaceMetaVal) -> anyhow::Result<()>;
    fn iface_meta_remove(&mut self, key: &IfaceMetaKey) -> anyhow::Result<()>;
    fn dhcp_meta_remove(&mut self, ifindex: u32) -> anyhow::Result<()>;
    fn floating_ips_upsert(&mut self, key: FloatingIPKey, val: [u8; 4]) -> anyhow::Result<()>;
    fn floating_ips_remove(&mut self, key: &FloatingIPKey) -> anyhow::Result<()>;
    fn floating_ips_get(&self, key: &FloatingIPKey) -> Option<[u8; 4]>;
    fn conntrack_flush(&mut self, scope: CtFlushScope) -> anyhow::Result<()>;
    /// v6 sibling of `conntrack_flush` — flush the `NAT_CT6` entries for a NAT66 teardown.
    fn conntrack6_flush(&mut self, scope: CtFlushScope6) -> anyhow::Result<()>;
    /// Flush ALL conntrack entries for a DETACHED interface's guest IPs — every v4 CONNTRACK entry
    /// whose key vni matches and whose src OR dst is `guest_ip`, and every v6 CONNTRACK6 entry
    /// matching `guest_ip6` (skipped when all-zero). Called on interface teardown so a later
    /// reschedule of the same `(VNI, overlayIP)` cannot inherit a stale established-flow firewall
    /// bypass (a CT hit skips the deny-by-default firewall). Unlike `conntrack_flush` this is NOT
    /// scoped to a NAT allocation.
    fn conntrack_flush_interface(
        &mut self,
        vni: u32,
        guest_ip: [u8; 4],
        guest_ip6: [u8; 16],
    ) -> anyhow::Result<()>;
}
