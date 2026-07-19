use anyhow::Context;
use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, DevMap, DevMapHash, HashMap, MapData,
};
use aya::Ebpf;
use flowplane_common::{
    CtEntry, CtKey, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceMetaKey,
    IfaceMetaVal, IfaceValue, InspectEntry, LbKey, LbValue, Local, MaglevKey, MeterState, NatKey,
    NatValue, NeighborNatEntry, PortMeta, RouteLpmData, RouteLpmData6, RouteValue, UnderlayValue,
    VipKey,
};

/// Typed handle over the `INTERFACES` BPF map (overlay (VNI, IPv4) -> delivery info).
// Exercised by the roundtrip test now; wired into the gRPC control plane in Task 12.
pub struct Interfaces {
    map: HashMap<MapData, IfaceKey, IfaceValue>,
}

impl Interfaces {
    /// Take ownership of the `INTERFACES` map from a loaded eBPF object.
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("INTERFACES")
                .context("INTERFACES map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: IfaceKey, val: IfaceValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert iface")
    }

    pub fn remove(&mut self, key: IfaceKey) -> anyhow::Result<()> {
        self.map.remove(&key).context("remove iface")
    }

    /// Read-back accessor exercised by the (root-only) roundtrip test; not used by the daemon.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get(&self, key: &IfaceKey) -> Option<IfaceValue> {
        self.map.get(key, 0).ok()
    }

    /// Snapshot every (key, value) — used at restart to rebuild in-memory bookkeeping from the
    /// surviving pinned map. Mirrors `Conntrack::entries`. (Wired in by Task 5's restart path.)
    pub(crate) fn entries(&self) -> Vec<(IfaceKey, IfaceValue)> {
        self.map.iter().filter_map(|r| r.ok()).collect()
    }
}

/// Typed handle over the `IFACE_META` restart journal (interface_id -> rebuild detail). Written by
/// the control plane on attach/detach and scanned on restart; never read by the datapath.
pub struct IfaceMetaMap {
    map: HashMap<MapData, IfaceMetaKey, IfaceMetaVal>,
}

impl IfaceMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("IFACE_META")
                .context("IFACE_META map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: IfaceMetaKey, val: IfaceMetaVal) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert iface_meta")
    }

    pub fn remove(&mut self, key: &IfaceMetaKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove iface_meta")
    }

    /// Snapshot the whole journal — scanned once on restart to rebuild bookkeeping.
    pub fn entries(&self) -> Vec<(IfaceMetaKey, IfaceMetaVal)> {
        self.map.iter().filter_map(|r| r.ok()).collect()
    }
}

/// Typed handle over the single-entry `LOCAL` Array map.
pub struct LocalMap {
    map: Array<MapData, Local>,
}

impl LocalMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("LOCAL").context("LOCAL map missing")?)?;
        Ok(Self { map })
    }

    pub fn set(&mut self, local: &Local) -> anyhow::Result<()> {
        self.map.set(0, local, 0).context("write LOCAL[0]")
    }
}

/// Typed handle over the `UPLINK_DEV` devmap (single slot 0 -> fabric uplink ifindex). The edge
/// `wan_rx` fabric redirect goes through this devmap so containerlab veth uplinks deliver the
/// XDP_REDIRECT without needing a peer XDP program (see the eBPF `UPLINK_DEV` comment).
pub struct UplinkDevMap {
    map: DevMap<MapData>,
}

impl UplinkDevMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = DevMap::try_from(
            ebpf.take_map("UPLINK_DEV")
                .context("UPLINK_DEV map missing")?,
        )?;
        Ok(Self { map })
    }

    /// Point slot 0 at the fabric uplink ifindex (no chained program).
    pub fn set(&mut self, uplink_ifindex: u32) -> anyhow::Result<()> {
        self.map
            .set(0, uplink_ifindex, None, 0)
            .context("write UPLINK_DEV[0]")
    }
}

/// Typed handle over the `GUEST_DEV` devmap-hash (tap ifindex -> same ifindex). `uplink_rx`'s guest
/// DELIVERY redirect goes through this so containerlab veth guest taps deliver the XDP_REDIRECT
/// without a peer XDP program (see the eBPF `GUEST_DEV` comment). Populated on attach, cleared on
/// detach, keyed by the tap ifindex (many guests, unlike the single-slot UPLINK_DEV).
pub struct GuestDevMap {
    map: DevMapHash<MapData>,
}

impl GuestDevMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = DevMapHash::try_from(
            ebpf.take_map("GUEST_DEV")
                .context("GUEST_DEV map missing")?,
        )?;
        Ok(Self { map })
    }

    /// Map `tap_ifindex` -> `tap_ifindex` so `GUEST_DEV.redirect(tap_ifindex)` delivers to the tap.
    pub fn insert(&mut self, tap_ifindex: u32) -> anyhow::Result<()> {
        self.map
            .insert(tap_ifindex, tap_ifindex, None, 0)
            .with_context(|| format!("write GUEST_DEV[{tap_ifindex}]"))
    }

    /// Remove a tap ifindex on detach (best-effort).
    pub fn remove(&mut self, tap_ifindex: u32) {
        let _ = self.map.remove(tap_ifindex);
    }
}

/// Typed handle over the `PORT_META` BPF map (ifindex -> per-port metadata).
pub struct PortMetaMap {
    map: HashMap<MapData, u32, PortMeta>,
}

impl PortMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("PORT_META")
                .context("PORT_META map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, ifindex: u32, meta: PortMeta) -> anyhow::Result<()> {
        self.map
            .insert(ifindex, meta, 0)
            .context("insert port_meta")
    }

    pub fn remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.map.remove(&ifindex).context("remove port_meta")
    }
}

/// Typed handle over the single-entry `INSPECT` Array map (debug packet inspector).
pub struct InspectMap {
    map: Array<MapData, InspectEntry>,
}

impl InspectMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("INSPECT").context("INSPECT map missing")?)?;
        Ok(Self { map })
    }

    pub fn get(&self) -> anyhow::Result<InspectEntry> {
        self.map.get(&0, 0).context("read INSPECT[0]")
    }
}

/// Typed handle over the `ROUTES` BPF LPM trie map.
pub struct Routes {
    map: LpmTrie<MapData, RouteLpmData, RouteValue>,
}

impl Routes {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = LpmTrie::try_from(ebpf.take_map("ROUTES").context("ROUTES map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData {
                vni: vni.to_be_bytes(),
                ipv4,
            },
        );
        self.map.insert(&key, val, 0).context("insert route")
    }

    pub fn remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData {
                vni: vni.to_be_bytes(),
                ipv4,
            },
        );
        self.map.remove(&key).context("remove route")
    }
}

/// Typed handle over the `ROUTES6` BPF LPM trie map (IPv6 overlay routes).
pub struct Routes6 {
    map: LpmTrie<MapData, RouteLpmData6, RouteValue>,
}

impl Routes6 {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = LpmTrie::try_from(ebpf.take_map("ROUTES6").context("ROUTES6 map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(128),
            RouteLpmData6 {
                vni: vni.to_be_bytes(),
                ipv6,
            },
        );
        self.map.insert(&key, val, 0).context("insert route6")
    }

    pub fn remove(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(128),
            RouteLpmData6 {
                vni: vni.to_be_bytes(),
                ipv6,
            },
        );
        self.map.remove(&key).context("remove route6")
    }
}

/// Typed handle over the `VIPS` BPF map.
pub struct Vips {
    map: HashMap<MapData, VipKey, [u8; 4]>,
}

impl Vips {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("VIPS").context("VIPS map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: VipKey, val: [u8; 4]) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert vip")
    }

    pub fn remove(&mut self, key: &VipKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove vip")
    }

    pub fn get(&self, key: &VipKey) -> Option<[u8; 4]> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `LB` BPF map.
pub struct Lb {
    map: HashMap<MapData, LbKey, LbValue>,
}

impl Lb {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("LB").context("LB map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert lb")
    }

    pub fn remove(&mut self, key: &LbKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove lb")
    }
}

/// Typed handle over the `MAGLEV` BPF map.
pub struct Maglev {
    map: HashMap<MapData, MaglevKey, [u8; 16]>,
}

impl Maglev {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("MAGLEV").context("MAGLEV map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: MaglevKey, val: [u8; 16]) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert maglev")
    }

    pub fn remove(&mut self, key: &MaglevKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove maglev")
    }
}

/// Typed handle over the `CONNTRACK` BPF map (LRU hash map).
pub struct Conntrack {
    map: HashMap<MapData, CtKey, CtEntry>,
}

impl Conntrack {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("CONNTRACK")
                .context("CONNTRACK map missing")?,
        )?;
        Ok(Self { map })
    }

    /// Adopt a previously-pinned CONNTRACK map (HA restart) instead of taking it from a loaded
    /// eBPF object.  The pinned file must reside on a bpffs (e.g. `/sys/fs/bpf`).
    pub fn from_pin(path: &str) -> anyhow::Result<Self> {
        use aya::maps::Map;
        let map_data = aya::maps::MapData::from_pin(path).context("open pinned CONNTRACK")?;
        // CONNTRACK is BPF_MAP_TYPE_LRU_HASH; wrap in the matching Map variant so
        // HashMap::try_from can validate + construct the typed wrapper.
        let map = HashMap::try_from(Map::LruHashMap(map_data))?;
        Ok(Self { map })
    }

    pub fn remove(&mut self, key: &CtKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove conntrack")
    }

    /// Snapshot all (key, entry) pairs for a GC sweep.
    pub fn entries(&self) -> Vec<(CtKey, CtEntry)> {
        self.map.iter().filter_map(|r| r.ok()).collect()
    }
}

/// Typed handle over the `NAT` BPF map ((vni, guest ipv4) -> nat config).
pub struct Nat {
    map: HashMap<MapData, NatKey, NatValue>,
}

impl Nat {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("NAT").context("NAT map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert nat")
    }

    pub fn remove(&mut self, key: &NatKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove nat")
    }

    pub fn get(&self, key: &NatKey) -> Option<NatValue> {
        self.map.get(key, 0).ok()
    }
}

/// Typed handle over the `FW_RULES` BPF map ((ifindex, slot) -> rule).
pub struct FwRules {
    map: HashMap<MapData, FwRuleKey, FwRule>,
}

impl FwRules {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("FW_RULES").context("FW_RULES map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: FwRuleKey, val: FwRule) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert fw rule")
    }

    pub fn remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove fw rule")
    }
}

/// Typed handle over the `FW_META` BPF map (ifindex -> per-direction rule counts).
pub struct FwMetaMap {
    map: HashMap<MapData, u32, FwMeta>,
}

impl FwMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("FW_META").context("FW_META map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()> {
        self.map.insert(ifindex, val, 0).context("insert fw meta")
    }
}

/// Typed handle over the `UNDERLAY` BPF map (underlay IPv6 -> VNI + tap + guest MAC).
pub struct Underlay {
    map: HashMap<MapData, [u8; 16], UnderlayValue>,
}

impl Underlay {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("UNDERLAY").context("UNDERLAY map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()> {
        self.map.insert(key, val, 0).context("insert underlay")
    }

    pub fn remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()> {
        self.map.remove(key).context("remove underlay")
    }

    pub fn get(&self, key: &[u8; 16]) -> Option<UnderlayValue> {
        self.map.get(key, 0).ok()
    }

    /// Every underlay /128 currently programmed — used at restart to rebuild `UnderlayIpam`'s
    /// used-set (via `mark_used`) so a recovered live allocation is never reissued. (Wired in by
    /// Task 5's restart path.)
    pub(crate) fn keys(&self) -> Vec<[u8; 16]> {
        self.map.keys().filter_map(|r| r.ok()).collect()
    }
}

/// Typed handle over the `NEIGHBOR_NAT` BPF map (slot index -> NeighborNatEntry).
pub struct NeighborNat {
    map: HashMap<MapData, u32, NeighborNatEntry>,
}

impl NeighborNat {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("NEIGHBOR_NAT")
                .context("NEIGHBOR_NAT map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()> {
        self.map.insert(idx, val, 0).context("insert neighbor_nat")
    }
}

/// Typed handle over the `METER` BPF map (ifindex -> per-interface token bucket state).
pub struct Meter {
    map: HashMap<MapData, u32, MeterState>,
}

impl Meter {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("METER").context("METER map missing")?)?;
        Ok(Self { map })
    }

    pub fn upsert(&mut self, ifindex: u32, val: MeterState) -> anyhow::Result<()> {
        self.map.insert(ifindex, val, 0).context("insert meter")
    }

    pub fn remove(&mut self, ifindex: &u32) -> anyhow::Result<()> {
        self.map.remove(ifindex).context("remove meter")
    }
}

/// Typed handle over the `NAT_IPS` BPF map ((vni, nat_ip) -> 1u8), marking NAT IP addresses
/// so the ingress can generate ICMP echo replies without involving the VM.
pub struct NatIps {
    map: HashMap<MapData, VipKey, u8>,
}

impl NatIps {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("NAT_IPS").context("NAT_IPS map missing")?)?;
        Ok(Self { map })
    }

    pub fn set(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()> {
        self.map
            .insert(VipKey { vni, ipv4: nat_ip }, 1u8, 0)
            .context("insert nat_ip")
    }

    pub fn remove(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()> {
        self.map
            .remove(&VipKey { vni, ipv4: nat_ip })
            .context("remove nat_ip")
    }
}

/// Typed handle over the single-entry `NEIGHBOR_NAT_COUNT` Array map.
pub struct NeighborNatCount {
    map: Array<MapData, u32>,
}

impl NeighborNatCount {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(
            ebpf.take_map("NEIGHBOR_NAT_COUNT")
                .context("NEIGHBOR_NAT_COUNT map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn set(&mut self, count: u32) -> anyhow::Result<()> {
        self.map
            .set(0, count, 0)
            .context("write NEIGHBOR_NAT_COUNT[0]")
    }
}

/// Typed handle over the single-entry `DHCP_CONFIG` Array map (server-wide DHCP parameters).
pub struct DhcpConfigMap {
    map: Array<MapData, DhcpConfig>,
}

impl DhcpConfigMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(
            ebpf.take_map("DHCP_CONFIG")
                .context("DHCP_CONFIG map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()> {
        self.map.set(0, cfg, 0).context("write DHCP_CONFIG[0]")
    }
}

/// Typed handle over the `DHCP_META` BPF map (ifindex -> per-interface DHCP metadata).
pub struct DhcpMetaMap {
    map: HashMap<MapData, u32, DhcpMeta>,
}

impl DhcpMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(
            ebpf.take_map("DHCP_META")
                .context("DHCP_META map missing")?,
        )?;
        Ok(Self { map })
    }

    pub fn remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.map.remove(&ifindex).context("remove dhcp_meta")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root/CAP_BPF; run via: sudo -E <test-bin> --include-ignored"]
    fn interfaces_roundtrip_through_bpf_map() {
        // Requires CAP_BPF/root and a real kernel; run the test binary under `sudo -E`.
        // The `pinned` state maps need a bpffs `map_pin_path`; a private tempdir isolates this run.
        let pin = tempfile::Builder::new()
            .prefix("flowplane-maps-test-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir");
        let mut ebpf = crate::loader::load_ebpf(pin.path()).expect("load ebpf object");
        let mut ifaces = Interfaces::open(&mut ebpf).expect("open INTERFACES");
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        let v = IfaceValue {
            tap_ifindex: 7,
            is_local: 1,
            underlay_ipv6: [0xfd; 16],
            guest_mac: [2, 0, 0, 0, 0, 5],
            _pad: [0; 2],
        };
        ifaces.upsert(k, v).expect("upsert");
        assert_eq!(ifaces.get(&k), Some(v));
    }
}
