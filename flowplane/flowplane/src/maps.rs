use anyhow::Context;
use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, HashMap, MapData,
};
use aya::Ebpf;
use flowplane_common::{
    CtEntry, CtEntry6, CtKey, CtKey6, DhcpConfig, DhcpMeta, FwMeta, FwRule, FwRule6, FwRuleKey,
    IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue, InspectEntry, LbBackend, LbKey,
    LbValue, Local, MaglevKey, MeterState, NatKey, NatKey6, NatValue, NatValue6, NeighborNat6Entry,
    NeighborNatEntry, PortMeta, RouteLpmData, RouteLpmData6, RouteValue, UnderlayValue, VipKey,
    VipKey6,
};

/// Generate a typed handle over a BPF `HashMap`.
///
/// Emits `struct $ty { map: HashMap<MapData, $key, $val> }` plus an `open` that `take_map`s
/// `$name` from a loaded eBPF object, and whichever of the accessor methods are listed:
///
/// - `upsert`         — `upsert(key: $key, val: $val)` → `HashMap::insert`
/// - `remove`         — `remove(key: &$key)`           → `HashMap::remove`
/// - `remove_owned`   — `remove(key: $key)`            → `HashMap::remove(&key)`
/// - `get`            — `get(key: &$key) -> Option<$val>`
/// - `get_owned`      — `get(key: $key)  -> Option<$val>`
/// - `entries`        — `pub fn entries() -> Vec<($key, $val)>`
/// - `entries_crate`  — `pub(crate) fn entries() -> Vec<($key, $val)>`
///
/// `$name` is the aya map name (must match the eBPF object) and doubles as the error context.
macro_rules! bpf_hash_map {
    (@upsert $key:ty, $val:ty, $name:literal) => {
        pub fn upsert(&mut self, key: $key, val: $val) -> anyhow::Result<()> {
            self.map.insert(key, val, 0).context(concat!("insert ", $name))
        }
    };
    (@remove $key:ty, $val:ty, $name:literal) => {
        pub fn remove(&mut self, key: &$key) -> anyhow::Result<()> {
            self.map.remove(key).context(concat!("remove ", $name))
        }
    };
    (@remove_owned $key:ty, $val:ty, $name:literal) => {
        pub fn remove(&mut self, key: $key) -> anyhow::Result<()> {
            self.map.remove(&key).context(concat!("remove ", $name))
        }
    };
    (@get $key:ty, $val:ty, $name:literal) => {
        pub fn get(&self, key: &$key) -> Option<$val> {
            self.map.get(key, 0).ok()
        }
    };
    (@get_owned $key:ty, $val:ty, $name:literal) => {
        pub fn get(&self, key: $key) -> Option<$val> {
            self.map.get(&key, 0).ok()
        }
    };
    (@entries $key:ty, $val:ty, $name:literal) => {
        pub fn entries(&self) -> Vec<($key, $val)> {
            self.map.iter().filter_map(|r| r.ok()).collect()
        }
    };
    (@entries_crate $key:ty, $val:ty, $name:literal) => {
        pub(crate) fn entries(&self) -> Vec<($key, $val)> {
            self.map.iter().filter_map(|r| r.ok()).collect()
        }
    };
    (
        $(#[$meta:meta])*
        $ty:ident, $name:literal, $key:ty, $val:ty $(, $method:ident)* $(,)?
    ) => {
        $(#[$meta])*
        pub struct $ty {
            map: HashMap<MapData, $key, $val>,
        }

        impl $ty {
            /// Take ownership of the `$name` map from a loaded eBPF object.
            pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
                let map = HashMap::try_from(
                    ebpf.take_map($name).context(concat!($name, " map missing"))?,
                )?;
                Ok(Self { map })
            }

            $( bpf_hash_map!(@$method $key, $val, $name); )*
        }
    };
}

/// Generate a typed handle over a single-entry BPF `Array` (index 0).
///
/// Emits `struct $ty { map: Array<MapData, $val> }` plus `open`, and one setter:
///
/// - `set_owned` — `set(value: $val)`  → `Array::set(0, value, 0)`
/// - `set_ref`   — `set(value: &$val)` → `Array::set(0, value, 0)`
macro_rules! bpf_array_map {
    (@set_owned $val:ty, $name:literal) => {
        pub fn set(&mut self, value: $val) -> anyhow::Result<()> {
            self.map.set(0, value, 0).context(concat!("write ", $name, "[0]"))
        }
    };
    (@set_ref $val:ty, $name:literal) => {
        pub fn set(&mut self, value: &$val) -> anyhow::Result<()> {
            self.map.set(0, value, 0).context(concat!("write ", $name, "[0]"))
        }
    };
    (
        $(#[$meta:meta])*
        $ty:ident, $name:literal, $val:ty $(, $method:ident)* $(,)?
    ) => {
        $(#[$meta])*
        pub struct $ty {
            map: Array<MapData, $val>,
        }

        impl $ty {
            /// Take ownership of the `$name` map from a loaded eBPF object.
            pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
                let map = Array::try_from(
                    ebpf.take_map($name).context(concat!($name, " map missing"))?,
                )?;
                Ok(Self { map })
            }

            $( bpf_array_map!(@$method $val, $name); )*
        }
    };
}

bpf_hash_map!(
    /// Typed handle over the `INTERFACES` BPF map (overlay (VNI, IPv4) -> delivery info).
    /// Exercised by the roundtrip test and consumed by the gRPC control plane. `entries` snapshots
    /// every pair at restart to rebuild in-memory bookkeeping from the surviving pinned map.
    Interfaces, "INTERFACES", IfaceKey, IfaceValue, upsert, remove_owned, get, entries_crate
);

bpf_hash_map!(
    /// Typed handle over the `INTERFACES6` BPF map (overlay (VNI, IPv6) -> delivery info). IPv6
    /// sibling of [`Interfaces`]; dual-written by the control plane alongside the v4 map.
    Interfaces6, "INTERFACES6", IfaceKey6, IfaceValue, upsert, remove_owned, get, entries_crate
);

bpf_hash_map!(
    /// Typed handle over the `IFACE_META` restart journal (interface_id -> rebuild detail). Written
    /// by the control plane on attach/detach and scanned on restart; never read by the datapath.
    IfaceMetaMap, "IFACE_META", IfaceMetaKey, IfaceMetaVal, upsert, remove, entries
);

bpf_hash_map!(
    /// Typed handle over the `PORT_META` BPF map (ifindex -> per-port metadata). `get` backs the
    /// E/W offload manager's offload-eligibility check (`PortMeta.offloaded`).
    PortMetaMap, "PORT_META", u32, PortMeta, upsert, remove_owned, get_owned
);

bpf_hash_map!(
    /// Typed handle over the `VIPS` BPF map.
    Vips, "VIPS", VipKey, [u8; 4], upsert, remove, get
);

bpf_hash_map!(
    /// Typed handle over the `LB` BPF map.
    Lb, "LB", LbKey, LbValue, upsert, remove
);

bpf_hash_map!(
    /// Typed handle over the `MAGLEV` BPF map.
    Maglev, "MAGLEV", MaglevKey, LbBackend, upsert, remove
);

bpf_hash_map!(
    /// Typed handle over the `CONNTRACK6` BPF map (LRU hash map). Firewall-only v6 mirror of
    /// [`Conntrack`]; the control plane holds it so it can flush a detached interface's v6 entries.
    Conntrack6, "CONNTRACK6", CtKey6, CtEntry, remove, entries
);

bpf_hash_map!(
    /// Typed handle over the `NAT` BPF map ((vni, guest ipv4) -> nat config).
    Nat, "NAT", NatKey, NatValue, upsert, remove, get
);

bpf_hash_map!(
    /// Typed handle over the `NAT6` BPF map ((vni, guest ipv6) -> NAT66 config). v6 mirror of
    /// [`Nat`].
    Nat6, "NAT6", NatKey6, NatValue6, upsert, remove, get
);

bpf_hash_map!(
    /// Typed handle over the `NAT_CT6` BPF map (LRU hash, `CtKey6` -> `CtEntry6`) — the dedicated
    /// NAT66 conntrack. Held by the control plane so a NAT66 teardown can flush the guest's entries
    /// (the map otherwise only auto-evicts via LRU).
    NatCt6, "NAT_CT6", CtKey6, CtEntry6, remove, entries
);

bpf_hash_map!(
    /// Typed handle over the `FW_RULES` BPF map ((ifindex, slot) -> rule).
    FwRules, "FW_RULES", FwRuleKey, FwRule, upsert, remove
);

bpf_hash_map!(
    /// Typed handle over the `FW_META` BPF map (ifindex -> per-direction rule counts).
    FwMetaMap, "FW_META", u32, FwMeta, upsert
);

bpf_hash_map!(
    /// Typed handle over the `FW_RULES6` BPF map ((ifindex, slot) -> IPv6 rule). Mirror of
    /// [`FwRules`].
    FwRules6, "FW_RULES6", FwRuleKey, FwRule6, upsert, remove
);

bpf_hash_map!(
    /// Typed handle over the `FW_META6` BPF map (ifindex -> per-direction rule counts). Mirror of
    /// [`FwMetaMap`].
    FwMetaMap6, "FW_META6", u32, FwMeta, upsert
);

bpf_hash_map!(
    /// Typed handle over the `UNDERLAY` BPF map (underlay IPv6 -> VNI + tap + guest MAC).
    Underlay, "UNDERLAY", [u8; 16], UnderlayValue, upsert, remove, get
);

bpf_hash_map!(
    /// Typed handle over the `NEIGHBOR_NAT` BPF map (slot index -> NeighborNatEntry).
    NeighborNat, "NEIGHBOR_NAT", u32, NeighborNatEntry, upsert
);

bpf_hash_map!(
    /// Typed handle over the `NEIGHBOR_NAT6` BPF map (slot index -> NeighborNat6Entry). v6 mirror
    /// of [`NeighborNat`].
    NeighborNat6, "NEIGHBOR_NAT6", u32, NeighborNat6Entry, upsert
);

bpf_hash_map!(
    /// Typed handle over the `METER` BPF map (ifindex -> per-interface token bucket state).
    Meter, "METER", u32, MeterState, upsert, remove
);

bpf_hash_map!(
    /// Typed handle over the `DHCP_META` BPF map (ifindex -> per-interface DHCP metadata).
    DhcpMetaMap, "DHCP_META", u32, DhcpMeta, remove_owned
);

bpf_array_map!(
    /// Typed handle over the single-entry `LOCAL` Array map.
    LocalMap, "LOCAL", Local, set_ref
);

bpf_array_map!(
    /// Typed handle over the single-entry `GENEVE_IFINDEX` Array map: the kernel `collect_md` geneve
    /// device's ifindex, read by the tc guest-egress encap path (`crate::tunnel::redirect`) to
    /// `bpf_redirect` an overlay-bound skb after `bpf_skb_set_tunnel_key` has stamped the tunnel-key
    /// metadata dst. Populated once by `Control::bring_up` right after `ensure_geneve_dev`.
    GeneveIfindexMap, "GENEVE_IFINDEX", u32, set_owned
);

bpf_array_map!(
    /// Typed handle over the single-entry `NEIGHBOR_NAT_COUNT` Array map.
    NeighborNatCount, "NEIGHBOR_NAT_COUNT", u32, set_owned
);

bpf_array_map!(
    /// Typed handle over the single-entry `NEIGHBOR_NAT6_COUNT` Array map. v6 mirror of
    /// [`NeighborNatCount`].
    NeighborNat6Count, "NEIGHBOR_NAT6_COUNT", u32, set_owned
);

bpf_array_map!(
    /// Typed handle over the single-entry `DHCP_CONFIG` Array map (server-wide DHCP parameters).
    DhcpConfigMap, "DHCP_CONFIG", DhcpConfig, set_ref
);

// ── Hand-written wrappers: maps whose accessors carry custom logic the macros don't cover ──

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

    /// Longest-prefix-match lookup for `ipv4` within `vni`'s routing table. A fully-specified
    /// (max prefix_len) lookup key makes the kernel LPM_TRIE do the longest-match search itself.
    /// Used by the E/W offload manager to resolve an established flow's remote VTEP + VNI.
    pub fn get(&self, vni: u32, ipv4: [u8; 4]) -> Option<RouteValue> {
        let key = Key::new(
            32 + 32,
            RouteLpmData {
                vni: vni.to_be_bytes(),
                ipv4,
            },
        );
        self.map.get(&key, 0).ok()
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

    /// v6 sibling of [`Routes::get`]: longest-prefix-match lookup for `ipv6` within `vni`'s
    /// routing table (`ROUTES6`).
    pub fn get(&self, vni: u32, ipv6: [u8; 16]) -> Option<RouteValue> {
        let key = Key::new(
            32 + 128,
            RouteLpmData6 {
                vni: vni.to_be_bytes(),
                ipv6,
            },
        );
        self.map.get(&key, 0).ok()
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

/// Typed handle over the `NAT_IPS6` BPF map ((vni, nat_ipv6) -> 1u8). v6 mirror of [`NatIps`],
/// keyed by [`VipKey6`]; marks NAT66 nat_ips for the ingress NAT-return demux (`is_nat_ip6`).
pub struct NatIps6 {
    map: HashMap<MapData, VipKey6, u8>,
}

impl NatIps6 {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("NAT_IPS6").context("NAT_IPS6 map missing")?)?;
        Ok(Self { map })
    }

    pub fn set(&mut self, vni: u32, nat_ip: [u8; 16]) -> anyhow::Result<()> {
        self.map
            .insert(VipKey6 { vni, ipv6: nat_ip }, 1u8, 0)
            .context("insert nat_ip6")
    }

    pub fn remove(&mut self, vni: u32, nat_ip: [u8; 16]) -> anyhow::Result<()> {
        self.map
            .remove(&VipKey6 { vni, ipv6: nat_ip })
            .context("remove nat_ip6")
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
            peer_capable: 0,
            _pad: [0; 1],
        };
        ifaces.upsert(k, v).expect("upsert");
        assert_eq!(ifaces.get(&k), Some(v));
    }
}
