use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use aya::Ebpf;
use flowplane_common::{
    CtKey, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceMetaKey, IfaceMetaVal, IfaceValue, LbKey,
    LbValue, Local, MaglevKey, NatKey, NatValue, NeighborNatEntry, PortMeta, RouteValue, VipKey,
    FW_DIR_EGRESS, FW_MAX_RULES, IFACE_DEV_MAX, NB_MAX_ENTRIES,
};

use crate::loader;
use crate::maps::{
    Conntrack, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwRules, GuestDevMap, IfaceMetaMap,
    Interfaces, Lb, LocalMap, Maglev, Meter, Nat, NatIps, NeighborNat, NeighborNatCount,
    PortMetaMap, Routes, Routes6, UplinkDevMap, Vips,
};

/// The owned link for a guest interface's attached datapath program. Dropping either variant
/// detaches the program from the device. The guest edge is tcx-only (`tc_guest_tx`); the uplink
/// is always XDP.
enum GuestLink {
    // The link handles are never read back; they are held solely so that dropping the variant
    // detaches the program from the device (RAII detach).
    Tc(#[allow(dead_code)] aya::programs::tc::SchedClassifierLink),
    /// pin-links mode: the link lives in bpffs at links/<name>; we track the name to unpin on detach.
    Pinned(String),
}

/// Lowercase-hex encode an interface_id for a filesystem-safe, collision-free link pin name.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// LB IP address (IPv4 or IPv6) for create/get LB operations.
pub enum LbIpBytes {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

/// Per-interface addressing + rate-limit parameters for `create_interface` / `program_iface_maps`.
/// Bundled into one struct so the programming path doesn't thread ten positional arguments.
pub struct IfaceParams {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub underlay_ipv6: [u8; 16],
    pub total_mbps: u64,
    pub public_mbps: u64,
}

// Named shapes for the shadow records and gRPC list/get return rows, so the signatures below read
// as `Vec<RouteRow>` rather than a bare six-tuple (keeps `clippy::type_complexity` quiet and
// documents each column). Fields are described where each is produced/consumed.

/// `(vni, prefix_ipv4, prefix_len, nexthop_vni, nexthop_underlay)` for list/delete_route.
pub(crate) type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// `(vni, prefix_ipv6, prefix_len, nexthop_vni, nexthop_underlay)` IPv6 routes shadow.
pub(crate) type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);
/// `(vni, ipv4, ipv6, underlay, device)` for a single interface.
pub(crate) type InterfaceDetail = (u32, [u8; 4], [u8; 16], [u8; 16], String);
/// `(interface_id, vni, ipv4, ipv6, underlay, device)` row.
pub(crate) type InterfaceRow = (Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16], String);
// The read-side row/detail shapes below (and the `Control` list/get methods that return them) were
// consumed solely by the now-removed DPDKironcore gRPC service. They are retained — unit-tested and
// a natural fit for future DataplaneNode read RPCs — so they carry `#[allow(dead_code)]` now that
// their last caller left with `grpc.rs`.
/// `(route_vni, ip_bytes_16, prefix_len, nexthop_vni, nexthop_ipv6, is_ipv6)` row.
#[allow(dead_code)]
pub(crate) type RouteRow = (u32, [u8; 16], u32, u32, [u8; 16], bool);
/// `(vni, ip_bytes, lb_underlay, ports)` for a single load balancer.
#[allow(dead_code)]
pub(crate) type LbDetail = (u32, LbIpBytes, [u8; 16], Vec<(u16, u8)>);
/// `(id, vni, ip_bytes, lb_underlay, ports)` load-balancer row.
#[allow(dead_code)]
pub(crate) type LbRow = (Vec<u8>, u32, LbIpBytes, [u8; 16], Vec<(u16, u8)>);
/// `(nat_ip, port_min, port_max, underlay, vni)` for a guest's NAT config.
#[allow(dead_code)]
pub(crate) type NatDetail = ([u8; 4], u16, u16, [u8; 16], u32);
/// `(interface_id, guest_ipv4, nat_ip, port_min, port_max, vni, underlay)` local-NAT row.
#[allow(dead_code)]
pub(crate) type LocalNatRow = (Vec<u8>, [u8; 4], [u8; 4], u16, u16, u32, [u8; 16]);

/// Resolve a gRPC `device_name` to an actual kernel netdev name.
///
/// If `device` already exists under `/sys/class/net`, it is used verbatim. Otherwise, if it is a
/// dpservice DPDK vdev name `net_tap<N>` (N >= 2), it is translated to the kernel tap `dtapvf_<N-2>`
/// — the `--vdev=net_tap{N+2},iface=dtapvf_N` naming dpservice used and that metalnet sends over
/// gRPC. flowplane attaches XDP to the kernel tap directly, so it needs the kernel name.
fn resolve_iface(device: &str) -> String {
    if std::path::Path::new(&format!("/sys/class/net/{device}")).exists() {
        return device.to_string();
    }
    if let Some(n) = device
        .strip_prefix("net_tap")
        .and_then(|s| s.parse::<u32>().ok())
    {
        if n >= 2 {
            return format!("dtapvf_{}", n - 2);
        }
    }
    device.to_string()
}

/// Full detail record for a registered local interface (shadow of eBPF map state).
#[derive(Clone)]
struct IfaceRecord {
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    device: String,
    underlay: [u8; 16],
}

/// LB IP address stored in the shadow state (IPv4 or IPv6).
#[derive(Clone)]
enum LbIp {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl LbIp {
    /// Return the last 4 bytes of the address for underlay derivation.
    fn last4(&self) -> [u8; 4] {
        match self {
            LbIp::Ipv4(ip) => *ip,
            LbIp::Ipv6(ip) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&ip[12..16]);
                b
            }
        }
    }

    #[allow(dead_code)] // retained for future DataplaneNode LB read RPCs (was DPDKironcore-only)
    fn as_lb_ip_bytes(&self) -> LbIpBytes {
        match self {
            LbIp::Ipv4(ip) => LbIpBytes::Ipv4(*ip),
            LbIp::Ipv6(ip) => LbIpBytes::Ipv6(*ip),
        }
    }
}

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `Inner.lbs` by the LB's id.
struct LbEntry {
    vni: u32,
    ip: LbIp,
    lb_underlay: [u8; 16],
    ports: Vec<(u16, u8)>,
    table_id: u32,
    backends: Vec<[u8; 16]>,
}

/// Prefix record: ip bytes (4 or 16), prefix_len, underlay route, is_ipv6 flag.
/// Fields were read only by the removed DPDKironcore list-prefix RPCs; kept for the shadow bookkeeping
/// and future DataplaneNode read RPCs.
#[derive(Clone)]
#[allow(dead_code)]
struct PrefixRecord {
    ip: [u8; 16], // first 4 bytes for IPv4, all 16 for IPv6
    len: u32,
    underlay: [u8; 16],
    is_ipv6: bool,
}

/// Owns the loaded eBPF object + map handles; mutated by the gRPC handlers.
pub struct Control {
    inner: Mutex<Inner>,
    /// Conntrack map handle, shared with the GC task. Held in an Arc so both
    /// the control plane (for CT flush on NAT/neigh-NAT delete) and the GC task
    /// can access it concurrently without moving ownership.
    conntrack: Arc<Mutex<Conntrack>>,
}

struct Inner {
    ebpf: Ebpf,
    /// Owned `GUEST_PROGS_TC` program array handle. Holds the tc_guest_dhcp/tc_guest_nat64
    /// tail-call slots so `tc_guest_tx`'s tail calls resolve. Kept alive here for the datapath's
    /// lifetime; dropping it would close the userspace map fd.
    _guest_progs: aya::maps::ProgramArray<aya::maps::MapData>,
    _locals: LocalMap,
    /// Owned `UPLINK_DEV` devmap handle. wan_rx is loaded LATER (attach_edge), so this handle MUST
    /// stay alive here — dropping it after set() closes the map fd and wan_rx then fails to verify
    /// ("fd is not pointing to valid bpf_map"), exactly like `_locals`/`_guest_progs`.
    _uplink_dev: UplinkDevMap,
    guest_dev: GuestDevMap,
    ports: PortMetaMap,
    ifaces: Interfaces,
    routes: Routes,
    routes6: Routes6,
    vips: Vips,
    lb: Lb,
    maglev: Maglev,
    nat: Nat,
    fw_rules: FwRules,
    fw_meta: FwMetaMap,
    underlay: crate::maps::Underlay,
    meter: Meter,
    neigh_nat: NeighborNat,
    neigh_nat_count: NeighborNatCount,
    nat_ips: NatIps,
    dhcp_config: DhcpConfigMap,
    dhcp_meta: DhcpMetaMap,
    /// Restart journal: interface_id -> rebuild detail. Written on attach/detach; scanned on adopt.
    iface_meta: IfaceMetaMap,
    /// Interfaces recovered by `rebuild_from_maps` on adopt: (interface_id, device) whose guest
    /// program must be re-attached by the caller (`Serve`). Empty on a fresh (non-adopt) bring-up.
    recovered: Vec<(Vec<u8>, String)>,
    /// Underlay /128s recovered from the surviving UNDERLAY map on adopt, for reseeding `UnderlayIpam`.
    recovered_underlays: Vec<[u8; 16]>,
    /// Link-pinning enabled: pin program links + adopt them atomically on restart.
    pin_links: bool,
    /// Persistent pin dir for link pins; mirrors the map pin dir passed to load_ebpf.
    pin_dir: std::path::PathBuf,
    /// In-memory neighbor NAT entries (drives the BPF map reprogram).
    neigh_nats: Vec<NeighborNatEntry>,
    /// loadbalancer_id -> its LB state.
    lbs: HashMap<Vec<u8>, LbEntry>,
    next_table_id: u32,
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
    /// interface_id -> ifindex
    by_ifindex: HashMap<Vec<u8>, u32>,
    /// interface_id -> its underlay /128
    iface_underlay: HashMap<Vec<u8>, [u8; 16]>,
    /// interface_id -> list of prefix records (IPv4 and IPv6)
    prefixes: HashMap<Vec<u8>, Vec<PrefixRecord>>,
    /// ifindex -> ordered (rule_id, rule) pairs
    fw: HashMap<u32, Vec<(Vec<u8>, FwRule)>>,
    /// interface_id -> list of LB-prefix records (announce-only).
    #[allow(dead_code)] // read only by the removed DPDKironcore list-lb-prefix RPCs
    lb_prefixes: HashMap<Vec<u8>, Vec<PrefixRecord>>,
    /// interface_id -> the owned guest datapath link (dropping it detaches the program).
    links: HashMap<Vec<u8>, GuestLink>,
    routes_shadow: Vec<RouteShadowV4>,
    routes6_shadow: Vec<RouteShadowV6>,
    /// Shadow cache of learned guest MACs: interface_id -> guest_mac.
    /// Persists across delete+recreate of the SAME interface so the datapath keeps delivering to a
    /// datapath-learned MAC (e.g. a VM's self-set MAC) when it is reprogrammed. Keyed by
    /// interface_id so a different interface reusing a freed underlay /128 never inherits it.
    learned_macs: HashMap<Vec<u8>, [u8; 6]>,
}

impl Control {
    /// Load + attach uplink_rx, set LOCAL, take the map handles.
    pub fn bring_up(
        uplink: &str,
        uplink_ifindex: u32,
        uplink_mac: [u8; 6],
        gateway_mac: [u8; 6],
        underlay_ipv6: [u8; 16],
        pin_dir: &Path,
        adopt: bool,
        pin_links: bool,
    ) -> anyhow::Result<Self> {
        let mut ebpf = loader::load_ebpf(pin_dir)?;
        loader::maybe_install_logger(&mut ebpf);
        // The uplink RX path is always XDP, regardless of the guest edge attach mode.
        if pin_links {
            let uplink_pin = format!("uplink-{uplink}");
            // Adopt: atomically re-point the surviving pinned link at the fresh program (no gap). A
            // missing/broken pin falls through to a fresh attach+pin.
            let readopted = adopt
                && loader::readopt_xdp_link(&mut ebpf, "uplink_rx", pin_dir, &uplink_pin)
                    .unwrap_or_else(|e| {
                        eprintln!("re-adopt uplink link failed ({e:#}); attaching fresh");
                        loader::unpin_link(pin_dir, &uplink_pin);
                        false
                    });
            if !readopted {
                loader::attach_xdp_pinned_at(&mut ebpf, "uplink_rx", uplink, pin_dir, &uplink_pin)?;
            }
        } else {
            // pin-links off: clear any stale pin from a previous pin-on run so the fresh (unpinned)
            // attach can't hit EBUSY against a link that survived the last process.
            loader::unpin_link(pin_dir, &format!("uplink-{uplink}"));
            loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;
        }
        loader::ensure_fq_qdisc(uplink);
        // Guest edge is tcx-only. Pre-load tc_guest_tx and register the tc DHCP/NAT64 tail-call
        // array (GUEST_PROGS_TC) once here; per-interface attach then only needs attach().
        let guest_progs = {
            let progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
            loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
            progs
        };
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex,
            uplink_mac,
            gateway_mac,
            underlay_ipv6,
        })?;
        // Point the uplink devmap at the fabric uplink so the wan_rx fabric redirect delivers over
        // containerlab veths. The handle is stored in Inner (below) so its fd stays open until
        // wan_rx is loaded in attach_edge.
        let mut uplink_dev = UplinkDevMap::open(&mut ebpf)?;
        uplink_dev.set(uplink_ifindex)?;
        let guest_dev = GuestDevMap::open(&mut ebpf)?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let iface_meta = IfaceMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        let mut inner = Inner {
            ebpf,
            _guest_progs: guest_progs,
            _locals: locals,
            _uplink_dev: uplink_dev,
            guest_dev,
            ports,
            ifaces,
            routes,
            routes6,
            vips,
            lb,
            maglev,
            nat,
            fw_rules,
            fw_meta,
            underlay,
            meter,
            neigh_nat,
            neigh_nat_count,
            nat_ips,
            dhcp_config,
            dhcp_meta,
            iface_meta,
            recovered: Vec::new(),
            recovered_underlays: Vec::new(),
            pin_links,
            pin_dir: pin_dir.to_path_buf(),
            neigh_nats: Vec::new(),
            lbs: HashMap::new(),
            next_table_id: 1,
            by_id: HashMap::new(),
            by_ifindex: HashMap::new(),
            iface_underlay: HashMap::new(),
            prefixes: HashMap::new(),
            fw: HashMap::new(),
            lb_prefixes: HashMap::new(),
            links: HashMap::new(),
            routes_shadow: Vec::new(),
            routes6_shadow: Vec::new(),
            learned_macs: HashMap::new(),
        };
        // Restart adopt: the pinned state maps were reused by map_pin_path, so rebuild the in-memory
        // bookkeeping (by_id/by_ifindex/iface_underlay) and the re-attach + IPAM-reseed lists from the
        // surviving IFACE_META journal and UNDERLAY map. A fresh (non-adopt) bring-up starts empty.
        if adopt {
            let (recovered, recovered_underlays) = Self::rebuild_from_maps(&mut inner)?;
            eprintln!(
                "adopt: recovered {} interface(s) and {} underlay /128(s) from pinned maps",
                recovered.len(),
                recovered_underlays.len()
            );
            inner.recovered = recovered;
            inner.recovered_underlays = recovered_underlays;
        }
        Ok(Self {
            inner: Mutex::new(inner),
            conntrack,
        })
    }

    /// After adopting pinned maps on restart, repopulate the in-memory bookkeeping from the surviving
    /// `IFACE_META` journal so subsequent AttachInterface/DetachInterface/get/list see the pre-restart
    /// state. Returns `(reattach, underlays)`:
    ///   - `reattach`: `(interface_id, device)` whose guest program must be RE-ATTACHED by the caller
    ///     (their links died with the old process; the maps survived).
    ///   - `underlays`: every programmed underlay /128 (from the surviving UNDERLAY map) so the caller
    ///     can reseed `UnderlayIpam` and never reissue a live allocation.
    fn rebuild_from_maps(g: &mut Inner) -> anyhow::Result<(Vec<(Vec<u8>, String)>, Vec<[u8; 16]>)> {
        let journal = g.iface_meta.entries();
        // Sanity cross-check: the journal should track the surviving INTERFACES map 1:1.
        let iface_count = g.ifaces.entries().len();
        if iface_count != journal.len() {
            eprintln!(
                "adopt: WARNING IFACE_META has {} entries but INTERFACES has {} — journal drift",
                journal.len(),
                iface_count
            );
        }
        let mut reattach = Vec::with_capacity(journal.len());
        for (k, v) in &journal {
            let (id, device, rec) = Self::decode_iface_meta(k, v);
            // Re-derive the CURRENT tap ifindex — the veth persists across the restart, but the
            // stored ifindex is only a cross-check. If the device is gone (pod deleted during the
            // downtime), skip re-attach; its stale maps are cleaned by a later DetachInterface.
            let tap = match crate::ifindex(&device) {
                Ok(ix) => ix,
                Err(e) => {
                    eprintln!("adopt: device {device} for a recovered interface is gone ({e}); skipping re-attach");
                    continue;
                }
            };
            if tap != v.tap_ifindex {
                eprintln!(
                    "adopt: {device} ifindex changed {} -> {tap} since attach; using live value",
                    v.tap_ifindex
                );
            }
            g.by_id.insert(id.clone(), rec);
            g.by_ifindex.insert(id.clone(), tap);
            g.iface_underlay.insert(id.clone(), v.underlay);
            // GUEST_DEV is pinned and keyed by ifindex; re-insert defensively in case ifindex drifted.
            let _ = g.guest_dev.insert(tap);
            reattach.push((id, device));
        }
        let underlays = g.underlay.keys();
        Ok((reattach, underlays))
    }

    /// Pure decode of one `IFACE_META` journal entry into `(interface_id, device, IfaceRecord)`.
    /// Factored out so the parsing is unit-testable without a live BPF map.
    fn decode_iface_meta(k: &IfaceMetaKey, v: &IfaceMetaVal) -> (Vec<u8>, String, IfaceRecord) {
        let id = k.id[..(v.id_len as usize).min(k.id.len())].to_vec();
        let device =
            String::from_utf8_lossy(&v.device[..(v.device_len as usize).min(v.device.len())])
                .into_owned();
        let rec = IfaceRecord {
            vni: v.vni,
            ipv4: v.ipv4,
            ipv6: v.ipv6,
            device: device.clone(),
            underlay: v.underlay,
        };
        (id, device, rec)
    }

    /// The `(interface_id, device)` list recovered on adopt, whose guest program the caller must
    /// re-attach. Empty after a fresh bring-up.
    pub fn recovered_interfaces(&self) -> Vec<(Vec<u8>, String)> {
        self.inner.lock().recovered.clone()
    }

    /// The underlay /128s recovered on adopt, for reseeding `UnderlayIpam`. Empty after a fresh
    /// bring-up.
    pub fn recovered_underlays(&self) -> Vec<[u8; 16]> {
        self.inner.lock().recovered_underlays.clone()
    }

    /// Re-attach the guest datapath program to an ADOPTED interface's device after a restart. The
    /// pinned maps and in-memory bookkeeping already describe it (map_pin_path reuse +
    /// `rebuild_from_maps`); this ONLY re-creates the `GuestLink` (the old one died with the process)
    /// and stores it so a later DetachInterface can drop it — no map writes, no bookkeeping insert.
    /// Mirrors the attach half of `create_interface`.
    pub fn reattach_guest(&self, interface_id: &[u8], device: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "tc_guest_tx", &pin_dir, &gname)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt guest link {gname} failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &gname);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "tc_guest_tx", device, &pin_dir, &gname)?;
            }
            g.links
                .insert(interface_id.to_vec(), GuestLink::Pinned(gname));
            return Ok(());
        }
        let link = GuestLink::Tc(
            loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                .with_context(|| format!("re-attach tc_guest_tx to {device}"))?,
        );
        g.links.insert(interface_id.to_vec(), link);
        Ok(())
    }

    /// WAN-edge role: attach `wan_rx` to the WAN uplink and register the edge's own underlay /128
    /// as a local-deliver UNDERLAY entry (sentinel tap). Fabric->WAN egress then decaps and
    /// XDP_PASSes to the local kernel (VyOS), while WAN->fabric returns to a `nat_ip` are caught by
    /// `wan_rx` and re-encapped to the block owner. Call once, after `bring_up`.
    pub fn attach_edge(&self, wan_uplink: &str, edge_underlay: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let pin_links = g.pin_links;
        let pin_dir = g.pin_dir.clone();
        if pin_links {
            let name = format!("wan-{wan_uplink}");
            let readopted = loader::readopt_xdp_link(&mut g.ebpf, "wan_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt wan link failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_xdp_pinned_at(&mut g.ebpf, "wan_rx", wan_uplink, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("wan-{wan_uplink}"));
            loader::attach_xdp(&mut g.ebpf, "wan_rx", wan_uplink)?;
        }
        loader::ensure_fq_qdisc(wan_uplink);
        g.underlay.upsert(
            edge_underlay,
            flowplane_common::UnderlayValue {
                vni: 0,
                tap_ifindex: flowplane_common::UNDERLAY_LOCAL_DELIVER,
                guest_mac: [0; 6],
                _pad: [0; 2],
            },
        )?;
        println!(
            "edge role: wan_rx attached to {wan_uplink}; UNDERLAY[{}] = local-deliver",
            std::net::Ipv6Addr::from(edge_underlay)
        );
        Ok(())
    }

    /// Attach `uplink_rx` on an ADDITIONAL fabric uplink (a dual-homed host decaps returns arriving
    /// via either ToR). The program is already loaded by `bring_up`; this just attaches it to
    /// another interface. LOCAL stays the primary uplink (egress + wan_rx redirect use it).
    pub fn attach_extra_uplink(&self, iface: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let pin_links = g.pin_links;
        let pin_dir = g.pin_dir.clone();
        if pin_links {
            let name = format!("uplink-{iface}");
            let readopted = loader::readopt_xdp_link(&mut g.ebpf, "uplink_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt extra uplink {iface} failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_xdp_pinned_at(&mut g.ebpf, "uplink_rx", iface, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("uplink-{iface}"));
            loader::attach_xdp_extra(&mut g.ebpf, "uplink_rx", iface)?;
        }
        loader::ensure_fq_qdisc(iface);
        println!("uplink_rx attached to extra uplink {iface}");
        Ok(())
    }

    /// Return a shared handle to the conntrack map (for the GC task and flush operations).
    pub fn take_conntrack(&self) -> Arc<Mutex<Conntrack>> {
        Arc::clone(&self.conntrack)
    }

    pub fn set_dhcp_config(
        &self,
        mtu: u16,
        dns4: &[[u8; 4]],
        dns6: &[[u8; 16]],
    ) -> anyhow::Result<()> {
        let mut cfg = flowplane_common::DhcpConfig {
            mtu,
            dns4_len: dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns6_len: dns6.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns4: [[0; 4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns4[i] = *a;
        }
        for (i, a) in dns6.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns6[i] = *a;
        }
        self.inner.lock().dhcp_config.set(&cfg)
    }

    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn set_dhcp_meta(
        &self,
        interface_id: &[u8],
        hostname: &[u8],
        pxe_host: &[u8],
        boot_filename: &[u8],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let mut m = flowplane_common::DhcpMeta {
            hostname: [0; 64],
            hostname_len: 0,
            boot_filename: [0; 64],
            boot_filename_len: 0,
            pxe_host: [0; 46],
            pxe_host_len: 0,
            _pad: [0; 1],
        };
        let hl = hostname.len().min(64);
        m.hostname[..hl].copy_from_slice(&hostname[..hl]);
        m.hostname_len = hl as u8;
        let bl = boot_filename.len().min(64);
        m.boot_filename[..bl].copy_from_slice(&boot_filename[..bl]);
        m.boot_filename_len = bl as u8;
        let pl = pxe_host.len().min(46);
        m.pxe_host[..pl].copy_from_slice(&pxe_host[..pl]);
        m.pxe_host_len = pl as u8;
        g.dhcp_meta.upsert(ifindex, m)
    }

    /// Build a `MeterState` from per-lane caps in Mbit/s. Egress total is EDT-shaped: only
    /// `total_bps` + the schedule cursor (`total_last_ns`, seeded 0) matter — no token bucket.
    /// Public + ingress are token-bucket policers (burst = 1/8 s of rate, min 2000B). All 0 =>
    /// unlimited. Single source of truth shared by program_iface_maps, the CLI, and ConfigureQoS.
    pub fn meter_state(
        egress_mbps: u64,
        public_mbps: u64,
        ingress_mbps: u64,
    ) -> flowplane_common::MeterState {
        let e = egress_mbps.saturating_mul(1_000_000) / 8;
        let p = public_mbps.saturating_mul(1_000_000) / 8;
        let i = ingress_mbps.saturating_mul(1_000_000) / 8;
        flowplane_common::MeterState {
            total_bps: e,
            total_burst: 0,
            total_tokens: 0,
            total_last_ns: 0,
            public_bps: p,
            public_burst: (p / 8).max(2000),
            public_tokens: p / 8,
            public_last_ns: 0,
            ingress_bps: i,
            ingress_burst: (i / 8).max(2000),
            ingress_tokens: i / 8,
            ingress_last_ns: 0,
        }
    }

    /// Program a LOCAL interface: attach tc_guest_tx to its device, set PORT_META + INTERFACES +
    /// UNDERLAY, retain the link for detach, and record shadow detail.
    pub fn create_interface(
        &self,
        interface_id: &[u8],
        device: &str,
        params: IfaceParams,
    ) -> anyhow::Result<()> {
        let (vni, ipv4, ipv6, underlay_ipv6) =
            (params.vni, params.ipv4, params.ipv6, params.underlay_ipv6);
        // Resolve the device name to a kernel netdev. metalnet (in dpservice tap mode) claims a tap
        // from its hardcoded pool dtapvf_N but sends the DPDK vdev name net_tap{N+2} over gRPC
        // (dpservice's --vdev=net_tap{N+2},iface=dtapvf_N convention). We have no DPDK — only the
        // kernel tap dtapvf_N — so translate net_tapX -> dtapvf_{X-2} when the literal name is
        // absent. Names that already exist as netdevs (e.g. dtapvf_N sent directly) pass through.
        let resolved = resolve_iface(device);
        let device = resolved.as_str();
        let tap = crate::ifindex(device)
            .map_err(|e| anyhow::anyhow!("read ifindex for {device}: {e}"))?;
        let mac = crate::mac_of(device)?;
        // The restart journal (IFACE_META) stores the interface_id and device in fixed-width fields;
        // reject anything that would not round-trip rather than silently truncate (a truncated id
        // could alias another interface on adopt).
        if interface_id.len() > flowplane_common::IFACE_ID_MAX {
            anyhow::bail!(
                "interface_id too long ({} > {}) for the restart journal",
                interface_id.len(),
                flowplane_common::IFACE_ID_MAX
            );
        }
        if device.len() > IFACE_DEV_MAX {
            anyhow::bail!(
                "device name {device:?} too long ({} > {IFACE_DEV_MAX}) for the restart journal",
                device.len()
            );
        }
        let mut g = self.inner.lock();
        if g.by_id.contains_key(interface_id) {
            anyhow::bail!("interface already exists");
        }
        // Check that the (vni, ipv4) combination is not already in use (ROUTE_EXISTS).
        if g.by_id.values().any(|r| r.vni == vni && r.ipv4 == ipv4) {
            anyhow::bail!("ROUTE_EXISTS: IP already in use in this VNI");
        }
        // Check that the (vni, ipv6) combination is not already in use (if non-zero).
        if ipv6 != [0u8; 16] && g.by_id.values().any(|r| r.vni == vni && r.ipv6 == ipv6) {
            anyhow::bail!("ROUTE_EXISTS: IPv6 already in use in this VNI");
        }
        // NOTE: preferred underlay collision is NOT checked here; it is checked only when
        // the caller explicitly supplies a preferred_underlay_route (see grpc.rs handler).
        // The guest program was pre-loaded in bring_up, so attach always succeeds and we get a
        // droppable link back — dropping it detaches the program on interface teardown.
        let link = if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            loader::attach_tc_pinned_at(&mut g.ebpf, "tc_guest_tx", device, &pin_dir, &gname)
                .with_context(|| format!("attach+pin tc_guest_tx to {device}"))?;
            GuestLink::Pinned(gname)
        } else {
            GuestLink::Tc(
                loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                    .with_context(|| format!("attach tc_guest_tx to {device}"))?,
            )
        };
        // Do the FALLIBLE datapath writes first and commit the in-memory bookkeeping only after they
        // all succeed. Otherwise a failed guest_dev/map write left a ghost by_id/links entry behind
        // while attach.rs (seeing the Err) deleted the veth + released the IPAM /128 — so Control
        // referenced a dead device and a retry of the same id hit "interface already exists". `link`
        // is a local until commit, so any early return here drops it, detaching the guest program.
        //
        // Register the tap in GUEST_DEV so uplink_rx's delivery redirect reaches it over clab veths.
        g.guest_dev
            .insert(tap)
            .context("register tap in GUEST_DEV")?;
        if let Err(e) = Self::program_iface_maps(&mut g, interface_id, device, tap, mac, &params) {
            let _ = g.guest_dev.remove(tap); // unwind the GUEST_DEV write
                                             // A non-pinned `link` drops here -> detaches. A pinned link is held by the bpffs pin, not
                                             // by `link`, so explicitly unpin to detach the program and avoid leaking the pin — keeping
                                             // the partial-failure rollback invariant (attach.rs deletes the veth + releases the /128).
            if let GuestLink::Pinned(name) = &link {
                let pd = g.pin_dir.clone();
                loader::unpin_link(&pd, name);
            }
            return Err(e);
        }
        // All datapath writes succeeded — commit the in-memory bookkeeping.
        g.links.insert(interface_id.to_vec(), link);
        g.by_id.insert(
            interface_id.to_vec(),
            IfaceRecord {
                vni,
                ipv4,
                ipv6,
                device: device.to_string(),
                underlay: underlay_ipv6,
            },
        );
        g.by_ifindex.insert(interface_id.to_vec(), tap);
        g.iface_underlay
            .insert(interface_id.to_vec(), underlay_ipv6);
        Ok(())
    }

    /// Program PORT_META / INTERFACES / UNDERLAY / METER / local self-route for one interface.
    fn program_iface_maps(
        g: &mut Inner,
        interface_id: &[u8],
        device: &str,
        tap: u32,
        mac: [u8; 6],
        params: &IfaceParams,
    ) -> anyhow::Result<()> {
        let IfaceParams {
            vni,
            ipv4,
            ipv6,
            gateway_ipv4,
            gateway_ipv6,
            underlay_ipv6,
            total_mbps,
            public_mbps,
        } = *params;
        // MAC learning persistence: prefer the shadow-cached learned MAC (populated by
        // detach_interface) so a delete+recreate of the SAME interface preserves a datapath-learned
        // MAC (e.g. a VM behind the tap using a self-set MAC) even though the BPF UNDERLAY entry is
        // gone. Keyed by interface_id (NOT the underlay /128): a DIFFERENT interface reusing a freed
        // underlay must NOT inherit the previous endpoint's MAC — it uses its own device MAC.
        let effective_mac = g.learned_macs.get(interface_id).copied().unwrap_or(mac);
        g.ports.upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: effective_mac,
                _pad: [0; 2],
                underlay_ipv6,
                gateway_ipv6,
                guest_ipv6: ipv6,
            },
        )?;
        g.ifaces.upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        g.underlay.upsert(
            underlay_ipv6,
            flowplane_common::UnderlayValue {
                vni,
                tap_ifindex: tap,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        // Local self-route: a same-host guest reaches this interface by its overlay IP. Program a
        // /32 (and /128 when dual-stack) route to this interface's OWN underlay so tc_guest_tx's
        // LPM resolves a local destination to a local underlay, and the local fast path delivers it
        // without a wire round-trip. These are NOT added to routes_shadow (not user-visible routes).
        g.routes.upsert(
            vni,
            ipv4,
            32,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: underlay_ipv6,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        if ipv6 != [0u8; 16] {
            g.routes6.upsert(
                vni,
                ipv6,
                128,
                RouteValue {
                    nexthop_vni: vni,
                    nexthop_ipv6: underlay_ipv6,
                    is_external: 0,
                    _pad: [0; 3],
                },
            )?;
        }
        if total_mbps != 0 || public_mbps != 0 {
            g.meter
                .upsert(tap, Self::meter_state(total_mbps, public_mbps, 0))?;
        }
        // Restart journal (never read by the datapath): persist what a restart needs to rebuild
        // bookkeeping and re-attach the guest program. Lengths are guarded in create_interface, so
        // `from_id` is `Some` and the device fits.
        if let Some(key) = IfaceMetaKey::from_id(interface_id) {
            let n = device.len().min(IFACE_DEV_MAX);
            let mut dev = [0u8; IFACE_DEV_MAX];
            dev[..n].copy_from_slice(&device.as_bytes()[..n]);
            g.iface_meta.upsert(
                key,
                IfaceMetaVal {
                    vni,
                    tap_ifindex: tap,
                    ipv4,
                    id_len: interface_id.len().min(flowplane_common::IFACE_ID_MAX) as u16,
                    device_len: n as u16,
                    ipv6,
                    underlay: underlay_ipv6,
                    device: dev,
                },
            )?;
        }
        Ok(())
    }

    /// Tear down a local interface: detach tc_guest_tx (drop the link) and clear its maps + shadow.
    /// Returns true if found and deleted, false if not found.
    /// When the last interface on a VNI is removed, also auto-resets the VNI (purges neighbor NATs,
    /// VIPs, and routes for that VNI) to match dpservice's behaviour.
    pub fn detach_interface(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let rec = match g.by_id.remove(interface_id) {
            Some(r) => r,
            None => return Ok(false),
        };
        let vni = rec.vni;
        let tap = g.by_ifindex.remove(interface_id).unwrap_or(0);
        g.guest_dev.remove(tap);
        g.iface_underlay.remove(interface_id);
        g.prefixes.remove(interface_id);
        // Drop the restart-journal entry so a later adopt does not resurrect a deleted interface.
        if let Some(k) = IfaceMetaKey::from_id(interface_id) {
            let _ = g.iface_meta.remove(&k);
        }
        // Dropping the link detaches the program from the device.
        if let Some(GuestLink::Pinned(name)) = g.links.remove(interface_id) {
            let pin_dir = g.pin_dir.clone();
            loader::unpin_link(&pin_dir, &name);
        }
        let _ = g.ports.remove(tap);
        let _ = g.ifaces.remove(IfaceKey::new(rec.vni, rec.ipv4));
        // Before removing the UNDERLAY entry, snapshot the currently-learned guest MAC
        // (the datapath may have updated it via DHCP/ARP MAC learning). This snapshot
        // survives the delete so that addinterface can restore the learned MAC.
        if let Some(u) = g.underlay.get(&rec.underlay) {
            g.learned_macs.insert(interface_id.to_vec(), u.guest_mac);
        }
        let _ = g.underlay.remove(&rec.underlay);
        let _ = g.meter.remove(&tap);
        let _ = g.dhcp_meta.remove(tap);
        // Remove the local self-route(s) programmed in program_iface_maps.
        let _ = g.routes.remove(rec.vni, rec.ipv4, 32);
        if rec.ipv6 != [0u8; 16] {
            let _ = g.routes6.remove(rec.vni, rec.ipv6, 128);
        }
        if let Some(rules) = g.fw.remove(&tap) {
            drop(rules);
        }
        // Auto-reset VNI when the last local interface on it is removed:
        // purge neighbor NATs (and orphaned VIP/NAT/route state) for that VNI. This matches
        // dpservice's async-deletion model where the VNI is implicitly reset on last-iface removal.
        let vni_still_in_use =
            g.by_id.values().any(|r| r.vni == vni) || g.lbs.values().any(|lb| lb.vni == vni);
        if !vni_still_in_use {
            // Purge neighbor NATs for this VNI.
            let before = g.neigh_nats.len();
            g.neigh_nats.retain(|e| e.vni != vni);
            if g.neigh_nats.len() != before {
                let n = g.neigh_nats.len() as u32;
                let remaining: Vec<NeighborNatEntry> = g.neigh_nats.clone();
                for (i, e) in remaining.iter().enumerate() {
                    let _ = g.neigh_nat.upsert(i as u32, *e);
                }
                let _ = g.neigh_nat_count.set(n);
            }
            // Purge VIP entries for the removed interface's guest IP (and its reverse).
            let maybe_vip = g.vips.get(&VipKey {
                vni,
                ipv4: rec.ipv4,
            });
            if let Some(vip) = maybe_vip {
                let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
            }
            let _ = g.vips.remove(&VipKey {
                vni,
                ipv4: rec.ipv4,
            });
            // Purge NAT config for the removed interface's guest IP.
            let _ = g.nat.remove(&NatKey {
                vni,
                ipv4: rec.ipv4,
            });
            // Purge routes for this VNI (same as reset_vni).
            let routes_to_del: Vec<([u8; 4], u32)> = g
                .routes_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes_to_del {
                let _ = g.routes.remove(vni, *p, *l);
            }
            g.routes_shadow.retain(|&(v, p, l, _, _)| {
                !routes_to_del
                    .iter()
                    .any(|&(rp, rl)| v == vni && rp == p && rl == l)
            });
            let routes6_to_del: Vec<([u8; 16], u32)> = g
                .routes6_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes6_to_del {
                let _ = g.routes6.remove(vni, *p, *l);
            }
            g.routes6_shadow.retain(|&(v, p, l, _, _)| {
                !routes6_to_del
                    .iter()
                    .any(|&(rp, rl)| v == vni && rp == p && rl == l)
            });
        }
        Ok(true)
    }

    /// Interface detail for get/list. Returns (vni, ipv4, ipv6, underlay, device).
    pub fn get_interface(&self, interface_id: &[u8]) -> Option<InterfaceDetail> {
        let g = self.inner.lock();
        g.by_id
            .get(interface_id)
            .map(|r| (r.vni, r.ipv4, r.ipv6, r.underlay, r.device.clone()))
    }

    /// Read the `INTERFACES` map entry for `(vni, ipv4)` straight back out of the live eBPF map.
    /// Used by the DataplaneNode AttachInterface path to confirm the endpoint is resident in the
    /// kernel map (a read-back that proves the program actually landed). Returns the tap ifindex.
    pub fn interface_readback(&self, vni: u32, ipv4: [u8; 4]) -> Option<u32> {
        let g = self.inner.lock();
        g.ifaces
            .get(&IfaceKey::new(vni, ipv4))
            .map(|v| v.tap_ifindex)
    }

    /// All interface ids with their (vni, ipv4, ipv6, underlay, device).
    pub fn list_interfaces(&self) -> Vec<InterfaceRow> {
        let g = self.inner.lock();
        g.by_id
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.vni,
                    r.ipv4,
                    r.ipv6,
                    r.underlay,
                    r.device.clone(),
                )
            })
            .collect()
    }

    pub fn create_route(
        &self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        // Check for duplicate — routes_shadow is the source of truth.
        if g.routes_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv4 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes.upsert(
            vni,
            ipv4,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes_shadow
            .push((vni, ipv4, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete a route. Returns true if found and deleted, false if not found.
    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.routes_shadow.len();
        g.routes_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv4 && l == prefix_len));
        if g.routes_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes.remove(vni, ipv4, prefix_len);
        Ok(true)
    }

    pub fn create_route6(
        &self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        // Check for duplicate.
        if g.routes6_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv6 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes6.upsert(
            vni,
            ipv6,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes6_shadow
            .push((vni, ipv6, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete an IPv6 route. Returns true if found, false if not found.
    pub fn delete_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.routes6_shadow.len();
        g.routes6_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv6 && l == prefix_len));
        if g.routes6_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes6.remove(vni, ipv6, prefix_len);
        Ok(true)
    }

    /// List routes for a VNI (or all if vni=0).
    /// Returns (route_vni, ip_bytes_16, prefix_len, nexthop_vni, nexthop_ipv6, is_ipv6).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_routes_all(&self, vni: u32) -> Vec<RouteRow> {
        let g = self.inner.lock();
        let mut result = Vec::new();
        // IPv4 routes.
        for &(rv, p, l, nhvni, n) in &g.routes_shadow {
            if vni == 0 || rv == vni {
                let mut ip = [0u8; 16];
                ip[..4].copy_from_slice(&p);
                result.push((rv, ip, l, nhvni, n, false));
            }
        }
        // IPv6 routes.
        for &(rv, p, l, nhvni, n) in &g.routes6_shadow {
            if vni == 0 || rv == vni {
                result.push((rv, p, l, nhvni, n, true));
            }
        }
        result
    }

    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn vni_in_use(&self, vni: u32) -> bool {
        let g = self.inner.lock();
        g.by_id.values().any(|r| r.vni == vni)
            || g.routes_shadow.iter().any(|&(v, _, _, _, _)| v == vni)
            || g.routes6_shadow.iter().any(|&(v, _, _, _, _)| v == vni)
            || g.lbs.values().any(|lb| lb.vni == vni)
            || g.neigh_nats.iter().any(|n| n.vni == vni)
    }

    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn reset_vni(&self, vni: u32) -> anyhow::Result<()> {
        // Remove all routes for the vni (interfaces are torn down via DeleteInterface).
        let ipv4_to_del: Vec<_> = {
            let g = self.inner.lock();
            g.routes_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect()
        };
        for (p, l) in ipv4_to_del {
            self.delete_route(vni, p, l)?;
        }
        let ipv6_to_del: Vec<_> = {
            let g = self.inner.lock();
            g.routes6_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect()
        };
        for (p, l) in ipv6_to_del {
            self.delete_route6(vni, p, l)?;
        }
        Ok(())
    }

    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: LbIpBytes,
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.lbs.contains_key(id) {
            anyhow::bail!("load balancer already exists");
        }
        let table_id = g.next_table_id;

        let lb_ip = match &ip {
            LbIpBytes::Ipv4(a) => LbIp::Ipv4(*a),
            LbIpBytes::Ipv6(a) => LbIp::Ipv6(*a),
        };
        let lb_ip_bytes4 = lb_ip.last4();

        // Write the per-port LB rows, tracking each so a partial failure can be unwound. Otherwise an
        // upsert error part-way left orphaned LB map rows (and a burned table_id) with NO `lbs`
        // bookkeeping — DelLbVip iterates entry.ports, so it could never reach or remove them.
        let mut written: Vec<LbKey> = Vec::with_capacity(ports.len());
        let mut result: anyhow::Result<()> = Ok(());
        for &(port, proto) in &ports {
            let key = LbKey {
                vni,
                ipv4: lb_ip_bytes4,
                port,
                proto,
                _pad: 0,
            };
            if let Err(e) = g.lb.upsert(
                key,
                LbValue {
                    table_id,
                    size: crate::maglev::TABLE_SIZE,
                },
            ) {
                result = Err(e);
                break;
            }
            written.push(key);
        }
        // Program the LB's own underlay /128 into UNDERLAY so ingress can identify it — but ONLY for
        // overlay (relay) LBs. The WAN edge (vni==0) reaches the LB via wan_rx on a raw WAN frame and
        // never resolves UNDERLAY[lb_underlay]; writing it there would clobber the edge's
        // LOCAL_DELIVER egress entry (attach_edge). So skip the write for vni==0.
        // tap_ifindex=0 and guest_mac=[0;6] because the LB VIP is anycast (no local tap).
        if result.is_ok() && vni != 0 {
            result = g
                .underlay
                .upsert(
                    lb_underlay,
                    flowplane_common::UnderlayValue {
                        vni,
                        tap_ifindex: 0,
                        guest_mac: [0; 6],
                        _pad: [0; 2],
                    },
                )
                .map_err(anyhow::Error::from);
        }
        if let Err(e) = result {
            for key in &written {
                let _ = g.lb.remove(key); // unwind the partial LB rows
            }
            return Err(e);
        }
        // All datapath writes succeeded — commit table_id + bookkeeping.
        g.next_table_id += 1;
        g.lbs.insert(
            id.to_vec(),
            LbEntry {
                vni,
                ip: lb_ip,
                lb_underlay,
                ports,
                table_id,
                backends: Vec::new(),
            },
        );
        Ok(())
    }

    /// Append a backend underlay /128 to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        // Reject duplicates.
        if entry.backends.contains(&backend) {
            anyhow::bail!("load balancer target already exists");
        }
        entry.backends.push(backend);
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        let table = crate::maglev::build(&backends);
        for (slot, &bi) in table.iter().enumerate() {
            g.maglev.upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Remove a backend from an LB. Returns true if found, false if not.
    pub fn del_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        let before = entry.backends.len();
        entry.backends.retain(|b| b != &backend);
        if entry.backends.len() == before {
            return Ok(false);
        }
        // Rebuild Maglev table.
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        if backends.is_empty() {
            // Clear all Maglev slots.
            for slot in 0..crate::maglev::TABLE_SIZE {
                let _ = g.maglev.remove(&MaglevKey { table_id, slot });
            }
        } else {
            let table = crate::maglev::build(&backends);
            for (slot, &bi) in table.iter().enumerate() {
                g.maglev.upsert(
                    MaglevKey {
                        table_id,
                        slot: slot as u32,
                    },
                    backends[bi as usize],
                )?;
            }
        }
        Ok(true)
    }

    /// Return detail for a single LB: (vni, ip_bytes, lb_underlay, ports).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn get_lb(&self, id: &[u8]) -> Option<LbDetail> {
        let g = self.inner.lock();
        g.lbs
            .get(id)
            .map(|e| (e.vni, e.ip.as_lb_ip_bytes(), e.lb_underlay, e.ports.clone()))
    }

    /// List all LBs: (id, vni, ip_bytes, lb_underlay, ports).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_lbs(&self) -> Vec<LbRow> {
        let g = self.inner.lock();
        g.lbs
            .iter()
            .map(|(id, e)| {
                (
                    id.clone(),
                    e.vni,
                    e.ip.as_lb_ip_bytes(),
                    e.lb_underlay,
                    e.ports.clone(),
                )
            })
            .collect()
    }

    /// List the backend underlay addresses for a given LB.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_lb_targets(&self, id: &[u8]) -> Vec<[u8; 16]> {
        let g = self.inner.lock();
        g.lbs
            .get(id)
            .map(|e| e.backends.clone())
            .unwrap_or_default()
    }

    /// List all backends across all LBs (global).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_lb_targets_all(&self) -> Vec<[u8; 16]> {
        let g = self.inner.lock();
        g.lbs
            .values()
            .flat_map(|e| e.backends.iter().copied())
            .collect()
    }

    /// Remove a load balancer: clear its `LB` service entries and `MAGLEV` slots.
    /// Returns true if found and deleted, false if not found.
    pub fn delete_lb(&self, id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let entry = match g.lbs.remove(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        let ip4 = entry.ip.last4();
        for &(port, proto) in &entry.ports {
            let _ = g.lb.remove(&LbKey {
                vni: entry.vni,
                ipv4: ip4,
                port,
                proto,
                _pad: 0,
            });
        }
        for slot in 0..crate::maglev::TABLE_SIZE {
            let _ = g.maglev.remove(&MaglevKey {
                table_id: entry.table_id,
                slot,
            });
        }
        Ok(true)
    }

    /// Program the VIPS map for SNAT (G->V) and DNAT (V->G).
    /// Returns the underlay route for this interface on success.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn create_vip(
        &self,
        interface_id: &[u8],
        vip: [u8; 4],
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        // Check for existing VIP.
        if g.vips.get(&VipKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: VIP already set for this interface");
        }
        // Check preferred underlay collision.
        let effective_underlay = if let Some(pul) = preferred_ul {
            if g.by_id.values().any(|r| r.underlay == pul)
                || g.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
            pul
        } else {
            underlay
        };
        // egress SNAT: (vni, guest_ip) -> vip
        g.vips.upsert(VipKey { vni, ipv4: gip }, vip)?;
        // ingress DNAT: (vni, vip) -> guest_ip
        g.vips.upsert(VipKey { vni, ipv4: vip }, gip)?;
        Ok(effective_underlay)
    }

    /// Remove both VIPS map entries for this interface.
    /// Returns true if a VIP existed and was removed, false if none existed.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn delete_vip(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        if g.vips.get(&VipKey { vni, ipv4: gip }).is_none() {
            return Ok(false);
        }
        if let Some(vip) = g.vips.get(&VipKey { vni, ipv4: gip }) {
            let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
        }
        let _ = g.vips.remove(&VipKey { vni, ipv4: gip });
        Ok(true)
    }

    /// Return the VIP and underlay for this interface, if one has been set.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn get_vip(&self, interface_id: &[u8]) -> Option<([u8; 4], [u8; 16])> {
        let g = self.inner.lock();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        g.vips
            .get(&VipKey { vni, ipv4: gip })
            .map(|vip| (vip, underlay))
    }

    /// Program a guest's NAT config: (vni, guest_ip) -> (nat_ip, port_min, port_max).
    /// Returns the underlay route on success.
    pub fn create_nat(
        &self,
        interface_id: &[u8],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;

        // Check for existing NAT on this interface (any NAT IP).
        if g.nat.get(&NatKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: NAT already configured for this interface");
        }

        // Check for overlapping port range across all interfaces in this VNI with the same nat_ip.
        for r in g.by_id.values() {
            if r.vni == vni {
                if let Some(v) = g.nat.get(&NatKey { vni, ipv4: r.ipv4 }) {
                    if v.nat_ipv4 == nat_ip {
                        // Overlapping port range?
                        if port_min < v.port_max && port_max > v.port_min {
                            anyhow::bail!("SNAT_EXISTS: overlapping NAT port range");
                        }
                    }
                }
            }
        }

        // Check preferred underlay collision.
        if let Some(pul) = preferred_ul {
            if g.by_id.values().any(|r| r.underlay == pul)
                || g.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
        }

        g.nat.upsert(
            NatKey { vni, ipv4: gip },
            NatValue {
                nat_ipv4: nat_ip,
                port_min,
                port_max,
            },
        )?;
        // Mark this nat_ip in NAT_IPS so the ingress can generate ICMP echo replies for it.
        let _ = g.nat_ips.set(vni, nat_ip);
        Ok(preferred_ul.unwrap_or(underlay))
    }

    /// Return a guest's NAT config (nat_ip, port_min, port_max, underlay, vni), if set.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn get_nat(&self, interface_id: &[u8]) -> Option<NatDetail> {
        let g = self.inner.lock();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        g.nat
            .get(&NatKey { vni, ipv4: gip })
            .map(|v| (v.nat_ipv4, v.port_min, v.port_max, underlay, vni))
    }

    /// List all local NAT entries: (interface_id, guest_ipv4, nat_ip, port_min, port_max, vni, underlay).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_local_nats(&self) -> Vec<LocalNatRow> {
        let g = self.inner.lock();
        let mut result: Vec<LocalNatRow> = g
            .by_id
            .iter()
            .filter_map(|(id, rec)| {
                g.nat
                    .get(&NatKey {
                        vni: rec.vni,
                        ipv4: rec.ipv4,
                    })
                    .map(|v| {
                        (
                            id.clone(),
                            rec.ipv4,
                            v.nat_ipv4,
                            v.port_min,
                            v.port_max,
                            rec.vni,
                            rec.underlay,
                        )
                    })
            })
            .collect();
        // Sort by guest IP in descending order to match expected list ordering.
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    /// Flush CONNTRACK entries whose egress 5-tuple originated from `(vni, src_ip)`.
    /// For NAT flows this removes both the forward entry (CT_REWRITE_SRC, key.src_ip == gip)
    /// and the reverse entry (CT_REWRITE_DST, key.dst_ip == nat_ip with xlate_port in range).
    fn ct_flush_for_guest(
        ct: &mut Conntrack,
        vni: u32,
        gip: [u8; 4],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) {
        // Collect all keys to remove first to avoid borrow issues during iteration.
        let to_remove: Vec<CtKey> = ct
            .entries()
            .into_iter()
            .filter_map(|(k, e)| {
                if k.vni != vni {
                    return None;
                }
                // Forward NAT entry: src_ip == guest IP, CT_REWRITE_SRC set.
                let is_fwd = k.src_ip == gip
                    && (e.flags & flowplane_common::CT_REWRITE_SRC != 0
                        || e.flags & flowplane_common::CT_F_SRC_NAT != 0);
                // Reverse NAT entry: dst_ip == nat_ip, dst_port in the NAT port range.
                let is_rev = k.dst_ip == nat_ip
                    && k.dst_port >= port_min
                    && k.dst_port < port_max
                    && e.flags & flowplane_common::CT_REWRITE_DST != 0;
                if is_fwd || is_rev {
                    Some(k)
                } else {
                    None
                }
            })
            .collect();
        for k in to_remove {
            let _ = ct.remove(&k);
        }
    }

    /// Remove a guest's NAT config. Returns true if found and deleted, false if no NAT was set.
    pub fn delete_nat(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let (vni, gip, nat_ip, port_min, port_max) = {
            let mut g = self.inner.lock();
            let rec = g
                .by_id
                .get(interface_id)
                .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
            let (vni, gip) = (rec.vni, rec.ipv4);
            let nat_val = match g.nat.get(&NatKey { vni, ipv4: gip }) {
                Some(v) => v,
                None => return Ok(false),
            };
            let nat_ip = nat_val.nat_ipv4;
            let port_min = nat_val.port_min;
            let port_max = nat_val.port_max;
            let _ = g.nat.remove(&NatKey { vni, ipv4: gip });
            // Remove the NAT_IPS marker if no other interface in this VNI uses the same nat_ip.
            let still_used = g.by_id.iter().any(|(other_id, r)| {
                other_id.as_slice() != interface_id
                    && r.vni == vni
                    && g.nat
                        .get(&NatKey {
                            vni: r.vni,
                            ipv4: r.ipv4,
                        })
                        .map(|v| v.nat_ipv4 == nat_ip)
                        .unwrap_or(false)
            });
            if !still_used {
                let _ = g.nat_ips.remove(vni, nat_ip);
            }
            (vni, gip, nat_ip, port_min, port_max)
        };
        // Flush CT entries for this guest outside the inner lock (conntrack lock is separate).
        let mut ct = self.conntrack.lock();
        Self::ct_flush_for_guest(&mut ct, vni, gip, nat_ip, port_min, port_max);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Firewall rule management
    // -----------------------------------------------------------------------

    /// Reprogram all firewall slots for one interface from the in-memory `fw` vec.
    fn fw_reprogram(g: &mut Inner, ifindex: u32) -> anyhow::Result<()> {
        let rules = g.fw.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = g.fw_rules.remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            g.fw_rules.upsert(
                FwRuleKey {
                    ifindex,
                    idx: i as u32,
                },
                *r,
            )?;
            if r.direction == FW_DIR_EGRESS {
                egress += 1;
            } else {
                ingress += 1;
            }
        }
        g.fw_meta.upsert(
            ifindex,
            FwMeta {
                ingress_count: ingress,
                egress_count: egress,
            },
        )?;
        Ok(())
    }

    /// Add or replace a firewall rule on an interface.
    /// Returns an error with "already exists" if a rule with that ID already exists.
    pub fn add_fw_rule(
        &self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        if entry.len() >= FW_MAX_RULES as usize {
            anyhow::bail!(
                "too many firewall rules for interface (max {})",
                FW_MAX_RULES
            );
        }
        // Reject duplicate rule IDs.
        if entry.iter().any(|(id, _)| id == &rule_id) {
            anyhow::bail!("ALREADY_EXISTS: firewall rule already exists");
        }
        entry.push((rule_id, rule));
        Self::fw_reprogram(&mut g, ifindex)
    }

    /// Remove a firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        Self::fw_reprogram(&mut g, ifindex)?;
        Ok(true)
    }

    /// Get a single firewall rule by id.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn get_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> Option<FwRule> {
        let g = self.inner.lock();
        let ifindex = *g.by_ifindex.get(interface_id)?;
        g.fw.get(&ifindex)?
            .iter()
            .find(|(id, _)| id.as_slice() == rule_id)
            .map(|(_, r)| *r)
    }

    /// List all firewall rules for an interface as (rule_id, rule) pairs.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_fw_rules(&self, interface_id: &[u8]) -> Vec<(Vec<u8>, FwRule)> {
        let g = self.inner.lock();
        match g.by_ifindex.get(interface_id) {
            Some(ifindex) => g.fw.get(ifindex).cloned().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn set_qos(
        &self,
        interface_id: &[u8],
        egress_mbps: u64,
        public_mbps: u64,
        ingress_mbps: u64,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let tap = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        if egress_mbps == 0 && public_mbps == 0 && ingress_mbps == 0 {
            let _ = g.meter.remove(&tap);
            Ok(())
        } else {
            let state = Self::meter_state(egress_mbps, public_mbps, ingress_mbps);
            g.meter.upsert(tap, state)
        }
    }

    // -----------------------------------------------------------------------
    // Alias prefix management
    // -----------------------------------------------------------------------

    /// Announce an alias prefix routed to an interface: program a route (vni, prefix/len) -> the
    /// interface's underlay /128. Returns the underlay route.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn add_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let underlay = *g
            .iface_underlay
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("interface has no underlay"))?;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ROUTE_EXISTS: prefix already exists");
            }
        }
        // Also check other interfaces in the same VNI.
        for (oid, pv) in &g.prefixes {
            if oid != interface_id {
                if let Some(orec) = g.by_id.get(oid) {
                    if orec.vni == vni
                        && pv
                            .iter()
                            .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
                    {
                        anyhow::bail!("ROUTE_EXISTS: prefix already in use in this VNI");
                    }
                }
            }
        }

        g.routes.upsert(
            vni,
            prefix,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: effective_ul,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&prefix);
        g.prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: ip16,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: false,
            });
        Ok(effective_ul)
    }

    /// Add an IPv6 alias prefix. Returns the underlay route.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn add_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let vni = rec.vni;
        let underlay = *g
            .iface_underlay
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("interface has no underlay"))?;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ROUTE_EXISTS: IPv6 prefix already exists");
            }
        }

        g.routes6.upsert(
            vni,
            prefix,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: effective_ul,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        g.prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: prefix,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: true,
            });
        Ok(effective_ul)
    }

    /// Remove an alias prefix. Returns true if removed, false if not found.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn del_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let pv = g.prefixes.get_mut(interface_id);
        if let Some(v) = pv {
            let before = v.len();
            v.retain(|pr| !((!pr.is_ipv6) && pr.ip[..4] == prefix && pr.len == prefix_len));
            if v.len() < before {
                let _ = g.routes.remove(vni, prefix, prefix_len);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove an IPv6 alias prefix. Returns true if removed, false if not found.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn del_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let vni = rec.vni;
        let pv = g.prefixes.get_mut(interface_id);
        if let Some(v) = pv {
            let before = v.len();
            v.retain(|pr| !(pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len));
            if v.len() < before {
                let _ = g.routes6.remove(vni, prefix, prefix_len);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return all alias prefixes for an interface as (ip_bytes_16, len, underlay, is_ipv6).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_prefixes_with_underlay(
        &self,
        interface_id: &[u8],
    ) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock();
        g.prefixes
            .get(interface_id)
            .map(|v| {
                v.iter()
                    .map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return all prefix records across all interfaces (global list).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_prefixes_all(&self) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock();
        g.prefixes
            .values()
            .flat_map(|v| v.iter().map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // LB prefix management
    // -----------------------------------------------------------------------

    /// Add an LB-prefix shadow entry (announce-only; no datapath route needed).
    /// Returns the underlay route.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn add_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let underlay = rec.underlay;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.lb_prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ALREADY_EXISTS: LB prefix already exists");
            }
        }

        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&prefix);
        g.lb_prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: ip16,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: false,
            });
        Ok(effective_ul)
    }

    /// Add an IPv6 LB-prefix shadow entry. Returns the underlay route.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn add_lb_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let underlay = rec.underlay;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.lb_prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ALREADY_EXISTS: IPv6 LB prefix already exists");
            }
        }

        g.lb_prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: prefix,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: true,
            });
        Ok(effective_ul)
    }

    /// Remove an LB-prefix shadow entry. Returns true if removed, false if not found.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn del_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        // Check interface exists.
        if !g.by_id.contains_key(interface_id) {
            anyhow::bail!("NO_VM: unknown interface");
        }
        if let Some(v) = g.lb_prefixes.get_mut(interface_id) {
            let before = v.len();
            v.retain(|pr| !((!pr.is_ipv6) && pr.ip[..4] == prefix && pr.len == prefix_len));
            if v.len() < before {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove an IPv6 LB-prefix shadow entry. Returns true if removed, false if not found.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode RPCs
    pub fn del_lb_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        if !g.by_id.contains_key(interface_id) {
            anyhow::bail!("NO_VM: unknown interface");
        }
        if let Some(v) = g.lb_prefixes.get_mut(interface_id) {
            let before = v.len();
            v.retain(|pr| !(pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len));
            if v.len() < before {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return LB-prefix entries for an interface as (ip_bytes_16, len, underlay, is_ipv6).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_lb_prefixes_with_underlay(
        &self,
        interface_id: &[u8],
    ) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock();
        g.lb_prefixes
            .get(interface_id)
            .map(|v| {
                v.iter()
                    .map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return all LB-prefix records across all interfaces (global).
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_lb_prefixes_all(&self) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock();
        g.lb_prefixes
            .values()
            .flat_map(|v| v.iter().map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Neighbor NAT management (distributed NAT return)
    // -----------------------------------------------------------------------

    /// Reprogram NEIGHBOR_NAT and NEIGHBOR_NAT_COUNT from the in-memory vec.
    fn neigh_nat_reprogram(g: &mut Inner) -> anyhow::Result<()> {
        let n = g.neigh_nats.len() as u32;
        for (i, e) in g.neigh_nats.iter().enumerate() {
            g.neigh_nat.upsert(i as u32, *e)?;
        }
        g.neigh_nat_count.set(n)?;
        Ok(())
    }

    /// Add a neighbor-NAT entry (capped at NB_MAX_ENTRIES).
    pub fn add_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.neigh_nats.len() >= NB_MAX_ENTRIES as usize {
            anyhow::bail!("neighbor NAT table full (max {})", NB_MAX_ENTRIES);
        }
        // Check for duplicate or overlapping port range.
        if g.neigh_nats.iter().any(|e| {
            e.nat_ip == nat_ip
                && (
                    // Exact match (same vni and ports) → always duplicate.
                    (e.vni == vni && e.port_min == port_min && e.port_max == port_max)
                // Overlapping port range for the same nat_ip (any vni) → also duplicate.
                || (e.port_min < port_max && e.port_max > port_min)
                )
        }) {
            anyhow::bail!(
                "ALREADY_EXISTS: neighbor NAT entry already exists or port range overlaps"
            );
        }
        g.neigh_nats.push(NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        });
        Self::neigh_nat_reprogram(&mut g)
    }

    /// Remove a neighbor-NAT entry matching (vni, nat_ip, port_min, port_max).
    /// Returns true if removed, false if not found.
    pub fn del_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.neigh_nats.len();
        g.neigh_nats.retain(|e| {
            !(e.vni == vni
                && e.nat_ip == nat_ip
                && e.port_min == port_min
                && e.port_max == port_max)
        });
        if g.neigh_nats.len() == before {
            return Ok(false);
        }
        Self::neigh_nat_reprogram(&mut g)?;
        Ok(true)
    }

    /// List all neighbor-NAT entries.
    #[allow(dead_code)] // was DPDKironcore-only; retained for future DataplaneNode read RPCs
    pub fn list_neighbor_nats(&self) -> Vec<NeighborNatEntry> {
        let g = self.inner.lock();
        g.neigh_nats.clone()
    }
}

#[cfg(test)]
impl Control {
    /// Build a `Control` from a freshly loaded eBPF object WITHOUT attaching any program to an
    /// interface. Opens every map handle exactly like `bring_up` does, but skips the XDP/tc attach
    /// so the test needs only CAP_BPF (a real kernel), not a live uplink. Used to exercise the
    /// userspace control plane's map programming (e.g. `create_lb`'s UNDERLAY writes) in isolation.
    fn from_ebpf_for_test() -> anyhow::Result<Self> {
        // Unique per-run bpffs dir: the `pinned` state maps need a `map_pin_path`, and a private
        // dir keeps this test's maps isolated from any other test in the same process. The maps
        // outlive the tempdir via the `ebpf` handle, so cleanup on drop is fine.
        let pin = tempfile::Builder::new()
            .prefix("flowplane-ctrl-test-")
            .tempdir_in("/sys/fs/bpf")
            .context("bpffs tempdir")?;
        let mut ebpf = loader::load_ebpf(pin.path())?;
        let guest_progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex: 0,
            uplink_mac: [0; 6],
            gateway_mac: [0; 6],
            underlay_ipv6: [0; 16],
        })?;
        let mut uplink_dev = UplinkDevMap::open(&mut ebpf)?;
        uplink_dev.set(0)?;
        let guest_dev = GuestDevMap::open(&mut ebpf)?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let iface_meta = IfaceMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _guest_progs: guest_progs,
                _locals: locals,
                _uplink_dev: uplink_dev,
                guest_dev,
                ports,
                ifaces,
                routes,
                routes6,
                vips,
                lb,
                maglev,
                nat,
                fw_rules,
                fw_meta,
                underlay,
                meter,
                neigh_nat,
                neigh_nat_count,
                nat_ips,
                dhcp_config,
                dhcp_meta,
                iface_meta,
                recovered: Vec::new(),
                recovered_underlays: Vec::new(),
                pin_links: false,
                pin_dir: std::path::PathBuf::from("/tmp"),
                neigh_nats: Vec::new(),
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
                by_ifindex: HashMap::new(),
                iface_underlay: HashMap::new(),
                prefixes: HashMap::new(),
                fw: HashMap::new(),
                lb_prefixes: HashMap::new(),
                links: HashMap::new(),
                routes_shadow: Vec::new(),
                routes6_shadow: Vec::new(),
                learned_macs: HashMap::new(),
            }),
            conntrack,
        })
    }

    /// Test-only: read the UNDERLAY map entry for `key` (the LB/interface /128).
    fn underlay_get(&self, key: &[u8; 16]) -> Option<flowplane_common::UnderlayValue> {
        self.inner.lock().underlay.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_pin_name_is_stable_and_hex() {
        assert_eq!(hex_encode(b"natpod"), "6e6174706f64");
        assert_eq!(hex_encode(b"rpod"), hex_encode(b"rpod"));
    }

    /// Three-lane mbps->MeterState conversion: egress=EDT (no token bucket, burst=0),
    /// public/ingress=token-bucket policers (burst = bps/8, min 2000B). 0 mbps = pass sentinel.
    #[test]
    fn meter_state_conversion() {
        let m = Control::meter_state(100, 40, 50);
        assert_eq!(m.total_bps, 100 * 1_000_000 / 8); // 12_500_000 B/s
        assert_eq!(m.public_bps, 40 * 1_000_000 / 8); // 5_000_000 B/s
        assert_eq!(m.ingress_bps, 50 * 1_000_000 / 8); // 6_250_000 B/s
                                                       // EDT total: no token bucket
        assert_eq!(m.total_burst, 0);
        assert_eq!(m.total_tokens, 0);
        // Public policer
        assert_eq!(m.public_burst, (m.public_bps / 8).max(2000));
        assert_eq!(m.public_tokens, m.public_bps / 8);
        // Ingress policer
        assert_eq!(m.ingress_burst, (m.ingress_bps / 8).max(2000));
        assert_eq!(m.ingress_tokens, m.ingress_bps / 8);
        assert_eq!(m.total_last_ns, 0);
        assert_eq!(m.public_last_ns, 0);
        assert_eq!(m.ingress_last_ns, 0);

        // 0 mbps = unlimited sentinel (bps==0).
        let z = Control::meter_state(0, 0, 0);
        assert_eq!(z.total_bps, 0);
        assert_eq!(z.public_bps, 0);
        assert_eq!(z.ingress_bps, 0);
        assert_eq!(z.total_burst, 0);
        assert_eq!(z.public_burst, 2000);
        assert_eq!(z.ingress_burst, 2000);
    }

    /// Pure (no-BPF) check that an IFACE_META journal entry round-trips back to the interface_id,
    /// device, and IfaceRecord the restart rebuild needs — the crux of the adopt path.
    #[test]
    fn rebuild_decode_roundtrip() {
        let id: &[u8] = b"550e8400-e29b-41d4-a716-446655440000/eth0";
        let key = IfaceMetaKey::from_id(id).expect("id fits IFACE_ID_MAX");
        let mut dev = [0u8; IFACE_DEV_MAX];
        dev[..8].copy_from_slice(b"dtapvf_3");
        let val = IfaceMetaVal {
            vni: 100,
            tap_ifindex: 42,
            ipv4: [10, 0, 0, 5],
            id_len: id.len() as u16,
            device_len: 8,
            ipv6: [0x20; 16],
            underlay: [0xfd; 16],
            device: dev,
        };
        let (got_id, got_dev, rec) = Control::decode_iface_meta(&key, &val);
        assert_eq!(
            got_id, id,
            "interface_id restored verbatim (not hashed/truncated)"
        );
        assert_eq!(got_dev, "dtapvf_3");
        assert_eq!(rec.vni, 100);
        assert_eq!(rec.ipv4, [10, 0, 0, 5]);
        assert_eq!(rec.ipv6, [0x20; 16]);
        assert_eq!(rec.underlay, [0xfd; 16]);
        assert_eq!(rec.device, "dtapvf_3");
    }

    /// An interface_id at the exact cap round-trips; one byte over is rejected (would alias on adopt).
    #[test]
    fn iface_meta_key_length_bounds() {
        let max = vec![b'x'; flowplane_common::IFACE_ID_MAX];
        let key = IfaceMetaKey::from_id(&max).expect("exactly IFACE_ID_MAX fits");
        assert_eq!(&key.id[..], &max[..]);
        let over = vec![b'x'; flowplane_common::IFACE_ID_MAX + 1];
        assert!(
            IfaceMetaKey::from_id(&over).is_none(),
            "over-cap id rejected"
        );
    }

    #[test]
    #[ignore = "requires root/CAP_BPF; run via: sudo -E <test-bin> --include-ignored"]
    fn create_lb_skips_underlay_write_for_wan_edge() {
        let ctrl = Control::from_ebpf_for_test().expect("build test control");
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];

        // WAN edge (vni==0): create_lb must NOT program UNDERLAY[lb_underlay] — wan_rx never resolves
        // it and a write would clobber attach_edge's LOCAL_DELIVER egress entry.
        ctrl.create_lb(
            b"vip-a",
            0,
            LbIpBytes::Ipv4([203, 0, 113, 50]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=0");
        assert!(
            ctrl.underlay_get(&lb_ul).is_none(),
            "vni=0 must NOT write UNDERLAY[lb_underlay]"
        );

        // Overlay relay LB (vni!=0): create_lb MUST program UNDERLAY[lb_underlay] as before.
        ctrl.create_lb(
            b"vip-b",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 1]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=100");
        assert!(
            ctrl.underlay_get(&lb_ul).is_some(),
            "vni!=0 must write UNDERLAY[lb_underlay]"
        );
    }
}
