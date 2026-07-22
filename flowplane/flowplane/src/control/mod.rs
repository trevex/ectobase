use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use aya::Ebpf;
use flowplane_common::{
    FwRule, IfaceKey, IfaceMetaKey, IfaceMetaVal, IfaceValue, Local, NatKey, NeighborNatEntry,
    PortMeta, RouteValue, VipKey, IFACE_DEV_MAX,
};

use crate::loader;
use crate::maps::{
    Conntrack, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwRules, GuestDevMap, IfaceMetaMap,
    Interfaces, Lb, LocalMap, Maglev, Meter, Nat, NatIps, NeighborNat, NeighborNatCount,
    PortMetaMap, Routes, Routes6, UplinkDevMap, Vips,
};
// `Nat`, `NatIps`, `NeighborNat`, `NeighborNatCount` are still opened in `bring_up`/the test ctor,
// then moved into `AyaWriter` (they no longer live in `Inner`).

// The `impl Control` blocks are split by domain into these child modules. Each is pure code
// movement out of this file; they reach `Inner`'s private state via `super`.
mod aya_writer;
mod firewall;
mod lb;
mod nat;
mod routes;

use aya_writer::AyaWriter;
use flowplane_control::{ControlCore, MapWriter};

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
// Shadow now lives in ControlCore; these aliases remain for call-site compatibility (Tasks 4-7).
#[allow(dead_code)]
pub(crate) type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// `(vni, prefix_ipv6, prefix_len, nexthop_vni, nexthop_underlay)` IPv6 routes shadow.
#[allow(dead_code)]
pub(crate) type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);
/// `(vni, ipv4, ipv6, underlay, device)` for a single interface.
pub(crate) type InterfaceDetail = (u32, [u8; 4], [u8; 16], [u8; 16], String);
/// `(interface_id, vni, ipv4, ipv6, underlay, device)` row.
pub(crate) type InterfaceRow = (Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16], String);

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
}

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `Inner.lbs` by the LB's id.
struct LbEntry {
    vni: u32,
    ip: LbIp,
    /// Task 4 moved the sole reader (NAT preferred-underlay collision check) into `ControlCore.lbs`;
    /// this field is now write-only in `Inner.lbs` (kept in sync via the create_lb mirror) until
    /// Task 5 deletes `Inner.lbs` and moves the full LB domain into the core.
    #[allow(dead_code)]
    lb_underlay: [u8; 16],
    ports: Vec<(u16, u8)>,
    table_id: u32,
    backends: Vec<[u8; 16]>,
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
    core: ControlCore<AyaWriter>,
    vips: Vips,
    lb: Lb,
    maglev: Maglev,
    fw_rules: FwRules,
    fw_meta: FwMetaMap,
    underlay: crate::maps::Underlay,
    meter: Meter,
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
    /// loadbalancer_id -> its LB state.
    lbs: HashMap<Vec<u8>, LbEntry>,
    next_table_id: u32,
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
    /// interface_id -> ifindex
    by_ifindex: HashMap<Vec<u8>, u32>,
    /// interface_id -> its underlay /128
    iface_underlay: HashMap<Vec<u8>, [u8; 16]>,
    /// ifindex -> ordered (rule_id, rule) pairs
    fw: HashMap<u32, Vec<(Vec<u8>, FwRule)>>,
    /// interface_id -> the owned guest datapath link (dropping it detaches the program).
    links: HashMap<Vec<u8>, GuestLink>,
    /// Shadow cache of learned guest MACs: interface_id -> guest_mac.
    /// Persists across delete+recreate of the SAME interface so the datapath keeps delivering to a
    /// datapath-learned MAC (e.g. a VM's self-set MAC) when it is reprogrammed. Keyed by
    /// interface_id so a different interface reusing a freed underlay /128 never inherits it.
    learned_macs: HashMap<Vec<u8>, [u8; 6]>,
}

/// `(interface_id, device)` pairs whose guest program must be re-attached after a graceful restart
/// (their bpf-links died with the old process; the pinned maps survived).
type ReattachList = Vec<(Vec<u8>, String)>;

impl Control {
    /// Load + attach uplink_rx, set LOCAL, take the map handles. The uplink identity + pinning policy
    /// are all distinct one-shot init inputs, so this constructor takes them positionally.
    #[allow(clippy::too_many_arguments)]
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
        let aya = AyaWriter {
            routes,
            routes6,
            nat,
            nat_ips,
            neigh_nat,
            neigh_nat_count,
            conntrack: Arc::clone(&conntrack),
        };
        let mut inner = Inner {
            ebpf,
            _guest_progs: guest_progs,
            _locals: locals,
            _uplink_dev: uplink_dev,
            guest_dev,
            ports,
            ifaces,
            core: ControlCore::new(aya),
            vips,
            lb,
            maglev,
            fw_rules,
            fw_meta,
            underlay,
            meter,
            dhcp_config,
            dhcp_meta,
            iface_meta,
            recovered: Vec::new(),
            recovered_underlays: Vec::new(),
            pin_links,
            pin_dir: pin_dir.to_path_buf(),
            lbs: HashMap::new(),
            next_table_id: 1,
            by_id: HashMap::new(),
            by_ifindex: HashMap::new(),
            iface_underlay: HashMap::new(),
            fw: HashMap::new(),
            links: HashMap::new(),
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
    fn rebuild_from_maps(g: &mut Inner) -> anyhow::Result<(ReattachList, Vec<[u8; 16]>)> {
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
            // Mirror the agnostic subset into the core so post-adopt NAT/LB conflict checks (moved
            // into ControlCore in Task 4) see the recovered interface, exactly as they saw `by_id`
            // before the refactor.
            g.core.register_iface_meta(
                id.clone(),
                flowplane_control::shadow::IfaceMeta {
                    vni: rec.vni,
                    ipv4: rec.ipv4,
                    ipv6: rec.ipv6,
                    underlay: rec.underlay,
                },
            );
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
            g.guest_dev.remove(tap); // unwind the GUEST_DEV write
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
        // Mirror the agnostic interface metadata into the core so the NAT/LB conflict checks (which
        // moved into ControlCore in Task 4) can read it. `by_id` stays authoritative on `Control`
        // until Task 7.
        g.core.register_iface_meta(
            interface_id.to_vec(),
            flowplane_control::shadow::IfaceMeta {
                vni,
                ipv4,
                ipv6,
                underlay: underlay_ipv6,
            },
        );
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
        g.core.writer_mut().route_upsert(
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
            g.core.writer_mut().route6_upsert(
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
        // Drop the core's agnostic mirror of this interface's metadata (registered in create_interface).
        g.core.forget_iface_meta(interface_id);
        let tap = g.by_ifindex.remove(interface_id).unwrap_or(0);
        g.guest_dev.remove(tap);
        g.iface_underlay.remove(interface_id);
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
        let _ = g.core.writer_mut().route_remove(rec.vni, rec.ipv4, 32);
        if rec.ipv6 != [0u8; 16] {
            let _ = g.core.writer_mut().route6_remove(rec.vni, rec.ipv6, 128);
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
            // Purge neighbor NATs for this VNI. The neigh-NAT vec + maps moved into ControlCore
            // (Task 4); this reset logic stays on `Control` until Task 7, so it reaches them via
            // `g.core.neigh_nats` and `g.core.writer_mut()`.
            let before = g.core.neigh_nats.len();
            g.core.neigh_nats.retain(|e| e.vni != vni);
            if g.core.neigh_nats.len() != before {
                let n = g.core.neigh_nats.len() as u32;
                let remaining: Vec<NeighborNatEntry> = g.core.neigh_nats.clone();
                for (i, e) in remaining.iter().enumerate() {
                    let _ = g.core.writer_mut().neigh_nat_upsert(i as u32, *e);
                }
                let _ = g.core.writer_mut().neigh_nat_count_set(n);
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
            let _ = g.core.writer_mut().nat_remove(&NatKey {
                vni,
                ipv4: rec.ipv4,
            });
            // Purge routes for this VNI (same as reset_vni).
            let routes_to_del: Vec<([u8; 4], u32)> = g
                .core
                .routes_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes_to_del {
                let _ = g.core.writer_mut().route_remove(vni, *p, *l);
            }
            g.core.routes_shadow.retain(|&(v, p, l, _, _)| {
                !routes_to_del
                    .iter()
                    .any(|&(rp, rl)| v == vni && rp == p && rl == l)
            });
            let routes6_to_del: Vec<([u8; 16], u32)> = g
                .core
                .routes6_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes6_to_del {
                let _ = g.core.writer_mut().route6_remove(vni, *p, *l);
            }
            g.core.routes6_shadow.retain(|&(v, p, l, _, _)| {
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
        let aya = AyaWriter {
            routes,
            routes6,
            nat,
            nat_ips,
            neigh_nat,
            neigh_nat_count,
            conntrack: Arc::clone(&conntrack),
        };
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _guest_progs: guest_progs,
                _locals: locals,
                _uplink_dev: uplink_dev,
                guest_dev,
                ports,
                ifaces,
                core: ControlCore::new(aya),
                vips,
                lb,
                maglev,
                fw_rules,
                fw_meta,
                underlay,
                meter,
                dhcp_config,
                dhcp_meta,
                iface_meta,
                recovered: Vec::new(),
                recovered_underlays: Vec::new(),
                pin_links: false,
                pin_dir: std::path::PathBuf::from("/tmp"),
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
                by_ifindex: HashMap::new(),
                iface_underlay: HashMap::new(),
                fw: HashMap::new(),
                links: HashMap::new(),
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
