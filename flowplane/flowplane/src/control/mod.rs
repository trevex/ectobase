use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use aya::Ebpf;
use flowplane_common::{IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, Local, IFACE_DEV_MAX};

use crate::loader;
use crate::maps::{
    Conntrack, Conntrack6, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwMetaMap6, FwRules, FwRules6,
    GeneveIfindexMap, IfaceMetaMap, Interfaces, Interfaces6, Lb, LocalMap, Maglev, Meter, Nat,
    NatIps, NeighborNat, NeighborNatCount, PortMetaMap, Routes, Routes6, Vips,
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
    /// L3 (netkit) edge: program `PORT_META.l3 = 1` and attach the guest program via `BPF_NETKIT`
    /// (Task B.4) rather than tcx/clsact. `false` for veth/tap/pod-tap (L2, unchanged tcx attach).
    pub l3: bool,
}

// Named shapes for the gRPC list/get return rows, so the signatures below read as
// `Vec<InterfaceRow>` rather than a bare six-tuple (keeps `clippy::type_complexity` quiet and
// documents each column). Fields are described where each is produced/consumed. The route shadow
// aliases moved into `flowplane-control` (`shadow::RouteShadowV4/V6`) with the orchestration.

/// `(interface_id, vni, ipv4, ipv6, underlay, device)` row.
pub(crate) type InterfaceRow = (Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16], String);

/// Full detail record for a registered local interface (shadow of eBPF map state).
#[derive(Clone)]
struct IfaceRecord {
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    device: String,
    underlay: [u8; 16],
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
    /// Owned `UPLINK_PROGS` program array handle. Holds the `xdp_uplink_v6` tail-call slot so
    /// `uplink_rx`'s inner-IPv6 tail call resolves (else it fails open to XDP_PASS and inner-v6
    /// overlay ingress is dropped). Kept alive here for the datapath's lifetime like `_guest_progs`.
    _uplink_progs: aya::maps::ProgramArray<aya::maps::MapData>,
    _locals: LocalMap,
    /// Owned `GENEVE_IFINDEX` map handle. `wan_rx` is loaded LATER (`attach_edge`), and its bytecode
    /// also reads `GENEVE_IFINDEX` (via `crate::tunnel::redirect`'s `geneve_ifindex()`), so this
    /// handle MUST stay alive here — dropping it after `set()` closes the map fd and `wan_rx` then
    /// fails to verify ("fd is not pointing to valid bpf_map"), exactly like `_locals`/`_guest_progs`.
    _geneve_ifindex: GeneveIfindexMap,
    /// ifindex of the node-wide `collect_md` Geneve device (`flowplane_device::GENEVE_DEV`),
    /// brought up in `bring_up` and programmed into `GENEVE_IFINDEX[0]` right after.
    #[allow(dead_code)]
    geneve_ifindex: u32,
    core: ControlCore<AyaWriter>,
    /// Interfaces recovered by `rebuild_from_maps` on adopt: (interface_id, device) whose guest
    /// program must be re-attached by the caller (`Serve`). Empty on a fresh (non-adopt) bring-up.
    recovered: Vec<(Vec<u8>, String)>,
    /// Link-pinning enabled: pin program links + adopt them atomically on restart.
    pin_links: bool,
    /// Persistent pin dir for link pins; mirrors the map pin dir passed to load_ebpf.
    pin_dir: std::path::PathBuf,
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
    /// interface_id -> its underlay /128
    iface_underlay: HashMap<Vec<u8>, [u8; 16]>,
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
        // Bring up the node-wide `collect_md` Geneve device (P2 overlay encap target). Idempotent
        // (delete-if-exists then add), so this is safe on both a fresh bring-up AND an adopt
        // restart — unlike the pinned BPF maps/links, this netdev is NOT torn down on graceful
        // shutdown (see the `Serve` shutdown handler in main.rs), so re-running `ensure_geneve_dev`
        // here just confirms/repairs it.
        let geneve_ifindex = flowplane_device::ensure_geneve_dev(flowplane_device::GENEVE_DEV)
            .context("bring up collect_md geneve device")?;
        let mut geneve_ifindex_map = GeneveIfindexMap::open(&mut ebpf)?;
        geneve_ifindex_map.set(geneve_ifindex)?;
        // uplink_rx is tcx on the geneve `collect_md` DEVICE's ingress — NOT the physical uplink
        // NIC. The kernel decaps on the geneve device's own RX path (that is what `collect_md`
        // means); only once that has happened does our tcx program see the (now-inner) frame, VNI
        // recovered via `get_tunnel_key`. Attaching to the raw uplink NIC instead would see the
        // still-encapsulated wire bytes (no tunnel-key metadata yet) and get_tunnel_key would just
        // fail every time.
        if pin_links {
            let uplink_pin = "uplink-geneve".to_string();
            // Adopt: atomically re-point the surviving pinned link at the fresh program (no gap). A
            // missing/broken pin falls through to a fresh attach+pin.
            let readopted = adopt
                && loader::readopt_tc_link(&mut ebpf, "uplink_rx", pin_dir, &uplink_pin)
                    .unwrap_or_else(|e| {
                        eprintln!("re-adopt uplink link failed ({e:#}); attaching fresh");
                        loader::unpin_link(pin_dir, &uplink_pin);
                        false
                    });
            if !readopted {
                loader::attach_tc_pinned_at(
                    &mut ebpf,
                    "uplink_rx",
                    flowplane_device::GENEVE_DEV,
                    pin_dir,
                    &uplink_pin,
                )?;
            }
        } else {
            // pin-links off: clear any stale pin from a previous pin-on run so the fresh (unpinned)
            // attach can't hit EBUSY against a link that survived the last process.
            loader::unpin_link(pin_dir, "uplink-geneve");
            loader::attach_tc_clsact_ingress(&mut ebpf, "uplink_rx", flowplane_device::GENEVE_DEV)?;
        }
        // The physical uplink NIC still needs the `fq` root qdisc for EDT egress shaping (unrelated
        // to the ingress attach above — this paces the departure time the guest-egress encap arm
        // stamps via `bpf_skb_set_tstamp`).
        loader::ensure_fq_qdisc(uplink);
        // Guest edge is tcx-only. Pre-load tc_guest_tx and register the tc DHCP/NAT64 tail-call
        // array (GUEST_PROGS_TC) once here; per-interface attach then only needs attach().
        let guest_progs = {
            let progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
            loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
            progs
        };
        // Register the inner-IPv6 uplink tail-call target (xdp_uplink_v6, now tc) so uplink_rx's v6
        // tail call resolves; without this the daemon fails open to TC_ACT_OK on inner-v6 ingress.
        let uplink_progs = loader::register_uplink_v6_tc(&mut ebpf)?;
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex,
            uplink_mac,
            gateway_mac,
            underlay_ipv6,
        })?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let ifaces6 = Interfaces6::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let fw_rules6 = FwRules6::open(&mut ebpf)?;
        let fw_meta6 = FwMetaMap6::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let iface_meta = IfaceMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        // v6 firewall conntrack handle for the interface-detach flush. No userspace GC task holds it
        // (the LRU map self-evicts), so AyaWriter owns the sole handle — no Control field needed.
        let conntrack6 = Arc::new(Mutex::new(Conntrack6::open(&mut ebpf)?));
        let aya = AyaWriter {
            routes,
            routes6,
            nat,
            nat_ips,
            neigh_nat,
            neigh_nat_count,
            lb,
            maglev,
            underlay,
            fw_rules,
            fw_meta,
            fw_rules6,
            fw_meta6,
            ports,
            ifaces,
            ifaces6,
            vips,
            meter,
            dhcp_config,
            dhcp_meta,
            iface_meta,
            conntrack: Arc::clone(&conntrack),
            conntrack6,
        };
        let mut inner = Inner {
            ebpf,
            _guest_progs: guest_progs,
            _uplink_progs: uplink_progs,
            _locals: locals,
            _geneve_ifindex: geneve_ifindex_map,
            geneve_ifindex,
            core: ControlCore::new(aya),
            recovered: Vec::new(),
            pin_links,
            pin_dir: pin_dir.to_path_buf(),
            by_id: HashMap::new(),
            iface_underlay: HashMap::new(),
            links: HashMap::new(),
            learned_macs: HashMap::new(),
        };
        // Restart adopt: the pinned state maps were reused by map_pin_path, so rebuild the in-memory
        // bookkeeping (by_id/by_ifindex/iface_underlay) and the re-attach list from the surviving
        // IFACE_META journal. A fresh (non-adopt) bring-up starts empty.
        if adopt {
            let recovered = Self::rebuild_from_maps(&mut inner)?;
            eprintln!(
                "adopt: recovered {} interface(s) from pinned maps",
                recovered.len(),
            );
            inner.recovered = recovered;
        }
        Ok(Self {
            inner: Mutex::new(inner),
            conntrack,
        })
    }

    /// After adopting pinned maps on restart, repopulate the in-memory bookkeeping from the surviving
    /// `IFACE_META` journal so subsequent AttachInterface/DetachInterface/get/list see the pre-restart
    /// state. Returns `reattach`: `(interface_id, device)` whose guest program must be RE-ATTACHED by
    /// the caller (their links died with the old process; the maps survived).
    fn rebuild_from_maps(g: &mut Inner) -> anyhow::Result<ReattachList> {
        let journal = g.core.writer().iface_meta_entries();
        // Sanity cross-check: the journal should track the surviving INTERFACES map 1:1.
        let iface_count = g.core.writer().ifaces_count();
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
            // Mirror the agnostic subset into the core so post-adopt NAT/LB conflict checks (which
            // live in ControlCore) see the recovered interface, exactly as they saw `by_id` before.
            g.core.register_iface_meta(
                id.clone(),
                flowplane_control::shadow::IfaceMeta {
                    vni: rec.vni,
                    ipv4: rec.ipv4,
                    ipv6: rec.ipv6,
                    underlay: rec.underlay,
                    ifindex: tap,
                },
            );
            g.by_id.insert(id.clone(), rec);
            g.iface_underlay.insert(id.clone(), v.underlay);
            reattach.push((id, device));
        }
        Ok(reattach)
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
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "wan_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt wan link failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "wan_rx", wan_uplink, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("wan-{wan_uplink}"));
            loader::attach_tc_clsact_ingress(&mut g.ebpf, "wan_rx", wan_uplink)?;
        }
        loader::ensure_fq_qdisc(wan_uplink);
        g.core.writer_mut().underlay_upsert(
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
    ///
    /// NOTE: under the P2 geneve `collect_md` model, decap happens on the geneve device's OWN RX
    /// path regardless of which physical NIC the encapped packet arrived on (a single virtual
    /// device demuxes the tunnel), and `bring_up` attaches the "real" `uplink_rx` there — see its
    /// doc comment. So attaching `uplink_rx` directly to a raw extra physical NIC (as this fn does)
    /// now only ever sees still-encapsulated bytes: `get_tunnel_key` fails immediately and the
    /// program passes every frame through unchanged. Kept (converted to tcx) for CLI/mechanical
    /// parity rather than as something dual-homing still needs; a follow-up can retire
    /// `--extra-uplink` entirely once that is confirmed in practice.
    pub fn attach_extra_uplink(&self, iface: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let pin_links = g.pin_links;
        let pin_dir = g.pin_dir.clone();
        if pin_links {
            let name = format!("uplink-{iface}");
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "uplink_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt extra uplink {iface} failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "uplink_rx", iface, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("uplink-{iface}"));
            loader::attach_tc_clsact_ingress(&mut g.ebpf, "uplink_rx", iface)?;
        }
        loader::ensure_fq_qdisc(iface);
        println!("uplink_rx attached to extra uplink {iface}");
        Ok(())
    }

    /// Return a shared handle to the conntrack map (for the GC task and flush operations).
    pub fn take_conntrack(&self) -> Arc<Mutex<Conntrack>> {
        Arc::clone(&self.conntrack)
    }

    /// Run `f` with an exclusive `&mut` borrow of the inner `ControlCore` under the `Inner` lock.
    /// Lets the shared `handlers` module's fns drive the same ControlCore the per-domain
    /// `Control` methods use, without duplicating their parse/marshalling.
    pub fn with_core<R>(&self, f: impl FnOnce(&mut ControlCore<AyaWriter>) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut g.core)
    }

    /// Set the guest DHCP config. Delegates to the backend-agnostic `ControlCore`.
    pub fn set_dhcp_config(
        &self,
        mtu: u16,
        dns4: &[[u8; 4]],
        dns6: &[[u8; 16]],
    ) -> anyhow::Result<()> {
        self.inner.lock().core.set_dhcp_config(mtu, dns4, dns6)
    }

    /// Build a `MeterState` from per-lane caps in Mbit/s. Thin re-export of the single source of
    /// truth now living in `flowplane-control` (`flowplane_control::meter_state`); kept as a
    /// `Control` associated fn so the CLI (`main.rs`) call site is unchanged.
    pub fn meter_state(
        egress_mbps: u64,
        public_mbps: u64,
        ingress_mbps: u64,
    ) -> flowplane_common::MeterState {
        flowplane_control::meter_state(egress_mbps, public_mbps, ingress_mbps)
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
        let resolved = device.to_string();
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
        // Check that the (vni, ipv4) combination is not already in use (if non-zero).
        // A zero ipv4 means an IPv6-only overlay; every such interface shares ipv4 == [0;4],
        // so skip the check to avoid a bogus ROUTE_EXISTS collision on the second v6-only attach.
        if ipv4 != [0u8; 4] && g.by_id.values().any(|r| r.vni == vni && r.ipv4 == ipv4) {
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
        //
        // netkit (L3) primaries take the guest program via `BPF_NETKIT_PRIMARY`, NOT tcx/clsact —
        // attaching a clsact/tcx program to an L3 netkit primary is the wrong attach point. netkit has
        // no aya attach API (aya-rs/aya#1540), so `attach_netkit_pinned_at` issues a raw
        // `bpf(BPF_LINK_CREATE)` and pins the link. Netkit only exists in the pin-links (production
        // Serve) path — `create_netkit_pair` is never created by a non-pinning debug caller — so a
        // non-pinning netkit attach is unsupported and rejected rather than silently mis-attached via
        // tcx. `tap` (resolved above from the device ifindex) IS the netkit PRIMARY ifindex.
        let link = if params.l3 {
            if !g.pin_links {
                anyhow::bail!("netkit (L3) attach requires pin-links mode (production Serve)");
            }
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            loader::attach_netkit_pinned_at(&mut g.ebpf, "tc_guest_tx", tap, &pin_dir, &gname)
                .with_context(|| {
                    format!("attach+pin tc_guest_tx to netkit {device} (ifindex {tap})")
                })?;
            GuestLink::Pinned(gname)
        } else if g.pin_links {
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
        // all succeed. Otherwise a failed map write left a ghost by_id/links entry behind while
        // attach.rs (seeing the Err) deleted the veth + released the IPAM /128 — so Control
        // referenced a dead device and a retry of the same id hit "interface already exists". `link`
        // is a local until commit, so any early return here drops it, detaching the guest program.
        //
        // MAC learning persistence: prefer the shadow-cached learned MAC (populated by
        // detach_interface) so a delete+recreate of the SAME interface preserves a datapath-learned
        // MAC (e.g. a VM behind the tap using a self-set MAC) even though the BPF UNDERLAY entry is
        // gone. Keyed by interface_id (NOT the underlay /128): a DIFFERENT interface reusing a freed
        // underlay must NOT inherit the previous endpoint's MAC — it uses its own device MAC.
        // Resolved here (device-side bookkeeping) and handed to the agnostic map programming.
        let effective_mac = g.learned_macs.get(interface_id).copied().unwrap_or(mac);
        // The MAP-programming half (PORT_META/INTERFACES/UNDERLAY/self-routes/METER/IFACE_META) moved
        // into the backend-agnostic `ControlCore`. `IfaceParams` carries the device-resolved
        // `tap`/`effective_mac` so the write set/order is byte-identical to the former inline body.
        if let Err(e) = g.core.program_interface(flowplane_control::IfaceParams {
            interface_id: interface_id.to_vec(),
            device: device.to_string(),
            tap,
            effective_mac,
            vni,
            ipv4,
            ipv6,
            gateway_ipv4: params.gateway_ipv4,
            gateway_ipv6: params.gateway_ipv6,
            underlay_ipv6,
            total_mbps: params.total_mbps,
            public_mbps: params.public_mbps,
            l3: params.l3,
        }) {
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
        g.iface_underlay
            .insert(interface_id.to_vec(), underlay_ipv6);
        // Mirror the agnostic interface metadata into the core so the NAT/LB/QoS conflict checks +
        // the `set_qos` tap resolution can read it (also the sole ifindex source now `by_ifindex` is
        // retired).
        g.core.register_iface_meta(
            interface_id.to_vec(),
            flowplane_control::shadow::IfaceMeta {
                vni,
                ipv4,
                ipv6,
                underlay: underlay_ipv6,
                ifindex: tap,
            },
        );
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
        // Resolve the tap ifindex from the core's agnostic mirror (formerly `Inner.by_ifindex`, now
        // retired — `ifaces_meta` is the single source of truth). Read it BEFORE `forget_iface_meta`.
        let tap = g.core.iface_ifindex(interface_id).unwrap_or(0);
        // Drop the core's agnostic mirror of this interface's metadata (registered in create_interface).
        g.core.forget_iface_meta(interface_id);
        g.iface_underlay.remove(interface_id);
        // Drop the restart-journal entry so a later adopt does not resurrect a deleted interface.
        if let Some(k) = IfaceMetaKey::from_id(interface_id) {
            let _ = g.core.writer_mut().iface_meta_remove(&k);
        }
        // Dropping the link detaches the program from the device.
        if let Some(GuestLink::Pinned(name)) = g.links.remove(interface_id) {
            let pin_dir = g.pin_dir.clone();
            loader::unpin_link(&pin_dir, &name);
        }
        let _ = g.core.writer_mut().ports_remove(tap);
        // Before removing the INTERFACES entries, snapshot the currently-learned guest MAC (the
        // datapath may have updated it via DHCP/ARP MAC learning) from INTERFACES (v4), falling back
        // to INTERFACES6 for a v6-only interface. This snapshot survives the delete so a later
        // addinterface can restore the learned MAC.
        let learned = g
            .core
            .writer()
            .ifaces_get(&IfaceKey::new(rec.vni, rec.ipv4))
            .or_else(|| {
                if rec.ipv6 != [0u8; 16] {
                    g.core
                        .writer()
                        .ifaces6_get(&IfaceKey6::new(rec.vni, rec.ipv6))
                } else {
                    None
                }
            });
        if let Some(iv) = learned {
            g.learned_macs.insert(interface_id.to_vec(), iv.guest_mac);
        }
        let _ = g
            .core
            .writer_mut()
            .ifaces_remove(IfaceKey::new(rec.vni, rec.ipv4));
        if rec.ipv6 != [0u8; 16] {
            let _ = g
                .core
                .writer_mut()
                .ifaces6_remove(IfaceKey6::new(rec.vni, rec.ipv6));
        }
        let _ = g.core.writer_mut().meter_remove(&tap);
        let _ = g.core.writer_mut().dhcp_meta_remove(tap);
        // Remove the local self-route(s) programmed by program_interface.
        let _ = g.core.writer_mut().route_remove(rec.vni, rec.ipv4, 32);
        if rec.ipv6 != [0u8; 16] {
            let _ = g.core.writer_mut().route6_remove(rec.vni, rec.ipv6, 128);
        }
        g.core.remove_fw_rules(tap);
        // Flush this interface's conntrack so a later reschedule of the same (VNI, overlayIP) cannot
        // inherit a stale established-flow firewall bypass. Best-effort + per-interface (not gated on
        // the last-iface purge_vni below, which only fires when the whole VNI empties).
        let _ = g
            .core
            .writer_mut()
            .conntrack_flush_interface(vni, rec.ipv4, rec.ipv6);
        // Auto-reset VNI when the last local interface on it is removed:
        // purge neighbor NATs (and orphaned VIP/NAT/route state) for that VNI. This matches
        // dpservice's async-deletion model where the VNI is implicitly reset on last-iface removal.
        // The reconciliation itself lives in `ControlCore::purge_vni`; Control keeps only
        // the "is the VNI still in use?" decision (it reads `by_id`, which stays authoritative here).
        let vni_still_in_use = g.by_id.values().any(|r| r.vni == vni) || g.core.vni_has_lb(vni);
        if !vni_still_in_use {
            g.core.purge_vni(vni, rec.ipv4)?;
        }
        Ok(true)
    }

    /// Read the `INTERFACES` map entry for `(vni, ipv4)` straight back out of the live eBPF map.
    /// Used by the DataplaneNode AttachInterface path to confirm the endpoint is resident in the
    /// kernel map (a read-back that proves the program actually landed). Returns the tap ifindex.
    pub fn interface_readback(&self, vni: u32, ipv4: [u8; 4]) -> Option<u32> {
        let g = self.inner.lock();
        g.core
            .writer()
            .ifaces_get(&IfaceKey::new(vni, ipv4))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_pin_name_is_stable_and_hex() {
        assert_eq!(hex_encode(b"natpod"), "6e6174706f64");
        assert_eq!(hex_encode(b"rpod"), hex_encode(b"rpod"));
    }

    // NOTE: the `meter_state_conversion` assertion moved verbatim into `flowplane-control`
    // (src/interface.rs) alongside the `meter_state` fn that now owns the math. It runs there
    // without CAP_BPF.

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
}
