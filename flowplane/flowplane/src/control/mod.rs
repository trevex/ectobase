use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use aya::Ebpf;
use flowplane_common::{
    IfaceKey, IfaceKey6, IfaceMetaKey, IfaceMetaVal, IfaceValue, Local, RouteValue, IFACE_DEV_MAX,
};

use crate::loader;
use crate::maps::{
    Conntrack, Conntrack6, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwMetaMap6, FwRules, FwRules6,
    GeneveIfindexMap, IfaceMetaMap, Interfaces, Interfaces6, Lb, LocalMap, Maglev, Meter, Nat,
    NatIps, NeighborNat, NeighborNatCount, PortMetaMap, Routes, Routes6, Vips,
};
// `Nat`, `NatIps`, `NeighborNat`, `NeighborNatCount` are opened in `bring_up`/the test ctor and
// moved into `AyaWriter`, which owns them; they are not held on `Inner`.

// The `impl Control` blocks are split by domain into these child modules. Each is pure code
// movement out of this file; they reach `Inner`'s private state via `super`.
mod aya_writer;
mod bringup;
mod firewall;
mod lb;
mod nat;
mod recover;
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

/// Result of `Control::overlay_status`: whether an overlay `(vni, ip)` is claimable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayStatus {
    /// No interface holds this (vni, ip) — a normal attach may proceed.
    Free,
    /// Already held by the SAME logical NIC (matching guest MAC) — an idempotent re-attach should
    /// adopt it (return success without creating a second device).
    SameEndpoint,
    /// Already held by a DIFFERENT endpoint (different MAC) — a genuine `ROUTE_EXISTS` conflict.
    Conflict,
}

impl OverlayStatus {
    /// Pure decision the `(vni, ip)` idempotency check makes: given whether the overlay address is
    /// already claimed and the resident guest MAC (if the INTERFACES entry is present), decide
    /// whether a re-attach with `req_mac` adopts (same endpoint), conflicts (different endpoint), or
    /// is free. A missing resident MAC on a claimed address is treated as a conflict (fail safe —
    /// don't adopt an endpoint we can't confirm is the same one).
    fn classify(present: bool, resident_mac: Option<[u8; 6]>, req_mac: [u8; 6]) -> OverlayStatus {
        if !present {
            return OverlayStatus::Free;
        }
        match resident_mac {
            Some(m) if m == req_mac => OverlayStatus::SameEndpoint,
            _ => OverlayStatus::Conflict,
        }
    }
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
    /// Attach the guest program via the `BPF_NETKIT_PEER` hook (raw `bpf(BPF_LINK_CREATE)`) rather
    /// than tcx/clsact — true for a netkit device (container L3 edge OR the VM L2 pod-tap edge),
    /// false for veth/tap. Decoupled from `l3`: the VM edge is netkit (`netkit=true`) but L2
    /// (`l3=false`), so the attach mechanism and the datapath L2/L3 semantics are chosen independently.
    pub netkit: bool,
    /// L3 (no-eth) datapath semantics: program `PORT_META.l3 = 1` so local delivery keeps the eth
    /// header with a zeroed dst (NOARP peer) instead of rewriting it to `guest_mac`. True only for the
    /// container netkit-L3 edge; false for veth/tap AND the VM netkit-L2 pod-tap (real MAC, ARP).
    pub l3: bool,
    /// The delivery device has a netns peer (veth/netkit) → local delivery may use `bpf_redirect_peer`
    /// (written to `IfaceValue.peer_capable`). True for veth/netkit/pod-tap; false for a peerless
    /// root-netns tap. Distinct from `netkit`: a veth is peer_capable but NOT netkit-attached.
    pub peer_capable: bool,
    /// SR-IOV VF/SF representor eligible for later hardware flow-offload (increment C). Forwarded
    /// into PORT_META via program_interface; datapath-inert in increment A.
    pub offloaded: bool,
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
    /// ifindex of the node-wide `collect_md` Geneve device (`flowplane_device::GENEVE_DEV`), brought
    /// up in `bring_up` and programmed into `GENEVE_IFINDEX[0]` right after. Exposed via
    /// [`Control::geneve_ifindex`] as the tc-flower redirect target for the E/W offload manager.
    geneve_ifindex: u32,
    core: ControlCore<AyaWriter>,
    /// Interfaces recovered by `rebuild_from_maps` on adopt: (interface_id, device) whose guest
    /// program must be re-attached by the caller (`Serve`). Empty on a fresh (non-adopt) bring-up.
    recovered: recover::ReattachList,
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

impl Control {
    /// Return a shared handle to the conntrack map (for the GC task and flush operations).
    pub fn take_conntrack(&self) -> Arc<Mutex<Conntrack>> {
        Arc::clone(&self.conntrack)
    }

    /// Return a shared handle to the v6 firewall conntrack map (`CONNTRACK6`), mirroring
    /// [`Control::take_conntrack`]. Unlike the v4 handle, `CONNTRACK6` lives on `AyaWriter` (not a
    /// dedicated `Control` field), so this reaches it through `core.writer()`.
    pub fn take_conntrack6(&self) -> Arc<Mutex<Conntrack6>> {
        Arc::clone(&self.inner.lock().core.writer().conntrack6)
    }

    /// The node-wide `collect_md` Geneve device's ifindex (`fp-geneve0`) — the tc-flower redirect
    /// target the E/W offload manager programs established flows onto.
    pub fn geneve_ifindex(&self) -> u32 {
        self.inner.lock().geneve_ifindex
    }

    /// `INTERFACES[(vni, ipv4)]` lookup: the representor's delivery info (tap ifindex, locality),
    /// used by the E/W offload manager to resolve an established flow's local representor.
    pub fn iface_lookup_v4(&self, vni: u32, ipv4: [u8; 4]) -> Option<IfaceValue> {
        self.inner
            .lock()
            .core
            .writer()
            .ifaces
            .get(&IfaceKey::new(vni, ipv4))
    }

    /// v6 sibling of [`Control::iface_lookup_v4`] (`INTERFACES6`).
    pub fn iface_lookup_v6(&self, vni: u32, ipv6: [u8; 16]) -> Option<IfaceValue> {
        self.inner
            .lock()
            .core
            .writer()
            .ifaces6
            .get(&IfaceKey6::new(vni, ipv6))
    }

    /// `ROUTES` longest-prefix-match lookup for `dst` — the remote VTEP + VNI an established
    /// flow's inner destination routes through. `None` if no route covers `dst`.
    pub fn route_lookup_v4(&self, vni: u32, dst: [u8; 4]) -> Option<RouteValue> {
        self.inner.lock().core.writer().routes.get(vni, dst)
    }

    /// v6 sibling of [`Control::route_lookup_v4`] (`ROUTES6`).
    pub fn route_lookup_v6(&self, vni: u32, dst: [u8; 16]) -> Option<RouteValue> {
        self.inner.lock().core.writer().routes6.get(vni, dst)
    }

    /// Whether `tap`'s `PORT_META` entry is offload-eligible (`offloaded == 1`); `false` if the
    /// port has no entry.
    pub fn port_offloaded(&self, tap: u32) -> bool {
        self.inner
            .lock()
            .core
            .writer()
            .ports
            .get(tap)
            .map(|m| m.offloaded != 0)
            .unwrap_or(false)
    }

    /// The distinct set of offload-capable representor ifindexes: every `INTERFACES`/`INTERFACES6`
    /// entry's `tap_ifindex` whose `PORT_META` has `offloaded == 1`. Used by the E/W offload
    /// manager's startup flush to find (and clear) any leaked flower filters across all VF
    /// representors.
    pub fn offloaded_reps(&self) -> Vec<u32> {
        let g = self.inner.lock();
        let w = g.core.writer();
        let mut set = BTreeSet::new();
        for (_k, v) in w.ifaces.entries() {
            if w.ports
                .get(v.tap_ifindex)
                .map(|m| m.offloaded != 0)
                .unwrap_or(false)
            {
                set.insert(v.tap_ifindex);
            }
        }
        for (_k, v) in w.ifaces6.entries() {
            if w.ports
                .get(v.tap_ifindex)
                .map(|m| m.offloaded != 0)
                .unwrap_or(false)
            {
                set.insert(v.tap_ifindex);
            }
        }
        set.into_iter().collect()
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

    /// Whether an overlay `(vni, ip)` is already claimed, and if so whether by the SAME logical
    /// endpoint (matching guest MAC) or a different one. Used by the attach path to make
    /// AttachInterface idempotent: a KubeVirt launcher attaches the flowplane NAD TWICE (the multus
    /// network source + the binding plugin's own NAD), so `flowplane-cni` runs twice for the SAME VM
    /// NIC — same (vni, ip) and same MAC, different interface_id. The 2nd attach must ADOPT the 1st
    /// (return success, no 2nd device) instead of failing `ROUTE_EXISTS`, which would wedge the pod
    /// sandbox in an infinite CreatePodSandbox retry. A genuinely different endpoint (different MAC)
    /// still conflicts. Read under the same lock `create_interface` uses so the two agree.
    pub fn overlay_status(
        &self,
        vni: u32,
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        mac: [u8; 6],
    ) -> OverlayStatus {
        let g = self.inner.lock();
        // Uniqueness is keyed the same way create_interface checks it: any by_id record on this VNI
        // holding this (non-zero) v4 or v6 overlay address.
        let v4_hit = ipv4 != [0u8; 4] && g.by_id.values().any(|r| r.vni == vni && r.ipv4 == ipv4);
        let v6_hit = ipv6 != [0u8; 16] && g.by_id.values().any(|r| r.vni == vni && r.ipv6 == ipv6);
        if !v4_hit && !v6_hit {
            return OverlayStatus::Free;
        }
        // Present: compare the resident guest MAC (from INTERFACES / INTERFACES6) to the requested
        // MAC. Same MAC => same logical NIC re-attaching => adopt; different => real conflict.
        let resident = if v4_hit {
            g.core
                .writer()
                .ifaces_get(&IfaceKey::new(vni, ipv4))
                .map(|v| v.guest_mac)
        } else {
            g.core
                .writer()
                .ifaces6_get(&IfaceKey6::new(vni, ipv6))
                .map(|v| v.guest_mac)
        };
        OverlayStatus::classify(true, resident, mac)
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
        // netkit (L3) devices take the guest-EGRESS program via the `BPF_NETKIT_PEER` hook
        // (PRIMARY=host→pod, PEER=pod egress; `tc_guest_tx` is the pod-egress pipeline), NOT
        // tcx/clsact — attaching a clsact/tcx program to an L3 netkit primary is the wrong attach point.
        // The attach targets the primary ifindex with attach_type PEER. netkit has
        // no aya attach API (aya-rs/aya#1540), so `attach_netkit_pinned_at` issues a raw
        // `bpf(BPF_LINK_CREATE)` and pins the link. Netkit only exists in the pin-links (production
        // Serve) path — `create_netkit_pair` is never created by a non-pinning debug caller — so a
        // non-pinning netkit attach is unsupported and rejected rather than silently mis-attached via
        // tcx. `tap` (resolved above from the device ifindex) IS the netkit PRIMARY ifindex.
        let link = if params.netkit {
            if !g.pin_links {
                anyhow::bail!("netkit attach requires pin-links mode (production Serve)");
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
            peer_capable: params.peer_capable,
            offloaded: params.offloaded,
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
        // the `set_qos` tap resolution can read it (also the sole ifindex source — there is no
        // separate `by_ifindex` map).
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
    /// VIPs, and routes for that VNI).
    pub fn detach_interface(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let rec = match g.by_id.remove(interface_id) {
            Some(r) => r,
            None => return Ok(false),
        };
        let vni = rec.vni;
        // Resolve the tap ifindex from the core's agnostic mirror (`ifaces_meta`, the single source of
        // truth). Read it BEFORE `forget_iface_meta`.
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
        // purge neighbor NATs (and orphaned VIP/NAT/route state) for that VNI — the VNI is
        // implicitly reset on last-iface removal.
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

    /// The idempotency crux: a re-attach of the same overlay (vni, ip) ADOPTS only when the resident
    /// MAC matches (the KubeVirt double-attach — one VM NIC, two launcher annotation entries, same
    /// MAC), and still CONFLICTS for a different endpoint or an unconfirmable (missing) resident MAC.
    #[test]
    fn overlay_status_classify_adopts_same_mac_only() {
        let mac = [0x52, 0x54, 0, 0, 0x05, 0x0a];
        let other = [0x52, 0x54, 0, 0, 0x05, 0x0b];
        // Free: address not claimed → normal attach.
        assert_eq!(
            OverlayStatus::classify(false, None, mac),
            OverlayStatus::Free
        );
        assert_eq!(
            OverlayStatus::classify(false, Some(other), mac),
            OverlayStatus::Free,
            "presence flag governs; a stray resident MAC on an unclaimed key is ignored"
        );
        // Same endpoint: claimed + resident MAC == requested → adopt (the KubeVirt 2nd attach).
        assert_eq!(
            OverlayStatus::classify(true, Some(mac), mac),
            OverlayStatus::SameEndpoint
        );
        // Conflict: claimed by a different MAC → real ROUTE_EXISTS.
        assert_eq!(
            OverlayStatus::classify(true, Some(other), mac),
            OverlayStatus::Conflict
        );
        // Fail safe: claimed but no resident MAC to confirm identity → conflict, never adopt.
        assert_eq!(
            OverlayStatus::classify(true, None, mac),
            OverlayStatus::Conflict
        );
    }
}
