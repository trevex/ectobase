//! `DpdkNodeService` — the DPDK `DataplaneNode` gRPC service.
//!
//! The DPDK sibling of the eBPF `flowplane::node::NodeService`. Every backend-agnostic RPC
//! (routes / NAT / neighbor-NAT / LB / firewall / QoS) is thin proto→args marshalling that drives
//! the SAME `flowplane_control::ControlCore` orchestration the eBPF binary runs — only the write
//! surface differs (`DpdkMapWriter` over `SharedConfigMaps` vs the eBPF `AyaWriter`). The
//! orchestration is single-source: handlers NEVER reimplement route/nat/lb/fw logic, they call the
//! ControlCore method 1:1 with the eBPF handler (the [[seam-not-duplicate-for-tests]] invariant).
//!
//! ── ATTACH/DETACH (VF-style preallocated af_xdp pool) ──────────────────────────────────────────
//! `AttachInterface` stands up a real container interface by ASSIGNING a preallocated per-guest
//! af_xdp port slot (the DPDK serve loop creates N guest veth pairs before EAL init — `fpg{i}`,
//! host-end bound to an ethdev port, giving a STATIC poll set; see `serve.rs`). Attach reserves a
//! free slot, moves ITS placeholder guest-end (`fpg{i}p`) into the pod netns, programs the config
//! maps (`PortMeta` keyed by the SLOT's host ifindex — the exact key the serve worker's `ports_get`
//! uses), IPAMs the underlay /128, configures the pod netns, and returns a real
//! `AttachInterfaceResponse`. This is a deliberate DIVERGENCE from the eBPF create-on-attach model:
//! the host-end veth never moves (so the af_xdp binding stays live) and the pool veth SURVIVES
//! detach for reuse. `DetachInterface` purges the agnostic map half (VNI state + `ports_remove` the
//! PortMeta + IfaceMeta), moves the guest-end back to the root netns as the placeholder, releases
//! the /128, and frees the slot. Every attach failure path rolls back fully (unbind + free slot +
//! release IPAM + purge). See the per-method comments + `serve.rs` for the pool lifecycle.
//!
//! ── LOCKING ────────────────────────────────────────────────────────────────────────────────────
//! `ctrl` is a `parking_lot::Mutex<ControlCore<DpdkMapWriter>>` — the process's SOLE writer. Handlers
//! lock it, call the sync ControlCore method, and DROP the lock before building the response; the
//! lock is NEVER held across an `.await` (parking_lot guards are not async-aware). All arg parsing
//! and validation happens off-lock; only the ControlCore call is under the lock.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use nfkit::SharedConfigMaps;
use parking_lot::Mutex;
use tonic::{Request, Response, Status};

use flowplane_control::shadow::IfaceMeta;
use flowplane_control::{ControlCore, IfaceParams, MapWriter};
use flowplane_node::{first_ipv4, first_ipv6, parse_mac};

/// Format a 6-byte MAC as `"aa:bb:cc:dd:ee:ff"` (lowercase, colon-separated). Mirrors
/// `fmt_mac` in `flowplane/src/attach.rs` so the response MAC format is identical.
fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

use crate::writer::DpdkMapWriter;

pub use flowplane_node::pb;
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, DetachInterfaceRequest, DetachInterfaceResponse, InterfaceInfo,
    ListInterfacesRequest, ListInterfacesResponse,
};
// The 13 agnostic RPC request/response types are resolved through flowplane_node::pb via the `use
// flowplane_node::pb` re-export above; no explicit imports needed for those types because their
// handler bodies use flowplane_node::{add_route, …} which references them internally.

/// The DPDK `DataplaneNode` gRPC service. Owns the single serialized `ControlCore` writer (behind a
/// `Mutex`) plus a read handle on the shared config maps (for getter-based reads that don't route
/// through ControlCore, symmetric with the eBPF service holding its `AttachState`).
pub struct DpdkNodeService {
    ctrl: Arc<Mutex<ControlCore<DpdkMapWriter>>>,
    #[allow(dead_code)] // held for symmetry + future getter-based reads (e.g. B2 device state)
    shared: Arc<SharedConfigMaps>,
    /// B2a host-device attach state: underlay IPAM + the registry of active guest veths.
    attach: Arc<crate::attach_state::DpdkAttachState>,
}

impl DpdkNodeService {
    #[must_use]
    pub fn new(
        ctrl: Arc<Mutex<ControlCore<DpdkMapWriter>>>,
        shared: Arc<SharedConfigMaps>,
        attach: Arc<crate::attach_state::DpdkAttachState>,
    ) -> Self {
        Self {
            ctrl,
            shared,
            attach,
        }
    }
}

#[tonic::async_trait]
impl DataplaneNode for DpdkNodeService {
    async fn attach_interface(
        &self,
        req: Request<AttachInterfaceRequest>,
    ) -> Result<Response<AttachInterfaceResponse>, Status> {
        let r = req.into_inner();
        // B2a supports the container/veth device_type only (Tap/PodTap are eBPF-only for now).
        if !(r.device_type.is_empty() || r.device_type == "veth") {
            return Err(Status::invalid_argument(format!(
                "device_type {:?} not supported on DPDK yet (B2a = veth/container only)",
                r.device_type
            )));
        }
        let ipv4 = first_ipv4(&r.requested_ips);
        let ipv6 = first_ipv6(&r.requested_ips);
        // At least one overlay family is required; either may be absent (all-zeros). v4-only,
        // v6-only, and dual-stack are all valid (the datapath delivery is route+UNDERLAY driven,
        // family-agnostic; program_interface programs each present family's self-route).
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            return Err(Status::invalid_argument(
                "attach requires at least one overlay IP (IPv4 or IPv6) in requested_ips",
            ));
        }
        // MAC: honour a caller-supplied MAC, else derive a stable deterministic one (FNV-1a of
        // interface_id, same as the eBPF `AttachState::mac_for`).
        let mac = if r.mac.is_empty() {
            crate::attach_state::mac_for(&r.interface_id)
        } else {
            parse_mac(&r.mac).map_err(|e| Status::invalid_argument(e.to_string()))?
        };
        // Guest-side interface name inside the netns (mirrors eBPF: guest_name = interface_id).
        let guest_name = r.interface_id.clone();

        let attach = self.attach.clone();

        // Underlay /128 from the node's /64 pool. Allocate before the device (rollback on error).
        let underlay = {
            let mut ipam = attach.ipam.lock().unwrap();
            ipam.allocate()
                .ok_or_else(|| Status::resource_exhausted("underlay /64 exhausted"))?
                .octets()
        };

        // ── DPDK pool model (a deliberate divergence from the eBPF create-on-attach) ─────────────
        // The DPDK serve process PREALLOCATES N guest af_xdp veth pairs at startup (`fpg{i}`, host-end
        // bound to ethdev ports 1..=N, giving a STATIC poll set). Attach ASSIGNS a free slot instead
        // of creating a fresh veth: reserve the slot under the pool lock, then move ITS placeholder
        // guest-end (`fpg{i}p`) into the pod netns. `PortMeta` is keyed by the SLOT's host ifindex —
        // the exact key the serve worker's `ports_get` uses to resolve the guest's identity.
        //
        // Reserve a free slot under the lock (set bound + copy out the fields we need); DROP the lock
        // before any `.await`/subprocess (std::sync::Mutex must not be held across await). The reserve
        // block returns an Option so the `guest_pool` guard is released at the block end — the
        // pool-exhausted IPAM release then happens OUTSIDE the pool lock (never nest the two locks;
        // every lock in this handler stays strictly non-overlapping).
        //
        // DEAD-SLOT DETECTION (netns-destroyed-without-detach): veth pairs die together. If a pod's
        // netns was destroyed WITHOUT a preceding DetachInterface, the slot's guest-end vanished and
        // took the host-end (`fpg{i}`, bound to the af_xdp ethdev port) with it — leaving the slot free
        // (`bound.is_none()`) but its ethdev BROKEN. Binding such a slot would silently blackhole the
        // new guest's traffic. So FIRST pass marks any free-but-not-yet-dead slot whose host-end no
        // longer exists as `dead` (a quick sysfs stat — `link_exists` — is fine under this std Mutex;
        // it does NOT block on a subprocess). THEN we reserve only a live free slot (`!s.dead`); dead
        // slots are neither reused nor counted as free, so a pool drained by dead slots correctly
        // surfaces as `resource_exhausted` below. LIVE RECOVERY (recreate the veth + rte_dev hotplug
        // rebind the af_xdp vdev) is a documented follow-up — NOT done here.
        let reserved = {
            let mut pool = attach.guest_pool.lock().unwrap();
            for s in pool.iter_mut() {
                if s.bound.is_none() && !s.dead && !flowplane_device::link_exists(&s.host_ifname) {
                    s.dead = true;
                    eprintln!(
                        "warn: guest af_xdp pool slot {} (port {}) is DEAD — host-end veth vanished \
                         (pod netns destroyed without DetachInterface; veth pairs die together, so \
                         the guest-end took the host-end + its ethdev down). Excluding from the free \
                         pool; live recovery (recreate veth + rte_dev hotplug rebind) is a follow-up.",
                        s.host_ifname, s.port_id
                    );
                }
            }
            pool.iter_mut()
                .find(|s| s.bound.is_none() && !s.dead)
                .map(|slot| {
                    slot.bound = Some(r.interface_id.clone());
                    (
                        slot.host_ifname.clone(),
                        slot.host_ifindex,
                        slot.port_id,
                        format!("{}p", slot.host_ifname),
                    )
                })
        }; // guest_pool guard dropped here
        let (slot_host_ifname, slot_host_ifindex, slot_port_id, placeholder_peer) = match reserved {
            Some(fields) => fields,
            None => {
                // No free slot: release IPAM (nothing else reserved yet) + resource_exhausted. The
                // pool guard is already dropped, so this ipam.lock() never nests inside it.
                attach
                    .ipam
                    .lock()
                    .unwrap()
                    .release(std::net::Ipv6Addr::from(underlay));
                return Err(Status::resource_exhausted(
                    "guest af_xdp port pool exhausted (increase --guest-ports)",
                ));
            }
        };
        let _ = slot_port_id; // recorded on the slot; not needed further in the attach path.

        // Helper to free the reserved slot on any rollback path below.
        let free_slot = |attach: &crate::attach_state::DpdkAttachState| {
            if let Some(s) = attach
                .guest_pool
                .lock()
                .unwrap()
                .iter_mut()
                .find(|s| s.host_ifindex == slot_host_ifindex)
            {
                s.bound = None;
            }
        };

        // Move the reserved slot's placeholder guest-end into the pod netns off-thread (shells out to
        // `ip`; must not block the tokio worker). The host-end stays put on the af_xdp ethdev port.
        {
            let placeholder_peer_task = placeholder_peer.clone();
            let netns_path = r.netns_path.clone();
            let guest_name_task = guest_name.clone();
            let guest_mtu = attach.guest_mtu;
            let join = tokio::task::spawn_blocking(move || {
                flowplane_device::bind_preallocated_guest_end(
                    &placeholder_peer_task,
                    &netns_path,
                    &guest_name_task,
                    mac,
                    guest_mtu,
                    false, // real NIC finalizes csum; clab detection is a follow-up
                )
            })
            .await;
            // Route BOTH the returned-Err (bind failed) AND the JoinError (bind task PANICKED) through
            // the SAME rollback. A bare `?` on the JoinError would return before any reclaim ran,
            // leaking the reserved slot (bound=Some) + the IPAM /128. A panic mid-bind can also strand
            // the guest-end inside the pod netns, so the panic arm additionally best-effort-unbinds it
            // (matching the program_interface-fail rollback's unbind+free+release shape).
            let failed: Option<(String, bool)> = match join {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some((format!("bind pool guest-end: {e}"), false)),
                Err(e) => Some((format!("attach bind task panicked: {e}"), true)),
            };
            if let Some((msg, panicked)) = failed {
                if panicked {
                    // A panic MID-bind could have moved the guest-end into the pod netns before
                    // dying; best-effort-restore the placeholder to the root netns.
                    let placeholder_peer = placeholder_peer.clone();
                    let netns_path = r.netns_path.clone();
                    let guest_name = guest_name.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        flowplane_device::unbind_preallocated_guest_end(
                            &netns_path,
                            &guest_name,
                            &placeholder_peer,
                        )
                    })
                    .await;
                }
                free_slot(&attach);
                attach
                    .ipam
                    .lock()
                    .unwrap()
                    .release(std::net::Ipv6Addr::from(underlay));
                return Err(Status::internal(msg));
            }
        }

        // Program the shared maps under the ctrl lock, keying PortMeta by the SLOT's host ifindex (the
        // key the serve worker's `ports_get` uses). The lock is taken, the sync ControlCore call runs,
        // and the lock is DROPPED before any .await (parking_lot guards are not async-aware).
        // Compute the program result inside the lock scope; the guard is dropped at the block end so
        // no parking_lot guard is ever held across the `.await` below (guards are not async-aware).
        let program_err = {
            let mut core = self.ctrl.lock();
            match core.program_interface(IfaceParams {
                interface_id: r.interface_id.clone().into_bytes(),
                device: slot_host_ifname.clone(),
                tap: slot_host_ifindex,
                effective_mac: mac,
                vni: r.vni,
                ipv4,
                ipv6,
                gateway_ipv4: attach.gateway_ipv4,
                gateway_ipv6: attach.gateway_ipv6,
                underlay_ipv6: underlay,
                total_mbps: 0,
                public_mbps: 0,
            }) {
                Err(e) => Some(e.to_string()),
                Ok(()) => {
                    core.register_iface_meta(
                        r.interface_id.clone().into_bytes(),
                        IfaceMeta {
                            vni: r.vni,
                            ipv4,
                            ipv6,
                            underlay,
                            ifindex: slot_host_ifindex,
                        },
                    );
                    None
                }
            }
        }; // ctrl lock dropped here
        if let Some(msg) = program_err {
            // Roll back (lock already dropped): move the guest-end back (best-effort, shells out) +
            // free the slot + release IPAM. The pool veth SURVIVES (owned by serve startup/shutdown).
            {
                let placeholder_peer = placeholder_peer.clone();
                let netns_path = r.netns_path.clone();
                let guest_name = guest_name.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    flowplane_device::unbind_preallocated_guest_end(
                        &netns_path,
                        &guest_name,
                        &placeholder_peer,
                    )
                })
                .await;
            }
            free_slot(&attach);
            attach
                .ipam
                .lock()
                .unwrap()
                .release(std::net::Ipv6Addr::from(underlay));
            return Err(Status::internal(msg));
        }

        // Register the live device so detach can find the slot (by host_ifindex) + the netns. The
        // registered `host_name` is the SLOT's `fpg{i}`; detach reconstructs the placeholder as
        // `format!("{host_name}p")`.
        attach.register(
            r.interface_id.clone().into_bytes(),
            crate::attach_state::AttachedDevice {
                host_ifindex: slot_host_ifindex,
                host_name: slot_host_ifname.clone(),
                netns_path: r.netns_path.clone(),
            },
        );

        // Deterministically configure the container's pod netns (overlay addr(s) + per-family
        // default route). Off the tokio thread (shells out). On failure, roll the whole attach back
        // (maps + veth + IPAM + registry) so no half-attached interface is left behind.
        let cfg = flowplane_device::GuestNetConfig {
            netns_path: r.netns_path.clone(),
            guest_ifname: guest_name.clone(),
            ipv4,
            gateway_ipv4: attach.gateway_ipv4,
            ipv6,
            gateway_ipv6: attach.gateway_ipv6,
        };
        let cfg_join =
            tokio::task::spawn_blocking(move || flowplane_device::configure_guest_netns(&cfg))
                .await;
        // Route BOTH the returned-Err (configure failed) AND the JoinError (configure task PANICKED)
        // through the SAME full rollback below. A bare `?` on the JoinError would return here BEFORE
        // the rollback ran, leaking: the reserved slot, the IPAM /128, the guest-end stranded in the
        // pod netns, and stale PortMeta + registry state — despite the rollback comment promising a
        // full reclaim. The panic must not bypass reclaim.
        let cfg_failed: Option<String> = match cfg_join {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("configure guest netns: {e}")),
            Err(e) => Some(format!("guest-netns task panicked: {e}")),
        };
        if let Some(cfg_msg) = cfg_failed {
            let id = r.interface_id.clone().into_bytes();
            {
                let mut core = self.ctrl.lock();
                if let Some((vni, ip4)) = core
                    .iface_meta_rows()
                    .into_iter()
                    .find(|(rid, ..)| rid.as_slice() == id.as_slice())
                    .map(|(_, vni, ip4, ..)| (vni, ip4))
                {
                    let _ = core.purge_vni(vni, ip4);
                }
                // Also remove the PortMeta we just programmed (keyed by the slot ifindex) so the
                // freed slot doesn't retain a stale PortMeta for the serve worker to act on.
                let _ = core.writer_mut().ports_remove(slot_host_ifindex);
                core.forget_iface_meta(&id);
            } // ctrl lock dropped before the subprocess below
              // Move the guest-end back to the root netns (best-effort) — the pool veth SURVIVES.
            {
                let placeholder_peer = placeholder_peer.clone();
                let netns_path = r.netns_path.clone();
                let guest_name = guest_name.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    flowplane_device::unbind_preallocated_guest_end(
                        &netns_path,
                        &guest_name,
                        &placeholder_peer,
                    )
                })
                .await;
            }
            free_slot(&attach);
            attach
                .ipam
                .lock()
                .unwrap()
                .release(std::net::Ipv6Addr::from(underlay));
            attach.forget(&id);
            return Err(Status::internal(cfg_msg));
        }

        // Build the response mirroring the eBPF `AttachOutcome` → `AttachInterfaceResponse` mapping
        // (flowplane/src/attach.rs + node.rs): ifname = guest name inside the netns (= interface_id
        // for Veth), ips = [overlay_ipv4], mac = "aa:bb:.." string, gateway = IPv4 gateway string,
        // underlay_route = /128 as "xxxx::yyyy" string.
        Ok(Response::new(AttachInterfaceResponse {
            ifname: guest_name,
            // Present overlay families (identical shape to the eBPF attach response): v4 then v6.
            ips: {
                let mut v = Vec::new();
                if ipv4 != [0u8; 4] {
                    v.push(std::net::Ipv4Addr::from(ipv4).to_string());
                }
                if ipv6 != [0u8; 16] {
                    v.push(std::net::Ipv6Addr::from(ipv6).to_string());
                }
                v
            },
            mac: fmt_mac(mac),
            // v4 gateway string, or empty for a v6-only overlay (this interface has no v4 addr,
            // so the node's v4 gateway is meaningless to it) — mirrors the eBPF attach response.
            gateway: if ipv4 == [0u8; 4] {
                String::new()
            } else {
                std::net::Ipv4Addr::from(attach.gateway_ipv4).to_string()
            },
            underlay_route: std::net::Ipv6Addr::from(underlay).to_string(),
        }))
    }

    async fn detach_interface(
        &self,
        req: Request<DetachInterfaceRequest>,
    ) -> Result<Response<DetachInterfaceResponse>, Status> {
        let id = req.into_inner().interface_id.into_bytes();

        // Snapshot the underlay /128 before the maps are purged (so we can release the IPAM slot).
        let underlay_to_release = {
            let core = self.ctrl.lock();
            core.iface_meta_rows()
                .into_iter()
                .find(|(rid, ..)| rid.as_slice() == id.as_slice())
                .map(|(_, _, _, _, ul, _)| ul)
        };

        // Snapshot the interface's tap ifindex before the maps are purged — this is the SLOT's host
        // ifindex (PortMeta is keyed by it) that we must both `ports_remove` AND match a pool slot on.
        let tap_ifindex = {
            let core = self.ctrl.lock();
            core.iface_ifindex(&id)
        };

        // Undo the agnostic map half: purge the interface's VNI state, remove its PortMeta, + drop its
        // meta record. Best-effort: run ALL reclaim steps regardless of a purge error.
        //
        // NOTE (PortMeta removal): `purge_vni` clears VNI-keyed state (neigh_nats/vips/nat/routes) and
        // `forget_iface_meta` only drops the in-memory `ifaces_meta` record — NEITHER removes the
        // `PortMeta` keyed by the tap ifindex (programmed by `program_interface`). Since the pool slot
        // is REUSED, a stale PortMeta would make the serve worker run `process_guest_tx` with the
        // PREVIOUS guest's identity for the next attach → a correctness bug. So detach explicitly
        // `ports_remove(tap_ifindex)`.
        {
            let mut core = self.ctrl.lock();
            if let Some((vni, ipv4)) = core
                .iface_meta_rows()
                .into_iter()
                .find(|(rid, ..)| rid.as_slice() == id.as_slice())
                .map(|(_, vni, ipv4, ..)| (vni, ipv4))
            {
                // Best-effort: a purge error must NOT short-circuit the remaining reclaim (meta
                // drop, IPAM release, veth teardown), else the /128 leaks and the veth dangles.
                let _ = core.purge_vni(vni, ipv4);
            }
            if let Some(tap) = tap_ifindex {
                let _ = core.writer_mut().ports_remove(tap);
            }
            core.forget_iface_meta(&id);
        } // ctrl lock dropped here

        // Release the underlay /128 back to the IPAM pool.
        if let Some(ul) = underlay_to_release {
            if ul != [0u8; 16] {
                self.attach
                    .ipam
                    .lock()
                    .unwrap()
                    .release(std::net::Ipv6Addr::from(ul));
            }
        }

        // Pool model: the guest-end MOVES BACK to the root netns (as the placeholder `fpg{i}p`) — the
        // pool veth SURVIVES detach for reuse. We must NOT `delete_link` the pool veth (that would
        // destroy the pair and, via the host-end, break that slot's static af_xdp poll set until serve
        // restart). Look up the registry entry to find the netns + the slot's host_name; a missing
        // entry (e.g. partial attach) is fine.
        //
        // CAVEAT (documented first-slice limitation): veth pairs die together. If a pod's netns is
        // destroyed WITHOUT a preceding DetachInterface, the guest-end vanishes and takes the host-end
        // (`fpg{i}`, bound to the af_xdp ethdev port) with it — breaking that pool slot until serve
        // restart. The happy path assumes explicit detach-before-netns-destruction; robust dead-slot
        // reclaim (detect + recreate the veth + rebind the ethdev) is a follow-up ("detach/reuse
        // hardening"), NOT implemented here.
        let dev = self.attach.forget(&id);
        if let Some(dev) = &dev {
            let netns_path = dev.netns_path.clone();
            let placeholder_peer = format!("{}p", dev.host_name);
            let guest_name = String::from_utf8_lossy(&id).into_owned();
            // Drop the JoinError: a `?` here would return BEFORE the slot-free below, leaking the
            // pool slot (bound=Some) while the registry entry is already gone. Detach runs ALL
            // reclaim steps regardless — the unbind is already best-effort/always-Ok internally, so
            // even a task panic must not stop us from freeing the slot for reuse.
            let _ = tokio::task::spawn_blocking(move || {
                // Best-effort: always Ok (see unbind_preallocated_guest_end).
                let _ = flowplane_device::unbind_preallocated_guest_end(
                    &netns_path,
                    &guest_name,
                    &placeholder_peer,
                );
            })
            .await;
        }

        // Free the pool slot for reuse — match by the slot's host ifindex (unique per slot). Prefer
        // the registry device's ifindex; fall back to the map-derived tap ifindex (e.g. registry miss).
        //
        // DEAD-SLOT BRANCH: after the best-effort unbind above, check whether the pool host-end still
        // exists. Normally it survives detach (only the guest-end moved) → free the slot for reuse
        // (`bound = None`, `dead` stays false). But if the pod's netns was destroyed WITHOUT this
        // detach (veth pairs die together → the guest-end took the host-end + its ethdev down), the
        // host-end is GONE: mark the slot `dead = true` instead of freeing it, so attach never binds a
        // blackhole slot (it surfaces as `resource_exhausted` once the live pool drains). Live recovery
        // (recreate the veth + rte_dev hotplug rebind) is a documented follow-up.
        let free_ifindex = dev.as_ref().map(|d| d.host_ifindex).or(tap_ifindex);
        if let Some(ifx) = free_ifindex {
            if let Some(slot) = self
                .attach
                .guest_pool
                .lock()
                .unwrap()
                .iter_mut()
                .find(|s| s.host_ifindex == ifx)
            {
                if flowplane_device::link_exists(&slot.host_ifname) {
                    slot.bound = None;
                } else {
                    slot.dead = true;
                    eprintln!(
                        "warn: guest af_xdp pool slot {} (port {}) is DEAD after detach — host-end \
                         veth is gone (pod netns destroyed without detach; veth pairs die together). \
                         Marking dead + excluding from the free pool; live recovery is a follow-up.",
                        slot.host_ifname, slot.port_id
                    );
                }
            }
        }

        Ok(Response::new(DetachInterfaceResponse {}))
    }

    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        // Read the agnostic interface-meta rows from ControlCore (the DPDK source of truth for the
        // attached set). `underlay_route` is the IPAM-allocated /128 recorded at attach (B2a); it
        // renders as "::" only for a row with no allocated underlay.
        let rows = self.ctrl.lock().iface_meta_rows();
        let interfaces = rows
            .into_iter()
            .map(|(id, vni, ipv4, ipv6, underlay, _ifindex)| InterfaceInfo {
                interface_id: String::from_utf8_lossy(&id).into_owned(),
                vni,
                ipv4: if ipv4 == [0, 0, 0, 0] {
                    String::new()
                } else {
                    std::net::Ipv4Addr::from(ipv4).to_string()
                },
                ipv6: if ipv6 == [0u8; 16] {
                    String::new()
                } else {
                    std::net::Ipv6Addr::from(ipv6).to_string()
                },
                underlay_route: std::net::Ipv6Addr::from(underlay).to_string(),
            })
            .collect();
        Ok(Response::new(ListInterfacesResponse { interfaces }))
    }

    async fn configure_network(
        &self,
        _req: Request<ConfigureNetworkRequest>,
    ) -> Result<Response<ConfigureNetworkResponse>, Status> {
        // Matches the eBPF handler: ConfigureNetwork is an Ok stub (per-VNI network config is derived
        // from AttachInterface + routes, not a distinct map).
        Ok(Response::new(ConfigureNetworkResponse {}))
    }

    async fn add_route(
        &self,
        req: Request<pb::AddRouteRequest>,
    ) -> Result<Response<pb::AddRouteResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_route(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn withdraw_route(
        &self,
        req: Request<pb::WithdrawRouteRequest>,
    ) -> Result<Response<pb::WithdrawRouteResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::withdraw_route(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn add_nat_source(
        &self,
        req: Request<pb::AddNatSourceRequest>,
    ) -> Result<Response<pb::AddNatSourceResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_nat_source(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn withdraw_nat_source(
        &self,
        req: Request<pb::WithdrawNatSourceRequest>,
    ) -> Result<Response<pb::WithdrawNatSourceResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::withdraw_nat_source(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn add_neighbor_nat(
        &self,
        req: Request<pb::AddNeighborNatRequest>,
    ) -> Result<Response<pb::AddNeighborNatResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_neighbor_nat(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn withdraw_neighbor_nat(
        &self,
        req: Request<pb::WithdrawNeighborNatRequest>,
    ) -> Result<Response<pb::WithdrawNeighborNatResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::withdraw_neighbor_nat(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn add_lb_vip(
        &self,
        req: Request<pb::AddLbVipRequest>,
    ) -> Result<Response<pb::AddLbVipResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_lb_vip(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn add_lb_backend(
        &self,
        req: Request<pb::AddLbBackendRequest>,
    ) -> Result<Response<pb::AddLbBackendResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_lb_backend(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn del_lb_vip(
        &self,
        req: Request<pb::DelLbVipRequest>,
    ) -> Result<Response<pb::DelLbVipResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::del_lb_vip(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn del_lb_backend(
        &self,
        req: Request<pb::DelLbBackendRequest>,
    ) -> Result<Response<pb::DelLbBackendResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::del_lb_backend(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn add_fw_rule(
        &self,
        req: Request<pb::AddFwRuleRequest>,
    ) -> Result<Response<pb::AddFwRuleResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_fw_rule(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn del_fw_rule(
        &self,
        req: Request<pb::DelFwRuleRequest>,
    ) -> Result<Response<pb::DelFwRuleResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::del_fw_rule(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }

    async fn configure_qo_s(
        &self,
        req: Request<pb::ConfigureQoSRequest>,
    ) -> Result<Response<pb::ConfigureQoSResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::configure_qos(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
    async fn add_route_programs_shared_maps() {
        let _eal = nfkit::Eal::init(
            [
                "fp_dpdk_node",
                "-l",
                "0-1",
                "--no-huge",
                "-m",
                "512",
                "--no-pci",
                "--file-prefix",
                "fp_dpdk_node",
            ]
            .iter()
            .copied(),
        )
        .unwrap();
        let shared = Arc::new(nfkit::SharedConfigMaps::new(0, 1024).unwrap());
        let ctrl = Arc::new(Mutex::new(ControlCore::new(DpdkMapWriter::new(
            shared.clone(),
        ))));
        // Stub attach state (no real underlay inference needed for this route test).
        let prefix: ipnet::Ipv6Net = "fd00:db8:0:1::/64".parse().unwrap();
        let attach = Arc::new(crate::attach_state::DpdkAttachState {
            ipam: std::sync::Mutex::new(flowplane_device::UnderlayIpam::new(prefix)),
            registry: std::sync::Mutex::new(std::collections::HashMap::new()),
            guest_mtu: 1450,
            gateway_ipv4: [169, 254, 0, 1],
            gateway_ipv6: [0u8; 16],
            guest_pool: std::sync::Mutex::new(Vec::new()),
        });
        let svc = DpdkNodeService::new(ctrl.clone(), shared.clone(), attach);

        let resp = svc
            .add_route(Request::new(pb::AddRouteRequest {
                vni: 7,
                prefix: "10.0.0.1/32".into(),
                nexthop_underlay: "2001::aa".into(),
                external: false,
            }))
            .await;
        assert!(resp.is_ok(), "add_route returned {resp:?}");
        // The route landed in the shared config maps (same path the datapath lcores read).
        assert!(shared.route4_get(7, &[10, 0, 0, 1]).is_some());
    }
}
