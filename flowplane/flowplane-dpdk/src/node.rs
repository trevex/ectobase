//! `DpdkNodeService` — the DPDK `DataplaneNode` gRPC service.
//!
//! The DPDK sibling of the eBPF `flowplane::node::NodeService`. Every backend-agnostic RPC
//! (routes / NAT / neighbor-NAT / LB / firewall / QoS) is thin proto→args marshalling that drives
//! the SAME `flowplane_control::ControlCore` orchestration the eBPF binary runs — only the write
//! surface differs (`DpdkMapWriter` over `SharedConfigMaps` vs the eBPF `AyaWriter`). The
//! orchestration is single-source: handlers NEVER reimplement route/nat/lb/fw logic, they call the
//! ControlCore method 1:1 with the eBPF handler (the [[seam-not-duplicate-for-tests]] invariant).
//!
//! ── ATTACH/DETACH (B1b vs B2 boundary) ─────────────────────────────────────────────────────────
//! `AttachInterface`/`DetachInterface` program the AGNOSTIC map half via ControlCore (so the config
//! tables — PORT_META/INTERFACES/UNDERLAY/routes/IFACE_META, or the VNI purge — are exercised by
//! tests and byte-parity fixtures), then return `Unimplemented`: the DPDK host-device step (creating
//! the physical tap/veth, resolving the real ifindex/MAC, IPAM of the underlay /128) is deferred to
//! B2. We signal `Unimplemented` rather than falsely claim an interface stood up. Re-attach is
//! idempotent at the ControlCore level (upserts replace), so programming the agnostic half before the
//! Unimplemented return leaves no harmful orphan state — a subsequent B2-complete attach overwrites
//! it. See the per-method comments.
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
use flowplane_control::{ControlCore, IfaceParams};
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
        // Deterministic host-side veth name (mirrors eBPF `AttachState::host_veth_name`).
        let host_name = crate::attach_state::host_veth_name(&r.interface_id);
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

        // Create the veth pair off-thread (shells out to `ip`; must not block the tokio worker).
        let spec = flowplane_device::VethSpec {
            host_name: host_name.clone(),
            guest_name: guest_name.clone(),
            netns_path: r.netns_path.clone(),
            mac,
            mtu: attach.guest_mtu,
            disable_csum_offload: false, // real NIC finalizes csum; clab detection is a follow-up
        };
        let info =
            match tokio::task::spawn_blocking(move || flowplane_device::create_veth_pair(&spec))
                .await
                .map_err(|e| Status::internal(format!("attach task panicked: {e}")))?
            {
                Ok(info) => info,
                Err(e) => {
                    // Roll back the IPAM allocation so the /128 isn't leaked.
                    attach
                        .ipam
                        .lock()
                        .unwrap()
                        .release(std::net::Ipv6Addr::from(underlay));
                    return Err(Status::internal(format!("create veth: {e}")));
                }
            };

        // Program the shared maps with REAL device-resolved values under the ctrl lock.
        // The lock is taken, the sync ControlCore call runs, and the lock is DROPPED before any
        // .await (parking_lot guards are not async-aware).
        {
            let mut core = self.ctrl.lock();
            if let Err(e) = core.program_interface(IfaceParams {
                interface_id: r.interface_id.clone().into_bytes(),
                device: info.host_name.clone(),
                tap: info.host_ifindex,
                effective_mac: info.mac,
                vni: r.vni,
                ipv4,
                ipv6,
                gateway_ipv4: attach.gateway_ipv4,
                gateway_ipv6: attach.gateway_ipv6,
                underlay_ipv6: underlay,
                total_mbps: 0,
                public_mbps: 0,
            }) {
                // Roll back: drop the ctrl lock FIRST, then delete the veth (best-effort, shells
                // out) + release the IPAM slot — never block on a subprocess under the lock.
                drop(core);
                flowplane_device::delete_link(&info.host_name);
                attach
                    .ipam
                    .lock()
                    .unwrap()
                    .release(std::net::Ipv6Addr::from(underlay));
                return Err(Status::internal(e.to_string()));
            }
            core.register_iface_meta(
                r.interface_id.clone().into_bytes(),
                IfaceMeta {
                    vni: r.vni,
                    ipv4,
                    ipv6,
                    underlay,
                    ifindex: info.host_ifindex,
                },
            );
        } // ctrl lock dropped here

        // Register the live device so detach can tear it down and B2b can af_xdp-bind it.
        attach.register(
            r.interface_id.clone().into_bytes(),
            crate::attach_state::AttachedDevice {
                host_ifindex: info.host_ifindex,
                host_name: info.host_name.clone(),
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
        if let Err(e) =
            tokio::task::spawn_blocking(move || flowplane_device::configure_guest_netns(&cfg))
                .await
                .map_err(|e| Status::internal(format!("guest-netns task panicked: {e}")))?
        {
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
                core.forget_iface_meta(&id);
            } // ctrl lock dropped before the subprocess below
            flowplane_device::delete_link(&info.host_name);
            attach
                .ipam
                .lock()
                .unwrap()
                .release(std::net::Ipv6Addr::from(underlay));
            attach.forget(&id);
            return Err(Status::internal(format!("configure guest netns: {e}")));
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

        // Undo the agnostic map half: purge the interface's VNI state + drop its meta record.
        // Best-effort: run ALL reclaim steps regardless of a purge error.
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

        // Tear down the host-side veth (its guest peer in the netns goes with it). Look up the
        // registry entry for the device name; a missing entry (e.g. partial attach) is fine.
        if let Some(dev) = self.attach.forget(&id) {
            let host_name = dev.host_name.clone();
            tokio::task::spawn_blocking(move || flowplane_device::delete_link(&host_name))
                .await
                .map_err(|e| Status::internal(format!("detach task panicked: {e}")))?;
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
