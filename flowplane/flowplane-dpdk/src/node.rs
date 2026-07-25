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
}

impl DpdkNodeService {
    #[must_use]
    pub fn new(
        ctrl: Arc<Mutex<ControlCore<DpdkMapWriter>>>,
        shared: Arc<SharedConfigMaps>,
    ) -> Self {
        Self { ctrl, shared }
    }
}

#[tonic::async_trait]
impl DataplaneNode for DpdkNodeService {
    async fn attach_interface(
        &self,
        req: Request<AttachInterfaceRequest>,
    ) -> Result<Response<AttachInterfaceResponse>, Status> {
        let r = req.into_inner();
        // Program the AGNOSTIC map half so the config tables (PORT_META/INTERFACES/UNDERLAY/routes/
        // IFACE_META) are populated + exercised by parity fixtures. The DPDK host-device step (tap/
        // veth creation, real ifindex/MAC + underlay IPAM) is B2, so the device-derived fields the
        // eBPF attach resolves are stubbed here: tap ifindex 0, the requested MAC as effective MAC,
        // and a zero underlay when unset. A B2-complete attach re-runs this with real values
        // (idempotent upserts overwrite), so this leaves no harmful orphan state.
        let ipv4 = first_ipv4(&r.requested_ips);
        let ipv6 = first_ipv6(&r.requested_ips);
        let effective_mac = if r.mac.is_empty() {
            [0u8; 6]
        } else {
            parse_mac(&r.mac).map_err(|e| Status::invalid_argument(e.to_string()))?
        };
        {
            let mut core = self.ctrl.lock();
            core.program_interface(IfaceParams {
                interface_id: r.interface_id.clone().into_bytes(),
                device: String::new(),
                tap: 0,
                effective_mac,
                vni: r.vni,
                ipv4,
                ipv6,
                gateway_ipv4: [0u8; 4],
                gateway_ipv6: [0u8; 16],
                underlay_ipv6: [0u8; 16],
                total_mbps: 0,
                public_mbps: 0,
            })
            .map_err(|e| Status::internal(e.to_string()))?;
            core.register_iface_meta(
                r.interface_id.clone().into_bytes(),
                IfaceMeta {
                    vni: r.vni,
                    ipv4,
                    ipv6,
                    underlay: [0u8; 16],
                    ifindex: 0,
                },
            );
        }
        // The agnostic maps are programmed; the physical device does NOT exist yet. Signal
        // Unimplemented rather than return a bogus AttachInterfaceResponse (B2 stands the tap/veth up
        // and returns the real ifname/ips/underlay).
        Err(Status::unimplemented(
            "DPDK host-device attach is B2 (agnostic maps programmed)",
        ))
    }

    async fn detach_interface(
        &self,
        req: Request<DetachInterfaceRequest>,
    ) -> Result<Response<DetachInterfaceResponse>, Status> {
        let id = req.into_inner().interface_id.into_bytes();
        // Undo the agnostic map half: purge the interface's VNI state (neigh-NAT/VIP/NAT/routes for
        // its guest IP) + drop its meta record. Symmetric with attach; the device teardown (tap/veth
        // destroy) is B2. Purge is best-effort against whatever attach programmed.
        {
            let mut core = self.ctrl.lock();
            if let Some((vni, ipv4)) = core
                .iface_meta_rows()
                .into_iter()
                .find(|(rid, ..)| rid.as_slice() == id.as_slice())
                .map(|(_, vni, ipv4, ..)| (vni, ipv4))
            {
                core.purge_vni(vni, ipv4)
                    .map_err(|e| Status::internal(e.to_string()))?;
            }
            core.forget_iface_meta(&id);
        }
        // Agnostic state torn down; the physical device teardown is B2.
        Err(Status::unimplemented(
            "DPDK host-device detach is B2 (agnostic maps purged)",
        ))
    }

    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        // Read the agnostic interface-meta rows from ControlCore (the DPDK source of truth for the
        // attached set). NOTE: on DPDK the underlay is B2 (not yet IPAM-allocated), so `underlay_route`
        // renders as "::" until B2 wires real underlay allocation; vni + overlay IPs are populated.
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
        let svc = DpdkNodeService::new(ctrl.clone(), shared.clone());

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
