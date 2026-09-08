use std::sync::Arc;

use tonic::{Request, Response, Status};

pub use crate::pb;
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, ConfigureQoSRequest, ConfigureQoSResponse, DetachInterfaceRequest,
    DetachInterfaceResponse, InterfaceInfo, ListInterfacesRequest, ListInterfacesResponse,
    ReplaceInterfaceFirewallRequest, ReplaceInterfaceFirewallResponse,
};

use crate::attach::AttachState;
use crate::handlers;

/// The DataplaneNode gRPC service. Holds the shared attach state (live datapath control + underlay
/// IPAM) when serving with a datapath; `None` means AttachInterface/DetachInterface are not wired
/// (e.g. a control-plane-less server) and return `failed_precondition`.
#[derive(Default)]
pub struct NodeService {
    attach: Option<Arc<AttachState>>,
}

impl NodeService {
    pub fn new(attach: Arc<AttachState>) -> Self {
        Self {
            attach: Some(attach),
        }
    }
}

#[tonic::async_trait]
impl DataplaneNode for NodeService {
    async fn attach_interface(
        &self,
        req: Request<AttachInterfaceRequest>,
    ) -> Result<Response<AttachInterfaceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let device_type = crate::attach::DeviceType::parse(&r.device_type)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // The datapath work shells out to `ip` and touches eBPF maps (blocking), so run it on the
        // blocking pool to keep the async reactor free.
        let outcome = tokio::task::spawn_blocking(move || {
            attach.attach(
                &r.interface_id,
                &r.netns_path,
                r.vni,
                &r.mac,
                &r.requested_ips,
                device_type,
                &r.tap_name,
                &r.pci_address,
            )
        })
        .await
        .map_err(|e| Status::internal(format!("attach task panicked: {e}")))?
        // Typed boundary: a `ServiceError::Conflict` (ROUTE_EXISTS) becomes `AlreadyExists`, an
        // `Invalid` becomes `InvalidArgument`, and only a genuine `Internal` becomes `Internal`
        // (rendered with the full `{:#}` anyhow context chain — see `From<ServiceError>`). This lets
        // the CNI distinguish a client conflict (don't retry / pick another IP) from a transient
        // fault, instead of auto-retrying every failure as `Internal`.
        .map_err(Status::from)?;

        Ok(Response::new(AttachInterfaceResponse {
            ifname: outcome.ifname,
            ips: outcome.ips,
            mac: outcome.mac,
            gateway: outcome.gateway,
            underlay_route: outcome.underlay_route,
        }))
    }

    async fn detach_interface(
        &self,
        req: Request<DetachInterfaceRequest>,
    ) -> Result<Response<DetachInterfaceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let id = req.into_inner().interface_id;
        tokio::task::spawn_blocking(move || attach.detach(&id))
            .await
            .map_err(|e| Status::internal(format!("detach task panicked: {e}")))?
            .map_err(Status::from)?;
        Ok(Response::new(DetachInterfaceResponse {}))
    }

    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let rows = tokio::task::spawn_blocking(move || attach.control.list_interfaces())
            .await
            .map_err(|e| Status::internal(format!("list task panicked: {e}")))?;
        let interfaces = rows
            .into_iter()
            .map(|(id, vni, ipv4, ipv6, underlay, _device)| InterfaceInfo {
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
        Ok(Response::new(ConfigureNetworkResponse {}))
    }

    async fn add_route(
        &self,
        req: Request<pb::AddRouteRequest>,
    ) -> Result<Response<pb::AddRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "ROUTE add vni={} prefix={} -> nexthop={} external={}",
            r.vni, r.prefix, r.nexthop_underlay, r.external
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::add_route(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_route task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn withdraw_route(
        &self,
        req: Request<pb::WithdrawRouteRequest>,
    ) -> Result<Response<pb::WithdrawRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!("ROUTE withdraw vni={} prefix={}", r.vni, r.prefix);
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::withdraw_route(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_route task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn add_nat_source(
        &self,
        req: Request<pb::AddNatSourceRequest>,
    ) -> Result<Response<pb::AddNatSourceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "NAT source vni={} src={} -> nat_ip={} ports={}..{}",
            r.vni, r.source_ip, r.nat_ip, r.port_min, r.port_max
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::add_nat_source(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_nat_source task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn withdraw_nat_source(
        &self,
        req: Request<pb::WithdrawNatSourceRequest>,
    ) -> Result<Response<pb::WithdrawNatSourceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!("NAT source withdraw vni={} src={}", r.vni, r.source_ip);
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::withdraw_nat_source(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_nat_source task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn add_neighbor_nat(
        &self,
        req: Request<pb::AddNeighborNatRequest>,
    ) -> Result<Response<pb::AddNeighborNatResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "NEIGHBOR_NAT add vni={} nat_ip={} ports={}..{} -> owner={}",
            r.vni, r.nat_ip, r.port_min, r.port_max, r.owner_underlay
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::add_neighbor_nat(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_neighbor_nat task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn withdraw_neighbor_nat(
        &self,
        req: Request<pb::WithdrawNeighborNatRequest>,
    ) -> Result<Response<pb::WithdrawNeighborNatResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "NEIGHBOR_NAT withdraw vni={} nat_ip={} ports={}..{}",
            r.vni, r.nat_ip, r.port_min, r.port_max
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::withdraw_neighbor_nat(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_neighbor_nat task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn add_lb_vip(
        &self,
        req: Request<pb::AddLbVipRequest>,
    ) -> Result<Response<pb::AddLbVipResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "LB VIP add id={} vni={} vip={} lb_underlay={} ports={:?}",
            r.id, r.vni, r.vip, r.lb_underlay, r.ports
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::add_lb_vip(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_lb_vip task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn add_lb_backend(
        &self,
        req: Request<pb::AddLbBackendRequest>,
    ) -> Result<Response<pb::AddLbBackendResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "LB backend add id={} backend={} overlay={} vni={}",
            r.id, r.backend_underlay, r.backend_overlay_ip, r.backend_vni
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::add_lb_backend(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_lb_backend task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn del_lb_vip(
        &self,
        req: Request<pb::DelLbVipRequest>,
    ) -> Result<Response<pb::DelLbVipResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!("LB VIP del id={}", r.id);
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::del_lb_vip(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("del_lb_vip task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn del_lb_backend(
        &self,
        req: Request<pb::DelLbBackendRequest>,
    ) -> Result<Response<pb::DelLbBackendResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!("LB backend del id={} backend={}", r.id, r.backend_underlay);
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::del_lb_backend(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("del_lb_backend task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn add_fw_rule(
        &self,
        req: Request<pb::AddFwRuleRequest>,
    ) -> Result<Response<pb::AddFwRuleResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "FW rule add iface={} id={} src={} dst={} proto={} dports={}..={} allow={} egress={}",
            r.interface_id,
            r.rule_id,
            r.src_cidr,
            r.dst_cidr,
            r.proto,
            r.dst_port_min,
            r.dst_port_max,
            r.allow,
            r.egress
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::add_fw_rule(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("add_fw_rule task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn del_fw_rule(
        &self,
        req: Request<pb::DelFwRuleRequest>,
    ) -> Result<Response<pb::DelFwRuleResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!("FW rule del iface={} id={}", r.interface_id, r.rule_id);
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::del_fw_rule(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("del_fw_rule task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn replace_interface_firewall(
        &self,
        req: Request<ReplaceInterfaceFirewallRequest>,
    ) -> Result<Response<ReplaceInterfaceFirewallResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "FW replace iface={} rules={}",
            r.interface_id,
            r.rules.len()
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| handlers::replace_interface_firewall(c, &r))
        })
        .await
        .map_err(|e| {
            Status::internal(format!("replace_interface_firewall task panicked: {e}"))
        })??;
        println!("{log}");
        Ok(Response::new(resp))
    }

    async fn configure_qo_s(
        &self,
        req: Request<ConfigureQoSRequest>,
    ) -> Result<Response<ConfigureQoSResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let log = format!(
            "QOS configure iface={} egress_mbps={} public_mbps={} ingress_mbps={}",
            r.interface_id, r.egress_mbps as u64, r.public_mbps as u64, r.ingress_mbps as u64
        );
        let resp = tokio::task::spawn_blocking(move || {
            attach.control.with_core(|c| handlers::configure_qos(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("configure_qos task panicked: {e}")))??;
        println!("{log}");
        Ok(Response::new(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn configure_network_returns_ok() {
        let svc = NodeService::default();
        let resp = svc
            .configure_network(Request::new(ConfigureNetworkRequest {
                vni: 100,
                gateway: "169.254.0.1".into(),
                mtu: 1450,
                dns: vec![],
            }))
            .await
            .unwrap();
        let _ = resp.into_inner();
    }

    #[tokio::test]
    async fn attach_without_datapath_is_failed_precondition() {
        let svc = NodeService::default();
        let err = svc
            .attach_interface(Request::new(AttachInterfaceRequest {
                interface_id: "t0".into(),
                netns_path: "/var/run/netns/x".into(),
                vni: 100,
                mac: String::new(),
                requested_ips: vec!["10.0.0.10".into()],
                device_type: String::new(),
                tap_name: String::new(),
                pci_address: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
