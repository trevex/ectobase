use std::sync::Arc;

use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, DetachInterfaceRequest, DetachInterfaceResponse,
};

use crate::attach::AttachState;

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
        // The datapath work shells out to `ip` and touches eBPF maps (blocking), so run it on the
        // blocking pool to keep the async reactor free.
        let outcome = tokio::task::spawn_blocking(move || {
            attach.attach(
                &r.interface_id,
                &r.netns_path,
                r.vni,
                &r.mac,
                &r.requested_ips,
            )
        })
        .await
        .map_err(|e| Status::internal(format!("attach task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;

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
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DetachInterfaceResponse {}))
    }

    async fn configure_network(
        &self,
        _req: Request<ConfigureNetworkRequest>,
    ) -> Result<Response<ConfigureNetworkResponse>, Status> {
        Ok(Response::new(ConfigureNetworkResponse {}))
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
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
