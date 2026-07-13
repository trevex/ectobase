use std::sync::Arc;

use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AddRouteRequest, AddRouteResponse, AttachInterfaceRequest, AttachInterfaceResponse,
    ConfigureNetworkRequest, ConfigureNetworkResponse, DetachInterfaceRequest,
    DetachInterfaceResponse, WithdrawRouteRequest, WithdrawRouteResponse,
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

    async fn add_route(
        &self,
        req: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let nexthop = parse_nexthop6(&r.nexthop_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Idempotent: drop any existing (vni, prefix) so a re-announce or a moved prefix
            // replaces the nexthop instead of hitting ROUTE_EXISTS. Remote routes program only
            // ROUTES (no UNDERLAY) so the datapath encaps to `nexthop` (egress.rs falls through
            // to Encap when the nexthop has no local UNDERLAY tap).
            if is_v6 {
                let _ = c.delete_route6(vni, bytes, len)?;
                c.create_route6(vni, bytes, len, nexthop, vni, false)
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                let _ = c.delete_route(vni, v4, len)?;
                c.create_route(vni, v4, len, nexthop, vni, false)
            }
        })
        .await
        .map_err(|e| Status::internal(format!("add_route task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "ROUTE add vni={vni} prefix={} -> nexthop={}",
            r.prefix, r.nexthop_underlay
        );
        Ok(Response::new(AddRouteResponse {}))
    }

    async fn withdraw_route(
        &self,
        req: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            if is_v6 {
                let _ = c.delete_route6(vni, bytes, len)?;
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                let _ = c.delete_route(vni, v4, len)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_route task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("ROUTE withdraw vni={vni} prefix={}", r.prefix);
        Ok(Response::new(WithdrawRouteResponse {}))
    }
}

/// Parse a CIDR string into (is_v6, 16-byte address buffer, prefix_len). For IPv4 the four
/// octets are left-aligned in the buffer (bytes[0..4]); the datapath route helpers take the
/// v4/v6 slices they need. Rejects a missing "/len" and an out-of-range length.
fn parse_prefix(cidr: &str) -> anyhow::Result<(bool, [u8; 16], u32)> {
    use std::net::IpAddr;
    let (addr, len) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("prefix {cidr:?} missing /len"))?;
    let len: u32 = len
        .parse()
        .map_err(|_| anyhow::anyhow!("bad prefix len in {cidr:?}"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("bad address in {cidr:?}"))?;
    let mut buf = [0u8; 16];
    match ip {
        IpAddr::V4(a) => {
            if len > 32 {
                anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}");
            }
            buf[..4].copy_from_slice(&a.octets());
            Ok((false, buf, len))
        }
        IpAddr::V6(a) => {
            if len > 128 {
                anyhow::bail!("v6 prefix len {len} > 128 in {cidr:?}");
            }
            buf.copy_from_slice(&a.octets());
            Ok((true, buf, len))
        }
    }
}

/// Parse an IPv6 nexthop underlay address into 16 bytes.
fn parse_nexthop6(s: &str) -> anyhow::Result<[u8; 16]> {
    let a: std::net::Ipv6Addr = s
        .parse()
        .map_err(|_| anyhow::anyhow!("bad nexthop underlay ipv6 {s:?}"))?;
    Ok(a.octets())
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

    #[test]
    fn parse_prefix_v4_and_v6() {
        // (is_v6, 16-byte buffer with the address left-aligned for v4, prefix_len)
        let (v6, bytes, len) = super::parse_prefix("10.0.0.5/32").unwrap();
        assert!(!v6);
        assert_eq!(&bytes[..4], &[10, 0, 0, 5]);
        assert_eq!(len, 32);

        let (v6, bytes, len) = super::parse_prefix("2001:db8::5/128").unwrap();
        assert!(v6);
        assert_eq!(
            bytes,
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets()
        );
        assert_eq!(len, 128);
    }

    #[test]
    fn parse_prefix_rejects_bad() {
        assert!(super::parse_prefix("10.0.0.5").is_err()); // no /len
        assert!(super::parse_prefix("10.0.0.5/33").is_err()); // v4 len > 32
        assert!(super::parse_prefix("nonsense/32").is_err());
    }
}
