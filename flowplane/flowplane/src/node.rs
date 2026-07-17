use std::sync::Arc;

use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AddFwRuleRequest, AddFwRuleResponse, AddLbBackendRequest, AddLbBackendResponse,
    AddLbVipRequest, AddLbVipResponse, AddNatSourceRequest, AddNatSourceResponse,
    AddNeighborNatRequest, AddNeighborNatResponse, AddRouteRequest, AddRouteResponse,
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, DelFwRuleRequest, DelFwRuleResponse, DelLbBackendRequest,
    DelLbBackendResponse, DelLbVipRequest, DelLbVipResponse, DetachInterfaceRequest,
    DetachInterfaceResponse, WithdrawNatSourceRequest, WithdrawNatSourceResponse,
    WithdrawNeighborNatRequest, WithdrawNeighborNatResponse, WithdrawRouteRequest,
    WithdrawRouteResponse,
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
        let external = r.external;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Idempotent: drop any existing (vni, prefix) so a re-announce or a moved prefix
            // replaces the nexthop instead of hitting ROUTE_EXISTS. Remote routes program only
            // ROUTES (no UNDERLAY) so the datapath encaps to `nexthop` (egress.rs falls through
            // to Encap when the nexthop has no local UNDERLAY tap).
            if is_v6 {
                let _ = c.delete_route6(vni, bytes, len)?;
                c.create_route6(vni, bytes, len, nexthop, vni, external)
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                let _ = c.delete_route(vni, v4, len)?;
                c.create_route(vni, v4, len, nexthop, vni, external)
            }
        })
        .await
        .map_err(|e| Status::internal(format!("add_route task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "ROUTE add vni={vni} prefix={} -> nexthop={} external={external}",
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

    async fn add_nat_source(
        &self,
        req: Request<AddNatSourceRequest>,
    ) -> Result<Response<AddNatSourceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let source =
            parse_ipv4(&r.source_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // create_nat is keyed by interface_id; resolve (vni, source) -> id from the
            // attached interfaces. The source must be locally attached (a source endpoint on
            // this gateway) for the SNAT block to be owned here.
            let id = find_interface_id(c, vni, source)?;
            // Idempotent: drop any existing NAT on this source so a re-announce or a moved
            // block replaces it instead of hitting SNAT_EXISTS.
            let _ = c.delete_nat(&id)?;
            c.create_nat(&id, nat_ip, port_min, port_max, None)?;
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("add_nat_source task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "NAT source vni={vni} src={} -> nat_ip={} ports={}..{}",
            r.source_ip, r.nat_ip, r.port_min, r.port_max
        );
        Ok(Response::new(AddNatSourceResponse {}))
    }

    async fn withdraw_nat_source(
        &self,
        req: Request<WithdrawNatSourceRequest>,
    ) -> Result<Response<WithdrawNatSourceResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let source =
            parse_ipv4(&r.source_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Removing an absent source is not an error: if the interface is gone or has no NAT,
            // treat it as already withdrawn.
            if let Ok(id) = find_interface_id(c, vni, source) {
                let _ = c.delete_nat(&id)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_nat_source task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("NAT source withdraw vni={vni} src={}", r.source_ip);
        Ok(Response::new(WithdrawNatSourceResponse {}))
    }

    async fn add_neighbor_nat(
        &self,
        req: Request<AddNeighborNatRequest>,
    ) -> Result<Response<AddNeighborNatResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let owner = parse_nexthop6(&r.owner_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Idempotent: drop any existing entry for this (vni, nat_ip, ports) first so a
            // re-announce (e.g. block reassignment on drain) replaces the owner underlay.
            let _ = c.del_neighbor_nat(vni, nat_ip, port_min, port_max)?;
            c.add_neighbor_nat(vni, nat_ip, port_min, port_max, owner)?;
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("add_neighbor_nat task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "NEIGHBOR_NAT add vni={vni} nat_ip={} ports={}..{} -> owner={}",
            r.nat_ip, r.port_min, r.port_max, r.owner_underlay
        );
        Ok(Response::new(AddNeighborNatResponse {}))
    }

    async fn withdraw_neighbor_nat(
        &self,
        req: Request<WithdrawNeighborNatRequest>,
    ) -> Result<Response<WithdrawNeighborNatResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Removing an absent entry is not an error (del_neighbor_nat returns Ok(false)).
            let _ = c.del_neighbor_nat(vni, nat_ip, port_min, port_max)?;
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_neighbor_nat task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "NEIGHBOR_NAT withdraw vni={vni} nat_ip={} ports={}..{}",
            r.nat_ip, r.port_min, r.port_max
        );
        Ok(Response::new(WithdrawNeighborNatResponse {}))
    }

    async fn add_lb_vip(
        &self,
        req: Request<AddLbVipRequest>,
    ) -> Result<Response<AddLbVipResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let lb_ip: crate::grpc::LbIpBytes = match r.vip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => crate::grpc::LbIpBytes::Ipv4(a.octets()),
            Ok(std::net::IpAddr::V6(a)) => crate::grpc::LbIpBytes::Ipv6(a.octets()),
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "invalid vip {:?}: {e}",
                    r.vip
                )))
            }
        };
        let lb_underlay =
            parse_nexthop6(&r.lb_underlay).map_err(|e| Status::invalid_argument(e.to_string()))?;
        // (port, proto) services: proto is the IP protocol number (6=TCP, 17=UDP, 1=ICMP).
        let ports: Vec<(u16, u8)> = r
            .ports
            .iter()
            .map(|pp| -> anyhow::Result<(u16, u8)> {
                let port = port_u16(pp.port)?;
                let proto = u8::try_from(pp.proto)
                    .map_err(|_| anyhow::anyhow!("proto {} > 255", pp.proto))?;
                Ok((port, proto))
            })
            .collect::<anyhow::Result<_>>()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = r.id.clone().into_bytes();
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            attach
                .control
                .create_lb(&id, vni, lb_ip, lb_underlay, ports)
        })
        .await
        .map_err(|e| Status::internal(format!("add_lb_vip task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "LB VIP add id={} vni={vni} vip={} lb_underlay={} ports={:?}",
            r.id, r.vip, r.lb_underlay, r.ports
        );
        Ok(Response::new(AddLbVipResponse {}))
    }

    async fn add_lb_backend(
        &self,
        req: Request<AddLbBackendRequest>,
    ) -> Result<Response<AddLbBackendResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let backend = parse_nexthop6(&r.backend_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = r.id.clone().into_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            attach.control.add_lb_target(&id, backend)
        })
        .await
        .map_err(|e| Status::internal(format!("add_lb_backend task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("LB backend add id={} backend={}", r.id, r.backend_underlay);
        Ok(Response::new(AddLbBackendResponse {}))
    }

    async fn del_lb_vip(
        &self,
        req: Request<DelLbVipRequest>,
    ) -> Result<Response<DelLbVipResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let id = r.id.clone().into_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            attach.control.delete_lb(&id)
        })
        .await
        .map_err(|e| Status::internal(format!("del_lb_vip task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("LB VIP del id={}", r.id);
        Ok(Response::new(DelLbVipResponse {}))
    }

    async fn del_lb_backend(
        &self,
        req: Request<DelLbBackendRequest>,
    ) -> Result<Response<DelLbBackendResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let backend = parse_nexthop6(&r.backend_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = r.id.clone().into_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            attach.control.del_lb_target(&id, backend)
        })
        .await
        .map_err(|e| Status::internal(format!("del_lb_backend task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("LB backend del id={} backend={}", r.id, r.backend_underlay);
        Ok(Response::new(DelLbBackendResponse {}))
    }

    async fn add_fw_rule(
        &self,
        req: Request<AddFwRuleRequest>,
    ) -> Result<Response<AddFwRuleResponse>, Status> {
        use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let (src_ip, src_mask) =
            parse_fw_cidr(&r.src_cidr).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let (dst_ip, dst_mask) =
            parse_fw_cidr(&r.dst_cidr).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let proto = u8::try_from(r.proto).map_err(|_| Status::invalid_argument("proto > 255"))?;
        let dst_port_min =
            port_u16(r.dst_port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        // dst_port_max of 0 means "unbounded" -> 65535 (0/0 = any port).
        let dst_port_max = if r.dst_port_max == 0 {
            65535u16
        } else {
            port_u16(r.dst_port_max).map_err(|e| Status::invalid_argument(e.to_string()))?
        };
        let rule = flowplane_common::FwRule {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min,
            dst_port_max,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto,
            action: if r.allow {
                FW_ACTION_ACCEPT
            } else {
                FW_ACTION_DROP
            },
            direction: if r.egress {
                FW_DIR_EGRESS
            } else {
                FW_DIR_INGRESS
            },
            enabled: 1,
        };
        let iface = r.interface_id.clone().into_bytes();
        let rule_id = r.rule_id.clone().into_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            attach.control.add_fw_rule(&iface, rule_id, rule)
        })
        .await
        .map_err(|e| Status::internal(format!("add_fw_rule task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "FW rule add iface={} id={} src={} dst={} proto={} dports={}..={} allow={} egress={}",
            r.interface_id,
            r.rule_id,
            r.src_cidr,
            r.dst_cidr,
            r.proto,
            dst_port_min,
            dst_port_max,
            r.allow,
            r.egress
        );
        Ok(Response::new(AddFwRuleResponse {}))
    }

    async fn del_fw_rule(
        &self,
        req: Request<DelFwRuleRequest>,
    ) -> Result<Response<DelFwRuleResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let iface = r.interface_id.clone().into_bytes();
        let rule_id = r.rule_id.clone().into_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            attach.control.del_fw_rule(&iface, &rule_id)
        })
        .await
        .map_err(|e| Status::internal(format!("del_fw_rule task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("FW rule del iface={} id={}", r.interface_id, r.rule_id);
        Ok(Response::new(DelFwRuleResponse {}))
    }
}

/// Resolve a locally-attached interface id from `(vni, ipv4)`. `create_nat`/`delete_nat` are keyed
/// by interface id, but the protocol-agnostic RPCs identify a source by its overlay (vni, ip); the
/// attach table is the bridge. Errors if no local interface matches (SNAT is owned where the source
/// is attached).
fn find_interface_id(
    control: &crate::control::Control,
    vni: u32,
    ipv4: [u8; 4],
) -> anyhow::Result<Vec<u8>> {
    control
        .list_interfaces()
        .into_iter()
        .find(|(_, v, ip, _, _, _)| *v == vni && *ip == ipv4)
        .map(|(id, ..)| id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "NO_VM: no local interface for vni={vni} ip={}.{}.{}.{}",
                ipv4[0],
                ipv4[1],
                ipv4[2],
                ipv4[3]
            )
        })
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

/// Parse an IPv4 firewall CIDR (e.g. "10.0.0.0/24", "0.0.0.0/0") into `(ip, mask)`. An empty
/// string means "any" (0.0.0.0/0). A bare address without "/len" is treated as a /32 host match.
fn parse_fw_cidr(cidr: &str) -> anyhow::Result<([u8; 4], [u8; 4])> {
    if cidr.is_empty() {
        return Ok(([0u8; 4], [0u8; 4]));
    }
    let (addr, len) = match cidr.split_once('/') {
        Some((a, l)) => (
            a,
            l.parse::<u32>()
                .map_err(|_| anyhow::anyhow!("bad prefix len in {cidr:?}"))?,
        ),
        None => (cidr, 32u32),
    };
    if len > 32 {
        anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}");
    }
    let ip: std::net::Ipv4Addr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("bad ipv4 address in {cidr:?}"))?;
    let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Ok((ip.octets(), mask.to_be_bytes()))
}

/// Parse an IPv6 nexthop underlay address into 16 bytes.
fn parse_nexthop6(s: &str) -> anyhow::Result<[u8; 16]> {
    let a: std::net::Ipv6Addr = s
        .parse()
        .map_err(|_| anyhow::anyhow!("bad nexthop underlay ipv6 {s:?}"))?;
    Ok(a.octets())
}

/// Parse an IPv4 address string into its four octets.
fn parse_ipv4(s: &str) -> anyhow::Result<[u8; 4]> {
    let a: std::net::Ipv4Addr = s.parse().map_err(|_| anyhow::anyhow!("bad ipv4 {s:?}"))?;
    Ok(a.octets())
}

/// Narrow a proto `uint32` port into a `u16`, rejecting out-of-range values.
fn port_u16(p: u32) -> anyhow::Result<u16> {
    u16::try_from(p).map_err(|_| anyhow::anyhow!("port {p} out of range (0..=65535)"))
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
