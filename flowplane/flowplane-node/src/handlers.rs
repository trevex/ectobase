//! Per-RPC marshalling fns shared by both DataplaneNode services. Each parses its `pb` request,
//! drives the SAME `ControlCore` calls the eBPF + DPDK handlers used, and builds the response —
//! side-effect-free apart from the ControlCore writes (no logging, no tonic transport), so each is
//! unit-testable directly against a `ControlCore<MemMapWriter>`.

use flowplane_control::{shadow::LbIpBytes, ControlCore, MapWriter};
use tonic::Status;

use crate::parse::{parse_fw_cidr, parse_ipv4, parse_nexthop6, parse_prefix, port_u16};
use crate::pb;

#[inline]
fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}
#[inline]
fn invalid(e: impl std::fmt::Display) -> Status {
    Status::invalid_argument(e.to_string())
}

pub fn add_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddRouteRequest,
) -> Result<pb::AddRouteResponse, Status> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    let nexthop = parse_nexthop6(&req.nexthop_underlay).map_err(invalid)?;
    let vni = req.vni;
    let external = req.external;
    // Idempotent: drop any existing (vni, prefix) so a re-announce or moved prefix replaces
    // the nexthop instead of hitting ROUTE_EXISTS (identical to the eBPF handler).
    let res: anyhow::Result<()> = if is_v6 {
        core.delete_route6(vni, bytes, len)
            .and_then(|_| core.create_route6(vni, bytes, len, nexthop, vni, external))
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        core.delete_route(vni, v4, len)
            .and_then(|_| core.create_route(vni, v4, len, nexthop, vni, external))
    };
    res.map_err(internal)?;
    Ok(pb::AddRouteResponse {})
}

pub fn withdraw_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawRouteRequest,
) -> Result<pb::WithdrawRouteResponse, Status> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    let vni = req.vni;
    let res: anyhow::Result<()> = if is_v6 {
        core.delete_route6(vni, bytes, len).map(|_| ())
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        core.delete_route(vni, v4, len).map(|_| ())
    };
    res.map_err(internal)?;
    Ok(pb::WithdrawRouteResponse {})
}

pub fn add_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNatSourceRequest,
) -> Result<pb::AddNatSourceResponse, Status> {
    let source = parse_ipv4(&req.source_ip).map_err(invalid)?;
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Resolve (vni, source) -> interface id via the ControlCore accessor (the eBPF handler's
    // `find_interface_id` seam), then delete-then-create NAT idempotently.
    let id = core.find_iface_by_vni_ipv4(vni, source).ok_or_else(|| {
        Status::internal(format!(
            "NO_VM: no local interface for vni={vni} ip={}",
            std::net::Ipv4Addr::from(source)
        ))
    })?;
    let res: anyhow::Result<()> = core.delete_nat(&id).and_then(|_| {
        core.create_nat(&id, nat_ip, port_min, port_max, None)
            .map(|_| ())
    });
    res.map_err(internal)?;
    Ok(pb::AddNatSourceResponse {})
}

pub fn withdraw_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNatSourceRequest,
) -> Result<pb::WithdrawNatSourceResponse, Status> {
    let source = parse_ipv4(&req.source_ip).map_err(invalid)?;
    let vni = req.vni;
    // Removing an absent source is not an error (mirror the eBPF handler): if the interface is
    // gone or has no NAT, treat it as already withdrawn.
    if let Some(id) = core.find_iface_by_vni_ipv4(vni, source) {
        core.delete_nat(&id).map_err(internal)?;
    }
    Ok(pb::WithdrawNatSourceResponse {})
}

pub fn add_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNeighborNatRequest,
) -> Result<pb::AddNeighborNatResponse, Status> {
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let owner = parse_nexthop6(&req.owner_underlay).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Idempotent: drop any existing entry for this (vni, nat_ip, ports) first so a re-announce
    // replaces the owner underlay.
    let res: anyhow::Result<()> = core
        .del_neighbor_nat(vni, nat_ip, port_min, port_max)
        .and_then(|_| core.add_neighbor_nat(vni, nat_ip, port_min, port_max, owner));
    res.map_err(internal)?;
    Ok(pb::AddNeighborNatResponse {})
}

pub fn withdraw_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNeighborNatRequest,
) -> Result<pb::WithdrawNeighborNatResponse, Status> {
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Removing an absent entry is not an error (del_neighbor_nat returns Ok(false)).
    core.del_neighbor_nat(vni, nat_ip, port_min, port_max)
        .map_err(internal)?;
    Ok(pb::WithdrawNeighborNatResponse {})
}

pub fn add_lb_vip<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLbVipRequest,
) -> Result<pb::AddLbVipResponse, Status> {
    let lb_ip: LbIpBytes = match req.vip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => LbIpBytes::Ipv4(a.octets()),
        Ok(std::net::IpAddr::V6(a)) => LbIpBytes::Ipv6(a.octets()),
        Err(e) => {
            return Err(Status::invalid_argument(format!(
                "invalid vip {:?}: {e}",
                req.vip
            )))
        }
    };
    let lb_underlay = parse_nexthop6(&req.lb_underlay).map_err(invalid)?;
    // (port, proto) services: proto is the IP protocol number (6=TCP, 17=UDP, 1=ICMP).
    let ports: Vec<(u16, u8)> = req
        .ports
        .iter()
        .map(|pp| -> anyhow::Result<(u16, u8)> {
            let port = port_u16(pp.port)?;
            let proto =
                u8::try_from(pp.proto).map_err(|_| anyhow::anyhow!("proto {} > 255", pp.proto))?;
            Ok((port, proto))
        })
        .collect::<anyhow::Result<_>>()
        .map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    let vni = req.vni;
    core.create_lb(&id, vni, lb_ip, lb_underlay, ports)
        .map_err(internal)?;
    Ok(pb::AddLbVipResponse {})
}

pub fn add_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLbBackendRequest,
) -> Result<pb::AddLbBackendResponse, Status> {
    let backend = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    core.add_lb_target(&id, backend).map_err(internal)?;
    Ok(pb::AddLbBackendResponse {})
}

pub fn del_lb_vip<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLbVipRequest,
) -> Result<pb::DelLbVipResponse, Status> {
    let id = req.id.clone().into_bytes();
    core.delete_lb(&id).map_err(internal)?;
    Ok(pb::DelLbVipResponse {})
}

pub fn del_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLbBackendRequest,
) -> Result<pb::DelLbBackendResponse, Status> {
    let backend = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    core.del_lb_target(&id, backend).map_err(internal)?;
    Ok(pb::DelLbBackendResponse {})
}

pub fn add_fw_rule<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddFwRuleRequest,
) -> Result<pb::AddFwRuleResponse, Status> {
    use crate::parse::FwCidr;
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
    let src = parse_fw_cidr(&req.src_cidr).map_err(invalid)?;
    let dst = parse_fw_cidr(&req.dst_cidr).map_err(invalid)?;
    let proto = u8::try_from(req.proto).map_err(|_| Status::invalid_argument("proto > 255"))?;
    let dst_port_min = port_u16(req.dst_port_min).map_err(invalid)?;
    // dst_port_max of 0 means "unbounded" -> 65535 (0/0 = any port).
    let dst_port_max = if req.dst_port_max == 0 {
        65535u16
    } else {
        port_u16(req.dst_port_max).map_err(invalid)?
    };
    let action = if req.allow {
        FW_ACTION_ACCEPT
    } else {
        FW_ACTION_DROP
    };
    let direction = if req.egress {
        FW_DIR_EGRESS
    } else {
        FW_DIR_INGRESS
    };
    let iface = req.interface_id.clone().into_bytes();
    let rule_id = req.rule_id.clone().into_bytes();
    // v6 rule if EITHER side is v6; the wildcard opposite side is re-encoded in the same family.
    if matches!(src, FwCidr::V6(..)) || matches!(dst, FwCidr::V6(..)) {
        let (src_ip, src_mask) = match src {
            FwCidr::V6(i, m) => (i, m),
            FwCidr::V4(..) => ([0u8; 16], [0u8; 16]),
        };
        let (dst_ip, dst_mask) = match dst {
            FwCidr::V6(i, m) => (i, m),
            FwCidr::V4(..) => ([0u8; 16], [0u8; 16]),
        };
        let rule = flowplane_common::FwRule6 {
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
            action,
            direction,
            enabled: 1,
        };
        core.add_fw_rule6(&iface, rule_id, rule).map_err(internal)?;
    } else {
        let (src_ip, src_mask) = match src {
            FwCidr::V4(i, m) => (i, m),
            _ => unreachable!(),
        };
        let (dst_ip, dst_mask) = match dst {
            FwCidr::V4(i, m) => (i, m),
            _ => unreachable!(),
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
            action,
            direction,
            enabled: 1,
        };
        core.add_fw_rule(&iface, rule_id, rule).map_err(internal)?;
    }
    Ok(pb::AddFwRuleResponse {})
}

pub fn del_fw_rule<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelFwRuleRequest,
) -> Result<pb::DelFwRuleResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    let rule_id = req.rule_id.clone().into_bytes();
    core.del_fw_rule(&iface, &rule_id).map_err(internal)?;
    Ok(pb::DelFwRuleResponse {})
}

pub fn configure_qos<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ConfigureQoSRequest,
) -> Result<pb::ConfigureQoSResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    let egress_mbps = req.egress_mbps as u64;
    let public_mbps = req.public_mbps as u64;
    let ingress_mbps = req.ingress_mbps as u64;
    core.set_qos(&iface, egress_mbps, public_mbps, ingress_mbps)
        .map_err(internal)?;
    Ok(pb::ConfigureQoSResponse {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_control::{mem::MemMapWriter, shadow::IfaceMeta};

    fn core() -> ControlCore<MemMapWriter> {
        ControlCore::new(MemMapWriter::default())
    }

    /// Register a minimal interface in the ControlCore shadow so handlers that look up
    /// `ifaces_meta` (add_fw_rule, configure_qos, add_nat_source) can find it.
    fn register_iface(c: &mut ControlCore<MemMapWriter>, id: &str, vni: u32, ipv4: [u8; 4]) {
        c.register_iface_meta(
            id.as_bytes().to_vec(),
            IfaceMeta {
                vni,
                ipv4,
                ipv6: [0u8; 16],
                underlay: [0u8; 16],
                ifindex: 0,
            },
        );
    }

    #[test]
    fn add_route_v4_programs_and_bad_prefix_rejected() {
        let mut c = core();
        // happy path: a valid external /24 route programs without error.
        let ok = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "10.0.0.0/24".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: true,
            },
        );
        assert!(ok.is_ok(), "valid route: {ok:?}");
        // bad input: malformed prefix → invalid_argument.
        let bad = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "not-a-cidr".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: true,
            },
        );
        assert_eq!(bad.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn withdraw_route_v4_is_idempotent() {
        let mut c = core();
        // Withdrawing a non-existent route must succeed (delete_route returns Ok(false)).
        let r = withdraw_route(
            &mut c,
            &pb::WithdrawRouteRequest {
                vni: 100,
                prefix: "10.0.0.0/24".into(),
            },
        );
        assert!(r.is_ok(), "withdraw non-existent: {r:?}");
    }

    #[test]
    fn add_fw_rule_programs() {
        let mut c = core();
        // add_fw_rule requires the interface to exist in ifaces_meta (resolved via ifindex).
        register_iface(&mut c, "if-1", 100, [10, 0, 0, 5]);
        let r = add_fw_rule(
            &mut c,
            &pb::AddFwRuleRequest {
                interface_id: "if-1".into(),
                rule_id: "r-1".into(),
                src_cidr: "0.0.0.0/0".into(),
                dst_cidr: "10.0.0.5/32".into(),
                proto: 6,
                dst_port_min: 443,
                dst_port_max: 443,
                allow: true,
                egress: false,
            },
        );
        assert!(r.is_ok(), "fw rule: {r:?}");
    }

    #[test]
    fn add_fw_rule_v6_programs_rules6() {
        let mut c = core();
        // register_iface programs ifindex 0; the v6 rule lands at (0, idx 0).
        register_iface(&mut c, "if0", 100, [10, 0, 0, 5]);
        add_fw_rule(
            &mut c,
            &pb::AddFwRuleRequest {
                interface_id: "if0".into(),
                rule_id: "r1".into(),
                src_cidr: "::/0".into(),
                dst_cidr: "2001:db8::1/128".into(),
                proto: 6,
                dst_port_min: 80,
                dst_port_max: 80,
                allow: true,
                egress: false,
            },
        )
        .unwrap();
        assert!(c
            .writer()
            .fw_rules6
            .contains_key(&flowplane_common::FwRuleKey { ifindex: 0, idx: 0 }));
    }

    #[test]
    fn configure_qos_programs() {
        let mut c = core();
        // configure_qos resolves the interface via ifaces_meta so the interface must exist.
        register_iface(&mut c, "if-1", 100, [10, 0, 0, 5]);
        let r = configure_qos(
            &mut c,
            &pb::ConfigureQoSRequest {
                interface_id: "if-1".into(),
                egress_mbps: 100,
                public_mbps: 50,
                ingress_mbps: 100,
                egress_burst_kb: 0,
                ingress_burst_kb: 0,
            },
        );
        assert!(r.is_ok(), "qos: {r:?}");
    }

    #[test]
    fn add_neighbor_nat_programs() {
        let mut c = core();
        let r = add_neighbor_nat(
            &mut c,
            &pb::AddNeighborNatRequest {
                vni: 100,
                nat_ip: "198.51.100.7".into(),
                owner_underlay: "2001:db8::bb".into(),
                port_min: 20000,
                port_max: 30000,
            },
        );
        assert!(r.is_ok(), "neighbor nat: {r:?}");
    }
}
