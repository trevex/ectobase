//! Per-RPC marshalling fns shared by both DataplaneNode services. Each parses its `pb` request,
//! drives the same `ControlCore` calls the eBPF node handlers use, and builds the response —
//! side-effect-free apart from the ControlCore writes (no logging, no tonic transport), so each is
//! unit-testable directly against a `ControlCore<MemMapWriter>`.

use flowplane_control::{shadow::LbIpBytes, ControlCore, MapWriter};

use crate::error::ServiceError;
use crate::parse::{parse_fw_cidr, parse_nexthop6, parse_prefix, port_u16};
use crate::pb;

/// Argument-validation failures (bad CIDR/IP/port). The genuinely-internal `ControlCore` errors are
/// `anyhow::Error` and convert to `ServiceError::Internal` through `?` (blanket `#[from]`), so there
/// is no `internal` helper — a bare `?` on an `anyhow::Result` does the right thing. The firewall
/// and neighbor-NAT calls return a typed `FwError` / `NeighborNatError` instead, which `?`
/// classifies via their `From` impls in `error.rs`.
#[inline]
fn invalid(e: impl std::fmt::Display) -> ServiceError {
    ServiceError::Invalid(e.to_string())
}

pub fn add_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddRouteRequest,
) -> Result<pb::AddRouteResponse, ServiceError> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    let nexthop = parse_nexthop6(&req.nexthop_underlay).map_err(invalid)?;
    let vni = req.vni;
    let external = req.external;
    // The on-wire Geneve VNI may differ from the route's own table VNI (e.g. VPC peering:
    // the route is keyed under the importer's local VNI, but delivery must be stamped with
    // the peer's origin VNI). 0 ⇒ no explicit delivery VNI given, so it defaults to `vni`.
    let dvni = if req.delivery_vni != 0 {
        req.delivery_vni
    } else {
        vni
    };
    // Idempotent: drop any existing (vni, prefix) so a re-announce or moved prefix replaces
    // the nexthop instead of hitting ROUTE_EXISTS (identical to the eBPF handler).
    let res: anyhow::Result<()> = if is_v6 {
        core.delete_route6(vni, bytes, len)
            .and_then(|_| core.create_route6(vni, bytes, len, nexthop, dvni, external))
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        core.delete_route(vni, v4, len)
            .and_then(|_| core.create_route(vni, v4, len, nexthop, dvni, external))
    };
    res?;
    Ok(pb::AddRouteResponse {})
}

/// Withdraw a route, and whether it was there to withdraw. Withdrawing an absent route succeeds
/// (the response has no field for it); the flag is for the caller's log.
pub fn withdraw_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawRouteRequest,
) -> Result<(pb::WithdrawRouteResponse, bool), ServiceError> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    let vni = req.vni;
    let removed = if is_v6 {
        core.delete_route6(vni, bytes, len)?
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        core.delete_route(vni, v4, len)?
    };
    Ok((pb::WithdrawRouteResponse {}, removed))
}

pub fn add_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNatSourceRequest,
) -> Result<pb::AddNatSourceResponse, ServiceError> {
    use std::net::IpAddr;
    // Proto is family-agnostic (source_ip/nat_ip are strings); dispatch by the parsed family.
    let source: IpAddr = req.source_ip.parse().map_err(invalid)?;
    let nat: IpAddr = req.nat_ip.parse().map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Resolve (vni, source) -> interface id via the ControlCore accessor (the eBPF handler's
    // `find_interface_id` seam), then delete-then-create NAT idempotently.
    match (source, nat) {
        (IpAddr::V4(s), IpAddr::V4(n)) => {
            let id = core
                .find_iface_by_vni_ipv4(vni, s.octets())
                .ok_or_else(|| {
                    ServiceError::NotFound(format!(
                        "NO_VM: no local interface for vni={vni} ip={s}"
                    ))
                })?;
            let res: anyhow::Result<()> = core.delete_nat(&id).and_then(|_| {
                core.create_nat(&id, n.octets(), port_min, port_max, None)
                    .map(|_| ())
            });
            res?;
        }
        (IpAddr::V6(s), IpAddr::V6(n)) => {
            let id = core
                .find_iface_by_vni_ipv6(vni, s.octets())
                .ok_or_else(|| {
                    ServiceError::NotFound(format!(
                        "NO_VM: no local interface for vni={vni} ip={s}"
                    ))
                })?;
            let res: anyhow::Result<()> = core.delete_nat6(&id).and_then(|_| {
                core.create_nat6(&id, n.octets(), port_min, port_max, None)
                    .map(|_| ())
            });
            res?;
        }
        _ => {
            return Err(ServiceError::Invalid(
                "source_ip and nat_ip must be the same address family".into(),
            ))
        }
    }
    Ok(pb::AddNatSourceResponse {})
}

pub fn withdraw_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNatSourceRequest,
) -> Result<pb::WithdrawNatSourceResponse, ServiceError> {
    use std::net::IpAddr;
    let source: IpAddr = req.source_ip.parse().map_err(invalid)?;
    let vni = req.vni;
    // Removing an absent source is not an error (mirror the eBPF handler): if the interface is
    // gone or has no NAT, treat it as already withdrawn.
    match source {
        IpAddr::V4(s) => {
            if let Some(id) = core.find_iface_by_vni_ipv4(vni, s.octets()) {
                core.delete_nat(&id)?;
            }
        }
        IpAddr::V6(s) => {
            if let Some(id) = core.find_iface_by_vni_ipv6(vni, s.octets()) {
                core.delete_nat6(&id)?;
            }
        }
    }
    Ok(pb::WithdrawNatSourceResponse {})
}

pub fn add_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNeighborNatRequest,
) -> Result<pb::AddNeighborNatResponse, ServiceError> {
    use std::net::IpAddr;
    let nat: IpAddr = req.nat_ip.parse().map_err(invalid)?;
    // The owner underlay is a v6 VTEP in BOTH families (the underlay is IPv6-only).
    let owner = parse_nexthop6(&req.owner_underlay).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Idempotent: a block already listed for this (nat_ip, ports) is refreshed in place, so a
    // re-announce moves its prefixes to the new owner underlay without unprogramming them.
    match nat {
        IpAddr::V4(n) => core.upsert_neighbor_nat(vni, n.octets(), port_min, port_max, owner)?,
        IpAddr::V6(n) => core.upsert_neighbor_nat6(vni, n.octets(), port_min, port_max, owner)?,
    }
    Ok(pb::AddNeighborNatResponse {})
}

pub fn withdraw_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNeighborNatRequest,
) -> Result<pb::WithdrawNeighborNatResponse, ServiceError> {
    use std::net::IpAddr;
    let nat: IpAddr = req.nat_ip.parse().map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let vni = req.vni;
    // Removing an absent entry is not an error (del_neighbor_nat returns Ok(false)).
    match nat {
        IpAddr::V4(n) => {
            core.del_neighbor_nat(vni, n.octets(), port_min, port_max)?;
        }
        IpAddr::V6(n) => {
            core.del_neighbor_nat6(vni, n.octets(), port_min, port_max)?;
        }
    }
    Ok(pb::WithdrawNeighborNatResponse {})
}

/// The whole neighbor-NAT set a complete route-bus snapshot carries; see
/// `ControlCore::replace_neighbor_nats`. A malformed block refuses the set before anything is
/// changed.
pub fn replace_neighbor_nats<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ReplaceNeighborNatsRequest,
) -> Result<pb::ReplaceNeighborNatsResponse, ServiceError> {
    use flowplane_common::{NeighborNat6Entry, NeighborNatEntry};
    use std::net::IpAddr;
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for b in &req.blocks {
        let nat: IpAddr = b.nat_ip.parse().map_err(invalid)?;
        // The owner underlay is a v6 VTEP in BOTH families (the underlay is IPv6-only).
        let underlay = parse_nexthop6(&b.owner_underlay).map_err(invalid)?;
        let port_min = port_u16(b.port_min).map_err(invalid)?;
        let port_max = port_u16(b.port_max).map_err(invalid)?;
        match nat {
            IpAddr::V4(n) => v4.push(NeighborNatEntry {
                underlay,
                nat_ip: n.octets(),
                vni: b.vni,
                port_min,
                port_max,
            }),
            IpAddr::V6(n) => v6.push(NeighborNat6Entry {
                underlay,
                nat_ip6: n.octets(),
                vni: b.vni,
                port_min,
                port_max,
            }),
        }
    }
    let n = core.replace_neighbor_nats(&v4, &v6)?;
    Ok(pb::ReplaceNeighborNatsResponse {
        added: n.added,
        kept: n.kept,
        removed: n.removed,
    })
}

pub fn add_load_balancer<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLoadBalancerRequest,
) -> Result<pb::AddLoadBalancerResponse, ServiceError> {
    let lb_ip: LbIpBytes = match req.ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => LbIpBytes::Ipv4(a.octets()),
        Ok(std::net::IpAddr::V6(a)) => LbIpBytes::Ipv6(a.octets()),
        Err(e) => {
            return Err(ServiceError::Invalid(format!(
                "invalid lb_ip {:?}: {e}",
                req.ip
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
    core.create_lb(&id, vni, lb_ip, lb_underlay, ports)?;
    Ok(pb::AddLoadBalancerResponse {})
}

/// Parse a backend overlay IP (v4 or v6) into its 16-byte wire form + the `is_v6` family flag: a v4
/// address is left-justified in the first 4 bytes (the rest zero), a v6 address fills all 16 bytes.
/// Shared by `add_lb_backend` and `del_lb_backend` so both encode/match overlay IPs identically.
fn parse_backend_overlay_ip(s: &str) -> Result<([u8; 16], u8), String> {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let o = a.octets();
            Ok((
                [o[0], o[1], o[2], o[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                0u8,
            ))
        }
        Ok(std::net::IpAddr::V6(a)) => Ok((a.octets(), 1u8)),
        Err(e) => Err(format!("invalid backend_overlay_ip {s:?}: {e}")),
    }
}

pub fn add_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLbBackendRequest,
) -> Result<pb::AddLbBackendResponse, ServiceError> {
    let node_vtep = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    let (overlay_ip, is_v6) =
        parse_backend_overlay_ip(&req.backend_overlay_ip).map_err(ServiceError::Invalid)?;
    let backend = flowplane_common::LbBackend {
        node_vtep,
        overlay_ip,
        vni: req.backend_vni,
        is_v6,
        _pad: [0; 3],
    };
    let id = req.id.clone().into_bytes();
    core.add_lb_target(&id, backend)?;
    Ok(pb::AddLbBackendResponse {})
}

pub fn del_load_balancer<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLoadBalancerRequest,
) -> Result<pb::DelLoadBalancerResponse, ServiceError> {
    let id = req.id.clone().into_bytes();
    core.delete_lb(&id)?;
    Ok(pb::DelLoadBalancerResponse {})
}

pub fn del_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLbBackendRequest,
) -> Result<pb::DelLbBackendResponse, ServiceError> {
    let backend_node_vtep = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    // backend_overlay_ip disambiguates two backends sharing the same node (two pods of one Service
    // scheduled on the same node). Empty is the legacy/CLI shape (older callers that predate this
    // field, e.g. main.rs's --lb-target path never sets it): fall back to an all-zero overlay IP,
    // which del_lb_target treats as "match by node_vtep alone" (removing every backend on that node),
    // preserving the pre-fix behavior for those callers instead of rejecting the request.
    let backend_overlay_ip = if req.backend_overlay_ip.is_empty() {
        [0u8; 16]
    } else {
        parse_backend_overlay_ip(&req.backend_overlay_ip)
            .map_err(ServiceError::Invalid)?
            .0
    };
    let id = req.id.clone().into_bytes();
    core.del_lb_target(&id, backend_node_vtep, backend_overlay_ip)?;
    Ok(pb::DelLbBackendResponse {})
}

/// One parsed firewall rule, family-tagged. The address family is inferred from the CIDRs: a v6
/// CIDR on either side makes it a v6 rule (the wildcard opposite side is re-encoded in-family).
enum ParsedFwRule {
    V4(flowplane_common::FwRule),
    V6(flowplane_common::FwRule6),
}

/// Parse the wire form of one firewall rule into a family-tagged `ParsedFwRule`.
fn parse_fw_rule(spec: &pb::FwRuleSpec) -> Result<ParsedFwRule, ServiceError> {
    use crate::parse::FwCidr;
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
    let (src_cidr, dst_cidr) = (spec.src_cidr.as_str(), spec.dst_cidr.as_str());
    let src = parse_fw_cidr(src_cidr).map_err(invalid)?;
    let dst = parse_fw_cidr(dst_cidr).map_err(invalid)?;
    let proto =
        u8::try_from(spec.proto).map_err(|_| ServiceError::Invalid("proto > 255".into()))?;
    let dst_port_min = port_u16(spec.dst_port_min).map_err(invalid)?;
    let dst_port_max = if spec.dst_port_max == 0 {
        65535u16
    } else {
        port_u16(spec.dst_port_max).map_err(invalid)?
    };
    if dst_port_min > dst_port_max {
        return Err(ServiceError::Invalid(format!(
            "dst port range {dst_port_min}-{dst_port_max} is inverted"
        )));
    }
    let (icmp_type, icmp_code) = parse_icmp_selectors(spec)?;
    let action = if spec.allow {
        FW_ACTION_ACCEPT
    } else {
        FW_ACTION_DROP
    };
    let direction = if spec.egress {
        FW_DIR_EGRESS
    } else {
        FW_DIR_INGRESS
    };
    // A rule must be single-family. An EMPTY CIDR is an untyped wildcard ("any"): `parse_fw_cidr`
    // defaults it to a v4 wildcard, but it adopts whichever family the other (specified) side is,
    // via the zero-fill arms below. Only two EXPLICITLY-specified CIDRs of different families are a
    // real mismatch — accepting one would take the v6 branch and silently zero-fill (widen to
    // `::/0`) the v4 side. Reject that.
    let src_is_v6 = matches!(src, FwCidr::V6(..));
    let dst_is_v6 = matches!(dst, FwCidr::V6(..));
    if !src_cidr.is_empty() && !dst_cidr.is_empty() && src_is_v6 != dst_is_v6 {
        return Err(ServiceError::Invalid(
            "firewall rule src and dst must be the same address family".into(),
        ));
    }
    if src_is_v6 || dst_is_v6 {
        // v6 rule: any empty/wildcard v4 side is re-encoded as the v6 wildcard `::/0`.
        let (src_ip, src_mask) = match src {
            FwCidr::V6(i, m) => (i, m),
            FwCidr::V4(..) => ([0u8; 16], [0u8; 16]),
        };
        let (dst_ip, dst_mask) = match dst {
            FwCidr::V6(i, m) => (i, m),
            FwCidr::V4(..) => ([0u8; 16], [0u8; 16]),
        };
        Ok(ParsedFwRule::V6(flowplane_common::FwRule6 {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min,
            dst_port_max,
            icmp_type,
            icmp_code,
            proto,
            action,
            direction,
            enabled: 1,
        }))
    } else {
        let (src_ip, src_mask) = match src {
            FwCidr::V4(i, m) => (i, m),
            _ => unreachable!(),
        };
        let (dst_ip, dst_mask) = match dst {
            FwCidr::V4(i, m) => (i, m),
            _ => unreachable!(),
        };
        Ok(ParsedFwRule::V4(flowplane_common::FwRule {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min,
            dst_port_max,
            icmp_type,
            icmp_code,
            proto,
            action,
            direction,
            enabled: 1,
        }))
    }
}

/// The ICMP(v6) selectors of a rule, as the datapath's `0xffff`-means-any u16s. Only an ICMP rule
/// (proto 1 or 58) may carry them, a code needs a type, and each is a single octet on the wire.
fn parse_icmp_selectors(spec: &pb::FwRuleSpec) -> Result<(u16, u16), ServiceError> {
    const ANY: u16 = 0xffff;
    if spec.icmp_type.is_none() && spec.icmp_code.is_none() {
        return Ok((ANY, ANY));
    }
    if spec.proto != 1 && spec.proto != 58 {
        return Err(ServiceError::Invalid(format!(
            "ICMP type/code on a proto {} rule (needs 1 or 58)",
            spec.proto
        )));
    }
    let octet = |what: &str, v: u32| {
        u8::try_from(v)
            .map(u16::from)
            .map_err(|_| ServiceError::Invalid(format!("ICMP {what} {v} > 255")))
    };
    match (spec.icmp_type, spec.icmp_code) {
        (Some(t), code) => Ok((
            octet("type", t)?,
            code.map(|c| octet("code", c)).transpose()?.unwrap_or(ANY),
        )),
        (None, _) => Err(ServiceError::Invalid(
            "ICMP code without an ICMP type".into(),
        )),
    }
}

/// Replace an interface's ENTIRE firewall rule set with `req.rules` (ingress + egress, v4 + v6),
/// clearing any prior rules. Splits the flat list into per-family slot-ordered vecs and replaces both
/// families (an absent family is cleared) — or neither, if the interface is unknown (`NotFound`) or
/// a family is over its rule budget (`ResourceExhausted`).
pub fn replace_interface_firewall<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ReplaceInterfaceFirewallRequest,
) -> Result<pb::ReplaceInterfaceFirewallResponse, ServiceError> {
    let iface = req.interface_id.clone().into_bytes();
    let mut v4: Vec<(Vec<u8>, flowplane_common::FwRule)> = Vec::new();
    let mut v6: Vec<(Vec<u8>, flowplane_common::FwRule6)> = Vec::new();
    for spec in &req.rules {
        let id = spec.rule_id.clone().into_bytes();
        match parse_fw_rule(spec)? {
            ParsedFwRule::V4(rule) => v4.push((id, rule)),
            ParsedFwRule::V6(rule) => v6.push((id, rule)),
        }
    }
    core.replace_interface_fw(&iface, v4, v6)?;
    Ok(pb::ReplaceInterfaceFirewallResponse {})
}

pub fn configure_qos<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ConfigureQoSRequest,
) -> Result<pb::ConfigureQoSResponse, ServiceError> {
    let iface = req.interface_id.clone().into_bytes();
    let egress_mbps = req.egress_mbps as u64;
    let public_mbps = req.public_mbps as u64;
    let ingress_mbps = req.ingress_mbps as u64;
    core.set_qos(&iface, egress_mbps, public_mbps, ingress_mbps)?;
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
    /// `ifaces_meta` (replace_interface_firewall, configure_qos, add_nat_source) can find it.
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
                delivery_vni: 0,
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
                delivery_vni: 0,
            },
        );
        assert_eq!(
            tonic::Status::from(bad.unwrap_err()).code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn add_route_v4_delivery_vni_overrides_nexthop_vni_key_stays_own_vni() {
        let mut c = core();
        // Peer-import shape: the route is keyed under the importer's own vni (100), but the
        // on-wire Geneve delivery must be stamped with the peer's origin vni (777).
        let ok = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "10.0.0.0/24".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: false,
                delivery_vni: 777,
            },
        );
        assert!(ok.is_ok(), "valid route: {ok:?}");
        let val = c
            .writer()
            .routes
            .get(&(100, [10, 0, 0, 0], 24))
            .expect("route programmed under its own vni");
        assert_eq!(
            val.nexthop_vni, 777,
            "delivery_vni must land in RouteValue.nexthop_vni"
        );

        // delivery_vni: 0 ⇒ falls back to vni (unchanged behavior).
        let ok2 = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 200,
                prefix: "10.1.0.0/24".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: false,
                delivery_vni: 0,
            },
        );
        assert!(ok2.is_ok(), "valid route: {ok2:?}");
        let val2 = c
            .writer()
            .routes
            .get(&(200, [10, 1, 0, 0], 24))
            .expect("route programmed");
        assert_eq!(val2.nexthop_vni, 200, "delivery_vni=0 must default to vni");
    }

    #[test]
    fn withdraw_route_v4_is_idempotent() {
        let mut c = core();
        // Withdrawing a non-existent route must succeed (delete_route returns Ok(false)), and say
        // it removed nothing, so the caller does not log a removal that never happened.
        let req = pb::WithdrawRouteRequest {
            vni: 100,
            prefix: "10.0.0.0/24".into(),
        };
        let r = withdraw_route(&mut c, &req);
        assert!(matches!(r, Ok((_, false))), "withdraw non-existent: {r:?}");
        add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "10.0.0.0/24".into(),
                nexthop_underlay: "fd00::1".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let r = withdraw_route(&mut c, &req);
        assert!(matches!(r, Ok((_, true))), "withdraw present: {r:?}");
        assert!(!c.writer().routes.contains_key(&(100, [10, 0, 0, 0], 24)));
    }

    /// Both families compile into the interface's classifier scopes.
    #[test]
    fn replace_interface_firewall_programs_both_families() {
        let mut c = core();
        // register_iface programs ifindex 0.
        register_iface(&mut c, "if0", 100, [10, 0, 0, 5]);
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![
                    pb::FwRuleSpec {
                        proto: 6,
                        dst_port_min: 443,
                        dst_port_max: 443,
                        ..fw_spec("r4", "10.0.0.0/24", true)
                    },
                    pb::FwRuleSpec {
                        proto: 6,
                        dst_port_min: 80,
                        dst_port_max: 80,
                        ..fw_spec("r6", "2001:db8::/32", true)
                    },
                ],
            },
        )
        .unwrap();
        let bind = c.writer().fw_bind[&0];
        assert_eq!(bind.egress_scope, 0, "no egress rules");
        let scope = &c.writer().fw_scopes[&bind.ingress_scope];
        assert!(!scope.v4.policy.is_empty() && !scope.v6.policy.is_empty());
    }

    /// The classifier matches a rule's PEER (source on ingress, destination on egress); a rule
    /// that also restricts the interface's own address cannot be expressed and is refused as a
    /// client error rather than silently widened.
    #[test]
    fn replace_interface_firewall_refuses_a_local_address_match() {
        let mut c = core();
        register_iface(&mut c, "if0", 100, [10, 0, 0, 5]);
        let err = replace_one(
            &mut c,
            pb::FwRuleSpec {
                dst_cidr: "10.0.0.5/32".into(),
                proto: 6,
                dst_port_min: 443,
                dst_port_max: 443,
                ..fw_spec("r1", "0.0.0.0/0", true)
            },
        )
        .unwrap_err();
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn replace_interface_firewall_rejects_mixed_family() {
        let mut c = core();
        register_iface(&mut c, "if0", 100, [10, 0, 0, 5]);
        // v4 src + v6 dst must be rejected rather than silently widened to ::/0, and the reverse.
        for (src, dst) in [
            ("10.0.0.0/24", "2001:db8::1/128"),
            ("2001:db8::/64", "10.0.0.5/32"),
        ] {
            let err = replace_one(
                &mut c,
                pb::FwRuleSpec {
                    dst_cidr: dst.into(),
                    ..fw_spec("r", src, true)
                },
            )
            .unwrap_err();
            assert_eq!(
                tonic::Status::from(err).code(),
                tonic::Code::InvalidArgument,
                "{src} -> {dst}"
            );
        }
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

    fn v6(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    /// The exact `NAT_OWNERS` entries the control core stores for a VNI-100 v4 block.
    fn owners4(
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: &str,
    ) -> Vec<(
        u32,
        flowplane_common::NatOwnerKey,
        flowplane_common::NatOwner,
    )> {
        flowplane_control::natowner::owner_prefixes4(&flowplane_common::NeighborNatEntry {
            underlay: v6(underlay),
            nat_ip,
            vni: 100,
            port_min,
            port_max,
        })
    }

    /// IPv6 sibling of [`owners4`].
    fn owners6(
        nat_ip6: &str,
        port_min: u16,
        port_max: u16,
        underlay: &str,
    ) -> Vec<(
        u32,
        flowplane_common::NatOwnerKey6,
        flowplane_common::NatOwner,
    )> {
        flowplane_control::natowner::owner_prefixes6(&flowplane_common::NeighborNat6Entry {
            underlay: v6(underlay),
            nat_ip6: v6(nat_ip6),
            vni: 100,
            port_min,
            port_max,
        })
    }

    /// The trie holds exactly `want`, nothing more.
    fn assert_trie<K: std::hash::Hash + Eq + Copy + std::fmt::Debug>(
        got: &std::collections::HashMap<(u32, K), flowplane_common::NatOwner>,
        want: &[(u32, K, flowplane_common::NatOwner)],
    ) {
        assert_eq!(got.len(), want.len(), "prefix count");
        for (plen, key, owner) in want {
            assert_eq!(got.get(&(*plen, *key)), Some(owner), "/{plen} {key:?}");
        }
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
        assert_trie(
            &c.writer().nat_owners,
            &owners4([198, 51, 100, 7], 20000, 30000, "2001:db8::bb"),
        );
    }

    #[test]
    fn add_neighbor_nat6_programs() {
        let mut c = core();
        let r = add_neighbor_nat(
            &mut c,
            &pb::AddNeighborNatRequest {
                vni: 100,
                nat_ip: "2001:db8:2b::7".into(),
                owner_underlay: "2001:db8::bb".into(),
                port_min: 20000,
                port_max: 30000,
            },
        );
        assert!(r.is_ok(), "neighbor nat6: {r:?}");
        assert_trie(
            &c.writer().nat_owners6,
            &owners6("2001:db8:2b::7", 20000, 30000, "2001:db8::bb"),
        );
    }

    // The mesh agent replays every block on reconnect, so a re-announce of a listed block must
    // succeed and leave it owned by the latest underlay; a withdraw must tolerate a repeat.
    #[test]
    fn neighbor_nat_reannounce_replaces_owner_and_withdraw_repeats() {
        let mut c = core();
        let add = |owner: &str| pb::AddNeighborNatRequest {
            vni: 100,
            nat_ip: "198.51.100.7".into(),
            owner_underlay: owner.into(),
            port_min: 20000,
            port_max: 30001,
        };
        add_neighbor_nat(&mut c, &add("2001:db8::bb")).unwrap();
        add_neighbor_nat(&mut c, &add("2001:db8::cc")).unwrap();
        assert_trie(
            &c.writer().nat_owners,
            &owners4([198, 51, 100, 7], 20000, 30001, "2001:db8::cc"),
        );

        let withdraw = pb::WithdrawNeighborNatRequest {
            vni: 100,
            nat_ip: "198.51.100.7".into(),
            port_min: 20000,
            port_max: 30001,
        };
        withdraw_neighbor_nat(&mut c, &withdraw).unwrap();
        assert!(c.writer().nat_owners.is_empty());
        withdraw_neighbor_nat(&mut c, &withdraw).unwrap();
    }

    #[test]
    fn neighbor_nat6_reannounce_replaces_owner_and_withdraw_repeats() {
        let mut c = core();
        let add = |owner: &str| pb::AddNeighborNatRequest {
            vni: 100,
            nat_ip: "2001:db8:2b::7".into(),
            owner_underlay: owner.into(),
            port_min: 20000,
            port_max: 30001,
        };
        add_neighbor_nat(&mut c, &add("2001:db8::bb")).unwrap();
        add_neighbor_nat(&mut c, &add("2001:db8::cc")).unwrap();
        assert_trie(
            &c.writer().nat_owners6,
            &owners6("2001:db8:2b::7", 20000, 30001, "2001:db8::cc"),
        );

        let withdraw = pb::WithdrawNeighborNatRequest {
            vni: 100,
            nat_ip: "2001:db8:2b::7".into(),
            port_min: 20000,
            port_max: 30001,
        };
        withdraw_neighbor_nat(&mut c, &withdraw).unwrap();
        assert!(c.writer().nat_owners6.is_empty());
        withdraw_neighbor_nat(&mut c, &withdraw).unwrap();
    }

    // The handler refreshes a re-announced block in place, so it never removes a prefix: with a
    // removal of its first prefix rigged to fail, a delete-then-add would fail the call, and in
    // between the block's whole return path would have been unprogrammed.
    #[test]
    fn neighbor_nat_reannounce_never_unprograms_the_block() {
        let mut c = core();
        let add = |owner: &str| pb::AddNeighborNatRequest {
            vni: 100,
            nat_ip: "198.51.100.7".into(),
            owner_underlay: owner.into(),
            port_min: 20000,
            port_max: 30001,
        };
        add_neighbor_nat(&mut c, &add("2001:db8::bb")).unwrap();
        let (plen, key, _) = owners4([198, 51, 100, 7], 20000, 30001, "2001:db8::bb")[0];
        c.writer_mut().nat_owner_fault.remove = Some((plen, key));
        add_neighbor_nat(&mut c, &add("2001:db8::cc")).unwrap();
        assert_trie(
            &c.writer().nat_owners,
            &owners4([198, 51, 100, 7], 20000, 30001, "2001:db8::cc"),
        );
    }

    #[test]
    fn neighbor_nat6_reannounce_never_unprograms_the_block() {
        let mut c = core();
        let add = |owner: &str| pb::AddNeighborNatRequest {
            vni: 100,
            nat_ip: "2001:db8:2b::7".into(),
            owner_underlay: owner.into(),
            port_min: 20000,
            port_max: 30001,
        };
        add_neighbor_nat(&mut c, &add("2001:db8::bb")).unwrap();
        let (plen, key, _) = owners6("2001:db8:2b::7", 20000, 30001, "2001:db8::bb")[0];
        c.writer_mut().nat_owner6_fault.remove = Some((plen, key));
        add_neighbor_nat(&mut c, &add("2001:db8::cc")).unwrap();
        assert_trie(
            &c.writer().nat_owners6,
            &owners6("2001:db8:2b::7", 20000, 30001, "2001:db8::cc"),
        );
    }

    #[test]
    fn add_neighbor_nat_overlap_is_already_exists() {
        let mut c = core();
        let req = |lo, hi| pb::AddNeighborNatRequest {
            vni: 100,
            nat_ip: "198.51.100.7".into(),
            owner_underlay: "2001:db8::bb".into(),
            port_min: lo,
            port_max: hi,
        };
        add_neighbor_nat(&mut c, &req(20000, 30000)).unwrap();
        let err = add_neighbor_nat(&mut c, &req(25000, 35000)).unwrap_err();
        let status = tonic::Status::from(err);
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
        assert!(
            status.message().starts_with("ALREADY_EXISTS:"),
            "{}",
            status.message()
        );
    }

    #[test]
    fn add_neighbor_nat_empty_range_is_invalid() {
        let mut c = core();
        let err = add_neighbor_nat(
            &mut c,
            &pb::AddNeighborNatRequest {
                vni: 100,
                nat_ip: "198.51.100.7".into(),
                owner_underlay: "2001:db8::bb".into(),
                port_min: 3000,
                port_max: 3000,
            },
        )
        .unwrap_err();
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::InvalidArgument
        );
    }

    /// A block of the set, owned by 2001:db8::cc in VNI 100.
    fn blk(nat_ip: &str, port_min: u32, port_max: u32) -> pb::NeighborNatBlock {
        pb::NeighborNatBlock {
            nat_ip: nat_ip.into(),
            port_min,
            port_max,
            owner_underlay: "2001:db8::cc".into(),
            vni: 100,
        }
    }

    // The set is the whole truth: the block that is not in it goes, both families' new ones land.
    #[test]
    fn replace_neighbor_nats_syncs_both_families() {
        let mut c = core();
        add_neighbor_nat(
            &mut c,
            &pb::AddNeighborNatRequest {
                vni: 100,
                nat_ip: "198.51.100.7".into(),
                owner_underlay: "2001:db8::bb".into(),
                port_min: 1024,
                port_max: 2048,
            },
        )
        .unwrap();
        let resp = replace_neighbor_nats(
            &mut c,
            &pb::ReplaceNeighborNatsRequest {
                blocks: vec![
                    blk("198.51.100.8", 20000, 30000),
                    blk("2001:db8:2b::7", 20000, 30000),
                ],
            },
        )
        .unwrap();
        assert_eq!((resp.added, resp.kept, resp.removed), (2, 0, 1));
        assert_trie(
            &c.writer().nat_owners,
            &owners4([198, 51, 100, 8], 20000, 30000, "2001:db8::cc"),
        );
        assert_trie(
            &c.writer().nat_owners6,
            &owners6("2001:db8:2b::7", 20000, 30000, "2001:db8::cc"),
        );
    }

    #[test]
    fn replace_neighbor_nats_refuses_an_overlapping_set() {
        let mut c = core();
        let err = replace_neighbor_nats(
            &mut c,
            &pb::ReplaceNeighborNatsRequest {
                blocks: vec![
                    blk("198.51.100.7", 20000, 30000),
                    blk("198.51.100.7", 25000, 35000),
                ],
            },
        )
        .unwrap_err();
        assert_eq!(tonic::Status::from(err).code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn replace_neighbor_nats_rejects_a_bad_block() {
        let mut c = core();
        let err = replace_neighbor_nats(
            &mut c,
            &pb::ReplaceNeighborNatsRequest {
                blocks: vec![blk("not-an-ip", 1, 2)],
            },
        )
        .unwrap_err();
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn add_nat_source_dispatches_v6_and_rejects_family_mismatch() {
        use std::net::Ipv6Addr;
        let mut c = core();
        c.register_iface_meta(
            b"if6".to_vec(),
            IfaceMeta {
                vni: 7,
                ipv4: [0u8; 4],
                ipv6: "fd00::9".parse::<Ipv6Addr>().unwrap().octets(),
                underlay: [1u8; 16],
                ifindex: 0,
            },
        );
        // both v6 → NAT66 path.
        let ok = add_nat_source(
            &mut c,
            &pb::AddNatSourceRequest {
                vni: 7,
                source_ip: "fd00::9".into(),
                nat_ip: "2001:db8:2b::1".into(),
                port_min: 1024,
                port_max: 2048,
            },
        );
        assert!(ok.is_ok(), "v6 nat source: {ok:?}");
        assert!(c
            .writer()
            .nat_ips6
            .contains(&(7, "2001:db8:2b::1".parse::<Ipv6Addr>().unwrap().octets())));
        // family mismatch (v6 source, v4 nat) → InvalidArgument.
        let bad = add_nat_source(
            &mut c,
            &pb::AddNatSourceRequest {
                vni: 7,
                source_ip: "fd00::9".into(),
                nat_ip: "198.51.100.7".into(),
                port_min: 1024,
                port_max: 2048,
            },
        );
        assert_eq!(
            tonic::Status::from(bad.unwrap_err()).code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn replace_interface_firewall_sets_full_set_and_clears() {
        let mut c = core();
        register_iface(&mut c, "if0", 5, [10, 0, 0, 2]);
        // Replace with one v4 ingress deny + one v6 ingress allow.
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![
                    fw_spec("fw-in-0", "0.0.0.0/0", false),
                    fw_spec("fw-in-1", "::/0", true),
                ],
            },
        )
        .unwrap();
        // Both families compile into the interface's ingress scope.
        let bind = c.writer().fw_bind[&0];
        let scope = &c.writer().fw_scopes[&bind.ingress_scope];
        assert!(!scope.v4.policy.is_empty() && !scope.v6.policy.is_empty());
        // Empty replace clears both families: no scope in either direction.
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![],
            },
        )
        .unwrap();
        let bind = c.writer().fw_bind[&0];
        assert_eq!((bind.ingress_scope, bind.egress_scope), (0, 0));
        assert!(c.writer().fw_scopes.is_empty());
    }

    fn fw_spec(id: &str, src_cidr: &str, allow: bool) -> pb::FwRuleSpec {
        pb::FwRuleSpec {
            rule_id: id.into(),
            src_cidr: src_cidr.into(),
            allow,
            ..Default::default()
        }
    }

    fn replace_one(
        c: &mut ControlCore<MemMapWriter>,
        spec: pb::FwRuleSpec,
    ) -> Result<(), ServiceError> {
        replace_interface_firewall(
            c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![spec],
            },
        )
        .map(|_| ())
    }

    /// The (proto, type, code) policy entries of `if0`'s ingress scope, one family: the ICMP
    /// selectors ride in the policy key's port bytes, a wildcard code as a shorter prefix.
    fn icmp_entries(c: &ControlCore<MemMapWriter>, v6: bool) -> Vec<(u8, [u8; 2], u32)> {
        let bind = c.writer().fw_bind[&0];
        let scope = &c.writer().fw_scopes[&bind.ingress_scope];
        let policy = if v6 {
            &scope.v6.policy
        } else {
            &scope.v4.policy
        };
        policy
            .iter()
            .map(|(plen, k, _)| (k.proto, k.port, *plen))
            .collect()
    }

    /// ICMP type/code reach the classifier with presence intact: type 0 (echo reply) is a real
    /// selector, and an unset code is a wildcard (the key's code byte left out of the prefix).
    #[test]
    fn replace_interface_firewall_carries_icmp_selectors() {
        use flowplane_common::FW_POL_PREFIX_FULL;
        let mut c = core();
        register_iface(&mut c, "if0", 5, [10, 0, 0, 2]);
        replace_one(
            &mut c,
            pb::FwRuleSpec {
                proto: 1,
                icmp_type: Some(8),
                ..fw_spec("echo", "10.0.0.0/8", true)
            },
        )
        .unwrap();
        assert_eq!(
            icmp_entries(&c, false),
            vec![(1, [8, 0], FW_POL_PREFIX_FULL - 8)],
            "type 8, any code"
        );

        replace_one(
            &mut c,
            pb::FwRuleSpec {
                proto: 58,
                icmp_type: Some(0),
                icmp_code: Some(0),
                ..fw_spec("reply6", "2001:db8::/32", true)
            },
        )
        .unwrap();
        assert_eq!(
            icmp_entries(&c, true),
            vec![(58, [0, 0], FW_POL_PREFIX_FULL)],
            "type 0 code 0 is an exact selector, not a wildcard"
        );
    }

    #[test]
    fn replace_interface_firewall_rejects_bad_selectors() {
        let mut c = core();
        register_iface(&mut c, "if0", 5, [10, 0, 0, 2]);
        for (what, spec) in [
            (
                "type > 255",
                pb::FwRuleSpec {
                    proto: 1,
                    icmp_type: Some(256),
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
            (
                "code > 255",
                pb::FwRuleSpec {
                    proto: 1,
                    icmp_type: Some(3),
                    icmp_code: Some(256),
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
            (
                "code without type",
                pb::FwRuleSpec {
                    proto: 1,
                    icmp_code: Some(0),
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
            (
                "type on TCP",
                pb::FwRuleSpec {
                    proto: 6,
                    icmp_type: Some(8),
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
            (
                "type on any proto",
                pb::FwRuleSpec {
                    icmp_type: Some(8),
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
            (
                "inverted port range",
                pb::FwRuleSpec {
                    proto: 6,
                    dst_port_min: 9000,
                    dst_port_max: 8000,
                    ..fw_spec("r", "10.0.0.0/8", true)
                },
            ),
        ] {
            let err = replace_one(&mut c, spec).expect_err(what);
            assert_eq!(
                tonic::Status::from(err).code(),
                tonic::Code::InvalidArgument,
                "{what}"
            );
        }
    }

    /// A rule list too large for a scope is a quota refusal, not a transient fault: it must surface
    /// as ResourceExhausted (clients must not blind-retry it as Internal), and it must be refused
    /// BEFORE anything is written — the v4 half is fine here, yet binding it while refusing v6 would
    /// leave the interface on half of the new policy.
    #[test]
    fn replace_interface_firewall_too_large_is_resource_exhausted_and_commits_nothing() {
        let mut c = core();
        register_iface(&mut c, "if0", 5, [10, 0, 0, 2]);
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![fw_spec("old", "0.0.0.0/0", false)],
            },
        )
        .unwrap();
        let before = c.writer().fw_bind[&0];

        let mut rules = vec![fw_spec("new-v4", "10.0.0.0/8", true)];
        for i in 0..=flowplane_common::FW_SCOPE_MAX_CLASSES {
            rules.push(fw_spec(
                &format!("v6-{i}"),
                &format!("2001:db8:{:x}:{:x}::/64", i >> 8, i & 0xff),
                true,
            ));
        }
        let err = replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules,
            },
        )
        .unwrap_err();
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(c.writer().fw_bind[&0], before, "the old binding stays");
        assert_eq!(c.writer().fw_scopes.len(), 1, "no new scope was created");
    }

    #[test]
    fn replace_interface_firewall_unknown_interface_is_not_found() {
        let mut c = core();
        let err = replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "nope".into(),
                rules: vec![fw_spec("r", "0.0.0.0/0", true)],
            },
        )
        .unwrap_err();
        assert_eq!(tonic::Status::from(err).code(), tonic::Code::NotFound);
    }

    /// End-to-end through the RPC handlers: two backends on the SAME node (same backend_underlay)
    /// but different backend_overlay_ip must both be added, and del_lb_backend targeting one overlay
    /// IP must remove only that backend — the other must remain reachable via the Maglev table.
    #[test]
    fn add_del_lb_backend_disambiguates_same_node_by_overlay_ip() {
        let mut c = core();
        add_load_balancer(
            &mut c,
            &pb::AddLoadBalancerRequest {
                id: "lb_ip".into(),
                vni: 100,
                ip: "203.0.113.60".into(),
                lb_underlay: "2001:db8::ee".into(),
                ports: vec![pb::PortProto {
                    port: 443,
                    proto: 6,
                }],
            },
        )
        .expect("add_load_balancer");

        add_lb_backend(
            &mut c,
            &pb::AddLbBackendRequest {
                id: "lb_ip".into(),
                backend_underlay: "2001:db8::1".into(),
                backend_overlay_ip: "10.0.0.5".into(),
                backend_vni: 100,
            },
        )
        .expect("add backend 1");
        add_lb_backend(
            &mut c,
            &pb::AddLbBackendRequest {
                id: "lb_ip".into(),
                backend_underlay: "2001:db8::1".into(), // SAME node as backend 1
                backend_overlay_ip: "10.0.0.7".into(),
                backend_vni: 100,
            },
        )
        .expect("add backend 2");

        let has_overlay = |c: &ControlCore<MemMapWriter>, want: [u8; 4]| {
            c.writer()
                .maglev
                .values()
                .any(|b| b.overlay_ip[..4] == want)
        };
        assert!(has_overlay(&c, [10, 0, 0, 5]), "backend 1 must be live");
        assert!(has_overlay(&c, [10, 0, 0, 7]), "backend 2 must be live");

        del_lb_backend(
            &mut c,
            &pb::DelLbBackendRequest {
                id: "lb_ip".into(),
                backend_underlay: "2001:db8::1".into(),
                backend_overlay_ip: "10.0.0.5".into(),
            },
        )
        .expect("del backend 1");

        assert!(
            !has_overlay(&c, [10, 0, 0, 5]),
            "backend 1 must be gone after its overlay-scoped withdraw"
        );
        assert!(
            has_overlay(&c, [10, 0, 0, 7]),
            "backend 2 (same node, different overlay) must survive"
        );
    }

    /// A caller that doesn't set backend_overlay_ip (the pre-fix / legacy shape) must fall back to
    /// removing by backend_underlay alone, so older callers are not broken by this change.
    #[test]
    fn del_lb_backend_empty_overlay_falls_back_to_underlay_match() {
        let mut c = core();
        add_load_balancer(
            &mut c,
            &pb::AddLoadBalancerRequest {
                id: "lb_ip".into(),
                vni: 100,
                ip: "203.0.113.61".into(),
                lb_underlay: "2001:db8::ef".into(),
                ports: vec![pb::PortProto {
                    port: 443,
                    proto: 6,
                }],
            },
        )
        .expect("add_load_balancer");
        add_lb_backend(
            &mut c,
            &pb::AddLbBackendRequest {
                id: "lb_ip".into(),
                backend_underlay: "2001:db8::2".into(),
                backend_overlay_ip: "10.0.0.9".into(),
                backend_vni: 100,
            },
        )
        .expect("add backend");

        del_lb_backend(
            &mut c,
            &pb::DelLbBackendRequest {
                id: "lb_ip".into(),
                backend_underlay: "2001:db8::2".into(),
                backend_overlay_ip: "".into(), // legacy caller: no overlay IP set
            },
        )
        .expect("legacy del");

        assert!(
            c.writer().maglev.is_empty(),
            "legacy del must still remove the backend"
        );
    }
}
