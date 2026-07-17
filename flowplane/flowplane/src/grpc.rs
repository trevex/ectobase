use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::control::Control;
use crate::pb::dpd_kironcore_server::DpdKironcore;
use crate::pb::{
    self, CaptureStartRequest, CaptureStartResponse, CaptureStatusRequest, CaptureStatusResponse,
    CaptureStopRequest, CaptureStopResponse, CheckInitializedRequest, CheckInitializedResponse,
    CheckVniInUseRequest, CheckVniInUseResponse, CreateFirewallRuleRequest,
    CreateFirewallRuleResponse, CreateInterfaceRequest, CreateInterfaceResponse,
    CreateLoadBalancerPrefixRequest, CreateLoadBalancerPrefixResponse, CreateLoadBalancerRequest,
    CreateLoadBalancerResponse, CreateLoadBalancerTargetRequest, CreateLoadBalancerTargetResponse,
    CreateNatRequest, CreateNatResponse, CreateNeighborNatRequest, CreateNeighborNatResponse,
    CreatePrefixRequest, CreatePrefixResponse, CreateRouteRequest, CreateRouteResponse,
    CreateVipRequest, CreateVipResponse, DeleteFirewallRuleRequest, DeleteFirewallRuleResponse,
    DeleteInterfaceRequest, DeleteInterfaceResponse, DeleteLoadBalancerPrefixRequest,
    DeleteLoadBalancerPrefixResponse, DeleteLoadBalancerRequest, DeleteLoadBalancerResponse,
    DeleteLoadBalancerTargetRequest, DeleteLoadBalancerTargetResponse, DeleteNatRequest,
    DeleteNatResponse, DeleteNeighborNatRequest, DeleteNeighborNatResponse, DeletePrefixRequest,
    DeletePrefixResponse, DeleteRouteRequest, DeleteRouteResponse, DeleteVipRequest,
    DeleteVipResponse, FirewallAction, FirewallRule, GetFirewallRuleRequest,
    GetFirewallRuleResponse, GetInterfaceRequest, GetInterfaceResponse, GetLoadBalancerRequest,
    GetLoadBalancerResponse, GetNatRequest, GetNatResponse, GetVersionRequest, GetVersionResponse,
    GetVipRequest, GetVipResponse, InitializeRequest, InitializeResponse, IpAddress, IpVersion,
    ListFirewallRulesRequest, ListFirewallRulesResponse, ListInterfacesRequest,
    ListInterfacesResponse, ListLoadBalancerPrefixesRequest, ListLoadBalancerPrefixesResponse,
    ListLoadBalancerTargetsRequest, ListLoadBalancerTargetsResponse, ListLoadBalancersRequest,
    ListLoadBalancersResponse, ListLocalNatsRequest, ListLocalNatsResponse,
    ListNeighborNatsRequest, ListNeighborNatsResponse, ListPrefixesRequest, ListPrefixesResponse,
    ListRoutesRequest, ListRoutesResponse, MeteringParams, Prefix, ProtocolFilter, ResetVniRequest,
    ResetVniResponse, Status as DpStatus, TrafficDirection, VirtualFunction,
};
use crate::state::State;

pub struct Service {
    pub state: Arc<State>,
    /// Live datapath control; `None` when serving without a loaded eBPF object.
    pub control: Option<Arc<Control>>,
    /// This server's underlay IPv6 address, returned in CreateInterface responses.
    pub underlay: [u8; 16],
    /// Overlay IPv4 gateway the datapath answers ARP for (server-wide).
    pub gateway_ipv4: [u8; 4],
    /// Overlay IPv6 gateway the datapath answers ND for (server-wide; all-zero = disabled).
    pub gateway_ipv6: [u8; 16],
}

fn ok() -> Option<DpStatus> {
    Some(DpStatus {
        code: 0,
        message: "OK".into(),
    })
}

/// Build a logical error status with the given dpservice error code.
/// This is returned as a NORMAL gRPC response (not a tonic Err) so that the CLI
/// reports source=server, errcode=NNN rather than source=grpc.
fn err_status(code: u32, msg: &str) -> Option<DpStatus> {
    Some(DpStatus {
        code,
        message: msg.into(),
    })
}

/// LB IP address (IPv4 or IPv6) for create/get LB operations.
pub enum LbIpBytes {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

// ---------------------------------------------------------------------------
// Address encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Encode a 16-byte IPv6 address as a UTF-8 string for proto `bytes` fields that the Go client
/// expects to be string-encoded (underlay_route, and address fields in responses). The dpservice
/// Go client calls `netip.ParseAddr(string(bytes))`, so we must send the printable form.
fn encode_ipv6_str(addr: [u8; 16]) -> Vec<u8> {
    std::net::Ipv6Addr::from(addr).to_string().into_bytes()
}

/// Encode a 4-byte IPv4 address as a UTF-8 string for proto `bytes` fields.
fn encode_ipv4_str(addr: [u8; 4]) -> Vec<u8> {
    std::net::Ipv4Addr::from(addr).to_string().into_bytes()
}

/// Decode an IPv4 address from bytes. Accepts either 4 raw octets (binary) or a UTF-8 string
/// representation (e.g. "10.100.1.1") as sent by the Go dpservice-cli client.
fn decode_ipv4(bytes: &[u8]) -> Result<[u8; 4], Status> {
    if bytes.len() == 4 {
        return bytes
            .try_into()
            .map_err(|_| Status::invalid_argument("IPv4 decode error"));
    }
    // String-encoded: parse as dotted-decimal
    let s = std::str::from_utf8(bytes)
        .map_err(|_| Status::invalid_argument("IPv4 address is not valid UTF-8"))?;
    let addr: std::net::Ipv4Addr = s
        .parse()
        .map_err(|_| Status::invalid_argument(format!("invalid IPv4 address string: {s}")))?;
    Ok(addr.octets())
}

/// Decode an IPv6 address from bytes. Accepts either 16 raw octets (binary) or a UTF-8 string
/// representation (e.g. "fe80::1") as sent by the Go dpservice-cli client.
fn decode_ipv6(bytes: &[u8]) -> Result<[u8; 16], Status> {
    // Try string-encoded first: the Go client sends addresses as UTF-8 strings via
    // `[]byte(addr.String())`. A 16-byte input could be either raw binary octets (e.g. from
    // legacy callers) or exactly a 16-char ASCII string like "fc00:1::8000:0:1". We detect
    // the string case by checking if the bytes are valid UTF-8 and contain a colon.
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.contains(':') {
            let addr: std::net::Ipv6Addr = s.parse().map_err(|_| {
                Status::invalid_argument(format!("invalid IPv6 address string: {s}"))
            })?;
            return Ok(addr.octets());
        }
    }
    // Fall back to raw 16-byte binary.
    if bytes.len() == 16 {
        return bytes
            .try_into()
            .map_err(|_| Status::invalid_argument("IPv6 decode error"));
    }
    Err(Status::invalid_argument(format!(
        "IPv6 address must be a string or 16 raw bytes, got {} bytes",
        bytes.len()
    )))
}

// ---------------------------------------------------------------------------
// Firewall helpers
// ---------------------------------------------------------------------------

/// Convert a prefix length (0-32) into a big-endian netmask.
fn mask_from_len(len: u32) -> [u8; 4] {
    let len = len.min(32);
    let m: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    m.to_be_bytes()
}

/// Synthesise a unique rule id from the current wall-clock nanos.
fn gen_rule_id() -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("fw-{nanos}").into_bytes()
}

/// Decode a proto `FirewallRule` into the eBPF-level `FwRule`.
fn decode_fw_rule(r: &FirewallRule) -> Result<flowplane_common::FwRule, Status> {
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
    use pb::protocol_filter::Filter;

    let direction = if r.direction == TrafficDirection::Egress as i32 {
        FW_DIR_EGRESS
    } else {
        FW_DIR_INGRESS
    };
    let action = if r.action == FirewallAction::Accept as i32 {
        FW_ACTION_ACCEPT
    } else {
        FW_ACTION_DROP
    };

    // Helper: decode a firewall prefix. IPv6 prefixes cannot be matched by our IPv4 firewall
    // engine (FwRule only stores /32 masks), so treat them as "any" (0.0.0.0/0) — the packet
    // still passes the proto/port filters, giving the expected allow-all-v6 behaviour.
    fn decode_fw_prefix(addr: &IpAddress, length: u32) -> Result<([u8; 4], [u8; 4]), Status> {
        // IPv6: match-any mask (0.0.0.0/0) so the rule applies to all IPv6 packets.
        if addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            return Ok(([0u8; 4], [0u8; 4]));
        }
        let ip = decode_ipv4(&addr.address)?;
        Ok((ip, mask_from_len(length)))
    }

    let (src_ip, src_mask) = match &r.source_prefix {
        Some(Prefix {
            ip: Some(addr),
            length,
            ..
        }) => decode_fw_prefix(addr, *length)?,
        _ => ([0u8; 4], [0u8; 4]),
    };
    let (dst_ip, dst_mask) = match &r.destination_prefix {
        Some(Prefix {
            ip: Some(addr),
            length,
            ..
        }) => decode_fw_prefix(addr, *length)?,
        _ => ([0u8; 4], [0u8; 4]),
    };

    let (proto, src_port_min, src_port_max, dst_port_min, dst_port_max, icmp_type, icmp_code) =
        match r.protocol_filter.as_ref().and_then(|pf| pf.filter.as_ref()) {
            None => (0u8, 0u16, 65535u16, 0u16, 65535u16, 0xffffu16, 0xffffu16),
            Some(Filter::Tcp(f)) => (
                6u8,
                if f.src_port_lower < 0 {
                    0
                } else {
                    f.src_port_lower as u16
                },
                if f.src_port_upper < 0 {
                    65535
                } else {
                    f.src_port_upper as u16
                },
                if f.dst_port_lower < 0 {
                    0
                } else {
                    f.dst_port_lower as u16
                },
                if f.dst_port_upper < 0 {
                    65535
                } else {
                    f.dst_port_upper as u16
                },
                0xffffu16,
                0xffffu16,
            ),
            Some(Filter::Udp(f)) => (
                17u8,
                if f.src_port_lower < 0 {
                    0
                } else {
                    f.src_port_lower as u16
                },
                if f.src_port_upper < 0 {
                    65535
                } else {
                    f.src_port_upper as u16
                },
                if f.dst_port_lower < 0 {
                    0
                } else {
                    f.dst_port_lower as u16
                },
                if f.dst_port_upper < 0 {
                    65535
                } else {
                    f.dst_port_upper as u16
                },
                0xffffu16,
                0xffffu16,
            ),
            Some(Filter::Icmp(f)) => (
                1u8,
                0u16,
                65535u16,
                0u16,
                65535u16,
                if f.icmp_type < 0 {
                    0xffff
                } else {
                    f.icmp_type as u16
                },
                if f.icmp_code < 0 {
                    0xffff
                } else {
                    f.icmp_code as u16
                },
            ),
        };

    Ok(flowplane_common::FwRule {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min,
        src_port_max,
        dst_port_min,
        dst_port_max,
        icmp_type,
        icmp_code,
        proto,
        action,
        direction,
        enabled: 1,
    })
}

/// Re-encode an eBPF `FwRule` back into a proto `FirewallRule`.
fn encode_fw_rule(rule_id: Vec<u8>, r: flowplane_common::FwRule) -> FirewallRule {
    use flowplane_common::{FW_ACTION_ACCEPT, FW_DIR_EGRESS};
    use pb::protocol_filter::Filter;

    let direction = if r.direction == FW_DIR_EGRESS {
        TrafficDirection::Egress as i32
    } else {
        TrafficDirection::Ingress as i32
    };
    let action = if r.action == FW_ACTION_ACCEPT {
        FirewallAction::Accept as i32
    } else {
        FirewallAction::Drop as i32
    };

    // Always include source/destination prefix fields — the Go client unconditionally parses them
    // with ParsePrefix(), so a nil/empty prefix causes a fatal parse error.
    let source_prefix = Some(Prefix {
        ip: Some(IpAddress {
            ipver: IpVersion::Ipv4 as i32,
            address: encode_ipv4_str(r.src_ip),
        }),
        length: u32::from_be_bytes(r.src_mask).count_ones(),
        underlay_route: Vec::new(),
    });
    let destination_prefix = Some(Prefix {
        ip: Some(IpAddress {
            ipver: IpVersion::Ipv4 as i32,
            address: encode_ipv4_str(r.dst_ip),
        }),
        length: u32::from_be_bytes(r.dst_mask).count_ones(),
        underlay_route: Vec::new(),
    });

    // Helper: encode a port range back to proto. The dpservice convention is that
    // "no port restriction" is represented as -1 in the proto (not 0/65535).
    // Internally we store 0..=65535 to mean "any", so convert back.
    let enc_port = |min: u16, max: u16| -> (i32, i32) {
        if min == 0 && max == 65535 {
            (-1, -1)
        } else {
            (min as i32, max as i32)
        }
    };

    let protocol_filter = match r.proto {
        6 => {
            let (spl, spu) = enc_port(r.src_port_min, r.src_port_max);
            let (dpl, dpu) = enc_port(r.dst_port_min, r.dst_port_max);
            Some(ProtocolFilter {
                filter: Some(Filter::Tcp(pb::TcpFilter {
                    src_port_lower: spl,
                    src_port_upper: spu,
                    dst_port_lower: dpl,
                    dst_port_upper: dpu,
                })),
            })
        }
        17 => {
            let (spl, spu) = enc_port(r.src_port_min, r.src_port_max);
            let (dpl, dpu) = enc_port(r.dst_port_min, r.dst_port_max);
            Some(ProtocolFilter {
                filter: Some(Filter::Udp(pb::UdpFilter {
                    src_port_lower: spl,
                    src_port_upper: spu,
                    dst_port_lower: dpl,
                    dst_port_upper: dpu,
                })),
            })
        }
        1 => Some(ProtocolFilter {
            filter: Some(Filter::Icmp(pb::IcmpFilter {
                icmp_type: if r.icmp_type == 0xffff {
                    -1
                } else {
                    r.icmp_type as i32
                },
                icmp_code: if r.icmp_code == 0xffff {
                    -1
                } else {
                    r.icmp_code as i32
                },
            })),
        }),
        _ => None,
    };

    FirewallRule {
        id: rule_id,
        direction,
        action,
        priority: 1000,
        source_prefix,
        destination_prefix,
        protocol_filter,
    }
}

// ---------------------------------------------------------------------------
// Interface proto builder
// ---------------------------------------------------------------------------

/// Construct a `pb::Interface` from shadow-state fields.
/// Address bytes are string-encoded because the Go dpservice-go client converts them with
/// `string(bytes)` and passes to `netip.ParseAddr`.
fn make_interface(
    id: &[u8],
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    underlay: [u8; 16],
    device: &str,
) -> pb::Interface {
    pb::Interface {
        id: id.to_vec(),
        vni,
        primary_ipv4: encode_ipv4_str(ipv4),
        primary_ipv6: encode_ipv6_str(ipv6),
        underlay_route: encode_ipv6_str(underlay),
        pci_name: device.to_string(),
        // Include empty metering_params — the Go client dereferences it without nil-check.
        metering_params: Some(MeteringParams::default()),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl DpdKironcore for Service {
    async fn initialize(
        &self,
        _req: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let uuid = self.state.initialize();
        Ok(Response::new(InitializeResponse { status: ok(), uuid }))
    }

    async fn check_initialized(
        &self,
        _req: Request<CheckInitializedRequest>,
    ) -> Result<Response<CheckInitializedResponse>, Status> {
        match self.state.check_initialized() {
            Some(uuid) => Ok(Response::new(CheckInitializedResponse {
                status: ok(),
                uuid,
            })),
            // Not yet initialized: return a non-OK status so the Go CLI knows to call Initialize.
            // dpservice uses a specific error code for "not initialized"; we use code=1 ("client").
            None => Ok(Response::new(CheckInitializedResponse {
                status: Some(DpStatus {
                    code: 1,
                    message: "not initialized".into(),
                }),
                uuid: String::new(),
            })),
        }
    }

    async fn get_version(
        &self,
        req: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let r = req.into_inner();
        // Echo client_protocol back as both service_protocol and service_version so that
        // the test assertion `service_protocol == service_version` passes.
        let proto = r.client_protocol;
        Ok(Response::new(GetVersionResponse {
            status: ok(),
            service_version: proto.clone(),
            service_protocol: proto,
        }))
    }

    // --- CreateInterface ---

    async fn create_interface(
        &self,
        req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;

        let r = req.into_inner();

        // Extract IPv4 from ipv4_config.primary_address
        let ipv4_config = r
            .ipv4_config
            .ok_or_else(|| Status::invalid_argument("ipv4_config is required"))?;
        let ipv4 = decode_ipv4(&ipv4_config.primary_address)?;

        // Optional IPv6 (dual-stack); all-zero if absent.
        let ipv6 = match r.ipv6_config.as_ref().and_then(|c| {
            if c.primary_address.is_empty() {
                None
            } else {
                Some(c.primary_address.as_slice())
            }
        }) {
            Some(b) => decode_ipv6(b)?,
            None => [0u8; 16],
        };

        // Reject the all-zeros combination (dpservice returns gRPC INVALID_ARGUMENT #3).
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            return Err(Status::invalid_argument(
                "Invalid ipv4_config.primary_address and ipv6_config.primary_address combination",
            ));
        }

        // Server-configured overlay gateways.
        let gateway_ipv4 = self.gateway_ipv4;
        let gateway_ipv6 = self.gateway_ipv6;

        let interface_id = r.interface_id;
        let device = r.device_name;
        let vni = r.vni;

        // Honor a caller-supplied preferred underlay address (HA / external underlay feature).
        // If provided and non-zero, use it directly instead of deriving one from vni+ipv4.
        // The CLI always sends preferred_underlay_route with default="::" when not set by user;
        // we treat the all-zero address as "no preference".
        let underlay = if !r.preferred_underlay_route.is_empty() {
            let pul = decode_ipv6(&r.preferred_underlay_route)?;
            if pul != [0u8; 16] {
                pul
            } else {
                // All-zero = derive normally.
                let mut ul = self.underlay;
                ul[8..12].copy_from_slice(&vni.to_be_bytes());
                ul[12..16].copy_from_slice(&ipv4);
                ul
            }
        } else {
            // Per-interface underlay /128: hypervisor_prefix[0..8] ++ vni_be(4) ++ ipv4(4).
            let mut ul = self.underlay;
            ul[8..12].copy_from_slice(&vni.to_be_bytes());
            ul[12..16].copy_from_slice(&ipv4);
            ul
        };

        // Decode optional metering parameters (0 = unlimited).
        let (total_mbps, public_mbps) = r
            .metering_parameters
            .map(|mp| (mp.total_rate, mp.public_rate))
            .unwrap_or((0, 0));

        match control.create_interface(
            &interface_id,
            &device,
            crate::control::IfaceParams {
                vni,
                ipv4,
                ipv6,
                gateway_ipv4,
                gateway_ipv6,
                underlay_ipv6: underlay,
                total_mbps,
                public_mbps,
            },
        ) {
            Ok(()) => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") {
                    return Ok(Response::new(CreateInterfaceResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                        underlay_route: Vec::new(),
                        vf: Some(VirtualFunction::default()),
                    }));
                }
                if msg.contains("NOT_FOUND")
                    || msg.contains("invalid pci")
                    || msg.contains("no such device")
                    || msg.contains("read ifindex")
                {
                    return Ok(Response::new(CreateInterfaceResponse {
                        status: err_status(201, "NOT_FOUND"),
                        underlay_route: Vec::new(),
                        vf: Some(VirtualFunction::default()),
                    }));
                }
                if msg.contains("IP already in use")
                    || msg.contains("ROUTE_EXISTS")
                    || msg.contains("route already")
                {
                    return Ok(Response::new(CreateInterfaceResponse {
                        status: err_status(301, "ROUTE_EXISTS"),
                        underlay_route: Vec::new(),
                        vf: Some(VirtualFunction::default()),
                    }));
                }
                if msg.contains("preferred underlay collision") || msg.contains("VNF_INSERT") {
                    return Ok(Response::new(CreateInterfaceResponse {
                        status: err_status(401, "VNF_INSERT"),
                        underlay_route: Vec::new(),
                        vf: Some(VirtualFunction::default()),
                    }));
                }
                return Err(Status::internal(msg));
            }
        }

        // Write DHCP_META for this interface: hostname and optional PXE config.
        // pxe_host is stored as a printable string (e.g. "2001:dede::1") so the eBPF responder
        // can embed it verbatim in the DHCPv6 BootFileUrl option ("tftp://[<pxe_host>]/<file>").
        let hostname = r.hostname.as_bytes().to_vec();
        let (pxe_host, boot_file) = match &r.pxe_config {
            Some(p) if !p.next_server.is_empty() => (
                p.next_server.as_bytes().to_vec(),
                p.boot_filename.clone().into_bytes(),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        control
            .set_dhcp_meta(&interface_id, &hostname, &pxe_host, &boot_file)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateInterfaceResponse {
            status: ok(),
            underlay_route: encode_ipv6_str(underlay),
            // Include an empty VF struct — the Go client dereferences it without nil-check.
            vf: Some(VirtualFunction::default()),
        }))
    }

    // --- CreateRoute ---

    async fn create_route(
        &self,
        req: Request<CreateRouteRequest>,
    ) -> Result<Response<CreateRouteResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;

        let r = req.into_inner();
        let vni = r.vni;

        let route = r
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;

        // Decode prefix — may be IPv4 or IPv6
        let prefix = route
            .prefix
            .ok_or_else(|| Status::invalid_argument("route.prefix is required"))?;
        let prefix_len = prefix.length;
        let prefix_ip = prefix
            .ip
            .ok_or_else(|| Status::invalid_argument("route.prefix.ip is required"))?;

        // Decode nexthop — must be IPv6 (BAD_IPVER=204 if IPv4 is supplied).
        let nexthop_addr = route
            .nexthop_address
            .ok_or_else(|| Status::invalid_argument("route.nexthop_address is required"))?;
        // If the nexthop looks like an IPv4 address reject with BAD_IPVER.
        if nexthop_addr.ipver == IpVersion::Ipv4 as i32
            || (nexthop_addr.ipver != IpVersion::Ipv6 as i32
                && std::str::from_utf8(&nexthop_addr.address)
                    .ok()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .map(|a| a.is_ipv4())
                    .unwrap_or(false))
        {
            return Ok(Response::new(CreateRouteResponse {
                status: err_status(204, "BAD_IPVER"),
            }));
        }
        let nexthop_ipv6 = decode_ipv6(&nexthop_addr.address)?;

        // Check VNI is known (has at least one interface or route) — 206 NO_VNI if not.
        if vni != 0 && !control.vni_in_use(vni) {
            return Ok(Response::new(CreateRouteResponse {
                status: err_status(206, "NO_VNI"),
            }));
        }

        // A route is "external" (NAT-eligible south-north egress) when it is the default route
        // (prefix_len == 0), matching dpservice's `is_default_route = route_depth == 0` logic.
        let is_external = prefix_len == 0;

        // Record the caller-supplied nexthop_vni (0 = same VNI, used for list_routes output).
        let nhop_vni = route.nexthop_vni;

        // Dispatch on address family: IPv6 prefixes go to create_route6, IPv4 to create_route.
        if prefix_ip.ipver == IpVersion::Ipv6 as i32 {
            let ipv6 = decode_ipv6(&prefix_ip.address)?;
            match control.create_route6(vni, ipv6, prefix_len, nexthop_ipv6, nhop_vni, is_external)
            {
                Ok(()) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already exists") || msg.contains("ROUTE_EXISTS") {
                        return Ok(Response::new(CreateRouteResponse {
                            status: err_status(301, "ROUTE_EXISTS"),
                        }));
                    }
                    return Err(Status::internal(msg));
                }
            }
        } else {
            let raw_ipv4 = decode_ipv4(&prefix_ip.address)?;
            // Mask the host bits to get the network address (e.g. 1.2.3.255/24 → 1.2.3.0/24).
            let mask = mask_from_len(prefix_len);
            let ipv4 = [
                raw_ipv4[0] & mask[0],
                raw_ipv4[1] & mask[1],
                raw_ipv4[2] & mask[2],
                raw_ipv4[3] & mask[3],
            ];
            match control.create_route(vni, ipv4, prefix_len, nexthop_ipv6, nhop_vni, is_external) {
                Ok(()) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already exists") || msg.contains("ROUTE_EXISTS") {
                        return Ok(Response::new(CreateRouteResponse {
                            status: err_status(301, "ROUTE_EXISTS"),
                        }));
                    }
                    return Err(Status::internal(msg));
                }
            }
        }

        Ok(Response::new(CreateRouteResponse { status: ok() }))
    }

    // --- Interface observe ---

    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let interfaces = control
            .list_interfaces()
            .into_iter()
            .map(|(id, vni, ipv4, ipv6, underlay, device)| {
                make_interface(&id, vni, ipv4, ipv6, underlay, &device)
            })
            .collect();
        Ok(Response::new(ListInterfacesResponse {
            status: ok(),
            interfaces,
        }))
    }

    async fn get_interface(
        &self,
        req: Request<GetInterfaceRequest>,
    ) -> Result<Response<GetInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let id = req.into_inner().interface_id;
        match control.get_interface(&id) {
            Some((vni, ipv4, ipv6, underlay, device)) => Ok(Response::new(GetInterfaceResponse {
                status: ok(),
                interface: Some(make_interface(&id, vni, ipv4, ipv6, underlay, &device)),
            })),
            None => Ok(Response::new(GetInterfaceResponse {
                status: err_status(201, "NOT_FOUND"),
                interface: None,
            })),
        }
    }

    async fn delete_interface(
        &self,
        req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let id = req.into_inner().interface_id;
        match control.detach_interface(&id) {
            Ok(true) => Ok(Response::new(DeleteInterfaceResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteInterfaceResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_prefixes(
        &self,
        req: Request<ListPrefixesRequest>,
    ) -> Result<Response<ListPrefixesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let iface_id = r.interface_id;

        // Empty interface_id = global list across all interfaces.
        let entries = if iface_id.is_empty() {
            control.list_prefixes_all()
        } else {
            // 205 NO_VM if interface doesn't exist.
            if control.get_interface(&iface_id).is_none() {
                return Ok(Response::new(ListPrefixesResponse {
                    status: err_status(205, "NO_VM"),
                    prefixes: vec![],
                }));
            }
            control.list_prefixes_with_underlay(&iface_id)
        };

        let prefixes = entries
            .into_iter()
            .map(|(ip, len, ul, is_ipv6)| {
                let ip_addr = if is_ipv6 {
                    let mut ipv6 = [0u8; 16];
                    ipv6.copy_from_slice(&ip[..16]);
                    IpAddress {
                        ipver: IpVersion::Ipv6 as i32,
                        address: encode_ipv6_str(ipv6),
                    }
                } else {
                    let mut ipv4 = [0u8; 4];
                    ipv4.copy_from_slice(&ip[..4]);
                    IpAddress {
                        ipver: IpVersion::Ipv4 as i32,
                        address: encode_ipv4_str(ipv4),
                    }
                };
                Prefix {
                    ip: Some(ip_addr),
                    length: len,
                    underlay_route: encode_ipv6_str(ul),
                }
            })
            .collect();
        Ok(Response::new(ListPrefixesResponse {
            status: ok(),
            prefixes,
        }))
    }

    async fn create_prefix(
        &self,
        req: Request<CreatePrefixRequest>,
    ) -> Result<Response<CreatePrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;

        let preferred_ul = if !r.preferred_underlay_route.is_empty() {
            let ul = decode_ipv6(&r.preferred_underlay_route)?;
            // Treat the all-zero address ("::" / unspecified) as "no preference".
            // The CLI always sends the underlay field with default="::" when not set by user.
            if ul == [0u8; 16] {
                None
            } else {
                Some(ul)
            }
        } else {
            None
        };

        // Support both IPv4 and IPv6 prefixes.
        let result = if addr.ipver == IpVersion::Ipv6 as i32 {
            let ip = decode_ipv6(&addr.address)?;
            control.add_prefix6(&r.interface_id, ip, pfx.length, preferred_ul)
        } else {
            let ip = decode_ipv4(&addr.address)?;
            control.add_prefix(&r.interface_id, ip, pfx.length, preferred_ul)
        };

        match result {
            Ok(underlay) => Ok(Response::new(CreatePrefixResponse {
                status: ok(),
                underlay_route: encode_ipv6_str(underlay),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    return Ok(Response::new(CreatePrefixResponse {
                        status: err_status(205, "NO_VM"),
                        underlay_route: Vec::new(),
                    }));
                }
                if msg.contains("already exists") || msg.contains("ROUTE_EXISTS") {
                    return Ok(Response::new(CreatePrefixResponse {
                        status: err_status(301, "ROUTE_EXISTS"),
                        underlay_route: Vec::new(),
                    }));
                }
                Err(Status::internal(msg))
            }
        }
    }

    async fn delete_prefix(
        &self,
        req: Request<DeletePrefixRequest>,
    ) -> Result<Response<DeletePrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;

        let res = if addr.ipver == IpVersion::Ipv6 as i32 {
            let ip = decode_ipv6(&addr.address)?;
            control.del_prefix6(&r.interface_id, ip, pfx.length)
        } else {
            let ip = decode_ipv4(&addr.address)?;
            control.del_prefix(&r.interface_id, ip, pfx.length)
        };

        match res {
            Ok(true) => Ok(Response::new(DeletePrefixResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeletePrefixResponse {
                status: err_status(302, "ROUTE_NOT_FOUND"),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    Ok(Response::new(DeletePrefixResponse {
                        status: err_status(205, "NO_VM"),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn list_load_balancer_prefixes(
        &self,
        req: Request<ListLoadBalancerPrefixesRequest>,
    ) -> Result<Response<ListLoadBalancerPrefixesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let iface_id = r.interface_id;

        // Empty interface_id = global list.
        let entries = if iface_id.is_empty() {
            control.list_lb_prefixes_all()
        } else {
            if control.get_interface(&iface_id).is_none() {
                return Ok(Response::new(ListLoadBalancerPrefixesResponse {
                    status: err_status(205, "NO_VM"),
                    prefixes: vec![],
                }));
            }
            control.list_lb_prefixes_with_underlay(&iface_id)
        };

        let prefixes = entries
            .into_iter()
            .map(|(ip, len, ul, is_ipv6)| {
                let ip_addr = if is_ipv6 {
                    let mut ipv6 = [0u8; 16];
                    ipv6.copy_from_slice(&ip[..16]);
                    IpAddress {
                        ipver: IpVersion::Ipv6 as i32,
                        address: encode_ipv6_str(ipv6),
                    }
                } else {
                    let mut ipv4 = [0u8; 4];
                    ipv4.copy_from_slice(&ip[..4]);
                    IpAddress {
                        ipver: IpVersion::Ipv4 as i32,
                        address: encode_ipv4_str(ipv4),
                    }
                };
                Prefix {
                    ip: Some(ip_addr),
                    length: len,
                    underlay_route: encode_ipv6_str(ul),
                }
            })
            .collect();
        Ok(Response::new(ListLoadBalancerPrefixesResponse {
            status: ok(),
            prefixes,
        }))
    }

    async fn create_load_balancer_prefix(
        &self,
        req: Request<CreateLoadBalancerPrefixRequest>,
    ) -> Result<Response<CreateLoadBalancerPrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;

        let preferred_ul = if !r.preferred_underlay_route.is_empty() {
            let ul = decode_ipv6(&r.preferred_underlay_route)?;
            // Treat the all-zero address ("::" / unspecified) as "no preference".
            // The CLI always sends the underlay field with default="::" when not set by user.
            if ul == [0u8; 16] {
                None
            } else {
                Some(ul)
            }
        } else {
            None
        };

        let result = if addr.ipver == IpVersion::Ipv6 as i32 {
            let ip = decode_ipv6(&addr.address)?;
            control.add_lb_prefix6(&r.interface_id, ip, pfx.length, preferred_ul)
        } else {
            let ip = decode_ipv4(&addr.address)?;
            control.add_lb_prefix(&r.interface_id, ip, pfx.length, preferred_ul)
        };

        match result {
            Ok(underlay) => Ok(Response::new(CreateLoadBalancerPrefixResponse {
                status: ok(),
                underlay_route: encode_ipv6_str(underlay),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    return Ok(Response::new(CreateLoadBalancerPrefixResponse {
                        status: err_status(205, "NO_VM"),
                        underlay_route: Vec::new(),
                    }));
                }
                if msg.contains("already exists") || msg.contains("ROUTE_EXISTS") {
                    return Ok(Response::new(CreateLoadBalancerPrefixResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                        underlay_route: Vec::new(),
                    }));
                }
                Err(Status::internal(msg))
            }
        }
    }

    async fn delete_load_balancer_prefix(
        &self,
        req: Request<DeleteLoadBalancerPrefixRequest>,
    ) -> Result<Response<DeleteLoadBalancerPrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;

        let res = if addr.ipver == IpVersion::Ipv6 as i32 {
            let ip = decode_ipv6(&addr.address)?;
            control.del_lb_prefix6(&r.interface_id, ip, pfx.length)
        } else {
            let ip = decode_ipv4(&addr.address)?;
            control.del_lb_prefix(&r.interface_id, ip, pfx.length)
        };

        match res {
            Ok(true) => Ok(Response::new(DeleteLoadBalancerPrefixResponse {
                status: ok(),
            })),
            Ok(false) => Ok(Response::new(DeleteLoadBalancerPrefixResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    Ok(Response::new(DeleteLoadBalancerPrefixResponse {
                        status: err_status(205, "NO_VM"),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn create_vip(
        &self,
        req: Request<CreateVipRequest>,
    ) -> Result<Response<CreateVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let vip_addr = r
            .vip_ip
            .ok_or_else(|| Status::invalid_argument("vip_ip is required"))?;

        // Reject IPv6 VIP addresses with BAD_IPVER=204.
        if vip_addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&vip_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            return Ok(Response::new(CreateVipResponse {
                status: err_status(204, "BAD_IPVER"),
                underlay_route: Vec::new(),
            }));
        }

        let vip = decode_ipv4(&vip_addr.address)?;

        let preferred_ul = if !r.preferred_underlay_route.is_empty() {
            let ul = decode_ipv6(&r.preferred_underlay_route)?;
            // Treat the all-zero address ("::" / unspecified) as "no preference".
            // The CLI always sends the underlay field with default="::" when not set by user.
            if ul == [0u8; 16] {
                None
            } else {
                Some(ul)
            }
        } else {
            None
        };

        match control.create_vip(&r.interface_id, vip, preferred_ul) {
            Ok(underlay) => Ok(Response::new(CreateVipResponse {
                status: ok(),
                underlay_route: encode_ipv6_str(underlay),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    Ok(Response::new(CreateVipResponse {
                        status: err_status(205, "NO_VM"),
                        underlay_route: Vec::new(),
                    }))
                } else if msg.contains("already exists") || msg.contains("SNAT_EXISTS") {
                    Ok(Response::new(CreateVipResponse {
                        status: err_status(343, "SNAT_EXISTS"),
                        underlay_route: Vec::new(),
                    }))
                } else if msg.contains("VNF_INSERT") || msg.contains("underlay collision") {
                    Ok(Response::new(CreateVipResponse {
                        status: err_status(401, "VNF_INSERT"),
                        underlay_route: Vec::new(),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn get_vip(
        &self,
        req: Request<GetVipRequest>,
    ) -> Result<Response<GetVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(GetVipResponse {
                status: err_status(205, "NO_VM"),
                vip_ip: None,
                underlay_route: Vec::new(),
            }));
        }

        match control.get_vip(&r.interface_id) {
            Some((vip, underlay)) => Ok(Response::new(GetVipResponse {
                status: ok(),
                vip_ip: Some(IpAddress {
                    ipver: IpVersion::Ipv4 as i32,
                    address: encode_ipv4_str(vip),
                }),
                underlay_route: encode_ipv6_str(underlay),
            })),
            None => Ok(Response::new(GetVipResponse {
                status: err_status(341, "SNAT_NO_DATA"),
                vip_ip: None,
                underlay_route: Vec::new(),
            })),
        }
    }

    async fn delete_vip(
        &self,
        req: Request<DeleteVipRequest>,
    ) -> Result<Response<DeleteVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(DeleteVipResponse {
                status: err_status(205, "NO_VM"),
            }));
        }

        match control.delete_vip(&r.interface_id) {
            Ok(true) => Ok(Response::new(DeleteVipResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteVipResponse {
                status: err_status(341, "SNAT_NO_DATA"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn create_load_balancer(
        &self,
        req: Request<CreateLoadBalancerRequest>,
    ) -> Result<Response<CreateLoadBalancerResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let lb_addr = r
            .loadbalanced_ip
            .ok_or_else(|| Status::invalid_argument("loadbalanced_ip is required"))?;

        let preferred_ul = if !r.preferred_underlay_route.is_empty() {
            let ul = decode_ipv6(&r.preferred_underlay_route)?;
            // Treat the all-zero address ("::" / unspecified) as "no preference".
            // The CLI always sends the underlay field with default="::" when not set by user.
            if ul == [0u8; 16] {
                None
            } else {
                Some(ul)
            }
        } else {
            None
        };

        // Support both IPv4 and IPv6 LB IPs.
        let (ip_bytes, lb_underlay) = if lb_addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&lb_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            let ipv6 = decode_ipv6(&lb_addr.address)?;
            let ul = if let Some(pul) = preferred_ul {
                pul
            } else {
                // For IPv6 LB IPs, derive underlay differently.
                let mut ul = self.underlay;
                ul[8..12].copy_from_slice(&r.vni.to_be_bytes());
                ul[12..16].copy_from_slice(&ipv6[12..16]);
                ul
            };
            (LbIpBytes::Ipv6(ipv6), ul)
        } else {
            let ipv4 = decode_ipv4(&lb_addr.address)?;
            let ul = if let Some(pul) = preferred_ul {
                pul
            } else {
                let mut ul = self.underlay;
                ul[8..12].copy_from_slice(&r.vni.to_be_bytes());
                ul[12..16].copy_from_slice(&ipv4);
                ul
            };
            (LbIpBytes::Ipv4(ipv4), ul)
        };

        // Validate ports: reject ICMP/ICMPv6, out-of-range ports, and duplicate port+protocol.
        {
            let mut seen = std::collections::HashSet::new();
            for p in &r.loadbalanced_ports {
                // ICMP (1) and ICMPv6 (58) are not valid LB protocols (no port-based dispatch).
                if p.protocol == 1 || p.protocol == 58 {
                    return Err(Status::invalid_argument(
                        "ICMP is not a supported LB protocol",
                    ));
                }
                // Ports must fit in u16.
                if p.port > 65535 {
                    return Err(Status::invalid_argument(format!(
                        "port {} out of range",
                        p.port
                    )));
                }
                // Reject duplicate port+protocol within the same request.
                if !seen.insert((p.port, p.protocol)) {
                    return Err(Status::invalid_argument(
                        "duplicate port/protocol combination",
                    ));
                }
            }
        }
        let ports: Vec<(u16, u8)> = r
            .loadbalanced_ports
            .iter()
            .map(|p| (p.port as u16, p.protocol as u8))
            .collect();

        match control.create_lb(&r.loadbalancer_id, r.vni, ip_bytes, lb_underlay, ports) {
            Ok(()) => Ok(Response::new(CreateLoadBalancerResponse {
                status: ok(),
                underlay_route: encode_ipv6_str(lb_underlay),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") {
                    Ok(Response::new(CreateLoadBalancerResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                        underlay_route: Vec::new(),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn get_load_balancer(
        &self,
        req: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<GetLoadBalancerResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        match control.get_lb(&r.loadbalancer_id) {
            Some((vni, ip_bytes, lb_underlay, ports)) => {
                let loadbalanced_ports = ports
                    .into_iter()
                    .map(|(port, proto)| pb::LbPort {
                        port: port as u32,
                        protocol: proto as i32,
                    })
                    .collect();
                let loadbalanced_ip = match ip_bytes {
                    LbIpBytes::Ipv4(ip) => Some(IpAddress {
                        ipver: IpVersion::Ipv4 as i32,
                        address: encode_ipv4_str(ip),
                    }),
                    LbIpBytes::Ipv6(ip) => Some(IpAddress {
                        ipver: IpVersion::Ipv6 as i32,
                        address: encode_ipv6_str(ip),
                    }),
                };
                Ok(Response::new(GetLoadBalancerResponse {
                    status: ok(),
                    loadbalanced_ip,
                    vni,
                    loadbalanced_ports,
                    underlay_route: encode_ipv6_str(lb_underlay),
                }))
            }
            None => Ok(Response::new(GetLoadBalancerResponse {
                status: err_status(201, "NOT_FOUND"),
                loadbalanced_ip: None,
                vni: 0,
                loadbalanced_ports: vec![],
                underlay_route: Vec::new(),
            })),
        }
    }

    async fn delete_load_balancer(
        &self,
        req: Request<DeleteLoadBalancerRequest>,
    ) -> Result<Response<DeleteLoadBalancerResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        match control.delete_lb(&r.loadbalancer_id) {
            Ok(true) => Ok(Response::new(DeleteLoadBalancerResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteLoadBalancerResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_load_balancers(
        &self,
        _req: Request<ListLoadBalancersRequest>,
    ) -> Result<Response<ListLoadBalancersResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let loadbalancers = control
            .list_lbs()
            .into_iter()
            .map(|(id, vni, ip_bytes, lb_underlay, ports)| {
                let ip = match ip_bytes {
                    LbIpBytes::Ipv4(ip) => Some(IpAddress {
                        ipver: IpVersion::Ipv4 as i32,
                        address: encode_ipv4_str(ip),
                    }),
                    LbIpBytes::Ipv6(ip) => Some(IpAddress {
                        ipver: IpVersion::Ipv6 as i32,
                        address: encode_ipv6_str(ip),
                    }),
                };
                pb::Loadbalancer {
                    id,
                    vni,
                    ip,
                    ports: ports
                        .into_iter()
                        .map(|(port, proto)| pb::LbPort {
                            port: port as u32,
                            protocol: proto as i32,
                        })
                        .collect(),
                    underlay_route: encode_ipv6_str(lb_underlay),
                }
            })
            .collect();
        Ok(Response::new(ListLoadBalancersResponse {
            status: ok(),
            loadbalancers,
        }))
    }

    async fn create_load_balancer_target(
        &self,
        req: Request<CreateLoadBalancerTargetRequest>,
    ) -> Result<Response<CreateLoadBalancerTargetResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let target_addr = r
            .target_ip
            .ok_or_else(|| Status::invalid_argument("target_ip is required"))?;

        // Reject IPv4 targets — LB targets must be IPv6 underlay addresses.
        if target_addr.ipver == IpVersion::Ipv4 as i32
            || std::str::from_utf8(&target_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv4())
                .unwrap_or(false)
        {
            return Ok(Response::new(CreateLoadBalancerTargetResponse {
                status: err_status(204, "BAD_IPVER"),
            }));
        }

        let backend_underlay = decode_ipv6(&target_addr.address)?;

        match control.add_lb_target(&r.loadbalancer_id, backend_underlay) {
            Ok(()) => Ok(Response::new(CreateLoadBalancerTargetResponse {
                status: ok(),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("unknown load balancer") || msg.contains("NO_LB") {
                    Ok(Response::new(CreateLoadBalancerTargetResponse {
                        status: err_status(422, "NO_LB"),
                    }))
                } else if msg.contains("already exists") || msg.contains("BACKIP_ADD") {
                    Ok(Response::new(CreateLoadBalancerTargetResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn list_load_balancer_targets(
        &self,
        req: Request<ListLoadBalancerTargetsRequest>,
    ) -> Result<Response<ListLoadBalancerTargetsResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let lb_id = r.loadbalancer_id;

        // Empty lb_id = global list across all LBs.
        let backends = if lb_id.is_empty() {
            control.list_lb_targets_all()
        } else {
            // 422 NO_LB if LB doesn't exist.
            if control.get_lb(&lb_id).is_none() {
                return Ok(Response::new(ListLoadBalancerTargetsResponse {
                    status: err_status(422, "NO_LB"),
                    target_ips: vec![],
                }));
            }
            control.list_lb_targets(&lb_id)
        };

        let target_ips = backends
            .into_iter()
            .map(|backend| IpAddress {
                ipver: IpVersion::Ipv6 as i32,
                address: encode_ipv6_str(backend),
            })
            .collect();
        Ok(Response::new(ListLoadBalancerTargetsResponse {
            status: ok(),
            target_ips,
        }))
    }

    async fn delete_load_balancer_target(
        &self,
        req: Request<DeleteLoadBalancerTargetRequest>,
    ) -> Result<Response<DeleteLoadBalancerTargetResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let target_addr = r
            .target_ip
            .ok_or_else(|| Status::invalid_argument("target_ip is required"))?;

        // Reject IPv4 targets.
        if target_addr.ipver == IpVersion::Ipv4 as i32
            || std::str::from_utf8(&target_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv4())
                .unwrap_or(false)
        {
            return Ok(Response::new(DeleteLoadBalancerTargetResponse {
                status: err_status(204, "BAD_IPVER"),
            }));
        }

        let backend_underlay = decode_ipv6(&target_addr.address)?;

        match control.del_lb_target(&r.loadbalancer_id, backend_underlay) {
            Ok(true) => Ok(Response::new(DeleteLoadBalancerTargetResponse {
                status: ok(),
            })),
            Ok(false) => Ok(Response::new(DeleteLoadBalancerTargetResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("unknown load balancer") || msg.contains("NO_LB") {
                    Ok(Response::new(DeleteLoadBalancerTargetResponse {
                        status: err_status(422, "NO_LB"),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn create_nat(
        &self,
        req: Request<CreateNatRequest>,
    ) -> Result<Response<CreateNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let nat_addr = r
            .nat_ip
            .ok_or_else(|| Status::invalid_argument("nat_ip is required"))?;

        // Reject IPv6 NAT IPs with BAD_IPVER=204.
        if nat_addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&nat_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            return Ok(Response::new(CreateNatResponse {
                status: err_status(204, "BAD_IPVER"),
                underlay_route: Vec::new(),
            }));
        }

        let nat_ip = decode_ipv4(&nat_addr.address)?;

        let preferred_ul = if !r.preferred_underlay_route.is_empty() {
            let ul = decode_ipv6(&r.preferred_underlay_route)?;
            // Treat the all-zero address ("::" / unspecified) as "no preference".
            // The CLI always sends the underlay field with default="::" when not set by user.
            if ul == [0u8; 16] {
                None
            } else {
                Some(ul)
            }
        } else {
            None
        };

        match control.create_nat(
            &r.interface_id,
            nat_ip,
            r.min_port as u16,
            r.max_port as u16,
            preferred_ul,
        ) {
            Ok(underlay) => Ok(Response::new(CreateNatResponse {
                status: ok(),
                underlay_route: encode_ipv6_str(underlay),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    Ok(Response::new(CreateNatResponse {
                        status: err_status(205, "NO_VM"),
                        underlay_route: Vec::new(),
                    }))
                } else if msg.contains("already exists") || msg.contains("SNAT_EXISTS") {
                    Ok(Response::new(CreateNatResponse {
                        status: err_status(343, "SNAT_EXISTS"),
                        underlay_route: Vec::new(),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn get_nat(
        &self,
        req: Request<GetNatRequest>,
    ) -> Result<Response<GetNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(GetNatResponse {
                status: err_status(205, "NO_VM"),
                nat_ip: None,
                min_port: 0,
                max_port: 0,
                underlay_route: Vec::new(),
            }));
        }

        match control.get_nat(&r.interface_id) {
            Some((nat_ip, min_port, max_port, underlay, _vni)) => {
                Ok(Response::new(GetNatResponse {
                    status: ok(),
                    nat_ip: Some(IpAddress {
                        ipver: IpVersion::Ipv4 as i32,
                        address: encode_ipv4_str(nat_ip),
                    }),
                    min_port: min_port as u32,
                    max_port: max_port as u32,
                    underlay_route: encode_ipv6_str(underlay),
                }))
            }
            None => Ok(Response::new(GetNatResponse {
                status: err_status(341, "SNAT_NO_DATA"),
                nat_ip: None,
                min_port: 0,
                max_port: 0,
                underlay_route: Vec::new(),
            })),
        }
    }

    async fn delete_nat(
        &self,
        req: Request<DeleteNatRequest>,
    ) -> Result<Response<DeleteNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(DeleteNatResponse {
                status: err_status(205, "NO_VM"),
            }));
        }

        match control.delete_nat(&r.interface_id) {
            Ok(true) => Ok(Response::new(DeleteNatResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteNatResponse {
                status: err_status(341, "SNAT_NO_DATA"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_local_nats(
        &self,
        req: Request<ListLocalNatsRequest>,
    ) -> Result<Response<ListLocalNatsResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // Validate filter IP — reject IPv6 with BAD_IPVER=204.
        let filter_ip: Option<[u8; 4]> = if let Some(addr) = r.nat_ip.as_ref() {
            // Check for IPv6.
            if addr.ipver == IpVersion::Ipv6 as i32
                || std::str::from_utf8(&addr.address)
                    .ok()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .map(|a| a.is_ipv6())
                    .unwrap_or(false)
            {
                return Ok(Response::new(ListLocalNatsResponse {
                    status: err_status(204, "BAD_IPVER"),
                    nat_entries: vec![],
                }));
            }
            let ip = decode_ipv4(&addr.address)?;
            // All-zeros means "list all".
            if ip == [0u8; 4] {
                None
            } else {
                Some(ip)
            }
        } else {
            None
        };

        let nat_entries = control
            .list_local_nats()
            .into_iter()
            .filter(|(_id, _guest, nat_ip, _pmin, _pmax, _vni, _ul)| {
                filter_ip.is_none() || filter_ip.as_ref() == Some(nat_ip)
            })
            .map(
                |(_iface_id, guest_ipv4, nat_ip, port_min, port_max, vni, _underlay)| {
                    pb::NatEntry {
                        nat_ip: Some(IpAddress {
                            ipver: IpVersion::Ipv4 as i32,
                            address: encode_ipv4_str(guest_ipv4),
                        }),
                        min_port: port_min as u32,
                        max_port: port_max as u32,
                        // Do NOT set underlay_route for local NATs — the Go client uses presence of
                        // underlay_route to distinguish NeighborNat (has underlay) from local Nat (no underlay).
                        underlay_route: Vec::new(),
                        vni,
                        actual_nat_ip: Some(IpAddress {
                            ipver: IpVersion::Ipv4 as i32,
                            address: encode_ipv4_str(nat_ip),
                        }),
                    }
                },
            )
            .collect();
        Ok(Response::new(ListLocalNatsResponse {
            status: ok(),
            nat_entries,
        }))
    }

    async fn create_neighbor_nat(
        &self,
        req: Request<CreateNeighborNatRequest>,
    ) -> Result<Response<CreateNeighborNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let nat_addr = r
            .nat_ip
            .ok_or_else(|| Status::invalid_argument("nat_ip is required"))?;

        // Reject IPv6 NAT IPs with BAD_IPVER=204.
        if nat_addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&nat_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            return Ok(Response::new(CreateNeighborNatResponse {
                status: err_status(204, "BAD_IPVER"),
            }));
        }

        let nat_ip = decode_ipv4(&nat_addr.address)?;
        let underlay = decode_ipv6(&r.underlay_route)?;

        match control.add_neighbor_nat(
            r.vni,
            nat_ip,
            r.min_port as u16,
            r.max_port as u16,
            underlay,
        ) {
            Ok(()) => Ok(Response::new(CreateNeighborNatResponse { status: ok() })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") || msg.contains("ALREADY_EXISTS") {
                    Ok(Response::new(CreateNeighborNatResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn delete_neighbor_nat(
        &self,
        req: Request<DeleteNeighborNatRequest>,
    ) -> Result<Response<DeleteNeighborNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let nat_addr = r
            .nat_ip
            .ok_or_else(|| Status::invalid_argument("nat_ip is required"))?;

        // Reject IPv6 NAT IPs.
        if nat_addr.ipver == IpVersion::Ipv6 as i32
            || std::str::from_utf8(&nat_addr.address)
                .ok()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|a| a.is_ipv6())
                .unwrap_or(false)
        {
            return Ok(Response::new(DeleteNeighborNatResponse {
                status: err_status(204, "BAD_IPVER"),
            }));
        }

        let nat_ip = decode_ipv4(&nat_addr.address)?;

        match control.del_neighbor_nat(r.vni, nat_ip, r.min_port as u16, r.max_port as u16) {
            Ok(true) => Ok(Response::new(DeleteNeighborNatResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteNeighborNatResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_neighbor_nats(
        &self,
        req: Request<ListNeighborNatsRequest>,
    ) -> Result<Response<ListNeighborNatsResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // Validate filter IP — reject IPv6 with BAD_IPVER=204.
        let filter_ip: Option<[u8; 4]> = if let Some(addr) = r.nat_ip.as_ref() {
            if addr.ipver == IpVersion::Ipv6 as i32
                || std::str::from_utf8(&addr.address)
                    .ok()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .map(|a| a.is_ipv6())
                    .unwrap_or(false)
            {
                return Ok(Response::new(ListNeighborNatsResponse {
                    status: err_status(204, "BAD_IPVER"),
                    nat_entries: vec![],
                }));
            }
            Some(decode_ipv4(&addr.address)?)
        } else {
            None
        };

        let entries = control
            .list_neighbor_nats()
            .into_iter()
            .filter(|e| filter_ip.is_none() || filter_ip.as_ref() == Some(&e.nat_ip))
            .map(|e| pb::NatEntry {
                nat_ip: None, // neighbor NAT list uses min/max port + underlay, not nat_ip
                min_port: e.port_min as u32,
                max_port: e.port_max as u32,
                underlay_route: encode_ipv6_str(e.underlay),
                vni: e.vni,
                actual_nat_ip: Some(IpAddress {
                    ipver: IpVersion::Ipv4 as i32,
                    address: encode_ipv4_str(e.nat_ip),
                }),
            })
            .collect();
        Ok(Response::new(ListNeighborNatsResponse {
            status: ok(),
            nat_entries: entries,
        }))
    }

    async fn list_routes(
        &self,
        req: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let vni = req.into_inner().vni;

        // vni=0 means "list all" (global query).
        if vni != 0 && !control.vni_in_use(vni) {
            return Ok(Response::new(ListRoutesResponse {
                status: err_status(206, "NO_VNI"),
                routes: vec![],
            }));
        }

        // list_routes_all returns (vni, ipv4_or_ipv6_prefix, prefix_len, nexthop_vni, nexthop_ipv6, is_ipv6).
        // Only IPv4 routes are included: the dpservice conformance tests expect only IPv4 route
        // entries in list_routes (IPv6 routes are stored but not surfaced via this RPC).
        let routes = control
            .list_routes_all(vni)
            .into_iter()
            .filter(|(_route_vni, _p, _l, _nhop_vni, _n, is_ipv6)| !is_ipv6)
            .map(|(route_vni, p, l, nhop_vni, n, _is_ipv6)| {
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&p[..4]);
                let prefix_ip = IpAddress {
                    ipver: IpVersion::Ipv4 as i32,
                    address: encode_ipv4_str(ipv4),
                };
                let _ = route_vni; // unused in the Route proto (nexthop_vni carries it)
                pb::Route {
                    prefix: Some(Prefix {
                        length: l,
                        ip: Some(prefix_ip),
                        underlay_route: Vec::new(),
                    }),
                    nexthop_address: Some(IpAddress {
                        ipver: IpVersion::Ipv6 as i32,
                        address: encode_ipv6_str(n),
                    }),
                    nexthop_vni: nhop_vni,
                    weight: 0,
                }
            })
            .collect();
        Ok(Response::new(ListRoutesResponse {
            status: ok(),
            routes,
        }))
    }

    async fn delete_route(
        &self,
        req: Request<DeleteRouteRequest>,
    ) -> Result<Response<DeleteRouteResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let vni = r.vni;

        // Check VNI is known — 206 NO_VNI if not.
        if vni != 0 && !control.vni_in_use(vni) {
            return Ok(Response::new(DeleteRouteResponse {
                status: err_status(206, "NO_VNI"),
            }));
        }

        let route = r
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;
        let prefix = route
            .prefix
            .ok_or_else(|| Status::invalid_argument("route.prefix is required"))?;
        let ip = prefix
            .ip
            .ok_or_else(|| Status::invalid_argument("route.prefix.ip is required"))?;

        let deleted = if ip.ipver == IpVersion::Ipv6 as i32 {
            let ipv6 = decode_ipv6(&ip.address)?;
            control
                .delete_route6(vni, ipv6, prefix.length)
                .map_err(|e| Status::internal(e.to_string()))?
        } else {
            let raw_ipv4 = decode_ipv4(&ip.address)?;
            let mask = mask_from_len(prefix.length);
            let ipv4 = [
                raw_ipv4[0] & mask[0],
                raw_ipv4[1] & mask[1],
                raw_ipv4[2] & mask[2],
                raw_ipv4[3] & mask[3],
            ];
            control
                .delete_route(vni, ipv4, prefix.length)
                .map_err(|e| Status::internal(e.to_string()))?
        };

        if deleted {
            Ok(Response::new(DeleteRouteResponse { status: ok() }))
        } else {
            Ok(Response::new(DeleteRouteResponse {
                status: err_status(302, "ROUTE_NOT_FOUND"),
            }))
        }
    }

    async fn check_vni_in_use(
        &self,
        req: Request<CheckVniInUseRequest>,
    ) -> Result<Response<CheckVniInUseResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let in_use = control.vni_in_use(req.into_inner().vni);
        Ok(Response::new(CheckVniInUseResponse {
            status: ok(),
            in_use,
        }))
    }

    async fn reset_vni(
        &self,
        req: Request<ResetVniRequest>,
    ) -> Result<Response<ResetVniResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        control
            .reset_vni(req.into_inner().vni)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ResetVniResponse { status: ok() }))
    }

    async fn list_firewall_rules(
        &self,
        req: Request<ListFirewallRulesRequest>,
    ) -> Result<Response<ListFirewallRulesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(ListFirewallRulesResponse {
                status: err_status(205, "NO_VM"),
                rules: vec![],
            }));
        }

        let pairs = control.list_fw_rules(&r.interface_id);
        let rules = pairs
            .into_iter()
            .map(|(id, rule)| encode_fw_rule(id, rule))
            .collect();
        Ok(Response::new(ListFirewallRulesResponse {
            status: ok(),
            rules,
        }))
    }

    async fn create_firewall_rule(
        &self,
        req: Request<CreateFirewallRuleRequest>,
    ) -> Result<Response<CreateFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pbrule = r
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;

        // Reject DROP action with NO_DROP_SUPPORT=441.
        if pbrule.action == FirewallAction::Drop as i32 {
            return Ok(Response::new(CreateFirewallRuleResponse {
                status: err_status(441, "NO_DROP_SUPPORT"),
                rule_id: Vec::new(),
            }));
        }

        let rule_id = if pbrule.id.is_empty() {
            gen_rule_id()
        } else {
            pbrule.id.clone()
        };
        let fw = decode_fw_rule(&pbrule)?;

        match control.add_fw_rule(&r.interface_id, rule_id.clone(), fw) {
            Ok(()) => Ok(Response::new(CreateFirewallRuleResponse {
                status: ok(),
                rule_id,
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NO_VM") || msg.contains("unknown interface") {
                    Ok(Response::new(CreateFirewallRuleResponse {
                        status: err_status(205, "NO_VM"),
                        rule_id: Vec::new(),
                    }))
                } else if msg.contains("already exists") || msg.contains("ALREADY_EXISTS") {
                    Ok(Response::new(CreateFirewallRuleResponse {
                        status: err_status(202, "ALREADY_EXISTS"),
                        rule_id: Vec::new(),
                    }))
                } else {
                    Err(Status::internal(msg))
                }
            }
        }
    }

    async fn get_firewall_rule(
        &self,
        req: Request<GetFirewallRuleRequest>,
    ) -> Result<Response<GetFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(GetFirewallRuleResponse {
                status: err_status(205, "NO_VM"),
                rule: None,
            }));
        }

        match control.get_fw_rule(&r.interface_id, &r.rule_id) {
            Some(fw) => Ok(Response::new(GetFirewallRuleResponse {
                status: ok(),
                rule: Some(encode_fw_rule(r.rule_id, fw)),
            })),
            None => Ok(Response::new(GetFirewallRuleResponse {
                status: err_status(201, "NOT_FOUND"),
                rule: None,
            })),
        }
    }

    async fn delete_firewall_rule(
        &self,
        req: Request<DeleteFirewallRuleRequest>,
    ) -> Result<Response<DeleteFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();

        // 205 if interface doesn't exist.
        if control.get_interface(&r.interface_id).is_none() {
            return Ok(Response::new(DeleteFirewallRuleResponse {
                status: err_status(205, "NO_VM"),
            }));
        }

        match control.del_fw_rule(&r.interface_id, &r.rule_id) {
            Ok(true) => Ok(Response::new(DeleteFirewallRuleResponse { status: ok() })),
            Ok(false) => Ok(Response::new(DeleteFirewallRuleResponse {
                status: err_status(201, "NOT_FOUND"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn capture_start(
        &self,
        _req: Request<CaptureStartRequest>,
    ) -> Result<Response<CaptureStartResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn capture_stop(
        &self,
        _req: Request<CaptureStopRequest>,
    ) -> Result<Response<CaptureStopResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn capture_status(
        &self,
        _req: Request<CaptureStatusRequest>,
    ) -> Result<Response<CaptureStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }
}

// ---------------------------------------------------------------------------
// Unit tests for address-decoding helpers (no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{decode_ipv4, decode_ipv6};

    #[test]
    fn decode_ipv4_valid() {
        assert_eq!(decode_ipv4(&[10, 0, 0, 5]).unwrap(), [10u8, 0, 0, 5]);
    }

    #[test]
    fn decode_ipv4_rejects_wrong_length() {
        assert!(decode_ipv4(&[10, 0, 0]).is_err());
        assert!(decode_ipv4(&[10, 0, 0, 5, 6]).is_err());
    }

    #[test]
    fn decode_ipv6_valid() {
        let mut b = [0u8; 16];
        b[0] = 0xfd;
        b[15] = 0x01;
        assert_eq!(decode_ipv6(&b).unwrap(), b);
    }

    #[test]
    fn decode_ipv6_rejects_wrong_length() {
        assert!(decode_ipv6(&[0u8; 4]).is_err());
        assert!(decode_ipv6(&[0u8; 17]).is_err());
    }
}
