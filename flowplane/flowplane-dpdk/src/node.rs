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

use flowplane_control::shadow::{IfaceMeta, LbIpBytes};
use flowplane_control::{ControlCore, IfaceParams};

use crate::writer::DpdkMapWriter;

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AddFwRuleRequest, AddFwRuleResponse, AddLbBackendRequest, AddLbBackendResponse,
    AddLbVipRequest, AddLbVipResponse, AddNatSourceRequest, AddNatSourceResponse,
    AddNeighborNatRequest, AddNeighborNatResponse, AddRouteRequest, AddRouteResponse,
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, ConfigureQoSRequest, ConfigureQoSResponse, DelFwRuleRequest,
    DelFwRuleResponse, DelLbBackendRequest, DelLbBackendResponse, DelLbVipRequest,
    DelLbVipResponse, DetachInterfaceRequest, DetachInterfaceResponse, InterfaceInfo,
    ListInterfacesRequest, ListInterfacesResponse, WithdrawNatSourceRequest,
    WithdrawNatSourceResponse, WithdrawNeighborNatRequest, WithdrawNeighborNatResponse,
    WithdrawRouteRequest, WithdrawRouteResponse,
};

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
        req: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let r = req.into_inner();
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let nexthop = parse_nexthop6(&r.nexthop_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        let external = r.external;
        {
            let mut core = self.ctrl.lock();
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
            res.map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddRouteResponse {}))
    }

    async fn withdraw_route(
        &self,
        req: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let r = req.into_inner();
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
            let res: anyhow::Result<()> = if is_v6 {
                core.delete_route6(vni, bytes, len).map(|_| ())
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                core.delete_route(vni, v4, len).map(|_| ())
            };
            res.map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(WithdrawRouteResponse {}))
    }

    async fn add_nat_source(
        &self,
        req: Request<AddNatSourceRequest>,
    ) -> Result<Response<AddNatSourceResponse>, Status> {
        let r = req.into_inner();
        let source =
            parse_ipv4(&r.source_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
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
            res.map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddNatSourceResponse {}))
    }

    async fn withdraw_nat_source(
        &self,
        req: Request<WithdrawNatSourceRequest>,
    ) -> Result<Response<WithdrawNatSourceResponse>, Status> {
        let r = req.into_inner();
        let source =
            parse_ipv4(&r.source_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
            // Removing an absent source is not an error (mirror the eBPF handler): if the interface is
            // gone or has no NAT, treat it as already withdrawn.
            if let Some(id) = core.find_iface_by_vni_ipv4(vni, source) {
                core.delete_nat(&id)
                    .map_err(|e| Status::internal(e.to_string()))?;
            }
        }
        Ok(Response::new(WithdrawNatSourceResponse {}))
    }

    async fn add_neighbor_nat(
        &self,
        req: Request<AddNeighborNatRequest>,
    ) -> Result<Response<AddNeighborNatResponse>, Status> {
        let r = req.into_inner();
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let owner = parse_nexthop6(&r.owner_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
            // Idempotent: drop any existing entry for this (vni, nat_ip, ports) first so a re-announce
            // replaces the owner underlay.
            let res: anyhow::Result<()> = core
                .del_neighbor_nat(vni, nat_ip, port_min, port_max)
                .and_then(|_| core.add_neighbor_nat(vni, nat_ip, port_min, port_max, owner));
            res.map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddNeighborNatResponse {}))
    }

    async fn withdraw_neighbor_nat(
        &self,
        req: Request<WithdrawNeighborNatRequest>,
    ) -> Result<Response<WithdrawNeighborNatResponse>, Status> {
        let r = req.into_inner();
        let nat_ip = parse_ipv4(&r.nat_ip).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_min = port_u16(r.port_min).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let port_max = port_u16(r.port_max).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
            // Removing an absent entry is not an error (del_neighbor_nat returns Ok(false)).
            core.del_neighbor_nat(vni, nat_ip, port_min, port_max)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(WithdrawNeighborNatResponse {}))
    }

    async fn add_lb_vip(
        &self,
        req: Request<AddLbVipRequest>,
    ) -> Result<Response<AddLbVipResponse>, Status> {
        let r = req.into_inner();
        let lb_ip: LbIpBytes = match r.vip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => LbIpBytes::Ipv4(a.octets()),
            Ok(std::net::IpAddr::V6(a)) => LbIpBytes::Ipv6(a.octets()),
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
        let id = r.id.into_bytes();
        let vni = r.vni;
        {
            let mut core = self.ctrl.lock();
            core.create_lb(&id, vni, lb_ip, lb_underlay, ports)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddLbVipResponse {}))
    }

    async fn add_lb_backend(
        &self,
        req: Request<AddLbBackendRequest>,
    ) -> Result<Response<AddLbBackendResponse>, Status> {
        let r = req.into_inner();
        let backend = parse_nexthop6(&r.backend_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = r.id.into_bytes();
        {
            let mut core = self.ctrl.lock();
            core.add_lb_target(&id, backend)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddLbBackendResponse {}))
    }

    async fn del_lb_vip(
        &self,
        req: Request<DelLbVipRequest>,
    ) -> Result<Response<DelLbVipResponse>, Status> {
        let id = req.into_inner().id.into_bytes();
        {
            let mut core = self.ctrl.lock();
            core.delete_lb(&id)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(DelLbVipResponse {}))
    }

    async fn del_lb_backend(
        &self,
        req: Request<DelLbBackendRequest>,
    ) -> Result<Response<DelLbBackendResponse>, Status> {
        let r = req.into_inner();
        let backend = parse_nexthop6(&r.backend_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = r.id.into_bytes();
        {
            let mut core = self.ctrl.lock();
            core.del_lb_target(&id, backend)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(DelLbBackendResponse {}))
    }

    async fn add_fw_rule(
        &self,
        req: Request<AddFwRuleRequest>,
    ) -> Result<Response<AddFwRuleResponse>, Status> {
        use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
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
        let iface = r.interface_id.into_bytes();
        let rule_id = r.rule_id.into_bytes();
        {
            let mut core = self.ctrl.lock();
            core.add_fw_rule(&iface, rule_id, rule)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(AddFwRuleResponse {}))
    }

    async fn del_fw_rule(
        &self,
        req: Request<DelFwRuleRequest>,
    ) -> Result<Response<DelFwRuleResponse>, Status> {
        let r = req.into_inner();
        let iface = r.interface_id.into_bytes();
        let rule_id = r.rule_id.into_bytes();
        {
            let mut core = self.ctrl.lock();
            core.del_fw_rule(&iface, &rule_id)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(DelFwRuleResponse {}))
    }

    async fn configure_qo_s(
        &self,
        req: Request<ConfigureQoSRequest>,
    ) -> Result<Response<ConfigureQoSResponse>, Status> {
        let r = req.into_inner();
        let iface = r.interface_id.into_bytes();
        let egress_mbps = r.egress_mbps as u64;
        let public_mbps = r.public_mbps as u64;
        let ingress_mbps = r.ingress_mbps as u64;
        {
            let mut core = self.ctrl.lock();
            core.set_qos(&iface, egress_mbps, public_mbps, ingress_mbps)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(ConfigureQoSResponse {}))
    }
}

/// First IPv4 in a `requested_ips` list, or `0.0.0.0` if none. The CNI passes overlay IPs as
/// strings; the DPDK attach programs the v4/v6 it finds (IPAM of unset IPs is B2).
fn first_ipv4(ips: &[String]) -> [u8; 4] {
    ips.iter()
        .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| a.octets())
        .next()
        .unwrap_or([0u8; 4])
}

/// First IPv6 in a `requested_ips` list, or the all-zero address if none.
fn first_ipv6(ips: &[String]) -> [u8; 16] {
    ips.iter()
        .filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok())
        .map(|a| a.octets())
        .next()
        .unwrap_or([0u8; 16])
}

/// Parse a `xx:xx:xx:xx:xx:xx` MAC into 6 bytes.
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            anyhow::bail!("bad mac {s:?}: too many octets");
        }
        out[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow::anyhow!("bad mac octet {part:?} in {s:?}"))?;
        n += 1;
    }
    if n != 6 {
        anyhow::bail!("bad mac {s:?}: expected 6 octets, got {n}");
    }
    Ok(out)
}

/// Parse a CIDR string into (is_v6, 16-byte address buffer, prefix_len). For IPv4 the four octets
/// are left-aligned in the buffer (bytes[0..4]). Verbatim from the eBPF node service.
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

/// Parse an IPv4 firewall CIDR into `(ip, mask)`. Empty = "any" (0.0.0.0/0); bare address = /32.
/// Verbatim from the eBPF node service.
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
        let shared = Arc::new(SharedConfigMaps::new(0, 1024).unwrap());
        let ctrl = Arc::new(Mutex::new(ControlCore::new(DpdkMapWriter::new(
            shared.clone(),
        ))));
        let svc = DpdkNodeService::new(ctrl.clone(), shared.clone());

        let resp = svc
            .add_route(Request::new(AddRouteRequest {
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
