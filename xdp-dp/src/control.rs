use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use aya::Ebpf;
use xdp_dp_common::{
    CtKey, FwMeta, FwRule, FwRuleKey, IfaceKey, IfaceValue, LbKey, LbValue, Local, MaglevKey,
    NatKey, NatValue, NeighborNatEntry, PortMeta, RouteValue, VipKey, FW_DIR_EGRESS, FW_MAX_RULES,
    NB_MAX_ENTRIES,
};

use crate::grpc::LbIpBytes;
use crate::loader;
use crate::maps::{
    Conntrack, DhcpConfigMap, DhcpMetaMap, FwMetaMap, FwRules, Interfaces, Lb, LocalMap, Maglev,
    Meter, Nat, NatIps, NeighborNat, NeighborNatCount, PortMetaMap, Routes, Routes6, Vips,
};

/// The owned link for a guest interface's attached datapath program. Dropping either variant
/// detaches the program from the device. The Tc variant (tc clsact on the guest tap) is the
/// default; the Xdp variant is the legacy fallback (`XDP_DP_GUEST_TC=0`). The uplink is always XDP.
enum GuestLink {
    // The link handles are never read back; they are held solely so that dropping the variant
    // detaches the program from the device (RAII detach).
    Xdp(#[allow(dead_code)] aya::programs::xdp::XdpLink),
    Tc(#[allow(dead_code)] aya::programs::tc::SchedClassifierLink),
}

/// Per-interface addressing + rate-limit parameters for `create_interface` / `program_iface_maps`.
/// Bundled into one struct so the programming path doesn't thread ten positional arguments.
pub struct IfaceParams {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub underlay_ipv6: [u8; 16],
    pub total_mbps: u64,
    pub public_mbps: u64,
}

// Named shapes for the shadow records and gRPC list/get return rows, so the signatures below read
// as `Vec<RouteRow>` rather than a bare six-tuple (keeps `clippy::type_complexity` quiet and
// documents each column). Fields are described where each is produced/consumed.

/// `(vni, prefix_ipv4, prefix_len, nexthop_vni, nexthop_underlay)` for list/delete_route.
pub(crate) type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// `(vni, prefix_ipv6, prefix_len, nexthop_vni, nexthop_underlay)` IPv6 routes shadow.
pub(crate) type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);
/// `(vni, ipv4, ipv6, underlay, device)` for a single interface.
pub(crate) type InterfaceDetail = (u32, [u8; 4], [u8; 16], [u8; 16], String);
/// `(interface_id, vni, ipv4, ipv6, underlay, device)` row.
pub(crate) type InterfaceRow = (Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16], String);
/// `(route_vni, ip_bytes_16, prefix_len, nexthop_vni, nexthop_ipv6, is_ipv6)` row.
pub(crate) type RouteRow = (u32, [u8; 16], u32, u32, [u8; 16], bool);
/// `(vni, ip_bytes, lb_underlay, ports)` for a single load balancer.
pub(crate) type LbDetail = (u32, LbIpBytes, [u8; 16], Vec<(u16, u8)>);
/// `(id, vni, ip_bytes, lb_underlay, ports)` load-balancer row.
pub(crate) type LbRow = (Vec<u8>, u32, LbIpBytes, [u8; 16], Vec<(u16, u8)>);
/// `(nat_ip, port_min, port_max, underlay, vni)` for a guest's NAT config.
pub(crate) type NatDetail = ([u8; 4], u16, u16, [u8; 16], u32);
/// `(interface_id, guest_ipv4, nat_ip, port_min, port_max, vni, underlay)` local-NAT row.
pub(crate) type LocalNatRow = (Vec<u8>, [u8; 4], [u8; 4], u16, u16, u32, [u8; 16]);

/// Resolve a gRPC `device_name` to an actual kernel netdev name.
///
/// If `device` already exists under `/sys/class/net`, it is used verbatim. Otherwise, if it is a
/// dpservice DPDK vdev name `net_tap<N>` (N >= 2), it is translated to the kernel tap `dtapvf_<N-2>`
/// — the `--vdev=net_tap{N+2},iface=dtapvf_N` naming dpservice used and that metalnet sends over
/// gRPC. xdp-dp attaches XDP to the kernel tap directly, so it needs the kernel name.
fn resolve_iface(device: &str) -> String {
    if std::path::Path::new(&format!("/sys/class/net/{device}")).exists() {
        return device.to_string();
    }
    if let Some(n) = device
        .strip_prefix("net_tap")
        .and_then(|s| s.parse::<u32>().ok())
    {
        if n >= 2 {
            return format!("dtapvf_{}", n - 2);
        }
    }
    device.to_string()
}

/// Full detail record for a registered local interface (shadow of eBPF map state).
#[derive(Clone)]
struct IfaceRecord {
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    device: String,
    underlay: [u8; 16],
}

/// LB IP address stored in the shadow state (IPv4 or IPv6).
#[derive(Clone)]
enum LbIp {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl LbIp {
    /// Return the last 4 bytes of the address for underlay derivation.
    fn last4(&self) -> [u8; 4] {
        match self {
            LbIp::Ipv4(ip) => *ip,
            LbIp::Ipv6(ip) => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&ip[12..16]);
                b
            }
        }
    }

    fn as_lb_ip_bytes(&self) -> LbIpBytes {
        match self {
            LbIp::Ipv4(ip) => LbIpBytes::Ipv4(*ip),
            LbIp::Ipv6(ip) => LbIpBytes::Ipv6(*ip),
        }
    }
}

/// Registered load balancer: its Maglev table id, the (port,proto) services it answers, and the
/// ordered backend list (drives the Maglev table). Keyed in `Inner.lbs` by the LB's id.
struct LbEntry {
    vni: u32,
    ip: LbIp,
    lb_underlay: [u8; 16],
    ports: Vec<(u16, u8)>,
    table_id: u32,
    backends: Vec<[u8; 16]>,
}

/// Prefix record: ip bytes (4 or 16), prefix_len, underlay route, is_ipv6 flag.
#[derive(Clone)]
struct PrefixRecord {
    ip: [u8; 16], // first 4 bytes for IPv4, all 16 for IPv6
    len: u32,
    underlay: [u8; 16],
    is_ipv6: bool,
}

/// Owns the loaded eBPF object + map handles; mutated by the gRPC handlers.
pub struct Control {
    inner: Mutex<Inner>,
    /// Conntrack map handle, shared with the GC task. Held in an Arc so both
    /// the control plane (for CT flush on NAT/neigh-NAT delete) and the GC task
    /// can access it concurrently without moving ownership.
    conntrack: Arc<Mutex<Conntrack>>,
}

struct Inner {
    ebpf: Ebpf,
    /// Owned `GUEST_PROGS` program array handle. Holds `GUEST_PROGS[GUEST_PROG_DHCP] = guest_dhcp`
    /// so guest_tx's DHCP tail call resolves. Kept alive here for the datapath's lifetime;
    /// dropping it would close the userspace map fd (the kernel map survives via guest_tx).
    _guest_progs: aya::maps::ProgramArray<aya::maps::MapData>,
    _locals: LocalMap,
    ports: PortMetaMap,
    ifaces: Interfaces,
    routes: Routes,
    routes6: Routes6,
    vips: Vips,
    lb: Lb,
    maglev: Maglev,
    nat: Nat,
    fw_rules: FwRules,
    fw_meta: FwMetaMap,
    underlay: crate::maps::Underlay,
    meter: Meter,
    neigh_nat: NeighborNat,
    neigh_nat_count: NeighborNatCount,
    nat_ips: NatIps,
    dhcp_config: DhcpConfigMap,
    dhcp_meta: DhcpMetaMap,
    /// In-memory neighbor NAT entries (drives the BPF map reprogram).
    neigh_nats: Vec<NeighborNatEntry>,
    /// loadbalancer_id -> its LB state.
    lbs: HashMap<Vec<u8>, LbEntry>,
    next_table_id: u32,
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
    /// interface_id -> ifindex
    by_ifindex: HashMap<Vec<u8>, u32>,
    /// interface_id -> its underlay /128
    iface_underlay: HashMap<Vec<u8>, [u8; 16]>,
    /// interface_id -> list of prefix records (IPv4 and IPv6)
    prefixes: HashMap<Vec<u8>, Vec<PrefixRecord>>,
    /// ifindex -> ordered (rule_id, rule) pairs
    fw: HashMap<u32, Vec<(Vec<u8>, FwRule)>>,
    /// interface_id -> list of LB-prefix records (announce-only).
    lb_prefixes: HashMap<Vec<u8>, Vec<PrefixRecord>>,
    /// interface_id -> the owned guest datapath link (dropping it detaches the program).
    /// Either a tc clsact link (default) or an XDP link when `guest_tc` is opted out.
    links: HashMap<Vec<u8>, GuestLink>,
    /// The guest edge is attached via tc clsact ingress (`tc_guest_tx`) by DEFAULT; set
    /// `XDP_DP_GUEST_TC=0/false/no/off` to fall back to XDP (`guest_tx`). The uplink stays XDP either way.
    guest_tc: bool,
    routes_shadow: Vec<RouteShadowV4>,
    routes6_shadow: Vec<RouteShadowV6>,
    /// Shadow cache of learned guest MACs: underlay_ipv6 -> guest_mac.
    /// Persists across interface delete+recreate so that the datapath can continue
    /// delivering to the last-known MAC even when the interface is reprogrammed.
    learned_macs: HashMap<[u8; 16], [u8; 6]>,
}

impl Control {
    /// Load + attach uplink_rx, set LOCAL, take the map handles.
    pub fn bring_up(
        uplink: &str,
        uplink_ifindex: u32,
        uplink_mac: [u8; 6],
        gateway_mac: [u8; 6],
        underlay_ipv6: [u8; 16],
    ) -> anyhow::Result<Self> {
        let mut ebpf = loader::load_ebpf()?;
        loader::maybe_install_logger(&mut ebpf);
        // The uplink RX path is always XDP, regardless of the guest edge attach mode.
        loader::attach_xdp(&mut ebpf, "uplink_rx", uplink)?;
        // Guest edge attach mode: tc clsact is the DEFAULT (native XDP can't intercept guest egress
        // on a vhost-backed tap — see the tc-BPF guest-edge design). Opt out to the legacy XDP
        // guest_tx with XDP_DP_GUEST_TC=0/false/no/off (kept for regression testing). We pre-load the
        // guest program (and register its DHCP/NAT64 tail-call array) once here so that every
        // per-interface attach only needs attach() — the returned link is then always droppable on
        // teardown (no ghost attachment surviving an interface delete).
        let guest_tc = !matches!(
            std::env::var("XDP_DP_GUEST_TC").as_deref(),
            Ok("0") | Ok("false") | Ok("no") | Ok("off"),
        );
        let guest_progs = if guest_tc {
            // tc path: register_guest_dhcp_tc loads tc_guest_dhcp/tc_guest_nat64 into GUEST_PROGS_TC;
            // tc_guest_tx itself still needs a separate pre-load.
            let progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
            loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
            progs
        } else {
            // XDP path: pre-load guest_tx, then wire guest_dhcp into GUEST_PROGS for its tail call.
            loader::load_program(&mut ebpf, "guest_tx")?;
            loader::register_guest_dhcp(&mut ebpf)?
        };
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex,
            uplink_mac,
            gateway_mac,
            underlay_ipv6,
        })?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _guest_progs: guest_progs,
                _locals: locals,
                ports,
                ifaces,
                routes,
                routes6,
                vips,
                lb,
                maglev,
                nat,
                fw_rules,
                fw_meta,
                underlay,
                meter,
                neigh_nat,
                neigh_nat_count,
                nat_ips,
                dhcp_config,
                dhcp_meta,
                neigh_nats: Vec::new(),
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
                by_ifindex: HashMap::new(),
                iface_underlay: HashMap::new(),
                prefixes: HashMap::new(),
                fw: HashMap::new(),
                lb_prefixes: HashMap::new(),
                links: HashMap::new(),
                guest_tc,
                routes_shadow: Vec::new(),
                routes6_shadow: Vec::new(),
                learned_macs: HashMap::new(),
            }),
            conntrack,
        })
    }

    /// WAN-edge role: attach `wan_rx` to the WAN uplink and register the edge's own underlay /128
    /// as a local-deliver UNDERLAY entry (sentinel tap). Fabric->WAN egress then decaps and
    /// XDP_PASSes to the local kernel (VyOS), while WAN->fabric returns to a `nat_ip` are caught by
    /// `wan_rx` and re-encapped to the block owner. Call once, after `bring_up`.
    pub fn attach_edge(&self, wan_uplink: &str, edge_underlay: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        loader::attach_xdp(&mut g.ebpf, "wan_rx", wan_uplink)?;
        g.underlay.upsert(
            edge_underlay,
            xdp_dp_common::UnderlayValue {
                vni: 0,
                tap_ifindex: xdp_dp_common::UNDERLAY_LOCAL_DELIVER,
                guest_mac: [0; 6],
                _pad: [0; 2],
            },
        )?;
        println!(
            "edge role: wan_rx attached to {wan_uplink}; UNDERLAY[{}] = local-deliver",
            std::net::Ipv6Addr::from(edge_underlay)
        );
        Ok(())
    }

    /// Attach `uplink_rx` on an ADDITIONAL fabric uplink (a dual-homed host decaps returns arriving
    /// via either ToR). The program is already loaded by `bring_up`; this just attaches it to
    /// another interface. LOCAL stays the primary uplink (egress + wan_rx redirect use it).
    pub fn attach_extra_uplink(&self, iface: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        loader::attach_xdp_extra(&mut g.ebpf, "uplink_rx", iface)?;
        println!("uplink_rx attached to extra uplink {iface}");
        Ok(())
    }

    /// Return a shared handle to the conntrack map (for the GC task and flush operations).
    pub fn take_conntrack(&self) -> Arc<Mutex<Conntrack>> {
        Arc::clone(&self.conntrack)
    }

    pub fn set_dhcp_config(
        &self,
        mtu: u16,
        dns4: &[[u8; 4]],
        dns6: &[[u8; 16]],
    ) -> anyhow::Result<()> {
        let mut cfg = xdp_dp_common::DhcpConfig {
            mtu,
            dns4_len: dns4.len().min(xdp_dp_common::DHCP_MAX_DNS) as u8,
            dns6_len: dns6.len().min(xdp_dp_common::DHCP_MAX_DNS) as u8,
            dns4: [[0; 4]; xdp_dp_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; xdp_dp_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(xdp_dp_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns4[i] = *a;
        }
        for (i, a) in dns6.iter().take(xdp_dp_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns6[i] = *a;
        }
        self.inner.lock().unwrap().dhcp_config.set(&cfg)
    }

    pub fn set_dhcp_meta(
        &self,
        interface_id: &[u8],
        hostname: &[u8],
        pxe_host: &[u8],
        boot_filename: &[u8],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let mut m = xdp_dp_common::DhcpMeta {
            hostname: [0; 64],
            hostname_len: 0,
            boot_filename: [0; 64],
            boot_filename_len: 0,
            pxe_host: [0; 46],
            pxe_host_len: 0,
            _pad: [0; 1],
        };
        let hl = hostname.len().min(64);
        m.hostname[..hl].copy_from_slice(&hostname[..hl]);
        m.hostname_len = hl as u8;
        let bl = boot_filename.len().min(64);
        m.boot_filename[..bl].copy_from_slice(&boot_filename[..bl]);
        m.boot_filename_len = bl as u8;
        let pl = pxe_host.len().min(46);
        m.pxe_host[..pl].copy_from_slice(&pxe_host[..pl]);
        m.pxe_host_len = pl as u8;
        g.dhcp_meta.upsert(ifindex, m)
    }

    fn meter_state(total_mbps: u64, public_mbps: u64) -> xdp_dp_common::MeterState {
        let tb = total_mbps.saturating_mul(1_000_000) / 8;
        let pb = public_mbps.saturating_mul(1_000_000) / 8;
        xdp_dp_common::MeterState {
            total_bps: tb,
            total_burst: (tb / 8).max(2000),
            total_tokens: tb / 8,
            total_last_ns: 0,
            public_bps: pb,
            public_burst: (pb / 8).max(2000),
            public_tokens: pb / 8,
            public_last_ns: 0,
        }
    }

    /// Program a LOCAL interface: attach guest_tx to its device, set PORT_META + INTERFACES +
    /// UNDERLAY, retain the XDP link for detach, and record shadow detail.
    pub fn create_interface(
        &self,
        interface_id: &[u8],
        device: &str,
        params: IfaceParams,
    ) -> anyhow::Result<()> {
        let (vni, ipv4, ipv6, underlay_ipv6) =
            (params.vni, params.ipv4, params.ipv6, params.underlay_ipv6);
        // Resolve the device name to a kernel netdev. metalnet (in dpservice tap mode) claims a tap
        // from its hardcoded pool dtapvf_N but sends the DPDK vdev name net_tap{N+2} over gRPC
        // (dpservice's --vdev=net_tap{N+2},iface=dtapvf_N convention). We have no DPDK — only the
        // kernel tap dtapvf_N — so translate net_tapX -> dtapvf_{X-2} when the literal name is
        // absent. Names that already exist as netdevs (e.g. dtapvf_N sent directly) pass through.
        let resolved = resolve_iface(device);
        let device = resolved.as_str();
        let tap = crate::ifindex(device)
            .map_err(|e| anyhow::anyhow!("read ifindex for {device}: {e}"))?;
        let mac = crate::mac_of(device)?;
        let mut g = self.inner.lock().unwrap();
        if g.by_id.contains_key(interface_id) {
            anyhow::bail!("interface already exists");
        }
        // Check that the (vni, ipv4) combination is not already in use (ROUTE_EXISTS).
        if g.by_id.values().any(|r| r.vni == vni && r.ipv4 == ipv4) {
            anyhow::bail!("ROUTE_EXISTS: IP already in use in this VNI");
        }
        // Check that the (vni, ipv6) combination is not already in use (if non-zero).
        if ipv6 != [0u8; 16] && g.by_id.values().any(|r| r.vni == vni && r.ipv6 == ipv6) {
            anyhow::bail!("ROUTE_EXISTS: IPv6 already in use in this VNI");
        }
        // NOTE: preferred underlay collision is NOT checked here; it is checked only when
        // the caller explicitly supplies a preferred_underlay_route (see grpc.rs handler).
        // The guest program was pre-loaded in bring_up, so attach always succeeds and we get a
        // droppable link back — dropping it detaches the program on interface teardown. Use tc
        // clsact ingress by default, or XDP when opted out (XDP_DP_GUEST_TC=0). (guest_tc lives on
        // Inner alongside ebpf/links, so it's readable here under the same lock.)
        let link = if g.guest_tc {
            GuestLink::Tc(
                loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                    .with_context(|| format!("attach tc_guest_tx to {device}"))?,
            )
        } else {
            GuestLink::Xdp(
                loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device)
                    .with_context(|| format!("load+attach guest_tx to {device}"))?,
            )
        };
        g.links.insert(interface_id.to_vec(), link);
        g.by_id.insert(
            interface_id.to_vec(),
            IfaceRecord {
                vni,
                ipv4,
                ipv6,
                device: device.to_string(),
                underlay: underlay_ipv6,
            },
        );
        g.by_ifindex.insert(interface_id.to_vec(), tap);
        g.iface_underlay
            .insert(interface_id.to_vec(), underlay_ipv6);
        Self::program_iface_maps(&mut g, tap, mac, &params)
    }

    /// Program PORT_META / INTERFACES / UNDERLAY / METER / local self-route for one interface.
    fn program_iface_maps(
        g: &mut Inner,
        tap: u32,
        mac: [u8; 6],
        params: &IfaceParams,
    ) -> anyhow::Result<()> {
        let IfaceParams {
            vni,
            ipv4,
            ipv6,
            gateway_ipv4,
            gateway_ipv6,
            underlay_ipv6,
            total_mbps,
            public_mbps,
        } = *params;
        // MAC learning persistence: use the shadow cache of learned MACs, which is populated
        // by detach_interface before it removes the UNDERLAY entry. This ensures that a
        // delete+recreate cycle preserves the datapath-learned MAC even though the BPF UNDERLAY
        // map entry is gone by the time program_iface_maps is called.
        let effective_mac = g.learned_macs.get(&underlay_ipv6).copied().unwrap_or(mac);
        g.ports.upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: effective_mac,
                _pad: [0; 2],
                underlay_ipv6,
                gateway_ipv6,
                guest_ipv6: ipv6,
            },
        )?;
        g.ifaces.upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        g.underlay.upsert(
            underlay_ipv6,
            xdp_dp_common::UnderlayValue {
                vni,
                tap_ifindex: tap,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        // Local self-route: a same-host guest reaches this interface by its overlay IP. Program a
        // /32 (and /128 when dual-stack) route to this interface's OWN underlay so guest_tx's LPM
        // resolves a local destination to a local underlay, and the local fast path delivers it
        // without a wire round-trip. These are NOT added to routes_shadow (not user-visible routes).
        g.routes.upsert(
            vni,
            ipv4,
            32,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: underlay_ipv6,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        if ipv6 != [0u8; 16] {
            g.routes6.upsert(
                vni,
                ipv6,
                128,
                RouteValue {
                    nexthop_vni: vni,
                    nexthop_ipv6: underlay_ipv6,
                    is_external: 0,
                    _pad: [0; 3],
                },
            )?;
        }
        if total_mbps != 0 || public_mbps != 0 {
            g.meter
                .upsert(tap, Self::meter_state(total_mbps, public_mbps))?;
        }
        Ok(())
    }

    /// Tear down a local interface: detach guest_tx (drop the link) and clear its maps + shadow.
    /// Returns true if found and deleted, false if not found.
    /// When the last interface on a VNI is removed, also auto-resets the VNI (purges neighbor NATs,
    /// VIPs, and routes for that VNI) to match dpservice's behaviour.
    pub fn detach_interface(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let rec = match g.by_id.remove(interface_id) {
            Some(r) => r,
            None => return Ok(false),
        };
        let vni = rec.vni;
        let tap = g.by_ifindex.remove(interface_id).unwrap_or(0);
        g.iface_underlay.remove(interface_id);
        g.prefixes.remove(interface_id);
        // Dropping the link detaches the program from the device.
        g.links.remove(interface_id);
        let _ = g.ports.remove(tap);
        let _ = g.ifaces.remove(IfaceKey::new(rec.vni, rec.ipv4));
        // Before removing the UNDERLAY entry, snapshot the currently-learned guest MAC
        // (the datapath may have updated it via DHCP/ARP MAC learning). This snapshot
        // survives the delete so that addinterface can restore the learned MAC.
        if let Some(u) = g.underlay.get(&rec.underlay) {
            g.learned_macs.insert(rec.underlay, u.guest_mac);
        }
        let _ = g.underlay.remove(&rec.underlay);
        let _ = g.meter.remove(&tap);
        let _ = g.dhcp_meta.remove(tap);
        // Remove the local self-route(s) programmed in program_iface_maps.
        let _ = g.routes.remove(rec.vni, rec.ipv4, 32);
        if rec.ipv6 != [0u8; 16] {
            let _ = g.routes6.remove(rec.vni, rec.ipv6, 128);
        }
        if let Some(rules) = g.fw.remove(&tap) {
            drop(rules);
        }
        // Auto-reset VNI when the last local interface on it is removed:
        // purge neighbor NATs (and orphaned VIP/NAT/route state) for that VNI. This matches
        // dpservice's async-deletion model where the VNI is implicitly reset on last-iface removal.
        let vni_still_in_use =
            g.by_id.values().any(|r| r.vni == vni) || g.lbs.values().any(|lb| lb.vni == vni);
        if !vni_still_in_use {
            // Purge neighbor NATs for this VNI.
            let before = g.neigh_nats.len();
            g.neigh_nats.retain(|e| e.vni != vni);
            if g.neigh_nats.len() != before {
                let n = g.neigh_nats.len() as u32;
                let remaining: Vec<NeighborNatEntry> = g.neigh_nats.clone();
                for (i, e) in remaining.iter().enumerate() {
                    let _ = g.neigh_nat.upsert(i as u32, *e);
                }
                let _ = g.neigh_nat_count.set(n);
            }
            // Purge VIP entries for the removed interface's guest IP (and its reverse).
            let maybe_vip = g.vips.get(&VipKey {
                vni,
                ipv4: rec.ipv4,
            });
            if let Some(vip) = maybe_vip {
                let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
            }
            let _ = g.vips.remove(&VipKey {
                vni,
                ipv4: rec.ipv4,
            });
            // Purge NAT config for the removed interface's guest IP.
            let _ = g.nat.remove(&NatKey {
                vni,
                ipv4: rec.ipv4,
            });
            // Purge routes for this VNI (same as reset_vni).
            let routes_to_del: Vec<([u8; 4], u32)> = g
                .routes_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes_to_del {
                let _ = g.routes.remove(vni, *p, *l);
            }
            g.routes_shadow.retain(|&(v, p, l, _, _)| {
                !routes_to_del
                    .iter()
                    .any(|&(rp, rl)| v == vni && rp == p && rl == l)
            });
            let routes6_to_del: Vec<([u8; 16], u32)> = g
                .routes6_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect();
            for (p, l) in &routes6_to_del {
                let _ = g.routes6.remove(vni, *p, *l);
            }
            g.routes6_shadow.retain(|&(v, p, l, _, _)| {
                !routes6_to_del
                    .iter()
                    .any(|&(rp, rl)| v == vni && rp == p && rl == l)
            });
        }
        Ok(true)
    }

    /// Interface detail for get/list. Returns (vni, ipv4, ipv6, underlay, device).
    pub fn get_interface(&self, interface_id: &[u8]) -> Option<InterfaceDetail> {
        let g = self.inner.lock().unwrap();
        g.by_id
            .get(interface_id)
            .map(|r| (r.vni, r.ipv4, r.ipv6, r.underlay, r.device.clone()))
    }

    /// Read the `INTERFACES` map entry for `(vni, ipv4)` straight back out of the live eBPF map.
    /// Used by the DataplaneNode AttachInterface path to confirm the endpoint is resident in the
    /// kernel map (a read-back that proves the program actually landed). Returns the tap ifindex.
    pub fn interface_readback(&self, vni: u32, ipv4: [u8; 4]) -> Option<u32> {
        let g = self.inner.lock().unwrap();
        g.ifaces
            .get(&IfaceKey::new(vni, ipv4))
            .map(|v| v.tap_ifindex)
    }

    /// All interface ids with their (vni, ipv4, ipv6, underlay, device).
    pub fn list_interfaces(&self) -> Vec<InterfaceRow> {
        let g = self.inner.lock().unwrap();
        g.by_id
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.vni,
                    r.ipv4,
                    r.ipv6,
                    r.underlay,
                    r.device.clone(),
                )
            })
            .collect()
    }

    pub fn create_route(
        &self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        // Check for duplicate — routes_shadow is the source of truth.
        if g.routes_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv4 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes.upsert(
            vni,
            ipv4,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes_shadow
            .push((vni, ipv4, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete a route. Returns true if found and deleted, false if not found.
    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let before = g.routes_shadow.len();
        g.routes_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv4 && l == prefix_len));
        if g.routes_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes.remove(vni, ipv4, prefix_len);
        Ok(true)
    }

    pub fn create_route6(
        &self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        // Check for duplicate.
        if g.routes6_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv6 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes6.upsert(
            vni,
            ipv6,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes6_shadow
            .push((vni, ipv6, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete an IPv6 route. Returns true if found, false if not found.
    pub fn delete_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let before = g.routes6_shadow.len();
        g.routes6_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv6 && l == prefix_len));
        if g.routes6_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes6.remove(vni, ipv6, prefix_len);
        Ok(true)
    }

    /// List routes for a VNI (or all if vni=0).
    /// Returns (route_vni, ip_bytes_16, prefix_len, nexthop_vni, nexthop_ipv6, is_ipv6).
    pub fn list_routes_all(&self, vni: u32) -> Vec<RouteRow> {
        let g = self.inner.lock().unwrap();
        let mut result = Vec::new();
        // IPv4 routes.
        for &(rv, p, l, nhvni, n) in &g.routes_shadow {
            if vni == 0 || rv == vni {
                let mut ip = [0u8; 16];
                ip[..4].copy_from_slice(&p);
                result.push((rv, ip, l, nhvni, n, false));
            }
        }
        // IPv6 routes.
        for &(rv, p, l, nhvni, n) in &g.routes6_shadow {
            if vni == 0 || rv == vni {
                result.push((rv, p, l, nhvni, n, true));
            }
        }
        result
    }

    pub fn vni_in_use(&self, vni: u32) -> bool {
        let g = self.inner.lock().unwrap();
        g.by_id.values().any(|r| r.vni == vni)
            || g.routes_shadow.iter().any(|&(v, _, _, _, _)| v == vni)
            || g.routes6_shadow.iter().any(|&(v, _, _, _, _)| v == vni)
            || g.lbs.values().any(|lb| lb.vni == vni)
            || g.neigh_nats.iter().any(|n| n.vni == vni)
    }

    pub fn reset_vni(&self, vni: u32) -> anyhow::Result<()> {
        // Remove all routes for the vni (interfaces are torn down via DeleteInterface).
        let ipv4_to_del: Vec<_> = {
            let g = self.inner.lock().unwrap();
            g.routes_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect()
        };
        for (p, l) in ipv4_to_del {
            self.delete_route(vni, p, l)?;
        }
        let ipv6_to_del: Vec<_> = {
            let g = self.inner.lock().unwrap();
            g.routes6_shadow
                .iter()
                .filter(|&&(v, _, _, _, _)| v == vni)
                .map(|&(_, p, l, _, _)| (p, l))
                .collect()
        };
        for (p, l) in ipv6_to_del {
            self.delete_route6(vni, p, l)?;
        }
        Ok(())
    }

    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: LbIpBytes,
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.lbs.contains_key(id) {
            anyhow::bail!("load balancer already exists");
        }
        let table_id = g.next_table_id;
        g.next_table_id += 1;

        let lb_ip = match &ip {
            LbIpBytes::Ipv4(a) => LbIp::Ipv4(*a),
            LbIpBytes::Ipv6(a) => LbIp::Ipv6(*a),
        };
        let lb_ip_bytes4 = lb_ip.last4();

        for &(port, proto) in &ports {
            g.lb.upsert(
                LbKey {
                    vni,
                    ipv4: lb_ip_bytes4,
                    port,
                    proto,
                    _pad: 0,
                },
                LbValue {
                    table_id,
                    size: crate::maglev::TABLE_SIZE,
                },
            )?;
        }
        // Program the LB's own underlay /128 into UNDERLAY so ingress can identify it — but ONLY for
        // overlay (relay) LBs. The WAN edge (vni==0) reaches the LB via wan_rx on a raw WAN frame and
        // never resolves UNDERLAY[lb_underlay]; writing it there would clobber the edge's
        // LOCAL_DELIVER egress entry (attach_edge). So skip the write for vni==0.
        // tap_ifindex=0 and guest_mac=[0;6] because the LB VIP is anycast (no local tap).
        if vni != 0 {
            g.underlay.upsert(
                lb_underlay,
                xdp_dp_common::UnderlayValue {
                    vni,
                    tap_ifindex: 0,
                    guest_mac: [0; 6],
                    _pad: [0; 2],
                },
            )?;
        }
        g.lbs.insert(
            id.to_vec(),
            LbEntry {
                vni,
                ip: lb_ip,
                lb_underlay,
                ports,
                table_id,
                backends: Vec::new(),
            },
        );
        Ok(())
    }

    /// Append a backend underlay /128 to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        // Reject duplicates.
        if entry.backends.contains(&backend) {
            anyhow::bail!("load balancer target already exists");
        }
        entry.backends.push(backend);
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        let table = crate::maglev::build(&backends);
        for (slot, &bi) in table.iter().enumerate() {
            g.maglev.upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Remove a backend from an LB. Returns true if found, false if not.
    pub fn del_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        let before = entry.backends.len();
        entry.backends.retain(|b| b != &backend);
        if entry.backends.len() == before {
            return Ok(false);
        }
        // Rebuild Maglev table.
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        if backends.is_empty() {
            // Clear all Maglev slots.
            for slot in 0..crate::maglev::TABLE_SIZE {
                let _ = g.maglev.remove(&MaglevKey { table_id, slot });
            }
        } else {
            let table = crate::maglev::build(&backends);
            for (slot, &bi) in table.iter().enumerate() {
                g.maglev.upsert(
                    MaglevKey {
                        table_id,
                        slot: slot as u32,
                    },
                    backends[bi as usize],
                )?;
            }
        }
        Ok(true)
    }

    /// Return detail for a single LB: (vni, ip_bytes, lb_underlay, ports).
    pub fn get_lb(&self, id: &[u8]) -> Option<LbDetail> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .get(id)
            .map(|e| (e.vni, e.ip.as_lb_ip_bytes(), e.lb_underlay, e.ports.clone()))
    }

    /// List all LBs: (id, vni, ip_bytes, lb_underlay, ports).
    pub fn list_lbs(&self) -> Vec<LbRow> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .iter()
            .map(|(id, e)| {
                (
                    id.clone(),
                    e.vni,
                    e.ip.as_lb_ip_bytes(),
                    e.lb_underlay,
                    e.ports.clone(),
                )
            })
            .collect()
    }

    /// List the backend underlay addresses for a given LB.
    pub fn list_lb_targets(&self, id: &[u8]) -> Vec<[u8; 16]> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .get(id)
            .map(|e| e.backends.clone())
            .unwrap_or_default()
    }

    /// List all backends across all LBs (global).
    pub fn list_lb_targets_all(&self) -> Vec<[u8; 16]> {
        let g = self.inner.lock().unwrap();
        g.lbs
            .values()
            .flat_map(|e| e.backends.iter().copied())
            .collect()
    }

    /// Remove a load balancer: clear its `LB` service entries and `MAGLEV` slots.
    /// Returns true if found and deleted, false if not found.
    pub fn delete_lb(&self, id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let entry = match g.lbs.remove(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        let ip4 = entry.ip.last4();
        for &(port, proto) in &entry.ports {
            let _ = g.lb.remove(&LbKey {
                vni: entry.vni,
                ipv4: ip4,
                port,
                proto,
                _pad: 0,
            });
        }
        for slot in 0..crate::maglev::TABLE_SIZE {
            let _ = g.maglev.remove(&MaglevKey {
                table_id: entry.table_id,
                slot,
            });
        }
        Ok(true)
    }

    /// Program the VIPS map for SNAT (G->V) and DNAT (V->G).
    /// Returns the underlay route for this interface on success.
    pub fn create_vip(
        &self,
        interface_id: &[u8],
        vip: [u8; 4],
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        // Check for existing VIP.
        if g.vips.get(&VipKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: VIP already set for this interface");
        }
        // Check preferred underlay collision.
        let effective_underlay = if let Some(pul) = preferred_ul {
            if g.by_id.values().any(|r| r.underlay == pul)
                || g.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
            pul
        } else {
            underlay
        };
        // egress SNAT: (vni, guest_ip) -> vip
        g.vips.upsert(VipKey { vni, ipv4: gip }, vip)?;
        // ingress DNAT: (vni, vip) -> guest_ip
        g.vips.upsert(VipKey { vni, ipv4: vip }, gip)?;
        Ok(effective_underlay)
    }

    /// Remove both VIPS map entries for this interface.
    /// Returns true if a VIP existed and was removed, false if none existed.
    pub fn delete_vip(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        if g.vips.get(&VipKey { vni, ipv4: gip }).is_none() {
            return Ok(false);
        }
        if let Some(vip) = g.vips.get(&VipKey { vni, ipv4: gip }) {
            let _ = g.vips.remove(&VipKey { vni, ipv4: vip });
        }
        let _ = g.vips.remove(&VipKey { vni, ipv4: gip });
        Ok(true)
    }

    /// Return the VIP and underlay for this interface, if one has been set.
    pub fn get_vip(&self, interface_id: &[u8]) -> Option<([u8; 4], [u8; 16])> {
        let g = self.inner.lock().unwrap();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        g.vips
            .get(&VipKey { vni, ipv4: gip })
            .map(|vip| (vip, underlay))
    }

    /// Program a guest's NAT config: (vni, guest_ip) -> (nat_ip, port_min, port_max).
    /// Returns the underlay route on success.
    pub fn create_nat(
        &self,
        interface_id: &[u8],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;

        // Check for existing NAT on this interface (any NAT IP).
        if g.nat.get(&NatKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: NAT already configured for this interface");
        }

        // Check for overlapping port range across all interfaces in this VNI with the same nat_ip.
        for r in g.by_id.values() {
            if r.vni == vni {
                if let Some(v) = g.nat.get(&NatKey { vni, ipv4: r.ipv4 }) {
                    if v.nat_ipv4 == nat_ip {
                        // Overlapping port range?
                        if port_min < v.port_max && port_max > v.port_min {
                            anyhow::bail!("SNAT_EXISTS: overlapping NAT port range");
                        }
                    }
                }
            }
        }

        // Check preferred underlay collision.
        if let Some(pul) = preferred_ul {
            if g.by_id.values().any(|r| r.underlay == pul)
                || g.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
        }

        g.nat.upsert(
            NatKey { vni, ipv4: gip },
            NatValue {
                nat_ipv4: nat_ip,
                port_min,
                port_max,
            },
        )?;
        // Mark this nat_ip in NAT_IPS so the ingress can generate ICMP echo replies for it.
        let _ = g.nat_ips.set(vni, nat_ip);
        Ok(preferred_ul.unwrap_or(underlay))
    }

    /// Return a guest's NAT config (nat_ip, port_min, port_max, underlay, vni), if set.
    pub fn get_nat(&self, interface_id: &[u8]) -> Option<NatDetail> {
        let g = self.inner.lock().unwrap();
        let rec = g.by_id.get(interface_id)?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;
        g.nat
            .get(&NatKey { vni, ipv4: gip })
            .map(|v| (v.nat_ipv4, v.port_min, v.port_max, underlay, vni))
    }

    /// List all local NAT entries: (interface_id, guest_ipv4, nat_ip, port_min, port_max, vni, underlay).
    pub fn list_local_nats(&self) -> Vec<LocalNatRow> {
        let g = self.inner.lock().unwrap();
        let mut result: Vec<LocalNatRow> = g
            .by_id
            .iter()
            .filter_map(|(id, rec)| {
                g.nat
                    .get(&NatKey {
                        vni: rec.vni,
                        ipv4: rec.ipv4,
                    })
                    .map(|v| {
                        (
                            id.clone(),
                            rec.ipv4,
                            v.nat_ipv4,
                            v.port_min,
                            v.port_max,
                            rec.vni,
                            rec.underlay,
                        )
                    })
            })
            .collect();
        // Sort by guest IP in descending order to match expected list ordering.
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    /// Flush CONNTRACK entries whose egress 5-tuple originated from `(vni, src_ip)`.
    /// For NAT flows this removes both the forward entry (CT_REWRITE_SRC, key.src_ip == gip)
    /// and the reverse entry (CT_REWRITE_DST, key.dst_ip == nat_ip with xlate_port in range).
    fn ct_flush_for_guest(
        ct: &mut Conntrack,
        vni: u32,
        gip: [u8; 4],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) {
        // Collect all keys to remove first to avoid borrow issues during iteration.
        let to_remove: Vec<CtKey> = ct
            .entries()
            .into_iter()
            .filter_map(|(k, e)| {
                if k.vni != vni {
                    return None;
                }
                // Forward NAT entry: src_ip == guest IP, CT_REWRITE_SRC set.
                let is_fwd = k.src_ip == gip
                    && (e.flags & xdp_dp_common::CT_REWRITE_SRC != 0
                        || e.flags & xdp_dp_common::CT_F_SRC_NAT != 0);
                // Reverse NAT entry: dst_ip == nat_ip, dst_port in the NAT port range.
                let is_rev = k.dst_ip == nat_ip
                    && k.dst_port >= port_min
                    && k.dst_port < port_max
                    && e.flags & xdp_dp_common::CT_REWRITE_DST != 0;
                if is_fwd || is_rev {
                    Some(k)
                } else {
                    None
                }
            })
            .collect();
        for k in to_remove {
            let _ = ct.remove(&k);
        }
    }

    /// Remove a guest's NAT config. Returns true if found and deleted, false if no NAT was set.
    pub fn delete_nat(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let (vni, gip, nat_ip, port_min, port_max) = {
            let mut g = self.inner.lock().unwrap();
            let rec = g
                .by_id
                .get(interface_id)
                .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
            let (vni, gip) = (rec.vni, rec.ipv4);
            let nat_val = match g.nat.get(&NatKey { vni, ipv4: gip }) {
                Some(v) => v,
                None => return Ok(false),
            };
            let nat_ip = nat_val.nat_ipv4;
            let port_min = nat_val.port_min;
            let port_max = nat_val.port_max;
            let _ = g.nat.remove(&NatKey { vni, ipv4: gip });
            // Remove the NAT_IPS marker if no other interface in this VNI uses the same nat_ip.
            let still_used = g.by_id.iter().any(|(other_id, r)| {
                other_id.as_slice() != interface_id
                    && r.vni == vni
                    && g.nat
                        .get(&NatKey {
                            vni: r.vni,
                            ipv4: r.ipv4,
                        })
                        .map(|v| v.nat_ipv4 == nat_ip)
                        .unwrap_or(false)
            });
            if !still_used {
                let _ = g.nat_ips.remove(vni, nat_ip);
            }
            (vni, gip, nat_ip, port_min, port_max)
        };
        // Flush CT entries for this guest outside the inner lock (conntrack lock is separate).
        let mut ct = self.conntrack.lock().unwrap();
        Self::ct_flush_for_guest(&mut ct, vni, gip, nat_ip, port_min, port_max);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Firewall rule management
    // -----------------------------------------------------------------------

    /// Reprogram all firewall slots for one interface from the in-memory `fw` vec.
    fn fw_reprogram(g: &mut Inner, ifindex: u32) -> anyhow::Result<()> {
        let rules = g.fw.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = g.fw_rules.remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            g.fw_rules.upsert(
                FwRuleKey {
                    ifindex,
                    idx: i as u32,
                },
                *r,
            )?;
            if r.direction == FW_DIR_EGRESS {
                egress += 1;
            } else {
                ingress += 1;
            }
        }
        g.fw_meta.upsert(
            ifindex,
            FwMeta {
                ingress_count: ingress,
                egress_count: egress,
            },
        )?;
        Ok(())
    }

    /// Add or replace a firewall rule on an interface.
    /// Returns an error with "already exists" if a rule with that ID already exists.
    pub fn add_fw_rule(
        &self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        if entry.len() >= FW_MAX_RULES as usize {
            anyhow::bail!(
                "too many firewall rules for interface (max {})",
                FW_MAX_RULES
            );
        }
        // Reject duplicate rule IDs.
        if entry.iter().any(|(id, _)| id == &rule_id) {
            anyhow::bail!("ALREADY_EXISTS: firewall rule already exists");
        }
        entry.push((rule_id, rule));
        Self::fw_reprogram(&mut g, ifindex)
    }

    /// Remove a firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        Self::fw_reprogram(&mut g, ifindex)?;
        Ok(true)
    }

    /// Get a single firewall rule by id.
    pub fn get_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> Option<FwRule> {
        let g = self.inner.lock().unwrap();
        let ifindex = *g.by_ifindex.get(interface_id)?;
        g.fw.get(&ifindex)?
            .iter()
            .find(|(id, _)| id.as_slice() == rule_id)
            .map(|(_, r)| *r)
    }

    /// List all firewall rules for an interface as (rule_id, rule) pairs.
    pub fn list_fw_rules(&self, interface_id: &[u8]) -> Vec<(Vec<u8>, FwRule)> {
        let g = self.inner.lock().unwrap();
        match g.by_ifindex.get(interface_id) {
            Some(ifindex) => g.fw.get(ifindex).cloned().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Alias prefix management
    // -----------------------------------------------------------------------

    /// Announce an alias prefix routed to an interface: program a route (vni, prefix/len) -> the
    /// interface's underlay /128. Returns the underlay route.
    pub fn add_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let underlay = *g
            .iface_underlay
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("interface has no underlay"))?;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ROUTE_EXISTS: prefix already exists");
            }
        }
        // Also check other interfaces in the same VNI.
        for (oid, pv) in &g.prefixes {
            if oid != interface_id {
                if let Some(orec) = g.by_id.get(oid) {
                    if orec.vni == vni
                        && pv
                            .iter()
                            .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
                    {
                        anyhow::bail!("ROUTE_EXISTS: prefix already in use in this VNI");
                    }
                }
            }
        }

        g.routes.upsert(
            vni,
            prefix,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: effective_ul,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&prefix);
        g.prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: ip16,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: false,
            });
        Ok(effective_ul)
    }

    /// Add an IPv6 alias prefix. Returns the underlay route.
    pub fn add_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let vni = rec.vni;
        let underlay = *g
            .iface_underlay
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("interface has no underlay"))?;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ROUTE_EXISTS: IPv6 prefix already exists");
            }
        }

        g.routes6.upsert(
            vni,
            prefix,
            prefix_len,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: effective_ul,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        g.prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: prefix,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: true,
            });
        Ok(effective_ul)
    }

    /// Remove an alias prefix. Returns true if removed, false if not found.
    pub fn del_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, _gip) = (rec.vni, rec.ipv4);
        let pv = g.prefixes.get_mut(interface_id);
        if let Some(v) = pv {
            let before = v.len();
            v.retain(|pr| !((!pr.is_ipv6) && pr.ip[..4] == prefix && pr.len == prefix_len));
            if v.len() < before {
                let _ = g.routes.remove(vni, prefix, prefix_len);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove an IPv6 alias prefix. Returns true if removed, false if not found.
    pub fn del_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let vni = rec.vni;
        let pv = g.prefixes.get_mut(interface_id);
        if let Some(v) = pv {
            let before = v.len();
            v.retain(|pr| !(pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len));
            if v.len() < before {
                let _ = g.routes6.remove(vni, prefix, prefix_len);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return all alias prefixes for an interface as (ip_bytes_16, len, underlay, is_ipv6).
    pub fn list_prefixes_with_underlay(
        &self,
        interface_id: &[u8],
    ) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock().unwrap();
        g.prefixes
            .get(interface_id)
            .map(|v| {
                v.iter()
                    .map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return all prefix records across all interfaces (global list).
    pub fn list_prefixes_all(&self) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock().unwrap();
        g.prefixes
            .values()
            .flat_map(|v| v.iter().map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // LB prefix management
    // -----------------------------------------------------------------------

    /// Add an LB-prefix shadow entry (announce-only; no datapath route needed).
    /// Returns the underlay route.
    pub fn add_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let underlay = rec.underlay;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.lb_prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| !pr.is_ipv6 && pr.ip[..4] == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ALREADY_EXISTS: LB prefix already exists");
            }
        }

        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&prefix);
        g.lb_prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: ip16,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: false,
            });
        Ok(effective_ul)
    }

    /// Add an IPv6 LB-prefix shadow entry. Returns the underlay route.
    pub fn add_lb_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let underlay = rec.underlay;
        let effective_ul = preferred_ul.unwrap_or(underlay);

        // Check for duplicate.
        if let Some(v) = g.lb_prefixes.get(interface_id) {
            if v.iter()
                .any(|pr| pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len)
            {
                anyhow::bail!("ALREADY_EXISTS: IPv6 LB prefix already exists");
            }
        }

        g.lb_prefixes
            .entry(interface_id.to_vec())
            .or_default()
            .push(PrefixRecord {
                ip: prefix,
                len: prefix_len,
                underlay: effective_ul,
                is_ipv6: true,
            });
        Ok(effective_ul)
    }

    /// Remove an LB-prefix shadow entry. Returns true if removed, false if not found.
    pub fn del_lb_prefix(
        &self,
        interface_id: &[u8],
        prefix: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        // Check interface exists.
        if !g.by_id.contains_key(interface_id) {
            anyhow::bail!("NO_VM: unknown interface");
        }
        if let Some(v) = g.lb_prefixes.get_mut(interface_id) {
            let before = v.len();
            v.retain(|pr| !((!pr.is_ipv6) && pr.ip[..4] == prefix && pr.len == prefix_len));
            if v.len() < before {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove an IPv6 LB-prefix shadow entry. Returns true if removed, false if not found.
    pub fn del_lb_prefix6(
        &self,
        interface_id: &[u8],
        prefix: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        if !g.by_id.contains_key(interface_id) {
            anyhow::bail!("NO_VM: unknown interface");
        }
        if let Some(v) = g.lb_prefixes.get_mut(interface_id) {
            let before = v.len();
            v.retain(|pr| !(pr.is_ipv6 && pr.ip == prefix && pr.len == prefix_len));
            if v.len() < before {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return LB-prefix entries for an interface as (ip_bytes_16, len, underlay, is_ipv6).
    pub fn list_lb_prefixes_with_underlay(
        &self,
        interface_id: &[u8],
    ) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock().unwrap();
        g.lb_prefixes
            .get(interface_id)
            .map(|v| {
                v.iter()
                    .map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return all LB-prefix records across all interfaces (global).
    pub fn list_lb_prefixes_all(&self) -> Vec<([u8; 16], u32, [u8; 16], bool)> {
        let g = self.inner.lock().unwrap();
        g.lb_prefixes
            .values()
            .flat_map(|v| v.iter().map(|pr| (pr.ip, pr.len, pr.underlay, pr.is_ipv6)))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Neighbor NAT management (distributed NAT return)
    // -----------------------------------------------------------------------

    /// Reprogram NEIGHBOR_NAT and NEIGHBOR_NAT_COUNT from the in-memory vec.
    fn neigh_nat_reprogram(g: &mut Inner) -> anyhow::Result<()> {
        let n = g.neigh_nats.len() as u32;
        for (i, e) in g.neigh_nats.iter().enumerate() {
            g.neigh_nat.upsert(i as u32, *e)?;
        }
        g.neigh_nat_count.set(n)?;
        Ok(())
    }

    /// Add a neighbor-NAT entry (capped at NB_MAX_ENTRIES).
    pub fn add_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.neigh_nats.len() >= NB_MAX_ENTRIES as usize {
            anyhow::bail!("neighbor NAT table full (max {})", NB_MAX_ENTRIES);
        }
        // Check for duplicate or overlapping port range.
        if g.neigh_nats.iter().any(|e| {
            e.nat_ip == nat_ip
                && (
                    // Exact match (same vni and ports) → always duplicate.
                    (e.vni == vni && e.port_min == port_min && e.port_max == port_max)
                // Overlapping port range for the same nat_ip (any vni) → also duplicate.
                || (e.port_min < port_max && e.port_max > port_min)
                )
        }) {
            anyhow::bail!(
                "ALREADY_EXISTS: neighbor NAT entry already exists or port range overlaps"
            );
        }
        g.neigh_nats.push(NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        });
        Self::neigh_nat_reprogram(&mut g)
    }

    /// Remove a neighbor-NAT entry matching (vni, nat_ip, port_min, port_max).
    /// Returns true if removed, false if not found.
    pub fn del_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().unwrap();
        let before = g.neigh_nats.len();
        g.neigh_nats.retain(|e| {
            !(e.vni == vni
                && e.nat_ip == nat_ip
                && e.port_min == port_min
                && e.port_max == port_max)
        });
        if g.neigh_nats.len() == before {
            return Ok(false);
        }
        Self::neigh_nat_reprogram(&mut g)?;
        Ok(true)
    }

    /// List all neighbor-NAT entries.
    pub fn list_neighbor_nats(&self) -> Vec<NeighborNatEntry> {
        let g = self.inner.lock().unwrap();
        g.neigh_nats.clone()
    }
}

#[cfg(test)]
impl Control {
    /// Build a `Control` from a freshly loaded eBPF object WITHOUT attaching any program to an
    /// interface. Opens every map handle exactly like `bring_up` does, but skips the XDP/tc attach
    /// so the test needs only CAP_BPF (a real kernel), not a live uplink. Used to exercise the
    /// userspace control plane's map programming (e.g. `create_lb`'s UNDERLAY writes) in isolation.
    fn from_ebpf_for_test() -> anyhow::Result<Self> {
        let mut ebpf = loader::load_ebpf()?;
        let guest_progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex: 0,
            uplink_mac: [0; 6],
            gateway_mac: [0; 6],
            underlay_ipv6: [0; 16],
        })?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        Ok(Self {
            inner: Mutex::new(Inner {
                ebpf,
                _guest_progs: guest_progs,
                _locals: locals,
                ports,
                ifaces,
                routes,
                routes6,
                vips,
                lb,
                maglev,
                nat,
                fw_rules,
                fw_meta,
                underlay,
                meter,
                neigh_nat,
                neigh_nat_count,
                nat_ips,
                dhcp_config,
                dhcp_meta,
                neigh_nats: Vec::new(),
                lbs: HashMap::new(),
                next_table_id: 1,
                by_id: HashMap::new(),
                by_ifindex: HashMap::new(),
                iface_underlay: HashMap::new(),
                prefixes: HashMap::new(),
                fw: HashMap::new(),
                lb_prefixes: HashMap::new(),
                links: HashMap::new(),
                guest_tc: true,
                routes_shadow: Vec::new(),
                routes6_shadow: Vec::new(),
                learned_macs: HashMap::new(),
            }),
            conntrack,
        })
    }

    /// Test-only: read the UNDERLAY map entry for `key` (the LB/interface /128).
    fn underlay_get(&self, key: &[u8; 16]) -> Option<xdp_dp_common::UnderlayValue> {
        self.inner.lock().unwrap().underlay.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root/CAP_BPF; run via: sudo -E <test-bin> --include-ignored"]
    fn create_lb_skips_underlay_write_for_wan_edge() {
        let ctrl = Control::from_ebpf_for_test().expect("build test control");
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];

        // WAN edge (vni==0): create_lb must NOT program UNDERLAY[lb_underlay] — wan_rx never resolves
        // it and a write would clobber attach_edge's LOCAL_DELIVER egress entry.
        ctrl.create_lb(
            b"vip-a",
            0,
            LbIpBytes::Ipv4([203, 0, 113, 50]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=0");
        assert!(
            ctrl.underlay_get(&lb_ul).is_none(),
            "vni=0 must NOT write UNDERLAY[lb_underlay]"
        );

        // Overlay relay LB (vni!=0): create_lb MUST program UNDERLAY[lb_underlay] as before.
        ctrl.create_lb(
            b"vip-b",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 1]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=100");
        assert!(
            ctrl.underlay_get(&lb_ul).is_some(),
            "vni!=0 must write UNDERLAY[lb_underlay]"
        );
    }
}
