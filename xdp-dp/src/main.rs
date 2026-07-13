// `tonic::Status` is a large type, and it is the error type the generated `DPDKironcore` trait
// mandates for every handler (and the decode helpers that feed them). Boxing it everywhere to
// satisfy `result_large_err` would add indirection and noise for no real benefit on a gRPC server.
#![allow(clippy::result_large_err)]

pub mod pb {
    tonic::include_proto!("dpdkironcore.v1");
}

mod conntrack_gc;
mod control;
mod grpc;
mod loader;
mod maglev;
mod maps;
mod node;
mod state;
mod underlay;

use anyhow::Context;
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// Sysfs / parse helpers
// ---------------------------------------------------------------------------

/// Read `/sys/class/net/<iface>/ifindex` and parse it as a u32.
pub(crate) fn ifindex(iface: &str) -> anyhow::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("read ifindex for {iface}"))?;
    Ok(s.trim().parse()?)
}

/// Read `/sys/class/net/<iface>/address` and return 6 MAC bytes.
pub(crate) fn mac_of(iface: &str) -> anyhow::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read mac for {iface}"))?;
    parse_mac(s.trim())
}

/// Parse `"aa:bb:cc:dd:ee:ff"` into 6 bytes.
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        anyhow::ensure!(i < 6, "too many octets in MAC {s}");
        out[i] = u8::from_str_radix(part, 16).with_context(|| format!("bad MAC octet {part}"))?;
        n += 1;
    }
    anyhow::ensure!(n == 6, "MAC {s} must have 6 octets");
    Ok(out)
}

/// Parse an IPv6 literal into 16 octets.
fn parse_ipv6(s: &str) -> anyhow::Result<[u8; 16]> {
    Ok(s.parse::<std::net::Ipv6Addr>()
        .with_context(|| format!("bad IPv6 {s}"))?
        .octets())
}

/// Parse an IPv4 literal into 4 octets.
fn parse_ipv4(s: &str) -> anyhow::Result<[u8; 4]> {
    Ok(s.parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("bad IPv4 {s}"))?
        .octets())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "xdp-dp")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

// One `Cmd` is parsed once at startup and lives for the process; the size gap between the tiny
// subcommands and the flag-heavy `Bringup`/`TcBringup` is irrelevant, and boxing variants fights
// clap's derive (it expects `#[arg]` fields directly on the variant).
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Cmd {
    /// Load and attach the XDP datapath to an interface, then idle.
    Load {
        #[arg(long)]
        uplink: String,
    },
    /// Start the gRPC control-plane server with a live datapath.
    Serve {
        /// Address to listen on (e.g. 127.0.0.1:1337).
        #[arg(long)]
        addr: String,
        /// Uplink interface (uplink_rx attaches here).
        #[arg(long)]
        uplink: String,
        /// This hypervisor's underlay IPv6 (outer src on encap).
        #[arg(long)]
        local_underlay: String,
        /// Underlay next-hop MAC — outer eth dst for ALL encapped traffic.
        #[arg(long)]
        gateway_mac: String,
        /// Override the CONNTRACK map capacity (entries). Also settable via XDP_DP_CONNTRACK_MAX.
        #[arg(long)]
        conntrack_max: Option<u32>,
        /// Overlay IPv4 gateway the datapath answers ARP for (e.g. 169.254.0.1).
        #[arg(long)]
        gateway: String,
        /// Overlay IPv6 gateway the datapath answers ND for (e.g. fe80::1).
        #[arg(long = "gateway6")]
        gateway6: Option<String>,
        /// Pin programs+maps under this dir for HA (control-plane restart re-adopts).
        #[arg(long = "pin-dir")]
        pin_dir: Option<String>,
        /// DHCP options (stored for sub-project 2b; accepted now to keep the ioiab arg list stable).
        #[arg(long = "dhcp-mtu")]
        dhcp_mtu: Option<u32>,
        #[arg(long = "dhcp-dns")]
        dhcp_dns: Vec<String>,
        #[arg(long = "dhcpv6-dns")]
        dhcpv6_dns: Vec<String>,
    },
    /// Infer this host's underlay /64 from its interface addresses (prefers a lo/dummy* fabric
    /// loopback) and print it, then exit. No datapath, no root — reads `ip -6 -o addr`. Used by the
    /// containerlab IPv6-fabric e2e to assert the inferred /64 matches the fabric-announced dummy0.
    InferUnderlay,
    /// Attach the trivial xdp_pass program to an interface (redirect-target enabler), then idle.
    Pass {
        #[arg(long)]
        iface: String,
    },
    /// Attach xdp_inspect to an interface and print the first packet bytes every 500 ms.
    Inspect {
        #[arg(long)]
        iface: String,
    },
    /// Bring up the map-driven datapath: attach programs and program all maps, then idle.
    Bringup {
        /// Uplink interface (uplink_rx attaches here).
        #[arg(long)]
        uplink: String,
        /// This hypervisor's underlay IPv6 (outer src on encap).
        #[arg(long)]
        local_underlay: String,
        /// Overlay gateway IPv4 the datapath answers ARP for (e.g. 10.0.0.1).
        #[arg(long)]
        gateway: String,
        /// Underlay next-hop (gateway/ToR router) MAC — outer eth dst for ALL encapped traffic.
        /// In a flat-L2 lab this is the peer hypervisor's uplink MAC.
        #[arg(long)]
        gateway_mac: String,
        /// Local guest, repeatable:
        /// "<ifname>=<overlay_ipv4>=<guest_mac>=<underlay_ipv6>=<vni>". The per-interface underlay
        /// /128 is the interface's identity on the underlay (UNDERLAY map key); guest_tx attaches
        /// to <ifname> (the hypervisor-side veth peer).
        #[arg(long = "guest")]
        guests: Vec<String>,
        /// Remote guest route, repeatable: "<overlay_ipv4>=<nexthop_underlay_ipv6>=<vni>" where the
        /// nexthop is the remote interface's underlay /128. The outer L2 next-hop is the single
        /// underlay gateway set via --gateway-mac.
        #[arg(long = "remote")]
        remotes: Vec<String>,
        /// VIP mapping, repeatable: "<interface_ipv4>=<vip_ipv4>" (programs both VIPS directions).
        #[arg(long = "vip")]
        vips: Vec<String>,
        /// Load balancer service, repeatable:
        /// "<ipv4>:<port>:<proto>:<lb_underlay_ipv6>" (proto numeric: 1=ICMP, 6=TCP, 17=UDP).
        /// For ICMP use port 0. The lb_underlay_ipv6 is the LB's own underlay /128 (programs
        /// UNDERLAY so the datapath can identify arriving LB-destined packets). Allocates a
        /// Maglev table; add backends via --lb-target.
        #[arg(long = "lb")]
        lbs: Vec<String>,
        /// LB backend, repeatable: "<ipv4>:<port>:<proto>:<lb_underlay_ipv6>=<backend_underlay_ipv6>".
        /// References an --lb service and appends a backend underlay /128, rebuilding that
        /// service's Maglev table.
        #[arg(long = "lb-target")]
        lb_targets: Vec<String>,
        /// NAT config, repeatable: "<guest_ipv4>=<nat_ipv4>:<port_min>:<port_max>".
        #[arg(long = "nat")]
        nats: Vec<String>,
        /// Mark a remote route external (NAT-eligible egress), repeatable: "<overlay_ipv4>".
        #[arg(long = "external")]
        externals: Vec<String>,
        /// Override the CONNTRACK map capacity (entries). Also settable via XDP_DP_CONNTRACK_MAX.
        #[arg(long)]
        conntrack_max: Option<u32>,
        /// Firewall rule, repeatable:
        /// "<ifname>:<in|eg>:<accept|drop>:<any|icmp|tcp|udp>:<src_cidr>:<dst_cidr>:<dport|*>".
        #[arg(long = "fw-rule")]
        fw_rules: Vec<String>,
        /// Whether the firewall actually drops on a deny (false = evaluate-only). Default true.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        firewall_enforce: bool,
        /// Neighbor NAT entry, repeatable:
        /// "<nat_ip>:<port_min>:<port_max>@<owner_underlay_ipv6>@<vni>". Programs NEIGHBOR_NAT
        /// so that return traffic to nat_ip:dport is re-forwarded to the owner's underlay node.
        #[arg(long = "neigh-nat")]
        neigh_nats: Vec<String>,
        /// Underlay VNI marker, repeatable: "<ipv6>:<vni>". Programs UNDERLAY[ipv6] with a
        /// vni-only entry (tap_ifindex=0, guest_mac=[0;6]) so that uplink_rx can resolve the VNI
        /// for a NAT-gateway node that does not host a local interface.
        #[arg(long = "underlay-marker")]
        underlay_markers: Vec<String>,
        /// Per-interface egress rate cap, repeatable: "<ifname>=<total_mbps>:<public_mbps>".
        /// Programs the METER map token bucket for the named interface (opt-in; 0 = unlimited).
        #[arg(long = "meter")]
        meters: Vec<String>,
        /// Pin the XDP links + CONNTRACK under this bpffs dir so the datapath survives a
        /// control-plane restart (HA). Requires bpffs (e.g. /sys/fs/bpf). Unset = non-HA
        /// (default behavior, unchanged).
        #[arg(long)]
        pin_dir: Option<String>,
        /// Adopt an already-running pinned datapath (after a restart): do NOT load/attach; just
        /// re-open the pinned CONNTRACK and resume aging. Requires --pin-dir.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        adopt: bool,
        /// Overlay IPv6 gateway the datapath answers ND for (e.g. fd00:ov::1).
        #[arg(long = "gateway6")]
        gateway6: Option<String>,
        /// Dual-stack guest v6, repeatable: "<ifname>=<overlay_ipv6>=<underlay_ipv6>=<vni>".
        /// Sets the interface's PortMeta.gateway_ipv6 (= --gateway6) so ND works; delivery is by
        /// UNDERLAY. The ifname must also appear in --guest for v4 fields to be set.
        #[arg(long = "guest6")]
        guests6: Vec<String>,
        /// Remote IPv6 route, repeatable: "<overlay_ipv6>[/len]=<nexthop_underlay_ipv6>=<vni>".
        /// Programs the ROUTES6 LPM trie so v6_guest_tx can forward overlay IPv6 packets.
        #[arg(long = "remote6")]
        remotes6: Vec<String>,
        /// DHCP MTU option (server-wide). Defaults to 1500 if unset.
        #[arg(long = "dhcp-mtu")]
        dhcp_mtu: Option<u32>,
        /// DHCPv4 DNS server, repeatable (server-wide).
        #[arg(long = "dhcp-dns")]
        dhcp_dns: Vec<String>,
        /// DHCPv6 DNS server, repeatable (server-wide).
        #[arg(long = "dhcpv6-dns")]
        dhcpv6_dns: Vec<String>,
    },
    /// Minimal tc guest-edge bringup for the Phase-1 DHCP gate: attach tc_guest_tx to one tap's
    /// clsact ingress, program PORT_META + DHCP config for it, then idle.
    TcBringup {
        #[arg(long)]
        tap: String,
        #[arg(long)]
        guest_ipv4: String,
        #[arg(long)]
        gateway_ipv4: String,
        /// Overlay IPv6 gateway, programmed into PortMeta.gateway_ipv6 so the ND responder has a
        /// target to match (dpservice presents the gateway at the VF's own MAC).
        #[arg(long = "gateway6", default_value = "fe80::1")]
        gateway6: String,
        #[arg(long)]
        guest_mac: String,
        #[arg(long)]
        gateway_mac: String,
        #[arg(long, default_value_t = 1500)]
        dhcp_mtu: u32,
        #[arg(long = "dhcp-dns")]
        dhcp_dns: Vec<String>,
        /// Uplink device. When set, programs LOCAL (uplink_ifindex/uplink_mac from this dev,
        /// gateway_mac from --gateway-mac, underlay from --local-underlay) so the egress encap
        /// path can build outer frames and redirect them out this dev.
        #[arg(long)]
        uplink: Option<String>,
        /// This hypervisor's underlay IPv6 (outer src on encap). Programmed into LOCAL.
        #[arg(long = "local-underlay", default_value = "fc00:1::1")]
        local_underlay: String,
        /// The guest's own underlay IPv6 (PortMeta.underlay_ipv6 = outer src identity), also
        /// programmed into UNDERLAY -> (vni, tap_ifindex, guest_mac) so the local fast-path can
        /// find it. Defaults to the local-underlay.
        #[arg(long = "guest-underlay", default_value = "fc00:1::1")]
        guest_underlay: String,
        /// Remote guest route, repeatable: "<overlay_ipv4>=<nexthop_underlay_ipv6>=<vni>".
        /// Programs ROUTES so guest traffic to that overlay IPv4 encaps toward the nexthop.
        #[arg(long = "remote")]
        remotes: Vec<String>,
        /// The guest's own overlay IPv6 (PortMeta.guest_ipv6). The DHCPv6 responder offers this
        /// address; v6 egress reads the inner v6 dst from the packet (program --remote6 to route).
        #[arg(long = "guest6")]
        guest6: Option<String>,
        /// Remote IPv6 route, repeatable: "<overlay_ipv6>[/len]=<nexthop_underlay_ipv6>=<vni>".
        /// Programs the ROUTES6 LPM trie so v6 guest egress encaps toward the nexthop.
        #[arg(long = "remote6")]
        remotes6: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logger backend for the eBPF `dlog!` tracing (active only with XDP_DP_DEBUG + a debug image).
    // Honors RUST_LOG; defaults to `info` so datapath traces show without extra config.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Load { uplink } => {
            let _ebpf = loader::attach_uplink(&uplink)?;
            println!("attached uplink_rx to {uplink}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::InferUnderlay => {
            // Pure, root-free observability hook for the containerlab IPv6-fabric e2e: read the
            // host ifaddrs and print the inferred underlay /64 in a stable, greppable form.
            let addrs = underlay::read_host_ifaddrs()?;
            let prefix = underlay::infer_underlay_prefix(&addrs)
                .context("no global-unicast IPv6 address found to infer underlay /64")?;
            println!("inferred underlay prefix: {prefix}");
        }
        Cmd::Serve {
            addr,
            uplink,
            local_underlay,
            gateway,
            gateway6,
            gateway_mac,
            conntrack_max,
            pin_dir: _pin_dir,
            dhcp_mtu,
            dhcp_dns,
            dhcpv6_dns,
        } => {
            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                std::env::set_var("XDP_DP_CONNTRACK_MAX", n.to_string());
            }
            let underlay = parse_ipv6(&local_underlay)?;
            let gateway_ipv4 = parse_ipv4(&gateway)?;
            let gateway_ipv6 = match &gateway6 {
                Some(s) => parse_ipv6(s)?,
                None => [0u8; 16],
            };
            let ctrl = control::Control::bring_up(
                &uplink,
                ifindex(&uplink)?,
                mac_of(&uplink)?,
                parse_mac(&gateway_mac)?,
                underlay,
            )?;
            let dns4: Vec<[u8; 4]> = dhcp_dns
                .iter()
                .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets()))
                .collect();
            let dns6: Vec<[u8; 16]> = dhcpv6_dns
                .iter()
                .filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok().map(|a| a.octets()))
                .collect();
            ctrl.set_dhcp_config(dhcp_mtu.unwrap_or(1500) as u16, &dns4, &dns6)
                .map_err(|e| anyhow::anyhow!(e))?;
            tokio::spawn(conntrack_gc::run(
                ctrl.take_conntrack(),
                std::time::Duration::from_secs(10),
            ));
            let svc = grpc::Service {
                state: std::sync::Arc::new(state::State::default()),
                control: Some(std::sync::Arc::new(ctrl)),
                underlay,
                gateway_ipv4,
                gateway_ipv6,
            };
            let server = crate::pb::dpd_kironcore_server::DpdKironcoreServer::new(svc);
            // gRPC health service (grpc.health.v1.Health) so the Kubernetes gRPC liveness probe
            // passes — the empty service name "" reports Serving (what the probe checks by default).
            // dpservice implements this; without it the probe SIGKILLs the pod every period.
            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_service_status("", tonic_health::ServingStatus::Serving)
                .await;
            println!("serving DPDKironcore on {addr}");
            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(server)
                .add_service(node::pb::dataplane_node_server::DataplaneNodeServer::new(
                    node::NodeService::default(),
                ))
                .serve(addr.parse()?)
                .await?;
        }
        Cmd::Bringup {
            uplink,
            local_underlay,
            gateway,
            gateway_mac,
            guests,
            remotes,
            vips: vips_args,
            lbs,
            lb_targets,
            nats,
            externals,
            conntrack_max,
            fw_rules,
            firewall_enforce,
            neigh_nats,
            underlay_markers,
            meters,
            pin_dir,
            adopt,
            gateway6,
            guests6,
            remotes6,
            dhcp_mtu,
            dhcp_dns,
            dhcpv6_dns,
        } => {
            // HA adopt path: re-open the pinned CONNTRACK and resume GC; no load/attach.
            if adopt {
                let dir = pin_dir.as_deref().context("--adopt requires --pin-dir")?;
                let ct = maps::Conntrack::from_pin(&format!("{dir}/CONNTRACK"))?;
                tokio::spawn(conntrack_gc::run(
                    std::sync::Arc::new(std::sync::Mutex::new(ct)),
                    std::time::Duration::from_secs(10),
                ));
                println!("adopted pinned datapath at {dir}; resuming conntrack GC; ctrl-c to stop");
                tokio::signal::ctrl_c().await?;
                return Ok(());
            }

            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                std::env::set_var("XDP_DP_CONNTRACK_MAX", n.to_string());
            }
            let mut ebpf = loader::load_ebpf()?;
            loader::maybe_install_logger(&mut ebpf);

            // Pass 1: attach ALL XDP programs while ebpf is still fully intact
            // (take_map consumes map entries, but programs are separate — still need &mut ebpf).
            // uplink_rx: load + attach once.
            match pin_dir.as_deref() {
                Some(dir) => {
                    loader::attach_xdp_pinned(&mut ebpf, "uplink_rx", &uplink, dir, false)?
                }
                None => loader::attach_xdp(&mut ebpf, "uplink_rx", &uplink)?,
            }
            // guest_tx: load once (first guest), then attach-only for additional guests.
            for (idx, g) in guests.iter().enumerate() {
                let mut it = g.splitn(3, '=');
                let ifname = it.next().context("--guest must be ifname=ipv4=mac")?;
                match pin_dir.as_deref() {
                    Some(dir) => {
                        loader::attach_xdp_pinned(&mut ebpf, "guest_tx", ifname, dir, idx != 0)?
                    }
                    None => {
                        if idx == 0 {
                            loader::attach_xdp(&mut ebpf, "guest_tx", ifname)?;
                        } else {
                            loader::attach_xdp_extra(&mut ebpf, "guest_tx", ifname)?;
                        }
                    }
                }
            }
            // Load guest_dhcp and register it in GUEST_PROGS so guest_tx's DHCP tail call resolves
            // (same wiring serve's bring_up does). Without this the lab bringup path attaches
            // guest_tx but the DHCP tail call misses → XDP_PASS → no DHCP reply. Held in scope below
            // (the arm parks on ctrl_c) so the userspace map fd lives for the datapath's lifetime.
            let _guest_progs = loader::register_guest_dhcp(&mut ebpf)?;

            // Pass 2: open map wrappers (each calls take_map, consuming the map slot).
            let mut local_map = maps::LocalMap::open(&mut ebpf)?;
            local_map.set(&xdp_dp_common::Local {
                uplink_ifindex: ifindex(&uplink)?,
                uplink_mac: mac_of(&uplink)?,
                gateway_mac: parse_mac(&gateway_mac)?,
                underlay_ipv6: parse_ipv6(&local_underlay)?,
            })?;

            let gw = parse_ipv4(&gateway)?;
            let mut ports = maps::PortMetaMap::open(&mut ebpf)?;
            let mut ifaces = maps::Interfaces::open(&mut ebpf)?;
            let mut underlay_map = maps::Underlay::open(&mut ebpf)?;
            // Collect v4 guest data keyed by ifname so --guest6 can look up the v4 fields.
            // Value columns: (overlay_ipv4, guest_mac, underlay_ipv6, vni).
            type GuestV4 = ([u8; 4], [u8; 6], [u8; 16], u32);
            let mut guest_v4: std::collections::HashMap<String, GuestV4> =
                std::collections::HashMap::new();
            // --guest: "<ifname>=<overlay_ipv4>=<guest_mac>=<underlay_ipv6>=<vni>". The per-interface
            // underlay IPv6 is the interface's identity on the underlay; UNDERLAY maps it -> (vni,tap).
            for g in &guests {
                let f: Vec<&str> = g.split('=').collect();
                anyhow::ensure!(
                    f.len() == 5,
                    "--guest must be ifname=ipv4=mac=underlay_ipv6=vni, got {g:?}"
                );
                let ifname = f[0];
                let ip = parse_ipv4(f[1])?;
                let guest_mac = parse_mac(f[2])?;
                let underlay = parse_ipv6(f[3])?;
                let vni: u32 = f[4].parse().context("--guest: bad vni")?;
                let tap = ifindex(ifname)?;
                ports.upsert(
                    tap,
                    xdp_dp_common::PortMeta {
                        vni,
                        guest_ipv4: ip,
                        gateway_ipv4: gw,
                        guest_mac,
                        _pad: [0; 2],
                        underlay_ipv6: underlay,
                        gateway_ipv6: [0u8; 16],
                        guest_ipv6: [0u8; 16],
                    },
                )?;
                ifaces.upsert(
                    xdp_dp_common::IfaceKey::new(vni, ip),
                    xdp_dp_common::IfaceValue {
                        tap_ifindex: tap,
                        is_local: 1,
                        underlay_ipv6: underlay,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
                underlay_map.upsert(
                    underlay,
                    xdp_dp_common::UnderlayValue {
                        vni,
                        tap_ifindex: tap,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
                guest_v4.insert(ifname.to_string(), (ip, guest_mac, underlay, vni));
            }

            // --gateway6: overlay IPv6 gateway for ND responder (default all-zeros = disabled).
            let gw6: [u8; 16] = match &gateway6 {
                Some(s) => parse_ipv6(s)?,
                None => [0u8; 16],
            };

            // --guest6: "<ifname>=<overlay_ipv6>=<underlay_ipv6>=<vni>".
            // Re-upserts the interface's PortMeta with gateway_ipv6 set so the ND responder works.
            // Also adds a UNDERLAY entry for the v6 underlay if the interface has no --guest entry
            // (v6-only mode; for dual-stack the UNDERLAY entry is already present from --guest).
            for g6 in &guests6 {
                let f: Vec<&str> = g6.split('=').collect();
                anyhow::ensure!(
                    f.len() == 4,
                    "--guest6 must be ifname=overlay_ipv6=underlay_ipv6=vni, got {g6:?}"
                );
                let ifname = f[0];
                let overlay_ipv6 = parse_ipv6(f[1])?;
                let underlay_ipv6 = parse_ipv6(f[2])?;
                let vni: u32 = f[3].parse().context("--guest6: bad vni")?;
                let tap = ifindex(ifname)?;
                let (guest_ipv4, guest_mac, _v4_underlay, _v4_vni) = match guest_v4.get(ifname) {
                    Some(v4) => *v4,
                    None => ([0u8; 4], [0u8; 6], [0u8; 16], vni),
                };
                // Re-upsert PortMeta with gateway_ipv6 now set.
                ports.upsert(
                    tap,
                    xdp_dp_common::PortMeta {
                        vni,
                        guest_ipv4,
                        gateway_ipv4: gw,
                        guest_mac,
                        _pad: [0; 2],
                        underlay_ipv6,
                        gateway_ipv6: gw6,
                        guest_ipv6: overlay_ipv6,
                    },
                )?;
                // For v6-only interfaces (no --guest), add the UNDERLAY entry here.
                if !guest_v4.contains_key(ifname) {
                    underlay_map.upsert(
                        underlay_ipv6,
                        xdp_dp_common::UnderlayValue {
                            vni,
                            tap_ifindex: tap,
                            guest_mac,
                            _pad: [0; 2],
                        },
                    )?;
                }
                // Store the v6 overlay address in INTERFACES so ingress can deliver to this tap.
                // Re-use the IfaceKey with the overlay IPv6's first 4 bytes as a placeholder;
                // actual v6 delivery goes via UNDERLAY, so this entry is informational / for
                // future use.
                let _ = overlay_ipv6; // used above only to record intent; INTERFACES is v4-keyed
            }

            // --remote6: "<overlay_ipv6>[/len]=<nexthop_underlay_ipv6>=<vni>".
            // Programs the ROUTES6 LPM trie. The overlay IPv6 may contain ':' so we split on '='
            // and handle the optional '/len' suffix only in the first field.
            let mut routes6 = maps::Routes6::open(&mut ebpf)?;
            for r6 in &remotes6 {
                let f: Vec<&str> = r6.split('=').collect();
                anyhow::ensure!(
                    f.len() == 3,
                    "--remote6 must be overlay_ipv6[/len]=nexthop_underlay_ipv6=vni, got {r6:?}"
                );
                let (ipv6_s, plen) = match f[0].split_once('/') {
                    Some((ip, l)) => (ip, l.parse::<u32>().context("--remote6: bad prefix len")?),
                    None => (f[0], 128u32),
                };
                let ipv6 = parse_ipv6(ipv6_s)?;
                let nh = parse_ipv6(f[1])?;
                let vni: u32 = f[2].parse().context("--remote6: bad vni")?;
                routes6.upsert(
                    vni,
                    ipv6,
                    plen,
                    xdp_dp_common::RouteValue {
                        nexthop_vni: vni,
                        nexthop_ipv6: nh,
                        is_external: 0,
                        _pad: [0; 3],
                    },
                )?;
            }

            let external_set: std::collections::HashSet<[u8; 4]> = externals
                .iter()
                .map(|s| parse_ipv4(s))
                .collect::<anyhow::Result<_>>()?;
            let mut routes = maps::Routes::open(&mut ebpf)?;
            // --remote: "<overlay_ipv4>[/len]=<nexthop_underlay_ipv6>=<vni>" (nexthop = the remote
            // interface's underlay /128). An optional /prefix_len suffix enables CIDR routes;
            // bare IPs default to /32 (host route, behavior-preserving).
            for r in &remotes {
                let f: Vec<&str> = r.split('=').collect();
                anyhow::ensure!(
                    f.len() == 3,
                    "--remote must be overlay_ipv4=nexthop_underlay_ipv6=vni, got {r:?}"
                );
                let (ip_s, plen) = match f[0].split_once('/') {
                    Some((ip, l)) => (ip, l.parse::<u32>().context("--remote: bad prefix len")?),
                    None => (f[0], 32u32),
                };
                let ip = parse_ipv4(ip_s)?;
                let nh = parse_ipv6(f[1])?;
                let vni: u32 = f[2].parse().context("--remote: bad vni")?;
                routes.upsert(
                    vni,
                    ip,
                    plen,
                    xdp_dp_common::RouteValue {
                        nexthop_vni: vni,
                        nexthop_ipv6: nh,
                        is_external: external_set.contains(&ip) as u8,
                        _pad: [0; 3],
                    },
                )?;
            }

            let mut vip_map = maps::Vips::open(&mut ebpf)?;
            for v in &vips_args {
                let (g, vip) = v.split_once('=').context("--vip must be ifaceip=vipip")?;
                let g = parse_ipv4(g)?;
                let vip = parse_ipv4(vip)?;
                vip_map.upsert(xdp_dp_common::VipKey { vni: 0, ipv4: g }, vip)?; // (0,G)->V egress SNAT
                vip_map.upsert(xdp_dp_common::VipKey { vni: 0, ipv4: vip }, g)?;
                // (0,V)->G ingress DNAT
            }

            // Load balancers: each --lb allocates a Maglev table_id and an LB service entry;
            // each --lb-target appends a backend underlay /128 to the named service. After
            // collecting all backends we build + write the Maglev table for every service.
            //
            // --lb spec: "<ipv4>:<port>:<proto>:<lb_underlay_ipv6>"
            // --lb-target spec: "<ipv4>:<port>:<proto>:<lb_underlay_ipv6>=<backend_underlay_ipv6>"
            let mut lb_map = maps::Lb::open(&mut ebpf)?;
            let mut maglev_map = maps::Maglev::open(&mut ebpf)?;
            // Parse "<ipv4>:<port>:<proto>:<lb_underlay_ipv6>" -> (ip, port, proto, lb_underlay).
            let parse_lb_spec = |spec: &str| -> anyhow::Result<([u8; 4], u16, u8, [u8; 16])> {
                let mut it = spec.split(':');
                let ip = parse_ipv4(it.next().context("--lb: missing ipv4")?)?;
                let port: u16 = it.next().context("--lb: missing port")?.parse()?;
                let proto: u8 = it.next().context("--lb: missing proto")?.parse()?;
                // The remaining fields (potentially multiple ':'-separated groups in the IPv6)
                // must be reassembled because parse_ipv6 expects the full address string.
                let rest: String = it.collect::<Vec<_>>().join(":");
                let lb_underlay = parse_ipv6(rest.trim())?;
                Ok((ip, port, proto, lb_underlay))
            };
            // Key: (ip, port, proto, lb_underlay) -> table_id
            let mut table_ids: std::collections::HashMap<([u8; 4], u16, u8, [u8; 16]), u32> =
                std::collections::HashMap::new();
            let mut backends: std::collections::HashMap<u32, Vec<[u8; 16]>> =
                std::collections::HashMap::new();
            let mut next_table_id = 1u32;
            for lb in &lbs {
                let (ip, port, proto, lb_underlay) = parse_lb_spec(lb)?;
                let tid = next_table_id;
                next_table_id += 1;
                table_ids.insert((ip, port, proto, lb_underlay), tid);
                backends.insert(tid, Vec::new());
                lb_map.upsert(
                    xdp_dp_common::LbKey {
                        vni: 0,
                        ipv4: ip,
                        port,
                        proto,
                        _pad: 0,
                    },
                    xdp_dp_common::LbValue {
                        table_id: tid,
                        size: maglev::TABLE_SIZE,
                    },
                )?;
                // Program the LB's own underlay /128 so ingress recognises LB-destined packets.
                underlay_map.upsert(
                    lb_underlay,
                    xdp_dp_common::UnderlayValue {
                        vni: 0,
                        tap_ifindex: 0,
                        guest_mac: [0; 6],
                        _pad: [0; 2],
                    },
                )?;
            }
            for t in &lb_targets {
                let (spec, backend_str) = t
                    .split_once('=')
                    .context("--lb-target must be spec=backend_underlay_ipv6")?;
                let (ip, port, proto, lb_underlay) = parse_lb_spec(spec)?;
                let backend = parse_ipv6(backend_str)?;
                let tid = *table_ids
                    .get(&(ip, port, proto, lb_underlay))
                    .context("--lb-target references an unknown --lb service")?;
                backends.get_mut(&tid).unwrap().push(backend);
            }
            for (tid, bes) in &backends {
                if bes.is_empty() {
                    continue;
                }
                let table = maglev::build(bes);
                for (slot, &bi) in table.iter().enumerate() {
                    maglev_map.upsert(
                        xdp_dp_common::MaglevKey {
                            table_id: *tid,
                            slot: slot as u32,
                        },
                        bes[bi as usize],
                    )?;
                }
            }

            // NAT-GW: each --nat programs (vni, guest_ip) -> (nat_ip, port_min, port_max). Egress
            // SNAT fires when the dst route is flagged external (see --external).
            let mut nat_map = maps::Nat::open(&mut ebpf)?;
            let mut nat_ips_map = maps::NatIps::open(&mut ebpf)?;
            for n in &nats {
                let (gip_str, cfg) = n.split_once('=').context("--nat must be guestip=cfg")?;
                let gip = parse_ipv4(gip_str)?;
                let mut it = cfg.split(':');
                let nat_ip = parse_ipv4(it.next().context("--nat: missing nat ipv4")?)?;
                let port_min: u16 = it.next().context("--nat: missing port_min")?.parse()?;
                let port_max: u16 = it.next().context("--nat: missing port_max")?.parse()?;
                nat_map.upsert(
                    xdp_dp_common::NatKey { vni: 0, ipv4: gip },
                    xdp_dp_common::NatValue {
                        nat_ipv4: nat_ip,
                        port_min,
                        port_max,
                    },
                )?;
                // Mark the nat_ip so ingress demuxes NAT returns peer-independently (and answers
                // ICMP echo for it). Mirrors the gRPC create_nat path.
                let _ = nat_ips_map.set(0, nat_ip);
            }

            // Firewall: each --fw-rule programs a per-interface rule; rules are appended in order
            // to FW_RULES[(ifindex, slot)] and the per-direction counts to FW_META[ifindex].
            // Whitelist semantics live in the datapath (empty direction => accept).
            let mut fw_rules_map = maps::FwRules::open(&mut ebpf)?;
            let mut fw_meta_map = maps::FwMetaMap::open(&mut ebpf)?;
            let mut fw_config = maps::FwConfig::open(&mut ebpf)?;
            fw_config.set(if firewall_enforce { 1 } else { 0 })?;
            // ifindex -> (ingress_count, egress_count) accumulators while assigning slots.
            let mut fw_slots: std::collections::HashMap<u32, u32> =
                std::collections::HashMap::new();
            let mut fw_counts: std::collections::HashMap<u32, (u32, u32)> =
                std::collections::HashMap::new();
            let parse_cidr = |s: &str| -> anyhow::Result<([u8; 4], [u8; 4])> {
                let (ip_s, len_s) = s
                    .split_once('/')
                    .context("--fw-rule: cidr must be ip/len")?;
                let ip = parse_ipv4(ip_s)?;
                let len: u32 = len_s.parse().context("--fw-rule: bad prefix length")?;
                anyhow::ensure!(len <= 32, "--fw-rule: prefix length > 32");
                let mask = if len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - len)
                };
                Ok((ip, mask.to_be_bytes()))
            };
            for spec in &fw_rules {
                let f: Vec<&str> = spec.split(':').collect();
                anyhow::ensure!(
                    f.len() == 7,
                    "--fw-rule must be ifname:dir:action:proto:src_cidr:dst_cidr:dport, got {spec:?}"
                );
                let ifindex = ifindex(f[0])?;
                let direction = match f[1] {
                    "in" => xdp_dp_common::FW_DIR_INGRESS,
                    "eg" => xdp_dp_common::FW_DIR_EGRESS,
                    o => anyhow::bail!("--fw-rule dir must be in|eg, got {o}"),
                };
                let action = match f[2] {
                    "accept" => xdp_dp_common::FW_ACTION_ACCEPT,
                    "drop" => xdp_dp_common::FW_ACTION_DROP,
                    o => anyhow::bail!("--fw-rule action must be accept|drop, got {o}"),
                };
                let proto: u8 = match f[3] {
                    "any" => 0,
                    "icmp" => 1,
                    "tcp" => 6,
                    "udp" => 17,
                    o => anyhow::bail!("--fw-rule proto must be any|icmp|tcp|udp, got {o}"),
                };
                let (src_ip, src_mask) = parse_cidr(f[4])?;
                let (dst_ip, dst_mask) = parse_cidr(f[5])?;
                let (dst_port_min, dst_port_max) = if f[6] == "*" {
                    (0u16, 65535u16)
                } else {
                    let p: u16 = f[6].parse().context("--fw-rule: bad dport")?;
                    (p, p)
                };
                let slot = fw_slots.entry(ifindex).or_insert(0);
                anyhow::ensure!(
                    *slot < xdp_dp_common::FW_MAX_RULES,
                    "--fw-rule: more than {} rules for {}",
                    xdp_dp_common::FW_MAX_RULES,
                    f[0]
                );
                fw_rules_map.upsert(
                    xdp_dp_common::FwRuleKey {
                        ifindex,
                        idx: *slot,
                    },
                    xdp_dp_common::FwRule {
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
                    },
                )?;
                *slot += 1;
                let c = fw_counts.entry(ifindex).or_insert((0, 0));
                if direction == xdp_dp_common::FW_DIR_EGRESS {
                    c.1 += 1;
                } else {
                    c.0 += 1;
                }
            }
            for (ifindex, (ingress_count, egress_count)) in &fw_counts {
                fw_meta_map.upsert(
                    *ifindex,
                    xdp_dp_common::FwMeta {
                        ingress_count: *ingress_count,
                        egress_count: *egress_count,
                    },
                )?;
            }

            // --underlay-marker: "<ipv6>:<vni>" — program a VNI-only marker into UNDERLAY so that
            // uplink_rx can resolve a VNI for a NAT-gateway node without a local guest interface.
            // The IPv6 may contain colons so we split on the LAST ':' to extract the vni field.
            for spec in &underlay_markers {
                let pos = spec
                    .rfind(':')
                    .context("--underlay-marker must be <ipv6>:<vni>")?;
                let ipv6_s = &spec[..pos];
                let vni: u32 = spec[pos + 1..]
                    .parse()
                    .context("--underlay-marker: bad vni")?;
                let ul = parse_ipv6(ipv6_s)?;
                underlay_map.upsert(
                    ul,
                    xdp_dp_common::UnderlayValue {
                        vni,
                        tap_ifindex: 0,
                        guest_mac: [0; 6],
                        _pad: [0; 2],
                    },
                )?;
            }

            // --neigh-nat: "<nat_ip>:<port_min>:<port_max>@<owner_underlay_ipv6>@<vni>"
            // We split on '@' to avoid colon-ambiguity with the IPv6 in the middle segment.
            let mut neigh_nat_map = maps::NeighborNat::open(&mut ebpf)?;
            let mut neigh_nat_count_map = maps::NeighborNatCount::open(&mut ebpf)?;
            let mut neigh_nat_idx: u32 = 0;
            for spec in &neigh_nats {
                anyhow::ensure!(
                    neigh_nat_idx < xdp_dp_common::NB_MAX_ENTRIES,
                    "--neigh-nat: too many entries (max {})",
                    xdp_dp_common::NB_MAX_ENTRIES
                );
                let parts: Vec<&str> = spec.splitn(3, '@').collect();
                anyhow::ensure!(
                    parts.len() == 3,
                    "--neigh-nat must be <nat_ip>:<port_min>:<port_max>@<underlay_ipv6>@<vni>, got {spec:?}"
                );
                let head = parts[0];
                let underlay_s = parts[1];
                let vni: u32 = parts[2].parse().context("--neigh-nat: bad vni")?;
                let underlay = parse_ipv6(underlay_s)?;
                let mut it = head.split(':');
                let nat_ip = parse_ipv4(it.next().context("--neigh-nat: missing nat_ip")?)?;
                let port_min: u16 = it
                    .next()
                    .context("--neigh-nat: missing port_min")?
                    .parse()?;
                let port_max: u16 = it
                    .next()
                    .context("--neigh-nat: missing port_max")?
                    .parse()?;
                neigh_nat_map.upsert(
                    neigh_nat_idx,
                    xdp_dp_common::NeighborNatEntry {
                        underlay,
                        nat_ip,
                        vni,
                        port_min,
                        port_max,
                        enabled: 1,
                        _pad: [0; 3],
                    },
                )?;
                neigh_nat_idx += 1;
            }
            neigh_nat_count_map.set(neigh_nat_idx)?;

            // --meter: "<ifname>=<total_mbps>:<public_mbps>" — program per-interface egress
            // token-bucket rate caps. Opt-in: interfaces without an entry are unlimited.
            let mut meter_map = maps::Meter::open(&mut ebpf)?;
            let mbps_to_bps = |mbps: u64| mbps.saturating_mul(1_000_000) / 8;
            for spec in &meters {
                let (ifname, rates) = spec
                    .split_once('=')
                    .context("--meter must be <ifname>=<total_mbps>:<public_mbps>")?;
                let (total_s, public_s) = rates
                    .split_once(':')
                    .context("--meter rates must be <total_mbps>:<public_mbps>")?;
                let total_mbps: u64 = total_s.parse().context("--meter: bad total_mbps")?;
                let public_mbps: u64 = public_s.parse().context("--meter: bad public_mbps")?;
                let tap = ifindex(ifname)?;
                let tb = mbps_to_bps(total_mbps);
                let pb = mbps_to_bps(public_mbps);
                meter_map.upsert(
                    tap,
                    xdp_dp_common::MeterState {
                        total_bps: tb,
                        total_burst: (tb / 8).max(2000),
                        total_tokens: tb / 8,
                        total_last_ns: 0,
                        public_bps: pb,
                        public_burst: (pb / 8).max(2000),
                        public_tokens: pb / 8,
                        public_last_ns: 0,
                    },
                )?;
            }

            // DHCP_CONFIG: program server-wide DHCP options (MTU + DNS servers).
            {
                let mut dhcp_config_map = maps::DhcpConfigMap::open(&mut ebpf)?;
                let dns4: Vec<[u8; 4]> = dhcp_dns
                    .iter()
                    .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets()))
                    .collect();
                let dns6: Vec<[u8; 16]> = dhcpv6_dns
                    .iter()
                    .filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok().map(|a| a.octets()))
                    .collect();
                let mtu = dhcp_mtu.unwrap_or(1500) as u16;
                let dns4_len = dns4.len().min(xdp_dp_common::DHCP_MAX_DNS) as u8;
                let dns6_len = dns6.len().min(xdp_dp_common::DHCP_MAX_DNS) as u8;
                let mut cfg = xdp_dp_common::DhcpConfig {
                    mtu,
                    dns4_len,
                    dns6_len,
                    dns4: [[0; 4]; xdp_dp_common::DHCP_MAX_DNS],
                    dns6: [[0; 16]; xdp_dp_common::DHCP_MAX_DNS],
                };
                for (i, a) in dns4.iter().take(xdp_dp_common::DHCP_MAX_DNS).enumerate() {
                    cfg.dns4[i] = *a;
                }
                for (i, a) in dns6.iter().take(xdp_dp_common::DHCP_MAX_DNS).enumerate() {
                    cfg.dns6[i] = *a;
                }
                dhcp_config_map.set(&cfg)?;
            }

            // Pin CONNTRACK BEFORE take_map (Conntrack::open) — take_map removes the map from
            // the Ebpf object's collection, so map_mut("CONNTRACK") would return None afterward.
            if let Some(dir) = pin_dir.as_deref() {
                loader::pin_map(&mut ebpf, "CONNTRACK", dir)?;
            }
            let ct = maps::Conntrack::open(&mut ebpf)?;
            tokio::spawn(conntrack_gc::run(
                std::sync::Arc::new(std::sync::Mutex::new(ct)),
                std::time::Duration::from_secs(10),
            ));

            println!(
                "bringup: uplink={uplink} guests={} guests6={} routes={} routes6={} vips={} lbs={} nats={} fw={} neigh_nats={} meters={}; ctrl-c to stop",
                guests.len(),
                guests6.len(),
                remotes.len(),
                remotes6.len(),
                vips_args.len(),
                lbs.len(),
                nats.len(),
                fw_rules.len(),
                neigh_nats.len(),
                meters.len()
            );
            tokio::signal::ctrl_c().await?;
        }
        Cmd::TcBringup {
            tap,
            guest_ipv4,
            gateway_ipv4,
            gateway6,
            guest_mac,
            gateway_mac,
            dhcp_mtu,
            dhcp_dns,
            uplink,
            local_underlay,
            guest_underlay,
            remotes,
            guest6,
            remotes6,
        } => {
            let mut ebpf = loader::load_ebpf()?;
            loader::maybe_install_logger(&mut ebpf);
            let tap_ifindex = ifindex(&tap)?;
            let guest_mac = parse_mac(&guest_mac)?;
            let guest_underlay = parse_ipv6(&guest_underlay)?;
            let guest_ipv6 = match &guest6 {
                Some(s) => parse_ipv6(s)?,
                None => [0u8; 16],
            };
            // Load (verify) + attach the tc programs BEFORE opening any map: the map `open()`
            // helpers `take_map()` the map out of the loader, after which a later `prog.load()`
            // can no longer bind the maps the program references ("fd N is not pointing to valid
            // bpf_map"). This mirrors the XDP `Serve` ordering (attach/register, then open maps).
            loader::attach_tc_clsact_ingress(&mut ebpf, "tc_guest_tx", &tap)?;
            let _gpt = loader::register_guest_dhcp_tc(&mut ebpf)?; // hold in scope for the datapath lifetime
            let mut ports = maps::PortMetaMap::open(&mut ebpf)?;
            ports.upsert(
                tap_ifindex,
                xdp_dp_common::PortMeta {
                    vni: 100,
                    guest_ipv4: parse_ipv4(&guest_ipv4)?,
                    gateway_ipv4: parse_ipv4(&gateway_ipv4)?,
                    guest_mac,
                    _pad: [0; 2],
                    underlay_ipv6: guest_underlay,
                    gateway_ipv6: parse_ipv6(&gateway6)?,
                    guest_ipv6,
                },
            )?;
            // Egress encap wiring (optional): program LOCAL (uplink identity) so forward_decision_v4
            // can build outer frames, a ROUTES entry per --remote, and the guest's own UNDERLAY /128
            // (so the local fast-path can find same-host peers).
            if let Some(uplink) = &uplink {
                let mut local_map = maps::LocalMap::open(&mut ebpf)?;
                local_map.set(&xdp_dp_common::Local {
                    uplink_ifindex: ifindex(uplink)?,
                    uplink_mac: mac_of(uplink)?,
                    gateway_mac: parse_mac(&gateway_mac)?,
                    underlay_ipv6: parse_ipv6(&local_underlay)?,
                })?;
            }
            {
                let mut underlay_map = maps::Underlay::open(&mut ebpf)?;
                underlay_map.upsert(
                    guest_underlay,
                    xdp_dp_common::UnderlayValue {
                        vni: 100,
                        tap_ifindex,
                        guest_mac,
                        _pad: [0; 2],
                    },
                )?;
            }
            {
                let mut routes = maps::Routes::open(&mut ebpf)?;
                // --remote: "<overlay_ipv4>=<nexthop_underlay_ipv6>=<vni>".
                for r in &remotes {
                    let f: Vec<&str> = r.split('=').collect();
                    anyhow::ensure!(
                        f.len() == 3,
                        "--remote must be overlay_ipv4=nexthop_underlay_ipv6=vni, got {r:?}"
                    );
                    let ip = parse_ipv4(f[0])?;
                    let nh = parse_ipv6(f[1])?;
                    let vni: u32 = f[2].parse().context("--remote: bad vni")?;
                    routes.upsert(
                        vni,
                        ip,
                        32,
                        xdp_dp_common::RouteValue {
                            nexthop_vni: vni,
                            nexthop_ipv6: nh,
                            is_external: 0,
                            _pad: [0; 3],
                        },
                    )?;
                }
            }
            {
                // --remote6: "<overlay_ipv6>[/len]=<nexthop_underlay_ipv6>=<vni>".
                // Copies the map-wrapper calls from Cmd::Bringup's --remote6 handling.
                let mut routes6 = maps::Routes6::open(&mut ebpf)?;
                for r6 in &remotes6 {
                    let f: Vec<&str> = r6.split('=').collect();
                    anyhow::ensure!(
                        f.len() == 3,
                        "--remote6 must be overlay_ipv6[/len]=nexthop_underlay_ipv6=vni, got {r6:?}"
                    );
                    let (ipv6_s, plen) = match f[0].split_once('/') {
                        Some((ip, l)) => {
                            (ip, l.parse::<u32>().context("--remote6: bad prefix len")?)
                        }
                        None => (f[0], 128u32),
                    };
                    let ipv6 = parse_ipv6(ipv6_s)?;
                    let nh = parse_ipv6(f[1])?;
                    let vni: u32 = f[2].parse().context("--remote6: bad vni")?;
                    routes6.upsert(
                        vni,
                        ipv6,
                        plen,
                        xdp_dp_common::RouteValue {
                            nexthop_vni: vni,
                            nexthop_ipv6: nh,
                            is_external: 0,
                            _pad: [0; 3],
                        },
                    )?;
                }
            }
            {
                let mut dhcp_config_map = maps::DhcpConfigMap::open(&mut ebpf)?;
                let dns4: Vec<[u8; 4]> = dhcp_dns
                    .iter()
                    .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets()))
                    .collect();
                let dns4_len = dns4.len().min(xdp_dp_common::DHCP_MAX_DNS) as u8;
                let mut cfg = xdp_dp_common::DhcpConfig {
                    mtu: dhcp_mtu as u16,
                    dns4_len,
                    dns6_len: 0,
                    dns4: [[0; 4]; xdp_dp_common::DHCP_MAX_DNS],
                    dns6: [[0; 16]; xdp_dp_common::DHCP_MAX_DNS],
                };
                for (i, a) in dns4.iter().take(xdp_dp_common::DHCP_MAX_DNS).enumerate() {
                    cfg.dns4[i] = *a;
                }
                dhcp_config_map.set(&cfg)?;
            }
            println!("tc-bringup: tc_guest_tx on {tap} (ifindex {tap_ifindex}); ctrl-c to stop");
            let _ = &gateway_mac; // consumed by the encap LOCAL branch when --uplink is set
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Pass { iface } => {
            let mut ebpf = loader::load_ebpf()?;
            loader::attach_xdp(&mut ebpf, "xdp_pass", &iface)?;
            println!("attached xdp_pass to {iface}; ctrl-c to detach");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Inspect { iface } => {
            let mut ebpf = loader::load_ebpf()?;

            // Try native (driver) mode first; fall back to SKB (generic) mode if rejected.
            let prog: &mut aya::programs::Xdp = ebpf
                .program_mut("xdp_inspect")
                .context("xdp_inspect program missing")?
                .try_into()?;
            prog.load().context("verify xdp_inspect")?;
            let mode = match prog.attach(&iface, aya::programs::XdpFlags::default()) {
                Ok(_) => "native/driver",
                Err(native_err) => {
                    eprintln!("native attach failed ({native_err}), retrying with SKB_MODE");
                    prog.attach(&iface, aya::programs::XdpFlags::SKB_MODE)
                        .with_context(|| format!("attach xdp_inspect to {iface} (SKB_MODE)"))?;
                    "SKB/generic"
                }
            };
            println!("xdp_inspect attached to {iface} in {mode} mode");

            let inspect = maps::InspectMap::open(&mut ebpf)?;

            let mut prev_seen = 0u32;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                        match inspect.get() {
                            Ok(e) => {
                                if e.seen != prev_seen {
                                    prev_seen = e.seen;
                                    let hex: String = e.bytes.iter()
                                        .map(|b| format!("{b:02x}"))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    // Probe multiple offsets for the ethertype-like u16.
                                    let et12 = u16::from_be_bytes([e.bytes[12], e.bytes[13]]);
                                    let et10 = u16::from_be_bytes([e.bytes[10], e.bytes[11]]);
                                    let et14 = u16::from_be_bytes([e.bytes[14], e.bytes[15]]);
                                    let et22 = u16::from_be_bytes([e.bytes[22], e.bytes[23]]);
                                    println!(
                                        "seen={} len={} bytes=[{hex}] \
                                         et@10={et10:#06x} et@12={et12:#06x} et@14={et14:#06x} et@22={et22:#06x}",
                                        e.seen, e.len,
                                    );
                                }
                            }
                            Err(e) => eprintln!("inspect read error: {e}"),
                        }
                    }
                }
            }
            println!("detaching");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests (no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_valid() {
        assert_eq!(parse_mac("02:00:00:00:00:01").unwrap(), [2, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn parse_mac_rejects_bad_octet() {
        assert!(parse_mac("zz:00:00:00:00:01").is_err());
    }

    #[test]
    fn parse_mac_rejects_too_short() {
        assert!(parse_mac("02:00:00:00:00").is_err());
    }

    #[test]
    fn parse_mac_rejects_too_long() {
        assert!(parse_mac("02:00:00:00:00:01:ff").is_err());
    }

    #[test]
    fn parse_ipv4_basic() {
        assert_eq!(parse_ipv4("10.0.0.5").unwrap(), [10, 0, 0, 5]);
    }

    #[test]
    fn parse_ipv4_rejects_garbage() {
        assert!(parse_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn parse_ipv6_last_byte() {
        let octets = parse_ipv6("fd00::1").unwrap();
        assert_eq!(octets[15], 1);
    }

    #[test]
    fn parse_ipv6_rejects_garbage() {
        assert!(parse_ipv6("not-an-ip").is_err());
    }
}
