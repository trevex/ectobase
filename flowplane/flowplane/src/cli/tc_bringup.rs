//! `flowplane tc-bringup`: minimal tc guest-edge bringup for the Phase-1 DHCP gate — attach
//! tc_guest_tx to one tap's clsact ingress, program PORT_META + DHCP config for it, then idle.
use anyhow::Context;

use crate::parse::{parse_ipv4, parse_ipv6, parse_mac};
use crate::{ifindex, loader, mac_of, maps, ENCAP_OVERHEAD_V6};

#[derive(clap::Args)]
pub struct TcBringupArgs {
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
    /// DHCP MTU option. Defaults to 1500 - ENCAP_OVERHEAD_V6 (1420).
    #[arg(long, default_value_t = 1500 - ENCAP_OVERHEAD_V6)]
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
}

pub async fn run(args: TcBringupArgs) -> anyhow::Result<()> {
    let TcBringupArgs {
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
    } = args;
    let mut ebpf = loader::load_ebpf(&loader::ephemeral_pin_dir()?)?;
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
        flowplane_common::PortMeta {
            vni: 100,
            guest_ipv4: parse_ipv4(&guest_ipv4)?,
            gateway_ipv4: parse_ipv4(&gateway_ipv4)?,
            guest_mac,
            l3: 0,
            offloaded: 0,
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
        local_map.set(&flowplane_common::Local {
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
            flowplane_common::UnderlayValue {
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
                flowplane_common::RouteValue {
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
                flowplane_common::RouteValue {
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
        let dns4_len = dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8;
        let mut cfg = flowplane_common::DhcpConfig {
            mtu: dhcp_mtu as u16,
            dns4_len,
            dns6_len: 0,
            dns4: [[0; 4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns4[i] = *a;
        }
        dhcp_config_map.set(&cfg)?;
    }
    println!("tc-bringup: tc_guest_tx on {tap} (ifindex {tap_ifindex}); ctrl-c to stop");
    let _ = &gateway_mac; // consumed by the encap LOCAL branch when --uplink is set
    tokio::signal::ctrl_c().await?;
    Ok(())
}
