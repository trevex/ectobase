//! `flowplane bringup`: bring up the map-driven datapath — attach programs, program all maps,
//! then idle. Debug/lab command (see the notes in `run` on how it differs from `serve`).
use anyhow::Context;

use crate::parse::{parse_ipv4, parse_ipv6, parse_mac};
use crate::{conntrack_gc, control, ifindex, loader, mac_of, maps, ENCAP_OVERHEAD_V6};

/// Firewall rule direction (the `dir` field of a `--fw-rule` spec). `.code()` yields the `u8` the
/// datapath's `FwRule.direction` expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Direction {
    #[value(name = "in")]
    Ingress,
    #[value(name = "eg")]
    Egress,
}

impl Direction {
    fn code(self) -> u8 {
        match self {
            Direction::Ingress => flowplane_common::FW_DIR_INGRESS,
            Direction::Egress => flowplane_common::FW_DIR_EGRESS,
        }
    }
}

/// Firewall rule action (the `action` field of a `--fw-rule` spec). `.code()` yields the `u8` the
/// datapath's `FwRule.action` expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum FwAction {
    Accept,
    Drop,
}

impl FwAction {
    fn code(self) -> u8 {
        match self {
            FwAction::Accept => flowplane_common::FW_ACTION_ACCEPT,
            FwAction::Drop => flowplane_common::FW_ACTION_DROP,
        }
    }
}

/// Firewall rule L4 protocol (the `proto` field of a `--fw-rule` spec). `.code()` yields the IP
/// protocol number the datapath's `FwRule.proto` expects (0 = any/wildcard).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum FwProto {
    Any,
    Icmp,
    Tcp,
    Udp,
}

impl FwProto {
    fn code(self) -> u8 {
        match self {
            FwProto::Any => 0,
            FwProto::Icmp => 1,
            FwProto::Tcp => 6,
            FwProto::Udp => 17,
        }
    }
}

#[derive(clap::Args)]
pub struct BringupArgs {
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
    /// /128 is the interface's identity on the underlay (UNDERLAY map key); tc_guest_tx attaches
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
    /// Override the CONNTRACK map capacity (entries). Also settable via FLOWPLANE_CONNTRACK_MAX.
    #[arg(long)]
    conntrack_max: Option<u32>,
    /// Firewall rule, repeatable:
    /// "<ifname>:<in|eg>:<accept|drop>:<any|icmp|tcp|udp>:<src_cidr>:<dst_cidr>:<dport|*>".
    #[arg(long = "fw-rule")]
    fw_rules: Vec<String>,
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
    /// Programs the ROUTES6 LPM trie so tc_guest_tx can forward overlay IPv6 packets.
    #[arg(long = "remote6")]
    remotes6: Vec<String>,
    /// DHCP MTU option (server-wide). Defaults to 1500 - ENCAP_OVERHEAD_V6 (1420) if unset.
    #[arg(long = "dhcp-mtu")]
    dhcp_mtu: Option<u32>,
    /// DHCPv4 DNS server, repeatable (server-wide).
    #[arg(long = "dhcp-dns")]
    dhcp_dns: Vec<String>,
    /// DHCPv6 DNS server, repeatable (server-wide).
    #[arg(long = "dhcpv6-dns")]
    dhcpv6_dns: Vec<String>,
}

pub async fn run(args: BringupArgs) -> anyhow::Result<()> {
    let BringupArgs {
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
    } = args;
    // HA adopt path: re-open the pinned CONNTRACK and resume GC; no load/attach.
    if adopt {
        let dir = pin_dir.as_deref().context("--adopt requires --pin-dir")?;
        let ct = maps::Conntrack::from_pin(&format!("{dir}/CONNTRACK"))?;
        tokio::spawn(conntrack_gc::run(
            std::sync::Arc::new(parking_lot::Mutex::new(ct)),
            std::time::Duration::from_secs(10),
        ));
        println!("adopted pinned datapath at {dir}; resuming conntrack GC; ctrl-c to stop");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    if let Some(n) = conntrack_max {
        // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
        std::env::set_var("FLOWPLANE_CONNTRACK_MAX", n.to_string());
    }
    // A `--pin-dir` bringup reuses/creates its pinned state maps there; without one, a fresh
    // ephemeral dir keeps the `pinned` maps satisfiable while behaving like a throwaway load.
    let map_pin_dir = match pin_dir.as_deref() {
        Some(d) => std::path::PathBuf::from(d),
        None => loader::ephemeral_pin_dir()?,
    };
    let mut ebpf = loader::load_ebpf(&map_pin_dir)?;
    loader::maybe_install_logger(&mut ebpf);

    // Pass 1: attach ALL tc programs while ebpf is still fully intact
    // (take_map consumes map entries, but programs are separate — still need &mut ebpf).
    // uplink_rx: load + attach once. NOTE: this debug/lab command (unlike `Serve`, which goes
    // through `control::Control::bring_up`) does NOT bring up the geneve `collect_md` device
    // and attaches `uplink_rx` directly to `--uplink` instead — so it only sees already-
    // decapped frames if something else decapped them first; it predates the P2 Geneve pivot
    // and was mechanically kept compiling (XDP -> tcx), not made geneve-aware.
    match pin_dir.as_deref() {
        Some(dir) => loader::attach_tc_pinned_at(
            &mut ebpf,
            "uplink_rx",
            &uplink,
            std::path::Path::new(dir),
            &format!("uplink_rx-{uplink}"),
        )?,
        None => loader::attach_tc_clsact_ingress(&mut ebpf, "uplink_rx", &uplink)?,
    }
    // Register the inner-v6 ingress tail-call target (xdp_uplink_v6, now tc) in UPLINK_PROGS
    // so uplink_rx's inner-v6 tail-call resolves. Loaded but NOT attached (tail-call only).
    // Held in scope so the userspace map fd lives for the datapath lifetime.
    let _uplink_progs = loader::register_uplink_v6_tc(&mut ebpf)?;
    loader::ensure_fq_qdisc(&uplink);
    // tc_guest_tx: pre-load once, then attach via clsact ingress for each guest.
    // Register GUEST_PROGS_TC (tc_guest_dhcp + tc_guest_nat64 tail calls) first, then
    // pre-load tc_guest_tx. Held in scope so the userspace map fd lives for the lifetime.
    let _guest_progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
    loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
    // Attach the (pre-loaded) program to EACH guest device via the load-free link variant
    // (self-loading `attach_tc_clsact_ingress` would re-load and collide — "already loaded" —
    // on the 2nd guest). Hold the links for the process lifetime; dropping one detaches.
    let mut _guest_tc_links = Vec::new();
    for g in guests.iter() {
        let mut it = g.splitn(3, '=');
        let ifname = it.next().context("--guest must be ifname=ipv4=mac")?;
        _guest_tc_links.push(loader::attach_tc_clsact_ingress_link(
            &mut ebpf,
            "tc_guest_tx",
            ifname,
        )?);
    }

    // Pass 2: open map wrappers (each calls take_map, consuming the map slot).
    let mut local_map = maps::LocalMap::open(&mut ebpf)?;
    local_map.set(&flowplane_common::Local {
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
    let mut guest_v4: std::collections::HashMap<String, GuestV4> = std::collections::HashMap::new();
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
            flowplane_common::PortMeta {
                vni,
                guest_ipv4: ip,
                gateway_ipv4: gw,
                guest_mac,
                l3: 0,
                offloaded: 0,
                underlay_ipv6: underlay,
                gateway_ipv6: [0u8; 16],
                guest_ipv6: [0u8; 16],
            },
        )?;
        ifaces.upsert(
            flowplane_common::IfaceKey::new(vni, ip),
            flowplane_common::IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6: underlay,
                guest_mac,
                // Debug CLI on an arbitrary named device: keep plain bpf_redirect (always
                // correct for veth/netkit/tap). The production attach path derives this from
                // the DeviceType.
                peer_capable: 0,
                _pad: [0; 1],
            },
        )?;
        underlay_map.upsert(
            underlay,
            flowplane_common::UnderlayValue {
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
            flowplane_common::PortMeta {
                vni,
                guest_ipv4,
                gateway_ipv4: gw,
                guest_mac,
                l3: 0,
                offloaded: 0,
                underlay_ipv6,
                gateway_ipv6: gw6,
                guest_ipv6: overlay_ipv6,
            },
        )?;
        // For v6-only interfaces (no --guest), add the UNDERLAY entry here.
        if !guest_v4.contains_key(ifname) {
            underlay_map.upsert(
                underlay_ipv6,
                flowplane_common::UnderlayValue {
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
            flowplane_common::RouteValue {
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
            flowplane_common::RouteValue {
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
        vip_map.upsert(flowplane_common::VipKey { vni: 0, ipv4: g }, vip)?; // (0,G)->V egress SNAT
        vip_map.upsert(flowplane_common::VipKey { vni: 0, ipv4: vip }, g)?;
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
    let mut backends: std::collections::HashMap<u32, Vec<flowplane_common::LbBackend>> =
        std::collections::HashMap::new();
    let mut next_table_id = 1u32;
    for lb in &lbs {
        let (ip, port, proto, lb_underlay) = parse_lb_spec(lb)?;
        let tid = next_table_id;
        next_table_id += 1;
        table_ids.insert((ip, port, proto, lb_underlay), tid);
        backends.insert(tid, Vec::new());
        lb_map.upsert(
            flowplane_common::LbKey {
                vni: 0,
                ipv4: ip,
                port,
                proto,
                _pad: 0,
            },
            flowplane_common::LbValue {
                table_id: tid,
                size: flowplane_control::maglev::TABLE_SIZE,
            },
        )?;
        // Program the LB's own underlay /128 so ingress recognises LB-destined packets.
        underlay_map.upsert(
            lb_underlay,
            flowplane_common::UnderlayValue {
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
        // The --lb-target CLI only carries the backend node underlay (sufficient for the
        // edge/reforward path, vni=0 WAN edge with remote backends reached by node_vtep);
        // overlay-IP/VNI-based LOCAL delivery is driven by the gRPC AddLbBackend path, not
        // this CLI, so overlay_ip/vni/is_v6 are left zeroed.
        backends
            .entry(tid)
            .or_default()
            .push(flowplane_common::LbBackend {
                node_vtep: backend,
                ..Default::default()
            });
    }
    for (tid, bes) in &backends {
        if bes.is_empty() {
            continue;
        }
        let table = flowplane_control::maglev::build(bes);
        for (slot, &bi) in table.iter().enumerate() {
            maglev_map.upsert(
                flowplane_common::MaglevKey {
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
            flowplane_common::NatKey { vni: 0, ipv4: gip },
            flowplane_common::NatValue {
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
    // Deny-by-default: the datapath always drops on no-match; the control plane materializes
    // k8s default-allow as explicit allow-all rules for unpolicied directions (Compile()).
    let mut fw_rules_map = maps::FwRules::open(&mut ebpf)?;
    let mut fw_meta_map = maps::FwMetaMap::open(&mut ebpf)?;
    // ifindex -> (ingress_count, egress_count) accumulators while assigning slots.
    let mut fw_slots: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
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
        // Parse the enum sub-fields via clap's ValueEnum (same variant spellings the type
        // documents) so the CLI vocabulary lives in one place; `.code()` maps to the u8 the
        // datapath map fields expect.
        use clap::ValueEnum;
        let direction = Direction::from_str(f[1], false)
            .map_err(|e| anyhow::anyhow!("--fw-rule dir must be in|eg, got {:?}: {e}", f[1]))?
            .code();
        let action = FwAction::from_str(f[2], false)
            .map_err(|e| {
                anyhow::anyhow!("--fw-rule action must be accept|drop, got {:?}: {e}", f[2])
            })?
            .code();
        let proto: u8 = FwProto::from_str(f[3], false)
            .map_err(|e| {
                anyhow::anyhow!(
                    "--fw-rule proto must be any|icmp|tcp|udp, got {:?}: {e}",
                    f[3]
                )
            })?
            .code();
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
            *slot < flowplane_common::FW_MAX_RULES,
            "--fw-rule: more than {} rules for {}",
            flowplane_common::FW_MAX_RULES,
            f[0]
        );
        fw_rules_map.upsert(
            flowplane_common::FwRuleKey {
                ifindex,
                idx: *slot,
            },
            flowplane_common::FwRule {
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
        if direction == flowplane_common::FW_DIR_EGRESS {
            c.1 += 1;
        } else {
            c.0 += 1;
        }
    }
    for (ifindex, (ingress_count, egress_count)) in &fw_counts {
        fw_meta_map.upsert(
            *ifindex,
            flowplane_common::FwMeta {
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
            flowplane_common::UnderlayValue {
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
            neigh_nat_idx < flowplane_common::NB_MAX_ENTRIES,
            "--neigh-nat: too many entries (max {})",
            flowplane_common::NB_MAX_ENTRIES
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
            flowplane_common::NeighborNatEntry {
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
        // Single-source the mbps→bps + burst derivation with the per-interface program
        // path and the ConfigureQoS RPC.
        meter_map.upsert(
            tap,
            control::Control::meter_state(total_mbps, public_mbps, 0),
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
        let mtu = dhcp_mtu.unwrap_or(1500 - ENCAP_OVERHEAD_V6) as u16;
        let dns4_len = dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8;
        let dns6_len = dns6.len().min(flowplane_common::DHCP_MAX_DNS) as u8;
        let mut cfg = flowplane_common::DhcpConfig {
            mtu,
            dns4_len,
            dns6_len,
            dns4: [[0; 4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns4[i] = *a;
        }
        for (i, a) in dns6.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
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
        std::sync::Arc::new(parking_lot::Mutex::new(ct)),
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
    Ok(())
}
