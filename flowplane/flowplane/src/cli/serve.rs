//! `flowplane serve`: start the gRPC control-plane server with a live datapath.
use anyhow::Context;
use ipnet::Ipv6Net;

use crate::parse::{parse_ipv4, parse_ipv6, parse_mac};
use crate::{attach, conntrack_gc, control, ifindex, mac_of, node, ENCAP_OVERHEAD_V6};

/// Node role for `serve`: `node` (a hypervisor) or `edge` (a WAN edge sidecar).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Role {
    Node,
    Edge,
}

#[derive(clap::Args)]
pub struct ServeArgs {
    /// Address to listen on (e.g. 127.0.0.1:1337).
    #[arg(long)]
    addr: String,
    /// Uplink interface (egress/EDT-shaping target; `uplink_rx` itself attaches to the geneve
    /// `collect_md` device, not directly here — see `control::Control::bring_up`).
    #[arg(long)]
    uplink: String,
    /// Node role: "node" (default, a hypervisor) or "edge" (a WAN edge sidecar sharing VyOS's
    /// netns — additionally attaches wan_rx and registers a local-deliver edge underlay).
    #[arg(long, value_enum, default_value = "node")]
    role: Role,
    /// WAN-facing uplink interface (edge role only; wan_rx attaches here). Required for
    /// `--role edge`.
    #[arg(long = "wan-uplink")]
    wan_uplink: Option<String>,
    /// Additional fabric uplink(s) to also attach `uplink_rx` on (repeatable). NOTE: under the
    /// geneve `collect_md` model a single virtual device demuxes decap regardless of which
    /// physical NIC the encapped packet arrived on, so `uplink_rx` (attached once, to the geneve
    /// device) already covers every fabric uplink; attaching it directly here as well is now a
    /// no-op (see `Control::attach_extra_uplink`'s doc comment).
    #[arg(long = "extra-uplink")]
    extra_uplink: Vec<String>,
    /// This hypervisor's underlay IPv6 (outer src on encap; also the /64 the AttachInterface
    /// pool allocates from). Optional: when unset, resolved from the kubelet node IP
    /// (`HOST_IP`/`NODE_IP` downward-API env) or inferred from the host's lo/dummy* fabric
    /// loopback. Set explicitly for tests / hosts without a fabric loopback.
    #[arg(long = "local-underlay")]
    local_underlay: Option<String>,
    /// Expected node-underlay aggregate (CIDR, e.g. `fd00:cafe::/32`). When set, the underlay
    /// address is the host address inside this prefix — the authoritative cluster-wide filter
    /// that ignores unrelated global addresses (mgmt `status.hostIP`, a Talos hostDNS `lo` ULA,
    /// CNI veth /128s). Takes precedence over HOST_IP + interface inference; `--local-underlay`
    /// still overrides it.
    #[arg(long = "underlay-within")]
    underlay_within: Option<String>,
    /// Underlay next-hop MAC — outer eth dst for ALL encapped traffic.
    #[arg(long)]
    gateway_mac: String,
    /// Override the CONNTRACK map capacity (entries). Also settable via FLOWPLANE_CONNTRACK_MAX.
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
    /// Pin program links to bpffs so a restart keeps the datapath attached (zero forwarding gap).
    /// Disable for a guaranteed fresh re-attach on every start.
    #[arg(long = "pin-links", default_value_t = true, action = clap::ArgAction::Set, env = "FLOWPLANE_PIN_LINKS")]
    pin_links: bool,
    /// Guest MTU override. Unset = auto-derive from the smallest uplink MTU minus the Geneve
    /// encap overhead (outer IPv6 + UDP + Geneve = 56). One node-wide value drives the veth link
    /// MTU, the pod route MTU (returned to the CNI), DHCPv4 opt-26, and the IPv6 RA MTU option.
    #[arg(long = "guest-mtu")]
    guest_mtu: Option<u32>,
    /// Deprecated alias for --guest-mtu (was: server-wide DHCP opt-26). Superseded because the
    /// same value now also drives the link/route MTU and the RA option, not just DHCP.
    #[arg(long = "dhcp-mtu")]
    dhcp_mtu: Option<u32>,
    #[arg(long = "dhcp-dns")]
    dhcp_dns: Vec<String>,
    #[arg(long = "dhcpv6-dns")]
    dhcpv6_dns: Vec<String>,
    /// Enable the E/W hardware flow-offload manager: reconcile established East/West overlay
    /// flows onto offload-capable representors as tc-flower (Geneve encap + mirred) filters.
    /// Default OFF — no manager task is spawned, zero datapath change.
    #[arg(long)]
    offload: bool,
}

pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    let ServeArgs {
        addr,
        uplink,
        role,
        wan_uplink,
        extra_uplink,
        local_underlay,
        underlay_within,
        gateway,
        gateway6,
        gateway_mac,
        conntrack_max,
        pin_dir,
        pin_links,
        guest_mtu,
        dhcp_mtu,
        dhcp_dns,
        dhcpv6_dns,
        offload,
    } = args;
    if let Some(n) = conntrack_max {
        // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
        std::env::set_var("FLOWPLANE_CONNTRACK_MAX", n.to_string());
    }
    let within = underlay_within
        .as_deref()
        .map(|s| s.parse::<Ipv6Net>())
        .transpose()
        .context("parse --underlay-within")?;
    let underlay = resolve_underlay_ipv6(local_underlay.as_deref(), within)?;
    let gateway_ipv4 = parse_ipv4(&gateway)?;
    let gateway_ipv6 = match &gateway6 {
        Some(s) => parse_ipv6(s)?,
        None => [0u8; 16],
    };
    // Graceful restart: pin the state maps under a persistent bpffs dir (default overridable
    // by --pin-dir). `adopt` = that dir already holds our pins from a previous run, so the
    // reloaded programs re-bind to the surviving maps and we rebuild in-memory state instead
    // of starting fresh. Detected by the presence of a marker pin (INTERFACES).
    let serve_pin_dir = pin_dir.unwrap_or_else(|| "/sys/fs/bpf/flowplane".to_string());
    std::fs::create_dir_all(&serve_pin_dir)
        .with_context(|| format!("create pin dir {serve_pin_dir}"))?;
    let serve_pin_dir = std::path::PathBuf::from(serve_pin_dir);
    let adopt = serve_pin_dir.join("INTERFACES").exists();
    if adopt {
        println!(
            "adopt: found pinned datapath at {} — recovering state",
            serve_pin_dir.display()
        );
    }
    let ctrl = control::Control::bring_up(
        &uplink,
        ifindex(&uplink)?,
        mac_of(&uplink)?,
        parse_mac(&gateway_mac)?,
        underlay,
        &serve_pin_dir,
        adopt,
        pin_links,
    )?;
    // WAN-edge role: attach wan_rx to the WAN uplink + register the local-deliver edge
    // underlay so this sidecar handles both egress decap and NAT-return re-encap.
    match role {
        Role::Node => {}
        Role::Edge => {
            let w = wan_uplink
                .as_deref()
                .context("--role edge requires --wan-uplink")?;
            ctrl.attach_edge(w, underlay)?;
        }
    }
    // Dual-homed hosts: also run uplink_rx on the additional fabric uplink(s) so returns
    // arriving via the other ToR (ECMP) are decapped too.
    for u in &extra_uplink {
        ctrl.attach_extra_uplink(u)?;
    }
    let dns4: Vec<[u8; 4]> = dhcp_dns
        .iter()
        .filter_map(|s| match s.parse::<std::net::Ipv4Addr>() {
            Ok(a) => Some(a.octets()),
            Err(_) => {
                eprintln!("ignoring unparseable --dhcp-dns entry {s:?}");
                None
            }
        })
        .collect();
    let dns6: Vec<[u8; 16]> = dhcpv6_dns
        .iter()
        .filter_map(|s| match s.parse::<std::net::Ipv6Addr>() {
            Ok(a) => Some(a.octets()),
            Err(_) => {
                eprintln!("ignoring unparseable --dhcpv6-dns entry {s:?}");
                None
            }
        })
        .collect();
    // One node-wide guest MTU: explicit --guest-mtu (or the deprecated --dhcp-mtu alias),
    // else derived from the smallest uplink MTU minus encap overhead. Drives DHCPv4 opt-26
    // here, and the veth link MTU + pod route MTU via AttachState below.
    let uplinks: Vec<&str> = std::iter::once(uplink.as_str())
        .chain(extra_uplink.iter().map(|s| s.as_str()))
        .collect();
    // Jumbo is offered only where the datapath can carry it: generic/SKB mode (skb handles
    // non-linear frames) or a native uplink advertising XDP scatter-gather. Otherwise the
    // guest is clamped to the standard MTU. An explicit --guest-mtu overrides the probe.
    let skb_mode = std::env::var_os("FLOWPLANE_SKB_MODE").is_some();
    let jumbo = probe_jumbo_ok(skb_mode, &uplinks);
    let guest_mtu = derive_guest_mtu(guest_mtu.or(dhcp_mtu), &uplinks, jumbo);
    println!(
        "guest MTU = {guest_mtu} (uplinks {uplinks:?}, encap overhead {ENCAP_OVERHEAD_V6}, \
                 jumbo_ok {jumbo}, skb_mode {skb_mode})"
    );
    ctrl.set_dhcp_config(guest_mtu, &dns4, &dns6)
        .map_err(|e| anyhow::anyhow!(e))?;
    let gc_ct = ctrl.take_conntrack();
    spawn_supervised("conntrack_gc", move || {
        conntrack_gc::run(gc_ct.clone(), std::time::Duration::from_secs(10))
    });
    // Wrap Control for the DataplaneNode service (the map handles live inside Control;
    // they can only be taken once).
    let control = std::sync::Arc::new(ctrl);

    // E/W hardware flow-offload manager (opt-in via --offload). Default OFF → no task
    // spawned → zero behavior change. When on, it reconciles established East/West overlay
    // flows onto offload-capable representors and owns the leak-safe install/GC lifecycle.
    if offload {
        let ctl = std::sync::Arc::clone(&control);
        let ct = ctl.take_conntrack();
        let ct6 = ctl.take_conntrack6();
        let cfg = crate::offload::OffloadCfg {
            interval: std::time::Duration::from_secs(5),
            idle_timeout_ns: 120 * 1_000_000_000,
            max_flows: 4096,
            pref_base: 40000,
        };
        spawn_supervised("offload", move || {
            crate::offload::run(
                std::sync::Arc::clone(&ctl),
                std::sync::Arc::clone(&ct),
                std::sync::Arc::clone(&ct6),
                cfg.clone(),
            )
        });
        log::info!("E/W flow offload manager started (--offload)");
    }

    // Disable guest tx-checksum offload at attach ONLY on a software-veth uplink (clab/kind),
    // which can't finalize CHECKSUM_PARTIAL; a real NIC finalizes the inner checksum in HW.
    let disable_guest_csum_offload = !attach::uplink_finalizes_checksum(&uplink);
    if disable_guest_csum_offload {
        println!(
            "uplink {uplink} is a software device (no HW csum finalize); disabling guest \
                     tx-checksum offload at attach"
        );
    }
    let attach_state = std::sync::Arc::new(attach::AttachState {
        control: std::sync::Arc::clone(&control),
        // Every interface on this node is programmed with the node VTEP as its underlay; local
        // delivery demuxes on the overlay (vni, ip) via INTERFACES/INTERFACES6.
        node_vtep: underlay,
        gateway_ipv4,
        gateway_ipv6,
        disable_guest_csum_offload,
        guest_mtu,
    });

    // On adopt, finish restart recovery: the maps + bookkeeping survived (bring_up), but the
    // guest program links died with the old process — re-attach each recovered interface's
    // program to its (surviving) veth.
    if adopt {
        let recovered = control.recovered_interfaces();
        let mut reattached = 0usize;
        for (id, device, l3) in &recovered {
            match control.reattach_guest(id, device, *l3) {
                Ok(()) => reattached += 1,
                Err(e) => {
                    eprintln!("adopt: re-attach guest program to {device} failed: {e:#}")
                }
            }
        }
        println!(
            "adopt: re-attached {reattached}/{} guest program(s)",
            recovered.len(),
        );
    }

    // gRPC health service (grpc.health.v1.Health) so the Kubernetes gRPC liveness probe
    // passes — the empty service name "" reports Serving (what the probe checks by default).
    // dpservice implements this; without it the probe SIGKILLs the pod every period.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    println!("serving DataplaneNode on {addr}");
    // Graceful shutdown that PRESERVES the pinned datapath: stop the gRPC server on SIGINT
    // (ctrl-c) or SIGTERM (kubelet/`docker stop` send SIGTERM, not SIGINT) WITHOUT any
    // map/link unpin. Pinned maps survive the process exit unconditionally, so the next
    // process adopts them; the programs re-attach fresh on that restart. Do NOT add cleanup
    // here — that would defeat the whole point of pinning.
    let shutdown = async {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("cannot install SIGTERM handler ({e}); ctrl-c only");
                    // Fall back to ctrl-c only.
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        println!("shutting down; pinned datapath preserved for adopt on restart");
    };
    let router = tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(node::pb::dataplane_node_server::DataplaneNodeServer::new(
            node::NodeService::new(attach_state),
        ));
    if let Some(path) = flowplane_device::addr::uds_path(&addr) {
        // Root-only unix socket: the dataplane gRPC is node-local and root-equivalent, so a
        // 0600 socket restricts it to root on this node instead of any process that can reach
        // a loopback TCP port.
        use std::os::unix::fs::PermissionsExt;
        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path); // clear a stale socket from a prior run
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        println!("dataplane gRPC listening on unix://{}", path.display());
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
        router
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await?;
    } else {
        router.serve_with_shutdown(addr.parse()?, shutdown).await?;
    }
    Ok(())
}

/// Resolve this hypervisor's underlay IPv6 identity (also the /64 the AttachInterface pool
/// allocates from), in precedence order:
///   1. `--local-underlay` when set — tests / hosts without a fabric loopback.
///   2. `--underlay-within <cidr>` when set — the authoritative cluster-wide filter: the host
///      address inside the expected node aggregate (e.g. `fd00:cafe::/32`). This overrides a wrong
///      `status.hostIP` (a mgmt address) and ignores unrelated global addresses (a Talos hostDNS
///      `lo` ULA, CNI veth /128s, the node's own API-VIP /64, …).
///   3. the kubelet node IP from the downward-API env (`HOST_IP`/`NODE_IP` = `status.hostIP`) —
///      the proper-cluster path (a KubeVirt node's fabric identity) when hostIP is the fabric addr.
///   4. inference from the host's `dummy*`/`lo` fabric-loopback address.
fn resolve_underlay_ipv6(flag: Option<&str>, within: Option<Ipv6Net>) -> anyhow::Result<[u8; 16]> {
    if let Some(s) = flag {
        return parse_ipv6(s);
    }
    if let Some(net) = within {
        let addrs = flowplane_device::read_host_ifaddrs()?;
        if let Some(a) = flowplane_device::infer_underlay_address_within(&addrs, Some(net)) {
            println!("underlay: selected {a} within {net}");
            return Ok(a.octets());
        }
        println!("underlay: no host address within {net}; falling back to HOST_IP/inference");
    }
    for var in ["HOST_IP", "NODE_IP"] {
        if let Ok(v) = std::env::var(var) {
            if let Ok(a) = v.parse::<std::net::Ipv6Addr>() {
                println!("underlay: using kubelet {var}={v}");
                return Ok(a.octets());
            }
        }
    }
    let addrs = flowplane_device::read_host_ifaddrs()?;
    if let Some(a) = flowplane_device::infer_underlay_address(&addrs) {
        println!("underlay: inferred fabric-loopback {a}");
        return Ok(a.octets());
    }
    anyhow::bail!(
        "cannot determine underlay IPv6: pass --local-underlay or --underlay-within, set HOST_IP \
         (status.hostIP), or run on a fabric node with a lo/dummy /64"
    )
}

/// Spawn a long-lived background loop that must never silently die: if the task panics or returns,
/// log it and restart after a short backoff. `make` is re-invoked per restart, so it must
/// re-derive (clone) any `Arc`/config it needs each time it is called.
fn spawn_supervised<F, Fut>(name: &'static str, make: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let h = tokio::spawn(make());
            match h.await {
                Ok(()) => {
                    log::error!("background task {name} exited unexpectedly; restarting in 5s")
                }
                Err(e) => log::error!("background task {name} panicked ({e}); restarting in 5s"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Read `/sys/class/net/<iface>/mtu` (the interface's L3 MTU). Best-effort: `None` on any error.
pub(crate) fn mtu_of(iface: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Standard (non-jumbo) underlay L3 MTU. When the datapath can't carry jumbo on the native fast
/// path (native XDP with no RX scatter-gather), the guest is clamped to this rather than handed a
/// jumbo MTU that would degrade or drop — an explicit `--guest-mtu` still overrides.
pub(crate) const STANDARD_LINK_MTU: u32 = 1500;

/// Node-wide guest MTU: the explicit override if set, else the smallest uplink MTU minus the encap
/// overhead (so an encapped full-size guest frame still fits the underlay). One value feeds the veth
/// link MTU, the pod route MTU (returned to the CNI), DHCPv4 option 26, and the IPv6 RA MTU option.
/// Falls back to 1500 base if no uplink MTU is readable. When `jumbo_ok` is false the underlay is
/// first clamped to the standard MTU so jumbo is only offered where the datapath can carry it
/// (generic/SKB mode, or a native NIC advertising RX scatter-gather — see [`jumbo_ok`]).
pub(crate) fn derive_guest_mtu(explicit: Option<u32>, uplinks: &[&str], jumbo_ok: bool) -> u16 {
    if let Some(m) = explicit {
        return m as u16;
    }
    let min_uplink = uplinks
        .iter()
        .filter_map(|u| mtu_of(u))
        .min()
        .unwrap_or(STANDARD_LINK_MTU);
    guest_mtu_from(min_uplink, jumbo_ok)
}

/// Pure guest-MTU policy given the smallest uplink MTU: clamp to standard when jumbo isn't safe,
/// subtract the encap overhead, floor at 576.
fn guest_mtu_from(min_uplink: u32, jumbo_ok: bool) -> u16 {
    let base = if jumbo_ok {
        min_uplink
    } else {
        min_uplink.min(STANDARD_LINK_MTU)
    };
    base.saturating_sub(ENCAP_OVERHEAD_V6).max(576) as u16
}

/// Parse `ip -d link show dev <iface>` for XDP scatter-gather (`rx-sg`) in the advertised
/// `xdp-features`. `None` when no xdp-features line is present (older iproute2 / no info); jumbo
/// multi-buffer (frags) XDP needs `rx-sg` on the native path.
pub(crate) fn parse_xdp_sg(ip_detail: &str) -> Option<bool> {
    let line = ip_detail.lines().find(|l| l.contains("xdp-features"))?;
    Some(line.contains("rx-sg"))
}

/// Best-effort probe of one uplink's XDP scatter-gather support via `ip -d link show` (shelling out
/// keeps the dependency surface small, consistent with flowplane-device). `None` on any error.
fn uplink_supports_sg(iface: &str) -> Option<bool> {
    let out = std::process::Command::new("ip")
        .args(["-d", "link", "show", "dev", iface])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_xdp_sg(&String::from_utf8_lossy(&out.stdout))
}

/// Whether jumbo guest MTUs are safe to hand out. Pure policy over the per-uplink SG probe results:
/// always true in generic/SKB mode (the skb carries non-linear frames), otherwise every uplink must
/// definitively advertise scatter-gather. Unknown (`None`) is treated as NOT jumbo-capable —
/// conservative: prefer a working standard MTU over a possibly-degraded jumbo one.
pub(crate) fn jumbo_ok(skb_mode: bool, sg: &[Option<bool>]) -> bool {
    skb_mode || (!sg.is_empty() && sg.iter().all(|s| *s == Some(true)))
}

/// Probe every uplink's SG support and decide whether jumbo is safe (see [`jumbo_ok`]). `skb_mode`
/// reflects the `FLOWPLANE_SKB_MODE` pin (generic XDP always carries jumbo).
pub(crate) fn probe_jumbo_ok(skb_mode: bool, uplinks: &[&str]) -> bool {
    let sg: Vec<Option<bool>> = uplinks.iter().map(|u| uplink_supports_sg(u)).collect();
    jumbo_ok(skb_mode, &sg)
}

// ---------------------------------------------------------------------------
// Unit tests (no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xdp_sg_detects_rx_sg() {
        let with = "12: eth1: <...> mtu 9000 ...\n    xdp-features: basic redirect ndo-xmit rx-sg";
        let without = "12: eth1: <...> mtu 1500 ...\n    xdp-features: basic redirect ndo-xmit";
        let none = "12: eth1: <...> mtu 1500 ...\n    link/ether 02:00:00:00:00:01";
        assert_eq!(parse_xdp_sg(with), Some(true));
        assert_eq!(parse_xdp_sg(without), Some(false));
        assert_eq!(parse_xdp_sg(none), None);
    }

    #[test]
    fn jumbo_ok_policy() {
        // SKB mode always carries jumbo (skb non-linear), regardless of SG.
        assert!(jumbo_ok(true, &[]));
        assert!(jumbo_ok(true, &[Some(false), None]));
        // Native: every uplink must definitively support SG.
        assert!(jumbo_ok(false, &[Some(true), Some(true)]));
        assert!(!jumbo_ok(false, &[Some(true), Some(false)]));
        // Unknown (None) is conservative — not jumbo-capable.
        assert!(!jumbo_ok(false, &[Some(true), None]));
        // No uplinks -> not jumbo-capable on native.
        assert!(!jumbo_ok(false, &[]));
    }

    #[test]
    fn guest_mtu_clamps_to_standard_without_jumbo() {
        // Jumbo ok: full underlay minus encap (Geneve overhead 56 + DSR option 24 = 80).
        assert_eq!(guest_mtu_from(9000, true), 8920);
        // Jumbo not ok: clamp to standard 1500 first, then minus encap.
        assert_eq!(guest_mtu_from(9000, false), 1420);
        // Small underlay is unaffected by the clamp either way.
        assert_eq!(guest_mtu_from(1500, false), 1420);
        assert_eq!(guest_mtu_from(1500, true), 1420);
        // Floor at 576.
        assert_eq!(guest_mtu_from(600, true), 576);
    }

    #[test]
    fn encap_overhead_v6_includes_dsr_geneve_option() {
        // The advertised guest MTU must leave room for the DSR Geneve option that the edge
        // stamps onto edge->backend redirected packets (B9), on top of the base Geneve overhead
        // (outer IPv6 40 + outer UDP 8 + Geneve header 8 = 56), so a full-MTU inner frame plus the
        // DSR option always fits the underlay path MTU.
        assert_eq!(
            crate::ENCAP_OVERHEAD_V6,
            flowplane_common::GENEVE_OVERHEAD as u32 + flowplane_core::dsr::DSR_OPT_BUF_LEN as u32
        );
        assert_eq!(crate::ENCAP_OVERHEAD_V6, 80);
    }

    #[test]
    fn derive_guest_mtu_explicit_overrides_probe() {
        // Explicit --guest-mtu wins even when jumbo is not ok and uplinks are unreadable.
        assert_eq!(derive_guest_mtu(Some(9000), &["nope0"], false), 9000);
    }
}
