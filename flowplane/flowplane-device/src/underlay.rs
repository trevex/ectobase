//! Underlay addressing: infer the host's fabric-loopback VTEP (its /128 and /64) from the host's
//! interface addresses.
//!
//! The hypervisor sits in an unnumbered IPv6-only BGP fabric: its stable identity is a /64 that
//! lives on a loopback/dummy interface (also the kubelet's primary IP). We INFER that address rather
//! than configure it. That single node VTEP is the underlay for EVERY interface on the node — local
//! delivery demuxes on the overlay `(vni, ip)` via INTERFACES/INTERFACES6, so no per-endpoint /128
//! is allocated. Overlay addresses are user-specified elsewhere.
//!
//! Inference is exposed via the `flowplane infer-underlay` subcommand (a root-free observability hook
//! the containerlab IPv6-fabric e2e asserts on). The bringup path that CONSUMES the inferred VTEP is
//! wired by `flowplane`'s `AttachState`.
use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

/// One address seen on a host interface (name, addr, prefix_len).
pub struct IfAddr {
    pub ifname: String,
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

/// True if `ip` is a routable unicast IPv6 address usable as an underlay endpoint: excludes
/// link-local (`fe80::/10`), loopback (`::1`), the unspecified address (`::`), and multicast.
///
/// ULA (`fc00::/7`) is deliberately INCLUDED: private underlay fabrics commonly number their
/// loopback /64s from ULA (the icn reference lab and our containerlab fabric both use
/// `fd00:db8::/…`, and kind's own pod network is ULA too). The `lo`/`dummy*` preference in
/// [`infer_underlay_prefix`] is what selects the fabric /64 among any ULA addresses.
fn is_underlay_candidate(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    // fe80::/10 link-local.
    (ip.segments()[0] & 0xffc0) != 0xfe80
}

/// Infer the host's underlay IPv6 ADDRESS — the node's fabric-loopback identity (the same address
/// the kubelet advertises as its node IP on an unnumbered IPv6 fabric).
///
/// Preference order: a `dummy*` global-unicast address (the fabric loopback we deliberately create
/// for the node identity), then `lo`, then the first global-unicast address anywhere. `dummy*` is
/// preferred over `lo` because some platforms park an unrelated ULA on `lo` — e.g. Talos hostDNS
/// binds `fd54:616c:6f73::…` ("Talos") to `lo`, which would otherwise shadow the fabric `/64`.
/// Returns `None` when there is no global-unicast address at all.
pub fn infer_underlay_address(addrs: &[IfAddr]) -> Option<Ipv6Addr> {
    addrs
        .iter()
        .find(|a| a.ifname.starts_with("dummy") && is_underlay_candidate(&a.addr))
        .or_else(|| {
            addrs
                .iter()
                .find(|a| a.ifname == "lo" && is_underlay_candidate(&a.addr))
        })
        .or_else(|| addrs.iter().find(|a| is_underlay_candidate(&a.addr)))
        .map(|a| a.addr)
}

/// Infer the host underlay ADDRESS, constrained to `within` when set — the authoritative
/// cluster-wide filter. The node's fabric identity is known to live inside a well-known aggregate
/// (e.g. `fd00:cafe::/32` on the Talos lab, `fd00:db8::/32` on the kind fabric), so when the
/// operator passes that aggregate we pick the host address inside it and ignore every unrelated
/// global address (a mgmt `status.hostIP`, a Talos hostDNS `lo` ULA, CNI veth /128s, …). A
/// `dummy*` address inside the aggregate is still preferred over any other match. `within = None`
/// falls back to [`infer_underlay_address`]'s interface-name heuristic.
pub fn infer_underlay_address_within(
    addrs: &[IfAddr],
    within: Option<Ipv6Net>,
) -> Option<Ipv6Addr> {
    let Some(net) = within else {
        return infer_underlay_address(addrs);
    };
    let inside = |a: &&IfAddr| is_underlay_candidate(&a.addr) && net.contains(&a.addr);
    addrs
        .iter()
        .find(|a| a.ifname.starts_with("dummy") && inside(a))
        .or_else(|| addrs.iter().find(inside))
        .map(|a| a.addr)
}

/// Infer the host underlay /64 — the /64 of [`infer_underlay_address`].
pub fn infer_underlay_prefix(addrs: &[IfAddr]) -> Option<Ipv6Net> {
    infer_underlay_address(addrs).and_then(|ip| Ipv6Net::new(ip, 64).ok().map(|n| n.trunc()))
}

/// Infer the host underlay /64 constrained to `within` (see [`infer_underlay_address_within`]).
pub fn infer_underlay_prefix_within(addrs: &[IfAddr], within: Option<Ipv6Net>) -> Option<Ipv6Net> {
    infer_underlay_address_within(addrs, within)
        .and_then(|ip| Ipv6Net::new(ip, 64).ok().map(|n| n.trunc()))
}

/// Read the host's IPv6 interface addresses by shelling out to `ip -6 -o addr`.
///
/// We shell out rather than pull in `rtnetlink` to keep the dependency surface small; the output
/// parsing is factored into [`parse_ip_o_addr`] so it can be unit-tested without a live host.
pub fn read_host_ifaddrs() -> anyhow::Result<Vec<IfAddr>> {
    use anyhow::Context;
    let out = std::process::Command::new("ip")
        .args(["-6", "-o", "addr"])
        .output()
        .context("run `ip -6 -o addr`")?;
    anyhow::ensure!(
        out.status.success(),
        "`ip -6 -o addr` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(parse_ip_o_addr(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse the output of `ip -6 -o addr`. Each line looks like:
/// `2: eth0    inet6 2001:db8::5/64 scope global \    valid_lft forever ...`
/// We extract (ifname, addr, prefix_len) from the `inet6 <addr>/<len>` token.
fn parse_ip_o_addr(s: &str) -> Vec<IfAddr> {
    let mut out = Vec::new();
    for line in s.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        // Layout: "<idx>: <ifname> inet6 <addr>/<len> scope ...".
        let Some(pos) = toks.iter().position(|&t| t == "inet6") else {
            continue;
        };
        let (Some(&ifname), Some(&cidr)) = (toks.get(1), toks.get(pos + 1)) else {
            continue;
        };
        let Some((ip_s, len_s)) = cidr.split_once('/') else {
            continue;
        };
        let (Ok(addr), Ok(prefix_len)) = (ip_s.parse::<Ipv6Addr>(), len_s.parse::<u8>()) else {
            continue;
        };
        out.push(IfAddr {
            ifname: ifname.trim_end_matches(':').to_string(),
            addr,
            prefix_len,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(n: &str, ip: &str, p: u8) -> IfAddr {
        IfAddr {
            ifname: n.into(),
            addr: ip.parse().unwrap(),
            prefix_len: p,
        }
    }

    #[test]
    fn infers_global_unicast_64_prefers_loopback_dummy() {
        let addrs = vec![
            a("eth0", "fe80::1", 64),              // link-local: skip
            a("lo", "::1", 128),                   // loopback host: skip
            a("dummy0", "2001:db8:fefe:1::1", 64), // fabric loopback: PICK
            a("eth0", "2001:db8:aaaa::5", 64),     // uplink: not preferred
        ];
        assert_eq!(
            infer_underlay_prefix(&addrs).unwrap(),
            "2001:db8:fefe:1::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn infers_ula_fabric_dummy_over_ula_podnet() {
        // Real containerlab/kind scan set: EVERY global addr is ULA (fc00::/7) — the fabric
        // underlay on dummy0, kind's pod network on eth0, and CNI veth /128s. The dummy0 fabric
        // /64 must still be picked (regression for the wrongful ULA exclusion found on the lab).
        let addrs = vec![
            a("lo", "::1", 128),                      // loopback host: skip
            a("eth0", "fc00:f853:ccd:e793::2", 64),   // kind pod net (ULA): not preferred
            a("eth0", "fe80::c80b:ff:fe0b:7af5", 64), // link-local: skip
            a("dummy0", "fd00:db8:0:1::1", 64),       // fabric underlay (ULA): PICK
            a("vethafc9dc1b", "fd00:10:244::1", 128), // CNI veth (ULA): not preferred
        ];
        assert_eq!(
            infer_underlay_prefix(&addrs).unwrap(),
            "fd00:db8:0:1::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn prefers_dummy_over_lo_global_ula_talos() {
        // Talos parks a branded ULA (fd54:616c:6f73:: = "Talos", hostDNS) on `lo`, which is a
        // GLOBAL candidate iterated before dummy0. The dummy0 fabric identity must still win —
        // otherwise the underlay pool becomes fd54:616c:6f73::/64 (not fabric-routable).
        let addrs = vec![
            a("lo", "fd54:616c:6f73:0:204f:5320:444e:531", 128), // Talos hostDNS lo ULA: NOT preferred
            a("dummy0", "fd00:cafe:1914::1", 128),               // fabric identity: PICK
        ];
        assert_eq!(
            infer_underlay_prefix(&addrs).unwrap(),
            "fd00:cafe:1914::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn within_filter_selects_the_expected_aggregate() {
        // The authoritative cluster-wide filter: even with a mgmt hostIP, a Talos lo ULA, and the
        // node's own API-VIP /64 all present, `within = fd00:cafe::/32` + dummy preference pins the
        // dummy0 node-identity /64 (fd00:cafe:1914::/64), never the API VIP (fd00:cafe:1914:1::/64).
        let addrs = vec![
            a("eth0", "3fff:172:20:20::7", 64), // docker mgmt (status.hostIP): excluded
            a("lo", "fd54:616c:6f73:0:204f:5320:444e:531", 128), // Talos hostDNS: excluded
            a("vip0", "fd00:cafe:1914:1::1", 128), // API VIP: in-aggregate but not dummy
            a("dummy0", "fd00:cafe:1914::1", 128), // node identity: PICK
        ];
        let within = Some("fd00:cafe::/32".parse::<Ipv6Net>().unwrap());
        assert_eq!(
            infer_underlay_prefix_within(&addrs, within).unwrap(),
            "fd00:cafe:1914::/64".parse::<Ipv6Net>().unwrap()
        );
        // within = None falls back to the interface-name heuristic (dummy0 still wins here).
        assert_eq!(
            infer_underlay_prefix_within(&addrs, None).unwrap(),
            "fd00:cafe:1914::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn infers_the_loopback_address_not_just_the_prefix() {
        // resolve_underlay_ipv6's cluster path needs the actual /128 (the kubelet IP), not just
        // the /64 — assert the dummy0 fabric-loopback address is returned, over the eth0 pod-net.
        let addrs = vec![
            a("eth0", "fd00:aaaa::5", 64),      // pod-net (ULA): not preferred
            a("dummy0", "fd00:db8:0:1::1", 64), // fabric loopback: PICK
        ];
        assert_eq!(
            infer_underlay_address(&addrs).unwrap(),
            "fd00:db8:0:1::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn none_when_no_global_unicast() {
        let addrs = vec![a("eth0", "fe80::1", 64), a("lo", "::1", 128)];
        assert!(infer_underlay_prefix(&addrs).is_none());
    }

    #[test]
    fn parses_ip_o_addr_output() {
        let sample = "\
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
2: dummy0    inet6 2001:db8:fefe:9::1/64 scope global \\       valid_lft forever preferred_lft forever
3: eth0    inet6 fe80::20c:29ff:fe12:3456/64 scope link \\       valid_lft forever preferred_lft forever";
        let addrs = parse_ip_o_addr(sample);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[1].ifname, "dummy0");
        assert_eq!(
            addrs[1].addr,
            "2001:db8:fefe:9::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(addrs[1].prefix_len, 64);
        // End-to-end through inference: dummy0's /64 wins.
        assert_eq!(
            infer_underlay_prefix(&addrs).unwrap(),
            "2001:db8:fefe:9::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    /// Root-gated end-to-end test: creates a netns + `dummy0` with `2001:db8:fefe:9::1/64`, then
    /// reads the host ifaddrs and infers the /64. Requires root and the `ip` iproute2 tool.
    ///
    /// Run with: `cargo test -p flowplane -- --ignored`  (must be run as root).
    #[test]
    #[ignore]
    fn infers_from_dummy_iface() {
        use std::process::Command;

        // Run the whole scenario inside a fresh netns so we don't touch the real host: `ip netns
        // exec` runs a child that (a) creates dummy0, (b) execs THIS test binary with a marker so
        // the child performs read_host_ifaddrs()+infer in the isolated namespace and prints it.
        let ns = "flowplane_underlay_test";
        let _ = Command::new("ip").args(["netns", "del", ns]).status();
        let mk = Command::new("ip")
            .args(["netns", "add", ns])
            .status()
            .expect("ip netns add (need root)");
        assert!(mk.success(), "ip netns add failed (need root?)");

        let run = |args: &[&str]| {
            let ok = Command::new("ip")
                .args(["netns", "exec", ns])
                .args(args)
                .status()
                .expect("ip netns exec");
            assert!(ok.success(), "command failed: {args:?}");
        };
        run(&["ip", "link", "add", "dummy0", "type", "dummy"]);
        run(&["ip", "link", "set", "dummy0", "up"]);
        run(&[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:fefe:9::1/64",
            "dev",
            "dummy0",
        ]);

        // Read + parse inside the netns.
        let out = Command::new("ip")
            .args(["netns", "exec", ns, "ip", "-6", "-o", "addr"])
            .output()
            .expect("ip -6 -o addr in netns");
        let addrs = parse_ip_o_addr(&String::from_utf8_lossy(&out.stdout));

        let _ = Command::new("ip").args(["netns", "del", ns]).status();

        assert_eq!(
            infer_underlay_prefix(&addrs).unwrap(),
            "2001:db8:fefe:9::/64".parse::<Ipv6Net>().unwrap()
        );
    }
}
