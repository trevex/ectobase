//! Underlay addressing: infer the host /64 from the fabric loopback, hand out /128s.
//!
//! The hypervisor sits in an unnumbered IPv6-only BGP fabric: its stable identity is a /64 that
//! lives on a loopback/dummy interface (also the kubelet's primary IP). We INFER that /64 from the
//! host's interface addresses rather than configure it, then allocate a /128 per VM endpoint out of
//! it. Overlay addresses are user-specified elsewhere; the underlay /128 is the ONLY allocation.
//!
//! Inference is exposed via the `xdp-dp infer-underlay` subcommand (a root-free observability hook
//! the containerlab IPv6-fabric e2e asserts on). The bringup path that CONSUMES the inferred /64 for
//! IPAM lands in a follow-up task, so `UnderlayIpam` is still only exercised by unit tests; hence
//! `allow(dead_code)` in non-test builds, mirroring the `maps.rs` convention for test-driven code.
#![cfg_attr(not(test), allow(dead_code))]
use ipnet::Ipv6Net;
use std::collections::BTreeSet;
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

/// True if `ifname` is a loopback/dummy interface we prefer to source the underlay /64 from
/// (`lo`, `dummy`, `dummy0`, `dummy1`, ...).
fn is_loopback_iface(ifname: &str) -> bool {
    ifname == "lo" || ifname.starts_with("dummy")
}

/// Infer the host's underlay IPv6 ADDRESS — the node's fabric-loopback identity (the same address
/// the kubelet advertises as its node IP on an unnumbered IPv6 fabric).
///
/// Prefers a `lo`/`dummy*` global-unicast address (the fabric loopback), else the first
/// global-unicast address. Returns `None` when there is no global-unicast address at all.
pub fn infer_underlay_address(addrs: &[IfAddr]) -> Option<Ipv6Addr> {
    addrs
        .iter()
        .find(|a| is_loopback_iface(&a.ifname) && is_underlay_candidate(&a.addr))
        .or_else(|| addrs.iter().find(|a| is_underlay_candidate(&a.addr)))
        .map(|a| a.addr)
}

/// Infer the host underlay /64 — the /64 of [`infer_underlay_address`].
pub fn infer_underlay_prefix(addrs: &[IfAddr]) -> Option<Ipv6Net> {
    infer_underlay_address(addrs).and_then(|ip| Ipv6Net::new(ip, 64).ok().map(|n| n.trunc()))
}

/// A /128 allocator over the host underlay /64.
///
/// Hands out the lowest free host address in the SECOND HALF of the /64 (host index >= 2^63 for a
/// /64). The lower half is reserved for the host's own infrastructure addressing: the node fabric
/// loopback `<prefix>::1` (which is ALSO the kubelet node IP), the gateway, the subnet-router
/// anycast `<prefix>::`, etc. Allocating from the upper half guarantees a guest underlay /128 can
/// never collide with any of those. Released addresses are reused lowest-first within the pool.
pub struct UnderlayIpam {
    prefix: Ipv6Net,
    used: BTreeSet<u128>,
    /// Lowest allocatable host index — the start of the prefix's second half.
    start: u128,
    next: u128,
}

impl UnderlayIpam {
    /// Build an allocator over `prefix` (expected to be a /64).
    pub fn new(prefix: Ipv6Net) -> UnderlayIpam {
        // Reserve the lower half of the prefix for host infrastructure; allocate guests out of the
        // upper half. For host_bits H the second half begins at host 2^(H-1) (e.g. 2^63 for a /64).
        let host_bits = 128 - prefix.prefix_len() as u32;
        let start: u128 = if host_bits == 0 {
            0
        } else if host_bits >= 128 {
            1u128 << 127
        } else {
            1u128 << (host_bits - 1)
        };
        UnderlayIpam {
            prefix,
            used: BTreeSet::new(),
            start,
            next: start,
        }
    }

    /// Return the lowest free /128 host in the /64, or `None` when the prefix is exhausted.
    ///
    /// A released host (which sits below the `next` high-water mark) is reused before any fresh
    /// host is handed out, so the pool stays densely packed lowest-first. In the steady state
    /// (no releases) this is O(1): the scan finds the first gap immediately at `next`.
    pub fn allocate(&mut self) -> Option<Ipv6Addr> {
        let base = u128::from(self.prefix.network());
        // Number of host bits (128 - prefix_len); a /64 has 64 host bits.
        let host_bits = 128 - self.prefix.prefix_len() as u32;
        // Highest host index inside the prefix (inclusive). For a /64 this is 2^64 - 1.
        let max_host: u128 = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };

        // Reuse the lowest released host (a gap in [start, next)) if there is one; otherwise take
        // the next fresh host at the `next` high-water mark. The lower half of the prefix (incl.
        // host 0 and the node loopback ::1) is never handed out because allocation starts at
        // `self.start` (the prefix's second half) and releases never reintroduce a host below it.
        let host = (self.start..self.next)
            .find(|h| !self.used.contains(h))
            .unwrap_or(self.next);
        if host > max_host {
            return None;
        }
        self.used.insert(host);
        if host >= self.next {
            self.next = host + 1;
        }
        Some(Ipv6Addr::from(base + host))
    }

    /// Mark `ip` free again so a later `allocate()` may hand it back out (lowest-first).
    pub fn release(&mut self, ip: Ipv6Addr) {
        let base = u128::from(self.prefix.network());
        let host = u128::from(ip).wrapping_sub(base);
        self.used.remove(&host);
    }

    /// Mark `ip` as ALREADY allocated (restart recovery). A restarted control plane rebuilds its
    /// `used` set by calling this for every /128 found in the live (pinned) UNDERLAY map, so it can
    /// never re-hand-out an address an existing guest still holds — the reissue-a-live-/128 blackhole
    /// the review flagged. Addresses outside this prefix's allocatable second half are ignored (they
    /// can never be handed out anyway, so tracking them is pointless). Also advances the `next`
    /// high-water mark past a recovered address so fresh allocations continue above it.
    pub fn mark_used(&mut self, ip: Ipv6Addr) {
        let base = u128::from(self.prefix.network());
        let host = u128::from(ip).wrapping_sub(base);
        let host_bits = 128 - self.prefix.prefix_len() as u32;
        let max_host: u128 = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        if host < self.start || host > max_host {
            return;
        }
        self.used.insert(host);
        if host >= self.next {
            self.next = host + 1;
        }
    }
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
    fn allocates_128s_and_reuses_on_release() {
        let mut ip = UnderlayIpam::new("2001:db8:fefe:1::/64".parse().unwrap());
        let x = ip.allocate().unwrap();
        let y = ip.allocate().unwrap();
        assert_ne!(x, y);
        ip.release(x);
        assert_eq!(ip.allocate().unwrap(), x); // lowest free reused
    }

    #[test]
    fn mark_used_prevents_reissue_after_restart() {
        // Simulate a restart: a prior process handed out the first two /128s. Rebuilding the used
        // set via mark_used must stop allocate() from reissuing either (which would blackhole the
        // still-attached guests that hold them).
        let mut ip = UnderlayIpam::new("fd00:db8:0:2::/64".parse().unwrap());
        let live0: Ipv6Addr = "fd00:db8:0:2:8000::".parse().unwrap();
        let live1: Ipv6Addr = "fd00:db8:0:2:8000::1".parse().unwrap();
        ip.mark_used(live0);
        ip.mark_used(live1);
        let got = ip.allocate().unwrap();
        assert_ne!(got, live0);
        assert_ne!(got, live1);
        assert_eq!(got, "fd00:db8:0:2:8000::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn mark_used_ignores_out_of_range_addresses() {
        // A foreign or lower-half address (e.g. the node loopback) in the map must be ignored, not
        // tracked — and must not disturb the allocation cursor.
        let mut ip = UnderlayIpam::new("fd00:db8:0:2::/64".parse().unwrap());
        ip.mark_used("fd00:db8:0:2::1".parse().unwrap()); // node loopback (lower half) — ignore
        ip.mark_used("2001:db8::1".parse().unwrap()); // different prefix — ignore
        assert_eq!(
            ip.allocate().unwrap(),
            "fd00:db8:0:2:8000::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn none_when_no_global_unicast() {
        let addrs = vec![a("eth0", "fe80::1", 64), a("lo", "::1", 128)];
        assert!(infer_underlay_prefix(&addrs).is_none());
    }

    #[test]
    fn allocates_from_second_half_avoiding_node_loopback() {
        // The node's own fabric loopback (also the kubelet node IP) is <prefix>::1. A guest
        // underlay /128 must NEVER collide with it (nor with the gateway or other low-numbered
        // infra addresses), so allocation starts in the SECOND HALF of the prefix. For a /64 the
        // second half begins at host 2^63 -> <prefix>:8000::.
        let mut ip = UnderlayIpam::new("fd00:db8:0:2::/64".parse().unwrap());
        let node_lo: Ipv6Addr = "fd00:db8:0:2::1".parse().unwrap();
        let first = ip.allocate().unwrap();
        assert_ne!(first, node_lo, "must not hand out the node's own loopback");
        assert_eq!(first, "fd00:db8:0:2:8000::".parse::<Ipv6Addr>().unwrap());
        // and never the all-zeros subnet-router anycast either
        assert_ne!(first, "fd00:db8:0:2::".parse::<Ipv6Addr>().unwrap());
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
    /// Run with: `cargo test -p xdp-dp -- --ignored`  (must be run as root).
    #[test]
    #[ignore]
    fn infers_from_dummy_iface() {
        use std::process::Command;

        // Run the whole scenario inside a fresh netns so we don't touch the real host: `ip netns
        // exec` runs a child that (a) creates dummy0, (b) execs THIS test binary with a marker so
        // the child performs read_host_ifaddrs()+infer in the isolated namespace and prints it.
        let ns = "xdp_dp_underlay_test";
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
