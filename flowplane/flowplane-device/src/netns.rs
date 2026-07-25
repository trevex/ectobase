//! Deterministic container guest-netns addressing/routes at attach: configure the pod's overlay
//! address(es) + per-family default route on the veth guest end. Containers only (VMs self-config
//! via DHCP/RA). Point-to-point veth: use `onlink` so no shared subnet is assumed.

use anyhow::{Context, Result};

use crate::veth::run_netns;

/// What to configure inside the pod netns. A zero family is skipped.
pub struct GuestNetConfig {
    pub netns_path: String,
    pub guest_ifname: String,
    pub ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub gateway_ipv6: [u8; 16],
}

/// Configure the present families on the guest end. Idempotent-ish: assumes a freshly created veth.
pub fn configure_guest_netns(c: &GuestNetConfig) -> Result<()> {
    let dev = &c.guest_ifname;
    if c.ipv4 != [0u8; 4] {
        let ip = std::net::Ipv4Addr::from(c.ipv4).to_string();
        let gw = std::net::Ipv4Addr::from(c.gateway_ipv4).to_string();
        run_netns(
            &c.netns_path,
            &["ip", "addr", "add", &format!("{ip}/32"), "dev", dev],
        )
        .context("add v4 addr")?;
        if c.gateway_ipv4 != [0u8; 4] {
            // On-link host route to the gateway, then default via it (Cilium point-to-point model).
            // The gateway (e.g. 169.254.0.1) is off-subnet from a /32 pod IP, so we must first
            // install it as a directly-reachable on-link host route before adding the default.
            run_netns(&c.netns_path, &["ip", "route", "add", &gw, "dev", dev])
                .context("add v4 gw onlink route")?;
            run_netns(
                &c.netns_path,
                &["ip", "route", "add", "default", "via", &gw, "dev", dev],
            )
            .context("add v4 default route")?;
        }
    }
    if c.ipv6 != [0u8; 16] {
        let ip = std::net::Ipv6Addr::from(c.ipv6).to_string();
        run_netns(
            &c.netns_path,
            &["ip", "-6", "addr", "add", &format!("{ip}/128"), "dev", dev],
        )
        .context("add v6 addr")?;
        if c.gateway_ipv6 != [0u8; 16] {
            let gw = std::net::Ipv6Addr::from(c.gateway_ipv6).to_string();
            // The datapath answers NS for gateway_ipv6 (the on-link gateway); default via it, onlink.
            run_netns(
                &c.netns_path,
                &[
                    "ip", "-6", "route", "add", "default", "via", &gw, "dev", dev, "onlink",
                ],
            )
            .context("add v6 default route")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veth::run_netns;

    /// Run `ip netns exec <ns> <args>` and return captured stdout (for assertions).
    fn capture(netns_path: &str, args: &[&str]) -> String {
        let ns = netns_path.rsplit('/').next().unwrap_or(netns_path);
        let mut full = vec!["netns", "exec", ns, "ip"];
        full.extend_from_slice(args);
        let out = std::process::Command::new("ip")
            .args(&full)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn mk_ns(ns: &str) -> String {
        let _ = crate::veth::delete_link("gnc-h0");
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", ns])
            .output();
        std::process::Command::new("ip")
            .args(["netns", "add", ns])
            .output()
            .unwrap();
        // a dummy dev inside the ns to configure
        let path = format!("/var/run/netns/{ns}");
        run_netns(&path, &["ip", "link", "add", "eth0", "type", "dummy"]).unwrap();
        run_netns(&path, &["ip", "link", "set", "eth0", "up"]).unwrap();
        path
    }

    #[test]
    fn struct_builds_without_privileges() {
        let _ = GuestNetConfig {
            netns_path: "/var/run/netns/test".into(),
            guest_ifname: "eth0".into(),
            ipv4: [10, 0, 0, 5],
            gateway_ipv4: [169, 254, 0, 1],
            ipv6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10],
            gateway_ipv6: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
    }

    #[test]
    #[ignore = "privileged: creates a netns + configures addrs/routes (needs CAP_NET_ADMIN)"]
    fn configures_v6_only() {
        let ns = "gnc-v6";
        let path = mk_ns(ns);
        configure_guest_netns(&GuestNetConfig {
            netns_path: path.clone(),
            guest_ifname: "eth0".into(),
            ipv4: [0; 4],
            gateway_ipv4: [0; 4],
            ipv6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10],
            gateway_ipv6: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        })
        .unwrap();
        // v6 addr present, v6 default route present, NO v4 addr/default route.
        let v6addr = capture(&path, &["-6", "addr", "show", "eth0"]);
        assert!(
            v6addr.contains("2001:db8"),
            "v6 addr must be present: {v6addr}"
        );
        assert!(
            run_netns(&path, &["ip", "-6", "route", "show", "default"]).is_ok(),
            "v6 default route must be present"
        );
        let v4routes = capture(&path, &["-4", "route", "show"]);
        assert!(
            !v4routes.contains("default"),
            "v6-only must have NO v4 default route: {v4routes}"
        );
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", ns])
            .output();
    }

    #[test]
    #[ignore = "privileged: needs CAP_NET_ADMIN"]
    fn configures_v4_only() {
        let ns = "gnc-v4";
        let path = mk_ns(ns);
        configure_guest_netns(&GuestNetConfig {
            netns_path: path.clone(),
            guest_ifname: "eth0".into(),
            ipv4: [10, 0, 0, 5],
            gateway_ipv4: [169, 254, 0, 1],
            ipv6: [0; 16],
            gateway_ipv6: [0; 16],
        })
        .unwrap();
        // v4 addr + default route present, NO v6 addr/default route.
        let v4addr = capture(&path, &["-4", "addr", "show", "eth0"]);
        assert!(
            v4addr.contains("10.0.0.5"),
            "v4 addr must be present: {v4addr}"
        );
        let v4routes = capture(&path, &["-4", "route", "show", "default"]);
        assert!(
            v4routes.contains("default"),
            "v4 default route must be present: {v4routes}"
        );
        let v6routes = capture(&path, &["-6", "route", "show", "default"]);
        assert!(
            !v6routes.contains("default"),
            "v4-only must have NO v6 default route: {v6routes}"
        );
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", ns])
            .output();
    }

    #[test]
    #[ignore = "privileged: needs CAP_NET_ADMIN"]
    fn configures_dual_stack() {
        let ns = "gnc-dual";
        let path = mk_ns(ns);
        configure_guest_netns(&GuestNetConfig {
            netns_path: path.clone(),
            guest_ifname: "eth0".into(),
            ipv4: [10, 0, 0, 7],
            gateway_ipv4: [169, 254, 0, 1],
            ipv6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20],
            gateway_ipv6: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        })
        .unwrap();
        run_netns(&path, &["ip", "route", "show", "default"]).unwrap();
        assert!(
            run_netns(&path, &["ip", "-6", "route", "show", "default"]).is_ok(),
            "v6 default route must be present in dual-stack"
        );
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", ns])
            .output();
    }
}
