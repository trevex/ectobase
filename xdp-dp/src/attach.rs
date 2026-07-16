//! Real `DataplaneNode.AttachInterface` / `DetachInterface` wiring.
//!
//! The CNI hands us `{interface_id, netns_path, vni, requested_ips}` and expects us to (a) create a
//! veth pair whose GUEST end lives inside the target netns and whose HOST end stays in the root
//! netns as the datapath tap, (b) allocate an underlay /128 for the endpoint out of the inferred
//! host /64, and (c) program the eBPF `INTERFACES`/`UNDERLAY` maps and attach the guest datapath
//! program to the host-side veth.
//!
//! Rather than duplicate the map-programming + datapath-attach sequence, we reuse the legacy
//! [`Control::create_interface`] path (the exact same one the dpservice CreateInterface handler
//! drives): it attaches `tc_guest_tx`/`guest_tx` to the host-side veth and programs PORT_META /
//! INTERFACES / UNDERLAY / the local self-route. Our job here is the veth+netns lifecycle plus the
//! underlay-/128 IPAM (via [`UnderlayIpam`]) and MAC allocation, then delegation.

use parking_lot::Mutex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;

use anyhow::{bail, Context};

use crate::control::{Control, IfaceParams};
use crate::underlay::UnderlayIpam;

/// Outcome of a successful attach, mapped 1:1 onto `AttachInterfaceResponse`.
pub struct AttachOutcome {
    pub ifname: String,
    pub ips: Vec<String>,
    pub mac: String,
    pub gateway: String,
    pub underlay_route: String,
}

/// Shared state threaded into the DataplaneNode service: the live datapath control plane, the
/// underlay /128 allocator (seeded from the inferred host /64 at serve startup), the server-wide
/// overlay IPv4 gateway, and a MAC counter for endpoints that don't request a specific MAC.
pub struct AttachState {
    pub control: Arc<Control>,
    pub ipam: Mutex<UnderlayIpam>,
    pub gateway_ipv4: [u8; 4],
    /// Monotonic MAC suffix so auto-allocated guest MACs are unique within this process.
    pub mac_seq: Mutex<u32>,
}

impl AttachState {
    /// Host-side veth name for an interface. Kept short and stable so detach can delete it and so
    /// the datapath tap is discoverable. Kernel IFNAMSIZ is 15 chars, so we hash long ids.
    fn host_veth_name(interface_id: &str) -> String {
        // "veth-<id>" when it fits; otherwise a stable short hash to stay within IFNAMSIZ.
        let candidate = format!("veth-{interface_id}");
        if candidate.len() <= 15 {
            candidate
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("veth-{h:08x}")
        }
    }

    /// Allocate a locally-administered unicast MAC (02:xx:...) from the process-local counter.
    fn alloc_mac(&self) -> [u8; 6] {
        let mut seq = self.mac_seq.lock();
        *seq = seq.wrapping_add(1);
        let s = seq.to_be_bytes();
        [0x02, 0x00, s[0], s[1], s[2], s[3]]
    }

    /// Attach an interface: create the veth pair, move the guest end into `netns_path`, allocate an
    /// underlay /128 + MAC, then delegate to `Control::create_interface` to program the maps and
    /// attach the datapath to the host-side veth.
    pub fn attach(
        &self,
        interface_id: &str,
        netns_path: &str,
        vni: u32,
        mac_req: &str,
        requested_ips: &[String],
    ) -> anyhow::Result<AttachOutcome> {
        if interface_id.is_empty() {
            bail!("interface_id is required");
        }
        // Primary overlay IPv4: first requested IPv4 (IPv6 requests are recorded but v4 is the
        // primary INTERFACES key for this path).
        let ipv4 = requested_ips
            .iter()
            .find_map(|s| s.parse::<Ipv4Addr>().ok())
            .map(|a| a.octets())
            .context("attach requires at least one IPv4 in requested_ips")?;

        // MAC: honour a caller-supplied MAC, else allocate one.
        let mac = if mac_req.is_empty() {
            self.alloc_mac()
        } else {
            parse_mac(mac_req).context("invalid mac")?
        };

        // Underlay /128 out of the inferred host /64.
        let underlay_ipv6 = {
            let mut ipam = self.ipam.lock();
            ipam.allocate().context("underlay /64 exhausted")?.octets()
        };

        // The guest end keeps the requested interface_id as its in-netns name (the CNI expects a
        // predictable ifname); the host end is our datapath tap.
        let host = Self::host_veth_name(interface_id);
        let guest_name = interface_id;

        // Create the veth pair (host end named `host`, guest end temporarily `guest_name`), move
        // the guest end into the target netns, name it, set its MAC + up. If anything fails after
        // the veth is created, tear it down so we don't leak.
        if let Err(e) = self.setup_veth(&host, guest_name, netns_path, mac) {
            let _ = run(&["ip", "link", "del", &host]);
            let mut ipam = self.ipam.lock();
            ipam.release(Ipv6Addr::from(underlay_ipv6));
            return Err(e);
        }

        // Delegate map-programming + datapath-attach to the legacy Control path (attaches
        // tc_guest_tx / guest_tx to the HOST-side veth and programs PORT_META/INTERFACES/UNDERLAY).
        let params = IfaceParams {
            vni,
            ipv4,
            ipv6: [0u8; 16],
            gateway_ipv4: self.gateway_ipv4,
            gateway_ipv6: [0u8; 16],
            underlay_ipv6,
            total_mbps: 0,
            public_mbps: 0,
        };
        if let Err(e) = self
            .control
            .create_interface(interface_id.as_bytes(), &host, params)
        {
            let _ = run(&["ip", "link", "del", &host]);
            let mut ipam = self.ipam.lock();
            ipam.release(Ipv6Addr::from(underlay_ipv6));
            return Err(e).context("program datapath for interface");
        }

        // Read the INTERFACES entry back out of the live map to prove it landed, and log a
        // greppable confirmation (the netns e2e asserts on this line; no bpftool in the dev shell).
        match self.control.interface_readback(vni, ipv4) {
            Some(tap) => println!(
                "INTERFACES readback vni={vni} ip={} -> tap_ifindex={tap}",
                Ipv4Addr::from(ipv4)
            ),
            None => {
                let _ = self.control.detach_interface(interface_id.as_bytes());
                let _ = run(&["ip", "link", "del", &host]);
                let mut ipam = self.ipam.lock();
                ipam.release(Ipv6Addr::from(underlay_ipv6));
                bail!("INTERFACES read-back failed after programming");
            }
        }

        Ok(AttachOutcome {
            ifname: guest_name.to_string(),
            ips: vec![Ipv4Addr::from(ipv4).to_string()],
            mac: fmt_mac(mac),
            gateway: Ipv4Addr::from(self.gateway_ipv4).to_string(),
            underlay_route: Ipv6Addr::from(underlay_ipv6).to_string(),
        })
    }

    /// Create the veth pair and place/configure the guest end inside the target netns.
    fn setup_veth(
        &self,
        host: &str,
        guest_name: &str,
        netns_path: &str,
        mac: [u8; 6],
    ) -> anyhow::Result<()> {
        // Fresh start: remove any stale host-side veth from a previous run.
        let _ = run(&["ip", "link", "del", host]);
        // Temporary guest-end name in the root netns before we move it (must differ from host and
        // be unique); derive it from the host name to avoid collisions.
        let tmp_guest = format!("{host}p");
        run(&[
            "ip", "link", "add", host, "type", "veth", "peer", "name", &tmp_guest,
        ])
        .context("create veth pair")?;
        // Move the guest end into the target netns (by path, e.g. /var/run/netns/<ns>).
        run(&["ip", "link", "set", &tmp_guest, "netns", netns_path])
            .context("move guest veth into netns")?;
        // Inside the netns: rename to the requested guest name, set MAC, bring up.
        let macs = fmt_mac(mac);
        run_netns(
            netns_path,
            &["ip", "link", "set", &tmp_guest, "name", guest_name],
        )
        .context("rename guest veth")?;
        run_netns(
            netns_path,
            &["ip", "link", "set", guest_name, "address", &macs],
        )
        .context("set guest veth mac")?;
        run_netns(netns_path, &["ip", "link", "set", guest_name, "up"]).context("guest veth up")?;
        // Disable tx-checksum offload on the guest end: the guest stack otherwise emits TCP/UDP with
        // CHECKSUM_PARTIAL (a pseudo-header-only partial csum, finalized "by hardware"). Our tc guest
        // edge SNATs (incremental csum update) + encapsulates and redirects, bypassing the xmit-time
        // finalization — so the inner L4 checksum reaches the wire partial/wrong and the peer drops
        // the segment (ICMP is immune; it has no offload). Forcing full csums here makes the SNAT's
        // incremental update land on a valid checksum. Best-effort: don't fail attach if unavailable.
        let _ = run_netns(
            netns_path,
            &["ethtool", "-K", guest_name, "tx-checksum-ip-generic", "off"],
        );
        // Give the HOST end the SAME (guest) MAC, then bring it up. `create_interface` derives the
        // datapath `guest_mac` from `mac_of(host)` (the "tap" it attaches the guest edge to), and the
        // local fast path rewrites a locally-delivered frame's dst to that `guest_mac`. If the host
        // veth kept its auto-generated MAC, local delivery would address the frame to that auto-MAC —
        // it reaches the peer netns but the guest iface (which has `mac`) drops it as not-for-me.
        run(&["ip", "link", "set", host, "address", &macs]).context("set host veth mac")?;
        run(&["ip", "link", "set", host, "up"]).context("host veth up")?;
        Ok(())
    }

    /// Detach: remove the datapath programming (which also removes INTERFACES/UNDERLAY), delete the
    /// host-side veth (its guest peer disappears with it), and release the underlay /128.
    pub fn detach(&self, interface_id: &str) -> anyhow::Result<()> {
        // Snapshot the underlay /128 before Control forgets it, so we can release the IPAM slot.
        let underlay = self
            .control
            .get_interface(interface_id.as_bytes())
            .map(|(_, _, _, ul, _)| ul);
        self.control
            .detach_interface(interface_id.as_bytes())
            .context("detach datapath")?;
        let host = Self::host_veth_name(interface_id);
        // Deleting the host end removes the veth pair (guest peer goes with it).
        let _ = run(&["ip", "link", "del", &host]);
        if let Some(ul) = underlay {
            self.ipam.lock().release(Ipv6Addr::from(ul));
        }
        Ok(())
    }
}

/// Run `ip`/other command in the root netns.
fn run(args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {args:?}"))?;
    if !out.status.success() {
        bail!(
            "command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Run a command inside the netns identified by `netns_path` via `ip netns exec <name>`.
/// `netns_path` is a path like `/var/run/netns/<name>`; we extract `<name>` for `ip netns exec`.
fn run_netns(netns_path: &str, args: &[&str]) -> anyhow::Result<()> {
    let ns = netns_path.rsplit('/').next().unwrap_or(netns_path);
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    run(&full)
}

/// Parse `"aa:bb:cc:dd:ee:ff"` into 6 bytes.
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            bail!("too many octets in MAC {s}");
        }
        out[i] = u8::from_str_radix(part, 16).with_context(|| format!("bad MAC octet {part}"))?;
        n += 1;
    }
    if n != 6 {
        bail!("MAC {s} must have 6 octets");
    }
    Ok(out)
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_veth_name_short_passthrough() {
        assert_eq!(AttachState::host_veth_name("t0"), "veth-t0");
    }

    #[test]
    fn host_veth_name_long_is_hashed_and_fits() {
        let n = AttachState::host_veth_name("a-very-long-interface-id-way-over-ifnamsiz");
        assert!(n.len() <= 15, "{n} exceeds IFNAMSIZ");
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn parse_mac_roundtrips() {
        assert_eq!(parse_mac("02:00:00:00:00:0a").unwrap(), [2, 0, 0, 0, 0, 10]);
        assert_eq!(fmt_mac([2, 0, 0, 0, 0, 10]), "02:00:00:00:00:0a");
    }

    #[test]
    fn parse_mac_rejects_bad() {
        assert!(parse_mac("zz:00:00:00:00:00").is_err());
        assert!(parse_mac("02:00:00").is_err());
    }
}
