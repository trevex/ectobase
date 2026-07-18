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
//! drives): it attaches `tc_guest_tx` to the host-side veth and programs PORT_META /
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
    /// Server-wide overlay IPv6 gateway (from `--gateway6`), programmed into
    /// `PortMeta.gateway_ipv6` so the ND / DHCPv6 responders have a gateway. All-zeros = disabled.
    pub gateway_ipv6: [u8; 16],
    /// Disable guest tx-checksum offload at attach. Only needed when the fabric uplink is a
    /// software veth (clab/kind) that advertises HW_CSUM but never finalizes CHECKSUM_PARTIAL, so
    /// the encapped inner L4 checksum would reach the wire partial/wrong. A real NIC finalizes the
    /// inner checksum in hardware after our encap, so we leave offload on there (avoids the guest-CPU
    /// checksum tax). See docs/superpowers/specs/2026-07-16-guest-egress-inner-checksum-design.md.
    pub disable_guest_csum_offload: bool,
}

/// Whether the fabric `uplink` can finalize a `CHECKSUM_PARTIAL` inner checksum in hardware. A real
/// NIC (PCI/virtio) has a `/sys/class/net/<iface>/device` link and offloads the checksum after our
/// encap; a software veth (clab/kind fabric) has no such link and never finalizes, so guests there
/// must emit complete checksums (offload disabled at attach). Errs toward "software" (disable offload)
/// on any uncertainty — the wrong guess that direction is a tiny perf tax, not a correctness bug.
pub fn uplink_finalizes_checksum(uplink: &str) -> bool {
    std::fs::symlink_metadata(format!("/sys/class/net/{uplink}/device")).is_ok()
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

    /// Reseed the underlay IPAM used-set from addresses recovered on restart (the surviving pinned
    /// UNDERLAY map), so a live guest's /128 is never handed out again after an flowplane restart —
    /// the reissue-a-live-/128 blackhole the review flagged. Called once, on adopt.
    pub fn seed_ipam(&self, addrs: &[[u8; 16]]) {
        let mut ipam = self.ipam.lock();
        for a in addrs {
            ipam.mark_used(std::net::Ipv6Addr::from(*a));
        }
    }

    /// A locally-administered unicast MAC (02:xx:...) derived DETERMINISTICALLY from the
    /// interface_id (FNV-1a, same idiom as `host_veth_name`). Determinism is a correctness
    /// requirement, not a nicety: on detach the datapath's current guest MAC is cached in
    /// `learned_macs` (control.rs) so a detach+re-attach of the SAME interface preserves it; a
    /// per-attach counter would hand the re-created veth a NEW MAC while the maps kept the cached
    /// OLD one, so `uplink_rx` would deliver returns to the stale MAC and the guest would drop them.
    /// Deriving from the id makes the re-attached veth, the cache, and the maps all agree.
    fn mac_for(interface_id: &str) -> [u8; 6] {
        let mut h: u32 = 2166136261;
        for b in interface_id.as_bytes() {
            h = (h ^ *b as u32).wrapping_mul(16777619);
        }
        let s = h.to_be_bytes();
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
        let ipv4 = primary_ipv4(requested_ips)
            .context("attach requires at least one IPv4 in requested_ips")?;

        // Primary overlay IPv6: first requested IPv6 (OPTIONAL — IPv4-only guests are valid, so this
        // defaults to all-zeros rather than bailing). Set into PortMeta.guest_ipv6, which the DHCPv6
        // responder (IA Address) and NAT64 require. Mirrors the bare-IP parse the v4 side uses.
        let ipv6 = primary_ipv6(requested_ips);

        // MAC: honour a caller-supplied MAC, else derive a stable one from the interface_id (so a
        // detach+re-attach reuses the same MAC — see `mac_for`).
        let mac = if mac_req.is_empty() {
            Self::mac_for(interface_id)
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
        // tc_guest_tx to the HOST-side veth and programs PORT_META/INTERFACES/UNDERLAY).
        let params = IfaceParams {
            vni,
            ipv4,
            ipv6,
            gateway_ipv4: self.gateway_ipv4,
            gateway_ipv6: self.gateway_ipv6,
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
        // Disable tx-checksum offload on the guest end — BUT ONLY when the uplink can't finalize
        // CHECKSUM_PARTIAL in hardware (software veth fabric, e.g. clab/kind). The guest stack
        // otherwise emits TCP/UDP with CHECKSUM_PARTIAL (a pseudo-header-only partial csum, meant to
        // be finalized "by hardware"); our encap redirects to the uplink bypassing that finalization,
        // so on a veth uplink the inner L4 checksum reaches the wire partial/wrong (ICMP is immune).
        // On a real NIC the hardware finalizes it after encap, so we keep offload on there (avoids the
        // guest-CPU checksum tax). Best-effort: don't fail attach if ethtool is unavailable.
        if self.disable_guest_csum_offload {
            let _ = run_netns(
                netns_path,
                &["ethtool", "-K", guest_name, "tx-checksum-ip-generic", "off"],
            );
        }
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
        // Best-effort cleanup: run ALL reclaim steps regardless of a datapath-detach failure. If the
        // datapath detach errored and we returned early (the old behaviour), the host veth AND the
        // underlay /128 would leak on every partial detach. Reclaim the veth + IPAM unconditionally,
        // then surface the datapath error to the caller.
        let dp = self
            .control
            .detach_interface(interface_id.as_bytes())
            .context("detach datapath");
        let host = Self::host_veth_name(interface_id);
        // Deleting the host end removes the veth pair (guest peer goes with it). Idempotent: an
        // already-absent veth is fine, so the error is intentionally ignored.
        let _ = run(&["ip", "link", "del", &host]);
        if let Some(ul) = underlay {
            self.ipam.lock().release(Ipv6Addr::from(ul));
        }
        dp.map(|_| ())
    }
}

/// First valid IPv4 address in `requested_ips`, as raw octets.  Returns `None` if none is present
/// (caller should `.context("requires at least one IPv4")`).
fn primary_ipv4(requested_ips: &[String]) -> Option<[u8; 4]> {
    requested_ips
        .iter()
        .find_map(|s| s.parse::<Ipv4Addr>().ok())
        .map(|a| a.octets())
}

/// First valid IPv6 address in `requested_ips`, as raw octets.  Returns `[0u8; 16]` when none is
/// present — dual-stack is optional, so an IPv4-only guest is valid.
fn primary_ipv6(requested_ips: &[String]) -> [u8; 16] {
    requested_ips
        .iter()
        .find_map(|s| s.parse::<Ipv6Addr>().ok())
        .map(|a| a.octets())
        .unwrap_or([0u8; 16])
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
    fn uplink_finalizes_checksum_false_for_virtual_and_missing() {
        // Loopback is a virtual device (no /sys/class/net/lo/device) → cannot finalize in HW.
        assert!(!uplink_finalizes_checksum("lo"));
        // A non-existent interface also has no device link → false (errs toward "software").
        assert!(!uplink_finalizes_checksum("definitely-not-an-iface-xyz"));
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
    fn mac_for_is_deterministic_laa_unicast_and_distinct() {
        let a1 = AttachState::mac_for("natpod");
        let a2 = AttachState::mac_for("natpod");
        // Determinism is the whole point: a detach+re-attach of the SAME id must reuse the SAME MAC
        // so the re-created veth agrees with the learned_macs cache + the datapath maps (else
        // uplink_rx delivers returns to a stale MAC and the guest silently drops them).
        assert_eq!(
            a1, a2,
            "mac_for must be stable across re-attach of the same interface_id"
        );
        // Locally-administered (bit 1 set) unicast (bit 0 clear).
        assert_eq!(
            a1[0] & 0x03,
            0x02,
            "must be a locally-administered unicast MAC"
        );
        // Different ids get different MACs (no aliasing between endpoints on a node).
        assert_ne!(a1, AttachState::mac_for("web"));
        assert_ne!(a1, AttachState::mac_for("natpod2"));
    }

    #[test]
    fn parse_mac_rejects_bad() {
        assert!(parse_mac("zz:00:00:00:00:00").is_err());
        assert!(parse_mac("02:00:00").is_err());
    }

    // ── primary_ipv4 / primary_ipv6 ──────────────────────────────────────────

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn requested_ips_v4_only() {
        let ips = strs(&["10.1.0.7"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_dual_stack() {
        let ips = strs(&["10.1.0.7", "2001:db8:1::7"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        // 2001:0db8:0001:0000:0000:0000:0000:0007
        assert_eq!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07
            ]
        );
    }

    #[test]
    fn requested_ips_v6_only() {
        let ips = strs(&["2001:db8::1"]);
        assert_eq!(primary_ipv4(&ips), None);
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        assert_eq!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        );
    }

    #[test]
    fn requested_ips_empty() {
        let ips: Vec<String> = vec![];
        assert_eq!(primary_ipv4(&ips), None);
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_malformed_skipped_first_valid_wins() {
        // Garbage entries are skipped; the first parseable address of each family wins.
        let ips = strs(&["garbage", "10.1.0.7", "::not-ip", "192.168.1.1"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_multiple_v6_first_wins() {
        // When multiple valid IPv6 addresses are present, the FIRST one is picked (mirrors v4
        // "first wins" convention — `find_map` stops at the first `Ok`).
        let ips = strs(&["fd00::1", "2001:db8::2"]);
        // fd00::1 = fd00:0000:...:0001
        assert_eq!(
            primary_ipv6(&ips),
            [
                0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        );
        // Ensure the second address is NOT returned.
        assert_ne!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02
            ]
        );
    }
}
