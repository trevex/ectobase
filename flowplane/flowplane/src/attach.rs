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

/// Guest-edge device backing an interface. Both run the SAME `tc_guest_tx` datapath on a single
/// root-netns device (via `Control::create_interface`); they differ only in how that device is
/// created and how the guest reaches it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceType {
    /// Container: a veth pair whose guest end is moved into the target netns (the pod's `eth0`) and
    /// whose host end stays in the root netns as the datapath device.
    Veth,
    /// VM (fd model): a single root-netns tap whose fd is handed to qemu. No netns move, no peer —
    /// symmetric with the container host-veth. The VM's virtio NIC MAC MUST be supplied (local
    /// delivery rewrites the frame dst to `guest_mac`, so a derived MAC would never match the VM).
    Tap,
    /// VM (KubeVirt-compatible): the tap lives in the POD netns (virt-launcher opens it by name),
    /// connected to a root-netns veth by `tc mirred`. The root-netns veth end is the unchanged
    /// datapath device (`tc_guest_tx` + `uplink_rx` target), exactly like a container; the pod-netns
    /// `mirred` splice replaces "the pod process on the veth peer". A point-to-point `mirred` splice
    /// (rather than a bridge) keeps it lean — no bridge MAC-learning / STP / unicast flooding, and it
    /// forwards regardless of the L2 addressing. MAC required (same reason as `Tap`).
    PodTap,
}

impl DeviceType {
    /// Parse the `AttachInterface.device_type` proto field. Empty or `"veth"` → `Veth` (the default,
    /// preserving container behavior); `"tap"` → `Tap` (root-netns fd model); `"pod-tap"` → `PodTap`
    /// (KubeVirt-compatible pod-netns tap); anything else is an error.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "" | "veth" => Ok(DeviceType::Veth),
            "tap" => Ok(DeviceType::Tap),
            "pod-tap" => Ok(DeviceType::PodTap),
            other => {
                bail!("unknown device_type {other:?} (want \"veth\", \"tap\", or \"pod-tap\")")
            }
        }
    }

    /// Whether this device type requires an explicit VM MAC (local delivery rewrites the frame dst to
    /// `guest_mac`, so a derived MAC would silently drop every inbound frame to the VM).
    fn requires_mac(self) -> bool {
        matches!(self, DeviceType::Tap | DeviceType::PodTap)
    }
}

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
    /// checksum tax). See `uplink_finalizes_checksum` below for how this is decided.
    pub disable_guest_csum_offload: bool,
    /// Node-wide guest MTU (derived from the uplink MTU minus encap overhead, or the --guest-mtu
    /// override). The dataplane owns the veth lifecycle, so it sets this on both veth ends at attach
    /// and enables PLPMTUD in the guest netns — the CNI needs no MTU knowledge. Since the link MTU is
    /// already the tunnel-adjusted value, no separate pod route MTU (RTAX_MTU) is needed.
    pub guest_mtu: u16,
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
    /// the datapath tap is discoverable. Kernel IFNAMSIZ caps names at 15 chars, and `setup_veth`
    /// derives the temporary peer name as `<host>p` (one char longer) — so the host name itself must
    /// be <= 14 chars for the pair to create. Longer ids are hashed to a fixed 13-char name.
    fn host_veth_name(interface_id: &str) -> String {
        // "veth-<id>" when it (plus the +1 peer suffix) fits; otherwise a stable short hash.
        let candidate = format!("veth-{interface_id}");
        if candidate.len() <= 14 {
            candidate
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("veth-{h:08x}")
        }
    }

    /// Root-netns tap device name for an interface (the tap analogue of `host_veth_name`). A tap is a
    /// single device with no `<host>p` peer suffix, so it may use the full IFNAMSIZ (15); longer ids
    /// are hashed to a stable short name. qemu is pointed at this name (or handed its fd).
    fn tap_name(interface_id: &str) -> String {
        let candidate = format!("tap-{interface_id}");
        if candidate.len() <= 15 {
            candidate
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("tap-{h:08x}")
        }
    }

    /// Pod-netns veth-peer name for the `PodTap` model — a stable short (`vp-<hash>`, 11 chars) name
    /// distinct from both the root veth (`veth-<id>`) and the pod-netns tap (`tap-<id>`). It only
    /// needs to be a valid, collision-free handle for the `mirred` splice inside the pod netns.
    fn pod_peer_name(interface_id: &str) -> String {
        let mut h: u32 = 2166136261;
        for b in interface_id.as_bytes() {
            h = (h ^ *b as u32).wrapping_mul(16777619);
        }
        format!("vp-{h:08x}")
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
        device_type: DeviceType,
        tap_name: &str,
    ) -> anyhow::Result<AttachOutcome> {
        if interface_id.is_empty() {
            bail!("interface_id is required");
        }
        // A tap serves a VM whose virtio NIC has a fixed MAC; local delivery rewrites the frame dst to
        // `guest_mac`, so the programmed MAC must equal the VM's — a derived one would silently drop
        // every inbound frame. Require it explicitly rather than deriving.
        if device_type.requires_mac() && mac_req.is_empty() {
            bail!("device_type={device_type:?} requires an explicit mac (the VM NIC MAC)");
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

        // The tap device name (for tap / pod-tap): the caller-supplied `tap_name` if set (KubeVirt's
        // domainAttachmentType:tap opens the primary tap by the literal name "tap0"), else derive it.
        let tap_dev = if tap_name.is_empty() {
            Self::tap_name(interface_id)
        } else {
            tap_name.to_string()
        };
        // The root-netns datapath device tc_guest_tx attaches to: a veth host end (its peer moves
        // into the pod netns) or a single tap (its fd is handed to qemu). `create_interface` runs
        // the identical datapath on either — the device type only changes how it's created here.
        // Veth + PodTap use a root-netns veth as the datapath device; Tap uses a root-netns tap.
        let device = match device_type {
            DeviceType::Veth | DeviceType::PodTap => Self::host_veth_name(interface_id),
            DeviceType::Tap => tap_dev.clone(),
        };
        // Create + configure the device. If anything fails after creation, tear it down so we don't
        // leak. veth: create the pair + move the guest end into the netns. tap: a single root-netns
        // device. pod-tap: the veth + a pod-netns tap (named `tap_dev`) wired by mirred (KubeVirt).
        let setup = match device_type {
            DeviceType::Veth => self.setup_veth(&device, interface_id, netns_path, mac),
            DeviceType::Tap => self.setup_tap(&device, mac),
            DeviceType::PodTap => self.setup_pod_tap(&device, netns_path, &tap_dev, mac),
        };
        if let Err(e) = setup {
            let _ = run(&["ip", "link", "del", &device]);
            let mut ipam = self.ipam.lock();
            ipam.release(Ipv6Addr::from(underlay_ipv6));
            return Err(e);
        }

        // Delegate map-programming + datapath-attach to the legacy Control path (attaches
        // tc_guest_tx to the root-netns device and programs PORT_META/INTERFACES/UNDERLAY).
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
            .create_interface(interface_id.as_bytes(), &device, params)
        {
            let _ = run(&["ip", "link", "del", &device]);
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
                let _ = run(&["ip", "link", "del", &device]);
                let mut ipam = self.ipam.lock();
                ipam.release(Ipv6Addr::from(underlay_ipv6));
                bail!("INTERFACES read-back failed after programming");
            }
        }

        // `ifname` returned to the caller: for a veth it's the guest end inside the netns (the pod's
        // interface); for a tap it's the root-netns tap the caller points qemu at (or opens for its fd).
        let ifname = match device_type {
            DeviceType::Veth => interface_id.to_string(),
            // The tap the caller points qemu/libvirt at: root-netns (Tap, == device) or the
            // pod-netns tap (PodTap). Both are `tap_dev` (the caller-supplied name, e.g. "tap0").
            DeviceType::Tap | DeviceType::PodTap => tap_dev.clone(),
        };
        Ok(AttachOutcome {
            ifname,
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
        // Set the guest link MTU (node-wide value = underlay MTU - encap overhead). This is the
        // authoritative, in-our-control way to bound a pod's frame size (Cilium sets the veth MTU
        // directly rather than advertising it). A self-configuring VM ignores this and learns its
        // MTU from DHCP opt-26 / the RA MTU option instead.
        let mtu = self.guest_mtu.to_string();
        run_netns(netns_path, &["ip", "link", "set", guest_name, "mtu", &mtu])
            .context("set guest veth mtu")?;
        // Enable TCP Packetization-Layer PMTUD (RFC 4821) in the guest netns so TCP discovers the
        // path MTU itself, resilient to ICMP-blocking (the mechanism Cilium enables by default).
        // Best-effort: a missing sysctl / read-only netns must not fail the attach.
        let _ = run_netns(netns_path, &["sysctl", "-wq", "net.ipv4.tcp_mtu_probing=1"]);
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
        // Host end MTU must be >= the guest's so a full-size guest frame is never dropped on the tap
        // before the datapath encaps it.
        run(&["ip", "link", "set", host, "mtu", &mtu]).context("set host veth mtu")?;
        run(&["ip", "link", "set", host, "up"]).context("host veth up")?;
        Ok(())
    }

    /// Create + configure a root-netns tap for a VM: a single device (no netns move, no peer),
    /// symmetric with the container host-veth. qemu drives it (by name, or by opening its fd).
    /// `create_interface` attaches `tc_guest_tx` and programs the maps afterwards, exactly as for the
    /// veth host end — so only device creation differs. Proven by `test/tap-vm-smoke.sh` (a real VM).
    fn setup_tap(&self, tap: &str, mac: [u8; 6]) -> anyhow::Result<()> {
        // Fresh start: remove any stale tap from a previous run.
        let _ = run(&["ip", "link", "del", tap]);
        // `vnet_hdr` so qemu's `vhost=on` virtio path works (matches the smoke tap). multi-queue is a
        // perf follow-up: it needs a matching `queues=N` on qemu's `-netdev`, so keep single-queue here.
        run(&["ip", "tuntap", "add", "dev", tap, "mode", "tap", "vnet_hdr"])
            .context("create tap")?;
        // The tap MAC is set to the VM's NIC MAC (the caller-supplied `mac`); PORT_META.guest_mac ==
        // this, so a locally-delivered frame (dst rewritten to guest_mac) is accepted by the VM.
        let macs = fmt_mac(mac);
        run(&["ip", "link", "set", tap, "address", &macs]).context("set tap mac")?;
        // Guest link MTU = node-wide tunnel-adjusted value (same source as the veth). A self-
        // configuring VM learns its MTU from DHCP opt-26 / the RA MTU option; this bounds the tap.
        let mtu = self.guest_mtu.to_string();
        run(&["ip", "link", "set", tap, "mtu", &mtu]).context("set tap mtu")?;
        run(&["ip", "link", "set", tap, "up"]).context("tap up")?;
        // Disable offloads ONLY on a software-uplink fabric that can't finalize CHECKSUM_PARTIAL
        // (clab/kind), same rationale as the veth end: our encap redirects to the uplink bypassing
        // NIC checksum finalization, so the inner L4 csum would reach the wire partial. On a real NIC
        // we keep offloads ON to preserve VM throughput (GSO/TSO through vhost-net). Best-effort.
        if self.disable_guest_csum_offload {
            let _ = run(&[
                "ethtool", "-K", tap, "tso", "off", "gso", "off", "gro", "off", "lro", "off",
            ]);
        }
        Ok(())
    }

    /// Create the KubeVirt-compatible pod-netns tap topology: a veth pair whose HOST end (`host`,
    /// root netns) is the unchanged datapath device (`tc_guest_tx` + `uplink_rx` target, exactly like
    /// a container), whose PEER moves into the pod netns, plus a `tap` in the pod netns that qemu
    /// drives. The peer and tap are spliced point-to-point with `tc mirred` — leaner than a Linux
    /// bridge (no MAC-learning / STP / unicast flooding): `mirred` shovels every frame peer<->tap
    /// unconditionally, so all guest egress (incl. gateway-bound frames to GW_MAC) reaches
    /// `tc_guest_tx` on the root veth, and delivery reaches the VM, regardless of L2 addressing.
    /// `Control::create_interface` later attaches the datapath to `host`, unchanged from the veth path.
    fn setup_pod_tap(
        &self,
        host: &str,
        netns_path: &str,
        tap: &str,
        mac: [u8; 6],
    ) -> anyhow::Result<()> {
        let _ = run(&["ip", "link", "del", host]);
        // veth: host end in the root netns, peer created here then moved into the pod netns.
        let peer = Self::pod_peer_name(host);
        run(&[
            "ip", "link", "add", host, "type", "veth", "peer", "name", &peer,
        ])
        .context("create pod-tap veth pair")?;
        run(&["ip", "link", "set", &peer, "netns", netns_path])
            .context("move peer into pod netns")?;

        let mtu = self.guest_mtu.to_string();
        // Pod-netns tap (what qemu/libvirt opens): vnet_hdr for vhost=on virtio; MTU + up. Its MAC is
        // the host-side backend MAC (qemu's virtio NIC is given `mac` separately); the datapath's
        // PortMeta.guest_mac == `mac`, and delivery to the VM works because mirred is unconditional.
        run_netns(
            netns_path,
            &["ip", "tuntap", "add", "dev", tap, "mode", "tap", "vnet_hdr"],
        )
        .context("create pod-netns tap")?;
        run_netns(
            netns_path,
            &["ip", "link", "set", tap, "address", &fmt_mac(mac)],
        )
        .context("set pod tap mac")?;
        run_netns(netns_path, &["ip", "link", "set", tap, "mtu", &mtu]).context("pod tap mtu")?;
        run_netns(netns_path, &["ip", "link", "set", tap, "up"]).context("pod tap up")?;
        run_netns(netns_path, &["ip", "link", "set", &peer, "mtu", &mtu])
            .context("pod peer mtu")?;
        run_netns(netns_path, &["ip", "link", "set", &peer, "up"]).context("pod peer up")?;

        // Point-to-point splice: clsact + a matchall `mirred` redirect each way (peer<->tap). No
        // bridge → no MAC learning → no gateway-at-own-MAC hairpin.
        run_netns(netns_path, &["tc", "qdisc", "add", "dev", tap, "clsact"])
            .context("clsact on pod tap")?;
        run_netns(netns_path, &["tc", "qdisc", "add", "dev", &peer, "clsact"])
            .context("clsact on pod peer")?;
        run_netns(
            netns_path,
            &[
                "tc", "filter", "add", "dev", tap, "ingress", "matchall", "action", "mirred",
                "egress", "redirect", "dev", &peer,
            ],
        )
        .context("mirred tap->peer")?;
        run_netns(
            netns_path,
            &[
                "tc", "filter", "add", "dev", &peer, "ingress", "matchall", "action", "mirred",
                "egress", "redirect", "dev", tap,
            ],
        )
        .context("mirred peer->tap")?;

        // Offloads off on a software-uplink fabric (same rationale as setup_veth/setup_tap).
        if self.disable_guest_csum_offload {
            for dev in [tap, peer.as_str()] {
                let _ = run_netns(
                    netns_path,
                    &[
                        "ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off", "lro",
                        "off",
                    ],
                );
            }
        }

        // Root-netns host veth: the datapath device. MAC = guest_mac + MTU + up, like the container
        // host end. (The mirred splice is MAC-agnostic, so the peer/tap MACs don't gate delivery.)
        run(&["ip", "link", "set", host, "address", &fmt_mac(mac)])
            .context("pod-tap host veth mac")?;
        run(&["ip", "link", "set", host, "mtu", &mtu]).context("pod-tap host veth mtu")?;
        run(&["ip", "link", "set", host, "up"]).context("pod-tap host veth up")?;
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
        // Delete the root-netns device. Detach only gets the interface_id (not the device type), so
        // remove BOTH candidate names — a given id is only one type, so the other is a harmless no-op.
        // Deleting a veth host end removes its pair (the netns peer goes with it); deleting a tap
        // removes it outright. Idempotent: an already-absent device is fine, so errors are ignored.
        let _ = run(&["ip", "link", "del", &Self::host_veth_name(interface_id)]);
        let _ = run(&["ip", "link", "del", &Self::tap_name(interface_id)]);
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
        // The host name PLUS the +1 peer suffix (`<host>p`) must fit IFNAMSIZ (15).
        assert!(
            n.len() <= 14,
            "{n} leaves no room for the +1 veth peer suffix"
        );
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn host_veth_name_15char_boundary_is_hashed() {
        // "blue-guest" -> "veth-blue-guest" is exactly 15 chars; verbatim it would make a 16-char
        // peer ("veth-blue-guestp") that exceeds IFNAMSIZ, so it must be hashed instead.
        let n = AttachState::host_veth_name("blue-guest");
        assert_eq!(
            n.len(),
            13,
            "{n} should be the 13-char hashed form, not verbatim"
        );
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn device_type_parse() {
        assert_eq!(DeviceType::parse("").unwrap(), DeviceType::Veth);
        assert_eq!(DeviceType::parse("veth").unwrap(), DeviceType::Veth);
        assert_eq!(DeviceType::parse("tap").unwrap(), DeviceType::Tap);
        assert_eq!(DeviceType::parse("pod-tap").unwrap(), DeviceType::PodTap);
        assert!(DeviceType::parse("bridge").is_err());
    }

    #[test]
    fn device_type_requires_mac() {
        // A VM's MAC must match the datapath's guest_mac; a container derives one.
        assert!(!DeviceType::Veth.requires_mac());
        assert!(DeviceType::Tap.requires_mac());
        assert!(DeviceType::PodTap.requires_mac());
    }

    #[test]
    fn pod_peer_name_fits_and_distinct() {
        let p = AttachState::pod_peer_name("a-very-long-interface-id-way-over-ifnamsiz");
        assert!(p.len() <= 15, "{p} exceeds IFNAMSIZ");
        assert!(p.starts_with("vp-"));
        // The three pod-tap devices for one id must all be distinct (peer, tap, root veth).
        let id = "v0";
        let peer = AttachState::pod_peer_name(id);
        assert_ne!(peer, AttachState::tap_name(id));
        assert_ne!(peer, AttachState::host_veth_name(id));
    }

    #[test]
    fn tap_name_short_passthrough_and_distinct_from_veth() {
        assert_eq!(AttachState::tap_name("t0"), "tap-t0");
        // A tap and a veth for the same id must never collide (both live in the root netns).
        assert_ne!(
            AttachState::tap_name("t0"),
            AttachState::host_veth_name("t0")
        );
    }

    #[test]
    fn tap_name_long_is_hashed_and_fits_ifnamsiz() {
        let n = AttachState::tap_name("a-very-long-interface-id-way-over-ifnamsiz");
        // A tap has no +1 peer suffix, so the full IFNAMSIZ (15) is available.
        assert!(n.len() <= 15, "{n} exceeds IFNAMSIZ");
        assert!(n.starts_with("tap-"));
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
