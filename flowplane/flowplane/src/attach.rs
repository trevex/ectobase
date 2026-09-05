//! Real `DataplaneNode.AttachInterface` / `DetachInterface` wiring.
//!
//! The CNI hands us `{interface_id, netns_path, vni, requested_ips}` and expects us to (a) create a
//! veth pair whose GUEST end lives inside the target netns and whose HOST end stays in the root
//! netns as the datapath tap, (b) program the eBPF `INTERFACES`/`INTERFACES6` maps with this node's
//! VTEP as the endpoint underlay, and (c) attach the guest datapath program to the host-side veth.
//!
//! Rather than duplicate the map-programming + datapath-attach sequence, we reuse the legacy
//! [`Control::create_interface`] path (the exact same one the dpservice CreateInterface handler
//! drives): it attaches `tc_guest_tx` to the host-side veth and programs PORT_META /
//! INTERFACES / INTERFACES6 / the local self-route. Every interface on a node shares the one node
//! VTEP as its underlay (local delivery demuxes on the overlay `(vni, ip)` via INTERFACES, not on a
//! per-endpoint /128), so our job here is just the veth+netns lifecycle plus MAC allocation.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context};

use crate::control::{Control, IfaceParams, OverlayStatus};

/// Guest-edge device backing an interface. Both run the SAME `tc_guest_tx` datapath on a single
/// root-netns device (via `Control::create_interface`); they differ only in how that device is
/// created and how the guest reaches it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceType {
    /// Default (empty / `"auto"`): let the node pick the best available container edge. Resolved at
    /// attach time — netkit L3 when the kernel supports it, else veth. Never reaches device creation
    /// as `Auto`: `attach` resolves it to a concrete type first (see the `resolved` match).
    Auto,
    /// Container: a veth pair whose guest end is moved into the target netns (the pod's `eth0`) and
    /// whose host end stays in the root netns as the datapath device.
    Veth,
    /// Container (L3): an in-kernel BPF-programmable `netkit` pair in `mode l3`. The primary lives in
    /// the root netns as the datapath device; the peer is the pod's `eth0`. Carries no L2/eth header
    /// and has no settable MAC (local L3 delivery doesn't consult a device MAC). The guest program is
    /// attached via `BPF_NETKIT` (Task B.4), NOT tcx — so an explicit netkit attach currently fails
    /// cleanly at the program-attach step until B.4 lands.
    Netkit,
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
    /// Parse the `AttachInterface.device_type` proto field. Empty or `"auto"` → `Auto` (the default:
    /// node picks netkit L3 if the kernel supports it, else veth); `"veth"` → `Veth` (explicit L2
    /// container); `"netkit"` → `Netkit` (explicit L3 container); `"tap"` → `Tap` (root-netns fd
    /// model); `"pod-tap"` → `PodTap` (KubeVirt-compatible pod-netns tap); anything else is an error.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "" | "auto" => Ok(DeviceType::Auto),
            "veth" => Ok(DeviceType::Veth),
            "netkit" => Ok(DeviceType::Netkit),
            "tap" => Ok(DeviceType::Tap),
            "pod-tap" => Ok(DeviceType::PodTap),
            other => {
                bail!(
                    "unknown device_type {other:?} \
                     (want \"\"/\"auto\", \"veth\", \"netkit\", \"tap\", or \"pod-tap\")"
                )
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

/// Shared state threaded into the DataplaneNode service: the live datapath control plane, this
/// node's VTEP (the shared underlay every interface is programmed with), the server-wide overlay
/// IPv4 gateway, and MAC/MTU/offload knobs applied at attach.
pub struct AttachState {
    pub control: Arc<Control>,
    /// This node's VTEP (fabric-loopback /128, resolved once at serve startup). It is programmed as
    /// the `underlay_ipv6` of every interface on this node — local delivery demuxes on the overlay
    /// `(vni, ip)` via INTERFACES/INTERFACES6, so no per-endpoint /128 is allocated.
    pub node_vtep: [u8; 16],
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

/// Whether this kernel can actually stand up an L3 `netkit` pod device. Probed ONCE (memoized in a
/// `OnceLock`) by creating a throwaway `netkit mode l3` link and deleting it: many kernels lack the
/// netkit driver (needs a recent kernel + `CONFIG_NETKIT`), and a feature check that only inspects a
/// version string would lie on backported/patched kernels. Actually creating the device is the only
/// honest probe. Cheap after the first call (cached bool). Used by the `Auto` device-type resolver in
/// `attach` to decide netkit-vs-veth: `Auto` resolves to netkit L3 when this returns true, else veth.
pub fn netkit_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        // A fixed, unlikely-to-collide throwaway name in the root netns. Delete any stale one first
        // (best-effort), create the L3 pair, then delete it — success on create == supported.
        let tmp = "fp-nkprobe0";
        let _ = run(&["ip", "link", "del", tmp]);
        let ok = run(&["ip", "link", "add", tmp, "type", "netkit", "mode", "l3"]).is_ok();
        let _ = run(&["ip", "link", "del", tmp]);
        ok
    })
}

impl AttachState {
    /// Host-side veth name for an interface. Kept short and stable so detach can delete it and so
    /// the datapath tap is discoverable. Kernel IFNAMSIZ caps names at 15 chars, and
    /// `flowplane_device::create_veth_pair` derives the temporary peer name as `<host>p` (one char
    /// longer) — so the host name itself must be <= 14 chars for the pair to create. Longer ids are
    /// hashed to a fixed 13-char name.
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

    /// Guest-side (in-netns) device name for a veth interface. The `interface_id` the CNI passes is
    /// `<pod-uid>/<cni-ifname>` (e.g. `3889a54a-.../net1`) — a fine map key but NOT a valid Linux
    /// device name (it contains `/` and exceeds IFNAMSIZ), so using it verbatim as the guest link
    /// name made `ip link set … name <id>` fail ("rename guest veth") for every real CNI-driven pod.
    /// We derive a valid name from the id: the component after the last `/` (the CNI's own ifname,
    /// e.g. `net1`) when it is a valid <=15-char device name, else a stable FNV hash (`g-<hash>`).
    /// The map key + the response `ifname` stay the full `interface_id`; only the actual link name is
    /// sanitized. gRPC callers that pass a clean id (`nic-a`) are unaffected (the whole id is valid).
    fn guest_ifname(interface_id: &str) -> String {
        let last = interface_id.rsplit('/').next().unwrap_or(interface_id);
        if is_valid_ifname(last) {
            last.to_string()
        } else if is_valid_ifname(interface_id) {
            interface_id.to_string()
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("g-{h:08x}")
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

    /// The tap device name KubeVirt's `domainAttachmentType: tap` derives for a SECONDARY-network
    /// binding: `GenerateTapDeviceName` returns `"tap" + podInterfaceName[3:]` (strip the 3-char
    /// `pod`/`net` prefix, prepend `tap`), e.g. `pod9404eea3257` -> `tap9404eea3257`. virt-launcher
    /// looks up THIS exact name in the launcher pod netns and points the domain `<target dev=…>` at it
    /// (`managed='no'`), so the pod-netns tap MUST carry it. `tap0` — the PRIMARY-only name — is never
    /// looked up for a secondary network and was the cause of the "Link not found" boot failure. The
    /// pod link (`pod<hash>`, ≤14 chars) always has a 3+ char prefix; guard the tiny-name case anyway.
    fn kubevirt_secondary_tap_name(pod_link: &str) -> String {
        if pod_link.len() > 3 {
            format!("tap{}", &pod_link[3..])
        } else {
            format!("tap-{pod_link}")
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

    /// Attach an interface: create the veth pair, move the guest end into `netns_path`, derive its
    /// MAC, then delegate to `Control::create_interface` to program the maps (with the node VTEP as
    /// the underlay) and attach the datapath to the host-side veth.
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
        // Overlay IPs: at least ONE family is required; either may be absent (all-zeros).
        let ipv4 = primary_ipv4(requested_ips).unwrap_or([0u8; 4]);
        let ipv6 = primary_ipv6(requested_ips);
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            bail!("attach requires at least one overlay IP (IPv4 or IPv6) in requested_ips");
        }

        // MAC: honour a caller-supplied MAC, else derive a stable one from the interface_id (so a
        // detach+re-attach reuses the same MAC — see `mac_for`).
        let mac = if mac_req.is_empty() {
            Self::mac_for(interface_id)
        } else {
            parse_mac(mac_req).context("invalid mac")?
        };

        // Underlay = this node's VTEP, shared by every interface. Local delivery demuxes on the
        // overlay (vni, ip) via INTERFACES/INTERFACES6, so no per-endpoint /128 is allocated.
        let underlay_ipv6 = self.node_vtep;

        // Resolve the caller's device type to a concrete one before any device work (moved ahead of the
        // tap-name derivation, which now depends on it). `Auto` (the default / empty device_type) picks
        // the best available container edge: netkit L3 when the kernel supports it (probed once,
        // cached — see `netkit_supported`), else veth. Explicit types pass through unchanged.
        let resolved = match device_type {
            DeviceType::Auto => {
                if netkit_supported() {
                    DeviceType::Netkit
                } else {
                    DeviceType::Veth
                }
            }
            dt => dt,
        };
        // Whether this is an L3 (netkit) edge — threaded into PORT_META.l3 so the datapath treats the
        // primary as an L3 (no-eth) device. Only netkit is L3; veth/tap/pod-tap are all L2.
        let l3 = matches!(resolved, DeviceType::Netkit);
        // Guest-side (in-netns) device name = the pod link. For a KubeVirt VM (PodTap) this MUST equal
        // the CNI_IFNAME Multus assigned (`pod<hash>`): virt-launcher's domainAttachmentType:tap
        // phase-2 discovery does a netlink LinkByName on the computed `pod<hash>` (then ordinal
        // `net<N>`) name and IGNORES the network-status metadata — so the in-pod device has to actually
        // carry that name, else discovery yields an empty name and libvirt aborts ("Link not found").
        // `guest_ifname` is the sanitized trailing CNI_IFNAME (the `<pod-uid>/<ifname>` id's tail).
        let guest_ifname = Self::guest_ifname(interface_id);
        // The tap device name. For pod-tap it MUST match what virt-launcher derives from the pod link —
        // `GenerateTapDeviceName` = "tap" + podInterfaceName[3:] (e.g. pod9404… -> tap9404…), NOT the
        // literal "tap0" (the PRIMARY-only name KubeVirt never looks for on a secondary network). For a
        // root-netns Tap, honour the caller's `tap_name` if set, else derive one.
        let tap_dev = match resolved {
            DeviceType::PodTap => Self::kubevirt_secondary_tap_name(&guest_ifname),
            _ if !tap_name.is_empty() => tap_name.to_string(),
            _ => Self::tap_name(interface_id),
        };
        // The root-netns datapath device tc_guest_tx attaches to: a veth/netkit host end (its peer
        // moves into the pod netns) or a single tap (its fd is handed to qemu). `create_interface`
        // runs the identical datapath on either — the device type only changes how it's created here.
        // Veth + PodTap + Netkit use a root-netns primary as the datapath device; Tap uses a tap.
        let device = match resolved {
            DeviceType::Veth | DeviceType::PodTap | DeviceType::Netkit => {
                Self::host_veth_name(interface_id)
            }
            DeviceType::Tap => tap_dev.clone(),
            DeviceType::Auto => unreachable!("Auto resolved to a concrete device type above"),
        };
        // The ifname reported to the CNI. Container edge: the guest device. VM (PodTap): the POD LINK
        // (`pod<hash>` = guest_ifname) that virt-launcher discovers — NOT the tap. (main.go's CNI
        // Result sets the interface name from CNI_IFNAME directly; this rides the gRPC response too.)
        // Computed before device creation so the idempotent-adopt path can return it without touching
        // devices.
        let ifname = match resolved {
            DeviceType::Veth | DeviceType::Netkit | DeviceType::PodTap => guest_ifname.clone(),
            DeviceType::Tap => tap_dev.clone(),
            DeviceType::Auto => unreachable!("Auto resolved to a concrete device type above"),
        };
        // Idempotent re-attach. A KubeVirt virt-launcher attaches the flowplane NAD TWICE — once as
        // the VMI's multus network source (carries the MAC + a generated ifname) and once as the
        // `flowplane` binding plugin's own NAD (carries logicNetworkName, no ifname) — so Multus runs
        // `flowplane-cni` twice for the SAME VM NIC: same (vni, ip) + MAC, DIFFERENT interface_id.
        // The 2nd ADD must adopt the 1st (return its outcome, create no 2nd device) or it fails
        // `ROUTE_EXISTS` and wedges the pod sandbox in an infinite CreatePodSandbox retry loop. The
        // binding attach must succeed for KubeVirt's domainAttachmentType:tap to resolve the pod
        // link, so we cannot simply drop one attach. A DIFFERENT endpoint (different MAC) claiming an
        // in-use (vni, ip) is still a real conflict. Checked before any device work so neither adopt
        // nor conflict churns devices.
        match self.control.overlay_status(vni, ipv4, ipv6, mac) {
            OverlayStatus::SameEndpoint => {
                return Ok(self.make_outcome(ifname, ipv4, ipv6, mac, underlay_ipv6));
            }
            OverlayStatus::Conflict => bail!("ROUTE_EXISTS: IP already in use in this VNI"),
            OverlayStatus::Free => {}
        }
        // Create + configure the device. If anything fails after creation, tear it down so we don't
        // leak. veth: create the pair + move the guest end into the netns. tap: a single root-netns
        // device. pod-tap: the veth + a pod-netns tap (named `tap_dev`) wired by mirred (KubeVirt).
        let setup = match resolved {
            DeviceType::Veth => flowplane_device::create_veth_pair(&flowplane_device::VethSpec {
                host_name: device.clone(),
                guest_name: guest_ifname.clone(),
                netns_path: netns_path.to_string(),
                mac,
                mtu: self.guest_mtu as u32,
                disable_csum_offload: self.disable_guest_csum_offload,
            })
            .map(|_dev| ()),
            // Netkit (the default container edge when the kernel supports it, via `Auto`): create the
            // L3 pair (primary in root netns, peer as the pod eth0). The netkit primary has no settable
            // MAC (L3, NOARP) — `mac` is carried only for map programming. `create_interface` attaches
            // `tc_guest_tx` on the netkit PEER hook (pod egress) via a raw bpf(BPF_LINK_CREATE).
            DeviceType::Netkit => {
                flowplane_device::netkit::create_netkit_pair(&flowplane_device::VethSpec {
                    host_name: device.clone(),
                    guest_name: guest_ifname.clone(),
                    netns_path: netns_path.to_string(),
                    mac,
                    mtu: self.guest_mtu as u32,
                    disable_csum_offload: self.disable_guest_csum_offload,
                })
                .map(|_dev| ())
            }
            DeviceType::Tap => self.setup_tap(&device, mac),
            DeviceType::PodTap => {
                self.setup_pod_tap(&device, netns_path, &guest_ifname, &tap_dev, mac)
            }
            DeviceType::Auto => unreachable!("Auto resolved to a concrete device type above"),
        };
        if let Err(e) = setup {
            let _ = run(&["ip", "link", "del", &device]);
            return Err(e);
        }

        // Delegate map-programming + datapath-attach to the legacy Control path (attaches
        // tc_guest_tx to the root-netns device and programs PORT_META/INTERFACES/INTERFACES6).
        let params = IfaceParams {
            vni,
            ipv4,
            ipv6,
            gateway_ipv4: self.gateway_ipv4,
            gateway_ipv6: self.gateway_ipv6,
            underlay_ipv6,
            total_mbps: 0,
            public_mbps: 0,
            l3,
        };
        if let Err(e) = self
            .control
            .create_interface(interface_id.as_bytes(), &device, params)
        {
            let _ = run(&["ip", "link", "del", &device]);
            return Err(e).context("program datapath for interface");
        }

        // Read the INTERFACES entry back out of the live map to prove it landed, and log a
        // greppable confirmation (the netns e2e asserts on this line; no bpftool in the dev shell).
        // A v6-only interface has no INTERFACES(v4) entry, so the read-back is only valid when ipv4
        // is present.
        if ipv4 != [0u8; 4] {
            match self.control.interface_readback(vni, ipv4) {
                Some(tap) => println!(
                    "INTERFACES readback vni={vni} ip={} -> tap_ifindex={tap}",
                    Ipv4Addr::from(ipv4)
                ),
                None => {
                    let _ = self.control.detach_interface(interface_id.as_bytes());
                    let _ = run(&["ip", "link", "del", &device]);
                    bail!("INTERFACES read-back failed after programming");
                }
            }
        }

        // Configure the container's pod netns with the overlay addr(s) + per-family default routes.
        // Containers only: Veth (L2, `via <gw>`) and Netkit (L3, on-link `default dev eth0`, no via)
        // don't self-config. VMs (Tap/PodTap) self-configure via DHCP/RA and must NOT be touched here.
        if matches!(resolved, DeviceType::Veth | DeviceType::Netkit) {
            if let Err(e) =
                flowplane_device::configure_guest_netns(&flowplane_device::GuestNetConfig {
                    netns_path: netns_path.to_string(),
                    guest_ifname: guest_ifname.clone(),
                    ipv4,
                    gateway_ipv4: self.gateway_ipv4,
                    ipv6,
                    gateway_ipv6: self.gateway_ipv6,
                    l3,
                })
            {
                // Roll back the programming + device we just claimed so a failed attach leaves no
                // half-configured state (mirrors the read-back failure path).
                let _ = self.control.detach_interface(interface_id.as_bytes());
                let _ = run(&["ip", "link", "del", &device]);
                return Err(e).context("configure guest netns");
            }
        }

        // `ifname` (computed before device creation) is the guest end for a veth/netkit or the tap
        // the caller points qemu at for a Tap/PodTap.
        Ok(self.make_outcome(ifname, ipv4, ipv6, mac, underlay_ipv6))
    }

    /// Build the `AttachOutcome` returned to the CNI. Shared by the normal success path and the
    /// idempotent-adopt path so a re-attach reports the identical {ips, mac, gateway, underlay} the
    /// first attach did.
    fn make_outcome(
        &self,
        ifname: String,
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        mac: [u8; 6],
        underlay_ipv6: [u8; 16],
    ) -> AttachOutcome {
        AttachOutcome {
            ifname,
            ips: {
                let mut v = Vec::new();
                if ipv4 != [0u8; 4] {
                    v.push(Ipv4Addr::from(ipv4).to_string());
                }
                if ipv6 != [0u8; 16] {
                    v.push(Ipv6Addr::from(ipv6).to_string());
                }
                v
            },
            mac: fmt_mac(mac),
            // v4 gateway string, or empty for a v6-only overlay (this interface has no v4 addr,
            // so the node's v4 gateway is meaningless to it — don't hand back a bogus gateway).
            gateway: if ipv4 == [0u8; 4] {
                String::new()
            } else {
                Ipv4Addr::from(self.gateway_ipv4).to_string()
            },
            underlay_route: Ipv6Addr::from(underlay_ipv6).to_string(),
        }
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
    ///
    /// `peer` and `tap` MUST be the names virt-launcher expects for a secondary-network
    /// domainAttachmentType:tap: `peer` = the pod link `pod<hash>` (= CNI_IFNAME, so phase-2 discovery
    /// finds it), `tap` = `tap<hash>` (= `GenerateTapDeviceName`, so `<target dev=…>` resolves). The
    /// caller derives both (`guest_ifname` / `kubevirt_secondary_tap_name`).
    fn setup_pod_tap(
        &self,
        host: &str,
        netns_path: &str,
        peer: &str,
        tap: &str,
        mac: [u8; 6],
    ) -> anyhow::Result<()> {
        // Idempotent on CNI-ADD retry: CRI/Multus retries the sandbox with the SAME interface_id
        // (pod UID is stable), so `host`/`peer`/`tap` names recur. A prior partial attach leaves the
        // root-netns host veth AND the pod-netns tap/peer behind; re-creating them then fails
        // (`RTNETLINK: File exists` on the veth, or `ioctl(TUNSETIFF): Device or resource busy` on the
        // tap), and the leaked devices accumulate (ifindex climbs every retry). Delete all three up
        // front (ignore "not found") so each attempt starts clean.
        let _ = run(&["ip", "link", "del", host]);
        let _ = run_netns(netns_path, &["ip", "link", "del", tap]);
        let _ = run_netns(netns_path, &["ip", "link", "del", peer]);
        // veth: host end in the root netns, peer created here then moved into the pod netns.
        run(&[
            "ip", "link", "add", host, "type", "veth", "peer", "name", peer,
        ])
        .context("create pod-tap veth pair")?;
        run(&["ip", "link", "set", peer, "netns", netns_path])
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
        run_netns(netns_path, &["ip", "link", "set", peer, "mtu", &mtu])
            .context("pod peer mtu")?;
        run_netns(netns_path, &["ip", "link", "set", peer, "up"]).context("pod peer up")?;

        // Point-to-point splice: clsact + a matchall `mirred` redirect each way (peer<->tap). No
        // bridge → no MAC learning → no gateway-at-own-MAC hairpin.
        run_netns(netns_path, &["tc", "qdisc", "add", "dev", tap, "clsact"])
            .context("clsact on pod tap")?;
        run_netns(netns_path, &["tc", "qdisc", "add", "dev", peer, "clsact"])
            .context("clsact on pod peer")?;
        run_netns(
            netns_path,
            &[
                "tc", "filter", "add", "dev", tap, "ingress", "matchall", "action", "mirred",
                "egress", "redirect", "dev", peer,
            ],
        )
        .context("mirred tap->peer")?;
        run_netns(
            netns_path,
            &[
                "tc", "filter", "add", "dev", peer, "ingress", "matchall", "action", "mirred",
                "egress", "redirect", "dev", tap,
            ],
        )
        .context("mirred peer->tap")?;

        // Offloads off on a software-uplink fabric (same rationale as setup_veth/setup_tap).
        if self.disable_guest_csum_offload {
            for dev in [tap, peer] {
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

    /// Detach: remove the datapath programming (which also removes INTERFACES/INTERFACES6) and
    /// delete the host-side veth (its guest peer disappears with it). No underlay to reclaim — the
    /// node VTEP is shared by every interface, never per-endpoint.
    pub fn detach(&self, interface_id: &str) -> anyhow::Result<()> {
        // Best-effort cleanup: run ALL reclaim steps regardless of a datapath-detach failure. If the
        // datapath detach errored and we returned early (the old behaviour), the host veth would leak
        // on every partial detach. Reclaim the veth unconditionally, then surface the datapath error.
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
        dp.map(|_| ())
    }
}

/// True iff `s` is a usable Linux network device name: non-empty, at most IFNAMSIZ-1 (15) bytes, and
/// free of `/`, whitespace, and the `.`/`..` special names (which `ip link set … name` rejects). Used
/// by `guest_ifname` to decide whether the CNI-supplied name can be used verbatim.
fn is_valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s != "."
        && s != ".."
        && !s
            .bytes()
            .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
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
    fn is_valid_ifname_accepts_and_rejects() {
        assert!(is_valid_ifname("net1"));
        assert!(is_valid_ifname("eth0"));
        assert!(is_valid_ifname("nic-a"));
        assert!(is_valid_ifname("012345678901234")); // 15 bytes
        assert!(!is_valid_ifname("")); // empty
        assert!(!is_valid_ifname("0123456789012345")); // 16 bytes > IFNAMSIZ-1
        assert!(!is_valid_ifname("uid/net1")); // contains '/'
        assert!(!is_valid_ifname("a:b")); // contains ':'
        assert!(!is_valid_ifname("a b")); // whitespace
        assert!(!is_valid_ifname(".")); // special
        assert!(!is_valid_ifname("..")); // special
    }

    #[test]
    fn guest_ifname_extracts_cni_ifname_from_uid_slash_ifname() {
        // The CNI passes `<pod-uid>/<cni-ifname>` — the guest link must be the valid trailing name.
        assert_eq!(
            AttachState::guest_ifname("3889a54a-a2a8-4bb9-a5c0-6e0a1c24f4a9/net1"),
            "net1"
        );
        assert_eq!(
            AttachState::guest_ifname("3889a54a-a2a8-4bb9-a5c0-6e0a1c24f4a9/eth0"),
            "eth0"
        );
    }

    #[test]
    fn guest_ifname_passes_through_clean_ids() {
        // A gRPC-driven caller with a clean, valid id keeps it verbatim (no `/`, <=15 chars).
        assert_eq!(AttachState::guest_ifname("nic-a"), "nic-a");
        assert_eq!(AttachState::guest_ifname("t0"), "t0");
    }

    #[test]
    fn guest_ifname_hashes_when_trailing_component_is_invalid() {
        // A trailing component that is itself too long / invalid falls back to a stable hash.
        let long_tail = "uid/this-name-is-way-too-long-for-ifnamsiz";
        let n = AttachState::guest_ifname(long_tail);
        assert!(is_valid_ifname(&n), "{n} must be a valid device name");
        assert!(n.starts_with("g-"));
        // Deterministic (same id -> same name), so detach/re-attach agree.
        assert_eq!(n, AttachState::guest_ifname(long_tail));
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
        // Empty and "auto" both mean "let the node choose" (Auto); "veth"/"netkit" are explicit.
        assert_eq!(DeviceType::parse("").unwrap(), DeviceType::Auto);
        assert_eq!(DeviceType::parse("auto").unwrap(), DeviceType::Auto);
        assert_eq!(DeviceType::parse("veth").unwrap(), DeviceType::Veth);
        assert_eq!(DeviceType::parse("netkit").unwrap(), DeviceType::Netkit);
        assert_eq!(DeviceType::parse("tap").unwrap(), DeviceType::Tap);
        assert_eq!(DeviceType::parse("pod-tap").unwrap(), DeviceType::PodTap);
        assert!(DeviceType::parse("bridge").is_err());
    }

    #[test]
    fn device_type_requires_mac() {
        // A VM's MAC must match the datapath's guest_mac; a container derives one. Netkit is an L3
        // container edge with no settable MAC, so like veth/auto it must NOT require one.
        assert!(!DeviceType::Auto.requires_mac());
        assert!(!DeviceType::Veth.requires_mac());
        assert!(!DeviceType::Netkit.requires_mac());
        assert!(DeviceType::Tap.requires_mac());
        assert!(DeviceType::PodTap.requires_mac());
    }

    /// The pod-tap tap name MUST match KubeVirt's `GenerateTapDeviceName` for a secondary network:
    /// "tap" + podInterfaceName[3:] (strip the `pod`/`net` prefix). virt-launcher looks this up by
    /// name; a mismatch (e.g. the old literal "tap0") is the "Link not found" boot failure.
    #[test]
    fn kubevirt_secondary_tap_name_matches_virtlauncher() {
        // pod<hash> pod link -> tap<hash> (KubeVirt strips "pod", prepends "tap").
        assert_eq!(
            AttachState::kubevirt_secondary_tap_name("pod9404eea3257"),
            "tap9404eea3257"
        );
        // Ordinal net<N> pod link -> tap<N> (same strip-3 rule).
        assert_eq!(AttachState::kubevirt_secondary_tap_name("net2"), "tap2");
        // Fits IFNAMSIZ (pod<hash> is 14 chars -> tap<hash> is 14).
        assert!(AttachState::kubevirt_secondary_tap_name("pod9404eea3257").len() <= 15);
        // Never the primary-only "tap0", which KubeVirt does not look up on a secondary network.
        assert_ne!(
            AttachState::kubevirt_secondary_tap_name("pod9404eea3257"),
            "tap0"
        );
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
