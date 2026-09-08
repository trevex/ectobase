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
use crate::error::ServiceError;

mod naming;
mod tap;

use naming::{fmt_mac, parse_mac, primary_ipv4, primary_ipv6};

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
    /// connected to a root-netns **netkit-L2** primary by `tc mirred`. The netkit primary is the
    /// datapath device (`tc_guest_tx` via the BPF_NETKIT_PEER hook + `uplink_rx` target), its peer is
    /// the pod link (`pod<hash>`); the pod-netns `mirred` splice bridges that peer to the tap. netkit
    /// (not veth) — the container edge already uses netkit, so no veth on the VM path either. L2 mode
    /// (real MAC): a KubeVirt VM reads the pod link's MAC and libvirt rejects the L3 zeroed MAC. A
    /// point-to-point `mirred` splice (rather than a bridge) keeps it lean — no MAC-learning / STP /
    /// flooding — and forwards regardless of L2 addressing. MAC required (same reason as `Tap`).
    PodTap,
    /// Container/VM (SR-IOV offload): a pre-provisioned VF whose switchdev REPRESENTOR (root netns)
    /// is the datapath device running `tc_guest_tx`; the VF itself is moved into the guest netns.
    /// L2 with a real MAC; `peer_capable=false` (switchdev delivers the VF, no bpf_redirect_peer);
    /// `offloaded=true` (recorded into PORT_META for the later flow-offload increment). Requires
    /// `pci_address` in the request.
    Vf,
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
            "vf" => Ok(DeviceType::Vf),
            other => {
                bail!(
                    "unknown device_type {other:?} \
                     (want \"\"/\"auto\", \"veth\", \"netkit\", \"tap\", \"pod-tap\", or \"vf\")"
                )
            }
        }
    }

    /// Whether this device type requires an explicit VM MAC (local delivery rewrites the frame dst to
    /// `guest_mac`, so a derived MAC would silently drop every inbound frame to the VM).
    fn requires_mac(self) -> bool {
        matches!(self, DeviceType::Tap | DeviceType::PodTap | DeviceType::Vf)
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
        pci_address: &str,
    ) -> Result<AttachOutcome, ServiceError> {
        if interface_id.is_empty() {
            return Err(ServiceError::Invalid("interface_id is required".into()));
        }
        // A tap serves a VM whose virtio NIC has a fixed MAC; local delivery rewrites the frame dst to
        // `guest_mac`, so the programmed MAC must equal the VM's — a derived one would silently drop
        // every inbound frame. Require it explicitly rather than deriving.
        if device_type.requires_mac() && mac_req.is_empty() {
            return Err(ServiceError::Invalid(format!(
                "device_type={device_type:?} requires an explicit mac (the VM NIC MAC)"
            )));
        }
        if device_type == DeviceType::Vf && pci_address.is_empty() {
            return Err(ServiceError::Invalid(
                "device_type=vf requires pci_address (the VF PCI BDF)".into(),
            ));
        }
        // Overlay IPs: at least ONE family is required; either may be absent (all-zeros).
        let ipv4 = primary_ipv4(requested_ips).unwrap_or([0u8; 4]);
        let ipv6 = primary_ipv6(requested_ips);
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            return Err(ServiceError::Invalid(
                "attach requires at least one overlay IP (IPv4 or IPv6) in requested_ips".into(),
            ));
        }

        // MAC: honour a caller-supplied MAC, else derive a stable one from the interface_id (so a
        // detach+re-attach reuses the same MAC — see `mac_for`).
        let mac = if mac_req.is_empty() {
            Self::mac_for(interface_id)
        } else {
            parse_mac(mac_req).map_err(|e| ServiceError::Invalid(format!("invalid mac: {e:#}")))?
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
        // SR-IOV VF: claim the pre-provisioned VF now (we need the representor name as the datapath
        // device). The VF moves into the pod netns as `guest_ifname`; the representor stays in the
        // root netns as the tc_guest_tx device. Unlike veth/netkit there is no name we can predict
        // before claiming, so VF resolves device/ifname here rather than in the generic matches below.
        if resolved == DeviceType::Vf {
            let ifname = Self::guest_ifname(interface_id);
            // Idempotency FIRST, before ANY device work — same invariant the generic path relies on
            // (see the long comment at the `overlay_status` match below): a KubeVirt virt-launcher
            // attaches the same NIC via two interface_ids, so the 2nd ADD must adopt the 1st (return
            // its outcome, claim NO 2nd VF) or it wedges the pod sandbox. `overlay_status` keys only on
            // (vni, ip, mac) — none depend on the representor name — so claiming can wait until `Free`.
            // A Conflict bails before claiming, so no VF was moved and no release is needed here.
            match self.control.overlay_status(vni, ipv4, ipv6, mac) {
                OverlayStatus::SameEndpoint => {
                    return Ok(self.make_outcome(ifname, ipv4, ipv6, mac, underlay_ipv6));
                }
                OverlayStatus::Conflict => {
                    return Err(ServiceError::Conflict(
                        "ROUTE_EXISTS: IP already in use in this VNI".into(),
                    ))
                }
                OverlayStatus::Free => {}
            }
            let dev = flowplane_device::claim_vf(&flowplane_device::sriov::VfSpec {
                pci_address: pci_address.to_string(),
                netns_path: (!netns_path.is_empty()).then(|| netns_path.to_string()),
                guest_name: Self::guest_ifname(interface_id),
                mac,
                mtu: self.guest_mtu as u32,
            })
            .context("claim VF")?;
            let device = dev.host_name; // the representor
            let params = IfaceParams {
                vni,
                ipv4,
                ipv6,
                gateway_ipv4: self.gateway_ipv4,
                gateway_ipv6: self.gateway_ipv6,
                underlay_ipv6,
                total_mbps: 0,
                public_mbps: 0,
                netkit: false, // representor takes tc_guest_tx via tcx/clsact, not netkit
                l3: false,     // VF is L2 with a real MAC
                peer_capable: false, // switchdev delivers the VF; no bpf_redirect_peer
                offloaded: true, // recorded into PORT_META for the later flow-offload increment
            };
            if let Err(e) = self
                .control
                .create_interface(interface_id.as_bytes(), &device, params)
            {
                let _ = flowplane_device::release_vf(
                    pci_address,
                    (!netns_path.is_empty()).then_some(netns_path),
                    &Self::guest_ifname(interface_id),
                );
                return Err(ServiceError::Internal(
                    e.context("program datapath for VF interface"),
                ));
            }
            if ipv4 != [0u8; 4] {
                if let Some(tap) = self.control.interface_readback(vni, ipv4) {
                    println!(
                        "INTERFACES readback vni={vni} ip={} -> tap_ifindex={tap}",
                        Ipv4Addr::from(ipv4)
                    );
                } else {
                    let _ = self.control.detach_interface(interface_id.as_bytes());
                    // Symmetric with the create_interface-Err arm above: release the claimed VF too,
                    // else it leaks (parked in the guest netns, unreclaimable) — VFs are a scarce
                    // hardware resource, unlike a veth we could just `ip link del`.
                    let _ = flowplane_device::release_vf(
                        pci_address,
                        (!netns_path.is_empty()).then_some(netns_path),
                        &Self::guest_ifname(interface_id),
                    );
                    return Err(ServiceError::Internal(anyhow::anyhow!(
                        "INTERFACES read-back failed after programming VF"
                    )));
                }
            }
            // Configure the pod netns with the overlay addr(s) + default routes — flowplane's CNI is
            // IPAM-less, so the dataplane assigns the guest IP INSIDE the netns (mirrors the generic
            // container path below). A VF is an L2 container edge (real MAC, `via <gw>` routes), so
            // `l3: false`. Skipped when there is no netns (a root-netns local test / a self-configuring
            // VM handed the VF directly). Roll back (detach + release the VF) on failure.
            if !netns_path.is_empty() {
                if let Err(e) =
                    flowplane_device::configure_guest_netns(&flowplane_device::GuestNetConfig {
                        netns_path: netns_path.to_string(),
                        guest_ifname: ifname.clone(),
                        ipv4,
                        gateway_ipv4: self.gateway_ipv4,
                        ipv6,
                        gateway_ipv6: self.gateway_ipv6,
                        l3: false,
                    })
                {
                    let _ = self.control.detach_interface(interface_id.as_bytes());
                    let _ = flowplane_device::release_vf(
                        pci_address,
                        (!netns_path.is_empty()).then_some(netns_path),
                        &Self::guest_ifname(interface_id),
                    );
                    return Err(ServiceError::Internal(
                        e.context("configure guest netns for VF"),
                    ));
                }
            }
            return Ok(self.make_outcome(ifname, ipv4, ipv6, mac, underlay_ipv6));
        }
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
            DeviceType::Vf => unreachable!("Vf handled in its dedicated branch above"),
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
            DeviceType::Vf => unreachable!("Vf handled in its dedicated branch above"),
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
            OverlayStatus::Conflict => {
                return Err(ServiceError::Conflict(
                    "ROUTE_EXISTS: IP already in use in this VNI".into(),
                ))
            }
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
            DeviceType::Netkit => flowplane_device::netkit::create_netkit_pair(
                &flowplane_device::VethSpec {
                    host_name: device.clone(),
                    guest_name: guest_ifname.clone(),
                    netns_path: netns_path.to_string(),
                    mac,
                    mtu: self.guest_mtu as u32,
                    disable_csum_offload: self.disable_guest_csum_offload,
                },
                flowplane_device::NetkitMode::L3,
            )
            .map(|_dev| ()),
            DeviceType::Tap => self.setup_tap(&device, mac),
            DeviceType::PodTap => {
                self.setup_pod_tap(&device, netns_path, &guest_ifname, &tap_dev, mac)
            }
            DeviceType::Auto => unreachable!("Auto resolved to a concrete device type above"),
            DeviceType::Vf => unreachable!("Vf handled in its dedicated branch above"),
        };
        if let Err(e) = setup {
            let _ = run(&["ip", "link", "del", &device]);
            return Err(e.into());
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
            // Attach via netkit (BPF_NETKIT_PEER) for BOTH the container netkit edge AND the VM
            // pod-tap edge (its datapath device is now a netkit-L2 primary, not a veth). `l3` stays
            // the L2/L3 SEMANTIC — true only for the container netkit-L3 edge, false for the L2 VM tap.
            netkit: matches!(resolved, DeviceType::Netkit | DeviceType::PodTap),
            l3,
            // Peer-capable = local delivery may use bpf_redirect_peer (inject at the pod-netns peer's
            // ingress). Only the CONTAINER edges qualify: for veth/netkit the peer IS the pod's eth0,
            // so peer-ingress delivery reaches the guest. PodTap is EXCLUDED: its netkit peer is an
            // intermediary spliced to the qemu tap by a pod-netns `tc mirred` on the peer's ingress,
            // and bpf_redirect_peer bypasses that ingress mirred (the frame lands in the peer's stack,
            // never the tap) — proven live (VM ping broke). A root-netns `Tap` has no peer either. So
            // VMs keep plain bpf_redirect: primary xmit → netkit forward → peer RX → mirred → tap.
            peer_capable: matches!(resolved, DeviceType::Veth | DeviceType::Netkit),
            // Task 4 flips this to true for VF attach; every existing device type keeps behavior
            // identical (not hardware-offload-eligible) for now.
            offloaded: false,
        };
        if let Err(e) = self
            .control
            .create_interface(interface_id.as_bytes(), &device, params)
        {
            let _ = run(&["ip", "link", "del", &device]);
            return Err(ServiceError::Internal(
                e.context("program datapath for interface"),
            ));
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
                    return Err(ServiceError::Internal(anyhow::anyhow!(
                        "INTERFACES read-back failed after programming"
                    )));
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
                return Err(ServiceError::Internal(e.context("configure guest netns")));
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

    /// Detach: remove the datapath programming (which also removes INTERFACES/INTERFACES6) and
    /// delete the host-side veth (its guest peer disappears with it). No underlay to reclaim — the
    /// node VTEP is shared by every interface, never per-endpoint.
    pub fn detach(&self, interface_id: &str) -> Result<(), ServiceError> {
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
        // KNOWN LIMITATION (SR-IOV VF path): a VF interface is NOT explicitly reclaimed here — detach
        // only has the interface_id, and neither the VF PCI address nor the representor is persisted
        // per-interface, so `sriov::release_vf` cannot be called. In the standard k8s SR-IOV model this
        // is acceptable: the device plugin owns VF allocation/reclaim by PCI address, and the kernel
        // auto-returns a VF to the root netns when the pod netns is destroyed. Explicit VF release on
        // detach (persisting the PCI/netns in the interface record + threading it through
        // DetachInterface) is a tracked follow-up, designed together with the CNI/device-plugin
        // integration — see the spec's deferred-work section. The map-side state IS cleaned above.
        dp.map(|_| ()).map_err(ServiceError::from)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uplink_finalizes_checksum_false_for_virtual_and_missing() {
        // Loopback is a virtual device (no /sys/class/net/lo/device) → cannot finalize in HW.
        assert!(!uplink_finalizes_checksum("lo"));
        // A non-existent interface also has no device link → false (errs toward "software").
        assert!(!uplink_finalizes_checksum("definitely-not-an-iface-xyz"));
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
    fn device_type_parse_vf() {
        assert_eq!(DeviceType::parse("vf").unwrap(), DeviceType::Vf);
        assert!(
            DeviceType::Vf.requires_mac(),
            "a VF needs an explicit guest MAC"
        );
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
}
