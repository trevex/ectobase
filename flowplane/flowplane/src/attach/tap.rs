//! tap / pod-tap device setup for VM-backed interfaces.
//!
//! Both create the root-netns datapath device (which `Control::create_interface` later attaches
//! `tc_guest_tx` to, exactly as for a container veth host end) — they differ only in HOW the device
//! is created and how the guest (qemu) reaches it: `setup_tap` is a single root-netns tap whose fd is
//! handed to qemu; `setup_pod_tap` is the KubeVirt-compatible topology (a root-netns netkit-L2
//! primary spliced to a pod-netns tap by `tc mirred`). Split out of `mod.rs` (review P1.2). The shell
//! wrappers (`run`/`run_netns`) and `fmt_mac` come from the parent/`naming` modules.

use anyhow::Context;

use super::naming::fmt_mac;
use super::{run, run_netns, AttachState};

impl AttachState {
    /// Create + configure a root-netns tap for a VM: a single device (no netns move, no peer),
    /// symmetric with the container host-veth. qemu drives it (by name, or by opening its fd).
    /// `create_interface` attaches `tc_guest_tx` and programs the maps afterwards, exactly as for the
    /// veth host end — so only device creation differs. Proven by `test/tap-vm-smoke.sh` (a real VM).
    pub(super) fn setup_tap(&self, tap: &str, mac: [u8; 6]) -> anyhow::Result<()> {
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

    /// Create the KubeVirt-compatible pod-netns tap topology: a **netkit-L2 pair** whose PRIMARY
    /// (`host`, root netns) is the datapath device (`tc_guest_tx` via the BPF_NETKIT_PEER hook +
    /// `uplink_rx` target), whose PEER moves into the pod netns as the pod link (`pod<hash>`), plus a
    /// `tap` in the pod netns that qemu drives. The peer and tap are spliced point-to-point with `tc
    /// mirred` — leaner than a Linux bridge (no MAC-learning / STP / unicast flooding): `mirred`
    /// shovels every frame peer<->tap unconditionally, so all guest egress reaches `tc_guest_tx` on the
    /// netkit primary and delivery reaches the VM, regardless of L2 addressing. netkit replaces the
    /// veth pair (the container edge already uses netkit) — no veth on the VM path. `create_interface`
    /// attaches the datapath to `host` via netkit (params.netkit), with L2 semantics (params.l3=false).
    ///
    /// `peer` and `tap` MUST be the names virt-launcher expects for a secondary-network
    /// domainAttachmentType:tap: `peer` = the pod link `pod<hash>` (= CNI_IFNAME, so phase-2 discovery
    /// finds it), `tap` = `tap<hash>` (= `GenerateTapDeviceName`, so `<target dev=…>` resolves). The
    /// caller derives both (`guest_ifname` / `kubevirt_secondary_tap_name`).
    pub(super) fn setup_pod_tap(
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
        // netkit-L2 pair: `host` (primary) is the root-netns datapath device (tc_guest_tx via the
        // BPF_NETKIT_PEER hook + uplink_rx target), `peer` (= pod<hash>) is the pod-netns pod link
        // KubeVirt discovers. L2 mode (eth-framed, real settable MAC) — a KubeVirt VM reads the pod
        // link's MAC and libvirt rejects the L3 mode's zeroed MAC. `create_netkit_pair` creates the
        // pair, moves + renames the peer to `peer`, sets its MAC, and brings both ends up at guest_mtu.
        flowplane_device::netkit::create_netkit_pair(
            &flowplane_device::VethSpec {
                host_name: host.to_string(),
                guest_name: peer.to_string(),
                netns_path: netns_path.to_string(),
                mac,
                mtu: self.guest_mtu as u32,
                disable_csum_offload: self.disable_guest_csum_offload,
            },
            flowplane_device::NetkitMode::L2,
        )
        .context("create pod-tap netkit-L2 pair")?;

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
        // (`peer` is already up at guest_mtu — create_netkit_pair brought it up.)

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
}
