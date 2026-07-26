//! Backend-agnostic guest-port pool lifecycle. VethBackend (containers) is implemented; TapBackend
//! (VMs) + VfBackend (SR-IOV real NIC) are documented SEAMS (spec 2026-07-26). The lifecycle is
//! IDENTICAL across kinds — only device mechanics differ — keeping software mode + real-NIC VFs
//! structurally the same (assign/release mirror a CNI re-homing a VF between PF and pod).
//!
//! ── WHY A TRAIT ────────────────────────────────────────────────────────────────────────────────
//! The DPDK serve loop runs a VF-style PREALLOCATED per-guest af_xdp pool: N host devices created
//! BEFORE EAL init (each handed to EAL as `--vdev=net_af_xdp<i>,iface=<name>`), a STATIC poll set,
//! with attach ASSIGNING a free slot's guest-facing device into a pod and detach RELEASING it back.
//! Today the ONLY device kind is veth (containers); tomorrow VMs want a kernel TAP and real NICs want
//! an SR-IOV VF. The lifecycle steps (preallocate / assign / release / is_alive / recover / teardown)
//! are the SAME for all three — only the underlying device mechanics differ — so a single
//! [`GuestPortBackend`] trait fronts them and the serve/attach/detach paths stay backend-agnostic.
//!
//! ── SEAMS (NOT built here) ─────────────────────────────────────────────────────────────────────
//! `TapBackend` (VM/KubeVirt guests, `preallocate` = create a kernel TAP, `assign`/`release` = hand
//! the tap fd to qemu) and `VfBackend` (real ConnectX SR-IOV, `preallocate` = a PF-hosted VF,
//! `assign`/`release` = re-home the VF representor between PF and pod) are documented FOLLOW-UP seams.
//! Do NOT create their structs until their tasks land — this module ships ONLY the trait + the
//! `VethBackend` impl (the behavior-preserving refactor of the existing veth pool mechanics).
use anyhow::Result;

use crate::attach_state::GuestPortSlot;

/// The consumer of an assigned guest-facing device: the pod's netns + the in-netns interface name.
/// For veth/vf this is the pod netns path + the guest ifname (the guest's `eth0`-equivalent).
pub struct AssignTarget {
    pub netns_path: String,
    pub guest_ifname: String,
}

/// A preallocated pool HOST device: the netdev name (for `--vdev=net_af_xdp<n>,iface=<name>`) + its
/// resolved ifindex (the key `PortMeta`/`ports_get` is keyed by in the datapath).
pub struct HostDevice {
    pub host_ifname: String,
    pub host_ifindex: u32,
}

/// Lifecycle of one preallocated guest-port pool slot, abstracted over the device kind (veth today;
/// tap/vf are documented seams). Every method is device-mechanics-only — the pool bookkeeping
/// (reserve/free/dead-slot marking) stays in the attach/detach handlers, which call THESE to touch
/// the actual device. `Send + Sync` so the serve loop can hold it as `Arc<dyn GuestPortBackend>` and
/// clone it into `spawn_blocking` closures (the device ops shell out to `ip`).
pub trait GuestPortBackend: Send + Sync {
    /// Create the pool HOST device for slot `index` BEFORE EAL init; returns the netdev name (for
    /// `--vdev=net_af_xdp<n>,iface=<name>`) + resolved ifindex.
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice>;
    /// Assign the guest-facing device (derived from `host_ifname`) into the consumer (pod netns for
    /// veth/vf).
    fn assign(
        &self,
        host_ifname: &str,
        target: &AssignTarget,
        mac: [u8; 6],
        mtu: u32,
    ) -> Result<()>;
    /// Release the guest-facing device back to the pool's idle/holding state. Best-effort.
    fn release(&self, host_ifname: &str, target: &AssignTarget);
    /// Is the slot's HOST device (the af_xdp ethdev's backing netdev) still alive?
    fn is_alive(&self, slot: &GuestPortSlot) -> bool;
    /// Recover a slot whose host device died (ungraceful teardown). Filled in by G3 (Task 6).
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32>;
    /// Destroy a preallocated host device (`host_ifname`). Startup rollback G5 + shutdown.
    /// Idempotent/best-effort.
    fn teardown(&self, host_ifname: &str);
}

/// The container/veth backend: preallocated pool devices are root-netns veth pairs (`fpg{i}` host-end
/// up + bound to the af_xdp ethdev port, `fpg{i}p` placeholder guest-end parked in the root netns).
/// `assign` moves the placeholder guest-end into the pod netns; `release` moves it back. Wraps the
/// existing `flowplane_device` veth ops 1:1 — a pure refactor of the mechanics already in serve/node.
pub struct VethBackend;

impl GuestPortBackend for VethBackend {
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice> {
        let host = format!("fpg{index}");
        // SAME placeholder MAC scheme serve.rs used inline (02:00:00:00:0e:<i>). Not
        // datapath-significant — the real guest MAC is programmed at attach; kept identical so the
        // refactor is byte-for-byte behavior-preserving.
        let mac = [0x02, 0x00, 0x00, 0x00, 0x0e, index as u8];
        let d = flowplane_device::create_preallocated_veth(&host, mac, mtu)?;
        Ok(HostDevice {
            host_ifname: d.host_name,
            host_ifindex: d.host_ifindex,
        })
    }

    fn assign(&self, host_ifname: &str, t: &AssignTarget, mac: [u8; 6], mtu: u32) -> Result<()> {
        // The placeholder guest-end lives in the root netns as `<host_ifname>p` (the
        // create_preallocated_veth convention); move it into the pod netns as `guest_ifname`.
        // `false` = don't disable csum offload (real NIC finalizes csum; clab detection is a
        // follow-up — identical to the value serve/node passed inline).
        let peer = format!("{host_ifname}p");
        flowplane_device::bind_preallocated_guest_end(
            &peer,
            &t.netns_path,
            &t.guest_ifname,
            mac,
            mtu,
            false,
        )
    }

    fn release(&self, host_ifname: &str, t: &AssignTarget) {
        // Move the guest-end back to the root netns as the placeholder `<host_ifname>p`. Best-effort
        // (always Ok internally): a destroyed pod netns is a documented first-slice limitation.
        let peer = format!("{host_ifname}p");
        let _ =
            flowplane_device::unbind_preallocated_guest_end(&t.netns_path, &t.guest_ifname, &peer);
    }

    fn is_alive(&self, slot: &GuestPortSlot) -> bool {
        // A cheap sysfs stat (no subprocess) — safe under the std pool Mutex, exactly as the inline
        // `link_exists` dead-slot checks were.
        flowplane_device::link_exists(&slot.host_ifname)
    }

    fn recover(&self, _slot: &mut GuestPortSlot, _pool_port_id: u16) -> Result<u32> {
        // Live dead-slot recovery (recreate the veth + rte_dev hotplug rebind the af_xdp vdev +
        // reconfigure the ethdev port) is G3 (Task 6). Not wired here.
        anyhow::bail!("VethBackend::recover not implemented until G3 (Task 6)")
    }

    fn teardown(&self, host_ifname: &str) {
        // Idempotent host-device delete (deletes the peer too). Used by startup rollback (G5) +
        // shutdown. Best-effort — `delete_link` ignores a missing link.
        flowplane_device::delete_link(host_ifname);
    }
}
