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
//! ── SEAMS (partially built) ────────────────────────────────────────────────────────────────────
//! `TapBackend` (VM/KubeVirt guests, `preallocate` = create a persistent kernel TAP netdev,
//! `assign`/`release` = no-ops beyond the target kind assertion — qemu holds the guest-facing fd) is
//! implemented here alongside `VethBackend`. `VfBackend` (real ConnectX SR-IOV, `preallocate` = a
//! PF-hosted VF, `assign`/`release` = re-home the VF representor between PF and pod) remains a
//! documented FOLLOW-UP seam — do NOT create its struct until its task lands.
use anyhow::Result;

use crate::attach_state::GuestPortSlot;

/// The consumer of an assigned guest-facing device, made TYPE-DISTINCT per device kind so a backend
/// can never be handed a target it can't service. `Veth` carries the pod netns path (the guest-end
/// veth moves INTO it) + the in-netns guest ifname; `Tap` carries only the guest ifname because the
/// tap netdev STAYS in the serve netns (qemu holds the guest-facing fd — there is no netns move).
///
/// The right variant is built by [`GuestPortBackend::assign_target`] so callers (node.rs) stay
/// backend-agnostic: they hand the raw attach inputs (netns_path + guest_ifname) to the backend and
/// get back the variant that backend's `assign`/`release` expect.
pub enum AssignTarget {
    /// Container/veth consumer: the guest-end veth is moved into `netns_path` as `guest_ifname`.
    Veth {
        netns_path: String,
        guest_ifname: String,
    },
    /// VM/tap consumer: no netns — the tap netdev stays in the serve netns; qemu holds the fd. Only
    /// the guest ifname is carried (for symmetry/logging); there is no bind/unbind of the netdev.
    Tap { guest_ifname: String },
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
    /// Build the backend-appropriate [`AssignTarget`] from the raw attach inputs (keeps callers
    /// agnostic — node.rs never picks the variant). Veth → `AssignTarget::Veth`, tap → `Tap` (which
    /// discards `netns_path`).
    fn assign_target(&self, netns_path: String, guest_ifname: String) -> AssignTarget;
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
    /// Recover a slot whose host device died (ungraceful teardown).
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32>;
    /// Destroy a preallocated host device (`host_ifname`). Startup rollback + shutdown.
    /// Idempotent/best-effort.
    fn teardown(&self, host_ifname: &str);
}

/// The container/veth backend: preallocated pool devices are root-netns veth pairs (`fpg{i}` host-end
/// up + bound to the af_xdp ethdev port, `fpg{i}p` placeholder guest-end parked in the root netns).
/// `assign` moves the placeholder guest-end into the pod netns; `release` moves it back. Wraps the
/// existing `flowplane_device` veth ops 1:1 — a pure refactor of the mechanics already in serve/node.
///
/// `mtu` is the guest link MTU (underlay MTU − encap overhead) — the SAME value `serve.rs` uses at
/// preallocation. `recover` needs it to recreate the veth with the identical link MTU the original
/// pool device had, so a recovered slot's guest link is indistinguishable from a fresh one.
pub struct VethBackend {
    pub mtu: u32,
}

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

    fn assign_target(&self, netns_path: String, guest_ifname: String) -> AssignTarget {
        AssignTarget::Veth {
            netns_path,
            guest_ifname,
        }
    }

    fn assign(&self, host_ifname: &str, t: &AssignTarget, mac: [u8; 6], mtu: u32) -> Result<()> {
        // Only a Veth target is valid here — `assign_target` guarantees it, but the enum makes a
        // mismatched kind a hard programmer error rather than a silent wrong-path.
        match t {
            AssignTarget::Veth {
                netns_path,
                guest_ifname,
            } => {
                // The placeholder guest-end lives in the root netns as `<host_ifname>p` (the
                // create_preallocated_veth convention); move it into the pod netns as `guest_ifname`.
                // `false` = don't disable csum offload (real NIC finalizes csum; clab detection is a
                // follow-up — identical to the value serve/node passed inline).
                let peer = format!("{host_ifname}p");
                flowplane_device::bind_preallocated_guest_end(
                    &peer,
                    netns_path,
                    guest_ifname,
                    mac,
                    mtu,
                    false,
                )
            }
            AssignTarget::Tap { .. } => unreachable!("VethBackend received a Tap target"),
        }
    }

    fn release(&self, host_ifname: &str, t: &AssignTarget) {
        match t {
            AssignTarget::Veth {
                netns_path,
                guest_ifname,
            } => {
                // Move the guest-end back to the root netns as the placeholder `<host_ifname>p`.
                // Best-effort (always Ok internally): a destroyed pod netns is a documented
                // first-slice limitation.
                let peer = format!("{host_ifname}p");
                let _ = flowplane_device::unbind_preallocated_guest_end(
                    netns_path,
                    guest_ifname,
                    &peer,
                );
            }
            AssignTarget::Tap { .. } => unreachable!("VethBackend received a Tap target"),
        }
    }

    fn is_alive(&self, slot: &GuestPortSlot) -> bool {
        // A cheap sysfs stat (no subprocess) — safe under the std pool Mutex, exactly as the inline
        // `link_exists` dead-slot checks were.
        flowplane_device::link_exists(&slot.host_ifname)
    }

    /// Live dead-slot recovery, DEVICE-MECHANICS HALF ONLY. Recreates the dead slot's veth pair and
    /// hot-rebinds its af_xdp vdev against the new host-end, then updates the slot's `host_ifindex` +
    /// clears `dead`. Returns the NEW host ifindex.
    ///
    /// ── SPLIT OF RESPONSIBILITY (deliberate) ────────────────────────────────────────────────────
    /// `recover` does the `Send` control-plane device work: `delete_link` the stale remnant, recreate
    /// the veth (same placeholder-MAC scheme), hot-REMOVE the (possibly-already-gone) dead vdev, and
    /// hot-ADD it against the fresh host-end. It does NOT `Port::configure` the re-added ethdev — that
    /// needs a `&Mempool` and must produce a `Port` to SWAP into the worker's shared cell + bump the
    /// generation, all of which is control-path orchestration that lives in `serve.rs` (see
    /// `serve::RecoverHandle::recover_slot`). The re-added ethdev's actual port id is NOT assumed to
    /// equal `pool_port_id` (DPDK assigns the lowest FREE id after the dead port closed); the caller
    /// re-resolves it via `nfkit::port_by_name`. This keeps `recover` free of the mempool/Port/worker
    /// coupling and testable at the pure device-mechanics level.
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32> {
        // Delete any stale remnant of the dead pair (the host-end may linger even after the guest-end
        // vanished, or a prior partial recovery may have left one) so `create_preallocated_veth` gets
        // a clean name. Best-effort/idempotent (ignores a missing link).
        flowplane_device::delete_link(&slot.host_ifname);
        // Recreate the veth with the SAME deterministic placeholder MAC scheme preallocation used
        // (02:00:00:00:0e:<i>, where `i = pool_port_id - 1` since uplink = port 0, guests = 1..=N),
        // at the guest link MTU. The real guest MAC is (re)programmed at the next attach.
        let dev = flowplane_device::create_preallocated_veth(
            &slot.host_ifname,
            [0x02, 0, 0, 0, 0x0e, (pool_port_id.saturating_sub(1)) as u8],
            self.mtu,
        )?;
        // Hot-remove the dead vdev first (best-effort — a fully-torn-down vdev may already be gone,
        // in which case remove errors harmlessly), then hot-add it against the fresh host-end. The
        // vdev device name is stable across recovery (`net_af_xdp<pool_port_id>`); only the backing
        // netdev + the resulting ethdev port id change.
        let vdev = format!("net_af_xdp{pool_port_id}");
        let _ = nfkit::hotplug_remove("vdev", &vdev);
        nfkit::hotplug_add(
            "vdev",
            &vdev,
            &format!("iface={},start_queue=0,queue_count=1", slot.host_ifname),
        )?;
        // Update the slot: new host ifindex (PortMeta/registry/free-slot key) + no longer dead. The
        // caller re-resolves the ethdev port id (via `port_by_name`), `Port::configure`s it, swaps it
        // into the worker's shared cell, and bumps the generation — NONE of which happens here.
        slot.host_ifindex = dev.host_ifindex;
        slot.dead = false;
        Ok(dev.host_ifindex)
    }

    fn teardown(&self, host_ifname: &str) {
        // Idempotent host-device delete (deletes the peer too). Used by startup rollback +
        // shutdown. Best-effort — `delete_link` ignores a missing link.
        flowplane_device::delete_link(host_ifname);
    }
}

/// The VM/KubeVirt guest-port backend: preallocated pool devices are PERSISTENT kernel TAP netdevs
/// (`fpgtap{i}`), each up in the serve netns + bound to its af_xdp ethdev port. Unlike veth there is
/// NO netns move at attach — the tap netdev stays put and the guest-facing fd is opened by qemu (or a
/// test) via [`flowplane_device::open_tap_fd`], NOT by this backend. This makes tap MORE VF-like than
/// veth: the persistent tap SURVIVES the VM (it is destroyed only at serve teardown), so `assign`
/// /`release` are near-no-ops and `recover` rarely has anything to do (contrast `VethBackend::recover`,
/// which hotplug-rebinds a veth pair that died together with the pod netns).
///
/// `mtu` is the guest link MTU (underlay MTU − encap overhead) — the SAME value `serve.rs` uses at
/// preallocation. `recover` needs it to recreate the tap with the identical link MTU on the (rare)
/// path where the netdev somehow vanished.
///
/// NOTE (slice scope): the real qemu fd-handoff (open the tap fd → pass it to the VM) is the deferred
/// KubeVirt attach path. This backend only owns the pool netdev lifecycle; `assign` is a no-op beyond
/// asserting the target kind.
pub struct TapBackend {
    pub mtu: u32,
}

impl GuestPortBackend for TapBackend {
    fn preallocate(&self, index: u16, mtu: u32) -> Result<HostDevice> {
        let host = format!("fpgtap{index}");
        // Deterministic placeholder MAC. The 0x0f family byte distinguishes the tap pool from the
        // veth pool (which uses 0x0e) so the two pools never collide on a MAC in the same netns. Not
        // datapath-significant — the real guest MAC is programmed at attach.
        let mac = [0x02, 0x00, 0x00, 0x00, 0x0f, index as u8];
        let d = flowplane_device::create_persistent_tap(&host, mac, mtu)?;
        Ok(HostDevice {
            host_ifname: d.host_name,
            host_ifindex: d.host_ifindex,
        })
    }

    fn assign_target(&self, _netns_path: String, guest_ifname: String) -> AssignTarget {
        // Tap has no netns move — drop `netns_path`, keep only the guest ifname.
        AssignTarget::Tap { guest_ifname }
    }

    fn assign(
        &self,
        _host_ifname: &str,
        target: &AssignTarget,
        _mac: [u8; 6],
        _mtu: u32,
    ) -> Result<()> {
        // The tap netdev already exists + is up (preallocate). The guest-facing fd is opened by the VM
        // (qemu) / the test via `flowplane_device::open_tap_fd(host_ifname)`, NOT here — so assign is a
        // no-op for the slice beyond asserting the target kind. (The real qemu fd-handoff is the
        // deferred KubeVirt path.)
        match target {
            AssignTarget::Tap { .. } => Ok(()),
            AssignTarget::Veth { .. } => unreachable!("TapBackend received a Veth target"),
        }
    }

    fn release(&self, _host_ifname: &str, _target: &AssignTarget) {
        // The persistent tap survives the VM; qemu owns closing the guest-facing fd. Nothing to undo.
    }

    fn is_alive(&self, slot: &GuestPortSlot) -> bool {
        // Cheap sysfs stat (no subprocess) — same shape as VethBackend.
        flowplane_device::link_exists(&slot.host_ifname)
    }

    /// Persistent tap SURVIVES the VM → near-no-op. Only recreate it on the (rare) path where the
    /// netdev somehow vanished; there is no vdev hotplug churn (contrast `VethBackend::recover`).
    fn recover(&self, slot: &mut GuestPortSlot, pool_port_id: u16) -> Result<u32> {
        if !flowplane_device::link_exists(&slot.host_ifname) {
            // Recreate with the SAME deterministic placeholder MAC scheme preallocation used
            // (02:00:00:00:0f:<i>, i = pool_port_id − 1 since uplink = port 0, guests = 1..=N).
            let d = flowplane_device::create_persistent_tap(
                &slot.host_ifname,
                [0x02, 0, 0, 0, 0x0f, (pool_port_id.saturating_sub(1)) as u8],
                self.mtu,
            )?;
            slot.host_ifindex = d.host_ifindex;
        }
        slot.dead = false;
        Ok(slot.host_ifindex)
    }

    fn teardown(&self, host_ifname: &str) {
        // Idempotent tap delete. Startup rollback + shutdown. Best-effort.
        flowplane_device::delete_tap(host_ifname);
    }
}
