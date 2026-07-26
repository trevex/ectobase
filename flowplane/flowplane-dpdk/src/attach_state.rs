//! DPDK host-device attach state: the underlay /128 IPAM + the registry of attached guest devices
//! (what B2b will af_xdp-bind + poll). Guarded by a Mutex; the attach/detach handlers are the only
//! writers.
//!
//! `mac_for` and `host_veth_name` are transcribed verbatim from `flowplane/src/attach.rs`
//! (`AttachState::mac_for` / `AttachState::host_veth_name`) so both backends produce identical
//! deterministic names/MACs for the same interface_id.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use flowplane_device::UnderlayIpam;

use crate::port_backend::GuestPortBackend;

/// One PREALLOCATED guest af_xdp port slot (VF-style). The serve process creates N guest veth pairs
/// BEFORE EAL init (so they can be passed as `--vdev=net_af_xdp<i>,iface=<host_ifname>`), giving a
/// STATIC poll set. Each slot maps to ethdev port id `port_id` (uplink = 0, guests = 1..=N).
///
/// Consumed by later tasks: Task 3 polls each slot's guest port in the worker loop; Task 4's
/// AttachInterface binds a free slot to an interface (moving the guest veth end into the pod netns +
/// recording the interface_id in `bound`). For THIS task (Task 2) the slot only records the
/// preallocated host device + its ethdev port id; `bound` is always `None`.
#[derive(Clone, Debug)]
pub struct GuestPortSlot {
    /// Host-end (root-netns) veth device name of the preallocated pair, e.g. `fpg0`.
    pub host_ifname: String,
    /// Resolved host-end ifindex (from `create_veth_pair`).
    pub host_ifindex: u32,
    /// The DPDK ethdev port id this slot's af_xdp vdev probed as (1..=N; uplink is 0).
    pub port_id: u16,
    /// Interface id bound to this slot, or `None` if free. Placeholder type for Task 2 — Task 4
    /// finalizes the binding (it may carry more than the id).
    pub bound: Option<String>,
    /// `true` once this slot's host-end veth (`host_ifname`) has been detected GONE — the pod's netns
    /// was destroyed WITHOUT a preceding DetachInterface, so the guest-end vanished and took the
    /// host-end (bound to the af_xdp ethdev port) with it (veth pairs die together). A dead slot is
    /// EXCLUDED from the free pool: attach never binds it (that would silently blackhole guest
    /// traffic), so a pool drained by dead slots correctly surfaces as `resource_exhausted`.
    ///
    /// LIVE RECOVERY (recreate the veth + `rte_dev` hotplug detach/attach the af_xdp vdev + reconfigure
    /// the ethdev port) is wired by G3 (Task 6): `port_backend::VethBackend::recover` recreates the
    /// veth + re-adds the vdev, the control path `Port::configure`s the re-added ethdev + swaps it into
    /// the worker's shared `Port` cell, and the worker rebuilds its `!Send` queue handles when it sees
    /// this slot's `generation` bump. Defaults to `false` at preallocation.
    pub dead: bool,
    /// Generation counter for THIS slot's `host_ifindex`, bumped by the control-plane recovery path
    /// each time the slot's underlying veth + af_xdp ethdev are recreated (dead-slot live recovery).
    /// It is the WRITER side of a generation handshake: the datapath worker that owns this slot's
    /// port caches the last-seen generation and, on a mismatch, rebuilds its `!Send`
    /// `RxQueue`/`TxQueue` handles ON ITS OWN LCORE against the freshly-swapped `Port` (see
    /// `serve.rs::worker_loop`). This is the ONE sanctioned mutation to the otherwise-static poll set.
    /// The pool-slot copy here is the DURABLE record (survives across attach/detach); the parallel
    /// `Arc<Vec<AtomicU32>>` in serve is the cross-thread SIGNAL. Defaults to 0 at preallocation.
    pub generation: u32,
}

/// One attached container device (veth host end).
#[derive(Clone, Debug)]
pub struct AttachedDevice {
    pub host_ifindex: u32,
    pub host_name: String,
    pub netns_path: String,
}

/// Process-wide attach state: underlay IPAM (seeded from the node /64) + the interface_id → device
/// registry. B2b iterates `registry` to bind/poll each guest af_xdp port.
pub struct DpdkAttachState {
    pub ipam: Mutex<UnderlayIpam>,
    pub registry: Mutex<HashMap<Vec<u8>, AttachedDevice>>,
    /// Guest link MTU (underlay MTU - encap overhead) applied to created veths.
    pub guest_mtu: u32,
    /// Gateway addresses programmed into IfaceParams (overlay gateway the datapath answers for).
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    /// The PREALLOCATED per-guest af_xdp port pool (VF-style), built at serve startup BEFORE EAL init
    /// (see `serve.rs::run`). A STATIC poll set: Task 3 polls each slot's `port_id` in the worker
    /// loop; Task 4's AttachInterface locks this to bind a free slot (`bound = Some(..)`) to an
    /// interface (moving the placeholder guest-end veth into the pod netns) and release it on detach.
    /// Empty for non-af-xdp backends (per-guest ports are af-xdp-only in this slice).
    pub guest_pool: Mutex<Vec<GuestPortSlot>>,
    /// The backend-agnostic guest-port pool lifecycle (device mechanics only). Attach/detach call
    /// `assign`/`release`/`is_alive`/`recover` on this instead of the raw `flowplane_device` veth ops,
    /// so the handlers stay device-kind-agnostic (veth today; tap/vf are documented seams).
    /// `Arc<dyn ...>` so it clones cheaply into the `spawn_blocking` closures that shell out to `ip`.
    pub backend: Arc<dyn GuestPortBackend>,
    /// Control-plane handle for dead-slot LIVE RECOVERY (G3/Task 6). Set ONCE by `serve.rs::run` after
    /// the datapath thread is spawned (the handle carries the shared `Mempool` + the `GuestDatapath`
    /// generation-handshake state, both of which are built alongside the workers). The attach path
    /// (`node.rs`) uses it to recover a dead slot when no free live slot remains. `OnceLock` because
    /// it is set exactly once at startup and only read thereafter; `None`/unset in unit tests + on
    /// non-serve construction (recovery is then simply unavailable — attach falls back to
    /// `resource_exhausted`, the pre-G3 behavior).
    pub recover: std::sync::OnceLock<crate::serve::RecoverHandle>,
}

impl DpdkAttachState {
    pub fn register(&self, id: Vec<u8>, dev: AttachedDevice) {
        self.registry.lock().unwrap().insert(id, dev);
    }

    pub fn forget(&self, id: &[u8]) -> Option<AttachedDevice> {
        self.registry.lock().unwrap().remove(id)
    }
}

/// A locally-administered unicast MAC (02:xx:...) derived DETERMINISTICALLY from the
/// `interface_id` (FNV-1a). Transcribed verbatim from `flowplane/src/attach.rs`
/// `AttachState::mac_for` so both backends agree on the MAC for the same id.
///
/// Determinism is a correctness requirement: on detach the datapath's current guest MAC is cached
/// in `learned_macs` (control.rs) so a detach+re-attach of the SAME interface preserves it; a
/// per-attach counter would hand the re-created veth a NEW MAC while the maps kept the cached OLD
/// one, so `uplink_rx` would deliver returns to the stale MAC and the guest would drop them.
pub fn mac_for(interface_id: &str) -> [u8; 6] {
    let mut h: u32 = 2166136261;
    for b in interface_id.as_bytes() {
        h = (h ^ *b as u32).wrapping_mul(16777619);
    }
    let s = h.to_be_bytes();
    [0x02, 0x00, s[0], s[1], s[2], s[3]]
}

/// Host-side veth name for an interface. Transcribed verbatim from `flowplane/src/attach.rs`
/// `AttachState::host_veth_name` so both backends produce the same root-netns device name.
///
/// NOTE: with the VF-style preallocated af_xdp pool model, the DPDK backend no longer names host
/// devices per-interface — pool host-ends are `fpg{i}` (see `serve.rs`), so this fn has no live
/// caller in the DPDK attach path. It is retained (with its regression tests) as the eBPF-parity
/// reference for the shared naming contract.
///
/// Kernel IFNAMSIZ caps names at 15 chars, and `flowplane_device::create_veth_pair` derives the
/// temporary peer name as `<host>p` (one char longer) — so the host name itself must be <= 14
/// chars for the pair to create. Longer ids are hashed to a fixed 13-char name.
pub fn host_veth_name(interface_id: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_device::UnderlayIpam;

    fn make_state() -> DpdkAttachState {
        let prefix: ipnet::Ipv6Net = "fd00:db8:0:1::/64".parse().unwrap();
        DpdkAttachState {
            ipam: Mutex::new(UnderlayIpam::new(prefix)),
            registry: Mutex::new(HashMap::new()),
            guest_mtu: 1400,
            gateway_ipv4: [169, 254, 0, 1],
            gateway_ipv6: [0u8; 16],
            guest_pool: Mutex::new(Vec::new()),
            backend: Arc::new(crate::port_backend::VethBackend { mtu: 1400 }),
            recover: std::sync::OnceLock::new(),
        }
    }

    // ── mac_for ──────────────────────────────────────────────────────────────
    #[test]
    fn mac_for_is_deterministic() {
        assert_eq!(mac_for("natpod"), mac_for("natpod"));
    }

    #[test]
    fn mac_for_is_locally_administered_unicast() {
        let m = mac_for("natpod");
        // Locally-administered (bit 1 set) unicast (bit 0 clear).
        assert_eq!(m[0] & 0x03, 0x02, "must be locally-administered unicast");
    }

    #[test]
    fn mac_for_distinct_ids_distinct_macs() {
        assert_ne!(mac_for("natpod"), mac_for("web"));
        assert_ne!(mac_for("natpod"), mac_for("natpod2"));
    }

    #[test]
    fn mac_for_matches_ebpf_known_value() {
        // Regression: the FNV-1a fold must produce the SAME bytes as `AttachState::mac_for` in
        // `flowplane/src/attach.rs`. Cross-check with a known input.
        let ebpf = {
            let mut h: u32 = 2166136261;
            for b in "natpod".as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            let s = h.to_be_bytes();
            [0x02u8, 0x00, s[0], s[1], s[2], s[3]]
        };
        assert_eq!(mac_for("natpod"), ebpf);
    }

    // ── host_veth_name ───────────────────────────────────────────────────────
    #[test]
    fn host_veth_name_short_passthrough() {
        assert_eq!(host_veth_name("t0"), "veth-t0");
    }

    #[test]
    fn host_veth_name_long_is_hashed_and_fits() {
        let n = host_veth_name("a-very-long-interface-id-way-over-ifnamsiz");
        // The host name PLUS the +1 peer suffix must fit IFNAMSIZ (15).
        assert!(
            n.len() <= 14,
            "{n} leaves no room for the +1 veth peer suffix"
        );
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn host_veth_name_15char_boundary_is_hashed() {
        // "blue-guest" → "veth-blue-guest" is exactly 15 chars; the peer ("veth-blue-guestp")
        // would be 16 — exceeds IFNAMSIZ, so must be hashed.
        let n = host_veth_name("blue-guest");
        assert_eq!(n.len(), 13, "{n} should be the 13-char hashed form");
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn host_veth_name_matches_ebpf() {
        // The hash algorithm must be identical to `AttachState::host_veth_name` (FNV-1a, same fold).
        let id = "a-very-long-interface-id-way-over-ifnamsiz";
        let ebpf = {
            let mut h: u32 = 2166136261;
            for b in id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("veth-{h:08x}")
        };
        assert_eq!(host_veth_name(id), ebpf);
    }

    // ── DpdkAttachState registry ─────────────────────────────────────────────
    #[test]
    fn register_and_forget() {
        let state = make_state();
        let id = b"iface0".to_vec();
        let dev = AttachedDevice {
            host_ifindex: 42,
            host_name: "veth-iface0".into(),
            netns_path: "/var/run/netns/ns0".into(),
        };
        state.register(id.clone(), dev);
        let got = state.forget(&id);
        assert!(got.is_some());
        assert_eq!(got.unwrap().host_ifindex, 42);
        // Second forget returns None.
        assert!(state.forget(&id).is_none());
    }

    #[test]
    fn ipam_allocates_from_second_half() {
        let state = make_state();
        let addr = state.ipam.lock().unwrap().allocate().unwrap();
        // The second half of fd00:db8:0:1::/64 starts at fd00:db8:0:1:8000::
        assert_eq!(
            addr,
            "fd00:db8:0:1:8000::".parse::<std::net::Ipv6Addr>().unwrap()
        );
    }
}
