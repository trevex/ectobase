//! DPDK `AttachInterface` (veth) stands up a real container device + programs the shared maps + returns
//! the real response. Needs CAP_NET_ADMIN (creates a veth + netns) AND EAL (--no-huge for SharedConfigMaps).
//!
//! Strategy: EAL + `SharedConfigMaps` integration test (strategy (a) from the plan) — builds the real
//! `DpdkNodeService`, calls `attach_interface`, asserts the real response fields + a registry entry +
//! that the maps are populated, then calls `detach_interface` and verifies teardown. The EAL init uses
//! `--no-huge` (same as `nfkit/tests/generation_invalidation.rs` + `meter_writer.rs`).
//!
//! Run under sudo with EAL:
//!   sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1
#![cfg(test)]

use std::sync::Arc;

use flowplane_control::ControlCore;
use flowplane_dpdk::attach_state::{DpdkAttachState, GuestPortSlot};
use flowplane_dpdk::node::{pb, DpdkNodeService};
use flowplane_dpdk::writer::DpdkMapWriter;
use nfkit::{Eal, SharedConfigMaps};
use parking_lot::Mutex;
use pb::dataplane_node_server::DataplaneNode;
use pb::{AttachInterfaceRequest, DetachInterfaceRequest};
use tonic::Request;

/// Initialise EAL once per process and LEAK the guard so `rte_eal_cleanup` is never called between
/// tests in the same binary. Integration test files share one process; tests run sequentially with
/// `--test-threads=1`, so each test's EAL usage must see a live (not cleaned-up) EAL.
///
/// DPDK does not support re-init after `rte_eal_cleanup` (the static flag in `eal.rs` prevents
/// it, and even if it didn't, DPDK's global hugepage bookkeeping can't be re-seeded). Leaking the
/// guard is the conventional pattern for DPDK test processes that run multiple test cases.
fn init_eal_once() {
    use std::sync::OnceLock;
    // `*const ()` is `Sync` (raw pointers are), so we can put a non-Sync value behind a leaked
    // pointer. The OnceLock just ensures we only leak once.
    static LEAKED: OnceLock<()> = OnceLock::new();
    LEAKED.get_or_init(|| {
        let eal = Eal::init([
            "fp-dpdk-attach-test",
            "-l",
            "0",
            "--no-huge",
            "-m",
            "512",
            "--no-pci",
            "--file-prefix",
            "fp_attach_veth",
        ])
        .expect("EAL init (--no-huge)");
        // Leak the guard so `rte_eal_cleanup` is NEVER called — subsequent tests in this process
        // see a live EAL and can safely allocate SharedConfigMaps / rte_hash tables.
        Box::leak(Box::new(eal));
    });
}

/// Build a `DpdkNodeService` wired to real `SharedConfigMaps` with a fixed underlay pool. The guest
/// pool is seeded EMPTY; privileged tests call [`seed_pool_slot`] to add a real preallocated slot.
fn make_svc(shared: Arc<SharedConfigMaps>) -> (DpdkNodeService, Arc<DpdkAttachState>) {
    let ctrl = Arc::new(Mutex::new(ControlCore::new(DpdkMapWriter::new(
        shared.clone(),
    ))));
    let prefix: ipnet::Ipv6Net = "fd00:db8:0:9::/64".parse().unwrap();
    let attach = Arc::new(DpdkAttachState {
        ipam: std::sync::Mutex::new(flowplane_device::UnderlayIpam::new(prefix)),
        registry: std::sync::Mutex::new(std::collections::HashMap::new()),
        guest_mtu: 1400,
        gateway_ipv4: [169, 254, 0, 1],
        gateway_ipv6: [0u8; 16],
        guest_pool: std::sync::Mutex::new(Vec::new()),
    });
    (DpdkNodeService::new(ctrl, shared, attach.clone()), attach)
}

/// Create a REAL preallocated pool veth (`<host_ifname>` up in root netns, placeholder `<host>p` down)
/// and push it into the attach state's guest pool as one idle slot. Needs CAP_NET_ADMIN. Returns the
/// slot's resolved host ifindex. Mirrors what `serve.rs::run` builds at startup (Task 2). The caller
/// must `flowplane_device::delete_link(host_ifname)` at the end of the test to clean up.
fn seed_pool_slot(attach: &DpdkAttachState, host_ifname: &str, port_id: u16) -> u32 {
    flowplane_device::delete_link(host_ifname);
    let info =
        flowplane_device::create_preallocated_veth(host_ifname, [0x02, 0, 0, 0, 0x0e, 0x00], 1450)
            .expect("create preallocated pool veth (needs CAP_NET_ADMIN)");
    attach.guest_pool.lock().unwrap().push(GuestPortSlot {
        host_ifname: host_ifname.to_string(),
        host_ifindex: info.host_ifindex,
        port_id,
        bound: None,
    });
    info.host_ifindex
}

/// Full attach + detach cycle with a real netns + veth. Needs CAP_NET_ADMIN + EAL.
#[tokio::test]
#[ignore = "privileged: needs CAP_NET_ADMIN (veth+netns) + EAL (--no-huge); run under sudo with --ignored --test-threads=1"]
async fn attach_veth_programs_maps_and_detach_removes_device() {
    init_eal_once();
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    let (svc, attach_state) = make_svc(shared.clone());

    // Seed ONE real preallocated pool slot (VF-style; what serve.rs builds at startup). Attach will
    // ASSIGN this slot rather than create a fresh veth.
    let slot_host = "fpgtest0";
    let slot_ifindex = seed_pool_slot(&attach_state, slot_host, 1);

    // Make a throwaway netns.
    let ns = "fpveth-test-ns";
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
    let ok = std::process::Command::new("ip")
        .args(["netns", "add", ns])
        .status()
        .expect("ip netns add");
    assert!(ok.success(), "ip netns add failed — need CAP_NET_ADMIN");
    let netns_path = format!("/var/run/netns/{ns}");

    // ── Attach ────────────────────────────────────────────────────────────────
    let iface_id = "test-b2a";
    let resp = svc
        .attach_interface(Request::new(AttachInterfaceRequest {
            interface_id: iface_id.into(),
            netns_path: netns_path.clone(),
            vni: 42,
            mac: String::new(), // derive deterministically
            requested_ips: vec!["10.0.9.5".into()],
            device_type: String::new(), // default = veth
            tap_name: String::new(),
        }))
        .await;
    assert!(resp.is_ok(), "attach_interface failed: {resp:?}");
    let r = resp.unwrap().into_inner();

    // The response must mirror the eBPF AttachOutcome field layout.
    assert_eq!(
        r.ifname, iface_id,
        "ifname = interface_id (guest name in the netns)"
    );
    assert_eq!(r.ips, vec!["10.0.9.5"], "ips = requested overlay IPv4");
    assert!(!r.mac.is_empty(), "mac non-empty");
    assert_eq!(r.gateway, "169.254.0.1", "gateway = overlay IPv4 gateway");
    // underlay_route is the allocated /128 from fd00:db8:0:9:8000::/128 upward
    let underlay: std::net::Ipv6Addr = r.underlay_route.parse().expect("underlay_route parses");
    let base: u128 = "fd00:db8:0:9::"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .into();
    let second_half_start: u128 = base + (1u128 << 63);
    assert!(
        u128::from(underlay) >= second_half_start,
        "underlay {underlay} must be in the second half of the /64"
    );

    // The device registry must have an entry for this interface, pointing at the SLOT's device.
    let dev = {
        let reg = attach_state.registry.lock().unwrap();
        reg.get(iface_id.as_bytes()).cloned()
    };
    assert!(dev.is_some(), "registry must have an entry for {iface_id}");
    let dev = dev.unwrap();
    assert_eq!(
        dev.host_name, slot_host,
        "registry host_name is the pool slot device"
    );
    assert_eq!(
        dev.host_ifindex, slot_ifindex,
        "registry host_ifindex matches the seeded slot"
    );

    // The pool host-side veth must still be up in the root netns (attach only MOVES the guest-end).
    let ifindex_s = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", dev.host_name))
        .expect("pool host veth exists in root netns");
    let ifindex: u32 = ifindex_s.trim().parse().unwrap();
    assert_eq!(ifindex, dev.host_ifindex, "sysfs ifindex matches resolved");

    // PortMeta must be programmed KEYED BY THE SLOT ifindex — the exact key the serve worker's
    // `ports_get` uses to resolve this guest's identity.
    assert!(
        shared.ports_get(slot_ifindex).is_some(),
        "PortMeta must be keyed by the pool slot ifindex"
    );

    // The slot must now be bound to this interface.
    {
        let pool = attach_state.guest_pool.lock().unwrap();
        let slot = pool
            .iter()
            .find(|s| s.host_ifindex == slot_ifindex)
            .unwrap();
        assert_eq!(
            slot.bound.as_deref(),
            Some(iface_id),
            "slot bound to the attached interface"
        );
    }

    // The bound guest-end must be visible inside the test netns as `interface_id` (moved from the
    // placeholder), and the placeholder `fpgtest0p` must be GONE from the root netns.
    let status = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "link", "show", iface_id])
        .status()
        .expect("ip netns exec");
    assert!(status.success(), "bound guest-end not found in netns");
    assert!(
        std::fs::metadata(format!("/sys/class/net/{slot_host}p")).is_err(),
        "placeholder peer must have moved out of the root netns"
    );

    // ── Detach ────────────────────────────────────────────────────────────────
    let dresp = svc
        .detach_interface(Request::new(DetachInterfaceRequest {
            interface_id: iface_id.into(),
        }))
        .await;
    assert!(dresp.is_ok(), "detach_interface failed: {dresp:?}");

    // The registry entry must be gone.
    {
        let reg = attach_state.registry.lock().unwrap();
        assert!(
            reg.get(iface_id.as_bytes()).is_none(),
            "registry entry removed after detach"
        );
    }

    // The slot must be FREED (reusable) but the pool host veth must SURVIVE detach.
    {
        let pool = attach_state.guest_pool.lock().unwrap();
        let slot = pool
            .iter()
            .find(|s| s.host_ifindex == slot_ifindex)
            .unwrap();
        assert!(slot.bound.is_none(), "slot freed after detach");
    }
    assert!(
        std::fs::metadata(format!("/sys/class/net/{slot_host}")).is_ok(),
        "pool host veth must SURVIVE detach (reused, not deleted)"
    );

    // The guest-end must be back in the ROOT netns as the placeholder `fpgtest0p`, NOT in the pod ns.
    assert!(
        std::fs::metadata(format!("/sys/class/net/{slot_host}p")).is_ok(),
        "guest-end must be back in the root netns as the placeholder"
    );
    let gone = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "link", "show", iface_id])
        .status()
        .expect("ip netns exec");
    assert!(
        !gone.success(),
        "bound guest-end must no longer be in the pod netns"
    );

    // PortMeta must be removed (freed slot must not retain the previous guest's identity).
    assert!(
        shared.ports_get(slot_ifindex).is_none(),
        "PortMeta must be removed on detach so a reused slot has no stale identity"
    );

    // Cleanup.
    flowplane_device::delete_link(slot_host);
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
}

/// v6-only overlay: attach with only an IPv6 requested. The response `ips` holds the v6 addr, and
/// `gateway` is empty (no v4 gateway is meaningful for a v6-only interface). The guest netns gets
/// the /128 v6 addr. Needs CAP_NET_ADMIN + EAL.
#[tokio::test]
#[ignore = "privileged: needs CAP_NET_ADMIN (veth+netns) + EAL (--no-huge); run under sudo with --ignored --test-threads=1"]
async fn attach_veth_v6_only() {
    init_eal_once();
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    let (svc, attach_state) = make_svc(shared.clone());
    let slot_host = "fpgtest1";
    seed_pool_slot(&attach_state, slot_host, 1);

    let ns = "fpveth-v6only-ns";
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
    let ok = std::process::Command::new("ip")
        .args(["netns", "add", ns])
        .status()
        .expect("ip netns add");
    assert!(ok.success(), "ip netns add failed — need CAP_NET_ADMIN");
    let netns_path = format!("/var/run/netns/{ns}");

    let iface_id = "test-v6only";
    let resp = svc
        .attach_interface(Request::new(AttachInterfaceRequest {
            interface_id: iface_id.into(),
            netns_path: netns_path.clone(),
            vni: 43,
            mac: String::new(),
            requested_ips: vec!["fd00:cafe::5".into()],
            device_type: String::new(),
            tap_name: String::new(),
        }))
        .await;
    assert!(resp.is_ok(), "attach_interface (v6-only) failed: {resp:?}");
    let r = resp.unwrap().into_inner();
    assert_eq!(r.ips, vec!["fd00:cafe::5"], "ips = requested overlay IPv6");
    assert_eq!(
        r.gateway, "",
        "v6-only: gateway must be empty (no v4 gateway)"
    );

    // The guest netns must have the v6 /128 addr and NO v4 default route.
    let v6addr = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-6", "addr", "show", iface_id])
        .output()
        .expect("ip -6 addr show");
    assert!(
        String::from_utf8_lossy(&v6addr.stdout).contains("fd00:cafe::5"),
        "guest must have the v6 overlay addr"
    );
    let v4routes = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-4", "route", "show"])
        .output()
        .expect("ip -4 route show");
    assert!(
        !String::from_utf8_lossy(&v4routes.stdout).contains("default"),
        "v6-only must have NO v4 default route"
    );

    let dresp = svc
        .detach_interface(Request::new(DetachInterfaceRequest {
            interface_id: iface_id.into(),
        }))
        .await;
    assert!(
        dresp.is_ok(),
        "detach_interface (v6-only) failed: {dresp:?}"
    );
    {
        let reg = attach_state.registry.lock().unwrap();
        assert!(reg.get(iface_id.as_bytes()).is_none());
    }
    flowplane_device::delete_link(slot_host);
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
}

/// Dual-stack overlay: attach with both an IPv4 and an IPv6 requested. The response `ips` holds
/// both (v4 then v6) and `gateway` is the v4 gateway. Needs CAP_NET_ADMIN + EAL.
#[tokio::test]
#[ignore = "privileged: needs CAP_NET_ADMIN (veth+netns) + EAL (--no-huge); run under sudo with --ignored --test-threads=1"]
async fn attach_veth_dual_stack() {
    init_eal_once();
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    let (svc, attach_state) = make_svc(shared.clone());
    let slot_host = "fpgtest2";
    seed_pool_slot(&attach_state, slot_host, 1);

    let ns = "fpveth-dual-ns";
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
    let ok = std::process::Command::new("ip")
        .args(["netns", "add", ns])
        .status()
        .expect("ip netns add");
    assert!(ok.success(), "ip netns add failed — need CAP_NET_ADMIN");
    let netns_path = format!("/var/run/netns/{ns}");

    let iface_id = "test-dual";
    let resp = svc
        .attach_interface(Request::new(AttachInterfaceRequest {
            interface_id: iface_id.into(),
            netns_path: netns_path.clone(),
            vni: 44,
            mac: String::new(),
            requested_ips: vec!["10.0.9.7".into(), "fd00:cafe::7".into()],
            device_type: String::new(),
            tap_name: String::new(),
        }))
        .await;
    assert!(resp.is_ok(), "attach_interface (dual) failed: {resp:?}");
    let r = resp.unwrap().into_inner();
    assert_eq!(
        r.ips,
        vec!["10.0.9.7", "fd00:cafe::7"],
        "ips = [v4, v6] in order"
    );
    assert_eq!(r.gateway, "169.254.0.1", "dual: gateway = v4 gateway");

    // Guest netns must have both the v4 and v6 overlay addrs.
    let v4addr = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-4", "addr", "show", iface_id])
        .output()
        .expect("ip -4 addr show");
    assert!(
        String::from_utf8_lossy(&v4addr.stdout).contains("10.0.9.7"),
        "guest must have the v4 overlay addr"
    );
    let v6addr = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-6", "addr", "show", iface_id])
        .output()
        .expect("ip -6 addr show");
    assert!(
        String::from_utf8_lossy(&v6addr.stdout).contains("fd00:cafe::7"),
        "guest must have the v6 overlay addr"
    );

    let dresp = svc
        .detach_interface(Request::new(DetachInterfaceRequest {
            interface_id: iface_id.into(),
        }))
        .await;
    assert!(dresp.is_ok(), "detach_interface (dual) failed: {dresp:?}");
    {
        let reg = attach_state.registry.lock().unwrap();
        assert!(reg.get(iface_id.as_bytes()).is_none());
    }
    flowplane_device::delete_link(slot_host);
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", ns])
        .status();
}

/// Non-veth device_type is rejected with InvalidArgument. No EAL needed (rejected before any work).
#[tokio::test]
#[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
async fn attach_tap_rejected_with_invalid_argument() {
    init_eal_once();
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    let (svc, _) = make_svc(shared);

    let resp = svc
        .attach_interface(Request::new(AttachInterfaceRequest {
            interface_id: "vm0".into(),
            netns_path: "/var/run/netns/nowhere".into(),
            vni: 1,
            mac: "02:00:00:00:00:01".into(),
            requested_ips: vec!["10.0.0.1".into()],
            device_type: "tap".into(), // unsupported on DPDK B2a
            tap_name: String::new(),
        }))
        .await;
    assert!(resp.is_err());
    let status = resp.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
