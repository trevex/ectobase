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
use flowplane_dpdk::attach_state::DpdkAttachState;
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

/// Build a `DpdkNodeService` wired to real `SharedConfigMaps` with a fixed underlay pool.
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
    });
    (DpdkNodeService::new(ctrl, shared, attach.clone()), attach)
}

/// Full attach + detach cycle with a real netns + veth. Needs CAP_NET_ADMIN + EAL.
#[tokio::test]
#[ignore = "privileged: needs CAP_NET_ADMIN (veth+netns) + EAL (--no-huge); run under sudo with --ignored --test-threads=1"]
async fn attach_veth_programs_maps_and_detach_removes_device() {
    init_eal_once();
    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps"));
    let (svc, attach_state) = make_svc(shared.clone());

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

    // The device registry must have an entry for this interface.
    let dev = {
        let reg = attach_state.registry.lock().unwrap();
        reg.get(iface_id.as_bytes()).cloned()
    };
    assert!(dev.is_some(), "registry must have an entry for {iface_id}");
    let dev = dev.unwrap();
    assert!(dev.host_ifindex >= 2, "host ifindex must be real (>= 2)");
    assert!(
        dev.host_name.starts_with("veth-"),
        "host_name must start with veth-"
    );

    // The host-side veth must be visible in the root netns.
    let ifindex_s = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", dev.host_name))
        .expect("host veth exists in root netns");
    let ifindex: u32 = ifindex_s.trim().parse().unwrap();
    assert_eq!(ifindex, dev.host_ifindex, "sysfs ifindex matches resolved");

    // The guest-side veth must be visible inside the test netns.
    let status = std::process::Command::new("ip")
        .args(["netns", "exec", ns, "ip", "link", "show", iface_id])
        .status()
        .expect("ip netns exec");
    assert!(status.success(), "guest veth not found in netns");

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

    // The host-side veth must be gone from the root netns.
    assert!(
        std::fs::metadata(format!("/sys/class/net/{}", dev.host_name)).is_err(),
        "host veth must be deleted after detach"
    );

    // Cleanup.
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
