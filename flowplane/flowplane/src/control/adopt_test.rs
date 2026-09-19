//! The graceful-restart (pinned-map adopt) contract, end to end through the real `Control`.
//!
//! `serve` survives a restart because its state maps and tcx links are PINNED on bpffs: the old
//! process exits, the kernel keeps enforcing, and the new process re-binds to the same maps
//! (`map_pin_path` reuse), rebuilds its bookkeeping from the `IFACE_META` journal and re-points each
//! guest's pinned link at its freshly loaded program. Everything here rides on aya's pinning, link
//! and map-reopen APIs, so this is the gate for an aya upgrade and for any change to the pinned map
//! set (new maps landing alongside old ones).
//!
//! Isolation: the test thread `unshare`s private network AND mount namespaces, so the geneve device,
//! dummy uplink and veth it creates never touch the host. The mount namespace is needed because
//! `Control` resolves devices through `/sys/class/net`, which shows the netns of whoever mounted
//! sysfs; remounting `/sys` then hides the host's bpffs, so a private bpffs instance is mounted on
//! `/sys/fs/bpf` and every pin dies with the test thread. Needs root:
//!   sudo -E cargo test -p flowplane --bin flowplane adopt_test -- --ignored

use std::path::Path;
use std::process::Command;

use aya::maps::{of_maps::HashOfMaps, Array, HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType};
use flowplane_common::{FwBind, FwPolKey};

use super::{hex_encode, Control, IfaceParams};
use crate::{handlers, pb};

/// The old first-match evaluator's pinned maps, gone since the classifier replaced it.
const RETIRED_MAPS: [&str; 4] = ["FW_RULES", "FW_META", "FW_RULES6", "FW_META6"];

fn sh(args: &[&str]) {
    let st = Command::new(args[0])
        .args(&args[1..])
        .status()
        .expect("spawn");
    assert!(st.success(), "{args:?} failed");
}

fn tcx_ingress_prog_count(dev: &str) -> usize {
    SchedClassifier::query_tcx(dev, TcAttachType::Ingress)
        .map(|(_, progs)| progs.len())
        .unwrap_or(0)
}

fn fw_bind_pinned(pin: &Path, ifindex: u32) -> Option<FwBind> {
    let map = MapData::from_pin(pin.join("FW_BIND")).expect("reopen pinned FW_BIND");
    let map: AyaHashMap<_, u32, FwBind> =
        AyaHashMap::try_from(aya::maps::Map::HashMap(map)).expect("FW_BIND is a hash map");
    map.get(&ifindex, 0).ok()
}

/// The node's firewall epoch from the pinned FW_EPOCH map.
fn fw_epoch_pinned(pin: &Path) -> u32 {
    let map = MapData::from_pin(pin.join("FW_EPOCH")).expect("reopen pinned FW_EPOCH");
    let map: Array<_, u32> =
        Array::try_from(aya::maps::Map::Array(map)).expect("FW_EPOCH is an array");
    map.get(&0, 0).expect("FW_EPOCH[0]")
}

/// The scope ids present in the pinned FW_POLICY outer map.
fn scopes_pinned(pin: &Path) -> Vec<u64> {
    let map = MapData::from_pin(pin.join("FW_POLICY")).expect("reopen pinned FW_POLICY");
    let map: HashOfMaps<_, u64, aya::maps::LpmTrie<MapData, FwPolKey, u32>> =
        HashOfMaps::try_from(aya::maps::Map::HashOfMaps(map)).expect("FW_POLICY is a hash of maps");
    let mut ids: Vec<u64> = map.keys().filter_map(Result::ok).collect();
    ids.sort_unstable();
    ids
}

fn replace_fw(ctl: &Control, rules: Vec<pb::FwRuleSpec>) {
    ctl.with_core(|c| {
        handlers::replace_interface_firewall(
            c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "ifA".into(),
                rules,
            },
        )
    })
    .expect("replace_interface_firewall");
}

/// Move the calling thread into private network + mount namespaces with a sysfs of the new netns
/// and a private bpffs on /sys/fs/bpf (see the module doc).
fn isolate_thread() {
    fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong) {
        let c = |s: &str| std::ffi::CString::new(s).unwrap();
        let (src, target, fstype) = (c(src), c(target), c(fstype));
        // SAFETY: valid NUL-terminated strings; no data argument.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        assert_eq!(
            rc,
            0,
            "mount {target:?}: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: unshare affects only the calling (test) thread; netlink sockets, mounts and `ip`
    // children created from this thread afterwards all live in the new namespaces.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) };
    assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());
    // Stop our mounts from propagating back into the host's mount namespace.
    mount("none", "/", "", libc::MS_REC | libc::MS_PRIVATE);
    mount("sysfs", "/sys", "sysfs", 0);
    mount("bpf", "/sys/fs/bpf", "bpf", 0);
}

fn bring_up(pin: &Path, adopt: bool) -> Control {
    Control::bring_up(
        "fpt-up0",
        crate::ifindex("fpt-up0").unwrap(),
        crate::mac_of("fpt-up0").unwrap(),
        [0x02, 0, 0, 0, 0, 0xfe],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        pin,
        adopt,
        true, // pin links, as production Serve does
    )
    .expect("bring_up")
}

#[test]
#[ignore = "requires root: unshares a network namespace and pins BPF objects on /sys/fs/bpf"]
fn restart_adopts_pinned_state_and_relinks_guests() {
    isolate_thread();
    sh(&["ip", "link", "set", "lo", "up"]);
    sh(&["ip", "link", "add", "fpt-up0", "type", "dummy"]);
    sh(&["ip", "link", "set", "fpt-up0", "up"]);
    sh(&[
        "ip", "link", "add", "fpt-g0", "type", "veth", "peer", "name", "fpt-g0p",
    ]);
    sh(&["ip", "link", "set", "fpt-g0", "up"]);
    sh(&["ip", "link", "set", "fpt-g0p", "up"]);
    let guest_ifindex = crate::ifindex("fpt-g0").unwrap();
    let pin = tempfile::Builder::new()
        .prefix("flowplane-adopt-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let (vni, ip) = (7u32, [10, 0, 0, 5]);

    // Incarnation 1: a guest interface, a route-worthy identity and a firewall.
    let ctl = bring_up(pin.path(), false);
    ctl.create_interface(
        b"ifA",
        "fpt-g0",
        IfaceParams {
            vni,
            ipv4: ip,
            ipv6: [0; 16],
            gateway_ipv4: [10, 0, 0, 1],
            gateway_ipv6: [0; 16],
            underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            total_mbps: 0,
            public_mbps: 0,
            netkit: false,
            l3: false,
            peer_capable: true,
            offloaded: false,
        },
    )
    .expect("create_interface");
    let rules = || {
        vec![
            pb::FwRuleSpec {
                rule_id: "in".into(),
                src_cidr: "10.0.0.0/8".into(),
                allow: true,
                ..Default::default()
            },
            pb::FwRuleSpec {
                rule_id: "eg".into(),
                dst_cidr: "::/0".into(),
                allow: true,
                egress: true,
                ..Default::default()
            },
        ]
    };
    // Two cutovers, so the surviving epoch (2) is not what a fresh process would start from.
    replace_fw(&ctl, rules()[..1].to_vec());
    replace_fw(&ctl, rules());
    assert_eq!(tcx_ingress_prog_count("fpt-g0"), 1, "tc_guest_tx attached");
    let bind = fw_bind_pinned(pin.path(), guest_ifindex).expect("classifier binding");
    assert!(
        bind.ingress_scope != 0 && bind.egress_scope != 0,
        "{bind:?}"
    );
    assert_eq!(fw_epoch_pinned(pin.path()), 2, "one epoch bump per cutover");
    let scopes = scopes_pinned(pin.path());
    assert_eq!(
        scopes.len(),
        2,
        "one scope per direction; the first set was freed"
    );

    // The process "exits": every fd and in-memory structure goes, only pins remain.
    drop(ctl);
    let guest_link = pin
        .path()
        .join("links")
        .join(format!("guest-{}", hex_encode(b"ifA")));
    assert!(
        guest_link.exists(),
        "guest link pin {} missing",
        guest_link.display()
    );
    assert_eq!(
        tcx_ingress_prog_count("fpt-g0"),
        1,
        "the pinned link keeps tc_guest_tx attached while no control plane runs"
    );
    assert_eq!(
        fw_bind_pinned(pin.path(), guest_ifindex),
        Some(bind),
        "binding survives"
    );
    assert_eq!(
        scopes_pinned(pin.path()),
        scopes,
        "scopes survive with no control plane"
    );
    assert_eq!(fw_epoch_pinned(pin.path()), 2, "the epoch survives");

    // A node upgraded from before the classifier still has the old evaluator's maps pinned; nothing
    // reads them any more, and adopt must not leave them holding kernel memory.
    for name in RETIRED_MAPS {
        let path = pin.path().join(name);
        if !path.exists() {
            Array::<MapData, u32>::create(1, 0)
                .expect("stand-in map")
                .pin(&path)
                .expect("pin stand-in");
        }
    }

    // Incarnation 2: adopt.
    let ctl = bring_up(pin.path(), true);
    for name in RETIRED_MAPS {
        assert!(
            !pin.path().join(name).exists(),
            "retired map {name} still pinned after adopt"
        );
    }
    let recovered = ctl.recovered_interfaces();
    assert_eq!(
        recovered,
        vec![(b"ifA".to_vec(), "fpt-g0".to_string(), false)],
        "the IFACE_META journal must bring the interface back"
    );
    for (id, dev, netkit) in &recovered {
        ctl.reattach_guest(id, dev, *netkit)
            .expect("reattach_guest");
    }
    assert_eq!(
        tcx_ingress_prog_count("fpt-g0"),
        1,
        "re-adopt re-points the pinned link (no second attach)"
    );
    assert!(
        ctl.iface_lookup_v4(vni, ip).is_some(),
        "INTERFACES was reused, not recreated empty"
    );

    // The agent re-pushes the same rules after a restart: the adopted scopes are reused and the
    // binding is untouched (no epoch bump, so established flows are not re-evaluated). Without the
    // adopt rebuild the re-push would rebind and bump.
    replace_fw(&ctl, rules());
    assert_eq!(
        fw_bind_pinned(pin.path(), guest_ifindex),
        Some(bind),
        "re-push is a no-op"
    );
    assert_eq!(fw_epoch_pinned(pin.path()), 2, "re-push bumps nothing");
    assert_eq!(scopes_pinned(pin.path()), scopes, "no duplicate scopes");

    // The adopted control plane is fully functional: a fresh replace lands in the same maps, and
    // the scopes nothing references any more are freed.
    replace_fw(&ctl, vec![]);
    let emptied = fw_bind_pinned(pin.path(), guest_ifindex).expect("binding after replace");
    assert_eq!((emptied.ingress_scope, emptied.egress_scope), (0, 0));
    assert_eq!(fw_epoch_pinned(pin.path()), 3, "a rebind bumps the epoch");
    assert!(
        scopes_pinned(pin.path()).is_empty(),
        "unreferenced scopes deleted"
    );

    // Unpinning detaches; the netns (and its devices) goes away with this thread.
    drop(ctl);
    let _ = std::fs::remove_dir_all(pin.path());
}
