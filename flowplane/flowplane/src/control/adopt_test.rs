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

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{of_maps::HashOfMaps, Array, HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType};
use flowplane_common::{FwBind, FwPolKey, NatOwner, NatOwnerKey, NatOwnerKey6};

use super::{hex_encode, Control, IfaceParams};
use crate::loader::RETIRED_PINNED_MAPS;
use crate::{handlers, pb};

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

fn nat_owners_trie<K: aya::Pod>(pin: &Path, name: &str) -> LpmTrie<MapData, K, NatOwner> {
    let map =
        MapData::from_pin(pin.join(name)).unwrap_or_else(|e| panic!("reopen pinned {name}: {e}"));
    LpmTrie::try_from(aya::maps::Map::LpmTrie(map))
        .unwrap_or_else(|e| panic!("{name} is an LPM trie: {e}"))
}

/// A pinned NAT owner trie's entries, sorted by (port, prefix_len). A failed walk panics rather
/// than ending the list early, so an "empty" assertion cannot pass on a read error.
fn nat_owner_entries<K: aya::Pod>(
    pin: &Path,
    name: &str,
    port: fn(&K) -> [u8; 2],
) -> Vec<(u32, K, NatOwner)> {
    let mut v: Vec<_> = nat_owners_trie(pin, name)
        .iter()
        .map(|r| r.unwrap_or_else(|e| panic!("walk pinned {name}: {e}")))
        .map(|(k, o)| (k.prefix_len(), k.data(), o))
        .collect();
    v.sort_by_key(|(p, k, _)| (u16::from_be_bytes(port(k)), *p));
    v
}

fn nat_owners_pinned(pin: &Path) -> Vec<(u32, NatOwnerKey, NatOwner)> {
    nat_owner_entries(pin, "NAT_OWNERS", |k: &NatOwnerKey| k.port)
}

fn nat_owners6_pinned(pin: &Path) -> Vec<(u32, NatOwnerKey6, NatOwner)> {
    nat_owner_entries(pin, "NAT_OWNERS6", |k: &NatOwnerKey6| k.port)
}

/// Delete one prefix straight from the pinned NAT_OWNERS trie, behind the control plane's back.
fn drop_nat_owner_pinned(pin: &Path, (plen, key, _): (u32, NatOwnerKey, NatOwner)) {
    nat_owners_trie(pin, "NAT_OWNERS")
        .remove(&Key::new(plen, key))
        .expect("remove one NAT_OWNERS prefix");
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

    // A neighbor-NAT block whose edges are not aligned, so the trie holds it as several prefixes
    // and a crash can leave it partly written.
    let nat_req = pb::AddNeighborNatRequest {
        vni: 7,
        nat_ip: "198.51.100.7".into(),
        owner_underlay: "fd00::99".into(),
        port_min: 20000,
        port_max: 30000,
    };
    ctl.with_core(|c| handlers::add_neighbor_nat(c, &nat_req))
        .expect("add neighbor NAT");
    let owners = nat_owners_pinned(pin.path());
    assert!(
        owners.len() > 1,
        "an unaligned block is several prefixes: {owners:?}"
    );
    // Its v6 twin lives in a trie of its own, adopted separately.
    let nat6_req = pb::AddNeighborNatRequest {
        nat_ip: "2001:db8:2b::7".into(),
        ..nat_req.clone()
    };
    ctl.with_core(|c| handlers::add_neighbor_nat(c, &nat6_req))
        .expect("add v6 neighbor NAT");
    let owners6 = nat_owners6_pinned(pin.path());
    assert!(!owners6.is_empty(), "the v6 block is programmed");

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
    assert_eq!(nat_owners_pinned(pin.path()), owners, "NAT owners survive");
    assert_eq!(
        nat_owners6_pinned(pin.path()),
        owners6,
        "v6 NAT owners survive"
    );

    // A crash mid-write: one of the block's prefixes never made it into the trie. The rest still
    // name the whole block, so adopt can tell what is missing.
    drop_nat_owner_pinned(pin.path(), owners[owners.len() / 2]);

    // A node upgraded from an older build still has the maps that build declared and this one does
    // not (the first-match firewall's rule slots, the scanned neighbor-NAT slots) pinned; nothing
    // reads them any more, and adopt must not leave them holding kernel memory. The stand-ins and
    // the "gone" check below both read the loader's list, so pin what it must hold: a name dropped
    // from it would stay pinned on every upgraded node while this test still passed.
    for name in [
        "FW_RULES",
        "FW_META",
        "FW_RULES6",
        "FW_META6",
        "NEIGHBOR_NAT",
        "NEIGHBOR_NAT_COUNT",
        "NEIGHBOR_NAT6",
        "NEIGHBOR_NAT6_COUNT",
    ] {
        assert!(
            RETIRED_PINNED_MAPS.contains(&name),
            "{name} is no longer retired at load: upgraded nodes would keep it pinned"
        );
    }
    for name in RETIRED_PINNED_MAPS {
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
    for name in RETIRED_PINNED_MAPS {
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

    // Adopt rebuilt the block list from the trie and rewrote the block's full prefix set, so the
    // prefix the crash lost is back.
    assert_eq!(
        nat_owners_pinned(pin.path()),
        owners,
        "adopt completes the block a crash left partial"
    );
    // The overlap check sees the adopted block: without the rebuilt list this would be written
    // over the live block's ports.
    let overlap = pb::AddNeighborNatRequest {
        vni: 8,
        port_min: 25000,
        port_max: 35000,
        ..nat_req.clone()
    };
    let err = ctl
        .with_core(|c| handlers::add_neighbor_nat(c, &overlap))
        .expect_err("a block overlapping the adopted one is refused");
    assert_eq!(
        tonic::Status::from(err).code(),
        tonic::Code::AlreadyExists,
        "an overlap with an adopted block is a conflict"
    );
    // The mesh agent replays its blocks after a restart: a re-announce with a new owner replaces
    // the adopted block in place, every prefix now naming the new owner.
    let new_owner: std::net::Ipv6Addr = "fd00::aa".parse().unwrap();
    let reannounce = pb::AddNeighborNatRequest {
        owner_underlay: new_owner.to_string(),
        ..nat_req
    };
    ctl.with_core(|c| handlers::add_neighbor_nat(c, &reannounce))
        .expect("re-announce the adopted block");
    let reowned: Vec<_> = owners
        .iter()
        .map(|&(plen, key, o)| {
            let underlay = new_owner.octets();
            (plen, key, NatOwner { underlay, ..o })
        })
        .collect();
    assert_eq!(
        nat_owners_pinned(pin.path()),
        reowned,
        "the re-announce moves every prefix to the new owner"
    );
    // A prefix already gone must not wedge the withdraw (a withdraw retried after a partial
    // failure removes every prefix of its block again): the kernel writer takes the absent prefix
    // as removed. `MemMapWriter`'s remove of an absent prefix never fails, so only a real trie
    // reaches this path.
    drop_nat_owner_pinned(pin.path(), reowned[reowned.len() - 1]);
    let withdraw = pb::WithdrawNeighborNatRequest {
        vni: 7,
        nat_ip: "198.51.100.7".into(),
        port_min: 20000,
        port_max: 30000,
    };
    ctl.with_core(|c| handlers::withdraw_neighbor_nat(c, &withdraw))
        .expect("withdraw a block missing a prefix");
    assert!(
        nat_owners_pinned(pin.path()).is_empty(),
        "the withdraw removes the block's remaining prefixes"
    );
    ctl.with_core(|c| handlers::withdraw_neighbor_nat(c, &withdraw))
        .expect("a repeated withdraw is a no-op");

    // The v6 block came back through adopt too. Its withdraw empties NAT_OWNERS6 only because
    // adopt listed the block: an unlisted block's withdraw finds nothing to remove.
    assert_eq!(
        nat_owners6_pinned(pin.path()),
        owners6,
        "the v6 block survives adopt"
    );
    let withdraw6 = pb::WithdrawNeighborNatRequest {
        nat_ip: "2001:db8:2b::7".into(),
        ..withdraw
    };
    ctl.with_core(|c| handlers::withdraw_neighbor_nat(c, &withdraw6))
        .expect("withdraw the adopted v6 block");
    assert!(
        nat_owners6_pinned(pin.path()).is_empty(),
        "the withdraw removes the adopted v6 block"
    );

    // Unpinning detaches; the netns (and its devices) goes away with this thread.
    drop(ctl);
    let _ = std::fs::remove_dir_all(pin.path());
}
