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
use flowplane_common::{
    FwBind, FwPolKey, LbBackend, LbKey, LbKey6, LbValue, MaglevKey, NatOwner, NatOwnerKey,
    NatOwnerKey6, RouteLpmData, RouteLpmData6, RouteValue,
};

use super::{hex_encode, Control, IfaceParams};
use crate::legacy_nat::{LegacyNeighborNat, LegacyNeighborNat6};
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

/// The pinned `ROUTES{,6}` tries' keys as `(vni, prefix, route prefix_len)`, sorted.
fn routes_pinned(pin: &Path) -> Vec<(u32, [u8; 4], u32)> {
    let map = MapData::from_pin(pin.join("ROUTES")).expect("reopen pinned ROUTES");
    let trie: LpmTrie<_, RouteLpmData, RouteValue> =
        LpmTrie::try_from(aya::maps::Map::LpmTrie(map)).expect("ROUTES is an LPM trie");
    let mut v: Vec<_> = trie
        .keys()
        .map(|k| {
            let k = k.expect("walk ROUTES");
            let d = k.data();
            (u32::from_be_bytes(d.vni), d.ipv4, k.prefix_len() - 32)
        })
        .collect();
    v.sort_unstable();
    v
}

/// The pinned `ROUTES` entry for one host route, by an exact /32 lookup.
fn route_pinned(pin: &Path, vni: u32, ipv4: [u8; 4]) -> Option<RouteValue> {
    let map = MapData::from_pin(pin.join("ROUTES")).expect("reopen pinned ROUTES");
    let trie: LpmTrie<_, RouteLpmData, RouteValue> =
        LpmTrie::try_from(aya::maps::Map::LpmTrie(map)).expect("ROUTES is an LPM trie");
    let data = RouteLpmData {
        vni: vni.to_be_bytes(),
        ipv4,
    };
    trie.get(&Key::new(32 + 32, data), 0).ok()
}

/// Write one host route straight into the pinned `ROUTES`, as an older build could have.
fn put_route_pinned(pin: &Path, vni: u32, ipv4: [u8; 4], val: RouteValue) {
    let map = MapData::from_pin(pin.join("ROUTES")).expect("reopen pinned ROUTES");
    let mut trie: LpmTrie<_, RouteLpmData, RouteValue> =
        LpmTrie::try_from(aya::maps::Map::LpmTrie(map)).expect("ROUTES is an LPM trie");
    let data = RouteLpmData {
        vni: vni.to_be_bytes(),
        ipv4,
    };
    trie.insert(&Key::new(32 + 32, data), val, 0)
        .expect("write pinned route");
}

fn routes6_pinned(pin: &Path) -> Vec<(u32, [u8; 16], u32)> {
    let map = MapData::from_pin(pin.join("ROUTES6")).expect("reopen pinned ROUTES6");
    let trie: LpmTrie<_, RouteLpmData6, RouteValue> =
        LpmTrie::try_from(aya::maps::Map::LpmTrie(map)).expect("ROUTES6 is an LPM trie");
    let mut v: Vec<_> = trie
        .keys()
        .map(|k| {
            let k = k.expect("walk ROUTES6");
            let d = k.data();
            (u32::from_be_bytes(d.vni), d.ipv6, k.prefix_len() - 32)
        })
        .collect();
    v.sort_unstable();
    v
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

/// The pinned `LB{,6}` service rows as `"address:port" -> table id`.
fn lb_tables_pinned(pin: &Path) -> std::collections::BTreeMap<String, u32> {
    let open = |name: &str| {
        let map = MapData::from_pin(pin.join(name)).expect("reopen pinned LB map");
        aya::maps::Map::HashMap(map)
    };
    let mut out = std::collections::BTreeMap::new();
    let lb: AyaHashMap<_, LbKey, LbValue> = AyaHashMap::try_from(open("LB")).expect("LB");
    for r in lb.iter() {
        let (k, v) = r.expect("walk LB");
        let ip = std::net::Ipv4Addr::from(k.ipv4);
        out.insert(format!("{ip}:{}", k.port), v.table_id);
    }
    let lb6: AyaHashMap<_, LbKey6, LbValue> = AyaHashMap::try_from(open("LB6")).expect("LB6");
    for r in lb6.iter() {
        let (k, v) = r.expect("walk LB6");
        let ip = std::net::Ipv6Addr::from(k.ipv6);
        out.insert(format!("{ip}:{}", k.port), v.table_id);
    }
    out
}

/// The pinned `MAGLEV` slots, keyed `(table id, slot)`.
fn maglev_pinned(pin: &Path) -> std::collections::BTreeMap<(u32, u32), LbBackend> {
    let map = MapData::from_pin(pin.join("MAGLEV")).expect("reopen pinned MAGLEV");
    let map: AyaHashMap<_, MaglevKey, LbBackend> =
        AyaHashMap::try_from(aya::maps::Map::HashMap(map)).expect("MAGLEV is a hash map");
    map.iter()
        .map(|r| {
            let (k, b) = r.expect("walk MAGLEV");
            ((k.table_id, k.slot), b)
        })
        .collect()
}

/// An edge load balancer as the mesh agent registers it: id == its address, WAN VNI 0.
fn add_lb(ctl: &Control, ip: &str, backend_overlay_ip: &str) {
    let lb = pb::AddLoadBalancerRequest {
        id: ip.into(),
        vni: 0,
        ip: ip.into(),
        lb_underlay: "fd00::1".into(),
        ports: vec![pb::PortProto {
            port: 443,
            proto: 6,
        }],
    };
    ctl.with_core(|c| handlers::add_load_balancer(c, &lb))
        .expect("add_load_balancer");
    add_lb_backend(ctl, ip, backend_overlay_ip);
}

fn add_lb_backend(ctl: &Control, ip: &str, backend_overlay_ip: &str) {
    let backend = pb::AddLbBackendRequest {
        id: ip.into(),
        backend_underlay: "fd00::99".into(),
        backend_overlay_ip: backend_overlay_ip.into(),
        backend_vni: 7,
    };
    ctl.with_core(|c| handlers::add_lb_backend(c, &backend))
        .expect("add_lb_backend");
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

    // Two mesh routes beside the interface's own self-route (10.0.0.5/32).
    let route = pb::AddRouteRequest {
        vni: 7,
        prefix: "10.0.0.61/32".into(),
        nexthop_underlay: "fd00::99".into(),
        ..Default::default()
    };
    let route6 = pb::AddRouteRequest {
        prefix: "2001:db8:61::/64".into(),
        ..route.clone()
    };
    for r in [&route, &route6] {
        ctl.with_core(|c| handlers::add_route(c, r))
            .expect("add route");
    }
    let r61 = (7, [10, 0, 0, 61], 32);
    let self_route = (vni, ip, 32);
    let r6: (u32, [u8; 16], u32) = (
        7,
        "2001:db8:61::"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
        64,
    );
    assert_eq!(routes_pinned(pin.path()), vec![self_route, r61]);
    assert_eq!(routes6_pinned(pin.path()), vec![r6]);

    // A load balancer per family, each with a backend.
    add_lb(&ctl, "203.0.113.50", "10.0.0.61");
    add_lb(&ctl, "2001:db8:50::1", "10.0.0.62");
    let lb_tables = lb_tables_pinned(pin.path());
    let maglev = maglev_pinned(pin.path());
    assert_eq!(lb_tables.len(), 2, "{lb_tables:?}");

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

    // The damage an older build left on live nodes: a mesh route overwrote ifA's self-route, so the
    // kernel sends traffic for a local guest to another node.
    let stale_owner: std::net::Ipv6Addr = "fd00::77".parse().unwrap();
    put_route_pinned(
        pin.path(),
        vni,
        ip,
        RouteValue {
            nexthop_vni: vni,
            nexthop_ipv6: stale_owner.octets(),
            is_external: 0,
            _pad: [0; 3],
        },
    );

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

    // Adopt repaired ifA's key: the self-route is back in the kernel, and the mesh route that had
    // overwritten it is listed (the fabric's view) behind it.
    let self_nh: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    assert_eq!(
        route_pinned(pin.path(), vni, ip).map(|r| r.nexthop_ipv6),
        Some(self_nh.octets()),
        "adopt restores the overwritten self-route"
    );

    // The routes came back through adopt: a withdraw after the restart removes them from the pinned
    // tries. Without adopt the empty shadow made each withdraw a silent no-op and the route kept
    // forwarding. The self-route was never a withdrawable route and still is not.
    let withdraw_of = |r: &pb::AddRouteRequest| pb::WithdrawRouteRequest {
        vni: r.vni,
        prefix: r.prefix.clone(),
    };
    for r in [&route, &route6] {
        let (_, removed) = ctl
            .with_core(|c| handlers::withdraw_route(c, &withdraw_of(r)))
            .expect("withdraw an adopted route");
        assert!(removed, "{} was adopted", r.prefix);
    }
    assert_eq!(routes_pinned(pin.path()), vec![self_route]);
    assert!(routes6_pinned(pin.path()).is_empty());
    let (_, removed) = ctl
        .with_core(|c| {
            handlers::withdraw_route(
                c,
                &pb::WithdrawRouteRequest {
                    vni,
                    prefix: "10.0.0.5/32".into(),
                },
            )
        })
        .expect("withdraw the self-route's key");
    assert!(
        removed,
        "the mesh route that had overwritten the self-route is listed"
    );
    assert_eq!(routes_pinned(pin.path()), vec![self_route]);
    assert_eq!(
        route_pinned(pin.path(), vni, ip).map(|r| r.nexthop_ipv6),
        Some(self_nh.octets()),
        "its withdraw leaves the held self-route alone"
    );
    let (_, removed) = ctl
        .with_core(|c| {
            handlers::withdraw_route(
                c,
                &pb::WithdrawRouteRequest {
                    vni,
                    prefix: "10.0.0.5/32".into(),
                },
            )
        })
        .expect("withdraw the self-route's key again");
    assert!(!removed, "a self-route is not adopted as a route");
    assert_eq!(routes_pinned(pin.path()), vec![self_route]);

    // The load balancers came back through adopt. A new one gets a table of its own: with the
    // table-id counter back at 1 it was handed the first LB's, and took that LB's traffic.
    add_lb(&ctl, "198.51.100.50", "10.0.0.63");
    let new_table = lb_tables_pinned(pin.path())["198.51.100.50:443"];
    assert!(
        lb_tables.values().all(|&t| t != new_table),
        "table {new_table} is already live: {lb_tables:?}"
    );
    let now = maglev_pinned(pin.path());
    assert!(
        maglev.iter().all(|(k, b)| now.get(k) == Some(b)),
        "the adopted tables are untouched"
    );
    // The agent, which kept running, still manages them by address: a new backend lands, and the
    // deletes take every row and table with them.
    add_lb_backend(&ctl, "203.0.113.50", "10.0.0.64");
    for ip in ["203.0.113.50", "2001:db8:50::1", "198.51.100.50"] {
        let del = pb::DelLoadBalancerRequest { id: ip.into() };
        ctl.with_core(|c| handlers::del_load_balancer(c, &del))
            .expect("del_load_balancer");
    }
    assert!(
        lb_tables_pinned(pin.path()).is_empty(),
        "no service row left"
    );
    assert!(maglev_pinned(pin.path()).is_empty(), "no table left");

    // Increment 1's gap, closed. Adopt cannot tell whether a block it found in the trie is still
    // wanted: if the agent restarted too it withdraws only what it installed itself, so a block
    // withdrawn (or handed to another node) while BOTH were down stays listed forever — still
    // relaying that public IP's return traffic to the old owner, and still refusing any overlapping
    // successor. The cure is declarative: the whole block set of a complete route-bus snapshot,
    // applied as one replace. Both tries are empty here, so whatever they hold after the replace is
    // exactly what the replace put there.
    let stale = pb::AddNeighborNatRequest {
        vni: 7,
        nat_ip: "198.51.100.9".into(),
        owner_underlay: "fd00::99".into(),
        port_min: 20000,
        port_max: 30000,
    };
    ctl.with_core(|c| handlers::add_neighbor_nat(c, &stale))
        .expect("add the block that will go stale");
    let stranded = nat_owners_pinned(pin.path());
    assert!(!stranded.is_empty(), "the block to strand is programmed");

    // Incarnation 3: the stranded block comes back through adopt, with no agent left that remembers
    // installing it.
    drop(ctl);
    let ctl = bring_up(pin.path(), true);
    assert_eq!(
        nat_owners_pinned(pin.path()),
        stranded,
        "the stranded block survives the restart"
    );
    // The first complete snapshot omits it and carries the successor that took over its ports — the
    // exact overlap `add_neighbor_nat` refuses above with AlreadyExists. One replace does both,
    // because it deletes every block outside the set before it stores any of the set's.
    let resp = ctl
        .with_core(|c| {
            handlers::replace_neighbor_nats(
                c,
                &pb::ReplaceNeighborNatsRequest {
                    blocks: vec![pb::NeighborNatBlock {
                        nat_ip: "198.51.100.9".into(),
                        port_min: 25000,
                        port_max: 35000,
                        owner_underlay: "fd00::aa".into(),
                        vni: 8,
                    }],
                },
            )
        })
        .expect("replace the adopted set with the snapshot's");
    assert_eq!(
        (resp.added, resp.kept, resp.removed),
        (1, 0, 1),
        "the adopted block is removed and its successor admitted"
    );
    let successor = nat_owners_pinned(pin.path());
    assert!(!successor.is_empty(), "the successor is stored");
    // Counting the removal is not enough: a surviving prefix of the stranded block (its ports
    // 20000..25000 are outside the successor's) would keep misrouting returns for that public IP.
    assert!(
        successor
            .iter()
            .all(|(_, k, o)| k.nat_ip == [198, 51, 100, 9] && o.port_min == 25000 && o.vni == 8),
        "only the successor's prefixes remain: {successor:?}"
    );

    // Incarnation 4: an upgrade from the retired 64-slot tables. The old control plane rewrote
    // slots 0..count on every change and never cleared the ones above, so a slot at or above the
    // count is a withdrawn block's corpse — pin one live block and one corpse per family and check
    // that adopt converts exactly the live ones. Both families, because `take4`/`take6` differ only
    // in the map names they reach for.
    drop(ctl);
    let migrated_ip = [203, 0, 113, 9];
    let migrated_ip6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let owner = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    {
        let slot = |nat_ip: [u8; 4]| LegacyNeighborNat {
            underlay: owner,
            nat_ip,
            vni,
            port_min: 20000,
            port_max: 21024,
            enabled: 1,
            _pad: [0; 3],
        };
        let mut slots = AyaHashMap::<MapData, u32, LegacyNeighborNat>::create(64, 0)
            .expect("create legacy NEIGHBOR_NAT");
        slots.insert(0, slot(migrated_ip), 0).expect("live slot");
        slots
            .insert(1, slot([203, 0, 113, 10]), 0)
            .expect("corpse above the count");
        // `pin` takes self by value, so it has to be the last use of the map.
        slots
            .pin(pin.path().join("NEIGHBOR_NAT"))
            .expect("pin legacy NEIGHBOR_NAT");

        let slot6 = |nat_ip6: [u8; 16]| LegacyNeighborNat6 {
            underlay: owner,
            nat_ip6,
            vni,
            port_min: 20000,
            port_max: 21024,
            enabled: 1,
            _pad: [0; 3],
        };
        let mut slots6 = AyaHashMap::<MapData, u32, LegacyNeighborNat6>::create(64, 0)
            .expect("create legacy NEIGHBOR_NAT6");
        slots6.insert(0, slot6(migrated_ip6), 0).expect("live slot");
        let mut corpse6 = migrated_ip6;
        corpse6[15] = 10;
        slots6
            .insert(1, slot6(corpse6), 0)
            .expect("corpse above the count");
        slots6
            .pin(pin.path().join("NEIGHBOR_NAT6"))
            .expect("pin legacy NEIGHBOR_NAT6");

        for name in ["NEIGHBOR_NAT_COUNT", "NEIGHBOR_NAT6_COUNT"] {
            let mut count = Array::<MapData, u32>::create(1, 0).expect("create legacy count");
            count.set(0, 1, 0).expect("one live slot");
            count
                .pin(pin.path().join(name))
                .unwrap_or_else(|e| panic!("pin {name}: {e}"));
        }
    }
    let before = nat_owners_pinned(pin.path());
    let before6 = nat_owners6_pinned(pin.path());
    let ctl = bring_up(pin.path(), true);

    let after = nat_owners_pinned(pin.path());
    let migrated: Vec<_> = after.iter().filter(|e| !before.contains(e)).collect();
    assert!(
        !migrated.is_empty(),
        "the retired slot table's live block must land in NAT_OWNERS"
    );
    for (_, key, o) in &migrated {
        assert_eq!(key.nat_ip, migrated_ip, "only the live slot migrates");
        assert_eq!((o.port_min, o.port_max, o.vni), (20000, 21024, vni));
        assert_eq!(o.underlay, owner, "the block keeps its owner");
    }
    assert!(
        before.iter().all(|e| after.contains(e)),
        "the blocks adopt rebuilt survive the migration"
    );

    let after6 = nat_owners6_pinned(pin.path());
    let migrated6: Vec<_> = after6.iter().filter(|e| !before6.contains(e)).collect();
    assert!(
        !migrated6.is_empty(),
        "the retired v6 slot table's live block must land in NAT_OWNERS6"
    );
    for (_, key, o) in &migrated6 {
        assert_eq!(key.nat_ip6, migrated_ip6, "only the live v6 slot migrates");
        assert_eq!((o.port_min, o.port_max, o.vni), (20000, 21024, vni));
    }

    // The loader's sweep runs on every load, so the migration is one-shot: the next upgrade finds
    // nothing to convert.
    for name in RETIRED_PINNED_MAPS {
        assert!(
            !pin.path().join(name).exists(),
            "retired map {name} still pinned after the migration"
        );
    }

    // A VM moving onto this node: the fabric still carries its old owner's /32 while the interface
    // is attached here. The adopted self-route keeps the kernel entry, the mesh route waits, and
    // the detach puts it back rather than leaving the address unrouted.
    let old_owner: std::net::Ipv6Addr = "fd00::99".parse().unwrap();
    let moved = pb::AddRouteRequest {
        vni,
        prefix: "10.0.0.5/32".into(),
        nexthop_underlay: old_owner.to_string(),
        ..Default::default()
    };
    ctl.with_core(|c| handlers::add_route(c, &moved))
        .expect("add the old owner's route");
    let self_nh: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    assert_eq!(
        route_pinned(pin.path(), vni, ip).map(|r| r.nexthop_ipv6),
        Some(self_nh.octets()),
        "the self-route holds its key against the mesh route"
    );
    // A second interface keeps the VNI in use, or the detach of the last one purges every route
    // in it, the reinstalled one included.
    sh(&[
        "ip", "link", "add", "fpt-g1", "type", "veth", "peer", "name", "fpt-g1p",
    ]);
    sh(&["ip", "link", "set", "fpt-g1", "up"]);
    ctl.create_interface(
        b"ifB",
        "fpt-g1",
        IfaceParams {
            vni,
            ipv4: [10, 0, 0, 6],
            ipv6: [0; 16],
            gateway_ipv4: [10, 0, 0, 1],
            gateway_ipv6: [0; 16],
            underlay_ipv6: self_nh.octets(),
            total_mbps: 0,
            public_mbps: 0,
            netkit: false,
            l3: false,
            peer_capable: true,
            offloaded: false,
        },
    )
    .expect("create_interface ifB");
    assert!(ctl.detach_interface(b"ifA").expect("detach ifA"));
    assert_eq!(
        route_pinned(pin.path(), vni, ip).map(|r| r.nexthop_ipv6),
        Some(old_owner.octets()),
        "the detach reinstalls the mesh route"
    );

    // Unpinning detaches; the netns (and its devices) goes away with this thread.
    drop(ctl);
    let _ = std::fs::remove_dir_all(pin.path());
}
