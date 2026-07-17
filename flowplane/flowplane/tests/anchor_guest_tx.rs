//! BPF_PROG_TEST_RUN byte-parity anchor for the guest-egress `guest_tx` SNAT datapath.
//!
//! Companion to `anchor_uplink.rs` (N-S deliver) and `anchor_lb.rs` (LB local-deliver). This one
//! anchors the guest-egress routing + network-NAT SNAT path that was extracted into `flowplane-core`
//! (`egress::route4`/`deliver` + `nat::snat_egress`): a guest sends a fresh TCP flow to an EXTERNAL
//! destination whose route is marked `is_external`. The datapath enforces the egress firewall,
//! SNATs the inner src IP -> nat_ip and src port -> an allocated nat_port (+ IP/TCP checksums),
//! tracks the flow, and encapsulates IP-in-IPv6 toward the underlay nexthop.
//!
//! It loads the REAL compiled `guest_tx` program, runs it on a crafted guest Ethernet frame via
//! `BPF_PROG_TEST_RUN`, and asserts the kernel-returned output (action + full encapped+NAT'd frame)
//! equals the native `flowplane-sim` `SimNode::guest_tx` output for the SAME input + map state.
//!
//! The port allocation is deterministic (hash-start + linear probe over the [port_min, port_max)
//! range against an empty conntrack), so the eBPF and native paths pick the SAME nat_port -> the
//! rewritten L4 port + folded TCP checksum are byte-identical.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, HashMap as AyaHashMap, ProgramArray,
};
use aya::programs::{ProgramFd, Xdp};
use flowplane_common::{
    FwMeta, FwRule, FwRuleKey, Local, NatKey, NatValue, PortMeta, RouteLpmData, RouteValue,
    FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Guest-egress SNAT fixture ---------------------------------------------------------------

const VNI: u32 = 100;
// `BPF_PROG_TEST_RUN`'s synthetic `xdp_md` sets `ingress_ifindex == 1` (not 0), so the guest_tx
// PORT_META / FW_META / FW_RULES the datapath keys on `ingress_ifindex` must be installed under 1.
// The native sim mirrors this via `SimNode::src_ifindex = 1` for the egress-firewall key. The value
// does not affect the emitted packet bytes (route/NAT key on `meta.vni`, not the ifindex) — it only
// has to make BOTH paths take the firewall ALLOW branch on the fresh flow.
const SRC_IFINDEX: u32 = 1;
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9]; // external destination (is_external route)
const NAT_IP: [u8; 4] = [198, 51, 100, 7]; // the guest's public NAT IPv4
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 20064;
const SPORT: u16 = 40000;
const DPORT: u16 = 443;
const SELF_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_IFINDEX: u32 = 7;
const UPLINK_MAC: [u8; 6] = [2; 6];
const GATEWAY_MAC: [u8; 6] = [1; 6];

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` from `GUEST_IP:SPORT` -> `EXT_IP:DPORT`.
fn guest_eth_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, EXT_IP, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0x22; 6],
        _pad: [0; 2],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: PORT_MIN,
        port_max: PORT_MAX,
    }
}

/// External route for EXT_IP in VNI (is_external=1, nexthop = NEXTHOP_UNDERLAY).
fn route_value() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: UPLINK_MAC,
        gateway_mac: GATEWAY_MAC,
        underlay_ipv6: SELF_UNDERLAY,
    }
}

/// A single egress ALLOW rule on SRC_IFINDEX (TCP GUEST_IP:* -> EXT_IP:DPORT).
fn allow_rule() -> FwRule {
    FwRule {
        src_ip: GUEST_IP,
        src_mask: [255, 255, 255, 255],
        dst_ip: EXT_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: DPORT,
        dst_port_max: DPORT,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// Build the guest input frame AND the native (pure-core) expected `SimOut` for it. The native side
/// installs the identical NAT config + route + firewall rule the eBPF maps get.
fn build_input_and_native() -> (Vec<u8>, Action, Vec<u8>) {
    let frame = guest_eth_frame();

    let mut node = SimNode::with_local(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.local = Some(local());
    node.maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        nat_value(),
    );
    node.maps.add_route4(VNI, EXT_IP, route_value());
    // No UNDERLAY[NEXTHOP] entry -> deliver() takes the Encap branch (external egress).
    node.maps.fw_meta.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert((SRC_IFINDEX, 0), allow_rule());

    let out = node.guest_tx(&frame, &port_meta());
    (frame, out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall ----------------------------------------------------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const XDP_REDIRECT: u32 = 4;

#[repr(C)]
#[derive(Default)]
struct BpfAttrTest {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

struct TestRunOut {
    retval: u32,
    data: Vec<u8>,
}

/// Issue `bpf(BPF_PROG_TEST_RUN)` on `prog_fd` with `input` as `data_in`. Returns the kernel's
/// return code (the XDP action) + the (possibly resized/mutated) output packet buffer.
fn bpf_prog_test_run(prog_fd: RawFd, input: &[u8]) -> std::io::Result<TestRunOut> {
    // The encap path GROWS the frame by 40 bytes (adjust_head(-40)); size the out buffer generously.
    let mut out_buf = vec![0u8; input.len() + 256];
    let mut attr = BpfAttrTest {
        prog_fd: prog_fd as u32,
        data_in: input.as_ptr() as u64,
        data_size_in: input.len() as u32,
        data_out: out_buf.as_mut_ptr() as u64,
        data_size_out: out_buf.len() as u32,
        repeat: 1,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &mut attr as *mut BpfAttrTest as *mut libc::c_void,
            std::mem::size_of::<BpfAttrTest>() as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    out_buf.truncate(attr.data_size_out as usize);
    Ok(TestRunOut {
        retval: attr.retval,
        data: out_buf,
    })
}

// --- The anchor test ------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn guest_tx_snat_bytecode_matches_native_sim() {
    // 1. Build the guest input + the native pure-core expected output for the SAME fixture.
    let (frame, native_action, native_pkt) = build_input_and_native();
    assert_eq!(
        native_action,
        Action::Redirect(UPLINK_IFINDEX),
        "sanity: native sim encaps the SNAT'd flow out the uplink"
    );
    // The guest_tx encap PREPENDS 40 bytes (`adjust_head(-40)`) then writes the 54-byte outer
    // Eth+IPv6 over the front, which consumes the 40 new bytes AND the 14-byte inner Ethernet —
    // leaving `[outer Eth+IPv6 (54)][inner IPv4 ...]`. So the output length is `input + IPV6_LEN`
    // (net +40, since the 14-byte inner Ethernet is overwritten by the 40-byte outer IPv6 tail) and
    // the inner IPv4 src sits at ETH_LEN + IPV6_LEN + 12.
    assert_eq!(
        native_pkt.len(),
        frame.len() + IPV6_LEN,
        "sanity: native output = input + outer IPv6 (inner Ethernet consumed by the outer header)"
    );
    let inner_src = ETH_LEN + IPV6_LEN + 12;
    assert_eq!(
        &native_pkt[inner_src..inner_src + 4],
        &NAT_IP,
        "sanity: native SNAT rewrote the inner src IP to NAT_IP"
    );

    // 2. Load the real eBPF object (same as loader::load_ebpf) and populate the maps guest_tx reads:
    //    PORT_META[ingress_ifindex=0], NAT, ROUTES, FW_META/FW_RULES, LOCAL.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-guest-tx-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut port_meta_map: AyaHashMap<_, u32, PortMeta> =
            AyaHashMap::try_from(ebpf.map_mut("PORT_META").expect("PORT_META map")).unwrap();
        port_meta_map
            .insert(SRC_IFINDEX, port_meta(), 0)
            .expect("insert PORT_META");
    }
    {
        let mut nat: AyaHashMap<_, NatKey, NatValue> =
            AyaHashMap::try_from(ebpf.map_mut("NAT").expect("NAT map")).unwrap();
        nat.insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP,
            },
            nat_value(),
            0,
        )
        .expect("insert NAT");
    }
    {
        let mut routes: LpmTrie<_, RouteLpmData, RouteValue> =
            LpmTrie::try_from(ebpf.map_mut("ROUTES").expect("ROUTES map")).unwrap();
        // prefix_len 64 = 32 VNI bits + 32 host bits (full /32 route), matching the datapath lookup.
        routes
            .insert(
                &Key::new(
                    64,
                    RouteLpmData {
                        vni: VNI.to_be_bytes(),
                        ipv4: EXT_IP,
                    },
                ),
                route_value(),
                0,
            )
            .expect("insert ROUTES");
        // Sanity: the /32 route must resolve at the datapath's exact-match prefix_len (64).
        let got = routes
            .get(
                &Key::new(
                    64,
                    RouteLpmData {
                        vni: VNI.to_be_bytes(),
                        ipv4: EXT_IP,
                    },
                ),
                0,
            )
            .expect("ROUTES readback resolves the inserted /32");
        assert_eq!(got.is_external, 1, "ROUTES readback is the external route");
    }
    {
        let mut fw_meta: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        fw_meta
            .insert(
                SRC_IFINDEX,
                FwMeta {
                    ingress_count: 0,
                    egress_count: 1,
                },
                0,
            )
            .expect("insert FW_META");
    }
    {
        let mut fw_rules: AyaHashMap<_, FwRuleKey, FwRule> =
            AyaHashMap::try_from(ebpf.map_mut("FW_RULES").expect("FW_RULES map")).unwrap();
        fw_rules
            .insert(
                FwRuleKey {
                    ifindex: SRC_IFINDEX,
                    idx: 0,
                },
                allow_rule(),
                0,
            )
            .expect("insert FW_RULES");
    }
    {
        let mut local_map: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local_map.set(0, local(), 0).expect("write LOCAL[0]");
    }

    // 3. `guest_tx` DHCP-classifies with a tail call into GUEST_PROGS[GUEST_PROG_DHCP]; the verifier
    //    requires that slot to resolve, so load `guest_dhcp` and register it first — exactly what the
    //    daemon's `loader::register_guest_dhcp` does at startup. The `ProgramArray` handle must stay
    //    alive for the rest of the test (dropping it closes the userspace map fd).
    {
        let prog: &mut Xdp = ebpf
            .program_mut("guest_dhcp")
            .expect("guest_dhcp program present")
            .try_into()
            .expect("guest_dhcp is an XDP program");
        prog.load().expect("verify/load guest_dhcp");
    }
    let mut guest_progs: ProgramArray<_> = ebpf
        .take_map("GUEST_PROGS")
        .expect("GUEST_PROGS map")
        .try_into()
        .expect("GUEST_PROGS is a ProgramArray");
    {
        let dhcp: &Xdp = ebpf
            .program("guest_dhcp")
            .expect("guest_dhcp program present")
            .try_into()
            .expect("guest_dhcp is an XDP program");
        let fd: &ProgramFd = dhcp.fd().expect("guest_dhcp fd");
        guest_progs
            .set(flowplane_common::GUEST_PROG_DHCP, fd, 0)
            .expect("register guest_dhcp in GUEST_PROGS");
    }

    // 4. Load (verify) the guest_tx program and get its kernel fd.
    let prog: &mut Xdp = ebpf
        .program_mut("guest_tx")
        .expect("guest_tx program present")
        .try_into()
        .expect("guest_tx is an XDP program");
    prog.load().expect("verify/load guest_tx");
    let prog_fd = prog.fd().expect("guest_tx fd").as_fd().as_raw_fd();

    // 5. Run the real bytecode on the guest frame via BPF_PROG_TEST_RUN.
    let out = bpf_prog_test_run(prog_fd, &frame)
        .expect("BPF_PROG_TEST_RUN on guest_tx (needs CAP_BPF + kernel test-run support)");

    // The external-egress path ends in bpf_redirect(uplink) -> XDP_REDIRECT, with the in-program
    // adjust_head(-40) + encap applied to data_out.
    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );

    // Primary anchor: full-frame byte parity between the native sim and the real bytecode. This
    // covers the encap header, the SNAT'd inner src IP + IP checksum, and the rewritten TCP src port
    // + folded TCP checksum all at once.
    assert_eq!(
        out.data.len(),
        native_pkt.len(),
        "native pure-core diverged from real bytecode: output length {} != native {}",
        out.data.len(),
        native_pkt.len()
    );
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: encapped+SNAT'd output bytes differ from SimNode"
    );

    // Belt-and-suspenders on the SNAT contract specifically: the inner src IP is NAT_IP and the
    // outer IPv6 nexthop is NEXTHOP_UNDERLAY.
    assert_eq!(
        &out.data[inner_src..inner_src + 4],
        &NAT_IP,
        "inner src IP SNAT'd to NAT_IP"
    );
    assert_eq!(
        &out.data[ETH_LEN + 24..ETH_LEN + 40],
        &NEXTHOP_UNDERLAY,
        "outer IPv6 dst = route nexthop underlay"
    );
    // The guest_tx encap only PREPENDS the outer Eth+IPv6 (`adjust_head(-40)`), keeping the inner
    // Ethernet — so the output is exactly `input + IPV6_LEN`.
    assert_eq!(
        out.data.len(),
        frame.len() + IPV6_LEN,
        "outer IPv6 (40B) prepended; inner frame kept (frame + 40)"
    );
}
