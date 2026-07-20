//! BPF_PROG_TEST_RUN byte-parity anchor for the guest-egress `tc_guest_tx` datapath — specifically
//! the outer-IPv6 flow-label ECMP computation (RFC 6438).
//!
//! The other anchors (`anchor_uplink`, `anchor_lb`, `anchor_dnat`) all set `flow_label: 0`, so none
//! of them exercise the inner-flow hash that `tc_guest_tx` writes into the outer IPv6 flow label on
//! encap. This anchor closes that gap: it loads the REAL compiled `tc_guest_tx` tc classifier, runs
//! it on a guest frame whose 5-tuple hashes to a NON-zero label, and asserts the kernel-returned
//! encapped bytes equal the native `SimNode::guest_tx` output for the SAME input + map state. Any
//! drift between the eBPF `egress_flow_label`/`inner_flow_label` and the native fold fails here.
//!
//! Unlike the XDP anchors, `tc_guest_tx` is a `SchedClassifier` that keys `PORT_META` on
//! `skb->ifindex` (tc.rs). So this test-run supplies a `struct __sk_buff` ctx with `ifindex` set to
//! the loopback ifindex (1, always present) and keys `PORT_META` on it. aya 0.13.1 exposes no tc
//! `test_run`, so — as in `anchor_uplink` — we issue the raw `bpf(BPF_PROG_TEST_RUN, ...)` syscall on
//! the fd of aya's loaded `SchedClassifier`.
//!
//! Privileged: needs CAP_BPF + a kernel with tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::SchedClassifier;
use flowplane_common::{
    FwMeta, FwRule, FwRuleKey, Local, PortMeta, RouteLpmData, RouteValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::parse::{flow_label20, hash5};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Fixture (mirrors flowplane_sim::flow_label_test::guest_tx_encap_carries_inner_flow_label) ---

/// Source ifindex the tc classifier keys PORT_META on. Loopback (1) always exists, so the kernel's
/// skb test-run can resolve `__sk_buff.ifindex` to a real device.
const IFINDEX: u32 = 1;
const UPLINK_IFINDEX: u32 = 7;
const VNI: u32 = 100;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const DEST_IP: [u8; 4] = [10, 1, 1, 1];
const NEXTHOP: [u8; 16] = [0x20, 1, 0xd, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0xaa; 6];
const SPORT: u16 = 12345;
const DPORT: u16 = 53;

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn route_value() -> RouteValue {
    // is_external:0 + no UNDERLAY entry for NEXTHOP → deliver returns Encap (no NAT rewrite), so the
    // label is computed from the unchanged inner 5-tuple.
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: NEXTHOP,
        is_external: 0,
        _pad: [0; 3],
    }
}

/// A permissive egress ALLOW rule on `IFINDEX` (the firewall is deny-by-default; the encap path is a
/// NEW flow, so it must pass an egress-allow rule).
fn egress_allow_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: [0; 4],
        dst_mask: [0; 4],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// A guest Ethernet frame `[Eth][IPv4][UDP]` from GUEST_IP:SPORT -> DEST_IP:DPORT.
fn guest_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let mut frame = Vec::new();
    PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, DEST_IP, 64)
        .udp(SPORT, DPORT)
        .write(&mut frame, &[])
        .unwrap();
    frame
}

/// Build the native (pure-core) expected output for the fixture: the same map state the eBPF maps
/// get, run through `SimNode::guest_tx`.
fn native_output(frame: &[u8]) -> (Action, Vec<u8>) {
    let mut node = SimNode::new();
    node.src_ifindex = IFINDEX;
    node.maps.local = Some(local());
    node.maps.add_route4(VNI, DEST_IP, route_value());
    node.maps.fw_meta.insert(
        IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert((IFINDEX, 0), egress_allow_rule());
    let out = node.guest_tx(frame, &port_meta());
    (out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall (with a __sk_buff ctx) --------------------------------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const TC_ACT_REDIRECT: u32 = 7;

/// `sizeof(struct __sk_buff)` and `offsetof(ifindex)` on this kernel's stable UAPI (uapi/linux/bpf.h:
/// `ifindex` is the 11th u32 → offset 40; the struct totals 192 bytes).
const SK_BUFF_SIZE: usize = 192;
const SKB_IFINDEX_OFF: usize = 40;

/// The `test` arm of `union bpf_attr` (uapi/linux/bpf.h). `#[repr(C)]` + explicit padding matches
/// the kernel struct layout exactly.
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

/// Issue `bpf(BPF_PROG_TEST_RUN)` on `prog_fd` with `input` as `data_in` and a `__sk_buff` ctx whose
/// `ifindex` field is `ifindex`. Returns the kernel's return code (the tc action) + the (grown,
/// mutated) output packet.
fn bpf_prog_test_run_skb(
    prog_fd: RawFd,
    input: &[u8],
    ifindex: u32,
) -> std::io::Result<TestRunOut> {
    // Encap grows the frame by 40 bytes; size the out buffer generously so data_size_out is never
    // clipped.
    let mut out_buf = vec![0u8; input.len() + 256];
    let mut ctx_in = [0u8; SK_BUFF_SIZE];
    ctx_in[SKB_IFINDEX_OFF..SKB_IFINDEX_OFF + 4].copy_from_slice(&ifindex.to_ne_bytes());
    let mut ctx_out = [0u8; SK_BUFF_SIZE];
    let mut attr = BpfAttrTest {
        prog_fd: prog_fd as u32,
        data_in: input.as_ptr() as u64,
        data_size_in: input.len() as u32,
        data_out: out_buf.as_mut_ptr() as u64,
        data_size_out: out_buf.len() as u32,
        ctx_in: ctx_in.as_ptr() as u64,
        ctx_size_in: ctx_in.len() as u32,
        ctx_out: ctx_out.as_mut_ptr() as u64,
        ctx_size_out: ctx_out.len() as u32,
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

// --- The anchor test --------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn guest_tx_encap_flow_label_bytecode_matches_native_sim() {
    // 1. Build the guest frame + the native pure-core expected output for the SAME fixture.
    let frame = guest_frame();
    let (native_action, native_pkt) = native_output(&frame);
    assert_eq!(
        native_action,
        Action::Redirect(UPLINK_IFINDEX),
        "sanity: native sim encaps + redirects out the uplink"
    );
    // The whole point of this anchor: the fixture must produce a NON-zero flow label, so the eBPF
    // `egress_flow_label` code path is actually exercised (not the flow_label:0 the other anchors use).
    let expected_label = flow_label20(hash5(&GUEST_IP, &DEST_IP, SPORT, DPORT, 17));
    assert_ne!(expected_label, 0, "fixture must hash to a non-zero label");
    let native_label = u32::from_be_bytes([
        native_pkt[ETH_LEN],
        native_pkt[ETH_LEN + 1],
        native_pkt[ETH_LEN + 2],
        native_pkt[ETH_LEN + 3],
    ]) & 0x000F_FFFF;
    assert_eq!(native_label, expected_label, "native label sanity");

    // 2. Load the real eBPF object the same way the daemon does, and populate the maps tc_guest_tx
    //    reads on the v4 encap path: PORT_META (keyed by skb ifindex), ROUTES (LPM /32), LOCAL[0],
    //    FW_META/FW_RULES (egress allow). CONNTRACK is left empty (fresh bpffs) so the flow is NEW
    //    and the egress firewall is enforced — exactly as the native SimNode sees it.
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
            .insert(IFINDEX, port_meta(), 0)
            .expect("insert PORT_META");
    }
    {
        let mut routes: LpmTrie<_, RouteLpmData, RouteValue> =
            LpmTrie::try_from(ebpf.map_mut("ROUTES").expect("ROUTES map")).unwrap();
        // Lookup key is Key::new(64, {vni: vni.to_be_bytes(), ipv4: dst}) — a /32 host route (32 VNI
        // bits + 32 host bits), matching coreimpl::route4_get.
        routes
            .insert(
                &Key::new(
                    64,
                    RouteLpmData {
                        vni: VNI.to_be_bytes(),
                        ipv4: DEST_IP,
                    },
                ),
                route_value(),
                0,
            )
            .expect("insert ROUTES");
    }
    {
        let mut local_map: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local_map.set(0, local(), 0).expect("write LOCAL[0]");
    }
    {
        let mut fw_meta: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        fw_meta
            .insert(
                IFINDEX,
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
                    ifindex: IFINDEX,
                    idx: 0,
                },
                egress_allow_rule(),
                0,
            )
            .expect("insert FW_RULES");
    }

    // 3. Load (verify) the tc_guest_tx classifier and get its kernel fd.
    let prog: &mut SchedClassifier = ebpf
        .program_mut("tc_guest_tx")
        .expect("tc_guest_tx program present")
        .try_into()
        .expect("tc_guest_tx is a SchedClassifier program");
    prog.load().expect("verify/load tc_guest_tx");
    let prog_fd = prog.fd().expect("tc_guest_tx fd").as_fd().as_raw_fd();

    // 4. Run the real bytecode on the guest frame via BPF_PROG_TEST_RUN with skb ifindex = IFINDEX.
    let out = bpf_prog_test_run_skb(prog_fd, &frame, IFINDEX)
        .expect("BPF_PROG_TEST_RUN on tc_guest_tx (needs CAP_BPF + kernel tc test-run support)");

    // The encap path ends in bpf_redirect(uplink) -> TC_ACT_REDIRECT, with the skb grown+rewritten
    // to the encapped frame in data_out.
    assert_eq!(
        out.retval, TC_ACT_REDIRECT,
        "native pure-core diverged from real bytecode: expected TC_ACT_REDIRECT ({TC_ACT_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );

    // Primary anchor: full-frame byte parity between the native sim and the real bytecode. This
    // covers the outer Eth+IPv6 header including the flow-label word, so any divergence in the eBPF
    // `egress_flow_label` fold vs the native `inner_flow_label` fold fails here.
    assert_eq!(
        out.data.len(),
        native_pkt.len(),
        "native pure-core diverged from real bytecode: output length {} != native {}",
        out.data.len(),
        native_pkt.len()
    );
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: encapped output bytes differ from SimNode"
    );

    // Belt-and-suspenders on the flow-label word specifically (the reason this anchor exists).
    let outer_word = u32::from_be_bytes([
        out.data[ETH_LEN],
        out.data[ETH_LEN + 1],
        out.data[ETH_LEN + 2],
        out.data[ETH_LEN + 3],
    ]);
    assert_eq!(outer_word >> 28, 6, "outer IPv6 version must stay 6");
    assert_eq!(
        outer_word & 0x000F_FFFF,
        expected_label,
        "real bytecode wrote the wrong outer flow label"
    );
}
