//! BPF_PROG_TEST_RUN byte-parity anchor for the North-South `uplink_rx` datapath.
//!
//! The conformance suite proves the eBPF bytecode against dpservice; the `xdp-dp-sim` tests prove
//! the native `xdp-dp-core` path (`SimNode`). This anchor closes the loop between them: it loads
//! the REAL compiled `uplink_rx` program, runs it on a crafted encapped frame via the kernel's
//! `BPF_PROG_TEST_RUN` API, and asserts the kernel-returned output equals the native `SimNode`
//! output for the SAME input + map state. Any future drift between the pure core and the real
//! bytecode (e.g. a core change that the eBPF crate doesn't pick up, or vice-versa) fails here.
//!
//! aya 0.13.1 does NOT expose an XDP `test_run`/`XdpTestRun` (verified by reading
//! `~/.cargo/.../aya-0.13.1/src/programs/xdp.rs` — only load/attach/detach/link methods exist, and
//! `aya::sys` has no `BPF_PROG_TEST_RUN` wrapper). So this test issues the raw
//! `bpf(BPF_PROG_TEST_RUN, ...)` syscall itself, taking the program fd from aya's loaded `Xdp`
//! (`prog.fd()?.as_fd()`), which is the sanctioned way to reach the kernel object aya loaded.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::Xdp;
use xdp_dp_common::{
    FwMeta, FwRule, FwRuleKey, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS,
};
use xdp_dp_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use xdp_dp_core::pkt::Action;
use xdp_dp_core::uplink::GW_MAC;
use xdp_dp_sim::SimNode;

// --- Shared N-S fixture (mirrors xdp_dp_sim::ns_scenario_test) -------------------------------

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const DPORT: u16 = 443;

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` from `EXT_IP` -> `GUEST_IP:DPORT`.
fn inner_eth_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, GUEST_IP, 64)
        .tcp(40000, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

fn encap_params() -> EncapParams {
    EncapParams {
        gateway_mac: [1; 6],
        uplink_mac: [2; 6],
        uplink_ifindex: 7,
        src_underlay: EDGE_UNDERLAY,
        nexthop_ipv6: HOST_UNDERLAY,
        inner_len: 0,   // set by edge_encap
        inner_proto: 4, // IPPROTO_IPIP
    }
}

/// The single ingress ALLOW rule the host installs on `TAP` (TCP -> GUEST_IP:DPORT).
fn allow_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: GUEST_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: DPORT,
        dst_port_max: DPORT,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

/// Build the encapped fabric input frame AND the native (pure-core) expected `SimOut` for it.
/// The native side installs the identical firewall allow rule + enforcement the eBPF maps get.
fn build_input_and_native() -> (Vec<u8>, Action, Vec<u8>) {
    let inner = inner_eth_frame();
    let encapped = SimNode::new().edge_encap(&inner, encap_params());
    // Outer IPv6 dst must be the host underlay (uplink_rx keys UNDERLAY on it).
    assert_eq!(&encapped[ETH_LEN + 24..ETH_LEN + 40], &HOST_UNDERLAY);

    let mut host = SimNode::new();
    host.maps.fw_enforcing = true;
    host.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    host.maps.fw_rules.insert((TAP, 0), allow_rule());
    let out = host.host_uplink(&encapped, VNI, TAP, GUEST_MAC);
    (encapped, out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall ----------------------------------------------------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const XDP_REDIRECT: u32 = 4;

/// The `test` arm of the kernel's `union bpf_attr` (uapi/linux/bpf.h). Only this arm is needed for
/// `BPF_PROG_TEST_RUN`; `#[repr(C)]` + explicit padding matches the kernel struct layout exactly.
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
    // XDP test-run may grow the frame by up to 256 bytes (kernel headroom); ours only shrinks
    // (decap strips 40 bytes), but size the out buffer generously so data_size_out is never clipped.
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
fn uplink_rx_bytecode_matches_native_sim() {
    // 1. Build the encapped input + the native pure-core expected output for the SAME fixture.
    let (encapped, native_action, native_pkt) = build_input_and_native();
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native sim delivers the fixture to the tap"
    );

    // 2. Load the real eBPF object the same way the daemon's `loader::load_ebpf` does (aya-build
    //    embeds the bpfel object at `$OUT_DIR/xdp-dp-prog`; `xdp-dp` is a binary-only crate with no
    //    lib target, so the load is inlined here rather than imported). Then populate the maps
    //    uplink_rx reads on the base-delivery path: UNDERLAY, FW_META/FW_RULES/FW_CONFIG, LOCAL.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    let mut ebpf = aya::EbpfLoader::new()
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut underlay: AyaHashMap<_, [u8; 16], UnderlayValue> =
            AyaHashMap::try_from(ebpf.map_mut("UNDERLAY").expect("UNDERLAY map")).unwrap();
        underlay
            .insert(
                HOST_UNDERLAY,
                UnderlayValue {
                    vni: VNI,
                    tap_ifindex: TAP,
                    guest_mac: GUEST_MAC,
                    _pad: [0; 2],
                },
                0,
            )
            .expect("insert UNDERLAY");
    }
    {
        let mut fw_meta: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        fw_meta
            .insert(
                TAP,
                FwMeta {
                    ingress_count: 1,
                    egress_count: 0,
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
                    ifindex: TAP,
                    idx: 0,
                },
                allow_rule(),
                0,
            )
            .expect("insert FW_RULES");
    }
    {
        let mut fw_config: Array<_, u32> =
            Array::try_from(ebpf.map_mut("FW_CONFIG").expect("FW_CONFIG map")).unwrap();
        fw_config.set(0, 1u32, 0).expect("enable FW enforcement");
    }
    {
        // LOCAL[0] is read by several uplink_rx branches (LB reforward, ICMP reply, edge deliver).
        // The base allow+decap path here doesn't require it, but populate it so no branch can trap
        // on a missing LOCAL and to mirror a real node's map state.
        let mut local: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local
            .set(
                0,
                Local {
                    uplink_ifindex: 7,
                    uplink_mac: [2; 6],
                    gateway_mac: [1; 6],
                    underlay_ipv6: HOST_UNDERLAY,
                },
                0,
            )
            .expect("write LOCAL[0]");
    }

    // 3. Load (verify) the uplink_rx program and get its kernel fd.
    let prog: &mut Xdp = ebpf
        .program_mut("uplink_rx")
        .expect("uplink_rx program present")
        .try_into()
        .expect("uplink_rx is an XDP program");
    prog.load().expect("verify/load uplink_rx");
    let prog_fd = prog.fd().expect("uplink_rx fd").as_fd().as_raw_fd();

    // 4. Run the real bytecode on the encapped input via BPF_PROG_TEST_RUN.
    let out = bpf_prog_test_run(prog_fd, &encapped)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel test-run support)");

    // The base delivery path ends in bpf_redirect(tap) -> XDP_REDIRECT. The kernel applies the
    // in-program adjust_head (decap) to data_out, so the output buffer is the decapped+rewritten
    // inner frame — byte-comparable to the native SimNode output.
    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );

    // Primary anchor: full-frame byte parity between the native sim and the real bytecode.
    assert_eq!(
        out.data.len(),
        native_pkt.len(),
        "native pure-core diverged from real bytecode: output length {} != native {}",
        out.data.len(),
        native_pkt.len()
    );
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: decapped output bytes differ from SimNode"
    );

    // Belt-and-suspenders on the inner-Ethernet rewrite specifically (the guest-facing contract):
    // dst = guest MAC, src = gateway MAC, ethertype = IPv4.
    assert_eq!(&out.data[0..6], &GUEST_MAC, "inner eth dst = guest MAC");
    assert_eq!(&out.data[6..12], &GW_MAC, "inner eth src = gateway MAC");
    assert_eq!(&out.data[12..14], &[0x08, 0x00], "inner ethertype = IPv4");
    // Outer Eth(14)+IPv6(40) stripped, inner Eth(14) restored: out == input - IPV6_LEN.
    assert_eq!(
        out.data.len(),
        encapped.len() - IPV6_LEN,
        "outer IPv6 (40B) stripped from the frame"
    );
}
