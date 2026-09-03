//! `BPF_PROG_TEST_RUN` anchor for the North-South `uplink_rx` tcx ingress program (post-P2 Geneve
//! retarget).
//!
//! ## Why this anchor no longer byte-compares delivery output
//!
//! `uplink_rx` is now a tc classifier (`#[classifier]`) attached to the geneve `collect_md` device
//! (P2 Task 4b): the kernel decaps the outer Eth/IPv6/UDP/Geneve header BEFORE this program ever
//! runs, and the VNI comes from `bpf_skb_get_tunnel_key` reading the tunnel-key metadata the decap
//! stamped on the skb — not from an outer address this program parses itself (see
//! `flowplane-ebpf/src/ingress.rs`'s module doc).
//!
//! `try_uplink_rx`'s FIRST action is that `get_tunnel_key` call; on failure it returns `TC_ACT_OK`
//! immediately, before touching any map or packet byte:
//! ```ignore
//! let vni = match get_tunnel_key(ctx.skb.skb) {
//!     Some((vni, _remote)) => vni,
//!     None => return Ok(TC_ACT_OK),
//! };
//! ```
//! `BPF_PROG_TEST_RUN` cannot construct that tunnel-key metadata for a `get_tunnel_key` caller: a
//! freshly-built test skb has no `dst_metadata` attached — that's only populated by a REAL
//! `collect_md` device on decap, or by `bpf_skb_set_tunnel_key` called EARLIER IN THE SAME program
//! run (confirmed empirically at Task 1's spike; see the plan doc). `uplink_rx` never calls
//! `set_tunnel_key` on its own input, so there is no way to drive the real bytecode past that gate
//! from userspace. The base N-S delivery logic this file used to byte-anchor (decap-and-deliver via
//! the `ROUTES`/`UNDERLAY` self-route reconstruction) has **no bytecode oracle anymore** — the
//! native sim is (per P2 Task 7's background).
//!
//! ## What this anchor still proves
//!
//! Fed a post-decap inner frame with no tunnel-key metadata — the only input `BPF_PROG_TEST_RUN` can
//! construct — the REAL compiled `uplink_rx` fails SAFE: `TC_ACT_OK`, packet byte-for-byte
//! unchanged, rather than crashing or (worse) mis-delivering. In production this branch is
//! unreachable (every packet that reaches `uplink_rx` arrived via the geneve device, which always
//! stamps a tunnel key), but it is exactly what `BPF_PROG_TEST_RUN` CAN exercise, and a regression
//! here — e.g. a future change that moves work ahead of the tunnel-key check — would be worth
//! catching.
//!
//! The base N-S delivery scenario this anchor's fixture models (decap → ingress-firewall-allow →
//! conntrack-create → inner-Ethernet rewrite → deliver to the guest tap) is exhaustively covered,
//! bytecode-free, by `flowplane_sim::ns_scenario_test` (see
//! `external_to_guest_encap_decap_fw_allow_ct` and friends), which drives the SAME
//! `flowplane_core::datapath::process_uplink_rx` the real bytecode calls. This file's
//! `native_reference` below re-derives the SAME fixture's expected delivery as a sanity check that
//! the fixture is well-formed, not as a byte-parity oracle.
//!
//! Privileged: needs CAP_BPF + a kernel that supports tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::programs::SchedClassifier;
use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Shared N-S fixture (mirrors flowplane_sim::ns_scenario_test) -------------------------------

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const DPORT: u16 = 443;

/// The POST-decap inner frame `[InnerEth(14)][IPv4][TCP]` from `EXT_IP` -> `GUEST_IP:DPORT` —
/// exactly what the kernel `collect_md` geneve device would hand `uplink_rx` after stripping the
/// outer Eth/IPv6/UDP/Geneve header (see the module doc). This is also the literal
/// `BPF_PROG_TEST_RUN` input below — there is no outer wrapper to build anymore.
fn inner_eth_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, GUEST_IP, 64)
        .tcp(40000, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
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

/// Native `flowplane_core::datapath::process_uplink_rx` reference for this fixture: what `uplink_rx`
/// WOULD deliver if `BPF_PROG_TEST_RUN` could hand it a real tunnel key (VNI threaded out-of-band,
/// standing in for `get_tunnel_key().tunnel_id` — see `flowplane_sim::SimNode::host_uplink`). This is
/// a sanity check on the fixture, not a byte-parity oracle (see the module doc for why the bytecode
/// half of this anchor can no longer provide one).
fn native_reference(inner: &[u8]) -> (Action, Vec<u8>) {
    let mut host = SimNode::new();
    host.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    host.maps.fw_rules.insert((TAP, 0), allow_rule());
    let out = host.host_uplink(inner, VNI, GUEST_IP, TAP, GUEST_MAC);
    (out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall (skb ctx — uplink_rx is a tc classifier, P2 Task 4b) ---------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const TC_ACT_OK: u32 = 0;

/// `sizeof(struct __sk_buff)` and `offsetof(ifindex)` on this kernel's stable UAPI (mirrors
/// `anchor_guest_tx.rs`).
const SK_BUFF_SIZE: usize = 192;
const SKB_IFINDEX_OFF: usize = 40;

/// The `test` arm of the kernel's `union bpf_attr` (uapi/linux/bpf.h). `#[repr(C)]` + explicit
/// padding matches the kernel struct layout exactly.
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
/// `ifindex` field is `ifindex`. Returns the kernel's return code (the tc verdict) + the (possibly
/// mutated) output packet buffer.
fn bpf_prog_test_run_skb(
    prog_fd: RawFd,
    input: &[u8],
    ifindex: u32,
) -> std::io::Result<TestRunOut> {
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

// --- The anchor test ------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn uplink_rx_bytecode_fails_safe_without_tunnel_key() {
    let inner = inner_eth_frame();

    // Sanity: what the native core delivers for this fixture given a REAL tunnel key (the sim is
    // the oracle for the base N-S delivery path — see the module doc).
    let (native_action, _native_pkt) = native_reference(&inner);
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native sim delivers the fixture to the tap given a real tunnel key"
    );

    // Load the real eBPF object the same way the daemon's `loader::load_ebpf` does (aya-build embeds
    // the bpfel object at `$OUT_DIR/flowplane-prog`; `flowplane` is a binary-only crate with no lib
    // target, so the load is inlined here rather than imported). No map population: the tunnel-key
    // gate is the FIRST thing `try_uplink_rx` does, before any map read (see the module doc), so
    // this test's `BPF_PROG_TEST_RUN` input never reaches one.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-uplink-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    let prog: &mut SchedClassifier = ebpf
        .program_mut("uplink_rx")
        .expect("uplink_rx program present")
        .try_into()
        .expect("uplink_rx is a SchedClassifier (tcx) program");
    prog.load().expect("verify/load uplink_rx");
    let prog_fd = prog.fd().expect("uplink_rx fd").as_fd().as_raw_fd();

    // Run the real bytecode on the (undecorated) inner frame — no tunnel-key metadata attached.
    let out = bpf_prog_test_run_skb(prog_fd, &inner, 1 /* loopback, always present */)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel tc test-run support)");

    assert_eq!(
        out.retval, TC_ACT_OK,
        "uplink_rx must fail SAFE (TC_ACT_OK passthrough) when no tunnel-key metadata is present — \
         BPF_PROG_TEST_RUN cannot construct a decap-side get_tunnel_key input (see the module doc); \
         production never reaches this branch (the geneve collect_md device always stamps one)"
    );
    assert_eq!(
        out.data, inner,
        "uplink_rx must not mutate the packet before its tunnel-key gate"
    );
}
