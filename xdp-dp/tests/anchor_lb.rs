//! BPF_PROG_TEST_RUN byte-parity anchor for the LB **local-deliver** `uplink_rx` datapath.
//!
//! Companion to `anchor_uplink.rs` (the base N-S deliver anchor). This one anchors the
//! load-balancer local-deliver branch: a single backend node owns an overlay LB VIP and is itself
//! the Maglev-selected backend, so `uplink_rx` takes the LB-local-deliver path (LB dispatch selects
//! this node's own underlay -> deliver to the local tap, DSR: no conntrack, inner dst stays the
//! VIP). It loads the REAL compiled `uplink_rx`, runs it on a crafted encapped frame whose inner
//! IPv4 dst is the OVERLAY_VIP via `BPF_PROG_TEST_RUN`, and asserts the kernel-returned output
//! equals the native `xdp-dp-sim` `SimNode::uplink` output for the SAME input + map state.
//!
//! The native LB dispatch glue and the eBPF `uplink_rx` LB glue are composed independently around
//! the shared `xdp-dp-core` LB fns; this anchor proves they produce byte-identical output.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::Xdp;
use xdp_dp_common::{
    FwMeta, FwRule, FwRuleKey, LbKey, LbValue, Local, MaglevKey, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_INGRESS,
};
use xdp_dp_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use xdp_dp_core::pkt::Action;
use xdp_dp_core::uplink::GW_MAC;
use xdp_dp_sim::SimNode;

// --- LB local-deliver fixture (mirrors xdp_dp_sim::ew_lb_local_deliver_no_reforward) ----------

const VNI: u32 = 100;
const TAP: u32 = 42;
const TABLE_ID: u32 = 1;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 20]; // the client guest (LB source)
const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1]; // the balanced overlay VIP (inner dst, DSR)
const ORIGIN_UL: [u8; 16] = ul(0xdd); // where the encapped frame nominally comes from
const BACKEND_UL: [u8; 16] = ul(0xbb); // this node's underlay == the Maglev backend
const DPORT: u16 = 443;

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

fn local() -> Local {
    Local {
        uplink_ifindex: 9,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: BACKEND_UL,
    }
}

fn underlay_value() -> UnderlayValue {
    UnderlayValue {
        vni: VNI,
        tap_ifindex: TAP,
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
    }
}

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` from `GUEST_IP` -> `OVERLAY_VIP:DPORT`.
fn inner_eth_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, OVERLAY_VIP, 64)
        .tcp(40000, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Encapsulate the inner frame IP-in-IPv6 toward `BACKEND_UL` (fabric wire format).
fn encapped_input() -> Vec<u8> {
    let inner = inner_eth_frame();
    let encapped = SimNode::new().edge_encap(
        &inner,
        EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: ORIGIN_UL,
            nexthop_ipv6: BACKEND_UL,
            inner_len: 0,
            inner_proto: 4, // IPPROTO_IPIP
        },
    );
    // Outer IPv6 dst must be the backend underlay (uplink_rx keys UNDERLAY on it).
    assert_eq!(&encapped[ETH_LEN + 24..ETH_LEN + 40], &BACKEND_UL);
    encapped
}

/// The single ingress ALLOW rule the backend installs on `TAP`, covering the VIP dst (DSR: the
/// inner dst stays the VIP, so the policy MUST cover `VIP:443`, not the backend's own IP).
fn allow_vip_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: OVERLAY_VIP,
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

/// Build the native (pure-core) expected `SimOut` for the LB local-deliver scenario: a backend
/// node whose UNDERLAY self-entry + overlay LB + Maglev self-selection + VIP-allow firewall match
/// exactly the eBPF maps the anchor populates.
fn native_output(encapped: &[u8]) -> (Action, Vec<u8>) {
    let mut node = SimNode::with_local(local());
    // UNDERLAY self-entry: BACKEND_UL -> this node's vni + tap + guest MAC.
    node.maps.underlay.insert(BACKEND_UL, underlay_value());
    // Overlay LB VIP -> Maglev table 1.
    node.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: DPORT,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: TABLE_ID,
            size: 1,
        },
    );
    // Maglev slot 0 -> this node's own underlay (LB selects self => local deliver, DSR).
    node.maps.maglev.insert(
        MaglevKey {
            table_id: TABLE_ID,
            slot: 0,
        },
        BACKEND_UL,
    );
    // Firewall: one ingress rule on TAP covering VIP:443 (enforcement is unconditional).
    node.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert((TAP, 0), allow_vip_rule());

    let l = local();
    let out = node.uplink(encapped, VNI, underlay_value(), BACKEND_UL, &l);
    (out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall (copied from anchor_uplink.rs) ----------------------------

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
fn uplink_rx_lb_deliver_bytecode_matches_native_sim() {
    // 1. Build the encapped inner frame (inner dst = OVERLAY_VIP) toward BACKEND_UL.
    let encapped = encapped_input();

    // 2. Native pure-core expected output for the SAME fixture + map state.
    let (native_action, native_pkt) = native_output(&encapped);
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native LB sim delivers the fixture to the backend's tap"
    );

    // 3. Load the real eBPF object (aya-build embeds the bpfel object at $OUT_DIR/xdp-dp-prog;
    //    xdp-dp is binary-only, so the load is inlined). Populate the maps the LB local-deliver
    //    path reads: UNDERLAY, LB, MAGLEV, FW_META/FW_RULES, LOCAL.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-dp-prog"));
    // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
    let pin = tempfile::Builder::new()
        .prefix("xdp-dp-anchor-lb-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut underlay: AyaHashMap<_, [u8; 16], UnderlayValue> =
            AyaHashMap::try_from(ebpf.map_mut("UNDERLAY").expect("UNDERLAY map")).unwrap();
        underlay
            .insert(BACKEND_UL, underlay_value(), 0)
            .expect("insert UNDERLAY");
    }
    {
        let mut lb: AyaHashMap<_, LbKey, LbValue> =
            AyaHashMap::try_from(ebpf.map_mut("LB").expect("LB map")).unwrap();
        lb.insert(
            LbKey {
                vni: VNI,
                ipv4: OVERLAY_VIP,
                port: DPORT,
                proto: 6,
                _pad: 0,
            },
            LbValue {
                table_id: TABLE_ID,
                size: 1,
            },
            0,
        )
        .expect("insert LB");
    }
    {
        let mut maglev: AyaHashMap<_, MaglevKey, [u8; 16]> =
            AyaHashMap::try_from(ebpf.map_mut("MAGLEV").expect("MAGLEV map")).unwrap();
        maglev
            .insert(
                MaglevKey {
                    table_id: TABLE_ID,
                    slot: 0,
                },
                BACKEND_UL,
                0,
            )
            .expect("insert MAGLEV");
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
                allow_vip_rule(),
                0,
            )
            .expect("insert FW_RULES");
    }
    {
        // LOCAL[0]: read by the LB reforward branch (not taken here — LB selects self) and by other
        // uplink_rx branches. Populate it defensively so no branch traps on a missing LOCAL and to
        // mirror a real node's map state.
        let mut local_map: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local_map.set(0, local(), 0).expect("write LOCAL[0]");
    }

    // 4. Load (verify) the uplink_rx program and get its kernel fd.
    let prog: &mut Xdp = ebpf
        .program_mut("uplink_rx")
        .expect("uplink_rx program present")
        .try_into()
        .expect("uplink_rx is an XDP program");
    prog.load().expect("verify/load uplink_rx");
    let prog_fd = prog.fd().expect("uplink_rx fd").as_fd().as_raw_fd();

    // 5. Run the real bytecode on the encapped input via BPF_PROG_TEST_RUN.
    let out = bpf_prog_test_run(prog_fd, &encapped)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel test-run support)");

    // The LB local-deliver path ends in bpf_redirect(tap) -> XDP_REDIRECT after the in-program
    // adjust_head (decap). The output buffer is the decapped+rewritten inner frame — byte-comparable
    // to the native SimNode output.
    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native LB pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );

    // Primary anchor: full-frame byte parity between the native LB sim and the real bytecode.
    assert_eq!(
        out.data.len(),
        native_pkt.len(),
        "native LB pure-core diverged from real bytecode: output length {} != native {}\n\
         bytecode: {:02x?}\nnative:   {:02x?}",
        out.data.len(),
        native_pkt.len(),
        out.data,
        native_pkt,
    );
    assert_eq!(
        out.data, native_pkt,
        "native LB pure-core diverged from real bytecode: decapped output bytes differ from SimNode\n\
         bytecode: {:02x?}\nnative:   {:02x?}",
        out.data, native_pkt,
    );

    // Sanity on the delivered inner-Ethernet rewrite (the guest-facing contract): dst = guest MAC,
    // src = gateway MAC, ethertype = IPv4. Inner IPv4 dst stays the VIP (DSR).
    assert_eq!(&out.data[0..6], &GUEST_MAC, "inner eth dst = guest MAC");
    assert_eq!(&out.data[6..12], &GW_MAC, "inner eth src = gateway MAC");
    assert_eq!(&out.data[12..14], &[0x08, 0x00], "inner ethertype = IPv4");
    // Outer Eth(14)+IPv6(40) stripped, inner Eth(14) restored: out == input - IPV6_LEN.
    assert_eq!(
        out.data.len(),
        encapped.len() - IPV6_LEN,
        "outer IPv6 (40B) stripped from the frame"
    );
    // DSR: the inner IPv4 dst is still the VIP (offset 14 eth + 16 into IPv4 header = dst addr).
    assert_eq!(
        &out.data[ETH_LEN + 16..ETH_LEN + 20],
        &OVERLAY_VIP,
        "DSR: inner IPv4 dst stays the overlay VIP"
    );
}
