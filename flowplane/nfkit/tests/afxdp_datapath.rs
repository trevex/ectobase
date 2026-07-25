//! af_xdp datapath e2e: run `uplink_fwd` on the DPDK af_xdp PMD over a real veth loopback (the
//! hack/dpdk/afxdp-uplink.sh harness reserves+restores hugepages), then assert the frame it tx'd
//! back (captured via scapy) is byte-identical to `process_uplink` on the sim side. SKIPS (passes)
//! when unprivileged / hugepages not reservable (script exit 77). Run with `--test-threads=1`.
use etherparse::PacketBuilder;
use flowplane_common::{FwMeta, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::Action;
use flowplane_sim::{MemMaps, SimNode, VecPkt};

// ── addressing (IDENTICAL to parity_uplink.rs scenario (a) AND examples/uplink_fwd.rs) ───────────
const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const DST_PORT: u16 = 443;

fn inner_frame(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

fn encap_to(inner: &[u8], dst_ul: [u8; 16]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        flowplane_core::encap::EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: EDGE_UL,
            nexthop_ipv6: dst_ul,
            inner_proto: 4,
            flow_label: 0,
        },
    )
}

fn allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 1,
        egress_count: 0,
    }
}

fn allow_rule(port: u16) -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: GUEST_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: port,
        dst_port_max: port,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

/// Parse every frame out of a minimal little-endian pcap (global 24B header + per-record 16B header,
/// linktype Ethernet). Returns the raw frame byte vectors.
fn read_pcap_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    assert!(bytes.len() >= 24, "pcap shorter than global header");
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    // Accept both the microsecond (0xa1b2c3d4) and nanosecond (0xa1b23c4d) LE pcap magics — the
    // net_pcap PMD writes the latter; both share the 24B global + 16B record header layout.
    assert!(
        magic == 0xa1b2c3d4 || magic == 0xa1b23c4d,
        "unexpected pcap magic {magic:#x}"
    );
    let mut frames = Vec::new();
    let mut off = 24usize;
    while off + 16 <= bytes.len() {
        let incl_len = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16;
        assert!(off + incl_len <= bytes.len(), "truncated pcap record");
        frames.push(bytes[off..off + incl_len].to_vec());
        off += incl_len;
    }
    frames
}

#[test]
fn afxdp_datapath_uplink_matches_sim() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let root = format!("{dir}/../..");
    let input = format!("{dir}/tests/data/uplink_in.pcap"); // reuse the committed fixture
    let out = format!("{}/afxdp_uplink_out.pcap", std::env::temp_dir().display());
    let _ = std::fs::remove_file(&out);

    let expected_frame = encap_to(&inner_frame(EXT_IP, GUEST_IP, DST_PORT), HOST_UL);

    // Build the example, then run the privileged harness (skips unprivileged).
    let b = std::process::Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "uplink_fwd"])
        .current_dir(&root)
        .status()
        .expect("build uplink_fwd");
    assert!(b.success());
    let bin = format!("{root}/target/debug/examples/uplink_fwd");

    let status = std::process::Command::new("bash")
        .arg(format!("{root}/hack/dpdk/afxdp-uplink.sh"))
        .env("UPLINK_BIN", &bin)
        .env("IN_PCAP", &input)
        .env("OUT_PCAP", &out)
        .current_dir(&root)
        .status()
        .expect("run afxdp-uplink.sh");
    match status.code() {
        Some(0) => {}
        Some(77) => {
            eprintln!("afxdp datapath skipped (unprivileged / no hugepages)");
            return;
        }
        other => panic!("afxdp-uplink.sh failed: exit {other:?}"),
    }

    // Compare the af_xdp-transported delivery to the sim output (byte parity). The harness injects
    // several times (af_xdp copy-mode on veth drops warmup frames) and captures ALL decapped
    // deliveries; we assert the exact sim-expected frame is AMONG them (robust to a warmup artifact
    // / af_xdp duplicates — the transport is byte-transparent, so the correct delivery appears).
    let out_frames = read_pcap_frames(&std::fs::read(&out).expect("read capture pcap"));
    assert!(!out_frames.is_empty(), "no decapped frames captured");
    let u = UnderlayValue {
        vni: VNI,
        tap_ifindex: TAP,
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
    };
    let zl = Local {
        uplink_ifindex: 0,
        uplink_mac: [0; 6],
        gateway_mac: [0; 6],
        underlay_ipv6: [0; 16],
    };
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(TAP, allow_meta());
    sim.fw_rules.insert((TAP, 0), allow_rule(DST_PORT));
    let mut vp = VecPkt::from_bytes(&expected_frame);
    let sim_action = process_uplink(
        &mut vp,
        &mut sim,
        &UplinkIn {
            vni: VNI,
            u,
            outer_dst: HOST_UL,
            local: &zl,
            now: 0,
            guest_ipv6: [0; 16],
        },
    );
    assert_eq!(sim_action, Action::Redirect(TAP));
    let sim_out = vp.into_bytes();
    assert!(
        out_frames.iter().any(|f| f == &sim_out),
        "sim-expected decapped frame not found among {} af_xdp-transported frame(s) — byte parity broken.\n  expected ({} B): {:02x?}\n  captured lens: {:?}",
        out_frames.len(),
        sim_out.len(),
        sim_out,
        out_frames.iter().map(|f| f.len()).collect::<Vec<_>>()
    );
}
