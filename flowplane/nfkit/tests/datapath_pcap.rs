//! net_pcap datapath end-to-end: run the `uplink_fwd` example on the DPDK net_pcap PMD over a
//! committed encapped-frame fixture, then assert the frame it tx'd back out equals the output the
//! SHARED `flowplane_core::datapath::process_uplink` produces on the sim side (`VecPkt`+`MemMaps`)
//! for the identical map config. This proves the shared uplink datapath runs through REAL DPDK
//! rx/tx (net_pcap) and is byte-identical to the sim.
//!
//! Deterministic: net_pcap needs no NIC and the example runs EAL with `--no-huge` (see
//! `Backend::eal_args`). Run with `--test-threads=1`.
use etherparse::PacketBuilder;
use flowplane_common::{FwMeta, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::Action;
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use std::process::Command;

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
fn datapath_pcap_uplink_matches_sim() {
    let dir = env!("CARGO_MANIFEST_DIR"); // .../flowplane/nfkit
    let root = format!("{dir}/../.."); // repo root
    let input = format!("{dir}/tests/data/uplink_in.pcap");
    let out = format!("{}/uplink_out.pcap", std::env::temp_dir().display());
    let _ = std::fs::remove_file(&out);

    // The committed fixture MUST be exactly the encapped frame the sim replicates (scenario (a)).
    let expected_frame = encap_to(&inner_frame(EXT_IP, GUEST_IP, DST_PORT), HOST_UL);
    let in_bytes = std::fs::read(&input).expect("read uplink_in.pcap");
    let in_frames = read_pcap_frames(&in_bytes);
    assert_eq!(in_frames.len(), 1, "fixture must hold exactly one frame");
    assert_eq!(
        in_frames[0], expected_frame,
        "committed fixture != encap_to(inner_frame(...)) — regenerate it"
    );

    // Build then run the example binary directly (a nested `cargo run` inside `cargo test` can
    // deadlock on the target-dir lock).
    let b = Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "uplink_fwd"])
        .current_dir(&root)
        .status()
        .expect("build uplink_fwd");
    assert!(b.success(), "build uplink_fwd failed");
    let bin = format!("{root}/target/debug/examples/uplink_fwd");
    let status = Command::new(&bin)
        .args(["pcap", &input, &out])
        .current_dir(&root)
        .status()
        .expect("run uplink_fwd");
    assert!(status.success(), "uplink_fwd exited non-zero");

    // Read the frame the DPDK net_pcap datapath tx'd back out.
    let out_bytes = std::fs::read(&out).expect("read uplink_out.pcap");
    let out_frames = read_pcap_frames(&out_bytes);
    assert_eq!(out_frames.len(), 1, "expected exactly one delivered frame");

    // Independently derive the expected output via the SIM side of the shared datapath.
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
    let in_ = UplinkIn {
        vni: VNI,
        u,
        outer_dst: HOST_UL,
        local: &zl,
        now: 0,
    };
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(TAP, allow_meta());
    sim.fw_rules.insert((TAP, 0), allow_rule(DST_PORT));
    let mut vp = VecPkt::from_bytes(&expected_frame);
    let sim_action = process_uplink(&mut vp, &mut sim, &in_);
    let sim_out = vp.into_bytes();

    assert_eq!(
        sim_action,
        Action::Redirect(TAP),
        "sim: base decap → local tap delivery"
    );
    assert_eq!(
        out_frames[0], sim_out,
        "DPDK net_pcap datapath output != sim output (byte parity broken)"
    );
}
