//! Functional QoS/meter over the DPDK shared-config + per-lcore compose path. EAL inits once, so
//! this is ONE `#[test]` built up in sections. Run with `--ignored --test-threads=1`.
#![cfg(test)]

use etherparse::PacketBuilder;
use flowplane_common::{Local, MeterConfig, PortMeta, RouteValue};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::pkt::Action;
use nfkit::{ComposedMaps, Eal, MbufPkt, Mempool, PerLcoreFlowMaps, SharedConfigMaps};

#[test]
#[ignore = "requires EAL --no-huge"]
fn meter_config_and_policing() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_meter",
    ])
    .expect("EAL init");

    // ── (1) Shared meter-config table round-trip ──────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
    let cfg = MeterConfig {
        total_bps: 100,
        total_burst: 200,
        public_bps: 300,
        public_burst: 400,
        ingress_bps: 500,
        ingress_burst: 600,
    };
    assert_eq!(shared.meter_config_get(7), None, "(1) empty before insert");
    assert!(shared.meter_config_insert(7, cfg), "(1) insert ok");
    assert_eq!(
        shared.meter_config_get(7),
        Some(cfg),
        "(1) get returns the inserted config"
    );
    assert!(
        shared.meter_config_remove(7),
        "(1) remove returns true when present"
    );
    assert_eq!(shared.meter_config_get(7), None, "(1) gone after remove");

    // ── (2) Functional policing: public lane drops once the per-lcore bucket empties ──
    const VNI: u32 = 100;
    const SRC_IFINDEX: u32 = 10;
    const UPLINK_IFINDEX: u32 = 7;
    const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
    const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
    const EXT_DST: [u8; 4] = [203, 0, 113, 9];
    const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let pool = Mempool::new("meter_pool", 1023, 250, 0).expect("pool");
    let sc = SharedConfigMaps::new(0, 1024).expect("shared config 3");
    sc.set_local(Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SRC_UL,
    });
    // External route → the public (external-egress) meter lane runs.
    assert!(sc.route4_insert(
        VNI,
        EXT_DST,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        },
    ));
    // Egress firewall allow-all on the source interface (deny-by-default otherwise).
    assert!(sc.fw_meta_insert(
        SRC_IFINDEX,
        flowplane_common::FwMeta {
            ingress_count: 0,
            egress_count: 1
        },
    ));
    assert!(sc.fw_rules_insert(
        flowplane_common::FwRuleKey {
            ifindex: SRC_IFINDEX,
            idx: 0
        },
        flowplane_common::FwRule {
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
            action: flowplane_common::FW_ACTION_ACCEPT,
            direction: flowplane_common::FW_DIR_EGRESS,
            enabled: 1,
        },
    ));

    // A guest frame [Eth][IPv4][UDP] GUEST_IP -> EXT_DST (~46 bytes on the wire).
    let frame = {
        let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
            .ipv4(GUEST_IP, EXT_DST, 64)
            .udp(12345, 443);
        let mut out = Vec::new();
        b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        out
    };
    let meta = PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    };
    let in_ = GuestTxIn {
        meta: &meta,
        src_ifindex: SRC_IFINDEX,
        now: 0,
    };

    // A tiny public burst: 100 bytes of credit at effectively no refill (now stays 0).
    assert!(sc.meter_config_insert(
        SRC_IFINDEX,
        MeterConfig {
            total_bps: 0,
            total_burst: 0,
            public_bps: 1_000_000,
            public_burst: 100, // burst 100 bytes
            ingress_bps: 0,
            ingress_burst: 0,
        },
    ));

    let flow = PerLcoreFlowMaps::new(0).expect("per-lcore flow");
    let mut maps = ComposedMaps { cfg: &sc, flow };

    // Helper: run one frame through process_guest_tx, return the verdict.
    let send = |maps: &mut ComposedMaps<'_>| -> Action {
        let mut mb = pool.alloc().expect("alloc");
        mb.append(frame.len() as u16).expect("append");
        mb.data_mut().copy_from_slice(&frame);
        let mut mp = MbufPkt::new(&mut mb);
        process_guest_tx(&mut mp, maps, &in_).action
    };

    // now stays 0 → no refill. Burst=100 bytes admits the first ~2 frames, then drops.
    let mut passed = 0;
    let mut dropped = 0;
    for _ in 0..6 {
        match send(&mut maps) {
            Action::Redirect(_) => passed += 1,
            Action::Drop => dropped += 1,
            Action::Pass => {}
        }
    }
    assert!(
        passed >= 1,
        "(2) at least the first packet passes (full bucket)"
    );
    assert!(
        dropped >= 1,
        "(2) ENFORCEMENT: packets drop once the public bucket empties (was: all passed)"
    );

    // ── (2b) Fresh bucket on a SECOND lcore's per-lcore state: full-rate-per-lcore ──
    let flow2 = PerLcoreFlowMaps::new(0).expect("per-lcore flow 2");
    let mut maps2 = ComposedMaps {
        cfg: &sc,
        flow: flow2,
    };
    assert_eq!(
        send(&mut maps2),
        Action::Redirect(UPLINK_IFINDEX),
        "(2b) a second lcore starts with a fresh full bucket (full-rate-per-lcore)"
    );

    // ── (2c) No config → unlimited (regression guard for the None branch) ──
    assert!(sc.meter_config_remove(SRC_IFINDEX));
    let flow3 = PerLcoreFlowMaps::new(0).expect("per-lcore flow 3");
    let mut maps3 = ComposedMaps {
        cfg: &sc,
        flow: flow3,
    };
    for _ in 0..10 {
        assert_eq!(
            send(&mut maps3),
            Action::Redirect(UPLINK_IFINDEX),
            "(2c) with no meter config the public lane is unlimited (all pass)"
        );
    }

    // ── (2d) EDT egress-shaping lane: a configured total_bps now yields a departure timestamp ──
    // The `total` lane SHAPES (EDT) rather than polices. With no shared config it was unreachable
    // (meter_get → None); now a configured total_bps composes through and `edt_egress` stamps a
    // departure time on the encap arm (was always None). Exercises the third meter lane end-to-end.
    assert!(sc.meter_config_insert(
        SRC_IFINDEX,
        MeterConfig {
            total_bps: 1_000_000,
            total_burst: 100_000,
            public_bps: 0,
            public_burst: 0,
            ingress_bps: 0,
            ingress_burst: 0,
        },
    ));
    let flow4 = PerLcoreFlowMaps::new(0).expect("per-lcore flow 4");
    let mut maps4 = ComposedMaps {
        cfg: &sc,
        flow: flow4,
    };
    let mut mb = pool.alloc().expect("alloc");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(&frame);
    let mut mp = MbufPkt::new(&mut mb);
    let out = process_guest_tx(&mut mp, &mut maps4, &in_);
    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "(2d) EDT-shaped frame is still forwarded"
    );
    assert!(
        out.edt_tstamp.is_some(),
        "(2d) EDT lane active (total_bps>0) → a departure timestamp is stamped (was None unconfigured)"
    );
}
