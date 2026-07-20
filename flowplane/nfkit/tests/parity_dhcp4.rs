//! DPDK guest-DHCPv4 byte-parity anchor. For a crafted DISCOVER frame (shorter than the fixed
//! `dhcp::REPLY_LEN`) + identical `DHCP_CONFIG`/`DHCP_META` contents in `DpdkMaps` and `MemMaps`,
//! assert `process_guest_dhcp4` over `MbufPkt`+`DpdkMaps` produces a byte-identical OFFER frame +
//! identical `Action` to `VecPkt`+`MemMaps`. Because the DISCOVER is shorter than `REPLY_LEN`, this
//! forces `MbufPkt::set_tail`'s zero-filling grow and then compares the WHOLE `REPLY_LEN` frame —
//! the real integration witness for the tail-padding path.
//!
//! EAL is process-global and can only init once, so this is ONE `#[test]` running its scenarios
//! sequentially. Run with `--test-threads=1`.

use flowplane_common::{DhcpConfig, DhcpMeta, DHCP_MAX_DNS};
use flowplane_core::datapath::{process_guest_dhcp4, GuestDhcp4In};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, VecPkt};
use nfkit::{DpdkMaps, Eal, MbufPkt, Mempool};

// ── addressing / config (mirrors flowplane-sim/src/dhcp_test.rs exactly) ─────
const GUEST_IPV4: [u8; 4] = [10, 0, 0, 42];
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1];
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const INGRESS_IFINDEX: u32 = 7;

const MTU: u16 = 1400;
const DNS4_A: [u8; 4] = [8, 8, 8, 8];
const DNS4_B: [u8; 4] = [1, 1, 1, 1];
const HOSTNAME: &[u8] = b"vm-node-7";

// ── frame geometry (mirrors flowplane_core::dhcp) ────────────────────────────
const ETH_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const F_BOOTP: usize = ETH_LEN + 20 + 8; // 42
const BOOTP_MAGIC_OFF: usize = 236;
const BOOTP_OPTIONS_OFF: usize = 240;
const F_OPTS: usize = F_BOOTP + BOOTP_OPTIONS_OFF; // 282
const REPLY_LEN: usize = F_OPTS + 146; // 428

const DHCP_MSG_DISCOVER: u8 = 1;

/// The DHCP config + per-interface meta the responder pulls the OFFER's MTU/DNS/host-name from.
fn dhcp_config() -> DhcpConfig {
    let mut dns4 = [[0u8; 4]; DHCP_MAX_DNS];
    dns4[0] = DNS4_A;
    dns4[1] = DNS4_B;
    DhcpConfig {
        mtu: MTU,
        dns4_len: 2,
        dns6_len: 0,
        dns4,
        dns6: [[0u8; 16]; DHCP_MAX_DNS],
    }
}

fn dhcp_meta() -> DhcpMeta {
    let mut hostname = [0u8; 64];
    hostname[..HOSTNAME.len()].copy_from_slice(HOSTNAME);
    DhcpMeta {
        hostname,
        hostname_len: HOSTNAME.len() as u8,
        boot_filename: [0u8; 64],
        boot_filename_len: 0,
        pxe_host: [0u8; 46],
        pxe_host_len: 0,
        _pad: [0; 1],
    }
}

/// Build a guest DHCPv4 request frame (Ethernet + IPv4 + UDP + BOOTP + options) with the given
/// message type. Verbatim mirror of `dhcp_test.rs::dhcp_request_frame`. Total length `F_OPTS + 4`
/// (286) is SHORTER than `REPLY_LEN` (428) — the responder grows the frame via `set_tail`.
fn dhcp_request_frame(msg_type: u8) -> Vec<u8> {
    let opts: &[u8] = &[53, 1, msg_type, 255];
    let total = F_OPTS + opts.len();
    let mut f = vec![0u8; total];

    f[0..6].copy_from_slice(&[0xff; 6]); // dst broadcast
    f[6..12].copy_from_slice(&CLIENT_MAC); // src = client
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());

    f[ETH_LEN] = 0x45;
    f[ETH_LEN + 9] = IPPROTO_UDP;

    f[ETH_LEN + 20..ETH_LEN + 22].copy_from_slice(&68u16.to_be_bytes()); // sport (client)
    f[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&67u16.to_be_bytes()); // dport (server)

    f[F_BOOTP] = 1;
    f[F_BOOTP + 4..F_BOOTP + 12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0]);
    f[F_BOOTP + 28..F_BOOTP + 34].copy_from_slice(&CLIENT_MAC);

    f[F_BOOTP + BOOTP_MAGIC_OFF..F_BOOTP + BOOTP_MAGIC_OFF + 4]
        .copy_from_slice(&0x6382_5363u32.to_be_bytes());

    f[F_OPTS..F_OPTS + opts.len()].copy_from_slice(opts);
    f
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to data-pointer moves).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

fn in_() -> GuestDhcp4In {
    GuestDhcp4In {
        guest_ipv4: GUEST_IPV4,
        gateway_ipv4: GATEWAY_IPV4,
        ingress_ifindex: INGRESS_IFINDEX,
    }
}

/// Load `frame` into a fresh mbuf and run `process_guest_dhcp4` over `MbufPkt` + `DpdkMaps`.
fn run_dpdk(pool: &Mempool, maps: &DpdkMaps, frame: &[u8]) -> (Vec<u8>, Action) {
    let mut mb = pool.alloc().expect("alloc mbuf");
    mb.append(frame.len() as u16).expect("append");
    mb.data_mut().copy_from_slice(frame);
    let mut mp = MbufPkt::new(&mut mb);
    let action = process_guest_dhcp4(&mut mp, maps, &in_());
    let out = mp_bytes(&mp);
    (out, action)
}

/// Run `process_guest_dhcp4` over `VecPkt` + `MemMaps`.
fn run_sim(maps: &MemMaps, frame: &[u8]) -> (Vec<u8>, Action) {
    let mut vp = VecPkt::from_bytes(frame);
    let action = process_guest_dhcp4(&mut vp, maps, &in_());
    (vp.into_bytes(), action)
}

#[test]
fn dpdk_guest_dhcp4_matches_sim() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_pd4",
    ])
    .expect("EAL init");
    let pool = Mempool::new("pd4_pool", 1023, 250, 0).expect("pool");

    // ───────────────── Scenario (a): DISCOVER → OFFER (exercises set_tail grow) ─────────────────
    {
        let frame = dhcp_request_frame(DHCP_MSG_DISCOVER);
        assert!(
            frame.len() < REPLY_LEN,
            "DISCOVER ({}) must be shorter than REPLY_LEN ({}) so set_tail grows the frame",
            frame.len(),
            REPLY_LEN
        );

        // sim reference — DHCP_CONFIG + DHCP_META[INGRESS_IFINDEX] programmed.
        let mut sim = MemMaps {
            dhcp_config: Some(dhcp_config()),
            ..Default::default()
        };
        sim.dhcp_meta.insert(INGRESS_IFINDEX, dhcp_meta());
        let (out_sim, a_sim) = run_sim(&sim, &frame);

        // dpdk under test — identical map contents.
        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (a)");
        dm.set_dhcp_config(dhcp_config());
        dm.add_dhcp_meta(INGRESS_IFINDEX, dhcp_meta());
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &dm, &frame);

        assert_eq!(
            a_sim,
            Action::Redirect(INGRESS_IFINDEX),
            "(a) sim: OFFER redirected to ingress ifindex"
        );
        assert_eq!(a_dpdk, a_sim, "(a) action parity");
        assert_eq!(
            out_dpdk.len(),
            REPLY_LEN,
            "(a) OFFER grown to the fixed reply length"
        );
        assert_eq!(out_dpdk, out_sim, "(a) full OFFER frame byte parity");
    }

    // ───────────────── Scenario (b): non-DHCP frame → Pass (unchanged) ─────────────────
    {
        // A frame with UDP dport != 67 is not a DHCP request → pass unchanged.
        let mut frame = dhcp_request_frame(DHCP_MSG_DISCOVER);
        frame[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&53u16.to_be_bytes());

        let mut sim = MemMaps {
            dhcp_config: Some(dhcp_config()),
            ..Default::default()
        };
        sim.dhcp_meta.insert(INGRESS_IFINDEX, dhcp_meta());
        let (out_sim, a_sim) = run_sim(&sim, &frame);

        let mut dm = DpdkMaps::new(0).expect("DpdkMaps::new (b)");
        dm.set_dhcp_config(dhcp_config());
        dm.add_dhcp_meta(INGRESS_IFINDEX, dhcp_meta());
        let (out_dpdk, a_dpdk) = run_dpdk(&pool, &dm, &frame);

        assert_eq!(a_sim, Action::Pass, "(b) sim: non-DHCP frame passes");
        assert_eq!(a_dpdk, a_sim, "(b) action parity");
        assert_eq!(out_sim, frame, "(b) sim: frame unchanged");
        assert_eq!(out_dpdk, out_sim, "(b) frame byte parity (unchanged)");
    }
}
