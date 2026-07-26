//! Task 5 (the slice's FUNCTIONAL PROOF): the guest-egress datapath running over an
//! **af_xdp-on-tap pool port driven by a raw tap fd** — i.e. the `TapBackend` transport, with the
//! tap's guest-facing char-device fd standing in for qemu.
//!
//! ── WHAT THIS PROVES ──────────────────────────────────────────────────────────────────────────
//! DIRECTION 5 (the KEY new proof — guest → fabric): a guest IPv4 TCP frame written to the tap's
//! char-device fd (as qemu's NIC backend would) egresses the tap netdev, is RX'd over af_xdp on the
//! DPDK pool port, wrapped in an [`MbufPkt`], and run through the SHARED-core guest-egress datapath
//! [`process_guest_tx`] keyed by the af_xdp-bound tap's ifindex — SNAT + outer-IPv6 encap →
//! `Action::Redirect(uplink_ifindex)`, +40 bytes. This is the guest_tx_datapath.rs fixture (proven
//! byte-parity vs the sim) run over the REAL af_xdp-on-tap transport instead of a synthetic mbuf.
//!
//! DIRECTION 6 (return transport — fabric → guest): a plain guest-delivery frame (inner eth dst =
//! guest_mac) TX'd on the pool port must become readable on the tap fd — confirming the return
//! transport reaches the VM. (This direction is a raw transport check; it does NOT go through
//! `process_uplink_rx` — the shared_ct handoff read-side is proven in guest_tx_nat_return_handoff.rs.)
//!
//! Together: the VM's frame reaches the shared datapath over af_xdp-on-tap AND the datapath's
//! delivery reaches the VM's fd. af_xdp-on-tap itself is the Task 1 gate (`afxdp_tap.rs`); this test
//! adds `process_guest_tx` on top, keyed by the tap ifindex (the value `ports_get` would use).
//!
//! SKIPS (passes) when unprivileged: tap creation + af_xdp bind need root/CAP_NET_ADMIN.
//!
//! EAL is process-global (inits once), so this is ONE `#[test]`. Own `--test` binary + unique
//! `--file-prefix fp_tapguest`. Run:
//! `sudo -E $(command -v cargo) test -p nfkit --test tap_guest_datapath -- --test-threads=1 --nocapture`
#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, NatKey, NatValue, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::pkt::{Action, Pkt};
use nfkit::{
    ComposedMaps, Eal, MbufBurst, MbufPkt, Mempool, PerLcoreFlowMaps, Port, SharedConfigMaps,
};
use std::os::fd::AsRawFd;

// ── addressing (mirrors guest_tx_datapath.rs — known-good fixture) ──────────────────────────────
const VNI: u32 = 100;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
const GW_MAC: [u8; 6] = [0xbb; 6]; // inner eth dst on egress (the guest's gateway MAC)
const EXT_DST: [u8; 4] = [203, 0, 113, 9];
const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
// NAT source: guest GUEST_IP masquerades behind NAT_IP with an allocatable port range.
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const NAT_PORT_MIN: u16 = 20000;
const NAT_PORT_MAX: u16 = 20200;
const SPORT: u16 = 12345;
const DPORT: u16 = 443;

/// The tap netdev this test creates + af_xdp-binds. Unique to avoid colliding with other harnesses.
const TAP: &str = "fpgtapd0";

fn node_local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SRC_UL,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// External default route (`0.0.0.0/0`, is_external=1) → guest_tx takes the SNAT + encap arm.
fn ext_route() -> RouteValue {
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: NEXTHOP_UL,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: NAT_PORT_MIN,
        port_max: NAT_PORT_MAX,
    }
}

fn egress_allow_meta() -> FwMeta {
    FwMeta {
        ingress_count: 0,
        egress_count: 1,
    }
}
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

/// A guest Ethernet frame `[Eth][IPv4][TCP]` GUEST_IP:SPORT → EXT_DST:DPORT (inner eth dst = gw mac).
fn guest_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, GW_MAC)
        .ipv4(GUEST_IP, EXT_DST, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// A plain decapped guest-delivery frame `[Eth dst=guest_mac][IPv4 EXT_DST→GUEST_IP][TCP]` — what the
/// datapath would TX toward the guest after reverse-DNAT. Carries a recognizable payload marker so a
/// frame read off the tap fd can be matched. This direction only checks the return TRANSPORT.
fn delivery_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, GW_MAC)
        .ipv4(EXT_DST, GUEST_IP, 64)
        .tcp(DPORT, SPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, b"POOL->GUEST-return-marker").unwrap();
    out
}

/// Read all `len()` bytes out of an `MbufPkt` via the `Pkt` reader (robust to grow_head data-pointer
/// moves — reads are relative to the current front).
fn mp_bytes(p: &MbufPkt) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        out.push(p.read_array::<1>(i).unwrap()[0]);
    }
    out
}

fn errno() -> String {
    // SAFETY: __errno_location returns a valid pointer to the thread-local errno.
    let e = unsafe { *libc::__errno_location() };
    format!("(errno={e})")
}

/// Set an fd non-blocking so a `read` on an empty tap returns EAGAIN instead of hanging.
fn set_nonblocking(fd: libc::c_int) {
    // SAFETY: fd is valid; F_GETFL/F_SETFL take/return the flag word.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        assert!(flags >= 0, "fcntl(F_GETFL) failed {}", errno());
        let rc = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        assert!(rc == 0, "fcntl(F_SETFL, O_NONBLOCK) failed {}", errno());
    }
}

/// RAII: delete the tap on any exit path (success, panic, early return).
struct TapGuard;
impl Drop for TapGuard {
    fn drop(&mut self) {
        flowplane_device::delete_tap(TAP);
    }
}

#[test]
fn guest_tx_over_afxdp_on_tap_and_return_transport() {
    // ── privilege gate ──────────────────────────────────────────────────────────
    // SAFETY: geteuid is always safe (no args, reads the process's effective uid).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "SKIP guest_tx_over_afxdp_on_tap_and_return_transport: not root (needs CAP_NET_ADMIN)"
        );
        return;
    }

    // ── 1. create the PERSISTENT tap + resolve its ifindex (the af_xdp-bound netdev's ifindex is the
    //    key the datapath's ports_get would use). The guard deletes it on any exit. ────────────────
    let _guard = TapGuard;
    flowplane_device::delete_tap(TAP); // clear any stale tap first
    let info = flowplane_device::create_persistent_tap(TAP, GUEST_MAC, 1450)
        .expect("create persistent tap (CAP_NET_ADMIN?)");
    let tap_ifindex = info.host_ifindex;
    assert_eq!(
        tap_ifindex,
        flowplane_device::ifindex_of(TAP).expect("ifindex_of"),
        "resolved tap ifindex is stable"
    );
    eprintln!("OK: created persistent tap {TAP} ifindex={tap_ifindex}");

    // ── 2. open the guest-facing char-device fd (the "VM side" = qemu analogue), set non-blocking. ─
    let owned_fd = flowplane_device::open_tap_fd(TAP).expect("open tap fd");
    let fd = owned_fd.as_raw_fd();
    set_nonblocking(fd);

    // ── 3. EAL init with the af_xdp vdev bound to the tap netdev; mempool; configure the port. ─────
    let vdev = format!("net_af_xdp0,iface={TAP},start_queue=0,queue_count=1");
    let _eal = Eal::init([
        "fp-tap-guest",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--vdev",
        &vdev,
        "--file-prefix",
        "fp_tapguest",
    ])
    .expect("EAL init with af_xdp vdev bound to the tap netdev");
    let pool = Mempool::new("tapguest_pool", 8191, 250, 0).expect("mempool create");
    let port =
        Port::configure(0, 1, &pool).expect("af_xdp Port::configure (bind) on the tap netdev");
    assert!(port.n_queues() >= 1, "tap-bound af_xdp port has a queue");
    eprintln!(
        "OK: af_xdp bound tap {TAP} -> port 0 with {} queue(s)",
        port.n_queues()
    );
    let (mut rxq, mut txq) = port.queue(0);

    // ── 4. Program the guest-tx fixture EXACTLY as guest_tx_datapath.rs does, but key PortMeta / the
    //    firewall by `tap_ifindex` (the af_xdp-bound tap's ifindex — the src_ifindex the datapath
    //    sees for a frame arriving on this port). ───────────────────────────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("SharedConfigMaps");
    shared.set_local(node_local());
    assert!(shared.route4_insert(VNI, EXT_DST, ext_route()), "route4");
    assert!(
        shared.nat_insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP
            },
            nat_value()
        ),
        "nat binding"
    );
    assert!(shared.nat_ips_insert(VNI, NAT_IP), "nat public ip");
    assert!(
        shared.fw_meta_insert(tap_ifindex, egress_allow_meta()),
        "fw_meta"
    );
    assert!(
        shared.fw_rules_insert(
            flowplane_common::FwRuleKey {
                ifindex: tap_ifindex,
                idx: 0,
            },
            egress_allow_rule(),
        ),
        "fw_rule"
    );

    let flow = PerLcoreFlowMaps::new(0).expect("PerLcoreFlowMaps");
    let mut composed = ComposedMaps { cfg: &shared, flow };
    let tok = shared.register_reader();
    let meta = port_meta();

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // DIRECTION 5 (guest → fabric): fd write → af_xdp rx → process_guest_tx → SNAT+encap → uplink.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let g_frame = guest_frame();
    let mut proven = false;
    'rx: for round in 0..80 {
        // Re-inject on every round: af_xdp copy-mode on tap drops warmup frames.
        for _ in 0..8 {
            // SAFETY: writing g_frame.len() bytes from a valid slice to our tap fd.
            let n = unsafe { libc::write(fd, g_frame.as_ptr().cast(), g_frame.len()) };
            assert!(n >= 0, "write(tap fd) failed {}", errno());
        }
        for _ in 0..25 {
            let mut burst = MbufBurst::new();
            let got = rxq.rx(&mut burst);
            for mb in burst.iter_mut().take(got) {
                // Only run the datapath on OUR guest frame (skip kernel-generated netdev noise).
                let data = mb.data();
                if data.len() < g_frame.len() || data[..g_frame.len()] != g_frame[..] {
                    continue;
                }
                let mut pkt = MbufPkt::new(mb);
                let out = process_guest_tx(
                    &mut pkt,
                    &mut composed,
                    &GuestTxIn {
                        meta: &meta,
                        src_ifindex: tap_ifindex,
                        now: 0,
                    },
                );
                let bytes = mp_bytes(&pkt);
                assert_eq!(
                    out.action,
                    Action::Redirect(UPLINK_IFINDEX),
                    "DIRECTION 5: SNAT+encap arm redirects out the uplink"
                );
                assert_eq!(
                    bytes.len(),
                    g_frame.len() + 40,
                    "DIRECTION 5: outer IPv6 header (40B) prepended by grow_head/write_outer_v6"
                );
                // Concrete outer-header sanity + inner SNAT (from flowplane_core::encap::ETH_LEN=14).
                let eth = flowplane_core::encap::ETH_LEN;
                assert_eq!(bytes[eth] >> 4, 6, "outer IPv6 version 6");
                assert_eq!(bytes[eth + 6], 4, "outer next-header = IPPROTO_IPIP");
                assert_eq!(
                    &bytes[eth + 8..eth + 24],
                    &SRC_UL,
                    "outer src = node underlay"
                );
                assert_eq!(
                    &bytes[eth + 24..eth + 40],
                    &NEXTHOP_UL,
                    "outer dst = route nexthop"
                );
                let inner_ip = eth + 40;
                assert_eq!(
                    &bytes[inner_ip + 12..inner_ip + 16],
                    &NAT_IP,
                    "inner IPv4 src SNAT'd to nat_ip"
                );
                proven = true;
                eprintln!(
                    "OK: DIRECTION 5 (fd write -> af_xdp rx -> process_guest_tx): guest frame reached \
                     the shared datapath over af_xdp-on-tap; SNAT+encap -> Redirect(uplink), +40B \
                     (round {round})"
                );
                break 'rx;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    assert!(
        proven,
        "DIRECTION 5 FAILED: no fd-written guest frame ever reached process_guest_tx over \
         af_xdp-on-tap after many injects"
    );

    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // DIRECTION 6 (fabric → guest, return transport): TX a decapped delivery frame on the pool port
    // → it becomes readable on the tap fd (the VM side). Raw transport check only.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    let d_frame = delivery_frame();
    let mut return_ok = false;
    'tx: for round in 0..80 {
        {
            let mut m = pool.alloc().expect("alloc mbuf from pool");
            let dst = m
                .append(d_frame.len() as u16)
                .expect("append into mbuf tailroom");
            dst.copy_from_slice(&d_frame);
            let mut burst = MbufBurst::new();
            burst.push(m);
            let _ = txq.tx(&mut burst); // copy-mode may drop warmup frames; retry on next round
        }
        for _ in 0..25 {
            let mut buf = [0u8; 2048];
            // SAFETY: reading into a valid, sized buffer from our non-blocking tap fd.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                let got = &buf[..n as usize];
                if got.len() >= d_frame.len() && got[..d_frame.len()] == d_frame[..] {
                    return_ok = true;
                    eprintln!(
                        "OK: DIRECTION 6 (af_xdp tx -> fd read): {}B delivery frame read off the tap \
                         fd matching the tx'd frame (round {round})",
                        got.len()
                    );
                    break 'tx;
                }
                // Not ours (kernel noise); keep draining.
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    assert!(
        return_ok,
        "DIRECTION 6 FAILED: a delivery frame TX'd on the pool port never became readable on the \
         tap fd — the return transport does not reach the VM"
    );

    eprintln!(
        "PROVEN: guest-egress datapath (process_guest_tx) runs over af_xdp-on-tap driven by a raw \
         tap fd, and the return transport reaches the fd."
    );

    shared.report_quiescent(&tok);

    // ── teardown: drop the Port (stop+close) BEFORE the fd/tap guards run. ─────────────────────────
    drop(port);
    drop(pool);
    // owned_fd closes the fd on drop; _guard deletes the tap.
}
