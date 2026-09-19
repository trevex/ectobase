//! `BPF_PROG_TEST_RUN` anchor for the edge's NAT return relay (`wan_rx` → `NAT_OWNERS{,6}`).
//!
//! The sim models the tries; this runs the real bytecode against the kernel's own tries, seeded
//! through the dataplane's decomposition (`owner_prefixes{4,6}`), and checks relay
//! (`TC_ACT_REDIRECT`) vs pass-through (`TC_ACT_OK`) at both edges of an unaligned (multi-prefix)
//! block and on both sides of a prefix boundary inside it, with parity against the native
//! `SimNode::wan_rx`. A key-layout divergence (address/port byte order, prefix lengths) between the
//! control plane's writer and the bytecode's lookup shows as a mismatch: the block's edges and
//! inner boundaries land in the wrong prefix, or in none.
//!
//! The owner's VNI and underlay ride the tunnel key, which test-run cannot observe (the relay
//! stamps it and redirects to the geneve device, writing no bytes); the sim oracle
//! (`neighbor_nat_test`) covers owner selection. What is observable here is the verdict and that
//! the frame leaves unchanged either way.
//!
//! Like `anchor_guest_tx`, `wan_rx` is a `SchedClassifier`, and aya 0.13.1 exposes no tc
//! `test_run`, so this issues the raw `bpf(BPF_PROG_TEST_RUN, ...)` syscall on the fd of aya's
//! loaded program with a `struct __sk_buff` ctx.
//!
//! Privileged: needs CAP_BPF + a kernel with tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::SchedClassifier;
use flowplane_common::{
    Local, NatOwner, NatOwnerKey, NatOwnerKey6, NeighborNat6Entry, NeighborNatEntry,
    NAT_OWNER_ADDR_BITS4, NAT_OWNER_ADDR_BITS6,
};
use flowplane_control::natowner::{owner_prefixes4, owner_prefixes6};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Fixture (an edge holding one v4 and one v6 neighbor-NAT block, no WAN LB addresses) --------

/// `wan_rx` keys nothing on the skb's ifindex; loopback (1) always exists, so the kernel's skb
/// test-run can resolve `__sk_buff.ifindex` to a real device.
const IFINDEX: u32 = 1;
const UPLINK_IFINDEX: u32 = 7;
const VNI: u32 = 100;
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const NAT_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const OWNER: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    }
}

/// Neither edge is aligned (20000 is a multiple of 32, 30000 of 16), so the block is ten prefixes
/// of mixed lengths — a single-prefix block would let a wrong prefix length pass unnoticed.
fn v4_block() -> NeighborNatEntry {
    NeighborNatEntry {
        underlay: OWNER,
        nat_ip: NAT_IP,
        vni: VNI,
        port_min: 20000,
        port_max: 30000,
        enabled: 1,
        _pad: [0; 3],
    }
}

/// Unaligned on both edges too (1100 is a multiple of 4, 5000 of 8): eleven prefixes.
fn v6_block() -> NeighborNat6Entry {
    NeighborNat6Entry {
        underlay: OWNER,
        nat_ip6: NAT_IP6,
        vni: VNI,
        port_min: 1100,
        port_max: 5000,
        enabled: 1,
        _pad: [0; 3],
    }
}

/// The port where a prefix inside the block begins, its predecessor ending one port below. Taken
/// from the middle of the decomposition so both sides are strictly inside the block: only a
/// correct prefix length on both prefixes relays both probes.
fn inner_boundary(entries: impl Iterator<Item = (u32, u16)>, addr_bits: u32) -> u16 {
    let mut prefixes: Vec<(u32, u16)> = entries.collect();
    prefixes.sort_by_key(|&(_, port)| port);
    let (plen, start) = prefixes[prefixes.len() / 2];
    let (prev_plen, prev_start) = prefixes[prefixes.len() / 2 - 1];
    assert!(plen > addr_bits && prev_plen > addr_bits, "port prefixes");
    let prev_span = 1u32 << (16 + addr_bits - prev_plen);
    assert_eq!(
        u32::from(prev_start) + prev_span,
        u32::from(start),
        "the decomposition's prefixes are contiguous"
    );
    start
}

/// A WAN return: Ethernet + IPv4 + TCP from an internet peer to `NAT_IP:dport`.
fn frame4(dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let mut f = Vec::new();
    PacketBuilder::ethernet2([0x02; 6], [0x04; 6])
        .ipv4([192, 0, 2, 1], NAT_IP, 64)
        .tcp(443, dport, 1, 1024)
        .ack(1)
        .write(&mut f, &[])
        .unwrap();
    f
}

/// The IPv6 twin of [`frame4`], to `NAT_IP6:dport`.
fn frame6(dport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let peer = [0x20, 1, 0xd, 0xb8, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut f = Vec::new();
    PacketBuilder::ethernet2([0x02; 6], [0x04; 6])
        .ipv6(peer, NAT_IP6, 64)
        .tcp(443, dport, 1, 1024)
        .ack(1)
        .write(&mut f, &[])
        .unwrap();
    f
}

// --- Raw BPF_PROG_TEST_RUN syscall (with a __sk_buff ctx), as in anchor_guest_tx.rs ------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const TC_ACT_OK: u32 = 0;
const TC_ACT_REDIRECT: u32 = 7;

/// `sizeof(struct __sk_buff)` and `offsetof(ifindex)` on this kernel's stable UAPI (mirrors
/// `anchor_guest_tx.rs`).
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
/// `ifindex` field is `ifindex`. Returns the kernel's return code (the tc action) + the (possibly
/// mutated) output packet.
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

// --- The anchor test --------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn nat_return_relay_matches_native_sim() {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-wan-rx-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .default_map_pin_directory(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    // `try_wan_rx` bails out (TC_ACT_OK) without LOCAL[0], before it ever reaches the tries — an
    // unseeded LOCAL would make every "relay" case fail and every "pass" case pass vacuously.
    {
        let mut l: Array<_, Local> = Array::try_from(ebpf.map_mut("LOCAL").unwrap()).unwrap();
        l.set(0, local(), 0).unwrap();
    }
    // Seed the kernel's tries with exactly what the control core writes for these blocks, so the
    // bytecode's lookup key is checked against the writer's key, not against a hand-built one.
    let entries4 = owner_prefixes4(&v4_block());
    assert!(
        entries4.len() > 1,
        "the v4 block must span several prefixes: {entries4:?}"
    );
    {
        let mut t: LpmTrie<_, NatOwnerKey, NatOwner> =
            LpmTrie::try_from(ebpf.map_mut("NAT_OWNERS").unwrap()).unwrap();
        for &(plen, key, owner) in &entries4 {
            t.insert(&Key::new(plen, key), owner, 0).unwrap();
        }
    }
    let entries6 = owner_prefixes6(&v6_block());
    assert!(
        entries6.len() > 1,
        "the v6 block must span several prefixes: {entries6:?}"
    );
    {
        let mut t: LpmTrie<_, NatOwnerKey6, NatOwner> =
            LpmTrie::try_from(ebpf.map_mut("NAT_OWNERS6").unwrap()).unwrap();
        for &(plen, key, owner) in &entries6 {
            t.insert(&Key::new(plen, key), owner, 0).unwrap();
        }
    }
    let mid4 = inner_boundary(
        entries4
            .iter()
            .map(|(plen, k, _)| (*plen, u16::from_be_bytes(k.port))),
        NAT_OWNER_ADDR_BITS4,
    );
    let mid6 = inner_boundary(
        entries6
            .iter()
            .map(|(plen, k, _)| (*plen, u16::from_be_bytes(k.port))),
        NAT_OWNER_ADDR_BITS6,
    );

    // `SimNode::wan_rx` reads the edge identity from the node itself, the core's maps from `maps`.
    let mut sim = SimNode::with_local(local());
    sim.maps.local = Some(local());
    sim.maps.add_neighbor_nat(v4_block());
    sim.maps.add_neighbor_nat6(v6_block());

    let prog: &mut SchedClassifier = ebpf
        .program_mut("wan_rx")
        .expect("wan_rx program present")
        .try_into()
        .expect("wan_rx is a SchedClassifier program");
    prog.load().expect("verify/load wan_rx");
    let fd = prog.fd().expect("wan_rx fd").as_fd().as_raw_fd();

    let (end4, end6) = (mid4 - 1, mid6 - 1);
    let cases: Vec<(Vec<u8>, bool, String)> = vec![
        (frame4(19999), false, "v4: just below the block".into()),
        (frame4(20000), true, "v4: first port".into()),
        (frame4(24999), true, "v4: inside".into()),
        (frame4(end4), true, format!("v4: {end4} ends a prefix")),
        (frame4(mid4), true, format!("v4: {mid4} starts the next")),
        (frame4(29999), true, "v4: last port".into()),
        (frame4(30000), false, "v4: just past the block".into()),
        (frame6(1099), false, "v6: just below the block".into()),
        (frame6(1100), true, "v6: first port".into()),
        (frame6(end6), true, format!("v6: {end6} ends a prefix")),
        (frame6(mid6), true, format!("v6: {mid6} starts the next")),
        (frame6(4999), true, "v6: last port".into()),
        (frame6(5000), false, "v6: just past the block".into()),
    ];
    for (frame, relay, what) in &cases {
        let out = bpf_prog_test_run_skb(fd, frame, IFINDEX).expect("BPF_PROG_TEST_RUN on wan_rx");
        let want = if *relay { TC_ACT_REDIRECT } else { TC_ACT_OK };
        assert_eq!(out.retval, want, "{what}: real bytecode");
        let native = sim.wan_rx(frame);
        let native_want = if *relay {
            Action::Redirect(UPLINK_IFINDEX)
        } else {
            Action::Pass
        };
        assert_eq!(native.action, native_want, "{what}: native sim");
        // The relay stamps the tunnel key and the pass hands the frame on: neither writes a byte.
        assert_eq!(out.data, *frame, "{what}: real bytecode wrote bytes");
        assert_eq!(native.pkt, *frame, "{what}: native sim wrote bytes");
    }
}
