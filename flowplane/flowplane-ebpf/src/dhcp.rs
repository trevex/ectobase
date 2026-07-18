use flowplane_common::PortMeta;

use crate::arp_nd::GW_MAC;
use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_UDP};

// The DHCPv4 request parse + reply byte construction lived in `flowplane_core::dhcp` over the
// `Pkt`/`Maps` seam. The XDP guest_dhcp entry point has been removed (the guest edge is now
// tcx-only); the DHCPv6 responder logic below is TC-only (`tc_dhcpv6_respond`). The helpers
// (`d6_checksum`, `d6_url_len`, `D6Reply`, constants) are shared between XDP (removed) and tc.

/// MAC learning for the egress edge: if the request's Ethernet source differs from the cached
/// `meta.guest_mac`, update PORT_META (keyed by ifindex), UNDERLAY (keyed by underlay IPv6), and
/// INTERFACES (keyed by vni+ipv4) so the local fast path and ingress delivery use the new MAC
/// immediately. The test suite sends REQUEST with a different Ethernet src than chaddr to verify
/// that the datapath learns the actual L2 source address used by the VM.
#[inline(always)]
pub(crate) fn learn_mac(ifindex: u32, meta: &PortMeta, eth_src: [u8; 6]) {
    if eth_src != meta.guest_mac {
        let mut updated = *meta;
        updated.guest_mac = eth_src;
        let _ = crate::maps::PORT_META.insert(&ifindex, &updated, 0);
        if let Some(u) = unsafe { crate::maps::UNDERLAY.get(&meta.underlay_ipv6) } {
            let mut u2 = *u;
            u2.guest_mac = eth_src;
            let _ = crate::maps::UNDERLAY.insert(&meta.underlay_ipv6, &u2, 0);
        }
        let ikey = flowplane_common::IfaceKey::new(meta.vni, meta.guest_ipv4);
        if let Some(iv) = unsafe { crate::maps::INTERFACES.get(&ikey) } {
            let mut iv2 = *iv;
            iv2.guest_mac = eth_src;
            let _ = crate::maps::INTERFACES.insert(&ikey, &iv2, 0);
        }
    }
}

// ──────────────────────── DHCPv6 responder ────────────────────────

// DHCPv6 message types (RFC 8415)
const D6_SOLICIT: u8 = 1;
const D6_ADVERTISE: u8 = 2;
const D6_REQUEST: u8 = 3;
const D6_CONFIRM: u8 = 4;
const D6_REPLY: u8 = 7;

// DHCPv6 option codes
const D6_OPT_CLIENTID: u16 = 1;
const D6_OPT_SERVERID: u16 = 2;
const D6_OPT_IA_NA: u16 = 3;
const D6_OPT_RAPID_COMMIT: u16 = 14;
const D6_OPT_USER_CLASS: u16 = 15;
const D6_OPT_VENDOR_CLASS: u16 = 16;
const D6_OPT_DNS: u16 = 23;
const D6_OPT_BOOT_FILE: u16 = 59;

// DUID type for server DUID-LL (DP_DHCPV6_HW_ID = 0xabcd)
const DUID_LL_TYPE: u16 = 3;
const DP_DHCPV6_HW_ID: u16 = 0xabcd;

// DHCPv6 packet starts at ETH+IPv6+UDP = 14+40+8 = 62
const F6_DHCP: usize = ETH_LEN + 40 + 8;
// Options start 4 bytes in (msg_type(1)+tid(3))
const F6_OPTS: usize = F6_DHCP + 4;
// Minimum packet we need to peek at: ETH + IPv6 + UDP + DHCPv6 header
const MIN_D6_LEN: usize = F6_OPTS;

// Vendor class enterprise number for PXE (343)
const PXE_ENTERPRISE: u32 = 343;

// PXE mode discriminator
const PXE_NONE: u8 = 0;
const PXE_TFTP: u8 = 1;
const PXE_HTTP: u8 = 2;

// TFTP path constant (mirrors dpservice DP_PXE_TFTP_PATH)
const TFTP_PATH: &[u8] = b"ipxe/x86_64/ipxe.new";

// Maximum DNS entries to include
const D6_MAX_DNS: usize = flowplane_common::DHCP_MAX_DNS; // 8 entries

// Cap DUID to 10 bytes: minimum for DUID-LL with MAC (type(2)+hwtype(2)+mac(6)=10)
const D6_MAX_DUID: usize = 10;

// Maximum boot file URL length: scheme(7) + "[" + host(46) + "]/" + path(64) = 120
const D6_MAX_URL: usize = 120;

// Maximum DHCPv6 options total size
const D6_MAX_OPTS: usize = 14 // ServerId: op(2)+len(2)+DUID_LL(10)=14
    + (4 + D6_MAX_DUID) // ClientId: op(2)+len(2)+duid_cap(10)=14
    + 4  // RapidCommit: op(2)+len(2)=4
    + 50 // IA_NA full with nested IAADDR+STATUS_CODE
    + (4 + D6_MAX_DNS * 16) // DNS: 4+128=132
    + (4 + D6_MAX_URL); // BootFileUrl: 4+120=124

/// Compute the URL length for PXE without building it in a buffer.
/// Returns 0 if PXE is not configured.
#[inline(always)]
fn d6_url_len(pxe_mode: u8, dm: &flowplane_common::DhcpMeta) -> usize {
    if pxe_mode == PXE_NONE {
        return 0;
    }
    let host_len = dm.pxe_host_len as usize;
    if host_len == 0 || host_len > 46 {
        return 0;
    }
    let path_len = if pxe_mode == PXE_TFTP {
        TFTP_PATH.len()
    } else {
        dm.boot_filename_len as usize
    };
    // scheme(7) + "[" + host + "]/" + path
    7 + 1 + host_len + 2 + path_len
}

// Scan window for the option parser: copied from the packet into a stack buffer so the parse
// loop iterates a fixed-size array (no per-iteration packet-bound branch, which is what made the
// inlined parser explode the verifier's state count). 192 bytes covers any realistic SOLICIT.
const D6_SCAN: usize = 128;

const D6_MAX_TOTAL: usize = F6_OPTS + D6_MAX_OPTS;

/// Parsed request fields plus the values the DHCPv6 responder computes before emitting the reply.
/// Passed by reference across the BPF-to-BPF call boundary so parse / emit verify independently.
#[derive(Clone, Copy)]
struct D6Reply {
    // Filled by the parse subprogram:
    got_clientid: bool,
    duid: [u8; D6_MAX_DUID],
    duid_len: u16,
    got_iana: bool,
    iaid: u32,
    rapid_commit: bool,
    pxe_mode: u8,
    // Filled by the responder entry point:
    reply_type: u8,
    tid: [u8; 3],
    dns6_count: u16,
    url_len: u16,
    real_reply_len: u16,
    req_src6: [u8; 16],
    req_eth_src: [u8; 6],
}

// Constant option bytes live in `.rodata` so `d6_emit` doesn't stage them on its stack — the
// combined stack of `guest_tx` + `d6_emit` must stay under the BPF 512-byte limit, and a 50-byte
// IA_NA stack buffer pushed it to 592. store_bytes copies straight from these read-only sources.
//
// IA_NA template: opt(3)+len(46) | iaid(0) | t1=∞ | t2=∞ | IAADDR opt(5)+len(30) | addr(0) |
//   preferred=∞ | valid=∞ | STATUS opt(13)+len(2)+code(0=SUCCESS). The iaid (offset 4) and the
//   IPv6 address (offset 20) are overwritten with two further small store_bytes from runtime data.
#[rustfmt::skip]
static IA_TEMPLATE: [u8; 50] = [
    0, 3,  0, 46,
    0, 0, 0, 0,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0, 5,  0, 30,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0, 13, 0, 2, 0, 0,
];
// RapidCommit option (opt 14, len 0).
static RC_OPT: [u8; 4] = [0, 14, 0, 0];
// One zero byte, used to null the odd-length checksum pad byte.
static ZERO1: [u8; 1] = [0];
// Boot file URL pieces.
static TFTP_SCHEME: [u8; 7] = *b"tftp://";
static HTTP_SCHEME: [u8; 7] = *b"http://";
static URL_LBRACKET: [u8; 1] = [b'['];
static URL_RBRACKET: [u8; 2] = [b']', b'/'];

/// Compute and write the DHCPv6 reply's UDP checksum. A separate BPF subprogram (not nested under
/// `d6_emit`) so its locals form their own short call chain with the large `guest_tx` frame rather
/// than adding to `guest_tx + d6_emit` (the combined-stack 512-byte limit is the binding one here).
///
/// `data`/`data_end` are passed in (re-deriving via `ctx` in a subprogram trips the verifier — see
/// `d6_parse`). Sums the IPv6 pseudo-header + UDP datagram over a CONSTANT number of words, folding
/// in only words within `udp_len` so the uninitialised pad past the real reply is read-but-ignored.
#[inline(never)]
fn d6_checksum(data: usize, data_end: usize, udp_len: u16) -> u32 {
    if data + D6_MAX_TOTAL > data_end {
        return 0;
    }
    let p = data as *const u8;
    const D6_UDP_CKSUM_LEN: usize = D6_MAX_TOTAL - ETH_LEN - 40;
    // Clamp to the constant scan length so the verifier knows the gate `j < udp_len_usize` is
    // bounded (an unbounded u16 param forked the loop state past the 1M instruction limit).
    let udp_len_usize = (udp_len as usize).min(D6_UDP_CKSUM_LEN);
    let mut cs: u32 = 0;
    let mut k: usize = 0;
    while k < 16 {
        cs = cs.wrapping_add(u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 8 + k) as *const u16)
        }) as u32);
        cs = cs.wrapping_add(u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 24 + k) as *const u16)
        }) as u32);
        k += 2;
    }
    cs = cs.wrapping_add(udp_len as u32);
    cs = cs.wrapping_add(IPPROTO_UDP as u32);
    let mut j: usize = 0;
    while j < D6_UDP_CKSUM_LEN {
        if j < udp_len_usize {
            cs = cs.wrapping_add(u16::from_be(unsafe {
                core::ptr::read_unaligned(p.add(ETH_LEN + 40 + j) as *const u16)
            }) as u32);
        }
        j += 2;
    }
    cs = (cs & 0xffff) + (cs >> 16);
    cs = (cs & 0xffff) + (cs >> 16);
    let cksum = !(cs as u16);
    unsafe {
        core::ptr::write_unaligned((data + ETH_LEN + 46) as *mut u16, cksum.to_be());
    }
    cksum as u32
}

// ──────────────────────── DHCPv6 responder (tc / skb) ────────────────────────

/// skb variant of `store`: copy `len` bytes from `buf` into the skb at byte `offset`.
#[inline(always)]
unsafe fn tc_store(
    skb: *mut aya_ebpf::bindings::__sk_buff,
    offset: usize,
    buf: *const u8,
    len: usize,
) -> bool {
    aya_ebpf::helpers::bpf_skb_store_bytes(
        skb,
        offset as u32,
        buf as *const core::ffi::c_void,
        len as u32,
        0,
    ) == 0
}

/// skb variant of `d6_store_url` (URL pieces, one small store_bytes each).
/// skb variant of `d6_store_url`. Separate subprogram (mirrors XDP's `d6_store_url`) so the early
/// `return 0` on a zero/oversized host length keeps each variable-length store's length bound
/// provable to the verifier without spilling it across the emit path's many prior stores.
#[inline(never)]
fn tc_d6_store_url(
    skb: *mut aya_ebpf::bindings::__sk_buff,
    base: usize,
    pxe_mode: u8,
    dm: &flowplane_common::DhcpMeta,
) -> usize {
    let host_len = dm.pxe_host_len as usize;
    if host_len == 0 || host_len > 46 {
        return 0;
    }
    let scheme_ptr = if pxe_mode == PXE_TFTP {
        TFTP_SCHEME.as_ptr()
    } else {
        HTTP_SCHEME.as_ptr()
    };
    let mut up = 0usize;
    unsafe {
        tc_store(skb, base + up, scheme_ptr, 7);
        up += 7;
        tc_store(skb, base + up, URL_LBRACKET.as_ptr(), 1);
        up += 1;
        tc_store(skb, base + up, dm.pxe_host.as_ptr(), host_len);
        up += host_len;
        tc_store(skb, base + up, URL_RBRACKET.as_ptr(), 2);
        up += 2;
        if pxe_mode == PXE_TFTP {
            let path_len = TFTP_PATH.len();
            tc_store(skb, base + up, TFTP_PATH.as_ptr(), path_len);
            up += path_len;
        } else {
            let file_len = (dm.boot_filename_len as usize).min(64);
            if file_len > 0 {
                tc_store(skb, base + up, dm.boot_filename.as_ptr(), file_len);
                up += file_len;
            }
        }
    }
    up
}

/// skb variant of `d6_parse`. Identical option walk; reads via bpf_skb_load_bytes.
#[inline(never)]
fn tc_d6_parse(skb: *mut aya_ebpf::bindings::__sk_buff, r: &mut D6Reply, n: usize) -> u32 {
    let mut i: usize = 0;
    let mut guard: u32 = 0;
    while i + 4 <= n && i + 4 <= D6_SCAN && guard < 12 {
        guard += 1;
        let mut hb = [0u8; 4];
        if unsafe {
            aya_ebpf::helpers::bpf_skb_load_bytes(
                skb as *const core::ffi::c_void,
                (F6_OPTS + i) as u32,
                hb.as_mut_ptr() as *mut core::ffi::c_void,
                4,
            )
        } != 0
        {
            break;
        }
        let code = ((hb[0] as u16) << 8) | hb[1] as u16;
        let olen = (((hb[2] as u16) << 8) | hb[3] as u16).min(D6_SCAN as u16);
        let v = i + 4;

        match code {
            D6_OPT_RAPID_COMMIT => r.rapid_commit = true,
            D6_OPT_USER_CLASS => {
                if r.pxe_mode == PXE_NONE {
                    r.pxe_mode = PXE_HTTP;
                }
            }
            D6_OPT_IA_NA => {
                let mut vb = [0u8; 4];
                if unsafe {
                    aya_ebpf::helpers::bpf_skb_load_bytes(
                        skb as *const core::ffi::c_void,
                        (F6_OPTS + v) as u32,
                        vb.as_mut_ptr() as *mut core::ffi::c_void,
                        4,
                    )
                } == 0
                {
                    r.iaid = u32::from_be_bytes(vb);
                    r.got_iana = true;
                }
            }
            D6_OPT_VENDOR_CLASS => {
                let mut vb = [0u8; 4];
                if unsafe {
                    aya_ebpf::helpers::bpf_skb_load_bytes(
                        skb as *const core::ffi::c_void,
                        (F6_OPTS + v) as u32,
                        vb.as_mut_ptr() as *mut core::ffi::c_void,
                        4,
                    )
                } == 0
                    && u32::from_be_bytes(vb) == PXE_ENTERPRISE
                    && r.pxe_mode == PXE_NONE
                {
                    r.pxe_mode = PXE_TFTP;
                }
            }
            D6_OPT_CLIENTID => {
                r.got_clientid = true;
                let dl = (olen as usize).min(D6_MAX_DUID);
                r.duid_len = dl as u16;
                let _ = unsafe {
                    aya_ebpf::helpers::bpf_skb_load_bytes(
                        skb as *const core::ffi::c_void,
                        (F6_OPTS + v) as u32,
                        r.duid.as_mut_ptr() as *mut core::ffi::c_void,
                        D6_MAX_DUID as u32,
                    )
                };
            }
            _ => {}
        }
        i = v + olen as usize;
    }
    r.pxe_mode as u32
}

/// skb variant of `d6_emit`. Identical bytes; variable-offset writes via bpf_skb_store_bytes,
/// fixed-offset writes via direct packet pointers (data/data_end passed in, post change_tail).
#[inline(never)]
fn tc_d6_emit(
    skb: *mut aya_ebpf::bindings::__sk_buff,
    data: usize,
    data_end: usize,
    meta: &PortMeta,
    r: &D6Reply,
) {
    if data + D6_MAX_TOTAL > data_end {
        return;
    }
    let ifindex = unsafe { (*skb).ifindex };
    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };
    let p = data as *mut u8;
    let real_reply_len = r.real_reply_len as usize;

    // ─── Ethernet ───
    unsafe {
        write6(p, &r.req_eth_src);
        write6(p.add(6), &GW_MAC);
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }

    // ─── IPv6 ───
    let ipv6_payload_len = (real_reply_len - ETH_LEN - 40) as u16;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 4) as *mut u16, ipv6_payload_len.to_be());
        *p.add(ETH_LEN + 6) = IPPROTO_UDP;
        *p.add(ETH_LEN + 7) = 64;
        write16(p.add(ETH_LEN + 8), &meta.gateway_ipv6);
        write16(p.add(ETH_LEN + 24), &r.req_src6);
    }

    // ─── UDP ───
    let udp_len = ipv6_payload_len;
    unsafe {
        core::ptr::write_unaligned(p.add(ETH_LEN + 40) as *mut u16, 547u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 42) as *mut u16, 546u16.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 44) as *mut u16, udp_len.to_be());
        core::ptr::write_unaligned(p.add(ETH_LEN + 46) as *mut u16, 0u16);
    }

    // ─── DHCPv6 message header ───
    unsafe {
        *p.add(F6_DHCP) = r.reply_type;
        *p.add(F6_DHCP + 1) = r.tid[0];
        *p.add(F6_DHCP + 2) = r.tid[1];
        *p.add(F6_DHCP + 3) = r.tid[2];
    }

    let duid_len_usize = (r.duid_len as usize).min(D6_MAX_DUID);
    let mut off: usize = 0;

    // ServerId: DUID-LL — constant offset, direct packet write.
    unsafe {
        core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_SERVERID.to_be());
        core::ptr::write_unaligned(p.add(F6_OPTS + off + 2) as *mut u16, 10u16.to_be());
        core::ptr::write_unaligned(p.add(F6_OPTS + off + 4) as *mut u16, DUID_LL_TYPE.to_be());
        core::ptr::write_unaligned(
            p.add(F6_OPTS + off + 6) as *mut u16,
            DP_DHCPV6_HW_ID.to_be(),
        );
        write6(p.add(F6_OPTS + off + 8), &meta.guest_mac);
    }
    off += 14;

    // ClientId: echo the client's DUID (off still constant 14 here).
    if r.got_clientid && duid_len_usize > 0 {
        unsafe {
            core::ptr::write_unaligned(p.add(F6_OPTS + off) as *mut u16, D6_OPT_CLIENTID.to_be());
            core::ptr::write_unaligned(
                p.add(F6_OPTS + off + 2) as *mut u16,
                (duid_len_usize as u16).to_be(),
            );
        }
        let duid_ptr = r.duid.as_ptr();
        let mut di = 0usize;
        while di < duid_len_usize && di < D6_MAX_DUID {
            unsafe {
                *p.add(F6_OPTS + off + 4 + di) = *duid_ptr.add(di);
            }
            di += 1;
        }
        off += 4 + duid_len_usize;
    }

    // From here `off` is runtime-variable → store_bytes.
    let mut hdr = [0u8; 4];

    if r.got_iana {
        let iaid_be = r.iaid.to_be_bytes();
        unsafe {
            tc_store(skb, F6_OPTS + off, IA_TEMPLATE.as_ptr(), 50);
            tc_store(skb, F6_OPTS + off + 4, iaid_be.as_ptr(), 4);
            tc_store(skb, F6_OPTS + off + 20, meta.guest_ipv6.as_ptr(), 16);
        }
        off += 50;
    }

    if r.rapid_commit {
        unsafe {
            tc_store(skb, F6_OPTS + off, RC_OPT.as_ptr(), 4);
        }
        off += 4;
    }

    let dns6_count = (r.dns6_count as usize).min(D6_MAX_DNS);
    if dns6_count > 0 {
        if let Some(cfg) = dhcp_cfg {
            let dns_data_len = (dns6_count as u16) * 16;
            hdr[0..2].copy_from_slice(&D6_OPT_DNS.to_be_bytes());
            hdr[2..4].copy_from_slice(&dns_data_len.to_be_bytes());
            unsafe {
                tc_store(skb, F6_OPTS + off, hdr.as_ptr(), 4);
            }
            let dns6_ptr = cfg.dns6.as_ptr();
            let mut di = 0usize;
            while di < dns6_count {
                unsafe {
                    tc_store(
                        skb,
                        F6_OPTS + off + 4 + di * 16,
                        dns6_ptr.add(di) as *const u8,
                        16,
                    );
                }
                di += 1;
            }
            off += 4 + dns6_count * 16;
        }
    }

    if r.url_len as usize > 0 {
        if let Some(dm) = dhcp_meta {
            hdr[0..2].copy_from_slice(&D6_OPT_BOOT_FILE.to_be_bytes());
            hdr[2..4].copy_from_slice(&r.url_len.to_be_bytes());
            unsafe {
                tc_store(skb, F6_OPTS + off, hdr.as_ptr(), 4);
                // Separate #[inline(never)] subprogram: its tight `return 0` on a zero/oversized
                // host_len keeps each variable-length store_bytes' length bound provable locally
                // (inlining lost the bound across the many preceding stores → "zero-sized read").
                let written = tc_d6_store_url(skb, F6_OPTS + off + 4, r.pxe_mode, dm);
                off += 4 + written;
            }
        }
    }
    let _ = off;

    // Zero the single odd-length pad byte (see d6_emit).
    unsafe {
        tc_store(skb, real_reply_len, ZERO1.as_ptr(), 1);
    }
}

/// In-datapath DHCPv6 responder for tc. Mirrors `try_dhcpv6_reply` but resizes the skb with
/// `bpf_skb_change_tail` (absolute length) + `pull_data` to make the head writable, and reads
/// `ifindex` from the `__sk_buff`. Returns `true` if a reply was built into the skb.
#[inline(always)]
pub fn tc_dhcpv6_respond(ctx: &aya_ebpf::programs::TcContext, meta: &PortMeta) -> bool {
    let skb = ctx.skb.skb;
    // Pull the fixed DHCPv6 header so the detection + initial fields are on direct packet access.
    if ctx.pull_data(MIN_D6_LEN as u32).is_err() {
        return false;
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + MIN_D6_LEN > data_end {
        return false;
    }
    let p = data as *const u8;

    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return false;
    }
    if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_UDP {
        return false;
    }
    let udp_dst =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16) });
    if udp_dst != 547 {
        return false;
    }

    let msg_type = unsafe { *p.add(F6_DHCP) };
    if msg_type != D6_SOLICIT && msg_type != D6_REQUEST && msg_type != D6_CONFIRM {
        return false;
    }

    let mut r = D6Reply {
        got_clientid: false,
        duid: [0u8; D6_MAX_DUID],
        duid_len: 0,
        got_iana: false,
        iaid: 0,
        rapid_commit: false,
        pxe_mode: PXE_NONE,
        reply_type: D6_REPLY,
        tid: [
            unsafe { *p.add(F6_DHCP + 1) },
            unsafe { *p.add(F6_DHCP + 2) },
            unsafe { *p.add(F6_DHCP + 3) },
        ],
        dns6_count: 0,
        url_len: 0,
        real_reply_len: 0,
        req_src6: unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) },
        req_eth_src: unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) },
    };

    // Real option-byte count from the skb's total length, captured before the grow.
    let cur_len = (data_end - data) as usize;
    let skb_len = unsafe { (*skb).len } as usize;
    let opts_avail = if skb_len > F6_OPTS {
        skb_len - F6_OPTS
    } else {
        0
    };
    let n = if opts_avail < D6_SCAN {
        opts_avail
    } else {
        D6_SCAN
    };

    // Parse options (reads via skb load_bytes, which can read the whole skb regardless of how much
    // is currently in the linear head).
    r.pxe_mode = tc_d6_parse(skb, &mut r, n) as u8;

    r.reply_type = if msg_type == D6_SOLICIT && !r.rapid_commit {
        D6_ADVERTISE
    } else {
        D6_REPLY
    };

    // Config-derived option sizes.
    let ifindex = unsafe { (*skb).ifindex };
    let dhcp_cfg = crate::maps::DHCP_CONFIG.get(0);
    let dhcp_meta = unsafe { crate::maps::DHCP_META.get(&ifindex) };

    let dns6_count = if let Some(cfg) = dhcp_cfg {
        (cfg.dns6_len as usize).min(D6_MAX_DNS)
    } else {
        0
    };
    r.dns6_count = dns6_count as u16;

    let url_len = if r.pxe_mode != PXE_NONE {
        if let Some(dm) = dhcp_meta {
            d6_url_len(r.pxe_mode, dm).min(D6_MAX_URL)
        } else {
            0
        }
    } else {
        0
    };
    r.url_len = url_len as u16;

    let duid_len_usize = (r.duid_len as usize).min(D6_MAX_DUID);
    let real_opts_len: usize =
        (14 + if r.got_clientid && duid_len_usize > 0 {
            4 + duid_len_usize
        } else {
            0
        } + if r.got_iana { 50 } else { 0 }
            + if r.rapid_commit { 4 } else { 0 }
            + if dns6_count > 0 {
                4 + dns6_count * 16
            } else {
                0
            }
            + if url_len > 0 { 4 + url_len } else { 0 })
        .min(D6_MAX_OPTS);
    r.real_reply_len = (F6_OPTS + real_opts_len) as u16;

    // Grow (or shrink) the skb to the MAX reply size so all emit/checksum accesses use one constant
    // bounds check, then re-pull to make the head writable. change_tail takes an ABSOLUTE length.
    if cur_len != D6_MAX_TOTAL
        && unsafe { aya_ebpf::helpers::bpf_skb_change_tail(skb, D6_MAX_TOTAL as u32, 0) } != 0
    {
        return false;
    }
    if ctx.pull_data(D6_MAX_TOTAL as u32).is_err() {
        return false;
    }
    let data = ctx.data();
    let data_end = ctx.data_end();

    tc_d6_emit(skb, data, data_end, meta, &r);
    // Re-derive the packet bounds: across the tc_d6_emit call the verifier spills/reloads `data` and
    // `data_end` as plain scalars, so passing them on to d6_checksum trips "invalid mem access
    // 'scalar'". Fresh ctx.data()/data_end() restore them as packet pointers.
    let data = ctx.data();
    let data_end = ctx.data_end();
    let udp_len = (real_opts_len + F6_OPTS - ETH_LEN - 40) as u16;
    let _ = d6_checksum(data, data_end, udp_len);
    true
}
