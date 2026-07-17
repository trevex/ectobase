//! Guest-facing DHCPv4 responder, ported over the `Pkt` + `Maps` trait seam so the SAME reply
//! builder runs in the eBPF `guest_dhcp` datapath (`RawPkt`/`GlobalMaps`), natively in the sim
//! (`VecPkt`/`MemMaps`), and under the `BPF_PROG_TEST_RUN` byte-parity anchor.
//!
//! Faithful port of the previous inline builder in `flowplane_common::dhcp`
//! (`parse_dhcpv4_request` / `write_dhcpv4_reply`): a guest DISCOVER/REQUEST for UDP dport 67 is
//! answered with an OFFER/ACK — assigned IP (`yiaddr`) = the port's configured IPv4, the virtual
//! gateway as server identity (siaddr/giaddr/server-id/classless-route gw/IP src), plus the MTU,
//! DNS, subnet-mask, classless-route and (optional) host-name options.
//!
//! ## The fixed-layout property (why this fits the `Pkt` seam)
//!
//! The DHCPv4 OFFER/ACK has a COMPILE-TIME-CONSTANT total length ([`REPLY_LEN`]) and every option
//! sits at a compile-time-constant offset. The variable parts (which DNS servers, whether a
//! host-name is present) are handled by writing option bytes into fixed slots and PAD-filling the
//! unused tail of each slot — never by advancing a runtime write cursor. So every packet write is a
//! constant-offset `write_array::<N>`, exactly like the ARP/ND responder: the XDP verifier keeps
//! packet-bound provenance across the core-call boundary. The glue resizes the frame to `REPLY_LEN`
//! (via `bpf_xdp_adjust_tail` / `bpf_skb_change_tail` / `VecPkt::grow_tail`) BEFORE calling the
//! writer, so the writer only ever sees an already-`REPLY_LEN` frame.
//!
//! Scope: this module owns the request parse + the reply byte construction (config-derived values
//! come through `Maps`). The eBPF/sim glue owns the classification entry (`ingress_ifindex` ->
//! `PortMeta`), MAC learning, the frame resize, and the reflect verdict.
//!
//! DHCPv6 is deliberately NOT here: its reply option block is genuinely runtime-variable-length
//! (echoed client DUID, conditional IA_NA/RapidCommit, runtime DNS count, runtime BootFileUrl), so
//! its options are emitted at runtime offsets via `bpf_xdp_store_bytes` — an idiom the fixed-size
//! const-generic `Pkt` trait cannot express. The DHCPv6 responder stays in the eBPF crate; its
//! conformance is covered by the goscapy real-lease smoke.

use crate::maps::Maps;
use crate::pkt::Pkt;

// Frame geometry (mirrors flowplane_common::dhcp / the eBPF parse module).
const ETH_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

pub const DHCP_MAGIC: u32 = 0x6382_5363;
pub const OPT_PAD: u8 = 0;
pub const OPT_END: u8 = 255;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_CLASSLESS_ROUTE: u8 = 121;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_MTU: u8 = 26;
pub const DHCP_MSG_DISCOVER: u8 = 1;
pub const DHCP_MSG_REQUEST: u8 = 3;
pub const DHCP_MSG_OFFER: u8 = 2;
pub const DHCP_MSG_ACK: u8 = 5;

const F_BOOTP: usize = ETH_LEN + 20 + 8;
const BOOTP_MAGIC_OFF: usize = 236;
const BOOTP_OPTIONS_OFF: usize = 240;
const F_OPTS: usize = F_BOOTP + BOOTP_OPTIONS_OFF;
pub const MIN_DHCP_LEN: usize = F_OPTS;

// Byte-by-byte option scan: fixed stride of 1 (verifier-safe), bounded to this many bytes.
const OPTS_SCAN_BYTES: usize = 128;

// Option-block slot offsets (relative to F_OPTS). Fixed, so every write is a constant offset.
const O_MSGTYPE: usize = 0;
const O_LEASE: usize = 3;
const O_SERVERID: usize = 9;
const O_CLASSLESS: usize = 15;
const O_SUBNET: usize = 29;
const O_MTU: usize = 35;
const O_ROUTER: usize = 39;
const O_DNS: usize = 45;
const O_HOSTNAME: usize = 79;
const OPT_BLOCK_MAX: usize = 146;

/// Total DHCPv4 OFFER/ACK frame length. Constant — the glue resizes to this before writing.
pub const REPLY_LEN: usize = F_OPTS + OPT_BLOCK_MAX;

/// Maximum host-name bytes echoed in the host-name option.
pub const MAX_HOSTNAME: usize = 64;

/// Max DNS servers carried (matches `flowplane_common::DHCP_MAX_DNS`).
pub const MAX_DNS: usize = flowplane_common::DHCP_MAX_DNS;

/// A parsed DISCOVER/REQUEST: exactly the fields the writer needs, no packet/map dependency.
#[derive(Clone, Copy)]
pub struct Dhcpv4Request {
    /// `DHCP_MSG_OFFER` (for DISCOVER) or `DHCP_MSG_ACK` (for REQUEST).
    pub reply_type: u8,
    /// The request's Ethernet source (= reply eth dst + BOOTP chaddr + MAC-learning source).
    pub client_mac: [u8; 6],
    /// BOOTP xid(4)+secs(2)+flags(2), copied verbatim into the reply.
    pub xid_secs_flags: [u8; 8],
}

/// Validate + parse a guest DISCOVER/REQUEST via the `Pkt` seam; `None` for anything else.
///
/// Fixed-offset header reads plus a byte-by-byte option state machine (stride 1, bounded to
/// `OPTS_SCAN_BYTES` — verifier-friendly). Byte-identical to the previous
/// `flowplane_common::dhcp::parse_dhcpv4_request`.
#[inline(always)]
pub fn parse<P: Pkt>(pkt: &P) -> Option<Dhcpv4Request> {
    // One dominating bound: the fixed DHCP header (through the magic cookie) must be present.
    pkt.read_array::<4>(F_BOOTP + BOOTP_MAGIC_OFF)?;

    if pkt.read_u16_be(12)? != ETH_P_IP {
        return None;
    }
    if pkt.read_u8(ETH_LEN)? & 0x0f != 5 {
        return None;
    }
    if pkt.read_u8(ETH_LEN + 9)? != IPPROTO_UDP {
        return None;
    }
    if pkt.read_u16_be(ETH_LEN + 22)? != 67 {
        return None;
    }
    if u32::from_be_bytes(pkt.read_array::<4>(F_BOOTP + BOOTP_MAGIC_OFF)?) != DHCP_MAGIC {
        return None;
    }

    // Byte-by-byte option state machine. sm_state: 0 = expect code, 1 = expect length, 2 = value.
    let mut msg_type: u8 = 0;
    let mut sm_state: u8 = 0;
    let mut sm_remain: usize = 0;
    let mut sm_is_msgtype: bool = false;

    let mut i: usize = 0;
    while i < OPTS_SCAN_BYTES {
        let b = match pkt.read_u8(F_OPTS + i) {
            Some(b) => b,
            None => break,
        };
        i += 1;

        if sm_state == 0 {
            if b == OPT_PAD {
                // no-op
            } else if b == OPT_END {
                break;
            } else {
                sm_is_msgtype = b == OPT_MESSAGE_TYPE;
                sm_state = 1;
            }
        } else if sm_state == 1 {
            sm_remain = b as usize;
            if sm_remain == 0 {
                sm_state = 0;
            } else {
                sm_state = 2;
            }
        } else {
            // Reading value bytes. MESSAGE_TYPE always has len=1, so the single value byte
            // (sm_remain==1 before the decrement) is the message type.
            if sm_is_msgtype && sm_remain == 1 {
                msg_type = b;
            }
            sm_remain -= 1;
            if sm_remain == 0 {
                sm_state = 0;
            }
        }
    }

    if msg_type != DHCP_MSG_DISCOVER && msg_type != DHCP_MSG_REQUEST {
        return None;
    }
    let reply_type = if msg_type == DHCP_MSG_DISCOVER {
        DHCP_MSG_OFFER
    } else {
        DHCP_MSG_ACK
    };

    // MAC learning uses the Ethernet source (bytes 6-11), not BOOTP chaddr.
    let client_mac = pkt.read_array::<6>(6)?;
    let xid_secs_flags = pkt.read_array::<8>(F_BOOTP + 4)?;

    Some(Dhcpv4Request {
        reply_type,
        client_mac,
        xid_secs_flags,
    })
}

/// Fold `[u8; 2]` big-endian words into a one's-complement checksum accumulator.
#[inline(always)]
fn csum_add(sum: &mut u32, hi: u8, lo: u8) {
    *sum = sum.wrapping_add(((hi as u32) << 8) | lo as u32);
}

/// Build the DHCPv4 OFFER/ACK into `pkt`, which the glue has ALREADY resized to [`REPLY_LEN`].
///
/// `guest_ipv4` = assigned address (`yiaddr`), `gateway_ipv4` = the virtual gateway (server
/// identity), `server_mac` = the reply Ethernet source (the synthetic gateway MAC the ARP/ND
/// responders advertise). Config (MTU, DNS servers, per-interface host-name) is read from `maps`
/// via [`Maps::dhcp_config`] / [`Maps::dhcp_meta`], keyed by `ifindex`.
///
/// Every packet write is a compile-time-constant offset (`write_array::<N>`), so the XDP verifier
/// keeps packet-bound provenance across the call. Returns `true` iff the frame was large enough and
/// the reply was written. Byte-for-byte identical to `flowplane_common::dhcp::write_dhcpv4_reply`
/// (composed with the glue's config gather).
#[inline(always)]
pub fn write<P: Pkt, M: Maps>(
    pkt: &mut P,
    req: &Dhcpv4Request,
    guest_ipv4: [u8; 4],
    gateway_ipv4: [u8; 4],
    server_mac: [u8; 6],
    maps: &M,
    ifindex: u32,
) -> bool {
    // One dominating bound: the whole REPLY_LEN frame must be writable (the glue grew it first).
    if pkt.read_array::<1>(REPLY_LEN - 1).is_none() {
        return false;
    }

    let gw = gateway_ipv4;
    let client_mac = req.client_mac;

    // ─── BOOTP header ───
    pkt.write_array::<1>(F_BOOTP, &[2]); // op = BOOTREPLY
    pkt.write_array::<8>(F_BOOTP + 4, &req.xid_secs_flags);
    pkt.write_array::<4>(F_BOOTP + 16, &guest_ipv4); // yiaddr
    pkt.write_array::<4>(F_BOOTP + 20, &gw); // siaddr
    pkt.write_array::<4>(F_BOOTP + 24, &gw); // giaddr
    pkt.write_array::<6>(F_BOOTP + 28, &client_mac); // chaddr
                                                     // sname(64)+file(128) = 192 zero bytes from +44.
    pkt.write_array::<192>(F_BOOTP + 44, &[0u8; 192]);

    // ─── option block: fixed slots ───
    pkt.write_array::<3>(F_OPTS + O_MSGTYPE, &[OPT_MESSAGE_TYPE, 1, req.reply_type]);
    let lease = 0xffff_ffffu32.to_be_bytes();
    pkt.write_array::<6>(
        F_OPTS + O_LEASE,
        &[OPT_LEASE_TIME, 4, lease[0], lease[1], lease[2], lease[3]],
    );
    pkt.write_array::<6>(
        F_OPTS + O_SERVERID,
        &[OPT_SERVER_ID, 4, gw[0], gw[1], gw[2], gw[3]],
    );
    pkt.write_array::<14>(
        F_OPTS + O_CLASSLESS,
        &[
            OPT_CLASSLESS_ROUTE,
            12,
            16,
            169,
            254,
            0,
            0,
            0,
            0,
            0,
            gw[0],
            gw[1],
            gw[2],
            gw[3],
        ],
    );
    pkt.write_array::<6>(
        F_OPTS + O_SUBNET,
        &[OPT_SUBNET_MASK, 4, 0xff, 0xff, 0xff, 0xff],
    );

    // MTU option (from DHCP_CONFIG; default 1500). A zero MTU pads the slot.
    let cfg = maps.dhcp_config();
    let mtu = cfg.map(|c| c.mtu).unwrap_or(1500);
    if mtu != 0 {
        let m = mtu.to_be_bytes();
        pkt.write_array::<4>(F_OPTS + O_MTU, &[OPT_MTU, 2, m[0], m[1]]);
    } else {
        pkt.write_array::<4>(F_OPTS + O_MTU, &[OPT_PAD; 4]);
    }
    // ROUTER(3) slot: PAD (no v4-PXE support, matching the original).
    pkt.write_array::<6>(F_OPTS + O_ROUTER, &[OPT_PAD; 6]);

    // DNS option (from DHCP_CONFIG). Clear the 34-byte slot, then fill in-place.
    pkt.write_array::<34>(F_OPTS + O_DNS, &[OPT_PAD; 34]);
    let dns_len = cfg.map(|c| (c.dns4_len as usize).min(MAX_DNS)).unwrap_or(0);
    if dns_len > 0 {
        let c = cfg.unwrap();
        pkt.write_array::<2>(F_OPTS + O_DNS, &[OPT_DNS, (dns_len * 4) as u8]);
        let mut j = 0usize;
        // Fixed-cap loop (verifier-friendly): constant slot offsets `O_DNS + 2 + j*4`.
        while j < MAX_DNS {
            if j < dns_len {
                pkt.write_array::<4>(F_OPTS + O_DNS + 2 + j * 4, &c.dns4[j]);
            }
            j += 1;
        }
    }

    // Host-name option (from DHCP_META[ifindex]). Clear the 66-byte slot, then fill in-place.
    pkt.write_array::<66>(F_OPTS + O_HOSTNAME, &[OPT_PAD; 66]);
    let dm = maps.dhcp_meta(ifindex);
    let hn_len = dm
        .map(|d| (d.hostname_len as usize).min(MAX_HOSTNAME))
        .unwrap_or(0);
    if hn_len > 0 {
        let d = dm.unwrap();
        pkt.write_array::<2>(F_OPTS + O_HOSTNAME, &[OPT_HOSTNAME, hn_len as u8]);
        let mut k = 0usize;
        while k < MAX_HOSTNAME {
            if k < hn_len {
                pkt.write_array::<1>(F_OPTS + O_HOSTNAME + 2 + k, &[d.hostname[k]]);
            }
            k += 1;
        }
    }
    pkt.write_array::<1>(F_OPTS + OPT_BLOCK_MAX - 1, &[OPT_END]);

    // ─── Ethernet ───
    pkt.write_array::<6>(0, &client_mac);
    pkt.write_array::<6>(6, &server_mac);
    pkt.write_array::<2>(12, &ETH_P_IP.to_be_bytes());

    // ─── IPv4 header ───
    let ip_total = (REPLY_LEN - ETH_LEN) as u16;
    let vihl = pkt.read_u8(ETH_LEN).unwrap_or(0x45);
    let tos = pkt.read_u8(ETH_LEN + 1).unwrap_or(0);
    let ip_hdr: [u8; 20] = [
        vihl,
        tos,
        (ip_total >> 8) as u8,
        (ip_total & 0xff) as u8,
        0,
        0,
        0,
        0,
        64,
        IPPROTO_UDP,
        0,
        0,
        gateway_ipv4[0],
        gateway_ipv4[1],
        gateway_ipv4[2],
        gateway_ipv4[3],
        255,
        255,
        255,
        255,
    ];
    let mut s: u32 = 0;
    csum_add(&mut s, ip_hdr[0], ip_hdr[1]);
    csum_add(&mut s, ip_hdr[2], ip_hdr[3]);
    csum_add(&mut s, ip_hdr[4], ip_hdr[5]);
    csum_add(&mut s, ip_hdr[6], ip_hdr[7]);
    csum_add(&mut s, ip_hdr[8], ip_hdr[9]);
    csum_add(&mut s, ip_hdr[12], ip_hdr[13]);
    csum_add(&mut s, ip_hdr[14], ip_hdr[15]);
    csum_add(&mut s, ip_hdr[16], ip_hdr[17]);
    csum_add(&mut s, ip_hdr[18], ip_hdr[19]);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    let ip_csum = !(s as u16);
    pkt.write_array::<20>(ETH_LEN, &ip_hdr);
    pkt.write_array::<2>(ETH_LEN + 10, &ip_csum.to_be_bytes());

    // ─── UDP header (checksum 0 = not computed, as before) ───
    let udp_len = (REPLY_LEN - ETH_LEN - 20) as u16;
    pkt.write_array::<2>(ETH_LEN + 20, &67u16.to_be_bytes());
    pkt.write_array::<2>(ETH_LEN + 22, &68u16.to_be_bytes());
    pkt.write_array::<2>(ETH_LEN + 24, &udp_len.to_be_bytes());
    pkt.write_array::<2>(ETH_LEN + 26, &[0, 0]);

    true
}
