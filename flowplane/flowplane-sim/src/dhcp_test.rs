//! Conformance for the guest-facing DHCPv4 responder (`SimNode::guest_dhcp4`, which runs the REAL
//! `flowplane_core::dhcp::{parse, write}` — the same code the eBPF `guest_dhcp` datapath calls,
//! byte-parity-anchored in `flowplane/tests/anchor_dhcp.rs`).
//!
//! A guest DISCOVER for UDP dport 67 must be answered with an OFFER: the assigned address (`yiaddr`)
//! equals the port's configured IPv4; the virtual gateway is the server identity (siaddr/giaddr/
//! server-id/classless-route gw/IP src); the MTU option carries `DHCP_CONFIG.mtu`; the DNS option
//! carries the `DHCP_CONFIG.dns4` servers; the host-name option carries `DHCP_META[ifindex].hostname`;
//! and the lease is infinite. A REQUEST is answered with an ACK; a non-DHCP frame passes unchanged.
//!
//! DHCPv6 is intentionally NOT covered here: its reply option block is runtime-variable-length and is
//! emitted at runtime offsets via `bpf_xdp_store_bytes`, an idiom the fixed-size const-generic `Pkt`
//! seam cannot express, so the DHCPv6 responder stays in the eBPF crate (its conformance lives in the
//! goscapy real-lease smoke). See `flowplane_core::dhcp` for the full rationale.

use flowplane_common::{DhcpConfig, DhcpMeta, PortMeta, DHCP_MAX_DNS};
use flowplane_core::pkt::Action;

use crate::SimNode;

const VNI: u32 = 100;
const GUEST_IPV4: [u8; 4] = [10, 0, 0, 42]; // the assigned address (yiaddr)
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1]; // the virtual gateway (server identity)
const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const INGRESS_IFINDEX: u32 = 7;

// The synthetic gateway MAC the ARP/ND + DHCP responders all advertise (flowplane_common::proto::GW_MAC).
const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const MTU: u16 = 1400;
const DNS4_A: [u8; 4] = [8, 8, 8, 8];
const DNS4_B: [u8; 4] = [1, 1, 1, 1];
const HOSTNAME: &[u8] = b"vm-node-7";

const ETH_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
// Frame geometry (mirrors flowplane_core::dhcp).
const F_BOOTP: usize = ETH_LEN + 20 + 8; // 42
const BOOTP_MAGIC_OFF: usize = 236;
const BOOTP_OPTIONS_OFF: usize = 240;
const F_OPTS: usize = F_BOOTP + BOOTP_OPTIONS_OFF; // 282
const REPLY_LEN: usize = F_OPTS + 146; // 428

const DHCP_MSG_DISCOVER: u8 = 1;
const DHCP_MSG_REQUEST: u8 = 3;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_ACK: u8 = 5;

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IPV4,
        gateway_ipv4: GATEWAY_IPV4,
        guest_mac: GUEST_MAC,
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: [0; 16],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// A node with DHCP_CONFIG (MTU + two DNS servers) and DHCP_META[ifindex] (host-name) programmed —
/// the exact config the responder pulls the OFFER's MTU/DNS/host-name options from.
fn node_with_dhcp_config() -> SimNode {
    let mut node = SimNode::new();
    let mut dns4 = [[0u8; 4]; DHCP_MAX_DNS];
    dns4[0] = DNS4_A;
    dns4[1] = DNS4_B;
    node.maps.dhcp_config = Some(DhcpConfig {
        mtu: MTU,
        dns4_len: 2,
        dns6_len: 0,
        dns4,
        dns6: [[0u8; 16]; DHCP_MAX_DNS],
    });
    let mut hostname = [0u8; 64];
    hostname[..HOSTNAME.len()].copy_from_slice(HOSTNAME);
    node.maps.dhcp_meta.insert(
        INGRESS_IFINDEX,
        DhcpMeta {
            hostname,
            hostname_len: HOSTNAME.len() as u8,
            boot_filename: [0u8; 64],
            boot_filename_len: 0,
            pxe_host: [0u8; 46],
            pxe_host_len: 0,
            _pad: [0; 1],
        },
    );
    node
}

/// Build a guest DHCPv4 request frame (Ethernet + IPv4 + UDP + BOOTP + options) with the given
/// message type. Only the fields the responder reads need to be correct: ethertype, IHL, UDP proto,
/// UDP dport 67, the BOOTP magic cookie, and the option-53 message type.
fn dhcp_request_frame(msg_type: u8) -> Vec<u8> {
    // Options: msg-type(53,1,msg_type) then END(255). Total request length is arbitrary (< REPLY_LEN).
    let opts: &[u8] = &[53, 1, msg_type, 255];
    let total = F_OPTS + opts.len();
    let mut f = vec![0u8; total];

    // Ethernet.
    f[0..6].copy_from_slice(&[0xff; 6]); // dst broadcast
    f[6..12].copy_from_slice(&CLIENT_MAC); // src = client
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());

    // IPv4: version 4 / IHL 5, proto UDP. (src/dst irrelevant to the responder.)
    f[ETH_LEN] = 0x45;
    f[ETH_LEN + 9] = IPPROTO_UDP;

    // UDP: dport 67 (BOOTP server).
    f[ETH_LEN + 20..ETH_LEN + 22].copy_from_slice(&68u16.to_be_bytes()); // sport (client)
    f[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&67u16.to_be_bytes()); // dport (server)

    // BOOTP: op=BOOTREQUEST(1), xid/secs/flags, chaddr.
    f[F_BOOTP] = 1;
    f[F_BOOTP + 4..F_BOOTP + 12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0]);
    f[F_BOOTP + 28..F_BOOTP + 34].copy_from_slice(&CLIENT_MAC);

    // BOOTP magic cookie 0x63825363.
    f[F_BOOTP + BOOTP_MAGIC_OFF..F_BOOTP + BOOTP_MAGIC_OFF + 4]
        .copy_from_slice(&0x6382_5363u32.to_be_bytes());

    // Options.
    f[F_OPTS..F_OPTS + opts.len()].copy_from_slice(opts);
    f
}

/// Verify the IPv4 header checksum folds to 0xffff.
fn ipv4_checksum_ok(reply: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut i = ETH_LEN;
    while i < ETH_LEN + 20 {
        sum += u16::from_be_bytes([reply[i], reply[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16 == 0xffff
}

/// Walk the DHCP option block starting at `F_OPTS`; return the value bytes of option `code` (first
/// occurrence), or None. Stops at OPT_END(255).
fn find_option(reply: &[u8], code: u8) -> Option<Vec<u8>> {
    let mut i = F_OPTS;
    while i < reply.len() {
        let c = reply[i];
        if c == 255 {
            break;
        }
        if c == 0 {
            i += 1; // PAD
            continue;
        }
        let len = reply[i + 1] as usize;
        if c == code {
            return Some(reply[i + 2..i + 2 + len].to_vec());
        }
        i += 2 + len;
    }
    None
}

#[test]
fn discover_becomes_offer_with_configured_contents() {
    let node = node_with_dhcp_config();
    let out = node.guest_dhcp4(
        &dhcp_request_frame(DHCP_MSG_DISCOVER),
        &port_meta(),
        INGRESS_IFINDEX,
    );

    // Reflected back to the guest via the ingress ifindex, resized to the fixed reply length.
    assert_eq!(out.action, Action::Redirect(INGRESS_IFINDEX));
    assert_eq!(out.pkt.len(), REPLY_LEN, "OFFER is the fixed reply length");
    let r = &out.pkt;

    // ─── Ethernet: dst = client, src = the synthetic gateway MAC, ethertype IPv4. ───
    assert_eq!(&r[0..6], &CLIENT_MAC, "eth dst = requesting client");
    assert_eq!(&r[6..12], &GW_MAC, "eth src = server (gateway) MAC");
    assert_eq!(&r[12..14], &ETH_P_IP.to_be_bytes(), "ethertype IPv4");

    // ─── IPv4: proto UDP, src = gateway, dst = broadcast, valid checksum. ───
    assert_eq!(r[ETH_LEN + 9], IPPROTO_UDP, "IPv4 proto = UDP");
    assert_eq!(
        &r[ETH_LEN + 12..ETH_LEN + 16],
        &GATEWAY_IPV4,
        "IPv4 src = gateway"
    );
    assert_eq!(
        &r[ETH_LEN + 16..ETH_LEN + 20],
        &[255, 255, 255, 255],
        "IPv4 dst = broadcast"
    );
    assert!(ipv4_checksum_ok(r), "IPv4 header checksum verifies");

    // ─── UDP: sport 67, dport 68. ───
    assert_eq!(
        &r[ETH_LEN + 20..ETH_LEN + 22],
        &67u16.to_be_bytes(),
        "UDP sport 67"
    );
    assert_eq!(
        &r[ETH_LEN + 22..ETH_LEN + 24],
        &68u16.to_be_bytes(),
        "UDP dport 68"
    );

    // ─── BOOTP: op=BOOTREPLY(2); yiaddr = the assigned (port) IPv4; xid echoed; chaddr = client. ───
    assert_eq!(r[F_BOOTP], 2, "BOOTP op = BOOTREPLY");
    assert_eq!(
        &r[F_BOOTP + 16..F_BOOTP + 20],
        &GUEST_IPV4,
        "yiaddr = assigned (port) IPv4"
    );
    assert_eq!(
        &r[F_BOOTP + 20..F_BOOTP + 24],
        &GATEWAY_IPV4,
        "siaddr = gateway (server id)"
    );
    assert_eq!(
        &r[F_BOOTP + 24..F_BOOTP + 28],
        &GATEWAY_IPV4,
        "giaddr = gateway"
    );
    assert_eq!(
        &r[F_BOOTP + 4..F_BOOTP + 12],
        &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0],
        "xid/secs/flags echoed"
    );
    assert_eq!(
        &r[F_BOOTP + 28..F_BOOTP + 34],
        &CLIENT_MAC,
        "chaddr = client MAC"
    );

    // ─── Options ───
    assert_eq!(
        find_option(r, 53).as_deref(),
        Some(&[DHCP_MSG_OFFER][..]),
        "message type = OFFER (DISCOVER -> OFFER)"
    );
    assert_eq!(
        find_option(r, 54).as_deref(),
        Some(&GATEWAY_IPV4[..]),
        "server-id = gateway IPv4"
    );
    assert_eq!(
        find_option(r, 51).as_deref(),
        Some(&0xffff_ffffu32.to_be_bytes()[..]),
        "lease time = infinite"
    );
    assert_eq!(
        find_option(r, 1).as_deref(),
        Some(&[0xff, 0xff, 0xff, 0xff][..]),
        "subnet mask = /32"
    );
    // MTU option (26) from DHCP_CONFIG.mtu.
    assert_eq!(
        find_option(r, 26).as_deref(),
        Some(&MTU.to_be_bytes()[..]),
        "MTU option = DHCP_CONFIG.mtu"
    );
    // DNS option (6): both configured servers, in order.
    let mut dns_expect = Vec::new();
    dns_expect.extend_from_slice(&DNS4_A);
    dns_expect.extend_from_slice(&DNS4_B);
    assert_eq!(
        find_option(r, 6).as_deref(),
        Some(dns_expect.as_slice()),
        "DNS option = DHCP_CONFIG.dns4 servers"
    );
    // Host-name option (12) from DHCP_META[ifindex].hostname.
    assert_eq!(
        find_option(r, 12).as_deref(),
        Some(HOSTNAME),
        "host-name option = DHCP_META hostname"
    );
    // Classless static route (121): the 169.254/16 route with the gateway as next-hop. Encoding:
    // prefix-len(16), significant dest octets (169,254), then the 4-byte next-hop = gateway. The
    // writer emits [16, 169, 254, 0, 0, 0, 0, 0, gw0, gw1, gw2, gw3] (matches dpservice byte-for-byte).
    assert_eq!(
        find_option(r, 121).as_deref(),
        Some(
            &[
                16,
                169,
                254,
                0,
                0,
                0,
                0,
                0,
                GATEWAY_IPV4[0],
                GATEWAY_IPV4[1],
                GATEWAY_IPV4[2],
                GATEWAY_IPV4[3]
            ][..]
        ),
        "classless static route = 169.254/16 via gateway"
    );
}

#[test]
fn request_becomes_ack() {
    let node = node_with_dhcp_config();
    let out = node.guest_dhcp4(
        &dhcp_request_frame(DHCP_MSG_REQUEST),
        &port_meta(),
        INGRESS_IFINDEX,
    );
    assert_eq!(out.action, Action::Redirect(INGRESS_IFINDEX));
    assert_eq!(out.pkt.len(), REPLY_LEN);
    assert_eq!(
        find_option(&out.pkt, 53).as_deref(),
        Some(&[DHCP_MSG_ACK][..]),
        "message type = ACK (REQUEST -> ACK)"
    );
    // Still carries the assigned address.
    assert_eq!(
        &out.pkt[F_BOOTP + 16..F_BOOTP + 20],
        &GUEST_IPV4,
        "yiaddr = assigned IPv4"
    );
}

#[test]
fn no_dhcp_config_falls_back_to_default_mtu_no_dns() {
    // Without DHCP_CONFIG, the responder defaults MTU = 1500 - GENEVE_OVERHEAD (1444) and omits DNS.
    let node = SimNode::new();
    let out = node.guest_dhcp4(
        &dhcp_request_frame(DHCP_MSG_DISCOVER),
        &port_meta(),
        INGRESS_IFINDEX,
    );
    assert_eq!(out.action, Action::Redirect(INGRESS_IFINDEX));
    let default_mtu = 1500u16 - flowplane_common::GENEVE_OVERHEAD as u16;
    assert_eq!(
        find_option(&out.pkt, 26).as_deref(),
        Some(&default_mtu.to_be_bytes()[..]),
        "default MTU = 1500 - GENEVE_OVERHEAD"
    );
    assert_eq!(
        find_option(&out.pkt, 6),
        None,
        "no DNS option without config"
    );
    assert_eq!(
        find_option(&out.pkt, 12),
        None,
        "no host-name without DHCP_META"
    );
}

#[test]
fn non_dhcp_frame_passes_unchanged() {
    let node = node_with_dhcp_config();
    // A frame with UDP dport != 67 is not a DHCP request → pass unchanged.
    let mut frame = dhcp_request_frame(DHCP_MSG_DISCOVER);
    frame[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&53u16.to_be_bytes()); // DNS port, not 67
    let out = node.guest_dhcp4(&frame, &port_meta(), INGRESS_IFINDEX);
    assert_eq!(out.action, Action::Pass, "non-DHCP frame is not answered");
    assert_eq!(out.pkt, frame, "frame unchanged");
}
