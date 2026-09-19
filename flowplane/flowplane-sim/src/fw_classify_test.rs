//! The two-stage firewall classifier (`flowplane_core::firewall::fw_classify{,6}`) against hand-built
//! scopes: binding, peer-class LPM, the two policy probes and their precedence arbitration, and the
//! proto/port/ICMP suffix of the policy key. The compiler that produces scopes from rule lists is
//! tested separately, against the old first-match semantics.

use crate::firewall_test::tcp_v4;
use crate::{MemMaps, VecPkt};
use etherparse::PacketBuilder;
use flowplane_common::{
    fw_precedence, FwBind, FwPolKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_CLASS_ANY, FW_DIR_EGRESS,
    FW_DIR_INGRESS, FW_POL_PREFIX_CLASS, FW_POL_PREFIX_FULL, FW_POL_PREFIX_PROTO,
};
use flowplane_core::firewall::{fw_classify, fw_classify6};

const IF: u32 = 42;
const SCOPE: u64 = 0xabc;
const TCP: u8 = 6;

fn bound(ingress: u64, egress: u64) -> MemMaps {
    let mut m = MemMaps::default();
    m.fw_bind.insert(
        IF,
        FwBind {
            ingress_scope: ingress,
            egress_scope: egress,
            ..Default::default()
        },
    );
    m
}

fn class4(m: &mut MemMaps, addr: [u8; 4], len: u8, class: u32) {
    m.fw_class4
        .entry(SCOPE)
        .or_default()
        .push((addr, len, class));
}

fn pol4(m: &mut MemMaps, plen: u32, key: FwPolKey, rank: u32, allow: bool) {
    m.fw_policy4
        .entry(SCOPE)
        .or_default()
        .push((plen, key, fw_precedence(rank, allow)));
}

fn tcp(src: [u8; 4], dst: [u8; 4], dport: u16) -> VecPkt {
    VecPkt::from_bytes(&tcp_v4(src, dst, 40000, dport))
}

fn udp(src: [u8; 4], dst: [u8; 4], dport: u16) -> VecPkt {
    let mut out = Vec::new();
    PacketBuilder::ipv4(src, dst, 64)
        .udp(40000, dport)
        .write(&mut out, &[])
        .unwrap();
    VecPkt::from_bytes(&out)
}

fn icmp_echo(src: [u8; 4], dst: [u8; 4], request: bool) -> VecPkt {
    let b = PacketBuilder::ipv4(src, dst, 64);
    let b = if request {
        b.icmpv4_echo_request(1, 1)
    } else {
        b.icmpv4_echo_reply(1, 1)
    };
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    VecPkt::from_bytes(&out)
}

const PEER: [u8; 4] = [10, 1, 2, 3];
const ME: [u8; 4] = [10, 9, 9, 9];
const OTHER: [u8; 4] = [192, 168, 1, 1];

fn ingress(m: &MemMaps, p: &VecPkt) -> u8 {
    fw_classify(p, m, 0, IF, FW_DIR_INGRESS)
}

#[test]
fn unbound_interface_or_empty_direction_drops() {
    let any_allow = |m: &mut MemMaps| {
        pol4(
            m,
            FW_POL_PREFIX_CLASS,
            FwPolKey::new(FW_CLASS_ANY, 0, [0; 2]),
            0,
            true,
        )
    };
    let mut m = MemMaps::default();
    any_allow(&mut m);
    assert_eq!(
        ingress(&m, &tcp(PEER, ME, 80)),
        FW_ACTION_DROP,
        "no FW_BIND entry"
    );

    let mut m = bound(0, SCOPE);
    any_allow(&mut m);
    assert_eq!(
        ingress(&m, &tcp(PEER, ME, 80)),
        FW_ACTION_DROP,
        "scope 0 = no rules"
    );

    let m = bound(SCOPE, 0);
    assert_eq!(
        ingress(&m, &tcp(PEER, ME, 80)),
        FW_ACTION_DROP,
        "bound scope with no tries"
    );
}

#[test]
fn any_peer_rule_matches_every_address() {
    let mut m = bound(SCOPE, 0);
    pol4(
        &mut m,
        FW_POL_PREFIX_CLASS,
        FwPolKey::new(FW_CLASS_ANY, 0, [0; 2]),
        0,
        true,
    );
    assert_eq!(ingress(&m, &tcp(PEER, ME, 80)), FW_ACTION_ACCEPT);
    assert_eq!(ingress(&m, &udp(OTHER, ME, 53)), FW_ACTION_ACCEPT);
}

#[test]
fn class_rule_matches_only_its_peers() {
    let mut m = bound(SCOPE, 0);
    class4(&mut m, [10, 0, 0, 0], 8, 1);
    pol4(
        &mut m,
        FW_POL_PREFIX_CLASS,
        FwPolKey::new(1, 0, [0; 2]),
        0,
        true,
    );
    assert_eq!(ingress(&m, &tcp(PEER, ME, 80)), FW_ACTION_ACCEPT);
    assert_eq!(ingress(&m, &tcp(OTHER, ME, 80)), FW_ACTION_DROP);
}

// Stage 1 returns the MOST specific class; a rule keyed only under a wider class does not match an
// address in a narrower one. Expanding rules into contained classes is the compiler's job.
#[test]
fn class_lookup_is_longest_prefix() {
    let mut m = bound(SCOPE, 0);
    class4(&mut m, [10, 0, 0, 0], 8, 1);
    class4(&mut m, [10, 1, 0, 0], 16, 2);
    pol4(
        &mut m,
        FW_POL_PREFIX_CLASS,
        FwPolKey::new(1, 0, [0; 2]),
        0,
        true,
    );
    assert_eq!(
        ingress(&m, &tcp([10, 7, 0, 1], ME, 80)),
        FW_ACTION_ACCEPT,
        "class 1"
    );
    assert_eq!(
        ingress(&m, &tcp(PEER, ME, 80)),
        FW_ACTION_DROP,
        "10.1.2.3 is class 2"
    );
}

// The two probes disagree: the higher precedence (earlier rank) decides, whichever probe it came
// from and whatever its action.
#[test]
fn precedence_arbitrates_between_the_probes() {
    for (class_rank, any_rank, want) in [(1, 0, FW_ACTION_DROP), (0, 1, FW_ACTION_ACCEPT)] {
        let mut m = bound(SCOPE, 0);
        class4(&mut m, [10, 0, 0, 0], 8, 1);
        pol4(
            &mut m,
            FW_POL_PREFIX_CLASS,
            FwPolKey::new(1, 0, [0; 2]),
            class_rank,
            true,
        );
        pol4(
            &mut m,
            FW_POL_PREFIX_CLASS,
            FwPolKey::new(FW_CLASS_ANY, 0, [0; 2]),
            any_rank,
            false,
        );
        assert_eq!(
            ingress(&m, &tcp(PEER, ME, 80)),
            want,
            "class rank {class_rank}"
        );
    }
}

// Ingress classifies the SOURCE, egress the DESTINATION: the peer is whoever is on the other end.
#[test]
fn peer_is_source_on_ingress_and_destination_on_egress() {
    let mut m = bound(SCOPE, SCOPE);
    class4(&mut m, [10, 0, 0, 0], 8, 1);
    pol4(
        &mut m,
        FW_POL_PREFIX_CLASS,
        FwPolKey::new(1, 0, [0; 2]),
        0,
        true,
    );
    let from_peer = tcp(PEER, OTHER, 80);
    let to_peer = tcp(OTHER, PEER, 80);
    assert_eq!(
        fw_classify(&from_peer, &m, 0, IF, FW_DIR_INGRESS),
        FW_ACTION_ACCEPT
    );
    assert_eq!(
        fw_classify(&to_peer, &m, 0, IF, FW_DIR_INGRESS),
        FW_ACTION_DROP
    );
    assert_eq!(
        fw_classify(&to_peer, &m, 0, IF, FW_DIR_EGRESS),
        FW_ACTION_ACCEPT
    );
    assert_eq!(
        fw_classify(&from_peer, &m, 0, IF, FW_DIR_EGRESS),
        FW_ACTION_DROP
    );
}

// Proto and port are the LPM suffix: the longest matching entry answers within one probe.
#[test]
fn proto_and_port_are_the_maskable_suffix() {
    let mut m = bound(SCOPE, 0);
    let any = FW_CLASS_ANY;
    pol4(
        &mut m,
        FW_POL_PREFIX_FULL,
        FwPolKey::new(any, TCP, 443u16.to_be_bytes()),
        0,
        true,
    );
    // TCP 1024-2047 = 0x0400/6: the top 6 port bits.
    pol4(
        &mut m,
        FW_POL_PREFIX_PROTO + 6,
        FwPolKey::new(any, TCP, 1024u16.to_be_bytes()),
        1,
        true,
    );
    pol4(
        &mut m,
        FW_POL_PREFIX_PROTO,
        FwPolKey::new(any, TCP, [0; 2]),
        2,
        false,
    );
    assert_eq!(ingress(&m, &tcp(PEER, ME, 443)), FW_ACTION_ACCEPT);
    assert_eq!(ingress(&m, &tcp(PEER, ME, 1500)), FW_ACTION_ACCEPT);
    assert_eq!(ingress(&m, &tcp(PEER, ME, 2048)), FW_ACTION_DROP);
    assert_eq!(ingress(&m, &tcp(PEER, ME, 80)), FW_ACTION_DROP);
    assert_eq!(
        ingress(&m, &udp(PEER, ME, 443)),
        FW_ACTION_DROP,
        "no UDP entry"
    );
}

// ICMP type and code ride in the port field: [type, code].
#[test]
fn icmp_type_and_code_are_the_port_field() {
    let mut m = bound(SCOPE, 0);
    pol4(
        &mut m,
        FW_POL_PREFIX_PROTO + 8,
        FwPolKey::new(FW_CLASS_ANY, 1, [8, 0]),
        0,
        true,
    );
    assert_eq!(
        ingress(&m, &icmp_echo(PEER, ME, true)),
        FW_ACTION_ACCEPT,
        "echo request"
    );
    assert_eq!(
        ingress(&m, &icmp_echo(PEER, ME, false)),
        FW_ACTION_DROP,
        "echo reply"
    );
}

fn tcp6(src: [u8; 16], dst: [u8; 16], dport: u16) -> VecPkt {
    let mut out = Vec::new();
    PacketBuilder::ipv6(src, dst, 64)
        .tcp(40000, dport, 0, 1024)
        .write(&mut out, &[])
        .unwrap();
    VecPkt::from_bytes(&out)
}

fn icmp6_echo(src: [u8; 16], dst: [u8; 16], request: bool) -> VecPkt {
    let b = PacketBuilder::ipv6(src, dst, 64);
    let b = if request {
        b.icmpv6_echo_request(1, 1)
    } else {
        b.icmpv6_echo_reply(1, 1)
    };
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    VecPkt::from_bytes(&out)
}

#[test]
fn v6_classifies_on_the_v6_tries() {
    let peer6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let other6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let me6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let mut m = bound(SCOPE, 0);
    let mut prefix = [0u8; 16];
    prefix[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    m.fw_class6.entry(SCOPE).or_default().push((prefix, 32, 1));
    m.fw_policy6.entry(SCOPE).or_default().extend([
        (
            FW_POL_PREFIX_PROTO,
            FwPolKey::new(1, TCP, [0; 2]),
            fw_precedence(0, true),
        ),
        (
            FW_POL_PREFIX_PROTO + 8,
            FwPolKey::new(FW_CLASS_ANY, 58, [128, 0]),
            fw_precedence(1, true),
        ),
    ]);
    // The v4 tries of the same scope must not leak into v6 evaluation.
    pol4(
        &mut m,
        FW_POL_PREFIX_CLASS,
        FwPolKey::new(FW_CLASS_ANY, 0, [0; 2]),
        0,
        true,
    );
    let v6 = |p: &VecPkt| fw_classify6(p, &m, 0, IF, FW_DIR_INGRESS);
    assert_eq!(v6(&tcp6(peer6, me6, 22)), FW_ACTION_ACCEPT, "class 1 TCP");
    assert_eq!(v6(&tcp6(other6, me6, 22)), FW_ACTION_DROP, "not class 1");
    assert_eq!(
        v6(&icmp6_echo(other6, me6, true)),
        FW_ACTION_ACCEPT,
        "ICMPv6 echo request"
    );
    assert_eq!(
        v6(&icmp6_echo(other6, me6, false)),
        FW_ACTION_DROP,
        "ICMPv6 echo reply"
    );
}
