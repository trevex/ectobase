//! Differential oracle for the firewall classifier: random rule lists, compiled by
//! `flowplane_control::fwclass::compile_scope` into scopes and evaluated by the core classifier
//! (`fw_classify{,6}` — the code the eBPF runs), must give the SAME verdict as the first-match
//! reference evaluator (`crate::fw_oracle`, the datapath's evaluator before the classifier) for
//! every packet, in both directions.
//!
//! The universe is small on purpose — a handful of nested and disjoint prefixes, the ports at every
//! range edge, the ICMP types the rules name — so random lists hit the interesting interactions
//! (a wider rule under a narrower class, a port inside a range, deny-then-allow on the same peer)
//! over and over. Lists hold up to [`MAX_RULES`] rules, the old datapath's per-family limit, which
//! keeps the verdict mix balanced (see `assert_balanced`).

use crate::fw_oracle::{first_match, first_match6};
use crate::rng::Rng;
use crate::{MemMaps, VecPkt};
use flowplane_common::{FwBind, FwRule, FwRule6, FW_ACTION_ACCEPT, FW_DIR_EGRESS, FW_DIR_INGRESS};
use flowplane_control::fwclass::{compile_scope, Scope};
use flowplane_core::firewall::{fw_classify, fw_classify6};

const IF: u32 = 7;
const MAX_RULES: u64 = 16;

/// Extra draws this differential oracle needs beyond the shared [`Rng::next`].
impl Rng {
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[(self.next() % xs.len() as u64) as usize]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

const PORT_RANGES: &[(u16, u16)] = &[
    (0, 65535),
    (22, 22),
    (80, 80),
    (443, 443),
    (0, 1023),
    (1024, 65535),
    (1000, 2000),
    (443, 8443),
];
const PORTS: &[u16] = &[
    0, 21, 22, 23, 79, 80, 81, 442, 443, 444, 999, 1000, 1023, 1024, 2000, 2001, 8080, 8443, 8444,
    65535,
];
/// (type, code) selectors; 0xffff = any.
const ICMP_SEL: &[(u16, u16)] = &[
    (0xffff, 0xffff),
    (8, 0xffff),
    (0, 0xffff),
    (3, 1),
    (3, 0xffff),
];
/// (type, code) of generated ICMP packets.
const ICMP_PKT: &[(u8, u8)] = &[(8, 0), (0, 0), (3, 1), (3, 3), (11, 0)];

fn mask<const N: usize>(len: u8) -> [u8; N] {
    let mut m = [0u8; N];
    for (i, b) in m.iter_mut().enumerate() {
        let bits = (len as i32 - 8 * i as i32).clamp(0, 8);
        *b = if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
    }
    m
}

/// A generated rule, family-agnostic: peer prefix index into the family's prefix table.
#[derive(Clone, Copy)]
struct Gen {
    peer: usize,
    proto: u8,
    ports: (u16, u16),
    icmp: (u16, u16),
    allow: bool,
    egress: bool,
}

fn gen_rule(r: &mut Rng, n_prefixes: usize, icmp_proto: u8) -> Gen {
    let proto = r.pick(&[0u8, 6, 17, icmp_proto, 6, 17]);
    let (ports, icmp) = match proto {
        6 | 17 => (r.pick(PORT_RANGES), (0xffff, 0xffff)),
        p if p == icmp_proto => ((0, 65535), r.pick(ICMP_SEL)),
        _ => ((0, 65535), (0xffff, 0xffff)),
    };
    Gen {
        peer: (r.next() % n_prefixes as u64) as usize,
        proto,
        ports,
        icmp,
        allow: r.chance(55),
        egress: r.chance(50),
    }
}

// ---------------------------------------------------------------------------------------------
// IPv4

const PREFIXES4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 0),
    ([10, 0, 0, 0], 8),
    ([10, 1, 0, 0], 16),
    ([10, 1, 128, 0], 17),
    ([10, 1, 2, 0], 24),
    ([10, 1, 2, 3], 32),
    ([192, 168, 0, 0], 16),
    ([192, 168, 1, 0], 24),
];
const ADDRS4: &[[u8; 4]] = &[
    [10, 1, 2, 3],
    [10, 1, 2, 4],
    [10, 1, 3, 1],
    [10, 1, 200, 1],
    [10, 2, 0, 1],
    [192, 168, 1, 5],
    [192, 168, 2, 5],
    [172, 16, 0, 1],
];

fn fw_rule4(g: &Gen) -> FwRule {
    let (addr, len) = PREFIXES4[g.peer];
    let (ip, m) = (addr, mask::<4>(len));
    let (src_ip, src_mask, dst_ip, dst_mask) = if g.egress {
        ([0; 4], [0; 4], ip, m)
    } else {
        (ip, m, [0; 4], [0; 4])
    };
    FwRule {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: g.ports.0,
        dst_port_max: g.ports.1,
        icmp_type: g.icmp.0,
        icmp_code: g.icmp.1,
        proto: g.proto,
        action: g.allow as u8,
        direction: g.egress as u8,
        enabled: 1,
    }
}

fn pkt4(r: &mut Rng) -> VecPkt {
    let (src, dst) = (r.pick(ADDRS4), r.pick(ADDRS4));
    let (proto, l4): (u8, Vec<u8>) = match r.next() % 5 {
        0 | 1 => {
            let mut t = vec![0u8; 20];
            t[2..4].copy_from_slice(&r.pick(PORTS).to_be_bytes());
            t[12] = 0x50;
            t[13] = 0x02;
            (6, t)
        }
        2 => {
            let mut u = vec![0u8; 8];
            u[2..4].copy_from_slice(&r.pick(PORTS).to_be_bytes());
            (17, u)
        }
        3 => {
            let (t, c) = r.pick(ICMP_PKT);
            (1, vec![t, c, 0, 0, 0, 1, 0, 1])
        }
        _ => (47, vec![0u8; 8]),
    };
    let mut p = vec![
        0x45,
        0,
        0,
        (20 + l4.len()) as u8,
        0,
        0,
        0,
        0,
        64,
        proto,
        0,
        0,
    ];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&l4);
    VecPkt::from_bytes(&p)
}

fn bind(m: &mut MemMaps, ingress: Option<Scope>, egress: Option<Scope>) {
    let mut b = FwBind::default();
    for (scope, slot) in [
        (ingress, &mut b.ingress_scope),
        (egress, &mut b.egress_scope),
    ] {
        if let Some(s) = scope {
            *slot = s.id;
            m.fw_class4.insert(s.id, s.v4.classes);
            m.fw_policy4.insert(s.id, s.v4.policy);
            m.fw_class6.insert(s.id, s.v6.classes);
            m.fw_policy6.insert(s.id, s.v6.policy);
        }
    }
    m.fw_bind.insert(IF, b);
}

#[test]
fn v4_classifier_matches_first_match() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut verdicts = [0u32; 2]; // [drop, accept]
    for list in 0..600 {
        let n = 1 + (r.next() % MAX_RULES) as usize;
        let rules: Vec<FwRule> = (0..n)
            .map(|_| fw_rule4(&gen_rule(&mut r, PREFIXES4.len(), 1)))
            .collect();
        let mut m = MemMaps::default();
        let ingress =
            compile_scope(FW_DIR_INGRESS, rules.iter(), [].iter()).expect("compile ingress");
        let egress = compile_scope(FW_DIR_EGRESS, rules.iter(), [].iter()).expect("compile egress");
        bind(&mut m, ingress, egress);
        for _ in 0..150 {
            let p = pkt4(&mut r);
            for dir in [FW_DIR_INGRESS, FW_DIR_EGRESS] {
                let want = first_match(&p, 0, &rules, dir);
                verdicts[(want == FW_ACTION_ACCEPT) as usize] += 1;
                let got = fw_classify(&p, &m, 0, IF, dir);
                assert_eq!(
                    got, want,
                    "list {list} dir {dir}: classifier {got} vs first-match {want}\nrules: {rules:#?}\npacket: {:?}",
                    p.bytes()
                );
            }
        }
    }
    assert_balanced(verdicts);
}

/// Guard the generator: if nearly every verdict were the same, agreement would prove little. (The
/// current mix is roughly 1 accept in 5.)
fn assert_balanced([drop, accept]: [u32; 2]) {
    let total = drop + accept;
    assert!(
        accept * 10 > total && drop * 10 > total,
        "degenerate verdict mix: {accept} accept / {drop} drop"
    );
}

// ---------------------------------------------------------------------------------------------
// IPv6

const fn v6(head: [u8; 4], tail: u8) -> [u8; 16] {
    [
        head[0], head[1], head[2], head[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, tail,
    ]
}
const PREFIXES6: &[([u8; 16], u8)] = &[
    (v6([0, 0, 0, 0], 0), 0),
    (v6([0x20, 0x01, 0x0d, 0xb8], 0), 32),
    (v6([0x20, 0x01, 0x0d, 0xb8], 0), 48),
    (v6([0x20, 0x01, 0x0d, 0xb8], 0), 64),
    (v6([0x20, 0x01, 0x0d, 0xb8], 5), 128),
    (v6([0xfd, 0, 0, 0], 0), 8),
];
const ADDRS6: &[[u8; 16]] = &[
    v6([0x20, 0x01, 0x0d, 0xb8], 5),
    v6([0x20, 0x01, 0x0d, 0xb8], 6),
    [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
    v6([0xfd, 0, 0, 1], 1),
    v6([0x26, 0x00, 0, 0], 1),
];

fn fw_rule6(g: &Gen) -> FwRule6 {
    let (addr, len) = PREFIXES6[g.peer];
    let (ip, m) = (addr, mask::<16>(len));
    let (src_ip, src_mask, dst_ip, dst_mask) = if g.egress {
        ([0; 16], [0; 16], ip, m)
    } else {
        (ip, m, [0; 16], [0; 16])
    };
    FwRule6 {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: g.ports.0,
        dst_port_max: g.ports.1,
        icmp_type: g.icmp.0,
        icmp_code: g.icmp.1,
        proto: g.proto,
        action: g.allow as u8,
        direction: g.egress as u8,
        enabled: 1,
    }
}

fn pkt6(r: &mut Rng) -> VecPkt {
    let (src, dst) = (r.pick(ADDRS6), r.pick(ADDRS6));
    let (proto, l4): (u8, Vec<u8>) = match r.next() % 5 {
        0 | 1 => {
            let mut t = vec![0u8; 20];
            t[2..4].copy_from_slice(&r.pick(PORTS).to_be_bytes());
            t[12] = 0x50;
            t[13] = 0x02;
            (6, t)
        }
        2 => {
            let mut u = vec![0u8; 8];
            u[2..4].copy_from_slice(&r.pick(PORTS).to_be_bytes());
            (17, u)
        }
        3 => {
            let (t, c) = r.pick(&[(128u8, 0u8), (129, 0), (1, 4), (1, 0), (3, 0)]);
            (58, vec![t, c, 0, 0, 0, 1, 0, 1])
        }
        _ => (47, vec![0u8; 8]),
    };
    let mut p = vec![0x60, 0, 0, 0, 0, l4.len() as u8, proto, 64];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&l4);
    VecPkt::from_bytes(&p)
}

#[test]
fn v6_classifier_matches_first_match() {
    let mut r = Rng(0xd1b5_4a32_d192_ed03);
    let mut verdicts = [0u32; 2]; // [drop, accept]
    for list in 0..600 {
        let n = 1 + (r.next() % MAX_RULES) as usize;
        let rules: Vec<FwRule6> = (0..n)
            .map(|_| {
                let mut g = gen_rule(&mut r, PREFIXES6.len(), 58);
                // ICMPv6 selectors name ICMPv6 types.
                if g.proto == 58 && g.icmp.0 != 0xffff {
                    g.icmp = r.pick(&[(128, 0xffff), (129, 0xffff), (1, 4), (1, 0xffff)]);
                }
                fw_rule6(&g)
            })
            .collect();
        let mut m = MemMaps::default();
        let ingress =
            compile_scope(FW_DIR_INGRESS, [].iter(), rules.iter()).expect("compile ingress");
        let egress = compile_scope(FW_DIR_EGRESS, [].iter(), rules.iter()).expect("compile egress");
        bind(&mut m, ingress, egress);
        for _ in 0..150 {
            let p = pkt6(&mut r);
            for dir in [FW_DIR_INGRESS, FW_DIR_EGRESS] {
                let want = first_match6(&p, 0, &rules, dir);
                verdicts[(want == FW_ACTION_ACCEPT) as usize] += 1;
                let got = fw_classify6(&p, &m, 0, IF, dir);
                assert_eq!(
                    got, want,
                    "list {list} dir {dir}: classifier {got} vs first-match {want}\nrules: {rules:#?}\npacket: {:?}",
                    p.bytes()
                );
            }
        }
    }
    assert_balanced(verdicts);
}

// A direction with no rules compiles to no scope: bound as scope 0, it denies everything, as the
// old evaluator does with a zero rule count.
#[test]
fn empty_direction_has_no_scope() {
    let rules = [fw_rule4(&Gen {
        peer: 0,
        proto: 0,
        ports: (0, 65535),
        icmp: (0xffff, 0xffff),
        allow: true,
        egress: false,
    })];
    assert!(compile_scope(FW_DIR_EGRESS, rules.iter(), [].iter())
        .unwrap()
        .is_none());
    assert!(compile_scope(FW_DIR_INGRESS, rules.iter(), [].iter())
        .unwrap()
        .is_some());
}
