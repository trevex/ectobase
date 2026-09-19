//! Firewall classifier compiler: one direction's ordered rule list (both families) → a SCOPE — the
//! class tries and policy tries `flowplane_core::firewall::fw_classify{,6}` evaluates.
//!
//! The rule list is already first-match ordered (priorities and list-level shadowing resolved by the
//! control-plane compiler). This turns "first match wins" into data a constant-cost lookup can
//! answer, Cilium-style:
//!
//! - every distinct non-`/0` peer prefix of a family becomes a scope-local class (1..=n);
//! - each rule becomes policy entries under its own class AND every class inside its prefix
//!   (stage 1 returns the MOST specific class, so a wider rule must be reachable from the narrower
//!   classes), or under class 0 for a `/0` peer; its proto/port (or ICMP type/code) is the maskable
//!   key suffix, a port range decomposed into prefixes;
//! - precedence comes from the rule's rank in the list, so across the two probes the earlier rule
//!   wins exactly as first-match would;
//! - within one trie, insert-time shadowing refuses an entry a higher-precedence entry covers and
//!   evicts lower-precedence entries a new one covers, so the longest match is always the
//!   highest-precedence match.
//!
//! The scope id is a hash of the compiled OUTPUT, so identical rule sets share one scope and any
//! compiler change that alters the output yields a new id rather than silently reusing a stale one.

use std::collections::HashMap;

use flowplane_common::{
    fw_precedence, FwPolKey, FwRule, FwRule6, FW_CLASS_ANY, FW_DIR_EGRESS, FW_POL_PREFIX_CLASS,
    FW_POL_PREFIX_PROTO,
};

use crate::FwError;

/// Per scope and family: the most peer classes / policy entries the compiler emits. They bound the
/// inner tries the dataplane creates; a rule list that expands past them is refused whole.
pub const SCOPE_MAX_CLASSES: usize = flowplane_common::FW_SCOPE_MAX_CLASSES as usize;
pub const SCOPE_MAX_ENTRIES: usize = flowplane_common::FW_SCOPE_MAX_ENTRIES as usize;

/// One family's compiled tries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeTries<A> {
    /// Class trie: `(peer prefix address, prefix length, class id)`.
    pub classes: Vec<(A, u8, u32)>,
    /// Policy trie: `(prefix length over the FwPolKey bits, key, precedence)`.
    pub policy: Vec<(u32, FwPolKey, u32)>,
}

/// A compiled scope: both families' tries for one direction's rule list, under its content id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    pub id: u64,
    pub v4: ScopeTries<[u8; 4]>,
    pub v6: ScopeTries<[u8; 16]>,
}

/// What a rule matches beyond peer and proto.
#[derive(Clone, Copy)]
enum Selector {
    /// Every port / type (also the only form for protocols without ports).
    Any,
    /// Inclusive TCP/UDP destination-port range.
    Ports(u16, u16),
    /// ICMP type, and optionally code.
    Icmp(u8, Option<u8>),
}

struct Parsed<const N: usize> {
    peer: [u8; N],
    len: u8,
    proto: u8,
    sel: Selector,
    allow: bool,
}

/// The fields of FwRule / FwRule6 the compiler reads, over the address width.
struct RuleView<'a, const N: usize> {
    src: &'a [u8; N],
    src_mask: &'a [u8; N],
    dst: &'a [u8; N],
    dst_mask: &'a [u8; N],
    sports: (u16, u16),
    dports: (u16, u16),
    icmp: (u16, u16),
    proto: u8,
    allow: bool,
    enabled: bool,
}

fn prefix_len<const N: usize>(mask: &[u8; N]) -> Option<u8> {
    let ones: u32 = mask.iter().map(|b| b.count_ones()).sum();
    let canonical = (0..N).all(|i| {
        let bits = (ones as i32 - 8 * i as i32).clamp(0, 8);
        mask[i] == if bits == 0 { 0 } else { 0xffu8 << (8 - bits) }
    });
    canonical.then_some(ones as u8)
}

fn masked<const N: usize>(addr: &[u8; N], len: u8) -> [u8; N] {
    let mut out = *addr;
    for (i, b) in out.iter_mut().enumerate() {
        let bits = (len as i32 - 8 * i as i32).clamp(0, 8);
        *b &= if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
    }
    out
}

/// True if the first `len` bits of `a` and `b` are equal.
fn bits_match(a: &[u8], b: &[u8], len: u32) -> bool {
    let full = (len / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = len % 8;
    rem == 0 || (a[full] ^ b[full]) & (0xffu8 << (8 - rem)) == 0
}

/// Read one rule the way the first-match semantics read it (the sim's reference evaluator,
/// `flowplane_sim`'s `fw_oracle`), or refuse the forms a peer classifier cannot express.
/// `Ok(None)`: the rule can never match (disabled, or an empty port range).
fn parse<const N: usize>(
    r: &RuleView<'_, N>,
    dir: u8,
    icmp_proto: u8,
) -> Result<Option<Parsed<N>>, FwError> {
    if !r.enabled {
        return Ok(None);
    }
    let (peer, peer_mask, local_mask) = if dir == FW_DIR_EGRESS {
        (r.dst, r.dst_mask, r.src_mask)
    } else {
        (r.src, r.src_mask, r.dst_mask)
    };
    if local_mask.iter().any(|&b| b != 0) {
        return Err(FwError::Unsupported(
            "a rule matching the interface's own address",
        ));
    }
    if r.sports != (0, 65535) {
        return Err(FwError::Unsupported("a source-port restriction"));
    }
    let len = prefix_len(peer_mask).ok_or(FwError::Unsupported("a non-contiguous peer mask"))?;
    let sel = match r.proto {
        6 | 17 if r.dports.0 > r.dports.1 => return Ok(None),
        6 | 17 if r.dports == (0, 65535) => Selector::Any,
        6 | 17 => Selector::Ports(r.dports.0, r.dports.1),
        p if p == icmp_proto => match r.icmp {
            (0xffff, 0xffff) => Selector::Any,
            (0xffff, _) => return Err(FwError::Unsupported("an ICMP code without a type")),
            (t, _) if t > 255 => return Err(FwError::Unsupported("an ICMP type above 255")),
            (t, 0xffff) => Selector::Icmp(t as u8, None),
            (_, c) if c > 255 => return Err(FwError::Unsupported("an ICMP code above 255")),
            (t, c) => Selector::Icmp(t as u8, Some(c as u8)),
        },
        // Any protocol: the old evaluator would apply ports to TCP/UDP and type/code to ICMP only.
        0 if r.dports != (0, 65535) || r.icmp != (0xffff, 0xffff) => {
            return Err(FwError::Unsupported(
                "ports or ICMP selectors on an any-protocol rule",
            ));
        }
        // Any protocol, or one without ports: the old evaluator ignores ports and type/code.
        _ => Selector::Any,
    };
    Ok(Some(Parsed {
        peer: masked(peer, len),
        len,
        proto: r.proto,
        sel,
        allow: r.allow,
    }))
}

fn view4(r: &FwRule) -> RuleView<'_, 4> {
    RuleView {
        src: &r.src_ip,
        src_mask: &r.src_mask,
        dst: &r.dst_ip,
        dst_mask: &r.dst_mask,
        sports: (r.src_port_min, r.src_port_max),
        dports: (r.dst_port_min, r.dst_port_max),
        icmp: (r.icmp_type, r.icmp_code),
        proto: r.proto,
        allow: r.action == flowplane_common::FW_ACTION_ACCEPT,
        enabled: r.enabled != 0,
    }
}

fn view6(r: &FwRule6) -> RuleView<'_, 16> {
    RuleView {
        src: &r.src_ip,
        src_mask: &r.src_mask,
        dst: &r.dst_ip,
        dst_mask: &r.dst_mask,
        sports: (r.src_port_min, r.src_port_max),
        dports: (r.dst_port_min, r.dst_port_max),
        icmp: (r.icmp_type, r.icmp_code),
        proto: r.proto,
        allow: r.action == flowplane_common::FW_ACTION_ACCEPT,
        enabled: r.enabled != 0,
    }
}

/// A policy-trie entry under construction.
#[derive(Clone, Copy)]
struct Entry {
    plen: u32,
    key: FwPolKey,
    prec: u32,
}

impl Entry {
    /// The bytes the LPM trie compares (class, proto, big-endian port), as the evaluator's probe
    /// key lays them out.
    fn bytes(&self) -> [u8; 7] {
        let c = self.key.class.to_ne_bytes();
        [
            c[0],
            c[1],
            c[2],
            c[3],
            self.key.proto,
            self.key.port[0],
            self.key.port[1],
        ]
    }

    /// Every key `other` matches, `self` matches too.
    fn covers(&self, other: &Entry) -> bool {
        self.plen <= other.plen && bits_match(&self.bytes(), &other.bytes(), self.plen)
    }
}

/// Insert-time shadowing into one class's entries: refuse an entry a higher-precedence entry
/// already covers, evict the lower-precedence entries it covers. Order-independent, and leaves the
/// longest match of every key equal to its highest-precedence match.
fn insert(entries: &mut Vec<Entry>, e: Entry) {
    if entries.iter().any(|x| x.prec > e.prec && x.covers(&e)) {
        return;
    }
    entries.retain(|x| !(e.prec > x.prec && e.covers(x)));
    entries.push(e);
}

fn compile_family<const N: usize>(
    rules: &[Parsed<N>],
    family: &'static str,
) -> Result<ScopeTries<[u8; N]>, FwError> {
    let mut prefixes: Vec<([u8; N], u8)> = rules
        .iter()
        .filter(|r| r.len > 0)
        .map(|r| (r.peer, r.len))
        .collect();
    prefixes.sort_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0)));
    prefixes.dedup();
    if prefixes.len() > SCOPE_MAX_CLASSES {
        return Err(FwError::ScopeTooLarge {
            family,
            what: "peer classes",
            count: prefixes.len(),
        });
    }
    let classes: Vec<([u8; N], u8, u32)> = prefixes
        .iter()
        .enumerate()
        .map(|(i, &(a, l))| (a, l, i as u32 + 1))
        .collect();

    let mut by_class: HashMap<u32, Vec<Entry>> = HashMap::new();
    for (rank, r) in rules.iter().enumerate() {
        let prec = fw_precedence(rank as u32, r.allow);
        let targets: Vec<u32> = if r.len == 0 {
            vec![FW_CLASS_ANY]
        } else {
            classes
                .iter()
                .filter(|(a, l, _)| *l >= r.len && bits_match(a, &r.peer, r.len as u32))
                .map(|&(_, _, c)| c)
                .collect()
        };
        let suffixes: Vec<(u32, [u8; 2])> = match (r.proto, r.sel) {
            (0, _) => vec![(FW_POL_PREFIX_CLASS, [0, 0])],
            (_, Selector::Any) => vec![(FW_POL_PREFIX_PROTO, [0, 0])],
            (_, Selector::Ports(lo, hi)) => crate::ports::port_prefixes(lo, hi)
                .into_iter()
                .map(|(v, bits)| (FW_POL_PREFIX_PROTO + bits as u32, v.to_be_bytes()))
                .collect(),
            (_, Selector::Icmp(t, None)) => vec![(FW_POL_PREFIX_PROTO + 8, [t, 0])],
            (_, Selector::Icmp(t, Some(c))) => vec![(FW_POL_PREFIX_PROTO + 16, [t, c])],
        };
        for &class in &targets {
            let bucket = by_class.entry(class).or_default();
            for &(plen, port) in &suffixes {
                insert(
                    bucket,
                    Entry {
                        plen,
                        key: FwPolKey::new(class, r.proto, port),
                        prec,
                    },
                );
            }
        }
    }

    let mut policy: Vec<(u32, FwPolKey, u32)> = by_class
        .into_values()
        .flatten()
        .map(|e| (e.plen, e.key, e.prec))
        .collect();
    policy.sort_by_key(|(plen, k, _)| (k.class, *plen, k.proto, k.port));
    if policy.len() > SCOPE_MAX_ENTRIES {
        return Err(FwError::ScopeTooLarge {
            family,
            what: "policy entries",
            count: policy.len(),
        });
    }
    Ok(ScopeTries { classes, policy })
}

/// FNV-1a 64 over the compiled tries — stable across processes and releases, unlike std's hasher.
fn scope_id(v4: &ScopeTries<[u8; 4]>, v6: &ScopeTries<[u8; 16]>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    fn tries<const N: usize>(t: &ScopeTries<[u8; N]>, feed: &mut impl FnMut(&[u8])) {
        for (a, l, c) in &t.classes {
            feed(a);
            feed(&[*l]);
            feed(&c.to_le_bytes());
        }
        feed(&[0xff]); // classes | policy
        for (plen, k, prec) in &t.policy {
            feed(&plen.to_le_bytes());
            feed(&k.class.to_le_bytes());
            feed(&[k.proto, k.port[0], k.port[1]]);
            feed(&prec.to_le_bytes());
        }
    }
    feed(&[4]);
    tries(v4, &mut feed);
    feed(&[6]);
    tries(v6, &mut feed);
    if h == flowplane_common::FW_SCOPE_NONE {
        1
    } else {
        h
    }
}

/// Compile the `dir` rules of an interface (the v4 and v6 slot lists, both directions mixed, in
/// first-match order) into a scope, or `None` when the direction has no rules — bound as scope 0,
/// which denies everything, as the old evaluator did with a zero rule count.
pub fn compile_scope<'a>(
    dir: u8,
    v4: impl IntoIterator<Item = &'a FwRule>,
    v6: impl IntoIterator<Item = &'a FwRule6>,
) -> Result<Option<Scope>, FwError> {
    let mut p4 = Vec::new();
    for r in v4.into_iter().filter(|r| r.direction == dir) {
        p4.extend(parse(&view4(r), dir, 1)?);
    }
    let mut p6 = Vec::new();
    for r in v6.into_iter().filter(|r| r.direction == dir) {
        p6.extend(parse(&view6(r), dir, 58)?);
    }
    if p4.is_empty() && p6.is_empty() {
        return Ok(None);
    }
    let v4 = compile_family(&p4, "IPv4")?;
    let v6 = compile_family(&p6, "IPv6")?;
    Ok(Some(Scope {
        id: scope_id(&v4, &v6),
        v4,
        v6,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};

    fn rule(peer: [u8; 4], len: u8, proto: u8, ports: (u16, u16), allow: bool) -> FwRule {
        let mut mask = [0u8; 4];
        for (i, b) in mask.iter_mut().enumerate() {
            let bits = (len as i32 - 8 * i as i32).clamp(0, 8);
            *b = if bits == 0 { 0 } else { 0xffu8 << (8 - bits) };
        }
        FwRule {
            src_ip: peer,
            src_mask: mask,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: ports.0,
            dst_port_max: ports.1,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto,
            action: if allow {
                FW_ACTION_ACCEPT
            } else {
                FW_ACTION_DROP
            },
            direction: FW_DIR_INGRESS,
            enabled: 1,
            ..Default::default()
        }
    }

    fn compile(rules: &[FwRule]) -> Scope {
        compile_scope(FW_DIR_INGRESS, rules.iter(), [].iter())
            .unwrap()
            .expect("non-empty")
    }

    // The increment-A note: R1 allow 10.1/16 any-proto outranks R2 deny 10/8 TCP/443. R2 survives
    // list-level shadowing (it is wider), but its expansion into class(10.1/16) is covered there by
    // R1 and must be refused — otherwise LPM would prefer the longer TCP/443 key and deny what
    // first-match allows.
    #[test]
    fn expansion_into_a_narrower_class_is_shadowed_there() {
        let s = compile(&[
            rule([10, 1, 0, 0], 16, 0, (0, 65535), true),
            rule([10, 0, 0, 0], 8, 6, (443, 443), false),
        ]);
        let class = |len| s.v4.classes.iter().find(|c| c.1 == len).unwrap().2;
        let under = |c: u32| -> Vec<(u32, u8)> {
            s.v4.policy
                .iter()
                .filter(|(_, k, _)| k.class == c)
                .map(|(plen, k, _)| (*plen, k.proto))
                .collect()
        };
        assert_eq!(
            under(class(16)),
            vec![(FW_POL_PREFIX_CLASS, 0)],
            "only R1 under 10.1/16"
        );
        assert_eq!(
            under(class(8)),
            vec![(FW_POL_PREFIX_PROTO + 16, 6)],
            "R2 under 10/8"
        );
    }

    #[test]
    fn unexpressible_rules_are_refused() {
        let mut local = rule([10, 0, 0, 0], 8, 0, (0, 65535), true);
        local.dst_ip = [10, 9, 9, 9];
        local.dst_mask = [255; 4];
        let mut sport = rule([10, 0, 0, 0], 8, 6, (0, 65535), true);
        sport.src_port_min = 1024;
        let port_on_any = rule([10, 0, 0, 0], 8, 0, (22, 22), true);
        let mut code_only = rule([10, 0, 0, 0], 8, 1, (0, 65535), true);
        code_only.icmp_code = 3;
        let mut hole = rule([10, 0, 0, 0], 8, 0, (0, 65535), true);
        hole.src_mask = [255, 0, 255, 0];
        for r in [local, sport, port_on_any, code_only, hole] {
            let err = compile_scope(FW_DIR_INGRESS, [r].iter(), [].iter()).unwrap_err();
            assert!(matches!(err, FwError::Unsupported(_)), "{err}");
        }
    }

    #[test]
    fn scope_id_is_the_compiled_content() {
        let a = [rule([10, 0, 0, 0], 8, 6, (80, 80), true)];
        let b = [rule([10, 0, 0, 0], 8, 6, (443, 443), true)];
        assert_eq!(compile(&a).id, compile(&a).id);
        assert_ne!(compile(&a).id, compile(&b).id);
        // Host bits outside the mask do not change what the rule matches, so not the id either.
        let mut a2 = a;
        a2[0].src_ip = [10, 7, 7, 7];
        assert_eq!(compile(&a).id, compile(&a2).id);
    }

    #[test]
    fn too_many_classes_is_refused() {
        let rules: Vec<FwRule> = (0..=SCOPE_MAX_CLASSES as u32)
            .map(|i| rule((i + 1).to_be_bytes(), 32, 0, (0, 65535), true))
            .collect();
        let err = compile_scope(FW_DIR_INGRESS, rules.iter(), [].iter()).unwrap_err();
        assert!(
            matches!(
                err,
                FwError::ScopeTooLarge {
                    what: "peer classes",
                    ..
                }
            ),
            "{err}"
        );
    }
}
