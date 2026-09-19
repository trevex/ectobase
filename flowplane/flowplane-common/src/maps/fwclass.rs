//! Firewall classifier map key & value types (`FW_BIND`, `FW_CLASS{,6}`, `FW_POLICY{,6}`) and the
//! precedence encoding shared by the compiler (flowplane-control) and the evaluator
//! (`flowplane_core::firewall::fw_classify{,6}`).
//!
//! Two-stage classification, Cilium-shaped: an interface is bound to one SCOPE per direction (a
//! compiled, content-addressed rule list, shared by every interface with the same rules). Stage 1
//! maps the packet's PEER address (source on ingress, destination on egress) to a scope-local class
//! by longest-prefix match in the scope's class trie; stage 2 probes the scope's policy trie twice —
//! with that class and with class 0 ("any peer") — and the higher precedence wins. Every other
//! precedence question was settled by the compiler (insert-time shadowing), so the datapath cost is
//! constant in the number of rules.

/// Class 0: "any peer" — the rules whose peer CIDR is the whole address family (`/0`). Never stored
/// in a class trie; the evaluator probes it explicitly. Real classes are 1..=n per scope.
pub const FW_CLASS_ANY: u32 = 0;

/// Scope 0 in an [`FwBind`] direction: the interface has no rules in that direction → DROP.
pub const FW_SCOPE_NONE: u64 = 0;

/// Distinct scopes a node holds (the outer `FW_CLASS{,6}` / `FW_POLICY{,6}` maps' capacity). A scope
/// is one direction's rule set, shared by every interface with identical rules.
pub const FW_SCOPES_MAX: u32 = 4096;
/// Per scope and family: the most peer classes (class-trie entries) and policy entries a scope may
/// hold. The compiler refuses larger rule lists; the eBPF inner-map templates use them as
/// max_entries; the dataplane sizes each scope's tries to their actual content.
pub const FW_SCOPE_MAX_CLASSES: u32 = 4096;
pub const FW_SCOPE_MAX_ENTRIES: u32 = 16384;

/// Policy-trie prefix lengths over [`FwPolKey`] (the LPM key's data bits, class first).
/// Class only (any proto, any port).
pub const FW_POL_PREFIX_CLASS: u32 = 32;
/// Class + proto (any port, or any ICMP type/code).
pub const FW_POL_PREFIX_PROTO: u32 = 40;
/// Class + proto + all 16 port bits (or ICMP type + code).
pub const FW_POL_PREFIX_FULL: u32 = 56;

/// Verdict class in the low byte of a precedence. Only the ALLOW value accepts; DENY is the largest
/// byte so that, were two precedences ever to share a rank, deny would win (they cannot: ranks are
/// unique per scope, family and direction).
pub const FW_PREC_ALLOW: u8 = 1;
pub const FW_PREC_DENY: u8 = 255;
/// Largest encodable rank (24 bits above the verdict byte).
pub const FW_RANK_MAX: u32 = 0x00FF_FFFF;

/// Encode a rule's precedence from its rank in the compiled first-match order (0 = first, wins) and
/// its action. Higher precedence wins; ranks beyond [`FW_RANK_MAX`] saturate (the compiler refuses
/// rule lists that large long before).
#[inline(always)]
pub const fn fw_precedence(rank: u32, allow: bool) -> u32 {
    let r = if rank > FW_RANK_MAX {
        FW_RANK_MAX
    } else {
        rank
    };
    let verdict = if allow { FW_PREC_ALLOW } else { FW_PREC_DENY };
    ((FW_RANK_MAX - r) << 8) | verdict as u32
}

/// Whether a matched precedence accepts the packet.
#[inline(always)]
pub const fn fw_precedence_allows(precedence: u32) -> bool {
    (precedence & 0xff) as u8 == FW_PREC_ALLOW
}

/// Per-interface scope binding (`FW_BIND[ifindex]`), both families and both directions in one value
/// so an interface cuts over to new rules with ONE map write. `gen` is bumped whenever either scope
/// changes; conntrack compares it to re-evaluate established flows after a policy change.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwBind {
    pub ingress_scope: u64,
    pub egress_scope: u64,
    pub gen: u8,
    pub _pad: [u8; 7],
}

impl FwBind {
    /// The scope governing `dir` (`FW_DIR_INGRESS` / `FW_DIR_EGRESS`).
    #[inline(always)]
    pub const fn scope(&self, dir: u8) -> u64 {
        if dir == crate::FW_DIR_EGRESS {
            self.egress_scope
        } else {
            self.ingress_scope
        }
    }
}

/// Policy-trie key data (after the LPM trie's 4-byte prefix length). `class` is always matched in
/// full; `proto` and then `port` are the maskable suffix — Cilium's nesting rule: a wildcard proto
/// implies a wildcard port. `port` is the destination port (big-endian, so a prefix masks its high
/// bits) or, for ICMP/ICMPv6, `[type, code]`. `_pad` rounds the key to 8 bytes (LPM value
/// alignment); no prefix ever covers it.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct FwPolKey {
    pub class: u32,
    pub proto: u8,
    pub port: [u8; 2],
    pub _pad: u8,
}

impl FwPolKey {
    #[inline(always)]
    pub const fn new(class: u32, proto: u8, port: [u8; 2]) -> Self {
        Self {
            class,
            proto,
            port,
            _pad: 0,
        }
    }
}

// SAFETY: `#[repr(C)]` fixed-size POD types whose only padding is the explicit `_pad` fields, so their
// raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for FwBind {}
    unsafe impl aya::Pod for FwPolKey {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn layouts() {
        // 8 + 8 (scopes) + 1 (gen) + 7 (pad) = 24.
        assert_eq!(size_of::<FwBind>(), 24);
        // 4 (class) + 1 (proto) + 2 (port) + 1 (pad) = 8: a multiple of the u32 value's alignment.
        assert_eq!(size_of::<FwPolKey>(), 8);
    }

    #[test]
    fn earlier_rank_outranks_later_whatever_the_action() {
        assert!(fw_precedence(0, true) > fw_precedence(1, false));
        assert!(fw_precedence(3, false) > fw_precedence(4, true));
        assert!(fw_precedence(FW_RANK_MAX - 1, true) > fw_precedence(FW_RANK_MAX, false));
    }

    #[test]
    fn verdict_rides_in_the_low_byte() {
        assert!(fw_precedence_allows(fw_precedence(7, true)));
        assert!(!fw_precedence_allows(fw_precedence(7, false)));
        // A saturated rank keeps its verdict.
        assert!(fw_precedence_allows(fw_precedence(u32::MAX, true)));
        assert_eq!(fw_precedence(u32::MAX, true) >> 8, 0);
    }

    #[test]
    fn bind_picks_the_direction() {
        let b = FwBind {
            ingress_scope: 7,
            egress_scope: 9,
            ..Default::default()
        };
        assert_eq!(b.scope(crate::FW_DIR_INGRESS), 7);
        assert_eq!(b.scope(crate::FW_DIR_EGRESS), 9);
    }
}
