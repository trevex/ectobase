# IPv6 firewall parity — design

Date: 2026-07-25
Status: designed, approved

## Problem

The directional, deny-by-default firewall is **IPv4-only end to end in the
dataplane**. `FwRule` (`flowplane-common`) is structurally v4
(`src_ip/dst_ip: [u8; 4]`), the sole evaluator `fw_eval_dir`
(`flowplane-core/src/firewall.rs`) reads the inner IPv4 header at fixed offsets
(+12/+16), and the inner-IPv6 datapath paths never call it at all:

- `flowplane-ebpf/src/v6.rs` `v6_uplink_rx` (inner-v6 ingress → guest tap) has
  **zero** `fw_eval_dir` calls.
- `flowplane-ebpf/src/egress.rs` `forward_decision_v6` (inner-v6 guest egress)
  has **zero** `fw_eval_dir` calls (the two calls at egress.rs:72/146 are in
  `forward_decision_v4`).

So **IPv6 overlay traffic is delivered and emitted with no policy enforcement in
either direction**, contradicting the stated deny-by-default posture
(`firewall.rs:1-5`). This was latent while overlays were v4-only, but the
dual-stack overlay work just merged (`main@793de03`) makes v6-only and
dual-stack guests attachable — so unfirewalled v6 traffic is now live and
reachable.

The **control plane is already family-agnostic**: `NetworkPolicyRule.CIDR` and
`CompiledFwRule.CIDR` are plain strings, and the gRPC `AddFwRuleRequest`
`src_cidr`/`dst_cidr` are strings — a v6 CIDR flows untouched all the way to the
Rust handler, where it dies in `parse_fw_cidr` (IPv4-only: "bad ipv4 address").

## Goal

Add IPv6 firewall enforcement with the same directional, deny-by-default
semantics the v4 path has, across all backends (eBPF, sim, DPDK), plus the
minimal control-plane wiring so existing guests are not broken.

## Key decisions (approved)

1. **Parallel v6 maps, v4 layout untouched.** Mirror the existing route/route6
   split (and the just-merged dual-stack work). Add a new `FwRule6` POD + a new
   `FW_RULES6` map, and a parallel `FW_META6` map (reusing the existing `FwMeta`
   struct for per-interface v6 rule counts). The v4 `FwRule` (size 32),
   `FwMeta` (size 8), `FW_RULES`, and `FW_META` are **byte-identical and
   untouched** — no regression to the v4 firewall path or its verifier anchor.
   (Chosen over widening `FwRule`/`FwMeta`, which would change the v4 POD sizes
   and touch every backend's byte-parity.)

2. **Dataplane stays strict deny-by-default for v6.** `fw_eval_dir6` denies on
   missing `FW_META6`, zero v6 rules in the direction, an unreadable header, or
   no matching rule — identical to v4. The non-breaking behavior for unpolicied
   guests comes entirely from the **control plane emitting default-allow rules**,
   not from any dataplane default.

3. **Default-allow only when a direction has no rules of EITHER family.** The v4
   compiler today emits a `0.0.0.0/0` allow-all for a direction iff that
   direction has zero compiled rules (`len(dir) == 0`). Compiled rules are a
   family-mixed CIDR-string list, so `len == 0` already means "no v4 AND no v6
   rules." Keep that exact gate; when it fires, emit **both** `0.0.0.0/0` (v4)
   and `::/0` (v6) allow-all. Consequence: writing **any** explicit rule (v4 or
   v6) in a direction suppresses the default-allow for **both** families →
   strict deny-by-default for everything not explicitly allowed, in both
   families, in that direction. (This is the approved refinement: "only add
   default allow if both ipv4 and ipv6 rules are absent.")

## The seam (single-source, testable)

The firewall seam is the **evaluator**, not the whole v6 datapath. `fw_eval_dir`
lives in `flowplane-core`, is called by the eBPF v4 datapath, the shared
`datapath.rs` orchestrators, AND directly by sim tests
(`flowplane-sim/src/firewall_test.rs:4` calls `fw_eval_dir` with a `VecPkt` +
mock `Maps`). `fw_eval_dir6` follows the identical pattern: the eBPF v6 paths
call it, and sim tests call it directly with v6 packets. This satisfies the
seam-not-duplicate rule — production and tests run the same evaluator — without
needing to seam the entire inner-v6 datapath (which remains eBPF-resident, like
today).

## Change set

### 1. `flowplane-common` — v6 POD types + constants

- New `FwRule6` (`#[repr(C)]`, mirror `FwRule` exactly but
  `src_ip/src_mask/dst_ip/dst_mask: [u8; 16]`; same
  `src_port_min/max`, `dst_port_min/max`, `icmp_type`, `icmp_code`, `proto`,
  `action`, `direction`, `enabled`). Layout: 4×`[u8;16]` = 64, + 4×`u16` ports =
  8, + 2×`u16` icmp = 4, + 4×`u8` = 4 → **80 bytes** (align 2, no trailing pad).
  Pin `size_of::<FwRule6>() == 80` in the layout test.
- Reuse `FwRuleKey { ifindex, idx }` for `FW_RULES6` (v6 rules get their own
  0..`FW_MAX_RULES` slot space in a separate map).
- Reuse `FwMeta { ingress_count, egress_count }` as the `FW_META6` value type.
- Keep `FW_MAX_RULES = 16` for v6.

### 2. `flowplane-core` — `fw_eval_dir6` + `Maps` trait + parse helpers

- `firewall.rs`: `pub fn fw_eval_dir6<P: Pkt, M: Maps>(pkt, maps, ip_off,
  ifindex, dir) -> u8`. Deny-by-default identical to `fw_eval_dir`, but:
  - meta from `maps.fw_meta6(ifindex)`; direction count from the v6 meta.
  - src = `pkt.read_array::<16>(ip_off + 8)`, dst = `pkt.read_array::<16>(ip_off
    + 24)` (IPv6 fixed header: src at +8, dst at +24).
  - L4: next header at `ip_off + 6`; L4 header at `ip_off + 40`. Add a v6
    variant of `l4_ports` / `icmp_type_code` in `parse.rs` that uses these
    offsets (ICMPv6 proto 58). Extension headers are NOT parsed — L4 is read at
    the fixed `ip_off + 40`, mirroring the v4 path's fixed-offset L4 access; a
    packet carrying ext headers reads the "L4" at the wrong offset and falls
    through to a proto-only match, the same conservative behavior as v4.
    Acceptable for v1.
  - scan `maps.fw_rule6(&FwRuleKey { ifindex, idx })`, match via new
    `fw_rule6_matches(&FwRule6, &PacketSelectors6)` (16-byte masked compare;
    ports/proto/icmp identical to v4).
- `parse.rs`: new `PacketSelectors6 { src: [u8;16], dst: [u8;16], proto, sport,
  dport, icmp_type, icmp_code }` and `fw_rule6_matches`.
- `maps.rs` `Maps` trait: add `fn fw_meta6(&self, ifindex: u32) ->
  Option<FwMeta>;` and `fn fw_rule6(&self, key: &FwRuleKey) -> Option<FwRule6>;`.
  Implement in every `Maps` impl (sim `VecMaps`, eBPF `GlobalMaps`, DPDK
  `DpdkMaps`). Provide trait defaults returning `None` only if that keeps
  unrelated impls compiling without behavior change — otherwise implement
  explicitly (prefer explicit for the three real backends).

### 3. `flowplane-ebpf` — declare maps, wire the v6 datapath

- `maps.rs`: declare `FW_RULES6: HashMap<FwRuleKey, FwRule6>` and `FW_META6:
  HashMap<u32, FwMeta>` BPF maps (mirroring `FW_RULES`/`FW_META`); impl
  `fw_meta6`/`fw_rule6` on `GlobalMaps`.
- `v6.rs` `v6_uplink_rx`: before delivering the decapped inner-v6 frame to the
  guest tap, call `fw_eval_dir6(.., inner_off, tap_ifindex, FW_DIR_INGRESS)`;
  on `FW_ACTION_DROP` return `XDP_DROP`. Mirror the v4 site (`ingress.rs:256-272`).
  The LB-v6 backend-delivery branch is delivered to a local backend tap — apply
  the same ingress eval there (mirroring the v4 LB local-delivery firewall at
  `datapath.rs:64-71`).
- `egress.rs` `forward_decision_v6`: before forwarding the guest's inner-v6
  packet, call `fw_eval_dir6(.., ip_off, src_ifindex, FW_DIR_EGRESS)`; on DROP
  return drop. Mirror `forward_decision_v4` (egress.rs:72).
- **Verifier budget (primary risk).** 16-byte addr reads + the v6 selector grow
  the stack; the 512B combined-frame limit is real (bit the flow-label work).
  Keep `fw_eval_dir6` `#[inline(always)]`, scan one rule at a time (no rule
  arrays, exactly as v4), and avoid stack-resident copies of the 16-byte fields
  beyond what the match needs. Validate with the verifier anchor (task below);
  if it blows the budget, fold the masked compare inline / stream it (per the
  [[flow-label-ecmp-anchor-and-stack]] technique).

### 4. `flowplane-node` — family-aware CIDR parse + handler routing

- `parse.rs`: replace `parse_fw_cidr(&str) -> ([u8;4],[u8;4])` with a
  family-aware `parse_fw_cidr(&str) -> FwCidr` where
  `enum FwCidr { V4([u8;4],[u8;4]), V6([u8;16],[u8;16]) }`. Empty string stays a
  wildcard — represent as `V4([0;4],[0;4])` (the caller decides; see below).
  v4 parses as today; v6 parses `Ipv6Addr` + prefix ≤ 128 → 16-byte mask.
- `handlers.rs` `add_fw_rule`: parse `src_cidr` and `dst_cidr`; the rule's
  family is determined by the non-wildcard side (a rule pairs a specific CIDR on
  one side with `0.0.0.0/0`/`::/0` on the other, per `compiledToFw`). If either
  side is v6 → build a `FwRule6` and write it to `FW_RULES6`, bumping `FW_META6`
  counts; else build a `FwRule` into `FW_RULES`/`FW_META` as today. Mixed v4/v6
  in a single rule (v4 src + v6 dst) is rejected as invalid (cannot occur from
  `compiledToFw`, which wildcards the opposite side). `del_fw_rule` mirrors:
  remove from whichever family map the `rule_id`→slot mapping recorded.
  - Wildcard handling: when one side is the family-appropriate wildcard, encode
    it in the same family as the specific side (v6 rule ⇒ the wildcard side is
    `[0u8;16]` mask `[0u8;16]`).
- The gRPC proto is **unchanged** (strings already carry v6). Update the field
  doc-comments in `dataplane.proto` from "IPv4 CIDR" to "IPv4 or IPv6 CIDR".

### 5. `flowplane-dpdk` — backend parity

- `SharedConfigMaps`: add `FW_RULES6` + `FW_META6` tables (mirror the v4 fw
  tables).
- `DpdkMapWriter`: add `fw_rule6_upsert`/`fw_rule6_delete` + `fw_meta6` write
  methods (1:1 with the v4 methods); `DpdkMaps` impls `fw_meta6`/`fw_rule6`.
- `flowplane-dpdk/src/node.rs` `add_fw_rule`/`del_fw_rule`: same family-branch as
  the eBPF handler (share the `flowplane-node` helper — both backends already
  route fw handlers through `flowplane-node`, so ideally the family branch lives
  there once and both backends inherit it).

### 6. `netplane/controllers/compilednic.go` — v6 default-allow

- In `Compile()`, where a direction with `len == 0` currently appends
  `{CIDR: "0.0.0.0/0", Action: "Allow"}`, append **both**
  `{CIDR: "0.0.0.0/0", Action: "Allow"}` and `{CIDR: "::/0", Action: "Allow"}`.
  Apply to both ingress and egress independently (as today). No other control
  change — explicit v6-CIDR rules already pass through untouched.

## Testing

1. **sim `firewall_test.rs` (seam-level, no root):** add v6 cases calling
   `fw_eval_dir6` directly with `VecPkt` IPv6 packets + a mock `Maps` populated
   with `FW_META6`/`FW_RULES6`: (a) no `FW_META6` ⇒ DROP; (b) zero v6 rules in
   direction ⇒ DROP; (c) explicit v6 allow rule matches ⇒ ACCEPT; (d) v6 CIDR
   mask (prefix) match/miss; (e) direction isolation (an egress rule doesn't
   accept ingress); (f) proto/port/ICMPv6-type match. Mirror the existing v4
   cases.
2. **`flowplane-common` layout test:** pin `size_of::<FwRule6>()` and assert the
   v4 `FwRule`/`FwMeta` sizes are unchanged (regression guard).
3. **`flowplane-node` `parse.rs`:** unit tests for v6 CIDR parsing (full /128,
   prefix /64, `::/0`, invalid, and v4 still works).
4. **eBPF verifier anchor:** extend the privileged verifier/`sim-anchor` target
   so the v6 datapath (with the new `fw_eval_dir6` calls) loads verifier-clean
   and within the stack budget. This is the gate for the eBPF wiring.
5. **Go `compilednic` controller test:** assert a NIC with no firewall policy
   gets BOTH `0.0.0.0/0` and `::/0` allow-all per direction; a NIC with any
   explicit rule (v4 or v6) gets NO default-allow in that direction.
6. **DPDK parity:** a writer/map test that a `fw_rule6_upsert` lands in
   `FW_RULES6` and `fw_meta6` reads it back (mirror the v4 fw writer test if one
   exists; else a focused `DpdkMaps` fw_rule6 round-trip).
7. **Regression:** existing v4 firewall tests + `make sim`/`make test` stay
   green; the v4 firewall byte-parity anchor is unchanged.

## Scope boundaries (YAGNI)

- **In:** `FwRule6`/`FW_RULES6`/`FW_META6`; `fw_eval_dir6` deny-by-default wired
  into inner-v6 ingress + egress (+ LB-v6 local delivery); family-aware CIDR
  parse + handler routing (both backends via `flowplane-node`); DPDK writer/map
  parity; v6 default-allow emission gated on a fully-ruleless direction; tests +
  verifier anchor.
- **Out:** NAT/LB v6 *semantic* changes beyond firewalling the existing paths;
  IPv6 extension-header parsing (v4 path doesn't parse options either);
  ICMPv6-specific policy semantics beyond type/code (reuse v4 logic); the latent
  DPDK-B2b findings from the correctness sweep (per-lcore NAT-return CT miss;
  `ct_touch` not in the core seam; NAT64 ingress unreachable on DPDK serve) —
  tracked separately, not reachable on the shipping eBPF datapath.
- **Untouched:** v4 `FwRule`/`FwMeta`/`FW_RULES`/`FW_META` byte layout + the v4
  firewall anchor; the gRPC proto message shape; the inner-v6 datapath structure
  (only firewall calls are inserted).
