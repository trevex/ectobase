# IPv6 Firewall Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the deny-by-default firewall full IPv6 parity — a parallel `FwRule6`/`FW_RULES6` rule path plus a firewall-only v6 conntrack (`CtKey6`/`CONNTRACK6`) for the stateful established-bypass — wired into the inner-v6 ingress + egress datapath across eBPF, sim, and DPDK backends, with control-plane v6 default-allow.

**Architecture:** Mirror the existing v4/v6 split (route/route6). New POD types + parallel maps leave the v4 `FwRule`/`FwMeta`/`CtKey`/`FW_RULES`/`FW_META`/`CONNTRACK` byte layout **untouched**. The firewall evaluator (`fw_eval_dir6`) and conntrack helpers (`ct_key6`, `ct_create_default6`) live in `flowplane-core` as the single-source seam — the eBPF v6 datapath calls them, and sim tests call them directly with `VecPkt`/`VecMaps` (same pattern as v4 `fw_eval_dir`). Control-plane CIDR handling is already family-agnostic strings; only the Rust parse + a v6 default-allow emission change.

**Tech Stack:** Rust (aya eBPF, `flowplane-core`/`-common`/`-control`/`-node`, DPDK `nfkit`), Go (netplane controllers), `#[repr(C)]` POD map values, BPF verifier (512B combined stack limit).

**Primary risk:** the eBPF verifier stack budget — v6 uses 16-byte addrs (`FwRule6` masks, `CtKey6`, selectors). Keep evaluators `#[inline(always)]`, scan one rule at a time (no arrays), and gate the eBPF wiring on the verifier anchor (Task 11).

**Reference sites to mirror (read these first):**
- v4 firewall eval: `flowplane-core/src/firewall.rs:16` (`fw_eval_dir`)
- v4 matcher + selectors: `flowplane-common/src/lib.rs:485` (`PacketSelectors`), `:498` (`fw_rule_matches`)
- v4 L4 parse: `flowplane-core/src/parse.rs:17` (`l4_ports`), `:191` (`icmp_type_code`)
- v4 conntrack core: `flowplane-core/src/conntrack.rs:47` (`ct_key`), `:95` (`invert_key`), `:242` (`ct_create_default`)
- v4 conntrack eBPF: `flowplane-ebpf/src/conntrack.rs:19` (`ct_key`), `:57` (`ct_touch`)
- v4 control programming: `flowplane-control/src/firewall.rs:18` (`fw_reprogram`), `:52` (`add_fw_rule`), `:80` (`del_fw_rule`)
- v4 node handler: `flowplane-node/src/handlers.rs:195` (`add_fw_rule`), `flowplane-node/src/parse.rs:41` (`parse_fw_cidr`)
- v4 eBPF datapath sites: `flowplane-ebpf/src/ingress.rs:256` (ingress fw+ct), `flowplane-ebpf/src/egress.rs:60` (egress fw+ct), `flowplane-ebpf/src/v6.rs:92` (`v6_uplink_rx`), `flowplane-ebpf/src/egress.rs:170` (`forward_decision_v6`)
- v4 DPDK writer/maps: `flowplane-dpdk/src/writer.rs:158`, `nfkit/src/dpdk_maps.rs:94`, `nfkit/src/shared_config.rs` (fw tables)
- v4 compiler default-allow: `netplane/controllers/compilednic.go:111`

---

## File Structure

- `flowplane/flowplane-common/src/lib.rs` — add `FwRule6`, `PacketSelectors6`, `fw_rule6_matches`, `CtKey6`; layout tests.
- `flowplane/flowplane-core/src/parse.rs` — add `l4_ports_v6`, `icmp_type_code_v6`.
- `flowplane/flowplane-core/src/conntrack.rs` — add `ct_key6`, `invert_key6`, `ct_create_default6`.
- `flowplane/flowplane-core/src/firewall.rs` — add `fw_eval_dir6`.
- `flowplane/flowplane-core/src/maps.rs` — `Maps` trait: add `fw_meta6`, `fw_rule6`, `conntrack6_get`, `conntrack6_insert`.
- `flowplane/flowplane-sim/src/maps.rs` — `VecMaps`: add `fw_meta6`, `fw_rules6`, `conntrack6` fields + impls.
- `flowplane/flowplane-sim/src/firewall_test.rs` + `conntrack_test.rs` (or existing) — v6 tests.
- `flowplane/flowplane-control/src/lib.rs` — `MapWriter` trait: add `fw_rules6_upsert/remove`, `fw_meta6_upsert`; `ControlCore` v6 fw shadow.
- `flowplane/flowplane-control/src/firewall.rs` — add `fw6_reprogram`, `add_fw_rule6`, `del_fw_rule6`; extend `del_fw_rule`.
- `flowplane/flowplane-control/src/mem.rs` — `MemMapWriter`: v6 fw map fields + impls.
- `flowplane/flowplane-node/src/parse.rs` — `FwCidr` enum + family-aware `parse_fw_cidr`.
- `flowplane/flowplane-node/src/handlers.rs` — `add_fw_rule` family branch.
- `flowplane/flowplane-ebpf/src/maps.rs` — declare `FW_RULES6`, `FW_META6`, `CONNTRACK6`.
- `flowplane/flowplane-ebpf/src/coreimpl.rs` — `GlobalMaps`: `fw_meta6`, `fw_rule6`, `conntrack6_get/insert`.
- `flowplane/flowplane-ebpf/src/conntrack.rs` — `ct_key6`, `ct_touch6`.
- `flowplane/flowplane-ebpf/src/v6.rs` + `egress.rs` — wire the datapath.
- `flowplane/flowplane/src/control/` (AyaWriter) — v6 fw write methods.
- `flowplane/nfkit/src/shared_config.rs` + `dpdk_maps.rs`, `flowplane/flowplane-dpdk/src/writer.rs` — DPDK parity.
- `netplane/controllers/compilednic.go` + test — v6 default-allow.

---

## Task 1: v6 POD types + layout tests (`flowplane-common`)

**Files:**
- Modify: `flowplane/flowplane-common/src/lib.rs` (near `FwRule` @398, `PacketSelectors` @485, `CtKey` @~/`CtEntry`)
- Test: same file's `#[cfg(test)] mod tests` (layout asserts near `size_of::<FwRule>()` @842)

- [ ] **Step 1: Write failing layout tests**

Add to the layout test module (next to the existing `size_of::<FwRule>() == 32` assertion):

```rust
assert_eq!(core::mem::size_of::<FwRule6>(), 80);
assert_eq!(core::mem::size_of::<CtKey6>(), 44);
// regression guard: v4 layouts unchanged
assert_eq!(core::mem::size_of::<FwRule>(), 32);
assert_eq!(core::mem::size_of::<FwMeta>(), 8);
assert_eq!(core::mem::size_of::<CtKey>(), 20);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-common 2>&1 | tail -5`
Expected: FAIL — `cannot find type FwRule6` / `CtKey6`.

- [ ] **Step 3: Add the types**

Add after `FwRule` (`flowplane-common/src/lib.rs:413`):

```rust
/// IPv6 firewall rule (fixed-size POD). Identical to `FwRule` but 16-byte addresses/masks.
/// Programmed into the parallel `FW_RULES6` map; the v4 `FwRule`/`FW_RULES` are untouched.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct FwRule6 {
    pub src_ip: [u8; 16],
    pub src_mask: [u8; 16],
    pub dst_ip: [u8; 16],
    pub dst_mask: [u8; 16],
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub enabled: u8,
}
```

Add after `PacketSelectors` (`:493`):

```rust
/// IPv6 packet selectors (16-byte addresses). Mirror of `PacketSelectors`.
pub struct PacketSelectors6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp_type: u16,
    pub icmp_code: u16,
}

/// Pure IPv6 firewall match. Mirror of `fw_rule_matches` (`:498`); ICMPv6 uses proto 58.
#[inline]
pub fn fw_rule6_matches(r: &FwRule6, s: &PacketSelectors6) -> bool {
    let PacketSelectors6 { src, dst, proto, sport, dport, icmp_type, icmp_code } = *s;
    if r.enabled == 0 {
        return false;
    }
    if r.proto != 0 && r.proto != proto {
        return false;
    }
    for i in 0..16 {
        if src[i] & r.src_mask[i] != r.src_ip[i] & r.src_mask[i] {
            return false;
        }
        if dst[i] & r.dst_mask[i] != r.dst_ip[i] & r.dst_mask[i] {
            return false;
        }
    }
    match proto {
        6 | 17 => {
            sport >= r.src_port_min
                && sport <= r.src_port_max
                && dport >= r.dst_port_min
                && dport <= r.dst_port_max
        }
        58 => {
            (r.icmp_type == 0xffff || icmp_type == r.icmp_type)
                && (r.icmp_code == 0xffff || icmp_code == r.icmp_code)
        }
        _ => true,
    }
}
```

Add after `CtKey`:

```rust
/// IPv6 conntrack key (firewall-only). Mirror of `CtKey` with 16-byte addresses.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct CtKey6 {
    pub vni: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-common 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-common/src/lib.rs
git commit -m "feat(common): FwRule6 + PacketSelectors6 + fw_rule6_matches + CtKey6"
```

---

## Task 2: v6 L4 parse helpers (`flowplane-core/src/parse.rs`)

**Files:**
- Modify: `flowplane/flowplane-core/src/parse.rs` (after `l4_ports` @17 and `icmp_type_code` @191)
- Test: `flowplane/flowplane-sim/src/` (new `parse_v6_test.rs` module, registered in that crate's `lib.rs`)

- [ ] **Step 1: Write failing test** (in a new `flowplane-sim` test file; sim has `VecPkt`)

```rust
use flowplane_core::parse::{icmp_type_code_v6, l4_ports_v6};
use flowplane_sim::pkt::VecPkt; // adjust path to the sim VecPkt

// Build a minimal IPv6 header (40B) + TCP, with next-header/ports at the v6 offsets.
fn v6_tcp(sport: u16, dport: u16) -> Vec<u8> {
    let mut b = vec![0u8; 40 + 20];
    b[6] = 6; // next header = TCP at ip_off+6
    b[40..42].copy_from_slice(&sport.to_be_bytes()); // L4 at ip_off+40
    b[42..44].copy_from_slice(&dport.to_be_bytes());
    b
}

#[test]
fn l4_ports_v6_reads_tcp_ports() {
    let pkt = VecPkt::new(v6_tcp(1234, 80));
    assert_eq!(l4_ports_v6(&pkt, 0), Some((6, 1234, 80)));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-sim l4_ports_v6 2>&1 | tail -5`
Expected: FAIL — `l4_ports_v6` not found.

- [ ] **Step 3: Implement the helpers** (`flowplane-core/src/parse.rs`, after `l4_ports`)

```rust
/// IPv6 variant of `l4_ports`: next header at `ip_off + 6`, L4 header at the fixed `ip_off + 40`
/// (no extension-header parsing — mirrors the v4 fixed-offset access). ICMPv6 (58) mirrors the
/// id into both ports like the v4 ICMP case.
pub fn l4_ports_v6<P: Pkt>(pkt: &P, ip_off: usize) -> Option<(u8, u16, u16)> {
    let nexthdr = pkt.read_u8(ip_off + 6)?;
    let l4 = ip_off + 40;
    match nexthdr {
        IPPROTO_TCP | IPPROTO_UDP => {
            let sp = pkt.read_u16_be(l4)?;
            let dp = pkt.read_u16_be(l4 + 2)?;
            Some((nexthdr, sp, dp))
        }
        58 => {
            // ICMPv6 echo: type@l4, code@l4+1, id@l4+4.
            let id = pkt.read_u16_be(l4 + 4)?;
            Some((nexthdr, id, id))
        }
        _ => None,
    }
}

/// IPv6 variant of `icmp_type_code`: ICMPv6 header at `ip_off + 40` when next header is 58.
pub fn icmp_type_code_v6<P: Pkt>(pkt: &P, ip_off: usize) -> (u16, u16) {
    if pkt.read_u8(ip_off + 6) != Some(58) {
        return (0xffff, 0xffff);
    }
    let l4 = ip_off + 40;
    let t = pkt.read_u8(l4).map(u16::from).unwrap_or(0xffff);
    let c = pkt.read_u8(l4 + 1).map(u16::from).unwrap_or(0xffff);
    (t, c)
}
```

(Confirm `read_u8`/`read_u16_be` exist on the `Pkt` trait — they are used by `l4_ports` at `:17`.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-sim l4_ports_v6 2>&1 | tail -5`
Expected: PASS. Also add + pass a UDP case and an ICMPv6 echo case (`icmp_type_code_v6` returns the type/code).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-core/src/parse.rs flowplane/flowplane-sim/
git commit -m "feat(core): l4_ports_v6 + icmp_type_code_v6 parse helpers"
```

---

## Task 3: v6 conntrack core + `Maps` trait + sim impl (`flowplane-core`, `flowplane-sim`)

**Files:**
- Modify: `flowplane/flowplane-core/src/conntrack.rs` (after `ct_key` @47, `invert_key` @95, `ct_create_default` @242)
- Modify: `flowplane/flowplane-core/src/maps.rs` (`Maps` trait, near `conntrack_get` @13)
- Modify: `flowplane/flowplane-sim/src/maps.rs` (`VecMaps` struct @~32 + impls @~95)
- Test: `flowplane/flowplane-sim/src/` conntrack test module

- [ ] **Step 1: Write failing test** (sim)

```rust
use flowplane_common::CtKey6;
use flowplane_core::conntrack::{ct_create_default6, ct_key6, invert_key6};
// VecPkt + VecMaps from the sim crate

#[test]
fn ct_create_default6_seeds_forward_and_reverse() {
    let src = [0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1];
    let dst = [0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2];
    let pkt = /* v6 TCP pkt src->dst sport=1111 dport=80, ip_off=0 */;
    let mut m = VecMaps::default();
    ct_create_default6(&pkt, &mut m, 0, 100, 5);
    let fwd = ct_key6(&pkt, 0, 100).unwrap();
    assert!(m.conntrack6_get(&fwd).is_some(), "forward entry seeded");
    assert!(m.conntrack6_get(&invert_key6(&fwd)).is_some(), "reverse entry pre-seeded");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-sim ct_create_default6 2>&1 | tail -5`
Expected: FAIL — items not found.

- [ ] **Step 3a: Add `Maps` trait methods** (`flowplane-core/src/maps.rs`, after `conntrack_insert` @14)

```rust
    fn conntrack6_get(&self, key: &flowplane_common::CtKey6) -> Option<CtEntry>;
    fn conntrack6_insert(&mut self, key: flowplane_common::CtKey6, entry: CtEntry);
```

(Also add `CtKey6` to the `flowplane_common::{...}` import at `maps.rs:2`.)

- [ ] **Step 3b: Add conntrack core helpers** (`flowplane-core/src/conntrack.rs`)

`ct_key6` — mirror `ct_key` (@47) but read v6 addresses and use `l4_ports_v6`:

```rust
pub fn ct_key6<P: Pkt>(pkt: &P, ip_off: usize, vni: u32) -> Option<CtKey6> {
    let src = pkt.read_array::<16>(ip_off + 8)?;
    let dst = pkt.read_array::<16>(ip_off + 24)?;
    let (proto, sport, dport) = crate::parse::l4_ports_v6(pkt, ip_off)
        .unwrap_or((pkt.read_u8(ip_off + 6).unwrap_or(0), 0, 0));
    Some(CtKey6 { vni, src_ip: src, dst_ip: dst, src_port: sport, dst_port: dport, proto, _pad: [0; 3] })
}

pub fn invert_key6(k: &CtKey6) -> CtKey6 {
    CtKey6 {
        vni: k.vni,
        src_ip: k.dst_ip,
        dst_ip: k.src_ip,
        src_port: k.dst_port,
        dst_port: k.src_port,
        proto: k.proto,
        _pad: [0; 3],
    }
}
```

`ct_create_default6` — verbatim mirror of `ct_create_default` (@242) using the v6 key/maps. Reuse `CtEntry` with the xlate/gen fields zeroed (v6 does no NAT):

```rust
pub fn ct_create_default6<P: Pkt, M: Maps>(pkt: &P, maps: &mut M, ip_off: usize, vni: u32, now: u64) {
    let key = match ct_key6(pkt, ip_off, vni) {
        Some(k) => k,
        None => return,
    };
    let tcp = tcp_flags_v6(pkt, ip_off).map(|fl| tcp_advance(0, fl)).unwrap_or(0);
    let e = CtEntry {
        last_seen: now,
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: CT_F_DEFAULT,
        tcp_state: tcp,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    };
    maps.conntrack6_insert(key, e);
    let rev = invert_key6(&key);
    if maps.conntrack6_get(&rev).is_none() {
        maps.conntrack6_insert(rev, e);
    }
}
```

Add a small `tcp_flags_v6<P: Pkt>(pkt, ip_off) -> Option<u8>` that reads the TCP flags byte at `ip_off + 40 + 13` when next-header is 6 (mirror the v4 `tcp_flags` helper `ct_create_default` uses at `:253`; read the v4 helper to match its return convention). Import `CtKey6` into `conntrack.rs`.

- [ ] **Step 3c: Implement on sim `VecMaps`** (`flowplane-sim/src/maps.rs`)

Add field (near `fw_rules` @33): `pub conntrack6: std::collections::HashMap<flowplane_common::CtKey6, CtEntry>,` and impls (near @98):

```rust
    fn conntrack6_get(&self, key: &flowplane_common::CtKey6) -> Option<CtEntry> {
        self.conntrack6.get(key).copied()
    }
    fn conntrack6_insert(&mut self, key: flowplane_common::CtKey6, entry: CtEntry) {
        self.conntrack6.insert(key, entry);
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-sim ct_create_default6 2>&1 | tail -5`
Expected: PASS. Add a second test: `ct_key6`/`invert_key6` round-trip (invert twice == original).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-core/ flowplane/flowplane-sim/
git commit -m "feat(core): v6 conntrack (ct_key6/invert_key6/ct_create_default6) + Maps conntrack6"
```

---

## Task 4: `fw_eval_dir6` evaluator + `Maps` fw6 methods + sim tests (`flowplane-core`, `flowplane-sim`)

**Files:**
- Modify: `flowplane/flowplane-core/src/firewall.rs` (after `fw_eval_dir` @64)
- Modify: `flowplane/flowplane-core/src/maps.rs` (`Maps` trait, near `fw_meta`/`fw_rule` @11-12)
- Modify: `flowplane/flowplane-sim/src/maps.rs` (`VecMaps` fields + impls)
- Test: `flowplane/flowplane-sim/src/firewall_test.rs`

- [ ] **Step 1: Write failing tests** (mirror the v4 cases in `firewall_test.rs`)

```rust
use flowplane_core::firewall::fw_eval_dir6;
use flowplane_common::{FwMeta, FwRule6, FwRuleKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};

// helper: a v6 TCP packet src->dst dport=80 at ip_off=0
// helper: VecMaps with fw_meta6[ifindex]={ingress_count:1} + fw_rules6[(ifindex,0)]=rule

#[test]
fn v6_deny_by_default_no_meta() {
    let pkt = v6_tcp(SRC, DST, 5000, 80);
    let empty = VecMaps::default();
    assert_eq!(fw_eval_dir6(&pkt, &empty, 0, 7, FW_DIR_INGRESS), FW_ACTION_DROP);
}

#[test]
fn v6_explicit_allow_matches() {
    let pkt = v6_tcp(SRC, DST, 5000, 80);
    let mut m = VecMaps::default();
    m.fw_meta6.insert(7, FwMeta { ingress_count: 1, egress_count: 0 });
    m.fw_rules6.insert((7, 0), FwRule6 {
        src_ip: [0;16], src_mask: [0;16],           // any src
        dst_ip: DST, dst_mask: [0xff;16],            // exact dst
        src_port_min: 0, src_port_max: 65535,
        dst_port_min: 80, dst_port_max: 80,
        icmp_type: 0xffff, icmp_code: 0xffff,
        proto: 6, action: FW_ACTION_ACCEPT, direction: FW_DIR_INGRESS, enabled: 1,
    });
    assert_eq!(fw_eval_dir6(&pkt, &m, 0, 7, FW_DIR_INGRESS), FW_ACTION_ACCEPT);
}
```

Also add: zero-rules-in-direction ⇒ DROP; direction isolation (an egress rule doesn't accept ingress); v6 prefix mask miss ⇒ DROP.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-sim v6_ 2>&1 | tail -8`
Expected: FAIL — `fw_eval_dir6` not found.

- [ ] **Step 3a: Add `Maps` trait fw6 methods** (`flowplane-core/src/maps.rs`, after @12)

```rust
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta>;
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6>;
```

- [ ] **Step 3b: Add `fw_eval_dir6`** (`flowplane-core/src/firewall.rs`, mirror `fw_eval_dir`)

```rust
use flowplane_common::{FwRuleKey, FwRule6, PacketSelectors6, FW_ACTION_DROP, FW_DIR_EGRESS, FW_MAX_RULES};

/// IPv6 firewall evaluator. Deny-by-default, identical semantics to `fw_eval_dir` but reads the
/// inner IPv6 header (src@+8, dst@+24, L4@+40) and scans `FW_RULES6`/`FW_META6`.
#[inline(always)]
pub fn fw_eval_dir6<P: Pkt, M: Maps>(pkt: &P, maps: &M, ip_off: usize, ifindex: u32, dir: u8) -> u8 {
    let meta = match maps.fw_meta6(ifindex) {
        Some(m) => m,
        None => return FW_ACTION_DROP,
    };
    let count = if dir == FW_DIR_EGRESS { meta.egress_count } else { meta.ingress_count };
    if count == 0 {
        return FW_ACTION_DROP;
    }
    let src = match pkt.read_array::<16>(ip_off + 8) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let dst = match pkt.read_array::<16>(ip_off + 24) {
        Some(v) => v,
        None => return FW_ACTION_DROP,
    };
    let (proto, sport, dport) = match crate::parse::l4_ports_v6(pkt, ip_off) {
        Some(v) => v,
        None => (pkt.read_u8(ip_off + 6).unwrap_or(0), 0u16, 0u16),
    };
    let (itype, icode) = crate::parse::icmp_type_code_v6(pkt, ip_off);
    let sel = PacketSelectors6 { src, dst, proto, sport, dport, icmp_type: itype, icmp_code: icode };
    let mut idx: u32 = 0;
    while idx < FW_MAX_RULES {
        if let Some(r) = maps.fw_rule6(&FwRuleKey { ifindex, idx }) {
            if r.direction == dir && flowplane_common::fw_rule6_matches(&r, &sel) {
                return r.action;
            }
        }
        idx += 1;
    }
    FW_ACTION_DROP
}
```

- [ ] **Step 3c: Implement on sim `VecMaps`** — add fields `pub fw_meta6: HashMap<u32, FwMeta>,` and `pub fw_rules6: HashMap<(u32, u32), FwRule6>,` + impls mirroring `fw_meta`/`fw_rule` (@95-99):

```rust
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> { self.fw_meta6.get(&ifindex).copied() }
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        self.fw_rules6.get(&(key.ifindex, key.idx)).copied()
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-sim v6_ 2>&1 | tail -8`
Expected: PASS (all v6 firewall cases).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-core/ flowplane/flowplane-sim/
git commit -m "feat(core): fw_eval_dir6 deny-by-default v6 firewall evaluator + sim tests"
```

---

## Task 5: control-plane v6 fw programming (`flowplane-control`)

**Files:**
- Modify: `flowplane/flowplane-control/src/lib.rs` (`MapWriter` trait + `ControlCore` struct: add `fw6` shadow field)
- Modify: `flowplane/flowplane-control/src/firewall.rs` (add `fw6_reprogram`, `add_fw_rule6`, `del_fw_rule6`; extend `del_fw_rule`)
- Modify: `flowplane/flowplane-control/src/mem.rs` (`MemMapWriter`: v6 fw fields + impls)
- Test: `flowplane/flowplane-control/src/firewall.rs` `#[cfg(test)]` (mirror @98)

- [ ] **Step 1: Write failing test** (in firewall.rs test module, mirror the v4 `add_fw_rule` test @~111)

```rust
#[test]
fn add_fw_rule6_programs_rules6_and_meta6() {
    let mut c = ControlCore::new(MemMapWriter::default());
    // program an interface so ifaces_meta has the ifindex (mirror the v4 test's setup)
    // ... attach/program_interface as the v4 test does ...
    let r6 = FwRule6 { /* ingress accept, dst ::/0 */ ..Default::default() };
    c.add_fw_rule6(b"if0", b"r1".to_vec(), r6).unwrap();
    let w = c.writer();
    assert!(w.fw_rules6.get(&FwRuleKey { ifindex: IFX, idx: 0 }).is_some());
    assert_eq!(w.fw_meta6.get(&IFX).unwrap().ingress_count, 1);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-control add_fw_rule6 2>&1 | tail -5`
Expected: FAIL — method/fields not found.

- [ ] **Step 3a: `MapWriter` trait** (`flowplane-control/src/lib.rs`, next to the v4 fw methods)

```rust
    fn fw_rules6_upsert(&mut self, key: FwRuleKey, val: FwRule6) -> anyhow::Result<()>;
    fn fw_rules6_remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()>;
    fn fw_meta6_upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()>;
```

Add a `fw6: HashMap<u32, Vec<(Vec<u8>, FwRule6)>>` field to `ControlCore` (mirror `fw` @/`self.fw`), default-initialized.

- [ ] **Step 3b: `ControlCore` v6 programming** (`flowplane-control/src/firewall.rs`)

Add `fw6_reprogram`, `add_fw_rule6`, `del_fw_rule6` as verbatim mirrors of `fw_reprogram` (@18), `add_fw_rule` (@52), `del_fw_rule` (@80), replacing `self.fw`→`self.fw6`, `FwRule`→`FwRule6`, `fw_rules_upsert/remove`→`fw_rules6_upsert/remove`, `fw_meta_upsert`→`fw_meta6_upsert`. Also update `remove_fw_rules` (@14) to also `self.fw6.remove(&ifindex)` and reprogram-clear v6 slots on interface teardown.

Extend `del_fw_rule` (@80) so a delete tries the v4 shadow first, then the v6 shadow (rule_ids are unique per interface; the handler doesn't know the family on delete):

```rust
pub fn del_fw_rule(&mut self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
    // try v4
    if self.del_fw_rule_v4(interface_id, rule_id)? { return Ok(true); }
    // then v6
    self.del_fw_rule6(interface_id, rule_id)
}
```

(Rename the current `del_fw_rule` body to `del_fw_rule_v4`; keep behavior identical.)

- [ ] **Step 3c: `MemMapWriter`** (`flowplane-control/src/mem.rs`) — add `pub fw_rules6: HashMap<FwRuleKey, FwRule6>` + `pub fw_meta6: HashMap<u32, FwMeta>` fields and the three trait impls (mirror the v4 fw impls in that file).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-control 2>&1 | tail -8`
Expected: PASS (new v6 test + existing v4 fw tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-control/
git commit -m "feat(control): ControlCore v6 firewall programming + MapWriter fw6 methods"
```

---

## Task 6: node handler family-aware CIDR parse + routing (`flowplane-node`)

**Files:**
- Modify: `flowplane/flowplane-node/src/parse.rs` (@41 `parse_fw_cidr`)
- Modify: `flowplane/flowplane-node/src/handlers.rs` (@195 `add_fw_rule`)
- Test: `flowplane/flowplane-node/src/parse.rs` tests + `handlers.rs` tests (@263)

- [ ] **Step 1: Write failing tests**

parse.rs:
```rust
#[test]
fn parse_fw_cidr_v6() {
    match parse_fw_cidr("2001:db8::/32").unwrap() {
        FwCidr::V6(ip, mask) => {
            assert_eq!(ip[0..2], [0x20, 0x01]);
            assert_eq!(mask[0..4], [0xff, 0xff, 0xff, 0xff]);
            assert_eq!(mask[4], 0x00);
        }
        _ => panic!("expected V6"),
    }
    assert!(matches!(parse_fw_cidr("10.0.0.0/8").unwrap(), FwCidr::V4(..)));
    assert!(matches!(parse_fw_cidr("::/0").unwrap(), FwCidr::V6(_, [0u8;16])));
}
```

handlers.rs (mirror `add_fw_rule_programs` @329):
```rust
#[test]
fn add_fw_rule_v6_programs_rules6() {
    let mut c = core();
    // program interface so ifaces_meta has ifindex (as the v4 test does)
    let req = pb::AddFwRuleRequest {
        interface_id: "if0".into(), rule_id: "r1".into(),
        src_cidr: "::/0".into(), dst_cidr: "2001:db8::1/128".into(),
        proto: 6, dst_port_min: 80, dst_port_max: 80, allow: true, egress: false,
    };
    add_fw_rule(&mut c, &req).unwrap();
    assert!(c.writer().fw_rules6.get(&FwRuleKey { ifindex: IFX, idx: 0 }).is_some());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-node parse_fw_cidr_v6 add_fw_rule_v6 2>&1 | tail -6`
Expected: FAIL.

- [ ] **Step 3a: Family-aware parse** (`flowplane-node/src/parse.rs`, replace `parse_fw_cidr` @41)

```rust
pub enum FwCidr {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

pub fn parse_fw_cidr(cidr: &str) -> anyhow::Result<FwCidr> {
    if cidr.is_empty() {
        return Ok(FwCidr::V4([0u8; 4], [0u8; 4])); // empty = v4 wildcard (caller may re-encode)
    }
    let (addr, len_str) = match cidr.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (cidr, None),
    };
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        let len: u32 = len_str.map(|l| l.parse()).transpose()?.unwrap_or(32);
        if len > 32 { anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}"); }
        let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        return Ok(FwCidr::V4(v4.octets(), mask.to_be_bytes()));
    }
    let v6: std::net::Ipv6Addr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("bad ip address in {cidr:?}"))?;
    let len: u32 = len_str.map(|l| l.parse()).transpose()?.unwrap_or(128);
    if len > 128 { anyhow::bail!("v6 prefix len {len} > 128 in {cidr:?}"); }
    let mask: u128 = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    Ok(FwCidr::V6(v6.octets(), mask.to_be_bytes()))
}
```

- [ ] **Step 3b: Handler family branch** (`flowplane-node/src/handlers.rs`, `add_fw_rule` @195)

Parse both sides; the rule's family is v6 iff either parsed side is `V6`. Build the specific-side + re-encode the wildcard opposite side in the same family, then call `core.add_fw_rule` (v4) or `core.add_fw_rule6` (v6). Concretely:

```rust
let src = parse_fw_cidr(&req.src_cidr).map_err(invalid)?;
let dst = parse_fw_cidr(&req.dst_cidr).map_err(invalid)?;
// ... proto/ports as today ...
let is_v6 = matches!(src, FwCidr::V6(..)) || matches!(dst, FwCidr::V6(..));
if is_v6 {
    let (s_ip, s_mask) = match src { FwCidr::V6(i, m) => (i, m), FwCidr::V4(..) => ([0u8;16], [0u8;16]) };
    let (d_ip, d_mask) = match dst { FwCidr::V6(i, m) => (i, m), FwCidr::V4(..) => ([0u8;16], [0u8;16]) };
    let rule = flowplane_common::FwRule6 {
        src_ip: s_ip, src_mask: s_mask, dst_ip: d_ip, dst_mask: d_mask,
        src_port_min: 0, src_port_max: 65535, dst_port_min, dst_port_max,
        icmp_type: 0xffff, icmp_code: 0xffff, proto,
        action: if req.allow { FW_ACTION_ACCEPT } else { FW_ACTION_DROP },
        direction: if req.egress { FW_DIR_EGRESS } else { FW_DIR_INGRESS },
        enabled: 1,
    };
    core.add_fw_rule6(&iface, rule_id, rule).map_err(internal)?;
} else {
    let (src_ip, src_mask) = match src { FwCidr::V4(i, m) => (i, m), _ => unreachable!() };
    let (dst_ip, dst_mask) = match dst { FwCidr::V4(i, m) => (i, m), _ => unreachable!() };
    let rule = flowplane_common::FwRule { /* as today */ };
    core.add_fw_rule(&iface, rule_id, rule).map_err(internal)?;
}
```

`del_fw_rule` (@240) is unchanged — `core.del_fw_rule` now tries both families (Task 5).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-node 2>&1 | tail -8`
Expected: PASS (v6 parse + v6 handler + existing v4 handler tests).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-node/
git commit -m "feat(node): family-aware fw CIDR parse + v6 rule routing"
```

---

## Task 7: eBPF maps + accessors + conntrack helpers (`flowplane-ebpf`, AyaWriter)

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/maps.rs` (declare maps, near `FW_RULES` @66)
- Modify: `flowplane/flowplane-ebpf/src/coreimpl.rs` (`GlobalMaps` impls, near `fw_meta` @24)
- Modify: `flowplane/flowplane-ebpf/src/conntrack.rs` (add `ct_key6`, `ct_touch6`)
- Modify: AyaWriter (find with `grep -rn "impl MapWriter for AyaWriter" flowplane/flowplane/src`) — v6 fw write methods
- Test: build-only (eBPF has no host unit tests; the anchor in Task 11 verifies the verifier)

- [ ] **Step 1: Declare BPF maps** (`flowplane-ebpf/src/maps.rs`)

```rust
#[map]
pub static FW_RULES6: HashMap<FwRuleKey, FwRule6> = HashMap::pinned(16384, 0);
#[map]
pub static FW_META6: HashMap<u32, FwMeta> = HashMap::pinned(1024, 0);
#[map]
pub static CONNTRACK6: HashMap<CtKey6, CtEntry> = HashMap::pinned(1 << 20, 0);
```

(Match the exact sizing/flags of `CONNTRACK`/`FW_RULES`/`FW_META`; import `FwRule6`, `CtKey6` from `flowplane_common`.)

- [ ] **Step 2: `GlobalMaps` accessors** (`flowplane-ebpf/src/coreimpl.rs`, mirror @24-30)

```rust
    fn fw_meta6(&self, ifindex: u32) -> Option<FwMeta> {
        unsafe { crate::maps::FW_META6.get(&ifindex).copied() }
    }
    fn fw_rule6(&self, key: &FwRuleKey) -> Option<flowplane_common::FwRule6> {
        unsafe { crate::maps::FW_RULES6.get(key).copied() }
    }
    fn conntrack6_get(&self, key: &flowplane_common::CtKey6) -> Option<CtEntry> {
        unsafe { crate::maps::CONNTRACK6.get(key).copied() }
    }
    fn conntrack6_insert(&mut self, key: flowplane_common::CtKey6, entry: CtEntry) {
        let _ = crate::maps::CONNTRACK6.insert(&key, &entry, 0);
    }
```

- [ ] **Step 3: eBPF conntrack helpers** (`flowplane-ebpf/src/conntrack.rs`, mirror `ct_key` @19 / `ct_touch` @57)

`ct_key6(data, data_end, ip_off, vni) -> Option<CtKey6>` — bounds-check `data + ip_off + 40 + 4 <= data_end`, read v6 src/dst/L4, build `CtKey6` (same tuple logic as the core `ct_key6`, but raw-pointer style like the eBPF `ct_key`). `ct_touch6(data, data_end, ip_off, key, e)` — set `e.last_seen = now()`, `tcp_advance` when TCP, `CONNTRACK6.insert(key, e, 0)`.

- [ ] **Step 4: AyaWriter v6 fw methods** — implement `fw_rules6_upsert/remove` and `fw_meta6_upsert` against the aya `FW_RULES6`/`FW_META6` maps, mirroring the v4 AyaWriter fw methods (the loader-side map handles). Find them alongside the existing `fw_rules_upsert`.

- [ ] **Step 5: Build**

Run: `cargo build -p flowplane 2>&1 | tail -5`
Expected: builds (eBPF object compiles; verifier not yet exercised — that's Task 11).

- [ ] **Step 6: Commit**

```bash
git add flowplane/flowplane-ebpf/ flowplane/flowplane/src/
git commit -m "feat(ebpf): FW_RULES6/FW_META6/CONNTRACK6 maps + GlobalMaps accessors + AyaWriter"
```

---

## Task 8: wire the eBPF v6 datapath (`flowplane-ebpf`)

**Files:**
- Modify: `flowplane/flowplane-ebpf/src/v6.rs` (`v6_uplink_rx` @92 — two delivery branches)
- Modify: `flowplane/flowplane-ebpf/src/egress.rs` (`forward_decision_v6` @170)
- Test: build-only; the anchor (Task 11) is the verifier gate

- [ ] **Step 1: Egress — `forward_decision_v6`** (`egress.rs:170`)

Rename `_ifindex` → `ifindex`. After reading `dst` (@178), before the route lookup, add the stateful firewall+conntrack (mirror `forward_decision_v4` @60-84, using `RawPkt` and `ct_key6`/`CONNTRACK6`):

```rust
if let Some(key) = crate::conntrack::ct_key6(data, data_end, ETH_LEN, meta.vni) {
    match unsafe { crate::maps::CONNTRACK6.get(&key) } {
        Some(e) => {
            let mut e = *e;
            crate::conntrack::ct_touch6(data, data_end, ETH_LEN, &key, &mut e);
        }
        None => {
            if flowplane_core::firewall::fw_eval_dir6(
                &crate::coreimpl::RawPkt::new(data, data_end),
                &crate::coreimpl::GlobalMaps,
                ETH_LEN,
                ifindex,
                flowplane_common::FW_DIR_EGRESS,
            ) == flowplane_common::FW_ACTION_DROP
            {
                return EgressVerdict::Drop;
            }
            flowplane_core::conntrack::ct_create_default6(
                &crate::coreimpl::RawPkt::new(data, data_end),
                &mut crate::coreimpl::GlobalMaps,
                ETH_LEN,
                meta.vni,
                crate::conntrack::now(),
            );
        }
    }
}
```

- [ ] **Step 2: Ingress — `v6_uplink_rx` normal delivery** (`v6.rs`, the branch at @148 before `adjust_head` @149)

Insert, using the inner offset `ETH_LEN + IPV6_LEN` and `u.tap_ifindex` (mirror `ingress.rs:256-290`; `CtxPkt { ctx }` is the eBPF `Pkt` here):

```rust
if let Some(key) = crate::conntrack::ct_key6(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, vni) {
    match unsafe { crate::maps::CONNTRACK6.get(&key) } {
        Some(e) => {
            let mut e = *e;
            crate::conntrack::ct_touch6(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, &key, &mut e);
        }
        None => {
            if flowplane_core::firewall::fw_eval_dir6(
                &crate::coreimpl::CtxPkt { ctx },
                &crate::coreimpl::GlobalMaps,
                ETH_LEN + IPV6_LEN,
                u.tap_ifindex,
                flowplane_common::FW_DIR_INGRESS,
            ) == flowplane_common::FW_ACTION_DROP
            {
                return Ok(xdp_action::XDP_DROP);
            }
            flowplane_core::conntrack::ct_create_default6(
                &crate::coreimpl::CtxPkt { ctx },
                &mut crate::coreimpl::GlobalMaps,
                ETH_LEN + IPV6_LEN,
                vni,
                crate::conntrack::now(),
            );
        }
    }
}
```

- [ ] **Step 3: Ingress — `v6_uplink_rx` LB-local delivery** (`v6.rs`, the branch @111-132, before `adjust_head` @117) — **stateless** (no conntrack):

```rust
if flowplane_core::firewall::fw_eval_dir6(
    &crate::coreimpl::CtxPkt { ctx },
    &crate::coreimpl::GlobalMaps,
    ETH_LEN + IPV6_LEN,
    bu.tap_ifindex,
    flowplane_common::FW_DIR_INGRESS,
) == flowplane_common::FW_ACTION_DROP
{
    return Ok(xdp_action::XDP_DROP);
}
```

- [ ] **Step 4: Build**

Run: `cargo build -p flowplane 2>&1 | tail -5`
Expected: builds. (Do NOT claim verifier-clean yet — Task 11.)

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-ebpf/
git commit -m "feat(ebpf): wire v6 firewall+conntrack into v6_uplink_rx + forward_decision_v6"
```

---

## Task 9: DPDK backend parity (`nfkit`, `flowplane-dpdk`)

**Files:**
- Modify: `flowplane/nfkit/src/shared_config.rs` (add `FW_RULES6`/`FW_META6` tables + insert/remove, mirror the v4 fw tables)
- Modify: `flowplane/nfkit/src/dpdk_maps.rs` (@94 fields; add `fw_rules6`/`fw_meta6`/`conntrack6` `DpdkHash` + `Maps` impls + `add_*` methods)
- Modify: `flowplane/flowplane-dpdk/src/writer.rs` (@158 — add `fw_rules6_upsert/remove`, `fw_meta6_upsert`)
- Test: `flowplane/flowplane-dpdk/tests/` or an `nfkit` test — a fw_rule6 round-trip (may need EAL `--no-huge`; mark `#[ignore]` like the existing DPDK tests)

- [ ] **Step 1: Write failing round-trip test** (mirror any existing v4 fw writer/map test; if none, an `nfkit` `DpdkMaps` test)

```rust
// after EAL init (--no-huge), build DpdkMaps, add a FwRule6 via the writer/add method,
// then assert fw_rule6(&FwRuleKey{ifindex, idx}) reads it back and fw_meta6 shows the count.
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p flowplane-dpdk fw_rule6 --no-run 2>&1 | tail -5` (compile-first; the EAL test is `#[ignore]`)
Expected: FAIL to compile — methods missing.

- [ ] **Step 3: Implement** — mirror every v4 fw table/method for v6:
  - `SharedConfigMaps`: `fw_rules6_insert/remove`, `fw_meta6_insert` + the backing tables.
  - `DpdkMaps`: `fw_rules6`, `fw_meta6`, `conntrack6` `DpdkHash` fields (unique rte_hash names, e.g. `dm_fr6_{n}`, `dm_fm6_{n}`, `dm_ct6_{n}`); implement `fw_meta6`/`fw_rule6`/`conntrack6_get`/`conntrack6_insert` (`Maps` trait) + `add_fw_meta6`/`add_fw_rule6`.
  - `DpdkMapWriter`: `fw_rules6_upsert/remove`, `fw_meta6_upsert` (mirror @158-166).

- [ ] **Step 4: Build + compile the test**

Run: `cargo build -p flowplane-dpdk 2>&1 | tail -5` then `cargo test -p flowplane-dpdk fw_rule6 --no-run 2>&1 | tail -3`
Expected: builds + test compiles. (Run the `#[ignore]` EAL test under sudo if hugepages available; otherwise note it as unrun, same as the other DPDK EAL tests.)

- [ ] **Step 5: Commit**

```bash
git add flowplane/nfkit/ flowplane/flowplane-dpdk/
git commit -m "feat(dpdk): FW_RULES6/FW_META6/CONNTRACK6 parity in SharedConfigMaps + DpdkMaps + writer"
```

---

## Task 10: control-plane v6 default-allow (`netplane`)

**Files:**
- Modify: `netplane/controllers/compilednic.go` (@111-117)
- Test: `netplane/controllers/compilednic_test.go` (add a case; find the existing default-allow test with `grep -n "0.0.0.0/0" netplane/controllers/*_test.go`)

- [ ] **Step 1: Write failing test**

```go
func TestCompile_EmitsV6DefaultAllowWhenNoRules(t *testing.T) {
    // Compile a NIC/policy with NO firewall rules; assert compiled ingress AND egress
    // each contain BOTH {CIDR:"0.0.0.0/0",Action:"Allow"} and {CIDR:"::/0",Action:"Allow"}.
    // Then a second case: a NIC WITH one explicit rule in a direction gets NO default-allow there.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd netplane && go test ./controllers/ -run V6DefaultAllow 2>&1 | tail -8`
Expected: FAIL — only `0.0.0.0/0` present.

- [ ] **Step 3: Emit both families** (`compilednic.go:111-117`)

```go
allowAll4 := netv1.CompiledFwRule{CIDR: "0.0.0.0/0", Action: "Allow"}
allowAll6 := netv1.CompiledFwRule{CIDR: "::/0", Action: "Allow"}
if len(compiled.Spec.Firewall.Ingress) == 0 {
    compiled.Spec.Firewall.Ingress = append(compiled.Spec.Firewall.Ingress, allowAll4, allowAll6)
}
if len(compiled.Spec.Firewall.Egress) == 0 {
    compiled.Spec.Firewall.Egress = append(compiled.Spec.Firewall.Egress, allowAll4, allowAll6)
}
```

(Apply to whichever directions the existing code gates; keep the exact `len == 0` gate.)

- [ ] **Step 4: Run to verify pass**

Run: `cd netplane && go test ./controllers/ 2>&1 | tail -8`
Expected: PASS (new test + existing compiler tests).

- [ ] **Step 5: Commit**

```bash
git add netplane/controllers/
git commit -m "feat(netplane): emit ::/0 v6 default-allow alongside 0.0.0.0/0 when a direction is ruleless"
```

---

## Task 11: verifier anchor for the v6 datapath (privileged)

**Files:**
- Modify: the verifier/anchor harness (find with `grep -rn "sim-anchor\|verifier" Makefile` and the anchor test under `flowplane/flowplane/tests/`)
- Test: the privileged verifier load

- [ ] **Step 1: Identify the anchor target**

Run: `grep -n "verifier\|sim-anchor" Makefile` and read the referenced anchor test. Confirm how it loads the XDP/tc objects (it load-verifies the programs).

- [ ] **Step 2: Ensure the v6 programs are load-verified**

The anchor loads the real objects; `v6_uplink_rx` (XDP uplink) and the tc guest-egress program (`forward_decision_v6`) must be among them. If the existing anchor already loads the uplink XDP + guest tc programs, the new `fw_eval_dir6`/`ct_*6` code is exercised automatically. If not, extend it to load those programs.

- [ ] **Step 3: Run the verifier anchor (privileged)**

Run: `make sim-anchor 2>&1 | tail -20` (or the verifier target; needs sudo per the Makefile)
Expected: PASS — all programs load verifier-clean.

- [ ] **Step 4: If the verifier rejects on stack size**

Apply the `flow-label-ecmp` technique: keep `fw_eval_dir6`/`ct_key6` `#[inline(always)]`; if the combined frame still exceeds 512B, reduce stack-resident 16-byte copies (compare masked bytes without materializing full `[u8;16]` locals where avoidable), and re-run. Do NOT merge Task 8 to main until this is green.

- [ ] **Step 5: Commit** (only if the anchor harness changed)

```bash
git add flowplane/flowplane/tests/ Makefile
git commit -m "test(anchor): load-verify the v6 firewall+conntrack datapath"
```

---

## Task 12: final integration verification

**Files:** none (verification only)

- [ ] **Step 1: Full host suite**

Run: `make check 2>&1 | tail -5 && make sim 2>&1 | grep "test result" && make test 2>&1 | grep "test result"`
Expected: clippy/fmt clean; sim + host tests green (including the new v6 firewall + conntrack sim tests).

- [ ] **Step 2: Go suite**

Run: `cd netplane && go test ./... 2>&1 | tail -15`
Expected: green (including the v6 default-allow test).

- [ ] **Step 3: Confirm v4 unregressed**

Run: `cargo test -p flowplane-common -p flowplane-control -p flowplane-node 2>&1 | grep "test result"`
Expected: the pre-existing v4 firewall/layout tests still pass (byte layouts unchanged).

- [ ] **Step 4: No commit** — this task gates the branch-finish step.

---

## Self-review notes (addressed)

- **Spec coverage:** v6 conntrack (Task 3), `fw_eval_dir6` (Task 4), parallel maps + v4-untouched (Tasks 1/7/9), control programming (Task 5), family-aware parse/routing (Task 6), eBPF wiring stateful ingress/egress + stateless LB (Task 8), DPDK parity (Task 9), v6 default-allow gated on ruleless direction (Task 10), verifier anchor (Task 11), tests throughout.
- **Type consistency:** `FwRule6`/`CtKey6`/`FwCidr`/`PacketSelectors6`/`fw_rule6_matches`/`fw_eval_dir6`/`ct_key6`/`invert_key6`/`ct_create_default6`/`ct_touch6`/`fw_meta6`/`fw_rule6`/`conntrack6_get`/`conntrack6_insert`/`fw_rules6_upsert`/`fw_rules6_remove`/`fw_meta6_upsert`/`add_fw_rule6`/`del_fw_rule6`/`fw6_reprogram` used consistently across tasks.
- **Verifier risk** is isolated to Task 11 as an explicit gate before merge.
