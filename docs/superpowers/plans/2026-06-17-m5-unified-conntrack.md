# M5 — Unified Conntrack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two feature-private conntrack maps (`CONNTRACK<CtKey,CtVal>` for LB, `NAT_CT<CtKey,NatCtVal>` for NAT) with **one unified `CONNTRACK<CtKey,CtEntry>` table that every flow passes through**, carrying the translation, a TCP state machine, and a `last_seen` timestamp, plus a userspace GC that ages idle entries — the keystone dpservice `flow_value` parity that M6 (firewall) and later milestones build on.

**Architecture:** A single `conntrack` eBPF module owns the unified `CONNTRACK` map and a generic `ct_apply` that rewrites a packet's src **or** dst address (+ L4 port / ICMP id, with checksums) from a matched entry. `guest_tx` and `uplink_rx` both do a conntrack lookup up front: on a hit they apply the stored translation and refresh state/`last_seen`; on a miss the feature "create" paths (LB select, NAT allocate) insert entries, and otherwise a no-translation `DEFAULT` entry is inserted so *every* flow is tracked. A userspace task sweeps the map by `last_seen` (30 s default / 1-day established-TCP timeout, mirroring dpservice).

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/netns-e2e.sh`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§3 keystone; milestone M5).

**Starting point (M1–M4 complete):** map-driven datapath, 8 passing e2e tests. LB conntrack: `CONNTRACK<CtKey,CtVal{lb_ipv4}>` — `ingress::…lb::lb_select_dnat` inserts a reverse entry; `egress::…lb::ct_reverse_snat` applies it. NAT conntrack: `NAT_CT<CtKey,NatCtVal{ipv4,port}>` — `nat::nat_snat_egress` inserts forward+reverse and applies the forward; `nat::nat_dnat_ingress` applies the reverse. `CtKey{src_ip,dst_ip,src_port,dst_port,proto,_pad[3]}` (16B). `csum::csum_replace4` (RFC-1624). `parse::l4_ports` (ICMP → `(1,id,id)`). egress order: `lb::ct_reverse_snat` → `vip::snat_egress` → ROUTES → `nat::nat_snat_egress` → encap. ingress order: `lb::lb_select_dnat` → `nat::nat_dnat_ingress` → INTERFACES → write inner eth → `vip::dnat_ingress` (guarded) → redirect.

**Behavior-preservation contract:** after every task, `loader::tests::both_programs_pass_verifier` passes (root) and `./env/netns-e2e.sh run` still passes Tests 1–8. New behavior (state, aging, DEFAULT tracking) is additive.

## Design: the unified entry

```
CtEntry {
  last_seen: u64,     // bpf_ktime_get_ns at last touch (for GC)
  xlate_ip:  [u8;4],  // address to substitute on a matching packet
  xlate_port:u16,     // L4 port / ICMP id to substitute (0 = leave L4 port unchanged)
  flags:     u8,      // CT_REWRITE_SRC|CT_REWRITE_DST | feature bits
  tcp_state: u8,      // TCP_* enum
  fwall_action:u8,    // 0 unset / 1 accept / 2 drop  (consumed by M6; written 0 here)
  _pad:[u8;7],
}                     // 24 bytes
```
An entry is keyed by the 5-tuple of the packet that will be *seen*, and says "rewrite SRC (or DST) to `xlate_ip` (and the L4 port to `xlate_port` if non-zero)". Mapping of the existing features:
- **LB reverse** (seen on egress, backend→client): key `(backend,client,dport,sport,proto)`, `xlate_ip=lb_ip`, `xlate_port=0`, flags `CT_REWRITE_SRC|CT_F_DST_LB`.
- **NAT forward** (seen on egress, guest→ext): key `(guest,ext,sport,dport,proto)`, `xlate_ip=nat_ip`, `xlate_port=nat_port`, flags `CT_REWRITE_SRC|CT_F_SRC_NAT`.
- **NAT reverse** (seen on ingress, ext→nat_ip): key `(ext,nat_ip,ext_l4,nat_port,proto)`, `xlate_ip=guest_ip`, `xlate_port=guest_l4`, flags `CT_REWRITE_DST|CT_F_SRC_NAT`.
- **DEFAULT** (any other flow, both directions): no `CT_REWRITE_*`, flags `CT_F_DEFAULT`.

## Scaling & BPF map sizing (cloud-cornerstone concern)

dpservice runs on every compute node of a cloud platform, so map capacity is a real constraint, not
a footnote. Key facts and decisions:

- **`max_entries` is a u32** (no practical hard cap); the real limit is **memory**. On kernels ≥ 5.11
  (this env is 7.0) BPF map memory is **memcg-accounted**, so there is no `RLIMIT_MEMLOCK` ceiling —
  it counts against the cgroup like any allocation.
- **`LRU_HASH` always preallocates** all `max_entries` at load. `1_048_576` entries × (`CtKey` 16 B +
  `CtEntry` 24 B + ~per-entry overhead) ≈ **80–100 MB** reserved up front. That is the right order of
  magnitude for a hypervisor and matches dpservice's `DP_FLOW_TABLE_MAX = 850000`.
- **LRU eviction means we never fail an insert** when full — but an undersized table evicts *active*
  flows early and breaks connections, so sizing for the node's concurrent-flow ceiling matters.
- **Configurability:** aya can override a map's `max_entries` at load time
  (`ebpf.map_mut("CONNTRACK")` → set before the program loads, or via a `--conntrack-max` flag).
  This plan hardcodes `1_048_576`; making it a loader flag is a small follow-on (noted in Task 6) so
  operators tune per node role (edge gateway vs. dense compute).
- **Other maps are out of M5 scope but flagged:** `ROUTES` (4096) and `INTERFACES` (1024) will need
  to grow for large VPCs — `ROUTES` especially (LPM trie + higher cap lands in **M8**), `INTERFACES`
  cap should rise with planned VM density. `MAGLEV` (65536 = ~64 tables) grows with LB count. These
  are tracked for M7/M8, not changed here.

## File Structure

```
flowplane-common/src/lib.rs    # + CtEntry + CT_* consts; remove CtVal/NatCtVal at the end (Task 3)
flowplane-ebpf/src/
  conntrack.rs              # NEW: unified map helpers (ct_lookup/ct_apply/ct_touch/tcp_advance/now/ct_key)
  maps.rs                   # CONNTRACK value -> CtEntry; remove NAT_CT (Task 3)
  lb.rs                     # ingress insert unified entry; remove ct_reverse_snat (Task 2)
  nat.rs                    # use unified entry; remove nat_dnat_ingress/NAT_CT (Task 3)
  egress.rs                 # generic ct apply-or-create on egress
  ingress.rs                # generic ct apply-or-create on ingress
  parse.rs                  # + tcp_flags() reader (Task 4)
  main.rs                   # + mod conntrack;
flowplane/src/
  maps.rs                   # Conntrack wrapper: value CtEntry + iter()/remove() (Task 6)
  conntrack_gc.rs           # NEW: userspace aging task (Task 6)
  main.rs / control.rs      # spawn GC in bringup + serve (Task 6)
env/netns-e2e.sh            # + conntrack/aging assertions (Task 7)
```

---

## Task 1: Unified `CtEntry` type + flag/TCP-state constants

**Files:** Modify `flowplane-common/src/lib.rs`

- [ ] **Step 1: Add the type + consts**

Add near the M3/M4 conntrack types:
```rust
/// Unified conntrack entry value. Keyed by the 5-tuple (`CtKey`) of the packet that will be SEEN;
/// `ct_apply` rewrites that packet's src or dst address (+L4 port) to `xlate_ip`/`xlate_port`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct CtEntry {
    pub last_seen: u64,
    pub xlate_ip: [u8; 4],
    pub xlate_port: u16,
    pub flags: u8,
    pub tcp_state: u8,
    pub fwall_action: u8,
    pub _pad: [u8; 7],
}

// CtEntry.flags bits
pub const CT_REWRITE_SRC: u8 = 0x01;
pub const CT_REWRITE_DST: u8 = 0x02;
pub const CT_F_SRC_NAT: u8 = 0x04;
pub const CT_F_DST_LB: u8 = 0x08;
pub const CT_F_DEFAULT: u8 = 0x10;
pub const CT_F_FIREWALL: u8 = 0x20;

// CtEntry.tcp_state values (mirror dpservice dp_flow_tcp_state)
pub const TCP_NONE: u8 = 0;
pub const TCP_NEW_SYN: u8 = 1;
pub const TCP_NEW_SYNACK: u8 = 2;
pub const TCP_ESTABLISHED: u8 = 3;
pub const TCP_FINWAIT: u8 = 4;
pub const TCP_RST_FIN: u8 = 5;
```
Add `unsafe impl aya::Pod for CtEntry {}` in the `user_impls` block.

- [ ] **Step 2: Layout test**

In the layout-test module add:
```rust
        assert_eq!(core::mem::size_of::<CtEntry>(), 24);
```
Run `cargo test -p flowplane-common --features user` → PASS.

- [ ] **Step 3: Build + commit**
```bash
cargo build -p flowplane
cargo fmt --all
git add flowplane-common
git commit -m "feat(ct): unified CtEntry conntrack value + flag/TCP-state consts"
```

## Task 2: `conntrack.rs` module + migrate LB onto the unified table

**Files:** Create `flowplane-ebpf/src/conntrack.rs`; Modify `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/main.rs`, `flowplane-ebpf/src/lb.rs`, `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/ingress.rs`

This task changes the `CONNTRACK` map value to `CtEntry`, adds the generic helpers, and moves LB onto them (NAT stays on `NAT_CT` until Task 3). Behavior-preserving.

- [ ] **Step 1: Change the `CONNTRACK` map value type**

In `flowplane-ebpf/src/maps.rs`: add `CtEntry` to the `flowplane_common` import and change the value type
**and size** (the old `65536` was a PoC value; size to dpservice's table — see "Scaling & BPF map
sizing" below):
```rust
/// Unified conntrack. Sized to dpservice's DP_FLOW_TABLE_MAX (850k); LRU_HASH preallocates, so
/// this reserves ~80-100 MB at load (memcg-accounted on kernels >= 5.11). Operators tune via the
/// loader (Task 6 note); 850k covers a densely-packed cloud hypervisor's concurrent flows.
pub static CONNTRACK: LruHashMap<CtKey, CtEntry> = LruHashMap::with_max_entries(1_048_576, 0);
```
(Leave `NAT_CT` and `CtVal`/`NatCtVal` imports for now — NAT still uses them this task.)

- [ ] **Step 2: Create `flowplane-ebpf/src/conntrack.rs`**

```rust
use aya_ebpf::{helpers::bpf_ktime_get_ns, programs::XdpContext};
use flowplane_common::{CtEntry, CtKey, CT_REWRITE_SRC};

use crate::csum::csum_replace4;
use crate::parse::l4_ports;

/// Fold a 16-bit field change (network-order) into an L4/ICMP checksum via csum_replace4.
#[inline(always)]
pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let o = old.to_be_bytes();
    let n = new.to_be_bytes();
    csum_replace4(check, &[o[0], o[1], 0, 0], &[n[0], n[1], 0, 0])
}

/// Current kernel monotonic time (ns).
#[inline(always)]
pub fn now() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Build the 5-tuple key for the packet at `ip_off` (host-order ports; ICMP id in both ports).
#[inline(always)]
pub fn ct_key(data: usize, data_end: usize, ip_off: usize) -> Option<CtKey> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
    Some(CtKey {
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    })
}

/// Apply a conntrack entry's translation to the packet at `ip_off`: rewrite the src (if
/// CT_REWRITE_SRC) or dst (if CT_REWRITE_DST) address to `xlate_ip`, and the corresponding L4
/// port / ICMP id to `xlate_port` when non-zero, fixing IP + L4/ICMP checksums. No-op for entries
/// without a rewrite flag (DEFAULT).
#[inline(always)]
pub fn ct_apply(ctx: &XdpContext, ip_off: usize, e: &CtEntry) {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ip_off + 20 > data_end {
        return;
    }
    let rewrite_src = e.flags & CT_REWRITE_SRC != 0;
    let addr_off = ip_off + if rewrite_src { 12 } else { 16 };
    let p = data as *mut u8;
    let old = unsafe { core::ptr::read_unaligned(p.add(addr_off) as *const [u8; 4]) };
    let new = e.xlate_ip;
    let proto = unsafe { *p.add(ip_off + 9) };
    let ihl = (unsafe { *p.add(ip_off) } & 0x0f) as usize * 4;
    unsafe {
        core::ptr::write_unaligned(p.add(addr_off) as *mut [u8; 4], new);
        let ipc = u16::from_be(core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16));
        core::ptr::write_unaligned(
            p.add(ip_off + 10) as *mut u16,
            csum_replace4(ipc, &old, &new).to_be(),
        );
        let l4 = ip_off + ihl;
        // TCP: csum at l4+16, src port l4+0, dst port l4+2
        if proto == 6 && data + l4 + 18 <= data_end {
            let c1 = csum_replace4(
                u16::from_be(core::ptr::read_unaligned(p.add(l4 + 16) as *const u16)),
                &old,
                &new,
            );
            if e.xlate_port != 0 {
                let poff = if rewrite_src { l4 } else { l4 + 2 };
                let oldp = u16::from_be(core::ptr::read_unaligned(p.add(poff) as *const u16));
                let c2 = csum_replace2(c1, oldp, e.xlate_port);
                core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, c2.to_be());
                core::ptr::write_unaligned(p.add(poff) as *mut u16, e.xlate_port.to_be());
            } else {
                core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, c1.to_be());
            }
        } else if proto == 17 && data + l4 + 8 <= data_end {
            let c0 = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 6) as *const u16));
            if c0 != 0 {
                let c1 = csum_replace4(c0, &old, &new);
                if e.xlate_port != 0 {
                    let poff = if rewrite_src { l4 } else { l4 + 2 };
                    let oldp = u16::from_be(core::ptr::read_unaligned(p.add(poff) as *const u16));
                    core::ptr::write_unaligned(
                        p.add(l4 + 6) as *mut u16,
                        csum_replace2(c1, oldp, e.xlate_port).to_be(),
                    );
                } else {
                    core::ptr::write_unaligned(p.add(l4 + 6) as *mut u16, c1.to_be());
                }
            }
            if e.xlate_port != 0 {
                let poff = if rewrite_src { l4 } else { l4 + 2 };
                core::ptr::write_unaligned(p.add(poff) as *mut u16, e.xlate_port.to_be());
            }
        } else if proto == 1 && data + l4 + 8 <= data_end && e.xlate_port != 0 {
            // ICMP: address change does not affect the checksum; the id (l4+4) does.
            let oldid = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 4) as *const u16));
            let c0 = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 2) as *const u16));
            core::ptr::write_unaligned(
                p.add(l4 + 2) as *mut u16,
                csum_replace2(c0, oldid, e.xlate_port).to_be(),
            );
            core::ptr::write_unaligned(p.add(l4 + 4) as *mut u16, e.xlate_port.to_be());
        }
    }
}
```
Add `mod conntrack;` to `flowplane-ebpf/src/main.rs` (alphabetical: after `mod arp_nd;`, before `mod csum;`).

- [ ] **Step 3: Move LB onto the unified entry**

In `flowplane-ebpf/src/lb.rs`: the reverse-conntrack insert in `lb_select_dnat` currently builds a `CtKey` and inserts a `CtVal{lb_ipv4}`. Replace that insert with a unified `CtEntry`:
```rust
    // reverse conntrack: backend->client expected on the return; restore lb (= dst) on egress.
    let key = CtKey {
        src_ip: backend,
        dst_ip: src,
        src_port: dport,
        dst_port: sport,
        proto,
        _pad: [0; 3],
    };
    let _ = CONNTRACK.insert(
        &key,
        &flowplane_common::CtEntry {
            last_seen: crate::conntrack::now(),
            xlate_ip: dst,
            xlate_port: 0,
            flags: flowplane_common::CT_REWRITE_SRC | flowplane_common::CT_F_DST_LB,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
        0,
    );
    Some(backend)
```
Update `lb.rs` imports: remove `CtVal`, keep `CtKey`; the `CONNTRACK` import stays. Then **delete `ct_reverse_snat`** entirely from `lb.rs` (the generic egress apply replaces it).

- [ ] **Step 4: Generic conntrack apply on egress (replaces `lb::ct_reverse_snat`)**

In `flowplane-ebpf/src/egress.rs`, replace the line `crate::lb::ct_reverse_snat(ctx, ETH_LEN);` with a generic lookup-and-apply:
```rust
    // Conntrack: apply any established translation (LB reverse, later NAT/DEFAULT) before SNAT/route.
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN) {
        if let Some(e) = unsafe { crate::maps::CONNTRACK.get(&key) } {
            let e = *e;
            crate::conntrack::ct_apply(ctx, ETH_LEN, &e);
        }
    }
```
(`data`/`data_end` are already in scope at that point in `try_guest_tx`; if not, fetch them with `let data = ctx.data(); let data_end = ctx.data_end();` just above.)

- [ ] **Step 5: Build + verifier gate + e2e**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
./env/netns-e2e.sh run 2>&1 | tail -20   # Tests 1-8 still pass (esp. Test 7 LB return)
```

- [ ] **Step 6: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(ct): unified conntrack map + generic ct_apply; migrate LB onto it"
```

## Task 3: Migrate NAT onto the unified conntrack; remove `NAT_CT`/`CtVal`/`NatCtVal`

**Files:** Modify `flowplane-ebpf/src/nat.rs`, `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/ingress.rs`, `flowplane-common/src/lib.rs`

- [ ] **Step 1: NAT egress uses the unified table**

In `flowplane-ebpf/src/nat.rs` `nat_snat_egress`: replace the forward-port reuse lookup and the two `NAT_CT.insert` calls with unified `CONNTRACK` operations. The forward lookup reuses an existing `CT_F_SRC_NAT` forward entry's `xlate_port`:
```rust
    use flowplane_common::{CtEntry, CT_F_SRC_NAT, CT_REWRITE_DST, CT_REWRITE_SRC};
    // Forward conntrack: reuse the allocated port for an already-tracked flow.
    let fwd_key = CtKey { src_ip: src, dst_ip: dst, src_port: sport, dst_port: dport, proto, _pad: [0; 3] };
    let nat_port = match unsafe { crate::maps::CONNTRACK.get(&fwd_key) } {
        Some(v) if v.flags & CT_F_SRC_NAT != 0 => v.xlate_port,
        _ => {
            let start = (hash5(&src, &dst, sport, dport, proto) % range as u32) as u16;
            let mut chosen = nat.port_min.wrapping_add(start);
            let mut i: u16 = 0;
            while i < PROBE_LIMIT {
                let cand = nat.port_min.wrapping_add((start.wrapping_add(i)) % range);
                let rev_src_port = if proto == IPPROTO_ICMP { cand } else { dport };
                let rev_key = CtKey { src_ip: dst, dst_ip: nat.nat_ipv4, src_port: rev_src_port, dst_port: cand, proto, _pad: [0; 3] };
                if unsafe { crate::maps::CONNTRACK.get(&rev_key) }.is_none() {
                    chosen = cand;
                    let _ = crate::maps::CONNTRACK.insert(&rev_key, &CtEntry {
                        last_seen: crate::conntrack::now(),
                        xlate_ip: src, xlate_port: sport,
                        flags: CT_REWRITE_DST | CT_F_SRC_NAT, tcp_state: 0, fwall_action: 0, _pad: [0; 7],
                    }, 0);
                    break;
                }
                i += 1;
            }
            let _ = crate::maps::CONNTRACK.insert(&fwd_key, &CtEntry {
                last_seen: crate::conntrack::now(),
                xlate_ip: nat.nat_ipv4, xlate_port: chosen,
                flags: CT_REWRITE_SRC | CT_F_SRC_NAT, tcp_state: 0, fwall_action: 0, _pad: [0; 7],
            }, 0);
            chosen
        }
    };
```
Leave the rest of `nat_snat_egress` (the actual src/port rewrite + checksums) unchanged — it still applies the rewrite inline. Remove the `use ... NatCtVal` and `use crate::maps::{NAT, NAT_CT}` → keep `NAT`, drop `NAT_CT`; add `use crate::maps::CONNTRACK;` (or fully-qualify as above).

- [ ] **Step 2: NAT ingress reverse becomes the generic apply**

In `flowplane-ebpf/src/ingress.rs`, the NAT reverse currently calls `crate::nat::nat_dnat_ingress(ctx, ETH_LEN + IPV6_LEN)` returning `Option<[u8;4]>` used for `deliver_ip`. Replace it with a generic conntrack lookup that both yields the delivery IP and applies the rewrite:
```rust
    let lb_backend = crate::lb::lb_select_dnat(ctx, ETH_LEN + IPV6_LEN, 0);
    let nat_guest = if lb_backend.is_none() {
        // Generic conntrack reverse: a NAT reverse entry rewrites dst nat_ip->guest and yields it.
        let d = ctx.data();
        let de = ctx.data_end();
        match crate::conntrack::ct_key(d, de, ETH_LEN + IPV6_LEN) {
            Some(key) => match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) if e.flags & flowplane_common::CT_REWRITE_DST != 0 => {
                    let e = *e;
                    crate::conntrack::ct_apply(ctx, ETH_LEN + IPV6_LEN, &e);
                    Some(e.xlate_ip)
                }
                _ => None,
            },
            None => None,
        }
    } else {
        None
    };
    let deliver_ip = lb_backend.or(nat_guest).unwrap_or(target);
```
Then **delete `nat_dnat_ingress`** from `nat.rs` (and its now-unused `csum_replace2` if it is duplicated — keep the one in `conntrack.rs`; `nat.rs` may `use crate::conntrack::csum_replace2;` for `nat_snat_egress`).

- [ ] **Step 3: Remove the dead map + types**

In `flowplane-ebpf/src/maps.rs`: delete the `NAT_CT` map and drop `NatCtVal`/`CtVal` from the import. In `flowplane-common/src/lib.rs`: delete `CtVal` and `NatCtVal` structs, their `Pod` impls, and their `size_of` assertions (their roles are now in `CtEntry`). In `flowplane/src/maps.rs`: delete the `NatCt` wrapper and the `Conntrack` wrapper's `CtVal` usage (the `Conntrack` wrapper is rebuilt in Task 6; for now make it open `CONNTRACK` as `HashMap<MapData, CtKey, CtEntry>` or delete it if unused — grep for `NatCt`/`Conntrack` references first and remove dead ones).

- [ ] **Step 4: Build + verifier + e2e**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
./env/netns-e2e.sh run 2>&1 | tail -20   # Tests 1-8 pass (esp. Test 8 NAT return)
```

- [ ] **Step 5: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf flowplane-common flowplane
git commit -m "feat(ct): migrate NAT onto unified conntrack; drop NAT_CT/CtVal/NatCtVal"
```

## Task 4: TCP state machine + `last_seen` refresh on every touch

**Files:** Modify `flowplane-ebpf/src/parse.rs`, `flowplane-ebpf/src/conntrack.rs`, `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/ingress.rs`

- [ ] **Step 1: TCP flags reader in `parse.rs`**
```rust
/// Read the TCP flags byte for an IPv4 packet at `ip_off`, or None if not TCP / out of bounds.
#[inline(always)]
pub fn tcp_flags(data: usize, data_end: usize, ip_off: usize) -> Option<u8> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    if unsafe { *p.add(ip_off + 9) } != IPPROTO_TCP {
        return None;
    }
    let ihl = (unsafe { *p.add(ip_off) } & 0x0f) as usize * 4;
    let l4 = ip_off + ihl;
    if data + l4 + 14 > data_end {
        return None;
    }
    Some(unsafe { *p.add(l4 + 13) }) // TCP flags byte (offset 13 in the TCP header)
}
```

- [ ] **Step 2: `tcp_advance` + `ct_touch` in `conntrack.rs`**
```rust
use flowplane_common::{TCP_ESTABLISHED, TCP_FINWAIT, TCP_NEW_SYN, TCP_NEW_SYNACK, TCP_RST_FIN};

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Advance the TCP state for a flow given a packet's TCP flags (functional parity with dpservice's
/// NONE->NEW_SYN->NEW_SYNACK->ESTABLISHED->FINWAIT->RST_FIN progression).
#[inline(always)]
pub fn tcp_advance(state: u8, flags: u8) -> u8 {
    if flags & TCP_RST != 0 {
        return TCP_RST_FIN;
    }
    if flags & TCP_FIN != 0 {
        return TCP_FINWAIT;
    }
    if flags & TCP_SYN != 0 {
        if flags & TCP_ACK != 0 {
            return TCP_NEW_SYNACK;
        }
        return TCP_NEW_SYN;
    }
    if flags & TCP_ACK != 0 && (state == TCP_NEW_SYNACK || state == TCP_NEW_SYN || state == TCP_ESTABLISHED) {
        return TCP_ESTABLISHED;
    }
    state
}

/// Refresh last_seen (and TCP state for TCP) on a matched entry, writing it back.
#[inline(always)]
pub fn ct_touch(ctx: &XdpContext, ip_off: usize, key: &CtKey, e: &mut CtEntry) {
    e.last_seen = now();
    if let Some(fl) = crate::parse::tcp_flags(ctx.data(), ctx.data_end(), ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    let _ = crate::maps::CONNTRACK.insert(key, e, 0);
}
```
(Imports: add `CtKey` to the `conntrack.rs` `use flowplane_common::{...}` line.)

- [ ] **Step 3: Touch on every hit (egress + ingress)**

In `egress.rs`'s generic apply block, after `ct_apply`, refresh:
```rust
        if let Some(e) = unsafe { crate::maps::CONNTRACK.get(&key) } {
            let mut e = *e;
            crate::conntrack::ct_apply(ctx, ETH_LEN, &e);
            crate::conntrack::ct_touch(ctx, ETH_LEN, &key, &mut e);
        }
```
In `ingress.rs`'s generic reverse block, after `ct_apply(ctx, ETH_LEN + IPV6_LEN, &e)`, add `crate::conntrack::ct_touch(ctx, ETH_LEN + IPV6_LEN, &key, &mut e_copy);` (make the bound `e` mutable: `let mut e = *e;`).

- [ ] **Step 4: Build + verifier + e2e + commit**
```bash
cargo build -p flowplane
# verifier gate (as in Task 2 Step 5) -> 1 passed
./env/netns-e2e.sh run 2>&1 | tail -8   # Tests 1-8 pass
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(ct): TCP state machine + last_seen refresh on conntrack hits"
```

## Task 5: DEFAULT-flow tracking (every flow gets an entry)

**Files:** Modify `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/ingress.rs`, `flowplane-ebpf/src/conntrack.rs`

- [ ] **Step 0 (CRITICAL): guard `ct_apply` so DEFAULT entries are a no-op**

`ct_apply` currently *always* rewrites (src if `CT_REWRITE_SRC`, else dst). A DEFAULT entry has neither flag and `xlate_ip = 0.0.0.0`, so applying it would corrupt the dst to `0.0.0.0`. Add an early return at the top of `ct_apply` (in `conntrack.rs`):
```rust
    // DEFAULT (and any flag-less) entries carry no translation — never rewrite.
    if e.flags & (flowplane_common::CT_REWRITE_SRC | flowplane_common::CT_REWRITE_DST) == 0 {
        return;
    }
```
Place it as the first statement of `ct_apply`, before the bounds check. (Add `CT_REWRITE_DST` to the `conntrack.rs` import if not already present.) Without this, the moment Step 2 starts inserting DEFAULT entries the egress apply block will null inbound destinations — so this step comes first.

- [ ] **Step 1: `ct_ensure_default` helper in `conntrack.rs`**
```rust
use flowplane_common::CT_F_DEFAULT;

/// Insert a no-translation DEFAULT conntrack entry for a flow on conntrack-miss, so every flow is
/// tracked (firewall + aging see it). Records last_seen + initial TCP state.
#[inline(always)]
pub fn ct_ensure_default(ctx: &XdpContext, ip_off: usize, key: &CtKey) {
    let tcp = crate::parse::tcp_flags(ctx.data(), ctx.data_end(), ip_off)
        .map(|fl| tcp_advance(0, fl))
        .unwrap_or(0);
    let e = CtEntry {
        last_seen: now(),
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: CT_F_DEFAULT,
        tcp_state: tcp,
        fwall_action: 0,
        _pad: [0; 7],
    };
    let _ = crate::maps::CONNTRACK.insert(key, &e, 0);
}
```

- [ ] **Step 2: Insert DEFAULT on egress miss**

In `egress.rs`, restructure the egress conntrack block so a miss (after VIP/NAT create paths have run, i.e. at the end, before encap) ensures a DEFAULT entry. Simplest: after the route lookup + `nat_snat_egress`, add:
```rust
    // Track every flow: if no conntrack entry exists for this (post-NAT) 5-tuple, insert DEFAULT.
    if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN) {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none() {
            crate::conntrack::ct_ensure_default(ctx, ETH_LEN, &key);
        }
    }
```
(Placed after `nat_snat_egress` so a NAT'd flow's forward entry already exists and we don't double-insert.)

- [ ] **Step 3: Insert DEFAULT on ingress miss**

In `ingress.rs`, after `deliver_ip` is resolved but before `adjust_head`, **touch** an existing inbound DEFAULT entry (refresh `last_seen`/TCP state so inbound-only flows don't age out) or **ensure** one on miss, for non-LB/non-NAT inbound flows:
```rust
    if lb_backend.is_none() && nat_guest.is_none() {
        if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN) {
            match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) => {
                    let mut e = *e;
                    crate::conntrack::ct_touch(ctx, ETH_LEN + IPV6_LEN, &key, &mut e);
                }
                None => crate::conntrack::ct_ensure_default(ctx, ETH_LEN + IPV6_LEN, &key),
            }
        }
    }
```
(`ct_apply` is intentionally NOT called here — DEFAULT entries carry no translation, and any `CT_REWRITE_DST` entry was already handled by the `nat_guest` block above.)

- [ ] **Step 4: Build + verifier + e2e + commit**
```bash
cargo build -p flowplane
# verifier gate -> 1 passed ; iterate if the added map ops trip bounds checks
./env/netns-e2e.sh run 2>&1 | tail -8   # Tests 1-8 pass
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(ct): DEFAULT-flow tracking (every flow gets a conntrack entry)"
```

## Task 6: Userspace conntrack GC (aging)

**Files:** Modify `flowplane/src/maps.rs`; Create `flowplane/src/conntrack_gc.rs`; Modify `flowplane/src/main.rs`, `flowplane/src/control.rs`

- [ ] **Step 1: `Conntrack` wrapper with iterate + remove**

In `flowplane/src/maps.rs`, ensure a `Conntrack` handle over `HashMap<MapData, CtKey, CtEntry>` exists with:
```rust
#[allow(dead_code)]
pub struct Conntrack {
    map: HashMap<MapData, CtKey, CtEntry>,
}

#[allow(dead_code)]
impl Conntrack {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("CONNTRACK").context("CONNTRACK map missing")?)?;
        Ok(Self { map })
    }
    /// Collect all (key, entry) pairs (snapshot for the GC sweep).
    pub fn entries(&self) -> Vec<(CtKey, CtEntry)> {
        self.map.iter().filter_map(|r| r.ok()).collect()
    }
    pub fn remove(&mut self, key: &CtKey) -> anyhow::Result<()> {
        self.map.remove(key).context("remove conntrack")
    }
}
```
(Add `CtEntry` to the `flowplane_common` import. `HashMap::iter` yields `Result<(K,V),_>`.)

- [ ] **Step 2: GC task in `flowplane/src/conntrack_gc.rs`**
```rust
//! Userspace conntrack aging: periodically evict entries idle longer than their timeout. Mirrors
//! dpservice (30 s default, 1-day established-TCP). Times are kernel-monotonic ns (bpf_ktime).
use std::time::Duration;

use flowplane_common::{CtEntry, TCP_ESTABLISHED};

use crate::maps::Conntrack;

const DEFAULT_TIMEOUT_NS: u64 = 30 * 1_000_000_000;
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

fn timeout_ns(e: &CtEntry) -> u64 {
    if e.tcp_state == TCP_ESTABLISHED {
        TCP_ESTABLISHED_TIMEOUT_NS
    } else {
        DEFAULT_TIMEOUT_NS
    }
}

/// Read the current kernel-monotonic time (ns) the same clock the datapath stamps with.
fn ktime_now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // CLOCK_MONOTONIC matches bpf_ktime_get_ns on Linux.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// Sweep loop: every `interval`, remove entries whose idle age exceeds their timeout.
pub async fn run(mut ct: Conntrack, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let now = ktime_now_ns();
        let stale: Vec<_> = ct
            .entries()
            .into_iter()
            .filter(|(_, e)| now.saturating_sub(e.last_seen) > timeout_ns(e))
            .map(|(k, _)| k)
            .collect();
        for k in stale {
            let _ = ct.remove(&k);
        }
    }
}
```
Add `libc = "0.2"` to `flowplane/Cargo.toml` `[dependencies]` if not present (check first). Add `mod conntrack_gc;` to `flowplane/src/main.rs`.

- [ ] **Step 3: Spawn the GC in `bringup` and `serve`**

In `flowplane/src/main.rs` `Cmd::Bringup`, after the maps are programmed and before `tokio::signal::ctrl_c().await?`, open a `Conntrack` and spawn the sweeper:
```rust
            let ct = maps::Conntrack::open(&mut ebpf)?;
            tokio::spawn(conntrack_gc::run(ct, std::time::Duration::from_secs(10)));
```
In `serve`, `Control::bring_up` should likewise open a `Conntrack` and the `serve` arm should `tokio::spawn(conntrack_gc::run(ct, Duration::from_secs(10)))`. If `Control` already consumes the ebpf object, add a `Control::take_conntrack(&self) -> Option<Conntrack>` that opens it during `bring_up` and hands it out once; simplest is to open it in `bring_up`, store `Option<Conntrack>` in `Inner`, and add `pub fn take_conntrack(&self) -> Option<Conntrack>` that `.take()`s it for the `serve` arm to spawn. Implement whichever keeps `cargo build` clean.

> **Sizing follow-on (not required for M5):** the `CONNTRACK` `max_entries` is hardcoded to
> `1_048_576`. A small follow-on adds a `--conntrack-max <n>` loader flag that overrides it via
> `ebpf.map_mut("CONNTRACK")` before the programs load, so operators size per node role. See
> "Scaling & BPF map sizing".

- [ ] **Step 4: Build + e2e + commit**
```bash
cargo build -p flowplane
./env/netns-e2e.sh run 2>&1 | tail -8   # Tests 1-8 pass (GC running, 10s interval, won't evict mid-test)
cargo fmt --all
git add flowplane
git commit -m "feat(ct): userspace conntrack GC (idle aging, 30s/1-day timeouts)"
```

## Task 7: Acceptance — unit tests + lab conntrack assertions

**Files:** Modify `flowplane/src/conntrack_gc.rs` (unit tests), `env/netns-e2e.sh`

- [ ] **Step 1: Host unit tests for aging eligibility + TCP timeout selection**

Add to `flowplane/src/conntrack_gc.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_common::{CtEntry, TCP_ESTABLISHED, TCP_NONE};

    fn entry(tcp_state: u8, last_seen: u64) -> CtEntry {
        CtEntry { last_seen, tcp_state, ..Default::default() }
    }

    #[test]
    fn established_tcp_gets_long_timeout() {
        assert_eq!(timeout_ns(&entry(TCP_ESTABLISHED, 0)), TCP_ESTABLISHED_TIMEOUT_NS);
        assert_eq!(timeout_ns(&entry(TCP_NONE, 0)), DEFAULT_TIMEOUT_NS);
    }

    #[test]
    fn idle_beyond_timeout_is_stale() {
        let now = 60 * 1_000_000_000u64; // 60s
        let fresh = entry(TCP_NONE, now - 5 * 1_000_000_000);  // 5s idle -> keep
        let old = entry(TCP_NONE, now - 40 * 1_000_000_000);   // 40s idle -> evict (>30s)
        assert!(now.saturating_sub(fresh.last_seen) <= timeout_ns(&fresh));
        assert!(now.saturating_sub(old.last_seen) > timeout_ns(&old));
    }
}
```
Run `cargo test -p flowplane conntrack_gc::` → PASS.

- [ ] **Step 2: Lab assertion that flows are tracked**

In `env/netns-e2e.sh` `cmd_test`, after Test 8, add a Test 9 that proves the unified conntrack tracks a plain (DEFAULT) overlay flow and an NAT flow. Since the maps aren't exposed via CLI, assert indirectly: run a sustained ping and confirm connectivity remains stable (entries created + refreshed, not mis-aged) and the NAT/LB returns still work under the GC:
```bash
    echo "=== Test 9: unified conntrack under GC — sustained flows stay healthy ==="
    # 12 pings (> the 10s GC interval) over a DEFAULT overlay flow and a NAT flow; both must stay 0% loss,
    # proving conntrack entries are created, refreshed (last_seen), and not mis-evicted mid-flow.
    LOSS_DEF=0; LOSS_NAT=0
    for _ in $(seq 1 12); do
        sudo ip netns exec guesta ping -c 1 -W 2 10.0.0.6 >/dev/null 2>&1 || LOSS_DEF=$((LOSS_DEF+1))
        sudo ip netns exec guesta ping -c 1 -W 2 10.0.0.8 >/dev/null 2>&1 || LOSS_NAT=$((LOSS_NAT+1))
        sleep 1
    done
    echo "  DEFAULT flow (guesta->guestb) lost=$LOSS_DEF/12 ; NAT flow (guesta->extsrv) lost=$LOSS_NAT/12"
    if [ "$LOSS_DEF" -eq 0 ] && [ "$LOSS_NAT" -eq 0 ]; then
        echo "  conntrack OK: flows tracked + refreshed across the GC interval"
    else
        echo "  WARNING: flow loss under conntrack/GC"
    fi
    echo ""
```

- [ ] **Step 3: Run + commit**
```bash
cargo test -p flowplane 2>&1 | tail -5
./env/netns-e2e.sh run 2>&1 | tail -30   # Tests 1-9 pass, clean teardown
cargo fmt --all
git add flowplane env/netns-e2e.sh
git commit -m "test(ct): conntrack aging unit tests + sustained-flow lab gate (Test 9)"
```

## Task 8: Configurable BPF map sizes (env vars + flag override)

**Files:** Modify `flowplane/src/loader.rs`, `flowplane/src/main.rs`

Operators must be able to size the hot maps per node role without recompiling. Make `load_ebpf`
apply `EbpfLoader::set_max_entries` overrides read from env vars (uniform across every subcommand
that loads the datapath), with the compile-time `with_max_entries` values as defaults.

- [ ] **Step 1: Env-driven `set_max_entries` in `loader.rs`**

Replace `load_ebpf` with an `EbpfLoader`-based version that overrides sizes from env vars when set:
```rust
pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let mut loader = aya::EbpfLoader::new();
    // Map name -> env var. Unset => keep the compile-time `with_max_entries` default.
    for (map, var) in [
        ("CONNTRACK", "FLOWPLANE_CONNTRACK_MAX"),
        ("NAT_CT", "FLOWPLANE_CONNTRACK_MAX"), // same knob while NAT_CT still exists (pre-Task 3)
        ("ROUTES", "FLOWPLANE_ROUTES_MAX"),
        ("INTERFACES", "FLOWPLANE_INTERFACES_MAX"),
        ("MAGLEV", "FLOWPLANE_MAGLEV_MAX"),
        ("NAT", "FLOWPLANE_NAT_MAX"),
        ("LB", "FLOWPLANE_LB_MAX"),
        ("PORT_META", "FLOWPLANE_PORT_META_MAX"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let n: u32 = v
                .parse()
                .with_context(|| format!("{var} must be a u32, got {v:?}"))?;
            loader.set_max_entries(map, n);
        }
    }
    loader
        .load(bytes)
        .context("load ebpf object")
}
```
Note: after Task 3 removes `NAT_CT`, drop that one line. `set_max_entries` on a non-existent map
name is ignored by aya, so the transient `NAT_CT` line is harmless either way; remove it for
cleanliness when NAT_CT goes.

- [ ] **Step 2: `--conntrack-max` flag on `serve`/`bringup` (optional convenience over the env var)**

In `flowplane/src/main.rs`, add an optional `#[arg(long)]  conntrack_max: Option<u32>` to the `Serve`
and `Bringup` subcommands; when set, export it so `load_ebpf` (called downstream) picks it up:
```rust
            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                unsafe { std::env::set_var("FLOWPLANE_CONNTRACK_MAX", n.to_string()) };
            }
```
Place this at the very top of the `Serve` / `Bringup` arms, before `load_ebpf`/`bring_up` runs.
(Keep it minimal — the env var is the primary mechanism; the flag is sugar for the common knob.)

- [ ] **Step 3: Build + verify override works**
```bash
cargo build -p flowplane
# Sanity: load with a tiny conntrack and confirm the program still loads (root).
sudo FLOWPLANE_CONNTRACK_MAX=4096 ./target/debug/flowplane pass --iface lo &
sleep 1; sudo pkill -f 'flowplane pass' || true
```
Expected: loads cleanly (no error). Then run the e2e once with an override to confirm nothing breaks:
```bash
FLOWPLANE_CONNTRACK_MAX=262144 ./env/netns-e2e.sh run 2>&1 | tail -6   # Tests pass
```

- [ ] **Step 4: Commit**
```bash
cargo fmt --all
git add flowplane
git commit -m "feat(loader): configurable BPF map sizes via env vars + --conntrack-max flag"
```

---

## Self-Review

**Spec coverage (§3 keystone):**
- One unified `CONNTRACK` table all flows pass through → Tasks 2,3,5. ✓
- Translation carried in the entry (LB/NAT/DEFAULT) → Tasks 1,2,3. ✓
- TCP state machine → Task 4. ✓
- `last_seen` + userspace GC aging (30 s / 1-day) → Tasks 4,6. ✓
- DEFAULT tracking (every flow) → Task 5. ✓
- M3/M4 feature maps collapsed → Task 3 removes `NAT_CT`/`CtVal`/`NatCtVal`. ✓
- `fwall_action` field present for M6 → Task 1 (written 0 until M6). ✓

**Placeholder scan:** No TBD. Task 6 Step 3 gives an explicit fallback for the `serve` wiring; Task 3 Step 3 says grep-then-remove dead wrappers (concrete). Verifier + 8-test e2e gate every datapath task.

**Type consistency:** `CtEntry{last_seen,xlate_ip,xlate_port,flags,tcp_state,fwall_action,_pad[7]}` (24B) defined Task 1, used identically in Tasks 2–6. `CtKey` (16B, M3) reused as the unified key. Flag consts `CT_REWRITE_SRC/DST`, `CT_F_SRC_NAT/DST_LB/DEFAULT/FIREWALL` and `TCP_*` defined Task 1, used in Tasks 2–6. `ct_key`/`ct_apply`/`ct_touch`/`ct_ensure_default`/`tcp_advance`/`now`/`csum_replace2` defined in `conntrack.rs` (Tasks 2,4,5), consumed by egress/ingress/nat. GC `timeout_ns`/`run` (Task 6) tested in Task 7.

**Risk note:** Tasks 2–5 each re-run the verifier gate AND the full 8-test e2e, so any behavioral regression in the LB/NAT refactor is caught immediately at the task that introduces it.
