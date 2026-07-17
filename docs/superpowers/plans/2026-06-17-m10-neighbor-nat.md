# M10 — Neighbor NAT (distributed NAT return) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dpservice-style **neighbor NAT** — horizontal NAT scaling where a NAT'd flow's return traffic may enter the cluster at a node that does **not** own the flow; that node looks up a `neighbor_nat` table (`(vni, nat_ip, dst_port∈[min,max)) → owning-node underlay`) and re-forwards the (already-decapped-then-re-encapped) packet to the owner, which performs the reverse translation — plus `CreateNeighborNat` gRPC.

**Scope note:** M10 as specified (`§4.5`) also lists **NAT64**. NAT64 (IPv6 guest → IPv4 external) fundamentally requires the IPv6 **overlay tenant** support that lands in **M15**, so it cannot be exercised end-to-end yet. **NAT64 is moved to M15** (where IPv6 tenants exist); M10 delivers the cross-node **NeighborNat** piece, which is fully testable on the current IPv4 overlay.

**Architecture:** A `NEIGHBOR_NAT` map holds a bounded set of `{vni, nat_ip, port_min, port_max, underlay}` entries (scanned linearly in the datapath, mirroring dpservice's `neighnat_head` list). On `uplink_rx`, a decapped packet whose inner dst is **not** a local LB target, **not** a locally-owned NAT return (no local conntrack), and **not** a local interface, is checked against `NEIGHBOR_NAT` by `(vni, inner_dst, L4 dst port)`; on a match it is re-forwarded to the owning node's underlay via the existing `encap::reforward`. The owner reverses it with its local NAT conntrack.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/netns-e2e.sh`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§4.5; milestone M10, NeighborNat half). Grounded in dpservice `src/nodes/dnat_node.c` (`dp_lookup_neighnat_underlay_ip` → `DP_CHG_UL_DST_IP` → re-encap to the neighbor) and `src/dp_nat.c` (`dp_add_neighnat_entry`, `neighnat_head` list).

**Starting point (M1–M9 complete):** NAT egress/ingress via the unified conntrack (`CT_REWRITE_DST` reverse entries). `encap::reforward(ctx, local, lb_underlay, backend)` re-encaps an already-encapped packet to a new underlay and redirects out the uplink (added in M9 for remote LB). `ingress::try_uplink_rx`: resolves `vni = UNDERLAY[outer_dst].vni`, does LB (`lb_ul`), NAT reverse (`nat_guest` via `CONNTRACK` `CT_REWRITE_DST`), then delivers to `deliver_u`. `parse::l4_ports(...)`. `LOCAL` map. CLI `--nat`/`--external`/`--remote`. 11 e2e tests on a 2-hypervisor (hypa/hypb) bridge lab.

## Design decisions locked for M10

- **NeighborNat table = bounded scanned array** (dpservice scans a linked list). `NEIGHBOR_NAT: HashMap<u32 idx, NeighborNatEntry>` with `NB_MAX = 64` slots + a `NEIGHBOR_NAT_COUNT` so the datapath scans only `0..count`. Entry: `{underlay:[u8;16], nat_ip:[u8;4], vni:u32, port_min:u16, port_max:u16, enabled:u8, _pad}`.
- **Match key:** `(vni, nat_ip == inner_dst, port_min ≤ dport < port_max)` where `dport` is the L4 dst port (or ICMP id) of the **inbound** packet. dpservice matches the same `(dst_ip, dst_vni, dst_port)`.
- **Action = re-forward** to the matched `underlay` (re-use `encap::reforward`), exactly like the M9 remote-LB path. No translation on the gateway node; the **owner** does the reverse via its local NAT conntrack.
- **Trigger ordering:** only consult `NEIGHBOR_NAT` when the packet is NOT an LB packet, NOT a locally-owned NAT return, and the inner dst is NOT a local interface (i.e. the local node has nothing to do with this nat_ip). This avoids hijacking normal local delivery.
- **NAT64 deferred to M15** (needs IPv6 overlay). Documented above.
- **Lab gets a 3rd hypervisor** (`hypc` + `extclient`) so the return genuinely enters at a non-owner node (`hypb` as the NAT gateway) and is forwarded to the owner (`hypa`).

## File Structure

```
flowplane-common/src/lib.rs   # + NeighborNatEntry (32B) + layout test
flowplane-ebpf/src/
  maps.rs                  # + NEIGHBOR_NAT, NEIGHBOR_NAT_COUNT maps
  nat.rs                   # + neighbor_nat_lookup(vni, dst, dport) -> Option<[u8;16]>
  ingress.rs               # neighbor-NAT re-forward when not locally handled
flowplane/src/
  maps.rs                  # NeighborNat wrapper
  control.rs               # add_neighbor_nat / del_neighbor_nat (+ shadow store)
  grpc.rs                  # CreateNeighborNat / DeleteNeighborNat / ListNeighborNats
  main.rs                  # --neigh-nat "<nat_ip>:<port_min>:<port_max>:<owner_underlay>:<vni>"
env/netns-e2e.sh           # + hypc + extclient; NeighborNat scenario (Test 12)
```

---

## Task 1: Common `NeighborNatEntry` type

**Files:** Modify `flowplane-common/src/lib.rs`

- [ ] **Step 1: Add the type + consts**
```rust
/// Max neighbor-NAT entries scanned in the datapath (bounded loop).
pub const NB_MAX_ENTRIES: u32 = 64;

/// A neighbor-NAT entry: a remote node owns `(vni, nat_ip, [port_min,port_max))` — return traffic
/// to that nat_ip:port is re-forwarded to `underlay`. `enabled` 1 = slot in use.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct NeighborNatEntry {
    pub underlay: [u8; 16],
    pub nat_ip: [u8; 4],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}
```
Add `unsafe impl aya::Pod for NeighborNatEntry {}` in `user_impls`. Add layout assert `size_of::<NeighborNatEntry>() == 32`. Run `cargo test -p flowplane-common --features user` → pass.

- [ ] **Step 2: Commit**
```bash
cargo fmt --all
git add flowplane-common
git commit -m "feat(neighnat): NeighborNatEntry POD type"
```

## Task 2: eBPF maps + `neighbor_nat_lookup`

**Files:** Modify `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/nat.rs`

- [ ] **Step 1: Maps (`maps.rs`)**
Add `NeighborNatEntry` to the `flowplane_common` import. Append:
```rust
#[map]
pub static NEIGHBOR_NAT: HashMap<u32, NeighborNatEntry> = HashMap::with_max_entries(64, 0);
/// Entry 0: number of populated NEIGHBOR_NAT slots (the datapath scans 0..count).
#[map]
pub static NEIGHBOR_NAT_COUNT: Array<u32> = Array::with_max_entries(1, 0);
```

- [ ] **Step 2: `neighbor_nat_lookup` (`nat.rs`)**
```rust
use flowplane_common::{NeighborNatEntry, NB_MAX_ENTRIES};
use crate::maps::{NEIGHBOR_NAT, NEIGHBOR_NAT_COUNT};

/// If `(vni, dst, dport)` matches a neighbor-NAT entry, return the owning node's underlay /128.
/// Bounded linear scan over the populated slots (dpservice scans a list of nat ranges).
#[inline(always)]
pub fn neighbor_nat_lookup(vni: u32, dst: [u8; 4], dport: u16) -> Option<[u8; 16]> {
    let count = match NEIGHBOR_NAT_COUNT.get(0) {
        Some(c) => *c,
        None => return None,
    };
    let mut idx: u32 = 0;
    while idx < NB_MAX_ENTRIES {
        if idx >= count {
            break;
        }
        if let Some(e) = unsafe { NEIGHBOR_NAT.get(&idx) } {
            let e: NeighborNatEntry = *e;
            if e.enabled != 0
                && e.vni == vni
                && e.nat_ip == dst
                && dport >= e.port_min
                && dport < e.port_max
            {
                return Some(e.underlay);
            }
        }
        idx += 1;
    }
    None
}
```

- [ ] **Step 3: build + verifier**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
```
(Not wired into a program yet — confirms the bounded scan compiles into the object and verifies.)

- [ ] **Step 4: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(neighnat): NEIGHBOR_NAT maps + bounded neighbor_nat_lookup"
```

## Task 3: Ingress neighbor-NAT re-forward

**Files:** Modify `flowplane-ebpf/src/ingress.rs`

- [ ] **Step 1: Re-forward on a neighbor match**
In `try_uplink_rx`, the current flow computes `lb_ul`, `deliver_u`, then `nat_guest`. After `nat_guest` is computed and BEFORE the firewall/delivery, add a neighbor-NAT check: if this is not an LB packet (`lb_ul.is_none()`), not a locally-owned NAT return (`nat_guest.is_none()`), and the inner dst is **not** a local interface for this VNI, consult `NEIGHBOR_NAT`. To know "not a local interface", check `INTERFACES`/`UNDERLAY`: the inner dst would be delivered to `deliver_u` (the underlay-resolved iface) — but for a neighbor-NAT gateway the `outer_dst` is the gateway's own marker and the inner dst is a foreign nat_ip. The simplest robust trigger: read the inner dst + dport and consult `NEIGHBOR_NAT`; if it matches, re-forward (the neighbor table only contains foreign nat_ips, so a match is authoritative). Insert after `let guest_mac = deliver_u.guest_mac;`:
```rust
    // Neighbor NAT: if this inbound packet is destined to a nat_ip owned by ANOTHER node (and we
    // are not the LB target / local NAT owner), re-forward it to the owner's underlay.
    if lb_ul.is_none() && nat_guest.is_none() {
        let d = ctx.data();
        let de = ctx.data_end();
        let off = ETH_LEN + IPV6_LEN;
        if d + off + 20 <= de {
            let q = d as *const u8;
            let inner_dst = unsafe { core::ptr::read_unaligned(q.add(off + 16) as *const [u8; 4]) };
            if let Some((_proto, _sport, dport)) = crate::parse::l4_ports(d, de, off) {
                if let Some(owner_ul) = crate::nat::neighbor_nat_lookup(vni, inner_dst, dport) {
                    let local = LOCAL.get(0).ok_or(())?;
                    return Ok(crate::encap::reforward(ctx, local, &outer_dst, &owner_ul));
                }
            }
        }
    }
```
(`outer_dst`, `vni`, `LOCAL` are already in scope. This runs before delivery, so a neighbor-NAT packet is forwarded to the owner instead of being mis-delivered locally.)

- [ ] **Step 2: build + verifier + e2e (regression)**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
./env/netns-e2e.sh run 2>&1 | tail -14   # Tests 1-11 still pass (NEIGHBOR_NAT empty -> no-op)
```

- [ ] **Step 3: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(neighnat): ingress re-forwards neighbor-NAT returns to the owner"
```

## Task 4: Control + CLI + gRPC

**Files:** Modify `flowplane/src/maps.rs`, `flowplane/src/control.rs`, `flowplane/src/grpc.rs`, `flowplane/src/main.rs`

- [ ] **Step 1: `NeighborNat` wrapper (`flowplane/src/maps.rs`)**
Add a wrapper over `HashMap<MapData, u32, NeighborNatEntry>` (`open("NEIGHBOR_NAT")`, `upsert(u32, NeighborNatEntry)`, `remove(&u32)`) AND a `NeighborNatCount` over `Array<MapData, u32>` (`open("NEIGHBOR_NAT_COUNT")`, `set(u32)`), mirroring `FwRules`/`FwConfig`.

- [ ] **Step 2: `Control` methods (`control.rs`)**
Add `neigh_nat: NeighborNat`, `neigh_nat_count: NeighborNatCount`, and a shadow `Vec<NeighborNatEntry>` to `Inner` (open the maps in `bring_up`). Methods `add_neighbor_nat(vni, nat_ip, port_min, port_max, underlay)` (append to the shadow vec — capped at `NB_MAX_ENTRIES` — rewrite all slots `0..n` to `NEIGHBOR_NAT` and `NEIGHBOR_NAT_COUNT = n`) and `del_neighbor_nat(...)` / `list_neighbor_nats()`. Each `NeighborNatEntry` has `enabled: 1`.

- [ ] **Step 3: gRPC (`grpc.rs`)**
Implement `create_neighbor_nat` / `delete_neighbor_nat` / `list_neighbor_nats` (currently stubs / `create_neighbor_nat` returns OK no-op). Verify the proto in the generated file: `CreateNeighborNatRequest{ nat_ip: Option<IpAddress>, vni: u32, min_port: u32, max_port: u32, underlay_route: Vec<u8> }` (CONFIRM field names — it carries the **owner's underlay** in `underlay_route`). Decode → `add_neighbor_nat`. Return OK.

- [ ] **Step 4: CLI (`main.rs`)**
Add `--neigh-nat` repeatable: `"<nat_ip>:<port_min>:<port_max>:<owner_underlay_ipv6>:<vni>"`. Parse (reassemble the IPv6 like `--lb` does — take the first 3 `:`-fields as ip/min/max, then the underlay may contain `:`, then a trailing `:<vni>` — **use a clear delimiter**: define the format as `"<nat_ip>:<port_min>:<port_max>@<owner_underlay_ipv6>@<vni>"` using `@` around the IPv6 to avoid the colon-ambiguity that bit `--lb`). Program the `NEIGHBOR_NAT` slots + `NEIGHBOR_NAT_COUNT` (open `maps::NeighborNat`/`NeighborNatCount` in bringup).

- [ ] **Step 5: build + commit**
```bash
cargo build -p flowplane
cargo test -p flowplane 2>&1 | tail -3
cargo fmt --all
git add flowplane
git commit -m "feat(neighnat): control + CLI + gRPC CreateNeighborNat program NEIGHBOR_NAT"
```

## Task 5: Lab — 3rd hypervisor + NeighborNat scenario (Test 12)

**Files:** Modify `env/netns-e2e.sh`

- [ ] **Step 1: Add `hypc` + `extclient` on the bridge**
Mirror the hypb setup: `hypc` netns with uplink `uC` (veth peer `uC-br` on `br-ul`, underlay `fd00::3`), an `extclient` guest (`gX-h`<->`gX`, overlay `10.0.0.9`, underlay `fd00:c::9`). Add `hypc extclient` to the namespace up/down loops; add the `xdp_pass` enabler on `gX` and `uC-br`; capture `GX_MAC`; add static underlay neighs `fd00::3 <-> fd00::1/::2` on all three uplinks.

- [ ] **Step 2: Wire the NeighborNat flow**
- **hypa** (NAT owner): guesta already has `--nat "10.0.0.5=10.0.0.50:20000:30000"`. Add an external route to extclient: `--remote "10.0.0.9=fd00:c::9=0"` + `--external "10.0.0.9"`. (guesta → extclient is NAT'd to 10.0.0.50.)
- **hypc** (extclient's node): bring up extclient as a guest; route the NAT IP's return to the **gateway** hypb (not the owner): `--remote "10.0.0.50=fd00:b::50=0"` where `fd00:b::50` is a NeighborNat **gateway marker** on hypb.
- **hypb** (NAT gateway): program a UNDERLAY marker for `fd00:b::50` (so its uplink_rx resolves a vni for the arriving packet) and a neighbor-NAT entry routing `10.0.0.50:20000-30000 → hypa underlay fd00:a::5`: `--neigh-nat "10.0.0.50:20000:30000@fd00:a::5@0"` and a way to program `UNDERLAY[fd00:b::50] = {vni:0,0,0}` (reuse the `--lb` marker mechanism OR add the marker via a small `--underlay-marker fd00:b::50:0` flag; simplest: program it as part of `--neigh-nat` — the gateway marker underlay can be a 6th field, or add `UNDERLAY[fd00:b::50]` through a dedicated `--marker` flag). Pick the minimal approach and note it.
- The return `extclient → 10.0.0.50` therefore: hypc encaps to `fd00:b::50` → hypb `uplink_rx` resolves vni via the marker, inner dst `10.0.0.50` is not local, `neighbor_nat_lookup(0, 10.0.0.50, nat_port)` matches → re-forward to `fd00:a::5` (hypa) → hypa reverses via its NAT conntrack → guesta.

- [ ] **Step 3: Test 12**
```bash
    echo "=== Test 12: Neighbor NAT — return via a non-owner gateway (hypb) re-forwarded to the owner (hypa) ==="
    # guesta (hypa, nat_ip 10.0.0.50) -> extclient (hypc). The return enters at hypb (NOT the owner)
    # and is re-forwarded to hypa via the neighbor-NAT table. 0% loss proves the cross-node return.
    if sudo ip netns exec guesta ping -c 3 -W 2 10.0.0.9 >/dev/null 2>&1; then
        echo "  NeighborNat OK: guesta -> extclient (return via hypb gateway -> hypa) works"
    else
        echo "  WARNING: NeighborNat return path failed"
    fi
    # SNAT proof: extclient must see the NAT IP as source.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec extclient "$TCPDUMP" -ni gX 'icmp' -c 4 >/tmp/nn.txt 2>&1 &
        TDN=$!; sleep 0.3
        sudo ip netns exec guesta ping -c 2 -W 2 10.0.0.9 >/dev/null 2>&1 || true
        sudo kill "$TDN" 2>/dev/null || true; wait "$TDN" 2>/dev/null || true
        grep -qE '10\.0\.0\.50 > 10\.0\.0\.9' /tmp/nn.txt \
            && echo "  SNAT proof OK: extclient sees source 10.0.0.50" \
            || echo "  WARNING: extclient did not see the NAT IP"
        rm -f /tmp/nn.txt
    fi
    echo ""
```
GATE: guesta→extclient works (0% loss) with the return crossing hypb→hypa via NeighborNat; Tests 1–11 still pass.

- [ ] **Step 4: Run + commit**
```bash
./env/netns-e2e.sh run 2>&1 | tail -55   # Tests 1-12 pass, clean teardown
git add env/netns-e2e.sh
git commit -m "test(e2e): neighbor NAT distributed return via a non-owner gateway"
```

---

## Self-Review

**Spec coverage (§4.5 NeighborNat half):**
- `neighbor_nat` table `(nat_ip, port range) → underlay` → Tasks 1,2,4. ✓
- return arriving at a non-owner node re-forwarded to the owner → Task 3 (`reforward`). ✓
- `CreateNeighborNat` gRPC → Task 4. ✓
- testing: cross-node return via a gateway → Task 5 (3-node lab, Test 12). ✓
- NAT64 → explicitly deferred to M15 (needs IPv6 overlay), documented in the header.

**Placeholder scan:** the `--neigh-nat` format uses `@` delimiters to avoid the IPv6-colon ambiguity (the bug that bit `--lb`); the UNDERLAY gateway-marker programming for hypb is flagged as "pick the minimal approach" in Task 5 Step 2 — resolve to either a 6th `--neigh-nat` field or a dedicated `--marker` flag during implementation. gRPC `CreateNeighborNatRequest` field names to confirm in Task 4.

**Type consistency:** `NeighborNatEntry{underlay,nat_ip,vni,port_min,port_max,enabled,_pad}`(32) defined Task 1; `NEIGHBOR_NAT: HashMap<u32, NeighborNatEntry>` + `NEIGHBOR_NAT_COUNT: Array<u32>` (Task 2) ↔ userspace `NeighborNat`/`NeighborNatCount` (Task 4). `neighbor_nat_lookup(vni, dst, dport) -> Option<[u8;16]>` (Task 2) called in `ingress.rs` (Task 3) → `encap::reforward` (M9). `NB_MAX_ENTRIES` bounds the scan.

**Risk note:** Task 3's neighbor check runs only when not LB / not local-NAT-owned, and the `NEIGHBOR_NAT` table only contains foreign nat_ips, so a match is authoritative — normal local delivery is unaffected (the table is empty in Tests 1–11). The 3-node lab is the main new surface; the verifier gate (Tasks 2,3) and the Tests 1–11 regression (Task 3) catch datapath issues before the multi-node scenario.
