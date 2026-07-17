# M8 — LPM Routing + Alias Prefixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the exact-`/32` `ROUTES` map with a **longest-prefix-match** lookup (dpservice `ipv4_lookup`), so overlay destinations resolve by the most specific matching prefix per VNI, and add **alias prefixes** (`CreatePrefix`/`DeletePrefix`/`ListPrefixes`) that announce a prefix routed to an interface.

**Architecture:** `ROUTES` becomes a `BPF_MAP_TYPE_LPM_TRIE` keyed by `[vni(4, big-endian) ++ ipv4(4)]`. The VNI occupies the high 32 bits (always fully specified ⇒ exact VRF match), and the IPv4 octets follow (variable prefix ⇒ LPM). Egress looks up with `prefix_len = 64` (full key) and the trie returns the value of the longest stored prefix. Routes/prefixes are inserted with `prefix_len = 32 + ipv4_prefix_len`.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/netns-e2e.sh`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§4.3; milestone M8).

**Starting point (M1–M7 complete):** `ROUTES: HashMap<RouteKey, RouteValue>` where `RouteKey{vni:u32, prefix_len:u32, ipv4:[u8;4]}` (12) and `RouteValue{nexthop_vni:u32, nexthop_ipv6:[u8;16], is_external:u8, _pad:[u8;3]}` (24). The datapath only ever looks up `prefix_len:32`. `egress::try_guest_tx` does `ROUTES.get(&RouteKey{vni:meta.vni, prefix_len:32, ipv4:dst})`. Userspace `Routes` wrapper (`open`/`upsert(RouteKey,RouteValue)`/`get`). `control::create_route(vni, ipv4, prefix_len, nexthop_ipv6, is_external)` writes `RouteKey{vni, prefix_len, ipv4}`. CLI `--remote "<ipv4>=<nexthop_underlay>=<vni>"` (M7) writes a `/32`. gRPC `create_prefix`/`delete_prefix`/`list_prefixes` are `unimplemented` stubs. 10 e2e tests.

## Design decisions locked for M8

- **LPM key layout:** `RouteLpmData{ vni: [u8;4], ipv4: [u8;4] }` (8 bytes), `vni` stored **big-endian** so the trie matches it MSB-first as a fixed 32-bit VRF discriminator, then the IPv4 octets (network order) provide the variable prefix. Stored prefix length = `32 + ipv4_prefix_len`; lookups use `prefix_len = 64`.
- **`BPF_F_NO_PREALLOC` required:** LPM tries must be created with `flags = 1` (`BPF_F_NO_PREALLOC`); the program load fails otherwise.
- **`/32` routes are just LPM entries with `ipv4_prefix_len = 32`** — all existing single-host routes keep working unchanged (now as max-length prefixes that always win).
- **Alias prefixes** (`CreatePrefix`) program a `ROUTES` entry `(vni, prefix) → the interface's underlay /128` (i.e. announce that the prefix is reachable via that interface). `is_external = 0`. `ListPrefixes`/`DeletePrefix` manage them via a userspace shadow store keyed by interface.
- **CLI `--remote` gains CIDR:** `"<ipv4>[/<len>]=<nexthop_underlay>=<vni>"` (no `/len` ⇒ `/32`), so the lab can program supernets.

## File Structure

```
flowplane-common/src/lib.rs   # + RouteLpmData (8B) + layout test
flowplane-ebpf/src/
  maps.rs                  # ROUTES: HashMap -> LpmTrie<RouteLpmData, RouteValue>
  egress.rs                # lookup via Key::new(64, RouteLpmData{vni_be, dst})
flowplane/src/
  maps.rs                  # Routes wrapper -> LpmTrie; upsert(vni,ipv4,prefix_len,RouteValue)
  control.rs               # create_route builds the LPM key; + prefix shadow store + add/del/list_prefix
  grpc.rs                  # CreatePrefix/DeletePrefix/ListPrefixes
  main.rs                  # --remote CIDR parsing
env/netns-e2e.sh           # LPM acceptance (a /32 beats a /24 supernet) (Test 11)
```

---

## Task 1: Common `RouteLpmData` type

**Files:** Modify `flowplane-common/src/lib.rs`

- [ ] **Step 1: Add the type**
```rust
/// LPM-trie key data for `ROUTES`: VNI (big-endian, matched MSB-first as a fixed 32-bit VRF
/// discriminator) followed by the IPv4 octets (network order, variable prefix). The trie key's
/// `prefix_len` is `32 + ipv4_prefix_len`; lookups use `prefix_len = 64`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RouteLpmData {
    pub vni: [u8; 4],
    pub ipv4: [u8; 4],
}
```
Add `unsafe impl aya::Pod for RouteLpmData {}` in `user_impls`.

- [ ] **Step 2: Layout test** — assert `size_of::<RouteLpmData>() == 8`. Run `cargo test -p flowplane-common --features user` → pass. `cargo build -p flowplane` (RouteLpmData unused yet — fine).

- [ ] **Step 3: Commit**
```bash
cargo fmt --all
git add flowplane-common
git commit -m "feat(lpm): RouteLpmData key for the LPM routes trie"
```

## Task 2: eBPF ROUTES → LPM trie + egress lookup

**Files:** Modify `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/egress.rs`

- [ ] **Step 1: Change the map type (`maps.rs`)**
Add to imports: `use aya_ebpf::maps::lpm_trie::LpmTrie;` and `RouteLpmData` from `flowplane_common`. Replace the `ROUTES` declaration:
```rust
// LPM trie: key data = [vni_be(4) ++ ipv4(4)], prefix_len = 32 + ipv4_prefix. flags=1 is
// BPF_F_NO_PREALLOC, REQUIRED for LPM tries (the load fails without it).
#[map]
pub static ROUTES: LpmTrie<RouteLpmData, RouteValue> = LpmTrie::with_max_entries(65536, 1);
```
(Keep `RouteKey` imported only if still used elsewhere in this file; the LPM map no longer uses it. `RouteValue` stays.)

- [ ] **Step 2: Egress lookup (`egress.rs`)**
The current lookup is:
```rust
    let route = unsafe {
        ROUTES.get(&RouteKey { vni: meta.vni, prefix_len: 32, ipv4: dst })
    }
    .ok_or(())?;
```
Replace with an LPM lookup (full-length key; the trie returns the longest stored match):
```rust
    let route = unsafe {
        ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
            64,
            flowplane_common::RouteLpmData {
                vni: meta.vni.to_be_bytes(),
                ipv4: dst,
            },
        ))
    }
    .ok_or(())?;
```
Update `egress.rs` imports: drop `RouteKey` (no longer used), keep `RouteValue` if referenced (it is via `route`). Add nothing else (`Key`/`RouteLpmData` are fully qualified above).

- [ ] **Step 3: build + verifier + e2e**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
```
The full e2e can't pass until Task 3 makes the userspace side write LPM entries — so the **verifier gate is Task 2's acceptance** (it confirms the LPM map loads with NO_PREALLOC and the program verifies). If the load fails with `BPF_F_NO_PREALLOC`-related errors, ensure `flags = 1`. (Tasks 3 restores the e2e.)

- [ ] **Step 4: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(lpm): ROUTES is an LPM trie; egress does longest-prefix match"
```

## Task 3: Userspace Routes wrapper → LPM + control + CLI

**Files:** Modify `flowplane/src/maps.rs`, `flowplane/src/control.rs`, `flowplane/src/main.rs`

- [ ] **Step 1: `Routes` wrapper over `LpmTrie` (`flowplane/src/maps.rs`)**
```rust
use aya::maps::lpm_trie::{Key, LpmTrie};
// ... add RouteLpmData to the flowplane_common import ...

#[allow(dead_code)]
pub struct Routes {
    map: LpmTrie<MapData, RouteLpmData, RouteValue>,
}

#[allow(dead_code)]
impl Routes {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = LpmTrie::try_from(ebpf.take_map("ROUTES").context("ROUTES map missing")?)?;
        Ok(Self { map })
    }
    /// Insert a route for (vni, ipv4/prefix_len). The trie key prefix length is 32 + prefix_len.
    pub fn upsert(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        val: RouteValue,
    ) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData { vni: vni.to_be_bytes(), ipv4 },
        );
        self.map.insert(&key, val, 0).context("insert route")
    }
    pub fn remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()> {
        let key = Key::new(
            32 + prefix_len.min(32),
            RouteLpmData { vni: vni.to_be_bytes(), ipv4 },
        );
        self.map.remove(&key).context("remove route")
    }
}
```
(Confirm `aya::maps::lpm_trie::{Key, LpmTrie}` import path; `MapData` already imported.)

- [ ] **Step 2: `control.rs` `create_route` uses the new wrapper signature**
`create_route(vni, ipv4, prefix_len, nexthop_ipv6, is_external)` currently calls `g.routes.upsert(RouteKey{...}, RouteValue{...})`. Change to:
```rust
        g.routes.upsert(
            vni,
            ipv4,
            prefix_len,
            RouteValue { nexthop_vni: vni, nexthop_ipv6, is_external: is_external as u8, _pad: [0; 3] },
        )?;
```
Drop the now-unused `RouteKey` import from `control.rs` if present.

- [ ] **Step 3: CLI `--remote` gains CIDR (`main.rs`)**
The `--remote` loop currently parses `"<ipv4>=<nexthop_underlay>=<vni>"` and calls `routes.upsert(RouteKey{vni, prefix_len:32, ipv4}, RouteValue{...})`. Change the first field to accept an optional `/len`, and call the new wrapper signature:
```rust
                let (ip_s, plen) = match f[0].split_once('/') {
                    Some((ip, l)) => (ip, l.parse::<u32>().context("--remote: bad prefix len")?),
                    None => (f[0], 32),
                };
                let ip = parse_ipv4(ip_s)?;
                let nh = parse_ipv6(f[1])?;
                let vni: u32 = f[2].parse().context("--remote: bad vni")?;
                routes.upsert(
                    vni,
                    ip,
                    plen,
                    flowplane_common::RouteValue {
                        nexthop_vni: vni,
                        nexthop_ipv6: nh,
                        is_external: external_set.contains(&ip) as u8,
                        _pad: [0; 3],
                    },
                )?;
```
(Adjust to the actual variable names in the loop; `f` is the `split('=')` vec from M7.)

- [ ] **Step 4: build + verifier + e2e**
```bash
cargo build -p flowplane
# verifier gate -> 1 passed
./env/netns-e2e.sh run 2>&1 | tail -14   # Tests 1-10 pass (all /32 routes now LPM entries)
```

- [ ] **Step 5: Commit**
```bash
cargo fmt --all
git add flowplane flowplane-ebpf
git commit -m "feat(lpm): userspace LPM Routes wrapper + create_route + --remote CIDR"
```

## Task 4: gRPC alias prefixes (CreatePrefix / DeletePrefix / ListPrefixes)

**Files:** Modify `flowplane/src/control.rs`, `flowplane/src/grpc.rs`

- [ ] **Step 1: `Control` prefix store + methods**
Add to `Inner`: `prefixes: std::collections::HashMap<Vec<u8>, Vec<([u8;4], u32)>>` (interface_id → list of (prefix_ip, prefix_len)). Methods:
```rust
    /// Announce an alias prefix routed to an interface (route prefix -> the interface's underlay).
    pub fn add_prefix(&self, interface_id: &[u8], prefix: [u8;4], prefix_len: u32) -> anyhow::Result<()>;
    pub fn del_prefix(&self, interface_id: &[u8], prefix: [u8;4], prefix_len: u32) -> anyhow::Result<()>;
    pub fn list_prefixes(&self, interface_id: &[u8]) -> Vec<([u8;4], u32)>;
```
`add_prefix` looks up the interface's (vni, underlay) — the interface's underlay must be retained. The M7 `create_interface` already records `by_id: interface_id -> (vni, guest_ipv4)` and programs the interface's underlay; add an `iface_underlay: HashMap<Vec<u8>, [u8;16]>` populated in `create_interface` so prefixes can resolve the interface's underlay /128. `add_prefix` then `g.routes.upsert(vni, prefix, prefix_len, RouteValue{nexthop_vni:vni, nexthop_ipv6: underlay, is_external:0, _pad:[0;3]})` and records it in `prefixes`. `del_prefix` calls `g.routes.remove(vni, prefix, prefix_len)` and drops it from the shadow store.

- [ ] **Step 2: Implement the RPCs (`grpc.rs`)**
Verify shapes in the generated file: `CreatePrefixRequest{interface_id, prefix: Option<Prefix>}` (Prefix{ip:Option<IpAddress>, length:u32, underlay_route:Vec<u8>}), `CreatePrefixResponse{status, underlay_route}`, `DeletePrefixRequest{interface_id, prefix}`, `ListPrefixesRequest{interface_id}`, `ListPrefixesResponse{status, prefixes: Vec<Prefix>}` (confirm field names). Decode `prefix.ip`→ipv4 + `prefix.length`; call the `Control` methods; `CreatePrefix` returns the interface's underlay as `underlay_route`; `ListPrefixes` re-encodes the shadow store to `Vec<Prefix>`.

- [ ] **Step 3: build + host tests + commit**
```bash
cargo build -p flowplane
cargo test -p flowplane 2>&1 | tail -3
cargo fmt --all
git add flowplane
git commit -m "feat(grpc): CreatePrefix/DeletePrefix/ListPrefixes (alias prefixes via LPM routes)"
```

## Task 5: Lab LPM acceptance (a /32 beats a /24 supernet)

**Files:** Modify `env/netns-e2e.sh`

- [ ] **Step 1: Add a less-specific supernet route on hypa**
In the hypa `bringup`, add a `10.0.0.0/24` supernet pointing at extsrv's underlay (a destination guesta does NOT intend for 10.0.0.6), alongside the existing specific `10.0.0.6/32 → guestb`:
```
        --remote "10.0.0.0/24=fd00:b::8=0" \
```
(extsrv is `fd00:b::8`. The existing `--remote "10.0.0.6=fd00:b::6=0"` is the more-specific /32.)

- [ ] **Step 2: Test 11 — LPM longest-prefix wins**
Add to `cmd_test` before "All tests passed":
```bash
    echo "=== Test 11: LPM routing — /32 to guestb wins over a /24 supernet to extsrv ==="
    # hypa has 10.0.0.6/32 -> guestb AND 10.0.0.0/24 -> extsrv. A guesta ping to 10.0.0.6 must take
    # the /32 (reach guestb) and NOT the /24 (extsrv). Capture on extsrv to confirm it sees nothing.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec extsrv "$TCPDUMP" -ni gE 'icmp and host 10.0.0.6' -c 3 >/tmp/lpm.txt 2>&1 &
        TDL=$!
        sleep 0.3
    fi
    if sudo ip netns exec guesta ping -c 2 -W 2 10.0.0.6 >/dev/null 2>&1; then
        echo "  /32 route OK: guesta -> 10.0.0.6 reaches guestb"
    else
        echo "  WARNING: guesta -> 10.0.0.6 failed under LPM"
    fi
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDL" 2>/dev/null || true; wait "$TDL" 2>/dev/null || true
        if grep -q 'ICMP' /tmp/lpm.txt; then
            echo "  WARNING: traffic to 10.0.0.6 hit the /24 supernet (extsrv) — LPM not most-specific"
        else
            echo "  LPM OK: the /32 beat the /24 supernet (extsrv saw nothing)"
        fi
        rm -f /tmp/lpm.txt
    fi
    echo ""
```
GATE: guesta→10.0.0.6 reaches guestb; extsrv sees no 10.0.0.6 traffic; Tests 1–10 still pass.

- [ ] **Step 3: Run + commit**
```bash
./env/netns-e2e.sh run 2>&1 | tail -40   # Tests 1-11 pass, clean teardown
git add env/netns-e2e.sh
git commit -m "test(e2e): LPM longest-prefix-match (/32 beats /24 supernet)"
```

---

## Self-Review

**Spec coverage (§4.3 LPM + prefixes):**
- LPM route lookup (replace exact /32) → Tasks 1,2,3. ✓
- alias prefixes (`CreatePrefix`/`Delete`/`List`) → Task 4. ✓
- CIDR routes via CLI → Task 3. ✓
- VRF isolation preserved (vni in the LPM key high bits) → Task 1 design. ✓
- testing: a more-specific prefix wins → Task 5. ✓

**Placeholder scan:** `BPF_F_NO_PREALLOC` flag is concrete (`1`); the prefix-store underlay resolution adds `iface_underlay` in `create_interface` (concrete). gRPC `ListPrefixesResponse.prefixes` field to confirm in Task 4. Tasks 2–3 are verifier+e2e gated.

**Type consistency:** `RouteLpmData{vni:[u8;4], ipv4:[u8;4]}`(8) defined Task 1; the eBPF `LpmTrie<RouteLpmData, RouteValue>` (Task 2) and userspace `LpmTrie<MapData, RouteLpmData, RouteValue>` (Task 3) agree. `Key::new(32+prefix_len, ..)` insert vs `Key::new(64, ..)` lookup. `Routes::upsert(vni, ipv4, prefix_len, RouteValue)` (Task 3) called from `create_route` (Task 3) and `--remote` (Task 3) and `add_prefix` (Task 4). `RouteValue` unchanged.

**Risk note:** Task 2 leaves the e2e red (the userspace still writes the old map shape until Task 3); the verifier gate covers Task 2, and Task 3 restores Tests 1–10. The LPM-trie `NO_PREALLOC` flag is the one load-time gotcha — Task 2's verifier gate catches it immediately.
