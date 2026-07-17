# M9 — Remote LB Backends (dpservice underlay-forwarding model) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the load balancer to dpservice's model — Maglev selects a backend **node by its underlay IPv6**, the datapath forwards the packet there (re-encap to the backend underlay; **no inner DNAT**), and the **backend VF owns the LB IP** (anycast) so replies are naturally sourced from the LB IP. This supports backends on **any** hypervisor and makes the return path symmetric with zero reverse-SNAT.

**Architecture:** `MAGLEV` slots map to a **backend underlay /128** (not an overlay IP). On `uplink_rx`, a packet whose inner dst is an LB IP is Maglev-hashed → backend underlay; if that underlay is local (in `UNDERLAY`) the packet is delivered to that interface, otherwise the outer Ethernet+IPv6 are rewritten (dst = backend underlay, src = the LB's underlay) and the frame is **re-forwarded out the uplink without decap**. The inner LB IP is never rewritten; backends own it and reply with it. The LB conntrack DNAT/reverse-SNAT from M3 is **removed**.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/netns-e2e.sh`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§4.4; milestone M9). Grounded in dpservice `src/nodes/lb_node.c` (`target_ip6 = dp_lb_get_backend_ip(...)`; `ul_dst = target_ip6`; no inner DNAT; backend owns the LB IP).

**Starting point (M1–M8 complete):** `MAGLEV: HashMap<MaglevKey,[u8;4]>` (backend overlay IP). `lb::lb_select_dnat(ctx, ip_off, vni) -> Option<[u8;4]>` DNATs the inner dst → backend overlay IP (+csum) and inserts a `CT_REWRITE_SRC|CT_F_DST_LB` conntrack reverse entry; `ingress::try_uplink_rx` resolves `u = UNDERLAY[outer_dst]` → `vni`, calls `lb_select_dnat`, and delivers an LB packet to `INTERFACES[(vni, backend)]`'s tap. `encap.rs` has `encap_and_redirect(ctx, local, src_underlay, route, inner_len)`. `LOCAL{uplink_ifindex, uplink_mac, gateway_mac, underlay_ipv6}`. CLI `--lb "<ipv4>:<port>:<proto>"` + `--lb-target "<ipv4>:<port>:<proto>=<backend_ipv4>"`. 11 e2e tests; Test 7 = LB distribution + conntrack reverse-SNAT proof.

## Design decisions locked for M9

- **Maglev backend = underlay /128.** `MAGLEV` value type changes `[u8;4]` → `[u8;16]`.
- **No inner DNAT, no LB conntrack.** `lb_select_dnat` becomes `lb_select_forward(ctx, ip_off, vni) -> Option<[u8;16]>` that only looks up the LB service + Maglev slot and returns the backend underlay. The csum/CONNTRACK code is deleted from `lb.rs`. Maglev determinism gives per-flow stickiness (same 5-tuple → same backend).
- **LB IP is anycast-owned by the backends.** Backends configure the LB IP as a secondary address; they reply from it → no reverse-SNAT.
- **The LB has its own underlay marker.** Clients route the LB IP to a dedicated underlay /128 on the LB-owning node; `UNDERLAY[lb_underlay] = {vni, tap:0, mac:0}` provides the VNI for the `LbKey` lookup. After Maglev picks a backend underlay, delivery/forwarding uses that.
- **Local vs remote:** if `UNDERLAY[backend_underlay]` resolves → deliver to that local interface; else **re-forward** (rewrite outer eth dst=`gateway_mac`/src=`uplink_mac`, outer IPv6 src=lb_underlay/dst=backend_underlay, `bpf_redirect` to the uplink — no `adjust_head`).
- **Backward compat:** all other features unchanged; the lab's existing LB test (Test 7) is reworked (backends own the LB IP; one backend is remote to exercise re-forward).

## File Structure

```
flowplane-ebpf/src/
  maps.rs        # MAGLEV value [u8;4] -> [u8;16]
  lb.rs          # lb_select_forward (no DNAT/conntrack) -> Option<[u8;16]>
  encap.rs       # + reforward(ctx, local, lb_underlay, backend) -> u32
  ingress.rs     # LB forward: local deliver vs remote re-forward
flowplane/src/
  maps.rs        # Maglev wrapper value [u8;16]
  control.rs     # create_lb(+lb_underlay, program UNDERLAY marker); add_lb_target(backend underlay)
  grpc.rs        # CreateLoadBalancer/Target decode underlays (or keep for ioiab; lab uses CLI)
  main.rs        # --lb "<ip>:<port>:<proto>:<lb_underlay>"; --lb-target "...=<backend_underlay>"
env/netns-e2e.sh # backends own the LB IP; LB underlay marker; a remote backend; rework Test 7
```

---

## Task 1: MAGLEV value → underlay /128 + `lb_select_forward`

**Files:** Modify `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/lb.rs`, `flowplane/src/maps.rs`

- [ ] **Step 1: MAGLEV value type (`flowplane-ebpf/src/maps.rs`)**
Change `pub static MAGLEV: HashMap<MaglevKey, [u8; 4]>` → `HashMap<MaglevKey, [u8; 16]>`.

- [ ] **Step 2: Rewrite `lb.rs`**
Replace the whole file with:
```rust
use aya_ebpf::programs::XdpContext;
use flowplane_common::{LbKey, MaglevKey};

use crate::maps::{LB, MAGLEV};
use crate::parse::{hash5, l4_ports};

/// If the inner IPv4 dst+port is an LB service, Maglev-select a backend and return its underlay
/// /128. No DNAT and no conntrack — the backend VF owns the LB IP and replies from it (the
/// dpservice anycast model). The caller forwards the (still-encapped) packet to the backend
/// underlay (local delivery or re-forward).
#[inline(always)]
pub fn lb_select_forward(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ip_off + 20 > data_end {
        return None;
    }
    let p = data as *const u8;
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
    // ICMP services are keyed with port=0 (one service matches all echo ids); the hash still uses
    // the real id for per-flow stickiness + cross-flow spread.
    let lookup_port = if proto == 1 { 0 } else { dport };
    let lb = unsafe { LB.get(&LbKey { vni, ipv4: dst, port: lookup_port, proto, _pad: 0 }) }?;
    if lb.size == 0 {
        return None;
    }
    let slot = hash5(&src, &dst, sport, dport, proto) % lb.size;
    let backend = unsafe { MAGLEV.get(&MaglevKey { table_id: lb.table_id, slot }) }?;
    Some(*backend)
}
```

- [ ] **Step 3: userspace Maglev wrapper value (`flowplane/src/maps.rs`)**
Change the `Maglev` wrapper's value type `[u8;4]` → `[u8;16]` (struct field + `upsert`/`get` signatures).

- [ ] **Step 4: build**
`cargo build -p flowplane` — this will FAIL to compile `ingress.rs`/`control.rs` (they still call `lb_select_dnat` / pass `[u8;4]` backends). That is expected; Tasks 2–3 fix the callers. **Do not gate Task 1 on a full build** — instead confirm `flowplane-ebpf` + the two `maps.rs` edits are internally consistent by checking the compile errors are ONLY about `lb_select_dnat`/Maglev callers (ingress.rs, control.rs, main.rs). Proceed to Task 2 before committing, OR commit Tasks 1–3 together. Prefer: do Tasks 2 + 3, then commit all three.

## Task 2: Ingress LB forward (local deliver vs remote re-forward)

**Files:** Modify `flowplane-ebpf/src/encap.rs`, `flowplane-ebpf/src/ingress.rs`

- [ ] **Step 1: `reforward` helper (`encap.rs`)**
```rust
use aya_ebpf::bindings::xdp_action;
// (write6/write16/ETH_LEN/IPV6_LEN already imported)

/// Re-forward an already-encapped packet to a new backend underlay (LB remote backend): rewrite
/// the outer Ethernet (dst=gateway_mac, src=uplink_mac) + outer IPv6 (src=lb_underlay,
/// dst=backend) and redirect out the uplink WITHOUT decap. Returns the XDP action.
#[inline(always)]
pub fn reforward(ctx: &XdpContext, local: &Local, lb_underlay: &[u8; 16], backend: &[u8; 16]) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return xdp_action::XDP_DROP;
    }
    let p = data as *mut u8;
    unsafe {
        write6(p, &local.gateway_mac);
        write6(p.add(6), &local.uplink_mac);
        // ethertype stays IPv6; outer IPv6 src/dst:
        let ip = p.add(ETH_LEN);
        write16(ip.add(8), lb_underlay);
        write16(ip.add(24), backend);
    }
    unsafe { bpf_redirect(local.uplink_ifindex, 0) as u32 }
}
```
(`bpf_redirect` is already imported in `encap.rs`.)

- [ ] **Step 2: Wire LB into `try_uplink_rx` (`ingress.rs`)**
The current block (after `let vni = u.vni;`) calls `lb_select_dnat` and computes `(tap_ifindex, guest_mac)` from `INTERFACES[(vni, backend)]` or `u`. Replace the LB + delivery-interface resolution with:
```rust
    // LB (dpservice model): Maglev-select a backend NODE by underlay. No inner DNAT; the backend
    // owns the LB IP and replies from it.
    let lb_ul = crate::lb::lb_select_forward(ctx, ETH_LEN + IPV6_LEN, vni);
    let deliver_u = match lb_ul {
        Some(bul) => match unsafe { crate::maps::UNDERLAY.get(&bul) } {
            Some(bu) => *bu, // local backend: deliver to its interface
            None => {
                // remote backend: re-forward the encapped packet to its underlay (no decap).
                let local = crate::maps::LOCAL.get(0).ok_or(())?;
                return Ok(crate::encap::reforward(ctx, local, &outer_dst, &bul));
            }
        },
        None => u,
    };
    // NAT reverse only applies when LB didn't match.
    let nat_guest = if lb_ul.is_none() {
        let d = ctx.data();
        let de = ctx.data_end();
        match crate::conntrack::ct_key(d, de, ETH_LEN + IPV6_LEN, vni) {
            Some(key) => match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) if e.flags & CT_REWRITE_DST != 0 => {
                    let mut e = *e;
                    crate::conntrack::ct_apply(ctx, ETH_LEN + IPV6_LEN, &e);
                    crate::conntrack::ct_touch(ctx, ETH_LEN + IPV6_LEN, &key, &mut e);
                    Some(e.xlate_ip)
                }
                _ => None,
            },
            None => None,
        }
    } else {
        None
    };
    let tap_ifindex = deliver_u.tap_ifindex;
    let guest_mac = deliver_u.guest_mac;
```
Then update the downstream guards that referenced `lb_backend`/`nat_guest`:
- the ingress firewall + DEFAULT-tracking blocks stay keyed on `vni` (already) and use `tap_ifindex`;
- the VIP-DNAT guard `if lb_backend.is_none() && nat_guest.is_none()` becomes `if lb_ul.is_none() && nat_guest.is_none()`.
`outer_dst` is the `[u8;16]` already read at the top of `try_uplink_rx`; ensure it is still in scope (it is — `let outer_dst = ...` precedes the `UNDERLAY` lookup). Remove the now-unused `IfaceKey`/`INTERFACES` import from `ingress.rs` IF the LB-backend `INTERFACES` lookup was its only use (check; `INTERFACES` may be unused now — drop it and `IfaceKey` if so).

- [ ] **Step 3: build + verifier gate**
```bash
cargo build -p flowplane     # (control.rs/main.rs LB callers still need Task 3; if they break, do Task 3 first)
```
If `flowplane-ebpf` compiles but `flowplane` userspace fails only on `create_lb`/`add_lb_target`/CLI, proceed to Task 3, then run the verifier gate after the whole workspace builds:
```bash
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
```

## Task 3: Control + CLI — LB underlay marker + backend underlays

**Files:** Modify `flowplane/src/control.rs`, `flowplane/src/main.rs`

- [ ] **Step 1: `control.rs`**
`create_lb(id, vni, ip, ports)` gains a `lb_underlay: [u8;16]` parameter: after writing the `LB` service entries, program the LB's UNDERLAY marker so `uplink_rx` resolves the VNI for this LB IP:
```rust
        g.underlay.upsert(lb_underlay, flowplane_common::UnderlayValue { vni, tap_ifindex: 0, guest_mac: [0; 6], _pad: [0; 2] })?;
```
`add_lb_target(id, backend)` changes `backend: [u8;4]` → `backend: [u8;16]` (a backend underlay); the Maglev build/write now stores `[u8;16]` per slot (`LbEntry.backends: Vec<[u8;16]>`). `crate::maglev::build(&backends)` operates on `&[[u8;16]]` — **update `maglev.rs` `build` to be generic or to take `&[[u8;16]]`** (the FNV hash over the bytes works the same; change the element type and the `table[i]` indexing returns `[u8;16]`). Update `Maglev::upsert(MaglevKey, [u8;16])`.

- [ ] **Step 2: `maglev.rs`**
Change `pub fn build(backends: &[[u8; 16]]) -> Vec<u32>` (it returns slot→backend_index; the index type is unaffected, only the input element width changes — so really just change the parameter type `&[[u8;4]]` → `&[[u8;16]]`). Update the host tests to use 16-byte backends.

- [ ] **Step 3: CLI (`main.rs`)**
`--lb` becomes `"<ipv4>:<port>:<proto>:<lb_underlay_ipv6>"`: parse the 4th field as the LB underlay, program `UNDERLAY[lb_underlay] = {vni:0, 0, 0}` and the `LB` service. `--lb-target` becomes `"<ipv4>:<port>:<proto>=<backend_underlay_ipv6>"`: the backend is now a `[u8;16]` underlay (parse_ipv6). Maglev table stores underlays. Update the bringup LB-programming block accordingly (it currently parses `parse_ipv4(backend_str)`; change to `parse_ipv6`).

- [ ] **Step 4: build + verifier + commit (Tasks 1–3 together)**
```bash
cargo build -p flowplane
cargo test -p flowplane maglev:: 2>&1 | tail -5   # maglev host tests pass (16-byte backends)
# verifier gate -> 1 passed
cargo fmt --all
git add flowplane-common flowplane-ebpf flowplane
git commit -m "feat(lb): dpservice underlay-forwarding LB (maglev->backend underlay, no DNAT)"
```

## Task 4: Lab — backends own the LB IP + a remote backend + Test 7 rework

**Files:** Modify `env/netns-e2e.sh`

- [ ] **Step 1: backends own the LB IP; LB underlay marker; remote backend**
- Give the backends the LB IP as a secondary address (so they reply from it): `sudo ip netns exec guesta ip addr add 10.0.0.200/32 dev gA`, same for guesta2 (`gA2`) and extsrv (`gE`).
- hypa `--lb "10.0.0.200:0:1:fd00:a::200"` (LB underlay marker fd00:a::200).
- hypa `--lb-target "10.0.0.200:0:1=fd00:a::5"` (guesta, local), `"...=fd00:a::7"` (guesta2, local), `"...=fd00:b::8"` (extsrv, REMOTE on hypb).
- hypb `--remote "10.0.0.200=fd00:a::200=0"` (route the LB IP to the LB underlay marker on hypa) — replace the old `10.0.0.200=fd00:a::5=0`.
- extsrv is a remote LB backend: it already has an underlay `fd00:b::8` (its interface). When Maglev picks it, hypa re-forwards to `fd00:b::8`; hypb delivers to extsrv; extsrv (owning 10.0.0.200) replies. No hypb LB config needed.

- [ ] **Step 2: Rework Test 7**
```bash
    echo "=== Test 7: LB (dpservice model) — guestb -> 10.0.0.200 across guesta+guesta2 (local) + extsrv (remote) ==="
    # Backends own 10.0.0.200 (anycast); Maglev selects a backend NODE by underlay. extsrv is on the
    # PEER hypervisor, exercising re-forward. Replies are naturally sourced from 10.0.0.200.
    if [[ -n "$TCPDUMP" ]]; then
        sudo ip netns exec guesta  "$TCPDUMP" -ni gA  'icmp' -c 50 >/tmp/lb-a.txt  2>&1 &
        TDA=$!
        sudo ip netns exec guesta2 "$TCPDUMP" -ni gA2 'icmp' -c 50 >/tmp/lb-a2.txt 2>&1 &
        TDA2=$!
        sudo ip netns exec extsrv  "$TCPDUMP" -ni gE  'icmp and dst 10.0.0.200' -c 50 >/tmp/lb-e.txt 2>&1 &
        TDE=$!
        sudo ip netns exec guestb  "$TCPDUMP" -ni gB  'icmp' -c 50 >/tmp/lb-b.txt  2>&1 &
        TDB=$!
        sleep 0.3
    fi
    for _ in $(seq 1 24); do sudo ip netns exec guestb ping -c 1 -W 2 10.0.0.200 >/dev/null 2>&1 || true; done
    sleep 1
    if [[ -n "$TCPDUMP" ]]; then
        sudo kill "$TDA" "$TDA2" "$TDE" "$TDB" 2>/dev/null || true
        wait "$TDA" "$TDA2" "$TDE" "$TDB" 2>/dev/null || true
        A=$(grep -c 'echo request' /tmp/lb-a.txt || true)
        B=$(grep -c 'echo request' /tmp/lb-a2.txt || true)
        E=$(grep -c '10.0.0.200: ICMP echo request' /tmp/lb-e.txt || true)
        echo "  hits  guesta=$A  guesta2=$B  extsrv(remote)=$E"
        if [ "${A:-0}" -gt 0 ] && [ "${B:-0}" -gt 0 ] && [ "${E:-0}" -gt 0 ]; then
            echo "  LB distribution OK across all 3 backends (incl. the REMOTE one via re-forward)"
        else
            echo "  WARNING: not all backends used (remote re-forward may be broken)"
        fi
        if grep -qE '10\.0\.0\.200 > 10\.0\.0\.6: ICMP echo reply' /tmp/lb-b.txt; then
            echo "  anycast OK: replies to guestb sourced from the LB IP 10.0.0.200 (no reverse-SNAT)"
        else
            echo "  WARNING: no LB-sourced replies at guestb"
        fi
        rm -f /tmp/lb-a.txt /tmp/lb-a2.txt /tmp/lb-e.txt /tmp/lb-b.txt
    fi
    echo ""
```
GATE: all three backends (incl. the remote extsrv) receive flows; guestb sees replies from 10.0.0.200; Tests 1–6, 8–11 still pass.

- [ ] **Step 3: Run + commit**
```bash
./env/netns-e2e.sh run 2>&1 | tail -50   # Tests 1-11 pass, clean teardown
git add env/netns-e2e.sh
git commit -m "test(e2e): LB underlay-forwarding across local + remote backends (anycast LB IP)"
```

---

## Self-Review

**Spec coverage (§4.4 remote LB backends):**
- Maglev backend = underlay endpoint → Tasks 1,3. ✓
- remote backend reached by re-forward in uplink_rx → Task 2 (`reforward`). ✓
- symmetric return (backend owns LB IP, replies from it; no reverse-SNAT) → Tasks 1,4. ✓
- local backends still work (deliver to the interface) → Task 2. ✓
- testing: distribution across local + remote backends, replies from the LB IP → Task 4. ✓

**Placeholder scan:** the LB underlay marker + backend-underlay formats are concrete; `maglev::build` element-type change is explicit; no TBD. The gRPC `CreateLoadBalancerTarget` decode (overlay→underlay) is noted for ioiab but the lab/e2e exercises the CLI path; update the gRPC target decode to `decode_ipv6` if kept (the handler currently `decode_ipv4`s the target — change to underlay, or leave the LB gRPC for the ioiab milestone and rely on CLI for M9; pick one and note it).

**Type consistency:** `MAGLEV: HashMap<MaglevKey,[u8;16]>` (ebpf) ↔ `Maglev` wrapper `[u8;16]` (userspace). `lb_select_forward(...) -> Option<[u8;16]>` (Task 1) called in `ingress.rs` (Task 2). `reforward(ctx, local, &[u8;16], &[u8;16]) -> u32` (Task 2). `create_lb(..., lb_underlay:[u8;16])` + `add_lb_target(..., backend:[u8;16])` + `LbEntry.backends: Vec<[u8;16]>` + `maglev::build(&[[u8;16]])` (Task 3). `UNDERLAY[lb_underlay] = {vni,0,0}` marker provides the VNI (Tasks 3,4).

**Risk note:** Tasks 1–3 are one atomic compile unit (the `[u8;4]→[u8;16]` ripple); commit them together with the verifier gate. Task 2's `reforward` keeps the packet encapped (no `adjust_head`) — the verifier sees a straight-line rewrite + redirect. Task 4's remote-backend hit (extsrv) is the proof the re-forward path works; the firewall on `gB-h` does not block the LB replies because the client's outbound seeds the reverse conntrack (established), exactly as in M6.
