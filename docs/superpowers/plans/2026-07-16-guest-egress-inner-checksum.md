# Guest-Egress Inner-L4 Checksum Fix — Implementation Plan

> **STATUS 2026-07-17: DEFERRED after Task 1.** The Task-1 prototype loop disproved the leading
> mechanism: `bpf_skb_adjust_room` does not maintain `skb->csum_start` on the inner L4 (it stays at the
> guest's original absolute offset; `NO_CSUM_RESET` and `ENCAP_L3_IPV6|FIXED_GSO` both failed —
> off_from_data stayed 54). Approach D (kernel finalizes) is not reachable via an adjust_room flag.
> Tasks 2-6 were NOT executed. The clab-only `ethtool` workaround (Task 3's target) is intentionally
> **kept**. Production real NICs already finalize the checksum for veth + tap. See the spec's STATUS
> block for the full prototype findings and the remaining candidates (3: compute-in-BPF + defeat
> re-finalize; 4: normalize headroom).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the encapped inner L4 (TCP/UDP) checksum correct on the wire for `CHECKSUM_PARTIAL` guest packets — without disabling guest offload — for both container veth and vhost-tap (VM) sources, and delete the `ethtool` workaround.

**Architecture:** The manual encap (`bpf_skb_adjust_room(+IPV6_LEN, BPF_ADJ_ROOM_MAC, 0)` + `write_outer_v6`) leaves `skb->csum_start` on the inner IP header instead of the inner L4, so the kernel's `skb_checksum_help` (uplink offload off) finalizes over the wrong range. The fix makes the encap keep `csum_start` on the inner L4 so the kernel (veth uplink, SW) / NIC (prod, HW) finalizes correctly. The exact mechanism is locked empirically in Task 1 (a one-flag change is the leading candidate).

**Tech Stack:** Rust, aya-ebpf 0.1.1 (`TcContext::adjust_room(len_diff:i32, mode:u32, flags:u64)`), bpftrace + tcpdump for live validation, containerlab kind fabric.

**Spec:** `docs/superpowers/specs/2026-07-16-guest-egress-inner-checksum-design.md`

---

## Background & Key Facts (read before starting)

- Encap call sites (all `ctx.adjust_room(IPV6_LEN as i32, BPF_ADJ_ROOM_MAC, 0)` — the trailing `0` is the `flags: u64`):
  - `flowplane-ebpf/src/tc.rs:140` — IPv6-inner encap branch.
  - `flowplane-ebpf/src/tc.rs:221` — IPv4-inner encap branch.
  - `flowplane-ebpf/src/nat64.rs` — the NAT64 translate→encap path (grep `adjust_room`; the ENCAP one adds `IPV6_LEN`).
- aya flags value: `aya_ebpf::bindings::BPF_F_ADJ_ROOM_NO_CSUM_RESET` (numeric 32). Import path is under `aya_ebpf::bindings`.
- The workaround to delete: `flowplane/src/attach.rs:210-219` (`ethtool -K <guest> tx-checksum-ip-generic off`).
- **Validator (already built):** with guest offload **ON**, the fix is confirmed by BOTH:
  1. bpftrace at eth1 xmit: `off_from_data == inner-L4 offset` (IPv4-inner 74, IPv6-inner 94).
  2. `tcpdump -vv` on eth1: inner TCP `cksum (correct)`.
- Live pipeline (controller runs these; a code subagent does NOT): rebuild image, `kind load`, roll DS, set natpod offload on, run the bpftrace/tcpdump validator. Kubeconfig at `/tmp/k01.conf` (server `[::1]:43107`; regenerate from `k01-control-plane:/etc/kubernetes/admin.conf` if stale). Image: `sudo docker build -t ghcr.io/trevex/ectobase/flowplane:dev . && sudo ~/go/bin/kind load docker-image ghcr.io/trevex/ectobase/flowplane:dev --name k01 && kubectl -n ectobase-system delete pod -l ... ` (recreate pods). bpftrace: `/nix/store/…-bpftrace-0.24.1/bin/bpftrace` (or `nix run nixpkgs#bpftrace`).

### The validator scripts (reuse verbatim)

`/tmp/csumtrace.bt` (bpftrace — off_from_data at eth1 xmit):
```
kprobe:validate_xmit_skb
{
  $skb = (struct sk_buff *)arg0;
  $dev = (struct net_device *)arg1;
  if ($dev != 0 && $dev->name == "eth1" && $skb->ip_summed == 3 && $skb->len > 60) {
    $headroom = (uint64)$skb->data - (uint64)$skb->head;
    printf("eth1 len=%d off_from_data=%d csum_offset=%d\n",
      $skb->len, (uint64)$skb->csum_start - $headroom, $skb->csum_offset);
  }
}
```
Wire check: `sudo docker exec k01-worker sh -c 'timeout 8 tcpdump -vvni eth1 -c 4 "ip6 and ip6[6]==4" & sleep 1; ip netns exec natpod /busybox wget -T4 -O /dev/null http://1.1.1.1/; wait' | grep -iE "cksum|Flags \[S\]"`

---

## Task 1: Prototype — lock the `csum_start` mechanism (CONTROLLER, live)

De-risks the fix empirically before touching all sites. Try candidates in order; stop at the first that yields `off_from_data == 74` AND on-wire `cksum (correct)` with offload ON.

**Files:**
- Modify (prototype only, IPv4 branch first): `flowplane-ebpf/src/tc.rs:221`

- [ ] **Step 1: Candidate 1 — add `BPF_F_ADJ_ROOM_NO_CSUM_RESET`**

Change `tc.rs:221` (IPv4 encap branch) from:
```rust
.adjust_room(crate::parse::IPV6_LEN as i32, BPF_ADJ_ROOM_MAC, 0)
```
to:
```rust
.adjust_room(
    crate::parse::IPV6_LEN as i32,
    BPF_ADJ_ROOM_MAC,
    aya_ebpf::bindings::BPF_F_ADJ_ROOM_NO_CSUM_RESET as u64,
)
```

- [ ] **Step 2: Build the eBPF object**

Run: `cargo build -p flowplane`
Expected: compiles.

- [ ] **Step 3: Build + deploy the image, reproduce with offload ON**

```bash
sudo docker build -t ghcr.io/trevex/ectobase/flowplane:dev .
sudo ~/go/bin/kind load docker-image ghcr.io/trevex/ectobase/flowplane:dev --name k01
KUBECONFIG=/tmp/k01.conf kubectl -n ectobase-system get pods | awk '/flowplane-/{print $1}' | xargs -r kubectl --kubeconfig /tmp/k01.conf -n ectobase-system delete pod
# re-establish natpod egress (SNAT+route+fw) and turn offload ON:
sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-nat-egress.sh
sudo docker exec k01-worker ip netns exec natpod ethtool -K natpod tx-checksum-ip-generic on
```

- [ ] **Step 4: Run the validator**

```bash
BT=$(nix build nixpkgs#bpftrace --no-link --print-out-paths)/bin/bpftrace
sudo timeout 10 "$BT" /tmp/csumtrace.bt > /tmp/bt.out 2>&1 &
sleep 2
sudo docker exec k01-worker ip netns exec natpod sh -c 'for i in 1 2 3; do /busybox wget -T2 -O /dev/null http://1.1.1.1/; done' >/dev/null 2>&1
sleep 8
grep "eth1 len=" /tmp/bt.out | head
# wire:
sudo docker exec k01-worker sh -c 'timeout 8 tcpdump -vvni eth1 -c 3 "ip6 and ip6[6]==4" & sleep 1; ip netns exec natpod /busybox wget -T4 -O /dev/null http://1.1.1.1/ ; wait' 2>/dev/null | grep -iE "cksum|Flags \[S\]"
```
Expected (PASS): `off_from_data=74` and inner TCP `cksum … (correct)`.

- [ ] **Step 5: If Candidate 1 fails — Candidate 2, then 3**

- **Candidate 2 (explicit csum_start):** after `write_outer_v6`, before `bpf_redirect`, re-point the
  checksum start at the inner L4. Investigate `TcContext`/`bpf_skb_adjust_room` helpers exposed by
  aya for setting csum_start; if none, this candidate is not viable — go to Candidate 3.
- **Candidate 3 (compute-in-BPF, device-independent):** after SNAT, compute the full inner L4
  checksum over the ≤MTU packet (`bpf_csum_diff` in bounded chunks + pseudo-header) and write a
  complete L4 checksum; ensure the kernel does not re-finalize (verify `off_from_data`/`ip_summed`
  behavior). Validate with the same Step-4 checks.

Record the winning mechanism in a one-line comment at each encap site in Task 2.

- [ ] **Step 6: Revert the prototype-only single-site edit**

The prototype touched only `tc.rs:221`. Leave it if Candidate 1 won (Task 2 extends it to the other
sites); otherwise `git checkout flowplane-ebpf/src/tc.rs` before Task 2. No commit in Task 1.

---

## Task 2: Apply the locked mechanism to ALL encap sites

**Files:**
- Modify: `flowplane-ebpf/src/tc.rs:140` (IPv6-inner), `flowplane-ebpf/src/tc.rs:221` (IPv4-inner)
- Modify: `flowplane-ebpf/src/nat64.rs` (the ENCAP `adjust_room(+IPV6_LEN, …)` site)

- [ ] **Step 1: Apply the Task-1 mechanism to both tc.rs encap branches**

If Task 1 locked Candidate 1, both `tc.rs:140` and `tc.rs:221` `adjust_room(...)` calls become:
```rust
.adjust_room(
    crate::parse::IPV6_LEN as i32,
    BPF_ADJ_ROOM_MAC,
    aya_ebpf::bindings::BPF_F_ADJ_ROOM_NO_CSUM_RESET as u64,
)
```
Add a one-line comment above each: `// keep csum_start on the inner L4 so the kernel finalizes the partial inner checksum correctly (see spec 2026-07-16-guest-egress-inner-checksum).`
(If Task 1 locked Candidate 3, apply that code instead — the same logic in both branches.)

- [ ] **Step 2: Apply to the NAT64 encap `adjust_room`**

In `flowplane-ebpf/src/nat64.rs`, find the ENCAP `adjust_room` that adds `IPV6_LEN` (the translate+encap
path; NOT the `-20` shrink or `+20` translate step) and apply the identical flag/mechanism. If NAT64
does its own inner L4 checksum recompute after translation (grep the function for `csum`), confirm the
partial-vs-complete interaction and match Task 1's decision.

- [ ] **Step 3: Build**

Run: `cargo build -p flowplane`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add flowplane-ebpf/src/tc.rs flowplane-ebpf/src/nat64.rs
git commit -m "fix(ebpf): keep csum_start on inner L4 across encap (correct partial checksum)"
```

---

## Task 3: Remove the ethtool workaround

**Files:**
- Modify: `flowplane/src/attach.rs` (delete the `ethtool -K … tx-checksum-ip-generic off` block ~210-219)

- [ ] **Step 1: Delete the workaround block**

Remove these lines (the comment + the `run_netns(... "ethtool" ...)` call) from `setup_veth`:
```rust
        // Disable tx-checksum offload on the guest end: the guest stack otherwise emits TCP/UDP with
        // CHECKSUM_PARTIAL ... Best-effort: don't fail attach if unavailable.
        let _ = run_netns(
            netns_path,
            &["ethtool", "-K", guest_name, "tx-checksum-ip-generic", "off"],
        );
```

- [ ] **Step 2: Build**

Run: `cargo build -p flowplane`
Expected: compiles (the `run_netns`/imports remain used elsewhere).

- [ ] **Step 3: Commit**

```bash
git add flowplane/src/attach.rs
git commit -m "refactor(attach): drop ethtool tx-csum workaround (datapath now finalizes the inner checksum)"
```

---

## Task 4: Verifier anchors still pass (CONTROLLER, root)

**Files:** none (regression gate).

- [ ] **Step 1: Run the root verifier/anchor tests**

Run: `sudo -E cargo test -p flowplane --test anchor_uplink --test anchor_lb --test verify_edge_wan_rx -- --ignored`
Then: `sudo chown -R "$(id -un):$(id -gn)" target`
Expected: all PASS (the added flag must not break tc/xdp program verification).

---

## Task 5: Live regression — inner checksum correct with offload ON (CONTROLLER)

**Files:**
- Create: `test/scenario-guest-csum.sh`

**Prereq:** image rebuilt with Tasks 2-3, loaded, DS rolled; natpod egress established (`scenario-nat-egress.sh`).

- [ ] **Step 1: Write the regression scenario**

```bash
#!/usr/bin/env bash
# test/scenario-guest-csum.sh — the inner L4 checksum is correct on the wire with guest offload ON
# (no ethtool workaround). Proves the datapath finalizes CHECKSUM_PARTIAL for both veth and tap.
set -uo pipefail
SRC_NODE=k01-worker; NIC=natpod
pass(){ echo "PASS: $*"; }; fail(){ echo "FAIL: $*"; exit 1; }
echo "== offload ON (reproduce the CHECKSUM_PARTIAL condition) =="
sudo docker exec "$SRC_NODE" ip netns exec "$NIC" ethtool -K "$NIC" tx-checksum-ip-generic on 2>/dev/null || true
echo "== capture encapped TCP SYN on eth1; assert inner cksum correct =="
OUT=$(sudo docker exec "$SRC_NODE" sh -c '
  timeout 8 tcpdump -vvni eth1 -c 3 "ip6 and ip6[6]==4" >/tmp/csum_cap.txt 2>/dev/null &
  sleep 1
  ip netns exec '"$NIC"' /busybox wget -T4 -O /dev/null http://1.1.1.1/ >/dev/null 2>&1
  wait; cat /tmp/csum_cap.txt')
echo "$OUT" | grep -iE "cksum|Flags \[S\]" | head -4
echo "$OUT" | grep -qiE "Flags \[S\].*cksum 0x[0-9a-f]+ \(correct\)" \
  && pass "inner TCP checksum CORRECT on the wire with offload ON" \
  || fail "inner TCP checksum still incorrect with offload ON"
echo "== ALL PASSED =="
```

- [ ] **Step 2: Run it live**

Run: `sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-guest-csum.sh`
Expected: `inner TCP checksum CORRECT on the wire with offload ON`.

- [ ] **Step 3: Also confirm the bpftrace off_from_data**

Run the `/tmp/csumtrace.bt` validator (Background section) while sending; expected `off_from_data=74`.

- [ ] **Step 4: Commit**

```bash
git add test/scenario-guest-csum.sh
git commit -m "test(csum): live regression — inner L4 checksum correct with guest offload ON"
```

---

## Task 6: Tap-path validation (CONTROLLER, best-effort)

**Files:** none (uses `test/tap-vm-smoke.sh`).

- [ ] **Step 1: Run the tap smoke test and check egress checksum**

Run: `test/tap-vm-smoke.sh` (or its documented invocation). While a VM/tap guest sends TCP, capture
the encapped egress on the fabric uplink and assert inner `cksum (correct)`. This proves the fix is
source-independent (tap, not just veth) — the core reason it replaces the container-only ethtool
workaround. If the tap harness is unavailable in this environment, record that the veth path (Task 5)
passed and the tap path is covered by the same datapath code (no per-source branch).

---

## Rollback / Risk

- If the datapath fix regresses, re-add the `ethtool -K … tx-checksum-ip-generic off` line in
  `attach.rs` (container-only mitigation) while investigating.
- If Candidate 1/2 can't yield correct `csum_start`, Task 1 falls to Candidate 3 (compute-in-BPF),
  which is device-independent and removes the egress-device-offload assumption.
- Verifier budget: prefer the flag-only change; the compute-in-BPF fallback needs bounded loops and a
  re-run of Task 4.

## Self-Review notes (author)

- Spec coverage: root-cause fix (Task 1-2), both tc branches + nat64 (Task 2), remove workaround
  (Task 3), verifier regression (Task 4), live veth checksum (Task 5), tap-path (Task 6) — all covered.
- Placeholder scan: mechanism is deliberately empirical (Task 1 locks it with a concrete validator +
  concrete candidate code), not a placeholder.
- Type consistency: `adjust_room(len_diff:i32, mode:u32, flags:u64)`, `BPF_F_ADJ_ROOM_NO_CSUM_RESET as u64`,
  `off_from_data`/inner-L4 offsets (74/94) used consistently.
