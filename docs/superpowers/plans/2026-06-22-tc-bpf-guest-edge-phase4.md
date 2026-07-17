# tc-BPF Guest Edge — Phase 4 (serve cutover → full conformance on tc) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `flowplane serve` attach the guest datapath via **tc (clsact)** instead of XDP `guest_tx` (uplink stays XDP), behind an env flag, and run the **full dpservice conformance suite against the tc datapath** — the definitive parity proof. Target: 93 passed / 2 skipped ON TC.

**Architecture:** The tc programs (`tc_guest_tx` + the `tc_guest_dhcp`/`tc_guest_nat64` tail-call splits) and `GUEST_PROGS_TC` already exist and are feature-complete. This phase only changes the *control-plane attach*: when `FLOWPLANE_GUEST_TC=1`, `control.rs` registers the tc tail-calls and attaches `tc_guest_tx` to each guest device's clsact-ingress (returning a detachable link), instead of attaching XDP `guest_tx`. `uplink_rx` stays XDP. The per-interface link map becomes an enum over XDP/tc links so teardown works for both.

**Tech Stack:** Rust + aya 0.13 (userspace loader/control), the vendored dpservice conformance suite (`test/conformance/`), bash. Build via `nix develop`.

**Context for the implementer:** `flowplane/src/control.rs`: `bring_up` (lines ~163–200) attaches `uplink_rx` (XDP), pre-loads `guest_tx`, and `register_guest_dhcp`. `program_interface` (~334–378) attaches `guest_tx` via `loader::attach_xdp_link` and stores the returned `XdpLink` in `links: HashMap<Vec<u8>, XdpLink>`. `unprogram_interface` (~494–509) drops the link to detach. `flowplane/src/loader.rs` already has `attach_tc_clsact_ingress(ebpf, prog, iface)` (no link returned) and `register_guest_dhcp_tc(ebpf)` (registers `tc_guest_dhcp` at `GUEST_PROG_DHCP` AND `tc_guest_nat64` at `GUEST_PROG_IPV6` in `GUEST_PROGS_TC`). The conformance harness (`test/conformance/run.sh` + `conftest.py`) starts `serve` via `sudo` (which scrubs env — flags must be passed THROUGH sudo, as `DPSERVICE_CLI` already is).

---

## File Structure

**Modified files:**
- `flowplane/src/loader.rs` — add `attach_tc_clsact_ingress_link(ebpf, prog, iface) -> SchedClassifierLink` (mirrors `attach_xdp_link` but for tc: qdisc_add_clsact + attach + `take_link` to return an owned, detach-on-drop link).
- `flowplane/src/control.rs` — add a `GuestLink { Xdp(XdpLink), Tc(SchedClassifierLink) }` enum; change `links` to `HashMap<Vec<u8>, GuestLink>`; read `FLOWPLANE_GUEST_TC` once in `bring_up` and branch the pre-load/register (tc: `register_guest_dhcp_tc` + pre-load `tc_guest_tx`) and `program_interface` (tc: clsact attach) accordingly; `unprogram_interface` drops the enum (both variants detach on drop).
- `test/conformance/run.sh` (or `conftest.py`) — pass `FLOWPLANE_GUEST_TC` through `sudo` to `serve` so the suite can run against tc.

---

## Task 1: tc attach path in the loader + control plane (behind `FLOWPLANE_GUEST_TC`)

**Files:** `flowplane/src/loader.rs`, `flowplane/src/control.rs`

- [ ] **Step 1: Add `attach_tc_clsact_ingress_link` to `loader.rs`**

Mirror `attach_xdp_link` but for tc, returning an owned `SchedClassifierLink` (so per-interface teardown can drop it):
```rust
use aya::programs::tc::SchedClassifierLink;

/// Attach an already-loaded `tc_guest_tx` to `iface`'s clsact INGRESS and return the owned link
/// (drop it to detach). Ensures the clsact qdisc exists (idempotent).
pub fn attach_tc_clsact_ingress_link(
    ebpf: &mut Ebpf, prog_name: &str, iface: &str,
) -> anyhow::Result<SchedClassifierLink> {
    let _ = tc::qdisc_add_clsact(iface);
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("tc program {prog_name} missing"))?
        .try_into()?;
    let link_id = prog
        .attach(iface, TcAttachType::Ingress)
        .with_context(|| format!("attach {prog_name} to {iface} (clsact ingress)"))?;
    let link = prog.take_link(link_id).context("take tc link")?;
    Ok(link)
}
```
Verify `SchedClassifier::take_link` + `SchedClassifierLink` exist in this aya version (check `~/.cargo/registry/src/*/aya-0.13*/src/programs/tc.rs`); adjust if the API differs (e.g. the link is returned directly by `attach`). Also add a `pub fn load_program_tc(ebpf, "tc_guest_tx")` (or reuse `load_program` if it works for classifier types) so `tc_guest_tx` is pre-loaded once in `bring_up` before per-interface attaches.

- [ ] **Step 2: `GuestLink` enum + `links` map type in `control.rs`**
```rust
enum GuestLink {
    Xdp(aya::programs::xdp::XdpLink),
    Tc(aya::programs::tc::SchedClassifierLink),
}
```
Change `links: HashMap<Vec<u8>, XdpLink>` → `links: HashMap<Vec<u8>, GuestLink>`. Dropping either variant detaches.

- [ ] **Step 3: Branch `bring_up` on the flag**

Read the flag once: `let guest_tc = std::env::var_os("FLOWPLANE_GUEST_TC").is_some();` Store it on the struct (e.g. a `guest_tc: bool` field) so `program_interface` sees it. Then:
- if `guest_tc`: `let guest_progs = loader::register_guest_dhcp_tc(&mut ebpf)?;` and pre-load `tc_guest_tx` (`load_program_tc`). DON'T attach XDP `guest_tx` per-interface.
- else: the existing XDP path (`load_program(guest_tx)` + `register_guest_dhcp`).
`uplink_rx` attach is unchanged (XDP) in BOTH branches. Keep the `guest_progs` `ProgramArray` alive on the struct as today.

- [ ] **Step 4: Branch `program_interface`**
```rust
let link = if self.guest_tc {
    GuestLink::Tc(loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)?)
} else {
    GuestLink::Xdp(loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device)?)
};
g.links.insert(interface_id.to_vec(), link);
```
`unprogram_interface` stays `g.links.remove(interface_id);` (drop detaches either variant).

- [ ] **Step 5: Build + the existing tc gates still pass**

Run: `nix develop -c cargo build -p flowplane 2>&1 | grep -E "error|Finished" | tail -3` → Finished.
Run: `nix develop -c ./test/tc-dhcp-netns.sh 2>&1 | tail -2` → still `PASS: tc DHCP + ARP + ND + DHCPv6 OK` (the netns gates use `tc-bringup`, not `serve`, so they're unaffected — this confirms no eBPF/loader breakage).
Run (XDP path unchanged): `nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93 passed, 2 skipped** (default = XDP; the flag is off).

- [ ] **Step 6: Commit**
```bash
git add flowplane/src/loader.rs flowplane/src/control.rs
git commit -m "feat(serve): attach tc guest edge (clsact) when FLOWPLANE_GUEST_TC=1"
```

---

## Task 2: Run the full conformance suite against the tc datapath

**Files:** `test/conformance/run.sh` (and/or `test/conformance/conftest.py`)

- [ ] **Step 1: Pass `FLOWPLANE_GUEST_TC` through sudo to `serve`**

The harness starts `serve` via `sudo` (env-scrubbed). Find where `conftest.py::_dp_service` builds the `serve` command (it already threads `DPSERVICE_CLI` through `sudo`). Add `FLOWPLANE_GUEST_TC` the same way: when the env var is set in the pytest process, prepend `FLOWPLANE_GUEST_TC=1` to the `sudo ... flowplane serve` argv (like `sudo "FLOWPLANE_GUEST_TC=1" ... serve`). Keep the default (unset) = XDP, so the normal `run.sh` is unchanged. Add a one-line note in `run.sh` documenting `FLOWPLANE_GUEST_TC=1 ./run.sh` runs the suite against tc.

- [ ] **Step 2: Run the full suite against tc**

Run: `FLOWPLANE_GUEST_TC=1 nix develop -c ./test/conformance/run.sh 2>&1 | tail -6`
Expected: **93 passed, 2 skipped** — now exercising `tc_guest_tx`/`tc_guest_dhcp`/`tc_guest_nat64` on the guest devices (uplink_rx still XDP). The conformance harness uses veth devices (clsact works on veth), so all paths run on tc.
If any test fails: the failure is a REAL tc-datapath gap/bug (not a harness issue, since the same suite passes on XDP). Capture the failing test + the `serve` log (it may show a verifier rejection if a tc program didn't load on the veth, or a wrong-bytes assertion). Diagnose: most likely a clsact-on-veth attach detail or a per-interface lifecycle bug from Task 1 — fix it (or report BLOCKED with the specific failing test + log if it's a deeper datapath issue). Do NOT mark done with red tests.

- [ ] **Step 3: Confirm BOTH datapaths pass**

Run: `nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93/2** (XDP, default).
Run: `FLOWPLANE_GUEST_TC=1 nix develop -c ./test/conformance/run.sh 2>&1 | tail -3` → **93/2** (tc).

- [ ] **Step 4: Commit**
```bash
git add test/conformance/run.sh test/conformance/conftest.py
git commit -m "test(conformance): FLOWPLANE_GUEST_TC runs the suite against the tc datapath"
```

---

## Done criteria (Phase 4)

- `flowplane serve` attaches the guest edge via tc clsact when `FLOWPLANE_GUEST_TC=1` (uplink stays XDP); per-interface attach/detach works for both XDP and tc links.
- The full dpservice conformance suite passes **93/2 on the tc datapath** (`FLOWPLANE_GUEST_TC=1`) AND still **93/2 on XDP** (default).
- This proves end-to-end parity: the tc guest edge is a complete drop-in for the XDP guest_tx. Remaining: Phase 5 — wire `FLOWPLANE_GUEST_TC=1` into the ioiab dpservice deployment and run the native lab (DHCP + VM↔VM ping, no SKB mode).
