# De-dpservice the Conformance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make conformance native — expand `flowplane-sim` to own packet-level behavior, add a thin
Go live smoke + a clab zero-drop restart test, then remove the `DPDKironcore` compat gRPC, the
vendored dpservice Python suite, and the `dpservice-cli` dependency. `flowplane serve` ends up
exposing only `DataplaneNode`.

**Architecture:** Test at the right level — sim (deterministic bytes) → Go e2e (real gRPC/attach +
connectivity) → clab (continuous forwarding / zero-drop). Safety order: build the native
replacement BEFORE deleting the dpservice oracle.

**Reference spec:** `docs/superpowers/specs/2026-07-17-de-dpservice-conformance-design.md`

**Branch:** `conformance/de-dpservice` (already created).

**Key facts (verified):**
- Production uses `DataplaneNode` (`dataplane.v1`); `DPDKironcore` (`dpdkironcore.v1`) is
  conformance/dev-only.
- `DPDKironcore` impl = `flowplane/flowplane/src/grpc.rs` (`impl DpdKironcore for Service`, ~2266
  LOC) + main.rs `pb` module (`include_proto!("dpdkironcore.v1")`) + main.rs wiring (server build
  at `main.rs:501`, `add_service` at `:535`, readiness print `serving DPDKironcore on` at `:509`).
- `DataplaneNode` impl = `flowplane/flowplane/src/node.rs` (+ `control.rs`/`attach.rs`); its `pb` =
  `include_proto!("dataplane.v1")`.
- `build.rs` compiles both `dpdk.proto` + `dataplane.proto` (`build.rs:44-45`).
- netns scripts (`test/*-netns.sh`) drive via **grpcurl** (not `dpservice-cli`); they use the
  `serving DPDKironcore on` log as a readiness marker. `dpservice-cli` is used ONLY by the Python
  suite (`test/conformance/`), wired in `flake.nix` (input `:16-17`, package `:37-41,92`, devShell
  PATH `:123`).
- Sim already covers: encap, LB (select + NS/EW scenarios), firewall, conntrack (create),
  north-south. Gaps to add: NAT source-blocks, DHCPv4/v6, ARP/ND, VNI isolation, flow timeout.

**Build/test commands** (nix devShell): `nix develop --command cargo test -p flowplane-sim`;
`nix develop --command cargo build -p flowplane`; `nix develop --command bash -c 'cd test/e2e && go build ./...'`.
Pre-commit hook runs clippy+rustfmt — `cargo fmt` before every commit and verify HEAD advanced.

---

## Phase 1 — Sim expansion (native conformance source of truth)

Each task adds a focused `flowplane-sim` test (native, in-process). **Mirror the existing sim test
pattern** — read a sibling first (e.g. `flowplane/flowplane-sim/src/ns_scenario_test.rs` and
`firewall_test.rs`) for how `VecPkt`/`MemMaps`/`SimNode` are set up. Where a real eBPF program backs
the behavior, add a `BPF_PROG_TEST_RUN` byte-parity anchor mirroring
`flowplane/flowplane/tests/anchor_uplink.rs`. **Before writing each test, read the responder/handler
source named in the task** to derive exact packet layouts and expected bytes (do NOT guess wire
formats — read the implementation).

### Task 1.1: NAT source-block conformance
**Files:** Create `flowplane/flowplane-sim/src/nat_test.rs`; register it in the sim lib
(`flowplane/flowplane-sim/src/lib.rs` — follow how `ns_scenario_test` is included).
**Read first:** the SNAT source-block logic in `flowplane/flowplane-core/` + `flowplane-ebpf`
(egress NAT path) and the netplane allocator semantics (`netplane/allocator`) for block layout.

- [ ] **Step 1: Write failing tests** covering: (a) a guest egress packet gets SNAT'd to a source
  IP+port within its assigned block; (b) two distinct sources get distinct, stable blocks (a
  lower-sorting source added later does not move an existing source's block — mirrors the
  allocator's `Preassign` guarantee); (c) DNAT/VIP rewrite on the return path maps back to the
  guest. Assert exact rewritten IP/port fields on the `VecPkt`.
- [ ] **Step 2: Run — expect FAIL** (`nix develop --command cargo test -p flowplane-sim nat_`).
  If the behavior already passes (core already correct), the test still has value as a regression
  guard — keep it; note it passed immediately.
- [ ] **Step 3: If a genuine gap exists in the core**, fix it minimally (this is conformance —
  the sim asserts the intended behavior; a real divergence is a bug to fix in `flowplane-core`).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (`cargo fmt` first): `test(sim): NAT source-block SNAT/DNAT conformance`.

### Task 1.2: DHCPv4 + DHCPv6 responder conformance
**Files:** Create `flowplane/flowplane-sim/src/dhcp_test.rs`; register in lib.
**Read first:** the in-datapath DHCP responder (grep `flowplane/flowplane-ebpf/src` for `dhcp`,
`GUEST_PROG_DHCP`, DHCP option building; and the `DHCP_CONFIG` handling in `main.rs`/`control.rs`
for MTU/DNS options).

- [ ] **Step 1: Write failing tests**: craft a DHCPv4 DISCOVER and a DHCPv6 SOLICIT `VecPkt`; run
  the responder path; assert the OFFER/ADVERTISE contents — assigned address (matches the port's
  configured IP), the MTU option, and the DNS server option(s) from `DHCP_CONFIG`. Cover both v4
  and v6.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Fix any genuine core gap** (else keep as regression guard).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit**: `test(sim): DHCPv4/v6 responder offer-contents conformance`.

### Task 1.3: ARP + IPv6 ND responder conformance
**Files:** Create `flowplane/flowplane-sim/src/arp_nd_test.rs`; register in lib.
**Read first:** `flowplane/flowplane-ebpf/src/arp_nd.rs` (gateway ARP reply + ND `try_nd_reply`).

- [ ] **Step 1: Write failing tests**: an ARP request for the gateway IP → assert a correct ARP
  reply (sender MAC = gateway MAC, target = requester); an IPv6 ND Neighbor Solicitation for the
  gateway → assert a Neighbor Advertisement with the gateway's link-layer address. Assert exact
  Ethernet + ARP/ICMPv6 fields on the `VecPkt`.
- [ ] **Step 2–4:** run→FAIL, fix any gap, run→PASS.
- [ ] **Step 5: Commit**: `test(sim): ARP + IPv6 ND gateway-responder conformance`.

### Task 1.4: VNI isolation conformance
**Files:** Create `flowplane/flowplane-sim/src/vni_test.rs`; register in lib.
**Read first:** how routes/underlay are keyed by VNI (`ROUTES6`/route LPM keys include `vni`) in
`flowplane-ebpf/src/egress.rs` and the sim `MemMaps`/`fabric.rs` setup.

- [ ] **Step 1: Write a failing test**: two guests in different VNIs; a packet from VNI-A destined
  to VNI-B's address does NOT resolve/deliver (route miss / drop), while the same address WITHIN
  VNI-B resolves. Assert the verdict (Pass/Drop) differs by VNI.
- [ ] **Step 2–4:** run→FAIL, fix any gap, run→PASS.
- [ ] **Step 5: Commit**: `test(sim): VNI isolation conformance`.

### Task 1.5: Flow-timeout (conntrack expiry) conformance
**Files:** Extend `flowplane/flowplane-sim/src/conntrack_test.rs`.
**Read first:** the conntrack expiry/eviction logic (grep `flowplane-ebpf`/`flowplane-core` for
conntrack timeout, `last_seen`, eviction) + how the sim can advance/inject time (check `MemMaps`
for a clock hook; if none exists, add a minimal test-settable clock to the sim's conntrack map view
rather than to production code).

- [ ] **Step 1: Write a failing test**: create a flow (conntrack entry), advance the sim clock past
  the timeout, assert the entry is treated as expired (a subsequent packet is a NEW flow, not a hit).
- [ ] **Step 2–4:** run→FAIL, fix/instrument, run→PASS.
- [ ] **Step 5: Commit**: `test(sim): conntrack flow-timeout expiry conformance`.

### Task 1.6: Coverage-parity check vs the dpservice suite
**Files:** none (analysis) — produce a short note appended to the spec or a `test/conformance-map.md`.

- [ ] **Step 1:** For each APPLICABLE dpservice Python test (per the spec's coverage table —
  encap, lb, flows, nat, dhcpv4/6, arp, nd, vni, vf_to_vf), confirm a named sim test now asserts the
  same behavior. List any residual gap. (Dropped dpservice-only tests — virtsvc, pf_to_vf, vf_to_pf,
  telemetry — are explicitly out of scope; record that.)
- [ ] **Step 2: Commit** the map note: `docs(conformance): sim coverage parity map vs dpservice suite`.

---

## Phase 2 — Thin Go live smoke (`test/e2e`)

**Read first:** the existing `test/e2e/{fabric_test.go,routebus_test.go}` for the clab/netns
orchestration + node-exec helpers, and `cni/gen/dataplanev1` for the `DataplaneNode` Go client.

### Task 2.1: Add goscapy + a DataplaneNode client helper
**Files:** `test/e2e/go.mod` (add `github.com/smallnest/goscapy`); create
`test/e2e/dataplane_client.go` (a small helper that dials `DataplaneNode` on a node and exposes
`AttachInterface`/`AddNatSource`/`AddLbVip`/… as needed).

- [ ] **Step 1:** `cd test/e2e && go get github.com/smallnest/goscapy` (or add to go.mod + `go mod tidy`).
- [ ] **Step 2:** Write the client helper (dials the node-local `DataplaneNode` gRPC via the
  generated client). Build: `go build ./...`. Commit: `test(e2e): goscapy dep + DataplaneNode client helper`.

### Task 2.2: Program-load-and-attach + NAT-egress smoke
**Files:** Create `test/e2e/smoke_datapath_test.go`.

- [ ] **Step 1:** A Go e2e test that: brings up the fabric (reuse existing helpers), starts
  `flowplane serve` on a node, issues an `AttachInterface` via the client, and asserts a guest can
  egress via NAT to an external target (connectivity assertion; optionally goscapy-inspect the
  SNAT'd source at the target). Guard with the same clab/root gating as existing e2e tests
  (`t.Skip` when not on the fabric host).
- [ ] **Step 2:** `go build ./...`; run on the clab host if available (else build-gate + skip).
  Commit: `test(e2e): datapath load/attach + NAT-egress smoke`.

### Task 2.3: LB-distribute + DHCP-lease smoke
**Files:** Extend `test/e2e/smoke_datapath_test.go` (or a sibling).

- [ ] **Step 1:** LB case — program a VIP + ≥2 backends via `DataplaneNode`, assert traffic reaches
  backends (distribution). DHCP case — a real client on a tap/veth obtains a lease; goscapy inspects
  the OFFER (assigned IP + MTU + DNS). Both clab/root-gated.
- [ ] **Step 2:** `go build ./...`; run where feasible. Commit: `test(e2e): LB-distribute + DHCP-lease smoke`.

---

## Phase 2b — clab graceful-restart zero-drop continuity

**Read first:** `test/scenario-restart.sh` (the existing crictl-kill live check) and the
link-pinning memory context (prog-id swap, pin survives).

### Task 2b.1: Continuous-flow zero-drop restart test
**Files:** Evolve `test/scenario-restart.sh` (or add `test/scenario-restart-continuity.sh`).

- [ ] **Step 1:** Script that: brings up the clab fabric with a guest whose traffic transits
  `flowplane`; starts a **continuous flow** across the restart boundary (`ping -i 0.2 -c N` or a
  small UDP/TCP stream with a sequence counter) between the guest and a peer/edge; `crictl stop`s
  the `flowplane` container mid-flow (it restarts + adopts).
- [ ] **Step 2:** Assert: packet loss ≤ a small bounded threshold (target ~0), the pinned bpf-link
  survived the stop, and the eBPF prog-id on the uplink/guest iface **swapped** (atomic re-point,
  not detach) — reproduce the live-validated prog-id-swap check. Emit a clear PASS/FAIL.
- [ ] **Step 3:** Run under `sudo -E` on the clab host (real setuid sudo `/run/wrappers/bin/sudo`);
  gate as a privileged/manual scenario. Commit: `test(clab): graceful-restart zero-drop continuity`.

---

## Phase 3 — Remove DPDKironcore + dpservice suite + dpservice-cli

Only after Phases 1–2b are green. This deletes the oracle now that the native replacement exists.

### Task 3.1: Re-point the netns dev scripts to DataplaneNode
**Files:** `test/*-netns.sh` (the ones that reference DPDKironcore).

- [ ] **Step 1:** `grep -rln 'DPDKironcore\|dpdkironcore' test/*.sh`. For each: change the readiness
  marker `serving DPDKironcore on` → the DataplaneNode readiness line (see Task 3.3 Step 3 for the
  new log string), and re-point any DPDKironcore grpcurl RPCs to their `DataplaneNode` equivalents
  (e.g. NAT → `AddNatSource`, route → `AddRoute`; `AttachInterface` is already DataplaneNode). Drop
  any script fully superseded by the sim/Go smoke (note which, and why, in the commit).
- [ ] **Step 2:** Smoke one re-pointed script under sudo on the fabric/netns host (e.g.
  `test/attach-netns.sh`) to confirm it drives DataplaneNode. Commit: `test: re-point netns scripts to DataplaneNode`.

### Task 3.2: Delete the vendored Python conformance + dpservice-cli
**Files:** remove `test/conformance/` (dir), and `flake.nix` dpservice wiring.

- [ ] **Step 1:** `git rm -r test/conformance`.
- [ ] **Step 2:** In `flake.nix` remove: the `dpservice` input (`:16-17`), its `outputs` arg
  (`:22`), the `dpservice-cli` `buildGoModule` package (`:37-41`), `packages.dpservice-cli`
  (`:92`), and the devShell PATH entry (`:123`). Also drop the `dpservice-cli`/python-scapy
  mentions in the Makefile prereqs comment if present.
- [ ] **Step 3:** `nix develop --command true` (devShell still evaluates) + `nix flake check` if
  quick. Commit: `chore: remove vendored dpservice conformance + dpservice-cli`.

### Task 3.3: Remove the DPDKironcore gRPC service from flowplane
**Files:** delete `flowplane/flowplane/src/grpc.rs`; edit `flowplane/flowplane/src/main.rs`;
edit `flowplane/flowplane/build.rs`; delete `api/proto/dataplane/v1/dpdk.proto`.

- [ ] **Step 1:** `git rm flowplane/flowplane/src/grpc.rs api/proto/dataplane/v1/dpdk.proto`.
- [ ] **Step 2:** In `main.rs`: remove `mod grpc;` (if declared), the `pub mod pb {
  include_proto!("dpdkironcore.v1") }`, the `DpdKironcoreServer::new(svc)` build (`:501`) and its
  `.add_service(server)` (`:535`). Keep the `DataplaneNodeServer` add_service and the shared
  `Control`.
- [ ] **Step 3:** Change the readiness print `serving DPDKironcore on {addr}` (`:509`) →
  `serving DataplaneNode on {addr}` (record this exact string; Task 3.1 depends on it).
- [ ] **Step 4:** In `build.rs`: remove `"../../api/proto/dataplane/v1/dpdk.proto"` from the
  `compile_protos` list (`:44`), leaving only `dataplane.proto`.
- [ ] **Step 5:** Build: `nix develop --command cargo build -p flowplane` — clean; `flowplane serve`
  now exposes only `DataplaneNode` + health. Run `cargo test -p flowplane-sim` (still green) and a
  DataplaneNode integration/attach smoke if available.
- [ ] **Step 6:** `cargo fmt`; commit: `refactor(flowplane): remove DPDKironcore gRPC; serve only DataplaneNode`.

### Task 3.4: Final sweep
- [ ] **Step 1:** `grep -rniE 'dpdkironcore|DpdKironcore|dpservice-cli|DPDKironcore' --exclude-dir=target --exclude-dir=.git .`
  — expected: only intentional history (the two 2026-07-17 conformance spec/plan docs, the
  ectobase-rename references, and any legacy note explicitly describing the removal). No live code
  or build wiring. Fix stragglers.
- [ ] **Step 2:** Full gate: `cargo build -p flowplane && cargo test -p flowplane-sim` +
  `cd netplane && go build ./... && go test ./...` + `cd test/e2e && go build ./...`. All green.
- [ ] **Step 3:** Commit any straggler fixes: `chore: final de-dpservice sweep`.

---

## Final

- [ ] Dispatch a final review over the branch; then `superpowers:finishing-a-development-branch`.
- [ ] Update memory: `[[dpservice-port-model]]` (dpservice is now conformance-removed, not a live
  API surface) and `[[compiled-nic-synthetic-testing]]` (sim is now the conformance source of
  truth; add the coverage areas) and `[[ectobase-rename]]` (the DPDKironcore-removal follow-through).

## Self-review notes

- **Spec coverage:** §1 remove → Phase 3; §2 sim expansion → Phase 1 (NAT/DHCP/ARP-ND/VNI/timeout);
  §3 Go smoke → Phase 2; §3b clab continuity → Phase 2b; §4 netns scripts → Task 3.1. Coverage-map
  → Task 1.6.
- **Safety order:** Phases 1–2b (build native replacement) strictly precede Phase 3 (delete oracle).
- **No-guess rule for wire formats:** every sim test task says "read the responder source first" —
  packet byte-vectors are derived against real code at implementation time, not guessed in the plan.
- **Cross-task consistency:** the new readiness string (`serving DataplaneNode on`) is defined in
  Task 3.3 Step 3 and consumed by Task 3.1 Step 1.
