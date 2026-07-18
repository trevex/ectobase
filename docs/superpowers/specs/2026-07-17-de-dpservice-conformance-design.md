# De-dpservice the Conformance — Design

**Status:** Approved (design); pending spec review
**Date:** 2026-07-17

## Summary

Break the dpservice API + test lineage. Today `flowplane serve` exposes **two** gRPC services:
the native **`DataplaneNode`** (`dataplane.v1`, used by `cni` + `netplane` in production) and the
dpservice-compatible **`DPDKironcore`** (`dpdkironcore.v1`, ~600-line `dpdk.proto`) that exists
*only* so the vendored dpservice Python conformance suite + `dpservice-cli` can drive the datapath.
We remove `DPDKironcore` entirely and make conformance **native**: the in-process Rust sim
(`flowplane-sim`) becomes the source of truth for packet-level behavior, backed by a **thin Go
live smoke** in `test/e2e` that exercises the real stack (real `flowplane`, real `DataplaneNode`
gRPC, real veth/netns) to catch sim↔real gaps.

Net effect: −~600 LOC proto, −~5000 LOC vendored Python, −1 external dependency
(`dpservice-cli`), −1 test language (Python); a single gRPC surface (`DataplaneNode`); conformance
that is native, fast, and deterministic.

## Current state (why this is safe)

- **`DataplaneNode` is production.** `cni/plugin` (`AttachInterface`/`DetachInterface`) and
  `netplane/agent` (routes/NAT/LB/FW) drive it via the generated Go client
  (`cni/gen/dataplanev1`). `flowplane` serves it from `node.rs`/`control.rs`/`attach.rs`.
- **`DPDKironcore` is conformance-only.** Served from `flowplane/flowplane/src/main.rs`
  (`DpdKironcoreServer`, sharing one `Control` with `DataplaneNode`). Its only callers are
  `test/conformance/*` (Python, via `dpservice-cli`) and the `test/*-netns.sh` dev scripts.
  Nothing in `cni`/`netplane` uses it.
- **The vendored suite** (`test/conformance/`, ~5000 LOC Python vendored from
  ironcore-dev/dpservice v0.3.22) drives `flowplane` through `dpservice-cli`→`DPDKironcore` and
  asserts packets with scapy. Much of it tests dpservice concepts that do not map to our CNI
  model (`test_virtsvc`, `test_pf_to_vf`/`test_vf_to_pf` SR-IOV representors, `test_telemetry`,
  the dpservice error-code table).
- **The sim** (`flowplane-sim`) + `BPF_PROG_TEST_RUN` byte-parity anchors already give native,
  in-process, packet-level validation for: encap, LB (select + NS/EW scenarios, anycast,
  reforward, policy interplay), firewall (deny-by-default, ingress allow), conntrack create, and
  the north-south external↔guest encap/decap/FW/CT path.

## Architecture: test at the right level

Each concern is asserted at the *cheapest level that can actually observe it* — sim for
determinism, Go e2e for the real gRPC/attach + connectivity, clab for behaviors that only
manifest under real continuous forwarding.

1. **Sim conformance (source of truth)** — `flowplane-sim`, native Rust, in-process,
   deterministic, no netns. Drives the pure core + real eBPF programs (via `BPF_PROG_TEST_RUN`)
   with `VecPkt` and asserts on exact bytes/verdicts. Owns byte-level behavior.
2. **Thin Go live smoke** (`test/e2e`) — a handful of end-to-end cases through the real stack;
   catches what the sim structurally cannot at the *control/connectivity* level: real program
   load/attach, real veth redirect, real gRPC over the wire, real DHCP client exchange, and
   graceful-restart **state survival** (adoption, no /128 reissue — asserted via `DataplaneNode`).
3. **clab continuity tests** (`test/scenario-*.sh`) — the things that only appear under real,
   continuous forwarding through the kernel: most importantly **zero-drop across a graceful
   restart** (the link-pinning guarantee), and native-XDP-only behaviors. A continuous flow runs
   *through* the datapath while `flowplane` is `crictl`-restarted; the test asserts ~0 packet
   loss + the eBPF prog-id atomically swaps (re-point, not detach). This is where "traffic is not
   dropped" is actually proven — a programmatic Go assertion cannot see a sub-second forwarding
   gap the way a continuous in-fabric flow can.
4. **`DataplaneNode` — the one and only control API.** No compatibility shim.

**Principle — test where sensible:** determinism/bytes → sim; real API + attach + connectivity →
Go e2e; real continuous forwarding / zero-drop / native-XDP → clab. Don't push a concern to a
heavier level than needed, and don't assert a forwarding-continuity property at a level that
can't observe it.

## §1 — Remove (break the lineage)

- `api/proto/dataplane/v1/dpdk.proto` + generated `dpdkproto` + the Makefile proto-dpdk target.
- The `DpdKironcoreServer` service impl + its wiring in `main.rs`; after this `flowplane serve`
  adds only `DataplaneNodeServer` + health. (Keep the shared `Control`; just drop the second
  `add_service`.)
- The `dpservice` / `dpservice-cli` flake input + `packages.dpservice-cli` in `flake.nix`, and
  its devShell PATH entry.
- `test/conformance/` (the vendored Python suite), `bin/dpservice-cli`, `VENDORED.md`,
  `DPSERVICE_ERROR_CODES.txt`.

## §2 — Complete the pure core, THEN add sim conformance (scope-expanded 2026-07-17)

**Discovery during implementation:** the behaviors we want the sim to assert (guest-egress NAT
SNAT/DNAT, the DHCP/ARP/ND responders, guest-egress routing/VNI) live **entirely in
`flowplane-ebpf` glue** — raw `data/data_end` pointers reading eBPF-`#[map]` statics — NOT in
`flowplane-core`. The sim drives only `flowplane-core` (via the `Pkt`/`Maps` traits), whose
surface today covers the *middle* transforms (encap `write_outer_v6`, `decap_and_rewrite`,
firewall `fw_eval`, conntrack, LB `lb_select`/`reforward`) but none of the guest-facing paths.
So the sim cannot assert these behaviors without first extracting them into the pure core.

**Decision (user, 2026-07-17): extract everything into `flowplane-core`.** Port the full guest
datapath out of ebpf glue into the pure core against `Pkt`/`Maps`, following the existing
precedent (`decap_and_rewrite`, `write_outer_v6`). This strengthens the pure-core/sim pattern and
makes the whole datapath deterministically testable. It is a real datapath refactor and precedes
the conformance tests.

**Extraction unit (per path — the load-bearing pattern):**
1. Add the `Maps`-trait accessors the path needs (+ `MemMaps` impl for the sim): e.g. a NAT-map
   accessor `nat_get`/`nat_insert`, a route/underlay accessor for the egress path, a DHCP-config
   accessor. (Some exist: `local`, `underlay_get`, `conntrack_*`, `fw_*`, `lb_get`, `maglev_get`.)
2. Write a core fn `…_core<P: Pkt, M: Maps>(…)` implementing the logic against the traits.
3. Replace the ebpf glue's inline impl with a call to the core fn (via `CtxPkt`/`RawPkt` +
   `GlobalMaps`) — the ebpf program now *calls* the core, it doesn't reimplement it.
4. Add a `SimNode` entry point (e.g. `guest_tx`) that calls the same core fn via `VecPkt`/`MemMaps`.
5. **Prove byte-parity:** a `BPF_PROG_TEST_RUN` anchor (the real eBPF program) and the sim (the
   core fn) MUST produce byte-identical output for the same input. This is the safety gate for
   touching the hot datapath — no behavior change is allowed, only relocation.
6. Then write the conformance test against the core fn.

**Paths to extract, then assert:**
- **Guest-egress routing + NAT SNAT** — `forward_decision_v4/v6` (eBPF-map-coupled) +
  `nat.rs::nat_snat_egress`. Enables NAT-SNAT + VNI-isolation conformance.
- **DNAT (return)** — the `conntrack.rs` `CT_REWRITE_DST` apply invoked from `ingress.rs`.
- **DHCPv4 / DHCPv6 responder** — offer/reply builder (assigned IP, MTU, DNS from `DHCP_CONFIG`).
- **ARP + IPv6 ND responder** — `arp_nd.rs` gateway reply builders.
- **VNI isolation** — falls out of the extracted guest-egress routing (route LPM keyed by VNI).
- **Flow timeout** — conntrack expiry; `conntrack_*` is already on the `Maps` trait, so this one
  is likely sim-reachable today without extraction (verify first).

**Dropped (dpservice-only; not our model):** `virtsvc`, SR-IOV PF/VF representor
(`pf_to_vf`/`vf_to_pf`), dpservice telemetry, dpservice error-code conformance.

## §3 — Thin Go live smoke (`test/e2e`)

A small set of end-to-end cases in the existing Go `test/e2e` suite (which already orchestrates
the clab fabric + netns exec), programming the datapath via the generated `DataplaneNode` Go
client and asserting with `ping`/`nc` for connectivity and `goscapy`
(github.com/smallnest/goscapy) only where packet inspection is required:

- **Program load + attach** — `flowplane serve` loads the eBPF object and attaches on real veth
  (verifier-anchor already covers load; this covers real attach + a DataplaneNode round-trip).
- **Guest egress via NAT** reaches an external target (connectivity + the SNAT'd source is what
  the target sees).
- **LB distributes** across ≥2 backends (connectivity + distribution).
- **DHCP lease** — a real client on a tap/veth gets a lease (goscapy inspects the offer).
- **Graceful-restart state survival** — `crictl` kill of `flowplane`; datapath state survives, no
  /128 reissue, asserted through `DataplaneNode` (the *control-plane* half of graceful restart).

`goscapy` is added as a `test/e2e` Go dependency. Cases needing byte-exact assertions stay in the
sim; the smoke asserts "works end-to-end through the real kernel + gRPC." The *forwarding-continuity*
half of graceful restart (zero drop) is NOT a Go smoke case — it lives in clab (§3b) because a
programmatic assertion can't observe a sub-second gap.

## §3b — clab graceful-restart continuity (zero-drop)

Formalize the link-pinning zero-gap guarantee as a repeatable clab test (evolve the existing
`test/scenario-restart.sh`):

- Bring up the clab fabric with a guest whose traffic transits the `flowplane` datapath.
- Start a **continuous flow** across the restart boundary — e.g. `ping -i 0.2` (or a small UDP/TCP
  stream with a sequence counter) between a guest and a peer/edge, through the datapath.
- `crictl stop` / restart the `flowplane` container (rolling-upgrade path: same or new bytecode).
- **Assert:** packet loss is ~0 (allow a tiny bounded threshold), the pinned bpf-link survived the
  stop, and the eBPF prog-id on the uplink/guest interfaces **atomically swapped** (re-point via
  `bpf_link_update`, not a detach/re-attach). This reproduces the live-validated result
  (prog-id 31133→31168, pin survives) as a checked-in, repeatable test.
- Runs under sudo on the clab host (the established `sudo -E` + nix-flake harness); gated in CI as
  a privileged/manual scenario, not a unit test.

## §4 — The dev netns scripts (`test/*-netns.sh`)

These currently drive the datapath via `dpservice-cli`→`DPDKironcore`. Disposition:
- **Re-point** the still-useful manual drivers to `grpcurl` against `DataplaneNode` (zero new
  code; `DataplaneNode` is a normal gRPC service — drive it with `grpcurl` + the proto).
- **Drop** the ones fully superseded by the sim or the Go smoke.
The plan enumerates each script's disposition; none are load-bearing for CI (CI uses cargo tests
+ the Go e2e smoke).

## §5 — Order (safety: never delete the oracle before its replacement proves out)

1. **Expand the sim** (§2) — land the native coverage first.
2. **Build the Go live smoke** (§3).
3. **Only then remove** `DPDKironcore` + the Python suite + `dpservice-cli` (§1) and re-point/drop
   the netns scripts (§4).

Removing the dpservice oracle before the native coverage exists would open a conformance gap; this
ordering keeps a working oracle until the replacement is proven.

## Coverage mapping (dpservice Python suite → destination)

| Python test | Destination |
|---|---|
| `test_encap` | sim (already) |
| `test_lb` | sim (already, extensive) |
| `test_flows` | sim conntrack (+ add flow-timeout) |
| `test_nat` | **sim (add NAT suite)** + live smoke (egress reaches target) |
| `test_dhcpv4` / `test_dhcpv6` | **sim (add DHCP responder)** + live smoke (real lease) |
| `test_arp` / `test_ipv6_nd` | **sim (add ARP/ND responder)** |
| `test_vni` | **sim (add VNI isolation)** |
| `test_vf_to_vf` | sim guest↔guest + live smoke connectivity |
| `test_zzz_grpc` (API surface) | covered by `DataplaneNode` unit/integration tests |
| `xtratest_ha` / `xtratest_flow_timeout` | Go smoke (restart **state survival**) + clab §3b (restart **zero-drop continuity**) + sim (flow timeout) |
| `test_virtsvc`, `test_pf_to_vf`, `test_vf_to_pf`, `test_telemetry` | **dropped** (dpservice-only) |

## Non-goals

- No change to the `DataplaneNode` API surface or any datapath behavior — this is a
  test/lineage change, not a datapath change.
- No new packet-assertion framework in Rust beyond what `flowplane-sim` already provides.
- Not a 1:1 port of the dpservice suite — it is a re-scoping to our CNI semantics.

## Risks

- **Datapath-refactor risk (NEW, the biggest).** The §2 extraction moves hot-path code
  (NAT/routing/DHCP/ARP-ND) from ebpf glue into `flowplane-core`. Any behavioral drift is a
  production bug. Mitigated by the mandatory per-path **byte-parity anchor** (`BPF_PROG_TEST_RUN`
  real-program output == sim core-fn output) — extraction is proven a pure relocation, and the
  ebpf verifier must still accept the refactored programs. Extract one path at a time, each gated.
- **Coverage regression** if a dpservice test asserted something our sim/smoke misses. Mitigated
  by §5 ordering (oracle stays until replacement proven) and the coverage-mapping table (every
  applicable Python test has a named destination before removal).
- **goscapy maturity** — smaller/less battle-tested than scapy; mitigated by keeping byte-exact
  assertions in the sim and using goscapy only for a few inspection cases.

## Scope note

The §2 "extract everything into core" decision makes this initiative substantially larger than a
test rewrite — it is a datapath-architecture effort (completing the pure core) that *enables* the
conformance. It may warrant being tracked/executed as its own phase set, extracting one path at a
time behind byte-parity gates, before the dpservice-removal phase.
