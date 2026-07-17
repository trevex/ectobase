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

## Architecture: three layers after the change

1. **Sim conformance (source of truth)** — `flowplane-sim`, native Rust, in-process,
   deterministic, no netns. Drives the pure core + real eBPF programs (via `BPF_PROG_TEST_RUN`)
   with `VecPkt` and asserts on exact bytes/verdicts.
2. **Thin Go live smoke** — `test/e2e`, a handful of end-to-end cases through the real stack;
   catches only what the sim structurally cannot (real program load/attach, real veth redirect,
   real gRPC over the wire, real DHCP client exchange, graceful-restart adoption).
3. **`DataplaneNode` — the one and only control API.** No compatibility shim.

## §1 — Remove (break the lineage)

- `api/proto/dataplane/v1/dpdk.proto` + generated `dpdkproto` + the Makefile proto-dpdk target.
- The `DpdKironcoreServer` service impl + its wiring in `main.rs`; after this `flowplane serve`
  adds only `DataplaneNodeServer` + health. (Keep the shared `Control`; just drop the second
  `add_service`.)
- The `dpservice` / `dpservice-cli` flake input + `packages.dpservice-cli` in `flake.nix`, and
  its devShell PATH entry.
- `test/conformance/` (the vendored Python suite), `bin/dpservice-cli`, `VENDORED.md`,
  `DPSERVICE_ERROR_CODES.txt`.

## §2 — Sim expansion (close the coverage gap)

Add focused sim conformance for the applicable semantics not yet covered. Each is a
`flowplane-sim` test over the pure core (`VecPkt` + `MemMaps`), with a `BPF_PROG_TEST_RUN`
byte-parity anchor where a real program backs the behavior:

- **NAT** — distributed SNAT source-block allocation (per-source block stability, port-range
  bounds) + DNAT/VIP rewrite. (N-S edge NAT is partially exercised in `ns_scenario_test`; add a
  focused NAT suite.)
- **DHCPv4 / DHCPv6** — the in-datapath responder: offer/reply contents (assigned IP, MTU
  option, DNS servers, lease), driven as request packets through the responder path.
- **ARP + IPv6 ND** — gateway MAC responder: a request in → a correct reply out.
- **VNI isolation** — traffic in VNI A must not resolve/deliver into VNI B.
- **Flow timeout** — conntrack entry expiry (create is already covered; add expiry/eviction).

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
- **Graceful-restart adoption** — `crictl` kill of `flowplane`; datapath state survives, no /128
  reissue (reuses the existing restart scenario, asserted through `DataplaneNode`).

`goscapy` is added as a `test/e2e` Go dependency. Cases needing byte-exact assertions stay in the
sim; the smoke asserts "works end-to-end through the real kernel + gRPC."

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
| `xtratest_ha` / `xtratest_flow_timeout` | live smoke (restart adoption) + sim (timeout) |
| `test_virtsvc`, `test_pf_to_vf`, `test_vf_to_pf`, `test_telemetry` | **dropped** (dpservice-only) |

## Non-goals

- No change to the `DataplaneNode` API surface or any datapath behavior — this is a
  test/lineage change, not a datapath change.
- No new packet-assertion framework in Rust beyond what `flowplane-sim` already provides.
- Not a 1:1 port of the dpservice suite — it is a re-scoping to our CNI semantics.

## Risks

- **Coverage regression** if a dpservice test asserted something our sim/smoke misses. Mitigated
  by §5 ordering (oracle stays until replacement proven) and the coverage-mapping table (every
  applicable Python test has a named destination before removal).
- **goscapy maturity** — smaller/less battle-tested than scapy; mitigated by keeping byte-exact
  assertions in the sim and using goscapy only for a few inspection cases.
