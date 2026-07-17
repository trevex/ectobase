# CompiledNIC → Dataplane Firewall Pipeline (Always-On Deny-by-Default) — Design

**Status:** Draft (brainstorm output) — design agreed 2026-07-15.
**Date:** 2026-07-15
**Parent:** the control-plane wiring keystone (sub-project **A** of "wire the control plane"; **B** = LoadBalancer wiring, later).
**Related:** `docs/superpowers/specs/2026-07-15-fabric-sim-lb-coverage-design.md` (firewall posture + the LB DSR gotcha the sim proved), `docs/superpowers/specs/2026-07-02-network-api-design.md` (the CRD set).

---

## 1. Summary

Make the distributed firewall **real and unconditional**, and build the control-plane pipeline that feeds it. Today the datapath firewall logic is deny-by-default (verdict), but nothing installs rules onto real interfaces (no `CompiledNIC` consumer, the agent's `Dataplane` interface has no `AddFwRule`), and enforcement is gated behind a flag. This subproject:

1. Makes firewall enforcement **unconditional** — removes the `fw_enforcing()`/`FW_CONFIG` gate; a DROP verdict always drops. There is no fail-open window: a NIC with no rules fails **closed** (deny) until the control plane installs its rules.
2. Builds the **CompiledNIC → dataplane pipeline**: a compiler controller writes `CompiledNIC` objects from `NetworkInterface`+`NetworkPolicy`; the per-node agent watches them and pushes firewall rules via a new `AddFwRule`.
3. Relies on `Compile()`'s **explicit per-direction allow-all** (already implemented) so unpolicied NICs flow *because of an explicit rule*, not a dataplane default.

**Posture decision (normative):** we no longer target dpservice firewall parity. The firewall is ours: always enforcing, deny-by-default, control-plane-supplied allow-all. Conformance is updated to install allow-all rules per VM.

## 2. Goals / Non-goals

**Goals**
- Firewall enforcement is unconditional (no flag, no map, no gate).
- `CompiledNIC` objects are produced by a compiler controller and consumed by the node agent, which installs firewall rules on the dataplane.
- End-to-end: NIC with no policy → allow-all installed → flows; NIC with a policy → uncovered traffic denied — enforcement always on.

**Non-goals (this subproject)**
- LoadBalancer wiring (`AddLbVip`/`AddLbBackend`, `CompiledNIC.LB`) — subproject **B**.
- Migrating routes/NAT onto `CompiledNIC` — the agent keeps its existing `NetworkInterface`-derived route/NAT logic; only firewall moves onto the `CompiledNIC` pipeline here.
- `AttachInterface` / CNI changes — interfaces are attached as today; this only programs firewall rules for them.
- VirtualIP/floating, VPCPeering.

## 3. Architecture

```
 NetworkInterface + NetworkPolicy          ┌──────────────────────────┐
        │                                  │ compiler controller       │  (central)
        ▼                                  │ Compile() → CompiledNIC    │
 [per-direction allow-all if unpolicied]   └───────────┬──────────────┘
                                                        │ writes CompiledNIC (per node)
                                                        ▼
                                        ┌───────────────────────────────┐
                                        │ node agent (reconcile loop)    │  (per node)
                                        │ watch CompiledNIC for my node  │
                                        │ → dp.AddFwRule / DelFwRule      │
                                        └───────────────┬───────────────┘
                                                        ▼ gRPC (DataplaneNode)
                                   dataplane: FW_RULES / FW_META maps
                                   fw_eval_dir = deny-by-default, ALWAYS enforced
                                   (fw_enforcing() / FW_CONFIG removed)
```

## 4. Components

### 4.1 Datapath cleanup (Rust) — revises commit `1a88241`
- **Remove** `fw_enforcing()` (eBPF `firewall.rs`), the `FW_CONFIG` `#[map]` + `FwConfig` opener (`maps.rs`), and the `firewall_enforce` clap flag + its `fw_config.set(...)` wiring (`main.rs`).
- **Remove** the `Maps::fw_enforcing` trait method (`flowplane-core`), the `GlobalMaps`/`MemMaps` impls, and the `MemMaps.fw_enforcing` field.
- `ingress.rs`/`egress.rs`: the firewall check drops on `fw_eval_dir(...) == FW_ACTION_DROP` **unconditionally** (delete `&& fw_enforcing()`).
- `flowplane-sim` `SimNode::uplink` + the tests: delete the `&& self.maps.fw_enforcing()` gate; drop is unconditional. `deny_by_default_when_no_rules` stays.
- `fw_eval_dir` deny-by-default verdict is unchanged (already correct).

### 4.2 Compiler controller (Go)
- In `netplane/controllers/compilednic.go`, add a `Reconciler` alongside the pure `Compile()`:
  - `SetupWithManager`: `For(&NetworkInterface{})`, `Watches(&NetworkPolicy{}, EnqueueRequestsFromMapFunc(nicsForPolicy))`.
  - `Reconcile`: fetch the NIC (ignore-not-found), list `NetworkPolicy`s, run `Compile(nic, policies)`, and `CreateOrUpdate` the `CompiledNIC` (name from the NIC, `spec.nodeName` carried through, owner ref → NIC for GC).
- Follows the `natgateway.go` structure exactly.

### 4.3 Agent (Go)
- **`Dataplane` interface** (`bus.go`): add
  ```go
  AddFwRule(ctx context.Context, interfaceID, ruleID string, rule FwRule) error
  DelFwRule(ctx context.Context, interfaceID, ruleID string) error
  ```
  `FwRule` is a small agent-side struct (src/dst CIDR, proto, ports, action, direction). `dpAdapter` implements them over `dpv1.DataplaneNodeClient` (RPCs already exist: `AddFwRule`/`DelFwRule`).
- **Reconcile step** (`reconcile.go` or a new `fwreconcile.go`): list `CompiledNIC` where `spec.nodeName == r.nodeID`; for each, translate `spec.firewall.ingress/egress` → `FwRule`s and push via `AddFwRule`. Track applied `(interfaceID, ruleID)` and `DelFwRule` any that disappeared (idempotent reconcile).
- **interface_id mapping:** the dataplane keys firewall rules by the interface id used at `AttachInterface` (the NIC/VM name). The agent maps `CompiledNIC.spec.nicRef.name` → that id. Rule ids are deterministic (e.g. `fw-in-<idx>` / `fw-eg-<idx>`) so reconcile can diff.

### 4.4 Conformance (Python)
- The interface-setup path (`conftest`/`dp_service`/`grpc_client`) installs an **allow-all** ingress+egress rule per VM after `addinterface` (we own the posture; VMs must flow under always-on deny-by-default).
- Re-enable the skipped `test2_vf_to_vf_firewall_tcp` deny test (enforcement is now real) — a rule for a non-matching source should now drop.

## 5. Data flow (happy path)
1. Operator creates `NetworkInterface` (scheduled to node N), optionally a `NetworkPolicy`.
2. Compiler controller reconciles → writes `CompiledNIC` (firewall = policy rules, or per-direction allow-all if unpolicied), `spec.nodeName = N`.
3. Agent on node N sees the `CompiledNIC`, calls `AddFwRule` for each rule against the NIC's interface id.
4. Dataplane `FW_RULES`/`FW_META` now hold the rules; `fw_eval_dir` (always enforcing) permits matching traffic, denies the rest.
5. Before step 3 completes, the interface has no rules → deny-by-default → fails **closed** (correct).

## 6. Error handling
- Compiler: on `Compile()` producing nothing valid (e.g. NIC status not ready), requeue; never write a partial `CompiledNIC` that would open or wrongly close an interface.
- Agent: `AddFwRule` failures are logged + retried on the next reconcile (the loop is level-triggered); a transient dataplane error must not leave a half-applied rule set that opens traffic (prefer applying allow/deny rules atomically per interface where the RPC allows, else order deny-affecting changes last).
- interface not yet attached (no dataplane interface id): skip + requeue; the interface stays fail-closed until attached + rules applied.

## 7. Testing
- **Compiler controller:** envtest (`compilednic_envtest_test.go`, mirroring `natgateway_envtest_test.go`) — NIC + policy → assert the `CompiledNIC` object + its rules (incl. per-direction allow-all). Pure `Compile()` unit tests already exist.
- **Agent:** unit test with a mock `Dataplane` + fake client (mirroring `reconcile_test.go`) — feed `CompiledNIC`s; assert `AddFwRule`/`DelFwRule` calls (add on new rule, del on removal, idempotent on no-change).
- **Dataplane (Rust):** `cargo test -p flowplane-sim` green after removing the enforce gate; both BPF anchors updated (no `FW_CONFIG`) and byte-parity; `deny_by_default_when_no_rules` stays.
- **Conformance:** updated setup (allow-all per VM) + re-enabled deny test → full suite green.
- **Success criterion:** the agent unit test + envtest demonstrate NIC(no policy)→allow-all→flows and NIC(policy)→uncovered-denied, with enforcement unconditionally on.

## 8. Risks & mitigations
- **Conformance churn.** Removing the enforce flag + always-on firewall breaks the vendored suite. *Mitigation:* accepted (we own the posture); update the setup to install allow-all per VM; re-enable the deny test. Keep the non-firewall parity tests unchanged.
- **Cold-start fail-closed.** A NIC drops traffic until the agent installs its rules. *Mitigation:* this is the intended secure default; keep the compiler + agent reconcile latency low (level-triggered, watch-driven).
- **Half-applied rule sets opening traffic.** *Mitigation:* deterministic rule ids + reconcile ordering so a partial apply never yields an unintended allow; the deny-by-default base means "missing rule" = deny, not allow.
- **interface_id contract.** The agent must use the same id the dataplane keyed at attach. *Mitigation:* the plan pins this against `grpc.rs`/`control.rs`; conformance's `addfwallrule` (keyed by VM name) is the reference.

## 9. Out of scope / follow-ons
- **Subproject B:** LoadBalancer controller → `CompiledNIC.LB` + `AddLbVip`/`AddLbBackend`; makes LB work in clab (reuses this pipeline).
- Migrating routes/NAT onto `CompiledNIC` (single-source the agent).
- VirtualIP/floating, VPCPeering.
- A live end-to-end (kind/clab) test of the full pipeline (the agent unit test + envtest + conformance cover the seams here).
