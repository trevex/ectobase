# VPC-peering firewall fix — design

Date: 2026-07-27
Status: approved (pending spec review)
Related memory: `vpc-peering-assertion2-rootcause`, `vpc-peering`, `live-e2e-nat-edge-findings`

## Problem

`test/scenario-vpc-peering.sh` fails: Assertion 1 spurious-passes, Assertion 2
really fails, Assertion 3 spurious-fails. A prior debugging session (on a
heavily-polluted, long-running controller pod) attributed Assertion 2 to the
CompiledNIC controller *accumulating firewall rules from deleted
NetworkPolicies*. A fresh code read shows a different, code-provable root cause,
and reframes the controller claim as a likely pollution artifact.

## Confirmed root cause of Assertion 2 (agent restart + dataplane duplicate-id rejection)

1. The scenario restarts `ds/netplane-agent` at every step (deny apply, peering,
   deny→allow swap) but never restarts the `flowplane` DaemonSet.
2. The agent's `ReconcileFirewall` (`netplane/agent/fwreconcile.go`) diffs the
   desired rules against `r.appliedFw`, an **in-memory** map. After a restart it
   is empty, so the delete-phase prunes nothing.
3. The dataplane keeps its **own persistent shadow** `self.fw`
   (`flowplane/flowplane-control/src/firewall.rs`) that survives agent restarts,
   and `add_fw_rule` **bails `ALREADY_EXISTS` on a duplicate rule id** instead of
   replacing.
4. Rule ids are positional (`fw-in-0`, `fw-in-1`, …). The deny-all rule and the
   later allow rule both map to `fw-in-0`. After the deny→restart→allow swap the
   agent calls `AddFwRule(iface, "fw-in-0", Allow)`; the dataplane still holds
   `fw-in-0 = Deny`, rejects the Allow, and the stale Deny at slot 0 shadows the
   packet (`fw_eval_dir` is first-match-by-index). → cross-VPC ping dropped.

This explains Assertion 2 **with no controller bug**, and it is a **real
production bug**: any agent pod restart (crash, rollout, node drain) reproduces
it, because the agent's diff state is lost while the dataplane's is not.

Corollary latent bug: `detach_interface` calls `remove_fw_rules(tap)`, which
drops only the in-memory shadow — it does **not** clear the BPF `FW_RULES` /
`FW_META` slots. A re-attached interface reusing that ifindex can inherit stale
kernel-map rules. The fix below subsumes this.

## Design

The dataplane is already set-based internally: `fw_reprogram` clears **all**
slots for an ifindex and rewrites from the shadow. We surface that as a
declarative primitive and make the agent drive it statelessly.

### 1. Dataplane — declarative per-interface firewall replace (core fix)

Add a control operation that sets an interface's entire firewall rule set at
once, for v4 and v6:

- `ControlCore::replace_fw_rules(interface_id, ingress: [(rule_id, FwRule)], egress: [...])`
  (and the v6 counterpart, or a single call carrying both families) that sets
  `self.fw` / `self.fw6` for the ifindex to exactly the supplied rules and calls
  the existing `fw_reprogram` / `fw6_reprogram`. Because `fw_reprogram` clears all
  slots first, this is "flush + set" on every call.
- Expose it over the DataplaneNode gRPC as `ReplaceInterfaceFirewall` (proto +
  handler in `flowplane-node`). Request carries `interface_id` and the full
  ordered ingress/egress rule lists; response is empty/ok.

Properties: restart-safe (no in-memory diff to lose), orphan-free (count-shrink
handled — all slots cleared each call), collision-free (no `ALREADY_EXISTS`).

`add_fw_rule` / `del_fw_rule` may remain for now (used elsewhere / tests) but the
agent stops using them. Keep the existing unit tests green; add a test that
`replace_fw_rules` clears stale higher-index slots on shrink and overwrites a
same-id rule whose content changed.

### 2. Agent — push the full desired set, delete the diff cache

`ReconcileFirewall` already builds `desired[iface] -> {ruleID -> FwRule}`. Change
it to build an **ordered** ingress/egress list per interface (preserving
CompiledNIC rule order — index = slot) and call `ReplaceInterfaceFirewall` once
per locally-attached interface. Remove `r.appliedFw` and the add/del-diff logic
entirely. This is what makes the path robust across the agent restarts the
scenario triggers.

Interfaces attached locally but with no rules: send an empty replace (clears any
stale rules). Interfaces not attached yet are skipped, as today.

### 3. Deploy — controller `:8080` metrics bind conflict

`netplane/cmd/controller/main.go` uses default `ctrl.Options`, so
controller-runtime serves metrics on `:8080`. On a `hostNetwork` Deployment with
default RollingUpdate (maxSurge), the new pod can't bind `:8080` while the old
holds it → crashloop; we can't rolling-restart the controller to ship fixes.

Fix: disable the manager metrics server (`Metrics: server.Options{BindAddress: "0"}`)
— nothing scrapes it in this deployment. Belt-and-suspenders: set the Deployment
`strategy: Recreate` in `config/deploy/controller.yaml` so it never surges two
hostNetwork pods. (The agent is a DaemonSet — terminate-then-start per node — so
it is unaffected and needs no change.)

### 4. Scenario tooling — `test/scenario-vpc-peering.sh`

- **Busybox pings.** The kind node has no `ping`, so Assertions 1 & 2 cannot
  actually drive ICMP (Assertion 1 spurious-passes on exec failure; Assertion 2
  cannot run). Stage a static busybox into the guest netns and use `/busybox ping`,
  mirroring the revived DHCP/NAT smokes.
- **Assertion 3 map read.** Drop the in-node nix-`bpftool` absolute-store-path
  exec (the node does not mount the host nix store → false negative). Read the
  map a working way (host-side `hack/clab/bpf-trace.sh`-style, or via gRPC), and
  reconsider the premise: local guests deliver via `INTERFACES`, not `ROUTES`, so
  the overlap-precedence check may need to assert on `INTERFACES` (or be reframed
  as a datapath ping that must land on the local green guest).

### 5. Controller — re-validate, fix only if real

Add a Go envtest: apply a NetworkPolicy that selects a NIC, assert its rule lands
in the CompiledNIC; delete the policy, assert the rule clears. My read is the
controller is correct (Reconcile lists policies fresh and replaces the spec; the
NetworkPolicy delete watch re-enqueues). If the envtest passes, no controller
code change; the memory's accumulation observation was a polluted-pod informer
artifact. Confirm again on the clean live run.

## Validation

- Rust: `flowplane-control` unit tests (replace semantics), existing firewall
  tests green.
- Go: `netplane` unit + envtest (firewall reconcile pushes replace; controller
  delete-clears).
- Live: fresh `hack/clab-up.sh` → deploy stack on k01 → `sudo -E env "PATH=$PATH"
  bash test/scenario-vpc-peering.sh`. Success = all 3 assertions pass on a clean
  run, and green→blue still works. Re-check nothing regressed in the NAT/LB
  scenarios that also program firewall rules.

## Out of scope (follow-ups)

- General NetworkPolicy rule **precedence/ordering** across multiple policies
  selecting one NIC (currently list-order-dependent, first-match). The scenario
  avoids this by replacing (not layering) policies. Defining explicit precedence
  (allow-wins / priority field) is a separate design.
- Removing `add_fw_rule` / `del_fw_rule` if they become fully unused.
