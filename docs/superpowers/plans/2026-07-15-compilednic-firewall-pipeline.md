# CompiledNIC → Dataplane Firewall Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the distributed firewall unconditional (always-on deny-by-default — remove the enforce flag) and build the control-plane pipeline that installs its rules: a compiler controller writes `CompiledNIC` objects, and the per-node agent pushes their firewall rules to the dataplane via `AddFwRule`.

**Architecture:** Rust datapath drops on a deny verdict unconditionally (delete `fw_enforcing()`/`FW_CONFIG`/flag). A Go compiler controller reconciles `NetworkInterface`+`NetworkPolicy` → `CompiledNIC` (via the existing `Compile()`, which already emits per-direction allow-all). The node agent watches `CompiledNIC` for its node and reconciles firewall rules onto the dataplane. Conformance owns the firewall posture (allow-all per VM).

**Tech Stack:** Rust (aya eBPF, `xdp-dp-core`/`xdp-dp-sim`), Go (controller-runtime, envtest), gRPC (`DataplaneNode.AddFwRule`/`DelFwRule` — already defined), Python conformance.

**Parent spec:** `docs/superpowers/specs/2026-07-15-compilednic-firewall-pipeline-design.md`

---

## Key existing facts (verified)

- Enforce gate call sites: `xdp-dp-ebpf/src/ingress.rs:258` (`&& crate::firewall::fw_enforcing()`), `egress.rs:57` (same), `xdp-dp-sim/src/sim.rs:119` (`&& self.maps.fw_enforcing()`).
- `fw_enforcing()` in `xdp-dp-ebpf/src/firewall.rs`; `FW_CONFIG` map in `maps.rs:51`; `FwConfig` opener in `xdp-dp/src/maps.rs:341`; `firewall_enforce` clap flag in `xdp-dp/src/main.rs:209` + `fw_config.set(...)` at `~856`.
- `Maps::fw_enforcing` in `xdp-dp-core/src/maps.rs`; `GlobalMaps::fw_enforcing` in `xdp-dp-ebpf/src/coreimpl.rs:38`; `MemMaps.fw_enforcing` field `xdp-dp-sim/src/maps.rs:14` + impl `:39`.
- Sim tests referencing `fw_enforcing`: `sim.rs:119`, `fabric.rs:202,218,220`, `ns_scenario_test.rs:48`, `compilednic.rs:148,171`, `firewall_test.rs:59` (comment).
- BPF anchors set `FW_CONFIG=1`: `xdp-dp/tests/anchor_uplink.rs`, `xdp-dp/tests/anchor_lb.rs`.
- `AddFwRuleRequest{ interface_id, rule_id, src_cidr, dst_cidr, proto:uint32, dst_port_min, dst_port_max, allow:bool, egress:bool }`; `DelFwRuleRequest{ interface_id, rule_id }`. `interface_id` = the id used at `AttachInterface` (conformance keys by VM name).
- `Dataplane` interface + `dpAdapter` in `netplane/agent/bus.go` (mirror `AddNatSource`). Agent reconcile in `netplane/agent/reconcile.go` (`Desired()`).
- Controller pattern: `netplane/controllers/natgateway.go` (`Reconcile`/`Sync`/`SetupWithManager`/`Watches`). Pure `Compile()` in `compilednic.go`.
- `CompiledFwRule{ CIDR, Proto, Port int32, Action }` (CIDR = dst; src = any). Ingress/Egress lists on `CompiledFirewall`.

---

## Task 1: Remove the firewall enforce gate — dataplane always enforces (Rust)

**Files:** Modify `xdp-dp-ebpf/src/{firewall.rs,maps.rs,ingress.rs,egress.rs,coreimpl.rs}`, `xdp-dp/src/{maps.rs,main.rs}`, `xdp-dp-core/src/maps.rs`, `xdp-dp-sim/src/{maps.rs,sim.rs,fabric.rs,ns_scenario_test.rs,compilednic.rs,firewall_test.rs}`, `xdp-dp/tests/{anchor_uplink.rs,anchor_lb.rs}`.

- [ ] **Step 1: Remove `fw_enforcing` from the `Maps` trait + impls.**
  - `xdp-dp-core/src/maps.rs`: delete the `fn fw_enforcing(&self) -> bool;` trait method.
  - `xdp-dp-ebpf/src/coreimpl.rs`: delete the `GlobalMaps::fw_enforcing` impl (lines ~35-39).
  - `xdp-dp-sim/src/maps.rs`: delete the `pub fw_enforcing: bool` field (line 14) and the `fn fw_enforcing(&self)` impl (line ~38-40).

- [ ] **Step 2: Drop unconditionally in the eBPF gates.**
  - `xdp-dp-ebpf/src/ingress.rs`: at the firewall check (~248-261), remove `&& crate::firewall::fw_enforcing()` so the condition is `if ct miss && fw_eval_dir(...) == FW_ACTION_DROP { return Ok(XDP_DROP); }`.
  - `xdp-dp-ebpf/src/egress.rs:57`: remove `&& crate::firewall::fw_enforcing()` similarly.

- [ ] **Step 3: Delete `fw_enforcing()` + `FW_CONFIG` + `FwConfig` + the flag.**
  - `xdp-dp-ebpf/src/firewall.rs`: delete the whole `fw_enforcing()` fn and `use crate::maps::FW_CONFIG;` (the file may then be empty except a doc comment — if so, remove `mod firewall;` from `main.rs` and delete the file; verify nothing else in the eBPF crate references `crate::firewall::*`).
  - `xdp-dp-ebpf/src/maps.rs:51`: delete the `FW_CONFIG` `#[map]` static.
  - `xdp-dp/src/maps.rs:340-...`: delete the `FwConfig` struct + its opener.
  - `xdp-dp/src/main.rs`: delete the `firewall_enforce` clap field (~209-211) and the `let mut fw_config = ...; fw_config.set(...)` lines (~855-856). Remove `firewall_enforce` from the destructuring (~479).

- [ ] **Step 4: Update the sim (drop is unconditional).**
  - `xdp-dp-sim/src/sim.rs:119`: change the firewall gate to drop without `&& self.maps.fw_enforcing()`:
    ```rust
    if let Some(key) = ct_key(&pkt, inner_off, vni) {
        if self.maps.conntrack_get(&key).is_none()
            && fw_eval_dir(&pkt, &self.maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
        {
            return SimOut { action: Action::Drop, pkt: pkt.into_bytes() };
        }
    }
    ```
  - `xdp-dp-sim/src/compilednic.rs`: in `apply()` delete `m.fw_enforcing = true;` (line 148); in the test delete the `assert!(maps.fw_enforcing, ...)` (line 171).
  - `xdp-dp-sim/src/ns_scenario_test.rs:48`: delete `node.maps.fw_enforcing = true;` in `allow_tcp` (the rule alone now governs).
  - `xdp-dp-sim/src/firewall_test.rs`: update the `deny_by_default_when_no_rules` doc comment (line ~59) to drop the "gated by `fw_enforcing()`" clause — the drop is now unconditional.

- [ ] **Step 5: Fix the Fabric 2-node test (backend now needs an explicit allow rule).** In `xdp-dp-sim/src/fabric.rs` the 2-node test currently sets `backend.maps.fw_enforcing = false` (lines ~202,218,220) to accept without a rule. Under always-on deny-by-default that would DROP. Replace those with an explicit allow-all ingress rule on the backend tap:
    ```rust
    // Always-on deny-by-default: the backend needs an explicit allow rule to deliver.
    backend.maps.fw_meta.insert(BACKEND_TAP, xdp_dp_common::FwMeta { ingress_count: 1, egress_count: 0 });
    backend.maps.fw_rules.insert((BACKEND_TAP, 0), xdp_dp_common::FwRule {
        src_ip: [0;4], src_mask: [0;4], dst_ip: [0;4], dst_mask: [0;4],
        src_port_min: 0, src_port_max: 65535, dst_port_min: 0, dst_port_max: 65535,
        icmp_type: 0xffff, icmp_code: 0xffff, proto: 0,
        action: xdp_dp_common::FW_ACTION_ACCEPT, direction: xdp_dp_common::FW_DIR_INGRESS, enabled: 1,
    });
    ```
    (Use the backend tap constant the test already defines; delete the `fw_enforcing = false` lines + their comments.)

- [ ] **Step 6: Update the BPF anchors (no `FW_CONFIG`).** In `xdp-dp/tests/anchor_uplink.rs` and `anchor_lb.rs`, delete the code that opens/sets `FW_CONFIG` (the map no longer exists). The anchors already install an allow rule, so delivery still holds. Keep everything else.

- [ ] **Step 7: Build + sim tests.**
  Run: `cargo build -p xdp-dp` → compiles (eBPF).
  Run: `cargo test -p xdp-dp-core -p xdp-dp-sim` → PASS (all sim tests green; `deny_by_default_when_no_rules` still drops).

- [ ] **Step 8: BPF anchors byte-parity.**
  Run: `nix develop -c bash -c 'make sim-anchor'` → both anchors PASS (byte-parity; no FW_CONFIG).
  (Conformance is NOT run here — it will fail until Task 2 installs allow-all per VM.)

- [ ] **Step 9: Commit.**
  ```bash
  git add xdp-dp-ebpf xdp-dp xdp-dp-core xdp-dp-sim
  git commit -m "feat(fw): firewall enforcement is unconditional (remove fw_enforcing/FW_CONFIG/flag)"
  ```

---

## Task 2: Conformance owns the firewall posture (allow-all per VM)

**Files:** Modify `test/conformance/{conftest.py or dp_service.py or grpc_client.py}`, `test/conformance/test_vf_to_vf.py`.

- [ ] **Step 1: Install an allow-all rule per VM at setup.** Find where interfaces are created (`grpc_client.addinterface` calls in `conftest.py`/`dp_service.py`, ~line 110). After each `addinterface`, add an allow-all ingress AND egress rule via the existing `grpc_client.addfwallrule` helper:
    ```python
    # Always-on deny-by-default firewall: give every conformance VM an explicit allow-all so the
    # datapath-parity tests forward. (Firewall-specific tests add their own narrower rules.)
    grpc_client.addfwallrule(VM.name, f"allow-all-in-{VM.name}", src_prefix="0.0.0.0/0", dst_prefix="0.0.0.0/0", action="accept", direction="ingress")
    grpc_client.addfwallrule(VM.name, f"allow-all-eg-{VM.name}", src_prefix="0.0.0.0/0", dst_prefix="0.0.0.0/0", action="accept", direction="egress")
    ```
    Apply for every VM the suite brings up (VM1..VM4). Put it in the shared fixture that creates interfaces so all tests inherit it.

- [ ] **Step 2: Re-enable the deny test.** In `test/conformance/test_vf_to_vf.py`, delete the `pytest.skip("Skipping till firewall gets fully enabled")` in `test2_vf_to_vf_firewall_tcp` (~line 66). NOTE: with an allow-all already installed, a *narrower* deny won't take effect unless it's evaluated first. The datapath returns the FIRST matching rule, so the deny test must install its rule at a lower index/priority than the allow-all — OR the test should DELETE the allow-all for that VM first. Simplest: in `test2`, delete the VM's allow-all ingress rule before adding the deny rule, and restore it after. Implement that in the test.

- [ ] **Step 2b: Run — verify the deny test fails first (rule ordering), then fix.** Run just `test2` (below). If it doesn't drop because the allow-all matches first, adjust per Step 1's note (remove allow-all in the test).
  Run: `nix develop -c bash -c 'CONF_TESTS=test_vf_to_vf.py ./test/conformance/run.sh -k firewall'`
  Expected: both firewall tests PASS (allow delivers; deny drops).

- [ ] **Step 3: Full conformance.**
  Run: `nix develop -c bash -c './test/conformance/run.sh'`
  Expected: full suite green (the previously-skipped deny test now runs and passes; count is 94+ passed / 1 skipped or 95 / 0 — report the exact line).

- [ ] **Step 4: Commit.**
  ```bash
  git add test/conformance
  git commit -m "test(conformance): install allow-all per VM (own the firewall posture) + re-enable deny test"
  ```

---

## Task 3: Extend the agent `Dataplane` interface with AddFwRule/DelFwRule (Go)

**Files:** Modify `netplane/agent/bus.go`. Test: `netplane/agent/bus_test.go` (or a new `fw_test.go`).

- [ ] **Step 1: Add an agent-side `FwRule` type + interface methods** in `bus.go`:
    ```go
    // FwRule is one compiled firewall rule the agent pushes to the dataplane.
    type FwRule struct {
        SrcCIDR, DstCIDR string // empty = any
        Proto            uint32 // 6/17/1; 0 = any
        DstPortMin       uint32
        DstPortMax       uint32
        Allow            bool
        Egress           bool
    }
    ```
    Add to the `Dataplane` interface:
    ```go
        AddFwRule(ctx context.Context, interfaceID, ruleID string, r FwRule) error
        DelFwRule(ctx context.Context, interfaceID, ruleID string) error
    ```

- [ ] **Step 2: Implement on `dpAdapter`** (mirror `AddNatSource`):
    ```go
    func (d dpAdapter) AddFwRule(ctx context.Context, interfaceID, ruleID string, r FwRule) error {
        _, err := d.c.AddFwRule(ctx, &dpv1.AddFwRuleRequest{
            InterfaceId: interfaceID, RuleId: ruleID,
            SrcCidr: r.SrcCIDR, DstCidr: r.DstCIDR, Proto: r.Proto,
            DstPortMin: r.DstPortMin, DstPortMax: r.DstPortMax,
            Allow: r.Allow, Egress: r.Egress,
        })
        return err
    }
    func (d dpAdapter) DelFwRule(ctx context.Context, interfaceID, ruleID string) error {
        _, err := d.c.DelFwRule(ctx, &dpv1.DelFwRuleRequest{InterfaceId: interfaceID, RuleId: ruleID})
        return err
    }
    ```
    (Verify the generated Go field names on `dpv1.AddFwRuleRequest` — `InterfaceId`/`RuleId`/`SrcCidr`/`DstCidr`/`Proto`/`DstPortMin`/`DstPortMax`/`Allow`/`Egress`. Adjust casing to the actual `*.pb.go`.)

- [ ] **Step 3: Build.** Run: `nix develop -c bash -c 'cd netplane && go build ./...'` → PASS.

- [ ] **Step 4: Commit.**
  ```bash
  git add netplane/agent/bus.go
  git commit -m "feat(agent): AddFwRule/DelFwRule on the Dataplane interface"
  ```

---

## Task 4: Agent firewall reconcile — CompiledNIC → AddFwRule (Go)

**Files:** Create `netplane/agent/fwreconcile.go`. Test: `netplane/agent/fwreconcile_test.go`.

- [ ] **Step 1: Write the failing unit test** `fwreconcile_test.go`. Use a fake controller-runtime client seeded with a `CompiledNIC` for the node, and a mock `Dataplane` recording `AddFwRule` calls:
    ```go
    func TestReconcileFirewall_PushesRules(t *testing.T) {
        c := &netv1.CompiledNIC{
            ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
            Spec: netv1.CompiledNICSpec{
                NodeName: "nodeA",
                NICRef:   netv1.LocalObjectReference{Name: "web-0-nic0"},
                Firewall: netv1.CompiledFirewall{
                    Ingress: []netv1.CompiledFwRule{{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"}},
                    Egress:  []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
                },
            },
        }
        cl := fakeClientWith(c) // sigs.k8s.io/controller-runtime fake client with the scheme
        dp := &mockDataplane{}
        r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
        if err := r.ReconcileFirewall(context.Background()); err != nil { t.Fatal(err) }
        // one ingress rule + one egress rule pushed against interface "web-0-nic0"
        if len(dp.added) != 2 { t.Fatalf("want 2 AddFwRule, got %d: %+v", len(dp.added), dp.added) }
        got := dp.added[0]
        if got.interfaceID != "web-0-nic0" || got.rule.DstCIDR != "10.0.0.0/24" || got.rule.Proto != 6 ||
            got.rule.DstPortMin != 443 || got.rule.DstPortMax != 443 || !got.rule.Allow || got.rule.Egress {
            t.Fatalf("ingress rule wrong: %+v", got)
        }
    }
    ```
    Include a minimal `mockDataplane` (records `AddFwRule`/`DelFwRule`) and `fakeClientWith` helper in the test. Run: `nix develop -c bash -c 'cd netplane && go test ./agent/ -run TestReconcileFirewall'` → FAIL (undefined).

- [ ] **Step 2: Implement `ReconcileFirewall`** in `fwreconcile.go`:
    ```go
    package agent

    import (
        "context"
        "fmt"
        netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
    )

    // ReconcileFirewall lists CompiledNICs scheduled to this node and installs their firewall rules
    // on the dataplane (idempotent: rule ids are deterministic; rules that disappear are deleted).
    func (r *Reconciler) ReconcileFirewall(ctx context.Context) error {
        if r.dp == nil {
            return nil
        }
        var list netv1.CompiledNICList
        if err := r.client.List(ctx, &list); err != nil {
            return fmt.Errorf("list compilednics: %w", err)
        }
        // desired: interfaceID -> ruleID -> FwRule
        desired := map[string]map[string]FwRule{}
        for i := range list.Items {
            c := &list.Items[i]
            if c.Spec.NodeName != r.nodeID {
                continue
            }
            iface := c.Spec.NICRef.Name
            rules := desired[iface]
            if rules == nil {
                rules = map[string]FwRule{}
                desired[iface] = rules
            }
            for idx, cr := range c.Spec.Firewall.Ingress {
                rules[fmt.Sprintf("fw-in-%d", idx)] = compiledToFw(cr, false)
            }
            for idx, cr := range c.Spec.Firewall.Egress {
                rules[fmt.Sprintf("fw-eg-%d", idx)] = compiledToFw(cr, true)
            }
        }
        // Apply. (Add-only for v1; diff/delete against a cache is Step 3.)
        for iface, rules := range desired {
            for ruleID, fr := range rules {
                if err := r.dp.AddFwRule(ctx, iface, ruleID, fr); err != nil {
                    return fmt.Errorf("AddFwRule %s/%s: %w", iface, ruleID, err)
                }
            }
        }
        r.appliedFw = desired // remember for the next reconcile's diff
        return nil
    }

    func compiledToFw(cr netv1.CompiledFwRule, egress bool) FwRule {
        return FwRule{
            SrcCIDR: "0.0.0.0/0", DstCIDR: cr.CIDR, Proto: protoNum(cr.Proto),
            DstPortMin: uint32(cr.Port), DstPortMax: uint32(cr.Port),
            Allow: cr.Action == "Allow", Egress: egress,
        }
    }
    func protoNum(s string) uint32 {
        switch s {
        case "TCP", "tcp": return 6
        case "UDP", "udp": return 17
        case "ICMP", "icmp": return 1
        default: return 0
        }
    }
    ```
    Add an `appliedFw map[string]map[string]FwRule` field to `Reconciler` (in `reconcile.go`). Run the test → PASS.

- [ ] **Step 3: Add the idempotent delete diff + a test.** Extend `ReconcileFirewall` so rule ids present in `r.appliedFw` but absent from `desired` are `DelFwRule`d before applying the new set. Write `TestReconcileFirewall_DeletesStaleRules` (first reconcile with 2 ingress rules, second with 1 → asserts one `DelFwRule`). Implement + PASS.

- [ ] **Step 4: Commit.**
  ```bash
  git add netplane/agent
  git commit -m "feat(agent): reconcile CompiledNIC firewall rules onto the dataplane (idempotent)"
  ```

---

## Task 5: Compiler controller — Reconciler for CompiledNIC (Go)

**Files:** Modify `netplane/controllers/compilednic.go`. Test: `netplane/controllers/compilednic_envtest_test.go`.

- [ ] **Step 1: Add a `Reconciler`** to `compilednic.go` (alongside the pure `Compile()`), following `natgateway.go`:
    ```go
    type Reconciler struct{ Client client.Client }

    func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
        var nic netv1.NetworkInterface
        if err := r.Client.Get(ctx, req.NamespacedName, &nic); err != nil {
            return ctrl.Result{}, client.IgnoreNotFound(err)
        }
        var policies netv1.NetworkPolicyList
        if err := r.Client.List(ctx, &policies, client.InNamespace(nic.Namespace)); err != nil {
            return ctrl.Result{}, fmt.Errorf("list networkpolicies: %w", err)
        }
        compiled := Compile(&nic, policies.Items)
        // CreateOrUpdate the CompiledNIC (owner ref -> nic for GC).
        var existing netv1.CompiledNIC
        key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
        switch err := r.Client.Get(ctx, key, &existing); {
        case apierrors.IsNotFound(err):
            if err := controllerutil.SetControllerReference(&nic, &compiled, r.Client.Scheme()); err != nil {
                return ctrl.Result{}, err
            }
            if err := r.Client.Create(ctx, &compiled); err != nil {
                return ctrl.Result{}, fmt.Errorf("create compilednic: %w", err)
            }
        case err != nil:
            return ctrl.Result{}, err
        default:
            existing.Spec = compiled.Spec
            if err := r.Client.Update(ctx, &existing); err != nil {
                return ctrl.Result{}, fmt.Errorf("update compilednic: %w", err)
            }
        }
        return ctrl.Result{}, nil
    }

    func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
        return ctrl.NewControllerManagedBy(mgr).
            For(&netv1.NetworkInterface{}).
            Owns(&netv1.CompiledNIC{}).
            Watches(&netv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPolicy)).
            Complete(r)
    }

    // nicsForPolicy re-triggers the NICs a policy selects (namespace-scoped, matching by labels).
    func (r *Reconciler) nicsForPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
        pol, ok := obj.(*netv1.NetworkPolicy)
        if !ok || pol.Spec.InterfaceSelector == nil {
            return nil
        }
        sel, err := metav1.LabelSelectorAsSelector(pol.Spec.InterfaceSelector)
        if err != nil {
            return nil
        }
        var nics netv1.NetworkInterfaceList
        if err := r.Client.List(ctx, &nics, client.InNamespace(pol.Namespace)); err != nil {
            return nil
        }
        var reqs []reconcile.Request
        for i := range nics.Items {
            if sel.Matches(labels.Set(nics.Items[i].Labels)) {
                reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
                    Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name}})
            }
        }
        return reqs
    }
    ```
    Add imports (`ctrl`, `client`, `handler`, `reconcile`, `types`, `apierrors`, `controllerutil`, `labels`, `metav1`, `fmt`) — mirror `natgateway.go`'s import block.

- [ ] **Step 2: Write the envtest** `compilednic_envtest_test.go` (mirror `natgateway_envtest_test.go` bring-up): start envtest, register the scheme, run the `Reconciler`; create a `NetworkInterface` (labels `{role: frontend}`, status vni/underlay/port) + a matching `NetworkPolicy`; then poll (`Eventually`) for the `CompiledNIC` object and assert its `Spec.Firewall.Ingress` has the policy rule and `Spec.Firewall.Egress` has the per-direction allow-all. Also assert an UNPOLICIED NIC yields ingress+egress allow-all.
  Run: `nix develop -c bash -c 'cd netplane && go test ./controllers/ -run TestCompiledNICReconciler'` → PASS (requires `KUBEBUILDER_ASSETS`, provided by the flake).

- [ ] **Step 3: Commit.**
  ```bash
  git add netplane/controllers
  git commit -m "feat(controller): CompiledNIC compiler reconciler (NIC+NetworkPolicy -> CompiledNIC)"
  ```

---

## Task 6: Wire into the manager + agent loop; docs

**Files:** Modify `netplane/cmd/*` (the controller-manager + the agent entrypoints), `README.md`.

- [ ] **Step 1: Register the compiler controller.** Find where `natgateway.Reconciler` is registered with the controller-runtime manager (grep `SetupWithManager` in `netplane/cmd`). Register the new `controllers.Reconciler{Client: mgr.GetClient()}` the same way. Run: `nix develop -c bash -c 'cd netplane && go build ./...'` → PASS.

- [ ] **Step 2: Call `ReconcileFirewall` in the agent loop.** Find the agent's reconcile driver (where `Reconciler.Desired()` is called on a timer/watch, in `netplane/cmd` or `netplane/agent`). Add a `r.ReconcileFirewall(ctx)` call alongside it (log + continue on error, like the NAT push). Run: `go build ./...` → PASS.

- [ ] **Step 3: Update the README firewall section.** Add a short paragraph: the firewall is always-on deny-by-default; `Compile()` emits per-direction allow-all for unpolicied NICs; the compiler controller writes `CompiledNIC` and the node agent installs the rules via `AddFwRule`. Link the spec.

- [ ] **Step 4: Full regression sweep.**
  Run: `nix develop -c bash -c 'cd netplane && go test ./...'` → PASS (agent + controller tests).
  Run: `cargo test` (workspace) → PASS.
  Run: `nix develop -c bash -c './test/conformance/run.sh'` → green (with the re-enabled deny test).
  Run: `nix develop -c bash -c 'make sim-anchor'` → both anchors byte-parity.

- [ ] **Step 5: Commit.**
  ```bash
  git add netplane README.md
  git commit -m "feat(control-plane): register CompiledNIC compiler + agent firewall reconcile; docs"
  ```

---

## Self-Review notes (for the executor)

- **Task 1 breaks conformance** (VMs go ruleless → deny). That's expected; Task 2 restores it (allow-all per VM). Don't run conformance between Task 1 and Task 2.
- **Rule ordering (Task 2 deny test):** the datapath returns the FIRST matching rule, so a broad allow-all installed at idx 0 shadows a later deny. The deny test must remove the VM's allow-all (or install its deny at a lower index) — implement per Task 2 Step 2.
- **Verify generated names before use:** `dpv1.AddFwRuleRequest` field casing (`InterfaceId`/`RuleId`/`SrcCidr`/...), `CompiledNIC`/`CompiledFwRule`/`NetworkPolicyRule` Go fields, the `Reconciler` struct field names in the agent (`client`/`nodeID`/`dp`/`appliedFw` — match `reconcile.go`).
- **interface_id contract:** the agent keys `AddFwRule` by `CompiledNIC.spec.nicRef.name`; the dataplane must have that same id from `AttachInterface`. If attach keys by a different id, the plan's mapping needs adjustment — confirm against `xdp-dp/src/control.rs`/`grpc.rs` `create_interface`/`add_fw_rule`.
- **Scope:** LB wiring (`AddLbVip`/`AddLbBackend`, `CompiledNIC.LB`) is subproject B — not here.
