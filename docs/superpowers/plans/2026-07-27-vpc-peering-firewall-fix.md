# VPC-peering Firewall Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make firewall programming converge statelessly so a policy change across an agent restart can't leave a stale dataplane rule shadowing the intended one (the confirmed `scenario-vpc-peering.sh` Assertion-2 root cause), and fix the deploy + scenario-tooling issues blocking clean live validation.

**Architecture:** Add a declarative `ReplaceInterfaceFirewall` RPC that sets an interface's entire firewall rule set at once (the dataplane already clears-all-slots-then-writes in `fw_reprogram`). The agent pushes the full desired set per interface every reconcile and drops its restart-fragile in-memory diff (`appliedFw`). Plus: disable the controller's `:8080` metrics server (hostNetwork rolling-restart conflict), stage busybox for the scenario pings, fix the Assertion-3 map read, and add a controller re-validation envtest.

**Tech Stack:** Rust (`flowplane-control`, `flowplane-node`, tonic/prost), Go (`netplane` controller-runtime agent), protobuf (`api/proto/dataplane/v1/dataplane.proto`), bash scenario, containerlab/kind fabric.

---

## File Structure

- `api/proto/dataplane/v1/dataplane.proto` — new `ReplaceInterfaceFirewall` rpc + `FwRuleSpec`/`ReplaceInterfaceFirewall{Request,Response}` messages (Task 1).
- `cni/gen/dataplanev1/*.pb.go` — regenerated Go stubs (Task 1, `make proto-go`).
- `flowplane/flowplane-control/src/firewall.rs` — `replace_fw_rules` / `replace_fw_rules6` core methods (Task 2).
- `flowplane/flowplane-node/src/handlers.rs` — `parse_fw_rule_fields` helper + `replace_interface_firewall` handler; `add_fw_rule` refactored onto the helper (Task 3).
- `flowplane/flowplane/src/node.rs` + `flowplane/flowplane-dpdk/src/node.rs` — wire the new trait method (Task 4).
- `netplane/agent/bus.go` — `Dataplane.ReplaceInterfaceFirewall` + `FwRuleWithID` + `dpAdapter` impl (Task 5).
- `netplane/agent/dp_fake_test.go` — recording fake gains `ReplaceInterfaceFirewall` (Task 5).
- `netplane/agent/fwreconcile.go` + `netplane/agent/reconcile.go` — rewrite reconcile to push replace; delete `appliedFw` (Task 6).
- `netplane/agent/fwreconcile_test.go` — rewritten for replace semantics + restart-safety (Task 6).
- `netplane/cmd/controller/main.go` + `config/deploy/controller.yaml` — disable metrics, `Recreate` strategy (Task 7).
- `netplane/controllers/compilednic_envtest_test.go` — NP-delete-clears re-validation test (Task 8).
- `test/scenario-vpc-peering.sh` — busybox pings + Assertion-3 map read (Task 9).

---

## Task 1: Proto — add `ReplaceInterfaceFirewall`

**Files:**
- Modify: `api/proto/dataplane/v1/dataplane.proto`
- Regenerate: `cni/gen/dataplanev1/dataplane.pb.go`, `cni/gen/dataplanev1/dataplane_grpc.pb.go`

- [ ] **Step 1: Add the rpc to the `DataplaneNode` service.** In `api/proto/dataplane/v1/dataplane.proto`, after the `DelFwRule` rpc (line 51) and before `ConfigureQoS`, insert:

```proto
  // ReplaceInterfaceFirewall atomically replaces an interface's ENTIRE firewall rule set
  // (ingress + egress, v4 + v6) with the supplied rules, clearing any prior rules. This is the
  // declarative, restart-safe primitive the node agent uses: it pushes the complete desired set
  // each reconcile, so a stale rule can never survive an agent restart or an in-place policy change.
  rpc ReplaceInterfaceFirewall(ReplaceInterfaceFirewallRequest) returns (ReplaceInterfaceFirewallResponse);
```

- [ ] **Step 2: Add the messages.** After `DelFwRuleResponse` (line 107), insert:

```proto
// FwRuleSpec is one firewall rule inside a ReplaceInterfaceFirewall set. Same fields as
// AddFwRuleRequest minus interface_id (carried once on the parent). The rule's address family is
// inferred from the CIDRs (a v6 CIDR on either side makes it a v6 rule), exactly like AddFwRule.
message FwRuleSpec {
  string rule_id = 1;      // stable rule id (debug/telemetry; slot order = position in the list)
  string src_cidr = 2;     // source CIDR ("0.0.0.0/0"/"::/0"/empty = any)
  string dst_cidr = 3;     // destination CIDR; empty = any
  uint32 proto = 4;        // IP protocol number (6=TCP, 17=UDP, 1=ICMP); 0 = any
  uint32 dst_port_min = 5; // inclusive destination-port range low
  uint32 dst_port_max = 6; // inclusive destination-port range high; 0 => treated as 65535
  bool allow = 7;          // true = accept, false = drop
  bool egress = 8;         // true = egress rule, false = ingress rule
}

message ReplaceInterfaceFirewallRequest {
  string interface_id = 1;        // target interface (as in AttachInterface)
  repeated FwRuleSpec rules = 2;  // the COMPLETE desired rule set; empty clears all rules
}
message ReplaceInterfaceFirewallResponse {}
```

- [ ] **Step 3: Regenerate Go stubs.**

Run: `cd /home/nik/Development/ironcore-net-xdp && make proto-go`
Expected: exit 0; `git status` shows `cni/gen/dataplanev1/dataplane.pb.go` and `dataplane_grpc.pb.go` modified (new `ReplaceInterfaceFirewallRequest`, `FwRuleSpec`, `ReplaceInterfaceFirewall` client/server methods).

- [ ] **Step 4: Confirm Go stubs compile.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./cni/gen/...`
Expected: exit 0, no output.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api/proto/dataplane/v1/dataplane.proto cni/gen/dataplanev1/
git commit -m "proto: add ReplaceInterfaceFirewall rpc + FwRuleSpec

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `flowplane-control` — `replace_fw_rules` core methods (TDD)

**Files:**
- Modify: `flowplane/flowplane-control/src/firewall.rs`

- [ ] **Step 1: Write the failing tests.** In `flowplane/flowplane-control/src/firewall.rs`, inside the existing `#[cfg(test)] mod tests`, add these two tests (after `fw_rules_capped_at_max`, before the closing `}`):

```rust
    #[test]
    fn replace_fw_rules_clears_stale_slots_on_shrink() {
        use flowplane_common::FW_DIR_INGRESS;
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 9u32;
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta { vni: 1, ipv4: [10, 0, 0, 1], ipv6: [0u8; 16], underlay: [1u8; 16], ifindex },
        );
        // Start with two rules at slots 0,1.
        c.replace_fw_rules(
            b"if1",
            vec![(b"a".to_vec(), rule(FW_DIR_INGRESS)), (b"b".to_vec(), rule(FW_DIR_INGRESS))],
        )
        .unwrap();
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        // Replace with ONE rule: slot 1 must be cleared, meta ingress_count == 1.
        c.replace_fw_rules(b"if1", vec![(b"a".to_vec(), rule(FW_DIR_INGRESS))]).unwrap();
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert!(!c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        assert_eq!(c.w.fw_meta.get(&ifindex).unwrap().ingress_count, 1);
    }

    #[test]
    fn replace_fw_rules_overwrites_same_id_content_and_empty_clears() {
        use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 11u32;
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta { vni: 1, ipv4: [10, 0, 0, 1], ipv6: [0u8; 16], underlay: [1u8; 16], ifindex },
        );
        let deny = FwRule { direction: FW_DIR_INGRESS, action: FW_ACTION_DROP, ..Default::default() };
        let allow = FwRule { direction: FW_DIR_INGRESS, action: FW_ACTION_ACCEPT, ..Default::default() };
        // Program a deny at rule-id "fw-in-0".
        c.replace_fw_rules(b"if1", vec![(b"fw-in-0".to_vec(), deny)]).unwrap();
        assert_eq!(c.w.fw_rules.get(&FwRuleKey { ifindex, idx: 0 }).unwrap().action, FW_ACTION_DROP);
        // Replace the SAME id with an allow: slot 0 now holds accept (no ALREADY_EXISTS rejection).
        c.replace_fw_rules(b"if1", vec![(b"fw-in-0".to_vec(), allow)]).unwrap();
        assert_eq!(c.w.fw_rules.get(&FwRuleKey { ifindex, idx: 0 }).unwrap().action, FW_ACTION_ACCEPT);
        // Empty replace clears the interface: no slot, meta counts zero.
        c.replace_fw_rules(b"if1", vec![]).unwrap();
        assert!(!c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert_eq!(c.w.fw_meta.get(&ifindex).unwrap().ingress_count, 0);
    }
```

- [ ] **Step 2: Run the tests to verify they fail.**

Run: `cd /home/nik/Development/ironcore-net-xdp/flowplane && cargo test -p flowplane-control replace_fw_rules 2>&1 | tail -20`
Expected: FAIL — compile error `no method named replace_fw_rules found`.

- [ ] **Step 3: Implement the core methods.** In `flowplane/flowplane-control/src/firewall.rs`, inside `impl<W: MapWriter> ControlCore<W>`, add after `remove_fw_rules` (line 17):

```rust
    /// Replace ALL v4 firewall rules for an interface with `rules` (both directions), clearing any
    /// prior rules/slots. Declarative + restart-safe: callers push the complete desired set each
    /// reconcile, so a stale rule can never survive. `rules` is slot-ordered (idx = position).
    pub fn replace_fw_rules(
        &mut self,
        interface_id: &[u8],
        rules: Vec<(Vec<u8>, FwRule)>,
    ) -> anyhow::Result<()> {
        let ifindex = self
            .ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        if rules.len() > FW_MAX_RULES as usize {
            anyhow::bail!("too many firewall rules for interface (max {})", FW_MAX_RULES);
        }
        self.fw.insert(ifindex, rules);
        self.fw_reprogram(ifindex)
    }

    /// Replace ALL v6 firewall rules for an interface with `rules` (both directions), clearing any
    /// prior rules/slots. v6 counterpart of [`replace_fw_rules`].
    pub fn replace_fw_rules6(
        &mut self,
        interface_id: &[u8],
        rules: Vec<(Vec<u8>, FwRule6)>,
    ) -> anyhow::Result<()> {
        let ifindex = self
            .ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        if rules.len() > FW_MAX_RULES as usize {
            anyhow::bail!("too many firewall rules for interface (max {})", FW_MAX_RULES);
        }
        self.fw6.insert(ifindex, rules);
        self.fw6_reprogram(ifindex)
    }
```

Note: the `use flowplane_common::{... FwRule6 ...}` import at the top of the file already includes `FwRule6` and `FW_MAX_RULES` — no import change needed.

- [ ] **Step 4: Run the tests to verify they pass (and nothing else broke).**

Run: `cd /home/nik/Development/ironcore-net-xdp/flowplane && cargo test -p flowplane-control firewall 2>&1 | tail -20`
Expected: PASS — all firewall tests including the two new ones.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/flowplane-control/src/firewall.rs
git commit -m "feat(flowplane-control): replace_fw_rules declarative set primitive

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `flowplane-node` — `replace_interface_firewall` handler (TDD)

**Files:**
- Modify: `flowplane/flowplane-node/src/handlers.rs`

- [ ] **Step 1: Write the failing test.** In `flowplane/flowplane-node/src/handlers.rs`, inside `#[cfg(test)] mod tests`, add (the helper `register_iface` already exists in that module):

```rust
    #[test]
    fn replace_interface_firewall_sets_full_set_and_clears() {
        let mut c = core();
        register_iface(&mut c, "if0", 5, [10, 0, 0, 2]);
        // Replace with one v4 ingress deny + one v6 ingress allow.
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest {
                interface_id: "if0".into(),
                rules: vec![
                    pb::FwRuleSpec {
                        rule_id: "fw-in-0".into(),
                        src_cidr: "0.0.0.0/0".into(),
                        dst_cidr: "".into(),
                        proto: 0,
                        dst_port_min: 0,
                        dst_port_max: 0,
                        allow: false,
                        egress: false,
                    },
                    pb::FwRuleSpec {
                        rule_id: "fw-in-1".into(),
                        src_cidr: "::/0".into(),
                        dst_cidr: "".into(),
                        proto: 0,
                        dst_port_min: 0,
                        dst_port_max: 0,
                        allow: true,
                        egress: false,
                    },
                ],
            },
        )
        .unwrap();
        // v4 slot 0 and v6 slot 0 are programmed.
        assert!(c.writer().fw_rules.contains_key(&flowplane_common::FwRuleKey { ifindex: 0, idx: 0 }));
        assert!(c.writer().fw_rules6.contains_key(&flowplane_common::FwRuleKey { ifindex: 0, idx: 0 }));
        // Empty replace clears both families.
        replace_interface_firewall(
            &mut c,
            &pb::ReplaceInterfaceFirewallRequest { interface_id: "if0".into(), rules: vec![] },
        )
        .unwrap();
        assert!(!c.writer().fw_rules.contains_key(&flowplane_common::FwRuleKey { ifindex: 0, idx: 0 }));
        assert!(!c.writer().fw_rules6.contains_key(&flowplane_common::FwRuleKey { ifindex: 0, idx: 0 }));
    }
```

Note: if `c.writer()` is not the accessor used in this module's existing tests, mirror whatever `add_fw_rule_v6_programs_rules6` (around line 391) uses to read `fw_rules6` — reuse that exact accessor expression.

- [ ] **Step 2: Run to verify it fails.**

Run: `cd /home/nik/Development/ironcore-net-xdp/flowplane && cargo test -p flowplane-node replace_interface_firewall 2>&1 | tail -20`
Expected: FAIL — `cannot find function replace_interface_firewall` (and `pb::ReplaceInterfaceFirewallRequest` resolves, since Task 1 added it to the proto compiled by this crate's build.rs).

- [ ] **Step 3: Refactor the per-rule parse into a shared helper + add the handler.** In `flowplane/flowplane-node/src/handlers.rs`, add this helper above `add_fw_rule` (line 195):

```rust
/// One parsed firewall rule, family-tagged. The address family is inferred from the CIDRs: a v6
/// CIDR on either side makes it a v6 rule (the wildcard opposite side is re-encoded in-family).
enum ParsedFwRule {
    V4(flowplane_common::FwRule),
    V6(flowplane_common::FwRule6),
}

/// Parse the wire fields of one firewall rule into a family-tagged `ParsedFwRule`. Shared by
/// `add_fw_rule` and `replace_interface_firewall` so both encode rules identically.
fn parse_fw_rule_fields(
    src_cidr: &str,
    dst_cidr: &str,
    proto: u32,
    dst_port_min: u32,
    dst_port_max: u32,
    allow: bool,
    egress: bool,
) -> Result<ParsedFwRule, Status> {
    use crate::parse::FwCidr;
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
    let src = parse_fw_cidr(src_cidr).map_err(invalid)?;
    let dst = parse_fw_cidr(dst_cidr).map_err(invalid)?;
    let proto = u8::try_from(proto).map_err(|_| Status::invalid_argument("proto > 255"))?;
    let dst_port_min = port_u16(dst_port_min).map_err(invalid)?;
    let dst_port_max = if dst_port_max == 0 { 65535u16 } else { port_u16(dst_port_max).map_err(invalid)? };
    let action = if allow { FW_ACTION_ACCEPT } else { FW_ACTION_DROP };
    let direction = if egress { FW_DIR_EGRESS } else { FW_DIR_INGRESS };
    if matches!(src, FwCidr::V6(..)) || matches!(dst, FwCidr::V6(..)) {
        let (src_ip, src_mask) = match src { FwCidr::V6(i, m) => (i, m), FwCidr::V4(..) => ([0u8; 16], [0u8; 16]) };
        let (dst_ip, dst_mask) = match dst { FwCidr::V6(i, m) => (i, m), FwCidr::V4(..) => ([0u8; 16], [0u8; 16]) };
        Ok(ParsedFwRule::V6(flowplane_common::FwRule6 {
            src_ip, src_mask, dst_ip, dst_mask,
            src_port_min: 0, src_port_max: 65535, dst_port_min, dst_port_max,
            icmp_type: 0xffff, icmp_code: 0xffff, proto, action, direction, enabled: 1,
        }))
    } else {
        let (src_ip, src_mask) = match src { FwCidr::V4(i, m) => (i, m), _ => unreachable!() };
        let (dst_ip, dst_mask) = match dst { FwCidr::V4(i, m) => (i, m), _ => unreachable!() };
        Ok(ParsedFwRule::V4(flowplane_common::FwRule {
            src_ip, src_mask, dst_ip, dst_mask,
            src_port_min: 0, src_port_max: 65535, dst_port_min, dst_port_max,
            icmp_type: 0xffff, icmp_code: 0xffff, proto, action, direction, enabled: 1,
        }))
    }
}
```

Then replace the body of `add_fw_rule` (lines 195-278) with:

```rust
pub fn add_fw_rule<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddFwRuleRequest,
) -> Result<pb::AddFwRuleResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    let rule_id = req.rule_id.clone().into_bytes();
    match parse_fw_rule_fields(
        &req.src_cidr, &req.dst_cidr, req.proto, req.dst_port_min, req.dst_port_max, req.allow, req.egress,
    )? {
        ParsedFwRule::V6(rule) => core.add_fw_rule6(&iface, rule_id, rule).map_err(internal)?,
        ParsedFwRule::V4(rule) => core.add_fw_rule(&iface, rule_id, rule).map_err(internal)?,
    };
    Ok(pb::AddFwRuleResponse {})
}

/// Replace an interface's ENTIRE firewall rule set with `req.rules` (ingress + egress, v4 + v6),
/// clearing any prior rules. Splits the flat list into per-family slot-ordered vecs and calls the
/// declarative core primitives; both families are replaced (an absent family is cleared).
pub fn replace_interface_firewall<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ReplaceInterfaceFirewallRequest,
) -> Result<pb::ReplaceInterfaceFirewallResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    let mut v4: Vec<(Vec<u8>, flowplane_common::FwRule)> = Vec::new();
    let mut v6: Vec<(Vec<u8>, flowplane_common::FwRule6)> = Vec::new();
    for spec in &req.rules {
        let id = spec.rule_id.clone().into_bytes();
        match parse_fw_rule_fields(
            &spec.src_cidr, &spec.dst_cidr, spec.proto, spec.dst_port_min, spec.dst_port_max, spec.allow, spec.egress,
        )? {
            ParsedFwRule::V4(rule) => v4.push((id, rule)),
            ParsedFwRule::V6(rule) => v6.push((id, rule)),
        }
    }
    core.replace_fw_rules(&iface, v4).map_err(internal)?;
    core.replace_fw_rules6(&iface, v6).map_err(internal)?;
    Ok(pb::ReplaceInterfaceFirewallResponse {})
}
```

- [ ] **Step 4: Run tests to verify pass (new + existing add/del fw tests).**

Run: `cd /home/nik/Development/ironcore-net-xdp/flowplane && cargo test -p flowplane-node fw 2>&1 | tail -25`
Expected: PASS — `replace_interface_firewall_sets_full_set_and_clears`, `add_fw_rule_programs`, `add_fw_rule_v6_programs_rules6` all green (the refactor preserved behavior).

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/flowplane-node/src/handlers.rs
git commit -m "feat(flowplane-node): replace_interface_firewall handler + shared rule parse

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Wire the rpc in both `DataplaneNode` service impls

**Files:**
- Modify: `flowplane/flowplane/src/node.rs` (after `del_fw_rule`, before `configure_qos`)
- Modify: `flowplane/flowplane-dpdk/src/node.rs` (after its `del_fw_rule`)

- [ ] **Step 1: Add the method to the eBPF node service.** In `flowplane/flowplane/src/node.rs`, after the `add_fw_rule`/`del_fw_rule` methods (around line 424-...), add inside `impl DataplaneNode for NodeService`:

```rust
    async fn replace_interface_firewall(
        &self,
        req: Request<pb::ReplaceInterfaceFirewallRequest>,
    ) -> Result<Response<pb::ReplaceInterfaceFirewallResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let (log_iface, log_n) = (r.interface_id.clone(), r.rules.len());
        let resp = tokio::task::spawn_blocking(move || {
            attach
                .control
                .with_core(|c| flowplane_node::replace_interface_firewall(c, &r))
        })
        .await
        .map_err(|e| Status::internal(format!("replace_interface_firewall task panicked: {e}")))??;
        println!("FW replace iface={log_iface} rules={log_n}");
        Ok(Response::new(resp))
    }
```

- [ ] **Step 2: Add the method to the DPDK node service.** In `flowplane/flowplane-dpdk/src/node.rs`, after its `del_fw_rule` (around line 795-...), add inside its `impl DataplaneNode`:

```rust
    async fn replace_interface_firewall(
        &self,
        req: Request<pb::ReplaceInterfaceFirewallRequest>,
    ) -> Result<Response<pb::ReplaceInterfaceFirewallResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::replace_interface_firewall(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }
```

- [ ] **Step 3: Build both crates to confirm the trait is satisfied.**

Run: `cd /home/nik/Development/ironcore-net-xdp/flowplane && cargo build -p flowplane -p flowplane-dpdk 2>&1 | tail -20`
Expected: exit 0. (A missing method would fail with "not all trait items implemented".)

- [ ] **Step 4: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/flowplane/src/node.rs flowplane/flowplane-dpdk/src/node.rs
git commit -m "feat(flowplane): wire ReplaceInterfaceFirewall in both node services

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Agent Go — `Dataplane.ReplaceInterfaceFirewall` + fake

**Files:**
- Modify: `netplane/agent/bus.go`
- Modify: `netplane/agent/dp_fake_test.go`

- [ ] **Step 1: Add `FwRuleWithID` + the interface method.** In `netplane/agent/bus.go`, in the `Dataplane interface` block (starts line 20), after the `DelFwRule` line (line 33), add:

```go
	// ReplaceInterfaceFirewall replaces an interface's ENTIRE firewall rule set (ingress+egress,
	// v4+v6) in one call. Declarative + restart-safe: the agent pushes the full desired set every
	// reconcile, so a stale dataplane rule never survives an agent restart or in-place policy change.
	ReplaceInterfaceFirewall(ctx context.Context, interfaceID string, rules []FwRuleWithID) error
```

Then, next to the `FwRule` type definition in `bus.go` (find it with `grep -n "type FwRule struct" netplane/agent/bus.go`), add:

```go
// FwRuleWithID pairs a stable rule id (slot order = list position) with a rule, for
// ReplaceInterfaceFirewall.
type FwRuleWithID struct {
	ID   string
	Rule FwRule
}
```

- [ ] **Step 2: Implement it on `dpAdapter`.** In `netplane/agent/bus.go`, after the `dpAdapter.DelFwRule` method (line 664-...), add:

```go
func (d dpAdapter) ReplaceInterfaceFirewall(ctx context.Context, interfaceID string, rules []FwRuleWithID) error {
	specs := make([]*dpv1.FwRuleSpec, 0, len(rules))
	for _, rr := range rules {
		specs = append(specs, &dpv1.FwRuleSpec{
			RuleId:     rr.ID,
			SrcCidr:    rr.Rule.SrcCIDR,
			DstCidr:    rr.Rule.DstCIDR,
			Proto:      rr.Rule.Proto,
			DstPortMin: rr.Rule.DstPortMin,
			DstPortMax: rr.Rule.DstPortMax,
			Allow:      rr.Rule.Allow,
			Egress:     rr.Rule.Egress,
		})
	}
	_, err := d.c.ReplaceInterfaceFirewall(ctx, &dpv1.ReplaceInterfaceFirewallRequest{
		InterfaceId: interfaceID,
		Rules:       specs,
	})
	return err
}
```

Note: confirm the `FwRule` Go struct field names (`SrcCIDR`, `DstCIDR`, `Proto`, `DstPortMin`, `DstPortMax`, `Allow`, `Egress`) against its definition; they match `compiledToFw` in `fwreconcile.go`. If any differ, use the real names.

- [ ] **Step 3: Add the method to the recording fake (models real replace semantics).** In `netplane/agent/dp_fake_test.go`, add a field to `recordingDP` (after `fwDels`, line 21):

```go
	// fwReplace records the LAST ReplaceInterfaceFirewall call per interface (the full desired set),
	// modelling the real dataplane where a replace overwrites the interface's entire rule set.
	fwReplace map[string][]FwRuleWithID
```

Initialize it in `newRecordingDP()` (add to the struct literal, e.g. after `fwInstalled`):

```go
		fwReplace: map[string][]FwRuleWithID{},
```

And add the method (near `AddFwRule`):

```go
func (f *recordingDP) ReplaceInterfaceFirewall(_ context.Context, iface string, rules []FwRuleWithID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Overwrite: the whole set for this interface becomes exactly `rules` (clears prior on empty).
	f.fwReplace[iface] = append([]FwRuleWithID(nil), rules...)
	// Keep fwInstalled consistent with a wholesale replace so any cross-checks stay accurate.
	for k := range f.fwInstalled {
		if len(k) > len(iface) && k[:len(iface)+1] == iface+"|" {
			delete(f.fwInstalled, k)
		}
	}
	for _, rr := range rules {
		f.fwInstalled[iface+"|"+rr.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Build the agent + confirm the fake still satisfies the interface.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./netplane/... && go vet ./netplane/agent/ 2>&1 | tail`
Expected: exit 0. The `var _ Dataplane = newRecordingDP()` assertion in `bus_test.go:18` now also requires `ReplaceInterfaceFirewall` — present, so it compiles.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/agent/bus.go netplane/agent/dp_fake_test.go
git commit -m "feat(netplane/agent): Dataplane.ReplaceInterfaceFirewall + fake

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Agent Go — rewrite `ReconcileFirewall` to push replace; delete `appliedFw` (TDD)

**Files:**
- Modify: `netplane/agent/fwreconcile.go`
- Modify: `netplane/agent/reconcile.go` (remove the `appliedFw` field + comment)
- Modify: `netplane/agent/fwreconcile_test.go`

- [ ] **Step 1: Rewrite `netplane/agent/fwreconcile_test.go` for replace semantics + restart-safety.** The three existing tests (`TestReconcileFirewall_PushesRules`, `_DeletesStaleRules`, `_ConvergesOnRepeat`) assert on `dp.fwAdds`/`dp.fwDels`, which the new declarative path no longer produces — DELETE all three and replace the whole file body (keep the package + imports) with these tests, which use the real scaffolding pattern from the old file (`fake.NewClientBuilder()`, `dp.ifaces = []LocalInterface{{InterfaceID:..., OverlayIPs:...}}`, `&Reconciler{client:cl, nodeID:..., dp:dp}`):

```go
package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fwScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The agent pushes the COMPLETE desired rule set per interface, in CompiledNIC order (ingress rules
// fw-in-0..N first, then egress fw-eg-0..N), via a single ReplaceInterfaceFirewall call.
func TestReconcileFirewall_PushesFullOrderedSet(t *testing.T) {
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall: netv1.CompiledFirewall{
				Ingress: []netv1.CompiledFwRule{
					{CIDR: "0.0.0.0/0", Action: "Deny"},
					{CIDR: "10.0.10.0/24", Proto: "ICMP", Action: "Allow"},
				},
				Egress: []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := dp.fwReplace["podUID/eth0"]
	if len(got) != 3 {
		t.Fatalf("want 3 rules in one replace, got %d: %+v", len(got), got)
	}
	if got[0].ID != "fw-in-0" || got[1].ID != "fw-in-1" || got[2].ID != "fw-eg-0" {
		t.Fatalf("wrong order/ids: %+v", got)
	}
	if got[0].Rule.Allow /* deny */ || !got[1].Rule.Allow /* allow */ || got[1].Rule.SrcCIDR != "10.0.10.0/24" {
		t.Fatalf("wrong rule contents: %+v", got)
	}
}

// The decisive regression: a fresh Reconciler (empty in-memory state = post-restart) sharing the
// same client+dp must converge a deny→allow swap to EXACTLY [allow] — the old in-memory-diff path
// left the stale deny in place after a restart (scenario-vpc-peering Assertion 2).
func TestReconcileFirewall_RestartSafeConverges(t *testing.T) {
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall:   netv1.CompiledFirewall{Ingress: []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Deny"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}

	// Incarnation 1: program the deny-all.
	r1 := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	if err := r1.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Swap deny → allow on the same object.
	cnic.Spec.Firewall.Ingress = []netv1.CompiledFwRule{{CIDR: "10.0.10.0/24", Proto: "ICMP", Action: "Allow"}}
	if err := cl.Update(context.Background(), cnic); err != nil {
		t.Fatal(err)
	}

	// Incarnation 2: a NEW Reconciler (no shared in-memory state) must converge to exactly [allow].
	r2 := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	if err := r2.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := dp.fwReplace["podUID/eth0"]
	if len(got) != 1 || !got[0].Rule.Allow || got[0].Rule.SrcCIDR != "10.0.10.0/24" {
		t.Fatalf("post-restart did not converge to [allow]: %+v", got)
	}
}

// Replace is idempotent: repeated reconciles never error (no ALREADY_EXISTS) and leave the final set.
func TestReconcileFirewall_ConvergesOnRepeat(t *testing.T) {
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall: netv1.CompiledFirewall{
				Ingress: []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Proto: "TCP", Port: 443, Action: "Allow"}},
				Egress:  []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	for i := 0; i < 3; i++ {
		if err := r.ReconcileFirewall(context.Background()); err != nil {
			t.Fatalf("reconcile #%d errored: %v", i+1, err)
		}
	}
	if got := dp.fwReplace["podUID/eth0"]; len(got) != 2 {
		t.Fatalf("want final set of 2 rules, got %d: %+v", len(got), got)
	}
}
```

Note: confirm `LocalInterface`'s field names (`InterfaceID`, `Vni`, `OverlayIPs`, `Underlay`) — copied verbatim from the old `fwreconcile_test.go:33`. If `dp.fwReplace` was named differently in Task 5, use that name.

- [ ] **Step 2: Run to verify the tests fail.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go test ./netplane/agent/ -run TestReconcileFirewall 2>&1 | tail -20`
Expected: FAIL — old `ReconcileFirewall` still calls `AddFwRule`, so `dp.fwReplace` is empty.

- [ ] **Step 3: Rewrite `ReconcileFirewall`.** Replace the body of `ReconcileFirewall` in `netplane/agent/fwreconcile.go` (lines 17-98) with:

```go
// ReconcileFirewall programs the firewall rules of every CompiledNIC scheduled to this node onto
// the dataplane. It is DECLARATIVE and restart-safe: for each locally-attached interface it computes
// the complete desired rule set (ingress rules first, then egress, in CompiledNIC order) and calls
// ReplaceInterfaceFirewall, which sets the interface's whole rule set at once. There is no in-memory
// diff to lose on restart, so an in-place policy change (or an agent restart mid-swap) always
// converges — no stale rule can survive to shadow the intended one.
func (r *Reconciler) ReconcileFirewall(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	// The dataplane is the source of truth for which interface a NIC's overlay IP is attached to.
	ifaceByIP, err := r.interfaceIDByOverlayIP(ctx)
	if err != nil {
		return err
	}
	var list netv1.CompiledNICList
	if err := r.client.List(ctx, &list); err != nil {
		return fmt.Errorf("list compilednics: %w", err)
	}
	// interfaceID -> ordered desired rules (ingress first, then egress; index = slot within family).
	desired := map[string][]FwRuleWithID{}
	for i := range list.Items {
		c := &list.Items[i]
		if c.Spec.NodeName != r.nodeID {
			continue
		}
		iface := ""
		for _, ip := range c.Spec.OverlayIPs {
			if id, ok := ifaceByIP[ip]; ok {
				iface = id
				break
			}
		}
		if iface == "" {
			continue // NIC not attached locally yet; nothing to program until it is
		}
		rules := desired[iface]
		for idx, cr := range c.Spec.Firewall.Ingress {
			rules = append(rules, FwRuleWithID{ID: fmt.Sprintf("fw-in-%d", idx), Rule: compiledToFw(cr, false)})
		}
		for idx, cr := range c.Spec.Firewall.Egress {
			rules = append(rules, FwRuleWithID{ID: fmt.Sprintf("fw-eg-%d", idx), Rule: compiledToFw(cr, true)})
		}
		desired[iface] = rules
	}
	var errs []error
	for iface, rules := range desired {
		if err := r.dp.ReplaceInterfaceFirewall(ctx, iface, rules); err != nil {
			errs = append(errs, fmt.Errorf("ReplaceInterfaceFirewall %s: %w", iface, err))
		}
	}
	return errors.Join(errs...)
}
```

Keep `compiledToFw` and `protoNum` in the file unchanged. The `errors` and `fmt` imports remain used.

- [ ] **Step 4: Delete the `appliedFw` field.** In `netplane/agent/reconcile.go`, remove the field + its comment (lines 24-26):

```go
	// appliedFw tracks the last set of firewall rules pushed to the dataplane so
	// ReconcileFirewall can diff and delete stale rules.
	appliedFw map[string]map[string]FwRule // interfaceID -> ruleID -> rule
```

Then `grep -rn "appliedFw" netplane/` and remove any remaining references (initialization in a constructor, etc.). There should be none outside this field after Task 6.

- [ ] **Step 5: Run the firewall tests + the whole agent package.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go test ./netplane/agent/ 2>&1 | tail -25`
Expected: PASS — the two new tests plus every other agent test (routes, LB, NAT, QoS unaffected).

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/agent/fwreconcile.go netplane/agent/reconcile.go netplane/agent/fwreconcile_test.go
git commit -m "fix(netplane/agent): declarative firewall reconcile (restart-safe)

Push the full desired rule set per interface via ReplaceInterfaceFirewall each
reconcile; delete the in-memory appliedFw diff that was lost on restart and let
a stale deny shadow a new allow (scenario-vpc-peering Assertion 2 root cause).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Deploy — disable controller metrics + `Recreate` strategy

**Files:**
- Modify: `netplane/cmd/controller/main.go`
- Modify: `config/deploy/controller.yaml`

- [ ] **Step 1: Disable the manager metrics server.** In `netplane/cmd/controller/main.go`, add the metrics-server import and set `BindAddress: "0"`. Change the import block to add:

```go
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
```

and change the manager construction (line 32) from:

```go
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme})
```

to:

```go
	// Disable the metrics server: the controller runs hostNetwork (see config/deploy/controller.yaml),
	// so a default :8080 listener collides on rolling restart (new pod can't bind while the old holds
	// it) → crashloop. Nothing scrapes it in this deployment; "0" turns it off.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
```

- [ ] **Step 2: Verify the controller builds.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go build ./netplane/cmd/controller/`
Expected: exit 0. If the import path errors, confirm the controller-runtime version's metrics package path with `grep -rn "metrics/server" $(go env GOMODCACHE)/sigs.k8s.io/controller-runtime*/pkg/manager/ 2>/dev/null | head` and use the matching import.

- [ ] **Step 3: Add `Recreate` strategy (belt-and-suspenders).** In `config/deploy/controller.yaml`, under `spec:` (after `replicas: 1`, line 10), add:

```yaml
  # hostNetwork singleton: never surge two pods (they'd collide on host ports). Recreate ensures the
  # old pod is torn down before the new one starts on rollout.
  strategy:
    type: Recreate
```

- [ ] **Step 4: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/cmd/controller/main.go config/deploy/controller.yaml
git commit -m "fix(deploy): disable controller metrics + Recreate strategy

hostNetwork controller crashlooped on rolling restart (:8080 bind conflict);
disable the unused metrics server and never surge two pods.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Controller re-validation envtest (delete NP → CompiledNIC clears)

**Files:**
- Modify: `netplane/controllers/compilednic_envtest_test.go`

- [ ] **Step 1: Read the existing envtest for scaffolding.** Run `sed -n '1,80p' netplane/controllers/compilednic_envtest_test.go` to learn how it stands up the envtest environment, creates a `VPC`/`NetworkInterface`, runs the reconciler, and reads back the `CompiledNIC` (the `Eventually`/`Get` pattern and the test manager wiring). Reuse that scaffolding verbatim.

- [ ] **Step 2: Add the delete-clears test.** Append a test that: creates a VPC + NIC (labels `{side: green}`), applies a `NetworkPolicy` selecting it with one ingress deny-all, waits for the `CompiledNIC.Spec.Firewall.Ingress` to contain that Deny; then DELETES the policy and asserts the CompiledNIC's ingress reverts to the ruleless default (the compiler's `allow-all` v4+v6, i.e. no Deny rule remains). Model the assertions on the existing envtest's `Eventually(...).Should(...)` style:

```go
func TestCompiledNIC_Envtest_DeletedPolicyClearsRule(t *testing.T) {
	// ... stand up envtest + reconciler exactly as the existing envtest does ...
	// 1. Create VPC(green, vni) + NIC(green-guest, labels side=green, ip 10.0.20.11).
	// 2. Apply NetworkPolicy{interfaceSelector: side=green, ingress:[{cidr 0.0.0.0/0, action Deny}]}.
	// 3. Eventually: CompiledNIC "default-green-guest".Spec.Firewall.Ingress contains {CIDR:"0.0.0.0/0", Action:"Deny"}.
	// 4. Delete the NetworkPolicy.
	// 5. Eventually: that Deny rule is GONE — Ingress is exactly the ruleless default
	//    [{0.0.0.0/0 Allow},{::/0 Allow}] (compilednic.go materializes allow-all for a ruleless direction).
}
```

Fill the body with the real envtest scaffolding from Step 1 (client, `k8sClient.Create/Delete`, `Eventually`). The contract: after policy delete, no `Deny` rule remains in the CompiledNIC.

- [ ] **Step 3: Run the envtest.**

Run: `cd /home/nik/Development/ironcore-net-xdp && go test ./netplane/controllers/ -run Envtest 2>&1 | tail -30`
Expected: PASS (confirms the controller correctly clears a deleted policy — the memory's "accumulation" was a polluted-pod informer artifact).
**Contingency:** if it FAILS, the controller genuinely drops deleted policies. Then invoke `superpowers:systematic-debugging`: inspect the NetworkPolicy delete watch (`nicsForPolicy` + `GenerationChangedPredicate` Delete handling in `compilednic.go` SetupWithManager) and fix so a delete re-enqueues + recompiles. Re-run until green.

- [ ] **Step 4: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/compilednic_envtest_test.go
git commit -m "test(netplane): envtest — deleted NetworkPolicy clears CompiledNIC rule

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Scenario tooling — busybox pings + Assertion-3 map read

**Files:**
- Modify: `test/scenario-vpc-peering.sh`

- [ ] **Step 1: Find the working busybox-ping pattern.** Run `grep -rn "busybox\|/busybox\|ping" test/scenario-nat-egress.sh test/*.sh | head -30` to copy the exact staging pattern the revived NAT/DHCP smokes use (how they get a static busybox into the guest netns and invoke `/busybox ping`). Reuse it verbatim.

- [ ] **Step 2: Add a `guest_ping` helper.** In `test/scenario-vpc-peering.sh`, after `detach_guest` (line 174), add a helper that runs a ping from a guest netns using staged busybox instead of the node's absent `ping`. Base it on the pattern from Step 1, e.g.:

```bash
# guest_ping <node> <src_nic> <dst_ip> <count> <timeout_s> — ping from a guest netns using a staged
# static busybox (the kind node image has no `ping`). Returns ping's exit code.
guest_ping() {
  local node="$1" nic="$2" dst="$3" count="${4:-3}" wto="${5:-2}"
  # Stage busybox into the node once (idempotent); path per scenario-nat-egress.sh.
  stage_busybox "$node"   # <- the helper/name copied from Step 1
  sudo docker exec "$node" ip netns exec "$nic" /busybox ping -c "$count" -W "$wto" "$dst"
}
```

If `scenario-nat-egress.sh` inlines the staging rather than exposing a helper, inline the same commands here (copy the busybox source path and `docker cp`/exec lines exactly).

- [ ] **Step 3: Use `guest_ping` in Assertions 1 & 2.** Replace the Assertion-1 ping (lines 348-353) and Assertion-2 ping (lines 384-389) so they call `guest_ping "$BLUE_NODE" "$BLUE_GUEST_NIC" "$GREEN_GUEST_IP" 3 2` (Assertion 1) / `... 3 4` (Assertion 2) instead of the bare `ip netns exec ... ping`. Keep the pass/fail logic identical (Assertion 1 expects non-zero exit = blocked; Assertion 2 expects zero exit = success).

- [ ] **Step 4: Fix the Assertion-3 map read.** The current read (`bpftool_map_dump` via in-node nix `bpftool`, lines 128-131 + 409-446) fails because the kind node doesn't mount the host nix store. Replace the ROUTES-map premise with a `INTERFACES`-based check OR a host-side read. Preferred: assert the overlap guest's local route is delivered locally by reading `INTERFACES` (local guests deliver via `INTERFACES`, not `ROUTES`) using the host `hack/clab/bpf-trace.sh` path, or via a `grpc` ListInterfaces call confirming `green-local`@`10.0.10.77` is attached on `GREEN_NODE` under `GREEN_VNI`. Concretely, replace the `[7]` block body with a check that does not exec an in-node absolute nix path:

```bash
# Assertion 3 (reframed): the overlap guest green-local@10.0.10.77 is a LOCAL interface on GREEN_NODE
# in VNI-green. Local delivery is via the INTERFACES map, so a local /32 shadows any imported peer
# prefix by construction. Confirm green-local is locally attached (authoritative, no in-node bpftool).
if grpc "$GREEN_NODE" '{}' ListInterfaces | grep -q "$OVERLAP_IP"; then
  pass "overlap-precedence: $OVERLAP_IP is a LOCAL interface on $GREEN_NODE (VNI $GREEN_VNI) — local delivery shadows any imported peer prefix"
else
  fail "overlap-precedence: $OVERLAP_IP not reported as a local interface on $GREEN_NODE"
fi
```

Verify the `ListInterfaces` gRPC method + response field names against `api/proto/dataplane/v1/dataplane.proto` (it returns `interfaces[].ipv4`); adjust the grep/`jq` accordingly if the JSON key differs. Remove the now-dead `NIX_BPFTOOL`, `bpftool_map_dump`, and `OVERLAP_HEX`/python block if nothing else uses them.

- [ ] **Step 5: Shellcheck / smoke-parse the script.**

Run: `cd /home/nik/Development/ironcore-net-xdp && bash -n test/scenario-vpc-peering.sh && shellcheck test/scenario-vpc-peering.sh 2>&1 | head -20`
Expected: `bash -n` exit 0; shellcheck warnings acceptable if pre-existing (don't introduce new errors).

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/scenario-vpc-peering.sh
git commit -m "test(scenario): vpc-peering busybox pings + INTERFACES-based overlap check

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Live validation on a clean fabric (manual)

**Files:** none (validation only). This task is run by the operator with sudo on the fabric host; it is not a subagent step.

- [ ] **Step 1: Bring up a fresh fabric.**

Run: `cd /home/nik/Development/ironcore-net-xdp && hack/clab-up.sh`
Expected: all nodes up. If `k03` boot-races (transient), re-run once.

- [ ] **Step 2: Build + load images and deploy the stack on k01.**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
make image-flowplane image-netplane            # or the repo's build targets for flowplane:dev + netplane:dev
kind load docker-image ghcr.io/trevex/ectobase/flowplane:dev --name k01
kind load docker-image ghcr.io/trevex/ectobase/netplane:dev --name k01
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > /tmp/k01.kc
KUBECONFIG=/tmp/k01.kc kubectl apply -k config/crd
KUBECONFIG=/tmp/k01.kc kubectl apply -k config/deploy
KUBECONFIG=/tmp/k01.kc kubectl -n ectobase-system rollout status ds/flowplane --timeout=180s
KUBECONFIG=/tmp/k01.kc kubectl -n ectobase-system rollout status deploy/netplane-controller --timeout=120s
KUBECONFIG=/tmp/k01.kc kubectl -n ectobase-system rollout status ds/netplane-agent --timeout=120s
```
Expected: all three roll out Ready. Confirm the controller does NOT crashloop on restart (Task 7 fix): `kubectl -n ectobase-system get pod -l app.kubernetes.io/name=netplane-controller` shows Running, 0 restarts after a `rollout restart deploy/netplane-controller`.

- [ ] **Step 2b (image name check):** confirm the deploy manifests reference `:dev` images and the build targets produce exactly those tags. If the repo's image/tag names differ from the placeholders above, use the real ones (`grep -n "image:" config/deploy/*.yaml`).

- [ ] **Step 3: Run the scenario.**

Run: `cd /home/nik/Development/ironcore-net-xdp && sudo -E env "PATH=$PATH" bash test/scenario-vpc-peering.sh`
Expected: `PASS: scenario-vpc-peering — all 3 assertions passed`. Specifically Assertion 2 (post-policy cross-VPC ping) now SUCCEEDS — the fix's decisive signal.

- [ ] **Step 4: Regression — NAT/LB scenarios still program firewall correctly.**

Run: `cd /home/nik/Development/ironcore-net-xdp && sudo -E env "PATH=$PATH" bash test/scenario-nat-egress.sh && sudo -E env "PATH=$PATH" bash test/scenario-lb-ingress.sh`
Expected: both PASS (these also add ingress ALLOW firewall rules; the replace path must not regress them).

- [ ] **Step 5: Update memory.** Update `vpc-peering-assertion2-rootcause` memory: record the CONFIRMED root cause (agent-restart + dataplane duplicate-id rejection, fixed via declarative ReplaceInterfaceFirewall), whether the controller envtest cleared it as a pollution artifact, and the live PASS. Cross-link `[[vpc-peering]]`.

---

## Notes for the executor

- Run git-mutating steps SEQUENTIALLY (per the DPDK-backlog lesson in memory — parallel git subagents corrupt the tree).
- Rust builds are slow; `cargo test -p <crate>` scoping (as written) keeps each step fast.
- Tasks 1-9 are CI-verifiable and land without a fabric. Task 10 is the live gate and needs the sudo fabric host.
- If Task 8's envtest reveals a real controller bug, that's an added sub-task (systematic-debugging), not a plan failure — the spec explicitly gated it on re-validation.
