# Node Underlay-/64 Agent Annotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Have the netplane agent stamp its node's real underlay /64 as a Node annotation so the Tier-2 broker reads the correct fence coordinate instead of the provisional `Node.Spec.PodCIDRs[0]`.

**Architecture:** A shared annotation-key const in the `api` module. The agent (cluster-self-contained; talks only to routebus + its own cluster apiserver) derives its /64 from `--underlay=$(NODE_IP)` and patches its own local Node each reconcile tick (best-effort, idempotent). The broker's `gatherNodes` reads that annotation. No dataplane/eBPF/Rust changes.

**Tech Stack:** Go (controller-runtime client, `net/netip`), the netplane agent + central broker, Helm/kustomize RBAC.

**Spec:** `docs/superpowers/specs/2026-08-05-node-underlay-prefix-annotation-design.md`
**Branch:** `feat/node-underlay-prefix-annotation` (exists).

---

## Conventions for every task

- Run Go tooling in the nix devShell: `nix develop --command bash -c '...'`. Modules: `api/` (`github.com/trevex/ectobase/api`), `netplane/`, `central/`. Both `central` and `netplane` `replace` the local `api` module (verified).
- Commit after each task with the shown message. Pre-commit skips rust for Go-only changes.

## File Structure

- `api/v1alpha1/annotations.go` (create) — the shared `NodeUnderlayPrefixAnnotation` const.
- `netplane/agent/nodeprefix.go` (create) — `underlayPrefix` (pure /64 derivation) + `Reconciler.StampNodePrefix` (patch own Node).
- `netplane/agent/nodeprefix_test.go` (create) — unit tests for both.
- `netplane/cmd/agent/main.go` (modify) — call `StampNodePrefix` in the reconcile closure; fix the `--kubeconfig` help text.
- `central/cmd/broker/main.go` (modify) — `nodePrefixFromNode` helper + `gatherNodes` uses the annotation (drop PodCIDRs + TODO).
- `central/cmd/broker/gathernodes_test.go` (create) — unit test for `nodePrefixFromNode`.
- `deploy/charts/ectobase/templates/rbac.yaml` + `config/deploy/rbac.yaml` (modify) — add `patch` to the agent `nodes` rule.
- `docs/superpowers/specs/2026-08-05-tier2-failover-fencing-design.md` (modify) — §9 no longer provisional.

---

## Task 1: Shared annotation-key const

**Files:**
- Create: `api/v1alpha1/annotations.go`

- [ ] **Step 1: Create the const**

Create `api/v1alpha1/annotations.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// NodeUnderlayPrefixAnnotation is set by the netplane agent on its own Node with that
// node's /64 underlay prefix — the Tier-2 fence coordinate (the CIDR the Ceph
// NetworkFence blocklists and whose nexthops the reflector route-fence suppresses).
// The broker reads it to populate ClusterPool.Status.NodePrefixes.
const NodeUnderlayPrefixAnnotation = "net.ectobase.dev/underlay-prefix"
```

- [ ] **Step 2: Build to verify**

Run: `nix develop --command bash -c 'cd api && go build ./...'`
Expected: clean, exit 0.

- [ ] **Step 3: Commit**

```bash
git add api/v1alpha1/annotations.go
git commit -m "feat(api): NodeUnderlayPrefixAnnotation const (Tier-2 fence coordinate)"
```

---

## Task 2: Agent /64 derivation (pure)

**Files:**
- Create: `netplane/agent/nodeprefix.go`
- Create: `netplane/agent/nodeprefix_test.go`

- [ ] **Step 1: Write the failing test**

Create `netplane/agent/nodeprefix_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestUnderlayPrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"2001:db8:0:1::a", "2001:db8:0:1::/64"},
		{"2001:db8:0:1::", "2001:db8:0:1::/64"},
		{"fd00:db8:0:9::1", "fd00:db8:0:9::/64"},
		{"10.0.0.1", ""},           // IPv4 -> not fence-eligible
		{"::ffff:10.0.0.1", ""},    // v4-mapped -> not a real v6 underlay
		{"not-an-ip", ""},          // garbage
		{"", ""},                   // empty
	}
	for _, c := range cases {
		if got := underlayPrefix(c.in); got != c.want {
			t.Errorf("underlayPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestUnderlayPrefix'`
Expected: FAIL — `underlayPrefix` undefined.

- [ ] **Step 3: Implement `underlayPrefix`**

Create `netplane/agent/nodeprefix.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "net/netip"

// underlayPrefix returns the /64 network of a node's underlay IPv6 address (the Tier-2
// fence coordinate), or "" if the input is not a genuine IPv6 address (a v4 or v4-mapped
// hostIP, or garbage) — such a node is simply not fence-eligible.
func underlayPrefix(underlay string) string {
	addr, err := netip.ParseAddr(underlay)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ""
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestUnderlayPrefix'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/nodeprefix.go netplane/agent/nodeprefix_test.go
git commit -m "feat(agent): underlayPrefix — derive node /64 fence coordinate from --underlay"
```

---

## Task 3: Agent stamps its own Node

**Files:**
- Modify: `netplane/agent/nodeprefix.go`
- Modify: `netplane/agent/nodeprefix_test.go`
- Modify: `netplane/cmd/agent/main.go`

- [ ] **Step 1: Write the failing test**

Append to `netplane/agent/nodeprefix_test.go`:

```go
func TestStampNodePrefix(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()
	r := &Reconciler{client: c, nodeID: "node-1", underlay: "2001:db8:0:1::a"}

	// First stamp writes the annotation.
	if err := r.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	got := &corev1.Node{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "node-1"}, got)
	if got.Annotations[netv1.NodeUnderlayPrefixAnnotation] != "2001:db8:0:1::/64" {
		t.Fatalf("annotation not set: %v", got.Annotations)
	}
	// Idempotent: a second stamp is a no-op (no error).
	if err := r.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("second stamp: %v", err)
	}

	// A v4 underlay skips silently (no error, no annotation).
	node2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}}
	c2 := fake.NewClientBuilder().WithScheme(s).WithObjects(node2).Build()
	r2 := &Reconciler{client: c2, nodeID: "node-2", underlay: "10.0.0.2"}
	if err := r2.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("v4 stamp should skip, got: %v", err)
	}
	got2 := &corev1.Node{}
	_ = c2.Get(context.Background(), client.ObjectKey{Name: "node-2"}, got2)
	if _, ok := got2.Annotations[netv1.NodeUnderlayPrefixAnnotation]; ok {
		t.Fatalf("v4 underlay must not stamp an annotation")
	}
}
```

Update the test file's imports to:

```go
import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestStampNodePrefix'`
Expected: FAIL — `StampNodePrefix` undefined.

- [ ] **Step 3: Implement `StampNodePrefix`**

Append to `netplane/agent/nodeprefix.go` (and extend its imports as shown):

```go
import (
	"context"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// StampNodePrefix stamps this node's /64 underlay prefix (NodeUnderlayPrefixAnnotation)
// onto its own Node so the Tier-2 broker reads the correct fence coordinate. Best-effort
// and idempotent: a non-IPv6 underlay is skipped (nil), an already-correct annotation is a
// no-op, and a not-yet-registered Node returns an error the caller logs and retries next tick.
func (r *Reconciler) StampNodePrefix(ctx context.Context) error {
	prefix := underlayPrefix(r.underlay)
	if prefix == "" {
		return nil // not a v6 underlay -> not fence-eligible
	}
	var node corev1.Node
	if err := r.client.Get(ctx, client.ObjectKey{Name: r.nodeID}, &node); err != nil {
		return fmt.Errorf("get node %s: %w", r.nodeID, err)
	}
	if node.Annotations[netv1.NodeUnderlayPrefixAnnotation] == prefix {
		return nil // already stamped
	}
	patch := client.MergeFrom(node.DeepCopy())
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	node.Annotations[netv1.NodeUnderlayPrefixAnnotation] = prefix
	return r.client.Patch(ctx, &node, patch)
}
```

(The file's existing `underlayPrefix` already imports `net/netip`; merge the imports into one block. `Reconciler` is defined in `reconcile.go` in the same package — the method attaches cleanly.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd netplane && go test ./agent/ -run "UnderlayPrefix|StampNodePrefix"'`
Expected: PASS (both).

- [ ] **Step 5: Wire into the reconcile tick + fix the flag help**

In `netplane/cmd/agent/main.go`, inside the `reconcile := func(ctx context.Context) ...` closure, add a best-effort stamp just before the final `return agent.DesiredState{...}` line:

```go
		if err := r.StampNodePrefix(ctx); err != nil {
			log.Printf("stamp node prefix: %v", err)
		}
```

Also fix the stale `--kubeconfig` flag help (currently line ~28):

```go
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig for this node's own cluster apiserver — where the broker syncs the compiled CRDs (empty = in-cluster). The agent never talks to central.")
```

- [ ] **Step 6: Build + full agent test**

Run: `nix develop --command bash -c 'cd netplane && go build ./... && go test ./agent/'`
Expected: clean build + all agent tests PASS.

- [ ] **Step 7: Commit**

```bash
git add netplane/agent/nodeprefix.go netplane/agent/nodeprefix_test.go netplane/cmd/agent/main.go
git commit -m "feat(agent): stamp node /64 underlay prefix annotation each reconcile tick"
```

---

## Task 4: Broker reads the annotation

**Files:**
- Modify: `central/cmd/broker/main.go`
- Create: `central/cmd/broker/gathernodes_test.go`

- [ ] **Step 1: Write the failing test**

Create `central/cmd/broker/gathernodes_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

func TestNodePrefixFromNode(t *testing.T) {
	withAnno := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:        "n1",
		Annotations: map[string]string{netv1.NodeUnderlayPrefixAnnotation: "2001:db8:0:1::/64"},
	}}
	if got := nodePrefixFromNode(withAnno); got != "2001:db8:0:1::/64" {
		t.Fatalf("want prefix from annotation, got %q", got)
	}
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}}
	if got := nodePrefixFromNode(bare); got != "" {
		t.Fatalf("no annotation must yield empty, got %q", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./cmd/broker/ -run TestNodePrefixFromNode'`
Expected: FAIL — `nodePrefixFromNode` undefined.

- [ ] **Step 3: Add the helper + rewrite `gatherNodes`**

In `central/cmd/broker/main.go`, add the import `netv1 "github.com/trevex/ectobase/api/v1alpha1"` to the import block (if not already present), then add the helper and replace the `gatherNodes` function (currently lines ~218-242, including its `TODO(fence-source)` doc comment) with:

```go
// nodePrefixFromNode returns the node's underlay /64 fence prefix from the annotation the
// netplane agent stamps on its own Node, or "" if absent (the node is not fence-eligible).
func nodePrefixFromNode(n *corev1.Node) string {
	return n.Annotations[netv1.NodeUnderlayPrefixAnnotation]
}

// gatherNodes lists downstream nodes and reads each node's /64 fence prefix from the
// agent-stamped NodeUnderlayPrefixAnnotation. A node without it is not fence-eligible
// (dropped from NodePrefixes by NodePrefixesFromNodes) — safer than a wrong prefix.
func (s *statusReporter) gatherNodes(ctx context.Context) ([]broker.NodeFact, error) {
	nodeList := &corev1.NodeList{}
	if err := s.downstream.List(ctx, nodeList); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]broker.NodeFact, 0, len(nodeList.Items))
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		out = append(out, broker.NodeFact{Name: n.Name, Prefix: nodePrefixFromNode(n)})
	}
	return out, nil
}
```

(This deletes the `PodCIDRs[0]` derivation and the entire `TODO(fence-source)` comment block. Keep the rest of `main.go` unchanged.)

- [ ] **Step 4: Run to verify it passes + build**

Run: `nix develop --command bash -c 'cd central && go test ./cmd/broker/ && go build ./...'`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add central/cmd/broker/main.go central/cmd/broker/gathernodes_test.go
git commit -m "feat(broker): read node /64 fence prefix from agent annotation (drop PodCIDRs stand-in)"
```

---

## Task 5: RBAC patch verb + spec update

**Files:**
- Modify: `deploy/charts/ectobase/templates/rbac.yaml`
- Modify: `config/deploy/rbac.yaml`
- Modify: `docs/superpowers/specs/2026-08-05-tier2-failover-fencing-design.md`

- [ ] **Step 1: Add `patch` to the agent `nodes` rule in BOTH files**

The chart-test asserts the Helm-rendered `rbac.yaml` matches `config/deploy/rbac.yaml`, so both must change identically. In each of `deploy/charts/ectobase/templates/rbac.yaml` and `config/deploy/rbac.yaml`, find the agent `netplane-agent` ClusterRole's rule whose `resources:` is `- nodes` and change its verbs line from:

```yaml
    verbs: ["get", "list", "watch"]
```

to:

```yaml
    verbs: ["get", "list", "watch", "patch"]
```

(There is exactly one `- nodes` resources block per file — the one under the `netplane-agent` ClusterRole. Change only that one.)

- [ ] **Step 2: Verify chart-test stays green (rendered == kustomize source)**

Run: `nix develop --command bash -c 'make chart-test 2>&1 | grep -E "rbac|FAIL" | head'`
Expected: `PASS: ebpf render rbac == config/deploy/rbac.yaml` (both files changed identically); no FAIL.

- [ ] **Step 3: Update the Tier-2 spec §9 (no longer provisional)**

In `docs/superpowers/specs/2026-08-05-tier2-failover-fencing-design.md`, replace the deferred bullet that begins "**Real node-/64 fence-source (implementation follow-up).**" with:

```markdown
- **Node-/64 fence-source — DONE (2026-08-05 follow-up).** The netplane agent stamps its node's real underlay /64 as the `net.ectobase.dev/underlay-prefix` Node annotation (derived from `--underlay`, address-family-correct), and the broker's `gatherNodes` reads it. The provisional `PodCIDRs[0]` stand-in is removed. See `2026-08-05-node-underlay-prefix-annotation-design.md`. This unblocks the single-cluster kind-lab gate.
```

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/templates/rbac.yaml config/deploy/rbac.yaml docs/superpowers/specs/2026-08-05-tier2-failover-fencing-design.md
git commit -m "feat(rbac): grant agent nodes/patch for /64 stamping; mark Tier-2 fence-source done"
```

---

## Final verification (after all tasks)

- [ ] Agent + broker suites: `nix develop --command bash -c 'cd netplane && go build ./... && go test ./agent/ && cd ../central && go build ./... && go test ./cmd/broker/ ./internal/...'` — all PASS.
- [ ] Chart-test green: `nix develop --command bash -c 'make chart-test >/dev/null 2>&1 && echo GREEN || echo RED'` — GREEN.
- [ ] No `PodCIDRs` or `TODO(fence-source)` remains: `grep -rn 'PodCIDRs\|TODO(fence-source)' central/cmd/broker/` — no output.
- [ ] No dataplane/Rust changes: `git diff --name-only main...HEAD | grep -E '^flowplane/|\.rs$'` — no output.
- [ ] Dispatch a final holistic review across `git diff main...HEAD`, then use `superpowers:finishing-a-development-branch`.
