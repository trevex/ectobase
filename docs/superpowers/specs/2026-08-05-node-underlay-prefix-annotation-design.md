# Node Underlay-/64 Agent Annotation — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-05
**Context:** Phase 5b (Tier-2 fence-gated failover) follow-up. Replaces the provisional `Node.Spec.PodCIDRs[0]` fence-source (the `TODO(fence-source)` in `central/cmd/broker/main.go`) with the correct per-node underlay /64, stamped by the agent that actually knows it. See `2026-08-05-tier2-failover-fencing-design.md` §9.

## 1. Goal

Give the broker the **correct** per-node /64 underlay prefix — the fence coordinate central acts on (Ceph `NetworkFence` CIDR + reflector route-blocklist). The provisional `PodCIDRs[0]` can be the wrong address family (an IPv4 `/24` on v4-primary clusters) or absent, so fencing could target a prefix that never matches the node's real underlay. The agent already knows its node's underlay (`--underlay=$(NODE_IP)`), so it stamps the derived /64 as a Node annotation the broker reads.

## 2. Architecture & flow

The agent is a per-node DaemonSet, **cluster-self-contained**: it talks only to routebus (the reflector) and its own cluster's apiserver (watching the broker-synced compiled CRDs). It patches its **own local Node** — Nodes are native cluster infra, not broker-synced. The broker already lists downstream Nodes via its `Downstream` client and reads the annotation.

```
agent (per node, local cluster)                      broker (Downstream client → same local cluster)
  --underlay=<node v6>  ── mask /64 ──▶  patch own Node:      gatherNodes: read Node annotation
    net.ectobase.dev/underlay-prefix: 2001:db8:0:1::/64  ──▶    → NodeFact{Name, Prefix}
                                                                 (was: Node.Spec.PodCIDRs[0])
                                              ▼
                          ClusterPool.Status.NodePrefixes (upward, existing) → central fences these /64s
```

`--node-id=$(NODE_NAME)` comes from `spec.nodeName`, so the agent's node identity **is** the k8s Node name — the same value `VirtualMachineInstance.Status.NodeName` reports — so the broker's VM→node→/64 join is exact.

## 3. The /64 is the real fence coordinate

`--underlay=$(NODE_IP)` = `status.hostIP` (the node's underlay IPv6). Under the fabric's one-/64-per-node (node-VIP) model, every address the node announces to the route bus and its Ceph-client address live in that /64. So masking `--underlay` to /64 yields the prefix that (a) contains the nexthops the reflector must block and (b) contains the RBD client the Ceph `NetworkFence` must blocklist — exactly what Tier-2 fences.

## 4. Components

### 4.1 Shared annotation key (`api/v1alpha1`)

A new `api/v1alpha1/annotations.go` (or equivalent) defining:

```go
// NodeUnderlayPrefixAnnotation is set by the netplane agent on its own Node with the
// node's /64 underlay prefix (the Tier-2 fence coordinate). The broker reads it.
const NodeUnderlayPrefixAnnotation = "net.ectobase.dev/underlay-prefix"
```

Both `central` and `netplane` import `github.com/trevex/ectobase/api/v1alpha1` (verified), so this is the single source of truth for writer + reader — no drifting string literals.

### 4.2 Agent (`netplane/agent` + `cmd/agent/main.go`)

- **Derive /64 (pure, unit-testable):** `underlayPrefix(underlay string) string` — `netip.ParseAddr(underlay)`; if a valid **IPv6** address, return `netip.PrefixFrom(addr, 64).Masked().String()`; otherwise (v4, or unparseable) return `""` → skip stamping (log, never fail the agent — a dev/v4 node simply isn't fence-eligible).
- **Stamp (best-effort I/O):** `stampNodePrefix(ctx, c client.Client, nodeName, prefix string) error` — Get the Node named `nodeName`; if its `NodeUnderlayPrefixAnnotation` already equals `prefix`, no-op; else set the annotation and `client.MergeFrom` patch. Uses the agent's **existing** `client.Client` (built from `--kubeconfig`, which points at the agent's own cluster).
- **When:** invoked best-effort each reconcile tick (the agent's existing periodic loop). Idempotent (patch only on diff) → self-heals Node recreation and startup ordering (a not-yet-registered Node just retries next tick). Errors are logged, never fail reconcile.

### 4.3 RBAC (`deploy/charts/ectobase/templates/rbac.yaml` + `config/deploy` sync)

Add `patch` to the agent `netplane-agent` ClusterRole's existing `nodes` rule (currently `["get","list","watch"]` → `["get","list","watch","patch"]`).

### 4.4 Broker (`central/cmd/broker/main.go`)

- Extract a pure helper `nodePrefixFromNode(node *corev1.Node) string` returning `node.Annotations[v1alpha1.NodeUnderlayPrefixAnnotation]` (or `""`).
- `gatherNodes` uses it instead of `Node.Spec.PodCIDRs[0]`. **Delete** the PodCIDRs fallback and the `TODO(fence-source)` comment. A Node without the annotation → `Prefix=""` → dropped from `NodePrefixes` (not fence-eligible — safer than a wrong prefix; the pure `NodePrefixesFromNodes` already skips empties).

### 4.5 Docs

- Fix the stale `--kubeconfig` flag help in `netplane/cmd/agent/main.go` — it is the agent's **own cluster** apiserver (where the broker syncs compiled CRDs), not "the central API".
- Update `2026-08-05-tier2-failover-fencing-design.md` §9: the node-/64 source is no longer provisional; real fence release is no longer gated on this follow-up (the single-cluster kind-lab gate is unblocked).

## 5. Testing

- **Agent unit:** `underlayPrefix` — a v6 address masks to its /64 (`2001:db8:0:1::a` → `2001:db8:0:1::/64`); a v4 address and garbage → `""`. `stampNodePrefix` against a controller-runtime fake client — annotation is set on a bare Node; a second call is a no-op when already equal; a missing Node returns an error the caller logs (agent unaffected).
- **Broker unit:** `nodePrefixFromNode` — annotation present → its value; absent → `""`.
- **No new envtest:** the existing Tier-2 envtest already exercises the /64 fence→rebind→release flow with explicit prefixes; this change only alters where the prefix originates, not the flow.

## 6. Scope boundaries

**In scope:** the shared const, the agent /64-derivation + Node stamp + reconcile-tick wiring, the RBAC `patch` verb, the broker annotation read (dropping PodCIDRs), the flag-help + spec-§9 doc fixes, and the unit tests above.

**Out of scope / deferred:** multi-/64-per-node (the fabric model is one /64 per node; a multi-prefix node would need `NodePrefixes` to carry several per node — not needed now); surfacing the prefix on `ClusterPool`/central beyond the existing `NodePrefixes` upward path (already built in Phase 5b); the live single-cluster kind-lab run itself (now unblocked, but still a separate manual validation).

## 7. Success criteria

- Agent stamps `net.ectobase.dev/underlay-prefix=<node /64>` on its own Node (idempotent, best-effort, v4/invalid → skip).
- Broker `gatherNodes` reads the annotation; no `PodCIDRs` reference or `TODO(fence-source)` remains.
- `NodePrefixes` now carries the real underlay /64 (address-family-correct), so Tier-2 fences target the right prefix.
- Unit tests green; no new envtest; no dataplane/eBPF/Rust changes.
