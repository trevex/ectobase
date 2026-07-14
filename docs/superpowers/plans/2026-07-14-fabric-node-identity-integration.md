# Fabric Node-Identity Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every kind node in the containerlab fabric its own BGP speaker whose kubelet Node InternalIP is its announced fabric `/64` address, by wiring the (already-spiked) custom `kindest/node-fabric` image into the fabric and removing the post-boot sidecar/`exec` scaffolding — with the xdp-dp dataplane + overlay still green on the new identity.

**Architecture:** The custom node image (`hack/kind-fabric-node/`) runs a `Before=kubelet.service` oneshot (`fabric-preboot`) that puts the node's `/64` on dummy0, sets kubelet `--node-ip` to `<prefix>::1` via `KUBELET_EXTRA_ARGS` (last-wins), and starts an in-node FRR announcing the `/64` over unnumbered eBGP. clab keeps the ToR + `eth1` links but drops the per-node `host*-frr` sidecars and the dummy0 `exec` (the node owns both now). The per-node `/64` is injected via kind `extraMounts` so it is known at systemd boot, before any clab post-boot step. Hybrid: kind still bootstraps + exports kubeconfig over docker; only Node identity + dataplane move to the fabric.

**Tech Stack:** containerlab, kind (custom node image), FRR, systemd, bash/YAML; the existing Rust xdp-dp + Go netplane stack (unchanged) for the regression check.

**Spike (already proven, `hack/kind-fabric-node/`):** node-ip = fabric addr survives container restart; FRR baked in and configured. See `docs/superpowers/research/2026-07-14-realistic-bgp-fabric-node-identity.md`.

**Scope:** Phase 1 only — single-homed fabric, faithful node identity. Deferred to separate plans: **dual-homing** (`eth2`+`sw2`, no spine interlink) and **xdp-dp egress ECMP** (two uplinks + 50/50 WCMP + per-port ToR MAC via netlink neigh, mirroring dpservice active-active).

---

## File Structure

- `Makefile` — add `image-kindnode` target building `kindest/node-fabric:$(TAG)` (Modify).
- `hack/kind-fabric-node/Dockerfile` — pin the base image by digest; already builds FRR + preboot (Modify).
- `hack/kind-fabric-node/fabric-preboot.sh` — also enable IPv6 forwarding (moved off the clab `exec`) (Modify).
- `hack/clab/prefixes/*.prefix` — per-node `/64` files mounted into nodes (Create).
- `hack/clab/kind-cluster.yaml` — k01 nodes get `image:` + per-node `extraMounts` (Modify).
- `hack/clab/kind-cluster-k02.yaml` — k02 node gets `image:` + `extraMounts` (Modify).
- `hack/clab/ipv6-fabric.clab.yml` — drop `host{1,2,3}-frr` sidecars + the dummy0/forwarding `exec` on the ext-container nodes (Modify).
- `hack/clab-up.sh` — build the kindnode image before deploy (or document the prereq) (Modify).

---

### Task 1: `image-kindnode` Makefile target + pinned base

**Files:**
- Modify: `Makefile`, `hack/kind-fabric-node/Dockerfile`

- [ ] **Step 1: Pin the base image by digest in the Dockerfile**

The current fabric uses `kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`. In `hack/kind-fabric-node/Dockerfile`, change the base ARG to pin the digest so the custom image and the fabric's kind version never drift:

```dockerfile
ARG BASE=kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f
FROM ${BASE}
```

- [ ] **Step 2: Add the Makefile target**

In `Makefile`, after the `image-netplane` target, add (reuse the existing `TAG`/`DOCKER_BUILD_NET` vars):

```makefile
KINDNODE_IMAGE ?= kindest/node-fabric
.PHONY: image-kindnode
image-kindnode: ## Build the fabric kind-node image (node-IP = pre-kubelet BGP /64)
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) \
		-t $(KINDNODE_IMAGE):$(TAG) hack/kind-fabric-node
```

- [ ] **Step 3: Build and verify the image**

Run: `make image-kindnode 2>&1 | tail -3 && docker images | grep node-fabric`
Expected: build succeeds; `kindest/node-fabric:dev` listed.

- [ ] **Step 4: Commit**

```bash
git add Makefile hack/kind-fabric-node/Dockerfile
git commit -m "build(fabric): image-kindnode target + pinned base

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: IPv6 forwarding in preboot (off the clab exec)

**Files:**
- Modify: `hack/kind-fabric-node/fabric-preboot.sh`

**Context:** The old clab `exec` set `net.ipv6.conf.all.forwarding=1` on each node. Since we drop that `exec`, the node's own preboot must enable forwarding (the node routes overlay↔underlay and FRR needs it).

- [ ] **Step 1: Add forwarding to the preboot script**

In `hack/kind-fabric-node/fabric-preboot.sh`, immediately after the `set -eu` line's prefix read (before the dummy0 block), add:

```bash
# The node routes underlay/overlay and runs FRR — enable IPv6 forwarding (this
# used to be a clab `exec`; the node owns it now).
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
```

- [ ] **Step 2: Rebuild the image**

Run: `make image-kindnode 2>&1 | tail -2`
Expected: build succeeds (the COPY layer re-runs).

- [ ] **Step 3: Commit**

```bash
git add hack/kind-fabric-node/fabric-preboot.sh
git commit -m "fix(fabric): enable IPv6 forwarding in preboot (was a clab exec)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Per-node prefix files + kind configs use the custom image

**Files:**
- Create: `hack/clab/prefixes/k01-control-plane.prefix`, `hack/clab/prefixes/k01-worker.prefix`, `hack/clab/prefixes/k02-control-plane.prefix`
- Modify: `hack/clab/kind-cluster.yaml`, `hack/clab/kind-cluster-k02.yaml`

- [ ] **Step 1: Create the per-node prefix files**

```bash
mkdir -p hack/clab/prefixes
echo "fd00:db8:0:1::/64" > hack/clab/prefixes/k01-control-plane.prefix
echo "fd00:db8:0:2::/64" > hack/clab/prefixes/k01-worker.prefix
echo "fd00:db8:0:3::/64" > hack/clab/prefixes/k02-control-plane.prefix
```

- [ ] **Step 2: Point k01's kind config at the custom image + mount the prefixes**

Replace the `nodes:` block in `hack/clab/kind-cluster.yaml` (the `extraMounts` hostPath must be an ABSOLUTE path; clab runs `kind` from `hack/clab/`, but kind resolves hostPaths relative to CWD unreliably — use the repo-absolute path the deploy script exports, see Task 5. For the committed file, use a path relative to the repo root that clab-up resolves). Use `$PWD`-independent absolute paths by templating in clab-up (Task 5); the committed YAML uses the canonical repo path:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv6
nodes:
  - role: control-plane
    image: kindest/node-fabric:dev
    extraMounts:
      - hostPath: PREFIX_DIR/k01-control-plane.prefix
        containerPath: /etc/fabric/prefix
        readOnly: true
  - role: worker
    image: kindest/node-fabric:dev
    extraMounts:
      - hostPath: PREFIX_DIR/k01-worker.prefix
        containerPath: /etc/fabric/prefix
        readOnly: true
```

`PREFIX_DIR` is a placeholder that `hack/clab-up.sh` substitutes with the absolute `hack/clab/prefixes` path at deploy time (Task 5), writing a `.gen` config clab consumes. (kind rejects relative `extraMounts` hostPaths, so this substitution is required.)

- [ ] **Step 3: Same for k02's kind config**

Replace the `nodes:` block in `hack/clab/kind-cluster-k02.yaml`:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv6
nodes:
  - role: control-plane
    image: kindest/node-fabric:dev
    extraMounts:
      - hostPath: PREFIX_DIR/k02-control-plane.prefix
        containerPath: /etc/fabric/prefix
        readOnly: true
```

- [ ] **Step 4: Commit**

```bash
git add hack/clab/prefixes hack/clab/kind-cluster.yaml hack/clab/kind-cluster-k02.yaml
git commit -m "feat(fabric): per-node /64 prefixes + custom node image in kind configs

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Strip the clab topology (drop sidecars + dummy0 exec)

**Files:**
- Modify: `hack/clab/ipv6-fabric.clab.yml`

**Context:** The node is now the BGP speaker and owns dummy0, so the `host{1,2,3}-frr` sidecars and the ext-container `exec` (dummy0 + forwarding) are obsolete. Keep the ToR (`sw1`), the `k8s-kind` nodes, the ext-container node declarations (link endpoints), and the `eth1` links.

- [ ] **Step 1: Delete the sidecar nodes**

In `hack/clab/ipv6-fabric.clab.yml`, remove the entire `host1-frr:`, `host2-frr:`, and `host3-frr:` node blocks (the `linux` kind sidecars sharing each node's netns).

- [ ] **Step 2: Strip the ext-container `exec` blocks**

For `k01-control-plane`, `k01-worker`, and `k02-control-plane`, remove their `exec:` lists (the `sysctl`/`ip link add dummy0`/`ip addr` commands). The node declarations remain as bare `kind: ext-container` entries (they are still needed as `eth1` link endpoints):

```yaml
    k01-control-plane:
      kind: ext-container
    k01-worker:
      kind: ext-container
    k02-control-plane:
      kind: ext-container
```

- [ ] **Step 3: Validate the topology parses**

Run: `PATH=$HOME/go/bin:$PATH containerlab inspect -t hack/clab/ipv6-fabric.clab.yml --format json 2>&1 | head -3 || true`
Expected: no YAML/parse error (it may say the lab isn't deployed — that's fine; a parse error would be a failure).

- [ ] **Step 4: Commit**

```bash
git add hack/clab/ipv6-fabric.clab.yml
git commit -m "refactor(fabric): drop FRR sidecars + dummy0 exec (node owns BGP now)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Deploy-time prefix-path substitution in clab-up

**Files:**
- Modify: `hack/clab-up.sh`

**Context:** kind rejects relative `extraMounts` hostPaths, so `hack/clab-up.sh` must (a) build the kindnode image and (b) render the `PREFIX_DIR` placeholder to the absolute prefixes path before clab deploys.

- [ ] **Step 1: Add image build + placeholder rendering to clab-up.sh**

In `hack/clab-up.sh`, after the tool checks and before the `exec ${CLAB} deploy` line, insert:

```bash
# The fabric nodes use the custom kind-node image (node-IP = pre-kubelet BGP /64).
# Build it if missing, and render the per-node prefix mount paths to absolutes
# (kind rejects relative extraMounts hostPaths).
REPO="$(cd "${HERE}/.." && pwd)"
if ! docker image inspect kindest/node-fabric:dev >/dev/null 2>&1; then
  make -C "${REPO}" image-kindnode
fi
PREFIX_DIR="${HERE}/clab/prefixes"
for f in "${HERE}/clab/kind-cluster.yaml" "${HERE}/clab/kind-cluster-k02.yaml"; do
  sed "s#PREFIX_DIR#${PREFIX_DIR}#g" "$f" > "${f}.gen"
done
```

Then change the two `startup-config:` references in the topology to the `.gen` files. **Note:** the topology (`ipv6-fabric.clab.yml`) currently has `startup-config: kind-cluster.yaml` / `kind-cluster-k02.yaml` — update those two lines to `kind-cluster.yaml.gen` / `kind-cluster-k02.yaml.gen`. Add `hack/clab/*.gen` to `.gitignore`.

- [ ] **Step 2: Update the topology startup-config refs**

In `hack/clab/ipv6-fabric.clab.yml`, change `startup-config: kind-cluster.yaml` → `startup-config: kind-cluster.yaml.gen` and `startup-config: kind-cluster-k02.yaml` → `startup-config: kind-cluster-k02.yaml.gen`.

- [ ] **Step 3: Ignore generated files**

```bash
echo "hack/clab/*.gen" >> .gitignore
```

- [ ] **Step 4: Commit**

```bash
git add hack/clab-up.sh hack/clab/ipv6-fabric.clab.yml .gitignore
git commit -m "feat(fabric): clab-up builds kindnode image + renders prefix mount paths

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Bring up the fabric and verify node identity + BGP end-to-end

**Files:** none (verification task)

- [ ] **Step 1: Tear down any prior fabric + spike, redeploy**

```bash
export PATH="$HOME/go/bin:$PATH"
kind delete cluster --name fabric-spike 2>/dev/null || true
sudo -E env "PATH=$HOME/go/bin:/usr/bin:/bin:$PATH" ./hack/clab-down.sh 2>/dev/null || true
sudo -E env "PATH=$HOME/go/bin:/usr/bin:/bin:$PATH" ./hack/clab-up.sh 2>&1 | tail -20
```
Expected: fabric deploys; no `host*-frr` nodes in the table.

- [ ] **Step 2: Verify each node's InternalIP is its fabric `/64` address**

```bash
sudo kind get kubeconfig --name k01 > /tmp/k01.kubeconfig
sudo kind get kubeconfig --name k02 > /tmp/k02.kubeconfig
kubectl --kubeconfig /tmp/k01.kubeconfig get nodes -o wide
kubectl --kubeconfig /tmp/k02.kubeconfig get nodes -o wide
```
Expected: `k01-control-plane` InternalIP `fd00:db8:0:1::1`, `k01-worker` `fd00:db8:0:2::1`, `k02-control-plane` `fd00:db8:0:3::1` — **not** the docker `fc00:…` addresses. All `Ready`.

- [ ] **Step 3: Verify FRR runs IN the node and the BGP session to sw1 is ESTABLISHED**

```bash
for n in k01-control-plane k01-worker k02-control-plane; do
  echo "== $n =="
  sudo docker exec "$n" sh -c 'systemctl is-active frr; vtysh -c "show bgp ipv6 unicast summary" 2>/dev/null | grep -A2 Neighbor | tail -1'
done
```
Expected: `active`; the eth1 neighbor shows an established session (a numeric `State/PfxRcd`, e.g. a prefix count, not `Active`/`Connect`/`Idle`). This is the "established session" the spike could not show without a peer.

- [ ] **Step 4: Verify cross-node + cross-cluster underlay reachability (the `/64`s are learned)**

```bash
sudo docker exec k01-control-plane ip -6 route show proto bgp | grep -E 'fd00:db8:0:(2|3)::/64'
sudo docker exec k02-control-plane ip -6 route show proto bgp | grep -E 'fd00:db8:0:1::/64'
```
Expected: k01-cp has routes to `fd00:db8:0:2::/64` and `fd00:db8:0:3::/64`; k02-cp has a route to `fd00:db8:0:1::/64` (all via eth1). Underlay reachable across nodes and clusters, learned from the in-node FRR.

- [ ] **Step 5: Confirm no sidecars remain**

```bash
sudo docker ps --format '{{.Names}}' | grep -E 'host[0-9]+-frr' && echo "FAIL: sidecar present" || echo "PASS: no FRR sidecars"
```
Expected: `PASS: no FRR sidecars`.

---

### Task 7: Regression — xdp-dp dataplane + overlay still green on the fabric identity

**Files:** none (verification task; reuses `config/` + `hack/multicluster-e2e.sh`)

**Context:** The identity change must not break the dataplane. xdp-dp still infers its `/64` from dummy0 (now set by preboot instead of the clab `exec`) and the DS wrapper still resolves the ToR MAC from `eth1` neigh. The reflector/agent still target `fd00:db8:0:1::1` — which is now *also* k01-cp's Node IP, still correct.

- [ ] **Step 1: Load images + run the multi-cluster overlay e2e**

```bash
export PATH="$HOME/go/bin:$PATH"
for c in k01 k02; do
  sudo kind load docker-image ghcr.io/trevex/dpservice-xdp:dev --name "$c"
  sudo kind load docker-image ghcr.io/trevex/netplane:dev --name "$c"
done
bash hack/multicluster-e2e.sh 2>&1 | tail -25
```
Expected: the script's final two pings (`k01 ep-a 10.0.0.1 -> k02 ep-c 10.0.0.3` and reverse) report **0% packet loss** — the cross-cluster overlay still works with nodes whose K8s identity is now the fabric `/64`.

- [ ] **Step 2: Confirm xdp-dp inferred the correct underlay on a node**

```bash
KX=$(sudo docker exec k01-worker crictl ps --name xdp-dp -o json 2>/dev/null | grep -o '"id": "[a-f0-9]*"' | head -1 | cut -d'"' -f4)
sudo docker exec k01-worker crictl logs "$KX" 2>&1 | grep -iE 'inferred|underlay pool'
```
Expected: `underlay pool = fd00:db8:0:2::/64` (unchanged — dummy0 still carries the `/64`, now set pre-kubelet).

- [ ] **Step 3: Final commit (docs note that Phase 1 is validated)**

Append a one-line status to the research doc's spike section noting the full fabric integration is green, then:

```bash
git add docs/superpowers/research/2026-07-14-realistic-bgp-fabric-node-identity.md
git commit -m "docs(fabric): phase-1 node-identity integration validated end-to-end

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec/design coverage:** Every element of the design doc's "Target architecture" + "Remaining before a full plan" is covered — custom image into clab (T3), drop sidecars + exec (T4), prefix via extraMounts (T3/T5), forwarding moved to preboot (T2), established-BGP verification (T6.3), and the xdp-dp/overlay regression (T7). Node-ip mechanism itself was proven in the spike (not re-litigated). Dual-homing + datapath ECMP are explicitly deferred to separate plans (scope check — each is its own working increment).

**2. Placeholder scan:** The only intentional placeholder is `PREFIX_DIR` in the committed kind configs, which Task 5 renders to an absolute path at deploy time (kind rejects relative extraMounts hostPaths) — this is a documented mechanism, not a gap. No TBD/"handle errors"/vague steps.

**3. Consistency:** Image name `kindest/node-fabric:dev` (Makefile `KINDNODE_IMAGE`+`TAG`) is used identically in the Dockerfile build, kind configs, and clab-up. Node/prefix mapping (`k01-control-plane`→`fd00:db8:0:1::/64`, `-worker`→`:2::`, `k02-control-plane`→`:3::`) matches the existing topology and the multicluster e2e's endpoint plan. `fabric-preboot` reads `/etc/fabric/prefix` (the extraMounts target) — consistent between the spike script and the mount. Reflector/agent addresses (`fd00:db8:0:1::1`) unchanged and still valid (now also the CP Node IP).

**Deferred (separate plans):** dual-homing (`eth2`+`sw2`); xdp-dp egress ECMP (two-uplink `LOCAL` + 50/50 WCMP + netlink-neigh ToR MACs).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-14-fabric-node-identity-integration.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks. Note: Tasks 6-7 are live-fabric verification (long; sudo + containerlab) — best driven inline with the controller watching, even under subagent execution.
2. **Inline Execution** — execute here with checkpoints.

Which approach?
