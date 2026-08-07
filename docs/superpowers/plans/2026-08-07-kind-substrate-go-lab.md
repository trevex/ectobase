# kind Node Substrate for the Go `test/lab` Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (fresh subagent per task, two-stage review). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Switch the Go `test/lab` clab harness from Talos-container nodes to **kind** clusters (stable init → reliable `docker kill` + no wedging), so the Tier-2 fenced-failover gate can run reliably; then remove the Talos substrate and the bash `hack/clab`.

**Architecture:** The clab fabric (VyOS switches/edges, NAT64, WAN, registry, ceph) and the `fabric.View` derivation are unchanged. Each cluster's node becomes a clab `k8s-kind` node running the existing `kind-node-fabric:dev` image (dummy0 `/64` identity + `kubelet --node-ip` + FRR eBGP = Talos parity). The deploy pipeline (`deploy.Ectobase`, `lab ceph`, `lab tier2`) and the `livetest` suite are substrate-agnostic and reused unchanged. Build kind + validate live FIRST, then delete Talos + bash.

**Tech Stack:** Go 1.26 + cobra; containerlab `k8s-kind`; kind (ipv6, disableDefaultCNI, kube-proxy off); Cilium; the `kind-node-fabric` image; the `net.ectobase.dev`/`platform.ectobase.dev` aggregated APIs.

**Spec:** `docs/superpowers/specs/2026-08-07-kind-substrate-go-lab-design.md`.

---

## Validation model (READ FIRST)

Two tiers:
- **Unit (CI-safe, TDD):** config/derivation + the kind render (golden kind `Cluster` configs + the clab topo with `k8s-kind` nodes) — `nix develop --command bash -c 'cd test/lab && go test ./internal/... ./topology/...'`. Write render tests with `-update` to regenerate goldens, then eyeball.
- **Live checkpoints (fabric host):** run in the devShell; live commands need real root: `sudo -E env "PATH=$PATH" ...`. Build the CLI with `cd test/lab && go build -o /tmp/lab .`. Commit after every green step. Leave untracked `central/broker`, `central/controller`, `go.work.sum` alone — and **never `git add -A`** (it stages those binaries); add explicit paths.

**Reference files to PORT (read, do not delete until Task 7):** `hack/clab/ipv6-fabric.clab.yml` (the `k8s-kind` node blocks ~lines 84-110), `hack/clab/kind-cluster.yaml` + `hack/clab/kind-cluster-k03.yaml` (the kind `Cluster` config + extraMounts), `hack/clab/env.sh` (`CLAB_IMAGE_KINDNODE`, `CLAB_PREFIX_DIR`), `hack/clab-up.sh` (the prefix/uplinks file rendering + Cilium loop), `hack/kind-fabric-node/fabric-preboot.sh` (the node's BGP/identity preboot).

**Current bring-up (`topology/fabric.go` `Up`):** Render → `clab deploy` → host→fabric route → per cluster { `talos.Bootstrap` → `WaitAPIServer` → Cilium `HelmInstall` → `WaitNodesReady` } → `deployEctobase`. The kind path replaces `talos.Bootstrap` with "collect the kind kubeconfig"; everything after `WaitAPIServer` is reused.

---

## Task 1: Fabric view accessors for the kind render

**Files:**
- Modify: `test/lab/internal/fabric/fabric.go`
- Modify/verify: `test/lab/internal/config/config.go`, `test/lab/internal/config/derive.go`

The render needs, per node: the node's underlay `/64` (the `prefix` file), the fabric uplink iface names (the `uplinks` file), the kind-node image, and the in-fabric registry mirror endpoint. Most already exist on `View`/`DerivedNode`.

- [ ] **Step 1: Confirm/add View accessors**

Grep what exists: `grep -nE "RegistryEndpoint|RegistryAddr|NodeNet64|IdentityAddr|Uplink|eth1|eth2|KindNode|Images" test/lab/internal/fabric/fabric.go test/lab/internal/config/derive.go`.
Ensure these are available to templates (add as `View` methods if missing, mirroring existing accessors):
- `func (v *View) RegistryEndpoint() string` — already exists (`http://[fd00:29::5]:5000`); add `RegistryHost() string` returning `[fd00:29::5]:5000` (host:port, no scheme) for the containerd mirror.
- `DerivedNode.NodeNet64` — the node's `/64` (already derived; for 1-node/cluster it equals the cluster `NodeNet64`). Confirm it is on `DerivedNode` (it was added for the ToR /64 origination); if only on `DerivedCluster`, expose a per-node accessor.
- Fabric uplink ifaces: the node's clab links are `eth1`↔sw1, `eth2`↔sw2 (see the clab template). Add `func (v *View) NodeUplinks() string { return "eth1 eth2" }` (space-separated, matches `kind-node-fabric`'s `/etc/fabric/uplinks`).
- The kind-node image: add `kindNode` to `lab.yaml` `images:` (`ghcr.io/trevex/ectobase/kind-node-fabric:dev`) and expose via the existing `Images` map the templates already read.

- [ ] **Step 2: Unit test + commit**

Add/extend `fabric_test.go` asserting `RegistryHost()` = `[fd00:29::5]:5000` and `NodeUplinks()` = `eth1 eth2`.
Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/fabric/ ./internal/config/'` → PASS.
Commit: `git add test/lab/internal/fabric test/lab/internal/config test/lab/lab.yaml && git commit -m "feat(lab): view accessors for the kind render (registry host, uplinks, kind-node image)"`.

---

## Task 2: Render kind clusters (clab `k8s-kind` nodes + kind `Cluster` configs + prefix/uplinks)

**Files:**
- Create: `test/lab/templates/k8s/kind-cluster.yaml.tmpl`
- Modify: `test/lab/templates/fabric.clab.yml.tmpl` (cluster-node block → `k8s-kind`)
- Modify: `test/lab/topology/fabric.go` (`Render` writes per-node `prefix`/`uplinks` + the kind `Cluster` config; stop rendering Talos configs)
- Create/Modify: golden `test/lab/internal/render/testdata/golden/*` + `test/lab/internal/render/kind_test.go`

- [ ] **Step 1: kind `Cluster` config template (TDD-ish via golden)**

Create `templates/k8s/kind-cluster.yaml.tmpl`, ported from `hack/clab/kind-cluster.yaml`, parameterised per cluster. It is rendered once per cluster to `build/<name>/kind/<cluster>-kind.yaml`:
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv6
  disableDefaultCNI: true
  kubeProxyMode: none
# Pull :dev + upstream images through the in-fabric registry mirror (fabric-parity
# with the removed Talos machine.registries.mirrors). {{ .RegistryHost }} = [fd00:29::5]:5000.
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."ghcr.io"]
      endpoint = ["http://{{ .RegistryHost }}"]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."quay.io"]
      endpoint = ["http://{{ .RegistryHost }}"]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
      endpoint = ["http://{{ .RegistryHost }}"]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
      endpoint = ["http://{{ .RegistryHost }}"]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."gcr.io"]
      endpoint = ["http://{{ .RegistryHost }}"]
    [plugins."io.containerd.grpc.v1.cri".registry.configs."{{ .RegistryHost }}".tls]
      insecure_skip_verify = true
nodes:
  - role: control-plane
    image: {{ index .Images "kindNode" }}
    extraMounts:
      - hostPath: {{ .PrefixPath }}
        containerPath: /etc/fabric/prefix
        readOnly: true
      - hostPath: {{ .UplinksPath }}
        containerPath: /etc/fabric/uplinks
        readOnly: true
```
Where `PrefixPath`/`UplinksPath` are absolute paths under `build/<name>/kind/` (kind rejects relative extraMounts). The template's data is a small per-cluster struct (cluster name, node, RegistryHost, Images, PrefixPath, UplinksPath) built in `Render`.

- [ ] **Step 2: clab topology `k8s-kind` node**

In `fabric.clab.yml.tmpl`, replace the cluster-node block (currently `kind: linux` + `image: talos` + `env-files: [talos/...]`) with, per node:
```yaml
    {{ $n.Cluster }}-{{ $n.Index }}:
      kind: k8s-kind
      startup-config: kind/{{ $n.Cluster }}-kind.yaml
      k8s_kind:
        deploy:
          wait: 180s   # clab k8s-kind boot-marker scan; must exceed the node preboot delay
```
Keep the same clab **links** (`<node>:eth1 ↔ sw1:ethX`, `<node>:eth2 ↔ sw2:ethX`) so the fabric wiring is identical. (Confirm the link block is separate from the node block; only the node `kind`/image/env changes.)

- [ ] **Step 3: `Render` writes the kind artifacts, not Talos**

In `topology/fabric.go` `Render`, replace the Talos per-cluster gen with: for each cluster, for each node, write `build/<name>/kind/<cluster>-<index>.prefix` (= `n.NodeNet64`), one `build/<name>/kind/<cluster>-uplinks` (= `v.NodeUplinks()`), and render `kind/<cluster>-kind.yaml` from the template with absolute `PrefixPath`/`UplinksPath`. Then render the clab topo (now with `k8s-kind` nodes). Do NOT call `talos.Gen`.

- [ ] **Step 4: Golden render test (unit)**

Add `internal/render/kind_test.go` (or extend the existing render test) that renders a 3-cluster fixture and asserts the clab golden contains `kind: k8s-kind` + `startup-config: kind/central-kind.yaml`, and that a `central-kind.yaml` golden contains `ipFamily: ipv6`, `disableDefaultCNI: true`, the `kindNode` image, the two `extraMounts`, and the registry mirror for `ghcr.io`. Regenerate goldens:
Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/render/ -update && go test ./internal/render/ -v'` → PASS. Eyeball the diff (Talos goldens will be removed in Task 6).

- [ ] **Step 5: `lab render` sanity + commit**

Run: `nix develop --command bash -c 'cd test/lab && go build -o /tmp/lab . && export LAB_CONFIG=$PWD/lab.yaml && sudo -E env "PATH=$PATH" /tmp/lab render'`; confirm `build/ectobase/ectobase.clab.yml` has `k8s-kind` nodes and `build/ectobase/kind/*-kind.yaml` exist. (Ignore any remaining Talos-render code path for now.)
Commit: `git add test/lab/templates test/lab/topology/fabric.go test/lab/internal/render && git commit -m "feat(lab): render kind clusters (k8s-kind nodes + kind Cluster configs + prefix/uplinks)"`.

---

## Task 3: kind bring-up in `topology.Up` (LIVE checkpoint)

**Files:**
- Modify: `test/lab/topology/fabric.go` (`Up`), possibly `test/lab/internal/deploy/k8s.go` (a `kindKubeconfig` helper)

- [ ] **Step 1: Replace the Talos bootstrap with kind kubeconfig collection**

In `Up`, replace the per-cluster `talos.Bootstrap(...)` call with collecting the kind kubeconfig into `p.clusterKubeconfig(cl.Name)`. clab's `k8s-kind` creates a kind cluster named after the clab node (or `<lab>-<cluster>`); resolve the kind cluster name (grep `hack/clab-up.sh`/clab docs — likely `<node>` or the topo default) and run `kind get kubeconfig --name <kindname> --internal=false` into the file, OR copy from where clab writes it. Add a helper:
```go
// writeKindKubeconfig writes cluster's kind kubeconfig to dst. The kind cluster
// name is the clab k8s-kind node name.
func writeKindKubeconfig(ctx context.Context, kindName, dst string) error {
    out, err := exec.Output(ctx, "kind", "get", "kubeconfig", "--name", kindName)
    if err != nil { return fmt.Errorf("kind get kubeconfig %s: %w", kindName, err) }
    return os.WriteFile(dst, out, 0o600)
}
```
Keep the rest of the loop: `WaitAPIServer` → Cilium `HelmInstall(p.ciliumValues(cl.Name))` → `WaitNodesReady`. (Cilium values are unchanged; verify `p.ciliumValues` doesn't reference Talos-only fields.) Then `deployEctobase`.

- [ ] **Step 2: Build + LIVE bring-up**

Prune disk first if needed (`docker builder/image/volume prune`, per the disk-pressure notes). Ensure the `kind-node-fabric:dev` image is present (`docker images | grep kind-node-fabric`; else `make image-kindnode` or the Makefile `KINDNODE_IMAGE` target). Then:
Run: `cd test/lab && go build -o /tmp/lab . && export LAB_CONFIG=$PWD/lab.yaml && nix develop --command bash -c 'sudo -E env "PATH=$PATH" /tmp/lab up'`
Expected: all clusters Ready; `deployEctobase` reaches both compute pools Ready with nodePrefixes.
**LIVE-ITERATE:** the kind cluster name resolution for the kubeconfig; clab k8s-kind wait timing; Cilium install on kind; the host→fabric route (reused). Each fix is its own commit.

- [ ] **Step 3: Commit** `feat(lab): kind bring-up in topology.Up (clab k8s-kind + kubeconfig collection)`.

**LIVE CHECKPOINT:** `lab up` (kind) → all clusters Ready + both compute pools Ready.

---

## Task 4: Fabric-only egress + registry reachability for kind (LIVE)

**Files:**
- Modify: `hack/kind-fabric-node/fabric-preboot.sh` (or a small addition) + rebuild the image
- Possibly: `test/lab/topology/fabric.go` (host egress setup is reused as-is)

The kind node must (a) reach the in-fabric registry `fd00:29::5` and pull upstreams over the fabric, and (b) prefer the switch RA default over docker's default (fabric-only egress, the Talos analog).

- [ ] **Step 1: Confirm the gap live**

After Task 3's `lab up`, on a kind node netns check: `ip -6 route show default` (is there a `proto ra` fabric default, and does the docker default outrank it?) and `curl`/pull test to `[fd00:29::5]:5000/v2/`. Determine whether images pulled via the mirror (containerd logs) and whether egress is fabric-only.

- [ ] **Step 2: Add RA-default + docker-default-demote to the preboot**

In `hack/kind-fabric-node/fabric-preboot.sh`, after the FRR/BGP setup, on each uplink set `net.ipv6.conf.<uplink>.accept_ra=2` (accept the RA default even with forwarding on — the exact lesson from the Talos accept_ra work), and demote the docker default (`ip -6 route del default via <docker-gw> dev eth0 2>/dev/null; ip -6 route add default via <docker-gw> dev eth0 metric 4096`), matching the Talos api-vip static pod's demote loop. Rebuild the image (`make image-kindnode TAG=dev` or the KINDNODE_IMAGE target).

- [ ] **Step 3: Re-up + verify LIVE**

`lab down` (kind `down` is clean — no zombie) then `lab up`. Verify a kind node reaches native-v6 + v4-via-NAT64 over the fabric (metric-1024 fabric default; mgmt only 4096), and images pull via the mirror. **LIVE-ITERATE** the egress (the Talos harness needed the per-switch RA + host NAT66 + FRR distance fixes — the fabric side of those is unchanged; only the node-side accept_ra/demote is new).

- [ ] **Step 4: Commit** `fix(lab): fabric-only egress + registry mirror for kind nodes (accept_ra + demote docker default)`.

---

## Task 5: Ceph + Tier-2 on kind (LIVE — the payoff)

**Files:** none new (validation + any live-found harness fixes).

- [ ] **Step 1: `lab ceph` + `TestRBDPVCBinds`**

Set `fabric.ceph.enabled: true` (already), `lab up` with ceph, then `lab ceph`, then `... go test -tags live -run TestRBDPVCBinds ./livetest/...`.
**LIVE-ITERATE:** krbd on kind — kind gives the kubelet a real `/dev`, so `EnsureNodeKrbd` may Just Work; if `rbd map` still can't see `/dev/rbdN`, the nodeplugin-devtmpfs approach (already implemented) applies. The Cilium route-source masquerade (already in `cilium-values`) makes pod→mon work.

- [ ] **Step 2: `lab tier2 up` + `TestTier2Failover` (THE gate)**

`lab tier2 up` (KubeVirt+CDI+materializer+fsid — unchanged), then `... go test -tags live -timeout 45m -run TestTier2Failover -v ./livetest/...`.
Expected: fixture→CompiledVM→broker→materializer→VMI `default-tier2-vm` + RBD; `docker kill` k02 (reliable on kind) → NetworkFence `Succeeded` + ceph blocklist + VM rebinds k03 + VMI on k03; recovery releases the fence.
**LIVE-ITERATE:** the guest need not fully boot (kind CDI/emulation limits are fine — the gate is fence+reschedule+RBD). The robust `hardKillNode` still works; on kind plain `docker kill` succeeds.

- [ ] **Step 3: Full `livetest` suite**

Run `... /tmp/lab test` (the whole suite: overlay ping, apivip, egress, registry, BGP/ECMP, ceph, tier2). Fix any substrate-sensitive assertion (e.g. a check that hardcoded a Talos detail). Commit fixes individually.

**LIVE CHECKPOINT:** `TestTier2Failover` green on kind + full `livetest` suite green.

---

## Task 6: Remove the Talos substrate

**Files:**
- Delete: `test/lab/internal/talos/**`, `test/lab/templates/talos/**`, Talos render goldens under `internal/render/testdata/golden/` (cluster-central/k02 talos configs), any Talos-only fixtures.
- Modify: `test/lab/topology/fabric.go` (remove the Talos import + any dead branch + the `taints:{}` strip if it lived in `talos.Gen` — it's deleted with the package), `internal/render` (remove Talos template refs), `lab.yaml` (drop the `talos` image key).

- [ ] **Step 1: Delete + de-reference**

`git rm -r test/lab/internal/talos test/lab/templates/talos`; remove the Talos golden files; drop the `talos:` image from `lab.yaml` + the `talos` case anywhere. Grep for leftover refs: `grep -rn "internal/talos\|templates/talos\|talos\." test/lab | grep -v _test`.

- [ ] **Step 2: Build + unit + `make chart-test`**

Run: `nix develop --command bash -c 'cd test/lab && go build ./... && go test ./internal/... ./topology/...'` → PASS. `make chart-test` unaffected (chart untouched).

- [ ] **Step 3: Commit** `refactor(lab): remove the Talos node substrate (kind is the substrate)`.

---

## Task 7: Remove the bash `hack/clab` fabric + superseded scripts

**Files:**
- Delete: `hack/clab/**`, `hack/clab-up.sh`, `hack/clab-down.sh`, `hack/tier2-failover-e2e.sh`, `hack/ceph-demo-up.sh`, `hack/ceph-external-up.sh`, `hack/csi-addons-up.sh`, `hack/install-stack.sh`, `hack/multicluster-e2e.sh`, `hack/rook-ceph-up.sh`.

- [ ] **Step 1: Audit references before deleting**

Grep the repo (excluding memory) for references so nothing live breaks: `grep -rn "hack/clab\|tier2-failover-e2e\|ceph-demo-up\|ceph-external-up\|csi-addons-up\|install-stack\|multicluster-e2e\|rook-ceph-up" --include='*.go' --include='*.sh' --include='Makefile' --include='*.md' . | grep -v docs/superpowers`. Update/remove any `Makefile` targets that call them. Keep `hack/kind-fabric-node/` (the kind-node image source) and `hack/bpf-cleanup.sh` (still used).

- [ ] **Step 2: Delete + build**

`git rm` the listed paths + any dead Makefile targets. Run `make chart-test` + `nix develop --command bash -c 'cd test/lab && go build ./...'` → PASS.

- [ ] **Step 3: Commit** `chore: remove the bash hack/clab fabric + tier2/ceph/csi scripts (superseded by the Go lab)`.

---

## Task 8: Docs + final verification + finish

**Files:** Modify `test/lab/README.md`; new `docs/superpowers/plans/...` untouched.

- [ ] **Step 1:** Rewrite `test/lab/README.md` for the kind substrate: `lab up`/`down`/`render`/`deploy`/`ceph`/`tier2`/`test`; the kind-node-fabric image + fabric egress; the `ceph.enabled` toggle; the live tests incl. `TestTier2Failover`; the kind/krbd notes. Remove Talos-specific text.

- [ ] **Step 2: Final verification:**
  - Unit: `nix develop --command bash -c 'cd test/lab && go test ./internal/... ./topology/...'` green.
  - Live: `lab up` (kind) → `lab ceph` → `lab tier2 up` → `lab test` (full suite incl. `TestTier2Failover`) green.
  - Regression: `make chart-test` green; central envtests green (`nix develop --command bash -c 'cd central && go test ./...'`); `git grep -n "internal/talos\|hack/clab"` empty (outside docs/memory).

- [ ] **Step 3: Commit** `docs(lab): document the kind substrate + Tier-2 gate`; then run `superpowers:finishing-a-development-branch`.

---

## Self-review notes

- **Spec coverage:** reuse (§Architecture)→T1/T3/T5; render change→T2; bring-up→T3; fabric egress→T4; ceph/tier2 payoff→T5; remove Talos→T6; remove bash→T7; testing→T2 (unit) + T3/T4/T5 (live); success criteria→T5/T8. No gaps.
- **Ordering:** build+validate kind (T1-T5) BEFORE deleting Talos/bash (T6-T7), so the harness is never broken mid-way. T7 audits references before deletion.
- **Live-resolved details (flagged, not placeholders):** kind kubeconfig cluster-name resolution (T3); fabric egress accept_ra/demote (T4); krbd on kind (T5) — each has a concrete probe + fallback.
- **Type consistency:** `RegistryHost()`, `NodeUplinks()`, `writeKindKubeconfig(ctx, kindName, dst)`, `PrefixPath`/`UplinksPath`, image key `kindNode` used consistently across tasks.
