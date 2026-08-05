# Tier-2 Live Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Prove Tier-2 fence-gated failover for real on the clab fabric — a stateful RBD-backed KubeVirt VM reschedules from a killed pool (k02) to a healthy one (k03), fenced from outside via a shared-Ceph `NetworkFence` + reflector route-withdrawal, disk following.

**Architecture:** Reuse the existing 3-cluster clab fabric (k01 central + reflector, k02/k03 compute). Add a `ceph/demo` **fabric node** (own /64), external ceph-csi in all three clusters, csi-addons **in k01** (fence executor, survives k02 death), a **broker Deployment** in the ectobase chart, and controller flag-wiring so the deployed failover controller runs the real fencers. A best-effort `hack/tier2-failover-e2e.sh` drives the live gate.

**Tech Stack:** containerlab (IPv6 BGP fabric), kind, Helm, KubeVirt/CDI, Rook/`ceph/demo`, ceph-csi (external mode), csi-addons `NetworkFence`, Go (central-broker image).

**Spec:** `docs/superpowers/specs/2026-08-05-tier2-live-gate-design.md`
**Branch:** `feat/tier2-live-gate` (exists).

---

## Validation model (READ FIRST)

This effort's core is **live multi-cluster infra**. Subagents can only validate at the **build level** — the actual fence/reschedule proof is a **live run on the fabric host**. Per task, the "test" is the strongest thing achievable without the fabric:
- Chart/RBAC/controller-args changes → `make chart-test` (render + kustomize-parity, real automated gate).
- Shell scripts → `nix develop --command bash -c 'bash -n <script> && <script> --help'`.
- The `central-broker` image → it builds.
- clab topology / ceph / csi YAML → `yaml`-parse + structural checks; **marked LIVE-ITERATE** — correct starting point, expected to need iteration on the fabric.

Each Phase ends with a **LIVE CHECKPOINT** (run on the fabric host) that is the real gate for that layer. The already-green **multi-envtest Tier-2** (`central/test/tier2_failover_e2e_test.go`) remains the authoritative *logic* gate — unaffected here.

Run tooling in the nix devShell: `nix develop --command bash -c '...'`. Live fabric commands need `sudo` (real `/run/wrappers/bin/sudo`) + docker + containerlab on the host.

---

## File Structure

**Phase 1 — Ceph fabric node + external ceph-csi**
- `hack/clab/ipv6-fabric.clab.yml` (modify) — add `ceph` node + `ceph-frr` sidecar + sw1/sw2 links.
- `hack/clab/prefixes/` (add) — ceph node's `fd00:db8:0:5::/64`.
- `hack/ceph-demo-up.sh` (create) — create `replicapool`, emit external-cluster params.
- `hack/ceph-external-up.sh` (create) — install external ceph-csi + secret + StorageClass into a target cluster.
- `hack/install-stack.sh` (modify) — `INSTALL_CEPH_EXTERNAL=1` wiring.

**Phase 2 — csi-addons (fence executor in k01)**
- `hack/csi-addons-up.sh` (create) — install csi-addons controller + `NetworkFence` CRD (pinned).
- `hack/install-stack.sh` (modify) — `INSTALL_CSI_ADDONS=1` wiring.

**Phase 3 — Broker deploy + controller wiring (chart-test-covered)**
- `central/Dockerfile.broker` or extend `central/hack/smoke.sh` (create/modify) — build `central-broker:dev`.
- `deploy/charts/ectobase/templates/broker.yaml` (create) — broker Deployment (gated).
- `deploy/charts/ectobase/templates/rbac.yaml` (modify) — broker SA + ClusterRole (+ central-side role fixture).
- `deploy/charts/ectobase/values.yaml` + `values.schema.json` (modify) — `broker` block + `images.centralBroker`.
- `central/config/controller.yaml` (modify) — failover controller args.
- `config/deploy/*` + `deploy/charts/ectobase/tests/render.sh` (modify) — chart-test coverage.

**Phase 4 — The e2e gate**
- `test/e2e/fixtures/multicluster-tier2/` (create) — VirtualMachine + Volume fixtures.
- `hack/tier2-failover-e2e.sh` (create) — the live gate driver.

---

## Phase 3 first? No — build order is 1→4 (each layer is a prerequisite of the next's live checkpoint). But Phase 3 (chart/config) is the only fully build-testable layer, so its tasks are the most prescriptive. Phases 1/2/4 produce correct-starting-point artifacts + live checkpoints.

---

## Task 1: Ceph fabric node in the clab topology

**Files:**
- Modify: `hack/clab/ipv6-fabric.clab.yml`
- Add: `hack/clab/prefixes/ceph` (or the repo's per-node prefix mechanism — inspect `hack/clab/prefixes/` first)

- [ ] **Step 1: Inspect the per-node /64 + sidecar mechanism**

Run: `nix develop --command bash -c 'ls hack/clab/prefixes/; sed -n "1,40p" hack/clab/kind-cluster-k02.yaml; sed -n "1,30p" hack/clab/frr/sw1.conf'`
Note how a node's /64 is assigned (kind nodes bake `fabric-preboot`; a non-kind node needs an FRR sidecar sharing its netns, like the old `edge1-xdp` pattern) and how sw1/sw2 accept a new uplink (eth6).

- [ ] **Step 2: Add the ceph node + FRR sidecar + links**

In `hack/clab/ipv6-fabric.clab.yml`, add under `topology.nodes` (a `ceph` container + a `ceph-frr` sidecar sharing its netns that creates `dummy0` `fd00:db8:0:5::1/64` and speaks unnumbered eBGP over eth1/eth2 — mirror the mechanism the kind `fabric-preboot` uses; the sidecar is the non-kind-node analog):

```yaml
    # --- shared Ceph for Tier-2 storage fencing: a fabric node with its own /64 so
    # each compute node's Ceph client is seen from its /64 underlay (the fence coordinate). ---
    ceph:
      kind: linux
      image: quay.io/ceph/demo:latest
      env:
        MON_IP: fd00:db8:0:5::1
        CEPH_PUBLIC_NETWORK: fd00:db8:0:5::/64
        CEPH_DEMO_UID: demo
      binds:
        - ceph-etc:/etc/ceph
        - ceph-data:/var/lib/ceph
      sysctls:
        net.ipv6.conf.all.forwarding: 1
    # FRR sidecar sharing ceph's netns: creates dummy0 (fd00:db8:0:5::1/64) + unnumbered eBGP
    # over eth1/eth2, exactly as the kind nodes' fabric-preboot does for their /64s.
    ceph-frr:
      kind: linux
      image: frrouting/frr:latest
      network-mode: container:clab-xdp-ipv6-fabric-ceph
      binds:
        - frr/daemons:/etc/frr/daemons
        - frr/ceph.conf:/etc/frr/frr.conf
        - ceph-preboot.sh:/ceph-preboot.sh:ro
      entrypoint: "/bin/sh /ceph-preboot.sh"
      sysctls:
        net.ipv6.conf.all.forwarding: 1
```

Add to `topology.links`:
```yaml
    - endpoints: ["ceph:eth1", "sw1:eth6"]
      mtu: 3000
    - endpoints: ["ceph:eth2", "sw2:eth6"]
      mtu: 3000
```

- [ ] **Step 3: Add `hack/clab/frr/ceph.conf` + `hack/clab/ceph-preboot.sh`**

`frr/ceph.conf` — mirror an existing host FRR config (unnumbered eBGP to sw1/sw2, redistribute connected so `fd00:db8:0:5::/64` is announced). Copy the structure from how kind-node prefixes are announced (inspect the kind `fabric-preboot` + a host's generated FRR conf). `ceph-preboot.sh` creates `dummy0` with `fd00:db8:0:5::1/64` then `exec`s FRR.

- [ ] **Step 4: Structural validation (build-level)**

Run: `nix develop --command bash -c 'python3 -c "import yaml,sys; yaml.safe_load(open(\"hack/clab/ipv6-fabric.clab.yml\"))" && echo YAML_OK'`
Expected: `YAML_OK` (topology parses). Full validity is the Phase-1 LIVE CHECKPOINT.

- [ ] **Step 5: Commit**

```bash
git add hack/clab/ipv6-fabric.clab.yml hack/clab/frr/ceph.conf hack/clab/ceph-preboot.sh
git commit -m "feat(clab): shared ceph/demo fabric node (fd00:db8:0:5::/64) for Tier-2 storage fencing"
```

---

## Task 2: `hack/ceph-demo-up.sh` — pool + external-cluster params

**Files:** Create `hack/ceph-demo-up.sh`.

- [ ] **Step 1: Create the script**

Dev-only header + `--help` (mirror `hack/rook-ceph-up.sh`). It `docker exec`s the `clab-xdp-ipv6-fabric-ceph` container to: wait for `HEALTH_OK`, `ceph osd pool create replicapool`, `rbd pool init replicapool`, create a client key (`ceph auth get-or-create client.rbd mon 'profile rbd' osd 'profile rbd pool=replicapool'`), and print the external-cluster params (fsid via `ceph fsid`, mon `[fd00:db8:0:5::1]:6789`, the client key) to stdout + a `--out <file>` artifact the ceph-csi installer consumes.

```bash
#!/usr/bin/env bash
set -euo pipefail
# Create the RBD pool on the shared clab ceph/demo node + emit external-cluster
# connection params (fsid, mon, client key) for external ceph-csi. Dev-only.
# Usage: hack/ceph-demo-up.sh [--out params.env] | --help
CEPH_CTR="${CEPH_CTR:-clab-xdp-ipv6-fabric-ceph}"
MON="${MON:-[fd00:db8:0:5::1]:6789}"
POOL="${POOL:-replicapool}"
OUT="${1:-}"
if [ "${1:-}" = "--help" ]; then sed -n '3,6p' "$0"; exit 0; fi
ex() { docker exec "$CEPH_CTR" "$@"; }
echo "== waiting for ceph HEALTH_OK =="; for i in $(seq 1 60); do ex ceph -s 2>/dev/null | grep -q 'HEALTH_OK\|HEALTH_WARN' && break; sleep 5; done
ex ceph osd pool create "$POOL" 8 8 2>/dev/null || true
ex rbd pool init "$POOL" || true
KEY=$(ex ceph auth get-or-create-key client.rbd mon 'profile rbd' osd "profile rbd pool=$POOL")
FSID=$(ex ceph fsid)
printf 'CEPH_FSID=%s\nCEPH_MON=%s\nCEPH_POOL=%s\nCEPH_RBD_KEY=%s\n' "$FSID" "$MON" "$POOL" "$KEY" | tee "${OUT:-/dev/stdout}"
```

- [ ] **Step 2: Validate + commit**

Run: `nix develop --command bash -c 'chmod +x hack/ceph-demo-up.sh && bash -n hack/ceph-demo-up.sh && hack/ceph-demo-up.sh --help'`
Expected: syntax clean; `--help` prints the header.

```bash
git add hack/ceph-demo-up.sh
git commit -m "feat(hack): ceph-demo-up.sh — RBD pool + external-cluster params from the fabric ceph node"
```

---

## Task 3: `hack/ceph-external-up.sh` — external ceph-csi into a cluster

**Files:** Create `hack/ceph-external-up.sh`; Modify `hack/install-stack.sh`.

- [ ] **Step 1: Create the script**

Dev-only header + `--help`. Takes `--kubeconfig <kc>` + reads the params from `hack/ceph-demo-up.sh` (env or `--params <file>`). Installs upstream **ceph-csi RBD** (the `ceph-csi` Helm chart or manifests, pinned) in external mode, creates the cephx Secret (`userID: rbd`, `userKey: $CEPH_RBD_KEY`) + a `csi-rbd-config` ConfigMap (`clusterID: $CEPH_FSID`, `monitors: ["$CEPH_MON"]`), and a `ceph-rbd` StorageClass (`provisioner: rbd.csi.ceph.com`, `clusterID: $CEPH_FSID`, `pool: $CEPH_POOL`, secret refs). Idempotent (`kubectl apply`). **LIVE-ITERATE**: the exact ceph-csi manifest set + IPv6 mon handling is the Phase-1 live-checkpoint work.

- [ ] **Step 2: Wire into install-stack.sh**

Append after the Rook block: `if [ "${INSTALL_CEPH_EXTERNAL:-}" = "1" ]; then bash "$(dirname "$0")/ceph-external-up.sh"; fi`

- [ ] **Step 3: Validate + commit**

Run: `nix develop --command bash -c 'chmod +x hack/ceph-external-up.sh && bash -n hack/ceph-external-up.sh && hack/ceph-external-up.sh --help && bash -n hack/install-stack.sh'`
Expected: clean.

```bash
git add hack/ceph-external-up.sh hack/install-stack.sh
git commit -m "feat(hack): ceph-external-up.sh — external ceph-csi (RBD) install into a cluster"
```

- [ ] **Step 4: PHASE-1 LIVE CHECKPOINT (fabric host)**

`sudo ./hack/clab-up.sh` (fabric incl. ceph node) → `hack/ceph-demo-up.sh --out /tmp/ceph.env` → `hack/ceph-external-up.sh --kubeconfig <k02> --params /tmp/ceph.env` and same for k03 → apply a test `PersistentVolumeClaim` (storageClassName `ceph-rbd`) in **both** k02 and k03 → assert both bind (RBD provisioned from the shared Ceph). Iterate on IPv6/mon/auth failures. This is the real Phase-1 gate.

---

## Task 4: `hack/csi-addons-up.sh` — fence executor in k01

**Files:** Create `hack/csi-addons-up.sh`; Modify `hack/install-stack.sh`.

- [ ] **Step 1: Create the script**

Dev-only header + `--help`. Installs the **csi-addons controller + CRDs** (`NetworkFence`, etc.) at a pinned version via `kubectl apply -f` of the csi-addons release manifests, into the target cluster (k01). The csi-addons NetworkFence needs a ceph-csi RBD instance with the NetworkFence capability — Task 3's `ceph-external-up.sh` on **k01** provides that (k01 = fence executor, runs no VMs). Wire `INSTALL_CSI_ADDONS=1` into `install-stack.sh`.

- [ ] **Step 2: Validate + commit**

Run: `nix develop --command bash -c 'chmod +x hack/csi-addons-up.sh && bash -n hack/csi-addons-up.sh && hack/csi-addons-up.sh --help'`

```bash
git add hack/csi-addons-up.sh hack/install-stack.sh
git commit -m "feat(hack): csi-addons-up.sh — NetworkFence controller (k01 fence executor)"
```

- [ ] **Step 3: PHASE-2 LIVE CHECKPOINT (fabric host)**

On k01: `ceph-external-up.sh` + `csi-addons-up.sh`. Hand-apply a `NetworkFence` CR (`fenceState: Fenced`, `cidrs: [<a k02 node /64>]`, driver `rbd.csi.ceph.com`, the k01 cephx secret) → assert `status.result=Succeeded` AND `docker exec clab-xdp-ipv6-fabric-ceph ceph osd blocklist ls` contains the k02 client. Un-fence → assert the blocklist entry clears. This proves the storage-fence actuator on real Ceph.

---

## Task 5: `central-broker` image build

**Files:** Create `central/Dockerfile.broker` (or a build step in `central/hack/smoke.sh` — inspect how it host-builds central-apiserver/controller and mirror it).

- [ ] **Step 1: Inspect the existing central image build**

Run: `nix develop --command bash -c 'sed -n "20,70p" central/hack/smoke.sh'`
Note the host-build (GOWORK=off, CGO off, static) + distroless bake for `central-apiserver`/`central-controller`. Mirror it for `central/cmd/broker` → `central-broker:dev`.

- [ ] **Step 2: Add the broker build**

Add a `central-broker` build mirroring the apiserver/controller path (same base, `go build ./cmd/broker`, distroless). Whether a `Dockerfile.broker` or a smoke.sh step — follow whatever pattern the other two use.

- [ ] **Step 3: Validate (build the image)**

Run: `nix develop --command bash -c 'cd central && CGO_ENABLED=0 GOWORK=off go build -o /tmp/broker ./cmd/broker && echo BROKER_BUILT'`
Expected: `BROKER_BUILT` (the binary compiles static). The image bake is exercised live.

- [ ] **Step 4: Commit**

```bash
git add central/Dockerfile.broker central/hack/smoke.sh
git commit -m "build(central): central-broker image (mirrors apiserver/controller host-build)"
```

---

## Task 6: Broker Deployment in the ectobase chart

**Files:** Create `deploy/charts/ectobase/templates/broker.yaml`; Modify `deploy/charts/ectobase/templates/rbac.yaml`, `values.yaml`, `values.schema.json`.

- [ ] **Step 1: Add the values block**

`values.yaml` — append:
```yaml
# Per-cluster broker (kubelet-analog): syncs compiled objects from central down + heartbeats
# the ClusterPool lease + reports NodePrefixes. Off by default; on for compute clusters.
broker:
  enabled: false
  clusterName: ""                      # this cluster's pool name (e.g. k02); required when enabled
  centralKubeconfigSecret: broker-central-kubeconfig  # Secret (key: kubeconfig) with a central token
images:
  # (add to the existing images block)
  centralBroker: ghcr.io/trevex/ectobase/central-broker:dev
```
Add to `values.schema.json` a `broker` object (`enabled` bool, `clusterName` string, `centralKubeconfigSecret` string) + `images.centralBroker` string; extend the `ectobase.validate` guard: `broker.enabled=true` requires a non-empty `broker.clusterName`.

- [ ] **Step 2: Add the broker Deployment template**

`deploy/charts/ectobase/templates/broker.yaml` (gated), mirroring `reflector.yaml`'s structure:
```yaml
{{- if .Values.broker.enabled }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: central-broker
  namespace: ectobase-system
  labels:
    app.kubernetes.io/name: central-broker
    app.kubernetes.io/part-of: netplane
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: central-broker
  template:
    metadata:
      labels:
        app.kubernetes.io/name: central-broker
        app.kubernetes.io/part-of: netplane
    spec:
      serviceAccountName: central-broker
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - operator: Exists
      containers:
        - name: broker
          image: {{ .Values.images.centralBroker }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
          command: ["broker"]
          args:
            - "--cluster-name={{ .Values.broker.clusterName }}"
            - "--central-kubeconfig=/secrets/central/kubeconfig"
          volumeMounts:
            - name: central-kubeconfig
              mountPath: /secrets/central
              readOnly: true
      volumes:
        - name: central-kubeconfig
          secret:
            secretName: {{ .Values.broker.centralKubeconfigSecret }}
{{- end }}
```

- [ ] **Step 3: Add broker RBAC**

In `deploy/charts/ectobase/templates/rbac.yaml` (gated `{{- if .Values.broker.enabled }}`): a `central-broker` ServiceAccount + a ClusterRole/Binding granting downstream write on `compilednics`/`compiledvms`/`compiledvolumeattachments` (net.ectobase.dev, verbs get/list/watch/create/update/patch/delete) + read `nodes` + read KubeVirt `virtualmachineinstances`. (The central-side token identity's RBAC — patch `clusterpools/status` + read `Compiled*` on central — is provisioned by the e2e script's token-mint step, not the chart, since it lives in a different cluster.)

- [ ] **Step 4: chart-test coverage**

Extend `deploy/charts/ectobase/tests/render.sh`: `broker.enabled=false` → zero broker manifests; `broker.enabled=true,broker.clusterName=k02` → the Deployment renders with `--cluster-name=k02` + the SA/ClusterRole; `broker.enabled=true` with empty clusterName → `helm template` fails (the validate guard). Follow the existing `render_show_only`/`neg` idioms.

- [ ] **Step 5: Run chart-test + commit**

Run: `nix develop --command bash -c 'make chart-test 2>&1 | grep -E "broker|FAIL" ; make chart-test >/dev/null 2>&1 && echo GREEN || echo RED'`
Expected: broker checks PASS, GREEN.

```bash
git add deploy/charts/ectobase/templates/broker.yaml deploy/charts/ectobase/templates/rbac.yaml deploy/charts/ectobase/values.yaml deploy/charts/ectobase/values.schema.json deploy/charts/ectobase/tests/render.sh
git commit -m "feat(chart): per-cluster broker Deployment + RBAC (opt-in broker.enabled)"
```

---

## Task 7: Central failover controller flag-wiring

**Files:** Modify `central/config/controller.yaml`.

- [ ] **Step 1: Wire the args**

In `central/config/controller.yaml`, change the failover controller container `args: []` to:
```yaml
          args:
            - "-reflector-admin=[fd00:db8:0:1::1]:1338"
            - "-csi-driver=rbd.csi.ceph.com"
            - "-csi-secret-name=csi-rbd-secret"
            - "-csi-secret-namespace=ceph-csi"
```
(Match the real flag names from `central/cmd/controller/main.go` — grep `flag.String` there; and the real cephx secret name/namespace `hack/ceph-external-up.sh` creates in k01.)

- [ ] **Step 2: Validate + commit**

Run: `nix develop --command bash -c 'python3 -c "import yaml; list(yaml.safe_load_all(open(\"central/config/controller.yaml\")))" && echo YAML_OK'`
Expected: `YAML_OK`. (kustomize build of `central/config` is the live check.)

```bash
git add central/config/controller.yaml
git commit -m "feat(central): wire failover controller args (reflector-admin + csi secret) for the live gate"
```

---

## Task 8: VM + Volume fixtures + the e2e gate script

**Files:** Create `test/e2e/fixtures/multicluster-tier2/vm.yaml`, `hack/tier2-failover-e2e.sh`.

- [ ] **Step 1: Create the fixtures**

`test/e2e/fixtures/multicluster-tier2/vm.yaml`: a `VirtualMachine` (net.ectobase.dev, central, bound to pool k02 via the placement anchor) + a `Volume` (RBD, `storageClass: ceph-rbd`) + the VPC/NetworkInterface it needs (mirror `test/e2e/fixtures/multicluster/vpc-nics.yaml` + the KubeVirt fixture in `hack/kubevirt-vm-e2e.sh`). The compiler emits `CompiledVM` + `CompiledVolumeAttachment` (clusterName k02).

- [ ] **Step 2: Create `hack/tier2-failover-e2e.sh`**

Dev-only header + `--help`. Drives the §5 flow: assert pools Ready + NodePrefixes; boot the RBD VM on k02 + write a sentinel; peer(k03)→VM reachable; `docker kill` k02 node; assert NetworkFence `Succeeded` + `ceph osd blocklist ls` has k02 + reflector withdrew k02 routes (peer can't reach) + VM re-bound k03; assert VM Running on k03 with sentinel intact + reachable; restart k02 → assert fence released (blocklist clears). Best-effort; documents each assertion. Reuses `hack/multicluster-e2e.sh` token-mint + `hack/kubevirt-vm-e2e.sh` VM/ping patterns.

- [ ] **Step 3: Validate + commit**

Run: `nix develop --command bash -c 'chmod +x hack/tier2-failover-e2e.sh && bash -n hack/tier2-failover-e2e.sh && hack/tier2-failover-e2e.sh --help && python3 -c "import yaml; list(yaml.safe_load_all(open(\"test/e2e/fixtures/multicluster-tier2/vm.yaml\")))" && echo OK'`
Expected: syntax clean, `--help` prints, fixtures parse.

```bash
git add test/e2e/fixtures/multicluster-tier2/ hack/tier2-failover-e2e.sh
git commit -m "feat(hack): tier2-failover-e2e.sh — live two-cluster reschedule gate + VM/Volume fixtures"
```

- [ ] **Step 4: PHASE-4 LIVE CHECKPOINT (fabric host)**

Full run: `sudo ./hack/clab-up.sh` → `INSTALL_ROOK= INSTALL_CEPH_EXTERNAL=1 INSTALL_CSI_ADDONS=1` stacks + central + broker charts on k01/k02/k03 → `hack/tier2-failover-e2e.sh`. Iterate to green. **This is the real gate.**

---

## Final verification (after all tasks)

- [ ] Build-level green: `nix develop --command bash -c 'cd central && CGO_ENABLED=0 GOWORK=off go build ./cmd/broker && cd .. && make chart-test >/dev/null 2>&1 && echo GREEN'` + every `hack/*.sh` `bash -n` clean.
- [ ] No dataplane/Rust changes: `git diff --name-only main...HEAD | grep -E '^flowplane/|\.rs$'` — empty.
- [ ] Multi-envtest Tier-2 still green: `nix develop --command bash -c 'cd central && go test ./test/ -run Tier2'`.
- [ ] The live gate (Phases 1/2/4 checkpoints) run on the fabric host — best-effort; capture failures for iteration.
- [ ] Final holistic review of `git diff main...HEAD`, then `superpowers:finishing-a-development-branch`.
