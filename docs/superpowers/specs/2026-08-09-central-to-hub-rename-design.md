# Rename `central` → `hub` (Effort 1 of the layout/rename work)

**Status:** Approved design (2026-08-09). Execution is a single subagent-driven round + a live clab sweep.

**Goal:** Rename the fleet control-plane component from `central` to `hub` everywhere it appears — the Go module + directory, the three container images, the Kubernetes object names, the code identifiers, and the fabric's kind cluster — so the naming is consistent and no longer generic.

**Architecture:** A large but mechanical rename. The component is the aggregated apiserver + fleet controllers (scheduler/failover/clusterpool/broker) that today lives in `central/` (module `github.com/trevex/ectobase/central`, images `central-{apiserver,controller,broker}`, kind cluster `central`). Every occurrence moves to `hub`. Correctness is gated by the full build + envtest matrix AND the live clab sweep — the R3 group-split showed that deploy-path naming (images, SA names, cluster names, kubeconfig filenames) hides bugs no static gate catches.

**Tech Stack:** Go (module rename via `go.work` + `replace` directives), Docker (image tags + Dockerfiles), Helm chart values, the `test/lab` fabric CLI (cluster topology + kubeconfigs + deploy), nix devShell tooling. `hub` builds `GOWORK=off` (as `central` did).

**Branch:** `feat/rename-central-to-hub` off `main`.

---

## Scope (from the approved decision: "Everything")

Rename covers all five layers:

### 1. Go module + directory
- `central/` → `hub/` (`git mv`).
- Module path `github.com/trevex/ectobase/central` → `github.com/trevex/ectobase/hub` in `hub/go.mod`.
- Update the ~93 Go files importing `.../central/...` → `.../hub/...` (across `hub/`, `netplane/`, `test/lab/`, and any other module).
- `go.work`: `./central` → `./hub`.
- `replace` directives: `hub/go.mod` keeps `replace github.com/trevex/ectobase/api => ../api`, `... => ../netplane`, and the apiserver-kit replace; any module that `require`s the renamed module (e.g. `test/lab/go.mod`) updates its `replace .../central => ../central` to `.../hub => ../hub`.
- The `hub/bin/.modules` codegen workaround dir moves with `hub/`.

### 2. Container images
- `ghcr.io/trevex/ectobase/central-{apiserver,controller,broker}` → `ghcr.io/trevex/ectobase/hub-{apiserver,controller,broker}`.
- `central/Dockerfile.{apiserver,controller,broker}` → `hub/Dockerfile.*` (move with the dir).
- `hub/hack/smoke.sh` image vars (`APISERVER_IMG` etc.).
- `test/lab/lab.yaml` registry `push:` list (`central-apiserver` → `hub-apiserver`, etc.).
- `hack/r3-live-sweep.sh` central image build block.

### 3. Kubernetes object names
- Deployments/ServiceAccounts/ClusterRoles/ClusterRoleBindings named `central-{apiserver,controller,broker}` → `hub-*` in `hub/config/*.yaml` and the chart broker template.
- Reconcile the broker identity naming: the chart's downstream broker SA `central-broker` and the lab-minted central-side identity `ectobase-broker` both become `hub-broker` (pick one consistent name; `hub-broker` for both the downstream SA and the central-side identity, updating the ClusterRoleBinding subjects + the lab deploy's minted role/binding + the `broker.centralKubeconfigSecret` wiring).
- The APIService `service.name: apiserver-service` in `hub/config/apiservice.yaml` stays (it's not "central"-named); the serving namespace `system` stays (a separate name, out of scope).

### 4. Code identifiers
- Exported/flag identifiers: `CentralIdentity` → `HubIdentity`, `--central-kubeconfig` → `--hub-kubeconfig`, `centralKubeconfig` locals, `broker.centralKubeconfigSecret` (chart value) → `hubKubeconfigSecret`, `Central` fields in the lab deploy `State`/config.
- Comments + log strings mentioning "central" → "hub" where they name the component (leave generic English uses of the word "central" alone if any).

### 5. Fabric kind cluster
- `test/lab/lab.yaml` `clusters: [{name: central, ...}]` → `{name: hub, ...}`.
- `test/lab/internal/config/derive_test.go` + any golden fixtures referencing cluster `central`.
- The clab/kind node name `central-control-plane` → `hub-control-plane` (derived from the cluster name — verify the topology renderer derives it).
- Kubeconfig filename `build/ectobase/central.kubeconfig` → `hub.kubeconfig` (derived from cluster name).
- The apiserver address / API VIP and the name-derived IPv6 prefix for the cluster (the deriver hashes/orders by cluster name — renaming `central`→`hub` changes the derived prefix; that is fine as long as it is internally consistent, which it is because everything derives from the one name).
- Any hardcoded `"central"` cluster references in `test/lab/internal/deploy/*.go` (e.g. `applyCentral`, which targets the central cluster) → `hub` (`applyHub` or keep the function name but point at the `hub` cluster — the function name is a code identifier, rename to `applyHub` for consistency).

## Non-goals (this effort)

- The namespace `system` (where the hub components run) is not renamed.
- The `config/` layout, moving `deploy/charts` to top-level, and **generating CRDs + RBAC into the chart from `+kubebuilder:rbac` markers (SolAr-style)** are **Effort 2** — deferred. Note: Effort 2 will regenerate/replace the hand-maintained RBAC this effort renames, so the RBAC renames here are interim; that is acceptable (each effort lands green independently).
- The `platform.ectobase.dev` group / any API group name is unchanged (groups are `*.ectobase.dev`, not `central`).

## Execution & green gates

Mechanical order (each step keeps the tree buildable):
1. `git mv central hub`; rewrite the module path + all import paths (`.../central` → `.../hub`) + `go.work` + `replace`s; `go build ./...` per module green.
2. Rename images (Dockerfiles, smoke.sh, lab.yaml push list, sweep script) + k8s object names (hub/config + chart) + the broker identity consolidation.
3. Rename code identifiers (`CentralIdentity`, `--central-kubeconfig`, chart value, lab `State`) + comments/logs.
4. Rename the fabric cluster `central` → `hub` (lab.yaml, deriver, node name, kubeconfig, `applyCentral`→`applyHub`) + fix the `derive_test.go` golden.
5. Regenerate anything generated (client-go/openapi under `hub/client-go`, chart `render.sh` goldens if object names changed).

**Green gates:**
- `hub`, `netplane`, `cni`, `api`, `test/lab` all `go build ./...`; `hub` builds `GOWORK=off`.
- `hub` envtests (real apiserver: TestVPC_CRUD / TestCompiledNIC selector / broker / scheduler) + netplane controller envtests pass.
- `render.sh` / `make chart-test` pass (chart object-name goldens updated for `hub-*`).
- **Live clab sweep green** (`hack/r3-live-sweep.sh` — now building `hub-*` images, bringing up the `hub` kind cluster): the deploy must come up with the renamed images/SAs/cluster and the full live suite (21/21) must pass. This is the real gate — the R3 saga proved image/SA/cluster/kubeconfig naming drift only surfaces on a live fabric.

## Risks & mitigations

- **Missed reference breaks the deploy silently** (an image tag, SA-name binding, or kubeconfig filename left as `central`). Mitigation: grep for residual `central` after each step (`grep -rniI 'central' --exclude-dir=.git` scoped per layer) and rely on the live sweep as the backstop.
- **Cluster-name-derived state** (IPv6 prefixes, kubeconfig paths, node names) must all derive from the single `hub` name — verify the deriver + `derive_test.go` golden together, and confirm no hardcoded `central-control-plane` / `central.kubeconfig` strings remain.
- **The word "central" as ordinary English** in unrelated comments — do not blanket-replace; scope renames to component/identifier/deploy references.
