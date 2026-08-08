# API Restructure — R3 (Group Split) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve the `compute` (VirtualMachine, Container), `storage` (Volume), and `compiled` (CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment) groups out of the monolithic `api/net` group into their own `api/<group>/(v1alpha1/)` packages + `*.ectobase.dev` API groups, leaving `net` with only the true networking types.

**Architecture:** Each carve is structurally identical to R2's platform/net move: `git mv` the per-type files (internal `<t>_types.go` + `<t>_rest.go`, external `v1alpha1/<t>_types.go`) into a new group package with its own `GroupName`/register/install/fuzzer/doc + `conversion-gen` marker, regenerate (conversions/deepcopy/openapi/client-go), update the apiserver registration + all consumers + the compiler's emitted `apiVersion` strings + per-group CRDs/RBAC/goldens. **Key simplifier proven during planning:** no compiled/compute/storage type embeds a `net` struct (the net-Kind names in compiled types are comments only); the sole cross-group type is the trivial `LocalObjectReference{Name string}` leaf, which each carved group gets its OWN copy of (YAGNI duplication of a 1-field value type — no shared package, no cross-group import, no codegen spike).

**Tech Stack:** Go (`api` + `central` + `netplane` + `cni` modules, go.work), `kube::codegen` (gen_helpers/openapi/client — pipeline stood up in R2), controller-gen (per-group CRDs), Helm chart RBAC + goldens, live clab kind fabric. Go tooling in the nix devShell (`nix develop --command bash -c '...'`); `central` builds `GOWORK=off`.

**Branch:** Continue on `feat/api-restructure` (R2 landed at `435e582`).

**Group → types → domain:**
| new group package | domain | types (Kinds) | needs local LocalObjectReference? |
|---|---|---|---|
| `api/compiled` | `compiled.ectobase.dev` | CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment | yes (CompiledNIC/VM/Container use it) |
| `api/compute` | `compute.ectobase.dev` | VirtualMachine, Container | yes (both use it) |
| `api/storage` | `storage.ectobase.dev` | Volume | no |
| `api/net` (remainder) | `net.ectobase.dev` | VPC, NetworkInterface, FirewallPolicy, FloatingIP, LoadBalancer, NATGateway, VPCPeering | keeps its own (+ PortStatus/PortType) |

**Facts established during planning:**
- `cmd/apiserver/main.go` registers each type via `apiserver.Resource(&netapi.<T>{}, netv1.SchemeGroupVersion)` and calls `netinstall.Install(scheme)` in `init()`. Each carved group needs its own `install.Install` + `Resource(&<g>api.<T>{}, <g>v1.SchemeGroupVersion)` lines.
- The compiler emits `TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1"}` for the four compiled types in `netplane/controllers/{compiledcontainer.go:42, compilednic.go:100, compiledvm.go:45, compiledvolumeattachment.go:39}` — these become `compiled.ectobase.dev/v1alpha1`.
- Chart RBAC (`deploy/charts/ectobase/templates/rbac.yaml`) has `net.ectobase.dev` blocks for netplane-agent (compilednics), netplane-controller (compilednics, virtualmachines+volumes, compiledvms+compiledvolumeattachments, containers, compiledcontainers), and central-broker (compilednics/compiledvms/compiledvolumeattachments/compiledcontainers). These resources move to their new `apiGroups`.
- `hack/sync-chart-crds.sh` copies only `net.ectobase.dev_*.yaml` into the chart — it must also copy the new groups' CRDs.
- `deploy/charts/ectobase/tests/render.sh` asserts 14 CRDs total (unchanged — types don't disappear, only regroup) and diffs `config/deploy/rbac.yaml` golden.
- RBAC-drift lesson (from the container feature): the DEPLOYED netplane-controller ClusterRole must carry each group's `apiGroups`, or the compiler's informers are forbidden and CompiledNICs never sync. envtests pass without RBAC — only the live sweep catches this. That is why Task 4 is a full live sweep.

---

## The carve recipe (applied per group in Tasks 1–3)

For a group `G` (package name `g`, domain `D = g.ectobase.dev`, internal import alias `<g>api`, external alias `<g>v1`) with type set `Ts`:

1. `mkdir -p api/g/v1alpha1`. `git mv` each type's files: internal `api/net/<t>_types.go` + `api/net/<t>_rest.go` → `api/g/`, external `api/net/v1alpha1/<t>_types.go` → `api/g/v1alpha1/`.
2. If `G` needs `LocalObjectReference`, create `api/g/common_types.go` (internal) + `api/g/v1alpha1/common_types.go` (external), each containing ONLY the `LocalObjectReference` struct (copied verbatim from `api/net/common_types.go` / `api/net/v1alpha1/common_types.go`). Do NOT copy PortStatus/PortType (net-only).
3. Create `api/g/doc.go` (`// +k8s:deepcopy-gen=package` + `// +groupName=D`), `api/g/register.go` (SchemeGroupVersion Group=D Version=`runtime.APIVersionInternal`, `addKnownTypes` listing `Ts`+Lists, `SchemeBuilder=runtime.NewSchemeBuilder(addKnownTypes)`, `AddToScheme`), `api/g/install/install.go` (Install registers `g.AddToScheme` + `v1alpha1.AddToScheme` + SetVersionPriority; plus `AddToScheme` wrapper), `api/g/v1alpha1/doc.go` (full marker set with `+k8s:conversion-gen=github.com/trevex/ectobase/api/g`, `+groupName=D`, `+k8s:openapi-model-package=dev.ectobase.g.v1alpha1`), `api/g/v1alpha1/register.go` (localSchemeBuilder shape, `GroupName=D`, `SchemeGroupVersion` Version `v1alpha1`, `init(){localSchemeBuilder.Register(addKnownTypes)}`, `addKnownTypes` listing `Ts`+Lists + `metav1.AddToGroupVersion`), `api/g/fuzzer/fuzzer.go` (copy the `FillNoCustom`-style entries for `Ts`' Spec types out of `api/net/fuzzer/fuzzer.go`), `api/g/install/roundtrip_test.go` (copy from `api/net/install/roundtrip_test.go`, updating imports + comment).
4. Drop the kit interface-assertions convention is already satisfied (the moved `<t>_rest.go` are already apimachinery-only from R2) — just confirm no `go.opendefense.cloud/kit` in `api/g/`.
5. Remove `Ts` from `api/net/register.go` (internal) and `api/net/v1alpha1/register.go` (external) `addKnownTypes`. Remove the moved fuzzer entries for `Ts` from `api/net/fuzzer/fuzzer.go`.
6. Update `central/cmd/apiserver/main.go`: add `<g>api "github.com/trevex/ectobase/api/g"`, `<g>install ".../api/g/install"`, `<g>v1 ".../api/g/v1alpha1"` imports; add `<g>install.Install(scheme)` in `init()`; change the `Resource(&netapi.<T>{}, netv1.SchemeGroupVersion)` lines for `Ts` to `Resource(&<g>api.<T>{}, <g>v1.SchemeGroupVersion)`.
7. Update consumers: for every moved type `T`, references `netv1.T` → `<g>v1.T` (external) and `netapi.T` → `<g>api.T` (internal) across netplane/cni/central; add the `<g>v1`/`<g>api` import alias to affected files; `go build ./...` per module and fix until green (the compiler enumerates every missed site).
8. If `T` is a compiled type, update its emitted `apiVersion` string in the compiler (Task-1 specifics below).
9. Regenerate: `make generate`; the group's CRD emits as `config/crd/bases/D_<plural>.yaml`.
10. `hack/sync-chart-crds.sh`: extend the `cp` glob to include `D_*.yaml`.
11. Chart RBAC: move `Ts`' resources from the `net.ectobase.dev` blocks into new `apiGroups: ["D"]` blocks (netplane-controller always; agent/broker where the type appears). Re-sync `config/deploy/rbac.yaml` golden (`helm template ... --show-only templates/rbac.yaml | grep -v '^# Source: ' | sed '1{/^---$/d}' > config/deploy/rbac.yaml`).
12. Green gate: `api`+`central`+`netplane`+`cni` build; `api/apicheck` invariant + `api/g/install` roundtrip fuzz + central `TestCompiledNIC`/`TestClusterPool`/broker/scheduler envtests + netplane controller envtests pass; `make chart-test` / `render.sh` pass (14 CRDs, RBAC golden matches).

---

## Task 1: Carve the `compiled` group

**Types:** CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment. Domain `compiled.ectobase.dev`. Aliases `compiledapi` / `compiledv1`. Needs local LocalObjectReference.

- [ ] **Step 1: Baseline green** — `nix develop --command bash -c 'cd api && go build ./... && go test ./apicheck/ ./net/install/ -count=1'` and `nix develop --command bash -c 'cd central && GOWORK=off go build ./...'`. Expect exit 0.

- [ ] **Step 2: Move files + scaffold the group** — apply recipe steps 1–5 for `compiled` (move the 4 `compilednic/compiledvm/compiledcontainer/compiledvolumeattachment`_types.go internal+external + their `_rest.go`; add `api/compiled/common_types.go` + `api/compiled/v1alpha1/common_types.go` with LocalObjectReference; create doc/register/install/fuzzer/roundtrip_test; strip the 4 types + their fuzzer entries from net). Use the exact file contents shown in the recipe, substituting `g=compiled`, `D=compiled.ectobase.dev`, the 4 type names, and `dev.ectobase.compiled.v1alpha1` for the openapi model package.

- [ ] **Step 3: Update the compiler's emitted apiVersion strings** — in `netplane/controllers/`:
  - `compilednic.go:100`: `APIVersion: "net.ectobase.dev/v1alpha1"` → `"compiled.ectobase.dev/v1alpha1"`
  - `compiledvm.go:45`: `APIVersion: "net.ectobase.dev/v1alpha1"` → `"compiled.ectobase.dev/v1alpha1"`
  - `compiledcontainer.go:42`: same → `"compiled.ectobase.dev/v1alpha1"`
  - `compiledvolumeattachment.go:39`: same → `"compiled.ectobase.dev/v1alpha1"`
  Verify none remain: `grep -rn '"net.ectobase.dev/v1alpha1"' netplane/ --include='*.go'` (any survivors must be non-compiled types — there are none today, so expect empty).

- [ ] **Step 4: apiserver registration** — recipe step 6 for the 4 compiled types (move their `Resource(...)` lines to `compiledapi`/`compiledv1`, add `compiledinstall.Install(scheme)`).

- [ ] **Step 5: Update consumers** — recipe step 7. Bulk-rename with sed then build-fix:
  ```bash
  cd /home/nik/Development/ironcore-net-xdp
  for T in CompiledNIC CompiledNICList CompiledVM CompiledVMList CompiledContainer CompiledContainerList CompiledVolumeAttachment CompiledVolumeAttachmentList; do
    grep -rlZ "netv1\.$T\b" --include='*.go' netplane cni central | xargs -0 -r sed -i "s#netv1\.$T\b#compiledv1.$T#g"
  done
  ```
  Then add the `compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"` import to each file the sed touched (the build errors list them), and repeat for any internal `netapi.<T>` refs (there should be few, mostly central/test). `go build ./...` per module until green. Note: files that reference BOTH net and compiled types keep BOTH imports.

- [ ] **Step 6: Regenerate + CRD sync + RBAC** — recipe steps 9–11. Extend `hack/sync-chart-crds.sh` `cp` to also copy `compiled.ectobase.dev_*.yaml`. In `deploy/charts/ectobase/templates/rbac.yaml` move `compilednics`(+status) [agent + controller + broker], `compiledvms`/`compiledvolumeattachments`(+status) [controller + broker], `compiledcontainers`(+status) [controller + broker] into `apiGroups: ["compiled.ectobase.dev"]` blocks. Re-sync the golden.

- [ ] **Step 7: Green gate** — recipe step 12. Expect: builds green; `api/compiled/install` roundtrip fuzz ok; central `TestCompiledNIC_SpecClusterNameSelector` + broker/scheduler envtests ok; netplane controllers ok; `render.sh` 14 CRDs + RBAC golden matches.

- [ ] **Step 8: Commit**
  ```bash
  git add api central netplane cni config deploy hack Makefile
  git commit -m "$(cat <<'EOF'
  refactor(api): carve compiled group (compiled.ectobase.dev) out of net

  Moves CompiledNIC/CompiledVM/CompiledContainer/CompiledVolumeAttachment into
  api/compiled(/v1alpha1) with generated conversions, updates the compiler's
  emitted apiVersion, apiserver registration, consumers, per-group CRD + RBAC +
  goldens. No net type embeds a compiled type; LocalObjectReference duplicated
  group-locally.

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  EOF
  )"
  ```

## Task 2: Carve the `compute` group

**Types:** VirtualMachine, Container. Domain `compute.ectobase.dev`. Aliases `computeapi`/`computev1`. Needs local LocalObjectReference. No compiler apiVersion strings (compute types are user-authored, not emitted). Apply the carve recipe (steps 1–12) exactly as in Task 1 with `g=compute`, `D=compute.ectobase.dev`, types VirtualMachine/Container, openapi model `dev.ectobase.compute.v1alpha1`.

- [ ] **Step 1: Baseline green** (from Task 1's committed state).
- [ ] **Step 2: Move files + scaffold** — recipe steps 1–5 for compute (move virtualmachine + container types/rest internal+external; add compute-local LocalObjectReference; doc/register/install/fuzzer/roundtrip_test; strip from net).
- [ ] **Step 3: apiserver registration** — recipe step 6 (VirtualMachine, Container → computeapi/computev1 + computeinstall.Install).
- [ ] **Step 4: Update consumers** — sed rename for `VirtualMachine`/`VirtualMachineList`/`Container`/`ContainerList` (`netv1.<T>`→`computev1.<T>`, `netapi.<T>`→`computeapi.<T>`) + import fixups + build-fix. NOTE: `Container` is a common word — scope the sed to the exact `netv1.Container`/`netv1.ContainerList` tokens only (word-boundary), and manually verify no false hits (e.g. corev1.Container is unaffected since it is a different alias).
- [ ] **Step 5: Regenerate + CRD sync + RBAC** — extend sync-chart-crds glob for `compute.ectobase.dev_*.yaml`; move `virtualmachines`(+status) and `containers`(+status) into `apiGroups: ["compute.ectobase.dev"]` blocks (controller; virtualmachines also add to any place volumes were grouped — but split volumes to storage in Task 3). Re-sync golden.
- [ ] **Step 6: Green gate** — builds + `api/compute/install` roundtrip + central envtests (TestVirtualMachine/Container paths, broker) + netplane controllers + render.sh.
- [ ] **Step 7: Commit** — message `refactor(api): carve compute group (compute.ectobase.dev) out of net` (same body shape as Task 1).

## Task 3: Carve the `storage` group

**Types:** Volume. Domain `storage.ectobase.dev`. Aliases `storageapi`/`storagev1`. Does NOT need LocalObjectReference. Apply the carve recipe with `g=storage`, `D=storage.ectobase.dev`, type Volume, openapi model `dev.ectobase.storage.v1alpha1`.

- [ ] **Step 1: Baseline green** (from Task 2's state).
- [ ] **Step 2: Move files + scaffold** — recipe steps 1–5 for storage (move volume types/rest internal+external; NO common_types; doc/register/install/fuzzer/roundtrip_test; strip Volume from net).
- [ ] **Step 3: apiserver registration** — recipe step 6 (Volume → storageapi/storagev1 + storageinstall.Install).
- [ ] **Step 4: Update consumers** — sed rename `Volume`/`VolumeList` (`netv1.Volume`→`storagev1.Volume`, `netapi.Volume`→`storageapi.Volume`) + import fixups + build-fix. NOTE: also watch for `CompiledVolumeAttachment` — do NOT rewrite it (it moved to compiled in Task 1); scope sed to exact `netv1.Volume`/`netv1.VolumeList` word-boundary tokens.
- [ ] **Step 5: Regenerate + CRD sync + RBAC** — extend sync-chart-crds glob for `storage.ectobase.dev_*.yaml`; move `volumes`(+status) into an `apiGroups: ["storage.ectobase.dev"]` block (controller). Re-sync golden.
- [ ] **Step 6: Green gate** — builds + `api/storage/install` roundtrip + central envtests + netplane controllers + render.sh. Also now confirm the `net.ectobase.dev` RBAC blocks list ONLY the 7 remaining net resources (vpcs, networkinterfaces, firewallpolicies, floatingips, loadbalancers, natgateways, vpcpeerings).
- [ ] **Step 7: Commit** — message `refactor(api): carve storage group (storage.ectobase.dev) out of net`.

## Task 4: Live clab sweep validation

**Goal:** Prove the four-group split works end-to-end on a real fabric — the only gate that catches per-group RBAC drift (deployed ClusterRole missing a group ⇒ forbidden informers ⇒ CompiledNICs never sync).

- [ ] **Step 1: Confirm goldens + chart in sync**
  ```bash
  nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && bash deploy/charts/ectobase/tests/render.sh 2>&1 | grep -E "FAIL|installCRDs"'
  ```
  Expect no FAIL, `installCRDs renders 14 CRDs`. Then `ls deploy/charts/ectobase/crd-bases/ | sed 's/_.*//' | sort -u` should list all four groups: `compiled.ectobase.dev`, `compute.ectobase.dev`, `net.ectobase.dev`, `storage.ectobase.dev`.

- [ ] **Step 2: Bring up the fabric**
  ```bash
  sudo -E env "PATH=$PATH" make lab-down 2>&1 | tail -3
  sudo -E env "PATH=$PATH" make lab-up 2>&1 | tail -20
  sudo -E env "PATH=$PATH" make lab-ceph 2>&1 | tail -10
  sudo -E env "PATH=$PATH" make lab-tier2-up 2>&1 | tail -10
  ```
  Expect each to complete without error (lab-up builds app images to the in-fabric mirror + deploys the ectobase chart, now with the four groups' CRDs + RBAC).

- [ ] **Step 3: Run the live suite**
  ```bash
  sudo -E env "PATH=$PATH" make lab-test 2>&1 | tee /tmp/r3-lab-test.log | tail -40
  ```
  Expect the full suite green — critically `TestPodOverlayPing`, `TestVPCPeering` (Container→compute group + CompiledContainer→compiled group end-to-end), `TestLbDistributeSmoke`, `TestDhcpLeaseSmoke`. `TestTier2Failover` may flake on aged-fabric Ceph `MON_DISK_LOW` (known, unrelated) — a fresh `lab-up` restores it. If ANY test fails with a `forbidden`/`cannot list ...` RBAC error naming a moved resource, that is per-group RBAC drift: add the missing `apiGroups` block to the netplane-controller/agent/broker ClusterRole, re-sync the golden, `make lab-deploy` + `kubectl rollout restart deploy/netplane-controller`, and re-run.

- [ ] **Step 4: Commit any RBAC fixes discovered live** — if Step 3 surfaced RBAC gaps, commit the chart + golden fix:
  ```bash
  git add deploy/charts/ectobase/templates/rbac.yaml config/deploy/rbac.yaml
  git commit -m "fix(rbac): grant netplane per-group apiGroups after the split (live-caught)

  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
  ```

- [ ] **Step 5: Tear down (optional)** — `sudo -E env "PATH=$PATH" make lab-down` when validation is complete.

---

## R3 Done Criteria

- `api/net` contains ONLY the 7 networking types (+ PortStatus/PortType + its own LocalObjectReference). `api/compiled`, `api/compute`, `api/storage` each hold their types with generated conversions and their own group registration.
- `cmd/apiserver/main.go` registers all four groups (`netinstall` + `compiledinstall` + `computeinstall` + `storageinstall`; per-group `SchemeGroupVersion`).
- The compiler emits `compiled.ectobase.dev/v1alpha1` for the four compiled types.
- Per-group CRDs (`config/crd/bases/{net,compute,storage,compiled}.ectobase.dev_*.yaml`, 14 total) synced into the chart; RBAC split across the four `apiGroups`; `render.sh`/`make chart-test` green.
- `api` invariant + all four `install` roundtrip fuzzers + central real-apiserver + netplane controller envtests pass.
- **Live clab sweep green** (per-group RBAC proven on a real fabric).
- Commits on `feat/api-restructure`. The three-round restructure is complete and ready to finish/merge.
