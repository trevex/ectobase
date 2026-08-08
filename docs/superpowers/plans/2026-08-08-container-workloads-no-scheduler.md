# Container workloads (no-scheduler slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a spec-tier `Container` workload whose compiler derives its owned NICs' placement and emits a `CompiledContainer`, which the broker syncs and a new `pod-materializer` turns into a real `v1.Pod` — so container workloads flow through central → compile → broker → materialize (no more raw `kubectl apply` in the pod tests), without a scheduler or failover.

**Architecture:** Mirror the existing `VirtualMachine` → compiler → `CompiledVM` → `vm-materializer` path. `Container` is the placement authority (`clusterName`/`nodeName` set by hand); the netplane compiler's `resolvePlacement` gains an owning-`Container` branch and a new reconciler emits `CompiledContainer`; the broker syncs `CompiledContainer`; `pod-materializer` server-side-applies the Pod on the compute cluster.

**Tech Stack:** Go, kubebuilder/controller-runtime, k8s aggregated apiserver (apiserver-kit), the `net.ectobase.dev` API group, Multus + flowplane-cni, the Go `test/lab` kind fabric.

**Spec:** `docs/superpowers/specs/2026-08-08-container-pod-materializer-thin-design.md`.

**Conventions (from the repo):** Go builds via `nix develop --command bash -c '...'`; central builds with `GOWORK=off`. `make generate` runs controller-gen (deepcopy + CRD yaml) — it is in the nix devShell. NEVER `git add -A`. Pre-commit runs clippy/rustfmt only (no Go); verify Go tests yourself. The central module has a local `apiserver-kit` replace (builds on this machine). Live/lab via `sudo -E env "PATH=$PATH"` + `make lab-*`. App images are local `:dev` pushed to the in-fabric mirror (`127.0.0.1:5000/trevex/ectobase/<name>:dev`); after rebuilding an app image, `crictl rmi` the stale image on the compute nodes + `rollout restart` the workload.

---

## File Structure

**New files**
- `api/v1alpha1/container_types.go` — spec-tier `Container` + `ContainerList`.
- `api/v1alpha1/compiledcontainer_types.go` — `CompiledContainer` + `CompiledContainerInterface` + `CompiledContainerList`.
- `central/apis/net/container_types.go`, `central/apis/net/container_rest.go` — internal type + REST storage.
- `central/apis/net/compiledcontainer_types.go`, `central/apis/net/compiledcontainer_rest.go` — internal type + REST storage.
- `netplane/controllers/compiledcontainer.go` — the `Container` → `CompiledContainer` reconciler.
- `netplane/controllers/podmaterializer.go`, `netplane/cmd/pod-materializer/main.go` — the Pod materializer.
- `config/deploy/pod-materializer.yaml` — SA + RBAC + Deployment for the compute cluster.

**Modified files**
- `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/...` (via `make generate`).
- `central/apis/net/register.go`, `central/apis/net/v1alpha1/aliases.go`, `central/apis/net/v1alpha1/conversion.go`, `central/apis/net/fuzzer/*`, `central/apis/net/zz_generated.deepcopy.go` (via generate), `central/cmd/apiserver/main.go`.
- `central/cmd/broker/main.go` (sync map + index).
- `netplane/controllers/compilednic.go` (`resolvePlacement` + watches).
- `netplane/` manager setup (register the new reconciler) + the netplane image build (add the pod-materializer binary) or a new image.
- `test/lab/internal/deploy/*.go` (deploy the pod-materializer + install the `CompiledContainer` CRD on compute clusters).
- `test/lab/livetest/pod_test.go`, `test/lab/livetest/vpcpeering_test.go`.

**Template files to mirror (read these before each task):** `api/v1alpha1/compiledvm_types.go`, `api/v1alpha1/virtualmachine_types.go`, `central/apis/net/compiledvm_types.go` + `compiledvm_rest.go` + `register.go`, `central/apis/net/v1alpha1/aliases.go` + `conversion.go`, `central/apis/net/install/roundtrip_test.go`, `central/cmd/broker/main.go`, `netplane/controllers/compilednic.go`, `netplane/controllers/vmmaterializer.go`, `netplane/cmd/vm-materializer/main.go`, `config/deploy/vm-materializer.yaml`, `test/lab/internal/deploy/kubevirt.go` (the `VMMaterializer` func), `test/lab/livetest/pod_test.go`.

---

## Task 1: API types (`Container` + `CompiledContainer`) in `api/v1alpha1`

**Files:**
- Create: `api/v1alpha1/container_types.go`
- Create: `api/v1alpha1/compiledcontainer_types.go`
- Modify (generated): `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/**`

- [ ] **Step 1: Write `container_types.go`** (mirror `virtualmachine_types.go`'s markers/registration):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerSpec is a schedulable container workload: it owns NetworkInterfaces and carries the pod
// template. Placement (ClusterName/NodeName) is the authority for its owned NICs; in this slice it is
// set by hand (no scheduler binds it yet).
type ContainerSpec struct {
	// ClusterName is the cluster this container is bound to (the placement authority for owned NICs).
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// NodeName pins the Pod (and the owned NICs) to a node; the agent firewall reconcile gates on it.
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// InterfaceRefs names the NetworkInterfaces (same namespace) this container owns.
	// +optional
	InterfaceRefs []LocalObjectReference `json:"interfaceRefs,omitempty"`
	// Image is the container image.
	// +optional
	Image string `json:"image,omitempty"`
	// Command overrides the image entrypoint.
	// +optional
	Command []string `json:"command,omitempty"`
	// Args are the container args.
	// +optional
	Args []string `json:"args,omitempty"`
	// Env are the container environment variables.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Resources is the compute request/limit.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// RestartPolicy is the Pod restart policy (default Always).
	// +optional
	RestartPolicy corev1.RestartPolicy `json:"restartPolicy,omitempty"`
}

// ContainerStatus is the observed state of a Container.
type ContainerStatus struct {
	// State is the compile/materialization state (e.g. Compiled, Pending).
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Container is a schedulable container workload on the ectobase overlay.
type Container struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContainerSpec   `json:"spec,omitempty"`
	Status ContainerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// ContainerList is a list of Container objects.
type ContainerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Container `json:"items"`
}
```

- [ ] **Step 2: Write `compiledcontainer_types.go`** (mirror `compiledvm_types.go`):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledContainerSpec is the lowered, ready-to-materialize intent for a container workload: the pod
// template + the cluster/node binding + the per-interface overlay wiring. A downstream pod-materializer
// turns this into a v1.Pod.
type CompiledContainerSpec struct {
	// ClusterName is the cluster this compiled container is bound to. The broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// NodeName is the pod nodeSelector (kubernetes.io/hostname).
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// Image / Command / Args / Env / Resources / RestartPolicy are the pod template essentials.
	// +optional
	Image string `json:"image,omitempty"`
	// +optional
	Command []string `json:"command,omitempty"`
	// +optional
	Args []string `json:"args,omitempty"`
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// +optional
	RestartPolicy corev1.RestartPolicy `json:"restartPolicy,omitempty"`
	// Interfaces are the container's overlay interfaces (one per owned NetworkInterface).
	// +optional
	Interfaces []CompiledContainerInterface `json:"interfaces,omitempty"`
}

// CompiledContainerInterface is a resolved overlay interface for a container.
type CompiledContainerInterface struct {
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	// +optional
	NetworkName string `json:"networkName,omitempty"`
	// NetworkInterfaceRef is "<namespace>/<nic>" — the pod's net.ectobase.dev/network-interface
	// annotation, which flowplane-cni resolves to the CompiledNIC.
	// +optional
	NetworkInterfaceRef string `json:"networkInterfaceRef,omitempty"`
	// MAC is the pinned L2 address (from the NetworkInterface).
	// +optional
	MAC string `json:"mac,omitempty"`
}

// CompiledContainerStatus is the observed state of a CompiledContainer.
type CompiledContainerStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledContainer is the lowered pod intent for a Container.
type CompiledContainer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledContainerSpec   `json:"spec,omitempty"`
	Status CompiledContainerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledContainerList is a list of CompiledContainer objects.
type CompiledContainerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledContainer `json:"items"`
}
```

Note: confirm `LocalObjectReference` is defined in `api/v1alpha1/common_types.go` (it is — `VirtualMachineSpec.InterfaceRefs` uses it).

- [ ] **Step 3: Generate deepcopy + CRDs:**

Run: `nix develop --command bash -c 'make generate'`
Expected: `api/v1alpha1/zz_generated.deepcopy.go` gains `Container*`/`CompiledContainer*` funcs; new CRD yaml under `config/crd/` (same dir as `...compiledvms.yaml`). No errors.

- [ ] **Step 4: Build:**

Run: `nix develop --command bash -c 'go build ./api/...'`
Expected: success.

- [ ] **Step 5: Commit:**

```bash
git add api/v1alpha1/container_types.go api/v1alpha1/compiledcontainer_types.go api/v1alpha1/zz_generated.deepcopy.go config/crd
git commit -m "feat(api): Container + CompiledContainer net.ectobase.dev types"
```

---

## Task 2: Central internal types + external aliases + register

**Files:**
- Create: `central/apis/net/container_types.go`, `central/apis/net/compiledcontainer_types.go`
- Modify: `central/apis/net/register.go`, `central/apis/net/v1alpha1/aliases.go`, `central/apis/net/zz_generated.deepcopy.go` (generated)

- [ ] **Step 1: Internal types** — mirror `central/apis/net/compiledvm_types.go` exactly (same fields as Task 1 but **no json tags**, `package net`). Write `central/apis/net/container_types.go` (`ContainerSpec`/`ContainerStatus`/`Container`/`ContainerList`) and `central/apis/net/compiledcontainer_types.go` (`CompiledContainerSpec`/`CompiledContainerInterface`/`CompiledContainerStatus`/`CompiledContainer`/`CompiledContainerList`). Keep the `// +genclient` / `// +k8s:deepcopy-gen` markers as in `compiledvm_types.go` (no kubebuilder markers on the internal type).

- [ ] **Step 2: Register internal types** — in `central/apis/net/register.go` `addKnownTypes`, add:

```go
		&Container{},
		&ContainerList{},
		&CompiledContainer{},
		&CompiledContainerList{},
```

- [ ] **Step 3: External aliases** — in `central/apis/net/v1alpha1/aliases.go`, add (mirroring the `CompiledVM` alias block ~line 74):

```go
	Container                  = netv1.Container
	ContainerList              = netv1.ContainerList
	ContainerSpec              = netv1.ContainerSpec
	ContainerStatus            = netv1.ContainerStatus
	CompiledContainer          = netv1.CompiledContainer
	CompiledContainerList      = netv1.CompiledContainerList
	CompiledContainerSpec      = netv1.CompiledContainerSpec
	CompiledContainerInterface = netv1.CompiledContainerInterface
	CompiledContainerStatus    = netv1.CompiledContainerStatus
```

and add `&Container{}`, `&ContainerList{}`, `&CompiledContainer{}`, `&CompiledContainerList{}` to that file's `addKnownTypes` (mirror the `&CompiledNIC{}` entry ~line 134). `netv1` is the `api/v1alpha1` import already aliased in that file.

- [ ] **Step 4: Generate central deepcopy:**

Run: `nix develop --command bash -c 'make generate'` (regenerates `central/apis/net/zz_generated.deepcopy.go`; the internal `net` package has its own deepcopy — confirm the Makefile `generate` target covers `central/apis/net` as it does for `CompiledVM`; if central uses a separate generate step, run that).

- [ ] **Step 5: Build central:**

Run: `nix develop --command bash -c 'cd central && GOWORK=off go build ./...'`
Expected: success.

- [ ] **Step 6: Commit:**

```bash
git add central/apis/net/container_types.go central/apis/net/compiledcontainer_types.go central/apis/net/register.go central/apis/net/v1alpha1/aliases.go central/apis/net/zz_generated.deepcopy.go
git commit -m "feat(central): internal Container/CompiledContainer types + aliases"
```

---

## Task 3: Central conversions + roundtrip fuzz

**Files:**
- Modify: `central/apis/net/v1alpha1/conversion.go`, `central/apis/net/fuzzer/*` (if the fuzzer enumerates types)
- Test: `central/apis/net/install/roundtrip_test.go` (usually auto-covers all registered types)

- [ ] **Step 1: Add conversion funcs** — in `central/apis/net/v1alpha1/conversion.go`, mirror the `// --- CompiledVM ---` block (lines ~232-250) for **both** `Container` and `CompiledContainer`: register `Convert_v1alpha1_Container_To_net_Container` (+ reverse), the `List` variants, and write the `Convert_*` function bodies (field-by-field copy; since external is an alias of internal, the bodies are trivial `*out = *in`-style or field copies — copy the shape of `Convert_v1alpha1_CompiledVM_To_net_CompiledVM` and its `Spec`/`Interface` sub-conversions). Because the external types are **aliases** to `api/v1alpha1` (not distinct structs), follow exactly how `CompiledVM`/`CompiledVMInterface` are converted in that file — do not hand-roll a different shape.

- [ ] **Step 2: Fuzzer** — check `central/apis/net/fuzzer/`; if it has an explicit per-type function list, add `Container`/`CompiledContainer` funcs mirroring `CompiledVM`'s. If the fuzzer is generic (reflection over registered types), no change is needed.

- [ ] **Step 3: Run the roundtrip fuzz test:**

Run: `nix develop --command bash -c 'cd central && GOWORK=off go test ./apis/net/... -run Roundtrip -count=1'`
Expected: PASS (round-trips Container + CompiledContainer internal↔external). If it fails on an unregistered conversion, the Step-1 registration is incomplete — fix and re-run.

- [ ] **Step 4: Commit:**

```bash
git add central/apis/net/v1alpha1/conversion.go central/apis/net/fuzzer
git commit -m "feat(central): Container/CompiledContainer conversions + roundtrip fuzz"
```

---

## Task 4: REST storage + apiserver registration

**Files:**
- Create: `central/apis/net/container_rest.go`, `central/apis/net/compiledcontainer_rest.go`
- Modify: `central/cmd/apiserver/main.go`

- [ ] **Step 1: REST storage** — write `container_rest.go` and `compiledcontainer_rest.go` mirroring `central/apis/net/compiledvm_rest.go` verbatim (same interfaces: `New`, `NamespaceScoped`, `GetObjectMeta`, `ShortNames`/`Categories` if present, status subresource wiring). Substitute the type names. Confirm the `spec.clusterName` field selector support the broker needs is provided the same way `CompiledVM`'s REST does it (the broker filters CompiledContainer on `spec.clusterName`).

- [ ] **Step 2: Register on the apiserver** — in `central/cmd/apiserver/main.go`, after the `CompiledVM` line (~68), add:

```go
		With(apiserver.Resource(&netapi.Container{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.CompiledContainer{}, netv1.SchemeGroupVersion)).
```

- [ ] **Step 3: Build + envtest/smoke:**

Run: `nix develop --command bash -c 'cd central && GOWORK=off go build ./... && GOWORK=off go test ./... -count=1'`
Expected: builds; existing central envtests pass. (If there is a controller/apiserver envtest that lists served resources, confirm `containers`/`compiledcontainers` appear.)

- [ ] **Step 4: Commit:**

```bash
git add central/apis/net/container_rest.go central/apis/net/compiledcontainer_rest.go central/cmd/apiserver/main.go
git commit -m "feat(central): serve Container + CompiledContainer on the aggregated apiserver"
```

---

## Task 5: Broker sync + compute-cluster CRD install

**Files:**
- Modify: `central/cmd/broker/main.go`
- Modify: wherever the compute-cluster compiled CRDs are installed (find with `grep -rn "compiledvms\|CompiledVM" test/lab/internal/deploy central/config config`).

- [ ] **Step 1: Broker sync** — in `central/cmd/broker/main.go`, add `CompiledContainer` alongside `CompiledVM` in THREE places (all shown in the read at ~101-131):
  - the `cache.Options.ByObject` map: `&netv1.CompiledContainer{}: { Field: fields.OneTermEqualSelector("spec.clusterName", clusterName) },`
  - the field index: `idx(&netv1.CompiledContainer{}, func(o client.Object) string { return o.(*netv1.CompiledContainer).Spec.ClusterName })`
  - the reconciler's synced-type set (the `brokerReconciler` syncs a list of types — add `CompiledContainer` to it; follow how `CompiledVM` is threaded through `brokerReconciler` and its `SetupWithManager`/`Watches`).

- [ ] **Step 2: Install the CompiledContainer CRD on compute clusters** — add the generated `compiledcontainers.net.ectobase.dev` CRD to the same manifest/step that installs `compilednics`/`compiledvms` on the compute clusters (located via the `grep` in **Files** above). Mirror that entry exactly.

- [ ] **Step 3: Test** — if a broker loopback envtest exists (`grep -rn "brokerReconciler\|loopback" central --include=*_test.go`), extend it to assert a `CompiledContainer` with `spec.clusterName == thisCluster` syncs downstream and one for another cluster does not. Otherwise add a focused test mirroring the `CompiledVM` broker test.

Run: `nix develop --command bash -c 'cd central && GOWORK=off go test ./cmd/broker/... ./internal/... -count=1'`
Expected: PASS.

- [ ] **Step 4: Commit:**

```bash
git add central/cmd/broker/main.go <crd-install-manifest-or-go>
git commit -m "feat(central): broker syncs CompiledContainer by spec.clusterName"
```

---

## Task 6: Compiler — `resolvePlacement` (owning Container) + `CompiledContainer` reconciler

**Files:**
- Modify: `netplane/controllers/compilednic.go`
- Create: `netplane/controllers/compiledcontainer.go`
- Modify: netplane manager setup (register the reconciler — find `SetupWithManager` wiring, e.g. `netplane/cmd/.../main.go` or a `controllers.Add`).
- Test: `netplane/controllers/*_test.go` (envtest — mirror an existing compilednic/compiledvm test)

- [ ] **Step 1: Extend `resolvePlacement`** in `compilednic.go`. Current signature (line 46): `resolvePlacement(nic *netv1.NetworkInterface, vms []netv1.VirtualMachine, defaultCluster string) Placement`. Add `containers []netv1.Container` and check them FIRST (precedence owning Container > owning VM > nic.spec.clusterName > default). Container ownership is by `spec.interfaceRefs` (same as VM). When a Container owns the NIC, take BOTH `clusterName` and `nodeName` from the Container:

```go
func resolvePlacement(nic *netv1.NetworkInterface, containers []netv1.Container, vms []netv1.VirtualMachine, defaultCluster string) Placement {
	for i := range containers {
		for _, ref := range containers[i].Spec.InterfaceRefs {
			if ref.Name == nic.Name {
				return Placement{ClusterName: containers[i].Spec.ClusterName, NodeName: containers[i].Spec.NodeName, WorkloadID: containers[i].Name}
			}
		}
	}
	// ... existing VM loop (unchanged) ...
	// ... existing nic.spec.clusterName / default fallback (unchanged) ...
}
```

Add `NodeName` to the `Placement` struct (line ~35) if not present, and make the CompiledNIC build (line ~64-91) use `placement.NodeName` when set, else the existing `nic.Spec.NodeName` fallback. Update the single existing caller (line ~302-324) to also `List` `netv1.ContainerList` and pass it. Add `.Watches(&netv1.Container{}, handler.EnqueueRequestsFromMapFunc(r.nicsForContainer))` next to the `VirtualMachine` watch (line ~358), and write `nicsForContainer` mirroring `nicsForVM` (line ~391).

- [ ] **Step 2: Write a failing compiler test** — envtest (mirror the existing compilednic placement test, e.g. `central/apis/net/v1alpha1/vm_placement_conversion_test.go` is a conversion test; the compiler envtest lives in `netplane/controllers`). Assert: given a `Container{clusterName: c1, nodeName: n1, interfaceRefs:[nic-a]}` + `NetworkInterface nic-a` (no clusterName), the produced `CompiledNIC default-nic-a` has `spec.clusterName == c1` and `spec.nodeName == n1`.

Run the test → expect FAIL (Container branch/reconciler not wired). Then implement to pass.

- [ ] **Step 3: Write `compiledcontainer.go`** — the `Container` → `CompiledContainer` reconciler, mirroring how `compiledvm.go` reconciles `VirtualMachine` → `CompiledVM`:

```go
// Reconcile emits a CompiledContainer named "<container>" (or the compiler's naming convention — match
// how CompiledVM is named from a VirtualMachine) stamped with the Container's clusterName/nodeName +
// pod template, with one Interfaces[] entry per owned NIC derived from that NIC's CompiledNIC:
//   NetworkName         = the overlay NAD constant (the same NAD flowplane-cni uses; grep the CompiledVM
//                         path / cni for the constant, e.g. "flowplane-overlay")
//   MAC                 = the NIC's spec.mac (or the CompiledNIC's mac)
//   NetworkInterfaceRef = "<container.Namespace>/<nic>"
// Use server-side apply / createOrUpdate exactly as compiledvm.go does. Reconcile on Container and on
// owned-CompiledNIC changes (so the interface list fills once the NIC compiles).
```

Write the full reconciler by mirroring `compiledvm.go` (open it; it is the authoritative template for naming, ownerRefs, SSA, and the Interfaces derivation from NICs). Register it in the netplane manager setup next to the CompiledVM reconciler.

- [ ] **Step 4: Run the compiler tests → PASS:**

Run: `nix develop --command bash -c 'go test ./netplane/controllers/... -count=1'`
Expected: PASS (placement derivation + CompiledContainer emission).

- [ ] **Step 5: Commit:**

```bash
git add netplane/controllers/compilednic.go netplane/controllers/compiledcontainer.go <manager-setup> netplane/controllers/<new_test>.go
git commit -m "feat(netplane): Container drives NIC placement + emits CompiledContainer"
```

---

## Task 7: `pod-materializer`

**Files:**
- Create: `netplane/controllers/podmaterializer.go`, `netplane/cmd/pod-materializer/main.go`
- Create: `config/deploy/pod-materializer.yaml`
- Modify: the netplane image build (add the `pod-materializer` binary) — mirror how `vm-materializer` is built (`grep -rn "vm-materializer" Dockerfile* Makefile`).

- [ ] **Step 1: Write `podmaterializer.go`** — mirror `netplane/controllers/vmmaterializer.go`. Watch `CompiledContainer`; SSA a `v1.Pod` named after the CompiledContainer, with:

```go
pod.Annotations = map[string]string{
	"k8s.v1.cni.cncf.io/networks":         iface0.NetworkName,        // Multus secondary net
	"net.ectobase.dev/network-interface":  iface0.NetworkInterfaceRef, // flowplane-cni -> CompiledNIC
}
pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": cc.Spec.NodeName}
pod.Spec.RestartPolicy = cc.Spec.RestartPolicy // default corev1.RestartPolicyAlways if empty
pod.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}}
pod.Spec.TerminationGracePeriodSeconds = ptr.To(int64(0))
pod.Spec.Containers = []corev1.Container{{
	Name: "c", Image: cc.Spec.Image, Command: cc.Spec.Command, Args: cc.Spec.Args,
	Env: cc.Spec.Env, Resources: cc.Spec.Resources,
}}
```

(For multiple interfaces, join the `k8s.v1.cni.cncf.io/networks` values with `,` and — matching the current `podManifest` — a single `net.ectobase.dev/network-interface`; the tests use one interface, so start with `Interfaces[0]` and note the multi-iface TODO in a comment.) Use SSA with field owner `"pod-materializer"`, exactly like `vmmaterializer`'s `vmFieldOwner`.

- [ ] **Step 2: Write `netplane/cmd/pod-materializer/main.go`** — mirror `netplane/cmd/vm-materializer/main.go` (manager on the compute cluster kubeconfig, register `PodMaterializerReconciler`, leader-election off or as vm-materializer sets it).

- [ ] **Step 3: `config/deploy/pod-materializer.yaml`** — mirror `config/deploy/vm-materializer.yaml`: ServiceAccount + ClusterRole (get/list/watch `compiledcontainers`; create/patch `pods`; get `nodes` if needed) + ClusterRoleBinding + Deployment in `ectobase-system` running the pod-materializer image. Reuse the netplane image if vm-materializer does; set the container command to the pod-materializer binary.

- [ ] **Step 4: Image** — add the `pod-materializer` binary to the netplane image build the same way `vm-materializer` is added (or a dedicated stage). Confirm with `grep -rn "vm-materializer" Dockerfile*`.

- [ ] **Step 5: Envtest** — `netplane/controllers/podmaterializer_test.go`: given a `CompiledContainer` (image, nodeName, one interface), assert the reconciler creates a `v1.Pod` with the two annotations, the nodeSelector, and the container. Run → PASS:

Run: `nix develop --command bash -c 'go test ./netplane/controllers/... -run PodMaterializer -count=1'`
Expected: PASS.

- [ ] **Step 6: Commit:**

```bash
git add netplane/controllers/podmaterializer.go netplane/cmd/pod-materializer config/deploy/pod-materializer.yaml Dockerfile.netplane netplane/controllers/podmaterializer_test.go
git commit -m "feat(netplane): pod-materializer (CompiledContainer -> Pod)"
```

---

## Task 8: Deploy wiring + rework the live tests

**Files:**
- Modify: `test/lab/internal/deploy/*.go` (add `deploy.PodMaterializer` + wire into the compute-cluster loop; install the CompiledContainer CRD there if not done in Task 5)
- Modify: `test/lab/livetest/pod_test.go`, `test/lab/livetest/vpcpeering_test.go`

- [ ] **Step 1: Deploy step** — add `deploy.PodMaterializer(ctx, r, kubeconfig, manifestPath)` mirroring `deploy.VMMaterializer` (`test/lab/internal/deploy/kubevirt.go:179`), and call it in the same compute-cluster deploy loop where `VMMaterializer` is called (or where the compute substrate is deployed). Point it at `config/deploy/pod-materializer.yaml`.

- [ ] **Step 2: Rework `pod_test.go`** — replace the raw-Pod flow with a `Container`-driven one. In `podCentralFixture` drop `clusterName`/`nodeName` from the `NetworkInterface`s, and apply a `Container` per endpoint instead of `podManifest`+`kubectl apply`:

```go
// per endpoint: a Container on central owns the NIC and carries placement + the busybox template.
containerFixture := fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: Container
metadata: {name: %s}
spec:
  clusterName: %q
  nodeName: %q
  interfaceRefs: [{name: %s}]
  image: busybox:1.36
  command: ["sleep","3600"]
`, "ctr-"+ep.nic, ep.node.Cluster, nodeK8sName(ep.node), ep.nic)
require.NoError(t, applyCentral(ctx, cfg, containerFixture))
```

Keep the NAD apply (`podNADManifest`) and the pod-Ready / overlay-ping assertions unchanged (the Pod name is now the materializer's — resolve it via a label or the CompiledContainer name; assert on `kubectl get pod -l net.ectobase.dev/container=<name>` or the deterministic pod name the materializer uses). Update `t.Cleanup` to delete the `Container` (which GCs the CompiledContainer + Pod via ownerRefs) instead of the raw Pod.

- [ ] **Step 2b: Rework `vpcpeering_test.go`** the same way (it also creates raw pods).

- [ ] **Step 3: Rebuild + redeploy the changed images** onto the warm fabric (netplane compiler + pod-materializer):

```bash
# rebuild netplane (+ pod-materializer) image, push to the mirror, restart on compute clusters
nix develop --command bash -c 'make image-netplane'   # or the target that builds the materializer image
sudo docker tag ghcr.io/trevex/ectobase/netplane:dev 127.0.0.1:5000/trevex/ectobase/netplane:dev
sudo docker push 127.0.0.1:5000/trevex/ectobase/netplane:dev
# central (broker/apiserver) images changed too — rebuild via central/hack/smoke.sh or the lab flow, and
# redeploy central + the compute pod-materializer. Follow the standard dev cycle (crictl rmi + rollout restart).
```

- [ ] **Step 4: Live-validate the reworked tests:**

Run:
```bash
cd test/lab && nix develop --command bash -c 'sudo -E env "PATH=$PATH" LAB_CONFIG="$(pwd)/lab.yaml" go test -tags live -run "TestPodOverlayPing|TestVPCPeering" -count=1 -v ./livetest/... -timeout 30m'
```
Expected: PASS — Pods now appear via central `Container` → compile → broker → pod-materializer, overlay ping + VPC peering green. **DO NOT** revert to raw `kubectl apply`; if a Pod never appears, debug the chain (CompiledContainer on central? synced downstream? materializer logs?) and fix the real gap.

- [ ] **Step 5: Commit:**

```bash
git add test/lab/internal/deploy test/lab/livetest/pod_test.go test/lab/livetest/vpcpeering_test.go
git commit -m "test(lab): drive pod overlay + VPC peering tests through a Container workload"
```

---

## Task 9: Full validation

- [ ] **Step 1: Fresh acceptance sweep** (from committed images):

```bash
nix develop --command bash -c 'make lab-down && make lab-up && make lab-ceph && make lab-tier2-up && make lab-test'
```
Expected: exit 0; the full suite green (incl. the reworked `TestPodOverlayPing`/`TestVPCPeering` + the existing datapath/Tier-2 tests). The Container CRDs are installed and the pod-materializer deployed by the lab flow.

- [ ] **Step 2: Central regression:**

Run: `nix develop --command bash -c 'cd central && GOWORK=off go test ./... -count=1'`
Expected: PASS (conversions/roundtrip/broker).

- [ ] **Step 3: Final review** — request a code review of the whole branch (superpowers:requesting-code-review), then finish per superpowers:finishing-a-development-branch.

---

## Notes / risks

- **Central conversion caveat (CP.2a):** the external `v1alpha1` types are aliases to `api/v1alpha1`, so conversion-gen can't generate them — the conversions in Task 3 are hand-written and MUST match the `CompiledVM` shape exactly, or the roundtrip fuzz fails. This is the highest-risk task; do it right after the types.
- **`make generate` scope:** confirm the Makefile `generate` target regenerates BOTH `api/v1alpha1` and `central/apis/net` deepcopy (central may have its own generate step). Run whatever `CompiledVM` used.
- **NAD name constant:** the compiler's `CompiledContainerInterface.NetworkName` must equal the Multus NAD the tests create (`flowplane-overlay` in `pod_test.go`'s `podNADName`) — reuse the same constant the CompiledVM path uses; don't hardcode a second copy.
- **Pod identity for assertions:** the materializer should give the Pod a deterministic name and/or a `net.ectobase.dev/container` label so the tests can find it; decide this in Task 7 and use it consistently in Task 8.
- **Multiple binaries/images:** if `vm-materializer` ships in the netplane image, `pod-materializer` should too (one image, two commands) to avoid a new image + mirror-push path.
