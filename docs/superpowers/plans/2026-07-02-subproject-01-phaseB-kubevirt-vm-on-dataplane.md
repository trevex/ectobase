# Sub-project ① Phase B — KubeVirt VM on the eBPF Dataplane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two KubeVirt VMs, each with **no pod network** (primary-UDN via Multus default-network + `managedTap` binding), boot in a single kind cluster, get **DHCP from the eBPF dataplane**, and **ping each other over the overlay**.

**Architecture:** Multus delegates the virt-launcher pod's *only* interface to our CNI (`multus.default: true` → `v1.multus-cni.io/default-network`); KubeVirt's built-in `managedTap` binding wires that interface into the guest. Our CNI (the default delegate) resolves the VM's `{vni, overlay ips}` and dials the node's `flowplane` `DataplaneNode.AttachInterface` gRPC (implemented in Phase A) to program the datapath. No pod network exists on the launcher pod.

**Tech Stack:** Go (CNI, controller-runtime/k8s client), KubeVirt v1.5 + Multus + CDI, containerlab+kind (the IPv6 fabric from Phase A), the `net.ectobase.dev/v1alpha1` CRDs + `flowplane` DataplaneNode (both from Phase A).

**Parent spec:** `docs/superpowers/specs/2026-07-02-subproject-01-vm-dataplane-attach-design.md`; mechanism research: `docs/superpowers/research/2026-07-02-primary-udn-mechanism.md`.

**Prereqs already in place (Phase A):** `flowplane` `DataplaneNode.AttachInterface` (netns veth + underlay `/128` + `INTERFACES`/`UNDERLAY`/`PORT_META`/DHCP programming, verified by `test/attach-netns.sh`); `VPC`/`NetworkInterface` Go types; the `ectobase/flowplane:dev` image; the containerlab+kind fabric harness; `kind` v0.32 + `containerlab` v0.77 installed.

---

## Design decision (resolve in Task 1, recommended default here)

**How does the CNI learn a VM's `{vni, overlay ips}`?** Recommended: the virt-launcher pod carries an annotation naming its `NetworkInterface` CRD (e.g. `net.ectobase.dev/network-interface: <ns>/<name>`), set on the `VirtualMachine`/VMI template; the CNI (or a thin resolver) reads that `NetworkInterface` → `spec.ips` (overlay) and its `VPC` → `status.vni`. For this e2e the `VPC` + two `NetworkInterface`s are **pre-created** with a manually-assigned VNI (no ② controller yet). Task 1's spike confirms the exact plumbing (how the CNI obtains the annotation/pod identity + queries the API from the node).

---

## File Structure

- `docs/superpowers/research/2026-07-02-cni-plumbing.md` — **Create** (Task 1): CNI resolution + node-install decision + manual proof.
- `hack/install-stack.sh` — **Replace** (Task 2): install KubeVirt v1.5 + Multus + CDI + register the `managedTap` binding + enable emulation.
- `cni/plugin/main.go`, `cni/plugin/attach.go` — **Create** (Task 3): the primary-UDN CNI (ADD/DEL → `AttachInterface`/`DetachInterface`).
- `cni/plugin/resolve.go` — **Create** (Task 3): pod → `NetworkInterface`/`VPC` → `{vni, ips}` resolver (per Task 1).
- `hack/clab/dpservice-daemonset.yaml`, `hack/clab/cni-install.yaml` — **Create** (Task 4): `flowplane` DaemonSet (host socket) + a CNI-installer DaemonSet that drops the CNI binary + NAD + kubeconfig on nodes.
- `test/e2e/vm_on_dataplane_test.go` — **Create** (Task 5): the two-VM boot+DHCP+ping+no-pod-net e2e.
- `test/e2e/manifests/` — **Create** (Task 5): `VPC`, two `NetworkInterface`, the NAD, two `VirtualMachine` YAMLs.

---

### Task 1: CNI plumbing research + spike (decision doc + manual proof)

Research spike (not TDD). Deliverable: a decision doc + a manual proof that one VM boots on a *trivial* custom-CNI primary network with **no pod network** in kind.

**Files:** Create `docs/superpowers/research/2026-07-02-cni-plumbing.md`.

- [ ] **Step 1: Resolve the CNI↔pod plumbing.** Determine, with citations: (a) how a CNI default-delegate obtains the pod identity (`CNI_ARGS` `K8S_POD_{NAME,NAMESPACE,UID}`) and reads pod annotations / queries the API from the node (in-cluster SA token vs a kubeconfig dropped on the node); (b) exactly how Multus passes the default-network delegate its config + runtime args; (c) how the CNI binary + its NAD + credentials get installed onto kind nodes (a CNI-installer DaemonSet writing to `/opt/cni/bin` + `/etc/cni/net.d`). Use WebSearch/WebFetch on the Multus + CNI-spec + a reference CNI (e.g. how ovn-k or a sample plugin does k8s lookups).

- [ ] **Step 2: Record the decision** in the doc: chosen resolution mechanism (annotation vs API query), the node-install approach, and the concrete steps the CNI must perform on ADD/DEL.

- [ ] **Step 3: Manual proof.** In a kind cluster (reuse `hack/clab-up.sh` or a plain kind cluster) with KubeVirt v1.5 + Multus + CDI (Task 2's script, or the research §6 commands), bring up **one** VM whose primary interface is a **stock bridge CNI as the default delegate** (`multus.default: true`) with `binding.name: managedTap` and **no `pod: {}`**. Confirm via the launcher pod: the network-status shows a single default attachment = our NAD, **no kindnet interface**, and the guest boots. Capture YAML + commands.

- [ ] **Step 4: Commit the doc.**
```bash
git add docs/superpowers/research/2026-07-02-cni-plumbing.md
git commit -m "docs(research): CNI plumbing + node-install decision for phase B"
```

**Gate:** Tasks 3–4's CNI specifics depend on this. Task 2 does not.

---

### Task 2: `hack/install-stack.sh` — KubeVirt + Multus + CDI + binding

**Files:** Replace the stub `hack/install-stack.sh`.

- [ ] **Step 1: Write the installer** (versions per the mechanism-research doc §6):
```bash
#!/usr/bin/env bash
set -euo pipefail
KV="${KUBEVIRT_VERSION:-v1.5.0}"
CDI="${CDI_VERSION:-v1.61.0}"
# Multus (thick)
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml
# KubeVirt operator + CR
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-cr.yaml"
kubectl -n kubevirt wait kv/kubevirt --for=condition=Available --timeout=10m
# kind has no KVM: emulation + register the managedTap binding
kubectl -n kubevirt patch kubevirt kubevirt --type=merge -p '{"spec":{"configuration":{
  "developerConfiguration":{"useEmulation":true},
  "network":{"binding":{"dataplane":{"domainAttachmentType":"managedTap"}}}}}}'
# CDI
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI}/cdi-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI}/cdi-cr.yaml"
kubectl -n cdi wait cdi/cdi --for=condition=Available --timeout=10m
```

- [ ] **Step 2: Run it against a kind cluster** (`hack/clab-up.sh` brings up the fabric+kind first, or `kind create cluster`).

Run: `KUBECONFIG=$(kind get kubeconfig ...) hack/install-stack.sh`
Expected: KubeVirt `Available`, Multus + CDI up, the `dataplane` binding present in the KubeVirt CR (`kubectl -n kubevirt get kubevirt kubevirt -o jsonpath='{.spec.configuration.network.binding.dataplane.domainAttachmentType}'` → `managedTap`).

- [ ] **Step 3: Commit.**
```bash
git add hack/install-stack.sh
git commit -m "feat(hack): install KubeVirt v1.5 + Multus + CDI + managedTap binding"
```

---

### Task 3: The primary-UDN CNI plugin (Go)

**Integration-heavy**, depends on Task 1. Begins by reading Task 1's decision doc.

**Files:** Create `cni/plugin/{main.go,attach.go,resolve.go}`; `cni/go.mod` already exists.

- [ ] **Step 1: Read `docs/superpowers/research/2026-07-02-cni-plumbing.md`** and follow its resolution + ADD/DEL contract.

- [ ] **Step 2: Write a failing integration test** for the resolver (`cni/plugin/resolve_test.go`): given a fake `NetworkInterface` (`spec.ips: ["10.0.0.1"]`, `vpcRef: v`) + `VPC v` (`status.vni: 100`), `resolve()` returns `{vni:100, ips:["10.0.0.1"]}`. Use a fake controller-runtime client. Run: `go test ./cni/...` → FAIL (undefined).

- [ ] **Step 3: Implement `resolve.go`** — `resolve(ctx, k8sClient, podRef) -> (vni uint32, ips []string, err error)`: read the pod/VMI's `net.ectobase.dev/network-interface` annotation → get the `NetworkInterface` → its `VPC.status.vni` + `spec.ips`. Green the test.

- [ ] **Step 4: Implement `main.go` + `attach.go`** — CNI `ADD`: parse stdin netconf + `CNI_ARGS`, `resolve()`, dial the node's `flowplane` `DataplaneNode` unix socket, `AttachInterface{netns_path: CNI_NETNS, vni, requested_ips: ips}`, return a CNI `types.Result` (v1.0.0) with the IP + gateway + routes from the reply. `DEL`: `DetachInterface`. Build the plugin binary.

Run: `go build ./cni/plugin/...`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add cni/plugin cni/go.mod cni/go.sum
git commit -m "feat(cni): primary-UDN CNI plugin -> DataplaneNode.AttachInterface"
```

---

### Task 4: Deploy `flowplane` DaemonSet + install the CNI on nodes

**Files:** Create `hack/clab/dpservice-daemonset.yaml`, `hack/clab/cni-install.yaml`.

- [ ] **Step 1: Write the `flowplane` DaemonSet** — runs `flowplane serve` on each node (hostNetwork, privileged, `HOST_IP` from `status.hostIP` via downward API for underlay resolution), exposing the `DataplaneNode` gRPC on a host unix socket via a `hostPath` mount (e.g. `/run/flowplane/node.sock`).

- [ ] **Step 2: Write the CNI-installer DaemonSet** — an initContainer that copies the CNI plugin binary into the node's `/opt/cni/bin` and writes the NAD + a node kubeconfig (per Task 1) into `/etc/cni/net.d`, using the `ectobase/flowplane:dev` image (or a small installer image).

- [ ] **Step 3: Apply both to a kind cluster and verify** the DaemonSets are Ready and the socket + CNI binary exist on a node (`docker exec <kind-node> ls /run/flowplane/node.sock /opt/cni/bin/<plugin>`).

- [ ] **Step 4: Commit.**
```bash
git add hack/clab/dpservice-daemonset.yaml hack/clab/cni-install.yaml
git commit -m "feat(deploy): flowplane DaemonSet + CNI installer for kind nodes"
```

---

### Task 5: Two-VM e2e — boot + DHCP + ping + no-pod-net

**Files:** Create `test/e2e/vm_on_dataplane_test.go`, `test/e2e/manifests/*.yaml`.

- [ ] **Step 1: Write the manifests** — `VPC` (`spec.vni: 100`), two `NetworkInterface` (`vpcRef: prod`, `spec.ips: ["10.0.0.1"]` / `["10.0.0.2"]`), the NAD referencing our CNI, and two `VirtualMachine`s (containerdisk cirros; `interfaces[].binding.name: dataplane`; `networks[].multus{networkName: <nad>, default: true}`; the `net.ectobase.dev/network-interface` annotation; **no `pod: {}`**).

- [ ] **Step 2: Write the e2e test** `TestVMsOnDataplane` (skip if `containerlab`/`kind` absent): `hack/clab-up.sh` → `hack/install-stack.sh` → apply Task 4 deploy + the manifests → wait both VMIs Ready → assert:
  (a) each virt-launcher pod's `network-status` shows a single default = our NAD, **no kindnet** iface;
  (b) each guest got its overlay IP via **DHCP** (`virtctl console`/guest-exec `ip addr` shows `10.0.0.1`/`.2`);
  (c) VM1 **pings** VM2 (`10.0.0.2`) with 0% loss. Tear down.

- [ ] **Step 3: Run it.**
Run: `cd test/e2e && sudo env "PATH=$PATH" go test -run TestVMsOnDataplane -v -timeout 30m ./...`
Expected: PASS (or SKIP without tooling).

- [ ] **Step 4: Commit.**
```bash
git add test/e2e/vm_on_dataplane_test.go test/e2e/manifests
git commit -m "test(e2e): two KubeVirt VMs on the eBPF dataplane (boot+DHCP+ping, no pod net)"
```

---

## Notes for the executor

- **Environment IS capable** (this session's host): passwordless sudo, Docker, `kind`+`containerlab` on `~/go/bin`, the `ectobase/flowplane:dev` image built. Run kind/containerlab/e2e under `sudo env "PATH=$PATH" …`. **`make image` needs `--network=host`** (already in the Makefile).
- **Commit hygiene (every task):** unrelated design docs are uncommitted — **never `git add -A`**; stage explicit paths; verify `git show --stat HEAD`.
- **Research/integration tasks (1, 3, 4):** report the discovered plumbing before writing code; if the CNI↔k8s resolution or node-install is genuinely opaque after a real attempt, stop and report `NEEDS_CONTEXT`.
- **The hard, novel risk is Task 1** (the CNI plumbing + true primary-UDN with a *custom* CNI on kind). De-risk it first; everything else is assembly.
