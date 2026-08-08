# flowplane-cni resolves CompiledNIC (not raw NIC) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Make the flowplane CNI resolve a Pod's overlay config from the broker-synced **CompiledNIC** (central compiled policy) instead of the raw `NetworkInterface`+`VPC` on the compute cluster — so a Pod uses the real production flow (central → compile → broker-sync → CNI), with no NIC duplicated on the compute cluster. User decision (2026-08-08), see [[feedback-tests-through-control-plane]].

**Root blocker (why this needs more than a CNI edit):** the compiler's `resolvePlacement` (netplane/controllers/compilednic.go:46) stamps `CompiledNIC.spec.clusterName` from the owning VM, else a single global `--cluster-name` default. A Pod has no owning VM, so its NIC can't land on the Pod's actual cluster. Fix: add an explicit placement field to `NetworkInterface` (mirroring `VirtualMachine.spec.clusterName`). Also: `CompiledNIC` doesn't carry MAC, and after this change the raw NIC won't exist on the compute cluster — so add `MAC` to `CompiledNICSpec` so the CNI reads everything from CompiledNIC (containers → empty MAC; VMs → the pinned MAC).

**Cross-cutting caveat:** the net.ectobase.dev types are ALSO served by central's aggregated apiserver with an internal version + external v1alpha1 + **hand-written conversions** + fuzzer roundtrip tests (`central/apis/net/…`, `conversion.go`, `vm_placement_conversion_test.go` is precedent). Every field added to `NetworkInterfaceSpec`/`CompiledNICSpec` must be mirrored there + in the conversions + regen.

**Design (mirrors the VM placement model):**
- `NetworkInterfaceSpec += ClusterName string` (optional): the compute cluster this standalone (Pod) NIC targets. `resolvePlacement`: owning VM > `nic.Spec.ClusterName` (if set) > `--cluster-name` default.
- `CompiledNICSpec += MAC string`: the compiler copies `nic.Spec.MAC`. The CNI reads `{vni: CompiledNIC.Spec.VNI, ips: CompiledNIC.Spec.OverlayIPs, mac: CompiledNIC.Spec.MAC}` — CompiledNIC only, no raw-NIC/VPC read.
- CNI RBAC: `compilednics.get` (drop `networkinterfaces`,`vpcs` gets).
- CompiledNIC name = `<ns>-<nic>` (compilednic.go:83). The CNI GETs `<ns>/<ns>-<nic>`.

---

## Task CP.2a — control-plane: API + central conversions + compiler (NO live)

**Files:**
- `api/v1alpha1/networkinterface_types.go` (+ ClusterName), `api/v1alpha1/compilednic_types.go` (+ MAC)
- regen: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/*`, chart CRDs (via `make generate` + `make chart-sync-crds`)
- `central/apis/net/networkinterface_types.go` + `central/apis/net/v1alpha1/…` + `central/apis/net/compilednic_types.go` + `central/apis/net/v1alpha1/conversion.go` (hand-written conversions) + fuzzer + central regen
- `netplane/controllers/compilednic.go` (`resolvePlacement` + `Compile` MAC copy)

- [ ] **Step 1 — API fields.** Add `ClusterName string `json:"clusterName,omitempty"`` (+optional, godoc: "the compute cluster this standalone/Pod NIC targets; the compiler uses it for placement when no VirtualMachine owns this NIC") to `NetworkInterfaceSpec`. Add `MAC string `json:"mac,omitempty"`` (+optional, godoc: "the guest L2 address, copied from the source NIC; the CNI programs it as the datapath guest MAC (empty for containers → derived)") to `CompiledNICSpec`.
- [ ] **Step 2 — mirror in central's internal + external types** (`central/apis/net/networkinterface_types.go`, `central/apis/net/v1alpha1/networkinterface_types.go`, and the CompiledNIC equivalents). Update the hand-written `central/apis/net/v1alpha1/conversion.go` to carry both new fields both directions (follow the existing pattern used for `VirtualMachine.spec.clusterName` / the vm_placement conversion). Update the fuzzer (`central/apis/net/fuzzer/fuzzer.go`) if it enumerates fields.
- [ ] **Step 3 — regen.** `make generate` (deepcopy + CRDs) then `make chart-sync-crds`. Regen central's generated code the same way central does it (check central's Makefile/`make generate` equivalent; the phase1b memory notes central uses its own codegen). Confirm the new fields appear in the CRD YAMLs + the central OpenAPI.
- [ ] **Step 4 — compiler.** In `resolvePlacement`, after the VM loop and before the default: `if nic.Spec.ClusterName != "" { return Placement{ClusterName: nic.Spec.ClusterName} }`. In `Compile`, set `MAC: nic.Spec.MAC` on the CompiledNICSpec.
- [ ] **Step 5 — unit/roundtrip tests.** Add a compiler test: a NIC with `spec.clusterName=k02` and no VM → CompiledNIC.spec.clusterName==k02 + MAC copied. Ensure the central conversion roundtrip fuzz test passes with the new fields (it will fail if a field is dropped in conversion — that's the guard).
- [ ] **Step 6 — build + test green (no live).**
  - `nix develop --command bash -c 'cd api && go build ./... && cd .. && go build ./... 2>&1 | tail'`
  - `nix develop --command bash -c 'cd netplane && go test ./controllers/... 2>&1 | tail'`
  - `nix develop --command bash -c 'cd central && GOWORK=off go test ./apis/... 2>&1 | tail'` (the conversion roundtrip fuzz)
  - `make chart-test`
- [ ] **Step 7 — commit** (`api/…`, `config/crd/…`, `deploy/charts/…` CRDs, `central/apis/net/…`, `netplane/controllers/compilednic.go` + tests). Message: `feat(net): NetworkInterface.spec.clusterName placement + CompiledNIC.spec.mac (CNI reads CompiledNIC)`.

## Task CP.2b — CNI + deploy + test (live)

**Files:**
- `cni/plugin/resolve.go` (+ `resolveCompiledNIC`), `cni/plugin/main.go` (call it), `cni/plugin/resolve_test.go`
- `deploy/charts/ectobase/templates/cni.yaml` (RBAC: `compilednics.get`)
- `test/lab/livetest/pod_test.go` (drive via central + CompiledNIC sync)
- rebuild the CNI image + redeploy

- [ ] **Step 1 — CNI resolver.** Add `resolveCompiledNIC(ctx, c, ns, nicName)`: GET `CompiledNIC` `types.NamespacedName{Namespace: ns, Name: ns+"-"+nicName}`; return `{VNI: uint32(spec.VNI), IPs: spec.OverlayIPs, MAC: spec.MAC}`. Error if `spec.VNI==0` (not compiled/synced yet). Replace the `resolve()` call in `main.go` cmdAdd. Remove the now-dead raw-NIC/VPC `resolve()` (+ its VPC read). Register CompiledNIC in the CNI's client scheme (check `attach.go`/scheme setup).
- [ ] **Step 2 — RBAC.** In `deploy/charts/ectobase/templates/cni.yaml`, change the `net.ectobase.dev` rule to `resources: ["compilednics"], verbs: ["get"]` (drop networkinterfaces/vpcs). Keep `pods.get`.
- [ ] **Step 3 — unit test** `resolve_test.go`: a fake client with a CompiledNIC `default/default-vm0` (VNI 100, OverlayIPs [10.0.0.1], MAC 52:…) → `resolveCompiledNIC` returns those. Build + `go test ./cni/...`.
- [ ] **Step 4 — rebuild + redeploy the CNI image.** Find the CNI image build (`Dockerfile.cni` + how `make lab-images`/the mirror handles it). Rebuild, push to the fabric mirror (mirror how the flowplane image was rebuilt+pushed in CP.1), and restart the `flowplane-cni-install` DaemonSet on k02+k03 so the new binary is dropped. Apply the updated RBAC (helm upgrade or kubectl apply the cni.yaml rendering).
- [ ] **Step 5 — rewrite `TestPodOverlayPing`** to the production flow: apply VPC + two NetworkInterfaces (each with `spec.clusterName=<the pod's cluster>` + `spec.nodeName` + overlay IP) to **central**; mark VPC+NICs Ready; wait for each `CompiledNIC default-<nic>` to sync to its compute cluster (mirror overlay_test.go's CompiledNIC-synced `eventually`); apply NAD + Pod (annotated `net.ectobase.dev/network-interface: default/<nic>`) to each compute cluster; wait Ready; ping across the overlay both ways. No raw NIC on the compute clusters. Keep distinct VNI/IPs (201 / 10.0.2.x).
- [ ] **Step 6 — live-validate.** `sudo -E env "PATH=$PATH" LAB_CONFIG=… go test -tags live -run TestPodOverlayPing …` → PASS. Diagnose (CNI logs via `kubectl describe pod`/kubelet; the CompiledNIC present on the compute cluster; RBAC) — do not skip.
- [ ] **Step 7 — regression:** re-run the full datapath group (DHCP/NAT/underlay/QoS/overlay/pod) → all green (the CNI change only affects Pod attach; gRPC-driven tests unaffected).
- [ ] **Step 8 — commit** (`cni/…`, `deploy/charts/…/cni.yaml`, `test/lab/livetest/pod_test.go`). Message: `feat(cni): resolve CompiledNIC (central policy) instead of raw NIC; Pod test drives central→compile→sync→CNI`.

## Acceptance
- A Pod annotated onto our overlay is attached by flowplane-cni reading the broker-synced CompiledNIC (no raw NIC on the compute cluster); `TestPodOverlayPing` PASS via the real central→compile→sync→CNI flow.
- Central conversion roundtrip fuzz + `make chart-test` + compiler unit tests green. Full datapath group regresses green.
