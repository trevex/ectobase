# Phase 6 — Ceph + Tier-2 + cross-cluster overlay on Talos — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task (fresh subagent per task, two-stage review). Steps use checkbox (`- [ ]`) syntax.

**Goal:** On the Talos lab harness (`test/lab/`), close the cross-cluster overlay datapath through the real compiler/broker pipeline, add fabric-attached Ceph + ceph-csi + csi-addons, and prove the Tier-2 fenced VM-reschedule gate — all as Go code + `//go:build live` tests.

**Architecture:** Port the proven kind-fabric tier2 mechanics (`hack/ceph-*`, `hack/csi-addons-up.sh`, `hack/install-stack.sh`, the ceph clab node, `hack/tier2-failover-e2e.sh`, the central fencer) into the Go `lab` harness on the Talos IPv6-BGP fabric. Reuse the existing committed artifacts (`central/config`, `config/deploy/*`, `deploy/charts/ectobase`, the `central` fencer/broker code) unchanged; the new code is the harness wiring + Talos-specific deltas.

**Tech Stack:** Go 1.26 + cobra; containerlab; Talos (container mode); VyOS; ceph/demo + ceph-csi-rbd (Helm) + csi-addons; KubeVirt + CDI; grpcurl (dataplane AttachInterface); the `net.ectobase.dev`/`platform.ectobase.dev` aggregated APIs.

**Spec:** `docs/superpowers/specs/2026-08-06-talos-ceph-tier2-overlay-design.md`.

---

## Validation model (READ FIRST)

Two tiers (matching the Talos-harness plan):
- **Unit (CI-safe, TDD):** config/derivation, template golden renders, and any pure helpers — `nix develop --command bash -c 'cd test/lab && go test ./internal/... ./topology/...'`. Write these test-first.
- **Live checkpoints (fabric host):** the real gates. Run in the devShell; live commands need real root: `sudo -E env "PATH=$PATH" ...`. The fabric is brought up with `lab up`; per-phase Ceph/KubeVirt via `lab ceph`.

Build the binary with `cd test/lab && go build -o /tmp/lab .` (NOT `go build ./...` from repo root — it walks the root-owned `build/`). Commit after every green step. Leave untracked `central/broker`, `central/controller`, `go.work.sum` alone.

**Key references to port (read, do not modify):** `hack/ceph-demo-up.sh`, `hack/ceph-external-up.sh`, `hack/csi-addons-up.sh`, `hack/install-stack.sh`, `hack/clab/ipv6-fabric.clab.yml` (ceph/ceph-net nodes, lines ~201-290), `hack/clab/ceph-preboot.sh`, `hack/clab/frr/{ceph.conf,daemons}`, `hack/tier2-failover-e2e.sh`, `test/e2e/fixtures/multicluster-tier2/vm.yaml`, `hack/multicluster-e2e.sh` (`attach_endpoint`, lines 137-155), `config/deploy/{controller.yaml,rbac.yaml}`, `central/config/controller.yaml`.

---

## Phase 6a — Cross-cluster overlay datapath (full pipeline)

### Task 1: Deploy the netplane compiler on central

**Files:**
- Modify: `test/lab/internal/deploy/ectobase.go`

The `netplane-controller` (compiler) turns `net.ectobase.dev/NetworkInterface` → `CompiledNIC` (clusterName-stamped). It is defined in `config/deploy/controller.yaml` (Deployment `netplane-controller`, ns `ectobase-system`, image `netplane:dev`, `command: ["controller"]`, hostNetwork on control-plane) and its ClusterRole is in `config/deploy/rbac.yaml` (already applied by the reflector step — it grants `net.ectobase.dev` read on vpcs/networkinterfaces/virtualmachines + write on compilednics/compiledvms/compiledvolumeattachments).

- [ ] **Step 1: Apply the compiler after the reflector**

In `deploy.Ectobase`, right after the reflector apply block (which already applies `config/deploy/{namespace,rbac,reflector}.yaml` and labels the ns privileged), add:
```go
slog.Info("deploying netplane compiler on central")
if err := kubectlApply(ctx, s.CentralKubeconfig,
	filepath.Join(s.RepoRoot, "config/deploy/controller.yaml"),
); err != nil {
	return fmt.Errorf("apply netplane compiler: %w", err)
}
```
(The `netplane-controller` ClusterRole/SA already came from `rbac.yaml`; the ns is already PSA-privileged. hostNetwork on control-plane schedules because `up` untainted the node.)

- [ ] **Step 2: Build + rerun the deploy on the up fabric (LIVE)**

Run: `cd test/lab && go build -o /tmp/lab . && sudo -E env "PATH=$PATH" /tmp/lab deploy`
Expected: completes; then `sudo -n kubectl --kubeconfig test/lab/build/ectobase/central.kubeconfig -n ectobase-system get deploy netplane-controller` shows `1/1`. If the compiler logs RBAC-forbidden, widen the `netplane-controller` ClusterRole in `config/deploy/rbac.yaml` for the missing verb/resource and note it.

- [ ] **Step 3: Commit**
```bash
git add test/lab/internal/deploy/ectobase.go && git commit -m "feat(lab): deploy netplane compiler on central (overlay pipeline)"
```

### Task 2: Cross-cluster overlay ping live test (full pipeline)

**Files:**
- Modify: `test/lab/livetest/ectobase_test.go`
- Create: `test/lab/livetest/overlay_test.go`
- Create: `test/lab/internal/deploy/overlay fixtures` inline (rendered by the test) — no new package.

The endpoints: `nic-a` (10.0.0.1) on k02, `nic-c` (10.0.0.3) on k03, same VPC (`vni` 100). Policy flows central `NetworkInterface` → compiler → `CompiledNIC(clusterName)` → broker → agent. The endpoint is attached via the real dataplane `AttachInterface` (127.0.0.1:1337 in the node netns) using `grpcurl` (image `fullstorydev/grpcurl:latest`, proto `api/proto/dataplane/v1/dataplane.proto`), then the allocated underlay `/128` is recorded into the NIC status so the agent announces it via the reflector.

- [ ] **Step 1: Move the skipped test into overlay_test.go and write the real test**

Delete the `TestCrossClusterOverlayPing` placeholder from `ectobase_test.go`. Create `test/lab/livetest/overlay_test.go`:
```go
//go:build live

package livetest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// overlay endpoints: same VPC (vni 100), one per compute cluster.
const (
	overlayVNI    = 100
	overlayIPk02  = "10.0.0.1"
	overlayIPk03  = "10.0.0.3"
	dataplanePort = "1337"
)

// TestCrossClusterOverlayPing drives the FULL pipeline: a VPC + two NetworkInterfaces
// on central compile (netplane compiler) to per-cluster CompiledNICs, the brokers sync
// them, the agents program policy; the test attaches an endpoint on each node's
// flowplane via the real dataplane AttachInterface, records the underlay /128 so the
// agent announces it via the reflector, then pings across the encapsulated overlay.
func TestCrossClusterOverlayPing(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	// 1. VPC + two NICs on central (workload-labelled so the compiler stamps clusterName).
	require.NoError(t, applyOverlayFixture(ctx, cfg))
	// mark the VPC Ready with a vni (compiler gates on it).
	_, err := kubectl(ctx, cfg, "central", "patch", "vpc", "blue", "--subresource=status",
		"--type=merge", "-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, overlayVNI))
	require.NoError(t, err)

	// 2. CompiledNICs land on each compute cluster (broker sync).
	for _, c := range []struct{ cluster, nic string }{{"k02", "nic-a"}, {"k03", "nic-c"}} {
		c := c
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			out, err := kubectl(ctx, cfg, c.cluster, "get", "compilednics.net.ectobase.dev",
				"-o", "jsonpath={.items[*].metadata.name}")
			if err != nil {
				return err
			}
			if !strings.Contains(out, c.nic) {
				return fmt.Errorf("cluster %s: CompiledNIC for %s not synced yet: %q", c.cluster, c.nic, out)
			}
			return nil
		})
	}

	// 3. Attach endpoints on both nodes' flowplane, record underlay /128 into NIC status.
	ulA := attachEndpoint(t, ctx, cfg, "k02", "nic-a", overlayIPk02)
	ulC := attachEndpoint(t, ctx, cfg, "k03", "nic-c", overlayIPk03)
	require.NotEmpty(t, ulA, "k02 underlay /128")
	require.NotEmpty(t, ulC, "k03 underlay /128")
	recordUnderlay(t, ctx, cfg, "nic-a", ulA)
	recordUnderlay(t, ctx, cfg, "nic-c", ulC)
	// nudge the agents to re-announce.
	_, _ = kubectl(ctx, cfg, "k02", "-n", "ectobase-system", "rollout", "restart", "ds/netplane-agent")
	_, _ = kubectl(ctx, cfg, "k03", "-n", "ectobase-system", "rollout", "restart", "ds/netplane-agent")

	// 4. Cross-cluster overlay ping both ways (the arbiter).
	nodeA := nodeContainerByCluster(cfg, "k02")
	nodeC := nodeContainerByCluster(cfg, "k03")
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return overlayPing(ctx, nodeA, "nic-a", overlayIPk03)
	})
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return overlayPing(ctx, nodeC, "nic-c", overlayIPk02)
	})
}
```

- [ ] **Step 2: Write the helpers** (append to `overlay_test.go`)

```go
// applyOverlayFixture applies a VPC + two NetworkInterfaces to central. Each NIC is
// labelled workload=<cluster> so the compiler stamps spec.clusterName.
func applyOverlayFixture(ctx context.Context, cfg *config.Config) error {
	// central identity of the two compute clusters is by name; the compiler reads a
	// workload/cluster hint from the NIC. Use the same label the compiler keys on:
	// `net.ectobase.dev/cluster` (confirm against the compiler; adjust if it keys on a
	// workload VM ref instead — see live note in Task 2).
	y := fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue}
spec: {}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: nic-a
  labels: {net.ectobase.dev/cluster: k02}
spec:
  vpcRef: {name: blue}
  ips: ["%s"]
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: nic-c
  labels: {net.ectobase.dev/cluster: k03}
spec:
  vpcRef: {name: blue}
  ips: ["%s"]
`, overlayIPk02, overlayIPk03)
	return kubectlApplyStdinCentral(ctx, cfg, y)
}

// attachEndpoint creates a netns on the node and calls the flowplane dataplane
// AttachInterface (127.0.0.1:1337) via grpcurl in the node's netns; returns the
// allocated underlay /128 (fd00:cafe:...). Mirrors hack/multicluster-e2e.sh.
func attachEndpoint(t *testing.T, ctx context.Context, cfg *config.Config, cluster, id, ip string) string {
	t.Helper()
	node := nodeContainerByCluster(cfg, cluster)
	_ = dockerExec(ctx, node, "ip", "netns", "add", id) // best-effort
	req := fmt.Sprintf(`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%d,"requested_ips":[%q]}`, id, id, overlayVNI, ip)
	out, _ := dockerRunGrpcurl(ctx, node, req)
	ul := grepFirst(out, "fd00:cafe:")
	// dpservice-style addressing inside the endpoint netns.
	_ = dockerExec(ctx, node, "sh", "-c",
		fmt.Sprintf("ip netns exec %s ip addr add %s/32 dev %s; ip netns exec %s ip route add 169.254.0.1/32 dev %s; ip netns exec %s ip route add default via 169.254.0.1 dev %s", id, ip, id, id, id, id, id))
	return ul
}
```
Add: `nodeContainerByCluster(cfg, cluster)` (find the cluster's node-1 container), `kubectlApplyStdinCentral` (pipe YAML to `sudo kubectl --kubeconfig central apply -f -`), `recordUnderlay` (`kubectl patch networkinterface <nic> --subresource=status --type=merge -p {"status":{"vni":100,"underlayRoute":"<ul>","state":"Ready"}}` on central), `dockerExec`/`dockerRunGrpcurl` (`sudo docker exec <node> ...` / `sudo docker run --rm --network container:<node> -v <repo>/api/proto:/proto:ro fullstorydev/grpcurl:latest -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d <req> 127.0.0.1:1337 dataplane.v1.DataplaneNode/AttachInterface`), `overlayPing` (`sudo docker exec <node> ip netns exec <id> ping -c2 -W2 <dst>` — stage a musl busybox first if the Talos node lacks ping-in-netns; reuse the `/busybox` copy trick from `hack/multicluster-e2e.sh` lines 178-183), and `grepFirst`.

- [ ] **Step 3: Build + run (LIVE CHECKPOINT)**

Run: `cd test/lab && go build -o /tmp/lab . && export LAB_CONFIG=$PWD/lab.yaml && sudo -E env "PATH=$PATH" LAB_CONFIG=$LAB_CONFIG go test -tags live -count=1 -run TestCrossClusterOverlayPing -v ./livetest/...`
Expected: PASS (both-direction overlay ping). LIVE-ITERATE: the compiler's clusterName-stamping key (label vs workload VM ref), the v4 firewall posture (if the ping is dropped, add an explicit same-VPC allow to the NIC fixture — see [[lb-firewall-dsr-gotcha]]), and whether the agent auto-attaches from CompiledNIC vs needing the manual grpcurl attach. Commit each fix.

- [ ] **Step 4: Commit**
```bash
git add test/lab/livetest && git commit -m "test(lab): cross-cluster overlay ping via full compiler/broker pipeline"
```

**LIVE CHECKPOINT (Phase 6a):** `lab test` now includes a passing `TestCrossClusterOverlayPing`.

---

## Phase 6b — Ceph + ceph-csi + csi-addons on Talos

### Task 3: Ceph clab node + fabric derivation + golden

**Files:**
- Modify: `test/lab/internal/config/{config.go,derive.go}`, `test/lab/internal/fabric/fabric.go`
- Modify: `test/lab/templates/fabric.clab.yml.tmpl`, `test/lab/templates/vyos/switch.set.tmpl`
- Create: `test/lab/templates/ceph/{ceph-preboot.sh,frr-daemons,frr.conf.tmpl}` (embedded)
- Modify/Create: golden `test/lab/internal/render/testdata/golden/fabric.clab.yml` (regen), `test/lab/internal/render/ceph_test.go`

- [ ] **Step 1: Config toggle + ceph prefix derivation (TDD)**

Add to `config.go`: `type Fabric struct{ ...; Ceph Ceph }` with `type Ceph struct{ Enabled bool }` (yaml `ceph`), default false. In `derive.go`, add fabric-level derived values computed with the existing `hash48`:
```go
// in Derived: CephNet64, CephMonAddr, CephNet string
h := hash48("ceph")
c.Derived.CephNet64 = fmt.Sprintf("fd00:cafe:%x::/64", h)
c.Derived.CephMonAddr = fmt.Sprintf("fd00:cafe:%x::1", h)
```
Test (`derive_test.go`): assert `CephMonAddr` is stable + distinct from every cluster prefix.
Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/config/ -run TestDeriveCeph -v'` → PASS.

- [ ] **Step 2: View accessors**

In `fabric.go` add `func (v *View) CephEnabled() bool { return v.Cfg.Fabric.Ceph.Enabled }`, `CephNet64()`, `CephMonAddr()`, and `CephMonEndpoint() string` = `"[" + CephMonAddr + "]:3300"`. Also a `CephPortSeq()` = total nodes + 1 (the switch host-port index for the ceph uplink).

- [ ] **Step 3: Ceph node in the clab template**

In `fabric.clab.yml.tmpl`, guarded by `{{- if .CephEnabled }}`, add the `ceph-net` + `ceph` nodes (port `hack/clab/ipv6-fabric.clab.yml` ceph blocks) with binds to the rendered `ceph/` files, `network-mode: container:clab-{{.Name}}-ceph-net`, `startup-delay: 20`, env (`MON_IP: "[{{.CephMonAddr}}]"`, `CEPH_PUBLIC_NETWORK: {{.CephNet64}}`, `IP_VERSION: "6"`, `CEPH_ARGS: "--ms-bind-ipv4=false --osd-pool-default-size=1"`, `DEMO_DAEMONS: osd`), and links `ceph-net:eth1↔sw1:eth{{add 2 .CephPortSeq}}`, `ceph-net:eth2↔sw2:eth{{add 2 .CephPortSeq}}` (mtu 3000). Render `ceph/ceph-preboot.sh` (port `hack/clab/ceph-preboot.sh` with `{{.CephMonAddr}}/64` on dummy0), `ceph/frr-daemons` (copy `hack/clab/frr/daemons`), `ceph/frr.conf` (port `hack/clab/frr/ceph.conf`: AS `{{.ASHost}}`, `network {{.CephNet64}}`, unnumbered eBGP on eth1/eth2).

- [ ] **Step 4: Switch peers the ceph port**

In `switch.set.tmpl`, guarded by `{{- if .CephEnabled }}`, add the ceph host-port peering on `eth{{add 2 $.CephPortSeq}}` into the same host peer-group (as-override), so the ceph `/64` propagates to the nodes. Add the RA/transit lines matching the node ports.

- [ ] **Step 5: Golden + render (unit)**

Add `ceph_test.go`: render with a `ceph.enabled: true` fixture; assert the clab golden contains `ceph-net`, `ceph`, the `MON_IP` bracketed addr, and `sw1`/`sw2` peer the ceph port. Regen goldens:
Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/render/ -run "Clab|Ceph|Vyos" -update && go test ./internal/render/ -v'` → PASS. Eyeball the diff.

- [ ] **Step 6: Commit** `git add test/lab && git commit -m "feat(lab): optional fabric-attached Ceph clab node + derivation + templates"`.

### Task 4: `lab ceph` — Ceph pool + ceph-csi + csi-addons deploy

**Files:**
- Create: `test/lab/internal/deploy/ceph.go`, `test/lab/internal/deploy/csiaddons.go`, `test/lab/cmd/ceph.go`
- Modify: `test/lab/topology/fabric.go` (a `Ceph(ctx,cfg)` entrypoint)

Port `hack/ceph-demo-up.sh` + `hack/ceph-external-up.sh` + `hack/csi-addons-up.sh` into Go. The ceph container is `clab-<name>-ceph`; the mon endpoint is `[<CephMonAddr>]:3300`.

- [ ] **Step 1: `deploy.CephDemo(ctx, spec)`** — port `ceph-demo-up.sh`:
  - `exec.Sudo(ctx, "modprobe", "rbd")` on the host (nodes share the host kernel).
  - Poll `docker exec clab-<name>-ceph ceph -s` until mon responsive + osd up; `ceph health mute OSD_UNREACHABLE --sticky`.
  - `ceph osd pool create replicapool 8 8`; `rbd pool init replicapool`; `ceph auth get-or-create-key client.rbd mon 'profile rbd' osd 'profile rbd pool=replicapool'`; `ceph fsid`.
  - Return a struct `CephParams{FSID, Mon, Pool, Key}` (also write `build/<name>/ceph.env`).
  - **Talos delta:** attempt an RBD PVC; if the node plugin errors on `/sys` ro or missing `/dev/rbd`, apply per-node fixups via nsenter (`mount -o remount,rw /sys`; `mount -t devtmpfs devtmpfs /dev`) — a helper `ensureNodeKrbd(ctx, cfg)` iterating compute node containers, called before the PVC test. Only apply if needed (probe first).
- [ ] **Step 2: `deploy.CephCSI(ctx, kubeconfig, params)`** — port `ceph-external-up.sh`: `helm upgrade --install ceph-csi-rbd ceph-csi/ceph-csi-rbd --version 3.11.0 --repo https://ceph.github.io/csi-charts -n ceph-csi --create-namespace -f <rendered values>` with `csiConfig[0]={clusterID:FSID, monitors:[Mon]}`, `provisioner.replicaCount=1`, `secret{create,name:csi-rbd-secret,userID:rbd,userKey:Key}`, `storageClass{create,name:ceph-rbd,clusterID:FSID,pool:replicapool,imageFeatures:layering,mapOptions:ms_mode=prefer-crc,fstype:ext4}`. Label ns `ceph-csi` PSA-privileged (Talos). Render the values YAML to `build/<name>/ceph/csi-values-<cluster>.yaml`.
- [ ] **Step 3: `deploy.CSIAddons(ctx, centralKubeconfig, version)`** — port `csi-addons-up.sh`: apply `crds.yaml`/`rbac.yaml`/`setup-controller.yaml` from the `v0.12.0` release (fetch over host internet or vendor); create `csi-addons-system` ns first; inject the `csi-addons` sidecar (`quay.io/csiaddons/k8s-sidecar:v0.12.0`, port 9070, the documented args/env, shared `socket-dir`) into the `ceph-csi-rbd-provisioner` Deployment; add the sidecar ClusterRole (csiaddonsnodes + pods + replicasets/deployments + `system:auth-delegator` binding). Label ns `csi-addons-system` privileged.
- [ ] **Step 4: `cmd/ceph.go` + `topology.Ceph`** — a `lab ceph` cobra command that loads config, requires `cfg.Fabric.Ceph.Enabled`, then: `CephDemo` (central-run params) → `CephCSI` on each compute cluster + central (central runs the provisioner as fence executor per tier2) → `CSIAddons` on central → `ensureNodeKrbd`. Add `lab ceph --purge` (helm uninstall + delete namespaces). Register on root.
- [ ] **Step 5: Build + unit** — `go build -o /tmp/lab .` + a unit test for the values-render + argv composition (inject a fake runner). Commit `feat(lab): lab ceph — Ceph pool + ceph-csi + csi-addons deploy`.

### Task 5: RBD PVC cross-cluster live test

**Files:** Create `test/lab/livetest/ceph_test.go` (append to the suite).

- [ ] **Step 1:** `TestRBDPVCBinds` (`//go:build live`): skip unless `cfg.Fabric.Ceph.Enabled` and the `ceph-rbd` StorageClass exists on k02. For each of k02, k03: apply a 1Gi PVC (`storageClassName: ceph-rbd`), `eventually` (2m) assert `status.phase == Bound`, then delete it. Assert the central provisioner pod is Running.
- [ ] **Step 2 (LIVE CHECKPOINT):**
  Run: `sudo -E env "PATH=$PATH" /tmp/lab up` (ensure fabric up with `ceph.enabled: true` in `lab.yaml`), then `sudo -E env "PATH=$PATH" /tmp/lab ceph`, then `... /tmp/lab test` (`-run TestRBDPVCBinds`).
  Expected: PVC Bound on both k02 and k03. LIVE-ITERATE the Talos krbd deltas (Task 4 step 1) + the msgr-v2-only mon (`:3300`, connection-refused on `:6789`). Commit fixes.
- [ ] **Step 3: Commit** `test(lab): RBD PVC binds cross-cluster on Talos`.

**LIVE CHECKPOINT (Phase 6b):** an RBD PVC binds on both compute clusters; `NetworkFence` CRD present on central.

---

## Phase 6c — Tier-2 fenced failover gate

### Task 6: KubeVirt + CDI + materializer + controller fsid wiring

**Files:**
- Create: `test/lab/internal/deploy/kubevirt.go`, add to `cmd/ceph.go` or a new `cmd/tier2.go`
- Modify: `test/lab/topology/fabric.go`

Port `hack/install-stack.sh` KubeVirt/CDI bits into Go.

- [ ] **Step 1: `deploy.KubeVirtCDI(ctx, kubeconfig)`** — apply KubeVirt `v1.5.0` operator+CR, wait `kv/kubevirt` Available; patch the CR with `developerConfiguration.useEmulation=true`, `featureGates:[NetworkBindingPlugins]`, and `network.binding.flowplane={domainAttachmentType: tap, networkAttachmentDefinition: "ectobase-system/flowplane"}`; apply CDI `v1.61.0` operator+CR, wait `cdi/cdi` Available. Label `kubevirt`/`cdi` namespaces privileged (Talos). Run per compute cluster.
- [ ] **Step 2: materializer + compiler-on-central VM perms** — the chart already ships `vm-materializer` on compute; confirm it's deployed (it is, via the chart). Ensure the central compiler (Task 1) + central controller have the VM/CompiledVM/CompiledVolumeAttachment perms (`config/deploy/rbac.yaml` + `central/config/controller.yaml` already grant these from tier2 — verify, widen live if forbidden).
- [ ] **Step 3: central controller fsid patch** — after `lab ceph` computes the FSID, patch the central controller `-csi-cluster-id=<fsid>` (the arg exists empty in `central/config/controller.yaml`): `kubectl -n system set env`/`patch deploy central-controller` to set the arg, OR re-apply controller.yaml with the fsid substituted. Add a `deploy.PatchCentralCSIClusterID(ctx, centralKubeconfig, fsid)` helper. Wire into `lab tier2` (below).
- [ ] **Step 4: `cmd/tier2.go`** — `lab tier2 up` = `KubeVirtCDI` on k02/k03 + `PatchCentralCSIClusterID`. Register on root. Build + commit `feat(lab): lab tier2 — KubeVirt+CDI+fencing wiring`.

### Task 7: Tier-2 failover fixture + live test

**Files:**
- Create: `test/lab/livetest/testdata/tier2-vm.yaml`, `test/lab/livetest/tier2_test.go`

Port `test/e2e/fixtures/multicluster-tier2/vm.yaml` + `hack/tier2-failover-e2e.sh` phases.

- [ ] **Step 1: fixture** — `testdata/tier2-vm.yaml`: VPC `blue` (vni 100), NetworkInterface `tier2-nic` (ips `10.0.0.20`, mac `52:54:00:00:00:20`), Volume `tier2-disk` (`size:1Gi, storageClass: ceph-rbd, bootImage: quay.io/containerdisks/fedora:41`), VirtualMachine `tier2-vm` (`clusterName: k02`, interfaceRefs/volumeRefs, `runStrategy: RerunOnFailure`, cpu 1/mem 1Gi).
- [ ] **Step 2: `TestTier2Failover` (`//go:build live`)** — port the e2e phases as Go, `eventually`-polling (long timeouts):
  1. `kubectl --kubeconfig central apply -f testdata/tier2-vm.yaml`; patch VPC status Ready.
  2. Assert VM `spec.clusterName==k02`; assert VMI materialized on k02 (`kubectl --kubeconfig k02 -n <ns> get vmi tier2-vm`) + RBD PVC Bound. **Boot-image note:** first try the real CDI import (fabric egress may let the importer pull — the kind blocker); if it stalls, switch the fixture Volume to a containerDisk + blank RBD data disk and assert the RBD attach instead (document the choice).
  3. Extract the k02 fence coordinate: `kubectl --kubeconfig central get clusterpools.platform.ectobase.dev k02 -o jsonpath={.status.nodePrefixes[0]}`.
  4. `sudo docker kill clab-<name>-k02-1`.
  5. Assert `NetworkFence` `status.result==Succeeded` (central) + `docker exec clab-<name>-ceph ceph osd blocklist ls` contains the k02 `/64` cidr.
  6. Assert VM `spec.clusterName==k03` (scheduler rebind) + VMI materializes on k03 with the same RBD.
  7. `sudo docker start clab-<name>-k02-1`; assert blocklist clears + NetworkFence deleted + pool k02 recovers.
- [ ] **Step 3 (LIVE CHECKPOINT):**
  Run: `sudo -E env "PATH=$PATH" /tmp/lab up` (ceph.enabled) → `lab ceph` → `lab tier2 up` → `... go test -tags live -run TestTier2Failover -v ./livetest/...`.
  Expected: fence `Succeeded` + blocklist + VM rebinds k02→k03 + RBD follows. LIVE-ITERATE (fence CR naming, reflector withdrawal timing, CDI vs containerDisk, KVM emulation). If guest OS can't fully boot (no `/dev/kvm`), assert the fence+reschedule+RBD-map core (matches tier2's validated scope) and document the guest-boot limit. Commit fixes.
- [ ] **Step 4: Commit** `test(lab): Tier-2 fenced VM-reschedule gate on Talos`.

**LIVE CHECKPOINT (Phase 6c):** `TestTier2Failover` proves the fenced cross-cluster reschedule with RBD following.

---

## Task 8: Docs + final verification

**Files:** Modify `test/lab/README.md`.

- [ ] **Step 1:** Extend `test/lab/README.md` with the new surface: `lab ceph`, `lab tier2 up`, the `ceph.enabled` config toggle, the three new live tests, and the Talos-specific notes (host `modprobe rbd`, krbd `/sys`+`/dev` fixups, CDI-over-fabric-egress, KVM/guest-boot caveat, csi-addons fence coordinate = node `/64`).
- [ ] **Step 2: Final verification:**
  - Unit: `nix develop --command bash -c 'cd test/lab && go test ./internal/... ./topology/...'` green.
  - Live: `lab test` (full suite) — overlay + RBD + tier2 assertions pass (or documented-skip for guest-boot).
  - Regression: `make chart-test` green; `git diff --name-only main...HEAD | grep -E '^flowplane/|\.rs$'` empty; central envtests green.
- [ ] **Step 3: Commit** `docs(lab): document lab ceph / lab tier2 + Tier-2 gate`; then run `superpowers:finishing-a-development-branch`.

---

## Self-review notes

- **Spec coverage:** §4 (6a)→T1/T2; §5 (6b ceph node)→T3, (deploy)→T4, (PVC)→T5; §6 (6c deploy)→T6, (failover test)→T7; §7 testing→T2/T5/T7 live + T3 golden + T4 unit; §8 surface→T1/T4/T6; §9 success→T2/T5/T7 checkpoints. No gaps.
- **Known live-resolved details (flagged, not placeholders):** the compiler's clusterName-stamping key (label vs VM ref) at T2; the v4 firewall posture at T2; the Talos krbd `/sys`+`/dev` fixups at T4/T5 (probe-then-fix); CDI-import vs containerDisk at T7; KVM guest-boot at T7 — each has a concrete fallback + a verification command.
- **Type consistency:** `CephParams{FSID,Mon,Pool,Key}`, `deploy.CephDemo/CephCSI/CSIAddons/KubeVirtCDI/PatchCentralCSIClusterID`, `View.Ceph*` accessors, `config.Derived.Ceph{Net64,MonAddr}` used consistently across tasks.
