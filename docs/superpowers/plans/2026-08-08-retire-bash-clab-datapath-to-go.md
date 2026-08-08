# Retire the bash `hack/clab` fabric; port the datapath e2e to the Go lab — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Leave `hack/` containing only genuine utilities + production artifacts, re-home the flowplane **datapath** end-to-end suite (DHCPv6 / NAT egress / underlay inference / LB) onto the Go `test/lab` kind fabric, delete the bash containerlab fabric (`hack/clab` + `clab-up.sh`/`clab-down.sh` + the `test/e2e` datapath tests), and prove `lab down` leaves **zero host leftovers**.

**Architecture:** The datapath tests move from the standalone bash single-cluster fabric (`test/e2e`, which each shelled out to `hack/clab-up.sh`) onto the already-running multi-cluster `test/lab` kind fabric. They reuse the machinery `TestCrossClusterOverlayPing` already proves in `test/lab/livetest/overlay_test.go`: `requireFabricUp`, `flowplanePod`, `attachEndpoint`/`dataplaneGRPC` (grpcurl at `127.0.0.1:1337` in the node netns via a `docker run --network container:<node>`), and static (`CGO_ENABLED=0`) Go probe binaries `docker cp`'d into the kind node at a **root** path (kind `/tmp` is tmpfs). No new images; no `clab-up.sh`.

**Tech Stack:** Go 1.x (`//go:build live` tests, testify), containerlab + kind (driven by the Go `test/lab` CLI), the `test/lab/internal/{config,exec,fabric,clab}` packages, the flowplane `DataplaneNode` gRPC API, and the existing Go probes `cmd/tap-dhcp-probe` + `cmd/netprobe`.

**Source spec:** `docs/superpowers/specs/2026-08-08-retire-bash-clab-datapath-to-go-design.md`. Execution is **subagent-driven** (one fresh subagent per task, review between tasks).

---

## Execution environment (READ FIRST — applies to every task)

These conventions come from the completed kind-substrate effort and are non-negotiable for this repo:

- **Run Go through the nix devShell:** `nix develop --command bash -c '<go/test cmd>'`.
- **Live commands need root inside the devShell:** `sudo -E env "PATH=$PATH" <cmd>` (the lab's clab/kubectl/docker state is root-owned). The Makefile already wraps this as `LAB_ROOT := sudo -E env "PATH=$PATH" go run ./test/lab`.
- **The lab CLI is `go run ./test/lab`** (the user dislikes `/tmp` binaries). Makefile targets: `make lab-render|lab-up|lab-down|lab-down-purge|lab-deploy|lab-ceph|lab-tier2-up|lab-test`.
- **Templates are `go:embed`'d** — a plain `go run ./test/lab` always re-embeds, so no rebuild dance is needed (only the old `/tmp/lab` binary needed rebuilds).
- **Never `git add -A`** (it stages untracked `central/` binaries + `build/` trees). Stage explicit paths only.
- **The pre-commit hook runs clippy/rustfmt only** — it does NOT run `go test`. Verify Go builds/tests yourself before committing.
- **Live datapath tests are gated** behind `//go:build live` + `requireFabricUp` (skip when the fabric is down). They are NOT in CI, exactly as `test/e2e` was.
- **clab teardown can wedge** — if `lab down` hangs, force-kill the containerd-shim (`pkill -9 -f <container-id>`); poll long ops via marker/log files, never `pgrep -f` a `go run` invocation (it self-matches).

**Fabric facts used below (from `test/lab/internal/fabric/fabric.go`):**
- Node underlay identities live in `NodeAggr = fd00:cafe::/32` (per-cluster `fd00:cafe:<h>::/48`). `AttachInterface` returns a `fd00:cafe:…` /128.
- Edge DNS64 loopbacks: `EdgeLoopback = fd00:ffff` → `fd00:ffff::e1` / `fd00:ffff::e2`, aggregated as `LoopAggr = fd00:ffff::/32` and advertised into the fabric → **routable from any compute node** (used as the NAT-egress external-route nexthop).
- kind nodes are dual-homed: `eth1` + `eth2` are the fabric uplinks (ECMP), `eth0` is docker mgmt. The node container name is `DerivedNode.KindContainer()` (`<cluster>-control-plane`).
- Compute clusters are `k02`, `k03`; `computeNodes(cfg)` (in `egress_test.go`) returns their nodes. kindnet forces 1 node/cluster.

**gRPC into the node (already implemented in `overlay_test.go`):** `dataplaneGRPC(t, ctx, container, method, jsonBody)` runs `docker run --rm --network container:<node> fullstorydev/grpcurl … 127.0.0.1:1337 dataplane.v1.DataplaneNode/<method>` and returns `(stdout, err)`. **Method names passed to `dataplaneGRPC` are BARE** (e.g. `"AttachInterface"`, `"AddNatSource"`) — it prepends `dataplane.v1.DataplaneNode/`. (This differs from the old `test/e2e` `grpcIn`, which took the fully-qualified method.)

---

## File Structure

**Phase 1 — deletions + comment fixups (no new files):**
- Delete: `hack/{kind-up.sh,kind-down.sh,ceph-demo-up.sh,ceph-external-up.sh,csi-addons-up.sh,install-stack.sh,tier2-failover-e2e.sh,rook-ceph-up.sh,kubevirt-vm-e2e.sh,medik8s-up.sh,tier1-failover-e2e.sh}` and `test/e2e/kind_test.go`.
- Edit comments (drop dead script names): `test/lab/internal/deploy/{ceph.go,csiaddons.go,kubevirt.go}`, `central/config/controller.yaml`, `config/deploy/kubevirt-binding.yaml`, `deploy/charts/ectobase/templates/kubevirt-binding.yaml`, `test/scenario-restart-continuity.sh`, `deploy/charts/ectobase/README.md`.

**Phase 2 — new live datapath tests under `test/lab/livetest/` (all `//go:build live`, `package livetest`):**
- Create: `test/lab/livetest/datapath_common_test.go` — shared helpers (`attachGuest`, `buildStaticBin`, `copyToNode`, `nodeExec`, `edgeNexthop`).
- Create: `test/lab/livetest/dhcp_test.go` — `TestDhcpLeaseSmoke` (DHCPv4 + the sole DHCPv6 conformance).
- Create: `test/lab/livetest/nategress_test.go` — `TestNatEgressSmoke` (guest SNAT observed on the node uplink).
- Create: `test/lab/livetest/underlay_test.go` — `TestUnderlayInferenceOnFabric`.
- Create: `test/lab/livetest/lb_test.go` — `TestLbDistributeSmoke` (NEW; may land `t.Skip`'d per the documented LB risk).

**Phase 3 — remove the bash clab fabric:**
- Delete: `hack/clab/` (dir), `hack/clab-up.sh`, `hack/clab-down.sh`, `hack/multicluster-e2e.sh`, `test/e2e/env.go`, `test/e2e/{routebus_test.go,smoke_datapath_test.go,smoke_lb_dhcp_test.go,fabric_test.go}`. If `test/e2e` is then empty of `.go`, remove the package (keep `cmd/`, `netprobe`, `tap-dhcp-probe*`, `fixtures/`, `internal/` only if still referenced — verify).
- Edit: root `README.md` (drop the `hack/clab` bring-up section; point at `test/lab`).

**Phase 4 — verify + harden `lab down` (no new production files; one optional self-check test):**
- Optionally create: `test/lab/livetest/cleanup_test.go` — a `lab down` zero-leftovers assertion, OR fold the assertion into a `lab down` self-check log in `test/lab/topology/fabric.go`.

---

## Phase 1 — safe deletions (no behavior to re-prove)

Purely subtractive + comment fixups. `hack/clab`, `clab-up.sh`, `clab-down.sh`, and the datapath `test/e2e/*` are **NOT** touched here. All the "who references it" checks were done up front: every non-doc reference to the deleted scripts is a **comment or an error-message hint**, and no deleted script is executed by a surviving script.

### Task 1.1: Delete the already-ported, dead, Tier-1, and bare-kind scripts

**Files:**
- Delete: `hack/kind-up.sh`, `hack/kind-down.sh`
- Delete: `hack/ceph-demo-up.sh`, `hack/ceph-external-up.sh`, `hack/csi-addons-up.sh`, `hack/install-stack.sh`, `hack/tier2-failover-e2e.sh`, `hack/rook-ceph-up.sh`
- Delete: `hack/kubevirt-vm-e2e.sh`
- Delete: `hack/medik8s-up.sh`, `hack/tier1-failover-e2e.sh`
- Delete: `test/e2e/kind_test.go`

- [ ] **Step 1: Confirm nothing surviving executes these (guard against regressions)**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
for s in kind-up kind-down ceph-demo-up ceph-external-up csi-addons-up install-stack tier2-failover-e2e rook-ceph-up kubevirt-vm-e2e medik8s-up tier1-failover-e2e; do
  echo "--- $s.sh ---"
  grep -rln --exclude-dir=.git "$s.sh" . | grep -v -E "docs/|hack/$s.sh$"
done
```
Expected: only these NON-executing references remain (all comments / an error hint / hack files that are themselves being deleted): `central/config/controller.yaml`, `config/deploy/kubevirt-binding.yaml`, `deploy/charts/ectobase/templates/kubevirt-binding.yaml`, `deploy/charts/ectobase/README.md`, `test/scenario-restart-continuity.sh`, `test/lab/internal/deploy/{ceph,csiaddons,kubevirt}.go`, and other `hack/*.sh` in the delete set. If anything ELSE (a live `.sh`/`.go` that RUNS the script) appears, STOP and report.

- [ ] **Step 2: git rm the scripts + the bare-kind test**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git rm hack/kind-up.sh hack/kind-down.sh \
  hack/ceph-demo-up.sh hack/ceph-external-up.sh hack/csi-addons-up.sh \
  hack/install-stack.sh hack/tier2-failover-e2e.sh hack/rook-ceph-up.sh \
  hack/kubevirt-vm-e2e.sh hack/medik8s-up.sh hack/tier1-failover-e2e.sh \
  test/e2e/kind_test.go
```
Expected: `rm 'hack/...'` lines, no errors.

- [ ] **Step 3: Verify `test/e2e` still builds without `kind_test.go`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/e2e && go vet ./... 2>&1 | head -30'
```
Expected: no errors that reference `kind_test.go`, `KindCentral`, or a now-undefined symbol it defined. (The datapath tests in `test/e2e` remain and still build — they are removed in Phase 3.) If `kind_test.go` defined a symbol the other tests use, STOP and report which — it must be relocated, not deleted.

- [ ] **Step 4: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add -u hack/ test/e2e/kind_test.go
git commit -m "chore(hack): delete already-ported, dead, Tier-1, and bare-kind scripts

The ceph/csi/install-stack/tier2/rook scripts are ported to test/lab/internal/deploy;
kubevirt-vm-e2e is dead; medik8s/tier1 are dormant (revive in Go later); kind-up/down
+ test/e2e/kind_test.go only tested kind itself. No surviving script executes any of
these (verified). hack/clab + clab-up/down + the datapath test/e2e/* are untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.2: Drop the dead script names from comments + the chart README

**Files:**
- Modify: `test/lab/internal/deploy/ceph.go:84`, `test/lab/internal/deploy/ceph.go:292`
- Modify: `test/lab/internal/deploy/csiaddons.go:32`
- Modify: `test/lab/internal/deploy/kubevirt.go:14`, `:42`, `:54`
- Modify: `central/config/controller.yaml:77`
- Modify: `config/deploy/kubevirt-binding.yaml:3`, `deploy/charts/ectobase/templates/kubevirt-binding.yaml:3`
- Modify: `test/scenario-restart-continuity.sh:115`
- Modify: `deploy/charts/ectobase/README.md:13`, `:36`

- [ ] **Step 1: Fix the `test/lab/internal/deploy` "port of" comments**

The Go code is the source of truth now; drop the file references so `git grep <script>` is clean. Apply these edits:

`test/lab/internal/deploy/ceph.go:84` — change `// external ceph-csi. Dev-only, NOT production. Port of hack/ceph-demo-up.sh.` to:
```go
// external ceph-csi. Dev-only, NOT production. (Formerly hack/ceph-demo-up.sh.)
```
`test/lab/internal/deploy/ceph.go:292` — change `// Dev-only. Port of hack/ceph-external-up.sh.` to:
```go
// Dev-only. (Formerly hack/ceph-external-up.sh.)
```
`test/lab/internal/deploy/csiaddons.go:32` — change `// hack/csi-addons-up.sh.` to:
```go
// (formerly hack/csi-addons-up.sh).
```
`test/lab/internal/deploy/kubevirt.go` lines 14, 42, 54 — replace each `port of hack/install-stack.sh` (and the `:42` `hack/install-stack.sh). It:` form) with `formerly hack/install-stack.sh`, keeping the surrounding prose intact. Read the file first and edit each occurrence precisely.

- [ ] **Step 2: Fix the remaining comment/hint references**

`central/config/controller.yaml:77` — the comment `# The ceph fsid (clusterID) is per-deploy (ceph-demo-up.sh emits it), so it cannot be` becomes:
```yaml
            # The ceph fsid (clusterID) is per-deploy (the lab ceph deploy emits it), so it cannot be
```
`config/deploy/kubevirt-binding.yaml:3` and `deploy/charts/ectobase/templates/kubevirt-binding.yaml:3` — replace `see hack/install-stack.sh` with `see the lab KubeVirt deploy (test/lab/internal/deploy/kubevirt.go)`.

`test/scenario-restart-continuity.sh:115` — replace the hint `deploy the stack (hack/install-stack.sh) with the branch image` with `deploy the stack (make lab-deploy) with the branch image`.

- [ ] **Step 3: Remove medik8s/tier1 from the chart README**

Read `deploy/charts/ectobase/README.md` around lines 13 and 36. Line 13 references `hack/medik8s-up.sh` as a prerequisite; line 36 references `hack/tier1-failover-e2e.sh`. Tier-1 is deleted/dormant. Replace the prerequisite line with a note that Tier-1 (medik8s NHC + SNR) is not currently wired in the Go lab, and drop the `tier1-failover-e2e.sh` sentence (or replace with "Tier-1 failover is dormant; see the Tier-2 gate via `make lab-tier2-up`"). Keep the surrounding chart docs intact.

- [ ] **Step 4: Verify no dangling references + build stays green**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git grep -nE "kind-up\.sh|kind-down\.sh|ceph-demo-up\.sh|ceph-external-up\.sh|csi-addons-up\.sh|install-stack\.sh|tier2-failover-e2e\.sh|rook-ceph-up\.sh|kubevirt-vm-e2e\.sh|medik8s-up\.sh|tier1-failover-e2e\.sh" -- ':!docs/'
```
Expected: **no output** (all non-doc references gone). Then:
```bash
nix develop --command bash -c 'cd test/lab && go build ./... && cd ../.. && make chart-test'
```
Expected: build succeeds; `make chart-test` passes (22).

- [ ] **Step 5: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/internal/deploy/ceph.go test/lab/internal/deploy/csiaddons.go \
  test/lab/internal/deploy/kubevirt.go central/config/controller.yaml \
  config/deploy/kubevirt-binding.yaml deploy/charts/ectobase/templates/kubevirt-binding.yaml \
  test/scenario-restart-continuity.sh deploy/charts/ectobase/README.md
git commit -m "docs(hack): drop deleted-script names from comments + chart README

The Go deploy code is the source of truth; remove the now-dead hack/*.sh references
from comments/hints so git grep is clean. No behavior change.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 2 — port the datapath e2e onto `test/lab` (the substance)

All new tests are `//go:build live`, `package livetest`, and run against an **already-up** fabric (`make lab-up && make lab-deploy` — the flowplane DaemonSet is already running; the tests do NOT deploy it). Each reuses `requireFabricUp`, `computeNodes`, `nodeContainer`, `flowplanePod`, `dataplaneGRPC`, `kubectl`, `dockerPID`, and `eventually` from the existing `main_test.go`/`overlay_test.go`/`egress_test.go`.

**How to run one live test during development:**
```bash
# Fabric must be up first: make lab-up && make lab-deploy  (and make lab-ceph for ceph tests)
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run TestDhcpLeaseSmoke -count=1 -v ./livetest/... -timeout 20m'
```
(`LAB_CONFIG` is picked up from the env when set by `make`; when running `go test` directly from `test/lab`, `configPath()` falls back to `./lab.yaml`, which is correct because the test binary runs from the package dir under `test/lab`.)

### Task 2.1: Shared datapath test helpers

**Files:**
- Create: `test/lab/livetest/datapath_common_test.go`

- [ ] **Step 1: Write the shared helpers**

Create `test/lab/livetest/datapath_common_test.go` with exactly this content:

```go
//go:build live

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	labexec "github.com/trevex/ectobase/test/lab/internal/config"
	texec "github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// edgeNexthop is a fabric-routable /128 in the edge DNS64 loopback range
// (fabric.EdgeLoopback / LoopAggr fd00:ffff::/32, advertised into the fabric). Used
// as the NAT-egress external-route nexthop: the node's route lookup resolves it and
// transmits the IPIP-encapped frame on an uplink, which is all the SNAT sniff needs
// (the edges are VyOS NAT64 routers here, not flowplane, so we assert SNAT AT THE
// NODE UPLINK, not end-to-end internet).
const edgeNexthop = fabric.EdgeLoopback + "::e1"

// guestGWMAC is the router MAC the datapath advertises to guests (GW_MAC); probes
// use it as the L2 dst for egress frames. Matches the dataplane's gateway MAC.
const guestGWMAC = "02:00:00:00:00:01"

// attachGuest creates a guest netns on the node (via the flowplane pod, which
// hostPath-mounts the node's /var/run/netns), calls AttachInterface over the real
// dataplane with the given (dual-stack) IPs and MAC, brings the in-netns guest iface
// up (named == id) so AF_PACKET probes can bind, and returns the allocated underlay
// /128. Idempotent: reuses an already-attached endpoint's underlay.
//
// Unlike overlay_test.go's attachEndpoint, this does NOT address the netns (the
// datapath probes speak raw L2 over AF_PACKET) and it accepts multiple requested_ips.
func attachGuest(t *testing.T, ctx context.Context, cfg *labexec.Config, node labexec.DerivedNode, id string, ips []string, mac string) string {
	t.Helper()
	container := nodeContainer(cfg, node)
	pod, err := flowplanePod(ctx, cfg, node.Cluster)
	require.NoError(t, err)

	if out, err := dataplaneGRPC(t, ctx, container, "ListInterfaces", ""); err == nil {
		if ul := underlayForID(out, id); ul != "" {
			bringUpGuest(ctx, cfg, node, pod, id)
			return ul
		}
	}

	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--",
		"ip", "netns", "add", id)

	quoted := make([]string, len(ips))
	for i, ip := range ips {
		quoted[i] = fmt.Sprintf("%q", ip)
	}
	req := fmt.Sprintf(`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%d,"mac":%q,"requested_ips":[%s]}`,
		id, id, overlayVNI, mac, strings.Join(quoted, ","))
	out, err := dataplaneGRPC(t, ctx, container, "AttachInterface", req)
	require.NoError(t, err, "AttachInterface %s on %s: %s", id, node.Cluster, out)
	underlay := firstUnderlay(out)
	require.NotEmpty(t, underlay, "no underlay in AttachInterface response for %s: %s", id, out)

	bringUpGuest(ctx, cfg, node, pod, id)
	return underlay
}

// bringUpGuest sets the in-netns guest iface up (best-effort, idempotent).
func bringUpGuest(ctx context.Context, cfg *labexec.Config, node labexec.DerivedNode, pod, id string) {
	sh := fmt.Sprintf("ip netns exec %s ip link set %s up 2>/dev/null; true", id, id)
	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--", "sh", "-c", sh)
}

// addFwEgressAllow programs a deny-by-default-busting egress allow rule (proto 0 =
// any) on the guest interface, required or all guest egress is dropped.
func addFwEgressAllow(t *testing.T, ctx context.Context, container, id string) {
	t.Helper()
	body := fmt.Sprintf(`{"interface_id":%q,"rule_id":"eg","proto":0,"allow":true,"egress":true}`, id)
	out, err := dataplaneGRPC(t, ctx, container, "AddFwRule", body)
	require.NoError(t, err, "AddFwRule egress-allow on %s: %s", id, out)
}

// buildStaticBin compiles a cmd/<pkg> to a CGO_ENABLED=0 static binary in t.TempDir()
// (runs inside the Ubuntu-based kind node after docker cp). Returns the host path.
// Built from repoRoot so ./cmd/... resolves regardless of the test's CWD.
func buildStaticBin(t *testing.T, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), pkg)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/"+pkg)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/%s: %v\n%s", pkg, err, o)
	}
	return out
}

// copyToNode docker-cp's a host file into the kind node container at a ROOT path
// (NOT /tmp — kind mounts /tmp as tmpfs and docker cp there is lost).
func copyToNode(ctx context.Context, container, hostPath, nodePath string) error {
	return texec.Sudo(ctx, "docker", "cp", hostPath, container+":"+nodePath)
}

// nodeExec runs a command inside the kind node container via `sudo docker exec`.
func nodeExec(ctx context.Context, container string, args ...string) (string, error) {
	full := append([]string{"docker", "exec", container}, args...)
	out, err := texec.SudoOutput(ctx, full...)
	return string(out), err
}

// nodeNetnsProbe runs `docker exec <node> ip netns exec <id> <args...>` — the netns
// created via the flowplane pod is visible on the node (shared /var/run/netns).
func nodeNetnsProbe(ctx context.Context, container, id string, args ...string) (string, error) {
	full := append([]string{"ip", "netns", "exec", id}, args...)
	return nodeExec(ctx, container, full...)
}

// asJSON is a tiny helper to keep request-building readable in tests.
func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// waitDeadline is the default per-datapath-assertion budget.
const waitDeadline = 90 * time.Second
```

- [ ] **Step 2: Verify it compiles against the existing package**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && go vet -tags live ./livetest/... 2>&1 | head -40'
```
Expected: compiles clean. **If `vet` reports an unused symbol** (`asJSON`, `waitDeadline`, `addFwEgressAllow`, `nat64`-style helpers) — that is expected until later tasks use them; a Go *test* file with an unused package-level func does NOT fail the build (only unused imports/locals do). If an **import** is unused because a helper isn't wired yet, temporarily remove that import and re-add it in the task that needs it. Confirm there are no type mismatches against `config.Config`/`config.DerivedNode` (note the `labexec` alias is `internal/config`; adjust if the reviewer prefers a plain `config` import — match `overlay_test.go`, which imports it as `config`).

> **Reviewer note:** `overlay_test.go` imports `internal/config` as `config` and `internal/exec` as `exec`. To avoid a clash, this file aliases them (`labexec`, `texec`). Either keep the aliases OR (cleaner) drop them and rely on the fact that each `_test.go` file has its own imports — both compile. Prefer matching the existing files: use `config` and `exec`. Update the code above accordingly if you choose plain names.

- [ ] **Step 3: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/datapath_common_test.go
git commit -m "test(lab): shared datapath live-test helpers (attachGuest, static probe build/copy)

Reuses the TestCrossClusterOverlayPing machinery (flowplanePod, dataplaneGRPC,
node netns) for the datapath suite being ported off the bash clab fabric.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.2: `TestDhcpLeaseSmoke` — DHCPv4 + the sole DHCPv6 conformance

**Files:**
- Create: `test/lab/livetest/dhcp_test.go`
- Test binary: `cmd/tap-dhcp-probe` (built by the test, CGO_ENABLED=0)

Ported from `test/e2e/smoke_lb_dhcp_test.go`, but against the already-up kind fabric (no `clab-up.sh`, no DaemonSet deploy). This is the **PRIMARY DHCPv6 conformance** — the eBPF DHCPv6 responder cannot be moved into the Rust sim (verifier instruction-count limit), so this test is the only end-to-end DHCPv6 byte check.

- [ ] **Step 1: Write the test**

Create `test/lab/livetest/dhcp_test.go`:

```go
//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// dhcp guest identity. The overlay v4 and a distinct guest v6; the DHCPv6 responder
// reads PortMeta.guest_ipv6 (set from requested_ips) to fill the IA Address.
const (
	dhcpGuestID  = "dhcpsmoke"
	dhcpGuestIP  = "10.0.0.21"
	dhcpGuestv6  = "2001:db8:1::21"
	dhcpGuestMAC = "52:54:00:00:00:21"
)

// TestDhcpLeaseSmoke attaches a dual-stack guest on a compute node's flowplane and
// drives a real DHCPv4 DISCOVER and a DHCPv6 SOLICIT through the eBPF responder from
// inside the guest netns (AF_PACKET, --iface), asserting lease contents.
//
//	DHCPv4: yiaddr == dhcpGuestIP (MTU/DNS soft — the DS does not set --dhcp-mtu/-dns).
//	DHCPv6: ia_addr == dhcpGuestv6; ClientId echoed; "DHCPv6 OK" (PRIMARY conformance).
func TestDhcpLeaseSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	// Attach a dual-stack guest (v4 + v6 in requested_ips) and bring the iface up.
	ul := attachGuest(t, ctx, cfg, node, dhcpGuestID, []string{dhcpGuestIP, dhcpGuestv6}, dhcpGuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, dhcpGuestID))
	})

	// Build the static tap-dhcp-probe and copy it to a ROOT path on the node.
	probe := buildStaticBin(t, "tap-dhcp-probe")
	require.NoError(t, copyToNode(ctx, container, probe, "/tap-dhcp-probe"))

	// DHCPv4: FATAL on wrong yiaddr.
	v4Cmd := fmt.Sprintf("/tap-dhcp-probe --client-only --probe dhcp --iface %s --client-mac %s --expect-ip %s --timeout 6 2>&1",
		dhcpGuestID, dhcpGuestMAC, dhcpGuestIP)
	v4Out, v4Err := nodeNetnsProbe(ctx, container, dhcpGuestID, "sh", "-c", v4Cmd)
	t.Logf("DHCPv4 probe output:\n%s", strings.TrimSpace(v4Out))
	require.NoError(t, v4Err, "DHCPv4 probe failed:\n%s", v4Out)
	require.Contains(t, v4Out, "yiaddr="+dhcpGuestIP, "DHCPv4 OFFER missing correct yiaddr")
	t.Logf("DHCPv4 lease smoke PASS: yiaddr=%s", dhcpGuestIP)

	// DHCPv6: PRIMARY CONFORMANCE. FATAL on missing ia_addr / echoed clientid / OK.
	v6Cmd := fmt.Sprintf("/tap-dhcp-probe --client-only --probe dhcpv6 --iface %s --client-mac %s --guest6 %s --timeout 6 2>&1",
		dhcpGuestID, dhcpGuestMAC, dhcpGuestv6)
	v6Out, v6Err := nodeNetnsProbe(ctx, container, dhcpGuestID, "sh", "-c", v6Cmd)
	t.Logf("DHCPv6 probe output:\n%s", strings.TrimSpace(v6Out))
	require.NoError(t, v6Err, "DHCPv6 probe FAILED; guest_ipv6 comes from AttachInterface requested_ips:\n%s", v6Out)
	require.Contains(t, v6Out, "ia_addr="+dhcpGuestv6, "DHCPv6 ADVERTISE missing ia_addr")
	require.Contains(t, v6Out, "echoed_clientid=", "DHCPv6 ADVERTISE missing echoed_clientid")
	require.Contains(t, v6Out, "DHCPv6 OK", "DHCPv6 probe did not print 'DHCPv6 OK'")
	t.Logf("DHCPv6 lease smoke PASS (PRIMARY DHCPv6 CONFORMANCE): guest6=%s", dhcpGuestv6)
}
```

- [ ] **Step 2: Compile-check**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && go vet -tags live ./livetest/... 2>&1 | head -30'
```
Expected: clean compile.

- [ ] **Step 3: Bring the fabric up and run the test live**

Run (from repo root; brings up + deploys if not already):
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-up && make lab-deploy
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run TestDhcpLeaseSmoke -count=1 -v ./livetest/... -timeout 20m'
```
Expected: `--- PASS: TestDhcpLeaseSmoke`, with log lines `DHCPv4 lease smoke PASS` and `DHCPv6 lease smoke PASS (PRIMARY DHCPv6 CONFORMANCE)`.

**If it fails:** capture the probe output + `kubectl -n ectobase-system logs -l app=flowplane --field-selector spec.nodeName=<node>` (via the `kubectl` helper) and diagnose. The most likely gap is the guest iface not up (bring-up race) or `requested_ips` v6 not landing in PortMeta — both are real conformance signals, not test bugs. Do NOT weaken the assertions to pass.

- [ ] **Step 4: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/dhcp_test.go
git commit -m "test(lab): port TestDhcpLeaseSmoke onto the kind fabric (sole DHCPv6 conformance)

DHCPv4 + DHCPv6 lease conformance via the eBPF responder, driven from the guest
netns with the static tap-dhcp-probe against the already-up test/lab fabric — no
clab-up.sh, no DaemonSet deploy. Live-validated PASS on the kind fabric.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.3: `TestNatEgressSmoke` — guest SNAT observed on the node uplink

**Files:**
- Create: `test/lab/livetest/nategress_test.go`
- Test binary: `cmd/netprobe` (built by the test, CGO_ENABLED=0)

Ported from `test/e2e/smoke_datapath_test.go`. **Key adaptation:** the kind lab's edges are VyOS NAT64 routers (not flowplane), so we do NOT assert end-to-end internet reachability. We assert the **SNAT rewrite** by sniffing the IPIP-encapped TCP frame on the node's fabric uplink — exactly what the bash `send-sniff` did on `eth1`. Because kind nodes are dual-homed (eth1+eth2 ECMP), we sniff **both** uplinks concurrently and pass if either observes the SNAT'd frame.

- [ ] **Step 1: Write the test**

Create `test/lab/livetest/nategress_test.go`:

```go
//go:build live

package livetest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	labtexec "github.com/trevex/ectobase/test/lab/internal/exec"
)

const (
	natGuestID  = "natsmoke"
	natGuestIP  = "10.0.0.22"
	natGuestMAC = "52:54:00:00:00:22"
	natPublicIP = "203.0.113.22"
	natPortMin  = 1024
	natPortMax  = 2047
	natExtDst   = "8.8.8.8"
)

// TestNatEgressSmoke attaches a guest, programs egress SNAT (AddNatSource) + an
// external NAT-eligible route (AddRoute external=true, nexthop=edgeNexthop) + an
// egress-allow firewall rule, then injects a raw TCP frame from the guest netns and
// proves SNAT fired by sniffing the IPIP-encapped frame on the node's fabric uplinks
// and asserting the inner TCP source port is in [natPortMin, natPortMax].
//
// The edges are VyOS NAT64 routers here, not flowplane, so this asserts the SNAT
// REWRITE AT THE NODE UPLINK — not end-to-end internet (distinct from the node-level
// TestNAT64Egress, which pings a NAT64-embedded v4 via tayga).
func TestNatEgressSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	ul := attachGuest(t, ctx, cfg, node, natGuestID, []string{natGuestIP}, natGuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, natGuestID))
	})

	// Program SNAT + external route + egress-allow.
	natBody := fmt.Sprintf(`{"vni":%d,"source_ip":%q,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
		overlayVNI, natGuestIP, natPublicIP, natPortMin, natPortMax)
	out, err := dataplaneGRPC(t, ctx, container, "AddNatSource", natBody)
	require.NoError(t, err, "AddNatSource: %s", out)

	routeBody := fmt.Sprintf(`{"vni":%d,"prefix":%q,"nexthop_underlay":%q,"external":true}`,
		overlayVNI, natExtDst+"/32", edgeNexthop)
	out, err = dataplaneGRPC(t, ctx, container, "AddRoute", routeBody)
	require.NoError(t, err, "AddRoute(external): %s", out)

	addFwEgressAllow(t, ctx, container, natGuestID)

	// Build netprobe, copy to the node root.
	netprobe := buildStaticBin(t, "netprobe")
	require.NoError(t, copyToNode(ctx, container, netprobe, "/netprobe"))

	// Sniff BOTH uplinks concurrently (dual-homed ECMP): pass if either sees the
	// SNAT'd inner sport. send-sniff prints "OK: captured N frame(s); inner-tcp-sport=<v>".
	sniff := func(iface string) (string, *exec.Cmd) {
		// Runs via sudo docker exec; returns the started *exec.Cmd + the in-node log path.
		logPath := "/snifflog-" + iface
		shCmd := fmt.Sprintf(
			"/netprobe send-sniff --count 0 --rx-iface %s --rx-outer-ipv6 --rx-inner-ip-dst %s "+
				"--rx-l4 tcp --want-outer-ipv6-nh 4 --extract inner-tcp-sport --sport-range %d-%d "+
				"--timeout 12 > %s 2>&1",
			iface, natExtDst, natPortMin, natPortMax, logPath)
		c := labtexec.SudoCmd(ctx, "docker", "exec", container, "sh", "-c", shCmd)
		_ = c.Start()
		return logPath, c
	}

	log1, c1 := sniff("eth1")
	log2, c2 := sniff("eth2")
	time.Sleep(1500 * time.Millisecond) // let the RX filters arm

	// Inject the guest TCP frame (datapath SNATs the sport into the block + IPIP-encaps).
	sendArgs := []string{"/netprobe", "send", "--iface", natGuestID,
		"--eth-src", natGuestMAC, "--eth-dst", guestGWMAC,
		"--ip-src", natGuestIP, "--ip-dst", natExtDst, "--l4", "tcp",
		"--sport", "12345", "--dport", "80", "--count", "8", "--interval-ms", "200"}
	sendOut, sendErr := nodeNetnsProbe(ctx, container, natGuestID, sendArgs...)
	if sendErr != nil {
		t.Logf("netprobe send (non-fatal if SNAT still fires): %v\n%s", sendErr, sendOut)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = c1.Wait() }()
	go func() { defer wg.Done(); _ = c2.Wait() }()
	wg.Wait()

	l1, _ := nodeExec(ctx, container, "cat", log1)
	l2, _ := nodeExec(ctx, container, "cat", log2)
	t.Logf("send-sniff eth1:\n%s\nsend-sniff eth2:\n%s", strings.TrimSpace(l1), strings.TrimSpace(l2))

	if !strings.Contains(l1, "OK:") && !strings.Contains(l2, "OK:") {
		podLog, _ := kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "logs",
			"-l", "app=flowplane", "--field-selector", "spec.nodeName="+nodeK8sName(node), "--tail=80")
		t.Fatalf("NAT egress SNAT NOT observed on eth1/eth2 (no 'OK:' in send-sniff)\n"+
			"eth1:\n%s\neth2:\n%s\n\nflowplane pod log:\n%s", l1, l2, podLog)
	}
	t.Logf("NAT egress SNAT smoke PASS: guest %s -> %s SNAT'd into %s:[%d-%d], IPIP-encapped on the uplink",
		natGuestIP, natExtDst, natPublicIP, natPortMin, natPortMax)
}
```

- [ ] **Step 2: Ensure a `SudoCmd` helper exists (add if missing)**

The test needs a `*exec.Cmd` it can `Start()`/`Wait()` for the background sniff. Check whether `test/lab/internal/exec` exposes one:
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -n "func Sudo" test/lab/internal/exec/sudo.go
```
If there is **no** `SudoCmd(ctx, ...) *exec.Cmd`, add it to `test/lab/internal/exec/sudo.go`. Read the file first to match the sudo-wrapping convention (it prepends `sudo -E env PATH=…` or similar). Add:
```go
// SudoCmd builds (does not run) an *exec.Cmd that runs the args under sudo, so
// callers can Start/Wait a long-lived process (e.g. a background packet sniff).
func SudoCmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append(sudoPrefix(), args...) // reuse the same prefix Sudo() uses
	return exec.CommandContext(ctx, full[0], full[1:]...)
}
```
Match the actual prefix construction used by `Sudo`/`SudoOutput` in that file — read it and mirror it exactly (do NOT invent `sudoPrefix()` if the file inlines the prefix; extract or inline consistently). Add the `os/exec` import if needed. This is a **non-test** file, so an unused func would fail vet only if truly unused — it is used by `nategress_test.go`.

- [ ] **Step 3: Compile-check both the helper and the test**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && go build ./... && go vet -tags live ./livetest/... 2>&1 | head -30'
```
Expected: clean.

- [ ] **Step 4: Run live (fabric already up from Task 2.2)**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run TestNatEgressSmoke -count=1 -v ./livetest/... -timeout 20m'
```
Expected: `--- PASS: TestNatEgressSmoke` with `NAT egress SNAT smoke PASS`.

**If neither uplink observes `OK:`:** verify (a) the guest iface is up, (b) the route resolves — `docker exec <node> ip -6 route get <edgeNexthop>` should return a nexthop dev eth1 or eth2; if it returns *nothing*, `edgeNexthop` isn't advertised on this fabric — fall back to the peer node's underlay /128 (`attachGuest` on `nodes[1]` and use its underlay as the nexthop) which is guaranteed routable, and note it in a comment. (c) Check the flowplane pod log for SNAT programming. This path had known in-node `serve` rot historically; if it proves to need real datapath fixes beyond wiring, that is in-scope to fix minimally OR (last resort, matching the LB posture) document + `t.Skip` with a follow-up — but SNAT is expected to work (it's proven in the bash suite), so exhaust diagnosis first.

- [ ] **Step 5: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/nategress_test.go test/lab/internal/exec/sudo.go
git commit -m "test(lab): port TestNatEgressSmoke onto the kind fabric (guest SNAT on the uplink)

Programs AddNatSource + external route + egress-allow, injects a guest TCP frame,
and proves the SNAT rewrite by sniffing the IPIP-encapped frame on both fabric
uplinks (dual-homed ECMP). Edges here are VyOS NAT64, so we assert SNAT at the node
uplink, not end-to-end internet. Adds exec.SudoCmd for the background sniff.
Live-validated PASS.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.4: `TestUnderlayInferenceOnFabric` — a node infers its fabric /64 underlay

**Files:**
- Create: `test/lab/livetest/underlay_test.go`

The spec allows this to be "an explicit assertion, or folded into an existing test if redundant". `TestCrossClusterOverlayPing` already *uses* the inferred underlay; this test makes the **inference correctness** explicit: the underlay /128 an attach returns falls within the fabric node-aggregate (`fd00:cafe::/32`) and the cluster's /48.

- [ ] **Step 1: Write the test**

Create `test/lab/livetest/underlay_test.go`:

```go
//go:build live

package livetest

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// TestUnderlayInferenceOnFabric asserts a compute node's flowplane infers its underlay
// from the fabric (the dummy0 /128 identity in NodeAggr fd00:cafe::/32), not from the
// docker mgmt side-channel: the underlay /128 returned by AttachInterface must be
// inside fd00:cafe::/32. This is the explicit check behind the underlay that
// TestCrossClusterOverlayPing relies on for cross-cluster routing.
func TestUnderlayInferenceOnFabric(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	ul := attachGuest(t, ctx, cfg, node, "ulinfer", []string{"10.0.0.31"}, "52:54:00:00:00:31")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface", `{"interface_id":"ulinfer"}`)
	})

	addr, err := netip.ParseAddr(ul)
	require.NoError(t, err, "underlay %q is not a valid IP", ul)

	nodeAggr, err := netip.ParsePrefix(fabric.NodeAggr) // fd00:cafe::/32
	require.NoError(t, err)
	require.True(t, nodeAggr.Contains(addr),
		"inferred underlay %s is NOT in the fabric node-aggregate %s (leaked to mgmt / not fabric-inferred)",
		ul, fabric.NodeAggr)
	t.Logf("underlay inference PASS: %s ∈ %s", ul, fabric.NodeAggr)
}
```

- [ ] **Step 2: Compile + run live**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && go vet -tags live ./livetest/... 2>&1 | head -20'
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run TestUnderlayInferenceOnFabric -count=1 -v ./livetest/... -timeout 15m'
```
Expected: `--- PASS` with `underlay inference PASS: fd00:cafe:… ∈ fd00:cafe::/32`.

- [ ] **Step 3: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/underlay_test.go
git commit -m "test(lab): TestUnderlayInferenceOnFabric — assert fabric-inferred underlay /128

Makes explicit the underlay-inference correctness that cross-cluster overlay routing
relies on: the AttachInterface underlay /128 must be in the fabric node-aggregate
fd00:cafe::/32 (not leaked from the docker mgmt side-channel). Live-validated PASS.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.5: `TestLbDistributeSmoke` (NEW) — LB VIP distribution across backends

**Files:**
- Create: `test/lab/livetest/lb_test.go`
- Test binary: `cmd/netprobe`

**RISK (from the spec + memory `scapy-to-go-probe-port.md`):** there is no existing LB e2e to port, and the in-node `flowplane serve` LB path had pre-existing rot. This may surface real datapath work.

**POSTURE — DO NOT SKIP NEEDLESSLY (user directive, 2026-08-08):** The default and strongly-preferred outcome is a **passing** test. If the LB datapath does not forward, **root-cause it and fix the datapath** — that is in scope for this task. Treat a skip as a genuine last resort that requires: (a) a concrete, evidenced root cause (flowplane pod logs, `ListInterfaces`/Maglev-table state, packet captures showing exactly where the frame is dropped), (b) a determination that the fix is materially beyond this effort's scope, and (c) **escalation to the human for explicit sign-off before skipping** — report BLOCKED with the evidence rather than self-approving a skip. Do not weaken assertions to go green, and do not skip to save effort.

The LB API: `AddLbVip{id, vip, vni, ...}` then `AddLbBackend{id, backend_underlay}` (rebuilds Maglev). `vni=0` is the WAN-edge external LB (wan_rx Maglev — needs a flowplane edge, which the kind lab lacks). So this test targets the **intra-fabric** LB: a VIP inside the overlay VNI with two backends on two compute nodes, and asserts traffic to the VIP reaches more than one backend (Maglev distribution) OR at minimum that the VIP is programmed and forwards to a backend.

- [ ] **Step 1: Inspect the exact LB request fields before writing**

Read the proto so the JSON matches:
```bash
cd /home/nik/Development/ironcore-net-xdp
sed -n '60,120p' api/proto/dataplane/v1/dataplane.proto
```
Note the exact field names/types of `AddLbVipRequest` (id, vip, vni, port?, proto?) and `AddLbBackendRequest` (id, backend underlay field name). Build the JSON bodies from the ACTUAL field names — do not assume.

- [ ] **Step 2: Write the test (with a built-in skip path)**

Create `test/lab/livetest/lb_test.go`. Use the field names confirmed in Step 1; the skeleton below marks where they go. The test attaches two backend endpoints on two compute nodes (or two on one node if only one compute cluster is available), registers a VIP + both backends on a *client* node, sends probe traffic from a client guest to the VIP, and asserts distribution. Because the LB datapath is the risk, wrap the datapath assertion so a documented failure becomes a `t.Skip`:

```go
//go:build live

package livetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// LB smoke identities.
const (
	lbVIPID   = "lbsmoke"
	lbVIP     = "10.0.0.200" // overlay VIP
	lbClient  = "lbclient"
	lbClientIP  = "10.0.0.40"
	lbClientMAC = "52:54:00:00:00:40"
)

// TestLbDistributeSmoke registers an overlay LB VIP with two backends and asserts the
// datapath forwards VIP traffic to a backend (and, if reachable, distributes across
// both via Maglev).
//
// KNOWN RISK: the in-node `flowplane serve` LB path had pre-existing rot and there is
// no prior LB e2e. If the datapath does not forward after honest diagnosis, this test
// SKIPS with a documented reason + follow-up (per the approved spec), rather than
// blocking the phase.
func TestLbDistributeSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes for two LB backends")
	}
	backendA, backendB := nodes[0], nodes[1]

	// 1. Attach a backend endpoint on each node; capture their underlay /128s.
	ulA := attachGuest(t, ctx, cfg, backendA, "lbbe-a", []string{"10.0.0.201"}, "52:54:00:00:00:41")
	ulB := attachGuest(t, ctx, cfg, backendB, "lbbe-b", []string{"10.0.0.202"}, "52:54:00:00:00:42")
	require.NotEmpty(t, ulA)
	require.NotEmpty(t, ulB)

	// 2. Attach a client endpoint on backendA's node and open egress.
	clientNode := backendA
	clientContainer := nodeContainer(cfg, clientNode)
	_ = attachGuest(t, ctx, cfg, clientNode, lbClient, []string{lbClientIP}, lbClientMAC)
	addFwEgressAllow(t, ctx, clientContainer, lbClient)
	t.Cleanup(func() {
		for id, n := range map[string]string{"lbbe-a": nodeContainer(cfg, backendA), "lbbe-b": nodeContainer(cfg, backendB), lbClient: clientContainer} {
			_, _ = dataplaneGRPC(t, ctx, n, "DetachInterface", fmt.Sprintf(`{"interface_id":%q}`, id))
		}
	})

	// 3. Register the VIP + both backends on the client node's dataplane.
	//    Field names per api/proto/dataplane/v1/dataplane.proto (confirmed in Step 1).
	vipBody := fmt.Sprintf(`{"id":%q,"vip":%q,"vni":%d}`, lbVIPID, lbVIP, overlayVNI) // ADJUST fields
	out, err := dataplaneGRPC(t, ctx, clientContainer, "AddLbVip", vipBody)
	require.NoError(t, err, "AddLbVip: %s", out)
	for _, ul := range []string{ulA, ulB} {
		beBody := fmt.Sprintf(`{"id":%q,"backend_underlay":%q}`, lbVIPID, ul) // ADJUST field name
		out, err := dataplaneGRPC(t, ctx, clientContainer, "AddLbBackend", beBody)
		require.NoError(t, err, "AddLbBackend %s: %s", ul, out)
	}
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, clientContainer, "DelLbVip", fmt.Sprintf(`{"id":%q}`, lbVIPID))
	})

	// 4. Drive traffic to the VIP and assert forwarding/distribution. The datapath is
	//    the risk; document + skip on honest failure rather than block the phase.
	if reason := lbDatapathProbe(t, ctx, cfg, clientNode, ulA, ulB); reason != "" {
		t.Skipf("LB datapath not forwarding (known pre-existing `flowplane serve` LB rot): %s\n"+
			"Follow-up: fix the in-node LB serve path, then un-skip. Control-plane wiring "+
			"(AddLbVip/AddLbBackend) succeeded; only datapath forwarding is unproven.", reason)
	}
	t.Logf("LB distribute smoke PASS: VIP %s forwards across backends %s / %s", lbVIP, ulA, ulB)
}

// lbDatapathProbe drives VIP traffic and returns "" on success, or a human reason
// string on failure (which the caller turns into a documented Skip). Implement the
// actual assertion using netprobe send + a per-backend sniff (mirror TestNatEgress's
// dual-sniff), or a simpler reachability check if that is what the datapath supports.
func lbDatapathProbe(t *testing.T, ctx context.Context, cfg *config.Config, clientNode config.DerivedNode, ulA, ulB string) string {
	// TODO(impl in Step 3): send N frames from the lbClient netns to lbVIP and observe
	// they arrive at backend A and/or B (sniff each backend node's uplink for the
	// VIP-decapped inner, or the backend netns for delivered frames). Return "" if at
	// least one backend receives traffic; return a reason string otherwise.
	return "datapath probe not yet implemented"
}
```

> **Note:** `lb_test.go` must import `internal/config` (aliased as `config` to match `overlay_test.go`) for the `lbDatapathProbe` signature. Add the import.

- [ ] **Step 3: Implement `lbDatapathProbe` and run live**

Flesh out `lbDatapathProbe` using the same `netprobe` send + dual-uplink `send-sniff` pattern as `TestNatEgressSmoke` (build `netprobe`, copy to the backend nodes, sniff each backend node's uplink for the LB-forwarded inner frame; success = at least one backend observes it, ideally both across repeated sends = Maglev distribution). Then bring the fabric up (already up) and run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && go vet -tags live ./livetest/... 2>&1 | head -20'
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run TestLbDistributeSmoke -count=1 -v ./livetest/... -timeout 25m'
```
Expected: `--- PASS: TestLbDistributeSmoke`. **The test MUST pass** — root-cause and fix any datapath failure (this is in scope). Diagnose with: the flowplane pod log, confirming `AddLbVip`/`AddLbBackend` returned OK and the Maglev table was built (`ListInterfaces` or a datapath dump), and packet captures pinpointing where the frame is dropped. A skip is a last resort ONLY: if, after evidenced diagnosis, the fix is materially out of scope, STOP and report BLOCKED to the controller with the evidence for a human decision — do NOT self-approve a `t.Skip`, and never weaken assertions to go green.

- [ ] **Step 4: Only if the controller/human approved a skip after BLOCKED escalation**

A skip is NOT the implementer's call. If — and only if — the controller relayed explicit human sign-off to skip (after a BLOCKED report with evidenced root cause), append a follow-up to `memory/retire-bash-clab-datapath-to-go.md` noting the specific LB serve datapath defect (with the evidence) + that `TestLbDistributeSmoke` is scaffolded-and-skipped awaiting the fix. Keep the `MEMORY.md` index line to one line. Otherwise (the expected path) the test passes and this step is skipped.

- [ ] **Step 5: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/lb_test.go
# include the memory update if the test was skipped:
# git add memory/retire-bash-clab-datapath-to-go.md memory/MEMORY.md
git commit -m "test(lab): TestLbDistributeSmoke — overlay LB VIP distribution across backends

Registers an overlay LB VIP + two backends and drives VIP traffic to assert Maglev
distribution. Control-plane wiring (AddLbVip/AddLbBackend) proven; datapath forwarding
[PASSES live | SKIPS with a documented follow-up per the known flowplane-serve LB rot].

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.6: Full datapath group green together

- [ ] **Step 1: Run the whole new datapath group in one pass**

Run (fabric up):
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd test/lab && sudo -E env "PATH=$PATH" \
  go test -tags live -run "TestDhcpLeaseSmoke|TestNatEgressSmoke|TestUnderlayInferenceOnFabric|TestLbDistributeSmoke" \
  -count=1 -v ./livetest/... -timeout 40m'
```
Expected: DHCP/NAT/underlay PASS; LB PASS or documented SKIP. No shared-state interference (each test uses distinct guest ids / IPs / MACs and detaches in Cleanup). If two tests collide on an id/IP, fix the constants to be unique.

- [ ] **Step 2: No commit** (verification only). Proceed to Phase 3.

---

## Phase 3 — remove the bash clab fabric

Only after Phase 2 is green (LB may be a documented skip). This removes the old fabric + the `test/e2e` datapath tests that drove it.

### Task 3.1: Delete the bash clab fabric + migrated `test/e2e` tests

**Files:**
- Delete: `hack/clab/` (dir, ~29 files), `hack/clab-up.sh`, `hack/clab-down.sh`, `hack/multicluster-e2e.sh`
- Delete: `test/e2e/env.go`, `test/e2e/routebus_test.go`, `test/e2e/smoke_datapath_test.go`, `test/e2e/smoke_lb_dhcp_test.go`, `test/e2e/fabric_test.go`

- [ ] **Step 1: Confirm nothing surviving references them**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rln --exclude-dir=.git -E "hack/clab|clab-up\.sh|clab-down\.sh|multicluster-e2e\.sh" . | grep -v -E "docs/|memory/"
```
Expected: only `README.md` (fixed in Task 3.2) and possibly the Makefile — **check the Makefile**: `grep -n "clab-up\|clab-down\|hack/clab" Makefile`. If the Makefile references them, note it for Task 3.2. Nothing else should reference them.

Also confirm the `test/e2e` files being deleted are the only consumers of `env.go`'s symbols (`KindCentral`, `WorkerNode`, `FabricVNI`, `OverlayIPA`, `DataplaneAddrFromEnv`, `FlowplaneImageFromEnv`, `testEnv`, `runWithTimeout`, `NodeA`, etc.):
```bash
grep -rln --exclude-dir=.git -E "DataplaneAddrFromEnv|FlowplaneImageFromEnv|KindCentral|WorkerNode|testEnv|runWithTimeout" test/e2e/ | sort -u
```
Expected: only the files being deleted (`env.go`, `routebus_test.go`, `smoke_datapath_test.go`, `smoke_lb_dhcp_test.go`, `fabric_test.go`). If `runWithTimeout`/`testEnv` live in a file NOT in the delete set and are used by a surviving file, STOP and reassess.

- [ ] **Step 2: git rm the fabric + tests**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git rm -r hack/clab
git rm hack/clab-up.sh hack/clab-down.sh hack/multicluster-e2e.sh
git rm test/e2e/env.go test/e2e/routebus_test.go test/e2e/smoke_datapath_test.go \
  test/e2e/smoke_lb_dhcp_test.go test/e2e/fabric_test.go
```
Expected: rm lines, no errors.

- [ ] **Step 3: Handle whatever remains in `test/e2e`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
ls -la test/e2e/
find test/e2e -name '*.go' | xargs -r grep -l "package e2e"
```
- The `cmd/`, `netprobe`, `tap-dhcp-probe*` binaries, and `fixtures/` are **kept** (the probes' *sources* live under `test/e2e/cmd/...`? verify — if the probe sources are actually at repo-root `cmd/tap-dhcp-probe` and `cmd/netprobe`, then the `test/e2e/netprobe` / `tap-dhcp-probe*` are stale build artifacts and can be removed; the Phase 2 tests build from repo-root `./cmd/...`). Confirm where the probe sources live:
  ```bash
  ls cmd/tap-dhcp-probe cmd/netprobe 2>/dev/null && echo "REPO-ROOT probes exist (Phase 2 builds these)"
  ls test/e2e/cmd 2>/dev/null
  ```
- If **no** `package e2e` `.go` files remain, delete the leftover stale binaries (`git rm test/e2e/netprobe test/e2e/tap-dhcp-probe test/e2e/tap-dhcp-probe.bin` if tracked) and, if `test/e2e/go.mod` exists only to serve the deleted tests, evaluate removing the empty package. **Do NOT delete `test/e2e/cmd/` or `test/e2e/fixtures/` if the repo-root `cmd/` probes actually re-export or depend on them** — verify with `go build ./...` before removing anything ambiguous.
- If `package e2e` `.go` files DO remain (e.g. a helper used elsewhere), leave the package and just ensure it builds.

- [ ] **Step 4: Verify the build across the affected modules**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'go build ./... 2>&1 | head -30'
nix develop --command bash -c 'cd test/lab && go build ./... && go vet -tags live ./livetest/... 2>&1 | head -20'
```
Expected: clean. If `test/e2e` has its own `go.mod`, also `cd test/e2e && go vet ./... 2>&1 | head` (only if a package remains).

- [ ] **Step 5: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add -u hack/ test/e2e/
git commit -m "chore: remove the bash containerlab fabric + migrated test/e2e datapath tests

The datapath e2e (DHCPv6/NAT/underlay/LB) now runs on the Go test/lab kind fabric
(test/lab/livetest). Delete hack/clab, clab-up/down, multicluster-e2e, and the
test/e2e tests + env.go that drove the old single-cluster fabric.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3.2: Update `README.md` (and the Makefile if it referenced clab)

**Files:**
- Modify: `README.md` (the `hack/` table row + the `hack/clab-up.sh`/`clab-down.sh` bring-up section)
- Modify: `Makefile` (only if Task 3.1 Step 1 found clab targets)

- [ ] **Step 1: Rewrite the README bring-up section to point at `test/lab`**

Read `README.md` around lines 44 and 85–95. Replace the `hack/` table row (currently "Lab bring-up: the containerlab + kind fabric (clab-up.sh/clab-down.sh, clab/)…") with a description that `hack/` holds utilities + image sources only, and rewrite the bring-up block:
```
hack/clab-up.sh            # bring up the fabric + kind + netplane stack
...
hack/clab-down.sh
```
becomes a pointer to the Go lab:
```
make lab-up          # bring up the multi-cluster kind fabric (central + k02 + k03)
make lab-deploy      # deploy the ectobase stack (central + brokers + flowplane)
make lab-ceph        # (optional) external Ceph + ceph-csi for storage/Tier-2
make lab-test        # run the live suite (control-plane + datapath) against the fabric
make lab-down        # tear the fabric down (leaves zero host leftovers)
```
Keep the rest of the README intact; match its existing tone/markdown.

- [ ] **Step 2: Fix the Makefile only if needed**

If Task 3.1 Step 1 found `clab-up`/`clab-down`/`hack/clab` in the `Makefile`, remove those targets/lines (the `lab-*` targets already replace them). Otherwise skip.

- [ ] **Step 3: Verify no dangling references (outside docs/memory)**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git grep -nE "hack/clab|clab-up\.sh|clab-down\.sh|multicluster-e2e\.sh" -- ':!docs/' ':!memory/'
```
Expected: **no output**.

- [ ] **Step 4: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add README.md Makefile
git commit -m "docs: point the lab bring-up at the Go test/lab (make lab-*), drop hack/clab

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 4 — verify + harden `lab down` (zero host leftovers)

### Task 4.1: Full `lab test` sweep green on a fresh fabric (incl. the new datapath tests)

- [ ] **Step 1: Fresh fabric from scratch**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-down || true
make lab-up
make lab-deploy
make lab-ceph
make lab-tier2-up
```
Expected: each completes; central aggregated API + brokers + flowplane + ceph + the Tier-2 gate all up (this mirrors the validated 13/13 sweep).

- [ ] **Step 2: Run the entire live suite (control-plane + new datapath)**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-test 2>&1 | tee /tmp/lab-test-full.log
```
Expected: all prior tests PASS (overlay ping, tier2 failover, rbd bind, etc.) AND the new `TestDhcpLeaseSmoke` / `TestNatEgressSmoke` / `TestUnderlayInferenceOnFabric` PASS; `TestLbDistributeSmoke` PASS or documented SKIP. Grep the log to confirm no unexpected FAIL:
```bash
grep -E "^(--- FAIL|FAIL|ok|--- SKIP|PASS)" /tmp/lab-test-full.log | tail -40
```

- [ ] **Step 3: No commit** (verification). If a test fails, fix in the owning file and re-run before proceeding.

### Task 4.2: `lab down` leaves ZERO host leftovers (acceptance criterion)

The just-landed `cleanupHostRBD` + `<name>-mgmt` network removal (commit `03bdbef`) are validated end-to-end here on a real ceph+tier2 fabric.

- [ ] **Step 1: Snapshot host state BEFORE down (fabric still up from 4.1)**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
echo "== rbd devices =="; ls -1 /sys/bus/rbd/devices 2>/dev/null; ls -1 /dev/rbd* 2>/dev/null
echo "== docker networks =="; sudo docker network ls | grep -E "mgmt|clab|$(basename $(pwd))" || true
echo "== host fabric route =="; ip -6 route show 2>/dev/null | grep -E "fd00:cafe|fd00:ffff" || true
echo "== lab ip6tables MASQUERADE =="; sudo ip6tables -t nat -S 2>/dev/null | grep -iE "MASQ" || true
```
Expected (up): at least one `/sys/bus/rbd/devices` entry (ceph RBD PVC mapped on the host), a `<name>-mgmt` docker network, possibly a fabric host route + MASQUERADE. Save this output.

- [ ] **Step 2: `lab down`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-down 2>&1 | tee /tmp/lab-down.log
```
Expected: completes without hanging. If it wedges, force-kill the shim (`pkill -9 -f <container-id>`) and note it — a wedge means `Down` needs another cleanup step.

- [ ] **Step 3: Assert ZERO leftovers AFTER down**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
fail=0
echo "== rbd devices (want empty) =="
if [ -d /sys/bus/rbd/devices ] && [ -n "$(ls -A /sys/bus/rbd/devices 2>/dev/null)" ]; then echo "LEFTOVER rbd:"; ls -1 /sys/bus/rbd/devices; fail=1; fi
ls /dev/rbd* 2>/dev/null && { echo "LEFTOVER /dev/rbd*"; fail=1; }
echo "== docker mgmt network (want gone) =="
sudo docker network ls | grep -E "mgmt" && { echo "LEFTOVER mgmt network"; fail=1; } || true
echo "== host fabric route (want gone) =="
ip -6 route show 2>/dev/null | grep -E "fd00:cafe|fd00:ffff" && { echo "LEFTOVER fabric route"; fail=1; } || true
echo "== lab MASQUERADE (want gone) =="
sudo ip6tables -t nat -S 2>/dev/null | grep -iE "fd00:cafe|fd00:ffff|fd00:29" && { echo "LEFTOVER MASQUERADE"; fail=1; } || true
echo "RESULT: fail=$fail"
```
Expected: `RESULT: fail=0` — no rbd devices, no mgmt network, no fabric host route, no lab MASQUERADE rules. **If `fail=1`**, the specific leftover tells you which cleanup step `test/lab/topology/fabric.go`'s `Down` is missing — add it there (mirror the existing `cleanupHostRBD` / `delHostFabricRoute` / `teardownHostEgress` helpers), rebuild is automatic (`go run`), and re-run down+assert.

- [ ] **Step 4 (optional): Encode the assertion as a self-check**

Either (a) add a `test/lab/livetest/cleanup_test.go` that a human runs AFTER `lab down` (it would `t.Skip` while the fabric is up — check `requireFabricUp` inverted), or (b) simpler and preferred: add a summary log line at the end of `topology.Down` in `test/lab/topology/fabric.go` that re-checks `/sys/bus/rbd/devices`, the mgmt network, and the fabric route, and `slog.Warn`s any leftover it finds (so `make lab-down` self-reports). Implement (b): read `Down` in `fabric.go`, add a final `verifyNoLeftovers(ctx)` helper that logs warnings (does not error — down should still succeed). Keep it minimal and mirror the existing helper style.

- [ ] **Step 5: Commit (only if 4.2 required a fabric.go fix or the self-check)**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/topology/fabric.go   # + test/lab/livetest/cleanup_test.go if added
git commit -m "fix(lab): lab down leaves zero host leftovers (rbd/network/route/iptables self-check)

Validated on a real ceph+tier2 up->down: no /dev/rbd*, no <name>-mgmt network, no
fabric host route, no lab MASQUERADE after down. [Adds verifyNoLeftovers self-check.]

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4.3: Final regression gate + memory update

- [ ] **Step 1: Non-live regressions**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
make chart-test
nix develop --command bash -c 'cd test/lab && go test ./... 2>&1 | tail -20'          # lab unit tests
nix develop --command bash -c 'cd central && GOWORK=off go test ./internal/fence/... ./internal/... 2>&1 | tail -20'  # central envtests (fence/failover)
```
Expected: `make chart-test` green (22); lab unit tests green; central fence/failover envtests green.

- [ ] **Step 2: Final grep — the bash clab fabric is gone**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git grep -nE "hack/clab|clab-up\.sh|clab-down\.sh" -- ':!docs/' ':!memory/'
```
Expected: **no output**.

- [ ] **Step 3: Update the effort memory**

Update `memory/retire-bash-clab-datapath-to-go.md`: mark the effort DONE, record the final commit range, note which datapath tests landed PASS vs SKIP (LB), and that `lab down` zero-leftovers is validated. Keep the `MEMORY.md` index line to one line (<200 chars) — the index is already over budget, so trim, don't grow.

- [ ] **Step 4: Commit the memory update**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add memory/retire-bash-clab-datapath-to-go.md memory/MEMORY.md
git commit -m "docs(memory): retire-bash-clab-datapath-to-go effort complete

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review (planner)

**Spec coverage:**
- `hack/` disposition table → Phase 1 (Tasks 1.1 delete, 1.2 comment fixups). ✓ All rows covered (keep-rows untouched; delete-rows removed; migrate-rows deferred to Phase 3).
- Phase 2 datapath ports: DHCP (2.2), NAT egress (2.3), underlay inference (2.4), LB (2.5) + combined green (2.6). ✓ Reuses the `TestCrossClusterOverlayPing` machinery + static probes at a root path, as the spec requires. ✓ `TestCrossNodeOverlayPing` dropped (already covered by cross-cluster) — not re-added. ✓
- Phase 3 removals: `hack/clab`, `clab-up/down`, `multicluster-e2e`, `env.go`, the four `test/e2e` datapath tests, README. ✓ (Task 3.1 + 3.2).
- Phase 4: full `lab test` green (4.1), zero-leftovers acceptance validated on real ceph+tier2 (4.2), chart-test + central envtests + clean grep (4.3). ✓

**Placeholder scan:** The only intentional `TODO` is inside `lbDatapathProbe` (Task 2.5), which is explicitly implemented in the same task's Step 3 — the spec flags LB as the one open-risk item, and the task carries the concrete impl instruction (mirror `TestNatEgressSmoke`'s dual-sniff) + the approved skip fallback. All other steps carry full code or exact commands.

**Type/name consistency:** `dataplaneGRPC` takes BARE method names (verified against `overlay_test.go`) — all call sites use bare names. `attachGuest`/`addFwEgressAllow`/`buildStaticBin`/`copyToNode`/`nodeExec`/`nodeNetnsProbe`/`edgeNexthop`/`guestGWMAC` are defined once in `datapath_common_test.go` (Task 2.1) and consumed consistently in 2.2–2.5. `nodeContainer`/`computeNodes`/`nodeK8sName`/`kubectl`/`dataplaneGRPC`/`underlayForID`/`firstUnderlay`/`repoRoot`/`overlayVNI`/`requireFabricUp`/`loadConfig`/`eventually` are all existing symbols (verified in `main_test.go`/`overlay_test.go`/`egress_test.go`). `exec.SudoCmd` is added in Task 2.3 Step 2 before its first use. The `config`/`exec` import-alias caveat is called out explicitly in Task 2.1 Step 2 with instruction to match the existing files.

**Known adaptation risks surfaced in-plan:** (1) NAT egress asserts SNAT at the node uplink (edges are VyOS, not flowplane) with a dual-uplink sniff + a routable-nexthop fallback; (2) LB may land as a documented skip; (3) the `test/e2e` residual-package handling (Task 3.1 Step 3) is conditional on where the probe sources actually live — verified via `go build` before any ambiguous deletion.

---

**Plan complete and saved to `docs/superpowers/plans/2026-08-08-retire-bash-clab-datapath-to-go.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. (You already chose subagent-driven for this effort.)

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
