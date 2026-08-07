//go:build live

package livetest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// tier2VMNS is the kube namespace the vm-materializer creates the VMI + RBD PVC in
// on the compute clusters. It mirrors the fixture namespace (default); flip to
// "ectobase-system" if the materializer places VMIs in the system namespace on the
// live fabric.
const tier2VMNS = "default"

// tier2VMName / tier2Volume match the names in testdata/tier2-vm.yaml.
const (
	tier2VMName = "tier2-vm"
	tier2Volume = "tier2-disk"
	// tier2VMIName is the KubeVirt VirtualMachine/VMI name the pipeline produces: the
	// compiler namespace-prefixes the CompiledVM (default-<vm>), and the vm-materializer
	// names the KubeVirt VM after it. So the net.ectobase.dev VM `tier2-vm` in namespace
	// `default` materializes as KubeVirt VMI `default-tier2-vm`.
	tier2VMIName = "default-" + tier2VMName
)

// fenceName mirrors central/internal/fence/storage.go fenceName(): "ectobase-" +
// prefix with ':' -> '-', '/' -> '--', '.' -> '-'. Used to look up the csi-addons
// NetworkFence CR for a node /64 by name.
func fenceName(prefix string) string {
	r := strings.NewReplacer(":", "-", "/", "--", ".", "-")
	return "ectobase-" + r.Replace(prefix)
}

// readFixture reads a file under the package's testdata/ dir. `go test` runs from
// the package dir, so a relative testdata path resolves.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err, "read fixture %s", name)
	return string(b)
}

// TestTier2Failover is the Tier-2 fenced cross-cluster VM-reschedule gate. It boots a
// stateful RBD-backed VirtualMachine on pool k02, hard-kills the k02 node container,
// and asserts central FENCES k02 (Ceph NetworkFence result==Succeeded + OSD blocklist)
// then RE-BINDS the VM to k03, where the VMI + the same RBD reattach. Recovery
// restarts k02 and asserts the fence releases. Best-effort on VMI Running (guest boot
// under software emulation + CDI import over the fabric is slow); the fence + reschedule
// core is the gate.
func TestTier2Failover(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	// --- Phase 1: skip guards -------------------------------------------------------
	if !cfg.Fabric.Ceph.Enabled {
		t.Skip("ceph disabled in lab config (fabric.ceph.enabled=false)")
	}
	compute := computeClusters(cfg)
	if len(compute) < 2 {
		t.Skip("need >=2 compute clusters (k02, k03) for cross-cluster failover")
	}
	// ceph-csi StorageClass must exist on the first compute cluster (lab ceph ran).
	if _, err := kubectl(ctx, cfg, compute[0].Name, "get", "storageclass", "ceph-rbd"); err != nil {
		t.Skipf("ceph not deployed (run `lab ceph`): %v", err)
	}
	// KubeVirt must be installed on k02 (lab tier2 up ran) — probe its CRD.
	if _, err := kubectl(ctx, cfg, "k02", "get", "crd", "virtualmachines.kubevirt.io"); err != nil {
		t.Skipf("KubeVirt not installed on k02 (run `lab tier2 up`): %v", err)
	}

	// --- Phase 2: apply fixture + Ready VPC -----------------------------------------
	require.NoError(t, applyCentral(ctx, cfg, readFixture(t, "tier2-vm.yaml")), "apply tier2 fixture to central")
	patchVNIReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "blue")

	// Best-effort teardown of the fixture regardless of outcome (delete by name; the
	// kubectl helper has no stdin, so `delete -f -` is not usable here).
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "central", "delete", "virtualmachines.net.ectobase.dev",
			tier2VMName, "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "central", "delete", "volumes.net.ectobase.dev",
			tier2Volume, "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "central", "delete", "networkinterfaces.net.ectobase.dev",
			"tier2-nic", "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "central", "delete", "vpcs.net.ectobase.dev",
			"blue", "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
	})

	// --- Phase 3: VM bound to k02 ---------------------------------------------------
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		return expectVMCluster(ctx, cfg, "k02")
	})

	// --- Phase 4: VMI + RBD Bound on k02 --------------------------------------------
	eventually(t, 5*time.Minute, 10*time.Second, func() error {
		return expectVMIAndRBD(ctx, cfg, "k02")
	})
	if phase, err := kubectl(ctx, cfg, "k02", "-n", tier2VMNS,
		"get", "vmi", tier2VMIName, "-o", "jsonpath={.status.phase}"); err == nil {
		t.Logf("k02 VMI %s phase=%q (not hard-required Running)", tier2VMIName, strings.TrimSpace(phase))
	}

	// --- Phase 5: k02 fence coordinate ----------------------------------------------
	k02Prefix, err := poolField(ctx, cfg, "k02", "{.status.nodePrefixes[0]}")
	require.NoError(t, err, "read k02 nodePrefixes[0]")
	require.NotEmpty(t, k02Prefix, "k02 fence coordinate (nodePrefixes[0]) empty")
	fenceCR := fenceName(k02Prefix)
	// The blocklist entries are client addresses inside the /64; match its leading
	// hextets (strip a trailing ::/64 / :: / /64).
	k02Hextets := strings.NewReplacer("/64", "", "::", "").Replace(k02Prefix)
	k02Hextets = strings.TrimSuffix(k02Hextets, ":")
	cephCtr := "clab-" + cfg.Name + "-ceph"
	t.Logf("k02 prefix=%s fenceCR=%s hextets=%s ceph=%s", k02Prefix, fenceCR, k02Hextets, cephCtr)

	// --- Phase 6: hard-kill k02 -----------------------------------------------------
	k02Node, ok := clusterNode(cfg, "k02")
	require.True(t, ok, "no derived node for cluster k02")
	k02Ctr := nodeContainer(cfg, k02Node)

	// Register recovery FIRST so a mid-test failure still restarts k02.
	t.Cleanup(func() {
		_, _ = exec.SudoOutput(context.Background(), "docker", "start", k02Ctr)
	})

	require.NoError(t, hardKillNode(ctx, k02Ctr), "kill k02 node container %s", k02Ctr)
	t.Logf("killed k02 node container %s", k02Ctr)

	// --- Phase 7: fence asserted (central) ------------------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		res, err := kubectl(ctx, cfg, "central",
			"get", "networkfence", fenceCR, "-o", "jsonpath={.status.result}")
		if err != nil {
			return fmt.Errorf("get NetworkFence %s: %w", fenceCR, err)
		}
		if strings.TrimSpace(res) != "Succeeded" {
			return fmt.Errorf("NetworkFence %s result=%q, want Succeeded", fenceCR, strings.TrimSpace(res))
		}
		return nil
	})

	// --- Phase 8: ceph blocklist contains a k02 client ------------------------------
	eventually(t, 5*time.Minute, 10*time.Second, func() error {
		bl, err := exec.SudoOutput(ctx, "docker", "exec", cephCtr, "ceph", "osd", "blocklist", "ls")
		if err != nil {
			return fmt.Errorf("ceph osd blocklist ls on %s: %w\n%s", cephCtr, err, bl)
		}
		if !strings.Contains(strings.ToLower(string(bl)), strings.ToLower(k02Hextets)) {
			return fmt.Errorf("ceph blocklist missing a k02 client (%s):\n%s", k02Hextets, bl)
		}
		return nil
	})

	// --- Phase 9: VM rebinds to k03 -------------------------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		return expectVMCluster(ctx, cfg, "k03")
	})

	// --- Phase 10: VMI + RBD Bound on k03 -------------------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		return expectVMIAndRBD(ctx, cfg, "k03")
	})
	if phase, err := kubectl(ctx, cfg, "k03", "-n", tier2VMNS,
		"get", "vmi", tier2VMIName, "-o", "jsonpath={.status.phase}"); err == nil {
		t.Logf("k03 VMI %s phase=%q (not hard-required Running)", tier2VMIName, strings.TrimSpace(phase))
	}

	// --- Phase 11: recovery — restart k02, assert fence released --------------------
	out, err = exec.SudoOutput(ctx, "docker", "start", k02Ctr)
	require.NoError(t, err, "docker start %s: %s", k02Ctr, out)
	t.Logf("restarted k02 node container %s", k02Ctr)

	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		// The blocklist no longer contains the k02 client.
		bl, err := exec.SudoOutput(ctx, "docker", "exec", cephCtr, "ceph", "osd", "blocklist", "ls")
		if err != nil {
			return fmt.Errorf("ceph osd blocklist ls on %s: %w\n%s", cephCtr, err, bl)
		}
		if strings.Contains(strings.ToLower(string(bl)), strings.ToLower(k02Hextets)) {
			return fmt.Errorf("ceph blocklist still contains k02 client (%s):\n%s", k02Hextets, bl)
		}
		// The NetworkFence CR is deleted (get errors).
		if _, err := kubectl(ctx, cfg, "central", "get", "networkfence", fenceCR); err == nil {
			return fmt.Errorf("NetworkFence %s still present (want deleted)", fenceCR)
		}
		return nil
	})
}

// hardKillNode simulates a node failure by stopping its container. It tries
// `docker kill` first; if that fails because the container's init has zombied
// (these clab Talos nodes run no init to reap/forward signals — the daemon then
// reports "PID is zombie and can not be killed"), it force-kills the container's
// containerd-shim by container ID, which tears the container down all the same.
// Recovery is a `docker start` in the caller's Cleanup.
func hardKillNode(ctx context.Context, container string) error {
	if _, err := exec.SudoOutput(ctx, "docker", "kill", container); err == nil {
		return nil
	}
	cid, err := exec.OutputStr(ctx, "docker", "inspect", "-f", "{{.Id}}", container)
	if err != nil {
		return fmt.Errorf("inspect %s for shim kill: %w", container, err)
	}
	// Force-kill the shim (and anything else) for this container ID.
	_, err = exec.SudoOutput(ctx, "pkill", "-9", "-f", strings.TrimSpace(cid))
	return err
}

// expectVMCluster asserts the VirtualMachine spec.clusterName equals want.
func expectVMCluster(ctx context.Context, cfg *config.Config, want string) error {
	cn, err := kubectl(ctx, cfg, "central",
		"get", "virtualmachines.net.ectobase.dev", tier2VMName, "-o", "jsonpath={.spec.clusterName}")
	if err != nil {
		return fmt.Errorf("get VirtualMachine %s clusterName: %w", tier2VMName, err)
	}
	if strings.TrimSpace(cn) != want {
		return fmt.Errorf("VirtualMachine %s clusterName=%q, want %q", tier2VMName, strings.TrimSpace(cn), want)
	}
	return nil
}

// expectVMIAndRBD asserts the KubeVirt VMI exists on the given cluster AND at least
// one PVC bound to the ceph-rbd StorageClass is Bound in tier2VMNS (the RBD reattach
// signal). It does NOT require the VMI phase to be Running.
func expectVMIAndRBD(ctx context.Context, cfg *config.Config, cluster string) error {
	if _, err := kubectl(ctx, cfg, cluster, "-n", tier2VMNS, "get", "vmi", tier2VMIName); err != nil {
		return fmt.Errorf("VMI %s not present on %s/%s: %w", tier2VMIName, cluster, tier2VMNS, err)
	}
	// Any ceph-rbd PVC Bound in the ns (the DataVolume/PVC name is derived by CDI).
	out, err := kubectl(ctx, cfg, cluster, "-n", tier2VMNS, "get", "pvc",
		"-o", "jsonpath={range .items[*]}{.spec.storageClassName}{\" \"}{.status.phase}{\"\\n\"}{end}")
	if err != nil {
		return fmt.Errorf("list PVCs on %s/%s: %w", cluster, tier2VMNS, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "ceph-rbd" && f[1] == "Bound" {
			return nil
		}
	}
	return fmt.Errorf("no Bound ceph-rbd PVC on %s/%s:\n%s", cluster, tier2VMNS, out)
}

// clusterNode returns the first derived node of a named cluster.
func clusterNode(cfg *config.Config, cluster string) (config.DerivedNode, bool) {
	for _, n := range allNodes(cfg) {
		if n.Cluster == cluster {
			return n, true
		}
	}
	return config.DerivedNode{}, false
}
