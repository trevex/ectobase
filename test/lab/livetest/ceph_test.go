//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// TestRBDPVCBinds proves an RBD-backed PVC binds on every compute cluster (k02,
// k03) through the ceph-csi provisioner. The `ceph-rbd` StorageClass provisions
// from the fabric ceph node's `replicapool`; the provisioner runs on the hub too
// (as the Tier-2 storage-fence executor). Skipped unless the fabric was brought
// up with Ceph enabled AND `lab ceph` has deployed the CSI stack.
func TestRBDPVCBinds(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	if !cfg.Fabric.Ceph.Enabled {
		t.Skip("ceph disabled in lab config (fabric.ceph.enabled=false)")
	}

	compute := computeClusters(cfg)
	if len(compute) == 0 {
		t.Skip("no compute clusters")
	}

	// The ceph-csi StorageClass is a prerequisite: if `lab ceph` never ran, the
	// class is absent on the compute clusters, so there is nothing to prove.
	if _, err := kubectl(ctx, cfg, compute[0].Name, "get", "storageclass", "ceph-rbd"); err != nil {
		t.Skipf("ceph not deployed (run `lab ceph`): %v", err)
	}

	// The hub ceph-csi RBD provisioner must be Running (it drives PVC binds and
	// is also the fence executor).
	require.NoError(t, requireProvisionerRunning(ctx, cfg), "hub ceph-csi provisioner not Running")

	for _, cl := range compute {
		cl := cl
		t.Run(cl.Name, func(t *testing.T) {
			// Best-effort cleanup regardless of outcome.
			t.Cleanup(func() {
				_, _ = kubectl(ctx, cfg, cl.Name,
					"delete", "pvc", "rbd-smoke", "--ignore-not-found")
			})

			require.NoError(t, applyCluster(ctx, cfg, cl.Name, rbdPVCFixture()),
				"apply rbd-smoke PVC to %s", cl.Name)

			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				phase, err := kubectl(ctx, cfg, cl.Name,
					"get", "pvc", "rbd-smoke", "-o", "jsonpath={.status.phase}")
				if err != nil {
					return fmt.Errorf("get pvc rbd-smoke on %s: %w", cl.Name, err)
				}
				if strings.TrimSpace(phase) != "Bound" {
					return fmt.Errorf("pvc rbd-smoke on %s phase=%q, want Bound", cl.Name, strings.TrimSpace(phase))
				}
				return nil
			})
		})
	}
}

// requireProvisionerRunning asserts hub's ceph-csi RBD provisioner pod is
// Running. It first tries the Helm chart's provisioner labels; if that selector
// yields nothing (chart label drift), it falls back to matching any pod named
// `ceph-csi-rbd-provisioner*` in the ceph-csi namespace.
func requireProvisionerRunning(ctx context.Context, cfg *config.Config) error {
	phases, err := kubectl(ctx, cfg, "hub", "-n", "ceph-csi", "get", "pods",
		"-l", "app=ceph-csi-rbd,component=provisioner", "-o", "jsonpath={.items[*].status.phase}")
	if err != nil {
		return fmt.Errorf("get ceph-csi provisioner pods on the hub: %w", err)
	}
	if strings.Contains(phases, "Running") {
		return nil
	}

	// Fallback: the label selector matched nothing; look for a provisioner pod by
	// name and require it Running.
	out, err := kubectl(ctx, cfg, "hub", "-n", "ceph-csi", "get", "pods",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.status.phase}{\"\\n\"}{end}")
	if err != nil {
		return fmt.Errorf("list ceph-csi pods on the hub: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.HasPrefix(f[0], "ceph-csi-rbd-provisioner") && f[1] == "Running" {
			return nil
		}
	}
	return fmt.Errorf("no Running ceph-csi-rbd provisioner pod on the hub (phases=%q, pods=%q)", phases, out)
}

// rbdPVCFixture renders a 1Gi ReadWriteOnce PVC bound to the ceph-rbd
// StorageClass, in the default namespace.
func rbdPVCFixture() string {
	return `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: rbd-smoke
  namespace: default
spec:
  storageClassName: ceph-rbd
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
`
}

// applyCluster applies a multi-doc YAML to a named cluster via `kubectl apply -f -`.
func applyCluster(ctx context.Context, cfg *config.Config, cluster, yaml string) error {
	return exec.SudoStdin(ctx, yaml,
		"kubectl", "--kubeconfig", kubeconfigPath(cfg, cluster), "apply", "-f", "-")
}
