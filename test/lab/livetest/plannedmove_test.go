// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
)

// Names for the planned-move fixture: distinct from the volume-move and Tier-2 fixtures so an
// asynchronous cleanup of one can never be mistaken for the state of another.
const (
	pmoveVM     = "pmove-vm"
	pmoveVolume = "pmove-disk"
	// pmoveVMI is the KubeVirt VM/VMI name the pipeline produces (<namespace>-<vm>), which is also
	// the vm.kubevirt.io/name label on its virt-launcher pod.
	pmoveVMI = volMoveNS + "-" + pmoveVM
)

// plannedMoveFixture is a VM that actually RUNS — so a virt-launcher holds its disk — with one blank
// RBD disk and no network. Blank (no bootImage) keeps a registry import out of the test; qemu starts
// and holds the block device whether or not anything on it boots, which is all the overlap needs.
func plannedMoveFixture(clusterName string) string {
	return fmt.Sprintf(`apiVersion: storage.ectobase.dev/v1alpha1
kind: Volume
metadata: {name: %[2]s, namespace: %[3]s}
spec: {size: 1Gi, storageClass: ceph-rbd}
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata: {name: %[1]s, namespace: %[3]s}
spec:
  clusterName: %[4]s
  volumeRefs: [{name: %[2]s}]
  runStrategy: Always
  resources:
    requests: {cpu: 100m, memory: 128Mi}
`, pmoveVM, pmoveVolume, volMoveNS, clusterName)
}

// launcherOn returns the virt-launcher pods for the fixture VM on cluster, by name.
func launcherOn(ctx context.Context, cfg *config.Config, cluster string) ([]string, error) {
	out, err := kubectl(ctx, cfg, cluster, "-n", volMoveNS, "get", "pods",
		"-l", "vm.kubevirt.io/name="+pmoveVMI, "-o", "name")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// TestPlannedMove moves a RUNNING, disk-backed VM between two healthy pools by changing
// spec.clusterName, and asserts the one property a planned move has to have: the target never runs
// the VM while the source still does. Two virt-launchers on one ReadWriteOnce RBD image, one per
// cluster, is two writers — Ceph does not refuse it (the images carry only `layering`), and
// ReadWriteOnce is enforced per cluster, not across them.
//
// A sampler polls both clusters from the moment the move is issued until the source holds nothing —
// not merely until the target looks ready, since that would stop watching before the real overlap
// window (the source can keep its launcher and disk claim for a while after the target starts). It
// reads the TARGET first and the source second, so a violation it records was observed on the source
// AFTER the target was already running — it cannot be an artefact of sampling order.
//
// Then the same end state Tier-2 asserts: the target adopted the original image by CSI handle, the
// image survived, and the source holds nothing.
func TestPlannedMove(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	if !cfg.Fabric.Ceph.Enabled {
		t.Skip("ceph disabled in lab config (fabric.ceph.enabled=false)")
	}
	compute := computeClusters(cfg)
	if len(compute) < 2 {
		t.Skip("need >=2 compute clusters to move a VM between them")
	}
	src, dst := compute[0].Name, compute[1].Name
	for _, c := range []string{src, dst} {
		if _, err := kubectl(ctx, cfg, c, "get", "crd", "virtualmachines.kubevirt.io"); err != nil {
			t.Skipf("KubeVirt not installed on %s (run `lab tier2 up`): %v", c, err)
		}
	}
	pool, err := rbdPool(ctx, cfg, src)
	require.NoError(t, err)

	applyDispatch(t, ctx, cfg, plannedMoveFixture(src))
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "virtualmachines.compute.ectobase.dev",
			pmoveVM, "-n", volMoveNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "volumes.storage.ectobase.dev",
			pmoveVolume, "-n", volMoveNS, "--ignore-not-found", "--wait=false")
	})
	att := attName(volMoveNS, pmoveVM, pmoveVolume)

	// GATE: the VM RUNS on the source (VMI phase Running — a launcher pod merely existing is not
	// enough: a Pending one is deleted instantly and the move then looks safe when nothing was ever
	// holding the disk), holds its disk, and the disk's identity is recorded — only a recorded
	// identity reaches the target twin, so only then is adoption (not a blank disk) the expected
	// outcome.
	var srcHandle, srcImage string
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		phase, err := kubectl(ctx, cfg, src, "-n", volMoveNS, "get", "vmi", pmoveVMI, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if p := strings.TrimSpace(phase); p != "Running" {
			return fmt.Errorf("VMI %s on %s is %q, want Running", pmoveVMI, src, p)
		}
		_, h, img, err := diskPV(ctx, cfg, src, att)
		if err != nil {
			return err
		}
		srcHandle, srcImage = h, img
		return nil
	})
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "volume.storage.ectobase.dev", pmoveVolume,
			"-n", volMoveNS, "-o", "jsonpath={.status.diskIdentity.csi.volumeHandle}")
		if err != nil {
			return err
		}
		if got := strings.TrimSpace(out); got != srcHandle {
			return fmt.Errorf("Volume records identity %q, want %q", got, srcHandle)
		}
		return nil
	})
	t.Logf("running on %s with disk %s (handle %s)", src, srcImage, srcHandle)

	// Sample the whole move.
	var (
		mu         sync.Mutex
		violations []string
	)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			onDst, err := launcherOn(ctx, cfg, dst)
			if err != nil || len(onDst) == 0 {
				continue
			}
			onSrc, _ := launcherOn(ctx, cfg, src)
			claim, _ := kubectl(ctx, cfg, src, "-n", volMoveNS, "get", "pvc", att, "--ignore-not-found", "-o", "name")
			if len(onSrc) > 0 || strings.TrimSpace(claim) != "" {
				mu.Lock()
				violations = append(violations, fmt.Sprintf("%s: %s runs %v while %s still has launcher %v / claim %q",
					time.Now().Format(time.TimeOnly), dst, onDst, src, onSrc, strings.TrimSpace(claim)))
				mu.Unlock()
			}
		}
	}()

	_, err = kubectl(ctx, cfg, "dispatch", "patch", "virtualmachines.compute.ectobase.dev", pmoveVM,
		"-n", volMoveNS, "--type=merge", "-p", fmt.Sprintf(`{"spec":{"clusterName":%q}}`, dst))
	require.NoError(t, err, "move the VM to %s", dst)
	t.Logf("moved %s: %s -> %s", pmoveVM, src, dst)

	// The target runs the VM on the ORIGINAL disk.
	eventually(t, 10*time.Minute, 5*time.Second, func() error {
		pods, err := launcherOn(ctx, cfg, dst)
		if err != nil {
			return err
		}
		if len(pods) == 0 {
			return fmt.Errorf("no virt-launcher for %s on %s yet", pmoveVMI, dst)
		}
		phase, err := kubectl(ctx, cfg, dst, "-n", volMoveNS, "get", "vmi", pmoveVMI, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if p := strings.TrimSpace(phase); p != "Running" {
			return fmt.Errorf("VMI %s on %s is %q, want Running", pmoveVMI, dst, p)
		}
		_, h, img, err := diskPV(ctx, cfg, dst, att)
		if err != nil {
			return err
		}
		if h != srcHandle {
			return fmt.Errorf("%s bound image %s (handle %s), want the original %s", dst, img, h, srcHandle)
		}
		return nil
	})

	imgs, err := rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, srcImage, "DATA LOSS: image %s gone from pool %s after the move", srcImage, pool)

	// The source holds nothing of the VM. The sampler is still running throughout this wait, so it
	// keeps observing right up to the moment the source has genuinely let go.
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		var left []string
		if pods, err := launcherOn(ctx, cfg, src); err != nil {
			return err
		} else if len(pods) > 0 {
			left = append(left, "virt-launcher pods "+strings.Join(pods, ","))
		}
		for _, o := range []struct{ kind, name string }{
			{"compiledvms.compiled.ectobase.dev", pmoveVMI},
			{"compiledvolumeattachments.compiled.ectobase.dev", att},
			{"virtualmachines.kubevirt.io", pmoveVMI},
			{"persistentvolumeclaims", att},
		} {
			out, err := kubectl(ctx, cfg, src, "-n", volMoveNS, "get", o.kind, o.name, "--ignore-not-found", "-o", "name")
			if err != nil {
				return err
			}
			if strings.TrimSpace(out) != "" {
				left = append(left, o.kind+"/"+o.name)
			}
		}
		if len(left) > 0 {
			return fmt.Errorf("%s still holds %v", src, left)
		}
		return nil
	})

	close(stop)
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, violations, "TWO WRITERS: the target ran the VM while the source still held it:\n%s",
		strings.Join(violations, "\n"))

	t.Logf("planned move PASS: %s ran only after %s let go; disk %s intact", dst, src, srcImage)
}
