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

// The names the fixture uses. The compiler derives the CompiledVolumeAttachment — and therefore the
// DataVolume and PVC — as <vmNamespace>-<vmName>-<volumeRef> (compiledvolumeattachment.go:45).
const (
	volMoveNS     = "default"
	volMoveVM     = "vmove-vm"
	volMoveVolume = "vmove-disk"
	volMoveAtt    = volMoveNS + "-" + volMoveVM + "-" + volMoveVolume
)

// volMoveFixture is a VM bound to clusterName with one RBD disk, and deliberately nothing else.
//
// No VPC, Subnet or NetworkInterface: interfaceRefs is optional, and a VM with none still compiles
// to a CompiledVolumeAttachment and materializes a real RBD image (verified on the live fabric).
// Leaving them out keeps IPAM, VNI allocation and subnet-prefix collisions entirely out of a test
// about disk lifetime.
//
// runStrategy Halted: KubeVirt creates the VirtualMachine object and no VMI, so there is no qemu and
// no software-emulated guest boot to wait on. No bootImage: the DataVolume source becomes Blank
// (volumematerializer.go:47), so nothing is pulled from a registry over the fabric's NAT64. The
// ceph-rbd StorageClass is volumeBindingMode: Immediate, so an image is still provisioned with no
// consumer pod. What is under test is the disk's lifetime, not a guest.
func volMoveFixture(clusterName string) string {
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
  runStrategy: Halted
  resources:
    requests: {cpu: "1", memory: 1Gi}
`, volMoveVM, volMoveVolume, volMoveNS, clusterName)
}

// rbdPool reads the RBD pool the ceph-rbd StorageClass provisions into, rather than hardcoding
// "replicapool": the pool is a lab bring-up parameter (deploy.Ceph.Pool), so asking the live
// StorageClass cannot drift from what the fabric actually deployed.
func rbdPool(ctx context.Context, cfg *config.Config, cluster string) (string, error) {
	out, err := kubectl(ctx, cfg, cluster, "get", "storageclass", "ceph-rbd",
		"-o", "jsonpath={.parameters.pool}")
	if err != nil {
		return "", fmt.Errorf("read ceph-rbd StorageClass pool: %w", err)
	}
	pool := strings.TrimSpace(out)
	if pool == "" {
		return "", fmt.Errorf("ceph-rbd StorageClass names no pool")
	}
	return pool, nil
}

// rbdImages lists the images in pool on the fabric's ceph node. This is the ground truth the test
// turns on: a PVC reappearing in the target cluster proves nothing, because the target provisions a
// blank image whether or not the original survived. Only the shared Ceph cluster can say whether
// the bytes still exist.
func rbdImages(ctx context.Context, cfg *config.Config, pool string) ([]string, error) {
	ctr := "clab-" + cfg.Name + "-ceph"
	out, err := exec.SudoOutput(ctx, "docker", "exec", ctr, "rbd", "ls", "-p", pool)
	if err != nil {
		return nil, fmt.Errorf("rbd ls -p %s on %s: %w\n%s", pool, ctr, err, out)
	}
	var imgs []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			imgs = append(imgs, l)
		}
	}
	return imgs, nil
}

// diskPV resolves the PV actually backing the attachment's disk in cluster, and returns its
// volumeHandle and RBD image name.
//
// The image is read from volumeAttributes.imageName, which ceph-csi sets, rather than derived from
// the handle. Deriving it is a trap: the handle is 0001-0024-<fsid>-<poolid>-<uuid> and BOTH the fsid
// and the uuid contain dashes, so splitting on the last dash yields only the uuid's final group.
// The driver already records the answer; ask it.
//
// It checks the attachment's own PVC first and falls back to a PVC that PVC owns, because CDI
// populates a block DataVolume through a "prime" PVC: the prime one binds the RBD image and the
// named target PVC stays Pending until the import finishes. So while an import is incomplete the
// image is reachable only via the prime child. Preferring the target PVC means this keeps reporting
// the same disk once imports complete, rather than encoding CDI's intermediate shape.
func diskPV(ctx context.Context, cfg *config.Config, cluster string) (pvName, handle, image string, err error) {
	out, err := kubectl(ctx, cfg, cluster, "get", "pvc", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}|{.metadata.name}|{.status.phase}|{.spec.volumeName}|{.metadata.ownerReferences[*].name}{\"\\n\"}{end}")
	if err != nil {
		return "", "", "", fmt.Errorf("list PVCs on %s: %w", cluster, err)
	}

	var target, viaPrime string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 4 || f[1] == "" {
			continue
		}
		name, phase, pv := f[1], f[2], f[3]
		if phase != "Bound" || pv == "" {
			continue
		}
		switch {
		case name == volMoveAtt:
			target = pv
		case len(f) > 4 && strings.Contains(f[4], volMoveAtt):
			viaPrime = pv
		}
	}
	pvName = target
	if pvName == "" {
		pvName = viaPrime
	}
	if pvName == "" {
		return "", "", "", fmt.Errorf("no Bound PVC for attachment %s on %s", volMoveAtt, cluster)
	}

	csi, err := kubectl(ctx, cfg, cluster, "get", "pv", pvName,
		"-o", "jsonpath={.spec.csi.volumeHandle}|{.spec.csi.volumeAttributes.imageName}")
	if err != nil {
		return pvName, "", "", fmt.Errorf("read csi block of PV %s on %s: %w", pvName, cluster, err)
	}
	f := strings.SplitN(strings.TrimSpace(csi), "|", 2)
	if len(f) != 2 || f[0] == "" || f[1] == "" {
		return pvName, "", "", fmt.Errorf("PV %s on %s has an incomplete csi block (%q): want both a "+
			"volumeHandle and volumeAttributes.imageName", pvName, cluster, csi)
	}
	return pvName, f[0], f[1], nil
}

// TestVolumeSurvivesClusterRebind is the red test for Phase 0 of
// docs/superpowers/specs/2026-09-23-vm-mobility-across-clusters.md: changing a VM's
// spec.clusterName must MOVE its disk, not destroy it.
//
// Today it fails, and the failure is total: within ten seconds of the patch the source pool's
// CompiledVolumeAttachment is deleted, that cascades through the DataVolume it owns to the PVC, and
// the StorageClass's reclaimPolicy: Delete removes the RBD image from Ceph. The target then
// provisions a fresh blank one. Reproduced by hand on 2026-09-24 before this test existed; the
// image went from present to absent in the shared pool.
//
// testdata/tier2-vm.yaml asserted the opposite ("The same RBD (volumeRefs) reattaches on k03") and
// TestTier2Failover repeats it, but that test creates no Volume at all, so the claim was never
// exercised — which is how it survived as documentation.
func TestVolumeSurvivesClusterRebind(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	if !cfg.Fabric.Ceph.Enabled {
		t.Skip("ceph disabled in lab config (fabric.ceph.enabled=false)")
	}
	compute := computeClusters(cfg)
	if len(compute) < 2 {
		t.Skip("need >=2 compute clusters to move a disk between them")
	}
	src, dst := compute[0].Name, compute[1].Name

	if _, err := kubectl(ctx, cfg, src, "get", "storageclass", "ceph-rbd"); err != nil {
		t.Skipf("ceph not deployed (run `lab ceph`): %v", err)
	}
	pool, err := rbdPool(ctx, cfg, src)
	require.NoError(t, err)

	applyDispatch(t, ctx, cfg, volMoveFixture(src))

	// GATE. Every precondition is required, never skipped past: an earlier hand-run of this
	// scenario flipped clusterName while the VM was unschedulable and its PVC had never bound, and
	// so "observed" the move of a disk that was never established. If the disk does not exist on
	// the source, there is nothing to move and the run says so instead of producing a verdict.
	var srcHandle, srcImage string
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		_, h, img, err := diskPV(ctx, cfg, src)
		if err != nil {
			return err
		}
		srcHandle, srcImage = h, img
		return nil
	})

	imgs, err := rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, srcImage,
		"precondition: the image %s that %s's PV names is not in pool %s — the handle->image mapping is "+
			"wrong, so fix that before reading any verdict from this test", srcImage, src, pool)
	t.Logf("disk established on %s: handle=%s image=%s", src, srcHandle, srcImage)

	// THE MOVE. This is exactly what Tier-2 failover does (failover.go:137) and what a planned
	// drain would do.
	_, err = kubectl(ctx, cfg, "dispatch", "patch", "virtualmachine.compute.ectobase.dev", volMoveVM,
		"-n", volMoveNS, "--type=merge", "-p", fmt.Sprintf(`{"spec":{"clusterName":%q}}`, dst))
	require.NoError(t, err, "patch spec.clusterName %s -> %s", src, dst)

	// 1. THE POINT: the bytes must still exist. Asserted against Ceph, not Kubernetes.
	//
	//    Checked repeatedly over the window in which the cascade runs (it completed in under ten
	//    seconds by hand) rather than once after a sleep, so a destroyed image cannot be missed by
	//    sampling before the deletion or after the target has provisioned a replacement.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		imgs, err := rbdImages(ctx, cfg, pool)
		require.NoError(t, err)
		require.Contains(t, imgs, srcImage,
			"DATA LOSS: image %s is gone from pool %s after moving the VM %s -> %s. The disk was "+
				"destroyed by the rebind instead of being moved.", srcImage, pool, src, dst)
		time.Sleep(3 * time.Second)
	}
	t.Logf("image %s survived the rebind", srcImage)

	// 2. And the moved VM must actually be given that disk back — a surviving-but-orphaned image
	//    with a blank disk attached in the target is still data loss from the guest's view.
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		pv, h, img, err := diskPV(ctx, cfg, dst)
		if err != nil {
			return err
		}
		if h != srcHandle {
			return fmt.Errorf("%s bound PV %s with image %s (handle %s), want the original %s (handle %s)",
				dst, pv, img, h, srcImage, srcHandle)
		}
		return nil
	})
	t.Logf("rebind PASS: %s attached the original disk %s", dst, srcImage)
}
