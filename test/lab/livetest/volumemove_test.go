//go:build live

package livetest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// The names the fixture uses. The compiler derives the CompiledVolumeAttachment — and therefore the
// DataVolume and PVC — as <vmNamespace>-<vmName>-<volumeRef> (compiledvolumeattachment.go:45).
const volMoveNS = "default"

// Each test in this file owns its OWN object names. They used to share one fixture, and that
// produced a quietly wrong result: the reclaim test inherited the move test's disk (same image name
// in both logs) because the first test's Volume was still finalizing when the second applied the
// same manifest, so the second never provisioned anything of its own. Its assertion still held, but
// it was no longer testing what it claimed to.
const (
	volMoveVM     = "vmove-vm"
	volMoveVolume = "vmove-disk"

	volReclaimVM     = "vreclaim-vm"
	volReclaimVolume = "vreclaim-disk"

	volRaceVM     = "vrace-vm"
	volRaceVolume = "vrace-disk"
)

// attName is the CompiledVolumeAttachment — and therefore DataVolume and PVC — the compiler derives
// for a (vm, volume) pair: <vmNamespace>-<vmName>-<volumeRef> (compiledvolumeattachment.go:45).
func attName(vm, volume string) string { return volMoveNS + "-" + vm + "-" + volume }

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
func volMoveFixture(vm, volume, clusterName string) string {
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
`, vm, volume, volMoveNS, clusterName)
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

// rbdRemove deletes an image from the pool on the fabric's ceph node. Only for a test that
// knowingly ORPHANS one: reclaim is driven by the recorded identity, so a disk moved before it was
// ever recorded has nothing left to reclaim it and would otherwise accumulate in the shared pool on
// every run.
func rbdRemove(ctx context.Context, cfg *config.Config, pool, image string) error {
	ctr := "clab-" + cfg.Name + "-ceph"
	out, err := exec.SudoOutput(ctx, "docker", "exec", ctr, "rbd", "rm", "-p", pool, image)
	if err != nil {
		return fmt.Errorf("rbd rm -p %s %s: %w\n%s", pool, image, err, out)
	}
	return nil
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
func diskPV(ctx context.Context, cfg *config.Config, cluster, att string) (pvName, handle, image string, err error) {
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
		case name == att:
			target = pv
		case len(f) > 4 && strings.Contains(f[4], att):
			viaPrime = pv
		}
	}
	pvName = target
	if pvName == "" {
		pvName = viaPrime
	}
	if pvName == "" {
		return "", "", "", fmt.Errorf("no Bound PVC for attachment %s on %s", att, cluster)
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
// Before Phase 0 the failure was total: within ten seconds of the patch the source pool's
// CompiledVolumeAttachment was deleted, that cascaded through the DataVolume it owns to the PVC, and
// the StorageClass's reclaimPolicy: Delete removed the RBD image from Ceph, leaving the target to
// provision a fresh blank one. Reproduced by hand on 2026-09-24 before this test existed; the image
// went from present to absent in the shared pool. It now passes: the image survives and the target
// attaches the original disk.
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

	applyDispatch(t, ctx, cfg, volMoveFixture(volMoveVM, volMoveVolume, src))
	att := attName(volMoveVM, volMoveVolume)

	// GATE. Every precondition is required, never skipped past: an earlier hand-run of this
	// scenario flipped clusterName while the VM was unschedulable and its PVC had never bound, and
	// so "observed" the move of a disk that was never established. If the disk does not exist on
	// the source, there is nothing to move and the run says so instead of producing a verdict.
	var srcHandle, srcImage string
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		_, h, img, err := diskPV(ctx, cfg, src, att)
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

	// GATE 2: the disk's identity must be RECORDED on the Volume before the move.
	//
	// This is a real precondition, not a convenience. A disk becomes protected when the pool that
	// provisioned it observes the bound claim: only then is the PersistentVolume flipped to Retain and
	// its CSI identity captured and carried up. Nothing can protect a disk that has not been observed
	// yet, so there is a window — seconds, between the claim binding and that first reconcile — in
	// which a rebind still destroys the image. Moving inside it is not a move this design claims to
	// survive, and asserting otherwise would be asserting something false.
	//
	// The Volume is the right thing to wait on rather than the attachment's status: it is the end of
	// the chain (pool -> attachment status -> broker -> dispatch -> mirror -> Volume) and it is what
	// the compiler reads when it stamps the next attachment. If it is set, every hop has happened.
	eventually(t, 3*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "volume.storage.ectobase.dev", volMoveVolume,
			"-n", volMoveNS, "-o", "jsonpath={.status.diskIdentity.csi.volumeHandle}")
		if err != nil {
			return fmt.Errorf("read the Volume's recorded identity: %w", err)
		}
		if got := strings.TrimSpace(out); got != srcHandle {
			return fmt.Errorf("Volume records identity %q, want the provisioned disk %q", got, srcHandle)
		}
		return nil
	})
	t.Logf("identity recorded on the Volume; the disk is now protected and the move is meaningful")

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
		pv, h, img, err := diskPV(ctx, cfg, dst, att)
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

// TestVolumeDeleteReclaimsTheImage is the counterweight to the move, and the reason Phase 0 needs
// one at all.
//
// Making a disk survive a cluster rebind means flipping its PersistentVolume to Retain, so the RBD
// image deliberately outlives every claim that ever referenced it and nothing reclaims it by cascade
// any more. Without an explicit reclaim, deleting a Volume would leak its image forever — trading a
// data-loss bug for an unbounded capacity leak, in a system with no way to tell which images are
// still owned. So this asserts the other half: when the intent goes, the bytes go.
//
// Ground truth is again the image list on the shared Ceph node. A Volume object disappearing proves
// nothing; the finalizer exists precisely so the object can outlive the delete request until the
// image is actually gone.
func TestVolumeDeleteReclaimsTheImage(t *testing.T) {
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
	src := compute[0].Name
	if _, err := kubectl(ctx, cfg, src, "get", "storageclass", "ceph-rbd"); err != nil {
		t.Skipf("ceph not deployed (run `lab ceph`): %v", err)
	}
	pool, err := rbdPool(ctx, cfg, src)
	require.NoError(t, err)

	applyDispatch(t, ctx, cfg, volMoveFixture(volReclaimVM, volReclaimVolume, src))
	att := attName(volReclaimVM, volReclaimVolume)

	// Establish the disk and wait until it is PROTECTED, i.e. Retain applied and the identity
	// recorded. Reclaim only has something to do once the image has stopped being reclaimed by
	// cascade, so a Volume deleted before that would be a test of nothing.
	var image string
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		_, _, img, err := diskPV(ctx, cfg, src, att)
		if err != nil {
			return err
		}
		image = img
		return nil
	})
	eventually(t, 3*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "volume.storage.ectobase.dev", volReclaimVolume,
			"-n", volMoveNS, "-o", "jsonpath={.status.diskIdentity.csi.volumeAttributes.imageName}")
		if err != nil {
			return fmt.Errorf("read the Volume's recorded identity: %w", err)
		}
		if got := strings.TrimSpace(out); got != image {
			return fmt.Errorf("Volume records image %q, want %q", got, image)
		}
		return nil
	})
	imgs, err := rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, image, "precondition: the disk's image must exist before deleting it")
	t.Logf("protected disk established: %s", image)

	// Delete the whole VM first, so the disk is detached and Retain is what is keeping the image
	// alive — exactly the state in which a leak would otherwise be permanent.
	_, err = kubectl(ctx, cfg, "dispatch", "delete", "virtualmachine.compute.ectobase.dev", volReclaimVM,
		"-n", volMoveNS, "--wait=true")
	require.NoError(t, err, "delete the VM")

	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		imgs, err := rbdImages(ctx, cfg, pool)
		if err != nil {
			return err
		}
		if !slices.Contains(imgs, image) {
			return fmt.Errorf("image %s was destroyed by deleting the VM; only deleting the VOLUME may "+
				"reclaim it, or a rebind would lose data", image)
		}
		return nil
	})
	t.Logf("image survived the VM's deletion, as Retain intends")

	// THE POINT: deleting the Volume — the intent that owns the disk — must delete the image.
	_, err = kubectl(ctx, cfg, "dispatch", "delete", "volume.storage.ectobase.dev", volReclaimVolume,
		"-n", volMoveNS, "--wait=false")
	require.NoError(t, err, "delete the Volume")

	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		imgs, err := rbdImages(ctx, cfg, pool)
		if err != nil {
			return err
		}
		if slices.Contains(imgs, image) {
			return fmt.Errorf("image %s still in pool %s after its Volume was deleted — every deleted "+
				"volume leaks its image", image, pool)
		}
		return nil
	})

	// And the Volume itself is released only once the image is gone: that ordering is the whole point
	// of the finalizer, and a Volume that vanished first would mean the reclaim was never observed.
	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "volumes.storage.ectobase.dev", "-n", volMoveNS,
			"-o", "jsonpath={range .items[*]}{.metadata.name} {end}")
		if err != nil {
			return fmt.Errorf("list Volumes: %w", err)
		}
		if strings.Contains(out, volReclaimVolume) {
			return fmt.Errorf("%s still held after its image was reclaimed; remaining: %q", volReclaimVolume, out)
		}
		return nil
	})
	t.Logf("reclaim PASS: deleting the Volume deleted image %s and then released the Volume", image)
}

// TestVolumeSurvivesAnImmediateRebind covers the capture window — the last way this design could
// still lose data, and the one case the move test deliberately excludes.
//
// TestVolumeSurvivesClusterRebind waits for the disk's identity to reach the Volume before moving,
// because only then can the target ADOPT it. This test does the opposite: it moves the instant the
// claim binds, before anything has protected or recorded the disk. That used to destroy the image
// outright — the PV still carried the StorageClass's Delete, so pruning the attachment took the claim
// and the volume with it.
//
// What is asserted here is narrower than the move test on purpose, and the difference matters:
//
//	the IMAGE SURVIVES                   — no data is destroyed (this test)
//	the TARGET ATTACHES THE SAME IMAGE   — the move works (TestVolumeSurvivesClusterRebind)
//
// Moving inside the window still costs the VM its disk on the far side, because adoption needs an
// identity that was never recorded; the target provisions a blank one and the original is left
// orphaned in Ceph. That is recoverable by an operator. Destroying it was not. Turning
// unrecoverable into recoverable is the whole claim, and overstating it would be worse than leaving
// the window documented.
func TestVolumeSurvivesAnImmediateRebind(t *testing.T) {
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

	applyDispatch(t, ctx, cfg, volMoveFixture(volRaceVM, volRaceVolume, src))
	att := attName(volRaceVM, volRaceVolume)

	// The ONLY gate is that the disk exists. Deliberately NOT waiting for the identity: racing that
	// reconcile is the entire point.
	var image string
	eventually(t, 5*time.Minute, 2*time.Second, func() error {
		_, _, img, err := diskPV(ctx, cfg, src, att)
		if err != nil {
			return err
		}
		image = img
		return nil
	})
	imgs, err := rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, image, "precondition: the disk must exist before we race its protection")
	t.Logf("disk exists on %s as %s; moving immediately, without waiting for it to be protected", src, image)

	// This test deliberately produces an orphan: surviving the move is the point, and with no
	// identity ever recorded there is nothing to reclaim it afterwards. That is the intended trade
	// (recoverable beats destroyed), but it is still garbage in a shared pool, so remove it here
	// rather than leave one behind on every run.
	t.Cleanup(func() {
		if err := rbdRemove(context.Background(), cfg, pool, image); err != nil {
			t.Logf("could not remove the orphan %s (it may already be gone): %v", image, err)
		}
	})

	_, err = kubectl(ctx, cfg, "dispatch", "patch", "virtualmachine.compute.ectobase.dev", volRaceVM,
		"-n", volMoveNS, "--type=merge", "-p", fmt.Sprintf(`{"spec":{"clusterName":%q}}`, dst))
	require.NoError(t, err, "patch spec.clusterName %s -> %s", src, dst)

	// THE POINT: whatever the move costs, it must not destroy the bytes. Sampled across the window in
	// which the prune and its cascade run, so a destroyed image cannot be missed between polls.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		imgs, err := rbdImages(ctx, cfg, pool)
		require.NoError(t, err)
		require.Contains(t, imgs, image,
			"DATA LOSS: image %s was destroyed by a move that raced its protection. The detach must "+
				"flip the PersistentVolume to Retain before releasing the claim, whatever happened earlier.",
			image)
		time.Sleep(3 * time.Second)
	}
	t.Logf("survival PASS: %s outlived a move taken before anything protected it", image)
}
